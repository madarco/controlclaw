//! The node relay (plan §5 "The desktop app as a node", spike for step 18; docs/plans/node-rules.md):
//! an OpenClaw node (the macOS app, `openclaw node run`) connects here instead of to the gateway, and
//! this relays its WebSocket to the gateway frame by frame, unchanged. It only logs: who connected
//! (role, client, device id, once the gateway accepted it) and what the gateway asks the node to do
//! (`node.invoke.request`: the command, and for `system.run` the command line), with the result's
//! outcome. No rules, nothing held.
//!
//! Standalone only, and off unless `NODE_RELAY=<listen host:port>=<gateway host:port>` is set. With
//! `NODE_RELAY_TLS=<cert.pem>,<key.pem>` it serves `wss://` (a node pins this certificate, not the
//! gateway's); the gateway side is plain `ws://`, so the gateway must be at a private address (the
//! firewall's own network to it) unless `NODE_RELAY_INSECURE=1`.
//!
//! OpenClaw's device signature covers the challenge's nonce, the device, client, role, scopes and
//! token, not the connection, so pairing passes a relay that does not change the frames.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};

use crate::integrations::mcp::public::is_public_address;

/// Above the gateway's own frame cap (25 MiB, `policy.maxPayload`).
const MAX_FRAME: usize = 32 * 1024 * 1024;
/// Frames above this are passed on but not parsed for the log: a parse into a JSON tree holds the
/// frame several times over in memory. One that names `node.invoke` gets a line saying it was not
/// read. (The gateway's answer to the connect is read at any size, field by field.)
const MAX_DESCRIBED: usize = 64 * 1024;
/// How much of a command line or a page's address a log line keeps.
const MAX_LOGGED: usize = 300;
/// How much of any other field (ids, names, role, platform) a log line keeps.
const MAX_FIELD: usize = 64;
/// Nodes at once: a few per person; more is someone holding sockets open.
const MAX_CONNECTIONS: usize = 64;
/// For the TLS handshake, the node's upgrade, and the gateway's.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How long the other direction may still pass frames after one side closed.
const DRAIN: Duration = Duration::from_secs(5);

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME))
}

/// `NODE_RELAY`: the listen address and the gateway's, `<host:port>=<host:port>`.
pub fn parse(spec: &str) -> Option<(String, String)> {
    let (listen, gateway) = spec.split_once('=')?;
    let ok = |a: &str| {
        a.rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok())
    };
    (ok(listen) && ok(gateway)).then(|| (listen.to_string(), gateway.to_string()))
}

/// At most `max` characters, control characters escaped: a field cannot write a line of its own
/// into the journal, nor fill it.
fn clip(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars().take(max) {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

fn field(v: &Value, k: &str) -> String {
    clip(v.get(k).and_then(Value::as_str).unwrap_or(""), MAX_FIELD)
}

/// The gateway's answer to a request, as far as acceptance needs it; serde skips the other fields
/// (the snapshot, the method list) without building them.
#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "type")]
    kind: Option<String>,
    id: Option<Value>,
    ok: Option<bool>,
    payload: Option<AnswerPayload>,
}

#[derive(Deserialize)]
struct AnswerPayload {
    #[serde(rename = "type")]
    kind: Option<String>,
}

/// What the log keeps of one connection. A node's `connect` is only a claim until the gateway
/// answers with `hello-ok`: it is logged then, and no result the node sends before counts.
#[derive(Default)]
pub struct Session {
    /// The first connect request's id and its line, until the gateway answers.
    pending: Option<(Value, String)>,
    /// The node sent a frame before acceptance that the relay did not read.
    unread: bool,
    accepted: bool,
}

impl Session {
    /// The line one frame gives the log, if any. `to_node` is the gateway's direction.
    pub fn frame(&mut self, text: &str, to_node: bool) -> Option<String> {
        if !self.accepted {
            return if to_node { self.answer(text) } else { self.claim(text) };
        }
        // Most frames say nothing the log keeps: skip the parse.
        if !text.contains("node.invoke") {
            return None;
        }
        let side = if to_node { "gateway" } else { "node" };
        if text.len() > MAX_DESCRIBED {
            return Some(format!(
                "{side} frame of {} bytes naming node.invoke, not read",
                text.len()
            ));
        }
        let v: Value = serde_json::from_str(text).ok()?;
        if to_node {
            return invoke_line(&v);
        }
        if v.get("type").and_then(Value::as_str) != Some("req")
            || v.get("method").and_then(Value::as_str) != Some("node.invoke.result")
        {
            return None;
        }
        let p = v.get("params")?;
        Some(format!(
            "result {} ok={}",
            field(p, "id"),
            p.get("ok")
                .and_then(Value::as_bool)
                .map_or("?".to_string(), |ok| ok.to_string())
        ))
    }

    /// A node frame before acceptance: the first connect is kept; a later one is not what the
    /// gateway answers (it takes the first frame), and results are not believed yet.
    fn claim(&mut self, text: &str) -> Option<String> {
        if self.pending.is_some() {
            return None;
        }
        if text.len() > MAX_DESCRIBED {
            self.unread = true;
            return None;
        }
        // Every frame is parsed here, not looked for by name: `connect` is a connect too.
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            self.unread = true;
            return None;
        };
        if v.get("type").and_then(Value::as_str) != Some("req")
            || v.get("method").and_then(Value::as_str) != Some("connect")
        {
            return None;
        }
        let p = v.get("params").unwrap_or(&Value::Null);
        let client = p.get("client").unwrap_or(&Value::Null);
        let device = p.get("device").map(|d| field(d, "id")).unwrap_or_default();
        let line = format!(
            "connect role={} client={} name={:?} platform={} device={}",
            field(p, "role"),
            field(client, "id"),
            field(client, "displayName"),
            field(client, "platform"),
            device.chars().take(16).collect::<String>()
        );
        self.pending = Some((v.get("id").cloned().unwrap_or(Value::Null), line));
        None
    }

    /// A gateway frame before acceptance: `hello-ok` accepts the connection, whatever its size.
    /// The gateway sends it only for a connect, so it accepts even a connect the relay could not
    /// read; the line then says so.
    fn answer(&mut self, text: &str) -> Option<String> {
        if !text.contains("hello-ok") {
            // An invoke never comes before hello-ok; if one did, it is still the gateway's.
            return if text.contains("node.invoke") && text.len() <= MAX_DESCRIBED {
                serde_json::from_str::<Value>(text).ok().as_ref().and_then(invoke_line)
            } else {
                None
            };
        }
        let a: Answer = serde_json::from_str(text).ok()?;
        let hello = a.kind.as_deref() == Some("res")
            && a.ok == Some(true)
            && a.payload.and_then(|p| p.kind).as_deref() == Some("hello-ok");
        if !hello {
            return None;
        }
        self.accepted = true;
        match self.pending.take() {
            Some((id, line)) if !id.is_null() && a.id.as_ref() == Some(&id) => Some(line),
            _ => Some(format!(
                "connect accepted by the gateway, its request not read{}",
                if self.unread {
                    " (over the size limit, or not JSON)"
                } else {
                    ""
                }
            )),
        }
    }
}

/// The log line of a `node.invoke.request` event.
fn invoke_line(v: &Value) -> Option<String> {
    if v.get("event").and_then(Value::as_str) != Some("node.invoke.request") {
        return None;
    }
    let p = v.get("payload")?;
    let command = field(p, "command");
    let params: Value = p
        .get("paramsJSON")
        .and_then(Value::as_str)
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or(Value::Null);
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let detail = match command.as_str() {
        "system.run" | "system.run.prepare" => match params.get("command") {
            Some(Value::Array(argv)) => argv
                .iter()
                .map(|a| a.as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(" "),
            Some(Value::String(c)) => c.clone(),
            _ => String::new(),
        },
        // The browser proxy: the method and path it asks the node's browser for, and the page
        // (`/tabs/open`, `/navigate`).
        "browser.proxy" => {
            let url = params.get("body").map(|b| s(b, "url")).unwrap_or_default();
            format!("{} {} {url}", s(&params, "method"), s(&params, "path"))
                .trim_end()
                .to_string()
        }
        _ => String::new(),
    };
    Some(format!(
        "invoke {} node={} {command} {}",
        field(p, "id"),
        field(p, "nodeId"),
        clip(&detail, MAX_LOGGED)
    ))
}

/// Started with the standalone control plane; does nothing without `NODE_RELAY`.
pub async fn serve() {
    let Ok(spec) = std::env::var("NODE_RELAY") else { return };
    let Some((listen, gateway)) = parse(&spec) else {
        tracing::error!("[node-relay] NODE_RELAY: not <host:port>=<host:port>: {spec}");
        return;
    };
    let tls = match std::env::var("NODE_RELAY_TLS").ok().filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => {
            let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
            let made = v
                .split_once(',')
                .ok_or_else(|| "not <cert.pem>,<key.pem>".to_string())
                .and_then(|(c, k)| cc_http::tls_acceptor(&read(c)?, &read(k)?));
            match made {
                Ok(a) => Some(a),
                Err(e) => {
                    tracing::error!("[node-relay] NODE_RELAY_TLS: {e}");
                    return;
                }
            }
        }
    };
    let insecure = std::env::var("NODE_RELAY_INSECURE").as_deref() == Ok("1");
    if let Err(e) = check_listen(&listen, tls.is_some(), insecure) {
        tracing::error!("[node-relay] not started: {e}");
        return;
    }
    // A gateway the policy refuses stops it here; one whose name does not resolve yet (the tunnel
    // not up) is tried again with each node.
    match resolve_gateway(&gateway, insecure).await {
        Err(Gateway::Refused(e)) => {
            tracing::error!("[node-relay] not started: {e}");
            return;
        }
        Err(Gateway::Unresolved(e)) => tracing::warn!("[node-relay] {e}; tried again with each node"),
        Ok(_) => {}
    }
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("[node-relay] {listen}: {e}");
            return;
        }
    };
    let scheme = if tls.is_some() { "wss" } else { "ws" };
    tracing::info!("[node-relay] {scheme}://{listen} to the gateway at {gateway} (logs only)");
    let gateway = Arc::new(gateway);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(c) => c,
                // Out of descriptors, most likely: wait rather than spin.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                tracing::warn!("[node-relay] {peer}: refused, {MAX_CONNECTIONS} connections open");
                continue;
            };
            let (gateway, tls) = (gateway.clone(), tls.clone());
            tokio::spawn(async move {
                let _slot = slot;
                let r = match tls {
                    Some(a) => match tokio::time::timeout(HANDSHAKE, a.accept(tcp)).await {
                        Ok(Ok(s)) => relay(s, &gateway, insecure, peer).await,
                        Ok(Err(e)) => Err(format!("tls: {e}")),
                        Err(_) => Err("tls: timed out".into()),
                    },
                    None => relay(tcp, &gateway, insecure, peer).await,
                };
                if let Err(e) = r {
                    tracing::info!("[node-relay] {peer}: {e}");
                }
            });
        }
    });
}

/// Plain `ws://` beyond loopback is refused, as the admin API refuses plain HTTP: the gateway token
/// in the node's first frame would cross the network in clear, unless `NODE_RELAY_INSECURE=1` (a
/// private network, or a port published only on loopback, as `up --local` does).
pub fn check_listen(listen: &str, tls: bool, insecure: bool) -> Result<(), String> {
    let host = listen
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(['[', ']']))
        .unwrap_or_default();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.to_canonical().is_loopback());
    if !tls && !insecure && !loopback {
        return Err(format!(
            "{listen} is beyond this machine and NODE_RELAY_TLS is not set: the gateway token would cross the network in clear (NODE_RELAY_INSECURE=1 to allow)"
        ));
    }
    Ok(())
}

/// Whether the relay may send nodes to a gateway at this address:
/// - never loopback or unspecified (in any spelling: `::ffff:127.0.0.1`, `0.0.0.0`): the gateway
///   would take every node as local and approve it without asking;
/// - a non-public address (private, CGNAT, link-local, unique local: the firewall's own network to
///   the gateway) by default, since the leg to the gateway is plain `ws://` and carries the token; a
///   public one only with `NODE_RELAY_INSECURE=1`.
pub fn gateway_ip_allowed(ip: IpAddr, insecure: bool) -> Result<(), String> {
    let ip = ip.to_canonical();
    if ip.is_loopback() || ip.is_unspecified() {
        return Err(format!(
            "the gateway's address {ip} is loopback or unspecified: it would take every node as local and approve it"
        ));
    }
    if is_public_address(ip) && !insecure {
        return Err(format!(
            "the gateway's address {ip} is public, and the relay speaks plain ws:// to it: the gateway token would cross in clear (NODE_RELAY_INSECURE=1 to allow)"
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum Gateway {
    /// The name does not resolve (yet).
    Unresolved(String),
    /// An address it resolves to is one the relay may not use.
    Refused(String),
}

/// The gateway's name resolved, and every address it gives checked; the relay connects to the
/// address checked, so the name is not looked up again between the check and the connection.
pub async fn resolve_gateway(gateway: &str, insecure: bool) -> Result<SocketAddr, Gateway> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(gateway)
        .await
        .map_err(|e| Gateway::Unresolved(format!("the gateway {gateway}: {e}")))?
        .collect();
    let first = *addrs
        .first()
        .ok_or_else(|| Gateway::Unresolved(format!("the gateway {gateway}: no address")))?;
    for a in &addrs {
        gateway_ip_allowed(a.ip(), insecure).map_err(|e| Gateway::Refused(format!("{gateway}: {e}")))?;
    }
    Ok(first)
}

/// The node's headers the gateway gets: not the WebSocket's own (the new connection has its own), and
/// not a client address the node states (the gateway would believe it of a trusted proxy).
fn forwarded(name: &str) -> bool {
    !name.starts_with("sec-websocket-")
        && !matches!(
            name,
            "host" | "connection" | "upgrade" | "content-length" | "forwarded" | "x-real-ip"
        )
        && !name.starts_with("x-forwarded-")
}

/// One connection: the node's WebSocket accepted, the gateway's opened on the same path with the
/// node's own headers, then every frame passed on as it came.
///
/// The node gets its 101 before the gateway is asked: a gateway that refuses is told to the node as
/// a close frame. A subprotocol is neither offered upstream nor answered (OpenClaw offers none).
// The handshake callback's error type is tungstenite's own (an HTTP response).
#[allow(clippy::result_large_err)]
async fn relay<S>(stream: S, gateway: &str, insecure: bool, peer: SocketAddr) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut upstream_req = None;
    let accept = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        |req: &Request, resp: Response| {
            upstream_req = Some((
                req.uri().path_and_query().map(|p| p.to_string()).unwrap_or("/".into()),
                req.headers().clone(),
            ));
            Ok(resp)
        },
        Some(ws_config()),
    );
    let mut node = match tokio::time::timeout(HANDSHAKE, accept).await {
        Ok(r) => r.map_err(|e| format!("handshake: {e}"))?,
        Err(_) => return Err("handshake: timed out".into()),
    };
    let (path, headers) = upstream_req.ok_or("no request")?;
    let gw = match tokio::time::timeout(HANDSHAKE, open_gateway(gateway, insecure, &path, &headers)).await {
        Ok(Ok(gw)) => gw,
        failed => {
            let why = match failed {
                Ok(Err(e)) => e,
                _ => "gateway: timed out".into(),
            };
            let _ = node
                .close(Some(CloseFrame {
                    code: CloseCode::Error,
                    reason: "gateway unavailable".into(),
                }))
                .await;
            return Err(why);
        }
    };
    tracing::info!("[node-relay] {peer} {}: open", clip(&path, MAX_FIELD));
    // Both directions are polled by this one task and the lock is never held across an await; a
    // RefCell would do, but would make this future not Send.
    let session = Mutex::new(Session::default());
    let log = |text: &str, to_node: bool| {
        let line = session.lock().unwrap_or_else(|e| e.into_inner()).frame(text, to_node);
        if let Some(line) = line {
            tracing::info!("[node-relay] {peer} {line}");
        }
    };
    let (mut node_tx, mut node_rx) = node.split();
    let (mut gw_tx, mut gw_rx) = gw.split();
    let up = async {
        while let Some(Ok(m)) = node_rx.next().await {
            if let Message::Text(t) = &m {
                log(t, false);
            }
            // Each side answers its own pings.
            if matches!(m, Message::Ping(_) | Message::Pong(_)) {
                continue;
            }
            if gw_tx.send(m).await.is_err() {
                break;
            }
        }
        let _ = gw_tx.close().await;
    };
    let down = async {
        while let Some(Ok(m)) = gw_rx.next().await {
            if let Message::Text(t) = &m {
                log(t, true);
            }
            if matches!(m, Message::Ping(_) | Message::Pong(_)) {
                continue;
            }
            if node_tx.send(m).await.is_err() {
                break;
            }
        }
        let _ = node_tx.close().await;
    };
    // When one side ends, its close goes to the other, whose last frames still pass for a while.
    tokio::pin!(up, down);
    tokio::select! {
        _ = &mut up => { let _ = tokio::time::timeout(DRAIN, &mut down).await; }
        _ = &mut down => { let _ = tokio::time::timeout(DRAIN, &mut up).await; }
    }
    tracing::info!("[node-relay] {peer} {}: closed", clip(&path, MAX_FIELD));
    Ok(())
}

async fn open_gateway(
    gateway: &str,
    insecure: bool,
    path: &str,
    headers: &http::HeaderMap,
) -> Result<WebSocketStream<tokio::net::TcpStream>, String> {
    // Resolved and checked for each node: an address that changed is followed, one that became
    // loopback is refused.
    let addr = resolve_gateway(gateway, insecure).await.map_err(|e| match e {
        Gateway::Unresolved(e) | Gateway::Refused(e) => e,
    })?;
    let mut req = http::Request::builder().uri(format!("ws://{gateway}{path}"));
    for (k, v) in headers {
        if forwarded(k.as_str()) {
            req = req.header(k, v);
        }
    }
    let req = req
        .header("host", gateway)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header(
            "sec-websocket-key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .map_err(|e| e.to_string())?;
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("gateway: {e}"))?;
    let (gw, _) = tokio_tungstenite::client_async_with_config(req, tcp, Some(ws_config()))
        .await
        .map_err(|e| format!("gateway handshake: {e}"))?;
    Ok(gw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECT: &str = r#"{"type":"req","id":"c1","method":"connect","params":{"role":"node","client":{"id":"node-host","displayName":"Mac","platform":"darwin"},"device":{"id":"6f97187d20549488ab07"}}}"#;
    const HELLO: &str = r#"{"type":"res","id":"c1","ok":true,"payload":{"type":"hello-ok","protocol":4}}"#;
    const RUN: &str = r#"{"type":"event","event":"node.invoke.request","payload":{"id":"i1","nodeId":"n1","command":"system.run","paramsJSON":"{\"command\":[\"sh\",\"-c\",\"id\"]}"}}"#;
    const RESULT: &str =
        r#"{"type":"req","id":"2","method":"node.invoke.result","params":{"id":"i1","nodeId":"n1","ok":true}}"#;
    const ACCEPTED_UNREAD: &str = "connect accepted by the gateway, its request not read";

    fn accepted() -> Session {
        let mut s = Session::default();
        assert_eq!(s.frame(CONNECT, false), None);
        assert!(s.frame(HELLO, true).is_some());
        s
    }

    #[test]
    fn connect_is_logged_once_the_gateway_said_hello_ok() {
        let mut s = Session::default();
        assert_eq!(s.frame(CONNECT, false), None, "a claim until the gateway answers");
        assert_eq!(s.frame(RESULT, false), None, "no result counts before hello-ok");
        assert_eq!(
            s.frame(HELLO, true).as_deref(),
            Some(r#"connect role=node client=node-host name="Mac" platform=darwin device=6f97187d20549488"#)
        );
        assert_eq!(
            s.frame(RUN, true).as_deref(),
            Some("invoke i1 node=n1 system.run sh -c id")
        );
        assert_eq!(s.frame(RESULT, false).as_deref(), Some("result i1 ok=true"));
        assert_eq!(
            s.frame(CONNECT, false),
            None,
            "a second connect on the same socket is not a new node"
        );

        // Refused: no connect line, and the results that follow are not believed either.
        let mut r = Session::default();
        r.frame(CONNECT, false);
        let refused = r#"{"type":"res","id":"c1","ok":false,"error":{"code":"NOT_PAIRED"}}"#;
        assert_eq!(r.frame(refused, true), None);
        assert_eq!(r.frame(RESULT, false), None);

        // The first connect is the one the gateway answers; a second one before hello-ok is not.
        let mut f = Session::default();
        f.frame(CONNECT, false);
        f.frame(
            &CONNECT
                .replace("\"Mac\"", "\"Alice's Mac\"")
                .replace("6f97187d", "deadbeef"),
            false,
        );
        let line = f.frame(HELLO, true).expect("line");
        assert!(
            line.contains("name=\"Mac\"") && line.contains("device=6f97187d"),
            "{line}"
        );

        // A numeric id is matched as such.
        let mut n = Session::default();
        n.frame(&CONNECT.replace("\"c1\"", "7"), false);
        assert_eq!(
            n.frame(&HELLO.replace("\"c1\"", "\"7\""), true).as_deref(),
            Some(ACCEPTED_UNREAD),
            "7 is not \"7\""
        );
    }

    #[test]
    fn a_connect_the_relay_cannot_read_does_not_turn_the_log_off() {
        // Escaped: still a connect, parsed as JSON rather than looked for by name.
        let mut e = Session::default();
        e.frame(&CONNECT.replace("\"connect\"", "\"conn\\u0065ct\""), false);
        assert!(e.frame(HELLO, true).expect("line").starts_with("connect role=node"));
        // Padded past the limit: not read, but the gateway's hello-ok still opens the log.
        let mut p = Session::default();
        let padded = CONNECT.replace("\"Mac\"", &format!("\"{}\"", "m".repeat(MAX_DESCRIBED)));
        p.frame(&padded, false);
        assert_eq!(
            p.frame(HELLO, true).as_deref(),
            Some("connect accepted by the gateway, its request not read (over the size limit, or not JSON)")
        );
        assert_eq!(
            p.frame(RUN, true).as_deref(),
            Some("invoke i1 node=n1 system.run sh -c id")
        );
        // A hello-ok over the limit (a large snapshot) is read too.
        let mut b = Session::default();
        b.frame(CONNECT, false);
        let big = HELLO.replace(
            "\"protocol\":4",
            &format!(
                "\"protocol\":4,\"snapshot\":{{\"x\":\"{}\"}}",
                "s".repeat(MAX_DESCRIBED)
            ),
        );
        assert!(b.frame(&big, true).expect("line").starts_with("connect role=node"));
    }

    #[test]
    fn every_field_is_capped_and_escaped() {
        let long = "a".repeat(5000);
        let connect = CONNECT
            .replace("\"node-host\"", &format!("\"{long}\""))
            .replace("\"Mac\"", &format!("\"\\n[node-relay] fake{long}\""))
            .replace("\"node\"", &format!("\"{long}\""))
            .replace("\"darwin\"", &format!("\"{long}\""));
        let mut s = Session::default();
        s.frame(&connect, false);
        let line = s.frame(HELLO, true).expect("line");
        assert!(line.len() < 4 * MAX_FIELD + 80, "{}", line.len());
        assert!(!line.contains('\n') && line.contains("\\n[node-relay] fake"), "{line}");
        let run = RUN
            .replace("\"i1\"", &format!("\"{long}\""))
            .replace("\"n1\"", &format!("\"{long}\""));
        let line = s.frame(&run, true).expect("line");
        assert!(line.len() < 2 * MAX_FIELD + MAX_LOGGED + 40, "{}", line.len());
        let forged = r#"{"type":"event","event":"node.invoke.request","payload":{"id":"i3","nodeId":"n1","command":"system.run","paramsJSON":"{\"command\":[\"sh\",\"-c\",\"x\\n[node-relay] fake\"]}"}}"#;
        assert_eq!(
            s.frame(forged, true).as_deref(),
            Some("invoke i3 node=n1 system.run sh -c x\\n[node-relay] fake")
        );
        let result = RESULT.replace("\"i1\"", &format!("\"{long}\""));
        assert!(s.frame(&result, false).expect("line").len() < MAX_FIELD + 20);
    }

    #[test]
    fn a_large_frame_is_passed_but_not_parsed() {
        let mut s = accepted();
        let big = RUN.replace(
            "sh\\\",\\\"-c\\\",\\\"id",
            &format!("sh\\\",\\\"-c\\\",\\\"{}", "y".repeat(MAX_DESCRIBED)),
        );
        assert!(big.len() > MAX_DESCRIBED);
        assert_eq!(
            s.frame(&big, true),
            Some(format!(
                "gateway frame of {} bytes naming node.invoke, not read",
                big.len()
            ))
        );
        // A large frame that is not an invoke says nothing.
        let chat = format!(
            r#"{{"type":"event","event":"chat","payload":"{}"}}"#,
            "z".repeat(MAX_DESCRIBED)
        );
        assert_eq!(s.frame(&chat, true), None);
    }

    #[test]
    fn browser_and_other_commands() {
        let mut s = accepted();
        let open = r#"{"type":"event","event":"node.invoke.request","payload":{"id":"i2","nodeId":"n1","command":"browser.proxy","paramsJSON":"{\"method\":\"POST\",\"path\":\"/tabs/open\",\"body\":{\"url\":\"https://example.org\"}}"}}"#;
        assert_eq!(
            s.frame(open, true).as_deref(),
            Some("invoke i2 node=n1 browser.proxy POST /tabs/open https://example.org")
        );
        let no_ok = r#"{"type":"req","id":"3","method":"node.invoke.result","params":{"id":"i1"}}"#;
        assert_eq!(s.frame(no_ok, false).as_deref(), Some("result i1 ok=?"));
        assert_eq!(s.frame(r#"{"type":"event","event":"tick"}"#, true), None);
    }

    #[test]
    fn plain_ws_beyond_loopback_is_refused() {
        assert!(check_listen("0.0.0.0:18790", true, false).is_ok());
        assert!(check_listen("127.0.0.1:18790", false, false).is_ok());
        assert!(check_listen("[::ffff:127.0.0.1]:18790", false, false).is_ok());
        assert!(
            check_listen("0.0.0.0:18790", false, false).is_err(),
            "the token in clear"
        );
        assert!(check_listen("172.31.252.2:18790", false, true).is_ok());
    }

    #[test]
    fn the_gateway_is_never_loopback_and_private_unless_insecure() {
        for ip in [
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "::ffff:127.0.0.1",
            "0.0.0.0",
            "::",
            "::ffff:0.0.0.0",
        ] {
            let ip: IpAddr = ip.parse().expect("ip");
            assert!(gateway_ip_allowed(ip, true).is_err(), "{ip}");
        }
        for ip in [
            "10.77.0.2",
            "172.31.251.10",
            "192.168.1.5",
            "100.64.0.9",
            "169.254.1.1",
            "fd00::5",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = ip.parse().expect("ip");
            assert!(gateway_ip_allowed(ip, false).is_ok(), "{ip}");
        }
        let public: IpAddr = "78.47.18.86".parse().expect("ip");
        assert!(gateway_ip_allowed(public, false).is_err(), "the token in clear");
        assert!(gateway_ip_allowed(public, true).is_ok());
    }

    #[tokio::test]
    async fn a_name_or_short_form_that_resolves_to_loopback_is_refused() {
        for g in [
            "127.1:18789",
            "localhost:18789",
            "[::ffff:127.0.0.1]:18789",
            "0.0.0.0:18789",
            "0:18789",
        ] {
            assert!(
                matches!(resolve_gateway(g, true).await, Err(Gateway::Refused(_))),
                "{g}"
            );
        }
        assert_eq!(
            resolve_gateway("10.77.0.2:18789", false).await,
            Ok("10.77.0.2:18789".parse().expect("addr"))
        );
        assert!(matches!(
            resolve_gateway("no-such-gateway.invalid:18789", false).await,
            Err(Gateway::Unresolved(_))
        ));
    }

    #[test]
    fn the_node_cannot_state_its_address() {
        for h in [
            "x-forwarded-for",
            "forwarded",
            "x-real-ip",
            "x-forwarded-proto",
            "sec-websocket-key",
            "host",
        ] {
            assert!(!forwarded(h), "{h}");
        }
        for h in ["origin", "user-agent", "authorization"] {
            assert!(forwarded(h), "{h}");
        }
    }

    #[test]
    fn the_spec_is_two_addresses() {
        assert_eq!(
            parse("10.77.0.1:18790=10.77.0.2:18789"),
            Some(("10.77.0.1:18790".into(), "10.77.0.2:18789".into()))
        );
        assert_eq!(parse("10.77.0.1:18790"), None);
        assert_eq!(parse("10.77.0.1=10.77.0.2:18789"), None);
        assert_eq!(parse(":1=a:2"), None);
    }
}
