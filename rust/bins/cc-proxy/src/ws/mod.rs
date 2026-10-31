//! Intercepted websockets. Owner: W1.
//!
//! An HTTP/1.1 upgrade is a flow like any request: its destination is checked, the request
//! pipeline runs (rules, the windows, the checks), and only then is the site dialled, on a
//! connection of its own. Every extension is taken out of the agent's offer (`permessage-deflate`
//! and any other), so the site turns none on and every frame arrives as plain text or bytes (plan
//! §2.3, owner decision 8). Frames and messages are capped at 4 MiB. The
//! site's 101 runs the response steps (the record, as mitmproxy writes one for the handshake) and
//! then `WsStart`.
//!
//! Then one pump per direction. Each frame is put on the flow (`flow.ws_frame`) and `WsFrame` runs:
//! `Continue` sends the frame on, rewritten if a step changed it; `Drop` leaves it out; `Kill`
//! closes both sides. Frames a step puts in `flow.inject` go out after it, in order, each to the
//! side its direction names (addon `inject.websocket`). A pump that is awaiting a step reads
//! nothing more from its side: that side is paused while the check runs, and frames keep their
//! order. The two directions share the flow behind one lock, held only while a frame's steps run,
//! so a step that holds for long holds the other direction's frames too. `WsEnd` runs once, when
//! either side closes.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use http::header::{self, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::flow::{Direction, Flow, FrameKind, Hook, Verdict, WsFrame};
use crate::http::buffered::Buffered;
use crate::http::upstream::UpstreamError;
use crate::http::{self as px, ClientBody, Conn, Killed, Mode, check_destination, to_client, to_origin_h1};

type Ws = WebSocketStream<TokioIo<Upgraded>>;
type Sink = Arc<Mutex<SplitSink<Ws, Message>>>;

fn boxed(r: Response<Bytes>, version: http::Version) -> Response<ClientBody> {
    to_client(r, version, false).map(|b| b.map_err(|never| match never {}).boxed())
}

/// The agent's offer with no extension at all: the frame steps must see every frame as plain
/// text or bytes, and an extension the proxy does not speak (`permessage-deflate` or any other)
/// would change what the frames mean (plan §2.3, owner decision 8).
pub fn strip_extensions(headers: &mut http::HeaderMap) {
    headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);
}

/// The largest frame and message either side may send through: a voice audio frame is up to
/// 512 KB, so a few MiB leaves room without letting one frame take the firewall's memory.
const MAX_WS_MESSAGE: usize = 4 << 20;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE))
}

/// How long closing one side may take before it is dropped: an agent that stops reading must not
/// keep the site's socket and the task alive.
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// One websocket upgrade, start to finish. As `exchange_buffered` sends a request, but on a
/// connection of its own whose upgrade is taken over when the site answers 101.
pub async fn exchange(conn: Arc<Conn>, mut req: Request<Incoming>) -> Result<Response<ClientBody>, Killed> {
    let version = req.version();
    let client_upgrade = hyper::upgrade::on(&mut req);
    let (mut parts, _) = req.into_parts();
    strip_extensions(&mut parts.headers);
    let mut flow = conn.new_flow();
    let mut head = Request::new(Bytes::new());
    *head.method_mut() = parts.method.clone();
    *head.uri_mut() = parts.uri.clone();
    *head.version_mut() = parts.version;
    *head.headers_mut() = parts.headers.clone();
    flow.request = Some(head);
    if conn.mode == Mode::Absolute {
        flow.meta.insert("absolute_form", serde_json::Value::Bool(true));
    }
    match check_destination(&conn, &flow).await {
        Ok(d) => flow.set_destination(d),
        Err(early) => return Ok(boxed(early.into_response(&conn, &mut flow), version)),
    }

    let shared = conn.shared.clone();
    let control_plane = px::mark_control_plane(&conn, &mut flow);
    if !control_plane && !shared.checks_present {
        return Ok(boxed(px::refuse_unchecked(&conn, &mut flow), version));
    }
    let before = px::RequestShape::before(&conn, &flow, control_plane);
    match run(&shared, Hook::Request, &mut flow).await {
        Verdict::Continue | Verdict::Forward => {}
        Verdict::Answer(resp) => {
            flow.response = Some(*resp);
            return client(px::respond(&conn, flow, version, false).await);
        }
        Verdict::Drop | Verdict::Kill(_) => return client(px::kill(&conn, flow, "Connection killed.").await),
    }

    // The request and destination as the steps left them, to the site.
    let Some(d) = flow.destination().cloned() else {
        return client(px::kill(&conn, flow, "no destination").await);
    };
    let tls = conn.mode == Mode::Tls || parts.uri.scheme_str() == Some("https");
    let mut up = flow.request.clone().unwrap_or_default();
    let authority = px::authority_of_head(up.headers(), up.uri(), &d);
    // `to_origin_h1` takes the connection headers out; the upgrade needs its own two back.
    to_origin_h1(&mut up, &authority);
    up.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    up.headers_mut()
        .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    let up = up.map(|b| Buffered::new(b, None));
    let dialled = if let Some(exit) = crate::residential::take_exit(&mut flow) {
        // Out through the residential exit, never from this box, as a plain request goes.
        crate::residential::upgrade_http(&shared.ctx, &exit, up, &d.name, d.port, tls).await
    } else {
        // Only an upgrade no step changed (no credential put in) may use a static-RSA suite.
        match conn
            .pool
            .upgrade(&d, tls, up, px::RequestShape::unchanged(before, &flow))
            .await
        {
            Ok(r) => Ok(r),
            Err(UpstreamError::Refused(why)) => Err(px::record_refused(&conn, &flow, &d, &why)),
            Err(UpstreamError::Failed(msg)) => Err(msg),
        }
    };
    let mut site = match dialled {
        Ok(r) => r,
        Err(msg) => return client(px::failed(&conn, flow, msg, version, false).await),
    };
    let site_upgrade = hyper::upgrade::on(&mut site);
    let (site_parts, site_body) = site.into_parts();
    if site_parts.status != StatusCode::SWITCHING_PROTOCOLS {
        // Not upgraded: an ordinary answer, through the response steps.
        let body = match http_body_util::Limited::new(site_body, px::MAX_BODY).collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => return client(px::failed(&conn, flow, format!("site body: {e}"), version, false).await),
        };
        flow.response = Some(Response::from_parts(site_parts, body));
        return client(px::respond(&conn, flow, version, false).await);
    }
    flow.response = Some(Response::from_parts(site_parts, Bytes::new()));
    match run(&shared, Hook::Response, &mut flow).await {
        Verdict::Continue | Verdict::Forward => {}
        // A step answered in the site's place: the agent gets that, and the upgrade is let go.
        // As `respond` does for plain HTTP: the response steps are not run again on it (the step
        // that answers writes its own record).
        Verdict::Answer(resp) => return Ok(boxed(*resp, version)),
        Verdict::Drop | Verdict::Kill(_) => return client(px::kill(&conn, flow, "Connection killed.").await),
    }
    if control_plane {
        // No step runs for it: its record (the handshake's 101).
        px::record_builtin(&conn, &mut flow, Some(StatusCode::SWITCHING_PROTOCOLS), None);
    }
    if let Verdict::Kill(_) | Verdict::Drop = run(&shared, Hook::WsStart, &mut flow).await {
        return client(px::kill(&conn, flow, "Connection killed.").await);
    }

    // The 101 to the agent: the handshake answer as the steps left it (a step may rewrite
    // `sec-websocket-protocol`), never with an extension the agent was not offered.
    let mut answer = Response::new(Buffered::empty());
    *answer.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    if let Some(r) = flow.response.as_ref() {
        *answer.headers_mut() = r.headers().clone();
    }
    answer.headers_mut().remove(header::SEC_WEBSOCKET_EXTENSIONS);
    let flow = Arc::new(Mutex::new(flow));
    let shared2 = shared.clone();
    tokio::spawn(async move {
        let (agent, site) = match (client_upgrade.await, site_upgrade.await) {
            (Ok(a), Ok(s)) => (a, s),
            _ => {
                end(&shared2, &flow).await;
                return;
            }
        };
        let agent = WebSocketStream::from_raw_socket(TokioIo::new(agent), Role::Server, Some(ws_config())).await;
        let site = WebSocketStream::from_raw_socket(TokioIo::new(site), Role::Client, Some(ws_config())).await;
        pump_both(shared2, flow, agent, site).await;
    });
    Ok(answer.map(|b| b.map_err(|never| match never {}).boxed()))
}

/// `exchange_buffered`'s reply, for the agent.
fn client(r: px::Reply) -> Result<Response<ClientBody>, Killed> {
    r.map(|r| r.map(|b| b.map_err(|never| match never {}).boxed()))
}

/// Whether the steps apply to this flow: not the control plane (as `respond` and `kill` skip it).
fn checked(flow: &Flow) -> bool {
    !flow.meta.contains_key("control_plane")
}

/// One hook's steps, none for the control plane.
async fn run(shared: &crate::net::Shared, hook: Hook, flow: &mut Flow) -> Verdict {
    if !checked(flow) {
        return Verdict::Continue;
    }
    shared.pipeline.run(hook, flow).await
}

async fn end(shared: &crate::net::Shared, flow: &Arc<Mutex<Flow>>) {
    let mut f = flow.lock().await;
    run(shared, Hook::WsEnd, &mut f).await;
    // The record a step left for the socket's end (a gpt-live call's billed seconds): the base
    // fields, then the step's own, as addon.py `_base_record(flow) | {...}`.
    match f.meta.remove(crate::flow::META_WS_END_RECORD) {
        None => {}
        Some(serde_json::Value::Object(fields)) => {
            let mut rec = serde_json::json!({
                "flow_id": f.id,
                "ts": crate::log::now(),
                "tenant": shared.ctx.config.tenant,
                "vm_id": f.vm_id,
            });
            if let Some(o) = rec.as_object_mut() {
                o.extend(fields);
                // `_log`: `rule_id` on every record with an effect.
                if o.contains_key("effect") {
                    o.entry("rule_id").or_insert(serde_json::Value::Null);
                }
            }
            shared.ctx.log.append_value(&rec);
        }
        Some(_) => tracing::warn!("[proxy] a websocket's end record is not an object; not written"),
    }
}

fn kind_of(m: &Message) -> Option<(FrameKind, Bytes)> {
    Some(match m {
        Message::Text(t) => (FrameKind::Text, Bytes::from(t.clone())),
        Message::Binary(b) => (FrameKind::Binary, b.clone()),
        Message::Ping(b) => (FrameKind::Ping, b.clone()),
        Message::Pong(b) => (FrameKind::Pong, b.clone()),
        Message::Close(c) => (
            FrameKind::Close,
            c.as_ref()
                .map(|c| {
                    let mut v = u16::from(c.code).to_be_bytes().to_vec();
                    v.extend_from_slice(c.reason.as_bytes());
                    Bytes::from(v)
                })
                .unwrap_or_default(),
        ),
        Message::Frame(_) => return None,
    })
}

/// A frame as a message to send. Text that is not UTF-8 any more (a step wrote bytes) goes as
/// binary rather than being refused.
fn message_of(f: &WsFrame) -> Message {
    match f.kind {
        FrameKind::Text => match Utf8Bytes::try_from(f.payload.clone()) {
            Ok(t) => Message::Text(t),
            Err(_) => Message::Binary(f.payload.clone()),
        },
        FrameKind::Binary => Message::Binary(f.payload.clone()),
        FrameKind::Ping => Message::Ping(f.payload.clone()),
        FrameKind::Pong => Message::Pong(f.payload.clone()),
        FrameKind::Close => {
            if f.payload.len() >= 2 {
                let code = u16::from_be_bytes([f.payload[0], f.payload[1]]);
                let reason = String::from_utf8_lossy(&f.payload[2..]).into_owned();
                Message::Close(Some(CloseFrame {
                    code: code.into(),
                    reason: reason.into(),
                }))
            } else {
                Message::Close(None)
            }
        }
    }
}

async fn pump_both(shared: Arc<crate::net::Shared>, flow: Arc<Mutex<Flow>>, agent: Ws, site: Ws) {
    let (agent_tx, agent_rx) = agent.split();
    let (site_tx, site_rx) = site.split();
    let agent_tx: Sink = Arc::new(Mutex::new(agent_tx));
    let site_tx: Sink = Arc::new(Mutex::new(site_tx));
    let out = pump(
        shared.clone(),
        flow.clone(),
        agent_rx,
        Direction::Out,
        site_tx.clone(),
        agent_tx.clone(),
    );
    let inn = pump(
        shared.clone(),
        flow.clone(),
        site_rx,
        Direction::In,
        agent_tx.clone(),
        site_tx.clone(),
    );
    // A step that watches the socket from outside its frames (a voice lease that ended while
    // the socket is quiet, addon.py `_voice_watch`): closed when its signal turns true.
    let signals = {
        let f = flow.lock().await;
        if checked(&f) {
            shared.pipeline.closing(&f)
        } else {
            Vec::new()
        }
    };
    let closing = async move {
        if signals.is_empty() {
            return std::future::pending::<()>().await;
        }
        let waits = signals.into_iter().map(|mut rx| {
            Box::pin(async move {
                // A dropped sender (the step let go of the socket) is not a reason to close.
                if rx.wait_for(|v| *v).await.is_err() {
                    std::future::pending::<()>().await;
                }
            })
        });
        futures_util::future::select_all(waits).await;
    };
    // When either side ends, a step kills the flow, or a watching step says so, both close.
    let killed = tokio::select! {
        _ = out => false,
        _ = inn => false,
        () = closing => true,
    };
    // A short wait for each close, then both are dropped whatever the peer does. A socket a step
    // closed from outside is dropped with no close handshake, as `flow.kill()` drops it: the
    // agent can tell a lease that ended from a call that finished.
    if !killed {
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, async { agent_tx.lock().await.close().await }).await;
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, async { site_tx.lock().await.close().await }).await;
    }
    drop((agent_tx, site_tx));
    end(&shared, &flow).await;
}

/// Read frames from one side and send them to the other, through the frame steps. `to` is the
/// side this direction writes to, `back` the one it came from (for frames injected the other way).
async fn pump(
    shared: Arc<crate::net::Shared>,
    flow: Arc<Mutex<Flow>>,
    mut from: SplitStream<Ws>,
    direction: Direction,
    to: Sink,
    back: Sink,
) {
    while let Some(Ok(msg)) = from.next().await {
        let Some((kind, payload)) = kind_of(&msg) else { continue };
        let closing = kind == FrameKind::Close;
        let (verdict, frame, inject) = {
            let mut f = flow.lock().await;
            f.ws_frame = Some(WsFrame {
                direction,
                kind,
                payload,
            });
            f.inject.clear();
            let v = run(&shared, Hook::WsFrame, &mut f).await;
            (v, f.ws_frame.take(), std::mem::take(&mut f.inject))
        };
        match verdict {
            Verdict::Kill(_) => return,
            Verdict::Drop => {}
            _ => {
                if let Some(frame) = frame
                    && to.lock().await.send(message_of(&frame)).await.is_err()
                {
                    return;
                }
            }
        }
        for extra in inject {
            let sink = if extra.direction == direction { &to } else { &back };
            if sink.lock().await.send(message_of(&extra)).await.is_err() {
                return;
            }
        }
        if closing {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Pipeline, Step, StepFuture, order};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Rewrites `secret` to `[removed]`, drops `drop-me`, and answers `ping-me` with an injected
    /// `ack` back to the agent before the frame goes on.
    struct Policy;

    impl Step for Policy {
        fn name(&self) -> &'static str {
            "test_ws_policy"
        }
        fn hooks(&self) -> &'static [Hook] {
            &[Hook::WsFrame]
        }
        fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
            Box::pin(async move {
                let Some(f) = flow.ws_frame.as_mut() else {
                    return Verdict::Continue;
                };
                if f.direction != Direction::Out {
                    return Verdict::Continue;
                }
                match &f.payload[..] {
                    b"drop-me" => Verdict::Drop,
                    b"secret" => {
                        f.payload = Bytes::from_static(b"[removed]");
                        Verdict::Continue
                    }
                    b"ping-me" => {
                        flow.inject.push(WsFrame {
                            direction: Direction::In,
                            kind: FrameKind::Text,
                            payload: Bytes::from_static(b"ack"),
                        });
                        Verdict::Continue
                    }
                    _ => Verdict::Continue,
                }
            })
        }
    }

    fn own_ip() -> Option<std::net::IpAddr> {
        let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        s.connect("192.0.2.1:9").ok()?;
        Some(s.local_addr().ok()?.ip()).filter(|ip| !ip.is_loopback())
    }

    /// A site that echoes every text frame, on this machine's own address.
    async fn echo_site(ip: std::net::IpAddr) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
        let site = tokio::net::TcpListener::bind((ip, 0)).await?;
        let site_addr = site.local_addr()?;
        tokio::spawn(async move {
            while let Ok((s, _)) = site.accept().await {
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else {
                        return;
                    };
                    while let Some(Ok(m)) = ws.next().await {
                        if m.is_text() && ws.send(m).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Ok(site_addr)
    }

    /// The proxy with `pipeline`, `ws.test` resolving to `site`; returns its address and its log.
    async fn proxy_for(
        site: std::net::SocketAddr,
        pipeline: Pipeline,
        name: &str,
    ) -> Result<(std::net::SocketAddr, std::path::PathBuf), Box<dyn std::error::Error>> {
        // An empty rules file: read, so nothing is refused for want of rules.
        let dir = std::env::temp_dir().join(format!("cc-proxy-ws-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("rules.json"), "[]")?;
        let vars: HashMap<String, String> = [
            ("MITM_RULES_PATH", dir.join("rules.json").display().to_string()),
            ("MITM_LOG_FILE", dir.join("traffic.jsonl").display().to_string()),
            ("MITM_DEV_RESOLVE", format!("ws.test={site}")),
            ("MITM_DEV_WITHOUT_CHECKS", "1".into()),
            ("MITM_ALLOW_DEV_FLAGS", "1".into()),
            ("MITM_CA_DIR", "/nonexistent".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let config = crate::config::Config::from_vars("127.0.0.1:0".parse()?, &vars)?;
        let shared = Arc::new(crate::net::Shared::new(config, pipeline));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy.local_addr()?;
        tokio::spawn(crate::net::serve(proxy, shared));
        Ok((proxy_addr, dir.join("traffic.jsonl")))
    }

    /// The agent: CONNECT (as redsocks sends it), then a plain websocket to `ws.test` inside.
    async fn agent_ws(
        proxy: std::net::SocketAddr,
    ) -> Result<WebSocketStream<tokio::net::TcpStream>, Box<dyn std::error::Error>> {
        let mut s = tokio::net::TcpStream::connect(proxy).await?;
        // An address redsocks might give; the request's Host is what is dialled.
        s.write_all(b"CONNECT 198.51.100.77:80 HTTP/1.1\r\n\r\n").await?;
        let mut head = [0u8; 39];
        s.read_exact(&mut head).await?;
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let (ws, resp) = tokio_tungstenite::client_async("ws://ws.test/x", s).await?;
        assert_eq!(resp.status(), 101);
        Ok(ws)
    }

    #[tokio::test]
    async fn frame_steps_rewrite_drop_and_inject() -> Result<(), Box<dyn std::error::Error>> {
        let Some(ip) = own_ip() else {
            eprintln!("skipped: no non-loopback address");
            return Ok(());
        };
        let site = echo_site(ip).await?;
        let mut pipeline = Pipeline::new();
        pipeline.push(order::WEB_CONTENT_RULES, Arc::new(Policy));
        let (proxy, _) = proxy_for(site, pipeline, "frames").await?;
        let mut ws = agent_ws(proxy).await?;
        for m in ["hello", "secret", "drop-me", "ping-me", "last"] {
            ws.send(Message::text(m)).await?;
        }
        let mut got = Vec::new();
        while got.len() < 5 {
            let m = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                .await?
                .ok_or("closed")??;
            got.push(m.into_text()?.to_string());
        }
        // `drop-me` never reached the site, and the echoes keep their order. The ack goes the other
        // way, right after `ping-me` is sent on, so it reaches the agent before that echo can
        // (where it falls among the earlier echoes is up to the site).
        let ack = got.iter().position(|m| m == "ack");
        let ping = got.iter().position(|m| m == "ping-me");
        assert!(ack.is_some() && ack < ping, "{got:?}");
        got.retain(|m| m != "ack");
        assert_eq!(got, ["hello", "[removed]", "ping-me", "last"]);
        Ok(())
    }

    /// A step that watches the socket from outside its frames (as W2's voice lease watcher does)
    /// and leaves an end record.
    struct Watcher(tokio::sync::watch::Sender<bool>);

    impl Step for Watcher {
        fn name(&self) -> &'static str {
            "test_ws_watcher"
        }
        fn hooks(&self) -> &'static [Hook] {
            &[Hook::WsEnd]
        }
        fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
            Box::pin(async move {
                flow.meta.insert(
                    crate::flow::META_WS_END_RECORD,
                    serde_json::json!({"flow_id": format!("{}:end", flow.id), "effect": "allow",
                                       "rule": "meeting_voice: m 3 s billed"}),
                );
                Verdict::Continue
            })
        }
        fn closing(&self, _: &Flow) -> Option<tokio::sync::watch::Receiver<bool>> {
            Some(self.0.subscribe())
        }
    }

    #[tokio::test]
    async fn a_quiet_socket_closes_when_a_step_says_and_its_end_record_is_written()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(ip) = own_ip() else {
            eprintln!("skipped: no non-loopback address");
            return Ok(());
        };
        let site = echo_site(ip).await?;
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut pipeline = Pipeline::new();
        pipeline.push(order::WEB_CONTENT_RULES, Arc::new(Watcher(tx.clone())));
        let (proxy, log) = proxy_for(site, pipeline, "watch").await?;
        let mut ws = agent_ws(proxy).await?;
        ws.send(Message::text("hi")).await?;
        let echo = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await?
            .ok_or("closed")??;
        assert_eq!(echo.into_text()?.as_str(), "hi");
        // The socket is quiet; the step's signal turns true: both sides close, no frame needed.
        tx.send_replace(true);
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await?;
        assert!(
            matches!(next, None | Some(Ok(Message::Close(_))) | Some(Err(_))),
            "{next:?}"
        );
        // The end record: the base fields, then the step's.
        let mut rec = None;
        for _ in 0..50 {
            rec = std::fs::read_to_string(&log)
                .ok()
                .and_then(|t| t.lines().find(|l| l.contains("s billed")).map(str::to_owned));
            if rec.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let rec: serde_json::Value = serde_json::from_str(&rec.ok_or("no end record")?)?;
        assert_eq!(rec["rule"], "meeting_voice: m 3 s billed");
        assert!(rec["flow_id"].as_str().is_some_and(|f| f.ends_with(":end")));
        assert!(rec["ts"].is_number() && rec.get("vm_id").is_some() && rec["rule_id"].is_null());
        Ok(())
    }

    #[test]
    fn no_extension_is_ever_offered() {
        let mut h = http::HeaderMap::new();
        h.insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate; client_max_window_bits, x-other"),
        );
        h.append(header::SEC_WEBSOCKET_EXTENSIONS, HeaderValue::from_static("x-more"));
        strip_extensions(&mut h);
        assert!(h.get(header::SEC_WEBSOCKET_EXTENSIONS).is_none());
    }

    #[test]
    fn frames_round_trip_as_messages() {
        let close = message_of(&WsFrame {
            direction: Direction::In,
            kind: FrameKind::Close,
            payload: Bytes::from_static(b"\x03\xe8bye"),
        });
        let (k, p) = kind_of(&close).unwrap_or((FrameKind::Text, Bytes::new()));
        assert_eq!(k, FrameKind::Close);
        assert_eq!(&p[..], b"\x03\xe8bye");
        let bad_text = message_of(&WsFrame {
            direction: Direction::Out,
            kind: FrameKind::Text,
            payload: Bytes::from_static(b"\xff"),
        });
        assert!(matches!(bad_text, Message::Binary(_)));
    }
}
