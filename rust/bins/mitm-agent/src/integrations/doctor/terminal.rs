//! Doctor's live terminal (`doctor-terminal.ts`): the session's coding agent in a terminal, over a
//! WebSocket, from an open intent in an enrolled browser. Each socket runs
//! `sudo -n -u ccdoctor /usr/local/bin/cc-doctor-attach <session> <cols> <rows>`; one socket a
//! session, a new one replaces the old one once that one's process is gone.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use cc_http::{Req, Resp};

use super::chat::{cookie_token, form_get, intent_session, notice, read_body, same_origin};
use super::firewall::DoctorFirewall;
use crate::app::App;

const COOKIE: &str = "__Secure-cc_doctor";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const OPEN_JS: &str = r#"const intent=new URLSearchParams(location.hash.slice(1)).get("i");history.replaceState(null,"",location.pathname);if(!intent){document.getElementById("status").textContent="Open the terminal from a running Doctor session."}else{const form=document.createElement("form");form.method="POST";form.action="/__cc/doctor/open";const input=document.createElement("input");input.type="hidden";input.name="intent";input.value=intent;form.append(input);document.body.append(form);form.submit()}"#;
const TERMINAL_HTML: &str = r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent Doctor terminal</title><link rel="stylesheet" href="/__cc/doctor/xterm.css"><style>body{margin:0;background:#121212;color:#eee;font:14px system-ui}header{padding:12px 16px;border-bottom:1px solid #444;display:flex;gap:16px;align-items:center}h1{font-size:16px;margin:0}#terminal{height:calc(100dvh - 100px);padding:8px}p{margin:0;padding:8px 16px;color:#aaa;font-size:12px}button{margin-left:auto;background:#333;color:#eee;border:1px solid #666;padding:5px 12px;border-radius:5px}</style></head><body><header><h1>Agent Doctor</h1><span id="status">Connecting…</span><button id="reconnect">Reconnect</button></header><p>Root access on your agent. Close this tab to detach. Stop the session from the console.</p><div id="terminal"></div><script src="/__cc/doctor/xterm.js"></script><script src="/__cc/doctor/fit.js"></script><script src="/__cc/doctor/terminal.js"></script></body></html>"##;
const TERMINAL_JS: &str = r##"const term=new Terminal({cursorBlink:true,convertEol:false,scrollback:3000,fontSize:14,theme:{background:"#121212"}});const fit=new FitAddon.FitAddon();term.loadAddon(fit);term.open(document.getElementById("terminal"));fit.fit();let socket;function connect(){if(socket)socket.close();socket=new WebSocket("wss://"+location.host+"/__cc/doctor/ws?cols="+term.cols+"&rows="+term.rows);socket.binaryType="arraybuffer";socket.onopen=()=>{document.getElementById("status").textContent="Connected";term.focus()};socket.onmessage=e=>term.write(new Uint8Array(e.data));socket.onclose=()=>document.getElementById("status").textContent="Detached";socket.onerror=()=>document.getElementById("status").textContent="Connection refused"}term.onData(data=>{if(socket&&socket.readyState===1)socket.send(JSON.stringify({type:"input",data}))});document.getElementById("reconnect").onclick=connect;window.addEventListener("resize",()=>{fit.fit();if(socket&&socket.readyState===1)socket.send(JSON.stringify({type:"resize",cols:Math.max(20,Math.min(300,term.cols)),rows:Math.max(5,Math.min(100,term.rows))}))});connect();"##;
const XTERM_JS: &str = include_str!("vendor/xterm.js");
const XTERM_CSS: &str = include_str!("vendor/xterm.css");
const FIT_JS: &str = include_str!("vendor/addon-fit.js");

/// The pages this serves under `/__cc/doctor` (the rest of it is other pages').
pub fn owns(path: &str) -> bool {
    matches!(
        path,
        "/__cc/doctor"
            | "/__cc/doctor/"
            | "/__cc/doctor/open"
            | "/__cc/doctor/open.js"
            | "/__cc/doctor/terminal.js"
            | "/__cc/doctor/xterm.js"
            | "/__cc/doctor/fit.js"
            | "/__cc/doctor/xterm.css"
    )
}

fn hash(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))
}

fn send(status: u16, kind: &str, text: String) -> Resp {
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        &format!("{kind}; charset=utf-8"),
        text,
    );
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    r
}

#[derive(Clone)]
struct Grant {
    session_id: String,
    vm_id: String,
    user_id: String,
    device_id: String,
    expires_at: i64,
}

/// What `cc-doctor-attach` is, for the tests: the program and its leading arguments.
pub type Attach = Arc<dyn Fn(&str, u32, u32) -> tokio::process::Command + Send + Sync>;

pub struct DoctorTerminal {
    app: Arc<App>,
    doctor: Arc<DoctorFirewall>,
    grants: Mutex<HashMap<String, Grant>>,
    /// The socket of each session: a new one stops the old one first.
    /// Per session: the socket's id, its stop, and whether its helper has exited.
    #[allow(clippy::type_complexity)]
    sockets: Mutex<
        HashMap<
            String,
            (
                u64,
                tokio::sync::watch::Sender<bool>,
                tokio::sync::watch::Receiver<bool>,
            ),
        >,
    >,
    attach: Attach,
    now: super::Clock,
}

impl DoctorTerminal {
    pub fn new(app: &Arc<App>, doctor: Arc<DoctorFirewall>, attach: Option<Attach>, now: super::Clock) -> Arc<Self> {
        let attach = attach.unwrap_or_else(|| {
            Arc::new(|id: &str, cols: u32, rows: u32| {
                let mut c = tokio::process::Command::new("sudo");
                c.args([
                    "-n",
                    "-u",
                    "ccdoctor",
                    "/usr/local/bin/cc-doctor-attach",
                    id,
                    &cols.to_string(),
                    &rows.to_string(),
                ])
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("TERM", "xterm-256color");
                c
            })
        });
        Arc::new(Self {
            app: app.clone(),
            doctor,
            grants: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            attach,
            now,
        })
    }

    fn refused(&self) -> Resp {
        let t = "Use an enrolled browser and open the terminal from a running Doctor session. To enroll this browser, open a working agent first.";
        send(
            403,
            "text/html",
            notice(&self.app, Some("Terminal unavailable"), t, None, None),
        )
    }

    fn grant(&self, headers: &HeaderMap) -> Option<Grant> {
        let token = cookie_token(headers, COOKIE)?;
        let g = self
            .grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash(&token))
            .cloned()?;
        let now = (self.now)();
        if g.expires_at <= now {
            return None;
        }
        let (vm, expires, _) = self.doctor.active(&g.session_id)?;
        if vm != g.vm_id || expires <= now {
            return None;
        }
        let access = self.app.contracts.page_access.get()?;
        access
            .device_active(headers, "doctor", &g.user_id, &g.device_id, Some(&g.vm_id))
            .then_some(g)
    }

    pub async fn handle(self: Arc<Self>, req: Req) -> Resp {
        let path = cc_http::pathname(&req.uri().to_string());
        let get = req.method() == Method::GET;
        if path == "/__cc/doctor/open" && get {
            return send(
                200,
                "text/html",
                notice(
                    &self.app,
                    None,
                    "Opening your Doctor terminal…",
                    Some("status"),
                    Some("/__cc/doctor/open.js"),
                ),
            );
        }
        if path == "/__cc/doctor/open.js" && get {
            return send(200, "text/javascript", OPEN_JS.into());
        }
        if path == "/__cc/doctor/open" && req.method() == Method::POST {
            if !same_origin(&self.app, req.headers()) {
                return send(403, "text/plain", String::new());
            }
            if !req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"))
            {
                return send(415, "text/plain", String::new());
            }
            let (parts, body) = req.into_parts();
            let Some(raw) = read_body(body, &parts.headers, 8192).await else {
                return send(500, "text/plain", String::new());
            };
            let Some(access) = self.app.contracts.page_access.get() else {
                return self.refused();
            };
            let person = access
                .authorize(&parts.headers, form_get(&raw, "intent"), "doctor")
                .await;
            // Root on the agent: an owner or admin only, checked by the access module and again here.
            let Some((p, (sid, vm))) = person
                .filter(|p| p.can_write)
                .and_then(|p| intent_session(&p).map(|x| (p, x)))
            else {
                return self.refused();
            };
            let now = (self.now)();
            let Some((avm, expires, _)) = self.doctor.active(&sid).filter(|(v, e, _)| *v == vm && *e > now) else {
                return self.refused();
            };
            if self.doctor.terminal(&sid).await.is_err() {
                return send(500, "text/plain", String::new());
            }
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
            {
                let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
                grants.retain(|_, g| g.expires_at > now && g.session_id != sid);
                grants.insert(
                    hash(&token),
                    Grant {
                        session_id: sid,
                        vm_id: avm,
                        user_id: p.user_id,
                        device_id: p.device_id,
                        expires_at: expires,
                    },
                );
            }
            let mut r = send(303, "text/plain", String::new());
            r.headers_mut().remove(http::header::CONTENT_TYPE);
            r.headers_mut()
                .insert(http::header::LOCATION, HeaderValue::from_static("/__cc/doctor/"));
            let cookie = format!(
                "{COOKIE}={token}; Path=/__cc/doctor; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                ((expires - now) / 1000).max(1)
            );
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert(http::header::SET_COOKIE, v);
            }
            return r;
        }
        if !get {
            return send(405, "text/plain", String::new());
        }
        if self.grant(req.headers()).is_none() {
            return self.refused();
        }
        match path.as_str() {
            "/__cc/doctor" | "/__cc/doctor/" => send(200, "text/html", TERMINAL_HTML.into()),
            "/__cc/doctor/terminal.js" => send(200, "text/javascript", TERMINAL_JS.into()),
            "/__cc/doctor/xterm.js" => send(200, "text/javascript", XTERM_JS.into()),
            "/__cc/doctor/fit.js" => send(200, "text/javascript", FIT_JS.into()),
            "/__cc/doctor/xterm.css" => send(200, "text/css", XTERM_CSS.into()),
            _ => send(404, "text/plain", String::new()),
        }
    }

    /// `/__cc/doctor/ws`: the socket, after the same checks, while the session runs as a terminal.
    pub async fn upgrade(self: Arc<Self>, mut req: Req) -> Resp {
        let fail = || {
            let mut r = cc_http::empty(403);
            r.headers_mut()
                .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
            r.headers_mut()
                .insert(http::header::CONTENT_LENGTH, HeaderValue::from(0));
            r
        };
        let path = cc_http::pathname(&req.uri().to_string());
        if path != "/__cc/doctor/ws" || !same_origin(&self.app, req.headers()) {
            return fail();
        }
        let Some(grant) = self.grant(req.headers()) else {
            return fail();
        };
        if self
            .doctor
            .active(&grant.session_id)
            .is_some_and(|(_, _, mode)| mode == "chat")
        {
            return fail();
        }
        let q = |k: &str| {
            url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| v.parse::<f64>().ok())
                .filter(|v| *v != 0.0 && v.is_finite())
        };
        let cols = q("cols").unwrap_or(100.0).clamp(20.0, 300.0).floor() as u32;
        let rows = q("rows").unwrap_or(30.0).clamp(5.0, 100.0).floor() as u32;
        let Some(key) = req
            .headers()
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
        else {
            return fail();
        };
        let headers = req.headers().clone();
        let on = hyper::upgrade::on(&mut req);
        let me = self.clone();
        tokio::spawn(async move {
            let Ok(up) = on.await else { return };
            let mut cfg = WebSocketConfig::default();
            cfg.max_message_size = Some(16 * 1024);
            cfg.max_frame_size = Some(16 * 1024);
            let ws =
                tokio_tungstenite::WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, Some(cfg)).await;
            me.attach(ws, headers, grant, cols, rows).await;
        });
        let mut r = http::Response::new(http_body_util::BodyExt::boxed(http_body_util::BodyExt::map_err(
            http_body_util::Empty::<bytes::Bytes>::new(),
            |never| match never {},
        )));
        *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let h = r.headers_mut();
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(http::header::CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Ok(v) = HeaderValue::from_str(&tokio_tungstenite::tungstenite::handshake::derive_accept_key(
            key.as_bytes(),
        )) {
            h.insert("sec-websocket-accept", v);
        }
        r
    }

    async fn attach<S>(
        self: Arc<Self>,
        ws: tokio_tungstenite::WebSocketStream<S>,
        headers: HeaderMap,
        grant: Grant,
        cols: u32,
        rows: u32,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Reserve this slot first: rapid reconnects replace pending sockets too.
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        // Says this one's helper is gone however the attachment ends.
        struct Done(tokio::sync::watch::Sender<bool>);
        impl Drop for Done {
            fn drop(&mut self) {
                let _ = self.0.send(true);
            }
        }
        let _done = Done(done_tx);
        let mine: u64 = rand::random();
        let previous = self
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(grant.session_id.clone(), (mine, stop_tx, done_rx));
        if let Some((_, p, mut previous_done)) = previous {
            let _ = p.send(true);
            // The helper reaps its process tree on EOF/TERM; the next one waits until it has.
            let _ = previous_done.wait_for(|d| *d).await;
        }
        let (mut tx, mut rx) = ws.split();
        let ok = |me: &Self| {
            me.grant(&headers).is_some() && me.doctor.active(&grant.session_id).is_some_and(|(_, _, m)| m != "chat")
        };
        if *stop_rx.borrow() || !ok(&self) || !self.doctor.touch(&grant.session_id) {
            let _ = tx.close().await;
            return;
        }
        let mut cmd = (self.attach)(&grant.session_id, cols, rows);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let Ok(mut child) = cmd.spawn() else {
            let _ = tx.close().await;
            return;
        };
        let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return;
        };
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let o2 = out_tx.clone();
        tokio::spawn(async move {
            let mut b = vec![0u8; 16 * 1024];
            while let Ok(n) = stdout.read(&mut b).await {
                if n == 0 || out_tx.send(b[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let mut b = vec![0u8; 16 * 1024];
            while let Ok(n) = stderr.read(&mut b).await {
                if n == 0 || o2.send(b[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        let mut check = tokio::time::interval(Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                _ = check.tick() => if !ok(&self) { break },
                out = out_rx.recv() => match out {
                    None => break,
                    // A browser that stops reading is detached, as the TS does past 1 MiB buffered:
                    // the loop must keep seeing a stop and the grant check.
                    Some(chunk) => if !matches!(tokio::time::timeout(STALLED, tx.send(Message::binary(chunk))).await, Ok(Ok(()))) { break },
                },
                msg = rx.next() => {
                    let Some(Ok(msg)) = msg else { break };
                    if !ok(&self) || !self.doctor.touch(&grant.session_id) { break }
                    let text = match msg {
                        Message::Text(t) => t.to_string(),
                        Message::Ping(_) | Message::Pong(_) => continue,
                        _ => break,
                    };
                    let Ok(v) = serde_json::from_str::<Value>(&text) else { break };
                    if !valid(&v) { break }
                    let line = format!("{}\n", crate::integrations::js::stringify(&v));
                    if !matches!(tokio::time::timeout(STALLED, stdin.write_all(line.as_bytes())).await, Ok(Ok(()))) { break }
                },
            }
        }
        let _ = tx.close().await;
        // `reapAttachment`: no more output is taken, stdin ends, SIGTERM to sudo (which passes it
        // on), SIGKILL after 3 s.
        drop(out_rx);
        drop(stdin);
        super::runner::terminate(&mut child, Duration::from_secs(3)).await;
        let mut socks = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        if socks.get(&grant.session_id).is_some_and(|(id, _, _)| *id == mine) {
            socks.remove(&grant.session_id);
        }
    }
}

/// How long a write to the browser or to the helper may wait before the attachment is dropped.
const STALLED: Duration = Duration::from_secs(5);

/// `input` of at most 8192 characters, or a `resize` within the terminal's bounds.
fn valid(v: &Value) -> bool {
    match v.get("type").and_then(Value::as_str) {
        Some("input") => v
            .get("data")
            .and_then(Value::as_str)
            .is_some_and(|d| d.encode_utf16().count() <= 8192),
        Some("resize") => {
            // `Number.isInteger`: `5.0` is an integer too.
            let n = |k: &str| {
                v.get(k)
                    .and_then(Value::as_f64)
                    .filter(|f| f.fract() == 0.0)
                    .map(|f| f as i64)
            };
            n("cols").is_some_and(|c| (20..=300).contains(&c)) && n("rows").is_some_and(|r| (5..=100).contains(&r))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
