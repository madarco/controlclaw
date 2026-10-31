//! The loopback listener a tool-only Doctor session talks to (`loopback-tools.ts`): Firewall
//! Doctor's repair commands (`fw_tools.rs`) and a Final check's reads (`tplcheck`). The coding agent
//! runs as `ccdoctor` with no privilege; its client posts `{ verb, arg?, extra? }` to `/run` with the
//! session's own token, and this daemon decides what runs. One command at a time, only while the
//! session is active, and no browser can reach it (an Origin header is refused).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use cc_http::{BoxFuture, Resp};

use super::firewall::SessionTools;
use crate::integrations::js;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAnswer {
    pub ok: bool,
    pub text: String,
}

impl ToolAnswer {
    pub fn new(ok: bool, text: impl Into<String>) -> Self {
        Self { ok, text: text.into() }
    }
}

/// `run(verb, arg, extra)`.
pub type RunFn = Arc<dyn Fn(String, Option<String>, Option<String>) -> BoxFuture<ToolAnswer> + Send + Sync>;

pub struct Options {
    /// Whether the session this listener belongs to may still act.
    pub active: Arc<dyn Fn() -> bool + Send + Sync>,
    pub run: RunFn,
    /// What a call with no verb is answered with.
    pub help: String,
    /// What a refused call is told the session is (default `repair`).
    pub what: Option<&'static str>,
    /// How long an argument may be (default 40).
    pub arg_max: Option<usize>,
}

const MAX_BODY: usize = 4096;
const HEADERS_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

pub struct LoopbackTools {
    token: String,
    opts: Options,
    busy: AtomicBool,
    closed: AtomicBool,
    cancel: CancellationToken,
    socket: Mutex<Option<std::path::PathBuf>>,
}

fn digest(v: &str) -> [u8; 32] {
    Sha256::digest(v.as_bytes()).into()
}

fn reply(status: u16, ok: bool, text: &str) -> Resp {
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        "application/json",
        js::stringify(&json!({"ok": ok, "text": text})),
    );
    r.headers_mut()
        .insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The length JavaScript gives a string.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

impl LoopbackTools {
    pub fn new(opts: Options) -> Arc<Self> {
        Arc::new(Self {
            token: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
            opts,
            busy: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            socket: Mutex::new(None),
        })
    }

    async fn listen(self: Arc<Self>, socket: Option<String>) -> Result<String, String> {
        if self.closed.load(Ordering::SeqCst) {
            return Err("Session tools closed.".into());
        }
        let refused = || "Session tools could not listen.".to_string();
        let me = self.clone();
        let handler = move |req: http::Request<Incoming>| {
            let me = me.clone();
            async move { Ok::<_, std::convert::Infallible>(me.handle(req).await) }
        };
        let cancel = self.cancel.clone();
        match socket {
            // For a session whose unit has no network of its own (a Final check): its folder is the
            // session's, and the socket is readable and writable by the folder's group, `ccdoctor`.
            Some(path) => {
                // Bound and recorded under the lock `shut` takes, after checking it has not run: a
                // close at the same moment either comes first (nothing is bound) or removes the file.
                let l = {
                    let mut socket = self.socket.lock().unwrap_or_else(|e| e.into_inner());
                    if self.closed.load(Ordering::SeqCst) {
                        return Err("Session tools closed.".into());
                    }
                    let _ = std::fs::remove_file(&path);
                    let l = tokio::net::UnixListener::bind(&path).map_err(|_| refused())?;
                    *socket = Some(path.clone().into());
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).map_err(|_| refused())?;
                    l
                };
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            a = l.accept() => match a {
                                Ok((s, _)) => serve(s, handler.clone(), cancel.clone()),
                                // Out of descriptors, say: wait rather than spin.
                                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                            },
                        }
                    }
                });
                Ok(path)
            }
            None => {
                let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|_| refused())?;
                let port = l.local_addr().map_err(|_| refused())?.port();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            a = l.accept() => match a {
                                Ok((s, _)) => serve(s, handler.clone(), cancel.clone()),
                                // Out of descriptors, say: wait rather than spin.
                                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                            },
                        }
                    }
                });
                Ok(format!("http://127.0.0.1:{port}"))
            }
        }
    }

    fn shut(&self) {
        let mut socket = self.socket.lock().unwrap_or_else(|e| e.into_inner());
        self.closed.store(true, Ordering::SeqCst);
        self.cancel.cancel();
        if let Some(p) = socket.take() {
            let _ = std::fs::remove_file(p);
        }
    }

    async fn handle(self: Arc<Self>, req: http::Request<Incoming>) -> Resp {
        let (parts, body) = req.into_parts();
        let token = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| a.strip_prefix("Bearer "))
            .unwrap_or("");
        if token.is_empty()
            || !cc_crypto::ct_eq(&digest(token), &digest(&self.token))
            || self.closed.load(Ordering::SeqCst)
            || !(self.opts.active)()
        {
            let what = self.opts.what.unwrap_or("repair");
            return reply(403, false, &format!("This {what} session is no longer active."));
        }
        // `new URL(req.url, "http://localhost").pathname`: dot segments resolved, as Node does.
        let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let path = url::Url::parse("http://localhost")
            .and_then(|b| b.join(target))
            .map(|u| u.path().to_string())
            .unwrap_or_default();
        // `String(undefined)` is "undefined": no content type is refused too.
        let json_type = parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).starts_with("application/json"))
            .unwrap_or(false);
        if parts.method != Method::POST
            || path != "/run"
            || parts.headers.contains_key(http::header::ORIGIN)
            || !json_type
        {
            return reply(403, false, "Refused.");
        }
        let raw = match tokio::time::timeout(REQUEST_TIMEOUT, read_body(body)).await {
            Ok(Ok(b)) => b,
            Ok(Err(true)) => return reply(413, false, "Refused."),
            // A body that broke off: the handler's own failure.
            Ok(Err(false)) => return reply(500, false, "The command failed on the firewall."),
            Err(_) => return cc_http::empty(408),
        };
        let Ok(body) = serde_json::from_slice::<Value>(&raw) else {
            return reply(400, false, "Refused.");
        };
        // `null.verb` throws in the TS, which answers as a failed command.
        if body.is_null() {
            return reply(500, false, "The command failed on the firewall.");
        }
        let max = self.opts.arg_max.unwrap_or(40);
        let text = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .filter(|v| js_len(v) <= max)
                .map(String::from)
        };
        let Some(verb) = text("verb").filter(|v| !v.is_empty()) else {
            return reply(400, false, &self.opts.help);
        };
        // One command at a time: a restart and a clean racing each other help nobody.
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return reply(429, false, "Another command is still running. Wait for it.");
        }
        // Free again only when the command is over, also when the client went away mid-command:
        // the command runs on its own task, which a dropped request does not end.
        struct Free(Arc<LoopbackTools>);
        impl Drop for Free {
            fn drop(&mut self) {
                self.0.busy.store(false, Ordering::SeqCst);
            }
        }
        let free = Free(self.clone());
        let run = (self.opts.run)(verb, text("arg"), text("extra"));
        let task = tokio::spawn(async move {
            let out = run.await;
            drop(free);
            out
        });
        match task.await {
            Ok(out) => reply(if out.ok { 200 } else { 400 }, out.ok, &out.text),
            Err(_) => reply(500, false, "The command failed on the firewall."),
        }
    }
}

/// The body, or Err(true) past 4 KB, Err(false) when it broke off.
async fn read_body(mut body: Incoming) -> Result<Vec<u8>, bool> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| false)?;
        if let Ok(data) = frame.into_data() {
            out.extend_from_slice(&data);
            if out.len() > MAX_BODY {
                return Err(true);
            }
        }
    }
    Ok(out)
}

/// What a session is handed: an `Arc<LoopbackTools>` that can start itself.
pub struct Listener(pub Arc<LoopbackTools>);

impl SessionTools for Listener {
    fn token(&self) -> String {
        self.0.token.clone()
    }
    fn start(&self, socket: Option<String>) -> BoxFuture<Result<String, String>> {
        Box::pin(self.0.clone().listen(socket))
    }
    fn close(&self) -> BoxFuture<()> {
        self.0.shut();
        Box::pin(async {})
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.0.shut();
    }
}

fn serve<S, F, Fut>(stream: S, handler: F, cancel: CancellationToken)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Fn(http::Request<Incoming>) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = Result<Resp, std::convert::Infallible>> + Send + 'static,
{
    tokio::spawn(async move {
        let conn = hyper::server::conn::http1::Builder::new()
            .max_buf_size(8_192)
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(HEADERS_TIMEOUT)
            .serve_connection(
                hyper_util::rt::TokioIo::new(stream),
                hyper::service::service_fn(handler),
            );
        tokio::select! {
            _ = conn => {}
            _ = cancel.cancelled() => {}
        }
    });
}

#[cfg(test)]
mod tests;
