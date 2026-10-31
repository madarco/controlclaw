//! The model bridge (`doctor-gateway.ts`): a key that never enters the CLI's environment. The CLI
//! holds a session token for this bridge, and the bridge puts the key on the requests it lets
//! through. Used for included tokens in every session, and for every credential of a Final check,
//! whose unit has no network at all and reaches this over a unix socket. Every request is checked
//! against the current list of models.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
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

use crate::integrations::js;

/// Where requests go and how the key is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upstream {
    pub base: &'static str,
    /// `bearer` or `x-api-key`.
    pub x_api_key: bool,
}

pub const AI_GATEWAY: Upstream = Upstream {
    base: "https://ai-gateway.vercel.sh",
    x_api_key: false,
};
pub const ANTHROPIC: Upstream = Upstream {
    base: "https://api.anthropic.com",
    x_api_key: true,
};

/// The key and the models it may be used with, read at every request.
pub struct GatewayCredential {
    pub key: String,
    pub allowed_models: Vec<String>,
}

pub type CredentialFn = Arc<dyn Fn() -> BoxFuture<Option<GatewayCredential>> + Send + Sync>;

pub struct Options {
    pub active: Arc<dyn Fn() -> bool + Send + Sync>,
    pub credential: CredentialFn,
    pub upstream: Option<Upstream>,
    /// A Final check: the Messages API only, the listed fields only, no server tools, at most
    /// `max_requests` requests.
    pub strict: Option<u32>,
    /// Where it sends (the tests' fake provider); None: the upstream's own base.
    pub base_override: Option<String>,
}

const PATHS: &[&str] = &[
    "/v1/messages",
    "/v1/messages/count_tokens",
    "/v1/responses",
    "/v1/chat/completions",
];
/// Gateway model fallbacks: top-level routing fields, refused in every spelling.
const ROUTING_FIELDS: &[&str] = &["providerOptions", "provider_options", "gateway", "models", "routing"];
const STRICT_FIELDS: &[&str] = &[
    "model",
    "messages",
    "system",
    "max_tokens",
    "tools",
    "tool_choice",
    "stream",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "metadata",
    "thinking",
];
const MAX_BODY: usize = 8 * 1024 * 1024;
const AT_ONCE: usize = 4;

pub struct DoctorGateway {
    pub token: String,
    opts: Options,
    closed: AtomicBool,
    open: Arc<AtomicUsize>,
    forwarded: AtomicU32,
    cancel: CancellationToken,
    http: reqwest::Client,
    socket: Mutex<Option<std::path::PathBuf>>,
}

fn digest(v: &str) -> [u8; 32] {
    Sha256::digest(v.as_bytes()).into()
}

fn reject(status: u16) -> Resp {
    let text = js::stringify(
        &json!({"error": {"message": "Doctor gateway request refused.", "type": "doctor_gateway_error"}}),
    );
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        "application/json",
        text,
    );
    r.headers_mut()
        .insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

impl DoctorGateway {
    pub fn new(opts: Options) -> Arc<Self> {
        Arc::new(Self {
            token: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
            opts,
            closed: AtomicBool::new(false),
            open: Arc::new(AtomicUsize::new(0)),
            forwarded: AtomicU32::new(0),
            cancel: CancellationToken::new(),
            // The host and paths are fixed. No redirects.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            socket: Mutex::new(None),
        })
    }

    /// Listens on loopback (its URL), or on a unix socket at `socket` (the path).
    pub async fn start(self: &Arc<Self>, socket: Option<&std::path::Path>) -> Result<String, String> {
        if self.closed.load(Ordering::SeqCst) {
            return Err("Doctor gateway closed.".into());
        }
        let me = self.clone();
        let handler = move |req: http::Request<Incoming>| {
            let me = me.clone();
            async move { Ok::<_, std::convert::Infallible>(me.handle(req).await) }
        };
        let base = match socket {
            Some(path) => {
                let _ = std::fs::remove_file(path);
                let l =
                    tokio::net::UnixListener::bind(path).map_err(|_| "Doctor gateway could not listen.".to_string())?;
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
                }
                *self.socket.lock().unwrap_or_else(|e| e.into_inner()) = Some(path.to_path_buf());
                let cancel = self.cancel.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            a = l.accept() => if let Ok((s, _)) = a { serve(s, handler.clone(), cancel.clone()); },
                        }
                    }
                });
                path.display().to_string()
            }
            None => {
                let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|_| "Doctor gateway could not listen.".to_string())?;
                let port = l
                    .local_addr()
                    .map_err(|_| "Doctor gateway could not listen.".to_string())?
                    .port();
                let cancel = self.cancel.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            a = l.accept() => if let Ok((s, _)) = a { serve(s, handler.clone(), cancel.clone()); },
                        }
                    }
                });
                format!("http://127.0.0.1:{port}")
            }
        };
        if self.closed.load(Ordering::SeqCst) || !(self.opts.active)() {
            self.close();
            return Err("Doctor gateway revoked.".into());
        }
        Ok(base)
    }

    /// Ends every request and the listener.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cancel.cancel();
        if let Some(p) = self.socket.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = std::fs::remove_file(p);
        }
    }

    async fn handle(self: Arc<Self>, req: http::Request<Incoming>) -> Resp {
        let h = req.headers();
        let token = match h.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
            Some(a) if a.starts_with("Bearer ") => Some(a[7..].to_string()),
            _ => h.get("x-api-key").and_then(|v| v.to_str().ok()).map(String::from),
        };
        let token_ok = token
            .as_deref()
            .is_some_and(|t| cc_crypto::ct_eq(&digest(t), &digest(&self.token)));
        if !token_ok || self.closed.load(Ordering::SeqCst) || !(self.opts.active)() {
            return reject(403);
        }
        let path = req.uri().path().to_string();
        let beta = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .find(|(k, _)| k == "beta")
            .is_some_and(|(_, v)| v == "true");
        let strict = self.opts.strict;
        if strict.is_some() && !path.starts_with("/v1/messages") {
            return reject(403);
        }
        let json_type = h
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("application/json"));
        if req.method() != Method::POST
            || !PATHS.contains(&path.as_str())
            || h.contains_key(http::header::ORIGIN)
            || !json_type
        {
            return reject(403);
        }
        if self.open.load(Ordering::SeqCst) >= AT_ONCE {
            return reject(429);
        }
        self.open.fetch_add(1, Ordering::SeqCst);
        // Held until the whole answer is written, as the TS holds it until the stream ends.
        let slot = Slot(self.open.clone());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        let pass: Vec<(String, String)> = if strict.is_some() {
            vec!["anthropic-version", "accept"]
        } else {
            vec!["anthropic-version", "anthropic-beta", "openai-beta", "accept"]
        }
        .into_iter()
        .filter_map(|n| {
            h.get(n)
                .and_then(|v| v.to_str().ok())
                .map(|v| (n.to_string(), v.to_string()))
        })
        .collect();
        let work = async {
            let body = http_body_util::Limited::new(req.into_body(), MAX_BODY).collect().await;
            let Ok(body) = body else { return reject(413) };
            let Ok(Value::Object(mut parsed)) = serde_json::from_slice::<Value>(&body.to_bytes()) else {
                return reject(400);
            };
            if ROUTING_FIELDS.iter().any(|f| parsed.contains_key(*f)) {
                return reject(403);
            }
            if strict.is_some() {
                // Only the fields a plain Messages request has; anything else is dropped.
                parsed.retain(|k, _| STRICT_FIELDS.contains(&k.as_str()));
                // A tool the model calls back has no `type`, or `custom`. Anything else runs at the provider.
                if let Some(Value::Array(tools)) = parsed.get_mut("tools") {
                    tools.retain(|t| {
                        matches!(t.get("type"), None | Some(Value::Null)) || t.get("type") == Some(&json!("custom"))
                    });
                }
            }
            let model = parsed.get("model").and_then(Value::as_str).map(String::from);
            let credential = (self.opts.credential)().await;
            let Some(cred) = credential.filter(|c| !c.key.is_empty()) else {
                return reject(403);
            };
            let allowed = model.as_ref().is_some_and(|m| cred.allowed_models.contains(m));
            if self.closed.load(Ordering::SeqCst) || !(self.opts.active)() || !allowed {
                return reject(403);
            }
            let up = self.opts.upstream.unwrap_or(AI_GATEWAY);
            // Counted when it is about to be sent: a refused request and a token count use none.
            if let Some(max) = strict
                && path == "/v1/messages"
                && self.forwarded.fetch_add(1, Ordering::SeqCst) + 1 > max
            {
                return reject(429);
            }
            let base = self.opts.base_override.clone().unwrap_or_else(|| up.base.to_string());
            let url = format!(
                "{base}{path}{}",
                if strict.is_none() && beta { "?beta=true" } else { "" }
            );
            let mut r = self.http.post(url).header("content-type", "application/json");
            r = if up.x_api_key {
                r.header("x-api-key", &cred.key)
            } else {
                r.header("authorization", format!("Bearer {}", cred.key))
            };
            for (k, v) in &pass {
                r = r.header(k, v);
            }
            // Written again from the checked value, so duplicate keys cannot read otherwise upstream.
            let sent = r.body(js::stringify(&Value::Object(parsed))).send().await;
            let Ok(upr) = sent else { return reject(502) };
            let status = upr.status().as_u16();
            if !(200..300).contains(&status) {
                return reject(if (400..600).contains(&status) { status } else { 502 });
            }
            let ct = upr
                .headers()
                .get(http::header::CONTENT_TYPE)
                .cloned()
                .unwrap_or(HeaderValue::from_static("application/json"));
            // The ten minutes and a close cover the streamed body too.
            let upstream = Box::pin(upr.bytes_stream());
            let cancel = self.cancel.clone();
            let stream = futures_util::stream::unfold(Some((upstream, slot, cancel)), move |state| async move {
                let (mut up, slot, cancel) = state?;
                tokio::select! {
                    c = futures_util::StreamExt::next(&mut up) => {
                        let c = c?;
                        Some((
                            c.map(hyper::body::Frame::data).map_err(|e| std::io::Error::other(e.without_url())),
                            Some((up, slot, cancel)),
                        ))
                    }
                    _ = cancel.cancelled() => Some((Err(std::io::Error::other("closed")), None)),
                    _ = tokio::time::sleep_until(deadline) => Some((Err(std::io::Error::other("timed out")), None)),
                }
            });
            let mut resp = http::Response::new(BodyExt::boxed(http_body_util::StreamBody::new(stream)));
            *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
            resp.headers_mut().insert(http::header::CONTENT_TYPE, ct);
            resp.headers_mut()
                .insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        };
        tokio::select! {
            r = work => r,
            _ = self.cancel.cancelled() => reject(403),
            _ = tokio::time::sleep_until(deadline) => reject(504),
        }
    }
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
            .max_buf_size(64 * 1024)
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
