//! The HTTP side of both agents: an HTTP/1.1 server (what Node's `http.createServer` speaks, and
//! all Caddy sends), an ordered router, the JSON helpers and error bodies the TS uses, the body
//! read that enforces a firewall token's body hash, and the first-byte TLS/HTTP split the firewall
//! runs on port 3100.
//!
//! The TS dispatches with one long chain of `if`s where order matters: a prefix taken early wins
//! over an exact path further down, and the console gate answers 401 for everything that reaches
//! it. [`Router`] keeps that: the binary declares named stages in order, each workstream adds its
//! routes to a stage, and a stage may have a gate that answers before its routes are looked at.

pub mod log;
mod slot;
pub use slot::{Missing, RequiredSlot, Slot};

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

pub type Body = BoxBody<Bytes, std::io::Error>;
pub type Req = Request<Incoming>;
pub type Resp = Response<Body>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a handler knows about the connection besides the request.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub remote: SocketAddr,
    pub local: SocketAddr,
    /// Whether the request came over TLS (the firewall's recovery routes).
    pub tls: bool,
}

pub type Handler = Arc<dyn Fn(Req, Ctx) -> BoxFuture<Resp> + Send + Sync>;
type Matcher = Box<dyn Fn(&Method, &str) -> bool + Send + Sync>;
/// A stage gate: `Some(response)` answers the request before the stage's routes.
type Gate = Box<dyn Fn(&http::request::Parts, &Ctx) -> Option<Resp> + Send + Sync>;

struct Route {
    matcher: Matcher,
    handler: Handler,
}

struct Stage {
    name: &'static str,
    gate: Option<Gate>,
    routes: Vec<Route>,
}

pub struct Router {
    stages: Vec<Stage>,
    /// Answers before any stage (pool mode on an unclaimed box).
    pre: Option<Gate>,
    /// Requests with an `Upgrade` header go here and nowhere else, as Node hands them to the
    /// server's `upgrade` event instead of its request handler.
    upgrades: Option<Box<Router>>,
    fallback: fn() -> Resp,
}

impl Router {
    /// `stages` in the order the TS chain checks them.
    pub fn new(stages: &[&'static str]) -> Self {
        Self {
            stages: stages
                .iter()
                .map(|n| Stage {
                    name: n,
                    gate: None,
                    routes: Vec::new(),
                })
                .collect(),
            pre: None,
            upgrades: None,
            fallback: not_found,
        }
    }

    /// What a request no route takes gets (JSON `{"error":"Not found"}` unless set).
    pub fn fallback(&mut self, f: fn() -> Resp) {
        self.fallback = f;
    }

    /// The router for upgrade requests. Without one they go through the normal stages.
    pub fn upgrades(&mut self, router: Router) {
        self.upgrades = Some(Box::new(router));
    }

    /// The upgrade router, to add routes to after [`Router::upgrades`].
    pub fn upgrades_mut(&mut self) -> Option<&mut Router> {
        self.upgrades.as_deref_mut()
    }

    fn stage(&mut self, name: &str) -> &mut Stage {
        let known: Vec<&str> = self.stages.iter().map(|s| s.name).collect();
        self.stages
            .iter_mut()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no router stage {name:?}; stages are {known:?}"))
    }

    pub fn pre_gate(&mut self, gate: impl Fn(&http::request::Parts, &Ctx) -> Option<Resp> + Send + Sync + 'static) {
        self.pre = Some(Box::new(gate));
    }

    pub fn gate(
        &mut self,
        stage: &str,
        gate: impl Fn(&http::request::Parts, &Ctx) -> Option<Resp> + Send + Sync + 'static,
    ) {
        self.stage(stage).gate = Some(Box::new(gate));
    }

    pub fn route<F, Fut>(
        &mut self,
        stage: &str,
        matcher: impl Fn(&Method, &str) -> bool + Send + Sync + 'static,
        handler: F,
    ) where
        F: Fn(Req, Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Resp> + Send + 'static,
    {
        let handler: Handler = Arc::new(move |r, c| Box::pin(handler(r, c)));
        self.stage(stage).routes.push(Route {
            matcher: Box::new(matcher),
            handler,
        });
    }

    /// An exact method and path, the common case.
    pub fn exact<F, Fut>(&mut self, stage: &str, method: Method, path: &'static str, handler: F)
    where
        F: Fn(Req, Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Resp> + Send + 'static,
    {
        self.route(stage, move |m, p| *m == method && p == path, handler);
    }

    /// Every path that starts with `prefix`, any method: the handler sorts them out, as the TS ones do.
    pub fn prefix<F, Fut>(&mut self, stage: &str, prefix: &'static str, handler: F)
    where
        F: Fn(Req, Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Resp> + Send + 'static,
    {
        self.route(stage, move |_, p| p.starts_with(prefix), handler);
    }

    pub fn dispatch(&self, req: Req, ctx: Ctx) -> BoxFuture<Resp> {
        let (parts, body) = req.into_parts();
        if let Some(up) = &self.upgrades
            && is_upgrade(&parts)
        {
            return up.dispatch(Request::from_parts(parts, body), ctx);
        }
        if let Some(r) = self.pre.as_ref().and_then(|g| g(&parts, &ctx)) {
            return Box::pin(async move { r });
        }
        // `new URL(req.url, "http://localhost").pathname`, so a handler sees what the TS saw.
        let path = pathname(&parts.uri.to_string());
        let mut handler = None;
        for stage in &self.stages {
            if let Some(r) = stage.gate.as_ref().and_then(|g| g(&parts, &ctx)) {
                return Box::pin(async move { r });
            }
            if let Some(route) = stage.routes.iter().find(|r| (r.matcher)(&parts.method, &path)) {
                handler = Some(route.handler.clone());
                break;
            }
        }
        match handler {
            Some(h) => h(Request::from_parts(parts, body), ctx),
            None => {
                let r = (self.fallback)();
                Box::pin(async move { r })
            }
        }
    }
}

/// An upgrade as Node sees one (llhttp's upgrade flag): an `Upgrade` header and `upgrade` among
/// the `Connection` tokens. Only those reach Node's `upgrade` event; anything else is a request.
fn is_upgrade(parts: &http::request::Parts) -> bool {
    parts.headers.contains_key(http::header::UPGRADE)
        && parts
            .headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

/// The WHATWG pathname of a request target, as `new URL(target, "http://localhost").pathname`
/// gives it: dot segments resolved, query and fragment dropped. `/` where the URL does not parse.
pub fn pathname(target: &str) -> String {
    url::Url::parse("http://localhost")
        .and_then(|base| base.join(target))
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/".to_string())
}

pub fn full(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::new(
        Full::new(body.into())
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *r.status_mut() = status;
    if !content_type.is_empty()
        && let Ok(v) = http::HeaderValue::from_str(content_type)
    {
        r.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    r
}

/// `res.writeHead(status, {"Content-Type": "application/json"}); res.end(JSON.stringify(body))`.
pub fn json(status: u16, body: &Value) -> Resp {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    full(status, "application/json", serde_json::to_vec(body).unwrap_or_default())
}

/// `sendJson` in `packages/vm-agent/src/http.ts`: as [`json`], plus `Cache-Control: no-store`.
pub fn send_json(status: u16, body: &Value) -> Resp {
    let mut r = json(status, body);
    r.headers_mut()
        .insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    r
}

pub fn not_found() -> Resp {
    json(404, &serde_json::json!({"error": "Not found"}))
}

/// `res.writeHead(404, {"content-length": "0"}); res.end()`: the firewall ingress's answer.
pub fn empty_not_found() -> Resp {
    full(StatusCode::NOT_FOUND, "", Bytes::new())
}

/// An empty answer with a status, as `res.writeHead(status, {"content-length": "0"})` gives.
pub fn empty(status: u16) -> Resp {
    let mut r = empty_not_found();
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r
}

pub fn unauthorized() -> Resp {
    json(401, &serde_json::json!({"error": "Unauthorized"}))
}

/// What a firewall token bound the body to, for [`read_json_body`]. Made from the accepted token
/// (`From<&Accepted>`), or explicitly as [`BodyBinding::not_firewall`] on a route that takes no
/// firewall token; there is no default, so a firewall route cannot forget the hash by accident.
#[derive(Debug, Clone)]
pub struct BodyBinding {
    /// The request came with a bound firewall token.
    bound: bool,
    /// Its `b` claim. On a bound token without one, every body is refused (the TS compares the
    /// hash with `undefined`).
    sha256: Option<String>,
}

impl BodyBinding {
    /// A route that takes no firewall token (the console's, a page's): no hash to check.
    pub fn not_firewall() -> Self {
        Self {
            bound: false,
            sha256: None,
        }
    }
}

impl From<&cc_auth::firewall::Accepted> for BodyBinding {
    fn from(a: &cc_auth::firewall::Accepted) -> Self {
        Self {
            bound: a.bound,
            sha256: a.body_sha256.clone(),
        }
    }
}

/// What a firewall route reads from the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadBody {
    /// Nothing (a GET, or a route that takes no body).
    No,
    /// A JSON object of at most this many bytes, checked against the token's hash.
    Json { limit: usize },
}

/// The body a firewall route got. Three outcomes, so a route that read nothing is never mistaken
/// for one whose body was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum FirewallBody {
    /// The route asked for no body ([`ReadBody::No`]).
    NotRead,
    /// The JSON object, the one the token named.
    Json(Map<String, Value>),
    /// Not a JSON object within the limit, or not the body the token named: `readJsonBody`
    /// returning null, which is the route's 400.
    Rejected,
}

/// A firewall-signed request, checked and read: what every firewall route starts with.
pub enum FirewallRequest {
    /// The token was taken.
    Accepted {
        parts: http::request::Parts,
        accepted: Box<cc_auth::firewall::Accepted>,
        body: FirewallBody,
    },
    /// The token was refused, with the binding's reason when there is one (`req.ccRefused`).
    Refused {
        parts: http::request::Parts,
        reason: Option<cc_auth::firewall::Refusal>,
    },
}

/// `verifyMitmRequest` then `readJsonBody`, in one step so the body hash is always checked.
pub async fn firewall_request(
    auth: &cc_auth::firewall::FirewallAuth,
    req: Req,
    purpose: &str,
    clock_tolerance_s: i64,
    read: ReadBody,
) -> FirewallRequest {
    let (parts, body) = req.into_parts();
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let request = cc_auth::firewall::RequestParts {
        method: parts.method.as_str(),
        url: &target,
        authorization: header(&parts, "authorization"),
        accepted_token_id: None,
    };
    match auth.verify(&request, purpose, clock_tolerance_s) {
        cc_auth::firewall::Outcome::Accepted(accepted) => {
            let body = match read {
                ReadBody::No => FirewallBody::NotRead,
                ReadBody::Json { limit } => match read_json_body(body, limit, &BodyBinding::from(&accepted)).await {
                    Some(m) => FirewallBody::Json(m),
                    None => FirewallBody::Rejected,
                },
            };
            FirewallRequest::Accepted {
                parts,
                accepted: Box::new(accepted),
                body,
            }
        }
        cc_auth::firewall::Outcome::Refused(r) => FirewallRequest::Refused { parts, reason: Some(r) },
        cc_auth::firewall::Outcome::Invalid => FirewallRequest::Refused { parts, reason: None },
    }
}

/// `readJsonBody`: a JSON object of at most `limit` bytes, or `None` for anything else (bad JSON,
/// an array, too large, or a body other than the one a bound firewall token named).
/// The body is also given at most [`BODY_TIMEOUT`]: a client that trickles it gets nothing for it.
pub async fn read_json_body(body: Incoming, limit: usize, binding: &BodyBinding) -> Option<Map<String, Value>> {
    let raw = read_body(body, limit).await?;
    if binding.bound && binding.sha256.as_deref() != Some(hex::encode(Sha256::digest(&raw)).as_str()) {
        return None;
    }
    match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// How long a request's body may take to arrive once its handler reads it. With the 60 s for the
/// headers on every listener, a request is bounded at about six minutes; Node bounded the whole
/// request at 300 s (`requestTimeout`), so this is close to it, not the same.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(300);

/// A whole body of at most `limit` bytes, within [`BODY_TIMEOUT`]; `None` when it is larger, slower
/// or broken. Every body a handler reads goes through this (or [`read_json_body`]), so no client can
/// hold a connection by sending a byte now and then.
pub async fn read_body<B>(body: B, limit: usize) -> Option<Bytes>
where
    B: http_body::Body<Data = Bytes> + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    read_body_within(body, limit, BODY_TIMEOUT).await
}

async fn read_body_within<B>(body: B, limit: usize, within: Duration) -> Option<Bytes>
where
    B: http_body::Body<Data = Bytes> + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    match tokio::time::timeout(within, Limited::new(body, limit).collect()).await {
        Ok(Ok(c)) => Some(c.to_bytes()),
        _ => None,
    }
}

/// The header's value as text, if present and valid.
pub fn header<'a>(parts: &'a http::request::Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

async fn serve_conn<I>(io: I, router: Arc<Router>, ctx: Ctx)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req: Req| {
        let router = router.clone();
        async move { Ok::<_, Infallible>(router.dispatch(req, ctx).await) }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        // Node's `headersTimeout`: a client that sends its headers a byte at a time is cut off.
        .header_read_timeout(HEADERS_TIMEOUT)
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades()
        .await
        && !e.is_incomplete_message()
    {
        tracing::debug!("connection from {}: {e}", ctx.remote);
    }
}

const HEADERS_TIMEOUT: Duration = Duration::from_secs(60);
/// Node's default `handshakeTimeout` for an https server.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// The next connection. A failed accept (out of descriptors) is logged and waited out rather than
/// retried at once, which would spin a core.
async fn accept(listener: &TcpListener) -> (tokio::net::TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(c) => return c,
            Err(e) => {
                tracing::error!("[http] accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Serve plain HTTP on `listener` until the process ends.
pub async fn serve(listener: TcpListener, router: Arc<Router>) {
    serve_from(listener, router, Vec::new()).await
}

/// [`serve`], closing at once every connection whose source is not in `allow` (an unmanaged
/// vm-agent that listens on a shared network for its firewall alone). An empty list takes all.
pub async fn serve_from(listener: TcpListener, router: Arc<Router>, allow: Vec<std::net::IpAddr>) {
    let local = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut said: Option<std::time::Instant> = None;
    loop {
        let (stream, remote) = accept(&listener).await;
        if !allow.is_empty() && !allow.contains(&remote.ip().to_canonical()) {
            drop(stream);
            if said.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
                said = Some(std::time::Instant::now());
                tracing::warn!(
                    "[http] closed a connection from {}: only {allow:?} may connect",
                    remote.ip()
                );
            }
            continue;
        }
        let router = router.clone();
        tokio::spawn(serve_conn(
            stream,
            router,
            Ctx {
                remote,
                local,
                tls: false,
            },
        ));
    }
}

const TLS_HANDSHAKE: u8 = 0x16;
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);

/// One port, two protocols (`muxTlsAndHttp` in `packages/mitm-agent/src/recovery-tls.ts`): a
/// connection whose first byte starts a TLS handshake goes to `tls`, anything else to `plain`. A
/// connection that sends nothing for 30 s is closed.
pub async fn serve_mux(
    listener: TcpListener,
    plain: Arc<Router>,
    tls: Arc<Router>,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    let local = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    loop {
        let (stream, remote) = accept(&listener).await;
        let (plain, tls, acceptor) = (plain.clone(), tls.clone(), acceptor.clone());
        tokio::spawn(async move {
            let mut first = [0u8; 1];
            match tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first)).await {
                Ok(Ok(1)) if first[0] == TLS_HANDSHAKE => {
                    if let Ok(Ok(s)) = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        serve_conn(
                            s,
                            tls,
                            Ctx {
                                remote,
                                local,
                                tls: true,
                            },
                        )
                        .await;
                    }
                }
                Ok(Ok(1)) => {
                    serve_conn(
                        stream,
                        plain,
                        Ctx {
                            remote,
                            local,
                            tls: false,
                        },
                    )
                    .await
                }
                _ => {}
            }
        });
    }
}

/// A TLS acceptor from PEM files (the firewall's `recovery_key.pem` / `recovery_cert.pem`).
pub fn tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<tokio_rustls::TlsAcceptor, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("no private key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_trickled_body_gets_nothing() {
        use futures_util::StreamExt;
        // A body that sends one byte and then nothing.
        let frames = futures_util::stream::iter([Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(
            Bytes::from_static(b"{"),
        ))])
        .chain(futures_util::stream::pending());
        let body = http_body_util::StreamBody::new(frames);
        let t = std::time::Instant::now();
        assert!(read_body_within(body, 1024, Duration::from_millis(100)).await.is_none());
        assert!(t.elapsed() < Duration::from_secs(1));
        let whole = Full::new(Bytes::from_static(b"{}"));
        assert_eq!(
            read_body_within(whole, 1024, Duration::from_millis(100))
                .await
                .as_deref(),
            Some(&b"{}"[..])
        );
        let big = Full::new(Bytes::from(vec![b'x'; 2048]));
        assert!(read_body_within(big, 1024, Duration::from_secs(1)).await.is_none());
    }

    #[test]
    fn pathnames() {
        assert_eq!(pathname("/a/../b?x=1"), "/b");
        assert_eq!(pathname("/a/./b/"), "/a/b/");
        assert_eq!(pathname("/a/.."), "/");
        assert_eq!(pathname("http://other:9/x/y?q"), "/x/y");
        assert_eq!(pathname("/a%20b"), "/a%20b");
    }

    #[tokio::test]
    async fn stages_gates_and_fallback() {
        let mut r = Router::new(&["early", "gated"]);
        r.prefix("early", "/__cc/", |_, _| async {
            json(200, &serde_json::json!({"stage": "early"}))
        });
        r.gate("gated", |parts, _| {
            (header(parts, "authorization") != Some("Bearer ok")).then(unauthorized)
        });
        r.exact("gated", Method::GET, "/health", |_, _| async {
            json(200, &serde_json::json!({"ok": true}))
        });
        let router = Arc::new(r);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(listener, router));
        let c = reqwest::Client::new();
        let get = |p: &str, auth: Option<&str>| {
            let mut b = c.get(format!("http://{addr}{p}"));
            if let Some(a) = auth {
                b = b.header("authorization", a);
            }
            b.send()
        };
        assert_eq!(get("/__cc/x", None).await.expect("req").status(), 200);
        assert_eq!(get("/health", None).await.expect("req").status(), 401);
        let ok = get("/health", Some("Bearer ok")).await.expect("req");
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.headers()["content-type"], "application/json");
        let nf = get("/nope", Some("Bearer ok")).await.expect("req");
        assert_eq!(nf.status(), 404);
        assert_eq!(nf.text().await.expect("body"), r#"{"error":"Not found"}"#);
    }
}
