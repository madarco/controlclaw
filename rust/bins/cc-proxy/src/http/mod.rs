//! Intercepted HTTP. Owner: W1.
//!
//! One hyper server per agent connection: HTTP/1.1 or h2 inside TLS (the ALPN the agent offered),
//! plain HTTP inside a CONNECT tunnel, or absolute-form requests sent to the proxy itself. Each
//! request is one [`Flow`]: its destination is checked (a request inside a TLS tunnel must name
//! the tunnel's host, else 421), the pipeline runs at `Request`, and only then is the site dialled
//! (the checked address, from a pool per agent connection). The answer runs the pipeline at
//! `Response` before the agent gets it. Bodies are buffered whole both ways, as mitmproxy buffers
//! them (no `stream_large_bodies`).
//!
//! W1 P8: websocket upgrades and their frame pumps.

pub mod answer;
pub mod backup;
pub mod body;
pub mod buffered;
pub mod h2print;
pub mod h2up;
pub mod judge;
pub mod policy;
pub mod swaps;
pub mod upstream;

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::FutureExt;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Version};
use http_body_util::BodyExt;

use buffered::{Buffered, Trailers};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::flow::{Authority, Destination, Flow, Hook, Verdict};
use crate::log::record::{self, NON_ROUTABLE_REFUSAL};
use crate::net::Shared;
use crate::net::destination::{self, Refused};
use upstream::{Pool, UpstreamError};

/// The largest body buffered either way. mitmproxy has no limit; one agent's upload or download
/// must not take the memory every agent's traffic needs, and every check reads far less than this.
pub const MAX_BODY: usize = 256 << 20;

/// Concurrent h2 streams on one agent connection.
pub const MAX_H2_STREAMS: u32 = 100;

/// The refusal of a build that has no checks in it (no W2 step registered).
pub const CHECKS_MISSING: &str = "checks_unavailable";

/// How the requests on one agent connection are addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Inside intercepted TLS: every request goes to the tunnel's destination, on TLS.
    Tls,
    /// Plain HTTP inside a CONNECT tunnel: each request to the host it names, on the CONNECT port.
    PlainTunnel,
    /// Absolute-form requests to the proxy itself: each to the host and port its URL names.
    Absolute,
}

/// What one agent connection's requests share.
pub struct Conn {
    pub shared: Arc<Shared>,
    pub mode: Mode,
    pub client_ip: IpAddr,
    pub connect: Authority,
    pub vm_id: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    /// The tunnel's destination (TLS mode), resolved at its first request and kept for the
    /// connection: the address checked is the address used, however long it stays open.
    /// Only a destination that resolved is kept: a failure is tried again on the next request.
    /// Parallel h2 streams wait for one lookup and share it, with no lock held while it runs.
    tunnel: OneLookup,
    /// The CONNECT address's own refusal, checked once for the connection.
    connect_refused: tokio::sync::OnceCell<Option<String>>,
    /// Plain HTTP: each (name, port) resolved once for the connection (at most 64 kept).
    plain: std::sync::Mutex<std::collections::HashMap<(String, u16), Arc<OneLookup>>>,
    pub(crate) pool: Pool,
}

impl Conn {
    /// A plain-HTTP connection (absolute form, a plain tunnel): its TLS dials, if any, use the
    /// built-in profile, there being no ClientHello of the agent's to copy.
    pub fn new(shared: Arc<Shared>, mode: Mode, conn_flow: &Flow) -> Self {
        Self::with(shared, mode, conn_flow, Arc::default(), None)
    }

    /// An intercepted TLS connection: dials copy the agent's `fingerprint`; `prepared` is the
    /// connection made before the agent's handshake ended, with the destination it was made to.
    pub fn intercepted(
        shared: Arc<Shared>,
        conn_flow: &Flow,
        fingerprint: Arc<upstream::Fingerprint>,
        prepared: Option<(upstream::Prepared, Destination)>,
    ) -> Self {
        let (prepared, d) = prepared.map_or((None, None), |(p, d)| (Some(p), Some(d)));
        let conn = Self::with(shared, Mode::Tls, conn_flow, fingerprint, prepared);
        if let Some(d) = d {
            conn.tunnel.set(d);
        }
        conn
    }

    fn with(
        shared: Arc<Shared>,
        mode: Mode,
        conn_flow: &Flow,
        fingerprint: Arc<upstream::Fingerprint>,
        prepared: Option<upstream::Prepared>,
    ) -> Self {
        Self {
            pool: Pool::new(shared.ctx.clone(), fingerprint, prepared),
            shared,
            mode,
            client_ip: conn_flow.client_ip,
            connect: conn_flow.connect.clone(),
            vm_id: conn_flow.vm_id.clone(),
            sni: conn_flow.sni.clone(),
            alpn: conn_flow.alpn.clone(),
            tunnel: OneLookup::default(),
            connect_refused: tokio::sync::OnceCell::new(),
            plain: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// A flow for one exchange on this connection.
    pub(crate) fn new_flow(&self) -> Flow {
        let mut f = Flow::new(self.client_ip, self.connect.clone());
        f.vm_id = self.vm_id.clone();
        f.sni = self.sni.clone();
        f.alpn = self.alpn.clone();
        if self.mode == Mode::Tls {
            f.meta.insert("tls", serde_json::Value::Bool(true));
        }
        f
    }
}

/// Serve HTTP/1.1 (and absolute-form, and plain-tunnel) requests on `io` until it closes.
pub async fn serve_h1<S>(conn: Arc<Conn>, io: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| exchange(conn.clone(), req));
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades()
        .await
    {
        tracing::debug!("[proxy] client connection: {e}");
    }
}

/// Serve h2 on `io` until it closes. Streams are handled at once, each its own flow.
pub async fn serve_h2<S>(conn: Arc<Conn>, io: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| exchange(conn.clone(), req));
    // At most this many requests at once on one connection, each buffered whole: one agent must
    // not hold the memory every agent's traffic needs.
    if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .max_concurrent_streams(MAX_H2_STREAMS)
        .serve_connection(TokioIo::new(io), svc)
        .await
    {
        tracing::debug!("[proxy] client h2 connection: {e}");
    }
}

/// The error a service returns to make hyper close the connection (h1) or reset the stream (h2):
/// a step killed the flow.
#[derive(Debug)]
pub struct Killed(pub String);

impl std::fmt::Display for Killed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "killed: {}", self.0)
    }
}

impl std::error::Error for Killed {}

pub(crate) type Reply = Result<Response<Buffered>, Killed>;

/// What the agent gets back: a whole body, or (the backup store) one streamed from the site.
pub type ClientBody = http_body_util::combinators::BoxBody<Bytes, upstream::BoxError>;

/// One request. The backup bucket is streamed both ways (multi-gigabyte ciphertext uploads);
/// everything else goes through the pipeline, each body buffered only when a step reads it.
async fn exchange(conn: Arc<Conn>, req: Request<Incoming>) -> Result<Response<ClientBody>, Killed> {
    if is_upgrade(&req) {
        return crate::ws::exchange(conn, req).await;
    }
    if backup::is_backup_request(&conn, &req) {
        return backup::stream(&conn, req).await;
    }
    exchange_http(conn, req).await
}

/// [`Reply`] for the agent.
fn client(r: Reply) -> Result<Response<ClientBody>, Killed> {
    r.map(|r| r.map(|b| b.map_err(|never| match never {}).boxed()))
}

/// The request's body: buffered for a step that reads it, else the agent's own, streamed on.
enum UpBody {
    Buffered,
    Streamed(Option<Incoming>),
}

async fn exchange_http(conn: Arc<Conn>, req: Request<Incoming>) -> Result<Response<ClientBody>, Killed> {
    let version = req.version();
    let head_only = req.method() == http::Method::HEAD;
    // The flow starts when the request head arrives, so the record's duration has the upload in it.
    let mut flow = conn.new_flow();
    if conn.mode == Mode::Absolute {
        flow.meta.insert("absolute_form", serde_json::Value::Bool(true));
    }
    let (mut parts, incoming) = req.into_parts();
    // The head first: the checks on the destination and whether a step reads the body need no
    // body, and a refused request is refused before its upload is read.
    flow.request = Some(head_of(&parts));
    match check_destination(&conn, &flow).await {
        Ok(d) => flow.set_destination(d),
        Err(answer) => {
            let resp = answer.into_response(&conn, &mut flow);
            return client(Ok(to_client(resp, version, head_only)));
        }
    }
    let shared = conn.shared.clone();
    let control_plane = mark_control_plane(&conn, &mut flow);
    if !control_plane && !shared.checks_present {
        return client(Ok(to_client(refuse_unchecked(&conn, &mut flow), version, head_only)));
    }

    let streamed = control_plane || !shared.pipeline.reads_body(Hook::Request, &mut flow);
    let mut up = if streamed {
        // No step reads it: it goes to the site as it comes, counted for the record. The flow
        // says so, so a step that reads it anyway refuses rather than read an empty body.
        flow.meta
            .insert(crate::checks::META_BODY_DECODED, serde_json::Value::Bool(false));
        flow.meta
            .insert(crate::checks::META_REQUEST_STREAMED, serde_json::Value::Bool(true));
        UpBody::Streamed(Some(incoming))
    } else {
        let (body, trailers) = match read_whole(incoming, version, head_only).await {
            Ok(b) => b,
            Err(reply) => return *reply,
        };
        if let Some(t) = trailers {
            parts.extensions.insert(Trailers(t));
        }
        // The checks read the body as the server will (W2's `META_BODY_DECODED`); the record
        // counts the bytes as they came.
        flow.request = Some(Request::from_parts(parts, Bytes::new()));
        set_request_body(&mut flow, body);
        // The body is held, so the steps may read the files afresh (a rule or credential that
        // changed while it came in applies): the snapshot only had to agree with the decision
        // when a body would not be there for them.
        crate::http::policy::forget_rules(&mut flow);
        crate::http::swaps::forget_credentials(&mut flow);
        UpBody::Buffered
    };

    let before = RequestShape::before(&conn, &flow, control_plane);
    let verdict = if control_plane {
        Verdict::Continue
    } else {
        shared.pipeline.run(Hook::Request, &mut flow).await
    };
    let unchanged = RequestShape::unchanged(before, &flow);
    match verdict {
        Verdict::Continue | Verdict::Forward => {}
        Verdict::Answer(resp) => {
            flow.response = Some(*resp);
            return client(respond(&conn, flow, version, head_only).await);
        }
        Verdict::Drop | Verdict::Kill(_) => return client(kill(&conn, flow, "Connection killed.").await),
    }

    let Some(d) = flow.destination().cloned() else {
        return client(kill(&conn, flow, "no destination").await);
    };
    let tls = conn.mode == Mode::Tls
        || flow
            .request
            .as_ref()
            .is_some_and(|r| r.uri().scheme_str() == Some("https"));
    if let Some(exit) = crate::residential::take_exit(&mut flow) {
        // Out through the residential exit, never from this box: one request, by name, over TLS
        // to the site when the agent's was (mitmproxy's upstream mode does the same). Sent
        // whole: a streamed body is read first, within the cap.
        if let UpBody::Streamed(body) = &mut up {
            let Some(incoming) = body.take() else {
                return client(kill(&conn, flow, "no request body").await);
            };
            let (collected, trailers) = match read_whole(incoming, version, head_only).await {
                Ok(b) => b,
                Err(reply) => return *reply,
            };
            if let (Some(t), Some(r)) = (trailers, flow.request.as_mut()) {
                r.extensions_mut().insert(Trailers(t));
            }
            // Held now: the flags say so, as for a body a step read.
            flow.meta.remove(crate::checks::META_REQUEST_STREAMED);
            set_request_body(&mut flow, collected);
        }
        let Some(req) = flow.request.as_ref() else {
            return client(kill(&conn, flow, "no request").await);
        };
        let authority = authority_of(req, &d);
        let up = upstream_request(clone_request(req), &authority, tls, false);
        let ctx = conn.shared.ctx.clone();
        return client(
            match crate::residential::send_http(&ctx, &exit, up, &d.name, d.port, tls).await {
                Ok(resp) => {
                    flow.response = Some(resp);
                    respond(&conn, flow, version, head_only).await
                }
                Err(msg) => failed(&conn, flow, msg, version, head_only).await,
            },
        );
    }
    let Some(req) = flow.request.as_ref() else {
        return client(kill(&conn, flow, "no request").await);
    };
    let authority = authority_of(req, &d);
    let template = clone_request(req);
    let counted = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let outgoing = match up {
        UpBody::Buffered => {
            let trailers = template.extensions().get::<Trailers>().map(|t| t.0.clone());
            upstream::Outgoing::Buffered(template.body().clone(), trailers)
        }
        UpBody::Streamed(mut body) => {
            let body = body
                .take()
                .map(|b| Counted::new(b.map_err(Into::into), counted.clone(), None).boxed_unsync());
            upstream::Outgoing::Streamed(body)
        }
    };
    // A buffered body's length is set for it; a streamed one keeps the agent's framing.
    let length = (!streamed).then(|| template.body().len());
    let sent = conn
        .pool
        .send_head(
            &d,
            tls,
            |h2| upstream_head(&template, &authority, tls, h2, length),
            outgoing,
            unchanged,
        )
        .await;
    if streamed {
        flow.extensions.insert(record::UploadCount(counted));
    }
    match sent {
        Ok(head) => answered(&conn, flow, head, version, head_only).await,
        Err(UpstreamError::Refused(why)) => {
            let msg = record_refused(&conn, &flow, &d, &why);
            client(failed(&conn, flow, msg, version, head_only).await)
        }
        Err(UpstreamError::Failed(msg)) => client(failed(&conn, flow, msg, version, head_only).await),
    }
}

/// A request body read whole, within `MAX_BODY`, with its trailers; else what to answer (413
/// past the cap, the connection closed when the agent went away mid-body).
async fn read_whole(
    incoming: hyper::body::Incoming,
    version: Version,
    head_only: bool,
) -> Result<(Bytes, Option<HeaderMap>), Box<Result<Response<ClientBody>, Killed>>> {
    match http_body_util::Limited::new(incoming, MAX_BODY).collect().await {
        Ok(b) => {
            let trailers = b.trailers().cloned();
            Ok((b.to_bytes(), trailers))
        }
        Err(e) if e.is::<http_body_util::LengthLimitError>() => {
            let resp = answer::mitmproxy_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large", version);
            Err(Box::new(client(Ok(to_client(resp, version, head_only)))))
        }
        // The agent went away mid-body: nothing to send, nothing to record.
        Err(e) => Err(Box::new(Err(Killed(format!("client body: {e}"))))),
    }
}

/// The request's body, held: decoded in place for the checks as the server will read it (W2's
/// `META_BODY_DECODED`), its size as it came kept for the record.
fn set_request_body(flow: &mut Flow, mut body: Bytes) {
    flow.extensions.insert(record::RawLen {
        request: body.len(),
        response: None,
    });
    let Some(req) = flow.request.as_mut() else { return };
    let decoded = body::decode_in_place(req.headers_mut(), &mut body);
    *req.body_mut() = body;
    flow.meta
        .insert(crate::checks::META_BODY_DECODED, serde_json::Value::Bool(decoded));
}

/// The site's answer once its head is in: buffered and through the response steps when one reads
/// its body (up to `MAX_BODY`), else through them on the head alone and streamed to the agent as it
/// comes, its record written when it ends.
async fn answered(
    conn: &Conn,
    mut flow: Flow,
    head: upstream::AnswerHead,
    version: Version,
    head_only: bool,
) -> Result<Response<ClientBody>, Killed> {
    let (parts, body) = head.into_parts();
    let site_status = parts.status;
    flow.response = Some(Response::from_parts(parts, Bytes::new()));
    let control_plane = flow.meta.contains_key("control_plane");
    if !control_plane && conn.shared.pipeline.reads_body(Hook::Response, &mut flow) {
        let parts = match flow.response.take() {
            Some(r) => r.into_parts().0,
            None => return client(kill(conn, flow, "no response").await),
        };
        return client(
            match upstream::collect(Response::from_parts(parts, body), MAX_BODY).await {
                Ok(resp) => {
                    flow.response = Some(resp);
                    respond(conn, flow, version, head_only).await
                }
                Err(UpstreamError::Refused(m) | UpstreamError::Failed(m)) => {
                    failed(conn, flow, m, version, head_only).await
                }
            },
        );
    }
    // No step reads it: the response steps see the head (the body is not decoded for them).
    flow.meta
        .insert(crate::checks::META_BODY_DECODED, serde_json::Value::Bool(false));
    flow.meta.insert(
        crate::checks::META_RESPONSE_BODY_DECODED,
        serde_json::Value::Bool(false),
    );
    flow.meta.insert(record::STREAMED, serde_json::Value::Bool(true));
    let verdict = if control_plane {
        // No step runs for it, the record step included: its record waits for the answer's end.
        let mut rec = record::allow_record(&conn.shared.ctx, &flow);
        rec.status = cc_contracts::Maybe::Value(u64::from(site_status.as_u16()).into());
        flow.extensions.insert(record::Pending(rec));
        Verdict::Continue
    } else {
        conn.shared.pipeline.run(Hook::Response, &mut flow).await
    };
    let (resp, answered) = match verdict {
        Verdict::Continue | Verdict::Forward => match flow.response.take() {
            Some(r) => (r, false),
            None => return client(kill(conn, flow, "no response").await),
        },
        Verdict::Answer(resp) => (*resp, true),
        Verdict::Drop | Verdict::Kill(_) => return client(kill(conn, flow, "Connection killed.").await),
    };
    // A step answered in the site's place, or changed the answer's status or wrote a body into
    // it: that is the answer, and the site's body is let go (never streamed under a head that is
    // not its own). Its record is written now, as the buffered path would.
    if answered || resp.status() != site_status || !resp.body().is_empty() {
        let mut resp = resp;
        if let Some(mut f) = finish_for(conn, &mut flow) {
            f.rec.status = cc_contracts::Maybe::Value(u64::from(resp.status().as_u16()).into());
            // A streamed upload may still be going: its bytes so far.
            f.write(resp.body().len() as u64, None);
        }
        if !answered {
            // The site's headers, kept by the step, described the site's body: they go with it.
            // The step's own is sent as it wrote it (`to_client` sets its length).
            let h = resp.headers_mut();
            for name in [
                header::CONTENT_ENCODING,
                header::CONTENT_RANGE,
                header::ETAG,
                header::LAST_MODIFIED,
                header::ACCEPT_RANGES,
            ] {
                h.remove(name);
            }
            h.remove("digest");
            h.remove("content-md5");
            h.remove("content-digest");
            h.remove("repr-digest");
            if resp.body().is_empty() {
                resp.headers_mut().remove(header::CONTENT_TYPE);
            }
        }
        return client(Ok(to_client(resp, version, head_only)));
    }
    let (mut parts, _) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.version = version;
    let done = finish_for(conn, &mut flow);
    let counted = Counted::new(body, Arc::new(std::sync::atomic::AtomicU64::new(0)), done);
    // An answer to a HEAD, a 204 or a 304 has no body, whatever its headers say, and the
    // agent's side never reads one. Read to its (empty) end all the same, so its connection goes
    // back to the pool and its record is written (not as cut off); a site that sends a body
    // anyway, or never ends it, is let go after a while (the record says so).
    let body = to_agent(counted, head_only || parts.status == 204 || parts.status == 304);
    Ok(Response::from_parts(parts, body))
}

/// A streamed answer's body for the agent. A bodiless one (`bodiless`) is read to its (empty) end
/// in the background instead, so its connection goes back to the pool and its record is written.
fn to_agent<B>(counted: Counted<B>, bodiless: bool) -> ClientBody
where
    B: http_body::Body<Data = Bytes, Error = upstream::BoxError> + Unpin + Send + Sync + 'static,
{
    if bodiless {
        tokio::spawn(async move {
            let _ = tokio::time::timeout(HEAD_DRAIN, counted.collect()).await;
        });
        return http_body_util::Empty::new().map_err(|never| match never {}).boxed();
    }
    counted.boxed()
}

/// How long a bodiless answer's (empty) body is read for, at most.
const HEAD_DRAIN: std::time::Duration = std::time::Duration::from_secs(30);

/// What a step can change in a request: compared before and after the request steps.
#[derive(PartialEq)]
pub(crate) struct RequestShape {
    method: http::Method,
    uri: http::Uri,
    headers: HeaderMap,
    body: Bytes,
}

impl RequestShape {
    /// The request as the agent sent it, before the request steps, to tell afterwards whether a
    /// step changed it (put a credential or a login in, or anything else): only an unchanged one
    /// may go on a connection in one of Chrome's static-RSA suites. Taken only for TLS (plain HTTP
    /// has no cipher), never for the control plane.
    pub(crate) fn before(conn: &Conn, flow: &Flow, control_plane: bool) -> Option<Self> {
        let r = flow.request.as_ref()?;
        let tls = conn.mode == Mode::Tls || r.uri().scheme_str() == Some("https");
        (tls && !control_plane).then(|| Self::of(r))
    }

    /// Whether the request is still as [`RequestShape::before`] saw it.
    pub(crate) fn unchanged(before: Option<Self>, flow: &Flow) -> bool {
        before.is_some_and(|b| flow.request.as_ref().is_some_and(|r| b == Self::of(r)))
    }

    fn of(r: &Request<Bytes>) -> Self {
        Self {
            method: r.method().clone(),
            uri: r.uri().clone(),
            headers: r.headers().clone(),
            body: r.body().clone(),
        }
    }
}

/// A request's head with no body, for the checks and the decisions made before its body is read.
fn head_of(parts: &http::request::Parts) -> Request<Bytes> {
    let mut head = Request::new(Bytes::new());
    *head.method_mut() = parts.method.clone();
    *head.uri_mut() = parts.uri.clone();
    *head.version_mut() = parts.version;
    *head.headers_mut() = parts.headers.clone();
    // hyper keeps the agent's header case here; it goes upstream as it came.
    *head.extensions_mut() = parts.extensions.clone();
    head
}

/// What a streamed answer writes when it ends: its record, with the bytes that went each way.
struct Finish {
    ctx: Arc<crate::net::Ctx>,
    rec: cc_contracts::traffic::TrafficRecord,
    started: std::time::Instant,
    up: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// A body passed through as it comes, its bytes counted; `done` writes the record when it ends
/// (or is dropped: the agent went away, the site broke off).
struct Counted<B> {
    inner: B,
    bytes: Arc<std::sync::atomic::AtomicU64>,
    done: Option<Finish>,
}

impl<B> Counted<B> {
    fn new(inner: B, bytes: Arc<std::sync::atomic::AtomicU64>, done: Option<Finish>) -> Self {
        Self { inner, bytes, done }
    }

    fn finish(&mut self, error: Option<String>) {
        let Some(f) = self.done.take() else { return };
        f.write(self.bytes.load(std::sync::atomic::Ordering::Relaxed), error);
    }
}

/// The record a streamed answer left waiting (`record::Pending`), ready to be written.
fn finish_for(conn: &Conn, flow: &mut Flow) -> Option<Finish> {
    let p = flow.extensions.remove::<record::Pending>()?;
    Some(Finish {
        ctx: conn.shared.ctx.clone(),
        rec: p.0,
        started: flow.started,
        up: flow.extensions.get::<record::UploadCount>().map(|s| s.0.clone()),
    })
}

impl Finish {
    /// The record, with the bytes that went each way so far.
    fn write(self, bytes_in: u64, error: Option<String>) {
        use std::sync::atomic::Ordering;
        let mut f = self;
        f.rec.extra.insert("bytes_in".into(), bytes_in.into());
        if let Some(up) = &f.up {
            f.rec
                .extra
                .insert("bytes_out".into(), up.load(Ordering::Relaxed).into());
        }
        f.rec.extra.insert(
            "duration_ms".into(),
            u64::try_from(f.started.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .into(),
        );
        if let Some(e) = error {
            f.rec
                .extra
                .insert("error".into(), crate::net::target::truncate(&e, 200).into());
        }
        f.ctx.log.append(&f.rec);
    }
}

impl<B> Drop for Counted<B> {
    /// Dropped before its end (the agent went away, the connection broke): recorded as cut off.
    fn drop(&mut self) {
        self.finish(Some("the answer was cut off before its end".into()));
    }
}

impl<B> http_body::Body for Counted<B>
where
    B: http_body::Body<Data = Bytes, Error = upstream::BoxError> + Unpin,
{
    type Data = Bytes;
    type Error = upstream::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, upstream::BoxError>>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    self.bytes
                        .fetch_add(d.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
                // A body of known length ends with its last frame: hyper does not poll it again.
                if self.inner.is_end_stream() {
                    self.finish(None);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                self.finish(Some(e.to_string()));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                self.finish(None);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// The control plane: held to its own name by the destination check, sent on with no rule, check
/// or swap, and no record (owner, 2026-10-28; it was passed through before). Allowed under the kill
/// switch. Over TLS on 443 only, as the passthrough it replaces: anything else is an ordinary
/// request. Marks the flow and says whether it is.
pub(crate) fn mark_control_plane(conn: &Conn, flow: &mut Flow) -> bool {
    let control_plane = backup::is_control_plane(conn, flow);
    if control_plane {
        flow.meta.insert("control_plane", serde_json::Value::Bool(true));
        flow.meta.insert("effect", "allow".into());
        flow.meta.insert("rule", backup::CONTROL_PLANE_RULE.into());
    }
    control_plane
}

/// A build without the checks fails closed: nothing is sent on unchecked. The record and the 403.
pub(crate) fn refuse_unchecked(conn: &Conn, flow: &mut Flow) -> Response<Bytes> {
    let ctx = &conn.shared.ctx;
    flow.meta.insert("effect", "block".into());
    flow.meta.insert("rule", CHECKS_MISSING.into());
    let mut rec = record::http_record(ctx, flow, "block");
    rec.status = cc_contracts::Maybe::Value(403u64.into());
    record::log_once(ctx, flow, &rec);
    let host = record::record_host(flow);
    answer::json(
        StatusCode::FORBIDDEN,
        &serde_json::json!({"error": CHECKS_MISSING, "host": host, "tenant": ctx.config.tenant}),
    )
}

/// addon.py `server_connect`: a dial refused at the address is its own record (the control plane
/// and the backup store included); returns the flow's error, which says so.
pub(crate) fn record_refused(conn: &Conn, flow: &Flow, d: &Destination, why: &str) -> String {
    {
        let ctx = &conn.shared.ctx;
        let mut rec = ctx.record(flow, "block");
        rec.flow_id = cc_contracts::Maybe::Value(crate::log::non_routable_flow_id(&d.name, d.port));
        rec.host = cc_contracts::Maybe::Value(conn.sni.clone().unwrap_or_else(|| d.name.clone()));
        rec.port = cc_contracts::Maybe::Value(u64::from(d.port).into());
        rec.rule = cc_contracts::Maybe::Value(destination::NON_ROUTABLE_RULE.into());
        rec.extra
            .insert("error".into(), crate::net::target::truncate(why, 200).into());
        ctx.log.append(&rec);
    }
    format!("{NON_ROUTABLE_REFUSAL} {why}")
}

/// The record of a control-plane or backup request (addon.py `response` / `error` for a built-in):
/// the allow record, with the status the site gave or the error.
pub(crate) fn record_builtin(conn: &Conn, flow: &mut Flow, status: Option<StatusCode>, error: Option<&str>) {
    let ctx = &conn.shared.ctx;
    let mut rec = record::allow_record(ctx, flow);
    if let Some(s) = status {
        rec.status = cc_contracts::Maybe::Value(u64::from(s.as_u16()).into());
    }
    if let Some(e) = error {
        rec.extra
            .insert("error".into(), crate::net::target::truncate(e, 200).into());
    }
    record::log_once(ctx, flow, &rec);
}

/// Run the response steps and hand the agent the answer.
pub(crate) async fn respond(conn: &Conn, mut flow: Flow, version: Version, head_only: bool) -> Reply {
    decode_response(&mut flow);
    let verdict = if flow.meta.contains_key("control_plane") {
        let status = flow.response.as_ref().map(Response::status);
        record_builtin(conn, &mut flow, status, None);
        Verdict::Continue
    } else {
        conn.shared.pipeline.run(Hook::Response, &mut flow).await
    };
    match verdict {
        Verdict::Continue | Verdict::Forward => {}
        Verdict::Answer(resp) => flow.response = Some(*resp),
        Verdict::Drop | Verdict::Kill(_) => return kill(conn, flow, "Connection killed.").await,
    }
    let resp = flow
        .response
        .take()
        .unwrap_or_else(|| answer::mitmproxy_error(StatusCode::BAD_GATEWAY, "no response", version));
    Ok(to_client(resp, version, head_only))
}

/// The answer's body decoded in place for the response steps (W2's `META_BODY_DECODED`), its
/// size as it came kept for the record. At the response steps the flag says both bodies are
/// decoded; `cc_response_body_decoded` says it of the answer alone.
fn decode_response(flow: &mut Flow) {
    let Some(resp) = flow.response.as_mut() else { return };
    let raw = resp.body().len();
    let (mut parts, mut body) = std::mem::take(resp).into_parts();
    let ok = body::decode_in_place(&mut parts.headers, &mut body);
    *resp = Response::from_parts(parts, body);
    // A request no step read (streamed) does not hold the answer's steps back: they read the
    // answer, and `checks::request_body_ready` refuses its own body.
    let request_ok = flow.meta.get(crate::checks::META_BODY_DECODED) == Some(&serde_json::Value::Bool(true))
        || flow.meta.get(crate::checks::META_REQUEST_STREAMED) == Some(&serde_json::Value::Bool(true));
    flow.meta.insert(
        crate::checks::META_BODY_DECODED,
        serde_json::Value::Bool(request_ok && ok),
    );
    flow.meta
        .insert(crate::checks::META_RESPONSE_BODY_DECODED, serde_json::Value::Bool(ok));
    let request = flow.extensions.get::<record::RawLen>().map_or(0, |r| r.request);
    flow.extensions.insert(record::RawLen {
        request,
        response: Some(raw),
    });
}

/// No answer from the site: the error steps run, the agent gets mitmproxy's 502 page.
pub(crate) async fn failed(conn: &Conn, mut flow: Flow, msg: String, version: Version, head_only: bool) -> Reply {
    flow.error = Some(msg.clone());
    if flow.meta.contains_key("control_plane") {
        // No step runs for it: its record, with the error (addon.py `error`), unless the address
        // check refused the dial, which wrote its own block record.
        if !msg.starts_with(NON_ROUTABLE_REFUSAL) {
            record_builtin(conn, &mut flow, None, Some(&msg));
        }
    } else {
        conn.shared.pipeline.run(Hook::Error, &mut flow).await;
    }
    Ok(to_client(
        answer::mitmproxy_error(StatusCode::BAD_GATEWAY, &msg, version),
        version,
        head_only,
    ))
}

/// A step killed the flow: the error steps run, then the connection (or h2 stream) is closed.
pub(crate) async fn kill(conn: &Conn, mut flow: Flow, msg: &str) -> Reply {
    // An exit chosen for this flow and never used: its credential goes with it.
    crate::residential::take_exit(&mut flow);
    flow.error = Some(msg.to_owned());
    if !flow.meta.contains_key("control_plane") {
        conn.shared.pipeline.run(Hook::Error, &mut flow).await;
    }
    Err(Killed(msg.to_owned()))
}

/// An answer given before any check runs.
pub(crate) enum Early {
    /// addon.py `_refuse_non_routable_http`.
    NonRoutable { host: String, port: u16, why: String },
    /// The request names another host than the tunnel's TLS name (#511 `_one_destination`).
    Misdirected {
        host: String,
        reason: String,
        status: StatusCode,
    },
}

impl Early {
    pub(crate) fn into_response(self, conn: &Conn, flow: &mut Flow) -> Response<Bytes> {
        let ctx = &conn.shared.ctx;
        let tenant = ctx.config.tenant.clone();
        match self {
            Early::NonRoutable { host, port, why } => {
                flow.meta.insert("effect", "block".into());
                flow.meta.insert("rule", destination::NON_ROUTABLE_RULE.into());
                let mut rec = record::http_record(ctx, flow, "block");
                rec.status = cc_contracts::Maybe::Value(403u64.into());
                rec.port = cc_contracts::Maybe::Value(u64::from(port).into());
                rec.extra
                    .insert("error".into(), crate::net::target::truncate(&why, 200).into());
                record::log_once(ctx, flow, &rec);
                tracing::warn!("[mitm] refused {host}:{port}: {why}");
                answer::json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({"error": "non_routable_target", "host": host, "reason": why, "tenant": tenant}),
                )
            }
            Early::Misdirected { host, reason, status } => {
                // 421: what an h2 client that reused a connection for another origin needs to retry
                // on one of its own.
                flow.meta.insert("effect", "block".into());
                flow.meta.insert("rule", destination::DESTINATION_RULE.into());
                let mut rec = record::http_record(ctx, flow, "block");
                rec.host = cc_contracts::Maybe::Value(host.clone());
                rec.status = cc_contracts::Maybe::Value(u64::from(status.as_u16()).into());
                rec.extra
                    .insert("error".into(), crate::net::target::truncate(&reason, 200).into());
                record::log_once(ctx, flow, &rec);
                tracing::warn!("[mitm] refused {host}: {reason}");
                answer::json(
                    status,
                    &serde_json::json!({"error": destination::DESTINATION_RULE, "host": host, "reason": reason, "tenant": tenant}),
                )
            }
        }
    }
}

/// Where this request goes, checked: the tunnel's destination (and the request must name it), or
/// for plain HTTP the host the request names.
pub(crate) async fn check_destination(conn: &Conn, flow: &Flow) -> Result<Destination, Early> {
    let config = &conn.shared.ctx.config;
    // More than one Host: the checks would read one and the site might route on another.
    if let Some(req) = flow.request.as_ref()
        && req.headers().get_all(header::HOST).iter().count() > 1
    {
        return Err(Early::Misdirected {
            host: raw_host(req).unwrap_or_default(),
            reason: "the request names more than one host".into(),
            status: StatusCode::BAD_REQUEST,
        });
    }
    let refused = |host: String, port: u16, r: Refused| {
        if r.rule == destination::DESTINATION_RULE && r.error.starts_with("the TLS name is") {
            Early::Misdirected {
                host,
                reason: r.error,
                status: StatusCode::FORBIDDEN,
            }
        } else {
            Early::NonRoutable {
                host,
                port,
                why: r.error,
            }
        }
    };
    if conn.mode != Mode::Absolute
        && let Some(why) = conn
            .connect_refused
            .get_or_init(|| async { destination::connect_refusal(flow, config) })
            .await
            .clone()
    {
        return Err(Early::NonRoutable {
            host: conn.connect.host.clone(),
            port: conn.connect.port,
            why,
        });
    }
    match conn.mode {
        Mode::Tls => {
            // One resolution at a time for the connection: the first request resolves, the
            // others wait for it and use what it found.
            let d = conn
                .tunnel
                .get(|| {
                    let (stand_in, ctx) = (lookup_flow(flow), conn.shared.ctx.clone());
                    async move { destination::intercepted(&stand_in, &ctx.config).await }.boxed()
                })
                .await;
            let host = conn.sni.clone().unwrap_or_else(|| conn.connect.host.clone());
            let d = d.map_err(|r| refused(host, conn.connect.port, r))?;
            // The URI authority and the Host header are both sent on: each must name the tunnel's host.
            let claimed = flow.request.as_ref().and_then(|r| {
                [raw_uri_authority(r), raw_host(r)]
                    .into_iter()
                    .flatten()
                    .find(|h| !destination::host_agrees(&d, Some(h)))
            });
            if claimed.is_some() {
                let host = claimed.unwrap_or_default();
                let shown = destination::wire_name(&host).unwrap_or_else(|| host.clone());
                let reason = format!(
                    "the TLS name is {} but the request is for {}",
                    crate::net::target::truncate(&d.name, 80),
                    crate::net::target::truncate(&shown, 80)
                );
                return Err(Early::Misdirected {
                    host: shown,
                    reason,
                    status: StatusCode::MISDIRECTED_REQUEST,
                });
            }
            Ok(d)
        }
        Mode::PlainTunnel | Mode::Absolute => {
            let req = flow.request.as_ref().ok_or_else(|| Early::NonRoutable {
                host: String::new(),
                port: 0,
                why: "no request".into(),
            })?;
            let named = plain_host(req).map_err(|(uri, host)| {
                let shown = destination::wire_name(&host).unwrap_or_else(|| host.clone());
                Early::Misdirected {
                    reason: format!(
                        "the request was sent to {} but is for {}",
                        crate::net::target::truncate(&uri, 80),
                        crate::net::target::truncate(&shown, 80)
                    ),
                    host: shown,
                    status: StatusCode::FORBIDDEN,
                }
            })?;
            let (host, port) = if conn.mode == Mode::PlainTunnel {
                // The port the agent connected to; the name the request gives.
                let host = named
                    .as_deref()
                    .and_then(destination::wire_name)
                    .unwrap_or_else(|| conn.connect.host.clone());
                (host, conn.connect.port)
            } else {
                let uri = req.uri();
                let default = if uri.scheme_str() == Some("https") { 443 } else { 80 };
                (uri.host().unwrap_or("").to_owned(), uri.port_u16().unwrap_or(default))
            };
            // One resolution per name for the connection, as a TLS tunnel has one.
            let key = (host.clone(), port);
            let one = {
                let mut map = conn.plain.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match map.get(&key) {
                    Some(one) => Some(one.clone()),
                    None if map.len() < 64 => Some(map.entry(key).or_default().clone()),
                    None => None,
                }
            };
            let d = match one {
                Some(one) => {
                    let d = one
                        .get(|| {
                            let (stand_in, ctx, h) = (lookup_flow(flow), conn.shared.ctx.clone(), host.clone());
                            async move { destination::plain(&stand_in, &h, port, &ctx.config).await }.boxed()
                        })
                        .await;
                    // Only names that resolved count toward the 64: a slot left empty goes.
                    if one.is_empty() {
                        let mut map = conn.plain.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        if map.get(&(host.clone(), port)).is_some_and(|o| Arc::ptr_eq(o, &one)) {
                            map.remove(&(host.clone(), port));
                        }
                    }
                    d
                }
                // Past 64 names on one connection: looked up each time, nothing more kept.
                None => destination::plain(flow, &host, port, config).await,
            };
            d.map_err(|r| refused(host, port, r))
        }
    }
}

/// The host a request's URI names (h2 `:authority`, absolute form), as it sent it.
pub(crate) fn raw_uri_authority<B>(req: &Request<B>) -> Option<String> {
    req.uri().authority().map(|a| a.as_str().to_owned())
}

/// The Host header, as it sent it.
pub(crate) fn raw_host<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned())
}

/// For plain HTTP, the one host a request names: its URI authority and its Host header must agree
/// (each goes on to the site, and a shared host would route on the header). `Err` names the two.
fn plain_host<B>(req: &Request<B>) -> Result<Option<String>, (String, String)> {
    let (uri, host) = (raw_uri_authority(req), raw_host(req));
    match (uri, host) {
        (Some(u), Some(h)) if destination::wire_name(&u) != destination::wire_name(&h) => Err((u, h)),
        (Some(u), _) => Ok(Some(u)),
        (None, h) => Ok(h),
    }
}

/// A destination with an address to dial (not a name left for the dial to resolve).
fn resolved(d: &Destination) -> bool {
    d.addr.is_some()
}

type Lookup =
    futures_util::future::Shared<futures_util::future::BoxFuture<'static, Result<Destination, destination::Refused>>>;

/// One destination lookup shared by every request that needs it: the first starts it, the others
/// await the same lookup, and no lock is held while it runs. A destination that resolved is kept;
/// anything else is let go, so the next request looks again.
#[derive(Default)]
struct OneLookup(std::sync::Mutex<Slot>);

#[derive(Default)]
enum Slot {
    #[default]
    Empty,
    Running(Lookup),
    Done(Destination),
}

impl OneLookup {
    /// A destination already checked (the tunnel's, checked before the agent's handshake).
    fn set(&self, d: Destination) {
        *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Slot::Done(d);
    }

    /// Nothing kept and nothing running.
    fn is_empty(&self) -> bool {
        matches!(
            *self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            Slot::Empty
        )
    }

    async fn get(
        &self,
        start: impl FnOnce() -> futures_util::future::BoxFuture<'static, Result<Destination, destination::Refused>>,
    ) -> Result<Destination, destination::Refused> {
        let running = {
            let mut slot = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*slot {
                Slot::Done(d) => return Ok(d.clone()),
                Slot::Running(f) => f.clone(),
                Slot::Empty => {
                    let f = start().shared();
                    *slot = Slot::Running(f.clone());
                    f
                }
            }
        };
        let d = running.clone().await;
        let mut slot = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only this lookup's own slot: a newer one may have started after a failure.
        if matches!(&*slot, Slot::Running(f) if f.ptr_eq(&running)) {
            *slot = match &d {
                Ok(ok) if resolved(ok) => Slot::Done(ok.clone()),
                _ => Slot::Empty,
            };
        }
        d
    }
}

/// What a destination lookup reads of the flow (the TLS name, the CONNECT target), owned, so the
/// lookup can outlive the request that started it.
fn lookup_flow(flow: &Flow) -> Flow {
    let mut f = Flow::new(flow.client_ip, flow.connect.clone());
    f.sni = flow.sni.clone();
    f.vm_id = flow.vm_id.clone();
    f
}

pub(crate) fn is_upgrade<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(header::UPGRADE)
        && req
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .any(|v| v.to_str().is_ok_and(|s| s.to_ascii_lowercase().contains("upgrade")))
}

/// What the site is asked for as its authority: the one the request named (it agrees with the
/// destination), else the destination's name with its port when it is not the default.
fn authority_of(req: &Request<Bytes>, d: &Destination) -> String {
    authority_of_head(req.headers(), req.uri(), d)
}

/// [`authority_of`] from a request's head alone.
pub(crate) fn authority_of_head(headers: &HeaderMap, uri: &http::Uri, d: &Destination) -> String {
    uri.authority()
        .map(|a| a.as_str().to_owned())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| {
            if d.port == 443 || d.port == 80 {
                d.name.clone()
            } else {
                format!("{}:{}", d.name, d.port)
            }
        })
}

fn clone_request(req: &Request<Bytes>) -> Request<Bytes> {
    let mut out = Request::new(req.body().clone());
    *out.method_mut() = req.method().clone();
    *out.uri_mut() = req.uri().clone();
    *out.version_mut() = req.version();
    *out.headers_mut() = req.headers().clone();
    // hyper keeps the agent's header case here; it goes upstream as it came.
    *out.extensions_mut() = req.extensions().clone();
    out
}

/// The headers that belong to one connection, never forwarded across a version change.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

pub(crate) fn strip_hop_by_hop(h: &mut HeaderMap) {
    // Names a `Connection` header lists are hop-by-hop too.
    let listed: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in listed {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
    if h.get(header::TE).is_some_and(|v| v != "trailers") {
        h.remove(header::TE);
    }
}

/// The request as the site gets it, for the protocol of the connection it goes on.
/// An HTTP/1.1 request as the site gets it: origin-form, a Host, and none of the agent's
/// connection headers (they were for its connection to us, not ours to the site).
pub(crate) fn to_origin_h1<B>(req: &mut Request<B>, authority: &str) {
    let pq = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
    if let Ok(uri) = pq.parse() {
        *req.uri_mut() = uri;
    }
    if !req.headers().contains_key(header::HOST)
        && let Ok(v) = HeaderValue::from_str(authority)
    {
        req.headers_mut().insert(header::HOST, v);
    }
    // h2 sends each cookie as its own field; HTTP/1.1 wants them as one, joined by "; " (RFC 9113
    // §8.2.3), and many servers read only the first.
    let cookies: Vec<String> = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    if cookies.len() > 1
        && let Ok(v) = HeaderValue::from_str(&cookies.join("; "))
    {
        req.headers_mut().insert(header::COOKIE, v);
    }
    strip_hop_by_hop(req.headers_mut());
    *req.version_mut() = Version::HTTP_11;
}

/// A request as the site gets it: the authority as checked, the hop-by-hop headers gone, on the
/// protocol the connection speaks, with the body (and its trailers) as buffered.
fn upstream_request(req: Request<Bytes>, authority: &str, tls: bool, h2: bool) -> Request<Buffered> {
    let len = req.body().len();
    let head = upstream_head(&req, authority, tls, h2, Some(len));
    let trailers = req.extensions().get::<Trailers>().map(|t| t.0.clone());
    head.map(|()| Buffered::new(req.into_body(), trailers))
}

/// The head of a request as the site gets it (see [`upstream_request`]). `length`: a buffered
/// body's, set on it; `None` for a streamed body, whose framing stays the agent's (none: chunked
/// on HTTP/1.1).
fn upstream_head(req: &Request<Bytes>, authority: &str, tls: bool, h2: bool, length: Option<usize>) -> Request<()> {
    let mut head = Request::new(());
    *head.method_mut() = req.method().clone();
    *head.uri_mut() = req.uri().clone();
    *head.version_mut() = req.version();
    *head.headers_mut() = req.headers().clone();
    // hyper keeps the agent's header case here; it goes upstream as it came.
    *head.extensions_mut() = req.extensions().clone();
    head.extensions_mut().remove::<Trailers>();
    let pq = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
    let scheme = if tls { "https" } else { "http" };
    if h2 {
        if let Ok(uri) = format!("{scheme}://{authority}{pq}").parse() {
            *head.uri_mut() = uri;
        }
        strip_hop_by_hop(head.headers_mut());
        head.headers_mut().remove(header::HOST);
        *head.version_mut() = Version::HTTP_2;
    } else {
        to_origin_h1(&mut head, authority);
    }
    if let Some(len) = length {
        fix_content_length(head.headers_mut(), len, false);
    }
    head
}

/// The answer as the agent gets it, on the protocol it asked with.
pub(crate) fn to_client(resp: Response<Bytes>, version: Version, head_only: bool) -> Response<Buffered> {
    let (mut parts, body) = resp.into_parts();
    // Every time, not only across versions: the site's connection headers (`Connection: close`,
    // `Transfer-Encoding: chunked`) were for its connection to us, and the body is now whole.
    // mitmproxy's own error page closes the agent's connection: that `Connection: close` stays.
    let close = parts.extensions.get::<answer::ProxyMade>().is_some()
        && version != Version::HTTP_2
        && parts.headers.get(header::CONNECTION).is_some_and(|v| v == "close");
    strip_hop_by_hop(&mut parts.headers);
    if close {
        parts
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    parts.version = version;
    let bodyless = head_only || parts.status.is_informational() || parts.status == 204 || parts.status == 304;
    if !bodyless {
        fix_content_length(&mut parts.headers, body.len(), false);
        let trailers = parts.extensions.remove::<Trailers>().map(|t| t.0);
        return Response::from_parts(parts, Buffered::new(body, trailers));
    }
    // No body on the wire, whatever was buffered: an answer the proxy made itself (a 403 to a
    // HEAD) would otherwise put bytes where a keep-alive client expects the next response. A HEAD
    // keeps the length the same GET would have: the site's, or the proxy's own body's.
    if head_only && !body.is_empty() {
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    Response::from_parts(parts, Buffered::empty())
}

/// A buffered body whose length a step changed gets its `content-length` put right (mitmproxy does
/// this when `.content` is set). A bodiless answer keeps what the site said.
fn fix_content_length(h: &mut HeaderMap, len: usize, bodiless: bool) {
    if bodiless {
        return;
    }
    if h.contains_key(header::TRANSFER_ENCODING) {
        return;
    }
    if let Some(v) = h.get(header::CONTENT_LENGTH)
        && v.to_str().ok().and_then(|s| s.trim().parse::<usize>().ok()) == Some(len)
    {
        return;
    }
    if h.contains_key(header::CONTENT_LENGTH) || len > 0 {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    }
}

/// For an `Infallible` service where one is needed.
pub type Never = Infallible;

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain-HTTP site on this machine's own address: `GET /bytes/<n>` sends n bytes, a POST
    /// answers with how many bytes it got.
    async fn byte_site(ip: std::net::IpAddr) -> std::io::Result<std::net::SocketAddr> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let site = tokio::net::TcpListener::bind((ip, 0)).await?;
        let addr = site.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = site.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if s.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let head = String::from_utf8_lossy(&head).to_string();
                    let len: u64 = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().to_owned())
                        })
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if head.split_whitespace().nth(1) == Some("/status/204") {
                        let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                        return;
                    }
                    if let Some(n) = head.split_whitespace().nth(1).and_then(|p| p.strip_prefix("/bytes/")) {
                        let n: usize = n.parse().unwrap_or(0);
                        let _ = s
                            .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").as_bytes())
                            .await;
                        let chunk = vec![0u8; 1 << 20];
                        let mut left = n;
                        while left > 0 {
                            let k = left.min(chunk.len());
                            if s.write_all(&chunk[..k]).await.is_err() {
                                return;
                            }
                            left -= k;
                        }
                    } else {
                        let mut got = 0u64;
                        let mut buf = vec![0u8; 1 << 16];
                        while got < len {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(k) => got += k as u64,
                            }
                        }
                        let body = got.to_string();
                        let _ = s
                            .write_all(
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes(),
                            )
                            .await;
                    }
                });
            }
        });
        Ok(addr)
    }

    /// This machine's own non-loopback address (the address check refuses loopback sites).
    fn site_ip() -> Option<std::net::IpAddr> {
        std::net::UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
            s.connect("192.0.2.1:9").ok()?;
            Some(s.local_addr().ok()?.ip()).filter(|ip| !ip.is_loopback())
        })
    }

    /// A proxy without W2's checks, `big.test` resolving to `site`, with the response record and
    /// what `steps` adds: its address and the folder its record is written in.
    async fn stream_proxy(
        site: std::net::SocketAddr,
        name: &str,
        steps: impl FnOnce(&mut crate::flow::Pipeline, Arc<crate::net::Ctx>),
    ) -> Result<(std::net::SocketAddr, std::path::PathBuf), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("cc-proxy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("rules.json"), "[]")?;
        let vars: std::collections::HashMap<String, String> = [
            ("MITM_RULES_PATH", dir.join("rules.json").display().to_string()),
            ("MITM_LOG_FILE", dir.join("traffic.jsonl").display().to_string()),
            ("MITM_DEV_RESOLVE", format!("big.test={site}")),
            ("MITM_DEV_WITHOUT_CHECKS", "1".into()),
            ("MITM_ALLOW_DEV_FLAGS", "1".into()),
            ("MITM_CA_DIR", "/nonexistent".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let config = crate::config::Config::from_vars("127.0.0.1:0".parse()?, &vars)?;
        let ctx = Arc::new(crate::net::Ctx::new(config.clone()));
        let mut pipeline = crate::flow::Pipeline::new();
        pipeline.push(
            crate::flow::order::RESPONSE_LOG,
            Arc::new(record::ResponseRecord(ctx.clone())),
        );
        steps(&mut pipeline, ctx);
        let shared = Arc::new(crate::net::Shared::new(config, pipeline));
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = proxy.local_addr()?;
        tokio::spawn(crate::net::serve(proxy, shared));
        Ok((addr, dir))
    }

    /// One request over its own connection (`Connection: close`), the whole answer back.
    async fn exchange(proxy: std::net::SocketAddr, request: &str) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(proxy).await?;
        s.write_all(request.as_bytes()).await?;
        let mut answer = Vec::new();
        s.read_to_end(&mut answer).await?;
        Ok(String::from_utf8_lossy(&answer).into_owned())
    }

    /// A test step: whether it reads the body at each hook, what it saw at the response, and
    /// what it does to the answer there.
    struct Probe {
        reads_request: bool,
        reads_response: bool,
        rewrite: bool,
        saw: Arc<std::sync::Mutex<Option<(bool, bool)>>>,
    }

    impl crate::flow::Step for Probe {
        fn name(&self) -> &'static str {
            "probe"
        }
        fn hooks(&self) -> &'static [Hook] {
            &[Hook::Request, Hook::Response]
        }
        fn reads_body(&self, hook: Hook, _: &mut Flow) -> bool {
            if hook == Hook::Request {
                self.reads_request
            } else {
                self.reads_response
            }
        }
        fn run<'a>(&'a self, hook: Hook, flow: &'a mut Flow) -> crate::flow::StepFuture<'a> {
            Box::pin(async move {
                if hook == Hook::Response {
                    *self.saw.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some((crate::checks::body_ready(flow), crate::checks::request_body_ready(flow)));
                    if self.rewrite
                        && let Some(r) = flow.response.as_mut()
                    {
                        *r.status_mut() = StatusCode::FORBIDDEN;
                        *r.body_mut() = Bytes::from_static(b"refused");
                    }
                }
                Verdict::Continue
            })
        }
    }

    /// An upload no step reads and an answer one does: the answer's body is decoded for the
    /// response steps, and the request's own is reported as not there.
    #[tokio::test]
    async fn a_streamed_upload_does_not_hold_back_a_read_answer() -> Result<(), Box<dyn std::error::Error>> {
        let Some(ip) = site_ip() else {
            eprintln!("skipped: no non-loopback address");
            return Ok(());
        };
        let site = byte_site(ip).await?;
        let saw = Arc::new(std::sync::Mutex::new(None));
        let probe = Probe {
            reads_request: false,
            reads_response: true,
            rewrite: false,
            saw: saw.clone(),
        };
        let (proxy, _) = stream_proxy(site, "read-answer", |p, _| p.push(1, Arc::new(probe))).await?;
        let answer = exchange(
            proxy,
            "POST http://big.test/sink HTTP/1.1\r\nHost: big.test\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789",
        )
        .await?;
        assert!(answer.starts_with("HTTP/1.1 200") && answer.ends_with("10"), "{answer}");
        assert_eq!(
            *saw.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            Some((true, false))
        );
        Ok(())
    }

    /// A step that changes a streamed answer's status and writes its own body: the agent gets
    /// that, never the site's body under it, and the record has the step's status.
    #[tokio::test]
    async fn a_rewritten_streamed_answer_is_sent_as_the_step_wrote_it() -> Result<(), Box<dyn std::error::Error>> {
        let Some(ip) = site_ip() else {
            eprintln!("skipped: no non-loopback address");
            return Ok(());
        };
        let site = byte_site(ip).await?;
        let probe = Probe {
            reads_request: false,
            reads_response: false,
            rewrite: true,
            saw: Arc::default(),
        };
        // Before the record step: the record it leaves waiting for the stream is written at once.
        let (proxy, dir) = stream_proxy(site, "rewrite", |p, _| p.push(1, Arc::new(probe))).await?;
        let answer = exchange(
            proxy,
            "GET http://big.test/bytes/5000 HTTP/1.1\r\nHost: big.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
        assert!(answer.ends_with("\r\n\r\nrefused"), "{answer}");
        assert!(answer.to_ascii_lowercase().contains("content-length: 7"), "{answer}");
        let mut recs = Vec::new();
        for _ in 0..100 {
            recs = std::fs::read_to_string(dir.join("traffic.jsonl"))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .collect();
            if !recs.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(recs[0]["status"], 403);
        assert_eq!(recs[0]["bytes_in"], 7);
        Ok(())
    }

    /// A 204 has no body: its record is written whole, not as an answer cut off before its end.
    #[tokio::test]
    async fn a_bodiless_answer_is_recorded_whole() -> Result<(), Box<dyn std::error::Error>> {
        let Some(ip) = site_ip() else {
            eprintln!("skipped: no non-loopback address");
            return Ok(());
        };
        let site = byte_site(ip).await?;
        let (proxy, dir) = stream_proxy(site, "bodiless", |_, _| {}).await?;
        let answer = exchange(
            proxy,
            "GET http://big.test/status/204 HTTP/1.1\r\nHost: big.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert!(answer.starts_with("HTTP/1.1 204"), "{answer}");
        let mut recs = Vec::new();
        for _ in 0..100 {
            recs = std::fs::read_to_string(dir.join("traffic.jsonl"))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .collect();
            if !recs.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(recs[0]["status"], 204);
        assert!(recs[0].get("error").is_none(), "{recs:?}");
        Ok(())
    }

    /// With only W1's steps (none of which reads these bodies), a download and an upload bigger
    /// than the buffer cap go through whole, and the record counts them as they went.
    #[tokio::test]
    async fn bodies_no_step_reads_stream_past_the_cap() -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Some(ip) = site_ip() else {
            eprintln!("skipped: no non-loopback address");
            return Ok(());
        };
        let site = byte_site(ip).await?;
        let (proxy_addr, dir) = stream_proxy(site, "stream", |_, _| {}).await?;

        const BIG: usize = MAX_BODY + 40_000_000;
        // A download: absolute form, the body read as it comes.
        let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;
        s.write_all(
            format!("GET http://big.test/bytes/{BIG} HTTP/1.1\r\nHost: big.test\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let mut got = 0usize;
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = s.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        assert!(got > BIG, "{got}");
        // An upload.
        let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;
        s.write_all(
            format!("POST http://big.test/sink HTTP/1.1\r\nHost: big.test\r\nContent-Length: {BIG}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let chunk = vec![b'x'; 1 << 20];
        let mut left = BIG;
        while left > 0 {
            let k = left.min(chunk.len());
            s.write_all(&chunk[..k]).await?;
            left -= k;
        }
        let mut answer = Vec::new();
        s.read_to_end(&mut answer).await?;
        assert!(
            String::from_utf8_lossy(&answer).ends_with(&BIG.to_string()),
            "{}",
            String::from_utf8_lossy(&answer)
        );
        // Two streamed uploads on one agent connection: the site closes after each answer, so the
        // second finds its pooled connection closed and goes again, body and all, on a new one.
        let mut s = tokio::net::TcpStream::connect(proxy_addr).await?;
        for (i, close) in [(1usize, ""), (2, "Connection: close\r\n")] {
            let n = 1_000_000 * i;
            let head =
                format!("POST http://big.test/sink HTTP/1.1\r\nHost: big.test\r\nContent-Length: {n}\r\n{close}\r\n");
            s.write_all(head.as_bytes()).await?;
            s.write_all(&vec![b'y'; n]).await?;
            let mut got = Vec::new();
            while !String::from_utf8_lossy(&got).ends_with(&n.to_string()) {
                let mut b = [0u8; 4096];
                let k = s.read(&mut b).await?;
                assert!(
                    k > 0,
                    "closed before the answer to upload {i}: {}",
                    String::from_utf8_lossy(&got)
                );
                got.extend_from_slice(&b[..k]);
            }
            assert!(
                String::from_utf8_lossy(&got).starts_with("HTTP/1.1 200"),
                "{}",
                String::from_utf8_lossy(&got)
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        // The records: written when each stream ended, with the bytes that went.
        let mut lines = Vec::new();
        for _ in 0..100 {
            lines = std::fs::read_to_string(dir.join("traffic.jsonl"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
            if lines.len() >= 4 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let recs: Vec<serde_json::Value> = lines.iter().filter_map(|l| serde_json::from_str(l).ok()).collect();
        assert_eq!(recs.len(), 4, "{lines:?}");
        assert_eq!(recs[0]["bytes_in"], BIG);
        assert_eq!(recs[1]["bytes_out"], BIG);
        assert_eq!(recs[3]["bytes_out"], 2_000_000);
        assert!(recs.iter().all(|r| r.get("error").is_none()), "{lines:?}");
        Ok(())
    }

    #[tokio::test]
    async fn one_lookup_is_shared_and_a_failure_is_tried_again() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let one = OneLookup::default();
        let start = |ok: bool| {
            let calls = calls.clone();
            move || {
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Ok(Destination {
                        name: "a.test".into(),
                        port: 443,
                        addr: ok.then(|| std::net::SocketAddr::from(([203, 0, 113, 1], 443))),
                    })
                }
                .boxed()
            }
        };
        // Unresolved: both waiters share one lookup, and nothing is kept.
        let (a, b) = tokio::join!(one.get(start(false)), one.get(start(false)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(a.is_ok_and(|d| d.addr.is_none()) && b.is_ok_and(|d| d.addr.is_none()));
        // Looked up again, resolved this time, and then kept.
        assert!(one.get(start(true)).await.is_ok_and(|d| d.addr.is_some()));
        assert!(one.get(start(true)).await.is_ok_and(|d| d.addr.is_some()));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn requests_change_shape_with_the_protocol() {
        let mut req = Request::new(Bytes::from_static(b"hello"));
        *req.uri_mut() = "/a?b=1".parse().expect("uri");
        req.headers_mut()
            .insert(header::HOST, HeaderValue::from_static("api.example.com"));
        req.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("keep-alive, x-gone"));
        req.headers_mut().insert("x-gone", HeaderValue::from_static("1"));
        let h2 = upstream_request(clone_request(&req), "api.example.com", true, true);
        assert_eq!(h2.uri().to_string(), "https://api.example.com/a?b=1");
        assert!(h2.headers().get(header::HOST).is_none());
        assert!(h2.headers().get("x-gone").is_none());
        assert_eq!(h2.headers()[header::CONTENT_LENGTH], "5");
        let h1 = upstream_request(req, "api.example.com", true, false);
        assert_eq!(h1.uri().to_string(), "/a?b=1");
        assert_eq!(h1.headers()[header::HOST], "api.example.com");
        assert_eq!(h1.version(), Version::HTTP_11);
    }

    #[test]
    fn bodiless_answers_carry_no_body() {
        let mut r = Response::new(Bytes::from_static(b"{\"error\": \"blocked_by_policy\"}"));
        *r.status_mut() = StatusCode::FORBIDDEN;
        let head = to_client(r.clone(), Version::HTTP_11, true);
        assert_eq!(hyper::body::Body::size_hint(head.body()).exact(), Some(0));
        assert_eq!(head.headers()[header::CONTENT_LENGTH], "30");
        let get = to_client(r, Version::HTTP_11, false);
        assert_eq!(hyper::body::Body::size_hint(get.body()).exact(), Some(30));
        let mut nc = Response::new(Bytes::from_static(b"x"));
        *nc.status_mut() = StatusCode::NOT_MODIFIED;
        assert_eq!(
            hyper::body::Body::size_hint(to_client(nc, Version::HTTP_11, false).body()).exact(),
            Some(0)
        );
    }

    #[test]
    fn connection_headers_never_cross_the_proxy() {
        let mut r = Response::new(Bytes::from_static(b"hello"));
        r.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close, x-hop"));
        r.headers_mut().insert("x-hop", HeaderValue::from_static("1"));
        r.headers_mut()
            .insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        let out = to_client(r, Version::HTTP_11, false);
        assert!(out.headers().get(header::CONNECTION).is_none());
        assert!(out.headers().get("x-hop").is_none());
        assert!(out.headers().get(header::TRANSFER_ENCODING).is_none());
        assert_eq!(out.headers()[header::CONTENT_LENGTH], "5");
        let mut q = Request::new(Bytes::from_static(b"abc"));
        *q.uri_mut() = "/x".parse().expect("uri");
        q.headers_mut()
            .insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        q.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        let up = upstream_request(q, "a.example", true, false);
        assert!(up.headers().get(header::TRANSFER_ENCODING).is_none());
        assert!(up.headers().get(header::CONNECTION).is_none());
        assert_eq!(up.headers()[header::CONTENT_LENGTH], "3");
    }

    #[test]
    fn the_proxys_error_page_keeps_connection_close() {
        let page = answer::mitmproxy_error(StatusCode::BAD_GATEWAY, "x", Version::HTTP_11);
        assert_eq!(
            to_client(page, Version::HTTP_11, false).headers()[header::CONNECTION],
            "close"
        );
        let page = answer::mitmproxy_error(StatusCode::BAD_GATEWAY, "x", Version::HTTP_2);
        assert!(
            to_client(page, Version::HTTP_2, false)
                .headers()
                .get(header::CONNECTION)
                .is_none()
        );
    }

    #[test]
    fn trailers_survive_the_buffer_and_cookies_are_joined() {
        use hyper::body::Body;
        let mut t = HeaderMap::new();
        t.insert("grpc-status", HeaderValue::from_static("0"));
        let mut r = Response::new(Bytes::from_static(b"msg"));
        r.extensions_mut().insert(Trailers(t));
        let mut out = to_client(r, Version::HTTP_2, false);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let body = std::pin::Pin::new(out.body_mut());
        let first = body.poll_frame(&mut cx);
        assert!(matches!(first, std::task::Poll::Ready(Some(Ok(ref f))) if f.is_data()));
        let second = std::pin::Pin::new(out.body_mut()).poll_frame(&mut cx);
        let std::task::Poll::Ready(Some(Ok(frame))) = second else {
            panic!("no trailers frame");
        };
        assert_eq!(
            frame.trailers_ref().map(|t| t["grpc-status"].clone()),
            Some(HeaderValue::from_static("0"))
        );
        assert!(out.body().is_end_stream());

        let mut q = Request::new(Bytes::new());
        *q.version_mut() = Version::HTTP_2;
        q.headers_mut().append(header::COOKIE, HeaderValue::from_static("a=1"));
        q.headers_mut().append(header::COOKIE, HeaderValue::from_static("b=2"));
        let up = upstream_request(q, "a.example", true, false);
        let cookies: Vec<_> = up.headers().get_all(header::COOKIE).iter().collect();
        assert_eq!(cookies, [HeaderValue::from_static("a=1; b=2")]);
    }

    #[test]
    fn content_length_follows_the_body() {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        fix_content_length(&mut h, 4, false);
        assert_eq!(h[header::CONTENT_LENGTH], "4");
        // A HEAD answer keeps the length of the body it did not send.
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("10"));
        fix_content_length(&mut h, 0, true);
        assert_eq!(h[header::CONTENT_LENGTH], "10");
        let mut h = HeaderMap::new();
        fix_content_length(&mut h, 0, false);
        assert!(h.get(header::CONTENT_LENGTH).is_none());
    }
}
