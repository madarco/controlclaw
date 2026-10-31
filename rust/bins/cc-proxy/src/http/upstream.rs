//! The connections the firewall opens to sites, one pool per agent connection (as mitmproxy keeps
//! its server connections per client connection), keyed by the destination's name, port, pinned
//! address and whether it is TLS. Only the checked address is dialled. Every TLS dial copies the
//! agent's own ClientHello (`tls::mirror`) and every HTTP/2 connection its preface (`h2up`). The
//! first connection of an intercepted tunnel is made before the agent's handshake ends, so the
//! agent gets the protocol the site chose (owner, 2026-10-28); the pool takes it over for the
//! first request (`Prepared`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;

use super::buffered::Buffered;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::h2up::{self, H2Error, H2Sender};
use crate::flow::Destination;
use crate::http::h2print::H2Print;
use crate::net::Ctx;
use crate::net::target::refusal;
use crate::tls::config::{H2, HTTP11};
use crate::tls::hello::Hello;

/// How long a dial (TCP and TLS) may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle HTTP/1 connections kept per key.
const IDLE_PER_KEY: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    name: String,
    port: u16,
    ip: IpAddr,
    tls: bool,
    /// The site chose one of Chrome's static-RSA suites (`tls::mirror::is_weak`): the connection
    /// carries only requests sent as the agent sent them.
    weak: bool,
}

impl Key {
    fn weak(&self) -> Key {
        Key {
            weak: true,
            ..self.clone()
        }
    }
}

enum Sender {
    H1(http1::SendRequest<UpBody>),
    H2(H2Sender),
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A request body as it goes to the site: a buffered one, or the agent's own streamed through.
pub type UpBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// A buffered body (with its trailers) as an [`UpBody`].
pub fn buffered(b: Buffered) -> UpBody {
    b.map_err(|never| match never {}).boxed_unsync()
}

/// The idle connections, by key.
#[derive(Default)]
struct Idle(Mutex<HashMap<Key, Vec<Sender>>>);

impl Idle {
    fn put_back(&self, key: Key, sender: Sender) {
        let mut idle = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.entry(key).or_default();
        match sender {
            Sender::H2(h) => {
                if h.is_open() && !list.iter().any(|s| matches!(s, Sender::H2(_))) {
                    list.push(Sender::H2(h));
                }
            }
            Sender::H1(h) => {
                if !h.is_closed() && list.len() < IDLE_PER_KEY {
                    list.push(Sender::H1(h));
                }
            }
        }
    }
}

/// The site's answer body, streamed from either protocol. An HTTP/1.1 connection goes back to the
/// pool when its body has been read to the end (not when it is dropped partway: it is then closed).
pub struct UpStream(Stream);

enum Stream {
    H1 {
        body: hyper::body::Incoming,
        back: Option<(Arc<Idle>, Key, http1::SendRequest<UpBody>)>,
    },
    H2(super::h2up::RecvBody),
}

impl http_body::Body for UpStream {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, BoxError>>> {
        match &mut self.get_mut().0 {
            Stream::H1 { body, back } => {
                let polled = std::pin::Pin::new(&mut *body).poll_frame(cx).map_err(Into::into);
                // Its end: no more frames, or the last one of a body of known length (which the
                // reader then does not poll again).
                let ended = matches!(polled, std::task::Poll::Ready(None))
                    || (matches!(polled, std::task::Poll::Ready(Some(Ok(_)))) && body.is_end_stream());
                if ended && let Some((idle, key, sender)) = back.take() {
                    idle.put_back(key, Sender::H1(sender));
                }
                polled
            }
            Stream::H2(b) => std::pin::Pin::new(b).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Stream::H1 { body, .. } => body.is_end_stream(),
            Stream::H2(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.0 {
            Stream::H1 { body, .. } => body.size_hint(),
            Stream::H2(b) => b.size_hint(),
        }
    }
}

/// What a request sends as its body, try after try.
pub enum Outgoing {
    /// Buffered (with its trailers): sent again as it is on a second try.
    Buffered(Bytes, Option<http::HeaderMap>),
    /// The agent's own, streamed through: sent once. A try that sent none of it gives it back
    /// ([`Outgoing::give_back`]), so a pooled connection the site had closed is tried again.
    Streamed(Option<UpBody>),
}

impl Outgoing {
    fn take(&mut self) -> Option<UpBody> {
        match self {
            Outgoing::Buffered(data, trailers) => Some(buffered(Buffered::new(data.clone(), trailers.clone()))),
            Outgoing::Streamed(body) => body.take(),
        }
    }

    fn give_back(&mut self, body: UpBody) {
        if let Outgoing::Streamed(slot) = self {
            *slot = Some(body);
        }
    }

    fn streamed(&self) -> bool {
        matches!(self, Outgoing::Streamed(_))
    }
}

/// The site's answer with its head in and its body still to come.
pub type AnswerHead = http::Response<UpStream>;

/// What an agent connection looks like, for the connections made on its behalf: its ClientHello
/// and, once read, the start of its HTTP/2 connection. Missing parts come from the built-in
/// profile (`tls::chrome`).
#[derive(Default)]
pub struct Fingerprint {
    pub hello: Option<Hello>,
    pub h2: std::sync::OnceLock<H2Print>,
}

impl Fingerprint {
    pub fn new(hello: Option<Hello>) -> Self {
        Self {
            hello,
            h2: std::sync::OnceLock::new(),
        }
    }

    pub fn hello(&self) -> &Hello {
        self.hello.as_ref().unwrap_or_else(|| crate::tls::chrome::hello())
    }

    /// The agent's HTTP/2 start; a request part it did not show (no request yet) is the profile's.
    pub fn h2(&self) -> H2Print {
        let profile = crate::tls::chrome::h2();
        match self.h2.get() {
            Some(p) if p.saw_headers => p.clone(),
            Some(p) => H2Print {
                pseudo_order: profile.pseudo_order.clone(),
                headers_priority: profile.headers_priority,
                ..p.clone()
            },
            None => profile.clone(),
        }
    }
}

/// A connection to the site made before the agent's handshake ended (upstream first).
pub struct Prepared {
    key: Key,
    io: Box<dyn Io>,
    h2: bool,
    made: std::time::Instant,
}

/// How long a connection made before the agent's handshake is kept for its first request. Sites
/// close idle connections (nginx after 60 s, many load balancers sooner); past this it is let go
/// and the request dials afresh.
const PREPARED_FOR: Duration = Duration::from_secs(20);

impl Prepared {
    /// Whether it is for `key` (ignoring how strong its cipher is), and usable for the request.
    fn fits(&self, key: &Key, allow_weak: bool) -> bool {
        self.key.weak() == key.weak() && (allow_weak || !self.key.weak)
    }

    /// The protocol the site chose: what the agent is offered.
    pub fn alpn(&self) -> &'static [u8] {
        if self.h2 { H2 } else { HTTP11 }
    }
}

/// Why a request got no answer from the site.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The address check refused the connection (addon.py `server_connect`): the record is written
    /// by the caller, and the flow's error carries `NON_ROUTABLE_REFUSAL`.
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Failed(String),
}

pub struct Pool {
    ctx: Arc<Ctx>,
    fingerprint: Arc<Fingerprint>,
    prepared: Mutex<Option<Prepared>>,
    idle: Arc<Idle>,
    dialing: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
}

/// What came back: the head and the whole body.
pub type Answer = http::Response<Bytes>;

impl Pool {
    pub fn new(ctx: Arc<Ctx>, fingerprint: Arc<Fingerprint>, prepared: Option<Prepared>) -> Self {
        Self {
            ctx,
            fingerprint,
            prepared: Mutex::new(prepared),
            idle: Arc::new(Idle::default()),
            dialing: Mutex::new(HashMap::new()),
        }
    }

    /// Send one request to `d` and return the answer once its head is in. `head(h2)` makes the
    /// request's head for the protocol the connection speaks (it may be asked twice: a pooled
    /// connection the site had closed is tried once more on a new one). `unchanged`: the request
    /// goes as the agent sent it, so a connection in one of Chrome's static-RSA suites may carry
    /// it; one a step changed (a credential, a login put in) never goes on such a connection.
    pub async fn send_head(
        &self,
        d: &Destination,
        tls: bool,
        head: impl Fn(bool) -> http::Request<()>,
        mut body: Outgoing,
        unchanged: bool,
    ) -> Result<AnswerHead, UpstreamError> {
        // A name left to the dial is resolved here, before the dial gate: a slow lookup holds up
        // only this request, never the others waiting on the gate.
        let (d, addr) = pin(d).await?;
        let d = &d;
        let key = Key {
            name: d.name.clone(),
            port: d.port,
            ip: addr.ip(),
            tls,
            weak: false,
        };
        if let Some((k, sender)) = self.checkout_for(&key, unchanged) {
            match self.send_on(k, sender, &head, &mut body).await {
                Err(Attempt::Unsent(_)) => {}
                other => return other.map_err(Attempt::into_error),
            }
        }
        // One dial per key at a time: parallel h2 streams wait for it and share the connection.
        let gate = {
            let mut dialing = self.dialing.lock().unwrap_or_else(PoisonError::into_inner);
            dialing.entry(key.clone()).or_default().clone()
        };
        let mut from_prepared = false;
        let (sent_key, sender) = {
            let _turn = gate.lock().await;
            match self.checkout_for(&key, unchanged) {
                Some(s) => s,
                None => {
                    from_prepared = self.has_prepared(&key, unchanged);
                    let (k, s) = match self.dial(d, tls, unchanged).await {
                        Ok(s) => s,
                        // The site closed the connection made early: once more, afresh.
                        Err(_) if from_prepared => {
                            from_prepared = false;
                            self.dial(d, tls, unchanged).await?
                        }
                        Err(e) => return Err(e),
                    };
                    if let Sender::H2(h) = &s {
                        self.put_back(k.clone(), Sender::H2(h.clone()));
                    }
                    (k, s)
                }
            }
        };
        {
            // Nobody else waiting on this key: its gate goes, so a long connection naming many
            // hosts does not keep one for each.
            let mut dialing = self.dialing.lock().unwrap_or_else(PoisonError::into_inner);
            if dialing.get(&key).is_some_and(|g| Arc::strong_count(g) <= 2) {
                dialing.remove(&key);
            }
        }
        drop(gate);
        match self.send_on(sent_key, sender, &head, &mut body).await {
            // The connection made early had been closed by the site before anything was sent on
            // it: once more on a new one.
            Err(Attempt::Unsent(_)) if from_prepared => {
                let (k, s) = self.dial(d, tls, unchanged).await?;
                self.send_on(k, s, &head, &mut body).await.map_err(Attempt::into_error)
            }
            other => other.map_err(Attempt::into_error),
        }
    }

    async fn send_on(
        &self,
        key: Key,
        sender: Sender,
        head: &impl Fn(bool) -> http::Request<()>,
        body: &mut Outgoing,
    ) -> Result<AnswerHead, Attempt> {
        let again = || Attempt::Sent(UpstreamError::Failed("the request's body was already sent once".into()));
        match sender {
            Sender::H2(s) => {
                let up = body.take().ok_or_else(again)?;
                let answer = s.send_head(head(true), up, ANSWER_TIMEOUT).await.map_err(|(e, back)| {
                    if let Some(b) = back {
                        body.give_back(b);
                    }
                    match e {
                        H2Error::Unsent(m) => Attempt::Unsent(UpstreamError::Failed(m)),
                        H2Error::Sent(m) => Attempt::Sent(UpstreamError::Failed(m)),
                    }
                });
                self.put_back(key, Sender::H2(s));
                answer.map(|r| r.map(|b| UpStream(Stream::H2(b))))
            }
            Sender::H1(mut s) => {
                s.ready().await.map_err(Attempt::unsent)?;
                let up = body.take().ok_or_else(again)?;
                let req = head(false).map(|()| up);
                let resp = match tokio::time::timeout(ANSWER_TIMEOUT, s.try_send_request(req)).await {
                    Err(_) => {
                        return Err(Attempt::Sent(UpstreamError::Failed(
                            "the site did not answer in time".into(),
                        )));
                    }
                    Ok(Ok(r)) => r,
                    Ok(Err(mut e)) => {
                        // hyper hands back a request it did not send (a connection the site had
                        // closed): its body goes out on a new one.
                        if let Some(req) = e.take_message() {
                            body.give_back(req.into_body());
                            return Err(Attempt::unsent(e.into_error()));
                        }
                        let e = e.into_error();
                        return Err(if (e.is_canceled() || e.is_closed()) && !body.streamed() {
                            Attempt::unsent(e)
                        } else {
                            Attempt::Sent(UpstreamError::Failed(describe(&e)))
                        });
                    }
                };
                // Back in the pool once its answer's body has been read to the end; until then
                // other requests dial their own (a streamed download does not hold them up). Not
                // after a streamed upload: it may still be going when the answer ends.
                let back = (!body.streamed()).then(|| (self.idle.clone(), key, s));
                Ok(resp.map(|body| UpStream(Stream::H1 { body, back })))
            }
        }
    }

    fn checkout(&self, key: &Key) -> Option<Sender> {
        let mut idle = self.idle.0.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.get_mut(key)?;
        while let Some(s) = list.pop() {
            match s {
                Sender::H2(h) if h.is_open() => {
                    // Multiplexed: it stays in the pool for the next request too.
                    list.push(Sender::H2(h.clone()));
                    return Some(Sender::H2(h));
                }
                Sender::H1(h) if !h.is_closed() => return Some(Sender::H1(h)),
                _ => {}
            }
        }
        None
    }

    /// An idle connection for `key`: one in an allowed cipher, or (for a request sent unchanged)
    /// one in a static-RSA suite. With the key it is pooled under.
    fn checkout_for(&self, key: &Key, unchanged: bool) -> Option<(Key, Sender)> {
        if let Some(s) = self.checkout(key) {
            return Some((key.clone(), s));
        }
        let weak = key.weak();
        unchanged.then(|| self.checkout(&weak).map(|s| (weak, s))).flatten()
    }

    fn put_back(&self, key: Key, sender: Sender) {
        self.idle.put_back(key, sender);
    }

    /// A new connection, with the key it is pooled under (weak or not).
    async fn dial(&self, d: &Destination, tls: bool, allow_weak: bool) -> Result<(Key, Sender), UpstreamError> {
        let (key, io, h2) = self.connect(d, tls, None, allow_weak).await?;
        if h2 {
            let sender = h2up::handshake(io, &self.fingerprint.h2())
                .await
                .map_err(UpstreamError::Failed)?;
            return Ok((key, Sender::H2(sender)));
        }
        Ok((key, handshake_h1(io).await?))
    }

    /// The connection made before the agent's handshake, when it is for `key` (and is HTTP/1.1
    /// when `h1_only`, and in an allowed cipher unless `allow_weak`).
    fn take_prepared(&self, key: &Key, h1_only: bool, allow_weak: bool) -> Option<(Key, Box<dyn Io>, bool)> {
        let mut slot = self.prepared.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_some_and(|p| p.made.elapsed() > PREPARED_FOR) {
            *slot = None;
        }
        if slot
            .as_ref()
            .is_some_and(|p| p.fits(key, allow_weak) && !(h1_only && p.h2))
        {
            return slot.take().map(|p| (p.key, p.io, p.h2));
        }
        None
    }

    /// Whether a connection made before the agent's handshake is waiting for `key`.
    fn has_prepared(&self, key: &Key, allow_weak: bool) -> bool {
        self.prepared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|p| p.fits(key, allow_weak))
    }

    /// The checked address, connected (and TLS with the destination's name). The pinned address
    /// is checked again: nothing reaches a link-local or loopback address, whatever led here.
    /// `alpn` replaces the agent's ALPN list (HTTP/1.1 only, for an upgrade or a streamed request).
    async fn connect(
        &self,
        d: &Destination,
        tls: bool,
        alpn: Option<&[Vec<u8>]>,
        allow_weak: bool,
    ) -> Result<(Key, Box<dyn Io>, bool), UpstreamError> {
        let pinned = pin(d).await?;
        let mut key = Key {
            name: pinned.0.name.clone(),
            port: pinned.0.port,
            ip: pinned.1.ip(),
            tls,
            weak: false,
        };
        if let Some(io) = self.take_prepared(&key, alpn.is_some(), allow_weak) {
            return Ok(io);
        }
        let (io, h2, weak) = dial_io(&self.ctx, self.fingerprint.hello(), &pinned, tls, alpn, allow_weak).await?;
        key.weak = weak;
        Ok((key, io, h2))
    }
}

/// Make the first connection of an intercepted tunnel, before the agent's handshake ends: the
/// agent is then offered the protocol the site chose.
pub async fn prepare(ctx: &Ctx, hello: &Hello, d: &Destination) -> Result<Prepared, UpstreamError> {
    let pinned = pin(d).await?;
    // Before any request is known: a static-RSA suite is taken, and the connection is used only
    // for a request sent unchanged.
    let (io, h2, weak) = dial_io(ctx, hello, &pinned, true, None, true).await?;
    let key = Key {
        name: pinned.0.name.clone(),
        port: pinned.0.port,
        ip: pinned.1.ip(),
        tls: true,
        weak,
    };
    Ok(Prepared {
        key,
        io,
        h2,
        made: std::time::Instant::now(),
    })
}

/// The checked address, connected (and TLS with the destination's name, copying `hello`). The
/// pinned address is checked again: nothing reaches a link-local or loopback address, whatever led
/// here.
async fn dial_io(
    ctx: &Ctx,
    hello: &Hello,
    pinned: &(Destination, std::net::SocketAddr),
    tls: bool,
    alpn: Option<&[Vec<u8>]>,
    allow_weak: bool,
) -> Result<(Box<dyn Io>, bool, bool), UpstreamError> {
    {
        let (d, addr) = (&pinned.0, pinned.1);
        // A name `MITM_DEV_RESOLVE` points at a test address (smoke rigs only) may be this machine's
        // own; non-routable addresses are refused even then.
        let dev = ctx.config.dev_resolve.contains_key(&d.name);
        if dev {
            if let Some(kind) = crate::net::target::non_routable_kind(addr.ip()) {
                return Err(UpstreamError::Refused(format!("{} is a {kind} address", addr.ip())));
            }
        } else if let Some(why) = refusal(addr.ip(), &addr.ip().to_string()) {
            return Err(UpstreamError::Refused(why));
        }
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| UpstreamError::Failed(format!("connecting to {addr} timed out")))?
            .map_err(|e| UpstreamError::Failed(format!("Connect call failed {addr}: {e}")))?;
        let _ = tcp.set_nodelay(true);
        if !tls {
            return Ok((Box::new(tcp), false, false));
        }
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            ctx.mirror.connect(hello, alpn, &d.name, tcp, allow_weak),
        )
        .await
        .map_err(|_| UpstreamError::Failed(format!("TLS handshake with {} timed out", d.name)))?
        .map_err(|e| UpstreamError::Failed(format!("TLS handshake with {} failed: {e}", d.name)))?;
        let h2 = stream.ssl().selected_alpn_protocol() == Some(H2);
        let weak = crate::tls::mirror::is_weak(&stream);
        Ok((Box::new(stream), h2, weak))
    }
}

/// HTTP/1.1, the only protocol an upgrade or a streamed request is sent with.
fn http11_only() -> [Vec<u8>; 1] {
    [HTTP11.to_vec()]
}

impl Pool {
    /// A websocket upgrade on a connection of its own (HTTP/1.1): the site's answer, whose upgrade
    /// the caller takes over when it is a 101.
    pub async fn upgrade(
        &self,
        d: &Destination,
        tls: bool,
        req: http::Request<Buffered>,
        unchanged: bool,
    ) -> Result<http::Response<hyper::body::Incoming>, UpstreamError> {
        let (_, io, _) = self.connect(d, tls, Some(&http11_only()), unchanged).await?;
        let failed = |e: hyper::Error| UpstreamError::Failed(describe(&e));
        let (mut send, conn) = http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(io))
            .await
            .map_err(failed)?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!("[proxy] upstream websocket connection: {e}");
            }
        });
        match tokio::time::timeout(ANSWER_TIMEOUT, send.send_request(req)).await {
            Ok(r) => r.map_err(failed),
            Err(_) => Err(UpstreamError::Failed("the site did not answer in time".into())),
        }
    }

    /// One request on a connection of its own, its body streamed up and the answer's streamed back
    /// (the backup store: bodies too big to buffer). HTTP/1.1 only.
    pub async fn stream_once(
        &self,
        d: &Destination,
        tls: bool,
        req: http::Request<UpBody>,
    ) -> Result<http::Response<hyper::body::Incoming>, StreamError> {
        // The control plane and the backup store: never in a static-RSA suite.
        let (_, io, _) = self
            .connect(d, tls, Some(&http11_only()), false)
            .await
            .map_err(StreamError::Connect)?;
        let (mut send, conn) = http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(io))
            .await
            .map_err(|e| StreamError::Connect(UpstreamError::Failed(describe(&e))))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("[proxy] upstream connection: {e}");
            }
        });
        // No answer timeout: the site answers a PUT after the whole body, and a backup takes as
        // long as it takes (the passthrough had no limit either).
        send.send_request(req)
            .await
            .map_err(|e| StreamError::Sent(describe(&e)))
    }
}

/// Why a streamed request failed: before anything was sent, or while it was going.
#[derive(Debug)]
pub enum StreamError {
    Connect(UpstreamError),
    Sent(String),
}

/// A connection to a site, plain or TLS.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// How long the site may take to answer (its head; the body is read after). mitmproxy has no
/// limit; this one is long enough for long polls (Telegram's `getUpdates` holds 50 s) and still
/// frees an agent connection from a site that never answers. It counts from the request's start,
/// so a streamed upload (no step reads its body) must be sent, and answered, within it: a larger
/// upload over a slow link is cut off at 15 minutes.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// One try on one connection.
enum Attempt {
    /// Failed before the request went out on a reused connection: safe to try a fresh one.
    Unsent(UpstreamError),
    Sent(UpstreamError),
}

impl Attempt {
    fn unsent(e: hyper::Error) -> Self {
        Attempt::Unsent(UpstreamError::Failed(describe(&e)))
    }
    fn into_error(self) -> UpstreamError {
        match self {
            Attempt::Unsent(e) | Attempt::Sent(e) => e,
        }
    }
}

async fn handshake_h1<S>(io: S) -> Result<Sender, UpstreamError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let failed = |e: hyper::Error| UpstreamError::Failed(describe(&e));
    {
        let (send, conn) = http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(io))
            .await
            .map_err(failed)?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("[proxy] upstream connection: {e}");
            }
        });
        Ok(Sender::H1(send))
    }
}

/// Read a whole answer, at most `max` bytes of body (the cap on a buffered body).
pub async fn collect(resp: AnswerHead, max: usize) -> Result<Answer, UpstreamError> {
    let (parts, body) = resp.into_parts();
    let collected = http_body_util::Limited::new(body, max).collect().await.map_err(|e| {
        if e.is::<http_body_util::LengthLimitError>() {
            UpstreamError::Failed(format!("the answer is larger than {max} bytes"))
        } else {
            UpstreamError::Failed(e.to_string())
        }
    })?;
    let mut parts = parts;
    if let Some(t) = collected.trailers().cloned() {
        parts.extensions.insert(super::buffered::Trailers(t));
    }
    Ok(http::Response::from_parts(parts, collected.to_bytes()))
}

/// hyper's error with its cause, which is where the useful part is.
fn describe(e: &hyper::Error) -> String {
    use std::error::Error;
    match e.source() {
        Some(src) => format!("{e}: {src}"),
        None => e.to_string(),
    }
}

/// The destination with its address: as checked, or for a name that did not resolve when the
/// request came, resolved again now, strictly (addon.py `server_connect`), and refused with the
/// resolver's own words if it still does not.
async fn pin(d: &Destination) -> Result<(Destination, std::net::SocketAddr), UpstreamError> {
    if let Some(addr) = d.addr {
        return Ok((d.clone(), addr));
    }
    let addrs = crate::net::target::resolve(&d.name, d.port)
        .await
        .map_err(|e| UpstreamError::Refused(e.into_message()))?;
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| {
            UpstreamError::Refused(format!(
                "could not resolve {}",
                crate::net::target::truncate(&d.name, 60)
            ))
        })?;
    Ok((
        Destination {
            addr: Some(addr),
            ..d.clone()
        },
        addr,
    ))
}
