//! The realtime phone stream relay (`PhoneStreamRelay` in `phone-stream.ts`): the firewall opens a
//! websocket to `GET /phone/stream` for each realtime call, and this box relays its text frames to
//! the voice-call plugin on `ws://127.0.0.1:8789/voice/stream/realtime/<id>` and back. No audio is
//! processed here; the frames are Twilio's media JSON.
//!
//! Before anything is relayed the request must carry a firewall token for `phone` (120 s of clock
//! skew allowed, at most 30 s of life) whose `phoneStream` claim is the sha256 of the signed
//! envelope in `X-CC-Phone-Stream` and the request's `Sec-WebSocket-Key`; the envelope must name the
//! active phone settings' generation, a ticket not used before, the plugin's realtime path and a
//! Twilio signature made with the placeholder. Every refusal is a bare 403 and a log line naming
//! the check, never a value from the request.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use cc_auth::firewall::{FirewallAuth, Outcome, RequestParts};
use cc_http::{Req, Resp, full, header};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use http::{HeaderValue, StatusCode};
use hyper_util::rt::TokioIo;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_util::sync::CancellationToken;

use super::history::{SID, StreamPatch, now_ms};

/// Why the relay ended its side of a stream, as the close code the firewall receives. The
/// firewall writes it into its Activity row (`phone stream: close transport_agent_close_<code>`),
/// so a failed call says where it broke without a root shell on the agent (T-138).
///
///   4100–4599  the local voice-call plugin refused the upgrade: 4000 + its HTTP status
///   4010       nothing listening on 127.0.0.1:8789
///   4011       local transport error before the plugin answered
///   4012       the plugin did not answer the upgrade in time
///   4013       the plugin closed an open stream
pub mod close {
    pub const LISTENER_UNAVAILABLE: u16 = 4010;
    pub const TRANSPORT: u16 = 4011;
    pub const TIMEOUT: u16 = 4012;
    pub const LOCAL_CLOSED: u16 = 4013;
    pub fn refused(status: u16) -> u16 {
        if (100..=599).contains(&status) {
            4000 + status
        } else {
            TRANSPORT
        }
    }
}

/// How far apart the agent's and the firewall's clocks may be before a stream is refused.
pub const MAX_CLOCK_SKEW_MS: f64 = 120_000.0;
const MAX_PAYLOAD: usize = 16384;
/// What may wait to be written before the relay gives up on a side: the plugin, the firewall,
/// and either after a write.
const PEER_BUFFER: usize = 12000;
const OUTER_BUFFER: usize = 65536;
const MAX_BUFFER: usize = 262144;

/// What the relay needs of the active phone settings (`PhoneApply` while its status is active).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBinding {
    pub generation: String,
    pub placeholder: Option<String>,
    /// Realtime speech is configured (`speech` is set).
    pub speech: bool,
    pub public_url: String,
    pub max_concurrent_calls: Option<u64>,
    pub max_duration_seconds: Option<u64>,
}

pub type BindingFn = Arc<dyn Fn() -> Option<StreamBinding> + Send + Sync>;
pub type NoteFn = Arc<dyn Fn(&str, &StreamPatch) + Send + Sync>;
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

static TICKET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").expect("regex"));
static REALTIME_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/voice/stream/realtime/[0-9a-f-]{36}$").expect("regex"));
static ENVELOPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+$").expect("regex"));
static WS_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[+/0-9A-Za-z]{22}==$").expect("regex"));
static TOKEN_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$").expect("regex"));

struct State {
    /// Tickets already taken, until when they are remembered.
    used: HashMap<String, f64>,
    active: HashMap<u64, Arc<Session>>,
    /// When refusals were logged in the last minute (at most 30 lines a minute).
    refusals: Vec<i64>,
    next_id: u64,
}

pub struct Relay {
    binding: BindingFn,
    log: LogFn,
    /// The call history's notes (`phone-history.ts`): what happened to each call's stream.
    note: NoteFn,
    /// The voice-call plugin's listener, `127.0.0.1:8789`.
    local: String,
    state: Mutex<State>,
}

/// One relayed stream; `stop` ends it once, whichever side asks first.
struct Session {
    id: u64,
    sid: String,
    closed: AtomicBool,
    cancel: CancellationToken,
}

/// A refusal: the check that failed, and the call it is about once the envelope is trusted.
struct Refused {
    sid: Option<String>,
    reason: &'static str,
}

impl Refused {
    fn new(sid: &Option<String>, reason: &'static str) -> Self {
        Self {
            sid: sid.clone(),
            reason,
        }
    }
}

/// What the checks hand to the relay.
struct Admitted {
    session: Arc<Session>,
    path: String,
    signature: String,
    deadline: f64,
    generation: String,
}

/// `String(value)` as JS gives it, for the checks that test a value as text.
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
            _ => n.to_string(),
        },
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// `Number(value)` as JS gives it.
fn js_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = s.trim();
            let radix = |p: &str, r: u32| {
                t.get(..2)
                    .filter(|h| h.eq_ignore_ascii_case(p))
                    .map(|_| u64::from_str_radix(&t[2..], r).map(|n| n as f64).unwrap_or(f64::NAN))
            };
            if t.is_empty() {
                0.0
            } else if let Some(n) = radix("0x", 16).or_else(|| radix("0o", 8)).or_else(|| radix("0b", 2)) {
                n
            } else if t == "Infinity" || t == "+Infinity" {
                f64::INFINITY
            } else if t == "-Infinity" {
                f64::NEG_INFINITY
            } else if t
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
            {
                t.parse().unwrap_or(f64::NAN)
            } else {
                f64::NAN
            }
        }
        Some(Value::Array(a)) => match a.len() {
            0 => 0.0,
            1 => js_number(Some(&Value::String(js_string(a.first())))),
            _ => f64::NAN,
        },
        Some(Value::Object(_)) => f64::NAN,
    }
}

/// `Buffer.from(raw, "base64url").toString("utf8")`: lenient, as Node is.
fn decode_envelope(raw: &str) -> String {
    let mut s = raw.as_bytes().to_vec();
    if s.len() % 4 == 1 {
        s.pop();
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    String::from_utf8_lossy(&engine.decode(&s).unwrap_or_default()).into_owned()
}

fn forbidden() -> Resp {
    let mut r = full(StatusCode::FORBIDDEN, "", Bytes::new());
    r.headers_mut()
        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    r
}

/// The `ws` server's answer to an upgrade it cannot complete (`abortHandshake`).
fn abort_handshake(code: u16, message: &str, extra: Option<(&'static str, &'static str)>) -> Resp {
    let mut r = full(
        StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
        "text/html",
        message.to_string(),
    );
    r.headers_mut()
        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    if let Some((k, v)) = extra {
        r.headers_mut().insert(k, HeaderValue::from_static(v));
    }
    r
}

/// The checks `WebSocketServer.handleUpgrade` makes before it answers 101; the subprotocol to
/// echo when it would.
fn handshake_problem(parts: &http::request::Parts) -> Result<Option<String>, Box<Resp>> {
    if !header(parts, "upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        return Err(Box::new(abort_handshake(400, "Invalid Upgrade header", None)));
    }
    if !header(parts, "sec-websocket-key").is_some_and(|k| WS_KEY.is_match(k)) {
        return Err(Box::new(abort_handshake(
            400,
            "Missing or invalid Sec-WebSocket-Key header",
            None,
        )));
    }
    let version = header(parts, "sec-websocket-version")
        .map(|v| js_number(Some(&Value::String(v.into()))))
        .unwrap_or(f64::NAN);
    if version != 13.0 && version != 8.0 {
        return Err(Box::new(abort_handshake(
            400,
            "Missing or invalid Sec-WebSocket-Version header",
            Some(("sec-websocket-version", "13, 8")),
        )));
    }
    let Some(offered) = header(parts, "sec-websocket-protocol") else {
        return Ok(None);
    };
    let tokens: Vec<&str> = offered.split(',').map(str::trim).collect();
    let mut seen = std::collections::HashSet::new();
    if tokens.iter().any(|t| !TOKEN_CHARS.is_match(t) || !seen.insert(*t)) {
        return Err(Box::new(abort_handshake(
            400,
            "Invalid Sec-WebSocket-Protocol header",
            None,
        )));
    }
    Ok(tokens.first().map(|t| t.to_string()))
}

impl Relay {
    pub fn new(binding: BindingFn, note: NoteFn) -> Arc<Self> {
        Self::with(
            binding,
            Arc::new(|e| tracing::warn!("[phone-stream] {e}")),
            note,
            "127.0.0.1:8789",
        )
    }

    /// With a log and a plugin address of the caller's choosing (the tests).
    pub fn with(binding: BindingFn, log: LogFn, note: NoteFn, local: &str) -> Arc<Self> {
        Arc::new(Self {
            binding,
            log,
            note,
            local: local.into(),
            state: Mutex::new(State {
                used: HashMap::new(),
                active: HashMap::new(),
                refusals: Vec::new(),
                next_id: 0,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A call's audio is passing through right now. For the watchdog (W6), which leaves the
    /// redirector alone during a call.
    pub fn busy(&self) -> bool {
        !self.state().active.is_empty()
    }

    fn refuse(&self, r: Refused) -> Resp {
        let now = now_ms();
        if let Some(sid) = &r.sid {
            (self.note)(
                sid,
                &StreamPatch {
                    at: Some(now),
                    outcome: Some("refused"),
                    reason: Some(r.reason.into()),
                    ..Default::default()
                },
            );
        }
        // Bounded: the route is reachable from the internet, so a flood of bad upgrades cannot
        // flood the journal.
        let log = {
            let mut st = self.state();
            st.refusals.retain(|t| *t > now - 60_000);
            let room = st.refusals.len() < 30;
            if room {
                st.refusals.push(now);
            }
            room
        };
        if log {
            (self.log)(&format!("refused reason={}", r.reason));
        }
        forbidden()
    }

    fn stop(&self, s: &Session) {
        if s.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        (self.note)(
            &s.sid,
            &StreamPatch {
                ended_at: Some(now_ms()),
                ..Default::default()
            },
        );
        s.cancel.cancel();
        self.state().active.remove(&s.id);
    }

    /// Every upgrade request this box gets (`server.on("upgrade")`), the phone stream or not.
    pub async fn upgrade(self: &Arc<Self>, auth: &FirewallAuth, mut req: Req) -> Resp {
        let on_upgrade = hyper::upgrade::on(&mut req);
        let (parts, _) = req.into_parts();
        let admitted = match self.admit(auth, &parts) {
            Ok(a) => a,
            Err(r) => return self.refuse(r),
        };
        let session = admitted.session.clone();
        self.watch(&admitted);
        let protocol = match handshake_problem(&parts) {
            Ok(p) => p,
            Err(resp) => {
                // The socket closes with the answer, and the reservation goes with it.
                self.stop(&session);
                return *resp;
            }
        };
        let key = header(&parts, "sec-websocket-key").unwrap_or_default();
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        let relay = self.clone();
        tokio::spawn(async move {
            let upgraded = tokio::select! {
                u = on_upgrade => u,
                () = session.cancel.cancelled() => return,
            };
            match upgraded {
                Ok(u) => relay.run(admitted, TokioIo::new(u)).await,
                Err(_) => relay.stop(&session),
            }
        });
        let mut r = full(StatusCode::SWITCHING_PROTOCOLS, "", Bytes::new());
        let h = r.headers_mut();
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(http::header::CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Ok(v) = HeaderValue::from_str(&accept) {
            h.insert("sec-websocket-accept", v);
        }
        if let Some(p) = protocol.and_then(|p| HeaderValue::from_str(&p).ok()) {
            h.insert("sec-websocket-protocol", p);
        }
        r
    }

    /// The checks, in the TS order, and the reservation of a slot for the call.
    fn admit(&self, auth: &FirewallAuth, parts: &http::request::Parts) -> Result<Admitted, Refused> {
        let mut sid: Option<String> = None;
        // `req.url`: the request target as sent, so an absolute-form target is not the route.
        let raw_target = parts.uri.to_string();
        let target = raw_target.as_str();
        if parts.method != http::Method::GET || target != "/phone/stream" {
            return Err(Refused::new(&sid, "route"));
        }
        let request = RequestParts {
            method: parts.method.as_str(),
            url: target,
            authorization: header(parts, "authorization"),
            accepted_token_id: None,
        };
        let claims = match auth.verify(&request, "phone", (MAX_CLOCK_SKEW_MS / 1000.0) as i64) {
            Outcome::Accepted(a) => a.claims,
            _ => return Err(Refused::new(&sid, "token")),
        };
        let b = (self.binding)();
        let issued = claims.get("iat").and_then(Value::as_f64);
        let expires = claims.get("exp").and_then(Value::as_f64);
        let now = now_ms() as f64;
        let (Some(issued), Some(expires)) = (issued, expires) else {
            return Err(Refused::new(&sid, "token_lifetime"));
        };
        if expires - issued > 30.0 || expires <= issued {
            return Err(Refused::new(&sid, "token_lifetime"));
        }
        // The firewall's clock, as far as this box can tell: its token was signed a moment ago. An
        // agent box has no reachable NTP server of its own until the firewall serves time, and a
        // drift of one second used to refuse every stream (T-138).
        let skew = issued * 1000.0 - now;
        let values: Vec<&str> = parts
            .headers
            .get_all("x-cc-phone-stream")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let raw = values.join(", ");
        if values.is_empty() || raw.len() > 4096 || !ENVELOPE.is_match(&raw) {
            return Err(Refused::new(&sid, "envelope"));
        }
        let envelope = decode_envelope(&raw);
        let key = header(parts, "sec-websocket-key").unwrap_or("undefined");
        let digest = hex::encode(Sha256::digest(format!("{envelope}\n{key}").as_bytes()));
        let signed = claims.get("phoneStream").and_then(Value::as_str).unwrap_or_default();
        if !claims.get("phoneStream").is_some_and(Value::is_string)
            || !cc_crypto::ct_eq(signed.as_bytes(), digest.as_bytes())
        {
            return Err(Refused::new(&sid, "envelope_digest"));
        }
        let p: Value = serde_json::from_str(&envelope).map_err(|_| Refused::new(&sid, "error"))?;
        if p.is_null() {
            return Err(Refused::new(&sid, "error"));
        }
        // The firewall signed this envelope, so its call SID names the call the checks below are
        // about; refusals from here on go into the call history.
        if let Some(s) = p.get("callSid").and_then(Value::as_str)
            && SID.is_match(s)
        {
            sid = Some(s.to_string());
        }
        let Some(b) = b.filter(|b| b.placeholder.as_deref().is_some_and(|p| !p.is_empty()) && b.speech) else {
            return Err(Refused::new(&sid, "not_assigned"));
        };
        let placeholder = b.placeholder.clone().unwrap_or_default();
        // From the slot count to the reservation, one lock: two upgrades cannot both take the
        // last slot or the same ticket.
        let mut st = self.state();
        if st.active.len() as u64 >= b.max_concurrent_calls.unwrap_or(1) {
            return Err(Refused::new(&sid, "concurrency"));
        }
        if skew.abs() > MAX_CLOCK_SKEW_MS {
            return Err(Refused::new(&sid, "clock_skew"));
        }
        st.used.retain(|_, until| *until >= now);
        let url = url::Url::parse(&js_string(p.get("url"))).map_err(|_| Refused::new(&sid, "error"))?;
        let origin = url::Url::parse(&b.public_url).map_err(|_| Refused::new(&sid, "error"))?;
        if p.get("generation").and_then(Value::as_str) != Some(b.generation.as_str()) {
            return Err(Refused::new(&sid, "generation"));
        }
        let ticket = p.get("ticket").and_then(Value::as_str).unwrap_or_default().to_string();
        let path = js_string(p.get("path"));
        let fields_ok = p.get("ticket").is_some_and(Value::is_string)
            && TICKET.is_match(&ticket)
            && SID.is_match(&js_string(p.get("callSid")))
            && REALTIME_PATH.is_match(&path)
            && url.origin().ascii_serialization()
                == origin.origin().ascii_serialization().replacen("https:", "wss:", 1)
            && url.path() == format!("/phone-stream/{ticket}")
            && url.query().is_none_or(str::is_empty)
            && url.fragment().is_none_or(str::is_empty)
            && url.username().is_empty()
            && url.password().is_none_or(str::is_empty);
        if !fields_ok {
            return Err(Refused::new(&sid, "envelope_fields"));
        }
        // The firewall's deadline on this box's clock.
        let deadline = js_number(p.get("deadline")) - skew;
        let longest = b.max_duration_seconds.unwrap_or(300) as f64 * 1000.0 + 1000.0;
        if !deadline.is_finite() || deadline <= now || deadline > now + longest {
            return Err(Refused::new(&sid, "deadline"));
        }
        if st.used.contains_key(&ticket) || st.used.len() >= 100 {
            return Err(Refused::new(&sid, "ticket_used"));
        }
        let mut mac =
            Hmac::<sha1::Sha1>::new_from_slice(placeholder.as_bytes()).map_err(|_| Refused::new(&sid, "error"))?;
        let Some(signed_url) = p.get("url").and_then(Value::as_str) else {
            return Err(Refused::new(&sid, "error"));
        };
        mac.update(signed_url.as_bytes());
        let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let Some(signature) = p.get("signature").and_then(Value::as_str) else {
            return Err(Refused::new(&sid, "signature"));
        };
        if signature.encode_utf16().count() != expected.len() {
            return Err(Refused::new(&sid, "signature"));
        }
        // Same length in JS characters but not in bytes: `timingSafeEqual` throws.
        if signature.len() != expected.len() {
            return Err(Refused::new(&sid, "error"));
        }
        if !cc_crypto::ct_eq(expected.as_bytes(), signature.as_bytes()) {
            return Err(Refused::new(&sid, "signature"));
        }
        // Remember the ticket for as long as its token could still verify, not only until the call
        // deadline: a short call limit would otherwise forget it while a copy of the request is
        // valid.
        st.used
            .insert(ticket, deadline.max(now + 30_000.0 + MAX_CLOCK_SKEW_MS * 2.0));
        let call = js_string(p.get("callSid"));
        st.next_id += 1;
        let session = Arc::new(Session {
            id: st.next_id,
            sid: call.clone(),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
        });
        // Reserved before the local handshake, so a second upgrade cannot race it.
        st.active.insert(session.id, session.clone());
        drop(st);
        (self.note)(
            &call,
            &StreamPatch {
                at: Some(now as i64),
                outcome: Some("connected"),
                ..Default::default()
            },
        );
        Ok(Admitted {
            session,
            path,
            signature: signature.to_string(),
            deadline,
            generation: b.generation,
        })
    }

    /// Ends the stream at the deadline, or when the phone settings change or go.
    fn watch(self: &Arc<Self>, a: &Admitted) {
        let (relay, session, deadline, generation) =
            (self.clone(), a.session.clone(), a.deadline, a.generation.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    () = session.cancel.cancelled() => return,
                }
                let live = (relay.binding)();
                let gone = live
                    .as_ref()
                    .is_none_or(|b| b.placeholder.as_deref().is_none_or(str::is_empty) || b.generation != generation);
                if now_ms() as f64 >= deadline || gone {
                    relay.stop(&session);
                    return;
                }
            }
        });
    }

    async fn run<S>(self: Arc<Self>, a: Admitted, io: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let session = a.session.clone();
        let cancel = session.cancel.clone();
        tokio::select! {
            () = self.clone().relay(a, io) => {}
            () = cancel.cancelled() => {}
        }
    }

    async fn relay<S>(self: Arc<Self>, a: Admitted, io: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let s = a.session.clone();
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_PAYLOAD))
            .max_frame_size(Some(MAX_PAYLOAD));
        let outer = WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
        let (outer_sink, mut outer_rx) = outer.split();
        let outer_w = Writer::spawn(outer_sink, OUTER_BUFFER, s.cancel.clone());

        // The close code the firewall gets once the local side is gone; see `close`.
        let end_local = |reason: Option<u16>| {
            if s.closed.load(Ordering::SeqCst) {
                return;
            }
            let code = reason.unwrap_or(close::LOCAL_CLOSED);
            (self.note)(
                &s.sid,
                &StreamPatch {
                    local_code: Some(code),
                    ..Default::default()
                },
            );
            if !outer_w.open() {
                return self.stop(&s);
            }
            outer_w.close(code);
            // A terminate right away could drop the close frame; the firewall's close ends it
            // sooner.
            let (relay, s) = (self.clone(), s.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                relay.stop(&s);
            });
        };

        let peer = match self.connect_local(&a).await {
            Ok(p) => p,
            Err(reason) => {
                end_local(Some(reason));
                // Wait for the firewall's close, or the stop a second from now.
                while let Some(Ok(_)) = outer_rx.next().await {}
                return self.stop(&s);
            }
        };
        let (peer_sink, mut peer_rx) = peer.split();
        let peer_w = Writer::spawn(peer_sink, PEER_BUFFER, s.cancel.clone());

        let to_peer = {
            let (relay, s, peer_w) = (self.clone(), s.clone(), peer_w.clone());
            async move {
                loop {
                    match outer_rx.next().await {
                        Some(Ok(Message::Text(t))) => {
                            if !peer_w.forward(t).await {
                                return relay.stop(&s);
                            }
                        }
                        Some(Ok(Message::Binary(_))) => return relay.stop(&s),
                        // A close is answered by the next read; the socket ends after it.
                        Some(Ok(_)) => {}
                        Some(Err(_)) | None => return relay.stop(&s),
                    }
                }
            }
        };
        let from_peer = {
            let s = s.clone();
            let outer_w = outer_w.clone();
            let this = self.clone();
            async move {
                let mut spoke = false;
                let reason = loop {
                    match peer_rx.next().await {
                        Some(Ok(Message::Text(t))) => {
                            // The first audio back to the caller, for the history's response
                            // time. The plugin's media events are the only ones that carry this.
                            if !spoke && t.as_str().contains("\"event\":\"media\"") {
                                spoke = true;
                                (this.note)(
                                    &s.sid,
                                    &StreamPatch {
                                        first_audio_at: Some(now_ms()),
                                        ..Default::default()
                                    },
                                );
                            }
                            if !outer_w.forward(t).await {
                                this.stop(&s);
                                return None;
                            }
                        }
                        Some(Ok(Message::Binary(_))) => {
                            this.stop(&s);
                            return None;
                        }
                        Some(Ok(_)) => {}
                        None
                        | Some(Err(
                            WsError::ConnectionClosed
                            | WsError::AlreadyClosed
                            | WsError::Io(_)
                            | WsError::Protocol(
                                tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                            ),
                        )) => break None,
                        Some(Err(_)) => {
                            (this.log)("local_transport_error");
                            break Some(close::TRANSPORT);
                        }
                    }
                };
                Some(reason)
            }
        };
        tokio::pin!(to_peer, from_peer);
        let mut outer_done = false;
        loop {
            tokio::select! {
                () = &mut to_peer, if !outer_done => { outer_done = true; }
                ended = &mut from_peer => {
                    if let Some(reason) = ended {
                        end_local(reason);
                    }
                    // Keep reading the firewall's side until it closes or the stop comes.
                    if !outer_done {
                        to_peer.await;
                    }
                    return;
                }
            }
        }
    }

    /// Opens the plugin's side of the stream, or says why it could not, as a close code.
    async fn connect_local(&self, a: &Admitted) -> Result<WebSocketStream<tokio::net::TcpStream>, u16> {
        let url = format!("ws://{}{}", self.local, a.path);
        let mut request = url.into_client_request().map_err(|_| close::TRANSPORT)?;
        if let Ok(v) = HeaderValue::from_str(&a.signature) {
            request.headers_mut().insert("x-twilio-signature", v);
        }
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_PAYLOAD))
            .max_frame_size(Some(MAX_PAYLOAD));
        let local = self.local.clone();
        let attempt = async move {
            let tcp = tokio::net::TcpStream::connect(&local).await.map_err(Err)?;
            tokio_tungstenite::client_async_with_config(request, tcp, Some(config))
                .await
                .map(|(ws, _)| ws)
                .map_err(Ok)
        };
        match tokio::time::timeout(Duration::from_millis(3000), attempt).await {
            Ok(Ok(ws)) => Ok(ws),
            Err(_) => {
                (self.log)("local_upgrade_timeout");
                Err(close::TIMEOUT)
            }
            Ok(Err(Err(e))) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                (self.log)("local_listener_unavailable");
                Err(close::LISTENER_UNAVAILABLE)
            }
            Ok(Err(Ok(WsError::Http(response)))) => {
                let status = response.status().as_u16();
                (self.log)(&format!("local_upgrade_refused status={status}"));
                Err(close::refused(status))
            }
            Ok(Err(_)) => {
                (self.log)("local_transport_error");
                Err(close::TRANSPORT)
            }
        }
    }
}

/// One side's writes, in order, with what is still waiting counted (`bufferedAmount`): a frame
/// counts from when it is queued until the socket has taken it.
#[derive(Clone)]
struct Writer {
    /// Each message with the bytes it was counted for (a close frame counts for none).
    tx: mpsc::UnboundedSender<(Message, usize)>,
    queued: Arc<AtomicUsize>,
    /// Woken each time the writer hands a frame to the socket.
    drained: Arc<tokio::sync::Notify>,
    open: Arc<AtomicBool>,
    limit: usize,
}

/// How long a reader waits for its writer to catch up before the side counts as too far behind.
/// A burst the firewall or the plugin sends in one go is decoded at once while the writer has not
/// run yet; in Node it went straight into the socket. A socket that takes nothing for this long is
/// what `bufferedAmount` over the limit meant there.
const DRAIN_WAIT: Duration = Duration::from_millis(100);

impl Writer {
    fn spawn<S>(mut sink: SplitSink<WebSocketStream<S>, Message>, limit: usize, cancel: CancellationToken) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel::<(Message, usize)>();
        let queued = Arc::new(AtomicUsize::new(0));
        let drained = Arc::new(tokio::sync::Notify::new());
        let open = Arc::new(AtomicBool::new(true));
        let (q, d, o) = (queued.clone(), drained.clone(), open.clone());
        tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    m = rx.recv() => m,
                    () = cancel.cancelled() => None,
                };
                let Some((m, n)) = next else { return };
                let sent = tokio::select! {
                    r = sink.send(m) => r.is_ok(),
                    () = cancel.cancelled() => false,
                };
                q.fetch_sub(n, Ordering::SeqCst);
                d.notify_waiters();
                if !sent {
                    o.store(false, Ordering::SeqCst);
                    return;
                }
            }
        });
        Self {
            tx,
            queued,
            drained,
            open,
            limit,
        }
    }

    fn open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    /// Queue a text frame; false when the side is gone or too far behind, which ends the stream.
    async fn forward(&self, text: tokio_tungstenite::tungstenite::Utf8Bytes) -> bool {
        let deadline = tokio::time::Instant::now() + DRAIN_WAIT;
        loop {
            if !self.open() {
                return false;
            }
            let drained = self.drained.notified();
            tokio::pin!(drained);
            // Registered before the check, so a drain between the two is not missed.
            drained.as_mut().enable();
            if self.queued.load(Ordering::SeqCst) <= self.limit {
                break;
            }
            if tokio::time::timeout_at(deadline, drained).await.is_err() {
                return false;
            }
        }
        let n = text.len();
        self.queued.fetch_add(n, Ordering::SeqCst);
        if self.tx.send((Message::Text(text), n)).is_err() {
            return false;
        }
        self.queued.load(Ordering::SeqCst) <= MAX_BUFFER
    }

    /// `ws.close(code)`: the close frame goes out after what is queued, and the side counts as
    /// closing.
    fn close(&self, code: u16) {
        self.open.store(false, Ordering::SeqCst);
        let frame = Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: "".into(),
        }));
        let _ = self.tx.send((frame, 0));
    }
}

#[cfg(test)]
mod tests;
