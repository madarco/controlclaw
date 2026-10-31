//! The realtime phone stream on the firewall (`phone-stream.ts`): firewall-owned admission of a
//! call, the `<Connect><Stream>` answer rewritten to this firewall's own websocket, Twilio's media
//! websocket verified and relayed to the agent's `/phone/stream`, and the call leases the proxy
//! reads (`phone-media.json`). Never accepts a stream destination the agent chose.
//!
//! The admission (`reserve`, `settle_reservation`) is the proxy's, on `127.0.0.1:8791`
//! (`phone-admission.ts`): an outbound call is reserved before Twilio can bill it.
//!
//! One difference from the TS, in how backpressure is seen: Node's `ws` exposes `bufferedAmount`
//! and tokio-tungstenite does not, so a write that does not finish within a second, or a frame
//! over 16 KB, ends the stream as "backpressure".

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderValue, StatusCode};
use hyper_util::rt::TokioIo;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use super::policy::phone_limits;
use super::twiml::allowed_phone_twiml;
use crate::core::url_form::{decode_form, url_form_signature, verify_url_form};

const HANGUP: &str = "<Response><Hangup/></Response>";
const MAX_PAYLOAD: usize = 16384;
const TERMINAL: [&str; 5] = ["completed", "canceled", "failed", "busy", "no-answer"];
static SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^CA[0-9a-f]{32}$").expect("regex"));
static STREAM_SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^MZ[0-9a-f]{32}$").expect("regex"));
static AUDIO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").expect("regex"));
/// With JavaScript's whitespace (`twiml::WS`), as the TS matches it.
static STREAM_TWIML: LazyLock<Regex> = LazyLock::new(|| {
    let ws = super::twiml::WS;
    Regex::new(&format!(
        r#"^(?:<\?xml version="1\.0" encoding="UTF-8"\?>{ws}*)?<Response>{ws}*<Connect>{ws}*<Stream url="([^"<>]+)"{ws}*/>{ws}*</Connect>{ws}*</Response>{ws}*$"#
    ))
    .expect("regex")
});
static CONNECT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<Connect\b").expect("regex"));
static LOCAL_STREAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/voice/stream/realtime/[0-9a-f-]{36}$").expect("regex"));

/// `validAudio`: base64, at most 12000 characters.
pub fn valid_audio(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.len() <= 12000 && AUDIO.is_match(s))
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;")
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

/// A number as JavaScript prints `ms / 1000`.
fn secs(ms: i64) -> Value {
    if ms % 1000 == 0 {
        json!(ms / 1000)
    } else {
        json!(ms as f64 / 1000.0)
    }
}

/// `Number(v)`, kept only when it is a safe integer.
fn safe_int(v: Option<&Value>) -> Option<i64> {
    let n = crate::core::ingress::js_number(v);
    (n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0).then_some(n as i64)
}

/// What the phone module says a stream may use (`streamBinding`), as it came.
#[derive(Debug, Clone, PartialEq)]
pub struct Binding(pub Map<String, Value>);

impl Binding {
    fn s(&self, k: &str) -> &str {
        self.0.get(k).and_then(Value::as_str).unwrap_or_default()
    }
    fn speech(&self) -> Option<&Value> {
        self.0.get("speech").filter(|v| !v.is_null())
    }
    fn speech_available(&self) -> bool {
        self.0.get("speechAvailable") == Some(&Value::Bool(true))
    }
    fn limits(&self) -> Result<super::policy::Limits, String> {
        phone_limits(&self.0).map_err(str::to_string)
    }
    /// `current`'s field-by-field comparison (`===`, so a missing field equals a missing one).
    fn same(&self, o: &Binding) -> bool {
        [
            "generation",
            "placeholder",
            "token",
            "hostname",
            "callerPolicy",
            "speechRevision",
            "voicePlaceholder",
        ]
        .iter()
        .all(|k| self.0.get(*k) == o.0.get(*k))
    }
}

struct Call {
    sid: String,
    binding: Binding,
    direction: &'static str,
    started_at: i64,
    deadline: i64,
    mode: &'static str,
    ticket: Option<String>,
    local_path: Option<String>,
    expires: Option<i64>,
    used: bool,
    started: bool,
    stream_sid: Option<String>,
    /// Ends the relay, with the call as it was when it was taken out of the map.
    close: Option<mpsc::UnboundedSender<(String, Option<Snapshot>)>>,
    bytes: i64,
    inbound_bytes: i64,
    outbound_bytes: i64,
    frames: i64,
}

impl Call {
    fn span_secs(&self) -> i64 {
        ((self.deadline - self.started_at) as f64 / 1000.0).ceil() as i64
    }
}

struct Reservation {
    binding: Binding,
    expires: i64,
    sid: Option<String>,
}

#[derive(Default)]
struct State {
    calls: IndexMap<String, Call>,
    reservations: IndexMap<String, Reservation>,
    ended: HashMap<String, i64>,
    attempts: Vec<i64>,
    refusals: Vec<i64>,
}

pub type Control =
    Arc<dyn Fn(String, Option<Vec<(String, String)>>) -> cc_http::BoxFuture<Option<Map<String, Value>>> + Send + Sync>;
pub type HostFor = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
pub type AgentBase = Arc<dyn Fn(&str) -> String + Send + Sync>;
pub type Sign = Arc<dyn Fn(&str, Map<String, Value>) -> Result<String, String> + Send + Sync>;

pub struct PhoneStreamsOptions {
    pub binding: Arc<dyn Fn() -> Option<Binding> + Send + Sync>,
    /// A token for the agent, `phone` purpose, with these claims.
    pub sign: Sign,
    /// Where this firewall has the agent on record; the stream goes there, as its token says.
    pub host_for: HostFor,
    pub media_dir: std::path::PathBuf,
    pub control: Control,
    pub log_path: Option<std::path::PathBuf>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Tests: the agent's websocket base (`ws://127.0.0.1:<port>`), with no TLS.
    pub agent_base: Option<AgentBase>,
}

/// What a call looked like when a line was written about it.
struct Snapshot {
    key: String,
    vm_id: String,
    direction: &'static str,
    provider: String,
    model: String,
    inbound: i64,
    outbound: i64,
    duration: i64,
    frames: i64,
}

pub struct PhoneStreams {
    opts: PhoneStreamsOptions,
    st: Mutex<State>,
    /// The binding as the relay's per-frame checks read it: at most 100 ms old (the tick, the hook
    /// and revocation read it fresh).
    cached: Mutex<Option<(std::time::Instant, Option<Binding>)>>,
    me: Weak<PhoneStreams>,
}

impl PhoneStreams {
    pub fn new(opts: PhoneStreamsOptions) -> Arc<Self> {
        let s = Arc::new_cyclic(|me| Self {
            opts,
            st: Mutex::new(State::default()),
            cached: Mutex::new(None),
            me: me.clone(),
        });
        let _ = s.publish();
        s
    }

    /// The 500 ms tick, with the TS's recovery: anything it cannot do ends every call and takes
    /// the leases away.
    pub fn start(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let Some(s) = me.upgrade() else { return };
                if s.tick().is_err() {
                    let now = s.now();
                    let calls: Vec<Call> = {
                        let mut st = s.lock();
                        let calls: Vec<Call> = st.calls.drain(..).map(|(_, c)| c).collect();
                        // Ended like any other: their webhooks are refused from now on.
                        for c in &calls {
                            st.ended.insert(c.sid.clone(), c.deadline + 300_000);
                        }
                        calls
                    };
                    for c in &calls {
                        if let Some(tx) = &c.close {
                            let _ = tx.send(("lease_error".into(), Some(Self::snapshot(c, now))));
                        }
                    }
                    // Existing leases expire in three seconds.
                    let _ = std::fs::remove_file(cc_contracts::FileSpec::PHONE_MEDIA.path_in(&s.opts.media_dir));
                    for c in calls {
                        let f = s.opts.control.clone();
                        tokio::spawn(async move {
                            f(c.sid, Some(vec![("Status".into(), "completed".into())])).await;
                        });
                    }
                }
            }
        });
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    fn current(&self, c: &Call) -> bool {
        self.current_with((self.opts.binding)().as_ref(), c)
    }

    fn current_with(&self, b: Option<&Binding>, c: &Call) -> bool {
        let Some(b) = b else { return false };
        let Ok(l) = b.limits() else { return false };
        b.same(&c.binding) && self.now() < c.deadline.min(c.started_at + l.max_duration_seconds * 1000)
    }

    fn binding_cached(&self) -> Option<Binding> {
        let mut c = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        match &*c {
            Some((at, b)) if at.elapsed() < Duration::from_millis(100) => b.clone(),
            _ => {
                let b = (self.opts.binding)();
                *c = Some((std::time::Instant::now(), b.clone()));
                b
            }
        }
    }

    fn snapshot(c: &Call, now: i64) -> Snapshot {
        let speech = c.binding.speech();
        Snapshot {
            key: hex::encode(Sha256::digest(
                format!("{}{}", c.binding.s("generation"), c.sid).as_bytes(),
            ))[..16]
                .to_string(),
            vm_id: c.binding.s("vmId").to_string(),
            direction: c.direction,
            provider: speech
                .and_then(|s| s.get("provider"))
                .and_then(Value::as_str)
                .unwrap_or("classic")
                .to_string(),
            model: speech
                .and_then(|s| s.get("model"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string(),
            inbound: c.inbound_bytes,
            outbound: c.outbound_bytes,
            duration: now - c.started_at,
            frames: c.frames,
        }
    }

    /// One line on the traffic log, metadata only.
    fn record(&self, kind: &str, reason: &str, c: Option<&Snapshot>) {
        let Some(path) = &self.opts.log_path else { return };
        let mut e = Map::new();
        e.insert("source".into(), json!("egress"));
        e.insert(
            "flow_id".into(),
            json!(format!(
                "{}-{}",
                c.map_or_else(|| rand_hex(8), |c| c.key.clone()),
                rand_hex(4)
            )),
        );
        e.insert("ts".into(), secs(self.now()));
        e.insert("method".into(), json!("WS"));
        e.insert("host".into(), json!("api.twilio.com"));
        e.insert("path".into(), json!("/phone-stream/[stream]"));
        if let Some(c) = c {
            e.insert("vm_id".into(), json!(c.vm_id));
        }
        let refusal = kind == "refusal";
        e.insert("effect".into(), json!(if refusal { "drop" } else { "allow" }));
        e.insert("status".into(), json!(if refusal { 403 } else { 101 }));
        e.insert("bytes_in".into(), json!(c.map_or(0, |c| c.inbound)));
        e.insert("bytes_out".into(), json!(c.map_or(0, |c| c.outbound)));
        e.insert("duration_ms".into(), json!(c.map_or(0, |c| c.duration)));
        e.insert(
            "rule".into(),
            json!(format!(
                "phone stream: {kind} {reason} {} {} {}",
                c.map_or("unknown", |c| c.direction),
                c.map_or("classic", |c| c.provider.as_str()),
                c.map_or("none", |c| c.model.as_str())
            )),
        );
        e.insert("frames".into(), json!(c.map_or(0, |c| c.frames)));
        if let Some(c) = c {
            e.insert("call_id".into(), json!(c.key));
        }
        let line = format!("{}\n", Value::Object(e));
        let _ = (|| -> std::io::Result<()> {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?
                .write_all(line.as_bytes())
        })();
    }

    fn hang_up(&self, sid: String) {
        let f = self.opts.control.clone();
        tokio::spawn(async move {
            f(sid, Some(vec![("Status".into(), "completed".into())])).await;
        });
    }

    /// Called only by the firewall-local proxy gate, before Twilio can bill a call.
    pub fn reserve(&self, vm_id: &Value, placeholder: &Value) -> Result<String, String> {
        self.tick()?;
        let b = (self.opts.binding)().ok_or("phone revoked")?;
        if b.0.get("vmId") != Some(vm_id) || b.0.get("placeholder") != Some(placeholder) {
            return Err("phone revoked".into());
        }
        let l = b.limits()?;
        let mut st = self.lock();
        if (st.calls.len() + st.reservations.len()) as i64 >= l.max_concurrent_calls {
            return Err("phone concurrency limit".into());
        }
        let id = rand_hex(24);
        st.reservations.insert(
            id.clone(),
            Reservation {
                binding: b,
                expires: self.now() + (l.max_duration_seconds + 90) * 1000,
                sid: None,
            },
        );
        Ok(id)
    }

    pub fn settle_reservation(&self, id: &str, sid: Option<&Value>, rejected: bool) {
        let mut st = self.lock();
        let Some(r) = st.reservations.get_mut(id) else { return };
        if rejected {
            st.reservations.shift_remove(id);
        } else if let Some(s) = sid.and_then(Value::as_str).filter(|s| SID.is_match(s)) {
            r.sid = Some(s.to_string());
        }
    }

    /// The hook's `prepareDelivery`: a call admitted (or refused) before its webhook reaches the
    /// agent, and the mode it is in. An error refuses the delivery.
    pub fn prepare(&self, body: &[u8], query: &str) -> Result<Map<String, Value>, String> {
        let p = decode_form(body).map_err(|e| e.0.to_string())?;
        let get = |k: &str| p.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let has = |k: &str| p.iter().any(|(n, _)| n == k);
        let q: Vec<(String, String)> = url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes())
            .into_owned()
            .collect();
        let qget = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let sid = get("CallSid").unwrap_or_default().to_string();
        if !SID.is_match(&sid) {
            return Err("invalid call".into());
        }
        let terminal = TERMINAL.contains(&get("CallStatus").unwrap_or_default());
        if qget("type") == Some("status") {
            if terminal {
                self.end(&sid, "completed", false);
                let mut st = self.lock();
                if let Some(id) = qget("ccCall") {
                    st.reservations.shift_remove(id);
                }
                st.reservations.retain(|_, r| r.sid.as_deref() != Some(sid.as_str()));
            }
            return Ok(Map::new());
        }
        self.tick()?;
        let mut new_call = false;
        {
            let mut st = self.lock();
            if st.ended.contains_key(&sid) {
                return Err("call ended".into());
            }
            if !st.calls.contains_key(&sid) {
                if q.iter().any(|(n, _)| n == "turnToken") || has("SpeechResult") || has("Digits") || terminal {
                    return Err("call setup required".into());
                }
                let b = (self.opts.binding)().ok_or("phone revoked")?;
                let l = b.limits()?;
                let reservation_id = qget("ccCall");
                if let Some(id) = reservation_id {
                    let ok = st.reservations.get(id).is_some_and(|r| {
                        r.binding.s("generation") == b.s("generation") && r.sid.as_deref().is_none_or(|s| s == sid)
                    });
                    if !ok {
                        return Err("invalid phone reservation".into());
                    }
                    st.reservations.shift_remove(id);
                }
                if (st.calls.len() + st.reservations.len()) as i64 >= l.max_concurrent_calls {
                    return Err("phone concurrency limit".into());
                }
                let now = self.now();
                st.attempts.retain(|t| *t > now - 60_000);
                if st.attempts.len() >= 10 {
                    return Err("phone rate limit".into());
                }
                st.attempts.push(now);
                let mode = if b.speech().is_some() && b.speech_available() {
                    "realtime"
                } else {
                    "classic"
                };
                st.calls.insert(
                    sid.clone(),
                    Call {
                        sid: sid.clone(),
                        direction: if get("Direction") == Some("inbound") {
                            "inbound"
                        } else {
                            "outbound"
                        },
                        started_at: now,
                        deadline: now + l.max_duration_seconds * 1000,
                        mode,
                        binding: b,
                        ticket: None,
                        local_path: None,
                        expires: None,
                        used: false,
                        started: false,
                        stream_sid: None,
                        close: None,
                        bytes: 0,
                        inbound_bytes: 0,
                        outbound_bytes: 0,
                        frames: 0,
                    },
                );
                new_call = true;
            }
        }
        if new_call {
            // Initial inbound webhooks arrive while ringing, before TwiML answers the call.
            let (me, s) = (self.me.clone(), sid.clone());
            tokio::spawn(async move {
                if let Some(me) = me.upgrade() {
                    me.cap_carrier(s).await;
                }
            });
        }
        let st = self.lock();
        let c = st.calls.get(&sid).ok_or("phone revoked")?;
        if !self.current(c) {
            return Err("phone revoked".into());
        }
        let mut out = Map::new();
        out.insert("x-cc-phone-mode".into(), json!(c.mode));
        Ok(out)
    }

    /// Whether this call is still the one in the map, and current.
    fn still(&self, sid: &str, started_at: i64) -> bool {
        // Read before the lock: the phone module's answer is not made under the streams' lock.
        let b = self.binding_cached();
        let st = self.lock();
        st.calls
            .get(sid)
            .is_some_and(|c| c.started_at == started_at && self.current_with(b.as_ref(), c))
    }

    /// The carrier's own time limit, once the call is answered: it also bounds a classic verb that
    /// never calls back.
    async fn cap_carrier(&self, sid: String) {
        let Some(started_at) = self.lock().calls.get(&sid).map(|c| c.started_at) else {
            return;
        };
        let answer_by = self.now() + 15_000;
        let failed = loop {
            if !self.still(&sid, started_at) {
                return;
            }
            let call = (self.opts.control)(sid.clone(), None).await;
            if !self.still(&sid, started_at) {
                return;
            }
            let status = call
                .as_ref()
                .and_then(|c| c.get("status"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if status == "in-progress" {
                // The deadline as it is now: a lowered limit while it rang is the carrier's too.
                let Some(deadline) = self.lock().calls.get(&sid).map(|c| c.deadline) else {
                    return;
                };
                let limit = (deadline - started_at) / 1000;
                break (self.opts.control)(sid.clone(), Some(vec![("TimeLimit".into(), limit.to_string())]))
                    .await
                    .is_none();
            }
            if TERMINAL.contains(&status.as_str()) {
                self.end(&sid, "completed", false);
                return;
            }
            if !["queued", "ringing", "initiated"].contains(&status.as_str()) || self.now() >= answer_by {
                break true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        if failed && self.lock().calls.get(&sid).is_some_and(|c| c.started_at == started_at) {
            tracing::warn!("[phone] carrier_duration_limit_failed");
            self.end(&sid, "duration_limit_failed", true);
        }
    }

    fn public_url(c: &Call) -> String {
        let origin = url::Url::parse(c.binding.s("hook"))
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default();
        format!(
            "{}/phone-stream/{}",
            origin.replacen("https:", "wss:", 1),
            c.ticket.clone().unwrap_or_default()
        )
    }

    fn stream_answer(c: &Call) -> String {
        format!(
            r#"<Response><Connect><Stream url="{}"/></Connect><Redirect method="POST">{}</Redirect></Response>"#,
            escape(&Self::public_url(c)),
            escape(&format!("{}?turnToken=classic", c.binding.s("hook")))
        )
    }

    /// The hook's `rewriteResponse`: the agent's `<Connect><Stream>` to its own plugin becomes this
    /// firewall's websocket, once per call. An error refuses the answer.
    pub fn rewrite(&self, xml: &str, body: &[u8], query: &str) -> Result<String, String> {
        let p = decode_form(body).map_err(|e| e.0.to_string())?;
        let sid = p
            .iter()
            .find(|(n, _)| n == "CallSid")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let status = url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes())
            .any(|(k, v)| k == "type" && v == "status");
        let mut st = self.lock();
        let current = st.calls.get(&sid).is_some_and(|c| self.current(c));
        if !status && !current {
            return Ok(HANGUP.into());
        }
        if !CONNECT.is_match(xml) {
            let hook = (self.opts.binding)()
                .map(|b| b.s("hook").to_string())
                .unwrap_or_default();
            if !allowed_phone_twiml(xml, &hook) {
                return Err("invalid TwiML".into());
            }
            return Ok(xml.to_string());
        }
        let Some(c) = st.calls.get_mut(&sid).filter(|_| current) else {
            return Err("stream not authorized".into());
        };
        if c.mode != "realtime" || query.contains("type=status") {
            return Err("stream not authorized".into());
        }
        let m = STREAM_TWIML
            .captures(super::twiml::js_trim(xml))
            .ok_or("invalid stream TwiML")?;
        let u = url::Url::parse(&m[1]).map_err(|_| "invalid local stream route")?;
        let origin = url::Url::parse(c.binding.s("hook")).map_err(|_| "invalid local stream route")?;
        let host = |u: &url::Url| {
            format!(
                "{}{}",
                u.host_str().unwrap_or_default(),
                u.port().map(|p| format!(":{p}")).unwrap_or_default()
            )
        };
        if u.scheme() != "wss"
            || host(&u) != host(&origin)
            || u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
            || !LOCAL_STREAM.is_match(u.path())
        {
            return Err("invalid local stream route".into());
        }
        if c.used || c.ticket.is_some() {
            return Ok(HANGUP.into());
        }
        c.local_path = Some(u.path().to_string());
        c.ticket = Some(rand_hex(32));
        c.expires = Some(self.now() + 30_000);
        Ok(Self::stream_answer(c))
    }

    /// The hook's `responseAllowed` for the answer `rewrite` wrote.
    pub fn response_allowed(&self, xml: &str) -> bool {
        let st = self.lock();
        st.calls
            .values()
            .any(|c| self.current(c) && c.mode == "realtime" && c.ticket.is_some() && xml == Self::stream_answer(c))
    }

    fn refuse(&self) -> cc_http::Resp {
        {
            let now = self.now();
            let mut st = self.lock();
            st.refusals.retain(|t| *t > now - 60_000);
            if st.refusals.len() < 60 {
                st.refusals.push(now);
                drop(st);
                self.record("refusal", "admission", None);
            }
        }
        let mut r = cc_http::full(StatusCode::FORBIDDEN, "", Bytes::new());
        r.headers_mut()
            .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        r
    }

    /// Twilio's websocket to `/phone-stream/<ticket>`: the exact URL signed with the account's
    /// token, once, within 30 seconds of the answer. Never a proxy header.
    pub fn upgrade(self: &Arc<Self>, req: cc_http::Req) -> cc_http::Resp {
        let (parts, body) = req.into_parts();
        let target = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let signatures: Vec<&HeaderValue> = parts.headers.get_all("x-twilio-signature").iter().collect();
        let sid = {
            let mut st = self.lock();
            let found = st
                .calls
                .values()
                .find(|c| {
                    c.ticket
                        .as_ref()
                        .is_some_and(|t| target == format!("/phone-stream/{t}"))
                })
                .map(|c| c.sid.clone());
            let Some(c) = found.and_then(|s| st.calls.get_mut(&s)) else {
                drop(st);
                return self.refuse();
            };
            let ok = self.current(c)
                && !c.used
                && c.expires.is_some_and(|e| e >= self.now())
                && parts.method == http::Method::GET
                && signatures.len() == 1
                && signatures[0]
                    .to_str()
                    .is_ok_and(|sig| verify_url_form(c.binding.s("token"), &Self::public_url(c), &vec![], sig));
            if !ok {
                drop(st);
                return self.refuse();
            }
            // The handshake is checked before the ticket is spent: a broken one costs nothing.
            let key = parts
                .headers
                .get("sec-websocket-key")
                .and_then(|v| v.to_str().ok())
                .filter(|k| {
                    base64::engine::general_purpose::STANDARD
                        .decode(k)
                        .is_ok_and(|b| b.len() == 16)
                })
                .map(str::to_string);
            let version = parts.headers.get("sec-websocket-version").and_then(|v| v.to_str().ok());
            let Some(key) = key.filter(|_| version == Some("13")) else {
                // `ws` answers a broken handshake with 400.
                return cc_http::full(StatusCode::BAD_REQUEST, "", Bytes::new());
            };
            c.used = true;
            (c.sid.clone(), key)
        };
        let (sid, key) = sid;
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        let req = http::Request::from_parts(parts, body);
        let me = self.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(up) => {
                    let ws = WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, Some(ws_config())).await;
                    me.connect(sid, ws).await;
                }
                // As a stream that dropped: the call goes on classic (the same-hook Redirect), or
                // ends when it is no longer current.
                Err(_) => me.dropped(&sid),
            }
        });
        let mut r = cc_http::full(StatusCode::SWITCHING_PROTOCOLS, "", Bytes::new());
        let h = r.headers_mut();
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(http::header::CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Ok(v) = HeaderValue::from_str(&accept) {
            h.insert("sec-websocket-accept", v);
        }
        r
    }

    /// The relay of one call: Twilio's frames to the agent and the agent's back, every one checked.
    async fn connect<S>(self: Arc<Self>, sid: String, mut ws: WebSocketStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, mut close_rx) = mpsc::unbounded_channel::<(String, Option<Snapshot>)>();
        // The call as `end` took it out of the map, for the close line.
        let mut ended: Option<Snapshot> = None;
        let Some(started_at) = ({
            let mut st = self.lock();
            st.calls.get_mut(&sid).map(|c| {
                c.close = Some(tx.clone());
                c.started_at
            })
        }) else {
            let _ = ws.close(None).await;
            return;
        };
        let mut agent: Option<AgentWs> = None;
        let mut opening: Option<tokio::task::JoinHandle<Result<AgentWs, String>>> = None;
        let mut pending: Vec<String> = Vec::new();
        let mut pending_bytes = 0usize;
        let (mut sequence, mut connected, mut start) = (0i64, false, false);
        let (mut count, mut window) = (0u32, self.now());
        let (mut sent_audio, mut played_audio, mut media_ts) = (0i64, 0i64, -1i64);
        let mut marks: IndexMap<String, i64> = IndexMap::new();
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);
        let mut timed = true;

        let (reason, detail): (String, Option<String>) = loop {
            tokio::select! {
                r = close_rx.recv() => {
                    let (why, snap) = r.unwrap_or_else(|| ("shutdown".into(), None));
                    ended = snap;
                    break (why, None);
                }
                () = &mut timeout, if timed => break ("start_timeout".into(), None),
                opened = async { opening.as_mut().expect("guarded").await }, if opening.is_some() => {
                    opening = None;
                    match opened {
                        Ok(Ok(mut peer)) => {
                            if !self.still(&sid, started_at) {
                                let _ = peer.close(None).await;
                                break ("revoked".into(), None);
                            }
                            timed = false;
                            let snap = self.snap(&sid);
                            self.record("open", "verified", snap.as_ref());
                            let mut ok = true;
                            for text in pending.drain(..) {
                                if !send(&mut peer, text).await { ok = false; break; }
                            }
                            pending_bytes = 0;
                            agent = Some(peer);
                            if !ok { break ("backpressure".into(), None); }
                        }
                        Ok(Err(detail)) => {
                            // The Activity row has it too; the journal is where an operator looks first.
                            tracing::warn!("[phone] agent stream failed: {detail}");
                            break ("transport".into(), Some(detail));
                        }
                        Err(_) => break ("transport".into(), Some("agent_connect".into())),
                    }
                }
                m = ws.next() => {
                    let msg = match m {
                        None | Some(Ok(Message::Close(_))) => break ("transport".into(), None),
                        Some(Err(e)) => break (if is_protocol(&e) { "invalid_frame" } else { "transport" }.into(), None),
                        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                        Some(Ok(m)) => m,
                    };
                    if !self.still(&sid, started_at) {
                        break ("revoked".into(), None);
                    }
                    let Message::Text(data) = msg else { break ("invalid_frame".into(), None) };
                    let data = data.to_string();
                    let now = self.now();
                    if now - window >= 1000 {
                        window = now;
                        count = 0;
                    }
                    count += 1;
                    let over = self.count(&sid, data.len() as i64, true, count);
                    let Ok(e) = (if over { Err(()) } else { serde_json::from_str::<Value>(&data).map_err(|_| ()) }) else {
                        break ("invalid_frame".into(), None);
                    };
                    let event = e.get("event").and_then(Value::as_str).unwrap_or_default().to_string();
                    let verdict: Result<(), ()> = (|| {
                        if event == "connected" {
                            if connected || sequence != 0 || start || e.get("protocol") != Some(&json!("Call")) || e.get("version") != Some(&json!("1.0.0")) {
                                return Err(());
                            }
                            connected = true;
                            return Ok(());
                        }
                        let n = safe_int(e.get("sequenceNumber")).ok_or(())?;
                        if n <= sequence {
                            return Err(());
                        }
                        sequence = n;
                        if event == "start" {
                            let st = e.get("start");
                            let g = |k: &str| st.and_then(|s| s.get(k));
                            let f = |k: &str| st.and_then(|s| s.get("mediaFormat")).and_then(|m| m.get(k));
                            let stream_sid = e.get("streamSid").and_then(Value::as_str).unwrap_or_default();
                            let binding_ok = self.lock().calls.get(&sid).is_some_and(|c| {
                                g("accountSid") == c.binding.0.get("accountSid") && g("callSid") == Some(&json!(c.sid))
                            });
                            if !connected || start || !binding_ok || !STREAM_SID.is_match(stream_sid)
                                || g("streamSid") != e.get("streamSid")
                                || f("encoding") != Some(&json!("audio/x-mulaw"))
                                || f("sampleRate") != Some(&json!(8000))
                                || f("channels") != Some(&json!(1))
                            {
                                return Err(());
                            }
                            start = true;
                            if let Some(c) = self.lock().calls.get_mut(&sid) {
                                c.stream_sid = Some(stream_sid.to_string());
                                c.started = true;
                            }
                            let _ = self.publish();
                            let me = self.clone();
                            let s = sid.clone();
                            opening = Some(tokio::spawn(async move { me.open_agent(&s).await }));
                            return Ok(());
                        }
                        let stream = self.lock().calls.get(&sid).and_then(|c| c.stream_sid.clone());
                        if !start || e.get("streamSid").and_then(Value::as_str) != stream.as_deref()
                            || !["media", "mark", "dtmf", "stop"].contains(&event.as_str())
                        {
                            return Err(());
                        }
                        if event == "media" {
                            let media = e.get("media");
                            let stamp = safe_int(media.and_then(|m| m.get("timestamp"))).ok_or(())?;
                            if !valid_audio(media.and_then(|m| m.get("payload")))
                                || media.and_then(|m| m.get("track")) != Some(&json!("inbound"))
                                || stamp < media_ts
                            {
                                return Err(());
                            }
                            media_ts = stamp;
                        }
                        if event == "mark"
                            && let Some(name) = e.get("mark").and_then(|m| m.get("name")).and_then(Value::as_str)
                            && let Some(&boundary) = marks.get(name)
                        {
                            played_audio = played_audio.max(boundary);
                            marks.retain(|_, at| *at > boundary);
                        }
                        Ok(())
                    })();
                    if verdict.is_err() {
                        break ("invalid_frame".into(), None);
                    }
                    if let Some(peer) = agent.as_mut() {
                        if !send(peer, data).await {
                            break ("backpressure".into(), None);
                        }
                    } else {
                        pending_bytes += data.len();
                        if pending_bytes > 12000 {
                            break ("invalid_frame".into(), None);
                        }
                        pending.push(data);
                    }
                    if event == "stop" {
                        break ("completed".into(), None);
                    }
                }
                m = async { agent.as_mut().expect("guarded").next().await }, if agent.is_some() => {
                    let msg = match m {
                        None => break ("transport".into(), Some("agent_close_1006".into())),
                        Some(Ok(Message::Close(f))) => {
                            let code = f.map_or(1005, |f| u16::from(f.code));
                            break ("transport".into(), Some(format!("agent_close_{code}")));
                        }
                        Some(Err(e)) if is_protocol(&e) => break ("invalid_agent_frame".into(), None),
                        // As `ws` reports a peer gone without a close frame.
                        Some(Err(_)) => break ("transport".into(), Some("agent_close_1006".into())),
                        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                        Some(Ok(m)) => m,
                    };
                    let Message::Text(text) = msg else { break ("invalid_agent_frame".into(), None) };
                    let text = text.to_string();
                    let now = self.now();
                    if now - window >= 1000 {
                        window = now;
                        count = 0;
                    }
                    count += 1;
                    let over = self.count(&sid, text.len() as i64, false, count);
                    let stream = self.lock().calls.get(&sid).and_then(|c| c.stream_sid.clone());
                    let verdict: Result<(), ()> = (|| {
                        let v: Value = serde_json::from_str(&text).map_err(|_| ())?;
                        let event = v.get("event").and_then(Value::as_str).unwrap_or_default();
                        if over || !self.still(&sid, started_at)
                            || v.get("streamSid").and_then(Value::as_str) != stream.as_deref()
                            || !["media", "mark", "clear"].contains(&event)
                        {
                            return Err(());
                        }
                        match event {
                            "media" => {
                                let payload = v.get("media").and_then(|m| m.get("payload"));
                                if !valid_audio(payload) {
                                    return Err(());
                                }
                                let raw = payload.and_then(Value::as_str).unwrap_or_default();
                                sent_audio += base64::engine::general_purpose::STANDARD.decode(raw).map_or(0, |b| b.len() as i64);
                                if sent_audio - played_audio > 16000 {
                                    return Err(());
                                }
                            }
                            "mark" => {
                                let name = v.get("mark").and_then(|m| m.get("name")).and_then(Value::as_str).ok_or(())?;
                                if crate::channels::js::js_len(name) > 160 || marks.contains_key(name) || marks.len() >= 64 {
                                    return Err(());
                                }
                                marks.insert(name.to_string(), sent_audio);
                            }
                            _ => {
                                marks.clear();
                                sent_audio = 0;
                                played_audio = 0;
                            }
                        }
                        Ok(())
                    })();
                    if verdict.is_err() {
                        break ("invalid_agent_frame".into(), None);
                    }
                    if !send(&mut ws, text).await {
                        break ("backpressure".into(), None);
                    }
                }
            }
        };
        if let Some(h) = opening.take() {
            h.abort();
        }
        // The call's fate first: a peer that does not take a close frame must not hold it back.
        let snap = ended.or_else(|| self.snap(&sid));
        let label = detail
            .as_ref()
            .map_or_else(|| reason.clone(), |d| format!("{reason}_{d}"));
        self.record("close", &label, snap.as_ref());
        let fall_back = {
            let mut st = self.lock();
            match st.calls.get_mut(&sid) {
                Some(c) => {
                    c.started = false;
                    c.close = None;
                    if reason == "transport" && self.current(c) {
                        c.mode = "classic";
                        c.ticket = None;
                        true
                    } else {
                        false
                    }
                }
                None => false,
            }
        };
        if fall_back {
            // The trailing same-hook Redirect performs the one-way classic transition.
            let _ = self.publish();
        } else {
            self.end(&sid, &reason, reason != "completed");
        }
        // Then the sockets: a close handshake for at most a second each, else dropped, as the TS
        // `terminate()`s them.
        let _ = tokio::time::timeout(Duration::from_secs(1), ws.close(None)).await;
        if let Some(mut peer) = agent.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), peer.close(None)).await;
        }
    }

    /// A stream that could not be opened: the call falls back to classic while it is current,
    /// and ends otherwise.
    fn dropped(&self, sid: &str) {
        let fall_back = {
            let mut st = self.lock();
            match st.calls.get_mut(sid) {
                Some(c) if self.current(c) => {
                    c.mode = "classic";
                    c.ticket = None;
                    true
                }
                _ => false,
            }
        };
        if fall_back {
            let _ = self.publish();
        } else {
            self.end(sid, "transport", true);
        }
    }

    fn snap(&self, sid: &str) -> Option<Snapshot> {
        let now = self.now();
        self.lock().calls.get(sid).map(|c| Self::snapshot(c, now))
    }

    /// Counts one frame on the call; whether it is over the call's budget (200 a second, and per
    /// second of the call 140 frames and 64 KB).
    fn count(&self, sid: &str, len: i64, inbound: bool, in_window: u32) -> bool {
        let mut st = self.lock();
        let Some(c) = st.calls.get_mut(sid) else { return true };
        c.bytes += len;
        if inbound {
            c.inbound_bytes += len;
        } else {
            c.outbound_bytes += len;
        }
        c.frames += 1;
        in_window > 200 || c.frames > c.span_secs() * 140 || c.bytes > c.span_secs() * 65536
    }

    /// The agent's `/phone/stream`, with a token bound to this envelope and this handshake's key.
    async fn open_agent(&self, sid: &str) -> Result<AgentWs, String> {
        let (vm_id, envelope) = {
            let st = self.lock();
            let c = st.calls.get(sid).ok_or("agent_connect")?;
            let url = Self::public_url(c);
            let envelope = json!({
                "generation": c.binding.s("generation"),
                "ticket": c.ticket,
                "callSid": c.sid,
                "path": c.local_path,
                "url": url,
                "deadline": c.deadline,
                "signature": url_form_signature(c.binding.s("placeholder"), &url, &vec![]),
            })
            .to_string();
            (c.binding.s("vmId").to_string(), envelope)
        };
        // Where this firewall has the agent on record: an agent it does not know gets no stream.
        let host = (self.opts.host_for)(&vm_id).ok_or("agent_connect")?;
        let base = self
            .opts
            .agent_base
            .as_ref()
            .map_or_else(|| format!("wss://{host}"), |f| f(&host));
        let mut request = format!("{base}/__cc/agent/phone/stream")
            .into_client_request()
            .map_err(|_| "agent_connect")?;
        let key = request
            .headers()
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let binding = hex::encode(Sha256::digest(format!("{envelope}\n{key}").as_bytes()));
        let mut claims = cc_auth::sign::binding_claims("GET", "/phone/stream", Some(&host), None);
        claims.insert("phoneStream".into(), json!(binding));
        let token = (self.opts.sign)(&vm_id, claims).map_err(|_| "agent_connect")?;
        if !self.lock().calls.get(sid).is_some_and(|c| self.current(c)) {
            return Err("agent_connect".into());
        }
        let h = request.headers_mut();
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| "agent_connect")?,
        );
        h.insert(
            "x-cc-phone-stream",
            HeaderValue::from_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope.as_bytes()))
                .map_err(|_| "agent_connect")?,
        );
        let connect = async {
            let uri = request.uri().clone();
            // `[::1]` as the URI writes an IPv6 literal; the address without the brackets.
            let host = uri
                .host()
                .unwrap_or_default()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            let tls = uri.scheme_str() == Some("wss");
            let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| "agent unavailable".to_string())?;
            let stream: AgentIo = if tls {
                let name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|_| "agent unavailable".to_string())?;
                let conn = tokio_rustls::TlsConnector::from(tls_config())
                    .connect(name, tcp)
                    .await
                    .map_err(|_| "agent unavailable".to_string())?;
                AgentIo::Tls(Box::new(conn))
            } else {
                AgentIo::Plain(tcp)
            };
            match tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config())).await {
                Ok((ws, _)) => Ok(ws),
                Err(WsError::Http(r)) => Err(format!("agent_http_{}", r.status().as_u16())),
                Err(_) => Err("agent unavailable".to_string()),
            }
        };
        let r = tokio::time::timeout(Duration::from_secs(5), connect)
            .await
            .unwrap_or_else(|_| Err("agent unavailable".to_string()));
        // Only `agent_http_<status>` says more than "it failed".
        r.map_err(|e| {
            if e.starts_with("agent_http_") {
                e
            } else {
                "agent_connect".into()
            }
        })
    }

    /// The leases the proxy reads: every started realtime call, by agent.
    fn publish(&self) -> Result<(), String> {
        let now = self.now();
        let mut live: IndexMap<String, Vec<Value>> = IndexMap::new();
        {
            let st = self.lock();
            for c in st.calls.values() {
                if !c.started || !self.current(c) || !c.binding.speech_available() || c.binding.speech().is_none() {
                    continue;
                }
                live.entry(c.binding.s("vmId").to_string()).or_default().push(json!({
                    "id": c.ticket,
                    "purpose": "phone",
                    "started": secs(c.started_at),
                    "expires": secs(c.deadline.min(now + 3000)),
                    "deadline": secs(c.deadline),
                    "speech": c.binding.speech(),
                    "voice_placeholder": c.binding.0.get("voicePlaceholder"),
                    "max_bytes": 512 * 1024 * 1024,
                }));
            }
        }
        cc_contracts::write_atomic(&self.opts.media_dir, &cc_contracts::FileSpec::PHONE_MEDIA, &live)
            .map_err(|e| e.to_string())
    }

    fn tick(&self) -> Result<(), String> {
        let now = self.now();
        let b = (self.opts.binding)();
        let limits = b.as_ref().map(Binding::limits).transpose()?;
        let limit = limits.as_ref().map_or(0, |l| l.max_concurrent_calls);
        let mut hang = Vec::new();
        let mut ends = Vec::new();
        {
            let mut st = self.lock();
            st.ended.retain(|_, t| *t >= now);
            let ids: Vec<String> = st.reservations.keys().cloned().collect();
            for id in ids {
                let gone = {
                    let r = &st.reservations[&id];
                    b.as_ref()
                        .is_none_or(|b| b.s("generation") != r.binding.s("generation"))
                        || r.expires <= now
                        || (st.reservations.len() + st.calls.len()) as i64 > limit
                };
                if gone
                    && let Some(r) = st.reservations.shift_remove(&id)
                    && let Some(sid) = r.sid
                {
                    hang.push(sid);
                }
            }
            let mut kept = 0;
            for c in st.calls.values_mut() {
                let cur = self.current(c);
                if !cur || (c.started && !b.as_ref().is_some_and(Binding::speech_available)) || kept >= limit {
                    ends.push((c.sid.clone(), "revoked"));
                } else if c.ticket.is_some() && !c.used && c.expires.is_some_and(|e| e < now) {
                    ends.push((c.sid.clone(), "admission_expired"));
                } else {
                    kept += 1;
                    if let Some(l) = &limits {
                        c.deadline = c.deadline.min(c.started_at + l.max_duration_seconds * 1000);
                    }
                }
            }
        }
        for sid in hang {
            self.hang_up(sid);
        }
        for (sid, why) in ends {
            self.end(&sid, why, true);
        }
        self.publish()
    }

    /// A call is over: its relay closes, Twilio is told to hang up when `hangup`.
    pub fn end(&self, sid: &str, reason: &str, hangup: bool) {
        let now = self.now();
        let (close, snap) = {
            let mut st = self.lock();
            let Some(c) = st.calls.shift_remove(sid) else { return };
            st.ended.insert(sid.to_string(), c.deadline + 300_000);
            let snap = Self::snapshot(&c, now);
            (c.close, snap)
        };
        if let Some(tx) = close {
            let _ = tx.send((reason.to_string(), Some(snap)));
        }
        if hangup {
            self.hang_up(sid.to_string());
        }
        let _ = self.publish();
    }

    /// Every call ends (`close`).
    #[allow(dead_code)] // shutdown
    pub fn close(&self) {
        let sids: Vec<String> = self.lock().calls.keys().cloned().collect();
        for sid in sids {
            self.end(&sid, "shutdown", true);
        }
    }
}

/// A frame that broke the protocol (`ws`'s `WS_*` error codes). A connection dropped without a
/// close handshake is not one: `ws` reports it as a close (1006).
fn is_protocol(e: &WsError) -> bool {
    use tokio_tungstenite::tungstenite::error::ProtocolError;
    match e {
        WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => false,
        WsError::Protocol(_) | WsError::Capacity(_) | WsError::Utf8(_) => true,
        _ => false,
    }
}

fn ws_config() -> WebSocketConfig {
    let mut c = WebSocketConfig::default();
    c.max_message_size = Some(MAX_PAYLOAD);
    c.max_frame_size = Some(MAX_PAYLOAD);
    c
}

/// One write, within a second, of at most 16 KB. False: the stream ends as backpressure.
async fn send<S>(ws: &mut WebSocketStream<S>, data: String) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if data.len() > MAX_PAYLOAD {
        return false;
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(1), ws.send(Message::text(data))).await,
        Ok(Ok(()))
    )
}

/// The Mozilla roots, and whatever NODE_EXTRA_CA_CERTS adds, as the firewall's other calls to agents.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Ok(path) = std::env::var("NODE_EXTRA_CA_CERTS")
            && let Ok(pem) = std::fs::read(&path)
        {
            for cert in rustls_pemfile::certs(&mut pem.as_slice()).flatten() {
                let _ = roots.add(cert);
            }
        }
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("tls versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    });
    CONFIG.clone()
}

pub enum AgentIo {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

type AgentWs = WebSocketStream<AgentIo>;

impl tokio::io::AsyncRead for AgentIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AgentIo::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            AgentIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for AgentIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            AgentIo::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            AgentIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AgentIo::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            AgentIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AgentIo::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            AgentIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// The proxy's admission on `127.0.0.1:8791` (`phone-admission.ts`): `reserve` before an outbound
/// call is placed, `settle` once Twilio answered. Anything else, or anything that fails: 403.
pub fn admission_router(streams: Arc<PhoneStreams>) -> cc_http::Router {
    let mut router = cc_http::Router::new(&["phone"]);
    router.route(
        "phone",
        |_, _| true,
        move |req, _| {
            let streams = streams.clone();
            async move {
                use http_body_util::BodyExt;
                let refused = || cc_http::full(StatusCode::FORBIDDEN, "", "{\"ok\":false}");
                let (parts, body) = req.into_parts();
                let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
                if parts.method != http::Method::POST || target != "/" {
                    return refused();
                }
                // The TS server's 5 s request timeout.
                let read = tokio::time::timeout(
                    Duration::from_secs(5),
                    http_body_util::Limited::new(body, 8192).collect(),
                );
                let Ok(Ok(raw)) = read.await else {
                    return refused();
                };
                let raw = raw.to_bytes();
                let Ok(text) = std::str::from_utf8(&raw) else {
                    return refused();
                };
                if crate::channels::js::js_len(text) > 2048 {
                    return refused();
                }
                let Ok(p) = serde_json::from_str::<Value>(text) else {
                    return refused();
                };
                let action = p.get("action").and_then(Value::as_str);
                let id = match action {
                    Some("reserve") => {
                        let none = Value::Null;
                        match streams.reserve(p.get("vmId").unwrap_or(&none), p.get("placeholder").unwrap_or(&none)) {
                            Ok(id) => Some(id),
                            Err(_) => return refused(),
                        }
                    }
                    Some("settle") if p.get("id").is_some_and(Value::is_string) => {
                        streams.settle_reservation(
                            p["id"].as_str().unwrap_or_default(),
                            p.get("sid"),
                            p.get("rejected") == Some(&Value::Bool(true)),
                        );
                        None
                    }
                    _ => return refused(),
                };
                let mut out = Map::new();
                out.insert("ok".into(), json!(true));
                if let Some(id) = id {
                    out.insert("id".into(), json!(id));
                }
                cc_http::full(StatusCode::OK, "application/json", Value::Object(out).to_string())
            }
        },
    );
    router
}
