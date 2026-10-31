//! Meeting and phone voice (appendix F features 26 and 23, addon.py 4160-4592 and 6013-6179).
//!
//! A voice socket is a call-scoped capability, separate from ordinary text credentials. It needs
//! an active lease the firewall agent published (`meeting-media.json`, `phone-media.json`), the
//! exact model the lease binds, of a family the firewall polices (`realtime` or `live`), at the
//! provider's own HTTPS name. The gateway's upstream token stays on the firewall: the agent gets
//! an opaque one-time stand-in (60 s), swapped back in the socket's upgrade. Every frame from the
//! agent is read against an allow-list; bytes, frames, responses and starts are counted per lease;
//! a watcher closes the socket when its lease ends (0.25 s for a call, 1 s for a meeting). The
//! question to the main agent and its answer are read by the content rules ([`rules`]).
//!
//! No audio, transcripts or tool arguments are kept here, beyond a 50-second transcript window
//! per socket while a rule reads voice coming in.
//!
//! **W1.** The socket closes from outside a frame through [`closing`]: select on it in the pump
//! and close both sides when it turns `true`. Until then a lease that ended still closes the
//! socket at its next frame, so nothing passes after it; only an idle socket stays open.

mod frames;
mod lease;
mod rules;

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub use frames::{live_client_event, speech_family, voice_client_event};
pub use lease::wake_sessions;

use super::check_host;
use super::content::{CheckError, Content};
use super::creds::{Creds, truthy};
use super::logins::scope::{header_values, is_https, method, port, target};
use crate::flow::{Direction, Flow, FrameKind, Hook, Pipeline, Step, StepFuture, Verdict, order};

pub const VOICE_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub const VOICE_MAX_FRAMES: u64 = 250_000;
pub const VOICE_FRAME_MAX: usize = 512 * 1024;
pub const VOICE_MAX_RESPONSES: u64 = 120;
pub const WAKE_MAX_SESSIONS: u64 = 40;
pub const WAKE_OPENS_PER_SESSION: u64 = 6;
pub const WAKE_START_GAP: f64 = 2.0;
const GATEWAY: &str = "ai-gateway.vercel.sh";
const OPENAI: &str = "api.openai.com";
const AUTH_PREFIX: &str = "ai-gateway-auth.";

/// The socket's admission, as the addon's `flow.metadata["cc_voice"]`; later frames keep their
/// per-socket state under it (`live`, `content`, `seconds`).
pub const META_VOICE: &str = "cc_voice";
/// The speech stand-in this request was admitted with: only it is swapped ([`VoiceSwap`]).
pub const META_CREDENTIAL: &str = "voice_credential";
/// The record of a gpt-live socket's billed seconds, written by the plumbing when the socket ends
/// (the addon's second record, `flow_id` + `:end`).
pub const META_END_RECORD: &str = "cc_voice_end_record";
/// The stand-in token the agent offered: what it sees again if the provider echoes the real one.
const META_OFFERED: &str = "cc_voice_offered";

fn voice_paths(host: &str) -> &'static [&'static str] {
    match host {
        GATEWAY => &[
            "/v1/realtime/client-secrets",
            "/v4/ai/realtime-model",
            "/v1/live/sessions",
        ],
        OPENAI => &["/v1/realtime", "/v1/live", "/v1/live/sessions", "/v1/realtime/calls"],
        _ => &[],
    }
}

/// An upstream token minted for a call, kept here and never shown to the agent.
#[derive(Clone)]
struct Minted {
    vm_id: String,
    lease_id: String,
    model: String,
    expires: f64,
    token: String,
    purpose: String,
}

/// One lease's counters (`_voice_usage`).
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub deadline: f64,
    pub bytes: u64,
    pub frames: u64,
    pub attempts: u64,
    /// The flow id of the socket using it.
    pub active: Option<String>,
    pub responses: u64,
    pub reserved_until: f64,
    pub last_start: f64,
    pub audio_sockets: u64,
}

/// Sockets a watcher may close: flow id → `true` once its lease ended.
type Closing = (tokio::sync::watch::Sender<bool>, Option<tokio::task::AbortHandle>);

/// Sockets a watcher may close: flow id → the signal, `true` once its lease ended, and its watcher.
static CLOSING: LazyLock<Mutex<HashMap<String, Closing>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// For the plumbing (W1): turns `true` when this voice socket must close. `None` for a flow that
/// is not a voice socket.
pub fn closing(flow_id: &str) -> Option<tokio::sync::watch::Receiver<bool>> {
    CLOSING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(flow_id)
        .map(|(tx, _)| tx.subscribe())
}

fn closed(flow_id: &str) -> bool {
    CLOSING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(flow_id)
        .is_some_and(|(tx, _)| *tx.borrow())
}

pub struct Voice {
    pub creds: Arc<Creds>,
    /// `identities.json`, read with the same cache as the credentials.
    pub identities: Creds,
    pub meeting_path: std::path::PathBuf,
    pub phone_path: std::path::PathBuf,
    pub content: Arc<Content>,
    /// `MEETING_PROXY_STARTED`: a lease that started before this process is not honoured.
    pub started: f64,
    /// `time.monotonic`, in seconds; a test's own clock.
    pub clock: Box<dyn Fn() -> f64 + Send + Sync>,
    tokens: Mutex<HashMap<String, Minted>>,
    usage: Mutex<HashMap<String, Usage>>,
}

fn monotonic() -> f64 {
    static START: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
    // Ahead of zero, as `time.monotonic` is: a window that starts "before" zero still works.
    START.elapsed().as_secs_f64() + 1000.0
}

impl Voice {
    pub fn new(creds: Arc<Creds>, content: Arc<Content>) -> Arc<Self> {
        let s = &content.settings;
        Arc::new(Self {
            identities: Creds::new(s.identities_path.clone()),
            meeting_path: s.meeting_media_path.clone(),
            phone_path: s.phone_media_path.clone(),
            creds,
            content,
            started: super::content::rules::now(),
            clock: Box::new(monotonic),
            tokens: Mutex::new(HashMap::new()),
            usage: Mutex::new(HashMap::new()),
        })
    }

    fn usage(&self) -> std::sync::MutexGuard<'_, HashMap<String, Usage>> {
        self.usage.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn tokens(&self) -> std::sync::MutexGuard<'_, HashMap<String, Minted>> {
        self.tokens.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A lease's counters, for tests.
    #[cfg(test)]
    pub fn usage_of(&self, lease_id: &str) -> Option<Usage> {
        self.usage().get(lease_id).cloned()
    }

    /// Set a lease's counters, for tests.
    #[cfg(test)]
    pub fn set_usage(&self, lease_id: &str, u: Usage) {
        self.usage().insert(lease_id.to_owned(), u);
    }

    /// Whether the request is on a voice path of its host (the name it went to or claims).
    pub fn on_voice_path(&self, flow: &Flow) -> bool {
        let full = target(flow);
        let path = full.split('?').next().unwrap_or("");
        let claimed = flow.claimed_host().unwrap_or_default();
        voice_paths(&check_host(flow)).contains(&path) || voice_paths(claimed.trim_end_matches('.')).contains(&path)
    }

    /// `voice_request`: `Some(refusal)` for a voice request the firewall refuses; `None` for one it
    /// admitted (marked on the flow) or one that is not voice.
    pub fn request(&self, flow: &mut Flow) -> Option<&'static str> {
        let host = check_host(flow);
        let full = target(flow);
        let path = full.split('?').next().unwrap_or("").to_owned();
        let vm_id = flow.vm_id.clone().unwrap_or_default();
        let credentials = self.creds.for_host(&host, Some(&vm_id));
        let authorization = header_values(flow, "authorization").join(", ");
        let speech_cred = credentials.into_iter().find(|c| {
            truthy(c.get("speech"))
                && c.get("placeholder")
                    .and_then(Value::as_str)
                    .is_some_and(|p| !p.is_empty() && authorization.contains(p))
        });
        let placeholder = speech_cred
            .as_ref()
            .and_then(|c| c.get("placeholder").and_then(Value::as_str))
            .unwrap_or("")
            .to_owned();
        if speech_cred.is_some() {
            let head: String = authorization.chars().take(7).collect();
            let rest: String = authorization.chars().skip(7).collect();
            if head.to_lowercase() != "bearer " || rest != placeholder {
                return Some("Invalid speech authorization");
            }
        }
        // The name the request claims counts too (the addon's `pretty_host`): a voice request sent
        // elsewhere is refused below, never passed on as an ordinary one.
        let claimed = flow.claimed_host().unwrap_or_default();
        let realtime = voice_paths(&host).contains(&path.as_str())
            || voice_paths(claimed.trim_end_matches('.')).contains(&path.as_str());
        if !realtime && speech_cred.is_none() {
            return None;
        }
        let mut purpose = if speech_cred.as_ref().is_some_and(|c| truthy(c.get("phone_speech"))) {
            "phone".to_owned()
        } else {
            "meeting".to_owned()
        };
        let protocols: Vec<String> = header_values(flow, "sec-websocket-protocol")
            .join(", ")
            .split(',')
            .map(|p| p.trim().to_owned())
            .collect();
        let auth_tokens: Vec<&str> = protocols.iter().filter_map(|p| p.strip_prefix(AUTH_PREFIX)).collect();
        let mut bound: Option<Minted> = None;
        if speech_cred.is_none() && auth_tokens.len() == 1 {
            bound = self.tokens().get(&digest(auth_tokens[0])).cloned();
            if let Some(b) = &bound {
                purpose.clone_from(&b.purpose);
            }
        }
        // The counters are held from here: a call lease is picked and reserved in one step, so two
        // calls starting at once do not both take the same free lease.
        let mut all = self.usage();
        let lease = if purpose == "phone" {
            self.phone_lease_in(&all, &vm_id, bound.as_ref().map(|b| b.lease_id.as_str()))
        } else {
            self.meeting_lease(&vm_id, None)
        };
        let speech = lease
            .as_ref()
            .and_then(|l| l.get("speech"))
            .and_then(Value::as_object)
            .cloned();
        let (Some(lease), Some(speech), true) = (lease, speech, realtime) else {
            return Some("Voice needs an active approved call");
        };
        let provider = speech.get("provider").and_then(Value::as_str).unwrap_or("").to_owned();
        let model_value = speech.get("model").cloned().unwrap_or(Value::Null);
        if speech_cred.is_some() && lease.get("voice_placeholder").and_then(Value::as_str) != Some(placeholder.as_str())
        {
            return Some("Speech credential does not match this call");
        }
        let expected = if provider == "gateway" { GATEWAY } else { OPENAI };
        // The addon re-points a transparent request at the provider's name. Here the plumbing
        // dials the checked destination: it has to be the provider's, on 443, and the client's
        // TLS name (when it sent one) the same.
        let sni = flow.sni.as_deref().unwrap_or("").to_lowercase();
        let dest_ok = flow
            .destination()
            .is_some_and(|d| d.port == 443 && d.name.trim_end_matches('.').eq_ignore_ascii_case(expected));
        if !is_https(flow) || port(flow) != 443 || (!sni.is_empty() && sni != expected) || !dest_ok {
            return Some("Voice requires the verified provider HTTPS destination");
        }
        let model = model_value.as_str().unwrap_or("").to_owned();
        let family = model_value.as_str().and_then(|m| speech_family(&provider, m));
        // `pretty_host` is the Host header's name: it has to be the provider's too.
        let claimed_ok = flow.claimed_host().is_none_or(|c| c.trim_end_matches('.') == expected);
        let (Some(family), true) = (family, host == expected && claimed_ok) else {
            return Some("Speech provider does not match this call");
        };
        let now = super::content::rules::now();
        let lease_id = lease.get("id").and_then(Value::as_str).unwrap_or("").to_owned();
        self.tokens().retain(|_, m| m.expires >= now);
        all.retain(|_, u| u.deadline >= now);
        let usage = all.entry(lease_id.clone()).or_insert_with(|| Usage {
            deadline: lease.get("deadline").and_then(Value::as_f64).unwrap_or(0.0),
            ..Usage::default()
        });
        if usage.bytes >= VOICE_MAX_BYTES || usage.responses >= VOICE_MAX_RESPONSES || usage.active.is_some() {
            return Some("Voice call limit reached");
        }
        let gateway = provider == "gateway";
        let mint = gateway && path == "/v1/realtime/client-secrets";
        let wake = wake_sessions(&lease, family, &purpose);
        let starts = mint || !gateway;
        if starts && usage.attempts >= (if wake > 0 { wake * WAKE_OPENS_PER_SESSION } else { 4 }) {
            return Some("Voice call limit reached");
        }
        if wake > 0 && starts && now - usage.last_start < WAKE_START_GAP {
            return Some("Voice sessions are starting too fast");
        }
        let query = query_pairs(&full);
        if mint {
            let expected_body = if family == "live" {
                json!({"model": model_value, "routeKind": "live"})
            } else {
                json!({"model": model_value, "expiresIn": 60})
            };
            // A body the plumbing did not decode cannot be compared: refused.
            let body = flow
                .request
                .as_ref()
                .filter(|_| super::request_body_ready(flow))
                .and_then(|r| std::str::from_utf8(r.body()).ok())
                .and_then(|t| super::json::loads(t).ok());
            if method(flow) != "POST"
                || speech_cred.is_none()
                || !body.is_some_and(|b| frames::py_eq(&b, &expected_body))
            {
                return Some("Invalid realtime token request");
            }
            usage.attempts += 1;
            usage.last_start = now;
        } else {
            let upgrade = header_values(flow, "upgrade").join(", ").to_lowercase();
            if method(flow) != "GET" || upgrade != "websocket" {
                return Some("Only the approved voice WebSocket is allowed");
            }
            if gateway {
                // gpt-live names its model in the first frame (session.start), checked frame by frame.
                let wrong = if family == "live" {
                    path != "/v1/live/sessions" || !query.is_empty()
                } else {
                    path != "/v4/ai/realtime-model" || query != [("ai-model-id".to_owned(), model.clone())]
                };
                if wrong {
                    return Some("Realtime model does not match this call");
                }
                if auth_tokens.len() != 1 {
                    return Some("Missing call token");
                }
                let taken = self.tokens().remove(&digest(auth_tokens[0]));
                let Some(b) = taken.filter(|b| {
                    b.vm_id == vm_id
                        && b.lease_id == lease_id
                        && b.model == model
                        && b.expires > now
                        && b.purpose == purpose
                }) else {
                    return Some("Call token expired or belongs to another call");
                };
                let rewritten: Vec<String> = protocols
                    .iter()
                    .map(|p| {
                        if p.starts_with(AUTH_PREFIX) {
                            format!("{AUTH_PREFIX}{}", b.token)
                        } else {
                            p.clone()
                        }
                    })
                    .collect();
                if let (Some(r), Ok(v)) = (
                    flow.request.as_mut(),
                    http::HeaderValue::from_str(&rewritten.join(", ")),
                ) {
                    r.headers_mut().insert(http::header::SEC_WEBSOCKET_PROTOCOL, v);
                } else {
                    return Some("Call token expired or belongs to another call");
                }
                flow.meta.insert(META_OFFERED, json!(auth_tokens[0]));
            } else {
                let wrong = if family == "live" {
                    path != "/v1/live/sessions" || !query.is_empty()
                } else {
                    path != "/v1/realtime" || query != [("model".to_owned(), model.clone())]
                };
                if speech_cred.is_none() || wrong {
                    return Some("Invalid provider voice request");
                }
                usage.attempts += 1;
                usage.last_start = now;
                if provider == "codex"
                    && let Some(account) = speech_cred
                        .as_ref()
                        .and_then(|c| c.get("speech_account_id"))
                        .filter(|a| truthy(Some(a)))
                        .and_then(Value::as_str)
                    && let (Some(r), Ok(v)) = (flow.request.as_mut(), http::HeaderValue::from_str(account))
                {
                    r.headers_mut().insert("chatgpt-account-id", v);
                }
            }
        }
        if purpose == "phone" {
            usage.reserved_until = now + 60.0;
        }
        drop(all);
        flow.meta.insert(
            META_VOICE,
            json!({"vm_id": vm_id, "lease_id": lease_id, "model": model, "provider": provider, "mint": mint,
                   "purpose": purpose, "family": family, "wake": wake}),
        );
        if speech_cred.is_some() {
            flow.meta.insert(META_CREDENTIAL, json!(placeholder));
        }
        None
    }

    /// `voice_response`: the gateway's minted token kept here, a one-time stand-in to the agent.
    pub fn response(&self, flow: &mut Flow) {
        let Some(voice) = flow.meta.get(META_VOICE).and_then(Value::as_object).cloned() else {
            return;
        };
        self.hide_token(flow);
        if voice.get("mint") != Some(&Value::Bool(true)) {
            return;
        }
        let s = |k: &str| voice.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let Some(resp) = flow.response.as_ref() else { return };
        if resp.status() != 200 {
            if let Some(u) = self.usage().get_mut(&s("lease_id")) {
                u.reserved_until = 0.0;
            }
            return;
        }
        // A body the plumbing did not decode cannot be read for the token: never passed on.
        let token = super::body_ready(flow)
            .then(|| std::str::from_utf8(resp.body()).ok())
            .flatten()
            .and_then(|t| super::json::loads(t).ok())
            .and_then(|v| v.get("token").cloned())
            .and_then(|t| t.as_str().map(str::to_owned))
            .filter(|t| t.chars().count() <= 8192);
        let Some(token) = token else {
            let mut r = http::Response::new(Bytes::from_static(br#"{"error":"Voice token unavailable"}"#));
            *r.status_mut() = http::StatusCode::BAD_GATEWAY;
            flow.response = Some(r);
            return;
        };
        let opaque = format!(
            "cc-voice-{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        self.tokens().insert(
            digest(&opaque),
            Minted {
                vm_id: s("vm_id"),
                lease_id: s("lease_id"),
                model: s("model"),
                expires: super::content::rules::now() + 60.0,
                token,
                purpose: Some(s("purpose"))
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| "meeting".into()),
            },
        );
        if let Some(r) = flow.response.as_mut() {
            super::set_body(r, super::pyjson::dumps(&json!({"token": opaque})).into_bytes());
        }
    }

    /// The upgrade's answer never shows the agent the provider's token: a subprotocol the provider
    /// echoes with it goes back to the stand-in the agent offered (the addon passed it on).
    fn hide_token(&self, flow: &mut Flow) {
        let offered = flow.meta.get(META_OFFERED).and_then(Value::as_str).map(str::to_owned);
        let Some(r) = flow.response.as_mut() else { return };
        let joined = r
            .headers()
            .get_all(http::header::SEC_WEBSOCKET_PROTOCOL)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        if !joined.contains(AUTH_PREFIX) {
            return;
        }
        let kept: Vec<String> = joined
            .split(',')
            .map(str::trim)
            .filter_map(|p| {
                if p.starts_with(AUTH_PREFIX) {
                    offered.as_ref().map(|o| format!("{AUTH_PREFIX}{o}"))
                } else {
                    Some(p.to_owned())
                }
            })
            .collect();
        r.headers_mut().remove(http::header::SEC_WEBSOCKET_PROTOCOL);
        if let Ok(v) = http::HeaderValue::from_str(&kept.join(", "))
            && !kept.is_empty()
        {
            r.headers_mut().insert(http::header::SEC_WEBSOCKET_PROTOCOL, v);
        }
    }

    /// `websocket_start`: the socket takes its lease, and a watcher closes it when the lease ends.
    fn start(self: &Arc<Self>, flow: &mut Flow) -> Verdict {
        let Some(voice) = flow.meta.get(META_VOICE).and_then(Value::as_object).cloned() else {
            return Verdict::Continue;
        };
        let lease_id = voice.get("lease_id").and_then(Value::as_str).unwrap_or("").to_owned();
        let live = self.voice_lease(&voice).is_some();
        {
            let mut all = self.usage();
            match all.get_mut(&lease_id) {
                Some(u) if u.active.is_none() && live => u.active = Some(flow.id.clone()),
                _ => return Verdict::Kill("voice: no lease".into()),
            }
        }
        let (tx, _) = tokio::sync::watch::channel(false);
        CLOSING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(flow.id.clone(), (tx, None));
        let every = if voice.get("purpose").and_then(Value::as_str) == Some("phone") {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(1)
        };
        let me = self.clone();
        let id = flow.id.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if me.voice_lease(&voice).is_none() {
                    if let Some((tx, _)) = CLOSING
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&id)
                    {
                        let _ = tx.send(true);
                    }
                    return;
                }
            }
        });
        if let Some(entry) = CLOSING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&flow.id)
        {
            entry.1 = Some(task.abort_handle());
        }
        self.hide_token(flow);
        Verdict::Continue
    }

    /// `websocket_end`: the lease is free again; a gpt-live socket's billed seconds are recorded.
    fn end(&self, flow: &mut Flow) {
        let Some(voice) = flow.meta.get(META_VOICE).and_then(Value::as_object).cloned() else {
            return;
        };
        if let Some((_, Some(watcher))) = CLOSING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&flow.id)
        {
            watcher.abort();
        }
        let lease_id = voice.get("lease_id").and_then(Value::as_str).unwrap_or("");
        if let Some(u) = self.usage().get_mut(lease_id)
            && u.active.as_deref() == Some(flow.id.as_str())
        {
            u.active = None;
            u.reserved_until = 0.0;
        }
        // Metadata only: never provider payloads or close reasons.
        if voice.get("family").and_then(Value::as_str) == Some("live")
            && let Some(seconds) = voice.get("seconds").and_then(Value::as_i64)
        {
            let host = flow.claimed_host().unwrap_or_default();
            let purpose = voice.get("purpose").and_then(Value::as_str).unwrap_or("meeting");
            let model = voice.get("model").and_then(Value::as_str).unwrap_or("");
            flow.meta.insert(
                META_END_RECORD,
                json!({"flow_id": format!("{}:end", flow.id), "host": host, "method": "GET",
                       "path": super::record::redact_path(&target(flow), &host), "effect": "allow",
                       "rule": format!("{purpose}_voice: {model} {seconds} s billed")}),
            );
        }
    }

    /// `websocket_message`: one frame on a voice socket.
    async fn frame(&self, flow: &mut Flow) -> Verdict {
        let Some(Value::Object(mut voice)) = flow.meta.remove(META_VOICE) else {
            return Verdict::Continue;
        };
        let verdict = self.frame_with(flow, &mut voice).await;
        flow.meta.insert(META_VOICE, Value::Object(voice));
        verdict
    }

    async fn frame_with(&self, flow: &mut Flow, voice: &mut Map<String, Value>) -> Verdict {
        let Some(frame) = flow.ws_frame.as_ref() else {
            return Verdict::Continue;
        };
        // Control frames carry nothing to the provider or back; mitmproxy never shows them.
        if matches!(frame.kind, FrameKind::Ping | FrameKind::Pong | FrameKind::Close) {
            return Verdict::Continue;
        }
        if closed(&flow.id) {
            return Verdict::Kill("voice: the lease ended".into());
        }
        let from_client = frame.direction == Direction::Out;
        let payload = frame.payload.clone();
        let s = |k: &str| voice.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let (provider, model, family) = (s("provider"), s("model"), s("family"));
        let wake = voice.get("wake").and_then(Value::as_u64).unwrap_or(0);
        let lease_id = s("lease_id");
        let live = self.voice_lease(voice).is_some();
        let mut reject;
        let event = std::str::from_utf8(&payload)
            .ok()
            .and_then(|t| super::json::loads(t).ok());
        {
            let mut all = self.usage();
            let usage = all.get_mut(&lease_id);
            reject = usage.is_none() || !live;
            let mut usage = usage;
            if let Some(u) = usage.as_deref_mut() {
                u.bytes += payload.len() as u64;
                u.frames += 1;
                reject |= u.bytes > VOICE_MAX_BYTES || u.frames > VOICE_MAX_FRAMES || payload.len() > VOICE_FRAME_MAX;
            }
            match &event {
                None => reject = true,
                Some(ev) if from_client => {
                    let state = obj(voice, "live");
                    reject |= !voice_client_event(ev, &provider, &model, &family, state);
                    if wake > 0
                        && let Some(u) = usage.as_deref_mut()
                    {
                        // A frame that is not an object was refused above (the addon raised here).
                        let audio = ev.get("type").and_then(Value::as_str) == Some("session.input_audio.append");
                        if audio && state.get("audio") != Some(&Value::Bool(true)) {
                            // This session is given meeting audio: it counts against the meeting's sessions.
                            state.insert("audio".into(), Value::Bool(true));
                            u.audio_sockets += 1;
                            reject |= u.audio_sockets > wake;
                        }
                    }
                }
                Some(ev) => match ev.get("type").and_then(Value::as_str) {
                    Some("session.usage.updated" | "session.closed") => {
                        // Billed seconds of a gpt-live session (cumulative): kept for its record.
                        let secs = ev
                            .get("usage")
                            .and_then(Value::as_object)
                            .and_then(|u| match u.get("seconds") {
                                Some(Value::Number(n)) => n.as_f64(),
                                Some(Value::Bool(b)) => Some(f64::from(u8::from(*b))),
                                _ => None,
                            });
                        if let Some(secs) = secs.filter(|s| (0.0..=86400.0).contains(s)) {
                            let before = voice.get("seconds").and_then(Value::as_i64).unwrap_or(0);
                            voice.insert("seconds".into(), json!(before.max(secs.trunc() as i64)));
                        }
                    }
                    Some("response-created" | "response.created") => {
                        if let Some(u) = usage {
                            u.responses += 1;
                            reject |= u.responses > VOICE_MAX_RESPONSES;
                        }
                    }
                    _ => {}
                },
            }
        }
        if reject {
            return Verdict::Kill("voice: frame refused".into());
        }
        let Some(mut event) = event else {
            return Verdict::Kill("voice: frame refused".into());
        };
        match rules::check(self, flow, voice, from_client, &mut event).await {
            Ok(rules::Outcome::Keep) => Verdict::Continue,
            Ok(rules::Outcome::Rewrite) => {
                if let Some(f) = flow.ws_frame.as_mut() {
                    f.payload = Bytes::from(super::pyjson::dumps(&event));
                }
                Verdict::Continue
            }
            Ok(rules::Outcome::Answer(answer)) => {
                // The box never starts this lookup: the firewall answers it on the socket itself.
                // mitmproxy ran the injected frame through `websocket_message` as one from the
                // agent: it counts against the lease and must pass the policy, or the voice ends.
                if !self.injected_frame_passes(voice, &answer) {
                    return Verdict::Kill("voice: frame refused".into());
                }
                flow.inject.push(crate::flow::WsFrame {
                    direction: Direction::Out,
                    kind: FrameKind::Text,
                    payload: Bytes::from(answer),
                });
                Verdict::Drop
            }
            Err(e) => {
                // Fail closed: a frame that could not be checked ends the voice.
                // The kind of failure only: its text could carry what was said.
                let kind = match e {
                    CheckError::TooLong(_) => "too long",
                    CheckError::Unreadable(_) => "rules unreadable",
                    CheckError::Failed(_) => "failed",
                };
                tracing::warn!("[content-rules] voice check failed, the voice was closed: {kind}");
                let mut extra = Map::new();
                extra.insert("purpose".into(), json!(purpose_of(voice)));
                self.content.audit(
                    Some(flow),
                    "error",
                    "voice",
                    if from_client { "out" } else { "in" },
                    "block",
                    None,
                    extra,
                );
                Verdict::Kill("voice: a frame could not be checked".into())
            }
        }
    }

    /// The accounting `websocket_message` did for a frame the firewall injects toward the provider
    /// (`content_rules_voice` skips an injected frame, so the rules never read it).
    fn injected_frame_passes(&self, voice: &mut Map<String, Value>, payload: &[u8]) -> bool {
        let s = |k: &str| voice.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let (provider, model, family, lease_id) = (s("provider"), s("model"), s("family"), s("lease_id"));
        let live = self.voice_lease(voice).is_some();
        let mut all = self.usage();
        let Some(u) = all.get_mut(&lease_id).filter(|_| live) else {
            return false;
        };
        u.bytes += payload.len() as u64;
        u.frames += 1;
        if u.bytes > VOICE_MAX_BYTES || u.frames > VOICE_MAX_FRAMES || payload.len() > VOICE_FRAME_MAX {
            return false;
        }
        drop(all);
        let event = std::str::from_utf8(payload)
            .ok()
            .and_then(|t| super::json::loads(t).ok());
        event.is_some_and(|ev| voice_client_event(&ev, &provider, &model, &family, obj(voice, "live")))
    }

    /// The speech key's swap (the speech part of `apply_swaps`): only on a request `request`
    /// admitted with that stand-in, only an exact `Bearer <stand-in>`.
    fn swap(&self, flow: &mut Flow) {
        let Some(placeholder) = flow
            .meta
            .get(META_CREDENTIAL)
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return;
        };
        let host = check_host(flow);
        let Some(cred) = self.creds.for_host(&host, flow.vm_id.as_deref()).into_iter().find(|c| {
            truthy(c.get("speech")) && c.get("placeholder").and_then(Value::as_str) == Some(placeholder.as_str())
        }) else {
            return;
        };
        let secret = cred.get("secret").and_then(Value::as_str).unwrap_or("").to_owned();
        if placeholder.is_empty() || secret.is_empty() {
            return;
        }
        let auth = header_values(flow, "authorization").join(", ");
        let head: String = auth.chars().take(7).collect();
        let rest: String = auth.chars().skip(7).collect();
        if head.to_lowercase() != "bearer " || rest != placeholder {
            return;
        }
        if let (Some(r), Ok(v)) = (
            flow.request.as_mut(),
            http::HeaderValue::from_str(&format!("Bearer {secret}")),
        ) {
            r.headers_mut().insert(http::header::AUTHORIZATION, v);
        }
        let e = flow.meta.entry("cc_applied").or_insert_with(|| json!([]));
        if let Some(a) = e.as_array_mut() {
            a.push(json!([secret, placeholder]));
        }
    }
}

fn digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Every pair of the query. The addon compared `dict(flow.request.query)`, which keeps a repeated
/// key's first value while the provider may read its last: a repeated key is refused here.
fn query_pairs(target: &str) -> Vec<(String, String)> {
    target
        .split_once('?')
        .map(|(_, q)| super::body::parse_qsl(q))
        .unwrap_or_default()
}

/// `voice.setdefault(key, {})`.
fn obj<'a>(voice: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let v = voice.entry(key).or_insert_with(|| Value::Object(Map::new()));
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    match v {
        Value::Object(m) => m,
        _ => unreachable!("set to an object above"),
    }
}

fn purpose_of(voice: &Map<String, Value>) -> String {
    voice
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("meeting")
        .to_owned()
}

pub struct VoiceRequest(pub Arc<Voice>);

impl Step for VoiceRequest {
    fn name(&self) -> &'static str {
        "voice"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// A voice path's body (the token mint is compared with what the lease allows).
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        super::request_has_body(flow) && self.0.on_voice_path(flow)
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            match self.0.request(flow) {
                None => Verdict::Continue,
                Some(why) => super::answer(flow, 403, &json!({"error": why}), "block", "meeting_voice", Map::new()),
            }
        })
    }
}

pub struct VoiceSwap(pub Arc<Voice>);

impl Step for VoiceSwap {
    fn name(&self) -> &'static str {
        "voice-swap"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// A header swap.
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            self.0.swap(flow);
            Verdict::Continue
        })
    }
}

pub struct VoiceResponse(pub Arc<Voice>);

impl Step for VoiceResponse {
    fn name(&self) -> &'static str {
        "voice-token"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// A token mint's answer: the token is kept on the firewall.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        flow.meta
            .get(META_VOICE)
            .is_some_and(|v| v.get("mint") == Some(&Value::Bool(true)))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            self.0.response(flow);
            Verdict::Continue
        })
    }
}

pub struct VoiceSocket(pub Arc<Voice>);

impl Step for VoiceSocket {
    fn name(&self) -> &'static str {
        "voice-socket"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::WsStart, Hook::WsFrame, Hook::WsEnd]
    }
    fn run<'a>(&'a self, hook: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            match hook {
                Hook::WsStart => self.0.start(flow),
                Hook::WsFrame => self.0.frame(flow).await,
                Hook::WsEnd => {
                    self.0.end(flow);
                    Verdict::Continue
                }
                _ => Verdict::Continue,
            }
        })
    }
    /// The lease watcher's signal (addon `_voice_watch`): set when the lease ends or the agent is
    /// stopped, so the plumbing closes a quiet socket too. Registered at `WsStart`, which the
    /// plumbing runs before it asks.
    fn closing(&self, flow: &Flow) -> Option<tokio::sync::watch::Receiver<bool>> {
        closing(&flow.id)
    }
}

pub fn register(pipeline: &mut Pipeline, voice: Arc<Voice>) {
    pipeline.push(order::VOICE, Arc::new(VoiceRequest(voice.clone())));
    pipeline.push(order::SWAPS, Arc::new(VoiceSwap(voice.clone())));
    pipeline.push(order::RESPONSE_VOICE, Arc::new(VoiceResponse(voice.clone())));
    pipeline.push(order::WS_VOICE, Arc::new(VoiceSocket(voice)));
}

#[cfg(test)]
mod tests;
