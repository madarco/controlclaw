//! The phone on the firewall (`phone.ts`): the Twilio account (its token never leaves this box),
//! one number assigned to one agent, the proxy entries, Twilio routing with a reconcile, and the
//! cleanup when an assignment ends.
//!
//!   phone.propose     { changeId, kind: connect|assign|limits|callers|wake|voice, … }
//!   phone.confirm     { changeId, code }
//!   phone.cancel      { changeId }
//!   phone.read        {}            numbers read again from Twilio
//!   phone.push        { vmId? }
//!   phone.unassign    {}
//!   phone.forget      { vmId }
//!   phone.disconnect  { changeId? }

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::api::{self, E164, PhoneError, PhoneNumber, TwilioCalls};
use super::policy::{
    Limits, SpeechPolicy, WakePolicy, mask_twilio_account_sids, parse_speech_policy, parse_wake_policy, phone_limits,
    phone_setup_error_code, speech_family,
};
use crate::channels::agent::{AgentCalls, Target};
use crate::channels::llm::SpeechCredential;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeRequest, ConsentCodes, Verify};
use crate::core::activity_sanitize::js_string;

const SCOPE: &str = "phone";
const CODE_SUBJECT: &str = "Phone (Twilio)";
const CODE_ATTEMPTS: u32 = 5;

static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9.-]{0,250}$").expect("regex"));
static CALL_SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^CA[0-9a-f]{32}$").expect("regex"));
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[0-9a-f]{32}$").expect("regex"));

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assignment {
    pub vm_id: String,
    pub hostname: String,
    pub name: String,
    pub number_sid: String,
    pub number: String,
    pub hook_id: String,
    pub placeholder: String,
    pub generation: String,
    pub allow_from: Vec<String>,
    pub allow_all: bool,
    /// `pending`, `active` or `setup_failed`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_error: Option<String>,
    pub routing_hash: String,
    pub routed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speech: Option<SpeechPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice_placeholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_calls: Option<Value>,
    /// Wake words (gpt-live plan, D4). Absent: off, as before the setting existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<WakePolicy>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Assignment {
    /// The limits as stored, normalised (`phoneLimits(a)`); a stored value that is not a number
    /// falls back to the defaults rather than failing the read.
    pub fn limits(&self) -> Limits {
        let mut m = Map::new();
        if let Some(v) = &self.max_duration_seconds {
            m.insert("maxDurationSeconds".into(), v.clone());
        }
        if let Some(v) = &self.max_concurrent_calls {
            m.insert("maxConcurrentCalls".into(), v.clone());
        }
        phone_limits(&m).unwrap_or(Limits {
            max_duration_seconds: 300,
            max_concurrent_calls: 1,
        })
    }
    fn set_limits(&mut self, l: Limits) {
        self.max_duration_seconds = Some(json!(l.max_duration_seconds));
        self.max_concurrent_calls = Some(json!(l.max_concurrent_calls));
    }
    fn target(&self) -> Target {
        Target::new(&self.vm_id, &self.hostname)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Store {
    pub version: u32,
    pub account_sid: Option<String>,
    pub token: Option<String>,
    pub account_type: Option<String>,
    #[serde(default)]
    pub numbers: Vec<PhoneNumber>,
    pub assignment: Option<Assignment>,
    pub cleanup: Option<Assignment>,
    #[serde(default)]
    pub completed: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            account_sid: None,
            token: None,
            account_type: None,
            numbers: vec![],
            assignment: None,
            cleanup: None,
            completed: vec![],
            extra: Map::new(),
        }
    }
}

/// What a code confirms. `connect`'s token is held by the firewall, not by the consent module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Proposal {
    Limits {
        #[serde(rename = "changeId")]
        change_id: String,
        generation: String,
        limits: Limits,
        previous: String,
    },
    Connect {
        #[serde(rename = "changeId")]
        change_id: String,
        sid: String,
        #[serde(rename = "accountType")]
        account_type: String,
        numbers: Vec<PhoneNumber>,
        #[serde(rename = "previousSid")]
        previous_sid: Option<String>,
    },
    Assign {
        #[serde(rename = "changeId")]
        change_id: String,
        assignment: Box<Assignment>,
        #[serde(rename = "accountSid")]
        account_sid: String,
    },
    Callers {
        #[serde(rename = "changeId")]
        change_id: String,
        generation: String,
        #[serde(rename = "allowFrom")]
        allow_from: Vec<String>,
        #[serde(rename = "allowAll")]
        allow_all: bool,
    },
    Wake {
        #[serde(rename = "changeId")]
        change_id: String,
        generation: String,
        wake: WakePolicy,
    },
    Voice {
        #[serde(rename = "changeId")]
        change_id: String,
        generation: String,
        speech: Option<SpeechPolicy>,
        #[serde(rename = "voicePlaceholder")]
        voice_placeholder: Option<String>,
        wake: Option<WakePolicy>,
        limits: Limits,
        previous: String,
    },
}

impl Proposal {
    fn change_id(&self) -> &str {
        match self {
            Proposal::Limits { change_id, .. }
            | Proposal::Connect { change_id, .. }
            | Proposal::Assign { change_id, .. }
            | Proposal::Callers { change_id, .. }
            | Proposal::Wake { change_id, .. }
            | Proposal::Voice { change_id, .. } => change_id,
        }
    }
}

/// The speech binding, limits and wake words, so confirming an older coded change cannot undo a
/// change saved since.
fn voice_state(a: &Assignment) -> String {
    json!([a.speech, a.limits(), a.wake]).to_string()
}

fn speech_line(s: Option<&SpeechPolicy>) -> String {
    match s {
        Some(s) => format!(
            "realtime audio goes to {} {}{}, read-only agent consultation, classic fallback",
            s.provider,
            s.model,
            if speech_family(&s.provider, &s.model) == Some("live") {
                " (billed per connected second)"
            } else {
                ""
            }
        ),
        None => "classic speech".into(),
    }
}

fn wake_line(w: &WakePolicy) -> String {
    if w.enabled {
        format!("answer only when called {}", w.words.join(" or "))
    } else {
        "answer every turn".into()
    }
}

/// `minutes` as JS writes `seconds / 60`.
fn minutes(seconds: i64) -> String {
    if seconds % 60 == 0 {
        (seconds / 60).to_string()
    } else {
        format!("{}", seconds as f64 / 60.0)
    }
}

fn hex_rand<const N: usize>() -> String {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

/// `callers`: up to 50 numbers in E.164.
fn parse_callers(v: Option<&Value>) -> Result<Vec<String>, PhoneError> {
    // `p.allowFrom ?? []`
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(vec![]);
    };
    let a = v
        .as_array()
        .filter(|a| a.len() <= 50)
        .ok_or(PhoneError("phone_setup_failed"))?;
    a.iter()
        .map(|x| {
            x.as_str()
                .filter(|s| E164.is_match(s))
                .map(str::to_string)
                .ok_or(PhoneError("phone_setup_failed"))
        })
        .collect()
}

/// Next to the store: the generation an unassign, forget or disconnect took away, until the store
/// that says so is saved. An id, nothing secret.
fn tombstone_path(store: &std::path::Path) -> PathBuf {
    let mut p = store.as_os_str().to_owned();
    p.push(".revoked");
    PathBuf::from(p)
}

type Codes = Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>;
pub type ValidTarget = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;
pub type SpeechCredentialFn = Arc<dyn Fn(&SpeechPolicy) -> Option<SpeechCredential> + Send + Sync>;

pub struct PhoneOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    /// `https://<firewall host>/`, where Twilio posts.
    pub public_origin: String,
    pub valid_target: ValidTarget,
    pub agent: Arc<dyn AgentCalls>,
    pub codes: Codes,
    /// `None` when the channel list cannot be read.
    pub code_routes: Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>,
    pub on_credentials_changed: Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>,
    pub speech_credential: SpeechCredentialFn,
    #[allow(dead_code)] // the stream relay (H7b)
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub api: Arc<dyn TwilioCalls>,
}

struct State {
    store: Store,
    /// A connect's token, waiting for its code.
    held: Option<(String, String)>,
}

pub struct PhoneFirewall {
    opts: PhoneOptions,
    origin: String,
    /// The realtime stream, once `register` built it.
    pub streams: std::sync::OnceLock<Arc<super::stream::PhoneStreams>>,
    serial: tokio::sync::Mutex<()>,
    /// Store edits take turns here, so the file and memory agree.
    saving: Mutex<()>,
    st: Mutex<State>,
    epoch: AtomicU64,
    reconciling: AtomicBool,
}

fn aad(org: &str, box_id: &str) -> String {
    format!("{org}:{box_id}:twilio-voice")
}

impl PhoneFirewall {
    /// `Err` when the public origin is not a bare https origin, or the store cannot be read: the
    /// module does not start then (the TS constructor throws).
    pub fn new(opts: PhoneOptions) -> Result<Arc<Self>, String> {
        let origin = url::Url::parse(&opts.public_origin).map_err(|_| "invalid phone public origin")?;
        if origin.scheme() != "https" || origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some()
        {
            return Err("invalid phone public origin".into());
        }
        let store = match cc_crypto::enc_file::load_encrypted_json(
            &opts.store_path,
            &opts.box_key,
            &aad(&opts.org_id, &opts.box_id),
        ) {
            Ok(None) => Store::default(),
            Ok(Some(v)) => {
                let s: Store = serde_json::from_value(v).map_err(|_| "phone store unavailable")?;
                if s.version != 1 {
                    return Err("unsupported phone store".into());
                }
                s
            }
            Err(_) => {
                cc_crypto::store_health::note_store_unreadable("twilio-voice", "encrypted store unavailable");
                return Err("phone store unavailable".into());
            }
        };
        if let Some(t) = &store.token {
            cc_crypto::enc_file::remember_encrypted_secrets(&json!(t), true);
        }
        // An unassign, forget or disconnect whose save failed: what the tombstone names stays
        // revoked across the restart.
        let mut store = store;
        let tomb = tombstone_path(&opts.store_path);
        let revoked = std::fs::read_to_string(&tomb)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.get("generation").and_then(Value::as_str).map(str::to_string));
        if let Some(g) = &revoked
            && store.assignment.as_ref().is_some_and(|a| &a.generation == g)
        {
            store.cleanup = store.assignment.take();
            tracing::warn!("[phone] an unassign that could not be saved is kept revoked");
        }
        let fw = Arc::new(Self {
            origin: opts.public_origin.trim_end_matches('/').to_string(),
            opts,
            streams: std::sync::OnceLock::new(),
            serial: tokio::sync::Mutex::new(()),
            saving: Mutex::new(()),
            st: Mutex::new(State { store, held: None }),
            epoch: AtomicU64::new(0),
            reconciling: AtomicBool::new(false),
        });
        if revoked.is_some() {
            // Saved now, the tombstone is no longer needed; not saved, it stays for next time.
            let s = fw.lock().store.clone();
            if fw.save_store(&s).is_err() {
                tracing::error!("[phone] the revoked assignment is still not saved; the tombstone stays");
            }
        }
        Ok(fw)
    }

    /// Forget the token held for a connect whose code is gone (`None`: whichever is held).
    fn drop_held(&self, change_id: Option<&str>) {
        let mut st = self.lock();
        if change_id.is_none_or(|id| st.held.as_ref().is_some_and(|(h, _)| h == id)) {
            st.held = None;
        }
    }

    #[cfg(test)]
    pub fn holds_token(&self) -> bool {
        self.lock().held.is_some()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save_store(&self, s: &Store) -> Result<(), PhoneError> {
        let v = serde_json::to_value(s).map_err(|_| PhoneError("phone_setup_failed"))?;
        cc_crypto::enc_file::save_store(
            "twilio-voice",
            &self.opts.store_path,
            &v,
            &self.opts.box_key,
            &aad(&self.opts.org_id, &self.opts.box_id),
        )
        .map_err(|e| {
            tracing::error!("[phone] could not save the store: {}", e.0);
            PhoneError("phone_setup_failed")
        })?;
        // The store says what the tombstone said, or later: it is no longer needed.
        let _ = std::fs::remove_file(tombstone_path(&self.opts.store_path));
        Ok(())
    }

    /// Change the store and save it in one step; nothing changes when the save fails. Edits take
    /// turns on `saving`; the state lock is not held while the file is written, so the hook's
    /// `authorize` never waits on the disk.
    fn edit<R>(&self, f: impl FnOnce(&mut Store) -> R) -> Result<R, PhoneError> {
        let _saving = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = self.lock().store.clone();
        let r = f(&mut next);
        self.save_store(&next)?;
        self.lock().store = next;
        Ok(r)
    }

    /// Like `edit`, for a change that takes something away (unassign, forget, disconnect): it holds
    /// in memory even when the save fails, so the proxy entries are revoked anyway. The error is
    /// still returned.
    fn edit_revoking(&self, f: impl FnOnce(&mut Store)) -> Result<(), PhoneError> {
        let _saving = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = self.lock().store.clone();
        let before = next.assignment.as_ref().map(|a| a.generation.clone());
        f(&mut next);
        // Written first: if the store cannot be saved, a restart still knows it was revoked.
        if let Some(g) = before.filter(|_| next.assignment.is_none()) {
            let tomb = tombstone_path(&self.opts.store_path);
            if let Err(e) = cc_store::write_atomic(
                &tomb,
                json!({"generation": g}).to_string().as_bytes(),
                0o600,
                cc_store::TmpName::Suffix,
            ) {
                tracing::error!("[phone] could not write the revocation tombstone: {e}");
            }
        }
        let saved = self.save_store(&next);
        self.lock().store = next;
        saved
    }

    pub fn hook_url(&self, a: &Assignment) -> String {
        format!("{}/hook/{}", self.origin, a.hook_id)
    }

    fn is_current(&self, generation: &str) -> bool {
        self.lock()
            .store
            .assignment
            .as_ref()
            .is_some_and(|a| a.generation == generation)
    }

    fn current(&self, generation: &str) -> Option<Assignment> {
        self.lock()
            .store
            .assignment
            .clone()
            .filter(|a| a.generation == generation)
    }

    async fn changed(&self) {
        (self.opts.on_credentials_changed)().await;
    }

    pub fn summary(&self) -> Value {
        let s = self.lock().store.clone();
        Self::summary_of(&s)
    }

    fn summary_of(s: &Store) -> Value {
        let a = s.assignment.as_ref().map(|a| {
            let l = a.limits();
            let mut m = json!({
                "vmId": a.vm_id,
                "numberSid": a.number_sid,
                "number": a.number,
                "status": a.status,
                "allowFrom": a.allow_from,
                "allowAll": a.allow_all,
                "speech": a.speech,
                "maxDurationSeconds": l.max_duration_seconds,
                "maxConcurrentCalls": l.max_concurrent_calls,
            });
            if a.status == "setup_failed"
                && let Some(code) = phone_setup_error_code(a.setup_error.as_ref().map(|e| json!(e)).as_ref())
            {
                m["setupError"] = json!(code);
            }
            if let Some(w) = &a.wake {
                m["wake"] = json!(w);
            }
            m
        });
        json!({
            "realtimeSupported": true,
            "accountSid": s.account_sid.as_deref().map(mask_twilio_account_sids),
            "accountType": s.account_type,
            "status": if s.token.is_some() { "connected" } else { "disconnected" },
            "numbers": s.numbers,
            "assignment": a,
            "cleanupPending": s.cleanup.is_some(),
        })
    }

    /// The proxy entries: the Twilio token on `api.twilio.com` (basic auth) and, with a speech
    /// binding, its credential on the speech host. Both scoped to the assigned agent.
    pub fn credentials(&self) -> Vec<Value> {
        let s = self.lock().store.clone();
        let (Some(a), Some(token)) = (&s.assignment, &s.token) else {
            return vec![];
        };
        if a.status == "setup_failed" {
            return vec![];
        }
        let mut out = vec![];
        if let (Some(speech), Some(ph)) = (&a.speech, &a.voice_placeholder)
            && let Some(c) = (self.opts.speech_credential)(speech)
        {
            let mut e = json!({
                "vm_id": a.vm_id,
                "placeholder": ph,
                "secret": c.secret,
                "match_domain": c.host,
                "locations": ["header:authorization"],
                "phone_speech": true,
                "speech": {"provider": speech.provider, "model": speech.model},
            });
            if let Some(id) = c.account_id {
                e["speech_account_id"] = json!(id);
            }
            out.push(e);
        }
        let l = a.limits();
        out.push(json!({
            "vm_id": a.vm_id,
            "placeholder": a.placeholder,
            "secret": token,
            "match_domain": "api.twilio.com",
            "locations": ["basic:authorization"],
            "phone": {
                "account_sid": s.account_sid,
                "from_number": a.number,
                "hook_url": self.hook_url(a),
                "max_duration": l.max_duration_seconds,
                "max_concurrent_calls": l.max_concurrent_calls,
            },
        }));
        out
    }

    /// `streamBinding`: what the stream relay may open, only for an active, unlocked assignment.
    pub fn stream_binding(&self) -> Option<Value> {
        let s = self.lock().store.clone();
        let a = s.assignment.as_ref().filter(|a| a.status == "active")?;
        let (token, sid) = (s.token.as_ref()?, s.account_sid.as_ref()?);
        if !(self.opts.valid_target)(&a.vm_id, &a.hostname) || (self.opts.locked)(&a.vm_id) {
            return None;
        }
        let credential = a.speech.as_ref().and_then(|sp| (self.opts.speech_credential)(sp));
        let mut b = serde_json::to_value(a).ok()?;
        let mut allow = a.allow_from.clone();
        allow.sort();
        let l = a.limits();
        b["speechRevision"] = json!(
            credential
                .as_ref()
                .map_or(String::new(), |c| hex::encode(Sha256::digest(c.secret.as_bytes())))
        );
        b["accountSid"] = json!(sid);
        b["token"] = json!(token);
        b["hook"] = json!(self.hook_url(a));
        b["speech"] = json!(a.speech);
        b["callerPolicy"] = json!(json!([a.allow_all, allow]).to_string());
        b["voicePlaceholder"] = json!(a.voice_placeholder.clone().unwrap_or_default());
        b["maxDurationSeconds"] = json!(l.max_duration_seconds);
        b["maxConcurrentCalls"] = json!(l.max_concurrent_calls);
        b["speechAvailable"] = json!(credential.is_some());
        Some(b)
    }

    /// The hook's `authorize`: a Twilio delivery for the assignment `generation` still holds, active,
    /// from this account, for a call to or from its number (inbound only from an allowed caller).
    pub fn authorize(&self, generation: &str, body: &[u8]) -> bool {
        let Ok(p) = crate::core::url_form::decode_form(body) else {
            return false;
        };
        let get = |k: &str| p.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let st = self.lock();
        let s = &st.store;
        let Some(a) = s
            .assignment
            .as_ref()
            .filter(|a| a.generation == generation && a.status == "active")
        else {
            return false;
        };
        if get("AccountSid") != s.account_sid.as_deref()
            || s.account_sid.is_none()
            || !CALL_SID.is_match(get("CallSid").unwrap_or(""))
        {
            return false;
        }
        match get("Direction") {
            Some("inbound") => {
                get("To") == Some(a.number.as_str())
                    && (a.allow_all || a.allow_from.iter().any(|f| Some(f.as_str()) == get("From")))
            }
            Some("outbound-api" | "outbound-dial") => get("From") == Some(a.number.as_str()),
            _ => false,
        }
    }

    /// The current assignment's generation and hook id, for the ingress registration.
    #[allow(dead_code)] // the stream relay (H7b)
    pub fn hook(&self) -> Option<(String, String)> {
        let st = self.lock();
        st.store.token.as_ref()?;
        st.store
            .assignment
            .as_ref()
            .map(|a| (a.generation.clone(), a.hook_id.clone()))
    }

    /// The Twilio hook the ingress serves for the assignment (`registrations`): verified with the
    /// account token over the URL and the form, re-signed with the agent's placeholder, bounded
    /// TwiML back. None without an account or an assignment.
    pub fn registrations(self: &Arc<Self>) -> Vec<crate::core::ingress::Registration> {
        use crate::core::ingress::{HmacRule, Registration, Target as HookTarget, VerifyRule};
        let s = self.lock().store.clone();
        // An empty token would make a key anyone can sign with; no hook rather than an open one.
        let (Some(a), Some(token)) = (s.assignment, s.token.filter(|t| !t.is_empty())) else {
            return vec![];
        };
        let url = self.hook_url(&a);
        // Built here, not with `parse_list`: that reads the console's rules and never takes
        // `input`, `publicUrl` or `resignSecret` from them, so it would make this a body HMAC that
        // no Twilio signature matches.
        let verify = if a.status == "active" {
            vec![VerifyRule::Hmac(HmacRule {
                url_form: true,
                public_url: Some(url.clone()),
                resign_secret: Some(a.placeholder.clone()),
                header: "x-twilio-signature".into(),
                sha1: true,
                base64: true,
                secret: token,
                ..Default::default()
            })]
        } else {
            vec![]
        };
        let (me, generation) = (self.clone(), a.generation.clone());
        let hook = url.clone();
        vec![Registration {
            id: a.hook_id.clone(),
            name: format!("Phone (Twilio) ****{}", &a.number[a.number.len().saturating_sub(4)..]),
            target: HookTarget {
                vm_id: a.vm_id.clone(),
                hostname: a.hostname.clone(),
                port: 8789.0,
                path: "/voice/webhook".into(),
            },
            verify,
            max_body_bytes: 256.0 * 1024.0,
            per_minute: 60.0,
            enabled: true,
            bounded: true,
            authorize: Some(Arc::new(move |body: &[u8]| me.authorize(&generation, body))),
            response_allowed: Some({
                let me = self.clone();
                Arc::new(move |xml: &str| {
                    super::twiml::allowed_phone_twiml(xml, &hook)
                        || me.streams.get().is_some_and(|s| s.response_allowed(xml))
                })
            }),
            prepare_delivery: Some({
                let me = self.clone();
                // No admission yet means no delivery: refused, never let through unadmitted.
                Arc::new(move |body: &[u8], query: &str| match me.streams.get() {
                    Some(s) => s.prepare(body, query),
                    None => Err("phone streams not ready".to_string()),
                })
            }),
            rewrite_response: Some({
                let me = self.clone();
                Arc::new(move |xml: &str, body: &[u8], query: &str| match me.streams.get() {
                    Some(s) => s.rewrite(xml, body, query),
                    None => Ok(xml.to_string()),
                })
            }),
        }]
    }

    /// End or change a call in progress (the stream relay's hang-up). A sid that is not a call's is
    /// ignored.
    pub async fn control_call(&self, sid: &str, fields: Option<Vec<(String, String)>>) -> Option<Map<String, Value>> {
        if !CALL_SID.is_match(sid) {
            return None;
        }
        let (account, token) = {
            let s = &self.lock().store;
            (s.account_sid.clone()?, s.token.clone()?)
        };
        api::request(
            &*self.opts.api,
            &account,
            &token,
            &format!("/2010-04-01/Accounts/{account}/Calls/{sid}.json"),
            fields,
        )
        .await
        .ok()
    }

    pub async fn command(&self, action: &str, p: Map<String, Value>) -> CommandOutcome {
        if action == "disconnect"
            && let Some(c) = p.get("changeId").and_then(Value::as_str)
            && self.lock().store.completed.iter().any(|x| x == c)
        {
            return self.ok("applied", None, None);
        }
        if action == "cancel" {
            self.epoch.fetch_add(1, Ordering::SeqCst);
            let id = p.get("changeId").map(|v| js_string(Some(v))).filter(|s| !s.is_empty());
            if let Some(c) = (self.opts.codes)() {
                c.cancel(SCOPE, id.as_deref());
            }
            self.drop_held(id.as_deref());
        }
        if matches!(action, "unassign" | "forget" | "disconnect") {
            self.epoch.fetch_add(1, Ordering::SeqCst);
            if let Some(c) = (self.opts.codes)() {
                c.forget(SCOPE);
            }
            self.lock().held = None;
            let vm = p.get("vmId").and_then(Value::as_str).map(str::to_string);
            let ours = |a: &mut Assignment| action != "forget" || vm.as_deref() == Some(a.vm_id.as_str());
            let saved = if self.lock().store.assignment.clone().as_mut().is_some_and(ours) {
                self.edit_revoking(|s| {
                    if let Some(a) = s.assignment.take_if(ours) {
                        s.cleanup = Some(a);
                    }
                })
            } else {
                Ok(())
            };
            // Revoked at the proxy at once, even when the save failed; the cleanup runs behind the queue.
            let changed = self.opts.on_credentials_changed.clone();
            tokio::spawn(async move { changed().await });
            if saved.is_err() {
                return self.failed("phone_setup_failed");
            }
        }
        let epoch = self.epoch.load(Ordering::SeqCst);
        let _serial = self.serial.lock().await;
        match self.run(action, &p, epoch).await {
            // A wrong or expired code is not a success: the summary, and what is left of the tries.
            Ok((status, _, data)) if status.ends_with('!') => {
                let mut d = self.summary().as_object().cloned().unwrap_or_default();
                d.extend(data.unwrap_or_default());
                CommandOutcome {
                    ok: false,
                    status: status.trim_end_matches('!').into(),
                    message: None,
                    data: Some(d),
                }
            }
            Ok((status, message, data)) => self.ok(&status, message, data),
            Err(e) => self.failed(e.0),
        }
    }

    fn ok(&self, status: &str, message: Option<String>, data: Option<Map<String, Value>>) -> CommandOutcome {
        let mut d = self.summary().as_object().cloned().unwrap_or_default();
        if let Some(extra) = data {
            d.extend(extra);
        }
        CommandOutcome {
            ok: true,
            status: status.into(),
            message,
            data: Some(d),
        }
    }

    fn failed(&self, code: &str) -> CommandOutcome {
        CommandOutcome {
            ok: false,
            status: "failed".into(),
            message: Some(code.into()),
            data: self.summary().as_object().cloned(),
        }
    }

    async fn run(
        &self,
        action: &str,
        p: &Map<String, Value>,
        epoch: u64,
    ) -> Result<(String, Option<String>, Option<Map<String, Value>>), PhoneError> {
        if epoch != self.epoch.load(Ordering::SeqCst) && matches!(action, "propose" | "confirm" | "push") {
            return Err(PhoneError("stale_proposal"));
        }
        match action {
            "propose" => self.propose(p, epoch).await,
            "confirm" => {
                let change_id = p.get("changeId").map(|v| js_string(Some(v))).unwrap_or_default();
                let code = p.get("code").map(|v| js_string(Some(v))).unwrap_or_default();
                let verdict = (self.opts.codes)().map_or(Verify::Unknown, |c| c.verify(SCOPE, &change_id, &code));
                let proposal = match verdict {
                    Verify::Ok(v) => v,
                    Verify::Wrong { tries_left } => {
                        if tries_left == 0 {
                            self.drop_held(Some(&change_id));
                        }
                        let mut d = Map::new();
                        d.insert("attemptsLeft".into(), json!(tries_left));
                        return Ok(("invalid_code!".into(), None, Some(d)));
                    }
                    Verify::Expired | Verify::Unknown => {
                        self.drop_held(Some(&change_id));
                        return Ok(("expired!".into(), None, None));
                    }
                };
                let mut proposal: Proposal =
                    serde_json::from_value(proposal).map_err(|_| PhoneError("phone_setup_failed"))?;
                let token = {
                    let mut st = self.lock();
                    match st.held.take() {
                        Some((id, t)) if id == change_id => Some(t),
                        other => {
                            st.held = other;
                            None
                        }
                    }
                };
                if let Proposal::Connect { .. } = &mut proposal {
                    let Some(token) = token else {
                        // The firewall restarted between the proposal and the code.
                        return Err(PhoneError("stale_proposal"));
                    };
                    self.apply(&proposal, Some(&token)).await?;
                } else {
                    self.apply(&proposal, None).await?;
                }
                Ok(("applied".into(), None, None))
            }
            "cancel" => {
                let id = p.get("changeId").map(|v| js_string(Some(v))).filter(|s| !s.is_empty());
                if let Some(c) = (self.opts.codes)() {
                    c.cancel(SCOPE, id.as_deref());
                }
                self.drop_held(id.as_deref());
                Ok(("cancelled".into(), None, None))
            }
            "unassign" | "forget" | "disconnect" => {
                self.changed().await;
                match self.cleanup().await {
                    // A token Twilio no longer takes can clean nothing up: a disconnect gives the
                    // routing up and removes the dead token anyway.
                    Err(PhoneError("invalid_credentials")) if action == "disconnect" => {
                        self.edit(|s| s.cleanup = None)?;
                    }
                    r => r?,
                }
                if action == "disconnect" {
                    let id = p.get("changeId").and_then(Value::as_str).map(str::to_string);
                    self.edit(|s| {
                        s.account_sid = None;
                        s.token = None;
                        s.account_type = None;
                        s.numbers.clear();
                        if let Some(id) = id {
                            let keep = s.completed.len().saturating_sub(99);
                            s.completed.drain(..keep);
                            s.completed.push(id);
                        }
                    })?;
                }
                Ok(("applied".into(), None, None))
            }
            "push" => {
                let a = self.lock().store.assignment.clone();
                // `!p.vmId || p.vmId === a.vmId`: an id that is not a string pushes nothing.
                if let Some(a) = a
                    && p.get("vmId")
                        .is_none_or(|v| !crate::core::sync::js_truthy(v) || v.as_str() == Some(a.vm_id.as_str()))
                {
                    self.push(&a.generation).await;
                }
                Ok(("applied".into(), None, None))
            }
            "read" => {
                let (sid, token) = {
                    let s = &self.lock().store;
                    (s.account_sid.clone(), s.token.clone())
                };
                if let (Some(sid), Some(token)) = (sid, token) {
                    let numbers = api::numbers(&*self.opts.api, &sid, &token).await?;
                    self.edit(|s| s.numbers = numbers)?;
                }
                Ok(("applied".into(), None, None))
            }
            _ => Err(PhoneError("invalid_input")),
        }
    }

    async fn propose(
        &self,
        p: &Map<String, Value>,
        epoch: u64,
    ) -> Result<(String, Option<String>, Option<Map<String, Value>>), PhoneError> {
        let bad = PhoneError("phone_setup_failed");
        let change_id = p
            .get("changeId")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty() && crate::channels::js::js_len(c) <= 100)
            .ok_or(bad.clone())?
            .to_string();
        if self.lock().store.completed.contains(&change_id) {
            return Ok(("applied".into(), None, None));
        }
        let store = self.lock().store.clone();
        let mut raises_limits = false;
        let mut token_held: Option<String> = None;
        let speech_ok = |s: &Option<SpeechPolicy>| -> Result<(), PhoneError> {
            if let Some(s) = s
                && (s.max_minutes != 5 || (self.opts.speech_credential)(s).is_none())
            {
                return Err(PhoneError("speech_unavailable"));
            }
            Ok(())
        };
        let parse_speech = |v: Option<&Value>| -> Result<Option<SpeechPolicy>, PhoneError> {
            match v {
                None | Some(Value::Null) => Ok(None),
                Some(v) => parse_speech_policy(v).map_err(|_| PhoneError("phone_setup_failed")),
            }
        };
        let parse_wake = |v: Option<&Value>| -> Result<Option<WakePolicy>, PhoneError> {
            match v {
                None | Some(Value::Null) => Ok(None),
                Some(v) => parse_wake_policy(v)
                    .map(Some)
                    .map_err(|_| PhoneError("phone_setup_failed")),
            }
        };
        let limits_of = |p: &Map<String, Value>| phone_limits(p).map_err(|_| PhoneError("phone_setup_failed"));
        let kind = p.get("kind").and_then(Value::as_str).unwrap_or("");
        let (proposal, summary) = match kind {
            "connect" => {
                let sid = p
                    .get("accountSid")
                    .and_then(Value::as_str)
                    .filter(|s| api::is_account_sid(s))
                    .ok_or(bad.clone())?;
                let token = p
                    .get("authToken")
                    .and_then(Value::as_str)
                    .filter(|s| TOKEN.is_match(s))
                    .ok_or(bad.clone())?;
                cc_crypto::enc_file::remember_encrypted_secrets(&json!(token), true);
                if store.account_sid.as_deref().is_some_and(|a| a != sid) {
                    return Err(PhoneError("account_mismatch"));
                }
                let account_type = api::account(&*self.opts.api, sid, token).await?;
                let numbers = api::numbers(&*self.opts.api, sid, token).await?;
                token_held = Some(token.to_string());
                (
                    Proposal::Connect {
                        change_id: change_id.clone(),
                        sid: sid.into(),
                        account_type: account_type.into(),
                        numbers,
                        previous_sid: store.account_sid.clone(),
                    },
                    format!(
                        "Connect Twilio account {}; keep its token on your firewall",
                        mask_twilio_account_sids(sid)
                    ),
                )
            }
            "assign" => {
                let (Some(token), Some(sid)) = (&store.token, &store.account_sid) else {
                    return Err(PhoneError("needs_token"));
                };
                if store.assignment.is_some() || store.cleanup.is_some() {
                    return Err(PhoneError("account_already_assigned"));
                }
                let number_sid = p
                    .get("numberSid")
                    .and_then(Value::as_str)
                    .filter(|s| api::is_number_sid(s))
                    .ok_or(bad.clone())?;
                let vm = p
                    .get("vmId")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty() && v.len() <= 100)
                    .ok_or(bad.clone())?;
                let host = p
                    .get("hostname")
                    .and_then(Value::as_str)
                    .filter(|h| HOSTNAME.is_match(h))
                    .ok_or(bad.clone())?;
                let name = p
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty() && crate::channels::js::js_len(n) <= 100)
                    .ok_or(bad.clone())?;
                if !(self.opts.valid_target)(vm, host) {
                    return Err(PhoneError("invalid_target"));
                }
                let raw = api::number(&*self.opts.api, sid, token, number_sid).await?;
                let n = api::number_metadata(sid, &raw)?;
                if !n.voice || n.blocked_routing {
                    return Err(PhoneError("number_routing_conflict"));
                }
                let speech = parse_speech(p.get("speech"))?;
                speech_ok(&speech)?;
                let limits = limits_of(p)?;
                let allow_from = parse_callers(p.get("allowFrom"))?;
                let allow_all = p.get("allowAll") == Some(&Value::Bool(true));
                let wake = parse_wake(p.get("wake"))?;
                let summary = format!(
                    "Assign Twilio {} to {host}; replace voice routing, clear it on unassign; {}; chargeable calls use this account; {}; {} calls at once, at most {} minutes per call",
                    n.number,
                    if allow_all {
                        "allow all callers".to_string()
                    } else if allow_from.is_empty() {
                        "allow no callers".into()
                    } else {
                        format!("allow {}", allow_from.join(", "))
                    },
                    speech_line(speech.as_ref()),
                    limits.max_concurrent_calls,
                    minutes(limits.max_duration_seconds),
                );
                let mut a = Assignment {
                    vm_id: vm.into(),
                    hostname: host.into(),
                    name: name.into(),
                    number_sid: number_sid.into(),
                    number: n.number.clone(),
                    hook_id: format!("hk_{}", hex_rand::<16>()),
                    placeholder: format!("CC-TWILIO-{}", hex_rand::<16>()),
                    generation: hex_rand::<16>(),
                    allow_from,
                    allow_all,
                    status: "pending".into(),
                    setup_error: None,
                    routing_hash: api::routing_hash(&raw),
                    routed: false,
                    speech,
                    voice_placeholder: Some(format!("cc-speech-{}", hex_rand::<24>())),
                    max_duration_seconds: None,
                    max_concurrent_calls: None,
                    wake,
                    extra: Map::new(),
                };
                a.set_limits(limits);
                (
                    Proposal::Assign {
                        change_id: change_id.clone(),
                        assignment: Box::new(a),
                        account_sid: sid.clone(),
                    },
                    summary,
                )
            }
            "limits" => {
                let a = store.assignment.as_ref().ok_or(PhoneError("not_assigned"))?;
                let previous = a.limits();
                let limits = limits_of(p)?;
                let summary = format!(
                    "Change call limits for Twilio {}: {} minutes per call, {} calls at once; chargeable calls use this account",
                    a.number,
                    minutes(limits.max_duration_seconds),
                    limits.max_concurrent_calls
                );
                let proposal = Proposal::Limits {
                    change_id: change_id.clone(),
                    generation: a.generation.clone(),
                    limits,
                    previous: json!(previous).to_string(),
                };
                if limits.max_duration_seconds <= previous.max_duration_seconds
                    && limits.max_concurrent_calls <= previous.max_concurrent_calls
                {
                    self.apply(&proposal, None).await?;
                    return Ok(("applied".into(), Some(summary), None));
                }
                (proposal, summary)
            }
            "callers" => {
                let a = store.assignment.as_ref().ok_or(PhoneError("not_assigned"))?;
                let allow_from = parse_callers(p.get("allowFrom"))?;
                let allow_all = p.get("allowAll") == Some(&Value::Bool(true));
                let summary = format!(
                    "Change callers for Twilio {}: {}",
                    a.number,
                    if allow_all {
                        "allow all callers".to_string()
                    } else if allow_from.is_empty() {
                        "block all callers".into()
                    } else {
                        allow_from.join(", ")
                    }
                );
                let narrows = !allow_all && (a.allow_all || allow_from.iter().all(|v| a.allow_from.contains(v)));
                let proposal = Proposal::Callers {
                    change_id: change_id.clone(),
                    generation: a.generation.clone(),
                    allow_from,
                    allow_all,
                };
                if narrows {
                    self.apply(&proposal, None).await?;
                    return Ok(("applied".into(), None, None));
                }
                (proposal, summary)
            }
            "wake" => {
                // Which names the agent answers to is not access: no code.
                let a = store.assignment.as_ref().ok_or(PhoneError("not_assigned"))?;
                let wake = parse_wake_policy(p.get("wake").unwrap_or(&Value::Null)).map_err(|_| bad.clone())?;
                let summary = format!("Change wake words for Twilio {}: {}", a.number, wake_line(&wake));
                self.apply(
                    &Proposal::Wake {
                        change_id: change_id.clone(),
                        generation: a.generation.clone(),
                        wake,
                    },
                    None,
                )
                .await?;
                return Ok(("applied".into(), Some(summary), None));
            }
            "voice" => {
                let a = store.assignment.as_ref().ok_or(PhoneError("not_assigned"))?;
                let speech = parse_speech(p.get("speech"))?;
                speech_ok(&speech)?;
                let wake = parse_wake(p.get("wake"))?;
                let before = a.limits();
                let limits = limits_of(p)?;
                let rebind = speech.is_some() && a.speech != speech;
                raises_limits = limits.max_duration_seconds > before.max_duration_seconds
                    || limits.max_concurrent_calls > before.max_concurrent_calls;
                let mut changes: Vec<String> = vec![];
                if a.speech != speech {
                    changes.push(format!(
                        "{} (was {})",
                        speech_line(speech.as_ref()),
                        a.speech
                            .as_ref()
                            .map_or("classic speech".to_string(), |s| format!("{} {}", s.provider, s.model))
                    ));
                }
                if let Some(w) = &wake
                    && Some(w) != a.wake.as_ref()
                {
                    changes.push(wake_line(w));
                }
                if limits.max_duration_seconds != before.max_duration_seconds {
                    changes.push(format!(
                        "{} minutes per call (was {})",
                        minutes(limits.max_duration_seconds),
                        minutes(before.max_duration_seconds)
                    ));
                }
                if limits.max_concurrent_calls != before.max_concurrent_calls {
                    changes.push(format!(
                        "{} calls at once (was {})",
                        limits.max_concurrent_calls, before.max_concurrent_calls
                    ));
                }
                let summary = format!(
                    "Change voice settings for Twilio {}: {}{}; saving re-applies the phone plugin and ends calls in progress",
                    a.number,
                    if changes.is_empty() {
                        "no changes".to_string()
                    } else {
                        changes.join("; ")
                    },
                    if raises_limits {
                        "; chargeable calls use this account"
                    } else {
                        ""
                    }
                );
                let proposal = Proposal::Voice {
                    change_id: change_id.clone(),
                    generation: a.generation.clone(),
                    speech,
                    voice_placeholder: rebind.then(|| format!("cc-speech-{}", hex_rand::<24>())),
                    wake,
                    limits,
                    previous: voice_state(a),
                };
                if !rebind && !raises_limits {
                    self.apply(&proposal, None).await?;
                    return Ok(("applied".into(), Some(summary), None));
                }
                (proposal, summary)
            }
            _ => return Err(PhoneError("invalid_input")),
        };
        let Some(routes) = (self.opts.code_routes)() else {
            return Err(PhoneError("channels_unavailable"));
        };
        if epoch != self.epoch.load(Ordering::SeqCst) {
            return Err(PhoneError("stale_proposal"));
        }
        if routes.is_empty() {
            let costs_more = match &proposal {
                Proposal::Limits { .. } => true,
                Proposal::Assign { assignment, .. } => {
                    let l = assignment.limits();
                    l.max_duration_seconds > 300 || l.max_concurrent_calls > 1
                }
                _ => raises_limits,
            };
            if costs_more {
                return Err(PhoneError("code_delivery_failed"));
            }
            self.apply(&proposal, token_held.as_deref()).await?;
            return Ok((
                "applied".into(),
                Some("Applied without a code: nobody is approved on a channel yet.".into()),
                None,
            ));
        }
        // Somebody to ask, but no codes on this firewall: refused.
        let codes = (self.opts.codes)().ok_or(PhoneError("code_delivery_failed"))?;
        // A new code replaces the one pending, and with it a token held for an earlier connect.
        self.lock().held = token_held.map(|t| (change_id.clone(), t));
        let sent = codes
            .send(CodeRequest {
                scope: SCOPE.into(),
                change_id: change_id.clone(),
                proposal: serde_json::to_value(&proposal).map_err(|_| bad.clone())?,
                agent_name: CODE_SUBJECT.into(),
                summary: summary.clone(),
                routes,
            })
            .await;
        if epoch != self.epoch.load(Ordering::SeqCst) {
            codes.cancel(SCOPE, Some(&change_id));
            self.drop_held(Some(&change_id));
            return Err(PhoneError("stale_proposal"));
        }
        let Some(via) = sent.sent_via else {
            self.drop_held(Some(&change_id));
            static RESTART: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r"(?i)gateway (?:not connected|disconnected|.*restart)|OpenClaw is not running|agent is not running|ECONNREFUSED|socket hang up").expect("regex")
            });
            return Err(PhoneError(if RESTART.is_match(sent.error.as_deref().unwrap_or("")) {
                "agent_restarting"
            } else {
                "code_delivery_failed"
            }));
        };
        let mut d = Map::new();
        d.insert("sentVia".into(), json!(via));
        d.insert(
            "expiresAt".into(),
            json!(cc_crypto::store_health::iso_from_millis(sent.expires_at_ms)),
        );
        d.insert("attemptsLeft".into(), json!(CODE_ATTEMPTS));
        Ok(("code_sent".into(), Some(summary), Some(d)))
    }

    async fn apply(&self, p: &Proposal, token: Option<&str>) -> Result<(), PhoneError> {
        if self.lock().store.completed.iter().any(|c| c == p.change_id()) {
            return Ok(());
        }
        let epoch = self.epoch.load(Ordering::SeqCst);
        let stale = || epoch != self.epoch.load(Ordering::SeqCst);
        match p {
            Proposal::Connect {
                sid,
                account_type,
                numbers,
                previous_sid,
                ..
            } => {
                let token = token.ok_or(PhoneError("stale_proposal"))?;
                if &self.lock().store.account_sid != previous_sid {
                    return Err(PhoneError("stale_proposal"));
                }
                api::account(&*self.opts.api, sid, token).await?;
                if stale() {
                    return Err(PhoneError("stale_proposal"));
                }
                self.edit(|s| {
                    s.account_sid = Some(sid.clone());
                    s.token = Some(token.to_string());
                    s.account_type = Some(account_type.clone());
                    s.numbers = numbers.clone();
                })?;
                self.changed().await;
            }
            Proposal::Assign {
                assignment,
                account_sid,
                ..
            } => {
                let store = self.lock().store.clone();
                if store.assignment.is_some()
                    || store.cleanup.is_some()
                    || store.account_sid.as_ref() != Some(account_sid)
                {
                    return Err(PhoneError("account_already_assigned"));
                }
                let token = store.token.ok_or(PhoneError("account_already_assigned"))?;
                let raw = api::number(&*self.opts.api, account_sid, &token, &assignment.number_sid).await?;
                if stale() || !(self.opts.valid_target)(&assignment.vm_id, &assignment.hostname) {
                    return Err(PhoneError("stale_proposal"));
                }
                if api::routing_hash(&raw) != assignment.routing_hash {
                    return Err(PhoneError("routing_changed"));
                }
                if let Some(s) = &assignment.speech
                    && (self.opts.speech_credential)(s).is_none()
                {
                    return Err(PhoneError("speech_unavailable"));
                }
                let a = (**assignment).clone();
                let generation = a.generation.clone();
                // Checked again where it is written: an unassign or disconnect may have come since.
                let written = self.edit(|s| {
                    let free =
                        s.assignment.is_none() && s.cleanup.is_none() && s.account_sid.as_ref() == Some(account_sid);
                    if free && !stale() {
                        s.assignment = Some(a);
                    }
                    free && s.assignment.is_some()
                })?;
                if !written {
                    return Err(PhoneError("stale_proposal"));
                }
                self.push(&generation).await;
            }
            other => {
                let generation = match other {
                    Proposal::Limits { generation, .. }
                    | Proposal::Voice { generation, .. }
                    | Proposal::Callers { generation, .. }
                    | Proposal::Wake { generation, .. } => generation,
                    _ => return Err(PhoneError("stale_proposal")),
                };
                if let Proposal::Voice { speech: Some(sp), .. } = other
                    && (self.opts.speech_credential)(sp).is_none()
                {
                    return Err(PhoneError("speech_unavailable"));
                }
                // Checked and changed where it is written, on the assignment as it is then: an
                // unassign, forget or disconnect since the code was sent is never undone.
                self.edit(|s| {
                    let Some(next) = s
                        .assignment
                        .as_mut()
                        .filter(|a| a.generation == *generation && !stale())
                    else {
                        return Err(PhoneError("stale_proposal"));
                    };
                    match other {
                        Proposal::Limits { limits, previous, .. } => {
                            if json!(next.limits()) != serde_json::from_str::<Value>(previous).unwrap_or(Value::Null) {
                                return Err(PhoneError("stale_proposal"));
                            }
                            next.set_limits(*limits);
                        }
                        Proposal::Wake { wake, .. } => next.wake = Some(wake.clone()),
                        Proposal::Voice {
                            speech,
                            voice_placeholder,
                            wake,
                            limits,
                            previous,
                            ..
                        } => {
                            if voice_state(next) != *previous {
                                return Err(PhoneError("stale_proposal"));
                            }
                            // Same generation and hook: Twilio routing stays; the agent re-applies
                            // the plugin and the reconcile takes the assignment back to active.
                            next.speech = speech.clone();
                            if speech.is_none() {
                                next.voice_placeholder = None;
                            } else if let Some(ph) = voice_placeholder {
                                next.voice_placeholder = Some(ph.clone());
                            }
                            if let Some(w) = wake {
                                next.wake = Some(w.clone());
                            }
                            next.set_limits(*limits);
                        }
                        Proposal::Callers {
                            allow_from, allow_all, ..
                        } => {
                            next.allow_all = *allow_all;
                            next.allow_from = allow_from.clone();
                        }
                        _ => {}
                    }
                    Ok(())
                })??;
                self.push(generation).await;
            }
        }
        let id = p.change_id().to_string();
        self.edit(|s| {
            let keep = s.completed.len().saturating_sub(99);
            s.completed.drain(..keep);
            s.completed.push(id);
        })?;
        Ok(())
    }

    /// Push the assignment to its agent. Earlier failed setup's disable is finished first.
    async fn push(&self, generation: &str) {
        if !self.is_current(generation) {
            return;
        }
        if self.lock().store.cleanup.is_some() {
            let _ = self.cleanup().await;
        }
        if !self.is_current(generation) {
            return;
        }
        if self
            .edit(|s| {
                if let Some(a) = s.assignment.as_mut() {
                    a.status = "pending".into();
                    a.setup_error = None;
                }
            })
            .is_err()
        {
            return;
        }
        self.changed().await;
        let Some(a) = self.current(generation) else { return };
        let (sid, l) = (self.lock().store.account_sid.clone(), a.limits());
        let mut body = json!({
            "generation": a.generation,
            "placeholder": a.placeholder,
            "accountSid": sid,
            "fromNumber": a.number,
            "publicUrl": self.hook_url(&a),
            "allowFrom": a.allow_from,
            "allowAll": a.allow_all,
            "speech": a.speech.as_ref().map(|s| {
                let mut v = json!(s);
                v["placeholder"] = json!(a.voice_placeholder);
                v
            }),
            "maxDurationSeconds": l.max_duration_seconds,
            "maxConcurrentCalls": l.max_concurrent_calls,
        });
        if let Some(w) = &a.wake {
            body["wake"] = json!(w);
        }
        if self
            .opts
            .agent
            .post(&a.target(), "/phone/apply", body, None)
            .await
            .is_err()
            && self.is_current(generation)
        {
            let ok = self
                .edit(|s| {
                    if let Some(a) = s.assignment.as_mut() {
                        a.status = "setup_failed".into();
                        a.setup_error = Some("agent_unavailable".into());
                    }
                })
                .is_ok();
            if ok {
                self.changed().await;
            }
        }
    }

    /// Every 10 s: finish a cleanup, read the agent's status, and once it is active route the number.
    pub async fn reconcile(&self) {
        if self.reconciling.swap(true, Ordering::SeqCst) {
            return;
        }
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _done = Done(&self.reconciling);
        let _serial = self.serial.lock().await;
        if let Err(e) = self.reconcile_once().await {
            let failed = self
                .edit(|s| {
                    let Some(a) = s.assignment.as_mut().filter(|a| a.status == "pending") else {
                        return false;
                    };
                    a.status = "setup_failed".into();
                    a.setup_error = Some(
                        phone_setup_error_code(Some(&json!(e.0)))
                            .unwrap_or("phone_setup_failed")
                            .into(),
                    );
                    if a.routed {
                        s.cleanup = Some(a.clone());
                    }
                    true
                })
                .unwrap_or(false);
            if failed {
                self.changed().await;
            }
        }
    }

    async fn reconcile_once(&self) -> Result<(), PhoneError> {
        if self.lock().store.cleanup.is_some() {
            self.cleanup().await?;
        }
        let s = self.lock().store.clone();
        let (Some(a), Some(token), Some(sid)) = (s.assignment, s.token, s.account_sid) else {
            return Ok(());
        };
        if a.status == "setup_failed" {
            return Ok(());
        }
        let Ok(r) = self.opts.agent.get(&a.target(), "/phone/status", None).await else {
            return Ok(());
        };
        if !self.is_current(&a.generation) {
            return Ok(());
        }
        // `!r.apply`: pushed; an `apply` that is not for this generation (or not an object) waits.
        if !r.get("apply").is_some_and(crate::core::sync::js_truthy) {
            self.push(&a.generation).await;
            return Ok(());
        }
        let Some(status) = r.get("apply").and_then(Value::as_object) else {
            return Ok(());
        };
        if status.get("generation").and_then(Value::as_str) != Some(a.generation.as_str()) {
            return Ok(());
        }
        let state = status.get("status").and_then(Value::as_str);
        if state == Some("failed") {
            let code = phone_setup_error_code(status.get("error")).unwrap_or("phone_setup_failed");
            self.edit(|s| {
                if let Some(x) = s.assignment.as_mut() {
                    x.status = "setup_failed".into();
                    x.setup_error = Some(code.into());
                    if x.routed {
                        s.cleanup = Some(x.clone());
                    }
                }
            })?;
            self.changed().await;
            return Ok(());
        }
        if state != Some("active") || a.status == "active" {
            return Ok(());
        }
        let raw = api::number(&*self.opts.api, &sid, &token, &a.number_sid).await?;
        if !self.is_current(&a.generation) {
            return Ok(());
        }
        let url = self.hook_url(&a);
        let field = |r: &Map<String, Value>, k: &str| r.get(k).cloned().unwrap_or(Value::Null);
        let truthy = |r: &Map<String, Value>, k: &str| r.get(k).is_some_and(crate::core::sync::js_truthy);
        if truthy(&raw, "voice_application_sid")
            || truthy(&raw, "trunk_sid")
            || (!a.routed && api::routing_hash(&raw) != a.routing_hash && field(&raw, "voice_url") != json!(url))
        {
            return Err(PhoneError("routing_changed"));
        }
        // The intended routing is saved before the remote write, so an ambiguous write can be cleared.
        self.edit(|s| {
            if let Some(x) = s.assignment.as_mut() {
                x.routed = true;
            }
        })?;
        let status_url = format!("{url}?type=status");
        api::route(
            &*self.opts.api,
            &sid,
            &token,
            &a.number_sid,
            vec![
                ("VoiceUrl".into(), url.clone()),
                ("VoiceMethod".into(), "POST".into()),
                ("StatusCallback".into(), status_url.clone()),
                ("StatusCallbackMethod".into(), "POST".into()),
                ("VoiceFallbackUrl".into(), String::new()),
            ],
        )
        .await?;
        if !self.is_current(&a.generation) {
            return Ok(());
        }
        let checked = api::number(&*self.opts.api, &sid, &token, &a.number_sid).await?;
        if !self.is_current(&a.generation) {
            return Ok(());
        }
        if truthy(&checked, "voice_application_sid")
            || truthy(&checked, "trunk_sid")
            || field(&checked, "voice_url") != json!(url)
            || field(&checked, "status_callback") != json!(status_url)
            || field(&checked, "voice_method") != json!("POST")
            || field(&checked, "status_callback_method") != json!("POST")
        {
            return Err(PhoneError("routing_not_active"));
        }
        self.edit(|s| {
            if let Some(x) = s.assignment.as_mut() {
                x.status = "active".into();
                x.setup_error = None;
            }
        })?;
        Ok(())
    }

    /// Take an ended assignment off its agent and off the number's Twilio routing.
    async fn cleanup(&self) -> Result<(), PhoneError> {
        let s = self.lock().store.clone();
        let (Some(a), Some(sid), Some(token)) = (s.cleanup, s.account_sid, s.token) else {
            return Ok(());
        };
        // Firewall revocation is already in effect; a box that does not answer cannot spend it.
        let _ = self
            .opts
            .agent
            .post(
                &a.target(),
                "/phone/apply",
                json!({"placeholder": null, "generation": a.generation}),
                None,
            )
            .await;
        let raw = api::number(&*self.opts.api, &sid, &token, &a.number_sid).await?;
        let url = self.hook_url(&a);
        let status_url = format!("{url}?type=status");
        let mut fields = vec![];
        if raw.get("voice_url") == Some(&json!(url)) {
            fields.push(("VoiceUrl".to_string(), String::new()));
        }
        if raw.get("status_callback") == Some(&json!(status_url)) {
            fields.push(("StatusCallback".to_string(), String::new()));
        }
        if !fields.is_empty() {
            api::route(&*self.opts.api, &sid, &token, &a.number_sid, fields).await?;
            let checked = api::number(&*self.opts.api, &sid, &token, &a.number_sid).await?;
            if checked.get("voice_url") == Some(&json!(url))
                || checked.get("status_callback") == Some(&json!(status_url))
            {
                return Err(PhoneError("routing_cleanup_failed"));
            }
        }
        if self.is_current(&a.generation) {
            let raw = api::number(&*self.opts.api, &sid, &token, &a.number_sid).await?;
            let hash = api::routing_hash(&raw);
            self.edit(|s| {
                if let Some(x) = s.assignment.as_mut() {
                    x.routed = false;
                    x.routing_hash = hash;
                }
            })?;
        }
        self.edit(|s| {
            if s.cleanup.as_ref().is_some_and(|c| c.generation == a.generation) {
                s.cleanup = None;
            }
        })?;
        Ok(())
    }
}
