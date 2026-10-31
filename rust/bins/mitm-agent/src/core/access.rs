//! The firewall signs every Open (`access.ts`, docs/plans/browser-enrollment.md). The control plane
//! says who is opening which agent, in a 60 s open intent signed with the key on this firewall's
//! row; this module adds whether the browser was enrolled with a code sent over the organization's
//! own channel. Only when both hold does it sign a box ticket with this box's key and send the
//! browser on to the agent.
//!
//! ```text
//! POST /__cc/open            {intent, c}    from the agent's /__cc/open page
//! POST /__cc/enroll/confirm  {p, code}      from the agent's /__cc/enroll page
//! access.revoke      {deviceIds}   forget those browsers, tell every agent
//! access.revoke_all  {}            forget every browser, tell every agent
//! ```
//!
//! Both routes answer with a bare status or a 303 and nothing else. The firewall cannot see the
//! browser's address, so every limit is per organization.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine;
use rand::RngCore;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::access_store::{AccessStore, AccessStoreFile, AgentPin, StoredDevice};
use super::agent_client::{AgentClient, AgentTarget};
use super::code_message::{CodeParts, TypedLine, build_code_message, clean_line, record_host, record_name};
use super::consent::{CODE_TTL_MS, DEV_SENDER_TYPE};
use super::identities::{Identity, str_field, vm_id_of};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRoute, CodeSender, CodeSent, ModuleCodes};

/// This module's consent codes (`code_service.module(MODULE)`).
pub const MODULE: &str = "access";
pub const OPEN_PATH: &str = "/__cc/open";
pub const CONFIRM_PATH: &str = "/__cc/enroll/confirm";

pub fn owns_access_path(path: &str) -> bool {
    path == OPEN_PATH || path == CONFIRM_PATH
}

pub const INTENT_MAX_LIFETIME_S: f64 = 120.0;
pub const TICKET_TTL_S: i64 = 60;
pub const DEVICE_TTL_MS: f64 = 90.0 * 24.0 * 60.0 * 60_000.0;
pub const PENDING_PER_HOUR: usize = 5;
pub const OPEN_PER_MINUTE: usize = 30;
pub const CONFIRM_PER_MINUTE: usize = 30;
pub const ACCESS_BODY_BYTES: usize = 8 * 1024;
pub const MAX_DEVICES: usize = 500;
pub const BEAT_DEVICES: usize = 200;
pub const CONFIG_RETRY_FIRST_MS: u64 = 15_000;
pub const CONFIG_RETRY_MS: u64 = 10 * 60_000;

const DEV_COOKIE: &str = "__Host-cc_dev";
pub const DEVICES_PER_BROWSER: usize = 5;
const PEND_COOKIE: &str = "__Host-cc_pend";
/// The consent scope, shared by every module: this module's own.
const SCOPE: &str = "access";

/// Where an intent's `next` sends the browser: the ticket's purpose, the path, and its own `next`.
fn next_route(next: &str) -> Option<(&'static str, &'static str, Option<&'static str>)> {
    Some(match next {
        "chat" => ("browser-login", "/__cc/login", None),
        "screen" => ("browser-view", "/__cc/browser", None),
        "files" => ("browser-login", "/__cc/login", Some("files")),
        "logs" => ("browser-login", "/__cc/login", Some("logs")),
        "whatsapp" => ("browser-login", "/__cc/login", Some("whatsapp")),
        "meetings" => ("browser-login", "/__cc/login", Some("meetings")),
        "phone" => ("browser-login", "/__cc/login", Some("phone")),
        "doctor-chat" => ("browser-login", "/__cc/doctor/chat/", None),
        "doctor" => ("browser-login", "/__cc/doctor/", None),
        "team-chat" => ("browser-login", "/__cc/team-chat/open", None),
        "ai-review" => ("browser-login", "/__cc/doctor/ai-review/", None),
        "firewall-logs" => ("browser-login", "/__cc/doctor/logs/", None),
        "doctor-start" => ("browser-login", "/__cc/doctor/start/", None),
        "logins" => ("browser-login", "/__cc/logins/open", None),
        "content-rules" => ("browser-login", "/__cc/doctor/content-rules/", None),
        _ => return None,
    })
}

/// The destinations served by this firewall itself, never by an agent's `/__cc/open`.
fn firewall_next(next: &str) -> bool {
    matches!(
        next,
        "doctor"
            | "doctor-chat"
            | "team-chat"
            | "ai-review"
            | "firewall-logs"
            | "doctor-start"
            | "logins"
            | "content-rules"
    )
}

/// `DoctorStartChoice`: one credential the console offered (labels and ids, never a secret).
pub type DoctorChoice = Value;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenIntent {
    pub org_id: String,
    pub vm_id: String,
    pub user_id: String,
    pub email: Option<String>,
    pub can_write: bool,
    pub next: String,
    pub jti: String,
    pub exp: f64,
    pub session_id: Option<String>,
    /// `team-chat` only: `Some(None)` when the intent had no usable name.
    pub name: Option<Option<String>>,
    pub doctor_choices: Option<Vec<DoctorChoice>>,
    pub doctor_agent: Option<String>,
}

#[derive(Debug, Clone)]
struct Pending {
    change_id: String,
    vm_id: String,
    intent: OpenIntent,
    c: String,
    pend_hash: String,
    label: String,
    expires_at: u64,
}

/// What a request to the two routes carries that this module reads.
#[derive(Debug, Clone, Default)]
pub struct AccessRequest {
    pub method: String,
    pub origin: Option<String>,
    pub cookie: Option<String>,
    pub user_agent: String,
    pub content_type: String,
    /// The body, or `None` when it could not be read within the cap.
    pub body: Option<Vec<u8>>,
}

/// A bare status, or a 303 with its location and cookies.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessReply {
    pub status: u16,
    pub location: Option<String>,
    pub cookies: Vec<String>,
}

impl AccessReply {
    fn bare(status: u16) -> Self {
        Self {
            status,
            location: None,
            cookies: Vec::new(),
        }
    }

    fn redirect(location: String, cookies: Vec<String>) -> Self {
        Self {
            status: 303,
            location: Some(location),
            cookies,
        }
    }

    pub fn into_response(self) -> cc_http::Resp {
        // A route that failed is the ingress's bare 500 (`content-length: 0` and nothing else).
        if self.status == 500 {
            return cc_http::empty(500);
        }
        let mut r = cc_http::empty(self.status);
        let h = r.headers_mut();
        h.insert("cache-control", http::HeaderValue::from_static("no-store"));
        h.insert("referrer-policy", http::HeaderValue::from_static("no-referrer"));
        h.insert("content-length", http::HeaderValue::from_static("0"));
        if let Some(l) = self.location.and_then(|l| http::HeaderValue::from_str(&l).ok()) {
            h.insert("location", l);
        }
        for c in self.cookies {
            if let Ok(v) = http::HeaderValue::from_str(&c) {
                h.append("set-cookie", v);
            }
        }
        r
    }
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn same_hash(a: &str, b: &str) -> bool {
    cc_crypto::ct_eq(a.as_bytes(), b.as_bytes())
}

/// The value of one cookie in a `Cookie` header, as `cookieValue` reads it.
pub fn cookie_value(header: Option<&str>, name: &str) -> Option<String> {
    for part in header?.split(';') {
        let Some(i) = part.find('=') else { continue };
        if part[..i].trim() == name {
            let v = part[i + 1..].trim();
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

/// `SameSite=None`: an org created before T-105 can have its firewall and its agents on two
/// sites. CSRF is covered by the Origin allowlist, the single-use intent and the browser binding.
fn set_cookie(name: &str, value: &str, max_age_s: u64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age={max_age_s}")
}

/// `deviceLabel`: browser and OS, coarse on purpose.
pub fn device_label(ua: &str) -> String {
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") {
        "Opera"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "A browser"
    };
    let os = if ua.contains("iPhone") {
        Some("iPhone")
    } else if ua.contains("iPad") {
        Some("iPad")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("Mac")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    match os {
        Some(o) => format!("{browser} on {o}"),
        None => browser.to_string(),
    }
}

static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$").expect("regex")
});
static BINDING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{43}$").expect("regex"));
static DEVICE_LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z ]{1,40}$").expect("regex"));
static SESSION_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]{1,80}$").expect("regex"));
static DAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$").expect("regex"));

fn plausible_hostname(h: &str) -> bool {
    h.len() <= 253 && HOSTNAME.is_match(h)
}

/// Milliseconds of an ISO time as `Date.parse` reads the ones written here; NaN otherwise.
pub fn parse_iso(s: &str) -> f64 {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    if b.len() < 20 || b.get(4) != Some(&b'-') || b.get(10) != Some(&b'T') || !s.ends_with('Z') {
        return f64::NAN;
    }
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) =
        (num(0..4), num(5..7), num(8..10), num(11..13), num(14..16), num(17..19))
    else {
        return f64::NAN;
    };
    let ms = if b.get(19) == Some(&b'.') {
        s.get(20..s.len() - 1)
            .and_then(|f| format!("0.{f}").parse::<f64>().ok())
            .map(|f| (f * 1000.0).round())
            .unwrap_or(f64::NAN)
    } else {
        0.0
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    ((days * 86_400 + h * 3600 + mi * 60 + se) * 1000) as f64 + ms
}

fn iso(ms: u64) -> String {
    super::consent::iso(ms)
}

/// A count of hits in a sliding window.
struct Window {
    hits: Vec<u64>,
    max: usize,
    ms: u64,
}

impl Window {
    fn new(max: usize, ms: u64) -> Self {
        Self {
            hits: Vec::new(),
            max,
            ms,
        }
    }

    fn take(&mut self, now: u64) -> bool {
        let floor = now.saturating_sub(self.ms);
        self.hits.retain(|t| *t > floor);
        if self.hits.len() >= self.max {
            return false;
        }
        self.hits.push(now);
        true
    }
}

/// `openCodeMessage`: a new browser's code, in two parts. The email is the control plane's word.
pub fn open_code_message(
    agent_name: Option<&str>,
    vm_id: &str,
    label: &str,
    email: Option<&str>,
    agent_hostname: &str,
    code: &str,
) -> Result<String, String> {
    let host = record_host(Some(agent_hostname));
    let shown = if DEVICE_LABEL.is_match(label) {
        label
    } else {
        "a browser"
    };
    let parts = CodeParts {
        ask: format!(
            "A new browser wants to open the agent {} ({host}): {shown}",
            record_name(agent_name, vm_id)
        ),
        outro: Some(format!(
            "Type the code only on the page that asked for it, at {host}. It expires in 10 minutes. If you did not just press Open, ignore this."
        )),
        typed: email
            .filter(|e| !e.is_empty())
            .map(|e| {
                vec![TypedLine {
                    label: "ControlClaw says this is".into(),
                    text: e.into(),
                    more: None,
                }]
            })
            .unwrap_or_default(),
        details: None,
    };
    build_code_message(code, Some(&parts), "", "", None, None).map_err(|e| e.0)
}

/// `silentListMessage`: the browsers that signed in before anyone could receive a code.
pub fn silent_list_message(devices: &[&StoredDevice], max: usize) -> String {
    let day = |iso: &str| -> String {
        let d: String = iso.chars().take(10).collect();
        if DAY.is_match(&d) { d } else { "?".into() }
    };
    let lines: Vec<String> = devices
        .iter()
        .take(max)
        .map(|d| {
            let label = if DEVICE_LABEL.is_match(&d.label) {
                d.label.as_str()
            } else {
                "a browser"
            };
            let who = match d.email.as_deref().filter(|e| !e.is_empty()) {
                Some(e) => format!(
                    ". ControlClaw says this was: {}",
                    clean_line(e).0.chars().take(100).collect::<String>()
                ),
                None => String::new(),
            };
            format!(
                "- {label}: first {}, last {}{who}",
                day(&d.created_at),
                day(&d.last_used_at)
            )
        })
        .collect();
    let more = if devices.len() > max {
        format!("\n...and {} more.", devices.len() - max)
    } else {
        String::new()
    };
    format!(
        "ControlClaw: {} signed in to your agents without a code, before anyone could receive one:\n{}{more}\nRemove any you don't recognise on the Devices page of your ControlClaw console.",
        if devices.len() == 1 {
            "this browser was"
        } else {
            "these browsers were"
        },
        lines.join("\n")
    )
}

/// `parseDoctorChoices`: the `doctorChoices` claim of a `doctor-start` intent, or `None` when any
/// part is malformed.
pub fn parse_doctor_choices(value: Option<&Value>) -> Option<Vec<Value>> {
    let list = value?.as_array()?;
    if list.len() > 20 {
        return None;
    }
    let text = |v: Option<&Value>, max: usize| -> Option<String> {
        let s = v?.as_str()?;
        let n = s.encode_utf16().count();
        (n > 0 && n <= max).then(|| s.to_string())
    };
    let mut out = Vec::new();
    for raw in list {
        let c = raw.as_object()?;
        let (id, label, provider) = (
            text(c.get("id"), 100),
            text(c.get("label"), 120),
            text(c.get("provider"), 40),
        );
        let clis: Vec<Value> = c
            .get("clis")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|x| matches!(x.as_str(), Some("claude" | "codex" | "pi")))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let models: Vec<Option<Value>> = c
            .get("models")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .take(40)
                    .map(|m| {
                        let m = m.as_object()?;
                        Some(json!({"id": text(m.get("id"), 150)?, "name": text(m.get("name"), 150)?}))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (Some(id), Some(label), Some(provider)) = (id, label, provider) else {
            return None;
        };
        if clis.is_empty() || models.iter().any(Option::is_none) {
            return None;
        }
        out.push(json!({"id": id, "label": label, "provider": provider, "clis": clis, "models": models.into_iter().flatten().collect::<Vec<_>>()}));
    }
    Some(out)
}

/// What the module reads from the rest of the firewall.
pub struct AccessOptions {
    pub store: AccessStoreFile,
    pub org_id: String,
    pub box_id: String,
    pub agent: AgentClient,
    pub consent: Arc<dyn ModuleCodes>,
    /// `codeRoutes()`; empty when there is no channels module.
    pub code_routes: Arc<dyn Fn() -> Vec<CodeRoute> + Send + Sync>,
    /// False when the channel store would not open: fail closed, never a free window.
    pub channels_ready: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Agents and the brain in the identity map.
    pub identities: Arc<dyn Fn() -> Vec<Identity> + Send + Sync>,
    /// True while the agent, or the whole organization, is under an emergency stop.
    pub stopped: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// This firewall's own public hostname, or `None`.
    pub hostname: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// PEM: the control plane's key for this firewall's row.
    pub saas_public_key: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// PEM: this box's own private key, the one every agent pins.
    pub signing_key: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    pub now: Arc<dyn Fn() -> u64 + Send + Sync>,
}

struct State {
    store: AccessStore,
    pending: Option<Pending>,
    used_jti: HashMap<String, f64>,
    opens: Window,
    confirms: Window,
    pendings: Window,
    configured: HashMap<String, String>,
    config_tried: HashMap<String, (u64, u64)>,
    listing: bool,
}

pub struct AccessFirewall {
    opts: AccessOptions,
    state: Mutex<State>,
    /// The store would not open at start, so the pins it had are lost (`pinnedAgents`).
    pins_lost: bool,
}

/// What an `authorize*` grants.
#[derive(Debug, Clone, PartialEq)]
pub struct Authorized {
    pub vm_id: String,
    pub user_id: String,
    pub device_id: String,
    pub can_write: bool,
    pub session_id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub doctor_choices: Option<Vec<Value>>,
    pub doctor_agent: Option<String>,
}

impl AccessFirewall {
    pub fn new(opts: AccessOptions) -> Arc<Self> {
        let store = opts.store.load();
        let pins_lost = cc_crypto::store_health::is_store_unreadable("access");
        Arc::new(Self {
            opts,
            state: Mutex::new(State {
                store,
                pending: None,
                used_jti: HashMap::new(),
                opens: Window::new(OPEN_PER_MINUTE, 60_000),
                confirms: Window::new(CONFIRM_PER_MINUTE, 60_000),
                pendings: Window::new(PENDING_PER_HOUR, 60 * 60_000),
                configured: HashMap::new(),
                config_tried: HashMap::new(),
                listing: false,
            }),
            pins_lost,
        })
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> u64 {
        (self.opts.now)()
    }

    fn save(&self, st: &State) -> Result<(), String> {
        self.opts.store.save(&st.store)
    }

    fn save_logged(&self, st: &State) {
        if let Err(e) = self.save(st) {
            tracing::error!("[access] could not save the browser store: {e}");
        }
    }

    // ---- state ----

    /// `https://<this firewall's hostname>`, or `None`.
    pub fn origin(&self) -> Option<String> {
        let h = (self.opts.hostname)()?;
        plausible_hostname(&h).then(|| format!("https://{}", h.to_lowercase()))
    }

    /// Whether this firewall can take Opens (`open_v1`).
    pub fn ready(&self) -> bool {
        self.origin().is_some() && (self.opts.saas_public_key)().is_some()
    }

    /// Real people a code can go to: the dev route is not a person.
    fn real_routes(&self) -> Vec<CodeRoute> {
        (self.opts.code_routes)()
            .into_iter()
            .map(|mut r| {
                r.senders.retain(|s| !matches!(s, CodeSender::Dev));
                r
            })
            .filter(|r| !r.senders.is_empty())
            .collect()
    }

    /// Nobody approved on any channel: the trust-on-first-use test every other change uses.
    pub fn free_window(&self) -> bool {
        (self.opts.channels_ready)() && self.real_routes().is_empty()
    }

    /// `notePins`: pin every agent the first time it appears; a pin never moves.
    pub fn note_pins(&self) {
        let identities = (self.opts.identities)();
        let at = iso(self.now());
        let mut st = self.st();
        let mut changed = false;
        for i in &identities {
            let vm_id = vm_id_of(i);
            let Some(offered) = str_field(i, "hostname").filter(|h| plausible_hostname(h)) else {
                continue;
            };
            if vm_id.is_empty() {
                continue;
            }
            let hostname = offered.to_lowercase();
            let alias = str_field(i, "access_hostname").map(str::to_lowercase);
            let domain = |h: &str| h.split('.').skip(1).collect::<Vec<_>>().join(".");
            let access_hostname =
                alias.filter(|a| plausible_hostname(a) && *a != hostname && domain(a) == domain(&hostname));
            match st.store.pins.get_mut(&vm_id) {
                None => {
                    st.store.pins.insert(
                        vm_id.clone(),
                        AgentPin {
                            hostname: hostname.clone(),
                            access_hostname: access_hostname.clone(),
                            at: at.clone(),
                            extra: Map::new(),
                        },
                    );
                    changed = true;
                    tracing::info!("[access] pinned {vm_id} to {hostname}");
                }
                Some(pin) if pin.hostname == hostname && pin.access_hostname.is_none() && access_hostname.is_some() => {
                    pin.access_hostname = access_hostname;
                    changed = true;
                }
                Some(pin) if pin.hostname != hostname || pin.access_hostname != access_hostname => {
                    tracing::info!(
                        "[access] the identity map says {vm_id} is at {hostname}; it stays pinned to {}",
                        pin.hostname
                    );
                }
                Some(_) => {}
            }
        }
        if changed {
            self.save_logged(&st);
        }
    }

    /// Only agents still in the identity map answer for an origin.
    fn pinned_by_origin(&self, st: &State, origin: &str, live: &[String]) -> Option<(String, String)> {
        let want = origin.to_lowercase();
        for (vm_id, pin) in &st.store.pins {
            if !live.contains(vm_id) {
                continue;
            }
            for h in [Some(&pin.hostname), pin.access_hostname.as_ref()]
                .into_iter()
                .flatten()
            {
                if format!("https://{h}") == want {
                    return Some((vm_id.clone(), h.clone()));
                }
            }
        }
        None
    }

    /// `pinnedHost`: the hostname pinned the first time the agent appeared.
    pub fn pinned_host(&self, vm_id: &str) -> Option<String> {
        self.st().store.pins.get(vm_id).map(|p| p.hostname.clone())
    }

    /// `pinnedAgents`: every pin, or `None` when the store would not open at start.
    pub fn pinned_agents(&self) -> Option<Vec<(String, String)>> {
        if self.pins_lost {
            return None;
        }
        Some(
            self.st()
                .store
                .pins
                .iter()
                .map(|(k, p)| (k.clone(), p.hostname.clone()))
                .collect(),
        )
    }

    fn agent_name(&self, identities: &[Identity], st: &State, vm_id: &str) -> String {
        identities
            .iter()
            .find(|i| vm_id_of(i) == vm_id)
            .and_then(|i| str_field(i, "name").filter(|n| !n.is_empty()).map(str::to_string))
            .or_else(|| st.store.pins.get(vm_id).map(|p| p.hostname.clone()))
            .unwrap_or_else(|| vm_id.to_string())
    }

    fn live(&self) -> (Vec<Identity>, Vec<String>) {
        let ids = (self.opts.identities)();
        let live = ids.iter().map(vm_id_of).collect();
        (ids, live)
    }

    // ---- the two routes ----

    pub async fn handle(&self, path: &str, req: AccessRequest) -> AccessReply {
        if req.method != "POST" {
            return AccessReply::bare(405);
        }
        let r = if path == OPEN_PATH {
            self.open(req).await
        } else {
            self.confirm(req).await
        };
        r.unwrap_or_else(|e| {
            tracing::error!("[access] {e}");
            AccessReply::bare(500)
        })
    }

    fn form(req: &AccessRequest) -> Option<HashMap<String, String>> {
        if !req
            .content_type
            .to_lowercase()
            .starts_with("application/x-www-form-urlencoded")
        {
            return None;
        }
        let body = req.body.as_ref()?;
        let mut out = HashMap::new();
        for (k, v) in url::form_urlencoded::parse(body) {
            out.entry(k.into_owned()).or_insert_with(|| v.into_owned());
        }
        Some(out)
    }

    fn agent_for(&self, req: &AccessRequest) -> Option<(String, String)> {
        let origin = req.origin.as_deref().filter(|o| !o.is_empty())?;
        let (_, live) = self.live();
        let st = self.st();
        self.pinned_by_origin(&st, origin, &live)
    }

    async fn open(&self, req: AccessRequest) -> Result<AccessReply, String> {
        let Some((agent_vm, agent_host)) = self.agent_for(&req) else {
            return Ok(AccessReply::bare(403));
        };
        let fail = |e: &str| AccessReply::redirect(format!("https://{agent_host}{OPEN_PATH}#e={e}"), Vec::new());
        let Some(form) = Self::form(&req) else {
            return Ok(AccessReply::bare(400));
        };
        let intent = self
            .verify_intent(form.get("intent").map(String::as_str).unwrap_or(""))
            .await;
        let c = form.get("c").cloned().unwrap_or_default();
        let Some(intent) = intent.filter(|i| !firewall_next(&i.next) && i.vm_id == agent_vm && BINDING.is_match(&c))
        else {
            return Ok(fail("invalid"));
        };
        let now = self.now();
        {
            let mut st = self.st();
            if !st.opens.take(now) {
                return Ok(fail("busy"));
            }
            if !consume_jti(&mut st, &intent.jti, intent.exp, now) {
                return Ok(fail("used"));
            }
        }
        if (self.opts.stopped)(&intent.vm_id) {
            return Ok(fail("stopped"));
        }
        let label = device_label(&req.user_agent);
        let enrolled = {
            let mut st = self.st();
            let found = enrolled(&st, req.cookie.as_deref(), &intent.user_id, now).map(|(id, _)| id);
            if let Some(id) = &found {
                if let Some(d) = st.store.devices.get_mut(id) {
                    d.last_used_at = iso(now);
                }
                self.save(&st)?;
            }
            found
        };
        if let Some(id) = enrolled {
            tracing::info!("[access] open {} on {agent_host}: enrolled browser {id}", intent.next);
            let cookie = self.device_cookie(req.cookie.as_deref(), None);
            return self.issue(&agent_host, &intent, &c, &id, vec![cookie]);
        }
        // The owner's first login: until someone is approved on a channel there is nobody to send
        // a code to, so a new browser is enrolled without one (and listed to the owner later).
        if self.free_window() {
            let (id, cookie) = self.enroll(&intent, &label, "tofu")?;
            tracing::info!(
                "[access] open {} on {agent_host}: browser {id} enrolled without a code (tofu)",
                intent.next
            );
            self.maybe_list().await;
            let cookie = self.device_cookie(req.cookie.as_deref(), Some(&cookie));
            return self.issue(&agent_host, &intent, &c, &id, vec![cookie]);
        }
        // Fail closed on a channel store that would not open.
        if !(self.opts.channels_ready)() {
            return Ok(fail("unreachable"));
        }
        if !self.st().pendings.take(now) {
            return Ok(fail("busy"));
        }
        let pend_cookie = token(32);
        let pending = Pending {
            change_id: format!("acc_{}", token(16)),
            vm_id: intent.vm_id.clone(),
            intent: intent.clone(),
            c: c.clone(),
            pend_hash: sha256_hex(&pend_cookie),
            label: label.clone(),
            expires_at: now + CODE_TTL_MS,
        };
        let (identities, _) = self.live();
        let agent_name = self.agent_name(&identities, &self.st(), &intent.vm_id);
        let record = identities
            .iter()
            .find(|i| vm_id_of(i) == intent.vm_id)
            .and_then(|i| str_field(i, "name").map(str::to_string));
        let message: crate::contracts::CodeText = {
            let (vm, lbl, email, host) = (
                intent.vm_id.clone(),
                label.clone(),
                intent.email.clone(),
                agent_host.clone(),
            );
            Arc::new(move |code: &str| open_code_message(record.as_deref(), &vm, &lbl, email.as_deref(), &host, code))
        };
        let sent = self
            .opts
            .consent
            .send(CodeAsk {
                scope: SCOPE.into(),
                change_id: pending.change_id.clone(),
                proposal: Value::Null,
                agent_name,
                summary: label.clone(),
                routes: (self.opts.code_routes)(),
                message: Some(message),
                ..Default::default()
            })
            .await;
        let sent_via = match sent {
            CodeSent::Sent { sent_via, .. } => sent_via,
            CodeSent::Failed { message } => {
                tracing::info!("[access] could not send a code for a new browser on {agent_host}: {message}");
                return Ok(fail("unreachable"));
            }
        };
        let change_id = pending.change_id.clone();
        // A newer Open replaces the one before it: one pending enrollment per organization.
        self.st().pending = Some(pending);
        let channel = sent_via.split(':').next().unwrap_or_default().to_string();
        if channel == DEV_SENDER_TYPE {
            tracing::info!(
                "[access] dev build: the code for {change_id} is {}",
                &sent_via[channel.len() + 1..]
            );
        } else {
            tracing::info!(
                "[access] open {} on {agent_host}: new browser, code sent via {channel}",
                intent.next
            );
        }
        Ok(AccessReply::redirect(
            format!(
                "https://{agent_host}/__cc/enroll#p={change_id}&via={}",
                super::permissions::encode_uri_component(&channel)
            ),
            vec![set_cookie(PEND_COOKIE, &pend_cookie, CODE_TTL_MS / 1000)],
        ))
    }

    /// Drop the pending Open when it is still this one: another browser's may have taken its place.
    fn clear_pending(&self, change_id: &str) {
        let mut st = self.st();
        if st.pending.as_ref().is_some_and(|p| p.change_id == change_id) {
            st.pending = None;
        }
    }

    async fn confirm(&self, req: AccessRequest) -> Result<AccessReply, String> {
        let Some((agent_vm, agent_host)) = self.agent_for(&req) else {
            return Ok(AccessReply::bare(403));
        };
        let expired = || AccessReply::redirect(format!("https://{agent_host}{OPEN_PATH}#e=code_expired"), Vec::new());
        let Some(form) = Self::form(&req) else {
            return Ok(AccessReply::bare(400));
        };
        let p = form.get("p").cloned().unwrap_or_default();
        let code: String = form
            .get("code")
            .map(|c| c.chars().filter(|ch| !ch.is_whitespace()).collect())
            .unwrap_or_default();
        let now = self.now();
        let pending = {
            let st = self.st();
            match &st.pending {
                Some(pd) if pd.change_id == p && pd.vm_id == agent_vm && now <= pd.expires_at => pd.clone(),
                _ => return Ok(expired()),
            }
        };
        // Only good in the browser that asked: without the cookie nothing is counted.
        let pend = cookie_value(req.cookie.as_deref(), PEND_COOKIE);
        if !pend.is_some_and(|v| same_hash(&sha256_hex(&v), &pending.pend_hash)) {
            return Ok(expired());
        }
        if !self.st().confirms.take(now) {
            return Ok(AccessReply::redirect(
                format!("https://{agent_host}{OPEN_PATH}#e=busy"),
                Vec::new(),
            ));
        }
        if (self.opts.stopped)(&pending.vm_id) {
            return Ok(AccessReply::redirect(
                format!("https://{agent_host}{OPEN_PATH}#e=stopped"),
                Vec::new(),
            ));
        }
        match self.opts.consent.verify(SCOPE, &p, &code) {
            CodeCheck::Expired => {
                self.clear_pending(&p);
                return Ok(expired());
            }
            CodeCheck::Wrong { tries_left } => {
                if tries_left == 0 {
                    self.clear_pending(&p);
                    tracing::info!("[access] the code for a new browser on {agent_host} ran out of tries");
                    return Ok(expired());
                }
                return Ok(AccessReply::redirect(
                    format!("https://{agent_host}/__cc/enroll#p={p}&e=invalid_code&left={tries_left}"),
                    Vec::new(),
                ));
            }
            CodeCheck::Ok { .. } => {}
        }
        self.clear_pending(&p);
        let (id, cookie) = self.enroll(&pending.intent, &pending.label, "code")?;
        tracing::info!(
            "[access] browser {id} enrolled with a code ({}) on {agent_host}",
            pending.label
        );
        let dev = self.device_cookie(req.cookie.as_deref(), Some(&cookie));
        self.issue(
            &agent_host,
            &pending.intent,
            &pending.c,
            &id,
            vec![dev, set_cookie(PEND_COOKIE, "", 0)],
        )
    }

    fn issue(
        &self,
        hostname: &str,
        intent: &OpenIntent,
        c: &str,
        device_id: &str,
        cookies: Vec<String>,
    ) -> Result<AccessReply, String> {
        let (purpose, path, next) = next_route(&intent.next).ok_or("unknown next")?;
        let ticket = self.sign_ticket(&intent.vm_id, purpose, c, device_id, intent.can_write, next)?;
        Ok(AccessReply::redirect(
            format!("https://{hostname}{path}#t={ticket}"),
            cookies,
        ))
    }

    // ---- intents, tickets, devices ----

    /// `verifyIntent`.
    pub async fn verify_intent(&self, jwt: &str) -> Option<OpenIntent> {
        let pem = (self.opts.saas_public_key)()?;
        if jwt.is_empty() {
            return None;
        }
        let key = cc_auth::jwt::VerifyKey::ed25519_spki_pem(&pem).ok()?;
        let now_ms = self.now();
        let p = cc_auth::jwt::verify(
            jwt,
            &key,
            cc_auth::jwt::VerifyOptions {
                clock_tolerance_s: 0,
                now: Some((now_ms / 1000) as i64),
            },
        )
        .ok()?;
        if p.get("purpose").and_then(Value::as_str) != Some("open-intent")
            || p.get("orgId").and_then(Value::as_str) != Some(self.opts.org_id.as_str())
        {
            return None;
        }
        let vm_id = p.get("vmId")?.as_str()?.to_string();
        let user_id = p.get("userId")?.as_str().filter(|s| !s.is_empty())?.to_string();
        let jti = p.get("jti")?.as_str().filter(|s| !s.is_empty())?.to_string();
        let exp = p.get("exp")?.as_f64()?;
        if exp - now_ms as f64 / 1000.0 > INTENT_MAX_LIFETIME_S {
            return None;
        }
        let next = p.get("next")?.as_str()?.to_string();
        next_route(&next)?;
        let session = p
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|s| SESSION_ID.is_match(s));
        if (next == "doctor" || next == "doctor-chat") && session.is_none() {
            return None;
        }
        if matches!(
            next.as_str(),
            "team-chat" | "firewall-logs" | "doctor-start" | "logins" | "content-rules"
        ) && vm_id != self.opts.box_id
        {
            return None;
        }
        let doctor_choices = if next == "doctor-start" {
            Some(parse_doctor_choices(p.get("doctorChoices"))?)
        } else {
            None
        };
        let doctor_agent = (next == "doctor-start")
            .then(|| {
                p.get("doctorAgent")
                    .and_then(Value::as_str)
                    .filter(|s| SESSION_ID.is_match(s))
            })
            .flatten()
            .map(str::to_string);
        let email = p
            .get("email")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf16_lossy(&s.encode_utf16().take(200).collect::<Vec<_>>()));
        let name = (next == "team-chat").then(|| {
            p.get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf16_lossy(&s.encode_utf16().take(80).collect::<Vec<_>>()))
        });
        Some(OpenIntent {
            org_id: self.opts.org_id.clone(),
            vm_id,
            user_id,
            email,
            can_write: p.get("canWrite") == Some(&Value::Bool(true)),
            session_id: (next == "doctor" || next == "doctor-chat")
                .then(|| session.map(str::to_string))
                .flatten(),
            next,
            jti,
            exp,
            name,
            doctor_choices,
            doctor_agent,
        })
    }

    /// The firewall's own pages about one agent (Doctor, the AI review history): an intent for
    /// that agent, from this firewall's origin, in a browser that is ALREADY enrolled.
    pub async fn authorize_open(
        &self,
        origin: Option<&str>,
        cookie: Option<&str>,
        jwt: &str,
        next: &str,
    ) -> Option<Authorized> {
        let mine = self.origin()?;
        if origin != Some(mine.as_str()) {
            return None;
        }
        let intent = self.verify_intent(jwt).await?;
        if intent.next != next
            || (next == "doctor" && !intent.can_write)
            || (next != "ai-review" && intent.session_id.is_none())
            || (self.opts.stopped)(&intent.vm_id)
        {
            return None;
        }
        let own = (next == "doctor" || next == "doctor-chat") && intent.vm_id == self.opts.box_id;
        let (_, live) = self.live();
        if !own && !live.contains(&intent.vm_id) {
            return None;
        }
        let now = self.now();
        let mut st = self.st();
        let (device_id, _) = enrolled(&st, cookie, &intent.user_id, now)?;
        if !st.opens.take(now) || !consume_jti(&mut st, &intent.jti, intent.exp, now) {
            return None;
        }
        Some(Authorized {
            vm_id: intent.vm_id,
            user_id: intent.user_id,
            device_id,
            can_write: intent.can_write,
            session_id: intent.session_id,
            email: None,
            name: None,
            doctor_choices: None,
            doctor_agent: None,
        })
    }

    /// One of this firewall's own pages (`team-chat`, `logins`, `firewall-logs`, `doctor-start`,
    /// `content-rules`): an intent naming this box, from its origin, in an enrolled browser.
    pub async fn authorize_firewall(
        &self,
        origin: Option<&str>,
        cookie: Option<&str>,
        jwt: &str,
        next: &str,
    ) -> Option<Authorized> {
        let mine = self.origin()?;
        if origin != Some(mine.as_str()) {
            return None;
        }
        let intent = self.verify_intent(jwt).await?;
        if intent.next != next || intent.vm_id != self.opts.box_id {
            return None;
        }
        let owner_only = matches!(next, "logins" | "doctor-start" | "content-rules");
        if owner_only && !intent.can_write {
            return None;
        }
        // The logins page is not refused under a stop (the TS does not check it there).
        if next != "logins" && (self.opts.stopped)(&intent.vm_id) {
            return None;
        }
        let now = self.now();
        let mut st = self.st();
        let (device_id, _) = enrolled(&st, cookie, &intent.user_id, now)?;
        if !st.opens.take(now) || !consume_jti(&mut st, &intent.jti, intent.exp, now) {
            return None;
        }
        if let Some(d) = st.store.devices.get_mut(&device_id) {
            d.last_used_at = iso(now);
        }
        self.save_logged(&st);
        Some(Authorized {
            vm_id: intent.vm_id,
            user_id: intent.user_id,
            device_id,
            can_write: intent.can_write,
            session_id: None,
            email: intent.email,
            name: intent.name.flatten(),
            doctor_choices: intent.doctor_choices,
            doctor_agent: intent.doctor_agent,
        })
    }

    /// Standalone (`local_intent`): an intent this firewall signed itself, for one of its own pages,
    /// enrolls the browser that brings it. Only someone who can read this firewall's key could make
    /// one, so it stands for the owner; there is no console to send a code from. The page's next,
    /// and the device cookie to set; `None` for an intent this route does not take.
    pub async fn local_enroll(&self, req: &AccessRequest, jwt: &str) -> Result<Option<(String, String)>, String> {
        // Each refusal is logged with its reason: the browser is told only that the link failed.
        let refuse = |why: &str| {
            tracing::info!("[access] local link refused: {why}");
            Ok(None)
        };
        let Some(mine) = self.origin() else {
            return refuse("no keys/vm_hostname, so this firewall has no address to compare");
        };
        if req.origin.as_deref() != Some(mine.as_str()) {
            return refuse(&format!("opened at {:?}, not {mine}", req.origin));
        }
        let Some(intent) = self.verify_intent(jwt).await else {
            return refuse("the link does not verify (another firewall's, expired, or for another organization)");
        };
        if !firewall_next(&intent.next) || intent.vm_id != self.opts.box_id {
            return refuse("not a link to one of this firewall's pages");
        }
        let now = self.now();
        let found = {
            let mut st = self.st();
            if !st.opens.take(now) {
                return refuse("too many opens this minute");
            }
            if !consume_jti(&mut st, &intent.jti, intent.exp, now) {
                return refuse("used already");
            }
            enrolled(&st, req.cookie.as_deref(), &intent.user_id, now).map(|(id, _)| id)
        };
        let added = match found {
            Some(_) => None,
            None => {
                let (id, cookie) = self.enroll(&intent, &device_label(&req.user_agent), "local")?;
                tracing::info!("[access] browser {id} enrolled with this firewall's own link");
                Some(cookie)
            }
        };
        Ok(Some((
            intent.next,
            self.device_cookie(req.cookie.as_deref(), added.as_deref()),
        )))
    }

    /// Whether a grant for one of this firewall's own pages still holds.
    pub fn firewall_device_active(&self, cookie: Option<&str>, user_id: &str, device_id: &str) -> bool {
        !(self.opts.stopped)(&self.opts.box_id) && self.device_is(cookie, user_id, device_id)
    }

    /// Whether a logins grant's browser is still enrolled for that person.
    pub fn logins_device_active(&self, cookie: Option<&str>, user_id: &str, device_id: &str) -> bool {
        self.device_is(cookie, user_id, device_id)
    }

    /// Whether a grant from `authorize_open` still holds.
    pub fn device_active(&self, cookie: Option<&str>, user_id: &str, device_id: &str, vm_id: &str) -> bool {
        let known = vm_id == self.opts.box_id || self.live().1.iter().any(|v| v == vm_id);
        !(self.opts.stopped)(vm_id) && known && self.device_is(cookie, user_id, device_id)
    }

    fn device_is(&self, cookie: Option<&str>, user_id: &str, device_id: &str) -> bool {
        let st = self.st();
        enrolled(&st, cookie, user_id, self.now()).is_some_and(|(id, _)| id == device_id)
    }

    /// `signTicket`: the claims, then `iss`, `jti`, `iat`, `exp` (60 s), with this box's key.
    pub fn sign_ticket(
        &self,
        vm_id: &str,
        purpose: &str,
        c: &str,
        device_id: &str,
        can_write: bool,
        next: Option<&str>,
    ) -> Result<String, String> {
        let pem = (self.opts.signing_key)().ok_or("no signing key")?;
        let key = cc_auth::jwt::SignKey::ed25519_pkcs8_pem(&pem).map_err(|e| e.to_string())?;
        let mut claims = Map::new();
        claims.insert("vmId".into(), json!(vm_id));
        claims.insert("purpose".into(), json!(purpose));
        claims.insert("c".into(), json!(c));
        claims.insert("deviceId".into(), json!(device_id));
        claims.insert("canWrite".into(), json!(can_write));
        if let Some(n) = next {
            claims.insert("next".into(), json!(n));
        }
        claims.insert("iss".into(), json!(format!("fw:{}", self.opts.box_id)));
        claims.insert("jti".into(), json!(token(16)));
        let now_s = (self.now() / 1000) as i64;
        cc_auth::jwt::sign(claims, &key, Some(TICKET_TTL_S), Some(now_s)).map_err(|e| e.to_string())
    }

    /// The device cookie to send back: every live device the browser holds, plus `added`.
    fn device_cookie(&self, cookie: Option<&str>, added: Option<&str>) -> String {
        let st = self.st();
        let mut tokens: Vec<String> = live_devices(&st, cookie, self.now()).into_iter().map(|d| d.2).collect();
        if let Some(a) = added {
            tokens.push(a.to_string());
        }
        let keep = tokens.len().saturating_sub(DEVICES_PER_BROWSER);
        set_cookie(DEV_COOKIE, &tokens[keep..].join("."), (DEVICE_TTL_MS / 1000.0) as u64)
    }

    fn enroll(&self, intent: &OpenIntent, label: &str, via: &str) -> Result<(String, String), String> {
        let cookie = token(32);
        let id = format!("dev_{}", token(12));
        let now = self.now();
        let at = iso(now);
        let mut st = self.st();
        st.store.devices.insert(
            id.clone(),
            StoredDevice {
                hash: sha256_hex(&cookie),
                user_id: intent.user_id.clone(),
                email: intent.email.clone(),
                label: label.into(),
                via: via.into(),
                created_at: at.clone(),
                last_used_at: at,
                listed_at: Some(Value::Null),
                extra: Map::new(),
            },
        );
        prune(&mut st.store, now);
        self.save(&st)?;
        Ok((id, cookie))
    }

    // ---- the owner's list, config, revocation ----

    /// `maybeList`: send the owner the browsers enrolled without a code, once there is an owner.
    pub async fn maybe_list(&self) {
        if !(self.opts.channels_ready)() {
            return;
        }
        let routes = self.real_routes();
        if routes.is_empty() {
            return;
        }
        let (unlisted, text) = {
            let mut st = self.st();
            if st.listing {
                return;
            }
            let unlisted: Vec<String> = st
                .store
                .devices
                .iter()
                .filter(|(_, d)| d.via != "code" && !d.listed_at.as_ref().is_some_and(super::sync::js_truthy))
                .map(|(k, _)| k.clone())
                .collect();
            if unlisted.is_empty() {
                return;
            }
            st.listing = true;
            let devices: Vec<&StoredDevice> = unlisted.iter().filter_map(|k| st.store.devices.get(k)).collect();
            let text = silent_list_message(&devices, 20);
            (unlisted, text)
        };
        // Reset however this ends: a request that is dropped mid-send must not stop the list for good.
        struct Listing<'a>(&'a AccessFirewall);
        impl Drop for Listing<'_> {
            fn drop(&mut self) {
                self.0.st().listing = false;
            }
        }
        let _listing = Listing(self);
        'out: for route in &routes {
            for sender in &route.senders {
                let CodeSender::Person { kind, id, .. } = sender else {
                    continue;
                };
                super::own_messages::remember_own(&text);
                let target = AgentTarget::new(&route.vm_id, &route.hostname);
                match self
                    .opts
                    .agent
                    .post(
                        &target,
                        "/channels/send",
                        &json!({"type": kind, "to": id, "text": text}),
                    )
                    .await
                {
                    Ok(_) => {
                        let at = iso(self.now());
                        let mut st = self.st();
                        for k in &unlisted {
                            if let Some(d) = st.store.devices.get_mut(k) {
                                d.listed_at = Some(json!(at));
                            }
                        }
                        self.save_logged(&st);
                        tracing::info!(
                            "[access] listed {} browser(s) enrolled without a code to the owner via {kind}",
                            unlisted.len()
                        );
                        break 'out;
                    }
                    Err(e) => tracing::info!(
                        "[access] could not send the browser list via {kind} on {}: {e}",
                        route.hostname
                    ),
                }
            }
        }
    }

    /// `pushConfig`: tell each agent where its firewall is, retried with a backoff.
    pub async fn push_config(&self) {
        let Some(origin) = self.origin() else { return };
        let (_, live) = self.live();
        let now = self.now();
        let due: Vec<(String, String, bool)> = {
            let mut st = self.st();
            let pins: Vec<(String, String)> = st
                .store
                .pins
                .iter()
                .map(|(k, p)| (k.clone(), p.hostname.clone()))
                .collect();
            let mut due = Vec::new();
            for (vm_id, host) in pins {
                if !live.contains(&vm_id) || st.configured.get(&vm_id) == Some(&origin) {
                    continue;
                }
                let tried = st.config_tried.get(&vm_id).copied();
                if let Some((at, wait)) = tried
                    && now.saturating_sub(at) < wait
                {
                    continue;
                }
                let wait = tried
                    .map(|(_, w)| (w * 2).min(CONFIG_RETRY_MS))
                    .unwrap_or(CONFIG_RETRY_FIRST_MS);
                st.config_tried.insert(vm_id.clone(), (now, wait));
                due.push((vm_id, host, tried.is_none()));
            }
            due
        };
        for (vm_id, host, first) in due {
            let target = AgentTarget::new(&vm_id, &host);
            match self
                .opts
                .agent
                .post(&target, "/access/config", &json!({"firewallOrigin": origin}))
                .await
            {
                Ok(_) => {
                    self.st().configured.insert(vm_id, origin.clone());
                    tracing::info!("[access] {host} knows this firewall is at {origin}");
                }
                Err(e) if first => {
                    tracing::info!("[access] could not tell {host} where this firewall is ({e}); trying again later")
                }
                Err(_) => {}
            }
        }
    }

    pub async fn tick(&self) {
        self.note_pins();
        self.push_config().await;
        self.maybe_list().await;
    }

    /// `access.revoke`.
    pub async fn revoke(&self, payload: Map<String, Value>) -> CommandOutcome {
        let ids: Vec<String> = payload
            .get("deviceIds")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if ids.is_empty() {
            return CommandOutcome::failed("failed", "malformed access.revoke payload");
        }
        let revoked: Vec<String> = {
            let mut st = self.st();
            let revoked: Vec<String> = ids
                .iter()
                .filter(|id| st.store.devices.contains_key(*id))
                .cloned()
                .collect();
            for id in &revoked {
                st.store.devices.shift_remove(id);
            }
            if !revoked.is_empty()
                && let Err(e) = self.save(&st)
            {
                return CommandOutcome::failed("failed", e);
            }
            revoked
        };
        tracing::info!("[access] removed {} browser(s)", revoked.len());
        let (pushed, failed) = self.push_revoke(json!({"deviceIds": ids})).await;
        let unknown: Vec<&String> = ids.iter().filter(|id| !revoked.contains(id)).collect();
        let mut data = Map::new();
        data.insert("revoked".into(), json!(revoked));
        data.insert("unknown".into(), json!(unknown));
        data.insert("pushed".into(), json!(pushed));
        data.insert("failed".into(), json!(failed));
        CommandOutcome {
            ok: true,
            status: "applied".into(),
            message: None,
            data: Some(data),
        }
    }

    /// `access.revoke_all`.
    pub async fn revoke_all(&self) -> CommandOutcome {
        let count = {
            let mut st = self.st();
            let count = st.store.devices.len();
            st.store.devices.clear();
            if let Err(e) = self.save(&st) {
                return CommandOutcome::failed("failed", e);
            }
            if st.pending.take().is_some() {
                self.opts.consent.forget(SCOPE);
            }
            count
        };
        tracing::info!("[access] signed out every browser ({count})");
        let (pushed, failed) = self.push_revoke(json!({"all": true})).await;
        let mut data = Map::new();
        data.insert("revoked".into(), json!(count));
        data.insert("pushed".into(), json!(pushed));
        data.insert("failed".into(), json!(failed));
        CommandOutcome {
            ok: true,
            status: "applied".into(),
            message: None,
            data: Some(data),
        }
    }

    /// Best effort: the firewall already stopped issuing tickets to those browsers.
    async fn push_revoke(&self, body: Value) -> (Vec<String>, Vec<Value>) {
        let (_, live) = self.live();
        let pins: Vec<(String, String)> = self
            .st()
            .store
            .pins
            .iter()
            .filter(|(k, _)| live.contains(k))
            .map(|(k, p)| (k.clone(), p.hostname.clone()))
            .collect();
        let mut pushed = Vec::new();
        let mut failed = Vec::new();
        for (vm_id, host) in pins {
            match self
                .opts
                .agent
                .post(&AgentTarget::new(&vm_id, &host), "/access/revoke", &body)
                .await
            {
                Ok(_) => pushed.push(vm_id),
                Err(e) => {
                    let msg = String::from_utf16_lossy(&e.to_string().encode_utf16().take(200).collect::<Vec<_>>());
                    failed.push(json!({"vmId": vm_id, "error": msg}));
                }
            }
        }
        (pushed, failed)
    }

    /// The beat's `access` section: ids, labels and dates; never a cookie or a hash.
    pub fn status(&self) -> Value {
        let origin = self.origin();
        let free = self.free_window();
        let now = self.now();
        let st = self.st();
        let mut devices: Vec<(&String, &StoredDevice)> = st.store.devices.iter().collect();
        // A stable sort, newest first, as the TS sorts by `Date.parse`.
        devices.sort_by(|a, b| {
            let (x, y) = (parse_iso(&b.1.last_used_at), parse_iso(&a.1.last_used_at));
            x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
        });
        let list: Vec<Value> = devices
            .into_iter()
            .take(BEAT_DEVICES)
            .map(|(id, d)| {
                json!({"deviceId": id, "userId": d.user_id, "email": d.email, "label": d.label, "via": d.via, "createdAt": d.created_at, "lastUsedAt": d.last_used_at, "listed": d.listed_at.as_ref().is_some_and(super::sync::js_truthy)})
            })
            .collect();
        let pending = st
            .pending
            .as_ref()
            .filter(|p| now <= p.expires_at)
            .map(|p| json!({"vmId": p.vm_id, "expiresAt": iso(p.expires_at)}))
            .unwrap_or(Value::Null);
        json!({"origin": origin, "freeWindow": free, "pending": pending, "devices": list, "deviceCount": st.store.devices.len()})
    }
}

fn consume_jti(st: &mut State, jti: &str, exp: f64, now_ms: u64) -> bool {
    let now_s = now_ms as f64 / 1000.0;
    st.used_jti.retain(|_, e| *e >= now_s);
    if st.used_jti.contains_key(jti) {
        return false;
    }
    st.used_jti.insert(jti.to_string(), exp);
    true
}

/// The live devices the browser's cookie names, in the order it holds them: `(id, device, token)`.
fn live_devices(st: &State, cookie: Option<&str>, now: u64) -> Vec<(String, StoredDevice, String)> {
    let Some(raw) = cookie_value(cookie, DEV_COOKIE) else {
        return Vec::new();
    };
    let tokens: Vec<&str> = raw.split('.').collect();
    let keep = tokens.len().saturating_sub(DEVICES_PER_BROWSER);
    let mut out = Vec::new();
    for t in &tokens[keep..] {
        if !BINDING.is_match(t) {
            continue;
        }
        let hash = sha256_hex(t);
        let Some((id, d)) = st.store.devices.iter().find(|(_, d)| same_hash(&d.hash, &hash)) else {
            continue;
        };
        if parse_iso(&d.last_used_at) + DEVICE_TTL_MS < now as f64 {
            continue;
        }
        out.push((id.clone(), d.clone(), t.to_string()));
    }
    out
}

/// The browser's device for this user (a second member on the same browser enrolls separately).
fn enrolled(st: &State, cookie: Option<&str>, user_id: &str, now: u64) -> Option<(String, StoredDevice)> {
    live_devices(st, cookie, now)
        .into_iter()
        .find(|d| d.1.user_id == user_id)
        .map(|d| (d.0, d.1))
}

fn prune(store: &mut AccessStore, now: u64) {
    store
        .devices
        .retain(|_, d| parse_iso(&d.last_used_at) + DEVICE_TTL_MS >= now as f64 || parse_iso(&d.last_used_at).is_nan());
    if store.devices.len() <= MAX_DEVICES {
        return;
    }
    let mut all: Vec<(String, f64)> = store
        .devices
        .iter()
        .map(|(k, d)| (k.clone(), parse_iso(&d.last_used_at)))
        .collect();
    all.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let drop = all.len() - MAX_DEVICES;
    for (k, _) in all.into_iter().take(drop) {
        store.devices.shift_remove(&k);
    }
}

/// The request facts of a hyper request, the body read up to the cap within 5 s.
pub async fn access_request(req: cc_http::Req) -> AccessRequest {
    let (mut r, body) = access_request_read(req).await;
    r.body = body.ok();
    r
}

/// The request, and its body or why it could not be read: 413 over the cap, 400 slower than 5 s
/// or broken off. [`access_request`] keeps no reason (its routes answer one way for both).
pub async fn access_request_read(req: cc_http::Req) -> (AccessRequest, Result<Vec<u8>, u16>) {
    use http_body_util::BodyExt;
    let (parts, body) = req.into_parts();
    let h = |n: &str| cc_http::header(&parts, n).map(str::to_string);
    let declared: Option<usize> = h("content-length").and_then(|v| v.trim().parse().ok());
    let body = if declared.is_some_and(|d| d > ACCESS_BODY_BYTES) {
        Err(413)
    } else {
        let read = http_body_util::Limited::new(body, ACCESS_BODY_BYTES).collect();
        match tokio::time::timeout(std::time::Duration::from_secs(5), read).await {
            Ok(Ok(b)) => Ok(b.to_bytes().to_vec()),
            Ok(Err(e)) if e.is::<http_body_util::LengthLimitError>() => Err(413),
            _ => Err(400),
        }
    };
    let r = AccessRequest {
        method: parts.method.to_string(),
        origin: h("origin"),
        cookie: h("cookie"),
        user_agent: h("user-agent").unwrap_or_default(),
        content_type: h("content-type").unwrap_or_default(),
        body: None,
    };
    (r, body)
}

#[cfg(test)]
mod tests;
