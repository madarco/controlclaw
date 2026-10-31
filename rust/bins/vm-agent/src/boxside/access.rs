//! The ControlClaw login shim under `/__cc/` (`routes/access.ts`). Caddy routes `/__cc/*` here
//! without the bearer gate and asks `/__cc/verify` before every request it proxies to OpenClaw.
//!
//! `/__cc/session` and `/__cc/view-session` take one kind of ticket: the org firewall's, signed with
//! the pinned firewall key, bound to this browser by a `__Host-cc_bind_<id>` cookie, and naming the
//! enrolled device, which the session carries so a revoke can end it. Every box and the console are
//! one site, so the Origin checks here are what keeps another box's page from spending this box's
//! cookies (docs/security-design.md).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use cc_http::{BodyBinding, Req, Resp, full};
use cc_origin::{OriginPolicy, Uncredentialed};
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use http::{HeaderValue, Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::access_state::{AccessState, now_ms};
use super::session::{self, SessionClaims, Sessions};
use super::shell::{self, NavState, ShellContext, escape_html, json_string};
use crate::app::App;

/// How long the login exchange waits for OpenClaw to mint a pairing link, in all.
const DASHBOARD_BUDGET_MS: u64 = 40_000;
/// Pause before the one retry.
const DASHBOARD_RETRY_WAIT_MS: u64 = 3_000;
/// Not worth starting an attempt with less than this left.
const DASHBOARD_MIN_ATTEMPT_MS: u64 = 5_000;

/// Where `/__cc/browser` sends you once the view cookie is set.
const NOVNC_URL: &str = "/__cc/novnc/vnc_lite.html?path=__cc/novnc/websockify&scale=1";

pub const BIND_COOKIE_PREFIX: &str = "__Host-cc_bind_";
const BIND_TTL_S: i64 = 15 * 60;
/// How many bindings a request is read for.
const BIND_READ_MAX: usize = 8;

const SANDBOX_SHELL: &str = "/mcp-app-sandbox";
const SANDBOX_TICKETS_PER_MINUTE: usize = 10;
const SANDBOX_DENIED: &str =
    "This widget can only be shown inside your agent's dashboard. Open the agent from your console and try again.";
const NOT_OWN_PAGE: &str = "This request did not come from your agent's own page.";

/// Why the firewall sent the browser back (`OPEN_ERRORS`), in the TS order.
pub const OPEN_ERRORS: &[(&str, &str)] = &[
    (
        "invalid",
        "This link is not valid any more. Open the agent from your ControlClaw console again.",
    ),
    (
        "used",
        "This link was already used. Open the agent from your ControlClaw console again.",
    ),
    (
        "stopped",
        "This agent is stopped by your organization's emergency stop.",
    ),
    (
        "busy",
        "Too many sign-ins in a short time. Wait a minute, then open the agent again.",
    ),
    (
        "unreachable",
        "This browser needs a code, and your firewall could not send one. Make sure the agent with your chat channel is running, then open the agent again.",
    ),
    (
        "code_expired",
        "That code expired or ran out of tries. Open the agent from your ControlClaw console again to get a new one.",
    ),
    (
        "no_firewall",
        "This agent cannot check your browser with its firewall yet. Open it again from your ControlClaw console.",
    ),
];

fn open_error(key: &str) -> &'static str {
    OPEN_ERRORS.iter().find(|e| e.0 == key).map(|e| e.1).unwrap_or_default()
}

/// The heading the sign-in page shows while it hands over to one of the box's pages.
const LOGIN_PAGE_TITLES: &[(&str, &str)] = &[
    ("files", "Opening files"),
    ("logs", "Opening logs"),
    ("whatsapp", "Opening WhatsApp"),
    ("meetings", "Opening meetings"),
    ("phone", "Opening call history"),
];

const CHANNEL_NAMES: &[(&str, &str)] = &[("telegram", "Telegram"), ("slack", "Slack"), ("whatsapp", "WhatsApp")];

const WHATSAPP_TEXT: &[(&str, &str)] = &[
    (
        "installing",
        "Setting up WhatsApp on this agent. The code appears here in a moment.",
    ),
    ("connected", "Linked. You can close this tab."),
    (
        "expired",
        "The code expired. Start the WhatsApp link again from your ControlClaw console.",
    ),
    (
        "failed",
        "The link did not work. Start it again from your ControlClaw console.",
    ),
    (
        "idle",
        "No WhatsApp link is waiting. Start one from your ControlClaw console.",
    ),
];

fn object(pairs: &[(&str, &str)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect(),
    )
}

/// The page texts, as the TS template literals have them; `${name}` is filled in by [`fill`].
mod text {
    pub const FORGET_GATEWAY_JS: &str = include_str!("pages/forget_gateway.js");
    pub const PAGE_CSS: &str = include_str!("pages/page.css");
    pub const LOGIN_HTML: &str = include_str!("pages/login.html");
    pub const LOGIN_JS: &str = include_str!("pages/login.js");
    pub const DENIED: &str = include_str!("pages/denied.html");
    pub const DENIED_VIEW: &str = include_str!("pages/denied_view.html");
    pub const DENIED_FILES: &str = include_str!("pages/denied_files.html");
    pub const DENIED_WHATSAPP: &str = include_str!("pages/denied_whatsapp.html");
    pub const DENIED_PHONE: &str = include_str!("pages/denied_phone.html");
    pub const DENIED_MEETINGS: &str = include_str!("pages/denied_meetings.html");
    pub const DENIED_LOGS: &str = include_str!("pages/denied_logs.html");
    pub const BROWSER_HTML: &str = include_str!("pages/browser.html");
    pub const BROWSER_JS: &str = include_str!("pages/browser.js");
    pub const OPEN_HTML: &str = include_str!("pages/open.html");
    pub const OPEN_JS: &str = include_str!("pages/open.js");
    pub const MINUS_SVG: &str = include_str!("pages/minus.svg");
    pub const CODE_BOXES_JS: &str = include_str!("pages/code_boxes.js");
    pub const ENROLL_NONE: &str = include_str!("pages/enroll_none.html");
    pub const ENROLL_HTML: &str = include_str!("pages/enroll.html");
    pub const ENROLL_JS: &str = include_str!("pages/enroll.js");
    pub const WHATSAPP_HTML: &str = include_str!("pages/whatsapp.html");
    pub const WHATSAPP_JS: &str = include_str!("pages/whatsapp.js");
}

/// Put each `${name}` of `template` in one pass, so a value is never read as a placeholder.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        match after.find('}').and_then(|j| {
            let name = &after[..j];
            values.iter().find(|(k, _)| *k == name).map(|(_, v)| (j, *v))
        }) {
            Some((j, v)) => {
                out.push_str(v);
                rest = &after[j + 1..];
            }
            None => {
                out.push_str("${");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// What one `openclaw dashboard --json` run gave (`DashboardAttempt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardAttempt {
    Url(String),
    Failed { reason: String, retryable: bool },
}

/// How the CLI ended, as `execFile` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliEnd {
    /// Exit 0.
    Ok,
    /// `ENOENT`: not installed.
    NotFound,
    /// Killed by our timeout.
    Killed,
    /// Any other error; the text is `err.message`'s first line.
    Failed(String),
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// `parseDashboardOutput`: the CLI's output as a bootstrap link rebased onto the public origin.
/// Stdout is read whatever the exit code: OpenClaw's `{"ok":false,"reason":…}` is the only record
/// of why a browser was not paired.
pub fn parse_dashboard_output(stdout: &str, hostname: &str, end: &CliEnd) -> DashboardAttempt {
    let fail = |reason: &str, retryable: bool| DashboardAttempt::Failed {
        reason: reason.to_string(),
        retryable,
    };
    let out: Option<Value> = if stdout.trim().is_empty() {
        None
    } else {
        serde_json::from_str(stdout).ok()
    };
    let field = |k: &str| out.as_ref().and_then(|o| o.as_object()).and_then(|o| o.get(k)).cloned();
    if let Some(url) = field("browserUrl").filter(truthy) {
        if let Some(link) = url.as_str().and_then(|u| rebase_bootstrap(u, hostname)) {
            return DashboardAttempt::Url(link);
        }
        return fail("the pairing link had no bootstrap token", false);
    }
    match end {
        CliEnd::NotFound => return fail("the OpenClaw CLI is not installed", false),
        CliEnd::Killed => return fail("the OpenClaw CLI did not answer in time", true),
        _ => {}
    }
    if field("ok") == Some(Value::Bool(false)) {
        let reason = field("reason")
            .filter(truthy)
            .map(|r| match r {
                Value::String(s) => s,
                other => other.to_string(),
            })
            .unwrap_or_else(|| "OpenClaw could not issue a pairing link".into());
        return fail(&reason, true);
    }
    match end {
        CliEnd::Failed(m) => fail(&format!("the OpenClaw CLI failed: {m}"), false),
        _ => fail("the OpenClaw CLI printed nothing usable", false),
    }
}

/// `/#<the link's fragment with gatewayUrl=wss://<hostname>>`, or `None` without a bootstrap token.
fn rebase_bootstrap(browser_url: &str, hostname: &str) -> Option<String> {
    let url = url::Url::parse(browser_url).ok()?;
    let hash = url.fragment().unwrap_or_default();
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(hash.as_bytes()).into_owned().collect();
    // `params.get` is the first one: an empty first one is no token.
    if pairs
        .iter()
        .find(|(k, _)| k == "bootstrapToken")
        .is_none_or(|(_, v)| v.is_empty())
    {
        return None;
    }
    // `URLSearchParams.set`: the first one takes the value, the others go.
    let gw = format!("wss://{hostname}");
    match pairs.iter().position(|(k, _)| k == "gatewayUrl") {
        Some(i) => {
            pairs[i].1 = gw;
            let mut seen = 0;
            pairs.retain(|(k, _)| {
                if k == "gatewayUrl" {
                    seen += 1;
                    seen == 1
                } else {
                    true
                }
            });
        }
        None => pairs.push(("gatewayUrl".into(), gw)),
    }
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &pairs {
        ser.append_pair(k, v);
    }
    Some(format!("/#{}", ser.finish()))
}

/// `installId`: a short hash of the gateway token, which is made once per box.
pub fn install_id(gateway_token: Option<&str>, vm_id: &str) -> String {
    hex::encode(Sha256::digest(gateway_token.unwrap_or(vm_id).as_bytes()))[..16].to_string()
}

/// Whether two origins are one site: the same last two labels of the hostname (`sameSite`).
pub fn same_site(a: Option<&str>, b: Option<&str>) -> bool {
    let site = |o: Option<&str>| -> Option<String> {
        let u = url::Url::parse(o?).ok()?;
        let host = u.host_str()?.to_string();
        let labels: Vec<&str> = host.split('.').collect();
        Some(labels[labels.len().saturating_sub(2)..].join("."))
    };
    let x = site(a);
    x.is_some() && x == site(b)
}

/// `sandboxReturn`: the sandbox shell with its query, unchanged, and nothing else.
pub fn sandbox_return(value: Option<&str>) -> Option<String> {
    let value = value.filter(|v| !v.is_empty())?;
    if value.encode_utf16().count() > 4000 {
        return None;
    }
    let base = url::Url::parse("https://sandbox.invalid").ok()?;
    let u = base.join(value).ok()?;
    if u.origin().ascii_serialization() != "https://sandbox.invalid" || u.path() != SANDBOX_SHELL {
        return None;
    }
    let search = u
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    Some(format!("{}{search}", u.path()))
}

fn binding_hash(value: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn is_43(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The bind cookies a request carries, the last eight (`bindings`).
fn bindings(cookie_header: Option<&str>) -> Vec<(String, String)> {
    let Some(h) = cookie_header.filter(|h| !h.is_empty()) else {
        return Vec::new();
    };
    let out: Vec<(String, String)> = h
        .split(';')
        .filter_map(|part| {
            let i = part.find('=')?;
            let name = part[..i].trim();
            let value = part[i + 1..].trim();
            (name.starts_with(BIND_COOKIE_PREFIX) && is_43(value)).then(|| (name.to_string(), value.to_string()))
        })
        .collect();
    let skip = out.len().saturating_sub(BIND_READ_MAX);
    out.into_iter().skip(skip).collect()
}

fn bind_cookie(name: &str, value: Option<&str>) -> String {
    match value {
        Some(v) => format!("{name}={v}; Path=/; Max-Age={BIND_TTL_S}; HttpOnly; Secure; SameSite=Lax"),
        None => format!("{name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
    }
}

fn random_b64url(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

// ---- Responses ----

fn with_headers(mut r: Resp, headers: &[(&str, String)]) -> Resp {
    for (k, v) in headers {
        match (http::HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            (Ok(name), Ok(value)) if name == http::header::SET_COOKIE => {
                r.headers_mut().append(name, value);
            }
            (Ok(name), Ok(value)) => {
                r.headers_mut().insert(name, value);
            }
            // Node throws ERR_INVALID_CHAR there; an answer without its Location or cookie would
            // fail without a word, so it is a 500.
            _ => {
                tracing::error!("[access] refused to send a {k} header with characters HTTP does not allow");
                return cc_http::send_json(500, &json!({"error": "Internal error"}));
            }
        }
    }
    r
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// `html()`: no-store, never framed.
pub fn html(code: u16, body: String, extra: &[(&str, String)]) -> Resp {
    let r = full(status(code), "text/html; charset=utf-8", body);
    let r = with_headers(
        r,
        &[("cache-control", "no-store".into()), ("x-frame-options", "DENY".into())],
    );
    with_headers(r, extra)
}

/// `json()` in access.ts: no-store.
fn json_resp(code: u16, body: &Value, extra: &[(&str, String)]) -> Resp {
    with_headers(cc_http::send_json(code, body), extra)
}

fn empty_ok() -> Resp {
    with_headers(
        full(StatusCode::OK, "", bytes::Bytes::new()),
        &[("cache-control", "no-store".into())],
    )
}

fn redirect(code: u16, location: &str, extra: &[(&str, String)]) -> Resp {
    let r = full(status(code), "", bytes::Bytes::new());
    let r = with_headers(
        r,
        &[("location", location.into()), ("cache-control", "no-store".into())],
    );
    with_headers(r, extra)
}

type Landing = Arc<dyn Fn() -> BoxFuture<'static, Result<String, String>> + Send + Sync>;

/// How a box that is not an agent uses this shim (`AccessOptions`): the brain serves the login
/// exchange and nothing else, lands on GBrain's admin page, and lets in only a writer.
#[derive(Clone, Default)]
pub struct AccessOptions {
    /// Every other path is a 404.
    pub only: Option<&'static [&'static str]>,
    /// A ticket without `canWrite` is refused with this message.
    pub require_write: Option<String>,
    /// Where the browser goes once the session is set: `Ok(next)` or `Err(message)` (a 502).
    pub landing: Option<Landing>,
    /// The two steps the login page shows after "Checking your ControlClaw pass".
    pub steps: Option<(String, String)>,
}

type DashboardFuture = Shared<BoxFuture<'static, DashboardAttempt>>;
type DashboardRun = Arc<dyn Fn(String, Duration) -> BoxFuture<'static, DashboardAttempt> + Send + Sync>;

pub struct Access {
    app: Arc<App>,
    pub sessions: Arc<Sessions>,
    pub state: Arc<AccessState>,
    /// `setConsolePage`: a brain box's "Back to console" goes to `/dashboard/brain`.
    console_page: Option<String>,
    /// `allowedOrigins`, read once: they only change when cc-reprovision restarts the agent.
    origins: OnceLock<(Option<String>, Option<String>)>,
    /// The `openclaw dashboard` run in flight, per hostname (`dashboardInFlight`).
    /// With an id per run, so a run only ever removes its own entry.
    dashboard: Arc<Mutex<HashMap<String, (u64, DashboardFuture)>>>,
    dashboard_runs: std::sync::atomic::AtomicU64,
    dashboard_run: Mutex<Option<DashboardRun>>,
    dashboard_budget: Mutex<(u64, u64)>,
    sandbox_tickets: Mutex<HashMap<String, Vec<i64>>>,
    /// The log page's reads (`logs.rs`), set by `register`; without it the log routes are a 404.
    pub logs: OnceLock<Arc<super::logs::Logs>>,
}

impl Access {
    pub fn new(app: &Arc<App>, sessions: Arc<Sessions>, state: Arc<AccessState>, console_page: Option<String>) -> Self {
        Self {
            app: app.clone(),
            sessions,
            state,
            console_page,
            origins: OnceLock::new(),
            dashboard: Arc::new(Mutex::new(HashMap::new())),
            dashboard_runs: std::sync::atomic::AtomicU64::new(0),
            dashboard_run: Mutex::new(None),
            dashboard_budget: Mutex::new((DASHBOARD_BUDGET_MS, DASHBOARD_RETRY_WAIT_MS)),
            sandbox_tickets: Mutex::new(HashMap::new()),
            logs: OnceLock::new(),
        }
    }

    /// `readKey`: trimmed, and an empty file is none.
    fn read_key(&self, name: &str) -> Option<String> {
        self.app.keys.read(name).filter(|s| !s.is_empty())
    }

    /// `allowedOrigins`: this box's own origin and the console's (the config API's origin).
    pub fn allowed_origins(&self) -> (Option<String>, Option<String>) {
        self.origins
            .get_or_init(|| {
                let box_origin = self.read_key("vm_hostname").map(|h| format!("https://{h}"));
                let console = self
                    .read_key("config_api_url")
                    .and_then(|u| url::Url::parse(&u).ok())
                    .map(|u| u.origin().ascii_serialization())
                    .filter(|o| o != "null");
                if box_origin.is_none() {
                    tracing::error!("[access] no vm_hostname in KEYS_DIR: this box cannot recognise its own Origin");
                }
                (box_origin, console)
            })
            .clone()
    }

    fn own_origins(&self) -> Vec<Option<String>> {
        vec![
            self.allowed_origins().0,
            self.read_key("access_hostname").map(|h| format!("https://{h}")),
        ]
    }

    fn agent_policy(&self) -> OriginPolicy {
        OriginPolicy {
            allowed: self.own_origins(),
            allow_top_level_navigation: true,
            uncredentialed: Uncredentialed::Allow,
        }
    }

    fn exchange_policy(&self) -> OriginPolicy {
        OriginPolicy {
            allowed: self.own_origins(),
            allow_top_level_navigation: false,
            uncredentialed: Uncredentialed::Check,
        }
    }

    fn logout_policy(&self) -> OriginPolicy {
        let (box_origin, console) = self.allowed_origins();
        let mut allowed = self.own_origins();
        allowed.push(box_origin);
        allowed.push(console);
        OriginPolicy {
            allowed,
            allow_top_level_navigation: false,
            uncredentialed: Uncredentialed::Check,
        }
    }

    /// `originAllowed`: true when the request may proceed; a refusal is logged.
    pub fn origin_allowed(&self, parts: &http::request::Parts, policy: &OriginPolicy, label: &str) -> bool {
        let facts = cc_origin::agent_request_facts(parts.method.as_str(), &parts.headers, None);
        match cc_origin::check_origin(&facts, policy) {
            cc_origin::OriginVerdict::Ok => true,
            cc_origin::OriginVerdict::Denied { reason, origin } => {
                tracing::warn!(
                    "[access] {label}: {}",
                    cc_origin::denial_message(reason, origin.as_deref())
                );
                false
            }
        }
    }

    /// The box's name and its page in the console, for the shared header (`shellContext`).
    pub fn shell_context(&self) -> ShellContext {
        let origin = self.allowed_origins().1;
        let vm_id = self.read_key("vm_id").unwrap_or_default();
        ShellContext {
            hostname: self.read_key("vm_hostname"),
            console_url: match &self.console_page {
                Some(p) => format!("{}{p}", origin.as_deref().unwrap_or("https://controlclaw.com")),
                None => shell::console_agent_url(origin.as_deref(), &vm_id),
            },
            doctor_url: match &self.console_page {
                Some(_) => None,
                None => Some(shell::console_doctor_url(origin.as_deref(), &vm_id)),
            },
        }
    }

    pub fn nav(&self) -> NavState {
        NavState::current(&self.app.contracts)
    }

    fn page(&self, title: &str, body: &str, script: &str) -> String {
        shell::shell_bare_page(
            &self.shell_context(),
            title,
            &format!(r#"{body}<div class="foot">Secured by ControlClaw</div>"#),
            text::PAGE_CSS,
            script,
        )
    }

    fn denied(&self, title: &str, template: &str) -> String {
        let url = escape_html(&self.shell_context().console_url);
        self.page(title, &fill(template, &[("consoleUrl", &url)]), "")
    }

    pub fn denied_page(&self) -> String {
        self.denied("This agent is private", text::DENIED)
    }
    pub fn denied_view_page(&self) -> String {
        self.denied("This browser is private", text::DENIED_VIEW)
    }
    pub fn denied_files_page(&self) -> String {
        self.denied("These files are private", text::DENIED_FILES)
    }
    pub fn denied_whatsapp_page(&self) -> String {
        self.denied("This code is private", text::DENIED_WHATSAPP)
    }
    /// The call history's refusal, for W8's calls pages (`DENIED_PHONE_PAGE`).
    pub fn denied_phone_page(&self) -> String {
        self.denied("These calls are private", text::DENIED_PHONE)
    }
    /// The meetings pages' refusal, for W8 (`DENIED_MEETINGS_PAGE`).
    pub fn denied_meetings_page(&self) -> String {
        self.denied("These meetings are private", text::DENIED_MEETINGS)
    }
    /// The log page's refusal (B2, `logs-page.ts`).
    pub fn denied_logs_page(&self) -> String {
        self.denied("This log is private", text::DENIED_LOGS)
    }

    fn names(&self) -> (String, String) {
        let hostname = self.read_key("vm_hostname");
        match hostname {
            Some(h) => (escape_html(h.split('.').next().unwrap_or_default()), escape_html(&h)),
            None => ("your agent".into(), String::new()),
        }
    }

    fn login_page(&self, steps: &(String, String)) -> String {
        let (agent, host) = self.names();
        let url = escape_html(&self.shell_context().console_url);
        let body = fill(
            text::LOGIN_HTML,
            &[
                ("agent", &agent),
                ("host", &host),
                ("step0", &escape_html(&steps.0)),
                ("step1", &escape_html(&steps.1)),
                ("consoleUrl", &url),
            ],
        );
        let script = fill(
            text::LOGIN_JS,
            &[
                ("FORGET_PREVIOUS_GATEWAY_JS", text::FORGET_GATEWAY_JS),
                ("LOGIN_PAGE_TITLES", &json_string(&object(LOGIN_PAGE_TITLES))),
            ],
        );
        self.page(&format!("Opening {agent}…"), &body, &script)
    }

    fn browser_page(&self) -> String {
        let (agent, host) = self.names();
        let body = fill(text::BROWSER_HTML, &[("host", &host)]);
        let script = fill(text::BROWSER_JS, &[("NOVNC_URL", &json_string(&json!(NOVNC_URL)))]);
        self.page(&format!("Connecting to {agent}…"), &body, &script)
    }

    fn open_page(&self) -> String {
        let (agent, host) = self.names();
        let url = escape_html(&self.shell_context().console_url);
        let body = fill(
            text::OPEN_HTML,
            &[("agent", &agent), ("host", &host), ("consoleUrl", &url)],
        );
        let script = fill(text::OPEN_JS, &[("OPEN_ERRORS", &json_string(&object(OPEN_ERRORS)))]);
        self.page(&format!("Opening {agent}…"), &body, &script)
    }

    fn enroll_page(&self, firewall: Option<&str>) -> String {
        let (agent, host) = self.names();
        let url = escape_html(&self.shell_context().console_url);
        let Some(firewall) = firewall else {
            let body = fill(
                text::ENROLL_NONE,
                &[
                    ("host", &host),
                    ("no_firewall", &escape_html(open_error("no_firewall"))),
                    ("consoleUrl", &url),
                ],
            );
            return self.page("Could not open the agent", &body, "");
        };
        let code_box = |i: usize| {
            format!(
                r#"<input id="d{i}" inputmode="numeric" {} aria-label="Digit {} of 6">"#,
                if i == 0 {
                    r#"autocomplete="one-time-code""#
                } else {
                    r#"autocomplete="off""#
                },
                i + 1
            )
        };
        let boxes = |r: std::ops::Range<usize>| r.map(code_box).collect::<String>();
        let code_boxes = format!(
            r#"<div class="otp" id="otp" role="group" aria-label="6-digit code" hidden><div class="g">{}</div><div class="sep" role="separator">{}</div><div class="g">{}</div></div>"#,
            boxes(0..3),
            text::MINUS_SVG,
            boxes(3..6)
        );
        let body = fill(
            text::ENROLL_HTML,
            &[
                ("host", &host),
                ("agent", &agent),
                ("firewall", &escape_html(firewall)),
                ("CODE_BOXES", &code_boxes),
            ],
        );
        let script = fill(
            text::ENROLL_JS,
            &[
                ("CHANNEL_NAMES", &json_string(&object(CHANNEL_NAMES))),
                (
                    "LEAD_START",
                    &json_string(&json!(
                        "This browser has not opened your organization's agents before. We sent a 6-digit code to your "
                    )),
                ),
                (
                    "LEAD_END",
                    &json_string(&json!(format!(". Type it here to open {agent}."))),
                ),
                ("CODE_BOXES_JS", text::CODE_BOXES_JS),
            ],
        );
        self.page("Confirm this browser", &body, &script)
    }

    fn whatsapp_page(&self) -> String {
        let (agent, host) = self.names();
        let body = fill(text::WHATSAPP_HTML, &[("agent", &agent), ("host", &host)]);
        let script = fill(text::WHATSAPP_JS, &[("TEXT", &json_string(&object(WHATSAPP_TEXT)))]);
        // `withSidebar`: the same card, with the sidebar of the agent's pages.
        shell::shell_page(
            &self.shell_context(),
            "Link WhatsApp",
            Some("whatsapp"),
            &format!(r#"<div class="mx-auto max-w-[34rem] px-4 py-8 md:px-9">{body}</div><script>{script}</script>"#),
            &format!("<style>{}</style>", text::PAGE_CSS),
            self.nav(),
        )
    }

    // ---- Dashboard pairing link ----

    /// For tests: a stand-in for the CLI, and a shorter budget.
    #[cfg(test)]
    pub fn set_dashboard_run(&self, run: DashboardRun, budget_ms: u64, retry_wait_ms: u64) {
        if let Ok(mut r) = self.dashboard_run.lock() {
            *r = Some(run);
        }
        if let Ok(mut b) = self.dashboard_budget.lock() {
            *b = (budget_ms, retry_wait_ms);
        }
    }

    fn run_dashboard(&self) -> DashboardRun {
        if let Some(r) = self.dashboard_run.lock().ok().and_then(|r| r.clone()) {
            return r;
        }
        let runner = self.app.runner.clone();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into());
        Arc::new(move |hostname: String, timeout: Duration| {
            let runner = runner.clone();
            let home = home.clone();
            async move {
                let bin = std::env::var("OPENCLAW_BIN").unwrap_or_else(|_| "/usr/bin/openclaw".into());
                let cmd = cc_proc::Cmd::new(&bin)
                    .args(["dashboard", "--json", "--no-open"])
                    .env("HOME", home)
                    .timeout(timeout);
                match runner.run(cmd).await {
                    Ok(out) => {
                        let end = if out.timed_out {
                            CliEnd::Killed
                        } else if out.success() {
                            CliEnd::Ok
                        } else {
                            CliEnd::Failed(format!("Command failed: {bin} dashboard --json --no-open"))
                        };
                        parse_dashboard_output(&out.stdout_str(), &hostname, &end)
                    }
                    Err(cc_proc::RunError::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                        parse_dashboard_output("", &hostname, &CliEnd::NotFound)
                    }
                    Err(cc_proc::RunError::Spawn(e)) => {
                        parse_dashboard_output("", &hostname, &CliEnd::Failed(format!("spawn {bin} {e}")))
                    }
                }
            }
            .boxed()
        })
    }

    /// `dashboardBootstrapUrl`: one run at a time per hostname; the answer is a one-shot token, so
    /// only the run in flight is shared, never cached.
    pub async fn dashboard_bootstrap_url(&self, hostname: &str) -> DashboardAttempt {
        let fut = {
            let mut map = self.dashboard.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, f)) = map.get(hostname) {
                f.clone()
            } else {
                let id = self.dashboard_runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let run = self.run_dashboard();
                let (budget, wait) = self.dashboard_budget.lock().map(|b| *b).unwrap_or_default();
                let host = hostname.to_string();
                let inflight = self.dashboard.clone();
                // Forget this run, and only this run (the TS's `.finally`): a newer entry stays.
                let forget = move || {
                    let mut map = inflight.lock().unwrap_or_else(|e| e.into_inner());
                    if map.get(&host).is_some_and(|(i, _)| *i == id) {
                        map.remove(&host);
                    }
                };
                let host = hostname.to_string();
                // Its own task, so a browser that gives up does not stop the run the next one shares.
                let task = tokio::spawn({
                    let forget = forget.clone();
                    async move {
                        let r = dashboard_attempt(&host, run, budget, wait).await;
                        forget();
                        r
                    }
                });
                let f: DashboardFuture = async move {
                    task.await.unwrap_or_else(|_| {
                        // The run panicked: the next Open asks again.
                        forget();
                        DashboardAttempt::Failed {
                            reason: "no time left to ask OpenClaw".into(),
                            retryable: false,
                        }
                    })
                }
                .boxed()
                .shared();
                map.insert(hostname.to_string(), (id, f.clone()));
                f
            }
        };
        fut.await
    }

    // ---- The widget sandbox ----

    fn sandbox_host(&self) -> Option<String> {
        let b = self.allowed_origins().0?;
        let u = url::Url::parse(&b).ok()?;
        let host = u.host_str()?;
        Some(match u.port() {
            Some(p) => format!("sandbox.{host}:{p}"),
            None => format!("sandbox.{host}"),
        })
    }

    /// The dashboard that framed the widget, by its Referer: one of this box's own names, or none.
    fn sandbox_dashboard(&self, parts: &http::request::Parts) -> Option<String> {
        let origin = url::Url::parse(cc_http::header(parts, "referer").unwrap_or_default())
            .ok()?
            .origin()
            .ascii_serialization();
        self.own_origins().contains(&Some(origin.clone())).then_some(origin)
    }

    /// The loop guard: each frame of a dashboard gets at most ten tickets a minute.
    fn sandbox_ticket_allowed(&self, cookie_header: Option<&str>, back: &str, now: i64) -> bool {
        let session = cc_origin::read_unique_cookie(Some(cookie_header.unwrap_or_default()), session::SESSION_COOKIE)
            .value
            .unwrap_or_default();
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{session}\0{back}")));
        let mut map = self.sandbox_tickets.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, times| !times.iter().all(|t| now - t > 60_000));
        let recent: Vec<i64> = map
            .get(&key)
            .map(|v| v.iter().copied().filter(|t| now - t <= 60_000).collect())
            .unwrap_or_default();
        if recent.len() >= SANDBOX_TICKETS_PER_MINUTE {
            return false;
        }
        let mut recent = recent;
        recent.push(now);
        map.insert(key, recent);
        true
    }

    fn sandbox_deny(&self) -> Resp {
        let ancestors: Vec<String> = self
            .own_origins()
            .into_iter()
            .flatten()
            .filter(|o| !o.is_empty())
            .collect();
        let ancestors = if ancestors.is_empty() {
            "'none'".to_string()
        } else {
            ancestors.join(" ")
        };
        let r = full(
            StatusCode::FORBIDDEN,
            "text/html; charset=utf-8",
            format!(
                r#"<!doctype html><meta charset="utf-8"><title>Not available</title><p style="font:14px system-ui;margin:16px">{}</p>"#,
                escape_html(SANDBOX_DENIED)
            ),
        );
        with_headers(
            r,
            &[
                ("cache-control", "no-store".into()),
                (
                    "content-security-policy",
                    format!("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors {ancestors}"),
                ),
            ],
        )
    }

    fn handle_sandbox(&self, parts: &http::request::Parts, pathname: &str, vm_id: &str) -> Resp {
        let Some(host) = self.sandbox_host() else {
            return self.sandbox_deny();
        };
        if parts.method != Method::GET {
            return self.sandbox_deny();
        }
        let dest = cc_http::header(parts, "sec-fetch-dest");
        let on_sandbox_host = cc_http::header(parts, "x-forwarded-host")
            .or_else(|| cc_http::header(parts, "host"))
            .is_some_and(|h| h.to_lowercase() == host);
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let query = |name: &str| -> Option<String> {
            let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            url::Url::parse("http://localhost")
                .and_then(|b| b.join(target))
                .ok()?
                .query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };
        match pathname {
            "/__cc/sandbox/verify" => {
                if !on_sandbox_host || dest != Some("iframe") {
                    return self.sandbox_deny();
                }
                if self.sessions.verify_sandbox_session(cookie.as_deref(), vm_id) {
                    return empty_ok();
                }
                let back = sandbox_return(cc_http::header(parts, "x-forwarded-uri"));
                let dashboard = self.sandbox_dashboard(parts);
                match (back, dashboard) {
                    (Some(back), Some(dashboard)) => redirect(
                        302,
                        &format!(
                            "{dashboard}/__cc/sandbox/ticket?r={}",
                            shell::encode_uri_component(&back)
                        ),
                        &[],
                    ),
                    _ => self.sandbox_deny(),
                }
            }
            "/__cc/sandbox/ticket" => {
                let back = sandbox_return(query("r").as_deref());
                let Some(back) = back else {
                    return self.sandbox_deny();
                };
                if on_sandbox_host
                    || dest != Some("iframe")
                    || cc_http::header(parts, "sec-fetch-site") == Some("cross-site")
                    || self.sandbox_dashboard(parts).is_none()
                {
                    return self.sandbox_deny();
                }
                let Some(ticket) = self.sessions.issue_sandbox_ticket(cookie.as_deref(), vm_id) else {
                    return self.sandbox_deny();
                };
                if !self.sandbox_ticket_allowed(cookie.as_deref(), &back, now_ms()) {
                    return self.sandbox_deny();
                }
                redirect(
                    302,
                    &format!(
                        "https://{host}/__cc/sandbox/exchange?t={}&r={}",
                        shell::encode_uri_component(&ticket),
                        shell::encode_uri_component(&back)
                    ),
                    &[],
                )
            }
            "/__cc/sandbox/exchange" => {
                let Some(back) = sandbox_return(query("r").as_deref()) else {
                    return self.sandbox_deny();
                };
                if !on_sandbox_host || dest != Some("iframe") {
                    return self.sandbox_deny();
                }
                match self
                    .sessions
                    .redeem_sandbox_ticket(&query("t").unwrap_or_default(), vm_id)
                {
                    Some((token, max_age)) => {
                        redirect(302, &back, &[("set-cookie", session::sandbox_cookie(&token, max_age))])
                    }
                    None => self.sandbox_deny(),
                }
            }
            _ => self.sandbox_deny(),
        }
    }

    // ---- The exchange ----

    /// `acceptTicket`: the firewall's ticket, matched against a binding this browser holds.
    fn accept_ticket(
        &self,
        cookie: Option<&str>,
        token: &str,
        vm_id: &str,
        purpose: &str,
    ) -> Result<(cc_auth::ticket::FirewallTicket, String), &'static str> {
        const INVALID: &str = "This link is not valid for this agent. Open it from your ControlClaw console again.";
        if token.is_empty() {
            return Err(INVALID);
        }
        let key = self.app.firewall_auth.pinned_key().ok_or(INVALID)?;
        let fw = cc_auth::ticket::verify_firewall_ticket(token, &key, vm_id, purpose, None).ok_or(INVALID)?;
        let matched = bindings(cookie)
            .into_iter()
            .find(|(_, value)| cc_crypto::ct_eq(binding_hash(value).as_bytes(), fw.c.as_bytes()));
        match matched {
            Some((name, _)) => Ok((fw, bind_cookie(&name, None))),
            None => Err("This link was opened in a different browser. Open the agent again from this one."),
        }
    }

    async fn session_exchange(&self, req: Req, opts: &AccessOptions, vm_id: &str) -> Resp {
        let (parts, body) = req.into_parts();
        if !self.origin_allowed(&parts, &self.exchange_policy(), "/__cc/session") {
            return json_resp(403, &json!({"error": NOT_OWN_PAGE}), &[]);
        }
        let body = cc_http::read_json_body(body, 8192, &BodyBinding::not_firewall()).await;
        let token = body
            .as_ref()
            .and_then(|b| b.get("token"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let (ticket, spent) = match self.accept_ticket(cookie.as_deref(), &token, vm_id, "browser-login") {
            Ok(t) => t,
            Err(e) => return json_resp(401, &json!({"error": e}), &[]),
        };
        // Rust only: once the ticket is accepted, every answer clears its spent bind cookie,
        // refusals and failures too. The TS cleared it only on success, so each such failed Open (a
        // brain still starting, a member's ticket, a used link) left one in the browser until it
        // expired. A ticket refused before this (expired, another browser) still leaves it.
        let clear = [("set-cookie", spent.clone())];
        if !self.sessions.consume_jti(&ticket.jti, ticket.exp) {
            return json_resp(
                401,
                &json!({"error": "This link was already used. Open the agent from your ControlClaw console again."}),
                &clear,
            );
        }
        let claims = SessionClaims {
            can_write: ticket.can_write,
            device_id: Some(ticket.device_id.clone()),
        };
        tracing::info!(
            "[access] sign-in with the firewall's ticket (browser {})",
            ticket.device_id
        );
        if let Some(msg) = &opts.require_write
            && !ticket.can_write
        {
            return json_resp(403, &json!({"error": msg}), &clear);
        }
        let issue = |claims: &SessionClaims| self.sessions.issue_session(vm_id, claims);
        let cookies = |session: String| -> Vec<(&'static str, String)> {
            vec![
                ("set-cookie", session::session_cookie(&session)),
                ("set-cookie", spent.clone()),
            ]
        };
        if let Some(landing) = &opts.landing {
            return match landing().await {
                Err(e) => json_resp(502, &json!({"error": e}), &clear),
                Ok(next) => match issue(&claims) {
                    Some(s) => json_resp(
                        200,
                        &json!({"next": next, "view": "direct", "paired": true}),
                        &cookies(s),
                    ),
                    None => session_failed(&clear),
                },
            };
        }
        // The file explorer and the log need the session and nothing from OpenClaw.
        if let Some(page) = ticket.next.as_deref().filter(|p| shell::is_login_page(p)) {
            let landing = shell::login_landing(page).unwrap_or("/");
            return match issue(&claims) {
                Some(s) => json_resp(
                    200,
                    &json!({"next": landing, "view": page, "paired": true}),
                    &cookies(s),
                ),
                None => session_failed(&clear),
            };
        }
        // Keep OpenClaw's browser WebSocket on the origin the exchange was checked against.
        let exchange_origin = cc_origin::node_header(&parts.headers, "origin");
        let hostname = match exchange_origin {
            Some(o) if self.own_origins().contains(&Some(o.clone())) => {
                url::Url::parse(&o).ok().and_then(|u| u.host_str().map(str::to_string))
            }
            _ => self.read_key("vm_hostname"),
        };
        let mut next = "/".to_string();
        let mut paired = false;
        let pair_error: Option<String>;
        match &hostname {
            Some(h) => match self.dashboard_bootstrap_url(h).await {
                DashboardAttempt::Url(u) => {
                    next = u;
                    paired = true;
                    pair_error = None;
                }
                DashboardAttempt::Failed { reason, .. } => pair_error = Some(reason),
            },
            None => pair_error = Some("this box does not know its own hostname".into()),
        }
        if !paired && let Some(t) = self.read_key("openclaw_gateway_token") {
            next = format!("/#token={}", shell::encode_uri_component(&t));
        }
        let Some(s) = issue(&claims) else {
            return session_failed(&clear);
        };
        let install = install_id(self.read_key("openclaw_gateway_token").as_deref(), vm_id);
        json_resp(
            200,
            &json!({"next": next, "install": install, "paired": paired, "pairError": pair_error}),
            &cookies(s),
        )
    }

    async fn view_exchange(&self, req: Req, vm_id: &str) -> Resp {
        let (parts, body) = req.into_parts();
        if !self.origin_allowed(&parts, &self.exchange_policy(), "/__cc/view-session") {
            return json_resp(403, &json!({"error": NOT_OWN_PAGE}), &[]);
        }
        let body = cc_http::read_json_body(body, 8192, &BodyBinding::not_firewall()).await;
        let token = body
            .as_ref()
            .and_then(|b| b.get("token"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let (ticket, spent) = match self.accept_ticket(cookie.as_deref(), &token, vm_id, "browser-view") {
            Ok(t) => t,
            Err(e) => {
                let e = e.replacen(
                    "Open it from your ControlClaw console again.",
                    "Open the browser from your ControlClaw console again.",
                    1,
                );
                return json_resp(401, &json!({"error": e}), &[]);
            }
        };
        let clear = [("set-cookie", spent.clone())];
        if !self.sessions.consume_jti(&ticket.jti, ticket.exp) {
            return json_resp(
                401,
                &json!({"error": "This link was already used. Press Screen again in your ControlClaw console."}),
                &clear,
            );
        }
        match self.sessions.issue_view_session(vm_id, Some(&ticket.device_id)) {
            Some(v) => json_resp(
                200,
                &json!({"ok": true}),
                &[("set-cookie", session::view_session_cookie(&v)), ("set-cookie", spent)],
            ),
            None => session_failed(&clear),
        }
    }

    fn whatsapp(&self, parts: &http::request::Parts, pathname: &str, vm_id: &str) -> Resp {
        let headers = [
            ("cache-control", "no-store".to_string()),
            ("referrer-policy", "no-referrer".to_string()),
        ];
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let session = self.sessions.read_session(cookie.as_deref(), vm_id);
        let page = pathname == "/__cc/whatsapp";
        if !page && !self.origin_allowed(parts, &self.exchange_policy(), "/__cc/whatsapp/qr") {
            return json_resp(403, &json!({"error": NOT_OWN_PAGE}), &headers);
        }
        if !session.is_some_and(|s| s.can_write) {
            return if page {
                html(401, self.denied_whatsapp_page(), &headers)
            } else {
                json_resp(
                    401,
                    &json!({"error": "Only an owner or admin who opened this agent can see the WhatsApp code."}),
                    &headers,
                )
            };
        }
        if page {
            return html(200, self.whatsapp_page(), &headers);
        }
        let login = self.app.contracts.whatsapp.get().and_then(|w| w.whatsapp_login());
        let body = match login {
            Some(l) => json!({"state": l.state, "qrDataUrl": l.qr_data_url, "message": l.message}),
            None => json!({"state": "idle", "qrDataUrl": null, "message": null}),
        };
        json_resp(200, &body, &headers)
    }

    /// `serveFilesPage`: the file explorer, for a browser holding this box's session.
    fn files_page(&self, parts: &http::request::Parts, vm_id: &str) -> Resp {
        let headers = [
            ("cache-control", "no-store".to_string()),
            ("x-frame-options", "DENY".to_string()),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".to_string(),
            ),
        ];
        let page =
            |code: u16, body: String| with_headers(full(status(code), "text/html; charset=utf-8", body), &headers);
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let Some(session) = self.sessions.read_session(cookie.as_deref(), vm_id) else {
            return page(401, self.denied_files_page());
        };
        let ctx = self.shell_context();
        let agent_name = shell::agent_name_of(ctx.hostname.as_deref());
        let data = json!({"canWrite": session.can_write, "agentName": agent_name, "consoleUrl": ctx.console_url});
        page(
            200,
            shell::shell_page(
                &ctx,
                &format!("{agent_name} · files"),
                Some("files"),
                &format!(
                    r#"<div id="root"></div><script id="cc-files" type="application/json">{}</script><script type="module" src="/__cc/files-ui/app.js"></script>"#,
                    shell::inline_json(&data)
                ),
                r#"<link rel="stylesheet" href="/__cc/files-ui/app.css">"#,
                self.nav(),
            ),
        )
    }

    /// `handleAccess`: every `/__cc/*` this shim serves.
    pub async fn handle(&self, req: Req, opts: &AccessOptions) -> Resp {
        let pathname = cc_http::pathname(&req.uri().to_string());
        let Some(vm_id) = self.read_key("vm_id") else {
            return json_resp(500, &json!({"error": "Box has no vm_id"}), &[]);
        };
        let method = req.method().clone();
        // Agent boxes only: a box with a route allow-list (the brain) has no OpenClaw widgets.
        if opts.only.is_none() && pathname.starts_with("/__cc/sandbox/") {
            let (parts, _) = req.into_parts();
            return self.handle_sandbox(&parts, &pathname, &vm_id);
        }
        if pathname == "/__cc/shell.js" && method == Method::GET {
            return with_headers(
                full(StatusCode::OK, "text/javascript; charset=utf-8", shell::SHELL_JS),
                &[
                    ("cache-control", "no-cache".into()),
                    ("x-content-type-options", "nosniff".into()),
                ],
            );
        }
        if let Some(name) = pathname.strip_prefix("/__cc/files-ui/")
            && method == Method::GET
        {
            return serve_files_asset(name).await;
        }
        if let Some(only) = opts.only
            && !only.contains(&pathname.as_str())
        {
            return json_resp(404, &json!({"error": "Not found"}), &[]);
        }
        // Doctor's pages are the firewall's; asked here, the browser goes to the console.
        if shell::is_doctor_path(&pathname)
            && (method == Method::GET || method == Method::HEAD)
            && let Some(target) = self.shell_context().doctor_url
        {
            return redirect(303, &target, &[]);
        }
        let (parts, body) = req.into_parts();
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        match (method.as_str(), pathname.as_str()) {
            ("GET", "/__cc/login") => {
                let default = (
                    "Pairing this browser with the agent".to_string(),
                    "Loading OpenClaw".to_string(),
                );
                html(200, self.login_page(opts.steps.as_ref().unwrap_or(&default)), &[])
            }
            ("GET", "/__cc/open") => html(200, self.open_page(), &[]),
            ("POST", "/__cc/open/begin") => {
                if !self.origin_allowed(&parts, &self.exchange_policy(), "/__cc/open/begin") {
                    return json_resp(403, &json!({"error": NOT_OWN_PAGE}), &[]);
                }
                let Some(firewall) = self.state.firewall_origin() else {
                    return json_resp(409, &json!({"error": open_error("no_firewall")}), &[]);
                };
                let value = random_b64url(32);
                let name = format!("{BIND_COOKIE_PREFIX}{}", random_b64url(6));
                json_resp(
                    200,
                    &json!({"c": binding_hash(&value), "firewall": firewall}),
                    &[("set-cookie", bind_cookie(&name, Some(&value)))],
                )
            }
            ("GET", "/__cc/enroll") => html(200, self.enroll_page(self.state.firewall_origin().as_deref()), &[]),
            ("GET", "/__cc/verify") => {
                if self.origin_allowed(&parts, &self.agent_policy(), "/__cc/verify")
                    && self.sessions.verify_session(cookie.as_deref(), &vm_id)
                {
                    empty_ok()
                } else {
                    html(401, self.denied_page(), &[])
                }
            }
            ("POST", "/__cc/session") => {
                self.session_exchange(http::Request::from_parts(parts, body), opts, &vm_id)
                    .await
            }
            ("GET", "/__cc/browser") => html(200, self.browser_page(), &[]),
            ("POST", "/__cc/view-session") => self.view_exchange(http::Request::from_parts(parts, body), &vm_id).await,
            ("GET", "/__cc/verify-view") => {
                // VIEW_POLICY is AGENT_POLICY's twin: own origins, top-level navigation allowed.
                if self.origin_allowed(&parts, &self.agent_policy(), "/__cc/verify-view")
                    && (self.sessions.verify_view_session(cookie.as_deref(), &vm_id)
                        || self.sessions.verify_session(cookie.as_deref(), &vm_id))
                {
                    empty_ok()
                } else {
                    html(401, self.denied_view_page(), &[])
                }
            }
            ("GET", "/__cc/files") => self.files_page(&parts, &vm_id),
            ("GET", "/__cc/whatsapp") | ("GET", "/__cc/whatsapp/qr") => self.whatsapp(&parts, &pathname, &vm_id),
            ("GET", "/__cc/logs") if self.logs.get().is_some() => super::logs::page::serve_page(self, &parts, &vm_id),
            ("GET", "/__cc/logs/snapshot") | ("GET", "/__cc/logs/stream") if self.logs.get().is_some() => {
                match self.logs.get() {
                    Some(l) => super::logs::page::serve_data(self, l, &parts, &pathname, &vm_id).await,
                    None => json_resp(404, &json!({"error": "Not found"}), &[]),
                }
            }
            ("POST", "/__cc/logout") => {
                if !self.origin_allowed(&parts, &self.logout_policy(), "/__cc/logout") {
                    return json_resp(403, &json!({"error": NOT_OWN_PAGE}), &[]);
                }
                json_resp(
                    200,
                    &json!({"ok": true}),
                    &[
                        ("set-cookie", session::clear_session_cookie()),
                        ("set-cookie", session::clear_view_session_cookie()),
                    ],
                )
            }
            _ => json_resp(404, &json!({"error": "Not found"}), &[]),
        }
    }
}

/// The secret was missing: the TS throws from `issueSession`, which the server answers with a 500.
fn session_failed(headers: &[(&str, String)]) -> Resp {
    json_resp(500, &json!({"error": "session secret not initialised"}), headers)
}

async fn dashboard_attempt(hostname: &str, run: DashboardRun, budget_ms: u64, retry_wait_ms: u64) -> DashboardAttempt {
    let deadline = std::time::Instant::now() + Duration::from_millis(budget_ms);
    let mut last = DashboardAttempt::Failed {
        reason: "no time left to ask OpenClaw".into(),
        retryable: false,
    };
    for attempt in 1..=2 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left < Duration::from_millis(DASHBOARD_MIN_ATTEMPT_MS) {
            break;
        }
        last = run(hostname.to_string(), left).await;
        let DashboardAttempt::Failed { reason, retryable } = &last else {
            return last;
        };
        tracing::error!("[access] openclaw dashboard failed (attempt {attempt}): {reason}");
        if !retryable || attempt == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(retry_wait_ms)).await;
    }
    last
}

/// Where the page bundle is: `FILES_UI_DIR`; else `files-ui/` next to the binary when there is
/// one; else the Node build's, which a switched box keeps installed
/// (`/opt/controlclaw/agent/dist/files-ui`, the role's `vm-agent.yml`).
fn ui_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("FILES_UI_DIR") {
        return d.into();
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join("files-ui")))
        .filter(|d| d.is_dir())
        .unwrap_or_else(|| "/opt/controlclaw/agent/dist/files-ui".into())
}

/// `serveFilesAsset`: a bundle file by name, nothing with a slash or a dot-dot in it.
pub async fn serve_files_asset(name: &str) -> Resp {
    let not_found = || full(StatusCode::NOT_FOUND, "text/plain", "Not found");
    let ext = name.rsplit_once('.');
    let ok = match ext {
        Some((stem, ext)) => {
            !stem.is_empty()
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && matches!(ext, "js" | "css" | "woff2")
        }
        None => false,
    };
    if !ok {
        return not_found();
    }
    let Ok(body) = tokio::fs::read(ui_dir().join(name)).await else {
        return not_found();
    };
    let ctype = match ext.map(|e| e.1) {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        _ => "font/woff2",
    };
    let cache = if name.starts_with("chunk-") || name.starts_with("asset-") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    with_headers(
        full(StatusCode::OK, ctype, body),
        &[
            ("cache-control", cache.into()),
            ("x-content-type-options", "nosniff".into()),
        ],
    )
}

#[cfg(test)]
mod tests;
