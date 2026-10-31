//! Channels on the agent box (`channels.ts`, `routes/channels.ts`). Everything goes through
//! OpenClaw's gateway over the agent's one socket, and its CLI where there is no gateway method:
//!
//! - apply: one `config.patch` with the channel block, in the background, with a record the
//!   firewall reads back when the call ends before the write (`lastApply`);
//! - send: gateway `send`, the text exactly as the firewall wrote it;
//! - approve: `openclaw pairing approve <channel> <code>`, recorded in `state/channels.json`;
//! - status: `channels.status`, the pending pairings (OpenClaw's own database first), install and
//!   apply progress;
//! - WhatsApp login: `web.login.start` / `web.login.wait`.
//!
//! Writes come only from the org firewall; reads from either side. `/channels/approved` is the
//! firewall's alone.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use cc_http::{FirewallBody, Router, send_json};
use cc_openclaw::config_queue::{PatchOptions, QueueOptions};
use futures_util::FutureExt;
use futures_util::future::Shared;
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::allow::{read_allow_list, read_pending};
use super::common::js_slice;
use super::common::{
    BODY_LIMIT, CONFIG_PATCH, CONFIG_PATCH_RESTART, Caller, Deps, GATEWAY_READ, at, caller, fail, lock, not_found,
    patch_restarts_gateway, text,
};
use super::time::{iso_ms, now_ms};
use crate::app::App;
use crate::stages;

pub const CHANNEL_TYPES: [&str; 3] = ["telegram", "slack", "whatsapp"];
/// The people's channels, plus Team chat (`clickclack`), which has no pairing.
pub const APPLY_CHANNELS: [&str; 4] = ["telegram", "slack", "whatsapp", "clickclack"];
pub const TEAMCHAT_GATE_PORT: u16 = 3930;
const MESSAGE_TEXT_MAX: usize = 4096;

/// Slack, WhatsApp and Team chat are external OpenClaw plugins; Telegram is built in.
fn plugin_of(t: &str) -> Option<&'static str> {
    match t {
        "slack" => Some("@openclaw/slack"),
        "whatsapp" => Some("@openclaw/whatsapp"),
        "clickclack" => Some("@openclaw/clickclack"),
        _ => None,
    }
}

const APPROVE_TIMEOUT: Duration = Duration::from_secs(45);
const LIST_TIMEOUT: Duration = Duration::from_secs(20);
const LIST_ATTEMPTS: usize = 3;
const LIST_RETRY_MS: [u64; 2] = [400, 1_200];
const APPROVED_CAP: usize = 200;
const APPROVE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
const PLUGIN_INSTALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(90);
const GATEWAY_POLL: Duration = Duration::from_millis(500);
const PAIRINGS_CACHE: Duration = Duration::from_secs(4);
const ALLOWED_CACHE: Duration = Duration::from_secs(5);
const WA_QR_TIMEOUT_MS: u64 = 120_000;
const WA_QR_STALE_MS: i64 = 150_000;
const WA_INSTALL_STALE_MS: i64 = 15 * 60_000;
const WA_RESULT_TTL_MS: i64 = 10 * 60_000;
/// budgets.ts
const APPLY_INLINE_WAIT: Duration = Duration::from_secs(25);
const CHANNEL_WRITE_BUDGET: Duration = Duration::from_secs(55);
/// How long a channel write that finds OpenClaw restarting waits for it, out of `CHANNEL_WRITE_BUDGET`.
const GATEWAY_RESTART_WAIT: Duration = Duration::from_secs(30);
const APPROVE_QUEUE_WAIT: Duration = Duration::from_secs(10);
const APPLY_RECORD_TTL_MS: i64 = 10 * 60_000;
const CHANNELS_STATUS: Duration = Duration::from_secs(8);

fn re(p: &str) -> Regex {
    Regex::new(p).expect("regex")
}

static BUSY_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(EBUSY|EAGAIN|ECONNREFUSED|SQLITE_BUSY)\b|database is locked|gateway (is )?(not running|unavailable|starting|restarting)|connection refused|socket hang up",
    )
});
static APPLY_ID_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_.:-]{1,64}$"));
static CODE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^[A-Z0-9-]{4,16}$"));
static SENDER_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)sender\s+(\S+?)\.?\s*$"));
static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| re("\x1b\\[[0-9;]*m"));
static ORIGIN_RE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"));
static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^cctc_[A-Za-z0-9_-]{20,100}$"));
static WORKSPACE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^wsp_[0-9a-z]{8,40}$"));
static USER_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^usr_[0-9a-z]{8,40}$"));
static FALLBACK_RE: LazyLock<Regex> = LazyLock::new(|| re(r"[_*~`\[\]<>|\\&]"));
static SPACES_RE: LazyLock<Regex> = LazyLock::new(|| re(r" {2,}"));
static TICKS_RE: LazyLock<Regex> = LazyLock::new(|| re(r"`{3,}"));

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `exactMessage`: the text as the person must read it. Telegram as escaped HTML; Slack and
/// WhatsApp in a code block, with Slack's angle brackets swapped for the single quotation marks.
pub fn exact_message(t: &str, text: &str) -> (String, Option<&'static str>) {
    if t == "telegram" {
        let m = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        return (m, Some("HTML"));
    }
    let body = TICKS_RE.replace_all(text, |c: &regex::Captures| "'".repeat(c[0].len()));
    let body = if t == "slack" {
        body.replace('<', "\u{2039}").replace('>', "\u{203A}")
    } else {
        body.into_owned()
    };
    (format!("```\n{body}\n```"), None)
}

/// `plainFallback`: every Markdown character a space, runs of spaces one.
pub fn plain_fallback(text: &str) -> String {
    let spaced = FALLBACK_RE.replace_all(text, " ");
    SPACES_RE.replace_all(&spaced, " ").into_owned()
}

fn bool_of(v: Option<&Value>) -> bool {
    v == Some(&Value::Bool(true))
}

/// WhatsApp's linked number: `{e164, jid}` or a plain string.
fn self_number(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        o @ Value::Object(_) => text(o.get("e164")).or_else(|| text(o.get("jid"))),
        _ => None,
    }
}

fn channel_account<'a>(t: &str, payload: &'a Value) -> Option<&'a Map<String, Value>> {
    let list = at(payload, &["channelAccounts", t])?.as_array()?;
    let accounts: Vec<&Map<String, Value>> = list.iter().filter_map(Value::as_object).collect();
    let default = text(at(payload, &["channelDefaultAccountId", t]));
    if let Some(d) = default
        && let Some(a) = accounts.iter().find(|a| a.get("accountId") == Some(&json!(d)))
    {
        return Some(a);
    }
    let enabled: Vec<&&Map<String, Value>> = accounts
        .iter()
        .filter(|a| a.get("enabled") != Some(&json!(false)))
        .collect();
    enabled
        .iter()
        .find(|a| a.get("connected") == Some(&json!(true)))
        .or(enabled.first())
        .map(|a| **a)
}

/// `channelStatusFrom`: one channel out of `channels.status`, or None when OpenClaw does not list it.
pub fn channel_status_from(t: &str, payload: &Value) -> Option<Map<String, Value>> {
    let s = at(payload, &["channels", t])?.as_object()?;
    let account = channel_account(t, payload);
    let pick = |k: &str| match s.get(k) {
        Some(Value::Bool(b)) => *b,
        _ => bool_of(account.and_then(|a| a.get(k))),
    };
    let mut e = Map::new();
    e.insert("configured".into(), json!(pick("configured")));
    e.insert("running".into(), json!(pick("running")));
    e.insert("connected".into(), json!(pick("connected")));
    let err = text(s.get("lastError")).or_else(|| text(account.and_then(|a| a.get("lastError"))));
    e.insert("lastError".into(), json!(err));
    if t == "whatsapp" {
        let me = self_number(s.get("self")).or_else(|| self_number(account.and_then(|a| a.get("self"))));
        e.insert("self".into(), json!(me));
    }
    Some(e)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pairing {
    pub kind: String,
    pub code: String,
    pub sender_id: String,
    pub label: Option<String>,
    pub created_at: Option<String>,
}

impl Pairing {
    fn json(&self) -> Value {
        json!({ "type": self.kind, "code": self.code, "senderId": self.sender_id, "label": self.label, "createdAt": self.created_at })
    }
}

fn to_pairing(t: &str, r: &Value) -> Option<Pairing> {
    let sender_id = text(r.get("id")).or_else(|| text(r.get("senderId")))?;
    let code = text(r.get("code"))?;
    let label = r
        .get("meta")
        .and_then(super::allow::label_of)
        .or_else(|| text(r.get("label")));
    Some(Pairing {
        kind: t.into(),
        code,
        sender_id,
        label,
        created_at: text(r.get("createdAt")),
    })
}

/// `openclaw pairing list <t> --json`: its requests, read from the first `{` on (the CLI prints log
/// lines first). As in the TS, a bare array (`[...]`) does not parse from there: kept as it is.
fn parse_listing(t: &str, stdout: &str) -> Result<Vec<Pairing>, String> {
    let start = stdout.find('{').unwrap_or(stdout.len());
    let parsed: Value = serde_json::from_str(&stdout[start..]).map_err(|e| e.to_string())?;
    let requests = match &parsed {
        Value::Array(a) => a.clone(),
        v => v.get("requests").and_then(Value::as_array).cloned().unwrap_or_default(),
    };
    Ok(requests.iter().filter_map(|r| to_pairing(t, r)).collect())
}

/// Why the pending listing came back short.
#[derive(Debug, Clone, PartialEq)]
pub struct PairingsError {
    pub busy: bool,
    pub message: String,
}

fn err_json(e: &Option<PairingsError>) -> Value {
    match e {
        Some(e) => json!({ "busy": e.busy, "message": e.message }),
        None => Value::Null,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Approved {
    pub kind: String,
    pub sender_id: String,
    pub code: Option<String>,
    pub at: String,
}

impl Approved {
    fn json(&self) -> Value {
        json!({ "type": self.kind, "senderId": self.sender_id, "code": self.code, "at": self.at })
    }
}

/// `state/channels.json`: who this box approved, and whether the one-time seed ran.
#[derive(Debug, Clone, PartialEq, Default)]
struct ChannelState {
    seeded_at: Option<String>,
    approved: Vec<Approved>,
}

fn read_state(path: Option<&PathBuf>) -> ChannelState {
    let Some(raw) = path.and_then(|p| std::fs::read_to_string(p).ok()) else {
        return ChannelState::default();
    };
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return ChannelState::default();
    };
    let approved = v
        .get("approved")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| {
            let sender_id = a.get("senderId")?.as_str()?.to_string();
            let code = match a.get("code") {
                Some(Value::String(c)) => Some(c.clone()),
                Some(Value::Null) => None,
                _ => return None,
            };
            let kind = a
                .get("type")?
                .as_str()
                .filter(|t| CHANNEL_TYPES.contains(t))?
                .to_string();
            // `at` is kept as written, whatever it is; the TS passes the record through.
            let at = a.get("at").and_then(Value::as_str).unwrap_or_default().to_string();
            Some(Approved {
                kind,
                sender_id,
                code,
                at,
            })
        })
        .collect();
    ChannelState {
        seeded_at: v.get("seededAt").and_then(Value::as_str).map(str::to_string),
        approved,
    }
}

fn write_state(path: &std::path::Path, s: &ChannelState) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let body = json!({
        "version": 1,
        "seededAt": s.seeded_at,
        "approved": s.approved.iter().map(Approved::json).collect::<Vec<_>>(),
    });
    cc_store::write_atomic(path, body.to_string().as_bytes(), 0o600, cc_store::TmpName::Suffix)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClickClack {
    pub base_url: String,
    pub api_base_url: String,
    pub token: String,
    pub workspace: String,
    pub bot_user_id: Option<String>,
    pub peers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApplyKind {
    Remove,
    ClickClack(ClickClack),
    Telegram { bot_token: String },
    Slack { bot_token: String, app_token: String },
    Whatsapp { personal: bool, me: Option<String> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplyInput {
    pub apply_id: Option<String>,
    pub kind: String,
    pub what: ApplyKind,
}

/// `channelBlock`: the `channels.<type>` block, or None to take it off.
pub fn channel_block(input: &ApplyInput) -> Option<Value> {
    match &input.what {
        ApplyKind::Remove => None,
        ApplyKind::Telegram { bot_token } => {
            Some(json!({ "enabled": true, "botToken": bot_token, "dmPolicy": "pairing" }))
        }
        ApplyKind::Slack { bot_token, app_token } => Some(
            json!({ "enabled": true, "mode": "socket", "botToken": bot_token, "appToken": app_token, "dmPolicy": "pairing" }),
        ),
        // `personal && self`: an empty number is no number.
        ApplyKind::Whatsapp { personal, me } => Some(match me.as_deref().filter(|m| !m.is_empty()) {
            Some(me) if *personal => {
                json!({ "enabled": true, "dmPolicy": "allowlist", "allowFrom": [me], "selfChatMode": true })
            }
            _ => json!({ "enabled": true, "dmPolicy": "pairing" }),
        }),
        ApplyKind::ClickClack(t) => {
            let mut b = Map::new();
            b.insert("enabled".into(), json!(true));
            b.insert("baseUrl".into(), json!(t.base_url));
            b.insert("apiBaseUrl".into(), json!(t.api_base_url));
            b.insert("token".into(), json!(t.token));
            b.insert("workspace".into(), json!(t.workspace));
            if let Some(bot) = &t.bot_user_id {
                b.insert("botUserId".into(), json!(bot));
            }
            b.insert("defaultTo".into(), json!("channel:general"));
            b.insert("requireMention".into(), json!(true));
            b.insert("allowBots".into(), json!("mentions"));
            let mut allow = vec![json!("*")];
            allow.extend(t.peers.iter().map(|p| json!(p)));
            b.insert("allowFrom".into(), Value::Array(allow));
            Some(Value::Object(b))
        }
    }
}

/// `parseClickClackSettings`: Team chat settings, with the API on this box's own firewall's gate.
pub fn parse_clickclack(raw: Option<&Value>, mitm_ip: Option<&str>) -> Option<ClickClack> {
    let r = raw?.as_object()?;
    let mitm_ip = mitm_ip?;
    let s = |k: &str, max: usize| match r.get(k) {
        Some(Value::String(v)) if !v.is_empty() && utf16_len(v) <= max => Some(v.clone()),
        _ => None,
    };
    let base_url = s("baseUrl", 300)?;
    let api_base_url = s("apiBaseUrl", 100)?;
    let token = s("token", 200)?;
    let workspace = s("workspace", 64)?;
    let bot_raw = r.get("botUserId").filter(|v| !v.is_null());
    let bot_user_id = match bot_raw {
        None => None,
        Some(_) => Some(s("botUserId", 64).filter(|b| USER_RE.is_match(b))?),
    };
    if !ORIGIN_RE.is_match(&base_url)
        || api_base_url != format!("http://{mitm_ip}:{TEAMCHAT_GATE_PORT}")
        || !TOKEN_RE.is_match(&token)
        || !WORKSPACE_RE.is_match(&workspace)
    {
        return None;
    }
    let raw_peers = match r.get("peers") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return None,
    };
    if raw_peers.len() > 200
        || !raw_peers
            .iter()
            .all(|p| p.as_str().is_some_and(|p| USER_RE.is_match(p)))
    {
        return None;
    }
    let mut peers: Vec<String> = Vec::new();
    for p in raw_peers {
        let p = p.as_str().unwrap_or_default().to_string();
        if !peers.contains(&p) {
            peers.push(p);
        }
    }
    Some(ClickClack {
        base_url,
        api_base_url,
        token,
        workspace,
        bot_user_id,
        peers,
    })
}

#[derive(Debug, Clone, PartialEq)]
struct ApplyRecord {
    id: String,
    state: &'static str,
    what: &'static str,
    error: Option<String>,
    at: String,
    at_ms: i64,
}

impl ApplyRecord {
    fn json(&self) -> Value {
        json!({ "id": self.id, "state": self.state, "what": self.what, "error": self.error, "at": self.at })
    }
}

#[derive(Debug, Clone)]
struct WaLogin {
    state: &'static str,
    qr: Option<String>,
    message: Option<String>,
    at: i64,
    personal: bool,
}

type Read = (Vec<Pairing>, Option<PairingsError>);
type SharedRead = Shared<cc_http::BoxFuture<Read>>;

struct Inner {
    state: ChannelState,
    allowed_cache: Option<(Instant, Value)>,
    /// Install progress per channel, in the order it started (a JS Map).
    setup: Vec<(String, Value)>,
    installing: HashMap<String, Shared<cc_http::BoxFuture<bool>>>,
    applies: HashMap<String, ApplyRecord>,
    wa: WaLogin,
    pairings: HashMap<String, (Instant, Read)>,
    pairings_running: HashMap<String, SharedRead>,
}

/// A copy of one of OpenClaw's files, in the agent's own folder: an unmanaged OpenClaw in a
/// container, whose folder the agent (root there) must not walk. None: not there, or not taken.
pub type CopyOut = Arc<dyn Fn(&std::path::Path) -> Option<Readable> + Send + Sync>;

/// Where one of OpenClaw's files is read: the file itself, or a copy in a folder of its own (with
/// a database's log beside it), which goes when this does. Each read has its own copy.
pub struct Readable {
    pub path: PathBuf,
    _dir: Option<tempfile::TempDir>,
}

impl Readable {
    pub fn copied(path: PathBuf, dir: tempfile::TempDir) -> Self {
        Self { path, _dir: Some(dir) }
    }
}

pub struct ChannelsService {
    deps: Deps,
    /// OpenClaw's files read through a copy (above); None: read where they are.
    copy_out: Option<CopyOut>,
    bin: String,
    credentials_dir: PathBuf,
    state_path: Option<PathBuf>,
    state_db: Option<PathBuf>,
    mitm_ca: Option<PathBuf>,
    mitm_ip: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    inner: Mutex<Inner>,
    /// Test seams.
    pub apply_inline_wait: Duration,
    pub write_budget: Duration,
    pub pairings_cache: Duration,
    /// How long `apply` waits for a gateway that is restarting (`Deps::gateway_back`).
    pub gateway_wait: Duration,
}

#[derive(Debug)]
pub struct ChannelError(pub String);

impl From<String> for ChannelError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

fn looks_busy(m: &str) -> bool {
    BUSY_RE.is_match(m)
}

impl ChannelsService {
    pub fn new(
        deps: Deps,
        credentials_dir: PathBuf,
        state_path: Option<PathBuf>,
        state_db: Option<PathBuf>,
        mitm_ca: Option<PathBuf>,
        mitm_ip: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        let state = read_state(state_path.as_ref());
        Self {
            bin: deps.bin.clone(),
            deps,
            copy_out: None,
            credentials_dir,
            state_path,
            state_db,
            mitm_ca,
            mitm_ip,
            inner: Mutex::new(Inner {
                state,
                allowed_cache: None,
                setup: Vec::new(),
                installing: HashMap::new(),
                applies: HashMap::new(),
                wa: WaLogin {
                    state: "idle",
                    qr: None,
                    message: None,
                    at: 0,
                    personal: false,
                },
                pairings: HashMap::new(),
                pairings_running: HashMap::new(),
            }),
            apply_inline_wait: APPLY_INLINE_WAIT,
            write_budget: CHANNEL_WRITE_BUDGET,
            pairings_cache: PAIRINGS_CACHE,
            gateway_wait: GATEWAY_RESTART_WAIT,
        }
    }

    /// Unmanaged, in a container: OpenClaw's files are read through `copy_out`.
    pub fn reading_through(mut self, copy_out: Option<CopyOut>) -> Self {
        self.copy_out = copy_out;
        self
    }

    /// Where OpenClaw's file `p` is read: itself, or a copy of it. On a blocking thread.
    fn readable(copy_out: &Option<CopyOut>, p: &std::path::Path) -> Option<Readable> {
        match copy_out {
            None => Some(Readable {
                path: p.to_path_buf(),
                _dir: None,
            }),
            Some(f) => f(p),
        }
    }

    /// OpenClaw's allow list, read on a blocking thread: the read can wait 2 s per channel on a lock.
    async fn db_allow(&self) -> super::allow::AllowListRead {
        let Some(p) = self.state_db.clone() else {
            return Default::default();
        };
        let log = self.deps.log.clone();
        let copy_out = self.copy_out.clone();
        tokio::task::spawn_blocking(move || match Self::readable(&copy_out, &p) {
            Some(r) => read_allow_list(&r.path, &CHANNEL_TYPES, &|l| log(l)),
            None => Default::default(),
        })
        .await
        .unwrap_or_default()
    }

    /// The pending requests in OpenClaw's store, on a blocking thread. None without a store path.
    async fn db_pending(&self, types: &[&str]) -> Option<super::allow::PendingRead> {
        let p = self.state_db.clone()?;
        let log = self.deps.log.clone();
        let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
        let copy_out = self.copy_out.clone();
        let read = tokio::task::spawn_blocking(move || {
            let refs: Vec<&str> = types.iter().map(String::as_str).collect();
            match Self::readable(&copy_out, &p) {
                Some(r) => read_pending(&r.path, &refs, &|l| log(l)),
                None => Default::default(),
            }
        })
        .await
        .unwrap_or_default();
        Some(read)
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    fn connected(&self) -> bool {
        self.deps.client().is_some_and(|w| w.gateway().connected())
    }

    pub fn clickclack_settings(&self, raw: Option<&Value>) -> Option<ClickClack> {
        parse_clickclack(raw, (self.mitm_ip)().as_deref())
    }

    async fn config(&self) -> Result<Value, String> {
        let snap = self.deps.call("config.get", json!({}), GATEWAY_READ).await?;
        let cfg = match snap.get("parsed") {
            Some(v) if !v.is_null() => v.clone(),
            _ => snap.get("config").cloned().unwrap_or(Value::Null),
        };
        Ok(if cfg.is_null() { json!({}) } else { cfg })
    }

    fn persist(&self, state: &ChannelState) {
        let Some(path) = &self.state_path else { return };
        if let Err(e) = write_state(path, state) {
            self.deps
                .log(&format!("[channels] could not write the channel state: {e}"));
        }
    }

    /// Everyone this box has approved. Seeds once from `commands.ownerAllowFrom`.
    pub async fn approved(&self) -> Vec<Approved> {
        self.seed().await;
        self.inner().state.approved.clone()
    }

    async fn seed(&self) {
        if self.inner().state.seeded_at.is_some() {
            return;
        }
        let config = match self.config().await {
            Ok(c) => c,
            Err(e) => {
                self.deps.log(&format!(
                    "[channels] could not read the config to seed approved senders: {e}"
                ));
                return;
            }
        };
        let now = iso_ms(now_ms());
        let mut found: Vec<Approved> = Vec::new();
        for raw in at(&config, &["commands", "ownerAllowFrom"])
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let s = match raw {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let mut parts = s.splitn(2, ':');
            let t = parts.next().unwrap_or_default();
            let sender = parts.next().unwrap_or_default();
            if sender.is_empty() || !CHANNEL_TYPES.contains(&t) || !bool_of(at(&config, &["channels", t, "enabled"])) {
                continue;
            }
            found.push(Approved {
                kind: t.into(),
                sender_id: sender.into(),
                code: None,
                at: now.clone(),
            });
        }
        let snapshot = {
            let mut i = self.inner();
            if i.state.seeded_at.is_some() {
                return;
            }
            let mut approved = i.state.approved.clone();
            for f in &found {
                if !approved.iter().any(|a| a.kind == f.kind && a.sender_id == f.sender_id) {
                    approved.push(f.clone());
                }
            }
            let skip = approved.len().saturating_sub(APPROVED_CAP);
            i.state = ChannelState {
                seeded_at: Some(now),
                approved: approved.split_off(skip),
            };
            i.state.clone()
        };
        self.persist(&snapshot);
        if !found.is_empty() {
            self.deps.log(&format!(
                "[channels] {} approved sender(s) read out of this agent's own config",
                found.len()
            ));
        }
    }

    fn record_approved(&self, kind: &str, sender_id: &str, code: Option<&str>) {
        let snapshot = {
            let mut i = self.inner();
            let mut kept: Vec<Approved> = i
                .state
                .approved
                .iter()
                .filter(|a| !(a.kind == kind && a.sender_id == sender_id))
                .cloned()
                .collect();
            kept.push(Approved {
                kind: kind.into(),
                sender_id: sender_id.into(),
                code: code.map(str::to_string),
                at: iso_ms(now_ms()),
            });
            let skip = kept.len().saturating_sub(APPROVED_CAP);
            i.state.approved = kept.split_off(skip);
            i.state.clone()
        };
        self.persist(&snapshot);
    }

    fn forget_approved(&self, kind: &str) {
        let (snapshot, logged) = {
            let mut i = self.inner();
            if !i.state.approved.iter().any(|a| a.kind == kind) {
                if i.state.seeded_at.is_some() {
                    return;
                }
                i.state.seeded_at = Some(iso_ms(now_ms()));
                (i.state.clone(), false)
            } else {
                if i.state.seeded_at.is_none() {
                    i.state.seeded_at = Some(iso_ms(now_ms()));
                }
                i.state.approved.retain(|a| a.kind != kind);
                (i.state.clone(), true)
            }
        };
        self.persist(&snapshot);
        if logged {
            self.deps.log(&format!(
                "[channels] forgot the approved {kind} senders: the channel was removed from this box"
            ));
        }
    }

    /// Who OpenClaw itself will talk to (a suggestion, never an approval).
    pub async fn allowed_by_agent(&self) -> Value {
        if let Some((t, v)) = &self.inner().allowed_cache
            && t.elapsed() < ALLOWED_CACHE
        {
            return v.clone();
        }
        let from_db = self.db_allow().await;
        let mut senders: Vec<Value> = Vec::new();
        let mut seen: Vec<(String, String)> = Vec::new();
        for s in &from_db.senders {
            if !CHANNEL_TYPES.contains(&s.channel.as_str()) {
                continue;
            }
            seen.push((s.channel.clone(), s.sender_id.clone()));
            senders.push(json!({ "type": s.channel, "senderId": s.sender_id, "label": s.label, "accountId": s.account_id, "at": s.at }));
        }
        if !from_db.canonical && from_db.error.is_none() {
            for (t, sender) in self.allowed_from_config().await {
                if !seen.contains(&(t.clone(), sender.clone())) {
                    seen.push((t.clone(), sender.clone()));
                    senders.push(
                        json!({ "type": t, "senderId": sender, "label": null, "accountId": "default", "at": null }),
                    );
                }
            }
        }
        let error = match &from_db.error {
            Some(e) => json!({ "busy": e.busy, "message": e.message }),
            None => Value::Null,
        };
        let value = json!({ "senders": senders, "error": error });
        self.inner().allowed_cache = Some((Instant::now(), value.clone()));
        value
    }

    async fn allowed_from_config(&self) -> Vec<(String, String)> {
        let Ok(config) = self.config().await else {
            return Vec::new();
        };
        let mut out: Vec<(String, String)> = Vec::new();
        for t in CHANNEL_TYPES {
            for e in at(&config, &["channels", t, "allowFrom"])
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(sender) = text(Some(e)) else { continue };
                if sender == "*" || sender.starts_with("accessGroup:") {
                    continue;
                }
                if out.iter().any(|(ot, os)| ot == t && *os == sender) {
                    continue;
                }
                out.push((t.into(), sender));
            }
        }
        out
    }

    /// Pending requests plus why the list is short; one read at a time per channel set, reused briefly.
    pub fn pairings_read(self: &Arc<Self>, types: &[&str]) -> SharedRead {
        let mut key: Vec<&str> = types.to_vec();
        key.sort();
        let key = key.join(",");
        if key.is_empty() {
            let f: cc_http::BoxFuture<Read> = Box::pin(async { (Vec::new(), None) });
            return f.shared();
        }
        let mut i = self.inner();
        if let Some((t, v)) = i.pairings.get(&key)
            && t.elapsed() < self.pairings_cache
        {
            let v = v.clone();
            let f: cc_http::BoxFuture<Read> = Box::pin(async move { v });
            return f.shared();
        }
        if let Some(running) = i.pairings_running.get(&key) {
            return running.clone();
        }
        let started = Instant::now();
        let me = self.clone();
        let types: Vec<String> = types.iter().map(|s| s.to_string()).collect();
        let k = key.clone();
        let f: cc_http::BoxFuture<Read> = Box::pin(async move {
            let refs: Vec<&str> = types.iter().map(String::as_str).collect();
            let r = me.read_pairings(&refs).await;
            let mut i = me.inner();
            i.pairings_running.remove(&k);
            // Stamped from when the run started.
            i.pairings.insert(k, (started, r.clone()));
            r
        });
        let shared = f.shared();
        i.pairings_running.insert(key, shared.clone());
        shared
    }

    fn forget_pairings(&self) {
        self.inner().pairings.clear();
    }

    async fn read_pairings(&self, types: &[&str]) -> Read {
        let from_db = self.db_pending(types).await;
        if let Some(db) = &from_db
            && db.canonical
        {
            let mut out: Vec<Pairing> = db
                .pairings
                .iter()
                .map(|p| Pairing {
                    kind: p.channel.clone(),
                    code: p.code.clone(),
                    sender_id: p.sender_id.clone(),
                    label: p.label.clone(),
                    created_at: p.created_at.clone(),
                })
                .collect();
            self.merge_legacy(&mut out);
            return (out, None);
        }
        if let Some(db) = &from_db
            && let Some(e) = &db.error
        {
            let mut out = Vec::new();
            self.merge_legacy(&mut out);
            return (
                out,
                Some(PairingsError {
                    busy: e.busy,
                    message: e.message.clone(),
                }),
            );
        }
        let results = futures_util::future::join_all(types.iter().map(|t| self.list_pairings(t))).await;
        let mut out = Vec::new();
        let mut failures = Vec::new();
        for (p, e) in results {
            out.extend(p);
            if let Some(e) = e {
                failures.push(e);
            }
        }
        self.merge_legacy(&mut out);
        let err = failures.iter().find(|f| !f.busy).or(failures.first()).cloned();
        (out, err)
    }

    fn merge_legacy(&self, out: &mut Vec<Pairing>) {
        for legacy in self.pairings_from_files() {
            if !out
                .iter()
                .any(|p| p.kind == legacy.kind && p.sender_id == legacy.sender_id)
            {
                out.push(legacy);
            }
        }
    }

    async fn list_pairings(&self, t: &str) -> Read {
        let mut last = String::new();
        for attempt in 0..LIST_ATTEMPTS {
            if attempt > 0 {
                let ms = LIST_RETRY_MS.get(attempt - 1).copied().unwrap_or(1_000);
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            match self
                .deps
                .exec(&self.bin, &["pairing", "list", t, "--json"], LIST_TIMEOUT, None, &[])
                .await
            {
                Ok(stdout) => match parse_listing(t, &stdout) {
                    Ok(p) => return (p, None),
                    Err(e) => last = e,
                },
                Err(line) => last = line,
            }
        }
        let busy = !self.connected() || looks_busy(&last);
        self.deps.log(&format!(
            "[channels] pairing list {t} failed after {LIST_ATTEMPTS} tries: {last}"
        ));
        let message = if busy {
            format!("The agent is busy right now, so who is waiting on {t} could not be read.")
        } else {
            format!("The agent could not list who is waiting on {t}: {last}")
        };
        (Vec::new(), Some(PairingsError { busy, message }))
    }

    /// Older gateways (before 2026.9) kept pending requests in `<channel>-pairing.json`.
    pub fn pairings_from_files(&self) -> Vec<Pairing> {
        let mut out = Vec::new();
        // Not for a container: its files are read through a copy (Docker, a blocking call on this
        // path), and the gateways in today's images keep their pairings in the database.
        if self.copy_out.is_some() {
            return out;
        }
        for t in CHANNEL_TYPES {
            let Ok(raw) = std::fs::read_to_string(self.credentials_dir.join(format!("{t}-pairing.json"))) else {
                continue;
            };
            match serde_json::from_str::<Value>(&raw) {
                Ok(v) => {
                    for r in v.get("requests").and_then(Value::as_array).into_iter().flatten() {
                        if let Some(p) = to_pairing(t, r) {
                            out.push(p);
                        }
                    }
                }
                Err(e) => self.deps.log(&format!("[channels] unreadable {t}-pairing.json: {e}")),
            }
        }
        out
    }

    /// The people's channels as OpenClaw reports them, for the minute sample. None while down.
    pub async fn channel_states(&self) -> Result<Option<Map<String, Value>>, String> {
        if !self.connected() {
            return Ok(None);
        }
        let payload = self
            .deps
            .call("channels.status", json!({ "probe": false }), CHANNELS_STATUS)
            .await?;
        let mut out = Map::new();
        for t in CHANNEL_TYPES {
            if let Some(e) = channel_status_from(t, &payload) {
                out.insert(t.into(), Value::Object(e));
            }
        }
        Ok(Some(out))
    }

    fn apply_record(&self, t: &str) -> Option<ApplyRecord> {
        let mut i = self.inner();
        let r = i.applies.get(t)?.clone();
        if r.state != "pending" && now_ms() - r.at_ms >= APPLY_RECORD_TTL_MS {
            i.applies.remove(t);
            return None;
        }
        Some(r)
    }

    fn note_apply(&self, t: &str, state: &'static str, id: &str, what: &'static str, error: Option<String>) {
        let now = now_ms();
        let mut i = self.inner();
        i.applies
            .retain(|_, r| !(r.state != "pending" && r.at_ms < now - APPLY_RECORD_TTL_MS));
        i.applies.insert(
            t.into(),
            ApplyRecord {
                id: id.into(),
                state,
                what,
                error,
                at: iso_ms(now),
                at_ms: now,
            },
        );
    }

    /// `status()`: per-channel state, the pending pairings and the WhatsApp login.
    pub async fn status(self: &Arc<Self>, team_chat_peers: bool) -> Result<Value, String> {
        let mut channels = Map::new();
        if self.connected() {
            let payload = self
                .deps
                .call("channels.status", json!({ "probe": false }), CHANNELS_STATUS)
                .await?;
            for t in APPLY_CHANNELS {
                if let Some(e) = channel_status_from(t, &payload) {
                    channels.insert(t.into(), Value::Object(e));
                }
            }
        }
        let blank = || json!({ "configured": false, "running": false, "connected": false, "lastError": null });
        let merge = |channels: &mut Map<String, Value>, t: &str, key: &str, v: Value| {
            let mut e = blank().as_object().cloned().unwrap_or_default();
            if let Some(Value::Object(have)) = channels.get(t) {
                for (k, x) in have {
                    e.insert(k.clone(), x.clone());
                }
            }
            e.insert(key.into(), v);
            channels.insert(t.into(), Value::Object(e));
        };
        let setup = self.inner().setup.clone();
        for (t, s) in setup {
            merge(&mut channels, &t, "setup", s);
        }
        for t in APPLY_CHANNELS {
            if let Some(r) = self.apply_record(t) {
                merge(&mut channels, t, "lastApply", r.json());
            }
        }
        if team_chat_peers
            && channels.get("clickclack").and_then(|c| c.get("configured")) == Some(&json!(true))
            && let Ok(config) = self.config().await
        {
            let mut peers: Vec<String> = at(&config, &["channels", "clickclack", "allowFrom"])
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_str().filter(|p| *p != "*").map(str::to_string))
                .collect();
            peers.sort();
            if let Some(Value::Object(c)) = channels.get_mut("clickclack") {
                c.insert("peers".into(), json!(peers));
            }
        }
        let wa = self.whatsapp_login();
        let configured: Vec<&str> = CHANNEL_TYPES
            .iter()
            .copied()
            .filter(|t| channels.get(*t).and_then(|c| c.get("configured")) == Some(&json!(true)))
            .collect();
        let (pairings, error) = self.pairings_read(&configured).await;
        let wa_state = wa["state"].clone();
        Ok(json!({
            "channels": channels,
            "pairings": pairings.iter().map(Pairing::json).collect::<Vec<_>>(),
            "pairingsError": err_json(&error),
            "whatsappLogin": if wa_state == "idle" { Value::Null } else { json!({ "state": wa_state }) },
        }))
    }

    async fn patch_config(
        &self,
        patch: Map<String, Value>,
        replace_paths: Vec<String>,
        budget: Option<Duration>,
    ) -> Result<(), String> {
        let w = self.deps.gateway()?;
        let timeout = if patch_restarts_gateway(&patch) {
            CONFIG_PATCH_RESTART
        } else {
            CONFIG_PATCH
        };
        let opts = PatchOptions {
            read_timeout: Some(GATEWAY_READ),
            replace_paths,
            budget,
            ..PatchOptions::new(timeout)
        };
        w.patch(&patch, opts).await.map_err(|e| e.to_string())
    }

    /// `apply`: the patch runs to completion in the background; the route waits up to 25 s.
    pub async fn apply(self: &Arc<Self>, input: ApplyInput) -> Result<Value, ChannelError> {
        // A gateway that is restarting is waited for inside the write, so the route keeps its inline
        // wait and the firewall can read the outcome back under the apply id.
        self.deps.gateway_or_restarting().await?;
        let block = channel_block(&input);
        let t = input.kind.clone();
        let mut patch = Map::new();
        patch.insert("channels".into(), json!({ t.clone(): block.clone() }));
        let what_text = if block.is_some() {
            format!("applied {t}")
        } else {
            format!("removed {t}")
        };
        let what: &'static str = if block.is_some() { "apply" } else { "remove" };
        let id = input
            .apply_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.note_apply(&t, "pending", &id, what, None);
        let replace = if t == "clickclack" {
            vec!["channels.clickclack.allowFrom".to_string()]
        } else {
            Vec::new()
        };
        let me = self.clone();
        let (tt, idc, wt, has_block) = (t.clone(), id.clone(), what_text.clone(), block.is_some());
        let (budget, gateway_wait) = (self.write_budget, self.gateway_wait);
        let write = tokio::spawn(async move {
            let started = Instant::now();
            let back = me.deps.gateway_back(gateway_wait).await;
            let wrote = match back {
                Ok(_) => {
                    me.patch_config(patch, replace, Some(budget.saturating_sub(started.elapsed())))
                        .await
                }
                Err(e) => Err(e),
            };
            match wrote {
                Ok(()) => {
                    me.note_apply(&tt, "applied", &idc, what, None);
                    me.deps.log(&format!("[channels] {wt}"));
                    if !has_block && tt != "clickclack" {
                        me.forget_approved(&tt);
                    }
                    if has_block {
                        let m = me.clone();
                        let tt = tt.clone();
                        tokio::spawn(async move {
                            m.ensure_plugin(&tt).await;
                        });
                    }
                    true
                }
                Err(e) => {
                    me.deps.log(&format!(
                        "[channels] could not {} {tt}: {e}",
                        if has_block { "apply" } else { "remove" }
                    ));
                    me.note_apply(&tt, "failed", &idc, what, Some(e));
                    false
                }
            }
        });
        match tokio::time::timeout(self.apply_inline_wait, write).await {
            Err(_) => {
                self.deps.log(&format!(
                    "[channels] {t} is still being written ({id}); the firewall will read the outcome back"
                ));
                Ok(json!({
                    "ok": true,
                    "status": "pending",
                    "applyId": id,
                    "message": format!("{} {t} on this agent…", if block.is_some() { "Applying" } else { "Removing" }),
                }))
            }
            Ok(Ok(true)) => Ok(json!({ "ok": true, "status": "applied", "applyId": id, "message": what_text })),
            Ok(_) => {
                let err = lock(&self.inner).applies.get(&t).and_then(|r| r.error.clone());
                Err(ChannelError(err.unwrap_or_else(|| {
                    format!("could not {} {t}", if block.is_some() { "apply" } else { "remove" })
                })))
            }
        }
    }

    fn plugin_installed(config: &Value, t: &str) -> bool {
        if plugin_of(t).is_none() {
            return true;
        }
        at(config, &["plugins", "entries"])
            .and_then(Value::as_object)
            .is_some_and(|e| e.contains_key(t))
    }

    fn set_setup(&self, t: &str, v: Option<Value>) {
        let mut i = self.inner();
        match v {
            Some(v) => match i.setup.iter_mut().find(|(k, _)| k == t) {
                Some(slot) => slot.1 = v,
                None => i.setup.push((t.into(), v)),
            },
            None => i.setup.retain(|(k, _)| k != t),
        }
    }

    fn setup_message(&self, t: &str) -> Option<String> {
        self.inner()
            .setup
            .iter()
            .find(|(k, _)| k == t)
            .and_then(|(_, v)| text(v.get("message")))
    }

    /// Install the channel's plugin if missing, then restart. Single-flight per channel; never fails.
    pub fn ensure_plugin(self: &Arc<Self>, t: &str) -> Shared<cc_http::BoxFuture<bool>> {
        let Some(pkg) = plugin_of(t) else {
            let f: cc_http::BoxFuture<bool> = Box::pin(async { true });
            return f.shared();
        };
        let mut i = self.inner();
        if let Some(running) = i.installing.get(t) {
            return running.clone();
        }
        let me = self.clone();
        let tt = t.to_string();
        let f: cc_http::BoxFuture<bool> = Box::pin(async move {
            let ok = me.install_plugin(&tt, pkg).await;
            me.inner().installing.remove(&tt);
            ok
        });
        let shared = f.shared();
        i.installing.insert(t.into(), shared.clone());
        drop(i);
        // Runs whether or not anybody waits on it.
        let s = shared.clone();
        tokio::spawn(async move {
            s.await;
        });
        shared
    }

    async fn install_plugin(&self, t: &str, pkg: &str) -> bool {
        match self.config().await {
            Ok(c) if Self::plugin_installed(&c, t) => return true,
            Ok(_) => {}
            Err(e) => {
                self.deps.log(&format!(
                    "[channels] could not read the config to check the {t} plugin: {e}"
                ));
                return false;
            }
        }
        self.set_setup(
            t,
            Some(json!({ "state": "installing", "message": format!("Setting up {t} on this agent…") })),
        );
        self.deps.log(&format!("[channels] installing {pkg}"));
        let env: Vec<(&str, String)> = match &self.mitm_ca {
            Some(ca) if ca.exists() => vec![("NODE_EXTRA_CA_CERTS", ca.to_string_lossy().to_string())],
            _ => Vec::new(),
        };
        let spec = format!("npm:{pkg}");
        if let Err(detail) = self
            .deps
            .exec(
                &self.bin,
                &["plugins", "install", &spec],
                PLUGIN_INSTALL_TIMEOUT,
                None,
                &env,
            )
            .await
        {
            if !self.plugin_present(t).await {
                self.set_setup(t, Some(json!({ "state": "failed", "message": detail })));
                self.deps.log(&format!("[channels] installing {pkg} failed: {detail}"));
                return false;
            }
            self.deps.log(&format!("[channels] {pkg} was already on this box"));
        }
        if !self.trust_plugin(t, pkg).await {
            return false;
        }
        if let Err(e) = self.deps.restart().await {
            self.set_setup(t, Some(json!({ "state": "failed", "message": e })));
            self.deps
                .log(&format!("[channels] restart after installing {pkg} failed: {e}"));
            return false;
        }
        if !self.wait_for_gateway().await {
            self.set_setup(
                t,
                Some(json!({ "state": "failed", "message": "the agent did not come back after the restart" })),
            );
            self.deps
                .log(&format!("[channels] gateway did not return after installing {pkg}"));
            return false;
        }
        self.set_setup(t, None);
        self.deps.log(&format!("[channels] installed {pkg}"));
        true
    }

    async fn plugin_present(&self, t: &str) -> bool {
        match self
            .deps
            .exec(&self.bin, &["plugins", "list", "--json"], LIST_TIMEOUT, None, &[])
            .await
        {
            Ok(stdout) => {
                let Some(start) = stdout.find('{') else {
                    return false;
                };
                serde_json::from_str::<Value>(&stdout[start..])
                    .ok()
                    .and_then(|v| v.get("plugins").and_then(Value::as_array).cloned())
                    .is_some_and(|p| p.iter().any(|p| p.get("id") == Some(&json!(t))))
            }
            Err(e) => {
                self.deps.log(&format!(
                    "[channels] could not list the plugins: {}",
                    e.split('\n').next().unwrap_or_default()
                ));
                false
            }
        }
    }

    async fn trust_plugin(&self, t: &str, pkg: &str) -> bool {
        let patch = json!({ "plugins": { "entries": { t: { "enabled": true } } } });
        match self
            .patch_config(patch.as_object().cloned().unwrap_or_default(), Vec::new(), None)
            .await
        {
            Ok(()) => true,
            Err(e) => {
                self.set_setup(t, Some(json!({ "state": "failed", "message": e })));
                self.deps.log(&format!("[channels] trusting {pkg} failed: {e}"));
                false
            }
        }
    }

    async fn wait_for_gateway(&self) -> bool {
        let deadline = Instant::now() + GATEWAY_READY_TIMEOUT;
        while Instant::now() < deadline {
            if self.connected() {
                return true;
            }
            tokio::time::sleep(GATEWAY_POLL).await;
        }
        self.connected()
    }

    /// On every connect: install the plugin of any enabled channel that has none.
    pub fn reconcile(self: &Arc<Self>) -> cc_http::BoxFuture<()> {
        let me = self.clone();
        Box::pin(async move {
            let config = match me.config().await {
                Ok(c) => c,
                Err(e) => {
                    me.deps.log(&format!(
                        "[channels] could not read the config to reconcile plugins: {e}"
                    ));
                    return;
                }
            };
            for t in APPLY_CHANNELS {
                if plugin_of(t).is_none() || !bool_of(at(&config, &["channels", t, "enabled"])) {
                    continue;
                }
                if Self::plugin_installed(&config, t) {
                    continue;
                }
                me.deps.log(&format!(
                    "[channels] {t} is configured but its plugin is missing; installing it"
                ));
                // It runs on its own (spawned); nobody here waits for it.
                drop(me.ensure_plugin(t));
            }
        })
    }

    /// Deliver a text over one of the agent's channels, exactly as written.
    pub async fn send(&self, t: &str, to: &str, text_in: &str) -> Result<Value, String> {
        let (message, parse_mode) = exact_message(t, text_in);
        let mut params =
            json!({ "channel": t, "to": to, "idempotencyKey": uuid::Uuid::new_v4().to_string(), "message": message });
        if let Some(pm) = parse_mode {
            params["parseMode"] = json!(pm);
        }
        if let Err(e) = self.deps.call("send", params, Duration::from_secs(30)).await {
            if parse_mode.is_none() || !e.contains("parseMode") {
                return Err(e);
            }
            self.deps.log(&format!(
                "[channels] this OpenClaw did not take the exact form of a message on {t}; sent with its formatting characters taken out"
            ));
            let fallback = json!({ "channel": t, "to": to, "idempotencyKey": uuid::Uuid::new_v4().to_string(), "message": plain_fallback(text_in) });
            self.deps.call("send", fallback, Duration::from_secs(30)).await?;
        }
        self.deps.log(&format!("[channels] sent a message on {t}"));
        Ok(json!({ "ok": true }))
    }

    /// `openclaw pairing approve <channel> <code>`, idempotent on the code.
    pub async fn approve_pairing(&self, t: &str, code: &str) -> Result<Value, String> {
        let known = self
            .inner()
            .state
            .approved
            .iter()
            .find(|a| a.kind == t && a.code.as_deref() == Some(code))
            .cloned();
        if let Some(k) = known {
            self.deps.log(&format!(
                "[channels] {t} sender {} was already approved with this code",
                k.sender_id
            ));
            return Ok(json!({ "ok": true, "senderId": k.sender_id, "alreadyApproved": true }));
        }
        let before = match self.pairing_from_store(t, code).await {
            Some(p) => Some(p),
            None => self.lookup_pairing(t, code).await,
        };
        let q = QueueOptions {
            max_queue_wait: Some(APPROVE_QUEUE_WAIT),
            ..QueueOptions::default()
        };
        // A failed command is an error, so the queue moves on at once, as a rejected promise does.
        let run = || async {
            let cmd = cc_proc::Cmd::new(&self.bin)
                .args(["pairing", "approve", t, code])
                .timeout(APPROVE_TIMEOUT)
                .env("HOME", self.deps.home.to_string_lossy().to_string())
                .stdin(Vec::new());
            match self.deps.runner.run(cmd).await {
                Ok(o) if o.success() => Ok(o.stdout_str()),
                Ok(o) if !o.stderr.is_empty() => Err(o.stderr_str()),
                Ok(o) if !o.stdout.is_empty() => Err(o.stdout_str()),
                Ok(_) => Err(format!("Command failed: {} pairing approve {t} {code}", self.bin)),
                Err(e) => Err(e.to_string()),
            }
        };
        let out = match self.deps.client() {
            Some(w) => w.file_write(run, q).await,
            None => run().await,
        };
        let stdout = out.map_err(|raw| approve_failure(&raw))?;
        let approved_id = SENDER_RE
            .captures(&ANSI_RE.replace_all(&stdout, ""))
            .map(|c| c[1].to_string());
        self.forget_pairings();
        let sender = before.map(|b| b.sender_id).or(approved_id);
        if let Some(s) = &sender {
            self.record_approved(t, s, Some(code));
        }
        self.deps.log(&format!(
            "[channels] approved {t} sender {}",
            sender.as_deref().unwrap_or("?")
        ));
        Ok(json!({ "ok": true, "senderId": sender }))
    }

    async fn pairing_from_store(&self, t: &str, code: &str) -> Option<Pairing> {
        let r = self.db_pending(&[t]).await?;
        r.pairings.into_iter().find(|p| p.code == code).map(|p| Pairing {
            kind: t.into(),
            code: p.code,
            sender_id: p.sender_id,
            label: p.label,
            created_at: p.created_at,
        })
    }

    async fn lookup_pairing(&self, t: &str, code: &str) -> Option<Pairing> {
        let stdout = self
            .deps
            .exec(
                &self.bin,
                &["pairing", "list", t, "--json"],
                APPROVE_LOOKUP_TIMEOUT,
                None,
                &[],
            )
            .await
            .ok()?;
        parse_listing(t, &stdout).ok()?.into_iter().find(|p| p.code == code)
    }

    /// The WhatsApp link state, with stale states read as what they have become.
    pub fn whatsapp_login(&self) -> Value {
        let l = self.inner().wa.clone();
        let now = now_ms();
        if l.state == "qr" && now - l.at > WA_QR_STALE_MS {
            return json!({ "state": "expired", "qrDataUrl": null, "message": "The QR code expired. Start again." });
        }
        if l.state == "installing" && now - l.at > WA_INSTALL_STALE_MS {
            return json!({ "state": "failed", "qrDataUrl": null, "message": "Setting up WhatsApp took too long. Try again." });
        }
        if l.state != "idle" && l.state != "qr" && now - l.at > WA_RESULT_TTL_MS {
            return json!({ "state": "idle", "qrDataUrl": null, "message": null });
        }
        json!({ "state": l.state, "qrDataUrl": l.qr, "message": l.message })
    }

    fn set_wa(&self, state: &'static str, qr: Option<String>, message: Option<String>, personal: Option<bool>) {
        let mut i = self.inner();
        let personal = personal.unwrap_or(i.wa.personal);
        i.wa = WaLogin {
            state,
            qr,
            message,
            at: now_ms(),
            personal,
        };
    }

    /// Start the QR login (installing the plugin first when it is missing).
    pub async fn whatsapp_login_start(self: &Arc<Self>, personal: bool) -> Result<Value, String> {
        let config = self.config().await?;
        if !Self::plugin_installed(&config, "whatsapp") {
            self.set_wa(
                "installing",
                None,
                Some("Setting up WhatsApp on this agent…".into()),
                Some(personal),
            );
            let me = self.clone();
            tokio::spawn(async move { me.install_then_login(personal).await });
            return Ok(json!({ "ok": true, "state": "installing", "qrDataUrl": null }));
        }
        self.start_qr(personal).await
    }

    async fn start_qr(self: &Arc<Self>, personal: bool) -> Result<Value, String> {
        self.deps.gateway()?;
        let started = self
            .deps
            .call(
                "web.login.start",
                json!({ "force": true, "timeoutMs": WA_QR_TIMEOUT_MS }),
                Duration::from_secs(30),
            )
            .await?;
        let qr = started.get("qrDataUrl").and_then(Value::as_str).map(str::to_string);
        let msg = started.get("message").and_then(Value::as_str).map(str::to_string);
        self.set_wa("qr", qr.clone(), msg, Some(personal));
        let me = self.clone();
        tokio::spawn(async move { me.wait_for_whatsapp().await });
        Ok(json!({ "ok": true, "state": "qr", "qrDataUrl": qr }))
    }

    async fn install_then_login(self: &Arc<Self>, personal: bool) {
        if !self.ensure_plugin("whatsapp").await {
            let why = self
                .setup_message("whatsapp")
                .unwrap_or_else(|| "WhatsApp could not be set up on this agent".into());
            self.set_wa("failed", None, Some(why), None);
            return;
        }
        if let Err(e) = self.start_qr(personal).await {
            self.set_wa("failed", None, Some(e.clone()), None);
            self.deps.log(&format!("[channels] whatsapp setup failed: {e}"));
        }
    }

    async fn wait_for_whatsapp(self: &Arc<Self>) {
        let r = self
            .deps
            .call(
                "web.login.wait",
                json!({ "timeoutMs": WA_QR_TIMEOUT_MS }),
                Duration::from_millis(WA_QR_TIMEOUT_MS + 10_000),
            )
            .await;
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                self.set_wa("failed", None, Some(e.clone()), None);
                self.deps.log(&format!("[channels] whatsapp login failed: {e}"));
                return;
            }
        };
        if r.get("connected") != Some(&json!(true)) {
            let m = r
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Not scanned in time")
                .to_string();
            self.set_wa("expired", None, Some(m), None);
            return;
        }
        let me = match self.status(false).await {
            Ok(s) => text(at(&s, &["channels", "whatsapp", "self"])),
            Err(_) => None,
        };
        let personal = self.inner().wa.personal;
        let input = ApplyInput {
            apply_id: None,
            kind: "whatsapp".into(),
            what: ApplyKind::Whatsapp {
                personal,
                me: me.clone(),
            },
        };
        match self.apply(input).await {
            Ok(_) => {
                let m = match &me {
                    Some(n) => format!("Linked {n}"),
                    None => "Linked".into(),
                };
                self.set_wa("connected", None, Some(m), None);
            }
            Err(e) => {
                self.set_wa("failed", None, Some(e.0.clone()), None);
                self.deps.log(&format!("[channels] whatsapp login failed: {}", e.0));
            }
        }
    }
}

/// The approve's error: OpenClaw's "No pending pairing" in the console's words, else the last line.
fn approve_failure(raw: &str) -> String {
    let detail = raw.trim().split('\n').next_back().unwrap_or_default().to_string();
    if detail.contains("No pending pairing") {
        "That pairing request is gone. Ask the person to message the bot again.".into()
    } else {
        format!("pairing approve failed: {detail}")
    }
}

/// The body of `POST /channels/apply`, or the 400's text.
pub fn parse_apply(body: &Map<String, Value>, service: &ChannelsService) -> Result<ApplyInput, &'static str> {
    let Some(kind) = body
        .get("type")
        .and_then(Value::as_str)
        .filter(|t| APPLY_CHANNELS.contains(t))
    else {
        return Err("type must be telegram, slack, whatsapp or clickclack");
    };
    let empty = json!({});
    let secrets = match body.get("secrets") {
        Some(v) if !v.is_null() => v,
        _ => &empty,
    };
    let apply_id = body
        .get("applyId")
        .and_then(Value::as_str)
        .filter(|i| APPLY_ID_RE.is_match(i))
        .map(str::to_string);
    let what = if body.get("remove") == Some(&json!(true)) {
        ApplyKind::Remove
    } else if kind == "clickclack" {
        match service.clickclack_settings(body.get("settings")) {
            Some(s) => ApplyKind::ClickClack(s),
            None => return Err("invalid Team chat settings"),
        }
    } else if kind == "telegram" {
        let Some(t) = secrets.get("botToken").and_then(Value::as_str) else {
            return Err("botToken required");
        };
        ApplyKind::Telegram { bot_token: t.into() }
    } else if kind == "slack" {
        let (Some(b), Some(a)) = (
            secrets.get("botToken").and_then(Value::as_str),
            secrets.get("appToken").and_then(Value::as_str),
        ) else {
            return Err("botToken and appToken required");
        };
        ApplyKind::Slack {
            bot_token: b.into(),
            app_token: a.into(),
        }
    } else {
        let s = match body.get("settings") {
            Some(v) if !v.is_null() => v.clone(),
            _ => json!({}),
        };
        ApplyKind::Whatsapp {
            personal: s.get("personal") == Some(&json!(true)),
            me: s.get("self").and_then(Value::as_str).map(str::to_string),
        }
    };
    Ok(ApplyInput {
        apply_id,
        kind: kind.into(),
        what,
    })
}

/// `/channels/*`.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/channels/", move |req, _| {
        let app = app.clone();
        async move {
            let write = req.method() == Method::POST;
            let (parts, who) = caller(&app, req, "channels", BODY_LIMIT).await;
            let Some(who) = who else {
                let error = if write {
                    "channel changes must come from the org firewall"
                } else {
                    "Unauthorized"
                };
                return send_json(401, &json!({ "error": error }));
            };
            let firewall = matches!(who, Caller::Firewall(_));
            let Some(service) = app.contracts.platform.get().and_then(|p| p.channels.get().cloned()) else {
                return send_json(503, &json!({ "ok": false, "error": super::common::NOT_RUNNING }));
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            let get = parts.method == Method::GET;
            if path == "/channels/status" && get {
                return match service.status(firewall).await {
                    Ok(s) => send_json(200, &s),
                    Err(e) => fail(&e, None),
                };
            }
            if path == "/channels/approved" && get {
                if !firewall {
                    return send_json(
                        403,
                        &json!({ "error": "who this agent has approved is the org firewall's to read" }),
                    );
                }
                let allowed = service.allowed_by_agent().await;
                let approved: Vec<Value> = service.approved().await.iter().map(Approved::json).collect();
                return send_json(200, &json!({ "approved": approved, "allowedByAgent": allowed }));
            }
            if path == "/channels/whatsapp/login" && get {
                return send_json(200, &service.whatsapp_login());
            }
            if !write {
                return not_found();
            }
            let body = match who {
                Caller::Firewall(FirewallBody::Json(b)) => b,
                _ => return send_json(400, &json!({ "ok": false, "error": "Invalid JSON body" })),
            };
            let bad = |e: &str| send_json(400, &json!({ "ok": false, "error": e }));
            match path.as_str() {
                "/channels/apply" => {
                    let input = match parse_apply(&body, &service) {
                        Ok(i) => i,
                        Err(e) => return bad(e),
                    };
                    match service.apply(input).await {
                        Ok(v) => send_json(200, &v),
                        Err(e) => fail(&e.0, None),
                    }
                }
                "/channels/send" => {
                    let t = body
                        .get("type")
                        .and_then(Value::as_str)
                        .filter(|t| CHANNEL_TYPES.contains(t));
                    let to = body.get("to").and_then(Value::as_str).filter(|s| !s.is_empty());
                    let text_in = body.get("text").and_then(Value::as_str).filter(|s| !s.is_empty());
                    let (Some(t), Some(to), Some(text_in)) = (t, to, text_in) else {
                        return bad("type, to and text required");
                    };
                    match service.send(t, to, &js_slice(text_in, MESSAGE_TEXT_MAX)).await {
                        Ok(v) => send_json(200, &v),
                        Err(e) => fail(&e, None),
                    }
                }
                "/channels/pairings/approve" => {
                    let t = body
                        .get("type")
                        .and_then(Value::as_str)
                        .filter(|t| CHANNEL_TYPES.contains(t));
                    let code = body.get("code").and_then(Value::as_str).filter(|c| CODE_RE.is_match(c));
                    let (Some(t), Some(code)) = (t, code) else {
                        return bad("type and code required");
                    };
                    match service.approve_pairing(t, &code.to_uppercase()).await {
                        Ok(v) => send_json(200, &v),
                        Err(e) => fail(&e, None),
                    }
                }
                "/channels/whatsapp/login" => {
                    match service
                        .whatsapp_login_start(body.get("personal") == Some(&json!(true)))
                        .await
                    {
                        Ok(v) => send_json(200, &v),
                        Err(e) => fail(&e, None),
                    }
                }
                _ => not_found(),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    //! channels.test.ts and openclaw-allow's use here, at the service.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};
    use cc_proc::{Output, RecordingRunner};

    use super::super::llm::tests::rig;
    use super::*;

    struct T {
        oc: FakeOpenClawConfig,
        gw: Arc<FakeConfigGateway>,
        runner: RecordingRunner,
        restarts: Arc<AtomicUsize>,
        sends: Arc<Mutex<Vec<Value>>>,
        dir: tempfile::TempDir,
        svc: Arc<ChannelsService>,
    }

    fn status_payload() -> Value {
        json!({ "channels": {
            "telegram": { "configured": true, "running": true, "connected": true, "lastError": null },
            "whatsapp": { "configured": true, "running": false, "connected": false, "lastError": "logged out", "self": { "e164": "+3912345", "jid": null } },
        } })
    }

    fn setup(apply: Option<u64>, cli: impl Fn(&cc_proc::Cmd) -> Option<Output> + Send + Sync + 'static) -> T {
        let oc = FakeOpenClawConfig::new(
            json!({ "plugins": { "entries": {} }, "channels": {} }),
            apply.map(Duration::from_millis),
            false,
        );
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        let sends = Arc::new(Mutex::new(Vec::new()));
        let s = sends.clone();
        gw.hook(move |m, p| match m {
            "channels.status" => Some(Ok(status_payload())),
            "send" => {
                lock(&s).push(p.clone());
                Some(Ok(json!({ "ok": true })))
            }
            "web.login.start" => Some(Ok(
                json!({ "qrDataUrl": "data:image/png;base64,QR", "message": "scan" }),
            )),
            "web.login.wait" => Some(Ok(json!({ "connected": true }))),
            _ => None,
        });
        let mut r = rig(gw.clone());
        let runner = RecordingRunner::new();
        runner.answer_with(cli);
        r.deps.runner = Arc::new(runner.clone());
        let dir = tempfile::tempdir().expect("dir");
        let mut svc = ChannelsService::new(
            r.deps.clone(),
            dir.path().join("credentials"),
            Some(dir.path().join("channels.json")),
            Some(dir.path().join("openclaw.sqlite")),
            None,
            Arc::new(|| Some("10.0.0.2".into())),
        );
        svc.apply_inline_wait = Duration::from_millis(80);
        T {
            oc,
            gw,
            runner,
            restarts: r.restarts.clone(),
            sends,
            dir,
            svc: Arc::new(svc),
        }
    }

    /// Every command succeeds; a listing finds nobody.
    fn ok_cli() -> impl Fn(&cc_proc::Cmd) -> Option<Output> + Send + Sync + 'static {
        |_| Some(cc_proc::ok("{}"))
    }

    /// `ok_cli`, with OpenClaw's unit stopped.
    fn stopped_cli() -> impl Fn(&cc_proc::Cmd) -> Option<Output> + Send + Sync + 'static {
        |c| {
            Some(cc_proc::ok(if c.program == "systemctl" {
                "LoadState=loaded\nUnitFileState=enabled\nActiveState=inactive\n"
            } else {
                "{}"
            }))
        }
    }

    fn input(v: Value, t: &T) -> ApplyInput {
        parse_apply(v.as_object().expect("o"), &t.svc).expect("valid")
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    fn args(t: &T) -> Vec<Vec<String>> {
        t.runner.calls().into_iter().map(|c| c.args).collect()
    }

    #[test]
    fn channel_blocks_match_openclaws_keys() {
        let b = |what: ApplyKind| {
            channel_block(&ApplyInput {
                apply_id: None,
                kind: "x".into(),
                what,
            })
        };
        assert_eq!(
            b(ApplyKind::Telegram { bot_token: "t".into() }),
            Some(json!({ "enabled": true, "botToken": "t", "dmPolicy": "pairing" }))
        );
        assert_eq!(
            b(ApplyKind::Slack {
                bot_token: "b".into(),
                app_token: "a".into()
            }),
            Some(json!({ "enabled": true, "mode": "socket", "botToken": "b", "appToken": "a", "dmPolicy": "pairing" }))
        );
        assert_eq!(
            b(ApplyKind::Whatsapp {
                personal: true,
                me: Some("+391".into())
            }),
            Some(json!({ "enabled": true, "dmPolicy": "allowlist", "allowFrom": ["+391"], "selfChatMode": true }))
        );
        assert_eq!(
            b(ApplyKind::Whatsapp {
                personal: false,
                me: None
            }),
            Some(json!({ "enabled": true, "dmPolicy": "pairing" }))
        );
        assert_eq!(
            b(ApplyKind::Whatsapp {
                personal: true,
                me: Some(String::new())
            }),
            Some(json!({ "enabled": true, "dmPolicy": "pairing" })),
            "an empty number allowlists nobody: the pairing block instead"
        );
        assert_eq!(b(ApplyKind::Remove), None);
    }

    #[test]
    fn channel_status_old_and_2026_9_shapes() {
        let old = json!({ "channels": {
            "slack": { "configured": true, "running": true, "connected": true, "lastError": null },
            "whatsapp": { "configured": true, "running": false, "connected": false, "lastError": "logged out", "self": { "e164": "+3912345", "jid": null } },
        } });
        assert_eq!(
            Value::Object(channel_status_from("slack", &old).expect("s")),
            json!({ "configured": true, "running": true, "connected": true, "lastError": null })
        );
        assert_eq!(
            Value::Object(channel_status_from("whatsapp", &old).expect("w")),
            json!({ "configured": true, "running": false, "connected": false, "lastError": "logged out", "self": "+3912345" })
        );
        assert_eq!(channel_status_from("telegram", &old), None);
        let mut p = json!({
            "channels": { "slack": { "configured": true, "running": true, "lastError": null } },
            "channelAccounts": { "slack": [{ "accountId": "default", "enabled": true, "connected": true, "lastError": null }] },
            "channelDefaultAccountId": { "slack": "default" },
        });
        assert_eq!(channel_status_from("slack", &p).expect("s")["connected"], json!(true));
        p["channelAccounts"]["slack"][0]["connected"] = json!(false);
        p["channelAccounts"]["slack"][0]["lastError"] = json!("invalid_auth");
        assert_eq!(
            channel_status_from("slack", &p).expect("s")["lastError"],
            json!("invalid_auth")
        );
        p["channels"]["slack"]["lastError"] = json!("socket closed");
        assert_eq!(
            channel_status_from("slack", &p).expect("s")["lastError"],
            json!("socket closed")
        );
        p["channelDefaultAccountId"] = json!({ "slack": "missing" });
        p["channelAccounts"] = json!({ "slack": [
            { "accountId": "off", "enabled": false, "connected": true, "lastError": "x" },
            { "accountId": "work", "enabled": true, "connected": true, "lastError": null },
        ] });
        p["channels"]["slack"]["lastError"] = Value::Null;
        assert_eq!(channel_status_from("slack", &p).expect("s")["connected"], json!(true));
        p["channelAccounts"] =
            json!({ "slack": [{ "accountId": "off", "enabled": false, "connected": true, "lastError": "x" }] });
        assert_eq!(
            channel_status_from("slack", &p).expect("s")["lastError"],
            Value::Null,
            "a disabled account does not count"
        );
        let wa = json!({
            "channels": { "whatsapp": { "configured": true, "running": true, "lastError": null } },
            "channelAccounts": { "whatsapp": [{ "accountId": "default", "enabled": true, "connected": true, "self": { "e164": null, "jid": "3912345@s.whatsapp.net" } }] },
            "channelDefaultAccountId": { "whatsapp": "default" },
        });
        assert_eq!(
            channel_status_from("whatsapp", &wa).expect("w")["self"],
            json!("3912345@s.whatsapp.net")
        );
    }

    #[test]
    fn messages_are_read_exactly_as_written() {
        assert_eq!(
            exact_message("telegram", "a <b> & _c_"),
            ("a &lt;b&gt; &amp; _c_".into(), Some("HTML"))
        );
        assert_eq!(
            exact_message("whatsapp", "x ```y``` z"),
            ("```\nx '''y''' z\n```".into(), None)
        );
        assert_eq!(
            exact_message("slack", "<!channel> hi"),
            ("```\n\u{2039}!channel\u{203A} hi\n```".into(), None)
        );
        assert_eq!(plain_fallback("a_*b*  [c](d) & e"), "a b c (d) e");
    }

    #[test]
    fn team_chat_settings_only_on_this_boxs_own_gate() {
        let ok = json!({ "baseUrl": "https://chat.example.com", "apiBaseUrl": "http://10.0.0.2:3930", "token": format!("cctc_{}", "a".repeat(24)), "workspace": "wsp_abcdefgh", "botUserId": "usr_abcdefgh", "peers": ["usr_peer0001", "usr_peer0001"] });
        let s = parse_clickclack(Some(&ok), Some("10.0.0.2")).expect("ok");
        assert_eq!(s.peers, ["usr_peer0001"]);
        assert_eq!(
            parse_clickclack(Some(&ok), Some("10.0.0.3")),
            None,
            "another firewall's gate"
        );
        assert_eq!(parse_clickclack(Some(&ok), None), None);
        for (k, v) in [
            ("token", json!("real-token")),
            ("baseUrl", json!("http://chat.example.com")),
            ("workspace", json!("w")),
            ("botUserId", json!("bot")),
            ("peers", json!("x")),
        ] {
            let mut b = ok.clone();
            b[k] = v;
            assert_eq!(parse_clickclack(Some(&b), Some("10.0.0.2")), None, "{k}");
        }
        let block = channel_block(&ApplyInput {
            apply_id: None,
            kind: "clickclack".into(),
            what: ApplyKind::ClickClack(s),
        })
        .expect("b");
        assert_eq!(block["allowFrom"], json!(["*", "usr_peer0001"]));
        assert_eq!(block["allowBots"], json!("mentions"));
        assert_eq!(block["requireMention"], json!(true));
    }

    #[tokio::test]
    async fn apply_writes_the_block_and_telegram_installs_nothing() {
        let t = setup(None, ok_cli());
        let r = t
            .svc
            .apply(input(
                json!({ "type": "telegram", "secrets": { "botToken": "123:abc" } }),
                &t,
            ))
            .await
            .expect("ok");
        assert_eq!(r["status"], "applied");
        assert_eq!(r["message"], "applied telegram");
        assert_eq!(
            t.oc.config()["channels"]["telegram"],
            json!({ "enabled": true, "botToken": "123:abc", "dmPolicy": "pairing" })
        );
        settle().await;
        assert!(args(&t).is_empty(), "telegram is built in");
    }

    #[tokio::test]
    async fn an_apply_that_outlives_the_wait_answers_pending_and_still_lands() {
        let t = setup(Some(300), ok_cli());
        let r = t
            .svc
            .apply(input(
                json!({ "type": "telegram", "secrets": { "botToken": "123:abc" }, "applyId": "apply-1" }),
                &t,
            ))
            .await
            .expect("ok");
        assert_eq!(r["status"], "pending");
        assert_eq!(r["applyId"], "apply-1");
        assert_eq!(
            t.svc.status(false).await.expect("s")["channels"]["telegram"]["lastApply"]["state"],
            "pending"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        let rec = t.svc.status(false).await.expect("s")["channels"]["telegram"]["lastApply"].clone();
        assert_eq!(
            (rec["id"].clone(), rec["state"].clone(), rec["what"].clone()),
            (json!("apply-1"), json!("applied"), json!("apply"))
        );
    }

    #[tokio::test]
    async fn a_write_that_fails_in_time_is_a_500_and_recorded() {
        let t = setup(None, ok_cli());
        t.gw.hook(|m, _| (m == "config.patch").then(|| Err("Error: EACCES".to_string())));
        let e = t
            .svc
            .apply(input(
                json!({ "type": "slack", "secrets": { "botToken": "b", "appToken": "a" }, "applyId": "apply-3" }),
                &t,
            ))
            .await
            .expect_err("fails");
        assert!(e.0.contains("EACCES"));
        t.gw.hook(|m, _| (m == "channels.status").then(|| Ok(status_payload())));
        let rec = t.svc.status(false).await.expect("s")["channels"]["slack"]["lastApply"].clone();
        assert_eq!(
            (rec["id"].clone(), rec["state"].clone()),
            (json!("apply-3"), json!("failed"))
        );
    }

    #[tokio::test]
    async fn slack_is_patched_first_then_its_plugin_installed_trusted_and_restarted() {
        let t = setup(None, ok_cli());
        t.svc
            .apply(input(
                json!({ "type": "slack", "secrets": { "botToken": "xoxb-1", "appToken": "xapp-1" } }),
                &t,
            ))
            .await
            .expect("ok");
        settle().await;
        assert!(args(&t).contains(&vec![
            "plugins".to_string(),
            "install".into(),
            "npm:@openclaw/slack".into()
        ]));
        assert_eq!(
            t.oc.config()["plugins"]["entries"]["slack"],
            json!({ "enabled": true }),
            "trusted"
        );
        assert_eq!(t.restarts.load(Ordering::SeqCst), 1);
        // Already installed: left alone.
        let before = args(&t).len();
        t.svc.reconcile().await;
        settle().await;
        assert_eq!(args(&t).len(), before);
    }

    #[tokio::test]
    async fn a_failed_install_is_reported_and_trusts_nothing() {
        let t = setup(None, |c| {
            Some(match c.args.get(1).map(String::as_str) {
                Some("install") => Output {
                    code: Some(1),
                    stderr: b"npm ERR! 404".to_vec(),
                    ..Default::default()
                },
                _ => cc_proc::ok("{\"plugins\":[]}"),
            })
        });
        t.svc
            .apply(input(
                json!({ "type": "slack", "secrets": { "botToken": "b", "appToken": "a" } }),
                &t,
            ))
            .await
            .expect("ok");
        settle().await;
        let s = t.svc.status(false).await.expect("s");
        assert_eq!(
            s["channels"]["slack"]["setup"],
            json!({ "state": "failed", "message": "npm ERR! 404" })
        );
        assert_eq!(t.oc.config()["plugins"]["entries"].get("slack"), None);
        assert_eq!(t.restarts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn remove_patches_null_never_installs_and_forgets_the_approved() {
        let t = setup(None, |_| Some(cc_proc::ok("Approved telegram sender 8734062810.\n")));
        t.svc.approve_pairing("telegram", "K7PQ2XZ9").await.expect("ok");
        assert_eq!(t.svc.approved().await.len(), 1);
        t.svc
            .apply(input(json!({ "type": "telegram", "remove": true }), &t))
            .await
            .expect("ok");
        settle().await;
        assert_eq!(t.oc.config()["channels"].get("telegram"), None);
        assert!(t.svc.approved().await.is_empty());
        assert!(
            !args(&t)
                .iter()
                .any(|a| a.first().map(String::as_str) == Some("plugins"))
        );
    }

    #[tokio::test]
    async fn send_is_exact_and_falls_back_when_the_parse_mode_is_unknown() {
        let t = setup(None, ok_cli());
        t.svc.send("telegram", "8734", "Code: <b>").await.expect("ok");
        let sent = lock(&t.sends)[0].clone();
        assert_eq!(sent["message"], "Code: &lt;b&gt;");
        assert_eq!(sent["parseMode"], "HTML");
        assert!(sent["idempotencyKey"].is_string());
        let s = t.sends.clone();
        let refused = Arc::new(AtomicBool::new(false));
        let r = refused.clone();
        t.gw.hook(move |m, p| {
            (m == "send").then(|| {
                if p.get("parseMode").is_some() {
                    r.store(true, Ordering::SeqCst);
                    Err("unknown parameter parseMode".to_string())
                } else {
                    lock(&s).push(p.clone());
                    Ok(json!({ "ok": true }))
                }
            })
        });
        t.svc.send("telegram", "8734", "a_b *c*").await.expect("ok");
        assert!(refused.load(Ordering::SeqCst));
        assert_eq!(lock(&t.sends).last().expect("s")["message"], "a b c ");
    }

    #[tokio::test]
    async fn approve_runs_the_cli_records_the_sender_and_is_idempotent_on_the_code() {
        let t = setup(None, |c| {
            Some(if c.args[1] == "approve" {
                cc_proc::ok("\x1b[32mApproved telegram sender 8734062810.\x1b[0m\n")
            } else {
                cc_proc::ok("{\"requests\":[]}")
            })
        });
        let r = t.svc.approve_pairing("telegram", "K7PQ2XZ9").await.expect("ok");
        assert_eq!(r, json!({ "ok": true, "senderId": "8734062810" }));
        let saved: Value =
            serde_json::from_str(&std::fs::read_to_string(t.dir.path().join("channels.json")).expect("f")).expect("j");
        assert_eq!(saved["approved"][0]["senderId"], "8734062810");
        assert_eq!(saved["approved"][0]["code"], "K7PQ2XZ9");
        let calls = args(&t).len();
        let again = t.svc.approve_pairing("telegram", "K7PQ2XZ9").await.expect("ok");
        assert_eq!(again["alreadyApproved"], json!(true));
        assert_eq!(args(&t).len(), calls, "the CLI did not run again");
    }

    #[tokio::test]
    async fn a_gone_request_reads_in_the_consoles_words() {
        let t = setup(None, |c| {
            Some(if c.args[1] == "approve" {
                Output {
                    code: Some(1),
                    stderr: b"Error: No pending pairing for code X\n".to_vec(),
                    ..Default::default()
                }
            } else {
                cc_proc::ok("{}")
            })
        });
        let e = t.svc.approve_pairing("telegram", "ABCD").await.expect_err("gone");
        assert_eq!(
            e,
            "That pairing request is gone. Ask the person to message the bot again."
        );
    }

    #[tokio::test]
    async fn pending_requests_come_from_the_store_with_no_cli() {
        let t = setup(None, ok_cli());
        super::super::allow::tests::db(
            t.dir.path(),
            &[("telegram", "default", "111", 1_760_000_000_000)],
            &[(
                "telegram",
                "8734",
                "K7PQ2XZ9",
                "2026-09-16T10:00:00.000Z",
                r#"{"name":"Test Person"}"#,
            )],
        );
        std::fs::create_dir_all(t.dir.path().join("credentials")).expect("d");
        std::fs::write(t.dir.path().join("credentials/whatsapp-pairing.json"), r#"{"requests":[{"id":"+391234","code":"LEGACY01","meta":{"name":"Old"},"createdAt":"2026-09-16T09:00:00Z"}]}"#).expect("w");
        let s = t.svc.status(false).await.expect("s");
        assert_eq!(s["channels"]["whatsapp"]["self"], "+3912345");
        assert_eq!(
            s["pairings"],
            json!([
                { "type": "telegram", "code": "K7PQ2XZ9", "senderId": "8734", "label": "Test Person", "createdAt": "2026-09-16T10:00:00.000Z" },
                { "type": "whatsapp", "code": "LEGACY01", "senderId": "+391234", "label": "Old", "createdAt": "2026-09-16T09:00:00Z" },
            ])
        );
        assert!(args(&t).is_empty());
        assert_eq!(s["whatsappLogin"], Value::Null);
        let allowed = t.svc.allowed_by_agent().await;
        assert_eq!(allowed["senders"][0]["senderId"], "111");
        assert_eq!(allowed["error"], Value::Null);
    }

    #[tokio::test]
    async fn an_older_openclaw_lists_through_the_cli_and_a_failing_list_says_so() {
        let t = setup(None, |c| {
            Some(if c.args.get(2).map(String::as_str) == Some("telegram") {
                cc_proc::ok("log\n{\"requests\":[{\"id\":\"9\",\"code\":\"ZZZZ\"}]}")
            } else {
                Output {
                    code: Some(1),
                    stderr: b"boom: something broke".to_vec(),
                    ..Default::default()
                }
            })
        });
        let (p, e) = t.svc.pairings_read(&["telegram"]).await;
        assert_eq!(p[0].sender_id, "9");
        assert_eq!(e, None);
        let (_, e) = t.svc.pairings_read(&["slack"]).await;
        let e = e.expect("error");
        assert!(!e.busy);
        assert_eq!(
            e.message,
            "The agent could not list who is waiting on slack: boom: something broke"
        );
        assert_eq!(
            args(&t)
                .iter()
                .filter(|a| a.get(2).map(String::as_str) == Some("slack"))
                .count(),
            3,
            "tried three times"
        );
    }

    #[tokio::test]
    async fn overlapping_polls_share_one_read() {
        let n = Arc::new(AtomicUsize::new(0));
        let m = n.clone();
        let t = setup(None, move |_| {
            m.fetch_add(1, Ordering::SeqCst);
            Some(cc_proc::ok("{\"requests\":[]}"))
        });
        let (a, b) = tokio::join!(t.svc.pairings_read(&["telegram"]), t.svc.pairings_read(&["telegram"]));
        assert_eq!(a, b);
        t.svc.pairings_read(&["telegram"]).await;
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn whatsapp_login_starts_the_qr_and_writes_the_block_on_connect() {
        let t = setup(None, ok_cli());
        // The plugin is there.
        t.oc.external_write(
            json!({ "plugins": { "entries": { "whatsapp": { "enabled": true } } } }),
            Duration::ZERO,
        );
        let r = t.svc.whatsapp_login_start(true).await.expect("ok");
        assert_eq!(
            r,
            json!({ "ok": true, "state": "qr", "qrDataUrl": "data:image/png;base64,QR" })
        );
        settle().await;
        assert_eq!(t.svc.whatsapp_login()["state"], "connected");
        assert_eq!(t.svc.whatsapp_login()["message"], "Linked +3912345");
        assert_eq!(
            t.oc.config()["channels"]["whatsapp"],
            json!({ "enabled": true, "dmPolicy": "allowlist", "allowFrom": ["+3912345"], "selfChatMode": true })
        );
    }

    #[tokio::test]
    async fn without_a_gateway_it_is_not_running_but_the_last_record_survives() {
        let t = setup(Some(300), stopped_cli());
        t.svc
            .apply(input(
                json!({ "type": "telegram", "secrets": { "botToken": "x" }, "applyId": "a1" }),
                &t,
            ))
            .await
            .expect("ok");
        t.gw.set_connected(false);
        let e = t
            .svc
            .apply(input(json!({ "type": "telegram", "secrets": { "botToken": "x" } }), &t))
            .await
            .expect_err("down");
        assert_eq!(e.0, "OpenClaw is not running on this box");
        let s = t.svc.status(false).await.expect("status answers without a gateway");
        assert_eq!(s["channels"]["telegram"]["lastApply"]["id"], "a1");
    }

    #[tokio::test]
    async fn a_write_waits_for_a_gateway_that_is_restarting_but_not_for_a_stopped_one() {
        let mut t = setup(Some(10), ok_cli());
        let svc = Arc::get_mut(&mut t.svc).expect("one owner");
        svc.gateway_wait = Duration::from_secs(5);
        svc.apply_inline_wait = Duration::from_secs(3);
        t.gw.set_connected(false);
        let gw = t.gw.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            gw.set_connected(true);
        });
        let r = t
            .svc
            .apply(input(json!({ "type": "telegram", "secrets": { "botToken": "x" } }), &t))
            .await
            .expect("applied once the gateway is back");
        assert_eq!(r["status"], "applied");

        // A unit that is stopped is refused at once, as before.
        let mut t = setup(Some(10), stopped_cli());
        let svc = Arc::get_mut(&mut t.svc).expect("one owner");
        svc.gateway_wait = Duration::from_secs(5);
        t.gw.set_connected(false);
        let started = Instant::now();
        let e = t
            .svc
            .apply(input(json!({ "type": "telegram", "secrets": { "botToken": "x" } }), &t))
            .await
            .expect_err("down");
        assert_eq!(e.0, "OpenClaw is not running on this box");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn an_owner_approved_before_records_is_read_out_of_the_config_once() {
        let t = setup(None, ok_cli());
        t.oc.external_write(json!({ "channels": { "telegram": { "enabled": true } }, "commands": { "ownerAllowFrom": ["telegram:8734", "slack:U1"] } }), Duration::ZERO);
        let a = t.svc.approved().await;
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].kind.as_str(), a[0].sender_id.as_str(), a[0].code.clone()),
            ("telegram", "8734", None)
        );
    }

    #[test]
    fn bad_apply_bodies() {
        let t = setup(None, ok_cli());
        let p = |v: Value| parse_apply(v.as_object().expect("o"), &t.svc).err();
        assert_eq!(
            p(json!({ "type": "irc" })),
            Some("type must be telegram, slack, whatsapp or clickclack")
        );
        assert_eq!(p(json!({ "type": "telegram" })), Some("botToken required"));
        assert_eq!(
            p(json!({ "type": "slack", "secrets": { "botToken": "b" } })),
            Some("botToken and appToken required")
        );
        assert_eq!(
            p(json!({ "type": "clickclack", "settings": {} })),
            Some("invalid Team chat settings")
        );
        let i = parse_apply(
            json!({ "type": "telegram", "secrets": { "botToken": "t" }, "applyId": "bad id!" })
                .as_object()
                .expect("o"),
            &t.svc,
        )
        .expect("ok");
        assert_eq!(i.apply_id, None, "an id that is not clean is dropped, not refused");
    }
}
