//! Content rules on the firewall (`content-rules.ts`, docs/plans/firewall-content-rules.md): what an
//! organization says its agents may not send or receive, checked on the text of each message by the
//! proxy. This module owns the rules and the two things the proxy cannot do on its own: keeping a
//! held message until a person decides, and telling the person in the chat.
//!
//! - The rules live here, encrypted, and nowhere else. The console reads them with `rules.read`, and
//!   **every** change is a `rules.propose` held for a confirmation code this firewall sends itself: a
//!   rule's reason reaches the agent, so a rule the control plane could set alone would be a way to
//!   talk to it. After a confirmed change the enabled rules are written to the file the proxy reads;
//!   nothing else writes that file.
//! - "Leaking secrets" is not here. It ships in the proxy and cannot be changed from the console.
//! - A held message (`/hold` on loopback) is kept in memory, never on disk: a restart drops it, which
//!   means it is not sent. The people on "Who gets confirmation codes" get the firewall's own message
//!   with Send and Don't send; Send delivers it with the bot's real token.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};
use std::time::Duration;

use base64::Engine;
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::schema::{CONTENT_RULES_MAX, ContentChange, ContentRule, parse_change, parse_rule};
use super::stopped::{ContentStoppedStore, NewStopped, RuleBrief};
use crate::channels::ai::judge::{AiPin, ContentAnswer, ContentAsk, pin_for, pin_matches, policy_model_allowed};
use crate::channels::ai::model::AiIdentity;
use crate::channels::chan::buttons::{
    CodeButtons, DecisionInput, DecisionLines, TapOwner, TapVerdict, TelegramButtonsRoute,
};
use crate::channels::content_engine::{
    CONTENT_CHANNELS, CORE_SECRETS_RULE, EngineRule, Judged, content_applies, content_text_max, evaluate,
    policies_to_ask, text_length, with_policies,
};
use crate::channels::js::{js_len, js_slice};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRoute, CodeSender, CodeSent, ContentError, ModuleCodes};
use crate::core::code_message::{CodeParts, Details, TypedLine, clean_line};

pub const CODE_SCOPE: &str = "content-rules";
pub const HOLD_TTL_MS: i64 = 24 * 3_600_000;
/// How long asking the people who get codes may take; the proxy waits 25 s for the answer.
pub const HOLD_ASK_MS: u64 = 15_000;
const HOLDS_MAX: usize = 50;
const NOTICE_GAP_MS: i64 = 60_000;
/// A read the agent repeats is recorded once in this long (`record`'s `once`).
const AUDIT_ONCE_MS: i64 = 3_600_000;
const TELEGRAM_API: &str = "https://api.telegram.org";
const SLACK_API: &str = "https://slack.com/api";
const AGENTMAIL_API: &str = "https://api.agentmail.to";
const POST_TIMEOUT: Duration = Duration::from_secs(15);
/// The methods a held message may be sent with: the ones the proxy holds.
const HOLD_METHODS: &[&str] = &[
    "sendMessage",
    "editMessageText",
    "editMessageCaption",
    "sendPhoto",
    "sendDocument",
    "sendVideo",
    "sendAudio",
    "sendAnimation",
    "sendVoice",
    "sendMediaGroup",
];

static CHAT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(-?\d{1,20}|@[A-Za-z0-9_]{4,32})$").expect("regex"));
static SLACK_CHANNEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Z0-9]{2,40}|#?[a-z0-9._-]{1,80})$").expect("regex"));
/// The AgentMail calls a held email may be sent with: a send, a reply, a reply to all, a forward.
static AGENTMAIL_SEND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/v0/inboxes/([^/]+)/messages/(?:send|[^/]+/(?:reply|reply-all|forward))$").expect("regex")
});
static BOT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{1,20}$").expect("regex"));
static HOLD_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{32}$").expect("regex"));
static STOPPED_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,40}$").expect("regex"));
static SLACK_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z0-9]{2,40}$").expect("regex"));
static THREAD_TS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{1,12}\.\d{1,8}$").expect("regex"));
static FINGERPRINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{16}$").expect("regex"));

fn channel_word(c: &str) -> &'static str {
    match c {
        "telegram" => "Telegram",
        "slack" => "Slack",
        "email" => "email",
        "web" => "website requests",
        "webhook" => "webhooks",
        "teamchat" => "team chat",
        "voice" => "meetings and calls",
        "apps" => "app actions",
        _ => "",
    }
}

/// "Telegram, Slack and email".
pub fn channel_words(channels: &[String]) -> String {
    let words: Vec<&str> = channels.iter().map(|c| channel_word(c)).collect();
    match words.split_last() {
        None => String::new(),
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

fn detector_words(d: &str) -> &'static str {
    match d {
        "secrets" => "passwords, keys and tokens",
        "iban" => "bank account numbers (IBAN)",
        "card" => "card numbers",
        "emails" => "five or more e-mail addresses",
        _ => "",
    }
}

/// The id of a line `once` names: the same every hour, as the proxy's (`_content_audit`).
pub fn audit_once_id(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))[..24].to_string()
}

/// The firewall's own words for the policies' model and key: facts it read itself, never console text.
pub fn ai_pin_words(pin: &AiPin) -> String {
    let provider = pin.provider.as_str();
    let place = match provider {
        "controlclaw_included" => "the plan's included AI tokens".to_string(),
        "vercel_gateway" => "your Vercel AI Gateway key".to_string(),
        p => format!("your {p} key"),
    };
    let fp = pin
        .key_fingerprint
        .as_deref()
        .filter(|f| !f.is_empty())
        .map(|f| format!(" (key fingerprint {})", &f[..f.len().min(8)]))
        .unwrap_or_default();
    format!("{} on {place}{fp}", pin.model)
}

pub(crate) fn pin_json(pin: &AiPin) -> Value {
    json!({"provider": pin.provider.as_str(), "model": pin.model, "keyFingerprint": pin.key_fingerprint})
}

fn parse_pin(v: &Value) -> Option<AiPin> {
    let m = v.as_object()?;
    let provider = cc_llm::Provider::parse(m.get("provider")?.as_str()?)?;
    let model = m.get("model")?.as_str().filter(|s| js_len(s) <= 200)?.to_string();
    let key_fingerprint = match m.get("keyFingerprint")? {
        Value::Null => None,
        Value::String(s) if FINGERPRINT.is_match(s) => Some(s.clone()),
        _ => return None,
    };
    Some(AiPin {
        provider,
        model,
        key_fingerprint,
    })
}

/// The words of a rule for the code message: the first few and a count, so a rule with fifty long
/// phrases still fits one Telegram message (the console shows them all).
pub fn words_summary(patterns: &[String]) -> String {
    const SHOWN: usize = 8;
    const CHARS: usize = 200;
    let mut shown: Vec<&str> = Vec::new();
    let mut length = 0;
    for p in patterns {
        if shown.len() >= SHOWN || length + js_len(p) > CHARS {
            break;
        }
        shown.push(p);
        length += js_len(p) + 2;
    }
    let rest = patterns.len() - shown.len();
    let more = if rest > 0 {
        format!(" and {rest} more")
    } else {
        String::new()
    };
    format!("{}{more} ({} in all)", shown.join(", "), patterns.len())
}

fn typed(label: &str, text: &str) -> TypedLine {
    TypedLine {
        label: label.into(),
        text: text.into(),
        more: None,
    }
}

/// The firewall's own sentence for a change, from fixed words and the rule's enums only.
pub fn describe_content_change(change: &ContentChange, before: &[ContentRule], ai: Option<&AiPin>) -> CodeParts {
    let pinned = ai
        .map(|p| format!(" Your content rules' AI checks will use {}.", ai_pin_words(p)))
        .unwrap_or_default();
    let parts = |ask: String, details: String, typed: Vec<TypedLine>| CodeParts {
        ask,
        details: Some(Details::Text(details)),
        typed,
        outro: None,
    };
    match change {
        ContentChange::Ai => parts(
            format!(
                "Confirm to let your rules' AI checks (Messages and Integrations) use {}.",
                ai.map_or("the AI review's model".to_string(), ai_pin_words)
            ),
            "The AI reads the messages and the integration calls your rules' sentences cover, and says what MCP tools do when their server does not. Ignore this if you did not change the AI review.".into(),
            vec![],
        ),
        ContentChange::Delete(id) => parts(
            "Confirm to delete one of your content rules.".into(),
            format!("Your agents' messages will no longer be checked against it.{pinned}"),
            before
                .iter()
                .find(|r| r.id == *id)
                .map(|old| vec![typed("Rule", &old.name)])
                .unwrap_or_default(),
        ),
        ContentChange::Put(r) => {
            let exists = before.iter().any(|x| x.id == r.id);
            let what = match r.action.as_str() {
                "block" => "stops",
                "hold" => "holds for approval",
                _ => "only records",
            };
            let which = match r.direction.as_str() {
                "out" => "messages from your agents",
                "in" => "messages to your agents",
                _ => "messages to and from your agents",
            };
            let n = r.patterns.len();
            let mut looks: Vec<String> = Vec::new();
            if r.policy.is_some() {
                looks.push("its policy, judged by the AI".into());
            }
            if n > 0 {
                let s = if n == 1 { "" } else { "s" };
                looks.push(format!("{n} word{s} or phrase{s}"));
            }
            looks.extend(r.detectors.iter().map(|d| detector_words(d).to_string()));
            let mut t = vec![typed("Rule", &r.name)];
            // The sentence the firewall's model is given: whoever approves sees exactly what it is told.
            if let Some(p) = &r.policy {
                t.push(typed("Policy", p));
            }
            t.push(typed("Reason", &r.reason));
            if n > 0 {
                t.push(typed("Words", &words_summary(&r.patterns)));
            }
            parts(
                format!(
                    "Confirm to {} a content rule that {what} {which} on {}{}.",
                    if exists { "change" } else { "add" },
                    channel_words(&r.channels),
                    if r.enabled { "" } else { " (turned off)" }
                ),
                format!(
                    "It looks for: {}. The reason below is shown to the agent and the people in the chat.{pinned}",
                    looks.join(", ")
                ),
                t,
            )
        }
    }
}

pub fn apply_content_change(rules: &[ContentRule], change: &ContentChange) -> Result<Vec<ContentRule>, &'static str> {
    match change {
        ContentChange::Ai => Ok(rules.to_vec()),
        ContentChange::Delete(id) => {
            if !rules.iter().any(|r| r.id == *id) {
                return Err("no such rule");
            }
            Ok(rules.iter().filter(|r| r.id != *id).cloned().collect())
        }
        ContentChange::Put(rule) => {
            let i = rules.iter().position(|r| r.id == rule.id);
            if i.is_none() && rules.len() >= CONTENT_RULES_MAX {
                return Err("too many rules");
            }
            Ok(match i {
                None => rules.iter().cloned().chain([rule.clone()]).collect(),
                Some(i) => rules
                    .iter()
                    .enumerate()
                    .map(|(j, r)| if j == i { rule.clone() } else { r.clone() })
                    .collect(),
            })
        }
    }
}

/// A line of the audit file as the console's Activity takes it: source `content_rule`, metadata
/// only. `None` for a line that is not a rule acting on a message (a rule changed) or has no id.
/// `name_of` gives the rule's name as it is now.
pub fn content_rule_activity(line: &Value, name_of: &dyn Fn(&str) -> Option<String>) -> Option<Value> {
    let r = line.as_object()?;
    let id = r.get("id")?.as_str()?;
    let ts = r.get("ts").filter(|v| v.is_number())?;
    let rule = r.get("rule")?.as_str()?;
    let channel = r.get("channel")?.as_str()?;
    let action = r.get("action")?.as_str()?;
    if !["block", "hold", "log", "released", "dropped"].contains(&action) {
        return None;
    }
    let mut out = Map::new();
    out.insert("source".into(), json!("content_rule"));
    out.insert("id".into(), json!(id));
    out.insert("ts".into(), ts.clone());
    out.insert("rule".into(), json!(js_slice(rule, 64)));
    if let Some(name) = name_of(rule).filter(|n| !n.is_empty()) {
        out.insert("name".into(), json!(js_slice(&name, 80)));
    }
    out.insert("channel".into(), json!(channel));
    out.insert(
        "direction".into(),
        json!(if r.get("direction").and_then(Value::as_str) == Some("in") {
            "in"
        } else {
            "out"
        }),
    );
    out.insert("action".into(), json!(action));
    out.insert(
        "vm_id".into(),
        r.get("vm_id").filter(|v| v.is_string()).cloned().unwrap_or(Value::Null),
    );
    if let Some(p) = r
        .get("purpose")
        .and_then(Value::as_str)
        .filter(|p| *p == "meeting" || *p == "phone")
    {
        out.insert("purpose".into(), json!(p));
    }
    if let Some(a) = r
        .get("ai")
        .and_then(Value::as_str)
        .filter(|a| *a == "found" || *a == "failed")
    {
        out.insert("ai".into(), json!(a));
    }
    Some(Value::Object(out))
}

/// Why a check could not run: the rules are unknown (the store would not open), or the engine said
/// so (too long, or anything else).
#[derive(Debug, Clone, PartialEq)]
pub enum CheckError {
    Unknown,
    Content(ContentError),
}

impl From<ContentError> for CheckError {
    fn from(e: ContentError) -> Self {
        CheckError::Content(e)
    }
}

/// A rule that acts, and whether the AI found it or could not run (then its reason says so).
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    pub rule: EngineRule,
    pub by: Option<&'static str>,
}

impl Checked {
    /// A rule as the integrations hand it back (`contracts::CheckedRule`).
    pub fn from_contract(r: &crate::contracts::CheckedRule, direction: &str) -> Self {
        Checked {
            rule: EngineRule {
                id: r.id.clone(),
                name: r.name.clone(),
                direction: direction.into(),
                channels: vec![],
                patterns: vec![],
                detectors: vec![],
                action: r.action.clone(),
                reason: r.reason.clone(),
                policy: None,
            },
            by: match r.by.as_deref() {
                Some("found") => Some("found"),
                Some("failed") => Some("failed"),
                _ => None,
            },
        }
    }

    pub fn brief(&self) -> RuleBrief {
        RuleBrief {
            id: self.rule.id.clone(),
            name: self.rule.name.clone().unwrap_or_else(|| self.rule.id.clone()),
            reason: self.rule.reason.clone(),
            ai: self.by.map(str::to_string),
        }
    }
}

/// A POST to Telegram, Slack or AgentMail: the status and the JSON answer (`None` when it was not
/// JSON). The error never carries the URL (Telegram's has the token in it).
pub trait Poster: Send + Sync {
    fn post(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        body: String,
    ) -> cc_http::BoxFuture<Result<(u16, Option<Value>), String>>;
}

pub struct LivePoster(pub reqwest::Client);

impl LivePoster {
    pub fn new() -> Result<Self, String> {
        reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(POST_TIMEOUT)
            .build()
            .map(Self)
            .map_err(|e| e.without_url().to_string())
    }
}

impl Poster for LivePoster {
    fn post(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        body: String,
    ) -> cc_http::BoxFuture<Result<(u16, Option<Value>), String>> {
        let client = self.0.clone();
        Box::pin(async move {
            let mut req = client.post(&url).body(body);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            let res = req.send().await.map_err(|e| e.without_url().to_string())?;
            let status = res.status().as_u16();
            let json = res.json::<Value>().await.ok();
            Ok((status, json))
        })
    }
}

type Send_ = Box<dyn FnOnce() -> cc_http::BoxFuture<Result<(), String>> + Send>;

/// What a hold needs from where it came from: what to show, and how to send it on Send.
struct HeldMessage {
    channel: String,
    rule: RuleBrief,
    /// "a Telegram message", "an email".
    what: String,
    /// Where it goes, one line, from fixed words and checked ids.
    where_: String,
    preview: String,
    /// The agent that wrote it: under an emergency stop, Send sends nothing.
    vm_id: String,
    send: Option<Send_>,
}

struct Hold {
    held: HeldMessage,
    created_at: i64,
    offers: Vec<String>,
    done: bool,
    /// When its entry on the stopped record was written, to find it again.
    recorded_at: Option<i64>,
    /// The people are still being asked: not counted or shown yet, but a tap already acts on it.
    asking: bool,
    /// What an offer that arrives after a Send or Don't send is told.
    closed_line: Option<String>,
    /// Sent, or dropped, while the people were still being asked: `keep` takes it away.
    finished: bool,
    /// Send was pressed (not Don't send): the others' offers say someone else did.
    released: bool,
    /// The buttons it was offered with, used again on Send and Don't send.
    buttons: Arc<CodeButtons>,
}

#[derive(Default)]
struct Holds {
    map: IndexMap<String, Hold>,
    /// How holds ended (Send pressed, the words), for offers that come back after they are gone.
    ended: IndexMap<String, (bool, String)>,
    by_key: HashMap<String, String>,
    cancelled: IndexSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct Store {
    rules: Vec<ContentRule>,
    ai: Option<AiPin>,
}

impl Store {
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("version".into(), json!(1));
        m.insert("rules".into(), json!(self.rules));
        if let Some(ai) = &self.ai {
            m.insert("ai".into(), pin_json(ai));
        }
        Value::Object(m)
    }
}

type Token2 = Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;
type SlackToken = Arc<dyn Fn(&str, Option<&str>) -> Option<String> + Send + Sync>;
pub type JudgeFn = Arc<dyn Fn(ContentAsk) -> cc_http::BoxFuture<ContentAnswer> + Send + Sync>;

pub struct ContentRulesOptions {
    pub store_path: PathBuf,
    /// The directory of the file the proxy reads (`content-rules.json`).
    pub proxy_dir: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    /// This module's codes (W3's code service), typed in the console: no buttons.
    pub codes: Arc<dyn Fn() -> Option<Arc<dyn ModuleCodes>> + Send + Sync>,
    /// Who gets codes: the channels' routes, the dev route last on a dev build. Empty when the
    /// channel store could not be read.
    pub code_routes: Arc<dyn Fn() -> Vec<CodeRoute> + Send + Sync>,
    /// The Send and Don't send buttons, while their tap listener is up.
    pub buttons: Arc<dyn Fn() -> Option<Arc<CodeButtons>> + Send + Sync>,
    /// The proxy's audit file (`content-rules.jsonl`): confirmed changes are recorded next to the hits.
    pub audit_path: Option<PathBuf>,
    /// The bot token for a bot id, only when that bot's connection is assigned to `vm_id`.
    pub telegram_token: Token2,
    /// A Slack bot token of `vm_id`'s, for the call that carried `auth`.
    pub slack_token: Option<SlackToken>,
    /// An AgentMail inbox's key, only when that inbox is `vm_id`'s.
    pub agentmail_key: Option<Token2>,
    /// Whether `vm_id` is under an emergency stop: a held message of its is not sent on Send.
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub poster: Arc<dyn Poster>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// How long asking may take (`HOLD_ASK_MS`).
    pub ask_ms: u64,
    /// Where each block and hold is kept with its text, for the firewall's own page.
    pub stopped: Option<Arc<ContentStoppedStore>>,
    /// The policies' AI check (`AiJudge.content`). Absent: a policy cannot be judged, and acts.
    pub judge: Option<JudgeFn>,
    /// The AI review's current model and key, which a rule change may pin.
    pub ai_identity: Arc<dyn Fn() -> Option<AiIdentity> + Send + Sync>,
}

struct State {
    store: Store,
    unreadable: bool,
}

pub struct ContentRulesFirewall {
    opts: ContentRulesOptions,
    aad: String,
    st: Mutex<State>,
    holds: Mutex<Holds>,
    last_notice: Mutex<HashMap<String, i64>>,
    recorded: Mutex<HashMap<String, i64>>,
    serial: tokio::sync::Mutex<()>,
    me: Weak<ContentRulesFirewall>,
}

fn write_rules_doc(dir: &std::path::Path, doc: &Value) {
    if let Err(e) = cc_contracts::write_atomic(dir, &cc_contracts::FileSpec::CONTENT_RULES, doc) {
        tracing::error!("[content-rules] could not write the proxy's rules file: {e}");
    }
}

fn random_hex12() -> String {
    let mut b = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

fn random_b64_12() -> String {
    let mut b = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn generic_failure() -> CommandOutcome {
    CommandOutcome::failed(
        "failed",
        "Content rules change could not be applied. Check the input, then retry.",
    )
}

/// `ts` as the TS writes it: seconds, with the milliseconds after a point when there are any.
fn ts_of(ms: i64) -> Value {
    if ms % 1000 == 0 {
        json!(ms / 1000)
    } else {
        json!(ms as f64 / 1000.0)
    }
}

/// Step 1's proxy sends no `channel`: its holds and notices are Telegram's.
fn with_channel(raw: &Value) -> Value {
    match raw.as_object() {
        Some(m) if !m.contains_key("channel") => {
            let mut m = m.clone();
            m.insert("channel".into(), json!("telegram"));
            Value::Object(m)
        }
        _ => raw.clone(),
    }
}

fn s_max<'a>(m: &'a Map<String, Value>, k: &str, min: usize, max: usize) -> Option<&'a str> {
    m.get(k)?.as_str().filter(|s| (min..=max).contains(&js_len(s)))
}

fn re<'a>(m: &'a Map<String, Value>, k: &str, r: &Regex) -> Option<&'a str> {
    m.get(k)?.as_str().filter(|s| r.is_match(s))
}

/// `heldRule`: a reason is up to 200 characters, and " (the AI check could not run)" when it could not.
fn held_rule(v: Option<&Value>) -> Option<RuleBrief> {
    let m = v?.as_object()?;
    let ai = match m.get("ai") {
        None => None,
        Some(Value::String(a)) if a == "found" || a == "failed" => Some(a.clone()),
        Some(_) => return None,
    };
    Some(RuleBrief {
        id: s_max(m, "id", 0, 64)?.into(),
        name: s_max(m, "name", 0, 80)?.into(),
        reason: s_max(m, "reason", 0, 240)?.into(),
        ai,
    })
}

/// `holdInput`, per channel.
enum HoldInput {
    Telegram {
        bot_id: String,
        method: String,
        body: String,
        chat_id: String,
        vm_id: String,
        key: String,
        rule: RuleBrief,
        text: Option<String>,
    },
    Slack {
        method: String,
        body: String,
        form: bool,
        chat_id: String,
        auth: Option<String>,
        vm_id: String,
        key: String,
        rule: RuleBrief,
        text: String,
    },
    Email {
        path: String,
        body: String,
        chat_id: String,
        vm_id: String,
        key: String,
        rule: RuleBrief,
        text: String,
    },
}

impl HoldInput {
    fn parse(raw: &Value) -> Option<Self> {
        let m = raw.as_object()?;
        let body = s_max(m, "body", 2, 262_144)?.to_string();
        let vm_id = s_max(m, "vmId", 1, 100)?.to_string();
        let key = re(m, "key", &HOLD_KEY)?.to_string();
        let rule = held_rule(m.get("rule"))?;
        let text = |req: bool| -> Option<Option<String>> {
            match m.get("text") {
                None if !req => Some(None),
                Some(Value::String(s)) if js_len(s) <= 16_384 => Some(Some(s.clone())),
                _ => None,
            }
        };
        Some(match m.get("channel")?.as_str()? {
            "telegram" => HoldInput::Telegram {
                bot_id: re(m, "botId", &BOT_ID)?.into(),
                method: m.get("method")?.as_str().filter(|x| HOLD_METHODS.contains(x))?.into(),
                body,
                chat_id: re(m, "chatId", &CHAT_ID)?.into(),
                vm_id,
                key,
                rule,
                text: text(false)?,
            },
            "slack" => HoldInput::Slack {
                method: m
                    .get("method")?
                    .as_str()
                    .filter(|x| *x == "chat.postMessage" || *x == "chat.update")?
                    .into(),
                body,
                form: match m.get("contentType")?.as_str()? {
                    "json" => false,
                    "form" => true,
                    _ => return None,
                },
                chat_id: re(m, "chatId", &SLACK_CHANNEL)?.into(),
                auth: match m.get("auth") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) if js_len(s) <= 200 => Some(s.clone()),
                    Some(_) => return None,
                },
                vm_id,
                key,
                rule,
                text: text(true)??,
            },
            "email" => {
                if m.get("method")?.as_str()? != "POST" {
                    return None;
                }
                let path = s_max(m, "path", 0, 400)?;
                if !AGENTMAIL_SEND.is_match(path) {
                    return None;
                }
                HoldInput::Email {
                    path: path.into(),
                    body,
                    chat_id: s_max(m, "chatId", 1, 320)?.into(),
                    vm_id,
                    key,
                    rule,
                    text: text(true)??,
                }
            }
            _ => return None,
        })
    }

    fn channel(&self) -> &'static str {
        match self {
            HoldInput::Telegram { .. } => "telegram",
            HoldInput::Slack { .. } => "slack",
            HoldInput::Email { .. } => "email",
        }
    }
    fn key(&self) -> &str {
        match self {
            HoldInput::Telegram { key, .. } | HoldInput::Slack { key, .. } | HoldInput::Email { key, .. } => key,
        }
    }
    fn rule(&self) -> &RuleBrief {
        match self {
            HoldInput::Telegram { rule, .. } | HoldInput::Slack { rule, .. } | HoldInput::Email { rule, .. } => rule,
        }
    }
    fn vm_id(&self) -> &str {
        match self {
            HoldInput::Telegram { vm_id, .. } | HoldInput::Slack { vm_id, .. } | HoldInput::Email { vm_id, .. } => {
                vm_id
            }
        }
    }
    fn text(&self) -> Option<&str> {
        match self {
            HoldInput::Telegram { text, .. } => text.as_deref(),
            HoldInput::Slack { text, .. } | HoldInput::Email { text, .. } => Some(text),
        }
    }
}

/// The named string fields of a held call's JSON body, for the preview.
fn text_of(body: &str, keys: &[&str]) -> String {
    let doc = parse_object(body);
    keys.iter()
        .filter_map(|k| doc.get(*k).and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_object(body: &str) -> Map<String, Value> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// A hold's decision, as the buttons hand it back.
struct HoldOwner {
    fw: Weak<ContentRulesFirewall>,
    id: String,
}

impl TapOwner for HoldOwner {
    fn tap(&self, _correct: bool) -> TapVerdict {
        if let Some(fw) = self.fw.upgrade() {
            let id = self.id.clone();
            tokio::spawn(async move { fw.release(&id).await });
        }
        TapVerdict::Ok
    }
    fn cancel(&self) {
        if let Some(fw) = self.fw.upgrade() {
            fw.drop_hold(&self.id, "It was not sent.", "not_sent");
        }
    }
}

impl ContentRulesFirewall {
    /// Tell the proxy the rules are unknown: before the store is loaded when the proxy has no file
    /// (after a reboot: the directory is a tmpfs), and when loading fails, so the proxy refuses
    /// rather than running without the organization's rules.
    pub fn mark_unknown(proxy_dir: &std::path::Path) {
        write_rules_doc(proxy_dir, &json!({"version": 1, "unreadable": true}));
    }

    pub fn new(opts: ContentRulesOptions) -> Result<Arc<Self>, String> {
        if !cc_contracts::FileSpec::CONTENT_RULES.path_in(&opts.proxy_dir).exists() {
            Self::mark_unknown(&opts.proxy_dir);
        }
        let aad = format!("{}:{}:content-rules", opts.org_id, opts.box_id);
        let loaded = Self::load(&opts, &aad);
        let (store, unreadable) = match loaded {
            Ok(x) => x,
            Err(e) => {
                Self::mark_unknown(&opts.proxy_dir);
                return Err(e);
            }
        };
        let fw = Arc::new_cyclic(|me| Self {
            opts,
            aad,
            st: Mutex::new(State { store, unreadable }),
            holds: Mutex::new(Holds::default()),
            last_notice: Mutex::new(HashMap::new()),
            recorded: Mutex::new(HashMap::new()),
            serial: tokio::sync::Mutex::new(()),
            me: me.clone(),
        });
        if unreadable {
            // A store that is there and will not open is not "no rules": starting empty would
            // quietly switch every rule off. The proxy is told the rules are unknown and refuses
            // until a confirmed change reseals the store.
            write_rules_doc(&fw.opts.proxy_dir, &json!({"version": 1, "unreadable": true}));
        } else {
            fw.write_rules_file();
        }
        Ok(fw)
    }

    fn load(opts: &ContentRulesOptions, aad: &str) -> Result<(Store, bool), String> {
        let existed = opts.store_path.exists();
        let stored =
            cc_crypto::enc_file::load_store_or_empty("content-rules", &opts.store_path, &opts.box_key, aad, &|l| {
                tracing::error!("{l}")
            });
        let Some(stored) = stored else {
            return Ok((
                Store {
                    rules: vec![],
                    ai: None,
                },
                existed,
            ));
        };
        if stored.get("version") != Some(&json!(1)) {
            return Err("Unsupported content rules store".into());
        }
        let rules = stored
            .get("rules")
            .and_then(Value::as_array)
            .ok_or("Unsupported content rules store")?
            .iter()
            .map(parse_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let ai = match stored.get("ai") {
            None | Some(Value::Null) => None,
            Some(v) => Some(parse_pin(v).ok_or("Unsupported content rules store")?),
        };
        Ok((Store { rules, ai }, false))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn holds(&self) -> MutexGuard<'_, Holds> {
        self.holds.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    pub fn rules(&self) -> Vec<ContentRule> {
        self.lock().store.rules.clone()
    }

    /// Whether the store opened: until a confirmed change reseals it, every check refuses.
    pub fn unreadable(&self) -> bool {
        self.lock().unreadable
    }

    /// A rule's name now, Leaking secrets included; `None` for one that is gone.
    pub fn name_of(&self, id: &str) -> Option<String> {
        if id == CORE_SECRETS_RULE.id {
            return CORE_SECRETS_RULE.name.clone();
        }
        self.lock()
            .store
            .rules
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
    }

    /// The model and key the policies may use (`AiJudge` checks it on every call).
    pub fn ai_pin(&self) -> Option<AiPin> {
        self.lock().store.ai.clone()
    }

    /// The rules the engine reads: Leaking secrets, then the enabled ones. An error while they are unknown.
    fn engine_rules(&self) -> Result<Vec<EngineRule>, CheckError> {
        let st = self.lock();
        if st.unreadable {
            return Err(CheckError::Unknown);
        }
        Ok(std::iter::once(CORE_SECRETS_RULE.clone())
            .chain(st.store.rules.iter().filter(|r| r.enabled).map(ContentRule::engine))
            .collect())
    }

    /// Whether any rule looks at this direction and channel. An error while the rules are unknown.
    pub fn applies(&self, direction: &str, channel: &str) -> Result<bool, CheckError> {
        Ok(content_applies(&self.engine_rules()?, direction, channel))
    }

    /// A body checked for the gates here (webhooks, team chat, app calls), which do not go through
    /// the proxy: the rule that acts (block or hold), or `None`. Words and detectors first, then the
    /// policies that cover it, in one call to the AI. Log-only hits are recorded.
    pub async fn check(
        &self,
        direction: &str,
        channel: &str,
        text: &str,
        vm_id: Option<&str>,
        once: Option<&str>,
    ) -> Result<Option<Checked>, CheckError> {
        let (j, _, _) = self
            .judged(self.engine_rules()?, direction, channel, text, vm_id)
            .await?;
        for hit in j.hits.iter().filter(|h| h.action == "log") {
            let mut extra = Map::new();
            if let Some(by) = j.by(&hit.id) {
                extra.insert("ai".into(), json!(by));
            }
            self.record(&hit.id, channel, direction, "log", vm_id, extra, once);
        }
        let Some(rule) = j.rule.clone().filter(|r| r.action != "log") else {
            return Ok(None);
        };
        Ok(Some(Checked {
            by: j.by(&rule.id),
            rule,
        }))
    }

    /// The engine, then the AI on the policies it left; the rules asked, and its answer.
    async fn judged(
        &self,
        rules: Vec<EngineRule>,
        direction: &str,
        channel: &str,
        text: &str,
        vm_id: Option<&str>,
    ) -> Result<(Judged, Vec<EngineRule>, Option<ContentAnswer>), CheckError> {
        let found = evaluate(&rules, direction, channel, text)?;
        let asked = policies_to_ask(&rules, direction, channel, &found, text);
        if asked.is_empty() {
            return Ok((
                Judged {
                    rule: found.rule,
                    hits: found.hits,
                    ai: vec![],
                },
                asked,
                None,
            ));
        }
        let answer = match &self.opts.judge {
            Some(judge) => {
                judge(ContentAsk {
                    direction: direction.into(),
                    channel: channel.into(),
                    text: text.into(),
                    rules: asked
                        .iter()
                        .map(|r| (r.id.clone(), r.policy.clone().unwrap_or_default()))
                        .collect(),
                    vm_id: vm_id.map(str::to_string),
                })
                .await
            }
            None => ContentAnswer::Failed("off".into()),
        };
        let matched = match &answer {
            ContentAnswer::Answered { matches, .. } => Some(matches.iter().cloned().collect::<HashSet<String>>()),
            ContentAnswer::Failed(why) => {
                tracing::info!("[content-rules] the AI check could not run ({why}): {channel} {direction}");
                None
            }
        };
        Ok((with_policies(found, &asked, matched.as_ref()), asked, Some(answer)))
    }

    /// `rules.try`: what the rules, the rule being edited included, would do with a message, and
    /// each policy's probability. Nothing is recorded or kept.
    async fn try_message(&self, raw: &Map<String, Value>) -> Result<CommandOutcome, ()> {
        let text = s_max(raw, "text", 1, 20_000).ok_or(())?;
        let direction = raw
            .get("direction")
            .and_then(Value::as_str)
            .filter(|d| *d == "in" || *d == "out")
            .ok_or(())?;
        let channel = raw
            .get("channel")
            .and_then(Value::as_str)
            .filter(|c| CONTENT_CHANNELS.contains(c))
            .ok_or(())?;
        let draft = match raw.get("draft") {
            None => None,
            Some(d) => Some(parse_rule(d).map_err(|_| ())?),
        };
        let own = {
            let st = self.lock();
            if st.unreadable {
                return Ok(CommandOutcome::failed(
                    "failed",
                    "Your firewall could not read its content rules, so it stops every checked message. Save any change with a code to repair them.",
                ));
            }
            st.store
                .rules
                .iter()
                .filter(|r| r.enabled && Some(&r.id) != draft.as_ref().map(|d| &d.id))
                .map(ContentRule::engine)
                .collect::<Vec<_>>()
        };
        if text_length(text) > content_text_max(channel) {
            return Ok(CommandOutcome::failed(
                "failed",
                "That message is longer than a check reads.",
            ));
        }
        let mut rules = vec![CORE_SECRETS_RULE.clone()];
        rules.extend(own);
        if let Some(d) = draft.filter(|d| d.enabled) {
            rules.push(d.engine());
        }
        let (j, asked, answer) = self
            .judged(rules, direction, channel, text, None)
            .await
            .map_err(|_| ())?;
        let brief = |r: &EngineRule| {
            let mut m = Map::new();
            m.insert("id".into(), json!(r.id));
            m.insert("name".into(), json!(r.name.clone().unwrap_or_else(|| r.id.clone())));
            m.insert("action".into(), json!(r.action));
            if let Some(by) = j.by(&r.id) {
                m.insert("by".into(), json!(by));
            }
            Value::Object(m)
        };
        let mut data = Map::new();
        data.insert("rule".into(), j.rule.as_ref().map_or(Value::Null, brief));
        data.insert("hits".into(), Value::Array(j.hits.iter().map(brief).collect()));
        data.insert(
            "asked".into(),
            json!(asked.iter().map(|r| r.id.clone()).collect::<Vec<_>>()),
        );
        match answer {
            Some(ContentAnswer::Failed(why)) => {
                data.insert("failed".into(), json!(why));
            }
            Some(ContentAnswer::Answered { probabilities, .. }) => {
                data.insert("probabilities".into(), json!(probabilities));
            }
            None => {}
        }
        Ok(CommandOutcome {
            ok: true,
            status: "tried".into(),
            message: None,
            data: Some(data),
        })
    }

    /// One line on the firewall's record for a rule that fired here, as the proxy writes them.
    /// Metadata only. `once` names the message on a read the agent repeats: recorded once an hour,
    /// not every poll, and always under the same id. The line's id, or `None` when it was not
    /// written again.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        rule: &str,
        channel: &str,
        direction: &str,
        action: &str,
        vm_id: Option<&str>,
        extra: Map<String, Value>,
        once: Option<&str>,
    ) -> Option<String> {
        let mut id = None;
        if let Some(once) = once {
            // `${vmId}` of null is "null".
            let key = format!(
                "{rule}|{channel}|{direction}|{action}|{}|{once}",
                vm_id.unwrap_or("null")
            );
            let now = self.now();
            let mut rec = self.recorded.lock().unwrap_or_else(|e| e.into_inner());
            if now - rec.get(&key).copied().unwrap_or(-AUDIT_ONCE_MS) < AUDIT_ONCE_MS {
                return None;
            }
            if rec.len() > 10_000 {
                rec.clear();
            }
            rec.insert(key.clone(), now);
            id = Some(audit_once_id(&key));
        }
        let mut entry = Map::new();
        entry.insert("rule".into(), json!(rule));
        entry.insert("channel".into(), json!(channel));
        entry.insert("direction".into(), json!(direction));
        entry.insert("action".into(), json!(action));
        entry.insert("vm_id".into(), json!(vm_id));
        entry.extend(extra);
        Some(self.audit(entry, id))
    }

    /// A webhook delivery, verified and about to be forwarded: `None` to forward it, or the answer
    /// its sender gets. A stopped one gets a 200, so the sender does not send it again; while the
    /// rules are unknown, a 503, so it does.
    pub async fn screen_webhook(
        &self,
        vm_id: &str,
        body: &[u8],
        content_type: &str,
        content_encoding: &str,
    ) -> Option<(u16, String)> {
        let vm = Some(vm_id);
        let r: Result<Option<(u16, String)>, CheckError> = async {
            if !self.applies("in", "webhook")? {
                return Ok(None);
            }
            // A compressed delivery is read as the agent will read it, not as bytes that are no text.
            let body = crate::channels::content_engine::decode_body(body, content_encoding)?;
            let Some(text) = crate::channels::content_engine::body_text(&body, Some(content_type))? else {
                return Ok(None);
            };
            if text.is_empty() {
                return Ok(None);
            }
            let Some(rule) = self.check("in", "webhook", &text, vm, None).await? else {
                return Ok(None);
            };
            if rule.by == Some("failed") {
                // Not judged, so not lost: the sender is asked to send it again later.
                let mut extra = Map::new();
                extra.insert("ai".into(), json!("failed"));
                self.record(&rule.rule.id, "webhook", "in", "wait", vm, extra, None);
                return Ok(Some((503, "content check could not run".into())));
            }
            let mut extra = Map::new();
            if let Some(by) = rule.by {
                extra.insert("ai".into(), json!(by));
            }
            let line = self.record(&rule.rule.id, "webhook", "in", "block", vm, extra, None);
            self.stopped_here(&rule, "webhook", "in", vm, &text, line.as_deref());
            Ok(Some((200, format!("stopped by content rule {}", rule.rule.id))))
        }
        .await;
        match r {
            Ok(x) => x,
            Err(CheckError::Unknown) => Some((503, "content rules not loaded".into())),
            Err(CheckError::Content(e)) => {
                let too_long = e == ContentError::TooLong;
                let mut extra = Map::new();
                if too_long {
                    extra.insert("detail".into(), json!("too long"));
                }
                self.record("error", "webhook", "in", "block", vm, extra, None);
                Some((
                    200,
                    if too_long {
                        "too long to check"
                    } else {
                        "content check failed"
                    }
                    .into(),
                ))
            }
        }
    }

    // ---- commands ---------------------------------------------------------------------------------

    fn summary(&self) -> Map<String, Value> {
        let id = (self.opts.ai_identity)();
        let held = self.holds().map.values().filter(|h| !h.done && !h.asking).count();
        let st = self.lock();
        let mut m = Map::new();
        m.insert("rules".into(), json!(st.store.rules));
        if st.unreadable {
            m.insert("unreadable".into(), json!(true));
        }
        m.insert(
            "core".into(),
            json!([{"id": "core-leaking-secrets", "name": "Leaking secrets", "direction": "out", "action": "block"}]),
        );
        m.insert("held".into(), json!(held));
        m.insert(
            "ai".into(),
            json!({
                "pinned": st.store.ai.as_ref().map(|p| json!({"provider": p.provider.as_str(), "model": p.model})),
                "current": id.as_ref().map(|i| json!({"provider": i.provider.as_str(), "model": i.model})),
                "allowed": id.as_ref().is_some_and(policy_model_allowed),
                "matches": pin_matches(st.store.ai.as_ref(), id.as_ref()),
            }),
        );
        m
    }

    /// The pin a change carries: the AI review's current model and key, when the rules after it
    /// have an enabled policy (or it is the `ai` change itself), that one may judge policies, and it
    /// is not the pinned one already. The code message names it, so the person accepts it knowingly.
    fn pin_with(&self, change: &ContentChange, after: &[ContentRule]) -> Option<AiPin> {
        let id = (self.opts.ai_identity)()?;
        if !policy_model_allowed(&id) || pin_matches(self.lock().store.ai.as_ref(), Some(&id)) {
            return None;
        }
        (matches!(change, ContentChange::Ai) || after.iter().any(|r| r.enabled && r.policy.is_some()))
            .then(|| pin_for(&id))
    }

    /// `rules.read`, `rules.propose`, `rules.confirm`, `rules.cancel`, `rules.try`, one at a time.
    pub async fn command(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _serial = self.serial.lock().await;
        match self.run(action, &payload).await {
            Ok(o) => o,
            Err(()) => generic_failure(),
        }
    }

    async fn run(&self, action: &str, p: &Map<String, Value>) -> Result<CommandOutcome, ()> {
        if action == "read" {
            return Ok(CommandOutcome {
                ok: true,
                status: "read".into(),
                message: None,
                data: Some(self.summary()),
            });
        }
        if action == "try" {
            return self.try_message(p).await;
        }
        let change_id = s_max(p, "changeId", 1, 100).ok_or(())?.to_string();
        let codes = (self.opts.codes)();
        if action == "cancel" {
            if let Some(c) = &codes {
                c.cancel(CODE_SCOPE, Some(&change_id));
            }
            return Ok(CommandOutcome {
                ok: true,
                status: "cancelled".into(),
                message: None,
                data: None,
            });
        }
        if action == "confirm" {
            let code = p
                .get("code")
                .and_then(Value::as_str)
                .filter(|c| js_len(c) <= 20)
                .ok_or(())?;
            let check = codes.map_or(CodeCheck::Expired, |c| c.verify(CODE_SCOPE, &change_id, code));
            let proposal = match check {
                CodeCheck::Ok { proposal, .. } => proposal,
                CodeCheck::Wrong { tries_left } => {
                    let mut d = Map::new();
                    d.insert("attemptsLeft".into(), json!(tries_left));
                    return Ok(CommandOutcome {
                        ok: false,
                        status: "invalid".into(),
                        message: None,
                        data: Some(d),
                    });
                }
                CodeCheck::Expired => {
                    return Ok(CommandOutcome {
                        ok: false,
                        status: "expired".into(),
                        message: None,
                        data: Some(Map::new()),
                    });
                }
            };
            let change = parse_change(proposal.get("change").ok_or(())?).map_err(|_| ())?;
            let ai = match proposal.get("ai") {
                None | Some(Value::Null) => None,
                Some(v) => Some(parse_pin(v).ok_or(())?),
            };
            return self.apply(&change, ai);
        }
        if action != "propose" {
            return Err(());
        }
        let change = parse_change(p.get("change").ok_or(())?).map_err(|_| ())?;
        // Refuse now what could not be applied later.
        let after = apply_content_change(&self.lock().store.rules, &change).map_err(|_| ())?;
        let ai = self.pin_with(&change, &after);
        if matches!(change, ContentChange::Ai) && ai.is_none() {
            let id = (self.opts.ai_identity)();
            let message = match id {
                None => "Your AI review is off: turn it on in AI review on the Firewall page first.",
                Some(id) if !policy_model_allowed(&id) => {
                    "Content rules judge sentences only with Jev, on the AI Gateway or the included AI tokens. Choose it in AI review on the Firewall page first."
                }
                Some(_) => "Your content rules already use this model and key.",
            };
            return Ok(CommandOutcome::failed("failed", message));
        }
        let undelivered = || {
            CommandOutcome::failed(
                "failed",
                "No confirmation code could be delivered. Add a recipient on the Firewall page.",
            )
        };
        let Some(codes) = codes else {
            return Ok(undelivered());
        };
        codes.forget(CODE_SCOPE);
        let mut proposal = Map::new();
        proposal.insert("changeId".into(), json!(change_id));
        proposal.insert("change".into(), change.to_json());
        if let Some(ai) = &ai {
            proposal.insert("ai".into(), pin_json(ai));
        }
        let parts = describe_content_change(&change, &self.lock().store.rules, ai.as_ref());
        // Every change, tightening included. No shortcut, no first-use pass.
        let sent = codes
            .send(CodeAsk {
                scope: CODE_SCOPE.into(),
                change_id,
                proposal: Value::Object(proposal),
                agent_name: "your content rules".into(),
                summary: String::new(),
                routes: (self.opts.code_routes)(),
                parts: Some(parts),
                // Typed in the console, which has no number to show for buttons yet.
                no_buttons: true,
                ..Default::default()
            })
            .await;
        Ok(match &sent {
            CodeSent::Sent { .. } => CommandOutcome {
                ok: true,
                status: "awaiting_code".into(),
                message: None,
                data: sent.awaiting_code_data(),
            },
            CodeSent::Failed { .. } => undelivered(),
        })
    }

    fn apply(&self, change: &ContentChange, ai: Option<AiPin>) -> Result<CommandOutcome, ()> {
        // The model and key named in the code message, still the AI review's: a change in between
        // is not accepted under the old message.
        if let Some(pin) = &ai
            && !pin_matches(Some(pin), (self.opts.ai_identity)().as_ref())
        {
            return Ok(CommandOutcome::failed(
                "failed",
                "Your AI review changed while the code was on its way. Save the change again to get a new code.",
            ));
        }
        // Re-applied to the rules as they are now: another change may have landed in between.
        // Saved first: a store that could not be written changes nothing, here or in the proxy's
        // file (the TS changed its memory and then failed).
        let store = {
            let st = self.lock();
            Store {
                rules: apply_content_change(&st.store.rules, change).map_err(|_| ())?,
                ai: ai.clone().or_else(|| st.store.ai.clone()),
            }
        };
        cc_crypto::enc_file::save_store(
            "content-rules",
            &self.opts.store_path,
            &store.to_json(),
            &self.opts.box_key,
            &self.aad,
        )
        .map_err(|e| tracing::error!("[content-rules] could not save the store: {}", e.0))?;
        {
            let mut st = self.lock();
            st.store = store;
            st.unreadable = false;
        }
        self.write_rules_file();
        let mut entry = Map::new();
        entry.insert("action".into(), json!("rule_changed"));
        entry.insert("op".into(), json!(change.op()));
        entry.insert(
            "rule".into(),
            match change {
                ContentChange::Put(r) => json!(r.id),
                ContentChange::Delete(id) => json!(id),
                ContentChange::Ai => Value::Null,
            },
        );
        if let ContentChange::Put(r) = change {
            entry.insert("enabled".into(), json!(r.enabled));
            entry.insert("ruleAction".into(), json!(r.action));
        }
        if let Some(pin) = &ai {
            entry.insert(
                "ai".into(),
                json!({"provider": pin.provider.as_str(), "model": pin.model}),
            );
        }
        self.audit(entry, None);
        Ok(CommandOutcome {
            ok: true,
            status: "applied".into(),
            message: None,
            data: Some(self.summary()),
        })
    }

    /// One line on the firewall's own record; its id. Metadata only.
    fn audit(&self, entry: Map<String, Value>, id: Option<String>) -> String {
        let id = id.unwrap_or_else(random_hex12);
        let Some(path) = &self.opts.audit_path else { return id };
        let mut line = Map::new();
        line.insert("ts".into(), ts_of(self.now()));
        line.insert("id".into(), json!(id));
        line.extend(entry);
        let text = format!("{}\n", Value::Object(line));
        let r = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.create(true).append(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
            o.open(path)?.write_all(text.as_bytes())
        })();
        if let Err(e) = r {
            tracing::error!("[content-rules] audit write failed: {e}");
        }
        id
    }

    /// The enabled rules, for the proxy. Written whole and renamed, so it never reads half a file.
    fn write_rules_file(&self) {
        let rules: Vec<Value> = self
            .lock()
            .store
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| {
                let mut v = json!(r);
                if let Some(m) = v.as_object_mut() {
                    m.shift_remove("enabled");
                }
                v
            })
            .collect();
        write_rules_doc(&self.opts.proxy_dir, &json!({"version": 1, "rules": rules}));
    }

    // ---- the stopped record -------------------------------------------------------------------

    /// Whether a rule looks for secrets: what it stops is not kept.
    fn secret_rule(&self, id: &str) -> bool {
        id == CORE_SECRETS_RULE.id
            || self
                .lock()
                .store
                .rules
                .iter()
                .find(|r| r.id == id)
                .is_some_and(|r| r.detectors.iter().any(|d| d == "secrets"))
    }

    #[allow(clippy::too_many_arguments)]
    fn record_stopped(
        &self,
        rule: RuleBrief,
        channel: &str,
        direction: &str,
        action: &str,
        vm_id: Option<&str>,
        text: Option<&str>,
        outcome: Option<&str>,
        id: Option<&str>,
        at: Option<i64>,
    ) -> Option<String> {
        let stopped = self.opts.stopped.as_ref()?;
        let secret = self.secret_rule(&rule.id);
        stopped.record(NewStopped {
            rule,
            channel: channel.into(),
            direction: direction.into(),
            action: action.into(),
            vm_id: vm_id.map(str::to_string),
            text: if secret { None } else { text.map(str::to_string) },
            withheld: secret.then(|| "secret".into()),
            outcome: outcome.map(str::to_string),
            id: id.map(str::to_string),
            at,
        })
    }

    /// A text the proxy stopped (`/stopped`): kept for the firewall's own page.
    pub fn stopped(&self, raw: &Value) -> Result<(), ()> {
        let m = raw.as_object().ok_or(())?;
        let vm_id = match m.get("vmId").ok_or(())? {
            Value::Null => None,
            Value::String(s) if (1..=100).contains(&js_len(s)) => Some(s.as_str()),
            _ => return Err(()),
        };
        let rule = held_rule(m.get("rule")).ok_or(())?;
        let channel = m
            .get("channel")
            .and_then(Value::as_str)
            .filter(|c| CONTENT_CHANNELS.contains(c))
            .ok_or(())?;
        let direction = m
            .get("direction")
            .and_then(Value::as_str)
            .filter(|d| *d == "in" || *d == "out")
            .ok_or(())?;
        let text = s_max(m, "text", 0, 16_384).ok_or(())?;
        let id = match m.get("id") {
            None => None,
            Some(_) => Some(re(m, "id", &STOPPED_ID).ok_or(())?),
        };
        self.record_stopped(rule, channel, direction, "block", vm_id, Some(text), None, id, None);
        Ok(())
    }

    /// A text a gate here stopped (webhooks, team chat, app calls), by the rule `check` answered;
    /// `id` is its audit line's.
    pub fn stopped_here(
        &self,
        rule: &Checked,
        channel: &str,
        direction: &str,
        vm_id: Option<&str>,
        text: &str,
        id: Option<&str>,
    ) {
        if rule.rule.id != CORE_SECRETS_RULE.id && !self.lock().store.rules.iter().any(|r| r.id == rule.rule.id) {
            return;
        }
        self.record_stopped(
            rule.brief(),
            channel,
            direction,
            "block",
            vm_id,
            Some(text),
            None,
            id,
            None,
        );
    }

    /// The holds waiting for someone's Send or Don't send, newest first.
    pub fn held_now(&self) -> Vec<Value> {
        self.sweep();
        let mut open: Vec<(i64, Value, String)> = {
            let holds = self.holds();
            holds
                .map
                .iter()
                .filter(|(_, h)| !h.done && !h.asking)
                .map(|(id, h)| {
                    let v = json!({
                        "id": id, "at": h.created_at, "expiresAt": h.created_at + HOLD_TTL_MS, "rule": h.held.rule,
                        "channel": h.held.channel, "what": h.held.what, "where": h.held.where_, "vmId": h.held.vm_id,
                        "text": js_slice(&h.held.preview, 2000),
                    });
                    (h.created_at, v, h.held.rule.id.clone())
                })
                .collect()
        };
        open.sort_by_key(|(at, _, _)| std::cmp::Reverse(*at));
        open.into_iter()
            .map(|(_, mut v, rule)| {
                // Null when the rule looks for secrets.
                if self.secret_rule(&rule) {
                    v["text"] = Value::Null;
                }
                v
            })
            .collect()
    }

    fn settle_stopped(&self, id: &str, recorded_at: Option<i64>, outcome: &str) {
        if let (Some(at), Some(s)) = (recorded_at, &self.opts.stopped) {
            s.settle(id, at, outcome);
        }
    }

    // ---- held messages ------------------------------------------------------------------------

    /// What a hold from the proxy shows, and how it is sent. `None` when the agent may not send it
    /// that way.
    fn held_from_proxy(&self, input: &HoldInput) -> Option<HeldMessage> {
        let poster = self.opts.poster.clone();
        // Never the URL: Telegram's has the token in it.
        async fn post(
            poster: Arc<dyn Poster>,
            url: String,
            headers: Vec<(String, String)>,
            body: String,
            ok: fn(Option<&Value>, u16) -> bool,
            who: &'static str,
        ) -> Result<(), String> {
            let (status, json) = poster.post(url, headers, body).await?;
            if ok(json.as_ref(), status) {
                return Ok(());
            }
            let why = ["description", "error", "message"]
                .iter()
                .find_map(|k| json.as_ref().and_then(|j| j.get(*k)).and_then(Value::as_str))
                .unwrap_or("");
            Err(format!(
                "{who} refused it (HTTP {status}{})",
                if why.is_empty() {
                    String::new()
                } else {
                    format!(": {}", js_slice(why, 120))
                }
            ))
        }
        let ok_true: fn(Option<&Value>, u16) -> bool = |j, _| j.and_then(|j| j.get("ok")) == Some(&Value::Bool(true));
        match input {
            HoldInput::Telegram {
                bot_id,
                method,
                body,
                chat_id,
                vm_id,
                rule,
                text,
                ..
            } => {
                // Only a bot of this agent's own: otherwise one agent could have a message sent
                // through another's.
                (self.opts.telegram_token)(bot_id, vm_id).or_else(|| {
                    tracing::info!("[content-rules] refused a hold: bot {bot_id} is not on the agent that sent it");
                    None
                })?;
                let token_for = self.opts.telegram_token.clone();
                let (bot, vm, method, body) = (bot_id.clone(), vm_id.clone(), method.clone(), body.clone());
                Some(HeldMessage {
                    channel: "telegram".into(),
                    rule: rule.clone(),
                    what: "a Telegram message".into(),
                    where_: format!("chat {chat_id}, through bot {bot_id}"),
                    preview: text
                        .clone()
                        .unwrap_or_else(|| text_of(body.as_str(), &["text", "caption"])),
                    vm_id: vm_id.clone(),
                    send: Some(Box::new(move || {
                        Box::pin(async move {
                            let token = token_for(&bot, &vm).ok_or("the bot is no longer connected")?;
                            post(
                                poster,
                                format!("{TELEGRAM_API}/bot{token}/{method}"),
                                vec![("content-type".into(), "application/json".into())],
                                body,
                                ok_true,
                                "Telegram",
                            )
                            .await
                        })
                    })),
                })
            }
            HoldInput::Slack {
                method,
                body,
                form,
                chat_id,
                auth,
                vm_id,
                rule,
                text,
                ..
            } => {
                let slack = self.opts.slack_token.clone();
                if slack.as_ref().and_then(|f| f(vm_id, auth.as_deref())).is_none() {
                    tracing::info!("[content-rules] refused a hold: no Slack bot of the agent that sent it");
                    return None;
                }
                let (vm, auth, method, body, form) = (vm_id.clone(), auth.clone(), method.clone(), body.clone(), *form);
                Some(HeldMessage {
                    channel: "slack".into(),
                    rule: rule.clone(),
                    what: "a Slack message".into(),
                    where_: format!("Slack conversation {chat_id}"),
                    preview: text.clone(),
                    vm_id: vm_id.clone(),
                    send: Some(Box::new(move || {
                        Box::pin(async move {
                            let token = slack
                                .and_then(|f| f(&vm, auth.as_deref()))
                                .ok_or("the Slack connection is no longer on this agent")?;
                            // A token in a form body is the agent's placeholder; the header carries
                            // the real one.
                            let body = if form {
                                let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
                                    .filter(|(k, _)| k != "token")
                                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                                    .collect();
                                url::form_urlencoded::Serializer::new(String::new())
                                    .extend_pairs(pairs)
                                    .finish()
                            } else {
                                body
                            };
                            let ctype = if form {
                                "application/x-www-form-urlencoded"
                            } else {
                                "application/json; charset=utf-8"
                            };
                            post(
                                poster,
                                format!("{SLACK_API}/{method}"),
                                vec![
                                    ("authorization".into(), format!("Bearer {token}")),
                                    ("content-type".into(), ctype.into()),
                                ],
                                body,
                                ok_true,
                                "Slack",
                            )
                            .await
                        })
                    })),
                })
            }
            HoldInput::Email {
                path,
                body,
                chat_id,
                vm_id,
                rule,
                text,
                ..
            } => {
                let raw = AGENTMAIL_SEND.captures(path)?.get(1)?.as_str();
                let inbox = crate::integrations::connectors::parse::decode_uri_component(raw)?;
                let key_for = self.opts.agentmail_key.clone();
                if inbox != *chat_id || key_for.as_ref().and_then(|f| f(&inbox, vm_id)).is_none() {
                    tracing::info!("[content-rules] refused a hold: the inbox is not the agent's");
                    return None;
                }
                let doc = parse_object(body);
                let to: Vec<String> = ["to", "cc", "bcc"]
                    .iter()
                    .flat_map(|k| match doc.get(*k) {
                        Some(Value::Array(a)) => a.clone(),
                        Some(v) => vec![v.clone()],
                        None => vec![],
                    })
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                let where_ = if to.is_empty() {
                    format!("inbox {inbox}")
                } else {
                    let more = if to.len() > 5 {
                        format!(" and {} more", to.len() - 5)
                    } else {
                        String::new()
                    };
                    format!("inbox {inbox}, to {}{more}", to[..to.len().min(5)].join(", "))
                };
                let (vm, path, body, inbox2) = (vm_id.clone(), path.clone(), body.clone(), inbox.clone());
                Some(HeldMessage {
                    channel: "email".into(),
                    rule: rule.clone(),
                    what: "an email".into(),
                    where_,
                    preview: text.clone(),
                    vm_id: vm_id.clone(),
                    send: Some(Box::new(move || {
                        Box::pin(async move {
                            let key = key_for
                                .and_then(|f| f(&inbox2, &vm))
                                .ok_or("the inbox is no longer on this agent")?;
                            post(
                                poster,
                                format!("{AGENTMAIL_API}{path}"),
                                vec![
                                    ("authorization".into(), format!("Bearer {key}")),
                                    ("content-type".into(), "application/json".into()),
                                ],
                                body,
                                |_, s| (200..300).contains(&s),
                                "AgentMail",
                            )
                            .await
                        })
                    })),
                })
            }
        }
    }

    /// The proxy holds a message: keep it and ask. `{ok: false}` when nobody could be asked (the
    /// proxy then stops it). An error for a request that does not read.
    pub async fn hold(&self, raw: &Value) -> Result<Value, ()> {
        let input = HoldInput::parse(&with_channel(raw)).ok_or(())?;
        let held = self.held_from_proxy(&input);
        let preview = held.as_ref().map(|h| h.preview.clone());
        let kept = match held {
            Some(h) => self.keep(h, Some(input.key())).await,
            None => Err("refused"),
        };
        match kept {
            Ok(id) => {
                let message_id: i64 = rand::Rng::gen_range(&mut rand::thread_rng(), 1_000_000_000..2_000_000_000);
                Ok(json!({"ok": true, "holdId": id, "messageId": message_id}))
            }
            Err(stopped) => {
                let text = preview.or_else(|| input.text().map(str::to_string));
                self.record_stopped(
                    input.rule().clone(),
                    input.channel(),
                    "out",
                    "hold",
                    Some(input.vm_id()),
                    text.as_deref(),
                    Some(stopped),
                    None,
                    None,
                );
                Ok(json!({"ok": false}))
            }
        }
    }

    /// An app call the connector gate holds. `send` runs it on Send, with the agent's runtime token
    /// as it is then; its result goes nowhere. The hold's id, or `None` when nobody could be asked
    /// (the gate then stops the call).
    pub async fn hold_app(&self, h: crate::contracts::AppHold) -> Option<String> {
        self.hold_out("apps", h.what, h.where_, h.text, h.vm_id, &h.rule, h.send)
            .await
    }

    /// A team chat message the 3930 gate holds (`holdTeamChat`): `send` posts it on Send.
    pub async fn hold_team_chat(&self, h: crate::contracts::ChatHold) -> Option<String> {
        self.hold_out(
            "teamchat",
            "a team chat message".into(),
            h.where_,
            h.text,
            h.vm_id,
            &h.rule,
            h.send,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn hold_out(
        &self,
        channel: &str,
        what: String,
        where_: String,
        text: String,
        vm: String,
        rule: &crate::contracts::CheckedRule,
        send: Send_,
    ) -> Option<String> {
        let rule = Checked::from_contract(rule, "out").brief();
        let kept = self
            .keep(
                HeldMessage {
                    channel: channel.into(),
                    rule: rule.clone(),
                    what,
                    where_,
                    preview: text.clone(),
                    vm_id: vm.clone(),
                    send: Some(send),
                },
                None,
            )
            .await;
        match kept {
            Ok(id) => Some(id),
            Err(stopped) => {
                self.record_stopped(
                    rule,
                    channel,
                    "out",
                    "hold",
                    Some(&vm),
                    Some(&text),
                    Some(stopped),
                    None,
                    None,
                );
                None
            }
        }
    }

    /// Keep a message and ask the people who get codes. The hold's id, or why it was stopped instead.
    async fn keep(&self, held: HeldMessage, key: Option<&str>) -> Result<String, &'static str> {
        const NOBODY: &str = "nobody_asked";
        self.sweep();
        if self.holds().map.values().filter(|h| !h.done).count() >= HOLDS_MAX {
            return Err("too_many");
        }
        let buttons = (self.opts.buttons)();
        let routes: Vec<CodeRoute> = (self.opts.code_routes)()
            .into_iter()
            .filter(|r| r.telegram.is_some())
            .collect();
        let Some(buttons) = buttons.filter(|_| !routes.is_empty()) else {
            return Err(NOBODY);
        };
        let id = random_b64_12();
        let created_at = self.now();
        let (rule, channel, vm_id, preview_full) = (
            held.rule.clone(),
            held.channel.clone(),
            held.vm_id.clone(),
            held.preview.clone(),
        );
        let what = held.what.clone();
        let where_ = held.where_.clone();
        let (preview, _) = clean_line(&preview_full);
        let preview = js_slice(&preview, 600);
        let cut = if js_len(&preview) >= 600 { " (cut)" } else { "" };
        let lines = [
            format!("ControlClaw: a rule of your organization held {what} from your agent. It has not been sent."),
            format!("It is for {}.", clean_line(&where_).0),
        ];
        let tail = [
            String::new(),
            "Text below came from your rules and your agent, not from your firewall:".into(),
            format!("Rule: {}", clean_line(&rule.name).0),
            format!("Reason: {}", clean_line(&rule.reason).0),
            format!("Message: {preview}{cut}"),
        ];
        let render: crate::channels::chan::buttons::Render = Arc::new(move |outro: &str| {
            Ok(lines
                .iter()
                .cloned()
                .chain([outro.to_string()])
                .chain(tail.iter().cloned())
                .collect::<Vec<_>>()
                .join("\n"))
        });
        let outro = "Send it? It waits on your firewall for 24 hours, then it is dropped.";
        let text = render(outro).unwrap_or_default();
        // In place before anyone is asked: a Send or Don't send tapped while the others are still
        // being asked acts on it. Counted with the ones being asked, under the same lock as the
        // insert, so two at once cannot both take the last place.
        {
            let mut holds = self.holds();
            if holds.map.values().filter(|h| !h.done).count() >= HOLDS_MAX {
                return Err("too_many");
            }
            holds.map.insert(
                id.clone(),
                Hold {
                    held,
                    created_at,
                    offers: vec![],
                    done: false,
                    recorded_at: None,
                    asking: true,
                    closed_line: None,
                    finished: false,
                    released: false,
                    buttons: buttons.clone(),
                },
            );
        }
        // Everyone at once: the proxy waits for this answer, and one slow Telegram call per person in
        // turn would outlast it (it then stops the message, and this hold must not exist).
        let mut asks = Vec::new();
        for route in &routes {
            let Some(t) = &route.telegram else { continue };
            // A route with `telegram` is a Telegram connection: its approved senders are Telegram users.
            for sender in &route.senders {
                let CodeSender::Person { id: sender_id, .. } = sender else {
                    continue;
                };
                let b = buttons.clone();
                let input = DecisionInput {
                    change_id: format!("hold:{id}"),
                    route: TelegramButtonsRoute {
                        connection_id: t.connection_id.clone(),
                        bot_token: t.bot_token.clone(),
                    },
                    sender_id: sender_id.clone(),
                    text: text.clone(),
                    render: render.clone(),
                    expires_at: created_at + HOLD_TTL_MS,
                    owner: Arc::new(HoldOwner {
                        fw: self.me.clone(),
                        id: id.clone(),
                    }),
                    lines: DecisionLines {
                        approved: "Sending…".into(),
                        cancelled: "Not sent.".into(),
                        expired: "Nobody answered in 24 hours. It was not sent.".into(),
                    },
                };
                asks.push(async move { b.offer_decision(input).await });
            }
        }
        // Bounded well inside the proxy's wait (25 s): a hold must never outlive the proxy's answer.
        let mut all = tokio::spawn(futures_util::future::join_all(asks));
        let closed = "This request is closed. The message was not sent.";
        let offers: Vec<String> = match tokio::time::timeout(Duration::from_millis(self.opts.ask_ms), &mut all).await {
            Ok(Ok(o)) => o.into_iter().flatten().collect(),
            Ok(Err(_)) => vec![],
            Err(_) => {
                // Too slow: the proxy will stop the message, so whoever was asked is told it is
                // closed; unless someone already answered, then the message is theirs.
                let decided = self.finish_asking(&id);
                let me = self.me.clone();
                let (id2, b) = (id.clone(), buttons.clone());
                tokio::spawn(async move {
                    if let (Ok(late), Some(fw)) = (all.await, me.upgrade()) {
                        let late: Vec<String> = late.into_iter().flatten().collect();
                        fw.late_offers(&id2, late, &b, closed).await;
                    }
                });
                return if decided { Ok(id) } else { Err(NOBODY) };
            }
        };
        let settle_all = |offers: Vec<String>, line: String| {
            let b = buttons.clone();
            tokio::spawn(async move {
                for n in offers {
                    b.settle(Some(&n), "closed", Some(&line)).await;
                }
            });
        };
        // Checked and taken under one lock: an answer that comes in between is never missed.
        let answered = {
            let mut holds = self.holds();
            let cancelled = key.is_some_and(|k| holds.cancelled.shift_remove(k));
            let Some(h) = holds.map.get_mut(&id) else {
                return Err(NOBODY);
            };
            if h.done {
                true
            } else if offers.is_empty() || cancelled {
                holds.map.shift_remove(&id);
                drop(holds);
                settle_all(offers, closed.to_string());
                return Err(NOBODY);
            } else {
                h.offers = offers.clone();
                h.recorded_at = Some(created_at);
                if let Some(k) = key {
                    holds.by_key.insert(k.to_string(), id.clone());
                }
                false
            }
        };
        if answered {
            // Someone answered while the others were being asked: the message is theirs, and the
            // agent is not told it was stopped.
            self.finish_asking(&id);
            self.late_offers(&id, offers, &buttons, closed).await;
            return Ok(id);
        }
        // Recorded before the hold counts as made, so an answer settles an entry that is there.
        self.record_stopped(
            rule.clone(),
            &channel,
            "out",
            "hold",
            Some(&vm_id),
            Some(&preview_full),
            Some("waiting"),
            Some(&id),
            Some(created_at),
        );
        {
            let mut holds = self.holds();
            if let Some(h) = holds.map.get_mut(&id) {
                h.asking = false;
                if h.finished {
                    holds.map.shift_remove(&id);
                }
            }
        }
        tracing::info!(
            "[content-rules] held {what} under rule {} ({} asked)",
            rule.id,
            offers.len()
        );
        Ok(id)
    }

    /// The asking is over. A hold nobody decided is gone (false); one someone decided stays with
    /// whoever is sending it, or goes when that is done (true).
    fn finish_asking(&self, id: &str) -> bool {
        let mut holds = self.holds();
        let Some(h) = holds.map.get_mut(id) else { return false };
        h.asking = false;
        if !h.done {
            holds.map.shift_remove(id);
            return false;
        }
        true
    }

    /// Offers that came back after someone answered. While Send is still sending they join the
    /// hold, so its result reaches the presser's; the others' buttons go now ("Someone else pressed
    /// Send."). Once it is over, the presser's message gets the result and the others say someone
    /// else pressed Send; after Don't send, every one gets its words. A hold nobody decided: `closed`.
    async fn late_offers(&self, id: &str, offers: Vec<String>, buttons: &CodeButtons, closed: &str) {
        let (released, line) = {
            let mut holds = self.holds();
            match holds.map.get_mut(id) {
                Some(h) if h.done && !h.finished => {
                    h.offers.extend(offers.iter().cloned());
                    (h.released, None)
                }
                Some(h) => {
                    let r = (h.released, h.closed_line.clone());
                    if h.finished {
                        holds.map.shift_remove(id);
                    }
                    r
                }
                None => match holds.ended.get(id) {
                    Some((released, line)) => (*released, Some(line.clone())),
                    None => (false, None),
                },
            }
        };
        for n in offers {
            let others = released && buttons.is_open(&n);
            let words = match &line {
                _ if others => "Someone else pressed Send.".to_string(),
                // Still sending: the presser's message gets the result when it is done.
                None if released => continue,
                None => closed.to_string(),
                Some(l) => l.clone(),
            };
            buttons.settle(Some(&n), "closed", Some(&words)).await;
        }
    }

    /// Send pressed: the message goes out with the real token, unless the agent is stopped.
    async fn release(&self, id: &str) {
        let (send, rule, channel, vm_id, what, offers, recorded_at, buttons) = {
            let mut holds = self.holds();
            let Some(h) = holds.map.get_mut(id).filter(|h| !h.done) else {
                return;
            };
            h.done = true;
            h.released = true;
            h.closed_line = Some("Someone else pressed Send.".into());
            (
                h.held.send.take(),
                h.held.rule.clone(),
                h.held.channel.clone(),
                h.held.vm_id.clone(),
                h.held.what.clone(),
                h.offers.clone(),
                h.recorded_at,
                h.buttons.clone(),
            )
        };
        // Everyone else's buttons go now, before the send: a Don't send tapped while it is on its
        // way would otherwise say "Not sent." under a message that went.
        for nonce in offers.iter().filter(|n| buttons.is_open(n)) {
            buttons
                .settle(Some(nonce), "closed", Some("Someone else pressed Send."))
                .await;
        }
        let result = if (self.opts.locked)(&vm_id) {
            Err("the agent is under an emergency stop".to_string())
        } else {
            match send {
                Some(s) => s().await,
                None => Err("it was already sent".into()),
            }
        };
        let line = match &result {
            Ok(()) => {
                self.settle_stopped(id, recorded_at, "sent");
                let mut e = Map::new();
                e.insert("action".into(), json!("released"));
                e.insert("rule".into(), json!(rule.id));
                e.insert("channel".into(), json!(channel));
                e.insert("direction".into(), json!("out"));
                e.insert("vm_id".into(), json!(vm_id));
                e.insert("hold".into(), json!(id));
                self.audit(e, None);
                tracing::info!("[content-rules] released {what} under rule {}", rule.id);
                "Sent on your approval.".to_string()
            }
            Err(e) => {
                self.settle_stopped(id, recorded_at, "send_failed");
                tracing::info!("[content-rules] {what} held could not be sent: {e}");
                format!("It could not be sent: {e}.")
            }
        };
        // The offers as they are now: ones that came back while it was sending joined them.
        let offers = self.holds().map.get(id).map_or(offers, |h| h.offers.clone());
        for nonce in &offers {
            buttons.settle(Some(nonce), "closed", Some(&line)).await;
        }
        self.finish(id, line);
    }

    /// A hold Send or Don't send ended: gone, unless its people are still being asked (then
    /// `keep` takes it away, and tells the late offers `line`).
    fn finish(&self, id: &str, line: String) {
        let mut holds = self.holds();
        // Late offers of a hold already gone still learn how it ended.
        if let Some(released) = holds.map.get(id).map(|h| h.released) {
            holds.ended.insert(id.to_string(), (released, line.clone()));
            if holds.ended.len() > 100 {
                holds.ended.shift_remove_index(0);
            }
        }
        if let Some(h) = holds.map.get_mut(id) {
            h.closed_line = Some(line);
            if h.asking {
                h.finished = true;
            } else {
                holds.map.shift_remove(id);
            }
        }
        holds.by_key.retain(|_, v| v != id);
    }

    /// Don't send, or the proxy gave up waiting: the hold is dropped and nothing is sent.
    fn drop_hold(&self, id: &str, line: &str, outcome: &str) {
        let (rule, channel, vm_id, what, offers, recorded_at, buttons) = {
            let mut holds = self.holds();
            let Some(h) = holds.map.get_mut(id).filter(|h| !h.done) else {
                return;
            };
            h.done = true;
            (
                h.held.rule.clone(),
                h.held.channel.clone(),
                h.held.vm_id.clone(),
                h.held.what.clone(),
                h.offers.clone(),
                h.recorded_at,
                h.buttons.clone(),
            )
        };
        self.finish(id, line.to_string());
        self.settle_stopped(id, recorded_at, outcome);
        let line = line.to_string();
        tokio::spawn(async move {
            for nonce in offers {
                buttons.settle(Some(&nonce), "closed", Some(&line)).await;
            }
        });
        let mut e = Map::new();
        e.insert("action".into(), json!("dropped"));
        e.insert("rule".into(), json!(rule.id));
        e.insert("channel".into(), json!(channel));
        e.insert("direction".into(), json!("out"));
        e.insert("vm_id".into(), json!(vm_id));
        e.insert("hold".into(), json!(id));
        self.audit(e, None);
        tracing::info!("[content-rules] dropped {what} under rule {}", rule.id);
    }

    /// The proxy stopped waiting for a hold and told the agent the message was stopped: the hold
    /// must not exist. Called before the hold was made, it is remembered for when it is.
    pub fn cancel(&self, raw: &Value) -> Result<(), ()> {
        let key = raw.as_object().and_then(|m| re(m, "key", &HOLD_KEY)).ok_or(())?;
        let id = self.holds().by_key.get(key).cloned();
        if let Some(id) = id.filter(|id| self.holds().map.contains_key(id)) {
            // The proxy told the agent it was stopped: nobody had answered in time.
            self.drop_hold(&id, "This request is closed. The message was not sent.", "nobody_asked");
            return Ok(());
        }
        let mut holds = self.holds();
        holds.cancelled.insert(key.to_string());
        if holds.cancelled.len() > 200 {
            holds.cancelled.shift_remove_index(0);
        }
        Ok(())
    }

    /// Holds nobody decided: gone after 24 hours (the buttons expire on their own).
    pub fn sweep(&self) {
        let now = self.now();
        let gone: Vec<(String, bool, Option<i64>)> = {
            let mut holds = self.holds();
            let ids: Vec<String> = holds
                .map
                .iter()
                .filter(|(_, h)| now - h.created_at > HOLD_TTL_MS)
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| holds.map.shift_remove(&id).map(|h| (id, h.done, h.recorded_at)))
                .collect()
        };
        for (id, done, at) in gone {
            if !done {
                self.settle_stopped(&id, at, "expired");
            }
        }
    }

    // ---- notices --------------------------------------------------------------------------------

    /// The firewall's own line to the person in the chat, at most one a minute per chat. An error
    /// for a request that does not read.
    pub fn notice_input(&self, raw: &Value) -> Result<Notice, ()> {
        let v = with_channel(raw);
        let m = v.as_object().ok_or(())?;
        let kind = m
            .get("kind")
            .and_then(Value::as_str)
            .filter(|k| *k == "in" || *k == "out")
            .ok_or(())?
            .to_string();
        let vm_id = s_max(m, "vmId", 1, 100).ok_or(())?.to_string();
        let reason = s_max(m, "reason", 0, 240).ok_or(())?.to_string();
        let failed = match m.get("failed") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(()),
        };
        let opt_re = |k: &str, r: &Regex| -> Result<Option<String>, ()> {
            match m.get(k) {
                None => Ok(None),
                Some(_) => re(m, k, r).map(|s| Some(s.to_string())).ok_or(()),
            }
        };
        let to = match m.get("channel").and_then(Value::as_str) {
            Some("telegram") => NoticeTo::Telegram {
                bot_id: re(m, "botId", &BOT_ID).ok_or(())?.into(),
                chat_id: re(m, "chatId", &CHAT_ID).ok_or(())?.into(),
            },
            Some("slack") => NoticeTo::Slack {
                chat_id: re(m, "chatId", &SLACK_CHANNEL).ok_or(())?.into(),
                user_id: opt_re("userId", &SLACK_USER)?,
                thread_ts: opt_re("threadTs", &THREAD_TS)?,
                auth: match m.get("auth") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) if js_len(s) <= 200 => Some(s.clone()),
                    Some(_) => return Err(()),
                },
            },
            _ => return Err(()),
        };
        Ok(Notice {
            kind,
            vm_id,
            reason,
            failed,
            to,
        })
    }

    pub async fn notice(&self, n: Notice) {
        let key = match &n.to {
            NoticeTo::Telegram { bot_id, chat_id } => format!("telegram:{bot_id}:{chat_id}"),
            NoticeTo::Slack { chat_id, .. } => format!("slack:{}:{chat_id}", n.vm_id),
        };
        {
            let now = self.now();
            let mut last = self.last_notice.lock().unwrap_or_else(|e| e.into_inner());
            if now - last.get(&key).copied().unwrap_or(0) < NOTICE_GAP_MS {
                return;
            }
            last.insert(key, now);
        }
        // A reason that ends a sentence itself is not given a second full stop.
        static END: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\s.]+$").expect("regex"));
        let reason = END.replace(&clean_line(&n.reason).0, "").into_owned();
        let text = if n.kind == "out" {
            format!(
                "ControlClaw: a message from your agent was not sent. Your organization's rules stopped it: {reason}."
            )
        } else if n.failed {
            "ControlClaw: your last message was not passed on to the agent: the firewall could not check it against your organization's rules just now. Send it again later.".into()
        } else {
            format!(
                "ControlClaw: your last message was not passed on to the agent. Your organization's rules stopped it: {reason}."
            )
        };
        let (url, headers, body) = match &n.to {
            NoticeTo::Telegram { bot_id, chat_id } => {
                let Some(token) = (self.opts.telegram_token)(bot_id, &n.vm_id) else {
                    return;
                };
                (
                    format!("{TELEGRAM_API}/bot{token}/sendMessage"),
                    vec![("content-type".to_string(), "application/json".to_string())],
                    json!({"chat_id": chat_id, "text": text}),
                )
            }
            NoticeTo::Slack {
                chat_id,
                user_id,
                thread_ts,
                auth,
            } => {
                let Some(token) = self
                    .opts
                    .slack_token
                    .as_ref()
                    .and_then(|f| f(&n.vm_id, auth.as_deref()))
                else {
                    return;
                };
                let headers = vec![
                    (
                        "content-type".to_string(),
                        "application/json; charset=utf-8".to_string(),
                    ),
                    ("authorization".to_string(), format!("Bearer {token}")),
                ];
                // Coming in, only the person who wrote it sees the notice; going out, the
                // conversation does.
                match user_id.as_ref().filter(|_| n.kind == "in") {
                    Some(user) => (
                        format!("{SLACK_API}/chat.postEphemeral"),
                        headers,
                        json!({"channel": chat_id, "user": user, "text": text}),
                    ),
                    None => {
                        let mut b = json!({"channel": chat_id, "text": text});
                        if let Some(ts) = thread_ts {
                            b["thread_ts"] = json!(ts);
                        }
                        (format!("{SLACK_API}/chat.postMessage"), headers, b)
                    }
                }
            }
        };
        match self.opts.poster.post(url, headers, body.to_string()).await {
            Ok((status, json)) => {
                if !(200..300).contains(&status) || json.as_ref().and_then(|j| j.get("ok")) != Some(&Value::Bool(true))
                {
                    tracing::info!("[content-rules] notice not sent (HTTP {status})");
                }
            }
            Err(e) => tracing::info!("[content-rules] notice not sent: {e}"),
        }
    }
}

/// `noticeInput`.
pub struct Notice {
    kind: String,
    vm_id: String,
    reason: String,
    failed: bool,
    to: NoticeTo,
}

enum NoticeTo {
    Telegram {
        bot_id: String,
        chat_id: String,
    },
    Slack {
        chat_id: String,
        user_id: Option<String>,
        thread_ts: Option<String>,
        auth: Option<String>,
    },
}
