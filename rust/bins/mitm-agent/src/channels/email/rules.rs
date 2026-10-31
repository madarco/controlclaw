//! Email rules on the firewall (`email-rules.ts`, docs/plans/email-rules.md): who may email an
//! agent, and whom an agent may email. The proxy asks this module, over the `8792` loopback
//! listener, about every AgentMail message it is about to hand to an agent and every send it is
//! about to let out; it holds no rule itself. Only metadata is ever looked at: addresses, labels,
//! authentication results, counts.
//!
//!   email.read     {}
//!   email.propose  { changeId, change }
//!   email.confirm  { changeId, code }
//!   email.cancel   { changeId }
//!
//! A change that lets somebody new reach an agent, or be reached by one, needs a code; with nobody
//! to send one to, it is refused.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::auth::{
    GmailHeader, agentmail_verdict, gmail_verdict, parse_address_field, parse_from_address,
    recipients_from_header_block,
};
use super::schema::{
    EMAIL_GRANT_SECONDS, EmailChange, EmailRules, MAX_RECIPIENTS, Mode, RuleEntry, apply_change, describe_change,
    domain_of, effective_mode, listed, parse_change, parse_rules, widens,
};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeRequest, ConsentCodes, Verify};

const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;
const HELD_DAYS: i64 = 7;
const CODE_SCOPE: &str = "email";
const CODE_SUBJECT: &str = "your email rules";
const CODE_ATTEMPTS: u32 = 5;
/// An ask nobody answered in this long is asked again under a new id (the proxy asks each id once).
const STALE_ASK_MS: i64 = HOUR;
/// How long a removal is remembered: past it, every ask from before it is stale or its window is over.
const DROPPED_KEEP_MS: i64 = 2 * HOUR;
const FAILED: &str = "Email rules change could not be applied. Check the input, then retry.";
const NOBODY: &str = "No confirmation code could be delivered. Add a recipient on the Firewall page.";
const REJECTED: [&str; 3] = ["spam", "blocked", "unauthenticated"];
const FULL_KEYS: [&str; 6] = [
    "authentication_results",
    "headers",
    "text",
    "html",
    "extracted_text",
    "extracted_html",
];

fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// The scope string a recipient request is keyed by; the proxy hashes it into a permission id. The
/// ask number makes every approval a fresh request: an approved request stays approved in the
/// console, so reusing one id would turn "approve once" into "approve always".
pub fn recipient_scope(mailbox: &str, recipient: &str, n: u32) -> String {
    if n == 0 {
        format!("EMAIL {mailbox} -> {recipient}")
    } else {
        format!("EMAIL {mailbox} -> {recipient} #{n}")
    }
}

/// The mailbox and recipient of a scope `recipient_scope` made; `None` for any other scope.
pub fn parse_recipient_scope(scope: &str) -> Option<(String, String)> {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^EMAIL ((?:agentmail|gmail):\S+) -> (\S+?)(?: #\d+)?$").expect("regex")
    });
    let m = RE.captures(scope)?;
    Some((m[1].to_string(), m[2].to_string()))
}

/// The same id the proxy computes (`permission_id_for` in addon.py).
pub fn permission_id_for(scope: &str) -> String {
    format!("perm_{}", &sha_hex(scope)[..32])
}

fn hash_mailbox(m: &str) -> String {
    sha_hex(m)[..24].to_string()
}

/// Whether the lists alone let `mailbox` email `address`, before any one-time approval.
fn listed_recipient(rules: &EmailRules, address: &str, mailbox: &str) -> bool {
    listed(&rules.outbound.recipients, address, mailbox)
        || (rules.outbound.replies_to_senders && listed(&rules.inbound.senders, address, mailbox))
}

/// What identifies one Gmail message for its `email_held` line, so the same message held again is
/// one line: its Message-ID, or its sender, date and subject together. Only ever hashed.
pub fn gmail_message_key(headers: &[GmailHeader]) -> Option<String> {
    let h = |name: &str| {
        headers
            .iter()
            .find(|x| x.name.to_lowercase() == name)
            .map_or("", |x| x.value.as_str())
    };
    let id = h("message-id");
    if !id.is_empty() {
        return Some(id.to_string());
    }
    let (from, date, subject) = (h("from"), h("date"), h("subject"));
    (!from.is_empty() || !date.is_empty() || !subject.is_empty()).then(|| format!("{from}\n{date}\n{subject}"))
}

/// Metadata reads the firewall makes itself, with the real credential, never through the agent.
pub trait EmailLookups: Send + Sync {
    fn agentmail_message(&self, inbox_id: &str, message_id: &str)
    -> cc_http::BoxFuture<Result<Map<String, Value>, ()>>;
    fn agentmail_draft(&self, inbox_id: &str, draft_id: &str) -> cc_http::BoxFuture<Result<Map<String, Value>, ()>>;
    /// `To:`/`Cc:`/`Bcc:` of a Gmail draft, as a header block.
    fn gmail_draft_head(&self, draft_id: &str) -> cc_http::BoxFuture<Result<String, ()>>;
    /// The connected Google account's address, lowercased; `None` when there is none.
    fn gmail_account(&self) -> Option<String>;
}

type Codes = Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>;
pub type RevokeGrants = Arc<dyn Fn(&dyn Fn(&str) -> bool) -> Vec<String> + Send + Sync>;
/// `Ok(None)`: the AgentMail store could not be read, the move waits. `Err`: a stored list does not
/// parse, and the rules do not start (the TS's `senders()` throws in the constructor).
pub type LegacySenders = Arc<dyn Fn() -> Result<Option<Vec<(String, Vec<String>)>>, ()> + Send + Sync>;

pub struct EmailOptions {
    pub store_path: PathBuf,
    /// Plain JSON: send timestamps per hashed mailbox and held-message metadata.
    pub counters_path: PathBuf,
    /// The traffic log the activity shipper reads: one `email_held` line per message held back,
    /// with the reason only (docs/plans/rule-metrics.md). No address, no domain, no subject.
    pub log_path: Option<PathBuf>,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub codes: Codes,
    /// The routes, or why they are not known.
    pub code_routes: Arc<dyn Fn() -> Result<Vec<Value>, &'static str> + Send + Sync>,
    pub lookups: Arc<dyn EmailLookups>,
    pub grant_active: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// Ends the one-time approvals whose scope matches. Called when a change takes someone off the
    /// lists: an approval from before must not outlive the removal.
    pub revoke_grants: Option<RevokeGrants>,
    /// Each AgentMail inbox's old sender list, moved in once. `None` when the AgentMail store could
    /// not be read: the move then waits for a start where it can, rather than moving nothing.
    pub legacy_senders: Option<LegacySenders>,
    pub on_changed: Option<Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// `seeded`: AgentMail inboxes that already got their default sender, so a removal sticks.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Store {
    version: u32,
    rules: Value,
    #[serde(default)]
    migrated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seeded: Option<Vec<String>>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Held {
    at: i64,
    mailbox: String,
    reason: String,
    domain: Option<String>,
}

/// Per hashed mailbox+recipient: which ask this is, when it was asked, whether its grant was used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Episode {
    n: u32,
    asked_at: Option<i64>,
    used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_from: Option<i64>,
}

/// Someone a change took off the lists, and when.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Dropped {
    value: String,
    mailbox: Option<String>,
    at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Counters {
    sends: IndexMap<String, Vec<i64>>,
    held: Vec<Held>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    episodes: Option<IndexMap<String, Episode>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dropped: Option<Vec<Dropped>>,
}

struct Reservation {
    mailbox: String,
    at: i64,
    draft: Option<String>,
}

struct Cached {
    deliver: bool,
    reason: Option<String>,
}

struct State {
    store: Store,
    rules: EmailRules,
    counters: Counters,
    reservations: HashMap<String, Reservation>,
    /// Drafts whose send is being checked or is on its way: an edit now could change the recipients.
    drafts_in_flight: HashMap<String, i64>,
    /// AgentMail verdicts by message id, so attachment reads need no second lookup.
    verdicts: IndexMap<String, Cached>,
}

/// keep: show as is. strip: show without the body preview. hide: never show.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundAction {
    pub action: &'static str,
    pub reason: Option<String>,
}

impl InboundAction {
    fn keep() -> Self {
        Self {
            action: "keep",
            reason: None,
        }
    }
    fn strip(reason: Option<&str>) -> Self {
        Self {
            action: "strip",
            reason: reason.map(str::to_string),
        }
    }
    fn hide(reason: &str) -> Self {
        Self {
            action: "hide",
            reason: Some(reason.to_string()),
        }
    }
    pub fn to_json(&self) -> Value {
        match &self.reason {
            Some(r) => json!({"action": self.action, "reason": r}),
            None => json!({"action": self.action}),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ask {
    pub scope: String,
    pub summary: String,
    pub recipient: String,
    pub mailbox: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SendDecision {
    Allow { id: String },
    Block { reason: &'static str },
    Ask { asks: Vec<Ask> },
}

impl SendDecision {
    pub fn to_json(&self) -> Map<String, Value> {
        let v = match self {
            SendDecision::Allow { id } => json!({"decision": "allow", "id": id}),
            SendDecision::Block { reason } => json!({"decision": "block", "reason": reason}),
            SendDecision::Ask { asks } => json!({"decision": "ask", "asks": asks.iter().map(|a| json!({
                "scope": a.scope, "summary": a.summary, "recipient": a.recipient, "mailbox": a.mailbox,
            })).collect::<Vec<_>>()}),
        };
        v.as_object().cloned().unwrap_or_default()
    }
}

/// `reserveInput`, parsed.
#[derive(Debug, Clone)]
pub struct ReserveInput {
    pub provider: String,
    pub inbox_id: Option<String>,
    pub op: String,
    pub message_id: Option<String>,
    pub draft_id: Option<String>,
    pub to: Option<Value>,
    pub cc: Option<Value>,
    pub bcc: Option<Value>,
    pub head: Option<String>,
}

use crate::channels::js::js_len;

/// An optional string as zod's `.string().max(n).optional()`: absent is fine, `null` is not.
fn opt_str(p: &Map<String, Value>, k: &str, max: usize) -> Result<Option<String>, ()> {
    match p.get(k) {
        None => Ok(None),
        Some(Value::String(s)) if js_len(s) <= max => Ok(Some(s.clone())),
        _ => Err(()),
    }
}

pub fn parse_reserve(p: &Map<String, Value>) -> Result<ReserveInput, ()> {
    if p.get("action").and_then(Value::as_str) != Some("email.reserve") {
        return Err(());
    }
    let vm = p.get("vmId").and_then(Value::as_str).ok_or(())?;
    if vm.is_empty() || js_len(vm) > 100 {
        return Err(());
    }
    let provider = p.get("provider").and_then(Value::as_str).ok_or(())?;
    if !matches!(provider, "agentmail" | "gmail") {
        return Err(());
    }
    let op = p.get("op").and_then(Value::as_str).ok_or(())?;
    if !matches!(op, "send" | "reply" | "reply_all" | "forward" | "draft_send") {
        return Err(());
    }
    // `.` and `..` would be normalised out of the lookup path and read another resource.
    let id = |k: &str| -> Result<Option<String>, ()> {
        let v = opt_str(p, k, 998)?;
        if v.as_deref().is_some_and(|v| v == "." || v == "..") {
            return Err(());
        }
        Ok(v)
    };
    Ok(ReserveInput {
        provider: provider.into(),
        inbox_id: opt_str(p, "inboxId", 254)?,
        op: op.into(),
        message_id: id("messageId")?,
        draft_id: id("draftId")?,
        to: p.get("to").cloned(),
        cc: p.get("cc").cloned(),
        bcc: p.get("bcc").cloned(),
        head: opt_str(p, "head", 262_144)?,
    })
}

/// `inboundInput`, parsed: the inbox and the items the proxy is about to show.
pub fn parse_inbound(p: &Map<String, Value>) -> Result<(String, Vec<Map<String, Value>>), ()> {
    if p.get("action").and_then(Value::as_str) != Some("email.inbound")
        || p.get("provider").and_then(Value::as_str) != Some("agentmail")
    {
        return Err(());
    }
    let inbox = p
        .get("inboxId")
        .and_then(Value::as_str)
        .filter(|s| js_len(s) <= 254)
        .ok_or(())?;
    let items = p
        .get("items")
        .and_then(Value::as_array)
        .filter(|a| a.len() <= 200)
        .ok_or(())?;
    let items = items
        .iter()
        .map(|i| i.as_object().cloned().ok_or(()))
        .collect::<Result<Vec<_>, ()>>()?;
    Ok((inbox.to_string(), items))
}

fn labels_of(v: Option<&Value>) -> Vec<Value> {
    v.and_then(Value::as_array).cloned().unwrap_or_default()
}

fn has(labels: &[Value], l: &str) -> bool {
    labels.iter().any(|x| x.as_str() == Some(l))
}

/// `ts` as `Date.now() / 1000` prints in JSON: whole seconds without a fraction.
fn js_seconds(ms: i64) -> Value {
    if ms % 1000 == 0 {
        json!(ms / 1000)
    } else {
        json!(ms as f64 / 1000.0)
    }
}

fn outcome(ok: bool, status: &str, message: Option<&str>, data: Option<Value>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.into(),
        message: message.map(str::to_string),
        data: data.and_then(|d| d.as_object().cloned()),
    }
}

/// A draft marked in flight by `reserve`: released on drop unless the send was allowed.
struct DraftHold<'a> {
    fw: &'a EmailRulesFirewall,
    key: String,
    keep: bool,
}

impl Drop for DraftHold<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.fw.lock().drafts_in_flight.remove(&self.key);
        }
    }
}

pub struct EmailRulesFirewall {
    opts: EmailOptions,
    aad: String,
    /// The commands, one at a time (the TS `serial`). The checks the proxy asks for do not wait on it.
    serial: tokio::sync::Mutex<()>,
    st: Mutex<State>,
}

impl EmailRulesFirewall {
    /// `Err` when the stored rules cannot be read field for field: email sends and AgentMail
    /// delivery are then refused, as the TS refuses them when its constructor throws.
    pub fn new(opts: EmailOptions) -> Result<Arc<Self>, String> {
        let aad = format!("{}:{}:email-rules", opts.org_id, opts.box_id);
        let log = |l: &str| tracing::info!("{l}");
        let stored =
            cc_crypto::enc_file::load_store_or_empty("email-rules", &opts.store_path, &opts.box_key, &aad, &log);
        let (store, rules) = match stored {
            Some(v) => {
                let store: Store =
                    serde_json::from_value(v).map_err(|_| "Unsupported email rules store".to_string())?;
                if store.version != 1 {
                    return Err("Unsupported email rules store".into());
                }
                let rules = parse_rules(&store.rules).ok_or("The stored email rules do not parse")?;
                (store, rules)
            }
            None => {
                let rules = EmailRules::default();
                let store = Store {
                    version: 1,
                    rules: serde_json::to_value(&rules).map_err(|e| e.to_string())?,
                    migrated: false,
                    seeded: None,
                    extra: Map::new(),
                };
                (store, rules)
            }
        };
        let counters = load_counters(&opts.counters_path);
        let me = Arc::new(Self {
            aad,
            serial: tokio::sync::Mutex::new(()),
            st: Mutex::new(State {
                store,
                rules,
                counters,
                reservations: HashMap::new(),
                drafts_in_flight: HashMap::new(),
                verdicts: IndexMap::new(),
            }),
            opts,
        });
        // As the TS constructor: a first start whose move cannot be saved does not start at all.
        me.migrate()
            .map_err(|()| "the email rules store could not be written".to_string())?;
        Ok(me)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    /// Write the store with these rules; the state changes only once that worked.
    fn commit(&self, st: &mut State, rules: EmailRules, migrated: bool, seeded: Option<Vec<String>>) -> Result<(), ()> {
        let mut store = st.store.clone();
        store.rules = serde_json::to_value(&rules).map_err(|_| ())?;
        store.migrated = migrated;
        store.seeded = seeded;
        let v = serde_json::to_value(&store).map_err(|_| ())?;
        cc_crypto::enc_file::save_store("email-rules", &self.opts.store_path, &v, &self.opts.box_key, &self.aad)
            .map_err(|e| tracing::error!("[email] could not save the rules: {}", e.0))?;
        st.store = store;
        st.rules = rules;
        Ok(())
    }

    /// Move each AgentMail inbox's sender list in, scoped to that inbox. No code: these senders
    /// are already allowed today, so nothing widens (docs/plans/email-rules.md §3).
    fn migrate(&self) -> Result<(), ()> {
        if self.lock().store.migrated {
            return Ok(());
        }
        let legacy = match &self.opts.legacy_senders {
            Some(f) => match f()? {
                Some(l) => l,
                None => return Ok(()),
            },
            None => vec![],
        };
        let mut st = self.lock();
        let mut rules = st.rules.clone();
        let mut seeded: Vec<String> = st.store.seeded.clone().unwrap_or_default();
        for (inbox, senders) in legacy {
            let id = inbox.to_lowercase();
            if !seeded.contains(&id) {
                seeded.push(id.clone());
            }
            for value in senders {
                // A duplicate or unparseable legacy entry is skipped.
                if let Some(change) = parse_change(
                    &json!({"action": "add_sender", "entry": {"value": value, "mailbox": format!("agentmail:{id}")}}),
                ) && let Ok(next) = apply_change(&rules, &change)
                {
                    rules = next;
                }
            }
        }
        self.commit(&mut st, rules, true, Some(seeded))
    }

    /// A new AgentMail inbox gets the AgentMail account owner's address as its one sender, once.
    /// No code: that address is the verified owner of the account the firewall holds. Removing it
    /// later sticks.
    pub fn seed_inbox(&self, inbox_id: &str, owner_email: Option<&str>) {
        let id = inbox_id.to_lowercase();
        let mut st = self.lock();
        let seeded = st.store.seeded.clone().unwrap_or_default();
        if !st.store.migrated || seeded.contains(&id) {
            return;
        }
        let mut rules = st.rules.clone();
        if let Some(owner) = owner_email
            && let Some(change) = parse_change(
                &json!({"action": "add_sender", "entry": {"value": owner, "mailbox": format!("agentmail:{id}")}}),
            )
            && let Ok(next) = apply_change(&rules, &change)
        {
            rules = next;
        }
        let mut seeded = seeded;
        seeded.push(id);
        let _ = self.commit(&mut st, rules, true, Some(seeded));
    }

    fn save_counters(&self, c: &mut Counters) {
        let now = self.now();
        c.sends.retain(|_, list| {
            list.retain(|t| now - t < DAY);
            !list.is_empty()
        });
        c.held.retain(|h| now - h.at < HELD_DAYS * DAY);
        if c.held.len() > 500 {
            c.held.drain(..c.held.len() - 500);
        }
        if let Some(d) = c.dropped.as_mut() {
            d.retain(|d| now - d.at < DROPPED_KEEP_MS);
        }
        if let Some(eps) = c.episodes.as_mut() {
            eps.retain(|_, ep| ep.used || ep.asked_at.is_none_or(|a| now - a <= 30 * DAY));
        }
        // Counting carries on in memory when this fails.
        let path = &self.opts.counters_path;
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        let tmp = path.with_file_name(format!(".{name}.tmp"));
        let Ok(body) = serde_json::to_string(c) else { return };
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(body.as_bytes())?;
            std::fs::rename(&tmp, path)
        };
        let _ = write();
    }

    pub fn rules(&self) -> EmailRules {
        self.lock().rules.clone()
    }

    /// Whether an address is an allowed sender for a mailbox (`agentmail:<inbox>` or `gmail:<account>`).
    #[allow(dead_code)] // the meetings' organizer check (H7)
    pub fn sender_listed(&self, address: &str, mailbox: &str) -> bool {
        listed(&self.lock().rules.inbound.senders, address, &mailbox.to_lowercase())
    }

    fn summary_of(&self, st: &State) -> Value {
        let now = self.now();
        let mut held: IndexMap<String, Value> = IndexMap::new();
        for h in &st.counters.held {
            if now - h.at >= HELD_DAYS * DAY {
                continue;
            }
            let k = format!("{}|{}|{}", h.mailbox, h.reason, h.domain.as_deref().unwrap_or("null"));
            let e = held
                .entry(k)
                .or_insert_with(|| json!({"mailbox": h.mailbox, "reason": h.reason, "domain": h.domain, "count": 0}));
            e["count"] = json!(e["count"].as_u64().unwrap_or(0) + 1);
        }
        json!({"rules": st.rules, "held": held.into_values().collect::<Vec<_>>()})
    }

    /// For the beat: the rules and what was held back this week, by mailbox, reason and domain.
    pub fn summary(&self) -> Value {
        let st = self.lock();
        self.summary_of(&st)
    }

    /// What the agent's AgentMail channel is told to accept for one inbox: the exact listed
    /// addresses, or `["*"]` when a domain entry (or more than the channel takes) applies. The
    /// firewall has already checked every message the channel sees.
    pub fn allow_from(&self, inbox_id: &str) -> Vec<String> {
        let mailbox = format!("agentmail:{inbox_id}").to_lowercase();
        let st = self.lock();
        let entries: Vec<&RuleEntry> = st
            .rules
            .inbound
            .senders
            .iter()
            .filter(|e| e.mailbox.as_deref().is_none_or(|m| m == mailbox))
            .collect();
        if entries.iter().any(|e| e.value.starts_with('@')) || entries.len() > 50 {
            return vec!["*".into()];
        }
        let mut out: Vec<String> = vec![];
        for e in entries {
            if !out.contains(&e.value) {
                out.push(e.value.clone());
            }
        }
        out
    }

    pub async fn command(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _serial = self.serial.lock().await;
        self.run(action, &payload)
            .await
            .unwrap_or_else(|()| outcome(false, "failed", Some(FAILED), None))
    }

    async fn run(&self, action: &str, p: &Map<String, Value>) -> Result<CommandOutcome, ()> {
        if action == "read" {
            return Ok(outcome(true, "read", None, Some(self.summary())));
        }
        let change_id = p
            .get("changeId")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty() && js_len(c) <= 100)
            .ok_or(())?
            .to_string();
        let codes = (self.opts.codes)();
        if action == "cancel" {
            if let Some(c) = &codes {
                c.cancel(CODE_SCOPE, Some(&change_id));
            }
            return Ok(outcome(true, "cancelled", None, None));
        }
        if action == "confirm" {
            let code = p
                .get("code")
                .and_then(Value::as_str)
                .filter(|c| js_len(c) <= 20)
                .ok_or(())?;
            let verdict = codes.map_or(Verify::Unknown, |c| c.verify(CODE_SCOPE, &change_id, code));
            return match verdict {
                Verify::Ok(proposal) => {
                    let change = proposal.get("change").and_then(parse_change).ok_or(())?;
                    self.apply(&change).await
                }
                Verify::Wrong { tries_left } => Ok(outcome(
                    false,
                    "invalid",
                    None,
                    Some(json!({"attemptsLeft": tries_left})),
                )),
                Verify::Expired | Verify::Unknown => Ok(outcome(false, "expired", None, Some(json!({})))),
            };
        }
        if action != "propose" {
            return Err(());
        }
        let change = p.get("change").and_then(parse_change).ok_or(())?;
        let rules = self.rules();
        let next = apply_change(&rules, &change).map_err(|_| ())?;
        if let Some(c) = &codes {
            c.forget(CODE_SCOPE);
        }
        if !widens(&rules, &next) {
            return self.apply(&change).await;
        }
        // No codes on this firewall, or nobody to send one to: refused (fail closed).
        let Some(codes) = codes else {
            return Ok(outcome(false, "failed", Some(NOBODY), None));
        };
        // Not known (the channel list cannot be read, or an approved person's agent has no address):
        // said as it is, not as "nobody".
        let routes = match (self.opts.code_routes)() {
            Ok(r) => r,
            Err(why) => return Ok(outcome(false, "failed", Some(why), None)),
        };
        if routes.is_empty() {
            return Ok(outcome(false, "failed", Some(NOBODY), None));
        }
        let sent = codes
            .send(CodeRequest {
                scope: CODE_SCOPE.into(),
                change_id: change_id.clone(),
                proposal: json!({"changeId": change_id, "change": change}),
                agent_name: CODE_SUBJECT.into(),
                summary: describe_change(&change, Some(&next)),
                routes,
            })
            .await;
        Ok(match sent.sent_via {
            Some(via) => outcome(
                true,
                "awaiting_code",
                None,
                Some(json!({
                    "sentVia": via,
                    "expiresAt": cc_crypto::store_health::iso_from_millis(sent.expires_at_ms),
                    "attemptsLeft": CODE_ATTEMPTS,
                })),
            ),
            None => outcome(false, "failed", Some(NOBODY), None),
        })
    }

    async fn apply(&self, change: &EmailChange) -> Result<CommandOutcome, ()> {
        {
            let mut st = self.lock();
            // Re-applied to the rules as they are now: another change may have landed in between.
            let before = st.rules.clone();
            let after = apply_change(&before, change).map_err(|_| ())?;
            let (migrated, seeded) = (st.store.migrated, st.store.seeded.clone());
            self.commit(&mut st, after.clone(), migrated, seeded)?;
            self.revoke_dropped(&mut st, &before, &after);
            // A verdict is a function of the rules: a released sender's mail must show, a removed one's not.
            st.verdicts.clear();
        }
        // The AgentMail push is retried by its own reconcile.
        if let Some(f) = &self.opts.on_changed {
            f().await;
        }
        Ok(outcome(true, "applied", None, Some(self.summary())))
    }

    /// Someone the lists let the agents email before this change, and no longer: any one-time
    /// approval for them ends now too. The removal is remembered, so an ask from before it is never
    /// honoured, whether its approval is in grants.json now or arrives later. Their next send asks
    /// again, under a new id.
    fn revoke_dropped(&self, st: &mut State, before: &EmailRules, after: &EmailRules) {
        let gone = |list: &[RuleEntry], kept: &[RuleEntry]| -> Vec<RuleEntry> {
            list.iter().filter(|e| !kept.contains(e)).cloned().collect()
        };
        let mut dropped = gone(&before.outbound.recipients, &after.outbound.recipients);
        if before.outbound.replies_to_senders {
            let kept: &[RuleEntry] = if after.outbound.replies_to_senders {
                &after.inbound.senders
            } else {
                &[]
            };
            dropped.extend(gone(&before.inbound.senders, kept));
        }
        if dropped.is_empty() {
            return;
        }
        let at = self.now();
        st.counters
            .dropped
            .get_or_insert_with(Vec::new)
            .extend(dropped.into_iter().map(|e| Dropped {
                value: e.value,
                mailbox: e.mailbox,
                at,
            }));
        self.save_counters(&mut st.counters);
        // The grants there are now, ended, and the console told (`cc-perm status` says revoked).
        if let Some(revoke) = &self.opts.revoke_grants {
            revoke(&|scope: &str| {
                parse_recipient_scope(scope)
                    .is_some_and(|(mb, r)| listed_recipient(before, &r, &mb) && !listed_recipient(after, &r, &mb))
            });
        }
    }

    /// Whether a change took `recipient` off the lists for `mailbox` after `since`.
    fn dropped_since(st: &State, mailbox: &str, recipient: &str, since: i64) -> bool {
        st.counters.dropped.as_deref().unwrap_or_default().iter().any(|d| {
            d.at > since
                && listed(
                    &[RuleEntry {
                        value: d.value.clone(),
                        mailbox: d.mailbox.clone(),
                    }],
                    recipient,
                    mailbox,
                )
        })
    }

    // ---- inbound ------------------------------------------------------------------------------

    fn hold(&self, st: &mut State, mailbox: &str, reason: &str, from: Option<&str>, message_id: Option<&str>) {
        st.counters.held.push(Held {
            at: self.now(),
            mailbox: mailbox.into(),
            reason: reason.into(),
            domain: from.and_then(domain_of),
        });
        self.save_counters(&mut st.counters);
        let Some(log) = &self.opts.log_path else { return };
        // The same message held again is the same line: its id comes from the message.
        let id = match message_id {
            Some(m) => sha_hex(&format!("{mailbox}|{m}"))[..24].to_string(),
            None => hex::encode(rand::random::<[u8; 12]>()),
        };
        let rec = json!({
            "source": "email_held",
            "id": id,
            "ts": js_seconds(self.now()),
            "direction": "in",
            "provider": if mailbox.starts_with("gmail:") { "gmail" } else { "agentmail" },
            "reason": reason.chars().take(64).collect::<String>(),
        });
        // Activity must never be what fails a check.
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(log) {
            let _ = writeln!(f, "{rec}");
        }
    }

    /// Whether one received AgentMail message (full, with its authentication fields) may reach the agent.
    pub fn agentmail_inbound(&self, inbox_id: &str, msg: &Map<String, Value>) -> InboundAction {
        let mut st = self.lock();
        self.agentmail_inbound_in(&mut st, inbox_id, msg)
    }

    fn agentmail_inbound_in(&self, st: &mut State, inbox_id: &str, msg: &Map<String, Value>) -> InboundAction {
        let labels = labels_of(msg.get("labels"));
        if !has(&labels, "received") && has(&labels, "sent") {
            return InboundAction::keep();
        }
        let mailbox = format!("agentmail:{inbox_id}").to_lowercase();
        let (verdict, from) = agentmail_verdict(msg);
        let out = match verdict {
            Err(reason) => InboundAction::hide(reason),
            Ok(()) if !listed(&st.rules.inbound.senders, from.as_deref().unwrap_or(""), &mailbox) => {
                InboundAction::hide("not_allowed")
            }
            Ok(()) => InboundAction::keep(),
        };
        if let Some(id) = msg.get("message_id").and_then(Value::as_str).filter(|i| !i.is_empty()) {
            if out.action == "hide" && !st.verdicts.contains_key(id) {
                let reason = out.reason.clone().unwrap_or_default();
                self.hold(st, &mailbox, &reason, from.as_deref(), Some(id));
            }
            st.verdicts.insert(
                id.to_string(),
                Cached {
                    deliver: out.action == "keep",
                    reason: out.reason.clone(),
                },
            );
            if st.verdicts.len() > 5000 {
                st.verdicts.shift_remove_index(0);
            }
        }
        out
    }

    fn cached(c: &Cached) -> InboundAction {
        if c.deliver {
            InboundAction::keep()
        } else {
            InboundAction {
                action: "hide",
                reason: c.reason.clone(),
            }
        }
    }

    /// A list entry: no authentication fields. Anything that fails on what it does show is hidden;
    /// the rest keeps its id, sender and subject, and its preview only once a full read passed.
    fn agentmail_list_item(st: &State, inbox_id: &str, msg: &Map<String, Value>) -> InboundAction {
        let labels = labels_of(msg.get("labels"));
        if !has(&labels, "received") && has(&labels, "sent") {
            return InboundAction::keep();
        }
        if REJECTED.iter().any(|r| has(&labels, r)) || !has(&labels, "received") {
            return InboundAction::hide("unauthenticated");
        }
        let Some(from) = msg.get("from").and_then(Value::as_str).and_then(parse_from_address) else {
            return InboundAction::hide("bad_from");
        };
        if !listed(
            &st.rules.inbound.senders,
            &from,
            &format!("agentmail:{inbox_id}").to_lowercase(),
        ) {
            return InboundAction::hide("not_allowed");
        }
        if let Some(c) = msg
            .get("message_id")
            .and_then(Value::as_str)
            .and_then(|id| st.verdicts.get(id))
        {
            return Self::cached(c);
        }
        InboundAction::strip(Some("unverified"))
    }

    /// A thread list entry: hidden unless somebody listed wrote in it; its preview is never shown.
    fn agentmail_thread_item(st: &State, inbox_id: &str, t: &Map<String, Value>) -> InboundAction {
        let labels = labels_of(t.get("labels"));
        if REJECTED.iter().any(|r| has(&labels, r)) {
            return InboundAction::hide("unauthenticated");
        }
        let me = inbox_id.to_lowercase();
        let senders: Vec<Option<String>> = labels_of(t.get("senders"))
            .iter()
            .map(|x| x.as_str().and_then(parse_from_address))
            .filter(|x| x.as_deref() != Some(me.as_str()))
            .collect();
        if senders.is_empty() {
            return InboundAction::strip(None);
        }
        let mailbox = format!("agentmail:{me}");
        if senders
            .iter()
            .flatten()
            .any(|x| listed(&st.rules.inbound.senders, x, &mailbox))
        {
            InboundAction::strip(None)
        } else {
            InboundAction::hide("not_allowed")
        }
    }

    /// Whether one Gmail message may wake an agent (§2.3). Used by the Gmail push module.
    pub fn gmail_inbound(
        &self,
        headers: &[GmailHeader],
        labels: &[String],
    ) -> (bool, Option<&'static str>, Option<String>) {
        let Some(account) = self.opts.lookups.gmail_account() else {
            return (false, Some("no_account"), None);
        };
        let mailbox = format!("gmail:{account}");
        let mut st = self.lock();
        let (verdict, from) = gmail_verdict(headers, labels, st.rules.inbound.require_auth);
        let key = gmail_message_key(headers);
        if let Err(reason) = verdict {
            self.hold(&mut st, &mailbox, reason, from.as_deref(), key.as_deref());
            return (false, Some(reason), from);
        }
        if !listed(&st.rules.inbound.senders, from.as_deref().unwrap_or(""), &mailbox) {
            self.hold(&mut st, &mailbox, "not_allowed", from.as_deref(), key.as_deref());
            return (false, Some("not_allowed"), from);
        }
        (true, None, from)
    }

    /// The proxy's question about AgentMail messages and threads it is about to show the agent.
    pub async fn inbound(&self, inbox_id: &str, items: &[Map<String, Value>]) -> Vec<InboundAction> {
        let mut out = vec![];
        for item in items {
            let kind = item.get("kind").and_then(Value::as_str);
            if kind == Some("thread") {
                out.push(Self::agentmail_thread_item(&self.lock(), inbox_id, item));
            } else if kind == Some("ref") {
                let Some(id) = item.get("message_id").and_then(Value::as_str).filter(|i| !i.is_empty()) else {
                    out.push(InboundAction::hide("bad_request"));
                    continue;
                };
                if let Some(a) = self.lock().verdicts.get(id).map(Self::cached) {
                    out.push(a);
                    continue;
                }
                match self.opts.lookups.agentmail_message(inbox_id, id).await {
                    Ok(m) => out.push(self.agentmail_inbound(inbox_id, &m)),
                    Err(()) => out.push(InboundAction::hide("lookup_failed")),
                }
            } else if FULL_KEYS.iter().any(|k| item.contains_key(*k)) {
                out.push(self.agentmail_inbound(inbox_id, item));
            } else {
                out.push(Self::agentmail_list_item(&self.lock(), inbox_id, item));
            }
        }
        out
    }

    // ---- outbound -----------------------------------------------------------------------------

    async fn recipients(&self, input: &ReserveInput) -> Result<Option<(String, Vec<String>)>, ()> {
        if input.provider == "gmail" {
            let Some(account) = self.opts.lookups.gmail_account() else {
                return Ok(None);
            };
            let mut head = input.head.clone();
            if input.op == "draft_send" && head.is_none() {
                let Some(d) = &input.draft_id else { return Ok(None) };
                head = Some(self.opts.lookups.gmail_draft_head(d).await?);
            }
            let Some(head) = head.filter(|_| input.op == "send" || input.op == "draft_send") else {
                return Ok(None);
            };
            return Ok(recipients_from_header_block(&head).map(|l| (format!("gmail:{account}"), l)));
        }
        let Some(raw_inbox) = input.inbox_id.as_deref().filter(|i| !i.is_empty()) else {
            return Ok(None);
        };
        let inbox = raw_inbox.to_lowercase();
        let mailbox = format!("agentmail:{inbox}");
        let mut list = vec![];
        for f in [&input.to, &input.cc, &input.bcc] {
            match parse_address_field(f.as_ref()) {
                Some(l) => list.extend(l),
                None => return Ok(None),
            }
        }
        if input.op == "draft_send" {
            let Some(d) = &input.draft_id else { return Ok(None) };
            let d = self.opts.lookups.agentmail_draft(raw_inbox, d).await?;
            for k in ["to", "cc", "bcc"] {
                match parse_address_field(d.get(k)) {
                    Some(l) => list.extend(l),
                    None => return Ok(None),
                }
            }
        } else if input.op == "reply" || input.op == "reply_all" {
            let Some(id) = &input.message_id else { return Ok(None) };
            let m = self.opts.lookups.agentmail_message(raw_inbox, id).await?;
            // A reply goes to Reply-To, else From; reply-all adds the original To and Cc. A `to`,
            // `cc` or `bcc` in the request is counted on top, whatever AgentMail does with it.
            let (Some(reply_to), Some(from)) = (
                parse_address_field(m.get("reply_to")),
                parse_address_field(m.get("from")),
            ) else {
                return Ok(None);
            };
            list.extend(if reply_to.is_empty() { from } else { reply_to });
            if input.op == "reply_all" {
                for k in ["to", "cc"] {
                    match parse_address_field(m.get(k)) {
                        Some(l) => list.extend(l),
                        None => return Ok(None),
                    }
                }
            }
        }
        let mut seen = HashSet::new();
        let list = list
            .into_iter()
            .filter(|a| a != &inbox && seen.insert(a.clone()))
            .collect();
        Ok(Some((mailbox, list)))
    }

    /// The proxy's question before a send: allow (and count), block, or ask the owner.
    pub async fn reserve(&self, input: &ReserveInput) -> SendDecision {
        let draft = match (&input.op[..], &input.draft_id) {
            ("draft_send", Some(d)) if !d.is_empty() => Some(format!(
                "{}:{}:{}",
                input.provider,
                input.inbox_id.as_deref().unwrap_or(""),
                d
            )),
            _ => None,
        };
        let mut hold = None;
        if let Some(d) = &draft {
            let now = self.now();
            let mut st = self.lock();
            // A send that never settled (the proxy gave up, nothing settled it) holds the draft for
            // ten minutes at most, as `draft_write` reads it.
            if st.drafts_in_flight.get(d).is_some_and(|at| now - at > 10 * 60_000) {
                st.drafts_in_flight.remove(d);
            }
            if st.drafts_in_flight.contains_key(d) {
                return SendDecision::Block { reason: "draft_busy" };
            }
            st.drafts_in_flight.insert(d.clone(), now);
            hold = Some(DraftHold {
                fw: self,
                key: d.clone(),
                keep: false,
            });
        }
        let out = self.reserve_checked(input, draft.as_deref()).await;
        // Released unless the send goes ahead, also when this future is dropped half way (the proxy
        // hung up while a lookup was still out).
        if let Some(h) = hold.as_mut() {
            h.keep = matches!(out, SendDecision::Allow { .. });
        }
        out
    }

    /// The proxy's question before editing a draft: refused while that draft's send is in flight.
    pub fn draft_write(&self, provider: &str, inbox_id: Option<&str>, draft_id: &str) -> bool {
        let key = format!("{provider}:{}:{draft_id}", inbox_id.unwrap_or(""));
        let now = self.now();
        let mut st = self.lock();
        if st.drafts_in_flight.get(&key).is_some_and(|at| now - at > 10 * 60_000) {
            st.drafts_in_flight.remove(&key);
        }
        !st.drafts_in_flight.contains_key(&key)
    }

    async fn reserve_checked(&self, input: &ReserveInput, draft: Option<&str>) -> SendDecision {
        let (mailbox, list) = match self.recipients(input).await {
            Err(()) => {
                return SendDecision::Block {
                    reason: "lookup_failed",
                };
            }
            Ok(None) => {
                return SendDecision::Block {
                    reason: "unreadable_recipients",
                };
            }
            Ok(Some(r)) => r,
        };
        if list.is_empty() {
            return SendDecision::Block {
                reason: "no_recipients",
            };
        }
        if list.len() > MAX_RECIPIENTS {
            return SendDecision::Block {
                reason: "too_many_recipients",
            };
        }
        let mut st = self.lock();
        let rules = st.rules.clone();
        let mode = effective_mode(&rules, &mailbox);
        if mode == Mode::Block {
            return SendDecision::Block { reason: "sending_off" };
        }
        // "anyone": no list check and no request; the recipient cap above and the limits below still apply.
        let unlisted: Vec<&String> = if mode == Mode::Anyone {
            vec![]
        } else {
            list.iter().filter(|a| !listed_recipient(&rules, a, &mailbox)).collect()
        };
        if !unlisted.is_empty() {
            if mode == Mode::Listed {
                return SendDecision::Block { reason: "not_allowed" };
            }
            let bare = mailbox.split_once(':').map_or(mailbox.as_str(), |(_, r)| r);
            let asks: Vec<Ask> = unlisted
                .iter()
                .filter_map(|a| {
                    self.approved_scope(&mut st, &mailbox, a).map(|scope| Ask {
                        scope,
                        summary: format!("Send email to {a} from {bare}"),
                        recipient: (*a).clone(),
                        mailbox: mailbox.clone(),
                    })
                })
                .collect();
            self.save_counters(&mut st.counters);
            if !asks.is_empty() {
                return SendDecision::Ask { asks };
            }
        }
        let key = hash_mailbox(&mailbox);
        let now = self.now();
        let mut all: Vec<i64> = st
            .counters
            .sends
            .get(&key)
            .map(|l| l.iter().copied().filter(|t| now - t < DAY).collect())
            .unwrap_or_default();
        all.extend(st.reservations.values().filter(|r| r.mailbox == key).map(|r| r.at));
        if all.iter().filter(|t| now - **t < HOUR).count() as i64 >= rules.outbound.per_hour {
            return SendDecision::Block { reason: "hourly_limit" };
        }
        if all.len() as i64 >= rules.outbound.per_day {
            return SendDecision::Block { reason: "daily_limit" };
        }
        let id = hex::encode(rand::random::<[u8; 24]>());
        st.reservations.insert(
            id.clone(),
            Reservation {
                mailbox: key,
                at: now,
                draft: draft.map(str::to_string),
            },
        );
        SendDecision::Allow { id }
    }

    /// `None` when an approved, unexpired grant covers `recipient` (it is marked used); otherwise
    /// the scope to ask under, moving to a new ask number once a grant was used or an ask went stale.
    fn approved_scope(&self, st: &mut State, mailbox: &str, recipient: &str) -> Option<String> {
        let key = hash_mailbox(&format!("{mailbox} {recipient}"));
        let now = self.now();
        let ep = st
            .counters
            .episodes
            .get_or_insert_with(IndexMap::new)
            .entry(key.clone())
            .or_insert(Episode {
                n: 0,
                asked_at: None,
                used: false,
                grant_from: None,
            })
            .clone();
        let fresh = |n: u32| Episode {
            n,
            asked_at: Some(now),
            used: false,
            grant_from: None,
        };
        // Taken off the lists since this id was asked: its approval, however it arrives, does not count.
        if let Some(asked) = ep.asked_at
            && Self::dropped_since(st, mailbox, recipient, asked)
        {
            self.put_episode(st, &key, fresh(ep.n + 1));
            return Some(recipient_scope(mailbox, recipient, ep.n + 1));
        }
        let mut ep = ep;
        // One window per approval, from the first send it covers: the bridge may grant the same id
        // again (after a restart it re-reads requests the console still has as approved).
        if (self.opts.grant_active)(&permission_id_for(&recipient_scope(mailbox, recipient, ep.n))) {
            let from = *ep.grant_from.get_or_insert(now);
            if now - from < EMAIL_GRANT_SECONDS * 1000 {
                ep.used = true;
                self.put_episode(st, &key, ep);
                return None;
            }
        }
        if ep.used || ep.grant_from.is_some() || ep.asked_at.is_some_and(|a| now - a > STALE_ASK_MS) {
            self.put_episode(st, &key, fresh(ep.n + 1));
            return Some(recipient_scope(mailbox, recipient, ep.n + 1));
        }
        ep.asked_at.get_or_insert(now);
        let n = ep.n;
        self.put_episode(st, &key, ep);
        Some(recipient_scope(mailbox, recipient, n))
    }

    fn put_episode(&self, st: &mut State, key: &str, ep: Episode) {
        st.counters
            .episodes
            .get_or_insert_with(IndexMap::new)
            .insert(key.to_string(), ep);
    }

    /// After the provider answered. A refused send (4xx) gives its slot back; anything else counts.
    pub fn settle(&self, id: &str, rejected: bool) {
        let mut st = self.lock();
        let Some(r) = st.reservations.remove(id) else { return };
        if let Some(d) = &r.draft {
            st.drafts_in_flight.remove(d);
        }
        if rejected {
            return;
        }
        st.counters.sends.entry(r.mailbox).or_default().push(r.at);
        self.save_counters(&mut st.counters);
    }

    /// A reservation the proxy never settled (a dropped connection) counts after ten minutes.
    pub fn sweep(&self) {
        let now = self.now();
        let stale: Vec<String> = self
            .lock()
            .reservations
            .iter()
            .filter(|(_, r)| now - r.at > 10 * 60_000)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.settle(&id, false);
        }
    }
}

/// A broken counters file starts empty; it holds nothing that must survive.
fn load_counters(path: &std::path::Path) -> Counters {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// The loopback service the proxy asks (`emailAdmission`): `POST /` with an `email.*` action.
/// Anything else, or anything that does not parse, is a 403 `{"ok":false}`.
pub fn router(rules: Arc<EmailRulesFirewall>) -> cc_http::Router {
    let mut router = cc_http::Router::new(&["email"]);
    router.route(
        "email",
        |_, _| true,
        move |req, _| {
            let rules = rules.clone();
            async move {
                use http_body_util::BodyExt;
                let refused = || cc_http::full(hyper::StatusCode::FORBIDDEN, "text/plain", "{\"ok\":false}");
                let (parts, body) = req.into_parts();
                let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
                if parts.method != hyper::Method::POST || target != "/" {
                    return refused();
                }
                let Ok(raw) = http_body_util::Limited::new(body, 1_048_576).collect().await else {
                    return refused();
                };
                let Ok(Value::Object(p)) = serde_json::from_slice::<Value>(&raw.to_bytes()) else {
                    return refused();
                };
                let Some(mut result) = answer(&rules, &p).await else {
                    return refused();
                };
                let mut out = Map::new();
                out.insert("ok".into(), Value::Bool(true));
                out.append(&mut result);
                cc_http::full(
                    hyper::StatusCode::OK,
                    "application/json",
                    Value::Object(out).to_string(),
                )
            }
        },
    );
    router
}

async fn answer(rules: &EmailRulesFirewall, p: &Map<String, Value>) -> Option<Map<String, Value>> {
    match p.get("action").and_then(Value::as_str)? {
        "email.reserve" => Some(rules.reserve(&parse_reserve(p).ok()?).await.to_json()),
        "email.settle" => {
            let id = p.get("id").and_then(Value::as_str)?;
            rules.settle(id, p.get("rejected") == Some(&Value::Bool(true)));
            Some(Map::new())
        }
        "email.inbound" => {
            let (inbox, items) = parse_inbound(p).ok()?;
            let actions = rules.inbound(&inbox, &items).await;
            let mut m = Map::new();
            m.insert(
                "actions".into(),
                Value::Array(actions.iter().map(InboundAction::to_json).collect()),
            );
            Some(m)
        }
        "email.draft_write" => {
            let draft = p.get("draftId").and_then(Value::as_str)?;
            let provider = p.get("provider").and_then(Value::as_str)?;
            let inbox = p.get("inboxId").and_then(Value::as_str);
            let mut m = Map::new();
            m.insert("draftOk".into(), Value::Bool(rules.draft_write(provider, inbox, draft)));
            Some(m)
        }
        _ => None,
    }
}
