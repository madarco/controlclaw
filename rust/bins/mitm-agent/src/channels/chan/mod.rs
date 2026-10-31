//! Channel commands on the firewall (`channels.ts`, docs/features/channels.md): hold the tokens,
//! decide whether a change needs a confirmation code, have an agent deliver the code over one of its
//! own channels, verify it, and push the config to the agent with our signature.
//!
//!   channels.propose  { changeId, kind, connectionId, type, hint, label,
//!                       agent?: {vmId, name, hostname}, from?: {vmId, hostname},
//!                       pairing?, sender?, settings?, secret? }
//!   channels.confirm  { changeId, code }
//!   channels.cancel   { changeId }
//!   channels.push     { vmId, agentName, hostname }
//!
//! A connection belongs to the organization and is live on at most one agent; moving it removes it
//! on the old box first. Approvals are reconciled: the agent box records every sender it approved
//! and hands the list back, so an approve whose answer was lost is picked up later.
//!
//! Consent rule: with at least one approved sender anywhere, every change needs a code. With
//! nobody approved, the first change applies (trust on first use). One pending change per org.

pub mod apply;
pub mod buttons;
pub mod store;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use self::apply::{ApplyOutcome, ChannelWriter, Deadline, Now};
use self::store::{ApprovedSender, ChannelStore, PendingApproval, StoredAgent, StoredConnection};
use crate::channels::agent::{AgentCalls, AgentError, Target};
use crate::commands::{CommandOutcome, CommandResult};
use crate::contracts::{CodeRequest, ConsentCodes, Verify};

/// One pending change per organization; the shared codes instance keys by scope.
pub const SCOPE: &str = "channels:org";
pub const CODE_SUBJECT: &str = "your organization's channels";
use crate::channels::llm::CODE_ATTEMPTS;

const PENDING_APPROVAL_TTL_MS: i64 = 15 * 60_000;
pub const RECONCILE_INTERVAL_MS: i64 = 60_000;
pub const AGENT_ALLOWED_INTERVAL_MS: i64 = 5 * 60_000;
const AGENT_ALLOWED_CAP: usize = 50;
const APPROVED_CAP: usize = 200;
const DECLINED_CAP: usize = 200;

pub const NO_CODES: &str = "Confirmation codes are not available on this firewall yet.";
/// The channel list could not be read, or a route's agent has no address yet: nobody can be said
/// to be approved, so nothing applies on first use.
pub const NO_CHANNELS: &str =
    "Your firewall cannot read its channel list right now, so it cannot ask you to confirm. Try again shortly.";
/// A connection with approved people is on an agent the firewall has no address for yet.
pub const NO_ADDRESS: &str = "A channel with approved people is on an agent your firewall has no address for yet, so it cannot ask them to confirm. Try again once the agent is up, or take the channel off that agent.";

fn type_name(kind: &str) -> &str {
    match kind {
        "telegram" => "Telegram",
        "slack" => "Slack",
        "whatsapp" => "WhatsApp",
        other => other,
    }
}

fn is_type(v: &str) -> bool {
    matches!(v, "telegram" | "slack" | "whatsapp")
}

fn s(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(x)) if !x.is_empty() => Some(x.clone()),
        _ => None,
    }
}

fn named(kind: &str, label: Option<&str>) -> String {
    match label {
        Some(l) => format!("{} {l}", type_name(kind)),
        None => type_name(kind).to_string(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRef {
    pub vm_id: String,
    pub name: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pairing {
    pub code: String,
    pub sender_id: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub change_id: String,
    pub kind: String,
    pub connection_id: String,
    pub ctype: String,
    pub hint: Option<String>,
    pub label: Option<String>,
    pub agent: Option<AgentRef>,
    pub from: Option<(String, Option<String>)>,
    pub pairing: Option<Pairing>,
    pub sender: Option<(String, Option<String>)>,
    /// `settings.personal`: `None` (no settings), `Some(None)` (settings without a boolean).
    pub personal: Option<Option<bool>>,
    pub bot_token: Option<String>,
    pub app_token: Option<String>,
    /// `remove` only: go on when the agent cannot be told (it is gone). Taken from a standalone
    /// firewall's signed-in admin only; a console's proposal never forces.
    pub force: bool,
}

pub fn parse_proposal(p: &Map<String, Value>) -> Result<Proposal, String> {
    let kind = p.get("kind").and_then(Value::as_str).unwrap_or_default();
    let ctype = p.get("type").and_then(Value::as_str).unwrap_or_default();
    let ok_kind = matches!(
        kind,
        "add"
            | "replace"
            | "remove"
            | "assign"
            | "unassign"
            | "approve_pairing"
            | "whatsapp_login"
            | "add_sender"
            | "remove_sender"
    );
    let (Some(change_id), Some(connection_id), true, true) =
        (s(p.get("changeId")), s(p.get("connectionId")), ok_kind, is_type(ctype))
    else {
        return Err("malformed channels.propose payload".into());
    };
    let agent = p.get("agent").and_then(|a| {
        let vm_id = s(a.get("vmId"))?;
        Some(AgentRef {
            name: s(a.get("name")).unwrap_or_else(|| vm_id.clone()),
            hostname: s(a.get("hostname")),
            vm_id,
        })
    });
    let from = p
        .get("from")
        .and_then(|f| Some((s(f.get("vmId"))?, s(f.get("hostname")))));
    let pairing = p.get("pairing").and_then(|x| {
        Some(Pairing {
            code: s(x.get("code"))?,
            sender_id: s(x.get("senderId"))?,
            label: s(x.get("label")),
        })
    });
    let sender = p.get("sender").and_then(|x| Some((s(x.get("id"))?, s(x.get("label")))));
    let personal = p
        .get("settings")
        .filter(|v| v.is_object())
        .map(|st| st.get("personal").and_then(Value::as_bool));
    let secret = p.get("secret").filter(|v| v.is_object());
    Ok(Proposal {
        change_id,
        kind: kind.into(),
        connection_id,
        ctype: ctype.into(),
        hint: s(p.get("hint")),
        label: s(p.get("label")),
        agent,
        from,
        pairing,
        sender,
        personal,
        bot_token: secret.and_then(|x| s(x.get("botToken"))),
        app_token: secret.and_then(|x| s(x.get("appToken"))),
        force: kind == "remove"
            && p.get("force") == Some(&Value::Bool(true))
            && crate::core::requested_via::local_admin(),
    })
}

fn who(sender: Option<&(String, Option<String>)>) -> String {
    match sender {
        None => "?".into(),
        Some((id, Some(label))) => format!("{label} ({id})"),
        Some((id, None)) => id.clone(),
    }
}

/// The one-line summary the code message carries.
pub fn summarize(p: &Proposal) -> String {
    let name = type_name(&p.ctype);
    let what = named(&p.ctype, p.label.as_deref());
    let on = p.agent.as_ref().map(|a| format!(" on {}", a.name)).unwrap_or_default();
    let other = || {
        p.agent
            .as_ref()
            .map(|a| a.name.clone())
            .unwrap_or_else(|| "another agent".into())
    };
    match p.kind.as_str() {
        "add" => format!("Add a {name} connection ({}){on}", p.hint.as_deref().unwrap_or("token")),
        "replace" => format!(
            "Replace the {name} token ({})",
            p.hint.as_deref().unwrap_or("new token")
        ),
        "remove" => format!("Remove {what} from the organization"),
        "assign" if p.from.is_some() => format!("Move {what} to {}", other()),
        "assign" => format!("Enable {what}{on}"),
        "unassign" => format!("Disable {what}{on}"),
        "approve_pairing" => format!(
            "Approve {name} sender {}",
            match &p.pairing {
                Some(Pairing {
                    label: Some(l),
                    sender_id,
                    ..
                }) => format!("{l} ({sender_id})"),
                Some(x) => x.sender_id.clone(),
                None => "?".into(),
            }
        ),
        "add_sender" => format!("Let {name} {} receive confirmation codes", who(p.sender.as_ref())),
        "remove_sender" => format!("Stop sending confirmation codes to {name} {}", who(p.sender.as_ref())),
        _ => {
            if p.from.is_some() {
                format!("Move WhatsApp to {} (needs a new QR scan)", other())
            } else if p.personal == Some(Some(true)) {
                format!("Connect WhatsApp by QR (personal number){on}")
            } else {
                format!("Connect WhatsApp by QR{on}")
            }
        }
    }
}

/// The placeholder an agent box holds instead of the real token; the proxy swaps it back.
pub fn placeholder_for(kind: &str, connection_id: &str, which: &str) -> String {
    let safe: String = connection_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    format!("__cc_{kind}_{which}_{safe}")
}

/// A Telegram bot token's stand-in: the bot's own id (the token's digits before `:`), then the
/// placeholder. The proxy's Telegram check reads the bot from the path (`/bot<id>:…/<method>`)
/// before the swap puts the token in, and OpenClaw reads the bot's id from it too.
pub fn telegram_placeholder(connection_id: &str, token: &str) -> String {
    let bot = token
        .split(':')
        .next()
        .filter(|b| !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()));
    let ph = placeholder_for("telegram", connection_id, "bot");
    match bot {
        Some(b) => format!("{b}:{ph}"),
        None => ph,
    }
}

/// A Slack token's stand-in, shaped as the token: `xoxb-` for the bot's; the app token's own
/// `xapp-<n>-<app id>-` for the app's (OpenClaw reads the app id from it to check the two tokens
/// belong to one app), then the placeholder.
pub fn slack_placeholder(connection_id: &str, which: &str, token: &str) -> String {
    let ph = placeholder_for("slack", connection_id, which);
    if which != "app" {
        return format!("xoxb-{ph}");
    }
    let mut parts = token.splitn(4, '-');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("xapp"), Some(n), Some(app), Some(_))
            if !n.is_empty()
                && n.bytes().all(|c| c.is_ascii_digit())
                && !app.is_empty()
                && app.bytes().all(|c| c.is_ascii_alphanumeric()) =>
        {
            format!("xapp-{n}-{app}-{ph}")
        }
        _ => format!("xapp-{ph}"),
    }
}

/// One sender OpenClaw will talk to, as an agent says: type, sender id, label, when. A suggestion,
/// never an approval.
pub type AllowedSender = (String, String, Option<String>, Option<String>);

/// What one agent box last said about OpenClaw's allow list.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentAllowedRead {
    /// `None`: the box said nothing about it (an agent too old).
    pub senders: Option<Vec<AllowedSender>>,
    pub error: Option<(bool, String)>,
    pub at: i64,
}

fn parse_agent_allowed(payload: &Map<String, Value>) -> (Option<Vec<AllowedSender>>, Option<(bool, String)>) {
    let Some(raw) = payload.get("allowedByAgent").filter(|v| v.is_object()) else {
        return (None, None);
    };
    let mut senders: Vec<AllowedSender> = Vec::new();
    for a in raw
        .get("senders")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let (Some(t), Some(id)) = (a.get("type").and_then(Value::as_str), s(a.get("senderId"))) else {
            continue;
        };
        if !is_type(t) || senders.iter().any(|x| x.0 == t && x.1 == id) {
            continue;
        }
        senders.push((t.into(), id, s(a.get("label")), s(a.get("at"))));
        if senders.len() >= AGENT_ALLOWED_CAP {
            break;
        }
    }
    let err = raw.get("error").filter(|e| e.is_object());
    let error = err.and_then(|e| s(e.get("message")).map(|m| (e.get("busy") == Some(&Value::Bool(true)), m)));
    (Some(senders), error)
}

/// One approval an agent recorded: type, sender id, the pairing code if it kept one, when.
type BoxApproval = (String, String, Option<String>, String);

/// `{type, senderId, code, at}` off `GET /channels/approved`.
fn parse_approved(payload: &Map<String, Value>) -> Vec<BoxApproval> {
    payload
        .get("approved")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|a| {
            let t = a.get("type").and_then(Value::as_str).filter(|t| is_type(t))?;
            let id = s(a.get("senderId"))?;
            Some((
                t.into(),
                id,
                s(a.get("code")),
                s(a.get("at")).unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into()),
            ))
        })
        .collect()
}

/// What the console is told when a box could not be asked who OpenClaw allows.
fn read_failure_message(e: &AgentError) -> String {
    if e.timed_out {
        "The agent did not answer in time, so who it has allowed could not be read.".into()
    } else {
        "Your agent could not be reached, so who it has allowed could not be read.".into()
    }
}

/// `Date.parse` of the ISO strings this store holds; 0 when it is not one.
fn parse_ms(s: &str) -> i64 {
    // YYYY-MM-DDTHH:MM:SS(.mmm)Z
    let b = s.as_bytes();
    if b.len() < 20 {
        return 0;
    }
    let num = |a: usize, z: usize| s.get(a..z).and_then(|x| x.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) =
        (num(0, 4), num(5, 7), num(8, 10), num(11, 13), num(14, 16), num(17, 19))
    else {
        return 0;
    };
    let ms = if b.get(19) == Some(&b'.') {
        num(20, 23).unwrap_or(0)
    } else {
        0
    };
    // Days from civil (Howard Hinnant).
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    ((days * 86_400 + h * 3600 + mi * 60 + se) * 1000) + ms
}

pub struct ChannelsOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    /// The agents the identity map lists: `(vm_id, hostname)`.
    pub identities: Arc<dyn Fn() -> Vec<(String, Option<String>)> + Send + Sync>,
    pub placeholder_swap: bool,
    /// A firewall built from the test repo (`devConsentAllowed`): the dev route goes last, so a
    /// code with nobody approved goes back to the console instead of applying on first use.
    pub dev: bool,
    pub codes: Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>,
    pub on_credentials_changed: Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>,
    pub now: Now,
    pub make_apply_id: Arc<dyn Fn() -> String + Send + Sync>,
    pub sleep: apply::Sleep,
}

struct Recorded {
    connection_id: String,
    vm_id: String,
    ctype: String,
    senders: Vec<ApprovedSender>,
}

pub struct ChannelsFirewall {
    opts: ChannelsOptions,
    writer: ChannelWriter,
    /// The store, held for a whole command or reconcile pass.
    state: tokio::sync::Mutex<ChannelStore>,
    /// The last saved store, for the synchronous readers (routes, the proxy sync, the beat).
    published: std::sync::RwLock<ChannelStore>,
    reports: Mutex<Vec<CommandResult>>,
    agent_allowed: Mutex<HashMap<String, AgentAllowedRead>>,
    sent_via: Mutex<Option<(String, String)>>,
    /// False when the store on disk would not parse: it is never written over.
    writable: bool,
    /// False when it would not decrypt or parse at load, until the process restarts. A save does not
    /// change it: the list of people saved over an unreadable store is not known to be complete.
    readable: std::sync::atomic::AtomicBool,
}

impl ChannelsFirewall {
    pub fn new(opts: ChannelsOptions) -> Arc<Self> {
        let (st, loaded) = store::load(&opts.store_path, &opts.box_key, &opts.org_id, &opts.box_id);
        let writable = loaded.writable;
        Arc::new(Self {
            writer: ChannelWriter {
                agent: opts.agent.clone(),
                now: opts.now.clone(),
                make_apply_id: opts.make_apply_id.clone(),
                sleep: opts.sleep.clone(),
            },
            published: std::sync::RwLock::new(st.clone()),
            state: tokio::sync::Mutex::new(st),
            writable,
            readable: std::sync::atomic::AtomicBool::new(loaded.readable),
            opts,
            reports: Mutex::new(Vec::new()),
            agent_allowed: Mutex::new(HashMap::new()),
            sent_via: Mutex::new(None),
        })
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    fn stamp(&self) -> String {
        cc_crypto::store_health::iso_from_millis(self.now())
    }

    fn snapshot(&self) -> std::sync::RwLockReadGuard<'_, ChannelStore> {
        self.published.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the store; an error fails the command, as `saveChannelStore` throwing does in the TS.
    fn save(&self, st: &ChannelStore) -> Result<(), String> {
        if !self.writable {
            return Err("This firewall could not read its channel store, so it does not write over it.".into());
        }
        store::save(
            &self.opts.store_path,
            st,
            &self.opts.box_key,
            &self.opts.org_id,
            &self.opts.box_id,
        )
        .map_err(|e| {
            tracing::error!("[channels] could not save the store: {e}");
            "The firewall could not save its channel store.".to_string()
        })?;
        *self.published.write().unwrap_or_else(|e| e.into_inner()) = st.clone();
        Ok(())
    }

    async fn credentials_changed(&self) {
        (self.opts.on_credentials_changed)().await;
    }

    fn target_in(&self, st: &ChannelStore, vm_id: &str, hostname: Option<&str>) -> Result<Target, String> {
        let known = (self.opts.identities)()
            .into_iter()
            .find(|(v, _)| v == vm_id)
            .and_then(|(_, h)| h);
        let host = hostname
            .map(str::to_string)
            .or(known)
            .or_else(|| st.agents.get(vm_id).and_then(|a| a.hostname.clone()));
        match host {
            Some(h) => Ok(Target::new(vm_id, &h)),
            None => Err("This agent has no hostname yet.".into()),
        }
    }

    /// The routes, or `None` when they are not known: the channel store could not be read, or a
    /// connection with approved people is on an agent with no address yet. "Nobody approved" (first
    /// use) and "I do not know who is" must not look the same to a module that would apply a change
    /// on first use. (The TS drops such a connection, and an unreadable store reads as empty; both
    /// are closed here.)
    pub fn code_routes_checked(&self) -> Option<Vec<Value>> {
        self.code_routes_status().ok()
    }

    /// The routes, or why they are not known (`NO_CHANNELS`, `NO_ADDRESS`).
    pub fn code_routes_status(&self) -> Result<Vec<Value>, &'static str> {
        // A standalone firewall's signed-in admin: one route, the admin, whatever the channels
        // say, so every module takes its code path and `Consent::send` hands the code back.
        if crate::core::requested_via::local_admin() {
            return Ok(vec![crate::core::requested_via::admin_route()]);
        }
        let st = self.snapshot().clone();
        self.code_routes_of(&st)
    }

    /// `channelsReady`: this firewall's channel store could be read.
    pub fn ready(&self) -> bool {
        crate::core::requested_via::local_admin()
            || (self.writable && self.readable.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn code_routes_of(&self, st: &ChannelStore) -> Result<Vec<Value>, &'static str> {
        if !self.ready() {
            return Err(NO_CHANNELS);
        }
        let mut out = Vec::new();
        for (id, c) in &st.connections {
            let Some(vm) = &c.assigned_vm_id else { continue };
            if c.approved_senders.is_empty() {
                continue;
            }
            let target = self.target_in(st, vm, None).map_err(|_| NO_ADDRESS)?;
            let mut route = json!({
                "target": target.to_json(),
                "senders": c.approved_senders.iter().map(|x| json!({"type": x.kind, "id": x.id, "label": x.label})).collect::<Vec<_>>(),
                "agentName": st.agents.get(vm).map(|a| a.name.clone()).unwrap_or_else(|| vm.clone()),
            });
            if c.kind == "telegram"
                && let Some(t) = c.secret("botToken")
            {
                route["telegram"] = json!({"connectionId": id, "botToken": t});
            }
            out.push(route);
        }
        if self.opts.dev {
            out.push(crate::channels::contracts_fill::dev_route_json());
        }
        Ok(out)
    }

    /// Whether any connection is on this agent.
    pub fn has_agent_connection(&self, vm_id: &str) -> bool {
        self.snapshot()
            .connections
            .values()
            .any(|c| c.assigned_vm_id.as_deref() == Some(vm_id))
    }

    pub fn drain_reports(&self) -> Vec<CommandResult> {
        std::mem::take(&mut *self.reports.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn is_code_recipient(&self, connection_id: &str, sender_id: &str) -> bool {
        self.snapshot()
            .connections
            .get(connection_id)
            .is_some_and(|c| c.approved_senders.iter().any(|x| x.id == sender_id))
    }

    /// The token of the Telegram bot with that id, if this firewall holds it.
    pub fn telegram_token(&self, bot_id: &str) -> Option<String> {
        self.snapshot().connections.values().find_map(|c| {
            let t = c.secret("botToken").filter(|_| c.kind == "telegram")?;
            (t.split(':').next() == Some(bot_id)).then(|| t.to_string())
        })
    }

    /// The bot token for a bot id, only when that bot's connection is on `vm_id`.
    #[allow(dead_code)] // the content rules' holds and notices (H4)
    pub fn telegram_token_for_agent(&self, bot_id: &str, vm_id: &str) -> Option<String> {
        self.snapshot().connections.values().find_map(|c| {
            let t = c.secret("botToken").filter(|_| c.kind == "telegram")?;
            (t.split(':').next() == Some(bot_id) && c.assigned_vm_id.as_deref() == Some(vm_id)).then(|| t.to_string())
        })
    }

    /// The bot token of a Slack connection on `vm_id`; `auth` must be that connection's.
    #[allow(dead_code)] // the content rules' holds and notices (H4)
    pub fn slack_token_for_agent(&self, vm_id: &str, auth: Option<&str>) -> Option<String> {
        let st = self.snapshot();
        let mine: Vec<(&String, &StoredConnection)> = st
            .connections
            .iter()
            .filter(|(_, c)| {
                c.kind == "slack" && c.assigned_vm_id.as_deref() == Some(vm_id) && c.secret("botToken").is_some()
            })
            .collect();
        match auth {
            Some(a) => mine
                .iter()
                .find(|(id, c)| {
                    let ph = slack_placeholder(id, "bot", "");
                    cc_crypto::ct_eq(a.as_bytes(), ph.as_bytes())
                        || c.secret("botToken")
                            .is_some_and(|t| cc_crypto::ct_eq(a.as_bytes(), t.as_bytes()))
                })
                .and_then(|(_, c)| c.secret("botToken").map(str::to_string)),
            None if mine.len() == 1 => mine[0].1.secret("botToken").map(str::to_string),
            None => None,
        }
    }

    /// Proxy credential entries for placeholder-mode channels.
    pub fn credentials(&self) -> Vec<Value> {
        if !self.opts.placeholder_swap {
            return vec![];
        }
        let st = self.snapshot();
        let mut out = Vec::new();
        for (id, c) in &st.connections {
            let Some(vm) = &c.assigned_vm_id else { continue };
            if c.kind == "telegram"
                && let Some(t) = c.secret("botToken")
            {
                out.push(json!({"placeholder": telegram_placeholder(id, t), "match_domain": "api.telegram.org", "secret": t, "locations": ["path"], "vm_id": vm}));
            }
            if c.kind == "slack" {
                for (which, key) in [("bot", "botToken"), ("app", "appToken")] {
                    if let Some(t) = c.secret(key) {
                        out.push(json!({"placeholder": slack_placeholder(id, which, t), "match_domain": "slack.com", "secret": t, "locations": ["header:authorization"], "vm_id": vm}));
                    }
                }
            }
        }
        out
    }

    /// "Who gets confirmation codes", for the beat (T-83): the firewall's own list, and what the
    /// agents say OpenClaw will talk to (a suggestion), `allowed` only once a box was read.
    pub fn code_recipients(&self) -> Value {
        let st = self.snapshot();
        let read_cache = self.agent_allowed.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut approved = Vec::new();
        let mut allowed = Vec::new();
        let mut allowed_error: Option<(bool, String)> = None;
        let mut read = false;
        for (id, c) in &st.connections {
            let agent_name = c
                .assigned_vm_id
                .as_ref()
                .map(|v| st.agents.get(v).map(|a| a.name.clone()).unwrap_or_else(|| v.clone()));
            for x in &c.approved_senders {
                if approved.len() >= APPROVED_CAP {
                    break;
                }
                approved.push(json!({
                    "connectionId": id, "type": c.kind, "connectionLabel": c.label, "senderId": x.id,
                    "senderLabel": x.label, "at": x.at, "vmId": c.assigned_vm_id, "agentName": agent_name,
                }));
            }
            let Some(vm) = &c.assigned_vm_id else { continue };
            let Some(from_box) = read_cache.get(vm) else { continue };
            if from_box.error.is_some() && allowed_error.is_none() {
                allowed_error = from_box.error.clone();
            }
            let Some(senders) = &from_box.senders else { continue };
            read = true;
            for (t, sid, label, at) in senders {
                if t != &c.kind || c.approved_senders.iter().any(|x| &x.id == sid) {
                    continue;
                }
                if allowed.len() >= AGENT_ALLOWED_CAP {
                    break;
                }
                allowed.push(json!({
                    "connectionId": id, "type": c.kind, "connectionLabel": c.label, "senderId": sid,
                    "senderLabel": label, "at": at, "vmId": vm, "agentName": agent_name.clone().unwrap_or_else(|| vm.clone()),
                }));
            }
        }
        let mut out = json!({"approved": approved});
        if read {
            out["allowed"] = json!(allowed);
        }
        if let Some((busy, message)) = allowed_error {
            out["allowedError"] = json!({"busy": busy, "message": message});
        }
        out
    }

    /// What the console may see: no secrets.
    pub fn summary(&self) -> Vec<Value> {
        self.snapshot()
            .connections
            .iter()
            .map(|(id, c)| json!({"id": id, "type": c.kind, "hint": c.hint, "label": c.label, "assignedVmId": c.assigned_vm_id, "approvedSenders": c.approved_senders.len()}))
            .collect()
    }

    // ---- reconciling approvals ----

    fn reconcile_targets(&self, st: &ChannelStore) -> IndexMap<String, Vec<String>> {
        let mut out: IndexMap<String, Vec<String>> = IndexMap::new();
        let cutoff = self.now() - PENDING_APPROVAL_TTL_MS;
        for (id, c) in &st.connections {
            let Some(vm) = &c.assigned_vm_id else { continue };
            let outstanding = c.pending_approvals.iter().flatten().any(|a| parse_ms(&a.at) > cutoff);
            if !c.approved_senders.is_empty() && !outstanding {
                continue;
            }
            out.entry(vm.clone()).or_default().push(id.clone());
        }
        out
    }

    /// Read the agents' own approved lists: `(vm, connections, approved)` for each agent asked.
    async fn fetch_approvals(
        &self,
        st: &ChannelStore,
        only: Option<&str>,
    ) -> Vec<(String, Vec<String>, Vec<BoxApproval>)> {
        let mut out = Vec::new();
        for (vm_id, ids) in self.reconcile_targets(st) {
            if only.is_some_and(|o| o != vm_id) {
                continue;
            }
            let approved = match self.target_in(st, &vm_id, None) {
                Err(e) => Err(e),
                Ok(t) => self
                    .opts
                    .agent
                    .get(&t, "/channels/approved", None)
                    .await
                    .map_err(|e| e.message),
            };
            match approved {
                Ok(p) => out.push((vm_id, ids, parse_approved(&p))),
                Err(e) => tracing::info!("[channels] could not read {vm_id} to reconcile approvals: {e}"),
            }
        }
        out
    }

    /// Merge what the agents said they approved. The box is the authority: it can only add somebody
    /// OpenClaw accepted, never invent one.
    fn merge_approvals(
        &self,
        st: &mut ChannelStore,
        fetched: Vec<(String, Vec<String>, Vec<BoxApproval>)>,
    ) -> Result<Vec<Recorded>, String> {
        let mut out = Vec::new();
        let mut changed = false;
        for (vm_id, ids, approved) in fetched {
            let now = self.now();
            for id in ids {
                let Some(c) = st.connections.get_mut(&id) else { continue };
                if c.assigned_vm_id.as_deref() != Some(vm_id.as_str()) {
                    continue;
                }
                let pending = c.pending_approvals.clone().unwrap_or_default();
                let mut added: Vec<ApprovedSender> = Vec::new();
                for (t, sid, code, at) in &approved {
                    if t != &c.kind
                        || c.approved_senders.iter().any(|x| &x.id == sid)
                        || added.iter().any(|x| &x.id == sid)
                    {
                        continue;
                    }
                    // Taken off the code list on purpose (T-83): not put back.
                    if c.declined_senders.iter().flatten().any(|d| d == sid) {
                        continue;
                    }
                    let label = pending
                        .iter()
                        .find(|pa| (code.is_some() && Some(&pa.code) == code.as_ref()) || &pa.sender_id == sid)
                        .and_then(|pa| pa.label.clone());
                    added.push(ApprovedSender {
                        kind: c.kind.clone(),
                        id: sid.clone(),
                        label,
                        at: at.clone(),
                        extra: Map::new(),
                    });
                }
                let kept: Vec<PendingApproval> = pending
                    .iter()
                    .filter(|pa| {
                        !approved.iter().any(|(t, sid, code, _)| {
                            t == &c.kind
                                && ((code.is_some() && Some(&pa.code) == code.as_ref()) || sid == &pa.sender_id)
                        }) && parse_ms(&pa.at) > now - PENDING_APPROVAL_TTL_MS
                    })
                    .cloned()
                    .collect();
                if added.is_empty() && kept.len() == pending.len() {
                    continue;
                }
                c.approved_senders.extend(added.clone());
                c.pending_approvals = (!kept.is_empty()).then_some(kept);
                changed = true;
                if !added.is_empty() {
                    tracing::info!(
                        "[channels] {} approved sender(s) on {} {id} came from the agent's own record",
                        added.len(),
                        c.kind
                    );
                    out.push(Recorded {
                        connection_id: id.clone(),
                        vm_id: vm_id.clone(),
                        ctype: c.kind.clone(),
                        senders: added,
                    });
                }
            }
        }
        if changed {
            self.save(st)?;
        }
        Ok(out)
    }

    /// Read and merge, the store lock held by the caller (inside a command, as the TS does).
    async fn reconcile_in(&self, st: &mut ChannelStore, only: Option<&str>) -> Vec<Recorded> {
        let fetched = self.fetch_approvals(st, only).await;
        self.merge_approvals(st, fetched).unwrap_or_else(|e| {
            tracing::error!("[channels] reconcile not saved: {e}");
            vec![]
        })
    }

    fn report(&self, recorded: &[Recorded]) {
        let mut r = self.reports.lock().unwrap_or_else(|e| e.into_inner());
        for x in recorded {
            let mut data = Map::new();
            data.insert("connectionId".into(), json!(x.connection_id));
            data.insert("vmId".into(), json!(x.vm_id));
            data.insert("type".into(), json!(x.ctype));
            data.insert(
                "senders".into(),
                json!(
                    x.senders
                        .iter()
                        .map(|s| json!({"id": s.id, "label": s.label}))
                        .collect::<Vec<_>>()
                ),
            );
            r.push(CommandResult {
                command_id: format!("channels.reconciled:{}", x.connection_id),
                ok: true,
                status: "applied".into(),
                message: String::new(),
                data: Some(data),
            });
        }
    }

    /// Periodic: OpenClaw's allow lists, then a reconcile of the agents that could be missing something.
    /// The agents are read without the store lock, so a slow box holds up no command; what they
    /// said is merged under it.
    pub async fn tick(&self) {
        self.refresh_agent_allowed(false).await;
        let snapshot = self.snapshot().clone();
        let fetched = self.fetch_approvals(&snapshot, None).await;
        if fetched.is_empty() {
            return;
        }
        let mut st = self.state.lock().await;
        match self.merge_approvals(&mut st, fetched) {
            Ok(recorded) => self.report(&recorded),
            Err(e) => tracing::error!("[channels] reconcile not saved: {e}"),
        }
    }

    /// Re-read OpenClaw's allow list off every agent that carries a connection.
    pub async fn refresh_agent_allowed(&self, force: bool) {
        let vms: Vec<String> = {
            let st = self.snapshot();
            let mut v: Vec<String> = Vec::new();
            for c in st.connections.values() {
                if let Some(vm) = &c.assigned_vm_id
                    && !v.contains(vm)
                {
                    v.push(vm.clone());
                }
            }
            v
        };
        for vm in &vms {
            let last = self
                .agent_allowed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(vm)
                .cloned();
            if !force
                && last
                    .as_ref()
                    .is_some_and(|l| self.now() - l.at < AGENT_ALLOWED_INTERVAL_MS)
            {
                continue;
            }
            self.read_agent_allowed(vm).await;
        }
        let keep: HashSet<&String> = vms.iter().collect();
        self.agent_allowed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| keep.contains(k));
    }

    async fn read_agent_allowed(&self, vm_id: &str) -> AgentAllowedRead {
        let target = {
            let st = self.snapshot();
            self.target_in(&st, vm_id, None)
        };
        let res = match target {
            Ok(t) => self.opts.agent.get(&t, "/channels/approved", None).await,
            Err(e) => Err(AgentError::new(e)),
        };
        let value = match res {
            Ok(p) => {
                let (senders, error) = parse_agent_allowed(&p);
                AgentAllowedRead {
                    senders,
                    error,
                    at: self.now(),
                }
            }
            Err(e) => {
                tracing::info!("[channels] could not read what {vm_id} has allowed: {}", e.message);
                let last = self
                    .agent_allowed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(vm_id)
                    .cloned();
                AgentAllowedRead {
                    senders: last.and_then(|l| l.senders),
                    error: Some((e.timed_out, read_failure_message(&e))),
                    at: self.now(),
                }
            }
        };
        self.agent_allowed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(vm_id.to_string(), value.clone());
        value
    }

    fn codes(&self) -> Option<Arc<dyn ConsentCodes>> {
        (self.opts.codes)()
    }

    // ---- commands ----

    pub async fn propose(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let dl = Deadline::new(self.opts.now.clone());
        let p = parse_proposal(&payload)?;
        let summary = summarize(&p);
        let mut data = Map::new();
        data.insert("changeId".into(), json!(p.change_id));
        data.insert("summary".into(), json!(summary));
        {
            let mut st = self.state.lock().await;
            note_agent(&mut st, p.agent.as_ref());
            let routes = match self.code_routes_of(&st) {
                Ok(r) => r,
                Err(why) => {
                    return Ok(CommandOutcome {
                        ok: false,
                        status: "failed".into(),
                        message: Some(why.into()),
                        data: Some(data),
                    });
                }
            };
            if routes.is_empty() {
                // Trust on first use: nobody can be asked yet.
                if let Some(c) = self.codes() {
                    c.forget(SCOPE);
                }
                let applied = self.apply(&mut st, &p, &dl).await?;
                data.extend(applied);
                data.insert("tofu".into(), json!(true));
                return Ok(outcome(data));
            }
            drop(st);
            let Some(codes) = self.codes() else {
                return Ok(CommandOutcome {
                    ok: false,
                    status: "failed".into(),
                    message: Some(NO_CODES.into()),
                    data: Some(data),
                });
            };
            let sent = codes
                .send(CodeRequest {
                    scope: SCOPE.into(),
                    change_id: p.change_id.clone(),
                    proposal: Value::Object(payload),
                    agent_name: CODE_SUBJECT.into(),
                    summary,
                    routes,
                })
                .await;
            let Some(via) = sent.sent_via.clone() else {
                return Ok(CommandOutcome {
                    ok: false,
                    status: "failed".into(),
                    message: sent.error,
                    data: Some(data),
                });
            };
            tracing::info!("[channels] code sent for {} {} via {via}", p.kind, p.ctype);
            *self.sent_via.lock().unwrap_or_else(|e| e.into_inner()) = Some((p.change_id.clone(), via.clone()));
            data.insert("sentVia".into(), json!(via));
            data.insert(
                "expiresAt".into(),
                json!(cc_crypto::store_health::iso_from_millis(sent.expires_at_ms)),
            );
            data.insert("attemptsLeft".into(), json!(CODE_ATTEMPTS));
            Ok(CommandOutcome {
                ok: true,
                status: "awaiting_code".into(),
                message: None,
                data: Some(data),
            })
        }
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let dl = Deadline::new(self.opts.now.clone());
        let Some(change_id) = s(payload.get("changeId")) else {
            return Err("malformed channels.confirm payload".into());
        };
        let code: String = s(payload.get("code"))
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut data = Map::new();
        data.insert("changeId".into(), json!(change_id));
        let verdict = self
            .codes()
            .map_or(Verify::Unknown, |c| c.verify(SCOPE, &change_id, &code));
        let proposal = match verdict {
            Verify::Ok(p) => p,
            Verify::Wrong { tries_left } => {
                data.insert("attemptsLeft".into(), json!(tries_left));
                return Ok(CommandOutcome {
                    ok: false,
                    status: "invalid_code".into(),
                    message: Some("Wrong code.".into()),
                    data: Some(data),
                });
            }
            Verify::Expired | Verify::Unknown => {
                return Ok(CommandOutcome {
                    ok: false,
                    status: "expired".into(),
                    message: Some("No change is waiting for a code, or the code expired.".into()),
                    data: Some(data),
                });
            }
        };
        let p = parse_proposal(proposal.as_object().unwrap_or(&Map::new()))?;
        let via = {
            let mut g = self.sent_via.lock().unwrap_or_else(|e| e.into_inner());
            match g.take() {
                Some((id, v)) if id == change_id => Some(v),
                other => {
                    *g = other;
                    None
                }
            }
        };
        let mut st = self.state.lock().await;
        let applied = self.apply(&mut st, &p, &dl).await?;
        data.extend(applied);
        data.insert("summary".into(), json!(summarize(&p)));
        data.insert("sentVia".into(), via.map_or(Value::Null, Value::String));
        data.insert("tofu".into(), json!(false));
        Ok(outcome(data))
    }

    pub async fn cancel(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let change_id = s(payload.get("changeId"));
        if let Some(c) = self.codes() {
            c.cancel(SCOPE, change_id.as_deref());
        }
        let mut data = Map::new();
        data.insert("changeId".into(), change_id.map_or(Value::Null, Value::String));
        Ok(CommandOutcome {
            ok: true,
            status: "cancelled".into(),
            message: None,
            data: Some(data),
        })
    }

    pub async fn push(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let Some(vm_id) = s(payload.get("vmId")) else {
            return Err("malformed channels.push payload".into());
        };
        let mut st = self.state.lock().await;
        note_agent(
            &mut st,
            Some(&AgentRef {
                name: s(payload.get("agentName")).unwrap_or_else(|| vm_id.clone()),
                hostname: s(payload.get("hostname")),
                vm_id: vm_id.clone(),
            }),
        );
        let mine: Vec<(String, StoredConnection)> = st
            .connections
            .iter()
            .filter(|(_, c)| c.assigned_vm_id.as_deref() == Some(vm_id.as_str()))
            .map(|(i, c)| (i.clone(), c.clone()))
            .collect();
        if mine.is_empty() {
            let mut d = Map::new();
            d.insert("vmId".into(), json!(vm_id));
            d.insert("applied".into(), json!([]));
            d.insert("failed".into(), json!([]));
            return Ok(CommandOutcome {
                ok: true,
                status: "applied".into(),
                message: None,
                data: Some(d),
            });
        }
        self.save(&st)?;
        let dl = Deadline::new(self.opts.now.clone());
        let (mut applied, mut unconfirmed, mut failed) = (Vec::new(), Vec::new(), Vec::new());
        for (id, c) in &mine {
            match self.apply_on(&st, &vm_id, id, c, None, Some(&dl)).await {
                Ok(ApplyOutcome::Applied) => applied.push(id.clone()),
                Ok(ApplyOutcome::Unconfirmed) => unconfirmed.push(id.clone()),
                Err(e) => failed.push(json!({"connectionId": id, "type": c.kind, "error": e})),
            }
        }
        let name = st
            .agents
            .get(&vm_id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| vm_id.clone());
        tracing::info!(
            "[channels] re-applied {} connection(s) on {name}{}{}",
            applied.len(),
            if unconfirmed.is_empty() {
                String::new()
            } else {
                format!(", {} unconfirmed", unconfirmed.len())
            },
            if failed.is_empty() {
                String::new()
            } else {
                format!(", {} failed", failed.len())
            }
        );
        let recorded = self.reconcile_in(&mut st, Some(&vm_id)).await;
        self.report(&recorded);
        let message = failed
            .iter()
            .map(|f| {
                format!(
                    "{}: {}",
                    f["type"].as_str().unwrap_or_default(),
                    f["error"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let mut d = Map::new();
        d.insert("vmId".into(), json!(vm_id));
        d.insert("applied".into(), json!(applied));
        d.insert("unconfirmed".into(), json!(unconfirmed));
        d.insert("failed".into(), json!(failed));
        Ok(CommandOutcome {
            ok: failed.is_empty(),
            status: if failed.is_empty() { "applied" } else { "failed" }.into(),
            message: Some(message),
            data: Some(d),
        })
    }

    // ---- applying ----

    fn apply_body(&self, connection_id: &str, c: &StoredConnection) -> Value {
        if c.kind == "whatsapp" {
            return json!({"type": c.kind, "settings": c.settings});
        }
        if !self.opts.placeholder_swap {
            return json!({"type": c.kind, "secrets": c.secrets});
        }
        let mut swapped = Map::new();
        if let Some(t) = c.secret("botToken") {
            let ph = match c.kind.as_str() {
                "telegram" => telegram_placeholder(connection_id, t),
                "slack" => slack_placeholder(connection_id, "bot", t),
                _ => placeholder_for(&c.kind, connection_id, "bot"),
            };
            swapped.insert("botToken".into(), json!(ph));
        }
        if let Some(t) = c.secret("appToken") {
            swapped.insert("appToken".into(), json!(slack_placeholder(connection_id, "app", t)));
        }
        json!({"type": c.kind, "secrets": swapped})
    }

    async fn apply_on(
        &self,
        st: &ChannelStore,
        vm_id: &str,
        id: &str,
        c: &StoredConnection,
        hostname: Option<&str>,
        dl: Option<&Deadline>,
    ) -> Result<ApplyOutcome, String> {
        let target = self.target_in(st, vm_id, hostname)?;
        self.writer.write(&target, &c.kind, self.apply_body(id, c), dl).await
    }

    /// Take a connection off the agent it is on; a box the identity map no longer lists is gone.
    async fn leave(
        &self,
        st: &mut ChannelStore,
        vm_id: &str,
        kind: &str,
        hostname: Option<&str>,
        dl: Option<&Deadline>,
    ) -> Result<ApplyOutcome, String> {
        let r = match self.target_in(st, vm_id, hostname) {
            Ok(t) => {
                self.writer
                    .write(&t, kind, json!({"type": kind, "remove": true}), dl)
                    .await
            }
            Err(e) => Err(e),
        };
        match r {
            Ok(o) => Ok(o),
            Err(e) => {
                let known = (self.opts.identities)().iter().any(|(v, _)| v == vm_id);
                if known {
                    return Err(e);
                }
                tracing::info!("[channels] {vm_id} is gone; leaving {kind} behind: {e}");
                st.agents.shift_remove(vm_id);
                Ok(ApplyOutcome::Applied)
            }
        }
    }

    async fn apply(&self, st: &mut ChannelStore, p: &Proposal, dl: &Deadline) -> Result<Map<String, Value>, String> {
        let mode = if self.opts.placeholder_swap && p.ctype != "whatsapp" {
            "placeholder"
        } else {
            "plain"
        };
        let stamp = self.stamp();
        let mut out = Map::new();
        let unsure = |out: &mut Map<String, Value>, o: ApplyOutcome, what: &str| {
            if o == ApplyOutcome::Unconfirmed {
                out.insert("unconfirmed".into(), json!(true));
                out.insert("unconfirmedWhat".into(), json!(what));
            }
        };
        let not_here = || "This connection is not on the firewall. Set it up again.".to_string();
        match p.kind.as_str() {
            "add" => {
                let Some(bot) = &p.bot_token else {
                    return Err("no token in the proposal".into());
                };
                if p.ctype == "slack" && p.app_token.is_none() {
                    return Err("Slack needs both a bot token and an app token".into());
                }
                let mut secrets = Map::new();
                secrets.insert("botToken".to_string(), json!(bot));
                if let Some(a) = &p.app_token {
                    secrets.insert("appToken".to_string(), json!(a));
                }
                let existing = st.connections.get(&p.connection_id).cloned();
                let c = StoredConnection {
                    kind: p.ctype.clone(),
                    secrets,
                    settings: existing.as_ref().map(|e| e.settings.clone()).unwrap_or_default(),
                    hint: p.hint.clone(),
                    label: p.label.clone(),
                    approved_senders: existing
                        .as_ref()
                        .map(|e| e.approved_senders.clone())
                        .unwrap_or_default(),
                    pending_approvals: existing
                        .as_ref()
                        .and_then(|e| e.pending_approvals.clone())
                        .filter(|x| !x.is_empty()),
                    declined_senders: None,
                    assigned_vm_id: p.agent.as_ref().map(|a| a.vm_id.clone()),
                    updated_at: stamp,
                    extra: Map::new(),
                };
                st.connections.insert(p.connection_id.clone(), c.clone());
                self.save(st)?;
                self.credentials_changed().await;
                let o = match &p.agent {
                    Some(a) => {
                        self.apply_on(st, &a.vm_id, &p.connection_id, &c, a.hostname.as_deref(), Some(dl))
                            .await?
                    }
                    None => ApplyOutcome::Applied,
                };
                out.insert("mode".into(), json!(mode));
                out.insert("vmId".into(), json!(p.agent.as_ref().map(|a| a.vm_id.clone())));
                unsure(&mut out, o, "apply");
            }
            "replace" => {
                let Some(bot) = &p.bot_token else {
                    return Err("no token in the proposal".into());
                };
                let c = st.connections.get_mut(&p.connection_id).ok_or_else(not_here)?;
                if p.ctype == "slack" && p.app_token.is_none() {
                    return Err("Slack needs both a bot token and an app token".into());
                }
                let mut secrets = Map::new();
                secrets.insert("botToken".to_string(), json!(bot));
                if let Some(a) = &p.app_token {
                    secrets.insert("appToken".to_string(), json!(a));
                }
                c.secrets = secrets;
                c.hint = p.hint.clone();
                if p.label.is_some() {
                    c.label = p.label.clone();
                }
                c.updated_at = stamp;
                let c = c.clone();
                self.save(st)?;
                self.credentials_changed().await;
                let o = match &c.assigned_vm_id {
                    Some(vm) => self.apply_on(st, vm, &p.connection_id, &c, None, Some(dl)).await?,
                    None => ApplyOutcome::Applied,
                };
                out.insert("mode".into(), json!(mode));
                out.insert("vmId".into(), json!(c.assigned_vm_id));
                unsure(&mut out, o, "apply");
            }
            "remove" => {
                let Some(c) = st.connections.get(&p.connection_id).cloned() else {
                    tracing::info!(
                        "[channels] {} {} is not on the firewall; nothing to remove",
                        p.ctype,
                        p.connection_id
                    );
                    out.insert("vmId".into(), Value::Null);
                    out.insert("missing".into(), json!(true));
                    return Ok(out);
                };
                let o = match &c.assigned_vm_id {
                    // Forced (an agent that is gone): removed here even when it cannot be told.
                    // Its copy holds a stand-in that no longer swaps for the token.
                    Some(vm) if p.force => match self.leave(st, vm, &c.kind, None, Some(dl)).await {
                        Ok(o) => o,
                        Err(e) => {
                            tracing::info!(
                                "[channels] removing {} {} although {vm} could not be told: {e}",
                                p.ctype,
                                p.connection_id
                            );
                            ApplyOutcome::Unconfirmed
                        }
                    },
                    Some(vm) => self.leave(st, vm, &c.kind, None, Some(dl)).await?,
                    None => ApplyOutcome::Applied,
                };
                st.connections.shift_remove(&p.connection_id);
                self.save(st)?;
                self.credentials_changed().await;
                out.insert("vmId".into(), Value::Null);
                unsure(&mut out, o, "remove");
            }
            "assign" => {
                let c = st.connections.get(&p.connection_id).cloned().ok_or_else(not_here)?;
                let Some(agent) = &p.agent else {
                    return Err("no agent in the proposal".into());
                };
                let leaving = p.from.as_ref().map(|f| f.0.clone()).or(c.assigned_vm_id.clone());
                if let Some(l) = leaving.filter(|l| l != &agent.vm_id) {
                    let host = p.from.as_ref().and_then(|f| f.1.clone());
                    self.leave(st, &l, &c.kind, host.as_deref(), Some(dl)).await?;
                }
                let c = {
                    let c = st.connections.get_mut(&p.connection_id).ok_or_else(not_here)?;
                    c.assigned_vm_id = Some(agent.vm_id.clone());
                    c.updated_at = stamp;
                    c.clone()
                };
                self.save(st)?;
                self.credentials_changed().await;
                let o = self
                    .apply_on(
                        st,
                        &agent.vm_id,
                        &p.connection_id,
                        &c,
                        agent.hostname.as_deref(),
                        Some(dl),
                    )
                    .await?;
                out.insert("mode".into(), json!(mode));
                out.insert("vmId".into(), json!(agent.vm_id));
                unsure(&mut out, o, "apply");
            }
            "unassign" => {
                let c = st.connections.get(&p.connection_id).cloned().ok_or_else(not_here)?;
                let o = match &c.assigned_vm_id {
                    Some(vm) => self.leave(st, vm, &c.kind, None, Some(dl)).await?,
                    None => ApplyOutcome::Applied,
                };
                if let Some(c) = st.connections.get_mut(&p.connection_id) {
                    c.assigned_vm_id = None;
                    c.updated_at = stamp;
                }
                self.save(st)?;
                self.credentials_changed().await;
                out.insert("vmId".into(), Value::Null);
                unsure(&mut out, o, "remove");
            }
            "approve_pairing" => {
                let Some(pairing) = &p.pairing else {
                    return Err("no pairing in the proposal".into());
                };
                let c = st.connections.get(&p.connection_id).cloned().ok_or_else(not_here)?;
                let Some(vm) = c.assigned_vm_id.clone() else {
                    return Err("This connection is not on an agent, so nobody can be approved on it.".into());
                };
                let target = self.target_in(st, &vm, None)?;
                let r = self
                    .opts
                    .agent
                    .post(
                        &target,
                        "/channels/pairings/approve",
                        json!({"type": c.kind, "code": pairing.code}),
                        None,
                    )
                    .await;
                let r = match r {
                    Ok(r) => r,
                    Err(e) if !e.timed_out => return Err(e.message),
                    Err(_) => {
                        if let Some(c) = st.connections.get_mut(&p.connection_id) {
                            note_pending_approval(c, pairing, &stamp);
                        }
                        self.save(st)?;
                        tracing::info!(
                            "[channels] {} approve on {vm} did not answer in time; asking the agent what it recorded",
                            c.kind
                        );
                        let recorded = self.reconcile_in(st, Some(&vm)).await;
                        let (mine, others): (Vec<Recorded>, Vec<Recorded>) =
                            recorded.into_iter().partition(|r| r.connection_id == p.connection_id);
                        self.report(&others);
                        if let Some(landed) = mine
                            .iter()
                            .flat_map(|r| r.senders.iter())
                            .find(|x| x.id == pairing.sender_id)
                        {
                            out.insert(
                                "approvedSender".into(),
                                json!(format!(
                                    "{}:{}",
                                    landed.kind,
                                    landed.label.clone().unwrap_or_else(|| landed.id.clone())
                                )),
                            );
                            out.insert("vmId".into(), json!(vm));
                            out.insert("reconciled".into(), json!(true));
                            return Ok(out);
                        }
                        out.insert("unconfirmed".into(), json!(true));
                        out.insert("vmId".into(), json!(vm));
                        out.insert("senderId".into(), json!(pairing.sender_id));
                        return Ok(out);
                    }
                };
                let id = s(r.get("senderId")).unwrap_or_else(|| pairing.sender_id.clone());
                let sender = ApprovedSender {
                    kind: c.kind.clone(),
                    id: id.clone(),
                    label: pairing.label.clone(),
                    at: stamp,
                    extra: Map::new(),
                };
                if let Some(c) = st.connections.get_mut(&p.connection_id) {
                    if !c.approved_senders.iter().any(|x| x.id == id) {
                        c.approved_senders.push(sender.clone());
                    }
                    undecline(c, &id);
                    let kept: Vec<PendingApproval> = c
                        .pending_approvals
                        .iter()
                        .flatten()
                        .filter(|pa| pa.code != pairing.code && pa.sender_id != id)
                        .cloned()
                        .collect();
                    c.pending_approvals = (!kept.is_empty()).then_some(kept);
                }
                self.save(st)?;
                out.insert(
                    "approvedSender".into(),
                    json!(format!(
                        "{}:{}",
                        sender.kind,
                        sender.label.clone().unwrap_or_else(|| sender.id.clone())
                    )),
                );
                out.insert("vmId".into(), json!(vm));
                if r.get("alreadyApproved") == Some(&Value::Bool(true)) {
                    out.insert("alreadyApproved".into(), json!(true));
                }
            }
            "add_sender" => {
                let Some((sid, slabel)) = &p.sender else {
                    return Err("no sender in the proposal".into());
                };
                let c = st.connections.get(&p.connection_id).cloned().ok_or_else(not_here)?;
                let Some(vm) = c.assigned_vm_id.clone() else {
                    return Err("This connection is not on an agent, so nobody can be added on it.".into());
                };
                // Read the box AGAIN, now: the agent's list is only a suggestion.
                let from_box = self.read_agent_allowed(&vm).await;
                let senders = match (&from_box.error, &from_box.senders) {
                    (None, Some(x)) => x.clone(),
                    (Some((true, _)), _) => {
                        return Err("The agent is busy right now, so who it has allowed could not be checked. Try again shortly.".into());
                    }
                    (None, None) => {
                        return Err(
                            "This agent is too old to say who it has allowed. Update it, then try again.".into(),
                        );
                    }
                    _ => return Err("The agent could not be asked who it has allowed, so nothing was changed.".into()),
                };
                let Some(still) = senders.iter().find(|x| x.0 == c.kind && &x.1 == sid) else {
                    return Err(format!(
                        "{} {sid} is no longer on the agent's own list, so nothing was changed.",
                        type_name(&c.kind)
                    ));
                };
                if c.approved_senders.iter().any(|x| &x.id == sid) {
                    tracing::info!("[channels] {} {sid} already gets the codes; nothing to add", c.kind);
                    out.insert("vmId".into(), json!(vm));
                    out.insert("senderId".into(), json!(sid));
                    out.insert("alreadyApproved".into(), json!(true));
                    return Ok(out);
                }
                let sender = ApprovedSender {
                    kind: c.kind.clone(),
                    id: sid.clone(),
                    label: still.2.clone().or(slabel.clone()),
                    at: stamp.clone(),
                    extra: Map::new(),
                };
                if let Some(c) = st.connections.get_mut(&p.connection_id) {
                    c.approved_senders.push(sender.clone());
                    undecline(c, sid);
                    c.updated_at = stamp;
                }
                self.save(st)?;
                tracing::info!("[channels] {} {sid} now gets confirmation codes", c.kind);
                out.insert("vmId".into(), json!(vm));
                out.insert("senderId".into(), json!(sid));
                out.insert(
                    "approvedSender".into(),
                    json!(format!(
                        "{}:{}",
                        sender.kind,
                        sender.label.clone().unwrap_or_else(|| sender.id.clone())
                    )),
                );
            }
            "remove_sender" => {
                let Some((sid, _)) = &p.sender else {
                    return Err("no sender in the proposal".into());
                };
                let c = st.connections.get_mut(&p.connection_id).ok_or_else(not_here)?;
                let before = c.approved_senders.len();
                c.approved_senders.retain(|x| &x.id != sid);
                let mut declined: Vec<String> = c.declined_senders.clone().unwrap_or_default();
                declined.retain(|x| x != sid);
                declined.push(sid.clone());
                let skip = declined.len().saturating_sub(DECLINED_CAP);
                c.declined_senders = Some(declined.split_off(skip));
                let kept: Vec<PendingApproval> = c
                    .pending_approvals
                    .iter()
                    .flatten()
                    .filter(|pa| &pa.sender_id != sid)
                    .cloned()
                    .collect();
                c.pending_approvals = (!kept.is_empty()).then_some(kept);
                let (kind, vm) = (c.kind.clone(), c.assigned_vm_id.clone());
                if c.approved_senders.len() == before {
                    self.save(st)?;
                    tracing::info!("[channels] {kind} {sid} was not a code recipient; nothing to remove");
                    out.insert("vmId".into(), json!(vm));
                    out.insert("senderId".into(), json!(sid));
                    out.insert("missing".into(), json!(true));
                    return Ok(out);
                }
                c.updated_at = stamp;
                self.save(st)?;
                let tofu_now = self.code_routes_of(st).is_ok_and(|r| r.is_empty());
                tracing::info!(
                    "[channels] {kind} {sid} no longer gets confirmation codes{}",
                    if tofu_now { " (nobody left)" } else { "" }
                );
                out.insert("vmId".into(), json!(vm));
                out.insert("senderId".into(), json!(sid));
                if tofu_now {
                    out.insert("noRecipientsLeft".into(), json!(true));
                }
            }
            _ => {
                // whatsapp_login
                let Some(agent) = &p.agent else {
                    return Err("no agent in the proposal".into());
                };
                let existing = st.connections.get(&p.connection_id).cloned();
                let personal = match p.personal {
                    Some(Some(b)) => b,
                    _ => existing.as_ref().and_then(|e| e.settings.get("personal")) == Some(&Value::Bool(true)),
                };
                let mut settings = Map::new();
                settings.insert("personal".into(), json!(personal));
                let leaving = p
                    .from
                    .as_ref()
                    .map(|f| f.0.clone())
                    .or(existing.as_ref().and_then(|e| e.assigned_vm_id.clone()));
                if let Some(l) = leaving.filter(|l| l != &agent.vm_id) {
                    let host = p.from.as_ref().and_then(|f| f.1.clone());
                    self.leave(st, &l, "whatsapp", host.as_deref(), None).await?;
                }
                let target = self.target_in(st, &agent.vm_id, agent.hostname.as_deref())?;
                let r = self
                    .opts
                    .agent
                    .post(
                        &target,
                        "/channels/whatsapp/login",
                        Value::Object(settings.clone()),
                        None,
                    )
                    .await
                    .map_err(|e| e.message)?;
                st.connections.insert(
                    p.connection_id.clone(),
                    StoredConnection {
                        kind: "whatsapp".into(),
                        secrets: Map::new(),
                        settings,
                        hint: None,
                        label: p.label.clone().or(existing.as_ref().and_then(|e| e.label.clone())),
                        approved_senders: existing
                            .as_ref()
                            .map(|e| e.approved_senders.clone())
                            .unwrap_or_default(),
                        pending_approvals: existing
                            .as_ref()
                            .and_then(|e| e.pending_approvals.clone())
                            .filter(|x| !x.is_empty()),
                        declined_senders: None,
                        assigned_vm_id: Some(agent.vm_id.clone()),
                        updated_at: stamp,
                        extra: Map::new(),
                    },
                );
                self.save(st)?;
                out.insert("mode".into(), json!("plain"));
                out.insert("vmId".into(), json!(agent.vm_id));
                out.insert(
                    "whatsapp".into(),
                    json!({"state": r.get("state").cloned().unwrap_or(json!("qr"))}),
                );
            }
        }
        Ok(out)
    }
}

/// What `apply` did, as a command result: everything is applied except what nobody confirmed.
fn outcome(data: Map<String, Value>) -> CommandOutcome {
    if data.get("unconfirmed") != Some(&Value::Bool(true)) {
        return CommandOutcome {
            ok: true,
            status: "applied".into(),
            message: None,
            data: Some(data),
        };
    }
    let message = match data.get("unconfirmedWhat").and_then(Value::as_str) {
        Some("apply") => {
            "Your agent is taking longer than usual to finish this. It usually lands within a minute, and this page will show it when it does."
        }
        Some("remove") => {
            "Your agent has not confirmed the removal yet. The connection is off your firewall either way."
        }
        _ => "The agent has not confirmed this yet. If it approved them, it will show here within a minute.",
    };
    CommandOutcome {
        ok: true,
        status: "unconfirmed".into(),
        message: Some(message.into()),
        data: Some(data),
    }
}

fn note_agent(st: &mut ChannelStore, r: Option<&AgentRef>) {
    let Some(r) = r else { return };
    let a = st.agents.entry(r.vm_id.clone()).or_insert_with(|| StoredAgent {
        name: r.name.clone(),
        hostname: None,
        extra: Map::new(),
    });
    if !r.name.is_empty() {
        a.name = r.name.clone();
    }
    if let Some(h) = &r.hostname {
        a.hostname = Some(h.clone());
    }
}

fn undecline(c: &mut StoredConnection, sender_id: &str) {
    let kept: Vec<String> = c
        .declined_senders
        .iter()
        .flatten()
        .filter(|x| *x != sender_id)
        .cloned()
        .collect();
    c.declined_senders = (!kept.is_empty()).then_some(kept);
}

fn note_pending_approval(c: &mut StoredConnection, pairing: &Pairing, at: &str) {
    let mut kept: Vec<PendingApproval> = c
        .pending_approvals
        .iter()
        .flatten()
        .filter(|pa| pa.code != pairing.code)
        .cloned()
        .collect();
    kept.push(PendingApproval {
        sender_id: pairing.sender_id.clone(),
        label: pairing.label.clone(),
        code: pairing.code.clone(),
        at: at.into(),
        extra: Map::new(),
    });
    c.pending_approvals = Some(kept);
}
