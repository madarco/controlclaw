//! Team chat (`teamchat.ts`, apps/saas/docs/features/team-chat.md): a ClickClack server on this
//! firewall that every agent of the organization is in, and that the organization's people open
//! from the console.
//!
//!   teamchat.propose  { changeId }        turn it on (a code, or trust-on-first-use)
//!   teamchat.confirm  { changeId, code }
//!   teamchat.cancel   { changeId }
//!   teamchat.disable  {}                  turn it off (no code: it only takes access away)
//!   teamchat.push     { vmId }            connect that agent now rather than on the next tick
//!   teamchat.forget   { vmId }            the agent was deleted: delete its bot
//!
//! What lives where. ClickClack (loopback 127.0.0.1:3931) holds the chat. This module holds, sealed
//! under the box key: whether it is on, the system owner's session (ClickClack only lets a person's
//! session manage bots), and per agent its bot and the bot's real `ccb_` token. The agent is given
//! a placeholder, never the token: the chat gate swaps one for the other after checking the request
//! comes from that agent's own private address.
//!
//! `reconcile` (every minute and after each command) makes the box match the store: the unit
//! running or stopped, a bot for every live agent and the channel pushed to it, the bots of agents
//! that are gone deleted.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::api::{ApiError, Bot, TeamChatApi};
use super::helper::TeamChatHelper;
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::contracts::{AgentIdentity, ApplyOutcome};
use crate::integrations::codes::{Codes, Verified};
use crate::integrations::connectors::firewall::js_slice;
use crate::integrations::ordmap::OrdMap;
use crate::integrations::{as_map, failed, js, outcome};

pub const TEAMCHAT_RECONCILE_MS: u64 = 60_000;
/// Where ClickClack listens. Loopback only; 8080 on this box is the egress proxy.
pub const TEAMCHAT_PORT: u16 = 3931;
/// The chat gate on the private address.
pub const TEAMCHAT_GATE_PORT: u16 = 3930;
/// How long the browser's team chat cookie lasts.
pub const TEAMCHAT_GRANT_MS: i64 = 12 * 60 * 60_000;
const MAX_GRANTS: usize = 500;
const BEAT_AGENTS: usize = 200;
const SCOPE: &str = "teamchat";
const STORE: &str = "teamchat";
/// First retry of a push that failed, doubling to `RETRY_MAX_MS`.
const RETRY_FIRST_MS: i64 = 60_000;
const RETRY_MAX_MS: i64 = 30 * 60_000;
const HEALTH_WAIT_MS: i64 = 30_000;
/// How often a connected agent is asked whether it still has the channel.
const RECHECK_MS: i64 = 5 * 60_000;
/// How long a forgotten agent is kept out, well past the identity map catching up with a delete.
const FORGOTTEN_MS: i64 = 60 * 60_000;

/// The line the person reads before typing the code.
pub const ENABLE_SUMMARY: &str =
    "Turn on Team chat: a chat room on your firewall that all your agents and your team can read and write";

/// One agent, as this firewall set it up. `token` is the bot's real token and never leaves this box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    pub name: String,
    pub handle: String,
    pub bot_user_id: String,
    pub token: String,
    /// What the agent holds instead of `token`. Only good from that agent's own address.
    pub placeholder: String,
    /// What was last written to the agent (see `push_key`); None while it still has to be written.
    pub pushed: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub at: String,
    /// Epoch ms before which a failed push is not tried again.
    pub retry_at: i64,
    pub retry_wait: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,
    /// Whether the channel block may be in the agent's config (see the TS for when it is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_box: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A browser that opened Team chat from the console. Only the hash of its cookie is kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub hash: String,
    pub user_id: String,
    pub device_id: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Owner {
    pub user_id: String,
    pub session_token: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Store {
    pub version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub owner: Option<Owner>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub named: bool,
    #[serde(default)]
    pub agents: OrdMap<Agent>,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            enabled: false,
            owner: None,
            workspace_id: None,
            named: false,
            agents: OrdMap::new(),
            grants: Vec::new(),
            extra: Map::new(),
        }
    }
}

fn sha256(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// A ClickClack handle out of an agent's name: `^[a-z0-9][a-z0-9_-]{1,31}$`. Not a secret and not
/// unique by itself; a taken handle gets a suffix (see `create_bot`).
pub fn handle_for(name: &str, suffix: u32) -> String {
    let lower = name.to_lowercase();
    let nfkd: String = icu_normalizer::DecomposingNormalizerBorrowed::new_nfkd()
        .normalize(&lower)
        .into_owned();
    // `replace(/[^a-z0-9_-]+/g, "-")`.
    let mut base = String::new();
    let mut in_run = false;
    for c in nfkd.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
            base.push(c);
            in_run = false;
        } else if !in_run {
            base.push('-');
            in_run = true;
        }
    }
    let base = base.trim_matches(|c| c == '-' || c == '_');
    // `replace(/-{2,}/g, "-")`.
    let mut squeezed = String::new();
    for c in base.chars() {
        if c == '-' && squeezed.ends_with('-') {
            continue;
        }
        squeezed.push(c);
    }
    let base = if squeezed.len() < 2 {
        format!("agent{squeezed}")
    } else {
        squeezed
    };
    let tail = if suffix > 0 {
        format!("-{suffix}")
    } else {
        String::new()
    };
    let head: String = base.chars().take(32 - tail.len()).collect();
    format!("{}{tail}", head.trim_end_matches(['-', '_']))
}

/// The ClickClack identity of a console user. Synthetic: their real email never enters the chat.
pub fn person_email(org_id: &str, user_id: &str) -> String {
    format!(
        "u-{}@people.team-chat.invalid",
        &sha256(&format!("{org_id}:{user_id}"))[..24]
    )
}

fn same_text(a: &str, b: &str) -> bool {
    a.len() == b.len() && cc_crypto::ct_eq(a.as_bytes(), b.as_bytes())
}

/// `str(v)`: a non-empty string.
fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|x| !x.is_empty()).map(String::from)
}

fn nonempty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|x| !x.is_empty())
}

/// A person opening Team chat (the open intent and their browser were checked by W3's access).
pub struct Person {
    pub user_id: String,
    pub device_id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub can_write: bool,
}

/// What the counter reads with (`CounterContext`), while Team chat is running.
pub struct CounterContext {
    pub workspace_id: String,
    pub owner_user_id: String,
    /// Bot user id → the agent's vm id.
    pub bots: HashMap<String, String>,
    /// Handle, lower case → bot user id.
    pub handles: HashMap<String, String>,
}

struct Live {
    store: Store,
    state: &'static str,
    message: Option<String>,
    pending: Option<(String, String)>,
    unit_down: bool,
    started_for: Option<String>,
    forgotten: HashMap<String, i64>,
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
pub type Sleep = Arc<dyn Fn(Duration) -> cc_http::BoxFuture<()> + Send + Sync>;

pub struct TeamChatFirewall {
    app: Arc<App>,
    path: PathBuf,
    aad: String,
    api: Arc<dyn TeamChatApi>,
    helper: Arc<dyn TeamChatHelper>,
    /// What agents dial: `http://<this box's private IP>:3930`.
    gateway_url: String,
    /// The console page the chat's home button goes back to.
    home_url: String,
    /// This firewall's public hostname, or None before it has one.
    hostname: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    live: Mutex<Live>,
    saving: Mutex<()>,
    running: tokio::sync::Mutex<()>,
    again: AtomicBool,
    codes: Codes,
    /// Set once the counter's timer runs, and reported on the beat.
    pub counting: AtomicBool,
    now: Clock,
    sleep: Sleep,
}

pub struct Options {
    pub path: PathBuf,
    pub api: Arc<dyn TeamChatApi>,
    pub helper: Arc<dyn TeamChatHelper>,
    pub gateway_url: String,
    pub home_url: String,
    pub hostname: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    pub now: Clock,
    pub sleep: Sleep,
}

fn remember(secret: &str) {
    cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(secret.into()), true);
}

impl TeamChatFirewall {
    pub fn new(app: &Arc<App>, o: Options) -> Arc<Self> {
        let aad = format!("{}:{}:teamchat", app.config.org_id, app.config.box_id);
        let log = |l: &str| tracing::info!("{l}");
        let loaded = cc_crypto::enc_file::load_store_or_empty(STORE, &o.path, &app.box_key, &aad, &log);
        let store = match loaded {
            Some(v) if v.get("version") == Some(&json!(1)) => serde_json::from_value::<Store>(v).unwrap_or_else(|_| {
                tracing::error!("[teamchat] the store does not read; starting from an empty one");
                Store::default()
            }),
            _ => Store::default(),
        };
        for a in store.agents.values() {
            remember(&a.token);
        }
        let state = if store.enabled { "starting" } else { "off" };
        Arc::new(Self {
            codes: Codes::new(app, SCOPE),
            app: app.clone(),
            path: o.path,
            aad,
            api: o.api,
            helper: o.helper,
            gateway_url: o.gateway_url,
            home_url: o.home_url,
            hostname: o.hostname,
            live: Mutex::new(Live {
                store,
                state,
                message: None,
                pending: None,
                unit_down: false,
                started_for: None,
                forgotten: HashMap::new(),
            }),
            saving: Mutex::new(()),
            running: tokio::sync::Mutex::new(()),
            again: AtomicBool::new(false),
            counting: AtomicBool::new(false),
            now: o.now,
            sleep: o.sleep,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self) {
        let _one = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let v = serde_json::to_value(&self.lock().store).unwrap_or(Value::Null);
        if let Err(e) = cc_crypto::enc_file::save_store(STORE, &self.path, &v, &self.app.box_key, &self.aad) {
            tracing::error!("[teamchat] could not save: {}", e.0);
        }
    }

    fn iso(&self) -> String {
        js::iso((self.now)())
    }

    fn agents(&self) -> Vec<AgentIdentity> {
        self.app
            .contracts
            .identities
            .require()
            .ok()
            .map(|i| i.agents())
            .unwrap_or_default()
    }

    /// Whether this box can run Team chat at all: the helper (and so ClickClack) is installed.
    pub fn available(&self) -> bool {
        self.helper.installed()
    }

    pub fn enabled(&self) -> bool {
        self.lock().store.enabled
    }

    /// Running and answering: what the people's routes and the gate wait for.
    pub fn serving(&self) -> bool {
        let l = self.lock();
        l.store.enabled && l.state == "running"
    }

    // ---- commands ----

    pub async fn handle(self: &Arc<Self>, action: &str, p: Map<String, Value>) -> CommandOutcome {
        match action {
            "propose" => self.propose(&p).await,
            "confirm" => self.confirm(&p),
            "cancel" => self.cancel(&p),
            "disable" => self.disable(),
            "push" => self.push(&p),
            "forget" => self.forget(&p).await,
            _ => failed(&format!("unknown command teamchat.{action}")),
        }
    }

    async fn propose(self: &Arc<Self>, p: &Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = s(p.get("changeId")) else {
            return failed("malformed teamchat.propose payload");
        };
        let data = as_map(json!({"changeId": change_id, "summary": ENABLE_SUMMARY}));
        let with = |extra: Value| {
            let mut d = data.clone();
            d.extend(as_map(extra));
            Some(d)
        };
        if !self.available() {
            return outcome(
                false,
                "failed",
                Some("Team chat is not installed on this firewall yet. Update the firewall first.".into()),
                Some(data),
            );
        }
        if self.enabled() {
            self.codes.forget();
            self.lock().pending = None;
            return outcome(true, "applied", None, with(json!({"tofu": false, "already": true})));
        }
        let channels_ready =
            "Your firewall cannot read its channel list right now, so it cannot ask you to confirm. Try again shortly.";
        // No code routes or consent codes on this build: whether anybody can be asked is not known,
        // so nothing is turned on (never trust-on-first-use by default). Fail closed.
        let routes = match self.codes.routes() {
            Ok(r) => r,
            Err(m) => return outcome(false, "failed", Some(m), Some(data)),
        };
        if !self.app.contracts.code_routes.get().is_some_and(|r| r.ready()) {
            return outcome(false, "failed", Some(channels_ready.into()), Some(data));
        }
        // The dev route is not a person: a dev pair with nobody approved is still trust-on-first-use.
        let people = routes.iter().filter(|r| {
            r.get("senders").and_then(Value::as_array).is_some_and(|ss| {
                ss.iter()
                    .any(|x| !(x.get("type") == Some(&json!("dev")) && x.get("id") == Some(&json!("dev"))))
            })
        });
        if people.count() == 0 {
            self.codes.forget();
            self.turn_on();
            return outcome(true, "applied", None, with(json!({"tofu": true})));
        }
        // A fixed sentence of ours: nothing in this message came from anywhere else.
        match self
            .codes
            .send(
                &change_id,
                json!({"changeId": change_id}),
                "your organization",
                ENABLE_SUMMARY,
                routes,
            )
            .await
        {
            Err(m) => outcome(false, "failed", Some(m), Some(data)),
            Ok(sent) => {
                self.lock().pending = Some((change_id.clone(), sent.expires_at.clone()));
                tracing::info!(
                    "[teamchat] code sent to turn Team chat on via {}",
                    sent.sent_via.split(':').next().unwrap_or("")
                );
                outcome(
                    true,
                    "awaiting_code",
                    None,
                    with(
                        json!({"sentVia": sent.sent_via, "expiresAt": sent.expires_at, "attemptsLeft": sent.attempts_left}),
                    ),
                )
            }
        }
    }

    fn confirm(self: &Arc<Self>, p: &Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = s(p.get("changeId")) else {
            return failed("malformed teamchat.confirm payload");
        };
        match self.codes.verify(&change_id, &s(p.get("code")).unwrap_or_default()) {
            Verified::Expired => {
                let mut l = self.lock();
                if l.pending.as_ref().is_some_and(|(c, _)| *c == change_id) {
                    l.pending = None;
                }
                outcome(
                    false,
                    "expired",
                    Some("No change is waiting for a code, or the code expired.".into()),
                    Some(as_map(json!({"changeId": change_id}))),
                )
            }
            Verified::Invalid { attempts_left } => {
                if attempts_left == 0 {
                    self.lock().pending = None;
                }
                outcome(
                    false,
                    "invalid_code",
                    Some("Wrong code.".into()),
                    Some(as_map(json!({"changeId": change_id, "attemptsLeft": attempts_left}))),
                )
            }
            Verified::Ok { sent_via, .. } => {
                self.lock().pending = None;
                self.turn_on();
                outcome(
                    true,
                    "applied",
                    None,
                    Some(as_map(
                        json!({"changeId": change_id, "summary": ENABLE_SUMMARY, "sentVia": sent_via, "tofu": false}),
                    )),
                )
            }
        }
    }

    fn cancel(&self, p: &Map<String, Value>) -> CommandOutcome {
        let change_id = s(p.get("changeId"));
        self.codes.cancel(change_id.as_deref());
        let mut l = self.lock();
        if l.pending.as_ref().map(|(c, _)| c.as_str()) == change_id.as_deref() {
            l.pending = None;
        }
        outcome(true, "cancelled", None, Some(as_map(json!({"changeId": change_id}))))
    }

    /// No code: turning it off only takes access away. The chat history stays on the encrypted disk.
    fn disable(self: &Arc<Self>) -> CommandOutcome {
        self.codes.forget();
        let changed = {
            let mut l = self.lock();
            l.pending = None;
            if l.store.enabled {
                l.store.enabled = false;
                // Everyone who opened it is signed out; opening it again takes the console.
                l.store.grants.clear();
                // A backoff left over from a failed write must not hold up taking the channel off.
                for a in l.store.agents.values_mut() {
                    a.retry_at = 0;
                    a.retry_wait = 0;
                }
                l.state = "stopping";
                true
            } else {
                false
            }
        };
        if changed {
            self.save();
            tracing::info!("[teamchat] turned off");
        }
        self.kick();
        outcome(true, "applied", None, Some(as_map(json!({"enabled": false}))))
    }

    fn push(self: &Arc<Self>, p: &Map<String, Value>) -> CommandOutcome {
        let Some(vm_id) = s(p.get("vmId")) else {
            return failed("malformed teamchat.push payload");
        };
        let had = {
            let mut l = self.lock();
            match l.store.agents.get_mut(&vm_id) {
                Some(a) => {
                    a.pushed = None;
                    a.retry_at = 0;
                    true
                }
                None => false,
            }
        };
        if had {
            self.save();
        }
        self.kick();
        outcome(true, "applied", None, Some(as_map(json!({"vmId": vm_id}))))
    }

    /// The agent is being deleted. Its bot goes now if ClickClack is up, else on the next reconcile.
    async fn forget(self: &Arc<Self>, p: &Map<String, Value>) -> CommandOutcome {
        let Some(vm_id) = s(p.get("vmId")) else {
            return failed("malformed teamchat.forget payload");
        };
        let until = (self.now)() + FORGOTTEN_MS;
        let entry = {
            let mut l = self.lock();
            l.forgotten.insert(vm_id.clone(), until);
            l.store.agents.get(&vm_id).cloned()
        };
        let Some(entry) = entry else {
            return outcome(
                true,
                "applied",
                None,
                Some(as_map(json!({"vmId": vm_id, "revoked": false}))),
            );
        };
        let mut revoked = false;
        let has_owner = self.lock().store.owner.is_some();
        if self.serving() && has_owner {
            let bot = entry.bot_user_id.clone();
            match self.with_owner(move |api, s| api.remove_bot(s, bot.clone())).await {
                Ok(()) => {
                    self.lock().store.agents.remove(&vm_id);
                    self.save();
                    revoked = true;
                    tracing::info!("[teamchat] deleted the bot of {}", entry.name);
                    // The other agents' list of bots they admit just changed.
                    self.kick();
                }
                Err(e) => tracing::info!(
                    "[teamchat] could not delete the bot of {} yet ({}); the next reconcile will",
                    entry.name,
                    e.message
                ),
            }
        }
        outcome(
            true,
            "applied",
            None,
            Some(as_map(json!({"vmId": vm_id, "revoked": revoked}))),
        )
    }

    fn turn_on(self: &Arc<Self>) {
        {
            let mut l = self.lock();
            l.store.enabled = true;
            l.state = "starting";
            l.message = None;
            l.unit_down = false;
            l.started_for = None;
        }
        self.save();
        tracing::info!("[teamchat] turned on");
        self.kick();
    }

    /// Run a reconcile now without making the command wait for it (it can take a minute).
    fn kick(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move { me.reconcile().await });
    }

    // ---- reconcile ----

    /// One run at a time; a call during a run schedules exactly one more after it, and waits for it.
    pub async fn reconcile(&self) {
        let _one = match self.running.try_lock() {
            Ok(g) => g,
            Err(_) => {
                self.again.store(true, Ordering::SeqCst);
                let g = self.running.lock().await;
                // The running loop saw this call's `again` and ran once more for it: done. If it had
                // already decided to stop, the run asked for has not happened: it happens here.
                if !self.again.load(Ordering::SeqCst) {
                    return;
                }
                g
            }
        };
        loop {
            self.again.store(false, Ordering::SeqCst);
            self.reconcile_once().await;
            if !self.again.load(Ordering::SeqCst) {
                break;
            }
        }
    }

    async fn reconcile_once(&self) {
        if !self.available() {
            let mut l = self.lock();
            let on = l.store.enabled;
            l.state = if on { "failed" } else { "off" };
            l.message = on.then(|| "Team chat is not installed on this firewall. Update the firewall.".to_string());
            return;
        }
        if self.enabled() {
            self.reconcile_on().await;
        } else {
            self.reconcile_off().await;
        }
    }

    fn set_failed(&self, m: String) {
        let mut l = self.lock();
        l.state = "failed";
        l.message = Some(js_slice(&m, 300));
    }

    async fn reconcile_on(&self) {
        let Some(hostname) = (self.hostname)() else {
            let mut l = self.lock();
            l.state = "failed";
            l.message = Some("This firewall has no public name yet, so Team chat cannot start.".into());
            return;
        };
        let start_key = format!("{hostname} {}", self.home_url);
        let start = async {
            let (running, started) = {
                let l = self.lock();
                (l.state == "running", l.started_for.clone())
            };
            let up = running && started.as_deref() == Some(start_key.as_str()) && self.api.healthy().await;
            if !up {
                {
                    let mut l = self.lock();
                    if l.state != "running" {
                        l.state = "starting";
                    }
                }
                self.helper.start(hostname.clone(), self.home_url.clone()).await?;
                if !self.wait_healthy().await {
                    return Err("ClickClack did not answer after starting".to_string());
                }
                self.lock().started_for = Some(start_key.clone());
            }
            self.ensure_owner().await.map_err(|e| e.message)
        };
        if let Err(e) = start.await {
            self.set_failed(format!("Team chat could not start: {e}"));
            tracing::info!("[teamchat] {}", self.lock().message.clone().unwrap_or_default());
            return;
        }
        {
            let mut l = self.lock();
            l.state = "running";
            l.message = None;
            let now = (self.now)();
            l.forgotten.retain(|_, until| *until > now);
        }
        let forgotten: Vec<String> = self.lock().forgotten.keys().cloned().collect();
        let map = self.agents();
        let live: Vec<AgentIdentity> = map
            .iter()
            .filter(|a| nonempty(&a.hostname).is_some() && !a.private_ip.is_empty() && !forgotten.contains(&a.vm_id))
            .cloned()
            .collect();
        // No sync yet: an empty map is not "every agent was deleted".
        let map_known = !map.is_empty();
        // Bots first, then the pushes: each agent is told the other agents' bots, so that list has
        // to be settled before anybody's channel is written.
        for a in &live {
            if let Err(e) = self.ensure_bot(a).await {
                tracing::info!("[teamchat] {}: {}", nonempty(&a.name).unwrap_or(&a.vm_id), e.message);
            }
        }
        if map_known {
            let live_ids: Vec<String> = map
                .iter()
                .map(|a| a.vm_id.clone())
                .filter(|id| !forgotten.contains(id))
                .collect();
            let gone: Vec<(String, Agent)> = self
                .lock()
                .store
                .agents
                .iter()
                .filter(|(id, _)| !live_ids.contains(id))
                .map(|(id, a)| (id.clone(), a.clone()))
                .collect();
            for (vm_id, entry) in gone {
                let bot = entry.bot_user_id.clone();
                match self.with_owner(move |api, s| api.remove_bot(s, bot.clone())).await {
                    Ok(()) => {
                        self.lock().store.agents.remove(&vm_id);
                        self.save();
                        tracing::info!("[teamchat] {} is gone; deleted its bot", entry.name);
                    }
                    Err(e) => tracing::info!("[teamchat] could not delete the bot of {}: {}", entry.name, e.message),
                }
            }
        }
        for a in &live {
            self.reconcile_agent(a).await;
        }
        self.prune_grants();
    }

    async fn reconcile_off(&self) {
        // Take the channel off every agent that still has it, before the unit stops, so an agent is
        // not left reconnecting to a server that is never coming back.
        let entries: Vec<(String, Agent)> = self
            .lock()
            .store
            .agents
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let map = self.agents();
        for (vm_id, entry) in entries {
            // A store written before `onBox` existed: what was pushed is what may be there.
            if !entry.on_box.unwrap_or(entry.pushed.is_some()) {
                continue;
            }
            let Some(host) = map
                .iter()
                .find(|a| a.vm_id == vm_id)
                .and_then(|a| nonempty(&a.hostname).map(String::from))
            else {
                // Gone from the map: there is no box left to take it off.
                if let Some(a) = self.lock().store.agents.get_mut(&vm_id) {
                    a.pushed = None;
                    a.on_box = Some(false);
                }
                continue;
            };
            if (self.now)() < entry.retry_at {
                continue;
            }
            if let Some(a) = self.lock().store.agents.get_mut(&vm_id) {
                a.status = "removing".into();
            }
            let wrote = self
                .write_channel(&vm_id, &host, json!({"type": "clickclack", "remove": true}))
                .await;
            {
                let now = (self.now)();
                let mut l = self.lock();
                if let Some(a) = l.store.agents.get_mut(&vm_id) {
                    match wrote {
                        Ok(_) => {
                            a.pushed = None;
                            a.on_box = Some(false);
                            a.error = None;
                            a.retry_wait = 0;
                            a.retry_at = 0;
                            tracing::info!("[teamchat] took Team chat off {}", a.name);
                        }
                        Err(e) => failed_entry(a, &e, now),
                    }
                    a.at = js::iso(now);
                }
            }
            self.save();
        }
        if self.lock().unit_down {
            return;
        }
        let stopped = async {
            let state = self.helper.status().await?;
            if state != "inactive" && state != "unknown" {
                self.helper.stop().await?;
            }
            Ok::<(), String>(())
        };
        match stopped.await {
            Ok(()) => {
                let mut l = self.lock();
                l.state = "off";
                l.message = None;
                l.unit_down = true;
            }
            Err(e) => self.set_failed(format!("Team chat could not stop: {e}")),
        }
    }

    async fn write_channel(&self, vm_id: &str, hostname: &str, body: Value) -> Result<ApplyOutcome, String> {
        let Some(w) = self.app.contracts.channel_writer.get() else {
            return Err("this firewall cannot write channels to agents yet".into());
        };
        w.write(vm_id, hostname, "clickclack", body).await
    }

    async fn wait_healthy(&self) -> bool {
        let until = (self.now)() + HEALTH_WAIT_MS;
        for _ in 0..60 {
            if self.api.healthy().await {
                return true;
            }
            if (self.now)() >= until {
                break;
            }
            (self.sleep)(Duration::from_millis(500)).await;
        }
        false
    }

    /// The system owner, its session and the workspace, made once and kept in the store.
    async fn ensure_owner(&self) -> Result<(), ApiError> {
        if self.lock().store.owner.is_none() {
            self.new_owner_session().await?;
        }
        if self.lock().store.workspace_id.is_none() {
            let ws = self.with_owner(|api, s| api.workspaces(s)).await?;
            let mine = ws.iter().find(|w| w.role.as_deref() == Some("owner")).or(ws.first());
            let Some(mine) = mine else {
                return Err(ApiError::new(0, "ClickClack has no workspace"));
            };
            self.lock().store.workspace_id = Some(mine.id.clone());
            self.save();
        }
        if !self.lock().store.named {
            let id = self.lock().store.workspace_id.clone().unwrap_or_default();
            self.with_owner(move |api, s| api.rename_workspace(s, id.clone(), "Team chat".into()))
                .await?;
            self.lock().store.named = true;
            self.save();
        }
        Ok(())
    }

    async fn new_owner_session(&self) -> Result<(), ApiError> {
        let (_, token) = self.helper.bootstrap().await.map_err(|e| ApiError::new(0, e))?;
        let (user_id, session) = self.api.consume(token).await?;
        self.lock().store.owner = Some(Owner {
            user_id,
            session_token: session,
        });
        self.save();
        Ok(())
    }

    /// A call as the owner, with one fresh session when the stored one has expired or was revoked.
    async fn with_owner<T, F>(&self, call: F) -> Result<T, ApiError>
    where
        F: Fn(&dyn TeamChatApi, String) -> cc_http::BoxFuture<Result<T, ApiError>>,
    {
        if self.lock().store.owner.is_none() {
            self.new_owner_session().await?;
        }
        let session = self
            .lock()
            .store
            .owner
            .as_ref()
            .map(|o| o.session_token.clone())
            .unwrap_or_default();
        match call(self.api.as_ref(), session).await {
            Err(e) if e.status == 401 => {
                self.new_owner_session().await?;
                let session = self
                    .lock()
                    .store
                    .owner
                    .as_ref()
                    .map(|o| o.session_token.clone())
                    .unwrap_or_default();
                call(self.api.as_ref(), session).await
            }
            r => r,
        }
    }

    async fn ensure_bot(&self, a: &AgentIdentity) -> Result<(), ApiError> {
        let name = js_slice(nonempty(&a.name).unwrap_or(&a.vm_id), 80);
        if self.lock().store.agents.contains_key(&a.vm_id) {
            return Ok(());
        }
        let bot = self.create_bot(&name).await?;
        remember(&bot.token);
        let entry = Agent {
            name: name.clone(),
            handle: bot.handle.clone(),
            bot_user_id: bot.bot_user_id,
            token: bot.token,
            placeholder: format!(
                "cctc_{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
            ),
            pushed: None,
            status: "connecting".into(),
            error: None,
            at: self.iso(),
            retry_at: 0,
            retry_wait: 0,
            checked_at: None,
            on_box: None,
            extra: Map::new(),
        };
        self.lock().store.agents.insert(a.vm_id.clone(), entry);
        self.save();
        tracing::info!("[teamchat] made @{} for {name}", bot.handle);
        Ok(())
    }

    /// The other agents' bots, which this agent admits when they mention it.
    fn peers(&self, vm_id: &str) -> Vec<String> {
        let mut p: Vec<String> = self
            .lock()
            .store
            .agents
            .iter()
            .filter(|(id, _)| *id != vm_id)
            .map(|(_, a)| a.bot_user_id.clone())
            .collect();
        p.sort();
        p
    }

    async fn reconcile_agent(&self, a: &AgentIdentity) {
        let vm_id = a.vm_id.clone();
        let host = nonempty(&a.hostname).unwrap_or("").to_string();
        let name = js_slice(nonempty(&a.name).unwrap_or(&vm_id), 80);
        let Some(entry) = self.lock().store.agents.get(&vm_id).cloned() else {
            return;
        };
        let peers = self.peers(&vm_id);
        let key = self.push_key(&entry, &peers);
        if entry.pushed.as_deref() == Some(key.as_str()) {
            if entry.status == "connecting" || (self.now)() - entry.checked_at.unwrap_or(0) > RECHECK_MS {
                self.read_status(&vm_id, &host).await;
            }
            let pushed = self.lock().store.agents.get(&vm_id).and_then(|e| e.pushed.clone());
            if pushed.as_deref() == Some(key.as_str()) {
                return;
            }
        }
        let retry_at = self.lock().store.agents.get(&vm_id).map(|e| e.retry_at).unwrap_or(0);
        if (self.now)() < retry_at {
            return;
        }
        let workspace = {
            let mut l = self.lock();
            if let Some(e) = l.store.agents.get_mut(&vm_id) {
                e.status = "connecting".into();
                e.on_box = Some(true);
            }
            l.store.workspace_id.clone()
        };
        let body = json!({"type": "clickclack", "settings": {
            "baseUrl": format!("https://{}", (self.hostname)().unwrap_or_else(|| "null".into())),
            "apiBaseUrl": self.gateway_url,
            "token": entry.placeholder,
            "workspace": workspace,
            "botUserId": entry.bot_user_id,
            "peers": peers,
        }});
        let wrote = self.write_channel(&vm_id, &host, body).await;
        {
            let now = (self.now)();
            let mut l = self.lock();
            if let Some(e) = l.store.agents.get_mut(&vm_id) {
                match wrote {
                    Ok(o) => {
                        e.pushed = Some(key);
                        e.status = if o == ApplyOutcome::Applied {
                            "connected"
                        } else {
                            "connecting"
                        }
                        .into();
                        e.error = None;
                        e.retry_wait = 0;
                        e.retry_at = 0;
                        tracing::info!(
                            "[teamchat] {name} {}",
                            if o == ApplyOutcome::Applied {
                                "is in Team chat"
                            } else {
                                "is joining Team chat"
                            }
                        );
                    }
                    Err(m) => failed_entry(e, &m, now),
                }
                e.at = js::iso(now);
            }
        }
        self.save();
    }

    /// What the agent was given. A change to any part of it (a new public name, say) is pushed again.
    fn push_key(&self, entry: &Agent, peers: &[String]) -> String {
        let workspace = self.lock().store.workspace_id.clone();
        sha256(&js::stringify(&json!([
            (self.hostname)(),
            self.gateway_url,
            workspace,
            entry.bot_user_id,
            entry.placeholder,
            peers
        ])))
    }

    /// A write that settled as unconfirmed: the box's own channel status says how it ended.
    async fn read_status(&self, vm_id: &str, _hostname: &str) {
        let Some(client) = self.app.contracts.agents.get() else {
            return;
        };
        // The agent is busy: ask again next tick.
        let Ok(status) = client.get(vm_id, "/channels/status").await else {
            return;
        };
        let cc = status.get("channels").and_then(|c| c.get("clickclack")).cloned();
        let peers = self.peers(vm_id);
        let now = (self.now)();
        {
            let mut l = self.lock();
            let Some(e) = l.store.agents.get_mut(vm_id) else { return };
            e.checked_at = Some(now);
            let get = |k: &str| cc.as_ref().and_then(|c| c.get(k)).filter(|v| !v.is_null()).cloned();
            let last_apply = get("lastApply");
            let setup = get("setup");
            let state_of = |v: &Option<Value>| v.as_ref().and_then(|x| x.get("state")).cloned();
            let configured = get("configured") == Some(Value::Bool(true));
            if state_of(&last_apply) == Some(json!("failed")) || state_of(&setup) == Some(json!("failed")) {
                e.pushed = None;
                let why = if state_of(&last_apply) == Some(json!("failed")) {
                    last_apply.as_ref().and_then(|x| x.get("error")).cloned()
                } else {
                    setup.as_ref().and_then(|x| x.get("message")).cloned()
                };
                let why = why.and_then(|w| w.as_str().filter(|w| !w.is_empty()).map(String::from));
                failed_entry(
                    e,
                    &why.unwrap_or_else(|| "the agent could not apply Team chat".into()),
                    now,
                );
            } else if configured
                && get("peers").as_ref().and_then(Value::as_array).is_some_and(|p| {
                    let mut got: Vec<Value> = p.clone();
                    got.sort_by_key(js::stringify);
                    js::stringify(&Value::Array(got)) != js::stringify(&json!(peers))
                })
            {
                // The agent's live config admits other bots than it should: write it again.
                tracing::info!(
                    "[teamchat] {} has an older list of the other agents; writing it again",
                    e.name
                );
                e.pushed = None;
            } else if configured {
                e.status = "connected".into();
                e.error = get("lastError").and_then(|v| v.as_str().filter(|x| !x.is_empty()).map(|x| js_slice(x, 200)));
            } else if cc.is_none() || (last_apply.is_none() && setup.is_none()) {
                // The agent does not have it at all (rebuilt, or its config put back): write it again.
                if e.status == "connected" {
                    tracing::info!("[teamchat] {} no longer has Team chat; writing it again", e.name);
                }
                e.pushed = None;
                e.status = "connecting".into();
            }
            e.at = js::iso(now);
        }
        self.save();
    }

    async fn create_bot(&self, name: &str) -> Result<Bot, ApiError> {
        let mut last: Option<ApiError> = None;
        for suffix in 0..10 {
            let (w, n, h) = (
                self.lock().store.workspace_id.clone().unwrap_or_default(),
                name.to_string(),
                handle_for(name, suffix),
            );
            match self
                .with_owner(move |api, s| api.create_bot(s, w.clone(), n.clone(), h.clone()))
                .await
            {
                Ok(b) => return Ok(b),
                Err(e) => {
                    // A handle another bot holds: try the next suffix. Anything else is a real failure.
                    let lower = e.message.to_lowercase();
                    let taken = e.status != 0
                        && (lower.contains("taken") || lower.contains("exists") || lower.contains("unique"));
                    if !taken {
                        return Err(e);
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| ApiError::new(0, "no free handle")))
    }

    // ---- the gate ----

    /// The agent a placeholder belongs to, with its real token and the address it must come from.
    /// None while Team chat is off, for an unknown placeholder, or for an agent no longer in the map.
    pub fn resolve(&self, placeholder: &str) -> Option<(String, String, String)> {
        if !self.serving() || !placeholder.starts_with("cctc_") {
            return None;
        }
        let hit = self
            .lock()
            .store
            .agents
            .iter()
            .find(|(_, e)| same_text(&e.placeholder, placeholder))
            .map(|(id, e)| (id.clone(), e.token.clone()))?;
        let ip = self
            .agents()
            .into_iter()
            .find(|a| a.vm_id == hit.0)
            .map(|a| a.private_ip)
            .filter(|ip| !ip.is_empty())?;
        Some((hit.0, hit.1, ip))
    }

    /// Every real token this box holds (each is in the log redaction set from when it is read).
    #[cfg(test)]
    pub fn tokens(&self) -> Vec<String> {
        self.lock().store.agents.values().map(|a| a.token.clone()).collect()
    }

    // ---- people ----

    /// A person opening Team chat from the console. Makes them a member with the role their console
    /// role maps to, mints the single-use magic link their browser consumes, and records the grant.
    pub async fn admit(&self, p: &Person) -> Result<(String, String), String> {
        let workspace = self.lock().store.workspace_id.clone();
        let (true, Some(workspace)) = (self.serving(), workspace) else {
            return Err("Team chat is not running".into());
        };
        let display = p
            .name
            .as_deref()
            .map(js::trim)
            .filter(|n| !n.is_empty())
            .map(String::from)
            .or_else(|| {
                p.email
                    .as_deref()
                    .filter(|e| !e.is_empty())
                    .map(|e| e.split('@').next().unwrap_or("").to_string())
            })
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Team member".into());
        let display = js_slice(&display, 80);
        let (user, token) = self
            .helper
            .login(
                workspace.clone(),
                person_email(&self.app.config.org_id, &p.user_id),
                display,
            )
            .await?;
        // Owners and admins moderate the room; members are members. Set on every open.
        let role = if p.can_write { "moderator" } else { "member" };
        let (w, u) = (workspace.clone(), user.clone());
        self.with_owner(move |api, s| api.set_role(s, w.clone(), u.clone(), role))
            .await
            .map_err(|e| e.message)?;
        let cookie = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        self.prune_grants();
        {
            let now = (self.now)();
            let mut l = self.lock();
            l.store.grants.push(Grant {
                hash: sha256(&cookie),
                user_id: p.user_id.clone(),
                device_id: p.device_id.clone(),
                expires_at: now + TEAMCHAT_GRANT_MS,
            });
            let n = l.store.grants.len();
            if n > MAX_GRANTS {
                l.store.grants.drain(..n - MAX_GRANTS);
            }
        }
        self.save();
        Ok((token, cookie))
    }

    /// The grant a team chat cookie names, if it is live.
    pub fn grant(&self, cookie: &str) -> Option<Grant> {
        let ok = cookie.len() == 43
            && cookie
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !ok {
            return None;
        }
        let hash = sha256(cookie);
        let now = (self.now)();
        self.lock()
            .store
            .grants
            .iter()
            .find(|g| same_text(&g.hash, &hash))
            .filter(|g| g.expires_at > now)
            .cloned()
    }

    fn prune_grants(&self) {
        let now = (self.now)();
        let changed = {
            let mut l = self.lock();
            let before = l.store.grants.len();
            l.store.grants.retain(|g| g.expires_at > now);
            l.store.grants.len() != before
        };
        if changed {
            self.save();
        }
    }

    // ---- the counter ----

    pub fn counter_context(&self) -> Option<CounterContext> {
        if !self.serving() {
            return None;
        }
        let l = self.lock();
        let owner = l.store.owner.as_ref()?;
        let workspace = l.store.workspace_id.clone()?;
        let mut bots = HashMap::new();
        let mut handles = HashMap::new();
        for (vm, a) in l.store.agents.iter() {
            bots.insert(a.bot_user_id.clone(), vm.clone());
            handles.insert(a.handle.to_lowercase(), a.bot_user_id.clone());
        }
        Some(CounterContext {
            workspace_id: workspace,
            owner_user_id: owner.user_id.clone(),
            bots,
            handles,
        })
    }

    /// The owner's session for the counter's reads; a fresh one when the stored one was refused.
    pub async fn owner_session(&self, fresh: bool) -> Result<String, ApiError> {
        if fresh || self.lock().store.owner.is_none() {
            self.new_owner_session().await?;
        }
        Ok(self
            .lock()
            .store
            .owner
            .as_ref()
            .map(|o| o.session_token.clone())
            .unwrap_or_default())
    }

    // ---- the beat ----

    pub fn status(&self) -> Value {
        let now = (self.now)();
        let l = self.lock();
        let pending = l
            .pending
            .as_ref()
            .filter(|(_, at)| js::parse_iso(at).is_some_and(|t| t > now))
            .map(|(c, at)| json!({"changeId": c, "expiresAt": at}))
            .unwrap_or(Value::Null);
        let agents: Vec<Value> = l
            .store
            .agents
            .iter()
            .filter(|(_, a)| l.store.enabled || a.pushed.is_some())
            .take(BEAT_AGENTS)
            .map(|(vm, a)| json!({"vmId": vm, "status": a.status, "error": a.error, "at": a.at}))
            .collect();
        json!({
            "enabled": l.store.enabled,
            "state": l.state,
            "message": l.message,
            "pending": pending,
            "agents": agents,
            "stats": self.counting.load(Ordering::SeqCst),
        })
    }
}

fn failed_entry(e: &mut Agent, message: &str, now: i64) {
    e.status = "failed".into();
    e.error = Some(js_slice(message, 200));
    e.retry_wait = if e.retry_wait > 0 {
        (e.retry_wait * 2).min(RETRY_MAX_MS)
    } else {
        RETRY_FIRST_MS.min(RETRY_MAX_MS)
    };
    e.retry_at = now + e.retry_wait;
    tracing::info!("[teamchat] {}: {}", e.name, e.error.clone().unwrap_or_default());
}

#[cfg(test)]
pub(crate) mod tests;
