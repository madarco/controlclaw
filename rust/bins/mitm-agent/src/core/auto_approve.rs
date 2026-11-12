//! The Auto approve rules, kept and checked on the firewall (docs/security-design.md, "Permission
//! requests"), as the integration rules are (`integrations/apps_rules/firewall.rs`). Kept in
//! `autoapprove-rules.enc`, the source of truth: the console reads and changes them with commands.
//!
//! ```text
//!   autoapprove.read     {}                    the rules
//!   autoapprove.propose  { changeId, change }  applied at once unless a request could now be
//!                                              approved that was not before; then held for a code
//!   autoapprove.confirm  { changeId, code }
//!   autoapprove.cancel   { changeId }
//! ```
//!
//! The rules the console kept before come once, in the sync's `auto_approve.seed`, to a store never
//! seeded, and need no code (they already answered requests). Until then the firewall checks nothing
//! and the console does it (`evaluateRules`); a standalone firewall is seeded empty at start.
//!
//! Two kinds of request meet the rules here: OpenClaw's own approvals, which an agent's vm-agent
//! sends to the 3940 gate ([`AgentApprovals`]), and the firewall's own asks, in the permission bridge
//! before it raises them (`permissions.rs`). Allow and Block are answered here and reported to the
//! control plane afterwards (`decided`); Ask goes to the control plane with the rule that asked
//! (`checked`), and a person answers it there.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use cc_contracts::auto_approve::{self, AGENT_KINDS, AutoApprove, AutoRule, Decision, Effect, RULES_MAX};
use cc_http::BoxFuture;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::code_message::{CodeParts, TypedLine};
use super::permissions::{PermissionBridge, encode_uri_component};
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::contracts::AgentPermissions;
use crate::integrations::codes::{Codes, Verified, record_name};
use crate::integrations::{as_map, js, outcome};

const STORE: &str = "autoapprove-rules";
const MODULE: &str = "autoapprove";
const SCOPE: &str = "autoapprove-rules";
pub const DEFAULT_PATH: &str = "/opt/controlclaw/state/autoapprove-rules.enc";
const NOT_SEEDED: &str =
    "Your firewall has not taken your Auto approve rules from ControlClaw yet. Try again in a minute.";

// ---------------------------------------------------------------------------------------------
// Changes and whether they let more through

#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Put { rule: AutoRule, at: Option<usize> },
    Delete { id: String },
    Move { id: String, to: usize },
}

fn index(v: Option<&Value>) -> Result<Option<usize>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(n) => n
            .as_u64()
            .filter(|n| *n <= RULES_MAX as u64)
            .map(|n| Some(n as usize))
            .ok_or_else(|| "invalid position".into()),
    }
}

fn strict(o: &Map<String, Value>, keys: &[&str]) -> Result<(), String> {
    match o.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(format!("unknown key {k}")),
        None => Ok(()),
    }
}

fn rule_id(o: &Map<String, Value>) -> Result<String, String> {
    match o.get("id").and_then(Value::as_str) {
        Some(s)
            if (1..=64).contains(&s.len())
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            Ok(s.to_string())
        }
        _ => Err("invalid rule id".into()),
    }
}

/// A rule as a change or a template brings it: only the rule's keys, and `check()`ed.
pub fn parse_rule(v: &Value) -> Result<AutoRule, String> {
    let o = v.as_object().ok_or("invalid rule")?;
    strict(
        o,
        &[
            "id",
            "name",
            "description",
            "kinds",
            "title_like",
            "title_match",
            "vm_id",
            "effect",
            "enabled",
        ],
    )?;
    let mut r: AutoRule = serde_json::from_value(v.clone()).map_err(|_| "invalid rule".to_string())?;
    // An empty title or agent is none.
    r.title_like = r.title_like.filter(|t| !t.is_empty());
    r.vm_id = r.vm_id.filter(|t| !t.is_empty());
    r.check().map_err(|f| format!("invalid rule {f}"))?;
    Ok(r)
}

pub fn parse_change(v: &Value) -> Result<Change, String> {
    let o = v.as_object().ok_or("invalid change")?;
    match o.get("op").and_then(Value::as_str) {
        Some("put") => {
            strict(o, &["op", "rule", "at"])?;
            Ok(Change::Put {
                rule: parse_rule(o.get("rule").unwrap_or(&Value::Null))?,
                at: index(o.get("at"))?,
            })
        }
        Some("delete") => {
            strict(o, &["op", "id"])?;
            Ok(Change::Delete { id: rule_id(o)? })
        }
        Some("move") => {
            strict(o, &["op", "id", "to"])?;
            let to = index(o.get("to"))?.ok_or("invalid position")?;
            Ok(Change::Move { id: rule_id(o)?, to })
        }
        _ => Err("invalid change".into()),
    }
}

pub fn apply_change(rules: &[AutoRule], change: &Change) -> Result<Vec<AutoRule>, String> {
    let at = |id: &str| rules.iter().position(|r| r.id == id).ok_or("no such rule");
    match change {
        Change::Delete { id } => {
            let i = at(id)?;
            let mut next = rules.to_vec();
            next.remove(i);
            Ok(next)
        }
        Change::Move { id, to } => {
            let i = at(id)?;
            let mut next = rules.to_vec();
            let r = next.remove(i);
            next.insert((*to).min(next.len()), r);
            Ok(next)
        }
        Change::Put { rule, at } => {
            if let Some(i) = rules.iter().position(|r| r.id == rule.id) {
                let mut next = rules.to_vec();
                next[i] = rule.clone();
                return Ok(next);
            }
            if rules.len() >= RULES_MAX {
                return Err("too many rules".into());
            }
            let mut next = rules.to_vec();
            next.insert(at.unwrap_or(next.len()).min(next.len()), rule.clone());
            Ok(next)
        }
    }
}

fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// Every request `inner` matches, `outer` matches too. Sure answers only: false when unsure.
pub fn covers(outer: &AutoRule, inner: &AutoRule) -> bool {
    let kinds =
        outer.kinds.is_empty() || (!inner.kinds.is_empty() && inner.kinds.iter().all(|k| outer.kinds.contains(k)));
    let vm = match (&outer.vm_id, &inner.vm_id) {
        (None, _) => true,
        (Some(a), Some(b)) => a == b,
        (Some(_), None) => false,
    };
    let title = match (outer.title(), inner.title()) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(o), Some(i)) => {
            let (o, i) = (lower(o), lower(i));
            if outer.exact() {
                inner.exact() && o == i
            } else {
                i.contains(&o)
            }
        }
    };
    // A rule that names no kind and no title never answers an app call (`evaluate`): it covers
    // only what cannot be one.
    let app_calls = outer.kinds.is_empty()
        && outer.title().is_none()
        && (inner.kinds.is_empty() || inner.kinds.iter().any(|k| k == "app_call"));
    kinds && vm && title && !app_calls
}

/// Some request could match both. True when unsure.
pub fn overlaps(a: &AutoRule, b: &AutoRule) -> bool {
    let kinds = a.kinds.is_empty() || b.kinds.is_empty() || a.kinds.iter().any(|k| b.kinds.contains(k));
    let vm = match (&a.vm_id, &b.vm_id) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    };
    let title = match (a.title(), b.title()) {
        (Some(x), Some(y)) => {
            let (x, y) = (lower(x), lower(y));
            match (a.exact(), b.exact()) {
                (true, true) => x == y,
                (true, false) => x.contains(&y),
                (false, true) => y.contains(&x),
                // A title can always hold both texts.
                (false, false) => true,
            }
        }
        _ => true,
    };
    kinds && vm && title
}

fn allows(r: &AutoRule) -> bool {
    r.enabled && r.effect() == Some(Effect::Allow)
}

/// Whether some request could be answered Allow after the change that was not before. Sure only
/// when it says false: every Allow rule after is checked to answer nothing new.
///
/// An Allow rule `a` in `after` answers what it matches less what an earlier rule takes. That is
/// nothing new when an earlier rule covers it, or when an Allow rule `b` in `before` covered it and
/// everything that took a part of `a` from `b` there (an earlier Ask or Block that overlaps `a`)
/// still comes before `a`, covered by a rule there.
pub fn allows_more(before: &[AutoRule], after: &[AutoRule]) -> bool {
    let enabled = |list: &[AutoRule]| list.iter().filter(|r| r.enabled).cloned().collect::<Vec<_>>();
    let (before, after) = (enabled(before), enabled(after));
    after.iter().enumerate().any(|(i, a)| {
        if !allows(a) {
            return false;
        }
        let earlier = &after[..i];
        if earlier.iter().any(|d| covers(d, a)) {
            return false;
        }
        let was = before.iter().enumerate().any(|(j, b)| {
            allows(b)
                && covers(b, a)
                && before[..j]
                    .iter()
                    .filter(|c| !allows(c) && overlaps(c, a))
                    .all(|c| earlier.iter().any(|d| covers(d, c)))
        });
        !was
    })
}

pub fn widens(rules: &[AutoRule], change: &Change) -> bool {
    match apply_change(rules, change) {
        Ok(after) => allows_more(rules, &after),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------------------------
// In words, for the code message

fn kind_words(k: &str) -> &'static str {
    match k {
        "exec" => "shell commands",
        "plugin" => "plugin actions",
        "system" => "system steps",
        "access" => "website asks",
        "email_recipient" => "new email recipients",
        "app_call" => "integration calls",
        "payment" => "payments",
        "delete" => "deletes",
        "settings_change" => "settings changes",
        "meeting_request" => "requests made in a meeting",
        _ => "other requests",
    }
}

fn effect_words(e: &str) -> &'static str {
    match e {
        "allow" => "approves",
        "block" => "denies",
        _ => "asks you about",
    }
}

fn agent_words(app: &App, vm_id: Option<&str>) -> String {
    match vm_id {
        None => "any agent".into(),
        Some(v) => {
            let name = app
                .contracts
                .identities
                .require()
                .ok()
                .and_then(|m| m.agent(v))
                .and_then(|a| a.name);
            format!("the agent {}", record_name(name.as_deref(), v))
        }
    }
}

/// What a rule matches, from its fields only. The title is typed text: said as "the text below".
fn match_words(app: &App, r: &AutoRule) -> String {
    let kinds = if r.kinds.is_empty() {
        "any request".to_string()
    } else {
        r.kinds.iter().map(|k| kind_words(k)).collect::<Vec<_>>().join(", ")
    };
    let title = match r.title() {
        None => String::new(),
        Some(_) if r.exact() => " whose text is exactly the text below".into(),
        Some(_) => " whose text contains the text below".into(),
    };
    format!("{kinds}{title} from {}", agent_words(app, r.vm_id.as_deref()))
}

/// Every (Allow, Ask or Block) pair where the Allow comes first and the two match some of the same
/// requests: the Ask or Block no longer decides those. By ids.
fn shadow_pairs(rules: &[AutoRule]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (i, a) in rules.iter().enumerate() {
        if !a.enabled || a.effect() != Some(Effect::Allow) {
            continue;
        }
        for x in &rules[i + 1..] {
            if x.enabled && matches!(x.effect(), Some(Effect::Ask | Effect::Block)) && overlaps(a, x) {
                out.push((a.id.clone(), x.id.clone()));
            }
        }
    }
    out
}

/// What a change puts in a new (Allow above Ask or Block) pair, seen from the rule it changes: the
/// Ask and Block rules a changed Allow now goes above, and the Allow rules a changed Ask or Block now
/// goes below. Pairs that were there before are not news.
fn newly_shadowed(rules: &[AutoRule], change: &Change) -> (Vec<AutoRule>, Vec<AutoRule>) {
    let id = match change {
        Change::Put { rule, .. } => rule.id.clone(),
        Change::Move { id, .. } => id.clone(),
        Change::Delete { .. } => return (vec![], vec![]),
    };
    let Ok(next) = apply_change(rules, change) else {
        return (vec![], vec![]);
    };
    let before = shadow_pairs(rules);
    let new: Vec<(String, String)> = shadow_pairs(&next)
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    let by_id = |want: &str| next.iter().find(|r| r.id == want).cloned();
    let above = new
        .iter()
        .filter(|(a, _)| *a == id)
        .filter_map(|(_, x)| by_id(x))
        .collect();
    let below = new
        .iter()
        .filter(|(_, x)| *x == id)
        .filter_map(|(a, _)| by_id(a))
        .collect();
    (above, below)
}

/// The firewall's words for a change (part one) and the typed texts it names (part two).
pub fn describe(app: &App, change: &Change, rules: &[AutoRule]) -> (String, Vec<TypedLine>) {
    let (mut words, mut typed) = describe_change(app, change, rules);
    let (above, below) = newly_shadowed(rules, change);
    let plural = |n: usize, one: &'static str, many: &'static str| if n == 1 { one } else { many };
    if !above.is_empty() {
        let n = above.len();
        words = format!(
            "{words}. It goes above {n} {} that {} for these requests, so {} no longer {} to them",
            plural(n, "rule", "rules"),
            plural(n, "asks or blocks", "ask or block"),
            plural(n, "it", "they"),
            plural(n, "applies", "apply"),
        );
        typed.extend(above.into_iter().map(|r| TypedLine {
            label: "Above the rule".into(),
            text: r.name,
            more: None,
        }));
    }
    if !below.is_empty() {
        let n = below.len();
        words = format!(
            "{words}. It goes below {n} {} that {} some of the same requests, so {} {} them now",
            plural(n, "rule", "rules"),
            plural(n, "approves", "approve"),
            plural(n, "that rule", "those rules"),
            plural(n, "approves", "approve"),
        );
        typed.extend(below.into_iter().map(|r| TypedLine {
            label: "Below the rule".into(),
            text: r.name,
            more: None,
        }));
    }
    (words, typed)
}

fn describe_change(app: &App, change: &Change, rules: &[AutoRule]) -> (String, Vec<TypedLine>) {
    let typed = |r: &AutoRule| {
        let mut t = vec![TypedLine {
            label: "Rule name".into(),
            text: r.name.clone(),
            more: None,
        }];
        if let Some(title) = r.title() {
            t.push(TypedLine {
                label: "Text".into(),
                text: title.to_string(),
                more: None,
            });
        }
        t
    };
    match change {
        Change::Delete { id } => match rules.iter().find(|r| r.id == *id) {
            Some(old) => (
                format!(
                    "Delete the Auto approve rule that {} {}",
                    effect_words(&old.effect),
                    match_words(app, old)
                ),
                typed(old),
            ),
            None => ("Delete an Auto approve rule".into(), vec![]),
        },
        Change::Move { id, to } => match rules.iter().find(|r| r.id == *id) {
            Some(old) => (
                format!(
                    "Move the Auto approve rule that {} {} to position {}",
                    effect_words(&old.effect),
                    match_words(app, old),
                    to + 1
                ),
                typed(old),
            ),
            None => (format!("Move an Auto approve rule to position {}", to + 1), vec![]),
        },
        Change::Put { rule: r, .. } => (
            format!(
                "{} an Auto approve rule that {} {} without asking{}",
                if rules.iter().any(|x| x.id == r.id) {
                    "Change"
                } else {
                    "Add"
                },
                effect_words(&r.effect),
                match_words(app, r),
                if r.enabled { "" } else { " (turned off)" }
            ),
            typed(r),
        ),
    }
}

/// One rule a template adds for `agent` (a name on this firewall's record), from its fields only.
pub fn rule_words(r: &AutoRule, agent: &str) -> String {
    let kinds = if r.kinds.is_empty() {
        "any request".to_string()
    } else {
        r.kinds.iter().map(|k| kind_words(k)).collect::<Vec<_>>().join(", ")
    };
    let title = match r.title() {
        None => "",
        Some(_) if r.exact() => " with exactly its text",
        Some(_) => " containing its text",
    };
    format!(
        "one that {} {kinds}{title} from {agent}{}",
        effect_words(&r.effect),
        if r.enabled { "" } else { " (turned off)" }
    )
}

// ---------------------------------------------------------------------------------------------
// The store

impl State {
    /// A new list: its version goes up, and to the clock's milliseconds when that is higher.
    fn bump(&mut self) {
        let now = super::now_ms();
        self.list_version = (self.list_version + 1).max(now);
    }
}

struct State {
    rules: Vec<AutoRule>,
    /// Which list this is: higher after every change, and never lower than the clock's milliseconds,
    /// so a firewall that lost its store and starts again still counts up. The console copies a list
    /// only when it is newer than the one it copied last.
    list_version: u64,
    seeded: bool,
    /// A store that is there and will not open is not "no rules": every request is asked about
    /// until a confirmed change reseals it.
    unreadable: bool,
    extra: Map<String, Value>,
}

pub struct AutoApproveFirewall {
    app: Arc<App>,
    path: PathBuf,
    aad: String,
    state: RwLock<State>,
    /// App ids to names, from the last sync: for an app call's title.
    app_names: RwLock<BTreeMap<String, String>>,
    codes: Codes,
    serial: tokio::sync::Mutex<()>,
}

/// The rules as one string, to tell whether they changed while a code was on its way.
fn basis_of(rules: &[AutoRule], unreadable: bool) -> String {
    let text = if unreadable {
        "unreadable".to_string()
    } else {
        js::stringify(&serde_json::to_value(rules).unwrap_or(Value::Null))
    };
    hex::encode(Sha256::digest(text.as_bytes()))
}

impl AutoApproveFirewall {
    pub fn new(app: &Arc<App>, path: PathBuf) -> Arc<Self> {
        let aad = format!("{}:{}:{STORE}", app.config.org_id, app.config.box_id);
        let existed = path.exists();
        let log = |l: &str| tracing::info!("{l}");
        let stored = cc_crypto::enc_file::load_store_or_empty(STORE, &path, &app.box_key, &aad, &log);
        let parsed: Option<Vec<AutoRule>> = stored.as_ref().and_then(|s| {
            if s.get("version") != Some(&json!(1)) {
                return None;
            }
            s.get("rules")?.as_array()?.iter().map(|r| parse_rule(r).ok()).collect()
        });
        let unreadable = (existed && stored.is_none()) || (stored.is_some() && parsed.is_none());
        if unreadable {
            tracing::info!(
                "[auto-approve] the store would not open: every request is asked about until a change is confirmed"
            );
        }
        let extra = stored
            .as_ref()
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .filter(|(k, _)| !["version", "rules", "seeded", "list_version"].contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let seeded = unreadable || stored.as_ref().and_then(|s| s.get("seeded")) == Some(&json!(true));
        let fw = Arc::new(Self {
            app: app.clone(),
            path,
            aad,
            state: RwLock::new(State {
                rules: parsed.unwrap_or_default(),
                list_version: stored
                    .as_ref()
                    .and_then(|s| s.get("list_version"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                seeded,
                unreadable,
                extra: if unreadable { Map::new() } else { extra },
            }),
            app_names: RwLock::new(BTreeMap::new()),
            codes: Codes::for_module(app, MODULE, SCOPE),
            serial: tokio::sync::Mutex::new(()),
        });
        // A standalone firewall has no rules to take from a console: it starts with none.
        if app.config.mode.standalone() && !fw.read().seeded {
            {
                let mut st = fw.write();
                st.seeded = true;
                st.bump();
            }
            fw.save();
            tracing::info!("[auto-approve] started with no rules");
        }
        fw
    }

    pub fn from_env(app: &Arc<App>) -> Arc<Self> {
        Self::new(
            app,
            std::env::var("AUTO_APPROVE_PATH")
                .unwrap_or_else(|_| DEFAULT_PATH.into())
                .into(),
        )
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    #[allow(dead_code)] // the tests'; the console reads the summary
    pub fn rules(&self) -> Vec<AutoRule> {
        self.read().rules.clone()
    }

    /// Checking here: the store was seeded (a console that sends the rules, or a standalone one).
    pub fn active(&self) -> bool {
        self.read().seeded
    }

    /// For the beat: enabled rules, and how many of them ask.
    /// The list's version (see `State::list_version`), for the beat.
    pub fn list_version(&self) -> u64 {
        self.read().list_version
    }

    pub fn counts(&self) -> (usize, usize) {
        let st = self.read();
        let on: Vec<_> = st.rules.iter().filter(|r| r.enabled).collect();
        (on.len(), on.iter().filter(|r| r.effect() == Some(Effect::Ask)).count())
    }

    fn save(&self) {
        let st = self.read();
        let mut v = Map::new();
        v.insert("version".into(), json!(1));
        v.insert("rules".into(), serde_json::to_value(&st.rules).unwrap_or(json!([])));
        v.insert("seeded".into(), json!(st.seeded));
        v.insert("list_version".into(), json!(st.list_version));
        v.extend(st.extra.clone());
        if let Err(e) =
            cc_crypto::enc_file::save_store(STORE, &self.path, &Value::Object(v), &self.app.box_key, &self.aad)
        {
            tracing::error!("[auto-approve] could not save: {}", e.0);
        }
    }

    /// What a sync read: the reply's `auto_approve`. Its names are kept for titles; a store never
    /// seeded takes its seed (no seed: none), once. While a change holds the lock the seed is taken as
    /// soon as it is released, never skipped: the console already counts it as taken.
    pub fn synced(self: &Arc<Self>, sent: Option<&Value>) {
        let Some(v) = sent.filter(|v| !v.is_null()) else { return };
        let a: AutoApprove = match serde_json::from_value(v.clone()) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("[auto-approve] the sync's rules do not read: {e}");
                return;
            }
        };
        *self.app_names.write().unwrap_or_else(|e| e.into_inner()) = a.app_names;
        if self.read().seeded {
            return;
        }
        let seed = a.seed.unwrap_or_default();
        match self.serial.try_lock() {
            Ok(_one) => self.take_seed(seed),
            Err(_) => {
                tracing::info!("[auto-approve] a change is in progress: the console's rules are taken when it ends");
                let me = self.clone();
                tokio::spawn(async move {
                    let _one = me.serial.lock().await;
                    me.take_seed(seed);
                });
            }
        }
    }

    /// The seed, once: every rule the console had (checked), past the cap for new changes too. Under
    /// the rule-change lock.
    fn take_seed(&self, seed: Vec<AutoRule>) {
        let mut rules = Vec::new();
        for r in seed {
            let r = match serde_json::to_value(&r)
                .map_err(|e| e.to_string())
                .and_then(|v| parse_rule(&v))
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("[auto-approve] a rule from the console was left out: {e}");
                    continue;
                }
            };
            if !rules.iter().any(|x: &AutoRule| x.id == r.id) {
                rules.push(r);
            }
        }
        {
            let mut st = self.write();
            if st.seeded {
                return;
            }
            st.rules = rules;
            st.seeded = true;
            st.bump();
        }
        self.save();
        tracing::info!("[auto-approve] took {} rules from the console", self.read().rules.len());
    }

    /// The decision for a raise (its `kind` and the title the console gives it), matched against
    /// `vm_id`. None when the rules are not checked here or the raise has no title. A store that will
    /// not open asks about everything.
    pub fn decide(&self, raise: &Value, vm_id: Option<&str>) -> Option<(Decision, String)> {
        let names = self.app_names.read().unwrap_or_else(|e| e.into_inner()).clone();
        let title = auto_approve::request_title(raise, &names)?;
        let st = self.read();
        if !st.seeded {
            return None;
        }
        let kind = raise.get("kind").and_then(Value::as_str).unwrap_or("access");
        let d = if st.unreadable {
            Decision {
                effect: Effect::Ask,
                rule: None,
            }
        } else {
            auto_approve::evaluate(&st.rules, kind, &title, vm_id)
        };
        Some((d, title))
    }

    fn summary(&self) -> Map<String, Value> {
        let st = self.read();
        let mut m = Map::new();
        m.insert("rules".into(), serde_json::to_value(&st.rules).unwrap_or(json!([])));
        m.insert("version".into(), json!(st.list_version));
        if st.unreadable {
            m.insert("unreadable".into(), json!(true));
        }
        m
    }

    pub async fn handle(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _one = self.serial.lock().await;
        self.command(action, &payload).await.unwrap_or_else(|()| {
            outcome(
                false,
                "failed",
                Some("The Auto approve rules change could not be applied. Check the input, then retry.".into()),
                None,
            )
        })
    }

    async fn command(&self, action: &str, payload: &Map<String, Value>) -> Result<CommandOutcome, ()> {
        if action == "read" {
            return Ok(outcome(true, "read", None, Some(self.summary())));
        }
        let change_id = payload
            .get("changeId")
            .and_then(Value::as_str)
            .filter(|s| (1..=100).contains(&s.encode_utf16().count()))
            .ok_or(())?
            .to_string();
        if action == "cancel" {
            self.codes.cancel(Some(&change_id));
            return Ok(outcome(
                true,
                "cancelled",
                None,
                Some(as_map(json!({"changeId": change_id}))),
            ));
        }
        // Until the console's rules came, a change here would be lost under them.
        if !self.read().seeded {
            return Ok(outcome(false, "failed", Some(NOT_SEEDED.into()), None));
        }
        if action == "confirm" {
            let code = payload
                .get("code")
                .and_then(Value::as_str)
                .filter(|c| c.encode_utf16().count() <= 20)
                .ok_or(())?;
            let proposal = match self.codes.verify(&change_id, code) {
                Verified::Ok { proposal, .. } => proposal,
                Verified::Invalid { attempts_left } => {
                    return Ok(outcome(
                        false,
                        "invalid",
                        None,
                        Some(as_map(json!({"attemptsLeft": attempts_left}))),
                    ));
                }
                Verified::Expired => return Ok(outcome(false, "expired", None, Some(Map::new()))),
            };
            let change = parse_change(proposal.get("change").ok_or(())?).map_err(|_| ())?;
            let basis = {
                let st = self.read();
                basis_of(&st.rules, st.unreadable)
            };
            if proposal.get("basis").and_then(Value::as_str) != Some(basis.as_str()) {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("Your Auto approve rules changed while the code was on its way, so this change was not made. Save it again to get a new code.".into()),
                    None,
                ));
            }
            return self.apply(&change, true, false);
        }
        let raw = payload.get("change").ok_or(())?;
        let change = parse_change(raw).map_err(|_| ())?;
        let (unreadable, rules) = {
            let st = self.read();
            (st.unreadable, st.rules.clone())
        };
        // Refuse now what could not be applied later.
        apply_change(&rules, &change).map_err(|_| ())?;
        if !unreadable && !widens(&rules, &change) {
            return self.apply(&change, false, false);
        }
        let routes = match self.codes.routes() {
            Ok(r) => r,
            Err(m) => return Ok(outcome(false, "failed", Some(m), None)),
        };
        self.codes.forget();
        if routes.is_empty() {
            return self.apply(&change, false, true);
        }
        let (words, typed) = describe(&self.app, &change, if unreadable { &[] } else { &rules });
        let ask = if unreadable {
            format!(
                "Your firewall could not read its Auto approve rules. Confirming starts them again from none and this change: {words}"
            )
        } else {
            words
        };
        let summary = ask.clone();
        let parts = CodeParts {
            ask,
            typed,
            ..Default::default()
        };
        let proposal = json!({"changeId": change_id, "change": raw, "basis": basis_of(&rules, unreadable)});
        Ok(
            match self
                .codes
                .send_parts(
                    &change_id,
                    proposal,
                    "your organization's Auto approve rules",
                    &summary,
                    routes,
                    Some(parts),
                )
                .await
            {
                Ok(sent) => outcome(
                    true,
                    "awaiting_code",
                    None,
                    Some(as_map(json!({"changeId": change_id, "sentVia": sent.sent_via,
                        "expiresAt": sent.expires_at, "attemptsLeft": sent.attempts_left}))),
                ),
                Err(m) => outcome(
                    false,
                    "failed",
                    Some(if m.is_empty() {
                        "No confirmation code could be delivered. Add a recipient on the Firewall page.".into()
                    } else {
                        m
                    }),
                    None,
                ),
            },
        )
    }

    fn apply(&self, change: &Change, confirmed: bool, tofu: bool) -> Result<CommandOutcome, ()> {
        {
            let mut st = self.write();
            // Re-applied to the rules as they are now: another change may have landed in between.
            let base = if st.unreadable { vec![] } else { st.rules.clone() };
            st.rules = apply_change(&base, change).map_err(|_| ())?;
            st.seeded = true;
            st.unreadable = false;
            st.bump();
        }
        self.save();
        let op = match change {
            Change::Put { .. } => "put",
            Change::Delete { .. } => "delete",
            Change::Move { .. } => "move",
        };
        let how = if confirmed {
            " with a code"
        } else if tofu {
            " (nobody can be asked yet)"
        } else {
            " (it lets nothing more through)"
        };
        tracing::info!("[auto-approve] {op} applied{how}");
        let mut data = self.summary();
        if tofu {
            data.insert("tofu".into(), json!(true));
        }
        Ok(outcome(true, "applied", None, Some(data)))
    }

    /// The rules with these added at the end. A rule whose id is already there is refused, never
    /// replaced: the code's message says the template adds rules, so it must not take one away.
    fn with_added(st: &State, rules: &[AutoRule]) -> Result<Vec<AutoRule>, String> {
        let mut next = if st.unreadable { vec![] } else { st.rules.clone() };
        for r in rules {
            if next.iter().any(|x| x.id == r.id) {
                return Err(format!(
                    "Your firewall already has an Auto approve rule with the id {}: a template adds rules and never replaces one. Apply the template again.",
                    r.id
                ));
            }
            next = apply_change(
                &next,
                &Change::Put {
                    rule: r.clone(),
                    at: None,
                },
            )?;
        }
        Ok(next)
    }

    /// Whether [`Self::add_locked`] would take these now (room, valid rules): checked before an
    /// apply hands the agents their tickets, so a template is not half applied.
    pub fn fits(&self, rules: &[AutoRule]) -> Result<(), String> {
        Self::with_added(&self.read(), rules).map(|_| ())
    }

    /// The rule-change lock, for a template's apply: held from the check of its rules, through the
    /// agents' tickets, to [`Self::add_locked`], so no change lands in between.
    pub async fn template_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.serial.lock().await
    }

    /// Rules a template adds, after its apply was confirmed with the firewall's code: each put at
    /// the end; an id that is already there is refused, never replaced. A store that will not open is
    /// resealed. Under the lock the caller holds ([`Self::template_lock`]).
    pub fn add_locked(&self, _held: &tokio::sync::MutexGuard<'_, ()>, rules: &[AutoRule]) -> Result<(), String> {
        if rules.is_empty() {
            return Ok(());
        }
        {
            let mut st = self.write();
            let next = Self::with_added(&st, rules)?;
            st.rules = next;
            st.seeded = true;
            st.unreadable = false;
            st.bump();
        }
        self.save();
        tracing::info!("[auto-approve] {} rules added by a confirmed template", rules.len());
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Requests

/// `decided` or `checked` on a raise, for the control plane. Allow and Block are `decided`; Ask is
/// `checked`, with the rule that asked, if one did.
pub fn mark(body: &mut Map<String, Value>, d: &Decision) {
    let (id, name) = match &d.rule {
        Some(r) => (json!(r.id), json!(r.name)),
        None => (Value::Null, Value::Null),
    };
    match d.effect {
        Effect::Ask => body.insert("checked".into(), json!({ "rule_id": id, "rule_name": name })),
        e => body.insert(
            "decided".into(),
            json!({ "effect": e.as_str(), "rule_id": id, "rule_name": name }),
        ),
    };
}

fn error(status: u16, message: &str) -> (u16, Value) {
    (status, json!({ "error": message }))
}

/// OpenClaw's approvals from the 3940 gate.
#[derive(Clone)]
pub struct AgentApprovals {
    pub store: Arc<AutoApproveFirewall>,
    pub bridge: Arc<PermissionBridge>,
}

impl AgentApprovals {
    /// The body as the agent sent it, for the agent the gate named: what the agent says about
    /// itself or about a decision is dropped.
    fn for_agent(vm_id: &str, body: Value) -> Option<Map<String, Value>> {
        let Value::Object(mut o) = body else { return None };
        for k in ["agent_vm_id", "decided", "checked"] {
            o.remove(k);
        }
        o.insert("agent_vm_id".into(), Value::String(vm_id.to_string()));
        Some(o)
    }

    async fn forward(&self, body: &Value) -> (u16, Value) {
        match self.bridge.post_json(body).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("[auto-approve] the control plane did not answer: {e}");
                error(502, "the control plane did not answer")
            }
        }
    }

    async fn raise_or_settle(&self, vm_id: String, body: Value) -> (u16, Value) {
        let Some(mut o) = Self::for_agent(&vm_id, body) else {
            return error(400, "Invalid body");
        };
        if o.contains_key("resolution") {
            // Settles go with the agent's token (`settle`), never as this firewall.
            return error(403, "a settle needs the agent's own token");
        }
        let pid = o.get("permission_id").and_then(Value::as_str).unwrap_or("").to_string();
        if pid.is_empty() || pid.len() > 128 {
            return error(400, "Invalid body");
        }
        let kind = o.get("kind").and_then(Value::as_str).unwrap_or("").to_string();
        // A meeting ask is a person's only, and the agent raises it to the control plane itself.
        if !AGENT_KINDS.contains(&kind.as_str()) {
            return error(403, &format!("an agent may not raise {kind} requests here"));
        }
        let raise = Value::Object(o.clone());
        let Some((d, title)) = self.store.decide(&raise, Some(&vm_id)) else {
            // No title: the control plane refuses it as it would have.
            return self.forward(&raise).await;
        };
        mark(&mut o, &d);
        let rule = d
            .rule
            .as_ref()
            .map(|r| r.name.as_str())
            .unwrap_or("every other request");
        tracing::info!(
            "[auto-approve] {kind} {pid} for {vm_id}: {} ({}), {} characters",
            d.effect.as_str(),
            js::stringify(&json!(rule)),
            title.chars().count()
        );
        if d.effect == Effect::Ask {
            return self.forward(&Value::Object(o)).await;
        }
        // Answered here; the control plane learns of it afterwards, for its counts and its log.
        self.bridge.report(Value::Object(o));
        (200, json!({ "ok": true, "status": d.effect.status() }))
    }
}

impl AgentPermissions for AgentApprovals {
    fn active(&self) -> bool {
        self.store.active()
    }

    fn raise(&self, vm_id: &str, body: Value) -> BoxFuture<(u16, Value)> {
        let (me, vm_id) = (self.clone(), vm_id.to_string());
        Box::pin(async move { me.raise_or_settle(vm_id, body).await })
    }

    fn status(&self, vm_id: &str, permission_id: &str) -> BoxFuture<(u16, Value)> {
        let q = format!(
            "permission_id={}&agent_vm_id={}",
            encode_uri_component(permission_id),
            encode_uri_component(vm_id)
        );
        let bridge = self.bridge.clone();
        Box::pin(async move {
            match bridge.get_json(&q).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("[auto-approve] the control plane did not answer: {e}");
                    error(502, "the control plane did not answer")
                }
            }
        })
    }

    fn settle(&self, vm_id: &str, body: Value, token: &str) -> BoxFuture<(u16, Value)> {
        let (me, token) = (self.clone(), token.to_string());
        let body = match body {
            // As the agent sends it to its control plane: nothing about another box or a verdict.
            Value::Object(mut o) => {
                for k in ["agent_vm_id", "decided", "checked"] {
                    o.remove(k);
                }
                // Through the gate an agent settles only OpenClaw's own approvals (exec, plugin,
                // system), never a meeting ask or the firewall's: the control plane checks it.
                o.insert("via_gate".into(), Value::Bool(true));
                Some(Value::Object(o))
            }
            _ => None,
        };
        let _ = vm_id;
        Box::pin(async move {
            let Some(body) = body else {
                return error(400, "Invalid body");
            };
            match me.bridge.post_as(&body, &token).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("[auto-approve] the control plane did not answer: {e}");
                    error(502, "the control plane did not answer")
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
