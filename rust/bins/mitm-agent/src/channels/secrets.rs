//! Firewall-held custom secrets (`secrets.ts`, `secrets-schema.ts`, docs/features/secrets.md): a
//! value the organization saves once, kept here and swapped by the proxy for a per-agent
//! placeholder, only toward the hosts and in the places the owner allowed.
//!
//!   secrets.read     {}
//!   secrets.propose  { changeId, action: create|update|replace|delete, name, rules?, vmIds?,
//!                      agents?: [{vmId, hostname}], secret?: {value} }
//!   secrets.confirm  { name, changeId, code }
//!   secrets.cancel   { name, changeId }
//!   secrets.retry    {}
//!
//! A new value, a replaced one, or an update that widens where it may go needs a code; deleting and
//! narrowing do not. With nobody to send a code to, the change is refused (no first-use pass).

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::channels::agent::{AgentCalls, Target};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeRequest, ConsentCodes, Verify};

const CODE_SUBJECT: &str = "your secrets";
const CODE_ATTEMPTS: u32 = 5;
const SECRETS_MAX: usize = 100;
const FAILED: &str = "Secrets change could not be applied. Check the input and firewall, then retry.";
const NOBODY: &str = "No confirmation code could be delivered. Add a recipient on the Firewall page.";

static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]{0,63}$").expect("regex"));
static RESERVED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:PATH|HOME|SHELL|USER|LOGNAME|ENV|BASH_ENV|IFS|NODE_.*|LD_.*|OPENCLAW_.*|CONTROLCLAW_.*|AGENTMAIL_.*)$",
    )
    .expect("regex")
});
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        .expect("regex")
});
static HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]{1,64}$").expect("regex"));
static QUERY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]{1,64}$").expect("regex"));
static TARGET_HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9.-]+$").expect("regex"));
static PRINTABLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\x20-\x7e]*$").expect("regex"));

/// Where the proxy may put the value: a header (with a prefix) or a query parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Location {
    Header { name: String, prefix: String },
    Query { name: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rules {
    pub hosts: Vec<String>,
    pub locations: Vec<Location>,
}

/// `secretSpec`: the name, where it may go, and on which agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub name: String,
    pub rules: Rules,
    pub vm_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    name: String,
    rules: Rules,
    vm_ids: Vec<String>,
    value: String,
    placeholders: IndexMap<String, String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StoredTarget {
    #[serde(rename = "vmId")]
    vm_id: String,
    hostname: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Store {
    version: u32,
    #[serde(default)]
    entries: IndexMap<String, Entry>,
    #[serde(default)]
    agents: IndexMap<String, StoredTarget>,
    #[serde(default)]
    pending: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            entries: IndexMap::new(),
            agents: IndexMap::new(),
            pending: vec![],
            extra: Map::new(),
        }
    }
}

/// `secretInput`, parsed.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    Create { spec: Spec, value: String },
    Update { spec: Spec },
    Replace { name: String, value: String },
    Delete { name: String },
}

impl Input {
    fn name(&self) -> &str {
        match self {
            Input::Create { spec, .. } | Input::Update { spec } => &spec.name,
            Input::Replace { name, .. } | Input::Delete { name } => name,
        }
    }

    fn action(&self) -> &'static str {
        match self {
            Input::Create { .. } => "create",
            Input::Update { .. } => "update",
            Input::Replace { .. } => "replace",
            Input::Delete { .. } => "delete",
        }
    }
}

fn parse_name(v: Option<&Value>) -> Result<String, ()> {
    let n = v.and_then(Value::as_str).ok_or(())?;
    (NAME.is_match(n) && !RESERVED.is_match(n))
        .then(|| n.to_string())
        .ok_or(())
}

fn parse_value(v: Option<&Value>) -> Result<String, ()> {
    let s = v.and_then(Value::as_str).ok_or(())?;
    let len = s.encode_utf16().count();
    ((1..=8192).contains(&len) && PRINTABLE.is_match(s))
        .then(|| s.to_string())
        .ok_or(())
}

fn parse_location(v: &Value) -> Result<Location, ()> {
    match v.get("kind").and_then(Value::as_str) {
        Some("header") => {
            let name = v
                .get("name")
                .and_then(Value::as_str)
                .filter(|n| HEADER.is_match(n))
                .ok_or(())?
                .to_lowercase();
            if [
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
                "trailer",
                "upgrade",
            ]
            .contains(&name.as_str())
            {
                return Err(());
            }
            let prefix = match v.get("prefix") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(p)) if p.encode_utf16().count() <= 100 && PRINTABLE.is_match(p) => p.clone(),
                _ => return Err(()),
            };
            Ok(Location::Header { name, prefix })
        }
        Some("query") => {
            let name = v
                .get("name")
                .and_then(Value::as_str)
                .filter(|n| QUERY.is_match(n))
                .ok_or(())?;
            Ok(Location::Query { name: name.into() })
        }
        _ => Err(()),
    }
}

fn parse_spec(p: &Map<String, Value>) -> Result<Spec, ()> {
    let name = parse_name(p.get("name"))?;
    let rules = p.get("rules").and_then(Value::as_object).ok_or(())?;
    let hosts: Vec<String> = rules
        .get("hosts")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(|h| {
            let h = h
                .as_str()
                .filter(|h| h.encode_utf16().count() <= 253)
                .ok_or(())?
                .to_lowercase();
            HOST.is_match(&h).then_some(h).ok_or(())
        })
        .collect::<Result<_, _>>()?;
    let locations: Vec<Location> = rules
        .get("locations")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(parse_location)
        .collect::<Result<_, _>>()?;
    if hosts.is_empty() || hosts.len() > 30 || locations.is_empty() || locations.len() > 20 {
        return Err(());
    }
    let vm_ids: Vec<String> = p
        .get("vmIds")
        .and_then(Value::as_array)
        .ok_or(())?
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|v| !v.is_empty() && v.encode_utf16().count() <= 100)
                .map(str::to_string)
                .ok_or(())
        })
        .collect::<Result<_, _>>()?;
    if vm_ids.len() > 100 {
        return Err(());
    }
    Ok(Spec {
        name,
        rules: Rules { hosts, locations },
        vm_ids,
    })
}

/// `secretInput.parse`, with the value from the command's secret object.
pub fn parse_input(p: &Map<String, Value>, value: Option<&Value>) -> Result<Input, ()> {
    match p.get("action").and_then(Value::as_str) {
        Some("create") => Ok(Input::Create {
            spec: parse_spec(p)?,
            value: parse_value(value)?,
        }),
        Some("update") => Ok(Input::Update { spec: parse_spec(p)? }),
        Some("replace") => Ok(Input::Replace {
            name: parse_name(p.get("name"))?,
            value: parse_value(value)?,
        }),
        Some("delete") => Ok(Input::Delete {
            name: parse_name(p.get("name"))?,
        }),
        _ => Err(()),
    }
}

/// `hostWithin`: the same host, or one under the old wildcard.
pub fn host_within(next: &str, previous: &str) -> bool {
    next == previous || (previous.starts_with("*.") && next.ends_with(&previous[1..]) && next != &previous[2..])
}

/// `widens`: a new agent, a host outside the old ones, or a place it was not allowed before.
pub fn widens(previous: &Spec, next: &Spec) -> bool {
    next.vm_ids.iter().any(|id| !previous.vm_ids.contains(id))
        || next
            .rules
            .hosts
            .iter()
            .any(|h| !previous.rules.hosts.iter().any(|old| host_within(h, old)))
        || next
            .rules
            .locations
            .iter()
            .any(|l| !previous.rules.locations.contains(l))
}

fn parse_targets(v: Option<&Value>) -> Result<Vec<Target>, ()> {
    let Some(v) = v else { return Ok(vec![]) };
    let list = v.as_array().filter(|l| l.len() <= 100).ok_or(())?;
    list.iter()
        .map(|t| {
            let vm = t
                .get("vmId")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty() && v.encode_utf16().count() <= 100)
                .ok_or(())?;
            let host = t
                .get("hostname")
                .and_then(Value::as_str)
                .filter(|h| h.len() <= 253 && TARGET_HOST.is_match(h))
                .ok_or(())?;
            Ok(Target::new(vm, host))
        })
        .collect()
}

fn location_words(l: &Location) -> String {
    match l {
        Location::Header { name, prefix } => format!(
            "header {name} prefix {}",
            serde_json::to_string(prefix).unwrap_or_default()
        ),
        Location::Query { name } => format!("query {name}"),
    }
}

pub struct SecretsOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    pub codes: Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>,
    /// The routes, or why they are not known.
    pub code_routes: Arc<dyn Fn() -> Result<Vec<Value>, &'static str> + Send + Sync>,
    pub on_credentials_changed: Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>,
}

pub struct SecretsFirewall {
    opts: SecretsOptions,
    aad: String,
    /// One command at a time (`enqueue` in the TS).
    state: tokio::sync::Mutex<Store>,
    published: std::sync::RwLock<Store>,
}

fn scope(name: &str) -> String {
    format!("secrets:{name}")
}

fn outcome(ok: bool, status: &str, message: Option<&str>, data: Option<Value>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.into(),
        message: message.map(str::to_string),
        data: data.and_then(|d| d.as_object().cloned()),
    }
}

impl SecretsFirewall {
    pub fn new(opts: SecretsOptions) -> Result<Arc<Self>, String> {
        let aad = format!("{}:{}:secrets", opts.org_id, opts.box_id);
        let log = |l: &str| tracing::info!("{l}");
        let raw = cc_crypto::enc_file::load_store_or_empty("secrets", &opts.store_path, &opts.box_key, &aad, &log);
        let store: Store = match raw {
            None => Store::default(),
            Some(v) => serde_json::from_value(v).map_err(|e| format!("Unsupported secrets store: {e}"))?,
        };
        if store.version != 1 {
            return Err("Unsupported secrets store".into());
        }
        // Remember every loaded value before a replacement or deletion removes it from the store.
        for e in store.entries.values() {
            cc_crypto::enc_file::remember_encrypted_secrets(&json!(e.value), true);
        }
        Ok(Arc::new(Self {
            opts,
            aad,
            published: std::sync::RwLock::new(store.clone()),
            state: tokio::sync::Mutex::new(store),
        }))
    }

    /// Write the store; an error fails the command (the TS's save throws inside the command).
    fn save(&self, st: &Store) -> Result<(), ()> {
        let v = serde_json::to_value(st).map_err(|_| ())?;
        cc_crypto::enc_file::save_store("secrets", &self.opts.store_path, &v, &self.opts.box_key, &self.aad).map_err(
            |e| {
                tracing::error!("[secrets] could not save the store: {}", e.0);
            },
        )?;
        *self.published.write().unwrap_or_else(|e| e.into_inner()) = st.clone();
        Ok(())
    }

    fn summary_of(st: &Store) -> Value {
        json!({"secrets": st.entries.values().map(|e| json!({
            "name": e.name,
            "rules": e.rules,
            "vmIds": e.vm_ids,
            "pendingVmIds": e.vm_ids.iter().filter(|id| st.pending.contains(id)).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()})
    }

    #[cfg(test)]
    pub fn summary(&self) -> Value {
        Self::summary_of(&self.published.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// The proxy's entries: one per agent a secret is on, with its own placeholder.
    pub fn credentials(&self) -> Vec<Value> {
        let st = self.published.read().unwrap_or_else(|e| e.into_inner());
        st.entries
            .values()
            .flat_map(|e| {
                e.vm_ids.iter().map(move |vm| {
                    let mut c = json!({
                        "secret_name": e.name,
                        "vm_id": vm,
                        "secret": e.value,
                        "allowed_hosts": e.rules.hosts,
                        "secret_locations": e.rules.locations,
                    });
                    if let Some(ph) = e.placeholders.get(vm) {
                        c["placeholder"] = json!(ph);
                    }
                    c
                })
            })
            .collect()
    }

    /// Retry the agents still owed a push (a timer, every 10 s).
    pub async fn reconcile(&self) {
        let mut st = self.state.lock().await;
        if !st.pending.is_empty() {
            (self.opts.on_credentials_changed)().await;
            self.push_pending(&mut st).await;
        }
    }

    /// Persist the desired state before delivery; offline agents are retried, removals included.
    async fn push_pending(&self, st: &mut Store) {
        for vm in st.pending.clone() {
            let Some(t) = st.agents.get(&vm).cloned() else { continue };
            let entries: Vec<Value> = st
                .entries
                .values()
                .filter(|e| e.vm_ids.contains(&vm))
                .map(|e| match e.placeholders.get(&vm) {
                    Some(ph) => json!({"name": e.name, "placeholder": ph}),
                    None => json!({"name": e.name}),
                })
                .collect();
            // Remote errors are not echoed: only metadata is observable.
            if self
                .opts
                .agent
                .post(
                    &Target::new(&t.vm_id, &t.hostname),
                    "/secrets/apply",
                    json!({"entries": entries}),
                    None,
                )
                .await
                .is_ok()
            {
                st.pending.retain(|id| id != &vm);
                // As the TS: a failed save here neither stops the other pushes nor fails the command.
                let _ = self.save(st);
            }
        }
    }

    pub async fn command(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        // These values live under an arbitrary name: captured before anything is queued.
        if let Some(v) = payload.get("secret").and_then(|s| s.get("value")) {
            cc_crypto::enc_file::remember_encrypted_secrets(v, true);
        }
        let mut st = self.state.lock().await;
        self.run(&mut st, action, payload)
            .await
            .unwrap_or_else(|()| outcome(false, "failed", Some(FAILED), None))
    }

    async fn run(&self, st: &mut Store, action: &str, payload: Map<String, Value>) -> Result<CommandOutcome, ()> {
        if action == "read" {
            return Ok(outcome(true, "read", None, Some(Self::summary_of(st))));
        }
        if action == "retry" {
            (self.opts.on_credentials_changed)().await;
            self.push_pending(st).await;
            return Ok(outcome(true, "applied", None, Some(Self::summary_of(st))));
        }
        let name = payload.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        let change_id = payload
            .get("changeId")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty() && c.encode_utf16().count() <= 100)
            .ok_or(())?
            .to_string();
        if action == "cancel" {
            if let Some(c) = (self.opts.codes)() {
                c.cancel(&scope(&name), Some(&change_id));
            }
            return Ok(outcome(true, "cancelled", None, None));
        }
        if action == "confirm" {
            let code = payload
                .get("code")
                .and_then(Value::as_str)
                .filter(|c| c.encode_utf16().count() <= 20)
                .ok_or(())?;
            let verdict = (self.opts.codes)().map_or(Verify::Unknown, |c| c.verify(&scope(&name), &change_id, code));
            return match verdict {
                Verify::Ok(p) => self.apply(st, &p).await,
                Verify::Wrong { tries_left } => Ok(outcome(
                    false,
                    "invalid",
                    None,
                    Some(json!({"attemptsLeft": tries_left})),
                )),
                Verify::Expired | Verify::Unknown => Ok(outcome(false, "expired", None, Some(json!({})))),
            };
        }
        // propose. Values arrive in the encrypted command's secret object.
        let value = payload.get("secret").and_then(|s| s.get("value"));
        let input = parse_input(&payload, value)?;
        let previous = st.entries.get(input.name()).cloned();
        if matches!(input, Input::Create { .. }) == previous.is_some() {
            let m = if previous.is_some() {
                "That name already exists."
            } else {
                "Secret not found."
            };
            return Ok(outcome(false, "failed", Some(m), None));
        }
        if matches!(input, Input::Create { .. }) && st.entries.len() >= SECRETS_MAX {
            return Err(());
        }
        let agents = parse_targets(payload.get("agents"))?;
        if let Input::Create { spec, .. } | Input::Update { spec } = &input
            && spec.vm_ids.iter().any(|id| !agents.iter().any(|a| &a.vm_id == id))
        {
            return Err(());
        }
        // The proposal as the consent module keeps it: only what apply reads, re-parsed on confirm.
        let mut proposal = Map::new();
        for k in ["changeId", "action", "name", "rules", "vmIds", "agents"] {
            if let Some(v) = payload.get(k) {
                proposal.insert(k.into(), v.clone());
            }
        }
        if let Some(v) = value {
            proposal.insert("secret".into(), json!({"value": v}));
        }
        let proposal = Value::Object(proposal);
        let codes = (self.opts.codes)();
        if let Some(c) = &codes {
            c.forget(&scope(input.name()));
        }
        let prev_spec = previous.as_ref().map(|p| Spec {
            name: p.name.clone(),
            rules: p.rules.clone(),
            vm_ids: p.vm_ids.clone(),
        });
        let needs_code = match &input {
            Input::Create { .. } | Input::Replace { .. } => true,
            Input::Update { spec } => prev_spec.as_ref().is_some_and(|p| widens(p, spec)),
            Input::Delete { .. } => false,
        };
        if !needs_code {
            return self.apply(st, &proposal).await;
        }
        let spec = match &input {
            Input::Create { spec, .. } | Input::Update { spec } => spec.clone(),
            _ => prev_spec.clone().ok_or(())?,
        };
        let summary = format!(
            "{} {}; hosts: {}; locations: {}; agents: {}.",
            if input.action() == "replace" {
                "Replace value for"
            } else {
                "Allow"
            },
            input.name(),
            spec.rules.hosts.join(", "),
            spec.rules
                .locations
                .iter()
                .map(location_words)
                .collect::<Vec<_>>()
                .join(", "),
            if spec.vm_ids.is_empty() {
                "none".to_string()
            } else {
                spec.vm_ids.join(", ")
            }
        );
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
                scope: scope(input.name()),
                change_id: change_id.clone(),
                proposal,
                agent_name: CODE_SUBJECT.into(),
                summary,
                routes,
            })
            .await;
        match sent.sent_via {
            Some(via) => Ok(outcome(
                true,
                "awaiting_code",
                None,
                Some(json!({
                    "sentVia": via,
                    "expiresAt": cc_crypto::store_health::iso_from_millis(sent.expires_at_ms),
                    "attemptsLeft": CODE_ATTEMPTS,
                    "name": input.name(),
                })),
            )),
            None => Ok(outcome(false, "failed", Some(NOBODY), None)),
        }
    }

    async fn apply(&self, live: &mut Store, proposal: &Value) -> Result<CommandOutcome, ()> {
        // Changed on a copy: a store that could not be saved keeps what it had.
        let mut next = live.clone();
        let st = &mut next;
        let p = proposal.as_object().ok_or(())?;
        let input = parse_input(p, p.get("secret").and_then(|s| s.get("value")))?;
        let agents = parse_targets(p.get("agents"))?;
        let old = st.entries.get(input.name()).cloned();
        let mut affected: Vec<String> = old.as_ref().map(|o| o.vm_ids.clone()).unwrap_or_default();
        match &input {
            Input::Delete { name } => {
                st.entries.shift_remove(name);
            }
            Input::Replace { name, value } => {
                let e = st.entries.get_mut(name).ok_or(())?;
                e.value = value.clone();
            }
            Input::Create { spec, .. } | Input::Update { spec } => {
                let mut placeholders = IndexMap::new();
                for id in &spec.vm_ids {
                    if !affected.contains(id) {
                        affected.push(id.clone());
                    }
                    let ph = old
                        .as_ref()
                        .and_then(|o| o.placeholders.get(id).cloned())
                        .unwrap_or_else(|| format!("CC-SEC-{}", hex::encode(rand::random::<[u8; 24]>())));
                    placeholders.insert(id.clone(), ph);
                }
                let value = match &input {
                    Input::Create { value, .. } => value.clone(),
                    _ => old.as_ref().ok_or(())?.value.clone(),
                };
                st.entries.insert(
                    spec.name.clone(),
                    Entry {
                        name: spec.name.clone(),
                        rules: spec.rules.clone(),
                        vm_ids: spec.vm_ids.clone(),
                        value,
                        placeholders,
                        extra: Map::new(),
                    },
                );
            }
        }
        for a in agents {
            st.agents.insert(
                a.vm_id.clone(),
                StoredTarget {
                    vm_id: a.vm_id,
                    hostname: a.hostname,
                    extra: Map::new(),
                },
            );
        }
        for id in affected {
            if !st.pending.contains(&id) {
                st.pending.push(id);
            }
        }
        self.save(st)?;
        *live = next;
        let st = live;
        // Revoke proxy access before removing a placeholder on an offline agent.
        (self.opts.on_credentials_changed)().await;
        self.push_pending(st).await;
        let mut data = Self::summary_of(st);
        data["pendingVmIds"] = json!(st.pending);
        Ok(outcome(true, "applied", None, Some(data)))
    }
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod tests;
