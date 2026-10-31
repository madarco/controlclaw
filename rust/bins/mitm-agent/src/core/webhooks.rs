//! The webhook registrations (`webhook-store.ts`, `webhooks.ts`): the half that decides whether a
//! delivery is genuine and where it goes, sealed under the box key and written only by a confirmed
//! change (`webhook.propose` / `webhook.confirm`). The console's sync may disable, rename, set
//! limits and revoke; it never creates a registration or moves a target or a check.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget};
use super::consent::iso;
use super::ingress::{
    INGRESS_DEFAULT_BODY_BYTES, INGRESS_DEFAULT_PER_MINUTE, INGRESS_MAX_BODY_BYTES, INGRESS_MAX_PER_MINUTE,
    Registration, Target, VerifyRule, js_number, num, target_port_allowed,
};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRouteSource, CodeSent, ModuleCodes};

/// This module's consent codes (`code_service.module(MODULE)`).
pub const MODULE: &str = "webhooks";
/// One scope for every hook, as the TS: a new proposal replaces the one waiting.
const SCOPE: &str = "webhooks";
static HOOK_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^hk_[0-9a-f]{32}$").expect("re"));
static TOPIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^projects/[a-z0-9-]{4,30}/topics/[A-Za-z0-9._~%+-]{3,255}$").expect("re"));

/// The Gmail push on the firewall (W4's `GmailPush`): start a watch, stop one.
pub trait GmailHooks: Send + Sync {
    fn configure(&self, hook_id: &str, target: &Target, topic: Option<&str>);
    fn stop(&self, hook_id: &str);
}

/// One stored registration, as `StoredWebhook` (unknown fields kept).
#[derive(Debug, Clone, PartialEq)]
struct Stored {
    id: String,
    name: String,
    target: Target,
    verify: Vec<VerifyRule>,
    max_body_bytes: f64,
    per_minute: f64,
    enabled: bool,
    gmail_topic: Option<String>,
    created_at: String,
    updated_at: String,
    extra: Map<String, Value>,
}

const KNOWN: &[&str] = &[
    "id",
    "name",
    "target",
    "verify",
    "maxBodyBytes",
    "perMinute",
    "enabled",
    "gmailTopic",
    "createdAt",
    "updatedAt",
];

fn s(v: &Map<String, Value>, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

impl Stored {
    fn parse(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let t = o.get("target").and_then(Value::as_object)?;
        Some(Self {
            id: s(o, "id"),
            name: s(o, "name"),
            target: Target {
                vm_id: s(t, "vmId"),
                hostname: s(t, "hostname"),
                port: js_number(t.get("port")),
                path: s(t, "path"),
            },
            verify: o
                .get("verify")
                .and_then(Value::as_array)
                .map(|l| l.iter().filter_map(rule_from_store).collect())
                .unwrap_or_default(),
            max_body_bytes: js_number(o.get("maxBodyBytes")),
            per_minute: js_number(o.get("perMinute")),
            enabled: o.get("enabled") != Some(&Value::Bool(false)),
            gmail_topic: o.get("gmailTopic").and_then(Value::as_str).map(str::to_string),
            created_at: s(o, "createdAt"),
            updated_at: s(o, "updatedAt"),
            extra: o
                .iter()
                .filter(|(k, _)| !KNOWN.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("name".into(), json!(self.name));
        m.insert("target".into(), target_json(&self.target));
        m.insert(
            "verify".into(),
            Value::Array(self.verify.iter().map(VerifyRule::to_json).collect()),
        );
        m.insert("maxBodyBytes".into(), num(self.max_body_bytes));
        m.insert("perMinute".into(), num(self.per_minute));
        m.insert("enabled".into(), json!(self.enabled));
        m.insert("gmailTopic".into(), json!(self.gmail_topic));
        m.insert("createdAt".into(), json!(self.created_at));
        m.insert("updatedAt".into(), json!(self.updated_at));
        m.extend(self.extra.clone());
        Value::Object(m)
    }

    fn is_gmail(&self) -> bool {
        self.gmail_topic.as_deref().is_some_and(|t| !t.is_empty()) && self.google_oidc().is_some()
    }

    fn google_oidc(&self) -> Option<(&str, Option<&str>)> {
        self.verify.iter().find_map(|v| match v {
            VerifyRule::Oidc {
                issuer,
                audience,
                subject_email,
            } if issuer.contains("accounts.google.com") => Some((audience.as_str(), subject_email.as_deref())),
            _ => None,
        })
    }
}

fn target_json(t: &Target) -> Value {
    json!({"vmId": t.vm_id, "hostname": t.hostname, "port": num(t.port), "path": t.path})
}

/// A rule as the store keeps it: what `parseVerifyRules` wrote, and the phone's own fields.
fn rule_from_store(v: &Value) -> Option<VerifyRule> {
    let mut r = VerifyRule::parse_list(Some(&Value::Array(vec![v.clone()])), false).pop()?;
    if let VerifyRule::Hmac(h) = &mut r
        && let Some(o) = v.as_object()
    {
        h.url_form = o.get("input").and_then(Value::as_str) == Some("url-form");
        h.public_url = o.get("publicUrl").and_then(Value::as_str).map(str::to_string);
        h.resign_secret = o.get("resignSecret").and_then(Value::as_str).map(str::to_string);
    }
    Some(r)
}

/// The store (`WebhookStore`): `{version: 1, hooks, pending}`, insertion order kept.
#[derive(Debug, Clone, Default)]
struct Store {
    hooks: Vec<Stored>,
    /// Ids the console lists that this firewall cannot serve: id to display name.
    pending: Vec<(String, String)>,
    extra: Map<String, Value>,
}

impl Store {
    fn parse(v: Option<Value>) -> Self {
        let Some(Value::Object(o)) = v else {
            return Self::default();
        };
        if o.get("version").and_then(Value::as_f64) != Some(1.0) {
            return Self::default();
        }
        let Some(hooks) = o.get("hooks").and_then(Value::as_object) else {
            return Self::default();
        };
        Self {
            hooks: hooks.values().filter_map(Stored::parse).collect(),
            pending: o
                .get("pending")
                .and_then(Value::as_object)
                .map(|p| {
                    p.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            extra: o
                .iter()
                .filter(|(k, _)| !["version", "hooks", "pending"].contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("version".into(), json!(1));
        m.insert(
            "hooks".into(),
            Value::Object(self.hooks.iter().map(|h| (h.id.clone(), h.to_json())).collect()),
        );
        m.insert(
            "pending".into(),
            Value::Object(self.pending.iter().map(|(k, v)| (k.clone(), json!(v))).collect()),
        );
        m.extend(self.extra.clone());
        Value::Object(m)
    }

    fn hook(&self, id: &str) -> Option<&Stored> {
        self.hooks.iter().find(|h| h.id == id)
    }

    fn hook_mut(&mut self, id: &str) -> Option<&mut Stored> {
        self.hooks.iter_mut().find(|h| h.id == id)
    }
}

/// What the sync may carry for one id (`WebhookSyncEntry`).
#[derive(Debug, Clone, Default)]
struct SyncEntry {
    id: String,
    name: Option<String>,
    enabled: Option<bool>,
    max_body_bytes: Option<f64>,
    per_minute: Option<f64>,
}

/// `applySync`: unknown ids are remembered as pending, never created; a target or a check is never
/// read off the sync; an id missing from the sync is dropped.
fn apply_sync(store: &mut Store, entries: &[SyncEntry], now: u64) -> (Vec<String>, Vec<String>, bool) {
    let listed: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
    let (mut unknown, mut dropped, mut changed) = (Vec::new(), Vec::new(), false);
    for e in entries {
        let Some(held) = store.hook_mut(&e.id) else {
            unknown.push(e.id.clone());
            let label = e.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| e.id.clone());
            match store.pending.iter_mut().find(|(k, _)| *k == e.id) {
                Some((_, v)) if *v == label => {}
                Some((_, v)) => {
                    *v = label;
                    changed = true;
                }
                None => {
                    store.pending.push((e.id.clone(), label));
                    changed = true;
                }
            }
            continue;
        };
        let before = held.to_json();
        if let Some(n) = e.name.as_ref().filter(|n| !n.is_empty()) {
            held.name = n.clone();
        }
        if let Some(b) = e.enabled {
            held.enabled = b;
        }
        if let Some(n) = e.max_body_bytes.filter(|n| n.is_finite()) {
            held.max_body_bytes = n;
        }
        if let Some(n) = e.per_minute.filter(|n| n.is_finite()) {
            held.per_minute = n;
        }
        if held.to_json() != before {
            held.updated_at = iso(now);
            changed = true;
        }
        store.pending.retain(|(k, _)| *k != e.id);
    }
    let before = store.hooks.len();
    store.hooks.retain(|h| {
        let keep = listed.contains(&h.id.as_str());
        if !keep {
            dropped.push(h.id.clone());
        }
        keep
    });
    changed |= store.hooks.len() != before;
    let before = store.pending.len();
    store.pending.retain(|(k, _)| listed.contains(&k.as_str()));
    changed |= store.pending.len() != before;
    (unknown, dropped, changed)
}

#[derive(Debug, Clone, PartialEq)]
enum Kind {
    Register,
    Retarget,
    Reverify,
    Forget,
}

/// `WebhookProposal`.
#[derive(Debug, Clone, PartialEq)]
struct Proposal {
    change_id: String,
    kind: Kind,
    hook_id: String,
    name: String,
    target: Option<Target>,
    verify: Option<Vec<VerifyRule>>,
    max_body_bytes: f64,
    per_minute: f64,
    gmail_topic: Option<String>,
}

impl Proposal {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id,
            "kind": match self.kind { Kind::Register => "register", Kind::Retarget => "retarget", Kind::Reverify => "reverify", Kind::Forget => "forget" },
            "hookId": self.hook_id,
            "name": self.name,
            "target": self.target.as_ref().map(target_json),
            "verify": self.verify.as_ref().map(|v| v.iter().map(VerifyRule::to_json).collect::<Vec<_>>()),
            "maxBodyBytes": num(self.max_body_bytes),
            "perMinute": num(self.per_minute),
            "gmailTopic": self.gmail_topic,
        })
    }

    fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let kind = match o.get("kind")?.as_str()? {
            "register" => Kind::Register,
            "retarget" => Kind::Retarget,
            "reverify" => Kind::Reverify,
            "forget" => Kind::Forget,
            _ => return None,
        };
        Some(Self {
            change_id: s(o, "changeId"),
            kind,
            hook_id: s(o, "hookId"),
            name: s(o, "name"),
            target: o.get("target").and_then(Value::as_object).map(|t| Target {
                vm_id: s(t, "vmId"),
                hostname: s(t, "hostname"),
                port: js_number(t.get("port")),
                path: s(t, "path"),
            }),
            verify: o
                .get("verify")
                .and_then(Value::as_array)
                .map(|l| l.iter().filter_map(rule_from_store).collect()),
            // A NaN (nothing was given) travels as `null`, and comes back as NaN.
            max_body_bytes: o
                .get("maxBodyBytes")
                .filter(|v| !v.is_null())
                .map(|v| js_number(Some(v)))
                .unwrap_or(f64::NAN),
            per_minute: o
                .get("perMinute")
                .filter(|v| !v.is_null())
                .map(|v| js_number(Some(v)))
                .unwrap_or(f64::NAN),
            gmail_topic: o.get("gmailTopic").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// `summarize`: what a person is asked to confirm, written here.
fn summarize(p: &Proposal) -> String {
    let port = p
        .target
        .as_ref()
        .map(|t| super::activity_sanitize::js_string(Some(&num(t.port))))
        .unwrap_or_else(|| "undefined".into());
    let host = p
        .target
        .as_ref()
        .map(|t| t.hostname.clone())
        .unwrap_or_else(|| "an agent".into());
    match p.kind {
        Kind::Register => format!("Let \"{}\" deliver to port {port} on {host}", p.name),
        Kind::Retarget => format!("Point \"{}\" at port {port} on {host}", p.name),
        Kind::Reverify => format!("Change how \"{}\" checks that a delivery is genuine", p.name),
        Kind::Forget => format!("Remove the webhook \"{}\"", p.name),
    }
}

/// `clamp` in `webhooks.ts`: a fallback for nothing or a non-positive value.
fn clamp_or(v: f64, low: f64, high: f64, fallback: f64) -> f64 {
    if !v.is_finite() || v <= 0.0 {
        return fallback;
    }
    v.max(low).min(high)
}

fn outcome(ok: bool, status: &str, message: Option<String>, data: Option<Value>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.into(),
        message,
        data: data.and_then(|d| d.as_object().cloned()),
    }
}

pub struct Webhooks {
    path: PathBuf,
    box_key: String,
    aad: String,
    store: Mutex<Store>,
    agent: AgentClient,
    consent: Arc<dyn ModuleCodes>,
    routes: Arc<dyn Fn() -> Option<Arc<dyn CodeRouteSource>> + Send + Sync>,
    pub gmail: OnceLock<Arc<dyn GmailHooks>>,
    /// The organization's Google address (W4), for the watch renewal on the agent box.
    pub gmail_account: OnceLock<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
}

impl Webhooks {
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        consent: Arc<dyn ModuleCodes>,
        routes: Arc<dyn Fn() -> Option<Arc<dyn CodeRouteSource>> + Send + Sync>,
    ) -> Self {
        let aad = format!("{org}:{box_id}:webhooks");
        let log = |l: &str| tracing::error!("{l}");
        let store = Store::parse(cc_crypto::enc_file::load_store_or_empty(
            "webhooks", &path, box_key, &aad, &log,
        ));
        Self {
            path,
            box_key: box_key.to_string(),
            aad,
            store: Mutex::new(store),
            agent,
            consent,
            routes,
            gmail: OnceLock::new(),
            gmail_account: OnceLock::new(),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st();
        self.save(&s);
    }

    fn st(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, store: &Store) {
        if let Err(e) =
            cc_crypto::enc_file::save_store("webhooks", &self.path, &store.to_json(), &self.box_key, &self.aad)
        {
            tracing::error!("[webhooks] could not save the store: {e}");
        }
    }

    /// `registrationsFor`: pending ids first (inert: no target, no checks), then the held ones.
    pub fn registrations(&self) -> Vec<Registration> {
        let st = self.st();
        let empty = Target {
            vm_id: String::new(),
            hostname: String::new(),
            port: 0.0,
            path: "/".into(),
        };
        st.pending
            .iter()
            .map(|(id, name)| Registration::plain(id, name, empty.clone(), Vec::new(), 0.0, 0.0, true))
            .chain(st.hooks.iter().map(|h| {
                Registration::plain(
                    &h.id,
                    &h.name,
                    h.target.clone(),
                    h.verify.clone(),
                    h.max_body_bytes,
                    h.per_minute,
                    h.enabled,
                )
            }))
            .collect()
    }

    /// `inventoryFor`: which registrations this firewall can serve.
    pub fn inventory(&self) -> Vec<Value> {
        let st = self.st();
        st.pending
            .iter()
            .map(|(id, _)| json!({"id": id, "ready": false}))
            .chain(
                st.hooks
                    .iter()
                    .map(|h| json!({"id": h.id, "ready": !h.verify.is_empty()})),
            )
            .collect()
    }

    /// `isGmail`.
    pub fn is_gmail(&self, hook_id: &str) -> bool {
        self.st().hook(hook_id).is_some_and(Stored::is_gmail)
    }

    #[allow(dead_code)] // W4's Gmail watch renewal
    /// `gmailHooks`: every enabled Gmail registration with its topic, for the watch renewal (W4).
    pub fn gmail_hooks(&self) -> Vec<(String, Option<String>)> {
        self.st()
            .hooks
            .iter()
            .filter(|h| h.enabled && h.is_gmail())
            .map(|h| (h.id.clone(), h.gmail_topic.clone()))
            .collect()
    }

    /// What the console may see: never a secret.
    fn summary(&self) -> Vec<Value> {
        self.st()
            .hooks
            .iter()
            .map(|h| {
                let checks: Vec<Value> = h
                    .verify
                    .iter()
                    .map(|v| match v {
                        VerifyRule::Hmac(r) => json!({"kind": "hmac", "header": r.header, "algo": if r.sha1 { "sha1" } else { "sha256" }, "replayProtected": r.timestamp_header.is_some()}),
                        VerifyRule::Oidc { issuer, audience, subject_email } => json!({"kind": "oidc", "issuer": issuer, "audience": audience, "subjectEmail": subject_email}),
                    })
                    .collect();
                json!({
                    "id": h.id, "name": h.name, "target": target_json(&h.target), "checks": checks,
                    "ready": !h.verify.is_empty(), "maxBodyBytes": num(h.max_body_bytes), "perMinute": num(h.per_minute),
                    "enabled": h.enabled, "createdAt": h.created_at, "updatedAt": h.updated_at,
                })
            })
            .collect()
    }

    fn parse_proposal(p: &Map<String, Value>) -> Result<Proposal, String> {
        let text = |k: &str| match p.get(k) {
            None | Some(Value::Null) => String::new(),
            v => super::activity_sanitize::js_string(v),
        };
        let change_id = text("changeId");
        let kind = text("kind");
        let hook_id = text("hookId");
        let name: String = String::from_utf16_lossy(&text("name").encode_utf16().take(120).collect::<Vec<_>>());
        if change_id.is_empty() {
            return Err("This change carries no id.".into());
        }
        let kind = match kind.as_str() {
            "register" => Kind::Register,
            "retarget" => Kind::Retarget,
            "reverify" => Kind::Reverify,
            "forget" => Kind::Forget,
            _ => return Err("That is not a change this firewall knows how to make.".into()),
        };
        if !HOOK_ID.is_match(&hook_id) {
            return Err("That is not a webhook id.".into());
        }
        if name.is_empty() && kind != Kind::Forget {
            return Err("A webhook needs a name.".into());
        }
        let mut out = Proposal {
            change_id,
            name: if name.is_empty() { hook_id.clone() } else { name },
            hook_id,
            target: None,
            verify: None,
            max_body_bytes: f64::NAN,
            per_minute: f64::NAN,
            gmail_topic: None,
            kind,
        };
        if matches!(out.kind, Kind::Register | Kind::Retarget) {
            let empty = Map::new();
            let t = p.get("target").and_then(Value::as_object).unwrap_or(&empty);
            let port = js_number(t.get("port"));
            let vm = t.get("vmId").and_then(Value::as_str).filter(|s| !s.is_empty());
            let host = t.get("hostname").and_then(Value::as_str).filter(|s| !s.is_empty());
            let Some(vm) = vm else {
                return Err("A webhook has to name the agent it delivers to.".into());
            };
            let Some(host) = host else {
                return Err("A webhook has to name the agent's hostname.".into());
            };
            if !target_port_allowed(port) {
                let given = super::activity_sanitize::js_string(t.get("port"));
                return Err(format!(
                    "A webhook may only deliver to a port between 8700 and 8799 (got {given})."
                ));
            }
            out.target = Some(Target {
                vm_id: vm.into(),
                hostname: host.into(),
                port,
                path: t
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|p| p.starts_with('/'))
                    .unwrap_or("/")
                    .into(),
            });
        }
        if matches!(out.kind, Kind::Register | Kind::Reverify) {
            let verify = VerifyRule::parse_list(p.get("verify"), true);
            if verify.is_empty() {
                return Err("A webhook needs at least one way to check that a delivery is genuine.".into());
            }
            out.verify = Some(verify);
        }
        if out.kind == Kind::Register {
            out.max_body_bytes = js_number(p.get("maxBodyBytes"));
            out.per_minute = js_number(p.get("perMinute"));
            let topic = p.get("gmailTopic").and_then(Value::as_str).unwrap_or("");
            if !topic.is_empty() && !TOPIC.is_match(topic) {
                return Err("That is not a Pub/Sub topic name.".into());
            }
            out.gmail_topic = (!topic.is_empty()).then(|| topic.to_string());
        }
        Ok(out)
    }

    pub async fn propose(self: Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let p = match Self::parse_proposal(&payload) {
            Ok(p) => p,
            Err(m) => return outcome(false, "refused", Some(m), None),
        };
        {
            let st = self.st();
            if p.kind != Kind::Register && st.hook(&p.hook_id).is_none() {
                return outcome(
                    false,
                    "refused",
                    Some("This firewall does not hold that webhook.".into()),
                    None,
                );
            }
            if p.kind == Kind::Register && st.hook(&p.hook_id).is_some() {
                return outcome(
                    false,
                    "refused",
                    Some("This firewall already holds a webhook with that id.".into()),
                    None,
                );
            }
        }
        let summary = summarize(&p);
        // No channel list (W4's not running, or its store unreadable): nobody can be asked.
        let Some(routes) = (self.routes)().filter(|r| r.ready()) else {
            return outcome(
                false,
                "no_channels",
                Some("This firewall cannot read its channel list, so it cannot ask anyone to confirm this. Nothing was changed.".into()),
                None,
            );
        };
        let routes = routes.routes();
        if routes.is_empty() {
            tracing::info!(
                "[webhooks] no approved sender on any channel; applying \"{summary}\" without a code (first use)"
            );
            if !self.apply(&p) {
                return outcome(
                    false,
                    "gone",
                    Some("That webhook is no longer on this firewall.".into()),
                    None,
                );
            }
            return outcome(
                true,
                "applied",
                Some(format!(
                    "{summary}. Nobody is approved on a channel yet, so this applied without a code."
                )),
                None,
            );
        }
        let sent = self
            .consent
            .send(CodeAsk {
                scope: SCOPE.into(),
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: p.name.clone(),
                summary: summary.clone(),
                routes,
                ..Default::default()
            })
            .await;
        let awaiting = sent.awaiting_code_data();
        match sent {
            CodeSent::Failed { message } => outcome(false, "failed", Some(message), None),
            CodeSent::Sent { .. } => outcome(
                true,
                "code_sent",
                Some(summary),
                Some(Value::Object(awaiting.unwrap_or_default())),
            ),
        }
    }

    pub fn confirm(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let text = |k: &str| match payload.get(k) {
            None | Some(Value::Null) => String::new(),
            v => super::activity_sanitize::js_string(v),
        };
        match self.consent.verify(SCOPE, &text("changeId"), &text("code")) {
            CodeCheck::Expired => outcome(
                false,
                "expired",
                Some("That change is no longer waiting for a code.".into()),
                None,
            ),
            CodeCheck::Wrong { tries_left } => outcome(
                false,
                "invalid_code",
                Some(format!("That code is not right. {tries_left} attempt(s) left.")),
                Some(json!({"attemptsLeft": tries_left})),
            ),
            CodeCheck::Ok { proposal, .. } => {
                let Some(p) = Proposal::from_json(&proposal) else {
                    return outcome(false, "failed", Some("That change could not be read.".into()), None);
                };
                if !self.apply(&p) {
                    return outcome(
                        false,
                        "gone",
                        Some("That webhook was removed while this change was waiting.".into()),
                        None,
                    );
                }
                outcome(true, "applied", Some(summarize(&p)), None)
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change = payload
            .get("changeId")
            .filter(|v| super::sync::js_truthy(v))
            .map(|v| super::activity_sanitize::js_string(Some(v)));
        let dropped = self.consent.cancel(SCOPE, change.as_deref());
        outcome(true, if dropped { "cancelled" } else { "nothing_waiting" }, None, None)
    }

    /// `webhook.forget`: drop a registration now; the sync would drop it too.
    pub fn forget(self: Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let hook_id = match payload.get("hookId") {
            None | Some(Value::Null) => String::new(),
            v => super::activity_sanitize::js_string(v),
        };
        let going = {
            let mut st = self.st();
            let Some(i) = st.hooks.iter().position(|h| h.id == hook_id) else {
                return outcome(true, "already_gone", None, None);
            };
            let going = st.hooks.remove(i);
            st.pending.retain(|(k, _)| *k != hook_id);
            self.save(&st);
            going
        };
        tokio::spawn(async move { self.stop_gmail(&going).await });
        outcome(true, "forgotten", None, None)
    }

    /// `webhook.sync`: the console's half (ids, `enabled`, the name, the limits).
    pub fn sync(&self, payload: &Value) -> CommandOutcome {
        let entries: Vec<SyncEntry> = payload
            .get("hooks")
            .and_then(Value::as_array)
            .map(|l| {
                l.iter()
                    .filter_map(|e| {
                        let o = e.as_object()?;
                        let id = o.get("id").and_then(Value::as_str).filter(|s| !s.is_empty())?;
                        let n = |k: &str| Some(js_number(o.get(k))).filter(|n| n.is_finite());
                        Some(SyncEntry {
                            id: id.into(),
                            name: o.get("name").and_then(Value::as_str).map(str::to_string),
                            enabled: o.get("enabled").and_then(Value::as_bool),
                            max_body_bytes: n("maxBodyBytes"),
                            per_minute: n("perMinute"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut st = self.st();
        let (unknown, dropped, changed) = apply_sync(&mut st, &entries, now_ms());
        if changed {
            self.save(&st);
        }
        if !unknown.is_empty() {
            tracing::info!(
                "[webhooks] the sync listed {} registration(s) this firewall does not hold; ignored",
                unknown.len()
            );
        }
        if !dropped.is_empty() {
            tracing::info!("[webhooks] dropped {} revoked registration(s)", dropped.len());
        }
        outcome(
            true,
            "synced",
            None,
            Some(json!({"unknown": unknown, "dropped": dropped, "held": st.hooks.len()})),
        )
    }

    pub fn read(&self) -> CommandOutcome {
        outcome(true, "read", None, Some(json!({"hooks": self.summary()})))
    }

    fn apply(self: &Arc<Self>, p: &Proposal) -> bool {
        let pushed = {
            let mut st = self.st();
            if p.kind == Kind::Forget {
                let going = st
                    .hooks
                    .iter()
                    .position(|h| h.id == p.hook_id)
                    .map(|i| st.hooks.remove(i));
                self.save(&st);
                drop(st);
                if let Some(g) = going {
                    let me = self.clone();
                    tokio::spawn(async move { me.stop_gmail(&g).await });
                }
                return true;
            }
            let now = iso(now_ms());
            if p.kind != Kind::Register && st.hook(&p.hook_id).is_none() {
                return false;
            }
            match p.kind {
                Kind::Register => {
                    let made = Stored {
                        id: p.hook_id.clone(),
                        name: p.name.clone(),
                        target: p.target.clone().unwrap_or_else(|| Target {
                            vm_id: String::new(),
                            hostname: String::new(),
                            port: 0.0,
                            path: "/".into(),
                        }),
                        verify: p.verify.clone().unwrap_or_default(),
                        max_body_bytes: clamp_or(
                            p.max_body_bytes,
                            1.0,
                            INGRESS_MAX_BODY_BYTES,
                            INGRESS_DEFAULT_BODY_BYTES,
                        ),
                        per_minute: clamp_or(p.per_minute, 1.0, INGRESS_MAX_PER_MINUTE, INGRESS_DEFAULT_PER_MINUTE),
                        enabled: true,
                        gmail_topic: p.gmail_topic.clone(),
                        created_at: now.clone(),
                        updated_at: now,
                        extra: Map::new(),
                    };
                    // `hooks[id] = …`: a second register of one id replaces it, in its place.
                    match st.hooks.iter_mut().find(|h| h.id == made.id) {
                        Some(h) => *h = made,
                        None => st.hooks.push(made),
                    }
                }
                Kind::Retarget => {
                    if let (Some(h), Some(t)) = (st.hook_mut(&p.hook_id), &p.target) {
                        h.target = t.clone();
                        h.updated_at = now;
                    }
                }
                _ => {
                    if let (Some(h), Some(v)) = (st.hook_mut(&p.hook_id), &p.verify) {
                        h.verify = v.clone();
                        h.updated_at = now;
                    }
                }
            }
            // A confirmed registration is no longer merely pending: left there it would shadow
            // the real one (pending is listed first).
            st.pending.retain(|(k, _)| *k != p.hook_id);
            self.save(&st);
            st.hook(&p.hook_id).cloned()
        };
        if let Some(h) = pushed {
            let me = self.clone();
            tokio::spawn(async move { me.push_gmail(&h).await });
        }
        true
    }

    /// `pushGmail`: start the watch, on the firewall (W4's Gmail push) or on the agent box.
    async fn push_gmail(&self, hook: &Stored) {
        let Some((audience, subject)) = hook.google_oidc() else {
            return;
        };
        let target = AgentTarget::new(&hook.target.vm_id, &hook.target.hostname);
        if let Some(g) = self.gmail.get()
            && hook.is_gmail()
        {
            g.configure(&hook.id, &hook.target, hook.gmail_topic.as_deref());
            let _ = self.agent.post(&target, "/hooks/gmail", &json!({"stop": true})).await;
            return;
        }
        let body = json!({
            "audience": audience,
            "path": hook.target.path,
            "port": num(hook.target.port),
            "subjectEmail": subject,
            "account": self.gmail_account.get().and_then(|f| f()),
            "topic": hook.gmail_topic,
        });
        match self.agent.post(&target, "/hooks/gmail", &body).await {
            Ok(_) => tracing::info!("[webhooks] gmail watcher configured on {}", hook.target.hostname),
            Err(e) => tracing::info!(
                "[webhooks] could not configure the gmail watcher on {}: {e}",
                hook.target.hostname
            ),
        }
    }

    async fn stop_gmail(&self, hook: &Stored) {
        if hook.google_oidc().is_none() {
            return;
        }
        if let Some(g) = self.gmail.get() {
            g.stop(&hook.id);
        }
        let target = AgentTarget::new(&hook.target.vm_id, &hook.target.hostname);
        if let Err(e) = self.agent.post(&target, "/hooks/gmail", &json!({"stop": true})).await {
            tracing::info!("[webhooks] could not stop the gmail watcher: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(id: &str) -> Stored {
        Stored {
            id: id.into(),
            name: "Hook".into(),
            target: Target {
                vm_id: "vm_1".into(),
                hostname: "a".into(),
                port: 8788.0,
                path: "/".into(),
            },
            verify: vec![],
            max_body_bytes: 4096.0,
            per_minute: 60.0,
            enabled: true,
            gmail_topic: None,
            created_at: "c".into(),
            updated_at: "u".into(),
            extra: Map::new(),
        }
    }

    #[test]
    fn a_sync_never_creates_never_moves_and_drops_what_it_no_longer_lists() {
        let mut st = Store {
            hooks: vec![held("hk_a"), held("hk_b")],
            ..Default::default()
        };
        let entries = vec![
            SyncEntry {
                id: "hk_a".into(),
                name: Some("Renamed".into()),
                enabled: Some(false),
                ..Default::default()
            },
            SyncEntry {
                id: "hk_new".into(),
                name: Some("New".into()),
                ..Default::default()
            },
        ];
        let (unknown, dropped, changed) = apply_sync(&mut st, &entries, 0);
        assert_eq!(
            (unknown, dropped, changed),
            (vec!["hk_new".to_string()], vec!["hk_b".to_string()], true)
        );
        assert_eq!(st.hooks.len(), 1);
        assert_eq!((st.hooks[0].name.as_str(), st.hooks[0].enabled), ("Renamed", false));
        assert_eq!(st.hooks[0].target.port, 8788.0);
        assert_eq!(st.pending, vec![("hk_new".to_string(), "New".to_string())]);
        let (_, _, changed) = apply_sync(&mut st, &entries, 0);
        assert!(!changed);
    }

    #[test]
    fn proposals_are_checked() {
        let p = |v: Value| Webhooks::parse_proposal(v.as_object().expect("obj"));
        let id = format!("hk_{}", "a".repeat(32));
        assert_eq!(p(json!({})).expect_err("id"), "This change carries no id.");
        assert_eq!(
            p(json!({"changeId": "c", "kind": "register", "hookId": id, "name": "N", "target": {"vmId": "v", "hostname": "h", "port": 3100}, "verify": [{"kind": "hmac", "header": "x", "secret": "s"}]}))
                .expect_err("port"),
            "A webhook may only deliver to a port between 8700 and 8799 (got 3100)."
        );
        assert_eq!(
            p(json!({"changeId": "c", "kind": "register", "hookId": id, "name": "N", "target": {"vmId": "v", "hostname": "h", "port": 8788}, "verify": [{"kind": "hmac", "header": "", "secret": "s"}]}))
                .expect_err("rules"),
            "A webhook needs at least one way to check that a delivery is genuine."
        );
        let ok = p(json!({"changeId": "c", "kind": "register", "hookId": id, "name": "N", "target": {"vmId": "v", "hostname": "h", "port": "8788"}, "verify": [{"kind": "hmac", "header": "x", "secret": "s"}], "gmailTopic": "projects/my-proj/topics/gmail"}))
            .expect("ok");
        assert_eq!(summarize(&ok), "Let \"N\" deliver to port 8788 on h");
        let back = Proposal::from_json(&ok.to_json()).expect("back");
        assert_eq!(
            (back.target, back.verify, back.gmail_topic.clone()),
            (ok.target.clone(), ok.verify.clone(), ok.gmail_topic.clone())
        );
        assert!(back.max_body_bytes.is_nan() && back.per_minute.is_nan());
    }
}
