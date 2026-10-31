//! Web search on the firewall (`search.ts`, `search-store.ts`): the organization's one search
//! provider key, held here; the agent boxes get a placeholder the proxy swaps for it on the
//! provider's own host. A code when someone can be asked; `search.push` re-applies on one agent,
//! `search.forget` drops a deleted one.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget};
use super::consent::iso;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, null_or, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CredentialContributor, CredentialOrder};

const SCOPE: &str = "search:org";

pub type OnChanged = Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>;

/// `parseProposal`, kept as the JSON the TS builds (it rides the consent code).
fn parse(p: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let (Some(change_id), Some(credential_id), Some(provider)) =
        (text(p, "changeId"), text(p, "credentialId"), text(p, "provider"))
    else {
        return Err("malformed search.propose payload".into());
    };
    let kind = p
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| ["add", "replace", "remove"].contains(k));
    let Some(kind) = kind else {
        return Err("malformed search.propose payload".into());
    };
    let empty = Map::new();
    let plugin = p.get("plugin").and_then(Value::as_object).unwrap_or(&empty);
    let swap = p.get("swap").and_then(Value::as_object).unwrap_or(&empty);
    let config: Map<String, Value> = p
        .get("config")
        .and_then(Value::as_object)
        .map(|c| {
            c.iter()
                .filter(|(_, v)| v.is_string())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    let list = |k: &str| p.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let mut out = obj(&[
        ("changeId", json!(change_id)),
        ("kind", json!(kind)),
        ("credentialId", json!(credential_id)),
        ("provider", json!(provider)),
        ("providerName", json!(text(p, "providerName").unwrap_or_else(|| provider.clone()))),
        ("placeholder", null_or(text(p, "placeholder"))),
        ("hint", null_or(text(p, "hint"))),
        (
            "plugin",
            match (text(plugin, "id"), text(plugin, "package")) {
                (Some(i), Some(pk)) => json!({"id": i, "package": pk}),
                _ => Value::Null,
            },
        ),
        ("baseUrl", null_or(text(p, "baseUrl"))),
        ("config", if config.is_empty() { Value::Null } else { Value::Object(config) }),
        (
            "swap",
            match (text(swap, "matchDomain"), swap.get("locations").and_then(Value::as_array)) {
                (Some(d), Some(l)) => json!({"matchDomain": d, "locations": l.iter().map(|x| json!(super::activity_sanitize::js_string(Some(x)))).collect::<Vec<_>>()}),
                _ => Value::Null,
            },
        ),
        ("defaultProvider", null_or(text(p, "defaultProvider"))),
        ("replaces", null_or(text(p, "replaces"))),
        (
            "remove",
            Value::Array(
                list("remove")
                    .iter()
                    .filter_map(|r| r.as_object().and_then(|r| text(r, "id")))
                    .map(|id| json!({"id": id}))
                    .collect(),
            ),
        ),
        (
            "agents",
            Value::Array(
                list("agents")
                    .iter()
                    .filter_map(Value::as_object)
                    .filter_map(|a| {
                        let vm = text(a, "vmId")?;
                        Some(json!({"vmId": vm, "name": text(a, "name").unwrap_or_else(|| vm.clone()), "hostname": text(a, "hostname")}))
                    })
                    .collect(),
            ),
        ),
    ]);
    if let Some(key) = p
        .get("secret")
        .and_then(Value::as_object)
        .and_then(|s| text(s, "apiKey"))
    {
        out.insert("apiKey".into(), json!(key));
    }
    Ok(out)
}

/// `summarize`.
fn summarize(p: &Map<String, Value>) -> String {
    let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
    let name = s("providerName").unwrap_or_default();
    match s("kind").as_deref() {
        Some("add") => format!(
            "Use {name} for web search (key {})",
            s("hint").unwrap_or_else(|| "key".into())
        ),
        Some("replace") => match s("replaces") {
            Some(r) => format!(
                "Switch web search from {r} to {name} (key {})",
                s("hint").unwrap_or_else(|| "new key".into())
            ),
            None => format!(
                "Replace the {name} web search key ({})",
                s("hint").unwrap_or_else(|| "new key".into())
            ),
        },
        _ => format!("Stop using {name} for web search"),
    }
}

pub struct Search {
    path: PathBuf,
    box_key: String,
    aad: String,
    /// `{version: 1, credentialId, credential, agents}`.
    store: Mutex<Map<String, Value>>,
    agent: AgentClient,
    kit: Kit,
    plain_keys: bool,
    on_changed: OnChanged,
    running: tokio::sync::Mutex<()>,
    /// Every placeholder this module has handed the proxy since start, so a fallback write can
    /// take this module's entries out of the last config, an old key's included.
    seen: Mutex<Vec<String>>,
}

fn empty_store() -> Map<String, Value> {
    obj(&[
        ("version", json!(1)),
        ("credentialId", Value::Null),
        ("credential", Value::Null),
        ("agents", json!({})),
    ])
}

impl Search {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: Kit,
        plain_keys: bool,
        on_changed: OnChanged,
    ) -> Self {
        let aad = format!("{org}:{box_id}:search");
        let log = |l: &str| tracing::error!("{l}");
        let store = match cc_crypto::enc_file::load_store_or_empty("search", &path, box_key, &aad, &log) {
            Some(Value::Object(o))
                if o.get("version").and_then(Value::as_f64) == Some(1.0)
                    && o.get("agents").is_some_and(Value::is_object) =>
            {
                o
            }
            _ => empty_store(),
        };
        Self {
            path,
            box_key: box_key.into(),
            aad,
            store: Mutex::new(store),
            agent,
            kit,
            plain_keys,
            on_changed,
            running: tokio::sync::Mutex::new(()),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st();
        self.save(&s).expect("save");
    }

    /// Whether a proxy credential is this module's (current or earlier key).
    pub fn owns(&self, entry: &Value) -> bool {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        entry
            .get("placeholder")
            .and_then(Value::as_str)
            .is_some_and(|p| seen.iter().any(|s| s == p))
    }

    fn st(&self) -> std::sync::MutexGuard<'_, Map<String, Value>> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A store that cannot be written fails the command (the TS throws): a removed key must not
    /// come back after a restart.
    fn save(&self, st: &Map<String, Value>) -> Result<(), String> {
        cc_crypto::enc_file::save_store(
            "search",
            &self.path,
            &Value::Object(st.clone()),
            &self.box_key,
            &self.aad,
        )
        .map_err(|e| format!("The web search settings could not be saved on your firewall: {e}"))
    }

    fn agents(st: &mut Map<String, Value>) -> &mut Map<String, Value> {
        if !st.get("agents").is_some_and(Value::is_object) {
            st.insert("agents".into(), json!({}));
        }
        st.get_mut("agents").and_then(Value::as_object_mut).expect("set above")
    }

    /// `summary`: no key.
    pub fn summary(&self) -> Value {
        let st = self.st();
        let c = st.get("credential").and_then(Value::as_object);
        json!({
            "provider": c.and_then(|c| c.get("provider")).cloned().unwrap_or(Value::Null),
            "credentialId": st.get("credentialId"),
            "hint": c.and_then(|c| c.get("hint")).cloned().unwrap_or(Value::Null),
            "agents": st.get("agents").and_then(Value::as_object).map(Map::len).unwrap_or(0),
        })
    }

    fn remember(st: &mut Map<String, Value>, a: &Value) {
        let Some(vm) = a.get("vmId").and_then(Value::as_str) else {
            return;
        };
        let agents = Self::agents(st);
        let mut entry = agents
            .get(vm)
            .cloned()
            .unwrap_or_else(|| json!({"name": a.get("name"), "hostname": a.get("hostname")}));
        if let Some(n) = a.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
            entry["name"] = json!(n);
        }
        if let Some(h) = a.get("hostname").and_then(Value::as_str).filter(|h| !h.is_empty()) {
            entry["hostname"] = json!(h);
        }
        agents.insert(vm.to_string(), entry);
    }

    /// `applyBody`: the whole desired state of one box.
    fn apply_body(&self, remove: &Value, default_provider: &Value) -> Value {
        let st = self.st();
        let search = st.get("credential").and_then(Value::as_object).map(|c| {
            let mut m = obj(&[
                ("provider", c.get("provider").cloned().unwrap_or(Value::Null)),
                ("plugin", c.get("plugin").cloned().unwrap_or(Value::Null)),
                ("baseUrl", c.get("baseUrl").cloned().unwrap_or(Value::Null)),
            ]);
            if let Some(cfg) = c.get("config").filter(|v| !v.is_null()) {
                m.insert("config".into(), cfg.clone());
            }
            let key = if self.plain_keys {
                c.get("apiKey")
            } else {
                c.get("placeholder")
            };
            m.insert("apiKey".into(), key.cloned().unwrap_or(Value::Null));
            Value::Object(m)
        });
        json!({"search": search, "defaultProvider": default_provider, "remove": remove})
    }

    async fn push_agents(&self, vm_ids: &[String], remove: &Value, default_provider: &Value) -> Vec<Value> {
        let body = self.apply_body(remove, default_provider);
        let mut failed = Vec::new();
        for vm in vm_ids {
            let host = self
                .st()
                .get("agents")
                .and_then(|a| a.get(vm))
                .and_then(|a| a.get("hostname"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let r = match host {
                None => Err("This agent has no hostname yet.".to_string()),
                Some(h) => self
                    .agent
                    .post(&AgentTarget::new(vm, &h), "/search/apply", &body)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            };
            if let Err(e) = r {
                failed.push(json!({"vmId": vm, "error": e}));
            }
        }
        failed
    }

    fn agent_ids(&self) -> Vec<String> {
        self.st()
            .get("agents")
            .and_then(Value::as_object)
            .map(|a| a.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn applied_of(vm_ids: &[String], failed: &[Value]) -> Value {
        json!(
            vm_ids
                .iter()
                .filter(|v| !failed.iter().any(|f| f["vmId"] == v.as_str()))
                .collect::<Vec<_>>()
        )
    }

    async fn apply(&self, p: &Map<String, Value>) -> Result<Map<String, Value>, String> {
        {
            let mut st = self.st();
            for a in p.get("agents").and_then(Value::as_array).cloned().unwrap_or_default() {
                Self::remember(&mut st, &a);
            }
        }
        if p.get("kind").and_then(Value::as_str) == Some("remove") {
            let (previous, remove, default_provider) = {
                let mut st = self.st();
                let previous = st.get("credential").and_then(Value::as_object).cloned();
                let remove = match &previous {
                    Some(c) => json!([{"id": c.get("plugin").and_then(|pl| pl.get("id"))}]),
                    None => p.get("remove").cloned().unwrap_or(json!([])),
                };
                let dp = previous
                    .as_ref()
                    .and_then(|c| c.get("defaultProvider"))
                    .cloned()
                    .unwrap_or_else(|| p.get("defaultProvider").cloned().unwrap_or(Value::Null));
                st.insert("credential".into(), Value::Null);
                st.insert("credentialId".into(), Value::Null);
                self.save(&st)?;
                (previous, remove, dp)
            };
            (self.on_changed)().await?;
            let vm_ids = self.agent_ids();
            let failed = self.push_agents(&vm_ids, &remove, &default_provider).await;
            let provider = previous
                .as_ref()
                .and_then(|c| c.get("provider"))
                .cloned()
                .unwrap_or_else(|| p.get("provider").cloned().unwrap_or(Value::Null));
            return Ok(obj(&[
                ("provider", provider),
                ("applied", Self::applied_of(&vm_ids, &failed)),
                ("failed", Value::Array(failed)),
            ]));
        }
        let key = p
            .get("apiKey")
            .and_then(Value::as_str)
            .ok_or("no key in the proposal")?;
        if ["placeholder", "plugin", "baseUrl", "swap"]
            .iter()
            .any(|k| p.get(*k).is_none_or(Value::is_null))
        {
            return Err("the proposal is missing the placeholder, plugin, base URL or swap location".into());
        }
        let remove = {
            let mut st = self.st();
            let new_plugin = p.get("plugin").and_then(|x| x.get("id")).cloned();
            let mut remove: Vec<Value> = match st
                .get("credential")
                .and_then(|c| c.get("plugin"))
                .and_then(|x| x.get("id"))
            {
                Some(old) if Some(old) != new_plugin.as_ref() => vec![json!({"id": old})],
                _ => Vec::new(),
            };
            remove.extend(p.get("remove").and_then(Value::as_array).cloned().unwrap_or_default());
            let cred = obj(&[
                ("provider", p["provider"].clone()),
                ("hint", p["hint"].clone()),
                ("placeholder", p["placeholder"].clone()),
                ("plugin", p["plugin"].clone()),
                ("baseUrl", p["baseUrl"].clone()),
                ("config", p["config"].clone()),
                ("swap", p["swap"].clone()),
                ("defaultProvider", p["defaultProvider"].clone()),
                ("apiKey", json!(key)),
                ("updatedAt", json!(iso(now_ms()))),
            ]);
            st.insert("credential".into(), Value::Object(cred));
            st.insert("credentialId".into(), p["credentialId"].clone());
            self.save(&st)?;
            Value::Array(remove)
        };
        (self.on_changed)().await?;
        let vm_ids = self.agent_ids();
        let failed = self.push_agents(&vm_ids, &remove, &p["defaultProvider"]).await;
        Ok(obj(&[
            ("mode", json!(if self.plain_keys { "plain" } else { "placeholder" })),
            ("provider", p["provider"].clone()),
            ("applied", Self::applied_of(&vm_ids, &failed)),
            ("failed", Value::Array(failed)),
        ]))
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let _one = self.running.lock().await;
        let summary = summarize(&p);
        let data = obj(&[("changeId", p["changeId"].clone()), ("summary", json!(summary))]);
        // The TS reads a missing channels module as nobody approved; here it fails closed.
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            self.kit.consent.forget(SCOPE);
            return match self.apply(&p).await {
                Ok(applied) => {
                    let mut d = data;
                    d.extend(applied);
                    d.insert("tofu".into(), json!(true));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: SCOPE.into(),
                change_id: p["changeId"].as_str().unwrap_or_default().into(),
                proposal: Value::Object(p.clone()),
                agent_name: "your organization's web search".into(),
                summary,
                routes,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!(
                "[search] code sent for {} {} via {sent_via}",
                p["kind"].as_str().unwrap_or_default(),
                p["provider"].as_str().unwrap_or_default()
            );
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed search.confirm payload");
        };
        let _one = self.running.lock().await;
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self.kit.consent.verify(SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail("expired", "No change is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let p = proposal.as_object().cloned().unwrap_or_default();
                match self.apply(&p).await {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize(&p)));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        self.kit.consent.cancel(SCOPE, change_id.as_deref());
        ok("cancelled", obj(&[("changeId", null_or(change_id))]))
    }

    /// `search.push`: re-apply what is stored, on one agent.
    pub async fn push(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(vm) = text(&payload, "vmId") else {
            return CommandOutcome::failed("failed", "malformed search.push payload");
        };
        let _one = self.running.lock().await;
        let (provider, dp) = {
            let mut st = self.st();
            let Some(c) = st.get("credential").and_then(Value::as_object).cloned() else {
                return ok(
                    "applied",
                    obj(&[("vmId", json!(vm)), ("applied", json!([])), ("failed", json!([]))]),
                );
            };
            Self::remember(
                &mut st,
                &json!({"vmId": vm, "name": text(&payload, "name").unwrap_or_else(|| vm.clone()), "hostname": text(&payload, "hostname")}),
            );
            if let Err(e) = self.save(&st) {
                return CommandOutcome::failed("failed", e);
            }
            (
                c.get("provider").cloned().unwrap_or(Value::Null),
                c.get("defaultProvider").cloned().unwrap_or(Value::Null),
            )
        };
        let failed = self.push_agents(std::slice::from_ref(&vm), &json!([]), &dp).await;
        let name = self
            .st()
            .get("agents")
            .and_then(|a| a.get(&vm))
            .and_then(|a| a.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| vm.clone());
        tracing::info!(
            "[search] re-applied {} on {name}{}",
            provider.as_str().unwrap_or_default(),
            failed
                .first()
                .map(|f| format!(" (failed: {})", f["error"].as_str().unwrap_or_default()))
                .unwrap_or_default()
        );
        let message = failed
            .iter()
            .map(|f| f["error"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
            .join("; ");
        CommandOutcome {
            ok: failed.is_empty(),
            status: if failed.is_empty() { "applied" } else { "failed" }.into(),
            message: Some(message),
            data: Some(obj(&[
                ("vmId", json!(vm)),
                ("provider", provider),
                ("applied", if failed.is_empty() { json!([vm]) } else { json!([]) }),
                ("failed", Value::Array(failed)),
            ])),
        }
    }

    /// `search.forget`: an agent is gone; no code (it takes nothing from anyone).
    pub fn forget(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(vm) = text(&payload, "vmId") else {
            return CommandOutcome::failed("failed", "malformed search.forget payload");
        };
        let mut st = self.st();
        let had = Self::agents(&mut st).shift_remove(&vm).is_some();
        if had && let Err(e) = self.save(&st) {
            return CommandOutcome::failed("failed", e);
        }
        tracing::info!("[search] {} {vm}", if had { "forgot" } else { "did not hold" });
        ok("applied", obj(&[("vmId", json!(vm)), ("forgotten", json!(had))]))
    }
}

impl CredentialContributor for Search {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Search
    }

    /// One entry, org-wide, scoped to the provider's own host.
    fn credentials(&self) -> Vec<Value> {
        let st = self.st();
        let Some(c) = st.get("credential").and_then(Value::as_object) else {
            return Vec::new();
        };
        if self.plain_keys {
            return Vec::new();
        }
        if let Some(ph) = c.get("placeholder").and_then(Value::as_str) {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            if !seen.iter().any(|s| s == ph) {
                seen.push(ph.to_string());
            }
        }
        let swap = c.get("swap").cloned().unwrap_or(Value::Null);
        vec![
            json!({"placeholder": c.get("placeholder"), "match_domain": swap.get("matchDomain"), "secret": c.get("apiKey"), "locations": swap.get("locations")}),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_and_summaries() {
        let p = |v: Value| parse(v.as_object().expect("obj"));
        assert_eq!(
            p(json!({"changeId": "c"})).expect_err("x"),
            "malformed search.propose payload"
        );
        let a = p(json!({"changeId": "c", "kind": "add", "credentialId": "cr", "provider": "tavily", "providerName": "Tavily", "hint": "tvly…ab", "secret": {"apiKey": "k"}, "agents": [{"vmId": "v"}, {"x": 1}]})).expect("ok");
        assert_eq!(summarize(&a), "Use Tavily for web search (key tvly…ab)");
        assert_eq!(a["agents"], json!([{"vmId": "v", "name": "v", "hostname": null}]));
        assert_eq!(a["apiKey"], "k");
        let r = p(json!({"changeId": "c", "kind": "replace", "credentialId": "cr", "provider": "brave", "providerName": "Brave", "replaces": "Tavily"})).expect("ok");
        assert_eq!(summarize(&r), "Switch web search from Tavily to Brave (key new key)");
    }
}
