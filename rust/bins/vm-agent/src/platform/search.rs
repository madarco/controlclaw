//! Web search on the agent box (`search.ts`, `routes/search.ts`). The firewall sends the whole
//! desired state in one `POST /search/apply`; this makes OpenClaw match it in one config write:
//! the provider's plugin entry with its key, `tools.web.search.provider`, and every other
//! key-based search plugin switched off. A provider somebody set by hand is left where it is.
//! Nothing is installed here: a missing plugin is reported.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use cc_http::{FirewallBody, Router, send_json};
use cc_openclaw::config_queue::PatchOptions;
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{
    BODY_LIMIT, CONFIG_PATCH_RESTART, Caller, Deps, GATEWAY_READ, HTTPS_RE, ID_RE, Snapshot, caller, fail, not_found,
};
use crate::app::App;
use crate::stages;

/// The search plugins the Ansible role installs and this manages, with the providers each serves.
/// Key-free ones are never switched off, only back on when their provider is the one in use.
pub const SEARCH_PLUGINS: [(&str, &[&str], bool); 3] = [
    ("parallel", &["parallel", "parallel-free"], true),
    ("tavily", &["tavily"], false),
    ("brave", &["brave"], false),
];

/// How long a start-up heal waits before looking again when the box is busy.
pub const HEAL_RETRY: Duration = Duration::from_secs(5 * 60);
const HEAL_ATTEMPTS: usize = 3;
const CLI_TIMEOUT: Duration = Duration::from_secs(30);

/// `tools.web.search.provider` values, which include hyphenated ones such as `parallel-free`.
static PROVIDER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[a-z0-9][a-z0-9_-]{0,60}$").expect("regex"));
const CONFIG_KEYS_MAX: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub struct Desired {
    pub provider: String,
    pub plugin_id: String,
    pub plugin_package: String,
    pub base_url: String,
    pub config: Option<Map<String, Value>>,
    pub api_key: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplyInput {
    pub search: Option<Desired>,
    pub default_provider: Option<String>,
    pub remove: Vec<String>,
}

fn parse_desired(raw: Option<&Value>) -> Result<Option<Desired>, &'static str> {
    let Some(s) = raw.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let st = |k: &str| s.get(k).and_then(Value::as_str);
    let Some(provider) = st("provider").filter(|p| PROVIDER_RE.is_match(p)) else {
        return Err("search.provider is invalid");
    };
    let plugin = s.get("plugin");
    let Some(id) = plugin
        .and_then(|p| p.get("id"))
        .and_then(Value::as_str)
        .filter(|i| ID_RE.is_match(i))
    else {
        return Err("search.plugin.id is invalid");
    };
    // `.length` counts UTF-16 units.
    let Some(package) = plugin
        .and_then(|p| p.get("package"))
        .and_then(Value::as_str)
        .filter(|p| p.encode_utf16().count() <= 120)
    else {
        return Err("search.plugin.package is invalid");
    };
    let Some(base_url) = st("baseUrl").filter(|u| HTTPS_RE.is_match(u)) else {
        return Err("search.baseUrl must be an https URL");
    };
    let Some(api_key) = st("apiKey").filter(|k| !k.is_empty()) else {
        return Err("search.apiKey required");
    };
    let config = match s.get("config") {
        None | Some(Value::Null) => None,
        // `typeof [] === "object"`, and `Object.entries` of an array keys it by index.
        Some(v @ (Value::Object(_) | Value::Array(_))) => {
            let entries: Vec<(String, &Value)> = match v {
                Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v)).collect(),
                Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v)).collect(),
                _ => Vec::new(),
            };
            if entries.len() > CONFIG_KEYS_MAX {
                return Err("search.config has too many keys");
            }
            let mut out = Map::new();
            for (k, v) in entries {
                match v {
                    Value::String(v) if ID_RE.is_match(&k) && v.encode_utf16().count() <= 200 => {
                        out.insert(k, json!(v));
                    }
                    _ => return Err("search.config values must be short strings"),
                }
            }
            Some(out)
        }
        Some(_) => return Err("search.config must be an object"),
    };
    Ok(Some(Desired {
        provider: provider.into(),
        plugin_id: id.into(),
        plugin_package: package.into(),
        base_url: base_url.into(),
        config,
        api_key: api_key.into(),
    }))
}

/// `parseApply` (routes/search.ts).
pub fn parse_apply(body: &Map<String, Value>) -> Result<ApplyInput, &'static str> {
    let search = parse_desired(body.get("search"))?;
    let default_provider = match body.get("defaultProvider") {
        None | Some(Value::Null) => None,
        Some(Value::String(p)) if PROVIDER_RE.is_match(p) => Some(p.clone()),
        _ => return Err("defaultProvider is invalid"),
    };
    let mut remove = Vec::new();
    for raw in body.get("remove").and_then(Value::as_array).into_iter().flatten() {
        let Some(id) = raw.get("id").and_then(Value::as_str).filter(|i| ID_RE.is_match(i)) else {
            return Err("remove[].id is invalid");
        };
        remove.push(id.to_string());
    }
    // The provider being written is always ours, so it is in the set the service may take off.
    if let Some(s) = &search
        && !remove.contains(&s.plugin_id)
    {
        remove.push(s.plugin_id.clone());
    }
    Ok(ApplyInput {
        search,
        default_provider,
        remove,
    })
}

fn entry<'a>(entries: &'a Map<String, Value>, id: &str) -> Option<&'a Map<String, Value>> {
    entries.get(id).and_then(Value::as_object)
}

fn has_key(e: Option<&Map<String, Value>>) -> bool {
    super::common::text(
        e.and_then(|e| e.get("config"))
            .and_then(|c| c.get("webSearch"))
            .and_then(|w| w.get("apiKey")),
    )
    .is_some()
}

fn enabled(e: Option<&Map<String, Value>>) -> Option<&Value> {
    e.and_then(|e| e.get("enabled"))
}

pub struct SearchService {
    deps: Deps,
    bin: String,
    busy: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Applies run one at a time: each reads the config, then writes against that read.
    queue: tokio::sync::Mutex<()>,
    healed: AtomicBool,
    heal_attempts: AtomicUsize,
    heal_waiting: AtomicBool,
}

impl SearchService {
    pub fn new(deps: Deps, busy: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self {
            // `OPENCLAW_BIN` on a managed box; the CLI discovery found on an unmanaged one.
            bin: deps.bin.clone(),
            deps,
            busy,
            queue: tokio::sync::Mutex::new(()),
            healed: AtomicBool::new(false),
            heal_attempts: AtomicUsize::new(0),
            heal_waiting: AtomicBool::new(false),
        }
    }

    /// Plugin ids this box has (`openclaw plugins list --json`), loaded or disabled, not failed.
    async fn installed(&self) -> BTreeSet<String> {
        match self
            .deps
            .exec(&self.bin, &["plugins", "list", "--json"], CLI_TIMEOUT, None, &[])
            .await
        {
            Ok(stdout) => {
                // The CLI prints its own log lines before the JSON; take it from the first brace.
                let Some(start) = stdout.find('{') else {
                    return BTreeSet::new();
                };
                let Ok(parsed) = serde_json::from_str::<Value>(&stdout[start..]) else {
                    self.deps.log("[search] could not list plugins: Unexpected JSON");
                    return BTreeSet::new();
                };
                parsed
                    .get("plugins")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|p| p.get("status") != Some(&json!("error")))
                    .filter_map(|p| super::common::text(p.get("id")))
                    .collect()
            }
            Err(line) => {
                self.deps.log(&format!("[search] could not list plugins: {line}"));
                BTreeSet::new()
            }
        }
    }

    async fn patch_config(&self, patch: Map<String, Value>, base: &Snapshot) -> Result<(), String> {
        let w = self.deps.gateway()?;
        let opts = PatchOptions {
            base_hash: Some(base.hash.clone()),
            snapshot: Some(base.raw.clone()),
            read_timeout: Some(GATEWAY_READ),
            ..PatchOptions::new(CONFIG_PATCH_RESTART)
        };
        w.patch(&patch, opts).await.map_err(|e| e.to_string())
    }

    /// Make OpenClaw match the desired state, one apply at a time.
    pub async fn apply(&self, input: &ApplyInput) -> Result<Value, String> {
        let _turn = self.queue.lock().await;
        self.apply_now(input).await
    }

    /// Once per process, when OpenClaw first answers: switch off the key-based plugins not in use.
    /// Waits while the box is busy, and tries at most three times.
    pub fn heal(self: &Arc<Self>) -> cc_http::BoxFuture<()> {
        let me = self.clone();
        Box::pin(async move {
            if me.healed.load(Ordering::SeqCst) || me.heal_waiting.load(Ordering::SeqCst) {
                return;
            }
            if (me.busy)() {
                me.deps.log("[search] busy; checking the search plugins later");
                me.heal_waiting.store(true, Ordering::SeqCst);
                let again = me.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(HEAL_RETRY).await;
                    again.heal_waiting.store(false, Ordering::SeqCst);
                    again.heal().await;
                });
                return;
            }
            // Set before the write: the restart it causes reconnects, which calls this again.
            me.healed.store(true, Ordering::SeqCst);
            let attempts = me.heal_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            let none = ApplyInput {
                search: None,
                default_provider: None,
                remove: Vec::new(),
            };
            if let Err(e) = me.apply(&none).await {
                me.deps
                    .log(&format!("[search] could not check the search plugins: {e}"));
                if attempts < HEAL_ATTEMPTS {
                    me.healed.store(false, Ordering::SeqCst);
                }
            }
        })
    }

    async fn apply_now(&self, input: &ApplyInput) -> Result<Value, String> {
        self.deps.gateway()?;
        let base = self.deps.read_config().await?;
        let config = Value::Object(base.config.clone());
        let entries = super::common::at(&config, &["plugins", "entries"])
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let current = super::common::text(super::common::at(&config, &["tools", "web", "search", "provider"]));
        let mut applied: Vec<String> = Vec::new();
        let mut entry_patch = Map::new();
        let ours: Vec<&str> = input.remove.iter().map(String::as_str).collect();
        let mut provider: Option<String> = match &input.search {
            Some(s) => Some(s.provider.clone()),
            None => match &current {
                Some(c) if ours.contains(&c.as_str()) => input.default_provider.clone(),
                c => c.clone(),
            },
        };
        let mut needs_restart = false;

        let installed = self.installed().await;
        if let Some(s) = &input.search {
            if !installed.contains(&s.plugin_id) {
                // An unmanaged OpenClaw was set up by its owner: the plugin is theirs to install.
                if self.deps.unit_down.is_some() {
                    return Err(format!(
                        "OpenClaw here does not have the {} search plugin: install it with `openclaw plugins install {}`, then try again.",
                        s.plugin_id, s.plugin_package
                    ));
                }
                return Err(format!(
                    "This box does not have the {} search plugin. It is installed at provisioning ({}); re-provision the box, or update it from its Settings page, and try again.",
                    s.plugin_id, s.plugin_package
                ));
            }
            // A plugin that was off is only loaded by a restart; a new key is hot-reloaded.
            if enabled(entry(&entries, &s.plugin_id)) != Some(&json!(true)) {
                needs_restart = true;
            }
            let mut web = Map::new();
            web.insert("apiKey".into(), json!(s.api_key));
            web.insert("baseUrl".into(), json!(s.base_url));
            if let Some(c) = &s.config {
                for (k, v) in c {
                    web.insert(k.clone(), v.clone());
                }
            }
            entry_patch.insert(
                s.plugin_id.clone(),
                json!({ "enabled": true, "config": { "webSearch": web } }),
            );
            applied.push(s.plugin_id.clone());
        }

        // The plugin serving the provider this box ends up on; None for one that is not ours.
        let active: Option<String> = match &input.search {
            Some(s) => Some(s.plugin_id.clone()),
            None => SEARCH_PLUGINS
                .iter()
                .find(|(_, providers, _)| provider.as_deref().is_some_and(|p| providers.contains(&p)))
                .map(|(id, _, _)| id.to_string()),
        };
        if input.search.is_none()
            && let Some(a) = &active
            && installed.contains(a)
            && enabled(entry(&entries, a)) == Some(&json!(false))
        {
            entry_patch.insert(a.clone(), json!({ "enabled": true }));
            needs_restart = true;
            applied.push(format!("enable:{a}"));
        }

        let key_free: Vec<&str> = SEARCH_PLUGINS.iter().filter(|p| p.2).map(|p| p.0).collect();
        let mut ids: Vec<String> = SEARCH_PLUGINS.iter().map(|p| p.0.to_string()).collect();
        for id in &input.remove {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        for id in ids {
            if Some(&id) == active.as_ref() || key_free.contains(&id.as_str()) {
                continue;
            }
            let e = entry(&entries, &id);
            let is_ours = ours.contains(&id.as_str());
            // A key the firewall did not name was put there by hand, and a plugin with a key works.
            if has_key(e) && !is_ours {
                continue;
            }
            if !installed.contains(&id) {
                if is_ours && entries.contains_key(&id) {
                    entry_patch.insert(id.clone(), Value::Null);
                    applied.push(format!("remove:{id}"));
                }
                continue;
            }
            let stale = e.is_some_and(|e| e.contains_key("config"));
            if enabled(e) != Some(&json!(false)) {
                let mut off = Map::new();
                off.insert("enabled".into(), json!(false));
                if stale {
                    off.insert("config".into(), Value::Null);
                }
                entry_patch.insert(id.clone(), Value::Object(off));
                needs_restart = true;
                applied.push(if is_ours {
                    format!("remove:{id}")
                } else {
                    format!("disable:{id}")
                });
            } else if stale {
                entry_patch.insert(id.clone(), json!({ "config": null }));
                applied.push(format!("clear:{id}"));
            }
        }

        let mut patch = Map::new();
        if !entry_patch.is_empty() {
            patch.insert("plugins".into(), json!({ "entries": entry_patch }));
        }
        if provider != current {
            patch.insert("tools".into(), json!({ "web": { "search": { "provider": provider } } }));
        }
        if patch.is_empty() {
            self.deps.log("[search] nothing to change");
            return Ok(json!({ "ok": true, "applied": [], "provider": current }));
        }

        if let Err(e) = self.patch_config(patch.clone(), &base).await {
            // The default provider handed back is plugin-backed and this box cannot serve it:
            // unset the provider instead and leave OpenClaw on its own auto-detection.
            let retryable = input.search.is_none()
                && provider.is_some()
                && provider != current
                && e.to_lowercase().contains("provider is not available");
            if !retryable {
                return Err(e);
            }
            self.deps.log(&format!(
                "[search] {} is not available on this box; unsetting the provider instead",
                provider.as_deref().unwrap_or_default()
            ));
            patch.insert("tools".into(), json!({ "web": { "search": { "provider": null } } }));
            let fresh = self.deps.read_config().await?;
            self.patch_config(patch.clone(), &fresh).await?;
            provider = None;
        }
        if patch.contains_key("tools") {
            applied.push("provider".into());
        }
        if needs_restart {
            match self.deps.restart().await {
                Ok(()) => {
                    self.deps
                        .log("[search] restarted OpenClaw so it loads the search plugins it should");
                    applied.push("restart".into());
                }
                Err(e) => self.deps.log(&format!("[search] restart failed: {e}")),
            }
        }
        self.deps.log(&format!(
            "[search] applied {} (provider {})",
            applied.join(", "),
            provider.as_deref().unwrap_or("none")
        ));
        Ok(json!({ "ok": true, "applied": applied, "provider": provider }))
    }

    /// What the box has right now. No secrets.
    pub async fn status(&self) -> Result<Value, String> {
        let snap = self.deps.read_config().await?;
        let provider = super::common::text(super::common::at(
            &Value::Object(snap.config),
            &["tools", "web", "search", "provider"],
        ));
        let plugins: Vec<String> = self.installed().await.into_iter().collect();
        Ok(json!({ "provider": provider, "plugins": plugins }))
    }
}

/// `/search/*`.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/search/", move |req, _| {
        let app = app.clone();
        async move {
            let write = req.method() == Method::POST;
            let (parts, who) = caller(&app, req, "search", BODY_LIMIT).await;
            let Some(who) = who else {
                let error = if write {
                    "web search changes must come from the org firewall"
                } else {
                    "Unauthorized"
                };
                return send_json(401, &json!({ "error": error }));
            };
            let Some(service) = app.contracts.platform.get().and_then(|p| p.search.get().cloned()) else {
                return send_json(503, &json!({ "ok": false, "error": super::common::NOT_RUNNING }));
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            if path == "/search/status" && parts.method == Method::GET {
                return match service.status().await {
                    Ok(s) => send_json(200, &s),
                    Err(e) => fail(&e, None),
                };
            }
            if !write {
                return not_found();
            }
            let body = match who {
                Caller::Firewall(FirewallBody::Json(b)) => b,
                _ => return send_json(400, &json!({ "ok": false, "error": "Invalid JSON body" })),
            };
            if path != "/search/apply" {
                return not_found();
            }
            let input = match parse_apply(&body) {
                Ok(i) => i,
                Err(e) => return send_json(400, &json!({ "ok": false, "error": e })),
            };
            match service.apply(&input).await {
                Ok(v) => send_json(200, &v),
                Err(e) => fail(&e, None),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    //! search.test.ts, at the service, over the merge-patch fake.

    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};

    use super::super::llm::tests::rig;
    use super::*;

    struct T {
        oc: FakeOpenClawConfig,
        gw: Arc<FakeConfigGateway>,
        rig: super::super::llm::tests::Rig,
        installed: Arc<Mutex<Value>>,
        busy: Arc<AtomicBool>,
    }

    fn on() -> Value {
        json!({ "enabled": true })
    }
    fn off() -> Value {
        json!({ "enabled": false })
    }

    fn setup(config: Value, installed: Value) -> T {
        let oc = FakeOpenClawConfig::new(config, None, false);
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        let r = rig(gw.clone());
        let installed = Arc::new(Mutex::new(installed));
        let i = installed.clone();
        // The plugin list, with a log line first as the CLI prints.
        let runner = cc_proc::RecordingRunner::new();
        runner.answer_with(move |c| {
            (c.args == ["plugins", "list", "--json"]).then(|| {
                let plugins: Vec<Value> = super::super::common::lock(&i)
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut p| {
                        if p.get("enabled").is_none() {
                            p["enabled"] = json!(true);
                        }
                        if p.get("status").is_none() {
                            p["status"] = json!("loaded");
                        }
                        p
                    })
                    .collect();
                cc_proc::ok(&format!("[config] loaded\n{}\n", json!({ "plugins": plugins })))
            })
        });
        let mut rig = r;
        rig.deps.runner = Arc::new(runner);
        T {
            oc,
            gw,
            rig,
            installed,
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    impl T {
        fn service(&self) -> Arc<SearchService> {
            let b = self.busy.clone();
            Arc::new(SearchService::new(
                self.rig.deps.clone(),
                Arc::new(move || b.load(Ordering::SeqCst)),
            ))
        }
        fn patches(&self) -> Vec<Value> {
            self.oc.state().patches.into_iter().map(|(p, _)| p).collect()
        }
        fn restarts(&self) -> usize {
            self.rig.restarts.load(Ordering::SeqCst)
        }
        fn entries(&self) -> Value {
            self.oc.config()["plugins"]["entries"].clone()
        }
    }

    fn tavily() -> Value {
        json!({ "search": { "provider": "tavily", "plugin": { "id": "tavily", "package": "@openclaw/tavily-plugin" }, "baseUrl": "https://api.tavily.com", "apiKey": "tvly-cc-abc123456" }, "defaultProvider": "parallel-free", "remove": [] })
    }
    fn brave() -> Value {
        json!({ "search": { "provider": "brave", "plugin": { "id": "brave", "package": "@openclaw/brave-plugin" }, "baseUrl": "https://api.search.brave.com", "config": { "mode": "web" }, "apiKey": "BSAccxyz789" }, "defaultProvider": "parallel-free", "remove": [{ "id": "tavily" }] })
    }
    fn unset() -> Value {
        json!({ "search": null, "defaultProvider": "parallel-free", "remove": [{ "id": "brave" }] })
    }
    fn input(v: Value) -> ApplyInput {
        parse_apply(v.as_object().expect("obj")).expect("valid")
    }
    fn two() -> Value {
        json!([{ "id": "tavily" }, { "id": "brave" }])
    }
    fn all() -> Value {
        json!([{ "id": "parallel" }, { "id": "duckduckgo" }, { "id": "tavily" }, { "id": "brave" }])
    }
    fn fresh(provider: Option<&str>, extra: Value) -> Value {
        let mut entries = json!({ "parallel": on(), "duckduckgo": on(), "tavily": on(), "brave": on(), "anthropic": { "config": { "sessionCatalog": { "enabled": false } } } });
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            entries[k] = v;
        }
        let mut c = json!({ "plugins": { "entries": entries } });
        if let Some(p) = provider {
            c["tools"] = json!({ "web": { "search": { "provider": p } } });
        }
        c
    }

    #[tokio::test]
    async fn a_key_writes_the_entry_and_the_provider_in_one_patch() {
        let t = setup(json!({}), two());
        let r = t.service().apply(&input(tavily())).await.expect("ok");
        assert_eq!(r["provider"], "tavily");
        assert_eq!(
            t.patches(),
            [
                json!({ "plugins": { "entries": { "tavily": { "enabled": true, "config": { "webSearch": { "apiKey": "tvly-cc-abc123456", "baseUrl": "https://api.tavily.com" } } }, "brave": off() } }, "tools": { "web": { "search": { "provider": "tavily" } } } })
            ]
        );
        assert_eq!(t.restarts(), 1);
    }

    #[tokio::test]
    async fn the_providers_own_config_rides_along_and_the_old_key_is_cleared() {
        let t = setup(
            json!({ "plugins": { "entries": { "tavily": { "enabled": true, "config": { "webSearch": { "apiKey": "tvly-cc-abc123456" } } } } }, "tools": { "web": { "search": { "provider": "tavily" } } } }),
            two(),
        );
        t.service().apply(&input(brave())).await.expect("ok");
        assert_eq!(
            t.patches()[0],
            json!({ "plugins": { "entries": {
                "tavily": { "enabled": false, "config": null },
                "brave": { "enabled": true, "config": { "webSearch": { "apiKey": "BSAccxyz789", "baseUrl": "https://api.search.brave.com", "mode": "web" } } },
            } }, "tools": { "web": { "search": { "provider": "brave" } } } })
        );
        assert_eq!(t.restarts(), 1);
    }

    #[tokio::test]
    async fn rotating_the_key_in_use_costs_no_restart() {
        let t = setup(
            json!({ "plugins": { "entries": { "tavily": { "enabled": true, "config": { "webSearch": { "apiKey": "tvly-cc-old" } } }, "brave": off() } }, "tools": { "web": { "search": { "provider": "tavily" } } } }),
            two(),
        );
        let mut b = tavily();
        b["search"]["apiKey"] = json!("tvly-cc-new999");
        let r = t.service().apply(&input(b)).await.expect("ok");
        assert_eq!(t.restarts(), 0);
        assert_eq!(
            t.patches()[0].as_object().expect("o").keys().collect::<Vec<_>>(),
            ["plugins"]
        );
        assert_eq!(r["applied"], json!(["tavily"]));
    }

    #[tokio::test]
    async fn a_missing_plugin_is_refused_and_a_disabled_one_used() {
        let t = setup(json!({}), json!([{ "id": "brave" }]));
        let e = t.service().apply(&input(tavily())).await.expect_err("missing");
        assert!(e.contains("does not have the tavily search plugin") && e.contains("@openclaw/tavily-plugin"));
        assert!(t.patches().is_empty());
        *t.installed.lock().expect("l") = json!([{ "id": "tavily", "enabled": false }]);
        let r = t.service().apply(&input(tavily())).await.expect("ok");
        assert_eq!(r["provider"], "tavily");
        assert_eq!(t.restarts(), 1);
        *t.installed.lock().expect("l") = json!([{ "id": "tavily", "status": "error" }]);
        assert!(
            t.service()
                .apply(&input(tavily()))
                .await
                .expect_err("error")
                .contains("does not have the tavily search plugin")
        );
    }

    #[tokio::test]
    async fn unset_goes_back_to_the_default_and_a_hand_set_provider_stays() {
        let t = setup(
            json!({ "plugins": { "entries": { "brave": { "enabled": true, "config": { "webSearch": { "apiKey": "BSAcc-old" } } } } }, "tools": { "web": { "search": { "provider": "brave" } } } }),
            two(),
        );
        let r = t.service().apply(&input(unset())).await.expect("ok");
        assert_eq!(r["provider"], "parallel-free");
        assert_eq!(
            t.patches()[0],
            json!({ "plugins": { "entries": { "brave": { "enabled": false, "config": null }, "tavily": off() } }, "tools": { "web": { "search": { "provider": "parallel-free" } } } })
        );
        let t = setup(
            json!({ "plugins": { "entries": { "brave": { "enabled": true } } }, "tools": { "web": { "search": { "provider": "searxng" } } } }),
            two(),
        );
        let r = t.service().apply(&input(unset())).await.expect("ok");
        assert_eq!(r["provider"], "searxng");
        assert_eq!(
            t.patches()[0],
            json!({ "plugins": { "entries": { "brave": off(), "tavily": off() } } })
        );
    }

    #[tokio::test]
    async fn a_default_provider_this_box_cannot_serve_unsets_the_provider() {
        let t = setup(
            json!({ "plugins": { "entries": { "brave": { "enabled": true } } }, "tools": { "web": { "search": { "provider": "brave" } } } }),
            two(),
        );
        let once = AtomicBool::new(true);
        t.gw.hook(move |m, _| {
            (m == "config.patch" && once.swap(false, Ordering::SeqCst)).then(|| {
                Err("Config validation failed: tools.web.search.provider: web_search provider is not available: parallel-free".to_string())
            })
        });
        let r = t.service().apply(&input(unset())).await.expect("ok");
        assert_eq!(r["provider"], Value::Null);
        assert_eq!(
            t.patches()[0],
            json!({ "plugins": { "entries": { "brave": off(), "tavily": off() } }, "tools": { "web": { "search": { "provider": null } } } })
        );
        let t = setup(json!({}), two());
        t.gw.hook(|m, _| {
            (m == "config.patch")
                .then(|| Err("Config validation failed: plugins.entries.tavily: something else entirely".to_string()))
        });
        assert!(
            t.service()
                .apply(&input(tavily()))
                .await
                .expect_err("e")
                .contains("something else entirely")
        );
    }

    #[tokio::test]
    async fn nothing_to_change_writes_nothing() {
        let t = setup(
            json!({ "plugins": { "entries": { "tavily": off(), "brave": off() } }, "tools": { "web": { "search": { "provider": "searxng" } } } }),
            two(),
        );
        let r = t
            .service()
            .apply(&input(
                json!({ "search": null, "defaultProvider": "parallel-free", "remove": [] }),
            ))
            .await
            .expect("ok");
        assert_eq!(r["applied"], json!([]));
        assert!(t.patches().is_empty());
    }

    #[tokio::test]
    async fn only_the_plugin_in_use_is_on() {
        // Default provider: tavily and brave off, parallel and the unmanaged ones untouched.
        let t = setup(fresh(Some("parallel-free"), json!({})), all());
        t.service().heal().await;
        assert_eq!(
            t.patches(),
            [json!({ "plugins": { "entries": { "tavily": off(), "brave": off() } } })]
        );
        assert_eq!(t.entries()["parallel"], on());
        assert_eq!(t.entries()["duckduckgo"], on());
        assert_eq!(
            t.entries()["anthropic"],
            json!({ "config": { "sessionCatalog": { "enabled": false } } })
        );
        assert_eq!(t.restarts(), 1);
        // Tavily on, then switched to Brave, then unset.
        let s = t.service();
        s.apply(&input(
            json!({ "search": tavily()["search"], "defaultProvider": "parallel-free", "remove": [{ "id": "tavily" }] }),
        ))
        .await
        .expect("ok");
        assert_eq!(t.entries()["brave"], off());
        assert_eq!(t.entries()["parallel"], on());
        s.apply(&input(json!({ "search": brave()["search"], "defaultProvider": "parallel-free", "remove": [{ "id": "tavily" }, { "id": "brave" }] }))).await.expect("ok");
        assert_eq!(t.entries()["tavily"], off());
        let r = s.apply(&input(unset())).await.expect("ok");
        assert_eq!(r["provider"], "parallel-free");
        assert_eq!(t.entries()["brave"], off());
        let before = t.patches().len();
        assert_eq!(s.apply(&input(unset())).await.expect("ok")["applied"], json!([]));
        assert_eq!(t.patches().len(), before);
    }

    #[tokio::test]
    async fn unset_turns_parallel_back_on_and_a_disabled_key_is_cleared_without_restart() {
        let t = setup(
            fresh(
                Some("brave"),
                json!({ "parallel": off(), "tavily": off(), "brave": { "enabled": true, "config": { "webSearch": { "apiKey": "BSAcc-old" } } } }),
            ),
            all(),
        );
        let r = t.service().apply(&input(unset())).await.expect("ok");
        assert_eq!(
            t.patches()[0],
            json!({ "plugins": { "entries": { "parallel": on(), "brave": { "enabled": false, "config": null } } }, "tools": { "web": { "search": { "provider": "parallel-free" } } } })
        );
        assert_eq!(
            r["applied"],
            json!(["enable:parallel", "remove:brave", "provider", "restart"])
        );
        let t = setup(
            fresh(
                Some("parallel-free"),
                json!({ "tavily": off(), "brave": { "enabled": false, "config": { "webSearch": { "apiKey": "BSAcc-old" } } } }),
            ),
            all(),
        );
        let r = t.service().apply(&input(unset())).await.expect("ok");
        assert_eq!(
            t.patches(),
            [json!({ "plugins": { "entries": { "brave": { "config": null } } } })]
        );
        assert_eq!(r["applied"], json!(["clear:brave"]));
        assert_eq!(t.restarts(), 0);
    }

    #[tokio::test]
    async fn a_provider_and_key_set_by_hand_are_left_alone() {
        let mine = json!({ "enabled": true, "config": { "webSearch": { "apiKey": "tvly-their-own-key" } } });
        let t = setup(fresh(Some("tavily"), json!({ "tavily": mine })), all());
        t.service().heal().await;
        assert_eq!(t.oc.config()["tools"]["web"]["search"]["provider"], "tavily");
        assert_eq!(t.entries()["tavily"], mine);
        assert_eq!(t.patches(), [json!({ "plugins": { "entries": { "brave": off() } } })]);
        let t = setup(fresh(Some("searxng"), json!({ "tavily": mine })), all());
        let r = t
            .service()
            .apply(&input(
                json!({ "search": null, "defaultProvider": "parallel-free", "remove": [] }),
            ))
            .await
            .expect("ok");
        assert_eq!(r["provider"], "searxng");
        assert_eq!(t.entries()["tavily"], mine);
        assert_eq!(t.patches(), [json!({ "plugins": { "entries": { "brave": off() } } })]);
    }

    #[tokio::test]
    async fn the_heal_runs_once_per_process_waits_when_busy_and_skips_a_box_without_plugins() {
        let t = setup(fresh(Some("parallel-free"), json!({})), all());
        let first = t.service();
        first.heal().await;
        first.heal().await;
        t.service().heal().await;
        assert_eq!(t.patches().len(), 1);
        assert_eq!(t.restarts(), 1);

        let t = setup(fresh(Some("parallel-free"), json!({})), all());
        t.busy.store(true, Ordering::SeqCst);
        let s = t.service();
        s.heal().await;
        assert!(t.patches().is_empty());
        t.busy.store(false, Ordering::SeqCst);
        s.apply(&input(
            json!({ "search": null, "defaultProvider": "parallel-free", "remove": [] }),
        ))
        .await
        .expect("ok");
        assert_eq!(t.patches().len(), 1);

        let t = setup(
            json!({ "plugins": { "entries": { "parallel": on() } }, "tools": { "web": { "search": { "provider": "parallel-free" } } } }),
            json!([{ "id": "parallel" }]),
        );
        t.service().heal().await;
        assert!(t.patches().is_empty());
        assert_eq!(t.restarts(), 0);
    }

    #[tokio::test]
    async fn status_says_what_the_box_has() {
        let t = setup(
            json!({ "tools": { "web": { "search": { "provider": "tavily" } } } }),
            two(),
        );
        assert_eq!(
            t.service().status().await.expect("s"),
            json!({ "provider": "tavily", "plugins": ["brave", "tavily"] })
        );
    }

    #[test]
    fn bad_bodies() {
        let p = |v: Value| parse_apply(v.as_object().expect("o")).err();
        let mut s = tavily();
        s["search"]["baseUrl"] = json!("http://api.tavily.com");
        assert_eq!(p(s), Some("search.baseUrl must be an https URL"));
        let mut s = tavily();
        s["search"]["provider"] = json!("bad provider!");
        assert_eq!(p(s), Some("search.provider is invalid"));
        let mut s = tavily();
        s["search"]["plugin"] = json!({ "id": "../etc", "package": "x" });
        assert_eq!(p(s), Some("search.plugin.id is invalid"));
        let mut s = tavily();
        s["search"]["apiKey"] = json!("");
        assert_eq!(p(s), Some("search.apiKey required"));
        assert_eq!(
            p(json!({ "search": null, "remove": [{ "id": "a b" }] })),
            Some("remove[].id is invalid")
        );
        assert_eq!(
            p(json!({ "search": null, "defaultProvider": "nope!" })),
            Some("defaultProvider is invalid")
        );
        // The provider written is always in the set it may take off.
        assert_eq!(
            parse_apply(tavily().as_object().expect("o")).expect("ok").remove,
            ["tavily"]
        );
    }
}
