//! Model providers on the agent box (`llm.ts`, `routes/llm.ts`). The firewall sends the whole
//! desired state in one `POST /llm/apply`, and this makes OpenClaw match it:
//!
//! - `api_key`: `openclaw models auth paste-api-key --provider <p> --profile-id <id>`, the key on stdin;
//! - `token` and `oauth`: the same with `paste-token` and `--expires-in 365d`;
//! - a custom provider block (`models.providers.<p>`) is written before its profile;
//! - `remove`: `openclaw models auth logout <id> --yes`, and/or the block set to null;
//! - the model order (`agents.defaults.model`), memory search and the phone's reply model, in one
//!   `config.patch`.
//!
//! After a credential changed, OpenClaw is restarted unless the gateway already reports every
//! profile just written. Only the org firewall may write; either side may read.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use cc_http::{FirewallBody, Router, send_json};
use cc_openclaw::config_queue::{MIN_QUEUE_WAIT, PatchOptions, QueueOptions};
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::js_slice;
use super::common::{
    BODY_LIMIT, CONFIG_PATCH, CONFIG_PATCH_RESTART, Caller, CliWrite, Deps, GATEWAY_READ, NEEDS_GATEWAY_STOPPED,
    Offline, Snapshot, at, caller, fail, not_found, patch_restarts_gateway, text,
};
use crate::app::App;
use crate::stages;

const CLI_TIMEOUT: Duration = Duration::from_secs(45);
const MODELS_CACHE: Duration = Duration::from_secs(30);
const REINDEX_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// `LLM_APPLY_BUDGET_MS`: the part of the firewall's 90 s its config writes may spend.
const APPLY_BUDGET: Duration = Duration::from_secs(80);
const MEMORY_CORE_PLUGIN: &str = "memory-core";
/// A retired spelling older agents wrote; cleared on apply.
const RETIRED_CODEX_PROVIDER_ID: &str = "openai-codex";

fn cli(args: &[&str], stdin: Option<String>) -> CliWrite {
    CliWrite {
        args: args.iter().map(|a| a.to_string()).collect(),
        stdin,
        timeout: CLI_TIMEOUT,
    }
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("regex")
}

use super::common::{HTTPS_RE, ID_RE as PROVIDER_RE};
static MODEL_ID_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9._:/-]{1,120}$"));
static GONE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)not found|no such|unknown profile"));
const KINDS: [&str; 3] = ["api_key", "token", "oauth"];
const BLOCK_APIS: [&str; 3] = ["openai-completions", "anthropic-messages", "openai-responses"];

#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    pub provider: String,
    pub kind: String,
    pub profile_id: String,
    pub value: String,
    pub model: String,
    pub codex: Option<String>,
    pub provider_block: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Remove {
    pub provider: String,
    pub profile_id: String,
    pub kind: Option<String>,
    pub provider_block: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Memory {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub api_key: String,
    pub dreaming: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplyInput {
    pub primary: Option<String>,
    pub fallbacks: Vec<String>,
    pub credentials: Vec<Credential>,
    pub remove: Vec<Remove>,
    /// Some(None) puts memory back on OpenClaw's defaults; None (an older firewall) leaves it.
    pub memory: Option<Option<Memory>>,
}

/// `knownCompat`: the caching switches out of a `compat` object, or None when it has none.
pub fn known_compat(raw: Option<&Value>) -> Option<Value> {
    let c = raw?.as_object()?;
    let mut out = Map::new();
    if let Some(Value::Bool(b)) = c.get("supportsPromptCacheKey") {
        out.insert("supportsPromptCacheKey".into(), json!(b));
    }
    if c.get("cacheControlFormat") == Some(&json!("anthropic")) {
        out.insert("cacheControlFormat".into(), json!("anthropic"));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

fn parse_provider_block(raw: Option<&Value>) -> Result<Option<Value>, &'static str> {
    let Some(b) = raw.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let base_url = b.get("baseUrl").and_then(Value::as_str);
    if !base_url.is_some_and(|u| HTTPS_RE.is_match(u)) {
        return Err("credentials[].providerBlock.baseUrl must be an https URL");
    }
    let api = b.get("api").and_then(Value::as_str);
    if !api.is_some_and(|a| BLOCK_APIS.contains(&a)) {
        return Err("credentials[].providerBlock.api is not supported");
    }
    let list = match b.get("models") {
        Some(Value::Array(l)) if !l.is_empty() && l.len() <= 50 => l,
        _ => return Err("credentials[].providerBlock.models must list 1-50 models"),
    };
    let mut models = Vec::new();
    for m in list {
        let Some(id) = m
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| MODEL_ID_RE.is_match(id))
        else {
            return Err("credentials[].providerBlock.models[].id is invalid");
        };
        let name = match m.get("name") {
            Some(Value::String(n)) if !n.is_empty() => js_slice(n, 120),
            _ => id.to_string(),
        };
        let mut model = json!({ "id": id, "name": name });
        if let Some(c) = known_compat(m.get("compat")) {
            model["compat"] = c;
        }
        models.push(model);
    }
    Ok(Some(json!({ "baseUrl": base_url, "api": api, "models": models })))
}

fn parse_memory(raw: Option<&Value>) -> Result<Option<Option<Memory>>, &'static str> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.is_null() {
        return Ok(Some(None));
    }
    let s = |k: &str| raw.get(k).and_then(Value::as_str);
    let Some(provider) = s("provider").filter(|p| PROVIDER_RE.is_match(p)) else {
        return Err("memory.provider is invalid");
    };
    let Some(model) = s("model").filter(|m| MODEL_ID_RE.is_match(m)) else {
        return Err("memory.model is invalid");
    };
    let Some(base_url) = s("baseUrl").filter(|u| HTTPS_RE.is_match(u)) else {
        return Err("memory.baseUrl must be an https URL");
    };
    let Some(api_key) = s("apiKey").filter(|k| !k.is_empty()) else {
        return Err("memory.apiKey required");
    };
    Ok(Some(Some(Memory {
        provider: provider.into(),
        model: model.into(),
        base_url: base_url.into(),
        api_key: api_key.into(),
        dreaming: raw.get("dreaming") == Some(&json!(true)),
    })))
}

/// `parseApply` (routes/llm.ts): the body, or the first thing wrong with it.
pub fn parse_apply(body: &Map<String, Value>) -> Result<ApplyInput, &'static str> {
    let empty = Value::Object(Map::new());
    let model = match body.get("model") {
        Some(v) if !v.is_null() => v,
        _ => &empty,
    };
    let primary = text(model.get("primary"));
    let fallbacks = model
        .get("fallbacks")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|f| f.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let list = |k: &str| body.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let mut credentials = Vec::new();
    for raw in list("credentials") {
        let s = |k: &str| raw.get(k).and_then(Value::as_str);
        let Some(provider) = s("provider").filter(|p| PROVIDER_RE.is_match(p)) else {
            return Err("credentials[].provider is invalid");
        };
        let Some(kind) = s("kind").filter(|k| KINDS.contains(k)) else {
            return Err("credentials[].kind must be api_key, token or oauth");
        };
        let Some(profile_id) = s("profileId").filter(|p| !p.is_empty()) else {
            return Err("credentials[].profileId required");
        };
        let Some(value) = s("value").filter(|v| !v.is_empty()) else {
            return Err("credentials[].value required");
        };
        let Some(model) = s("model").filter(|m| !m.is_empty()) else {
            return Err("credentials[].model required");
        };
        let codex = at(&raw, &["codex", "accountId"])
            .and_then(Value::as_str)
            .map(str::to_string);
        let provider_block = parse_provider_block(raw.get("providerBlock"))?;
        credentials.push(Credential {
            provider: provider.into(),
            kind: kind.into(),
            profile_id: profile_id.into(),
            value: value.into(),
            model: model.into(),
            codex,
            provider_block,
        });
    }
    let mut remove = Vec::new();
    for raw in list("remove") {
        let s = |k: &str| raw.get(k).and_then(Value::as_str);
        let Some(provider) = s("provider").filter(|p| PROVIDER_RE.is_match(p)) else {
            return Err("remove[].provider is invalid");
        };
        let Some(profile_id) = s("profileId").filter(|p| !p.is_empty()) else {
            return Err("remove[].profileId required");
        };
        remove.push(Remove {
            provider: provider.into(),
            profile_id: profile_id.into(),
            kind: s("kind").filter(|k| KINDS.contains(k)).map(str::to_string),
            provider_block: raw.get("providerBlock") == Some(&json!(true)),
        });
    }
    let memory = parse_memory(body.get("memory"))?;
    Ok(ApplyInput {
        primary,
        fallbacks,
        credentials,
        remove,
        memory,
    })
}

/// `memory.search` and the dreaming sweep as the config has them (`readMemory`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Configured {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub dreaming: bool,
}

pub fn read_memory(config: &Value) -> Configured {
    let search = at(config, &["memory", "search"]);
    let field = |p: &[&str]| text(search.and_then(|s| at(s, p)));
    // OpenClaw's own default is on, so anything but an explicit `false` reads as on.
    let dreaming = at(
        config,
        &[
            "plugins",
            "entries",
            MEMORY_CORE_PLUGIN,
            "config",
            "dreaming",
            "enabled",
        ],
    );
    Configured {
        provider: field(&["provider"]),
        model: field(&["model"]),
        base_url: field(&["remote", "baseUrl"]),
        api_key: field(&["remote", "apiKey"]),
        dreaming: dreaming != Some(&json!(false)),
    }
}

/// `memoryPatch`: the patch that puts memory search where `want` says, and whether the vectors
/// must be rebuilt; None when there is nothing to do.
pub fn memory_patch(want: &Option<Option<Memory>>, have: &Configured) -> Option<(Map<String, Value>, bool)> {
    let want = want.as_ref()?;
    let Some(want) = want else {
        if have.provider.is_none()
            && have.model.is_none()
            && have.base_url.is_none()
            && have.api_key.is_none()
            && have.dreaming
        {
            return None;
        }
        let patch = json!({
            "memory": { "search": { "provider": null, "model": null, "remote": null } },
            "plugins": { "entries": { MEMORY_CORE_PLUGIN: { "config": { "dreaming": { "enabled": null } } } } },
        });
        return Some((obj(patch), have.provider.is_some() || have.model.is_some()));
    };
    let same = |h: &Option<String>, w: &str| h.as_deref() == Some(w);
    if same(&have.provider, &want.provider)
        && same(&have.model, &want.model)
        && same(&have.base_url, &want.base_url)
        && same(&have.api_key, &want.api_key)
        && have.dreaming == want.dreaming
    {
        return None;
    }
    let patch = json!({
        "memory": { "search": { "provider": want.provider, "model": want.model, "remote": { "baseUrl": want.base_url, "apiKey": want.api_key } } },
        "plugins": { "entries": { MEMORY_CORE_PLUGIN: { "config": { "dreaming": { "enabled": want.dreaming } } } } },
    });
    let reindex = !same(&have.provider, &want.provider) || !same(&have.model, &want.model);
    Some((obj(patch), reindex))
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// `readBlocks`: each provider block's model ids and caching switches, sorted by provider.
pub fn read_blocks(config: &Value) -> Vec<Value> {
    let Some(providers) = at(config, &["models", "providers"]).and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out: Vec<(String, Value)> = Vec::new();
    for (provider, raw) in providers {
        let Some(list) = raw.get("models").and_then(Value::as_array) else {
            continue;
        };
        let models: Vec<Value> = list
            .iter()
            .filter(|m| m.get("id").is_some_and(Value::is_string))
            .map(|m| json!({ "id": m["id"], "compat": known_compat(m.get("compat")) }))
            .collect();
        out.push((provider.clone(), json!({ "provider": provider, "models": models })));
    }
    // `localeCompare`; the ids are ASCII.
    out.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()).then(a.0.cmp(&b.0)));
    out.into_iter().map(|(_, v)| v).collect()
}

/// The voice-call plugin's entry for the new primary model (`phoneModelEntry`, W8's
/// phone-model.ts). Returns the TS's throw as an error.
pub type PhoneModel = Arc<dyn Fn(&Value, Option<&str>) -> Result<Option<Value>, String> + Send + Sync>;

pub struct LlmService {
    deps: Deps,
    bin: String,
    state_path: Option<PathBuf>,
    mitm_ca_path: Option<PathBuf>,
    phone_model: Option<PhoneModel>,
    models_cache: Mutex<HashMap<String, (Instant, Vec<Value>)>>,
    reindex_failed: Arc<Mutex<Option<String>>>,
    reindexing: Arc<AtomicBool>,
}

#[derive(Debug, PartialEq)]
pub struct ApplyError {
    pub message: String,
    pub applied: Option<Vec<String>>,
}

impl From<String> for ApplyError {
    fn from(message: String) -> Self {
        Self { message, applied: None }
    }
}

fn read_reindex_failure(path: Option<&PathBuf>) -> Option<String> {
    let text = std::fs::read_to_string(path?).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    super::common::text(v.get("error"))
}

impl LlmService {
    pub fn new(
        deps: Deps,
        state_path: Option<PathBuf>,
        mitm_ca_path: Option<PathBuf>,
        phone_model: Option<PhoneModel>,
    ) -> Self {
        let failed = read_reindex_failure(state_path.as_ref());
        if let Some(f) = &failed {
            deps.log(&format!("[llm] the memory index was left unbuilt: {f}"));
        }
        Self {
            bin: deps.bin.clone(),
            deps,
            state_path,
            mitm_ca_path,
            phone_model,
            models_cache: Mutex::new(HashMap::new()),
            reindex_failed: Arc::new(Mutex::new(failed)),
            reindexing: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    pub fn with_bin(mut self, bin: &str) -> Self {
        self.bin = bin.into();
        self
    }

    async fn patch_config(
        &self,
        patch: Map<String, Value>,
        base: Option<&Snapshot>,
        replace_paths: Vec<String>,
        budget: Option<Duration>,
    ) -> Result<(), String> {
        let read;
        let snapshot = match base {
            Some(b) => b,
            None => {
                read = self.deps.read_config().await?;
                &read
            }
        };
        let writer = self.deps.gateway()?;
        let opts = PatchOptions {
            base_hash: Some(snapshot.hash.clone()),
            snapshot: Some(snapshot.raw.clone()),
            timeout: if patch_restarts_gateway(&patch) {
                CONFIG_PATCH_RESTART
            } else {
                CONFIG_PATCH
            },
            read_timeout: Some(GATEWAY_READ),
            replace_paths,
            budget,
            ..PatchOptions::default()
        };
        writer.patch(&patch, opts).await.map_err(|e| e.to_string())
    }

    /// A CLI command that writes OpenClaw's config file, in the queue (`withConfigFileWrite`).
    /// From OpenClaw 2026.11 a credential write is refused while the gateway runs; [`Self::apply`]
    /// makes those again with it stopped ([`super::common::OfflineRun`]). Earlier versions write
    /// with it running, so they never stop it.
    async fn cli_write(
        &self,
        args: &[&str],
        stdin: Option<String>,
        max_queue_wait: Duration,
    ) -> Result<String, String> {
        let q = QueueOptions {
            max_queue_wait: Some(max_queue_wait),
            ..QueueOptions::default()
        };
        let run = || self.deps.exec(&self.bin, args, CLI_TIMEOUT, stdin, &[]);
        match self.deps.client() {
            Some(w) => w.file_write(run, q).await,
            None => run().await,
        }
    }

    /// Make OpenClaw match the desired state. Applies what it can and reports each failure by name.
    pub async fn apply(&self, input: &ApplyInput) -> Result<Value, ApplyError> {
        self.deps.gateway()?;
        let deadline = Instant::now() + APPLY_BUDGET;
        let left = || deadline.saturating_duration_since(Instant::now());
        let cli_wait = || MIN_QUEUE_WAIT.max(left().saturating_sub(CLI_TIMEOUT));
        let mut applied: Vec<String> = Vec::new();
        let mut failed: Vec<(String, String)> = Vec::new();
        let mut provider_patch = Map::new();
        // Writes OpenClaw refused while its gateway runs (2026.11 on), made together with it
        // stopped: what goes in `applied`, what in `failed`, the write.
        let mut held: Vec<(String, String, CliWrite)> = Vec::new();

        for r in &input.remove {
            let profile = r.profile_id.contains(':');
            if r.provider_block || !profile {
                provider_patch.insert(r.provider.clone(), Value::Null);
            }
            let logout = ["models", "auth", "logout", &r.profile_id, "--yes"];
            let result = if profile {
                self.cli_write(&logout, None, cli_wait()).await.map(|_| ())
            } else {
                Ok(())
            };
            match result {
                Ok(()) => applied.push(format!("remove:{}", r.provider)),
                // Already gone is fine: the goal is that it is not there.
                Err(line) if GONE_RE.is_match(&line) => applied.push(format!("remove:{}", r.provider)),
                Err(line) if NEEDS_GATEWAY_STOPPED.is_match(&line) => held.push((
                    format!("remove:{}", r.provider),
                    format!("remove {}", r.provider),
                    cli(&logout, None),
                )),
                Err(line) => failed.push((format!("remove {}", r.provider), line)),
            }
        }

        for c in &input.credentials {
            // Written before the profile: OpenClaw only takes a key for a provider it knows.
            if let Some(block) = &c.provider_block {
                let patch = obj(json!({ "models": { "providers": { c.provider.clone(): block } } }));
                let replace = vec![format!("models.providers.{}.models", c.provider)];
                if let Err(e) = self.patch_config(patch, None, replace, Some(left())).await {
                    failed.push((c.provider.clone(), e));
                    continue;
                }
            }
            let sub = if c.kind == "api_key" {
                "paste-api-key"
            } else {
                "paste-token"
            };
            let mut args = vec![
                "models",
                "auth",
                sub,
                "--provider",
                &c.provider,
                "--profile-id",
                &c.profile_id,
            ];
            if c.kind != "api_key" {
                args.extend(["--expires-in", "365d"]);
            }
            let stdin = Some(format!("{}\n", c.value));
            match self.cli_write(&args, stdin.clone(), cli_wait()).await {
                Ok(_) => applied.push(c.provider.clone()),
                Err(line) if NEEDS_GATEWAY_STOPPED.is_match(&line) => {
                    held.push((c.provider.clone(), c.provider.clone(), cli(&args, stdin)))
                }
                Err(line) => failed.push((c.provider.clone(), line)),
            }
        }

        let snapshot = self.deps.read_config().await?;
        let config = Value::Object(snapshot.config.clone());
        if at(&config, &["models", "providers"])
            .and_then(Value::as_object)
            .is_some_and(|p| p.contains_key(RETIRED_CODEX_PROVIDER_ID))
        {
            provider_patch.insert(RETIRED_CODEX_PROVIDER_ID.into(), Value::Null);
        }
        let mut patch = Map::new();
        if !provider_patch.is_empty() {
            patch.insert("models".into(), json!({ "providers": provider_patch }));
        }
        let model = match &input.primary {
            Some(p) => json!({ "primary": p, "fallbacks": input.fallbacks }),
            None => Value::Null,
        };
        patch.insert("agents".into(), json!({ "defaults": { "model": model } }));
        let memory = memory_patch(&input.memory, &read_memory(&config));
        if let Some((m, _)) = &memory {
            for (k, v) in m {
                patch.insert(k.clone(), v.clone());
            }
        }
        if let Some(phone_model) = &self.phone_model {
            match phone_model(&config, input.primary.as_deref()) {
                Ok(Some(entry)) => {
                    let mut plugins = patch.remove("plugins").map(obj).unwrap_or_default();
                    let mut entries = plugins.remove("entries").map(obj).unwrap_or_default();
                    entries.insert("voice-call".into(), entry);
                    plugins.insert("entries".into(), Value::Object(entries));
                    patch.insert("plugins".into(), Value::Object(plugins));
                }
                Ok(None) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut reindex = false;
        match self
            .patch_config(patch, Some(&snapshot), Vec::new(), Some(left()))
            .await
        {
            Ok(()) => {
                applied.push("model".into());
                if let Some((_, r)) = memory {
                    applied.push("memory".into());
                    reindex = r;
                }
            }
            Err(e) => failed.push(("model".into(), e)),
        }
        // The refused writes last, once for all of them: the model order above is written while
        // the gateway runs, and it reads both as it starts again.
        let mut restarted = false;
        if !held.is_empty() {
            let writes: Vec<CliWrite> = held.iter().map(|h| h.2.clone()).collect();
            let run = || (self.deps.offline)(self.deps.clone(), self.bin.clone(), writes);
            let q = QueueOptions {
                max_queue_wait: Some(cli_wait()),
                ..QueueOptions::default()
            };
            let outcome = match self.deps.client() {
                Some(w) => w.file_write(run, q).await,
                None => run().await,
            };
            match outcome {
                Ok(Offline { results, started }) => {
                    let mut results = results.into_iter();
                    for (ok, name, _) in held {
                        match results.next() {
                            Some(Ok(_)) => applied.push(ok),
                            Some(Err(line)) if ok.starts_with("remove:") && GONE_RE.is_match(&line) => applied.push(ok),
                            Some(Err(line)) => failed.push((name, line)),
                            None => failed.push((name, "not written".into())),
                        }
                    }
                    match started {
                        Ok(()) => restarted = true,
                        Err(e) => failed.push(("restart".into(), e)),
                    }
                    self.deps
                        .log("[llm] credentials written with OpenClaw's gateway stopped");
                }
                Err(e) => failed.extend(held.into_iter().map(|(_, name, _)| (name, e.clone()))),
            }
        }
        super::common::lock(&self.models_cache).clear();
        let changed = input.credentials.iter().any(|c| applied.contains(&c.provider))
            || input
                .remove
                .iter()
                .any(|r| applied.contains(&format!("remove:{}", r.provider)));
        if changed {
            let ids: Vec<&str> = input.credentials.iter().map(|c| c.profile_id.as_str()).collect();
            // Started again after the writes, it read them as it started; one that did not start
            // is not restarted either (failed above).
            let stopped = !restarted && failed.iter().any(|f| f.0 == "restart");
            if restarted || (!stopped && self.restart_if_auth_stale(&ids).await) {
                applied.push("restart".into());
            }
        }
        // After the restart, never before it: a restart in the middle would kill the rebuild.
        let failed_before = super::common::lock(&self.reindex_failed).is_some();
        if reindex || (failed_before && matches!(input.memory, Some(Some(_)))) {
            self.reindex_memory();
        }
        let failed_names: Vec<&str> = failed.iter().map(|f| f.0.as_str()).collect();
        self.deps.log(&format!(
            "[llm] applied {}{}",
            if applied.is_empty() {
                "nothing".to_string()
            } else {
                applied.join(", ")
            },
            if failed.is_empty() {
                String::new()
            } else {
                format!("; failed {}", failed_names.join(", "))
            }
        ));
        if !failed.is_empty() {
            return Err(ApplyError {
                message: failed
                    .iter()
                    .map(|(w, e)| format!("{w}: {e}"))
                    .collect::<Vec<_>>()
                    .join("; "),
                applied: Some(applied),
            });
        }
        Ok(json!({ "ok": true, "applied": applied, "failed": [] }))
    }

    /// Rebuild the memory index in the background, one at a time, with the firewall's CA.
    fn reindex_memory(&self) {
        if self.reindexing.swap(true, Ordering::SeqCst) {
            self.deps
                .log("[llm] memory index rebuild already running; not starting another");
            return;
        }
        // Written before the run: an agent that dies mid-rebuild comes back knowing.
        write_reindex_failure(
            &self.reindex_failed,
            self.state_path.as_ref(),
            Some("the memory index rebuild did not finish"),
            &self.deps,
        );
        let env: Vec<(&'static str, String)> = match &self.mitm_ca_path {
            Some(ca) if ca.exists() => vec![("NODE_EXTRA_CA_CERTS", ca.to_string_lossy().to_string())],
            _ => Vec::new(),
        };
        // Cleared when the run ends however it ends (the TS's `.finally`), a panic included.
        struct Running(Arc<AtomicBool>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let (deps, bin, failed, path, running) = (
            self.deps.clone(),
            self.bin.clone(),
            self.reindex_failed.clone(),
            self.state_path.clone(),
            self.reindexing.clone(),
        );
        tokio::spawn(async move {
            let _running = Running(running);
            match deps
                .exec(&bin, &["memory", "index", "--force"], REINDEX_TIMEOUT, None, &env)
                .await
            {
                Ok(_) => {
                    write_reindex_failure(&failed, path.as_ref(), None, &deps);
                    deps.log("[llm] memory index rebuilt for the new embedding provider");
                }
                Err(line) => {
                    write_reindex_failure(&failed, path.as_ref(), Some(&line), &deps);
                    deps.log(&format!("[llm] memory index rebuild failed: {line}"));
                }
            }
        });
    }

    /// True when a restart was run because the gateway does not report every profile just written.
    async fn restart_if_auth_stale(&self, profile_ids: &[&str]) -> bool {
        let ready = match self
            .deps
            .call("models.authStatus", json!({ "refresh": true }), Duration::from_secs(15))
            .await
        {
            Ok(r) => {
                let seen: BTreeSet<String> = r
                    .get("providers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .flat_map(|p| p.get("profiles").and_then(Value::as_array).cloned().unwrap_or_default())
                    .map(|prof| {
                        text(prof.get("profileId"))
                            .or_else(|| text(prof.get("id")))
                            .unwrap_or_default()
                            .to_lowercase()
                    })
                    .collect();
                let unavailable = r.get("unavailable").is_some_and(truthy);
                !unavailable && profile_ids.iter().all(|id| seen.contains(&id.to_lowercase()))
            }
            Err(e) => {
                self.deps
                    .log(&format!("[llm] models.authStatus failed after apply: {e}"));
                false
            }
        };
        if ready {
            return false;
        }
        match self.deps.restart().await {
            Ok(()) => {
                self.deps.log("[llm] restarted OpenClaw so it loads the new credential");
                true
            }
            Err(e) => {
                self.deps.log(&format!("[llm] restart failed: {e}"));
                false
            }
        }
    }

    /// What the box has right now, from the config and `models.authStatus`. No secrets.
    pub async fn status(&self) -> Result<Value, String> {
        let snapshot = self.deps.read_config().await?;
        let config = Value::Object(snapshot.config);
        let configured = read_memory(&config);
        let mut providers = BTreeSet::new();
        let mut profiles = Vec::new();
        if let Some(p) = at(&config, &["auth", "profiles"]).and_then(Value::as_object) {
            for (profile_id, p) in p {
                let provider = text(p.get("provider"))
                    .unwrap_or_else(|| profile_id.split(':').next().unwrap_or_default().to_string());
                providers.insert(provider.clone());
                profiles.push(json!({ "profileId": profile_id, "provider": provider, "mode": text(p.get("mode")) }));
            }
        }
        if let Some(p) = at(&config, &["models", "providers"]).and_then(Value::as_object) {
            providers.extend(p.keys().cloned());
        }
        let blocks = read_blocks(&config);
        let auth: Vec<Value> = match self
            .deps
            .call("models.authStatus", json!({}), Duration::from_secs(10))
            .await
        {
            Ok(r) => r
                .get("providers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|p| {
                    json!({
                        "provider": text(p.get("provider")).or_else(|| text(p.get("id"))).unwrap_or_else(|| "?".into()),
                        "status": text(p.get("status")).or_else(|| text(p.get("state"))),
                        "profiles": p.get("profiles").and_then(Value::as_array).map_or(0, Vec::len),
                    })
                })
                .collect(),
            Err(e) => {
                self.deps.log(&format!("[llm] models.authStatus failed: {e}"));
                Vec::new()
            }
        };
        let model = at(&config, &["agents", "defaults", "model"]);
        let fallbacks: Vec<Value> = model
            .and_then(|m| m.get("fallbacks"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|f| f.is_string()).cloned().collect())
            .unwrap_or_default();
        let index_error = if self.reindexing.load(Ordering::SeqCst) {
            Some("the memory index is being rebuilt".to_string())
        } else {
            super::common::lock(&self.reindex_failed).clone()
        };
        // `[...providers].sort()`: code-unit order, which a BTreeSet of ASCII ids already is.
        let providers: Vec<String> = providers.into_iter().collect();
        Ok(json!({
            "model": { "primary": text(model.and_then(|m| m.get("primary"))), "fallbacks": fallbacks },
            "providers": providers,
            "profiles": profiles,
            "auth": auth,
            "memory": {
                "provider": configured.provider,
                "model": configured.model,
                "dreaming": configured.dreaming,
                "indexError": index_error,
            },
            "blocks": blocks,
        }))
    }

    /// The models OpenClaw knows for a provider (`models.list`, full catalog), as `provider/model`.
    pub async fn models(&self, provider: &str) -> Result<Vec<Value>, String> {
        if let Some((at, v)) = super::common::lock(&self.models_cache).get(provider)
            && at.elapsed() < MODELS_CACHE
        {
            return Ok(v.clone());
        }
        let r = self
            .deps
            .call(
                "models.list",
                json!({ "view": "all", "provider": provider }),
                Duration::from_secs(20),
            )
            .await?;
        let mut out = Vec::new();
        for m in r.get("models").and_then(Value::as_array).into_iter().flatten() {
            let Some(raw) = text(m.get("id")).or_else(|| text(m.get("model"))) else {
                continue;
            };
            let id = match text(m.get("provider")) {
                Some(p) if !raw.starts_with(&format!("{p}/")) => format!("{p}/{raw}"),
                _ if raw.contains('/') => raw,
                _ => format!("{provider}/{raw}"),
            };
            if !id.starts_with(&format!("{provider}/")) {
                continue;
            }
            let name = text(m.get("name")).unwrap_or_else(|| id[provider.len() + 1..].to_string());
            out.push(json!({ "id": id, "name": name }));
        }
        super::common::lock(&self.models_cache).insert(provider.to_string(), (Instant::now(), out.clone()));
        Ok(out)
    }
}

/// JavaScript truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

fn write_reindex_failure(slot: &Mutex<Option<String>>, path: Option<&PathBuf>, error: Option<&str>, deps: &Deps) {
    *super::common::lock(slot) = error.map(str::to_string);
    let Some(path) = path else { return };
    let body = json!({ "version": 1, "error": error }).to_string();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = cc_store::write_atomic(path, body.as_bytes(), 0o600, cc_store::TmpName::Suffix) {
        deps.log(&format!("[llm] could not record the memory index state: {e}"));
    }
}

/// `/llm/*`.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/llm/", move |req, _| {
        let app = app.clone();
        async move {
            let write = req.method() == Method::POST;
            let query = req.uri().query().map(str::to_string);
            let (parts, who) = caller(&app, req, "llm", BODY_LIMIT).await;
            let Some(who) = who else {
                let error = if write {
                    "model changes must come from the org firewall"
                } else {
                    "Unauthorized"
                };
                return send_json(401, &json!({ "error": error }));
            };
            let Some(service) = app.contracts.platform.get().and_then(|p| p.llm.get().cloned()) else {
                return send_json(503, &json!({ "ok": false, "error": super::common::NOT_RUNNING }));
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            if path == "/llm/status" && parts.method == Method::GET {
                return match service.status().await {
                    Ok(s) => send_json(200, &s),
                    Err(e) => fail(&e, None),
                };
            }
            if path == "/llm/models" && parts.method == Method::GET {
                let provider = query_param(query.as_deref(), "provider").unwrap_or_default();
                if !PROVIDER_RE.is_match(&provider) {
                    return send_json(400, &json!({ "ok": false, "error": "provider required" }));
                }
                return match service.models(&provider).await {
                    Ok(m) => send_json(200, &json!({ "models": m })),
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
            if path != "/llm/apply" {
                return not_found();
            }
            let input = match parse_apply(&body) {
                Ok(i) => i,
                Err(e) => return send_json(400, &json!({ "ok": false, "error": e })),
            };
            match service.apply(&input).await {
                Ok(v) => send_json(200, &v),
                Err(e) => fail(&e.message, e.applied.map(|a| ("applied", json!(a)))),
            }
        }
    });
}

/// `url.searchParams.get(name)`: the first value, percent-decoded, `+` as a space.
pub fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query?.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    //! llm.test.ts, at the service: a fake gateway and the recording runner stand in for OpenClaw
    //! and its CLI. The route's auth and parsing are covered by the conformance cases.

    use std::sync::atomic::AtomicUsize;

    use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};
    use cc_openclaw::config_queue::{BoxFuture, ConfigGateway};
    use cc_openclaw::{ConfigWriter, GatewayError};
    use cc_proc::{Output, RecordingRunner};

    use super::*;

    /// A gateway that answers `config.get` from `config`, takes every patch and records calls.
    pub struct Fake {
        pub connected: AtomicBool,
        pub config: Mutex<Value>,
        pub auth: Mutex<Value>,
        pub calls: Mutex<Vec<(String, Value)>>,
    }

    impl Fake {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                connected: AtomicBool::new(true),
                config: Mutex::new(json!({})),
                auth: Mutex::new(
                    json!({ "providers": [{ "provider": "openai", "status": "ok", "profiles": [{ "id": "openai:controlclaw" }] }] }),
                ),
                calls: Mutex::new(Vec::new()),
            })
        }
        pub fn patches(&self) -> Vec<Value> {
            super::super::common::lock(&self.calls)
                .iter()
                .filter(|(m, _)| m == "config.patch")
                .map(|(_, p)| serde_json::from_str(p["raw"].as_str().unwrap_or("null")).expect("raw"))
                .collect()
        }
    }

    impl ConfigGateway for Fake {
        fn connected(&self) -> bool {
            self.connected.load(Ordering::SeqCst)
        }
        fn call(&self, method: &str, params: Value, _t: Duration) -> BoxFuture<'_, Result<Value, GatewayError>> {
            super::super::common::lock(&self.calls).push((method.to_string(), params));
            let r = match method {
                "config.get" => Ok(json!({ "hash": "h1", "parsed": *super::super::common::lock(&self.config) })),
                "config.patch" => Ok(json!({ "ok": true })),
                "models.authStatus" => Ok(super::super::common::lock(&self.auth).clone()),
                "models.list" => Ok(json!({ "models": [
                    { "id": "gpt-5.6-sol", "name": "GPT-5.6 Sol", "provider": "openai" },
                    { "id": "openai/gpt-5.4-mini", "name": "GPT-5.4 mini" },
                    { "id": "claude-opus-5", "provider": "anthropic" },
                ] })),
                other => Err(GatewayError::Remote {
                    code: None,
                    message: Some(format!("unexpected {other}")),
                }),
            };
            Box::pin(async move { r })
        }
    }

    pub struct Rig {
        pub runner: RecordingRunner,
        pub restarts: Arc<AtomicUsize>,
        /// The writes made with the gateway stopped, one entry a stop.
        pub offline: Arc<Mutex<Vec<Vec<CliWrite>>>>,
        pub fail: Arc<Mutex<Option<String>>>,
        pub deps: Deps,
        pub dir: tempfile::TempDir,
    }

    /// Deps over `gw`, with a CLI that answers ok unless `fail` holds stderr.
    pub fn rig(gw: Arc<dyn ConfigGateway>) -> Rig {
        let runner = RecordingRunner::new();
        let fail: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let f = fail.clone();
        runner.answer_with(move |_| {
            Some(match super::super::common::lock(&f).clone() {
                Some(stderr) => Output {
                    code: Some(1),
                    stderr: stderr.into_bytes(),
                    ..Default::default()
                },
                None => cc_proc::ok("Auth profile: openai:controlclaw (openai/api_key)\n"),
            })
        });
        let writer = Arc::new(ConfigWriter::new(gw));
        let restarts = Arc::new(AtomicUsize::new(0));
        let r = restarts.clone();
        let dir = tempfile::tempdir().expect("dir");
        let offline: Arc<Mutex<Vec<Vec<CliWrite>>>> = Arc::default();
        let o = offline.clone();
        let deps = Deps {
            writer: Arc::new(move || Some(writer.clone())),
            runner: Arc::new(runner.clone()),
            home: dir.path().to_path_buf(),
            restart: Arc::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }),
            log: Arc::new(|_| {}),
            bin: crate::platform::common::OPENCLAW_BIN.to_string(),
            unit_down: None,
            offline: Arc::new(move |_, _, writes: Vec<CliWrite>| {
                let n = writes.len();
                super::super::common::lock(&o).push(writes);
                Box::pin(async move {
                    Ok(Offline {
                        results: vec![Ok("Auth profile: x".to_string()); n],
                        started: Ok(()),
                    })
                })
            }),
        };
        Rig {
            runner,
            restarts,
            offline,
            fail,
            deps,
            dir,
        }
    }

    fn service(r: &Rig) -> LlmService {
        let ca = r.dir.path().join("mitm-ca.crt");
        std::fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\nnot-a-real-ca\n-----END CERTIFICATE-----\n",
        )
        .expect("ca");
        LlmService::new(
            r.deps.clone(),
            Some(r.dir.path().join("memory-index.json")),
            Some(ca),
            None,
        )
        .with_bin("/fake/openclaw")
    }

    fn input(v: Value) -> ApplyInput {
        parse_apply(v.as_object().expect("obj")).expect("valid")
    }

    fn apply_body() -> Value {
        json!({
            "model": { "primary": "openai/gpt-5.6-sol", "fallbacks": ["anthropic/claude-opus-5"] },
            "credentials": [
                { "provider": "openai", "kind": "api_key", "profileId": "openai:controlclaw", "value": "sk-cc-openai-abc123456", "model": "openai/gpt-5.6-sol" },
                { "provider": "anthropic", "kind": "token", "profileId": "anthropic:controlclaw", "value": "sk-ant-oat01-cc-xyz", "model": "anthropic/claude-opus-5" },
            ],
            "remove": [],
        })
    }

    fn included_block() -> Value {
        json!({ "baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [
            { "id": "moonshotai/kimi-k2.6", "name": "Kimi K2.6" },
            { "id": "anthropic/claude-haiku-4.5", "name": "Claude Haiku 4.5" },
        ] })
    }

    fn argv(r: &Rig) -> Vec<(Vec<String>, String)> {
        r.runner
            .calls()
            .into_iter()
            .map(|c| {
                (
                    c.args,
                    String::from_utf8(c.stdin.unwrap_or_default()).unwrap_or_default(),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn keys_go_on_stdin_and_the_model_order_is_patched() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        let out = s.apply(&input(apply_body())).await.expect("ok");
        assert_eq!(out["ok"], json!(true));
        let calls = argv(&r);
        assert_eq!(
            calls[0].0,
            [
                "models",
                "auth",
                "paste-api-key",
                "--provider",
                "openai",
                "--profile-id",
                "openai:controlclaw"
            ]
        );
        assert_eq!(calls[0].1, "sk-cc-openai-abc123456\n");
        assert_eq!(
            calls[1].0,
            [
                "models",
                "auth",
                "paste-token",
                "--provider",
                "anthropic",
                "--profile-id",
                "anthropic:controlclaw",
                "--expires-in",
                "365d"
            ]
        );
        assert_eq!(calls[1].1, "sk-ant-oat01-cc-xyz\n");
        assert!(
            calls.iter().all(|(a, _)| !a.iter().any(|x| x.contains("sk-"))),
            "no secret in argv"
        );
        let patch = gw
            .calls
            .lock()
            .expect("lock")
            .iter()
            .find(|(m, _)| m == "config.patch")
            .cloned()
            .expect("patch");
        assert_eq!(patch.1["baseHash"], "h1");
        assert_eq!(
            gw.patches()[0],
            json!({ "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol", "fallbacks": ["anthropic/claude-opus-5"] } } } })
        );
        // anthropic is not in the auth status: restarted once.
        assert_eq!(r.restarts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn writes_refused_while_the_gateway_runs_are_made_with_it_stopped_once() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        // OpenClaw 2026.11.3's refusals, word for word.
        *r.fail.lock().expect("lock") = Some("--profile-id is not supported by models.authSetApiKey. Omit --profile-id to use the Gateway's API-key profile, or stop the Gateway through its service owner and rerun this command.".into());
        let mut body = apply_body();
        body["remove"] = json!([{ "provider": "google", "profileId": "google:controlclaw" }]);
        let out = s.apply(&input(body)).await.expect("ok");
        assert_eq!(
            out["applied"],
            json!(["model", "remove:google", "openai", "anthropic", "restart"]),
            "{out}"
        );
        let stops = r.offline.lock().expect("lock").clone();
        assert_eq!(stops.len(), 1, "one stop for every write");
        let args: Vec<Vec<String>> = stops[0].iter().map(|w| w.args.clone()).collect();
        assert_eq!(args[0], ["models", "auth", "logout", "google:controlclaw", "--yes"]);
        assert_eq!(args[1][..3], ["models", "auth", "paste-api-key"]);
        assert_eq!(args[2][..3], ["models", "auth", "paste-token"]);
        assert_eq!(stops[0][1].stdin.as_deref(), Some("sk-cc-openai-abc123456\n"));
        assert_eq!(
            r.restarts.load(Ordering::SeqCst),
            0,
            "started again by the stop, not restarted"
        );
    }

    #[tokio::test]
    async fn a_gateway_that_does_not_stop_fails_each_held_write_by_name() {
        let gw = Fake::new();
        let mut r = rig(gw.clone());
        r.deps.offline =
            Arc::new(|_, _, _| Box::pin(async { Err("OpenClaw did not stop to save it: timed out".to_string()) }));
        let s = service(&r);
        *r.fail.lock().expect("lock") = Some("Cannot admit models.auth … To run offline, stop the Gateway through its service owner, wait for ownership to release, then rerun this exact command.".into());
        let e = s.apply(&input(apply_body())).await.expect_err("failed");
        assert!(e.message.contains("openai: OpenClaw did not stop"), "{}", e.message);
        assert!(e.message.contains("anthropic: OpenClaw did not stop"), "{}", e.message);
        assert_eq!(e.applied, Some(vec!["model".to_string()]));
    }

    #[tokio::test]
    async fn a_gateway_that_does_not_start_again_is_a_failure_not_a_restart() {
        let gw = Fake::new();
        let mut r = rig(gw.clone());
        r.deps.offline = Arc::new(|_, _, writes: Vec<CliWrite>| {
            let n = writes.len() - 1;
            Box::pin(async move {
                Ok(Offline {
                    results: vec![Ok(String::new()); n],
                    started: Err("Job for openclaw.service failed".into()),
                })
            })
        });
        let s = service(&r);
        *r.fail.lock().expect("lock") = Some("… stop the Gateway through its service owner …".into());
        let e = s.apply(&input(apply_body())).await.expect_err("failed");
        assert!(
            e.message.contains("anthropic: not written"),
            "a write with no result: {}",
            e.message
        );
        assert!(
            e.message.contains("restart: Job for openclaw.service failed"),
            "{}",
            e.message
        );
        assert_eq!(e.applied, Some(vec!["model".to_string(), "openai".to_string()]));
        assert_eq!(r.restarts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn restarted_only_when_the_gateway_does_not_report_the_profiles() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        *gw.auth.lock().expect("lock") = json!({ "providers": [
            { "provider": "openai", "profiles": [{ "profileId": "openai:controlclaw" }] },
            { "provider": "anthropic", "profiles": [{ "profileId": "anthropic:controlclaw" }] },
        ] });
        let out = s.apply(&input(apply_body())).await.expect("ok");
        assert_eq!(r.restarts.load(Ordering::SeqCst), 0, "both reported: no restart");
        assert!(!out["applied"].as_array().expect("a").contains(&json!("restart")));
        *gw.auth.lock().expect("lock") =
            json!({ "providers": [], "unavailable": { "code": "PREPARED_MODEL_AUTH_UNAVAILABLE" } });
        let out = s.apply(&input(apply_body())).await.expect("ok");
        assert_eq!(r.restarts.load(Ordering::SeqCst), 1, "unavailable → restart");
        assert!(out["applied"].as_array().expect("a").contains(&json!("restart")));
        let model_only =
            json!({ "model": { "primary": "openai/gpt-5.6-sol", "fallbacks": [] }, "credentials": [], "remove": [] });
        s.apply(&input(model_only)).await.expect("ok");
        assert_eq!(
            r.restarts.load(Ordering::SeqCst),
            1,
            "a model-only change never restarts"
        );
        // A second profile of a provider the gateway reports still restarts.
        *gw.auth.lock().expect("lock") = json!({ "providers": [{ "provider": "openai", "status": "ok", "profiles": [{ "profileId": "openai:controlclaw" }] }] });
        let chatgpt = json!({ "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "fallbacks": [] }, "credentials": [
            { "provider": "openai", "kind": "oauth", "profileId": "openai:controlclaw-chatgpt", "value": "eyJhbGciOiJub25lIn0.eyJjYyI6MX0.cc", "model": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt" }
        ], "remove": [] });
        s.apply(&input(chatgpt)).await.expect("ok");
        assert_eq!(r.restarts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_chatgpt_login_is_a_token_profile_and_the_retired_block_goes() {
        let gw = Fake::new();
        *gw.config.lock().expect("lock") = json!({ "models": { "providers": { "openai-codex": { "baseUrl": "https://chatgpt.com/backend-api/codex" } } } });
        let r = rig(gw.clone());
        let s = service(&r);
        let body = json!({
            "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "fallbacks": [] },
            "credentials": [{ "provider": "openai", "kind": "oauth", "profileId": "openai:controlclaw-chatgpt", "value": "eyJhbGciOiJub25lIn0.eyJjYyI6MX0.cc", "model": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "codex": { "accountId": "acct_1" } }],
            "remove": [{ "provider": "openai", "profileId": "openai:controlclaw", "kind": "api_key" }],
        });
        s.apply(&input(body)).await.expect("ok");
        let calls = argv(&r);
        assert_eq!(calls[0].0, ["models", "auth", "logout", "openai:controlclaw", "--yes"]);
        assert_eq!(
            calls[1].0,
            [
                "models",
                "auth",
                "paste-token",
                "--provider",
                "openai",
                "--profile-id",
                "openai:controlclaw-chatgpt",
                "--expires-in",
                "365d"
            ]
        );
        assert_eq!(
            gw.patches()[0],
            json!({ "models": { "providers": { "openai-codex": null } }, "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "fallbacks": [] } } } })
        );
        // No model: the default comes back.
        let r2 = rig(gw.clone());
        let s2 = service(&r2);
        *gw.config.lock().expect("lock") = json!({});
        gw.calls.lock().expect("lock").clear();
        s2.apply(&input(json!({ "model": { "primary": null, "fallbacks": [] }, "credentials": [], "remove": [{ "provider": "openai", "profileId": "openai:controlclaw-chatgpt", "kind": "oauth" }] })))
            .await
            .expect("ok");
        assert_eq!(
            argv(&r2)[0].0,
            ["models", "auth", "logout", "openai:controlclaw-chatgpt", "--yes"]
        );
        assert_eq!(gw.patches()[0], json!({ "agents": { "defaults": { "model": null } } }));
    }

    #[tokio::test]
    async fn a_cli_failure_names_the_provider_and_still_patches_the_rest() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        *r.fail.lock().expect("lock") = Some("Error: That does not look like an OpenAI API key.".into());
        let e = s.apply(&input(apply_body())).await.expect_err("fails");
        assert!(
            e.message
                .starts_with("openai: Error: That does not look like an OpenAI API key."),
            "{}",
            e.message
        );
        assert_eq!(e.applied, Some(vec!["model".to_string()]));
        assert!(!gw.patches().is_empty(), "the model order is still written");
    }

    #[test]
    fn bad_bodies_are_refused() {
        let p = |v: Value| parse_apply(v.as_object().expect("obj"));
        assert_eq!(
            p(
                json!({ "model": {}, "credentials": [{ "provider": "openai", "kind": "magic", "profileId": "x", "value": "v", "model": "m" }] })
            ),
            Err("credentials[].kind must be api_key, token or oauth")
        );
        assert_eq!(
            p(
                json!({ "model": {}, "credentials": [{ "provider": "../evil", "kind": "api_key", "profileId": "x", "value": "v", "model": "m" }] })
            ),
            Err("credentials[].provider is invalid")
        );
        let cred = json!({ "provider": "controlclaw", "kind": "api_key", "profileId": "controlclaw:included", "value": "v", "model": "m" });
        for (block, why) in [
            (
                json!({ "baseUrl": "http://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [{ "id": "a" }] }),
                "credentials[].providerBlock.baseUrl must be an https URL",
            ),
            (
                json!({ "baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "shell", "models": [{ "id": "a" }] }),
                "credentials[].providerBlock.api is not supported",
            ),
            (
                json!({ "baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [] }),
                "credentials[].providerBlock.models must list 1-50 models",
            ),
            (
                json!({ "baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [{ "id": "a b" }] }),
                "credentials[].providerBlock.models[].id is invalid",
            ),
        ] {
            let mut c = cred.clone();
            c["providerBlock"] = block;
            assert_eq!(p(json!({ "model": {}, "credentials": [c] })), Err(why));
        }
        let memory = json!({ "provider": "openai-compatible", "model": "m", "baseUrl": "https://ai-gateway.vercel.sh/v1", "apiKey": "k" });
        for (k, v, why) in [
            (
                "baseUrl",
                json!("http://ai-gateway.vercel.sh/v1"),
                "memory.baseUrl must be an https URL",
            ),
            ("provider", json!("not a provider"), "memory.provider is invalid"),
            ("apiKey", json!(""), "memory.apiKey required"),
        ] {
            let mut m = memory.clone();
            m[k] = v;
            assert_eq!(p(json!({ "memory": m })), Err(why));
        }
        // Known compat switches kept, the rest dropped.
        let mut c = cred.clone();
        c["providerBlock"] = json!({ "baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [
            { "id": "moonshotai/kimi-k2.6", "name": "Kimi K2.6", "compat": { "supportsPromptCacheKey": true, "cacheControlFormat": "openai", "requiresStringContent": true } }
        ] });
        let i = p(json!({ "credentials": [c] })).expect("ok");
        assert_eq!(
            i.credentials[0].provider_block.as_ref().expect("block")["models"],
            json!([{ "id": "moonshotai/kimi-k2.6", "name": "Kimi K2.6", "compat": { "supportsPromptCacheKey": true } }])
        );
    }

    #[tokio::test]
    async fn a_provider_block_is_written_before_its_key_and_cleared_on_remove() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        let body = json!({
            "model": { "primary": "controlclaw/moonshotai/kimi-k2.6@controlclaw:included", "fallbacks": [] },
            "credentials": [{ "provider": "controlclaw", "kind": "api_key", "profileId": "controlclaw:included", "value": "vck-cc-abc123", "model": "controlclaw/moonshotai/kimi-k2.6@controlclaw:included", "providerBlock": included_block() }],
            "remove": [],
        });
        s.apply(&input(body)).await.expect("ok");
        assert_eq!(
            gw.patches()[0],
            json!({ "models": { "providers": { "controlclaw": included_block() } } })
        );
        let calls = argv(&r);
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            [
                "models",
                "auth",
                "paste-api-key",
                "--provider",
                "controlclaw",
                "--profile-id",
                "controlclaw:included"
            ]
        );
        gw.calls.lock().expect("lock").clear();
        let r2 = rig(gw.clone());
        service(&r2)
            .apply(&input(json!({ "model": { "primary": null, "fallbacks": [] }, "credentials": [], "remove": [{ "provider": "controlclaw", "profileId": "controlclaw:included", "kind": "api_key", "providerBlock": true }] })))
            .await
            .expect("ok");
        assert_eq!(
            argv(&r2)[0].0,
            ["models", "auth", "logout", "controlclaw:included", "--yes"]
        );
        assert_eq!(
            gw.patches()[0],
            json!({ "models": { "providers": { "controlclaw": null } }, "agents": { "defaults": { "model": null } } })
        );
    }

    #[test]
    fn memory_patch_cases() {
        let want = Memory {
            provider: "openai-compatible".into(),
            model: "text-embedding-3-small".into(),
            base_url: "https://ai-gateway.vercel.sh/v1".into(),
            api_key: "vck-cc-included1".into(),
            dreaming: false,
        };
        let none = Configured {
            dreaming: true,
            ..Configured::default()
        };
        let settled = Configured {
            provider: Some(want.provider.clone()),
            model: Some(want.model.clone()),
            base_url: Some(want.base_url.clone()),
            api_key: Some(want.api_key.clone()),
            dreaming: false,
        };
        let w = Some(Some(want.clone()));
        assert_eq!(memory_patch(&None, &none), None);
        let (patch, reindex) = memory_patch(&w, &none).expect("set");
        assert_eq!(
            patch["memory"],
            json!({ "search": { "provider": "openai-compatible", "model": "text-embedding-3-small", "remote": { "baseUrl": want.base_url, "apiKey": want.api_key } } })
        );
        assert_eq!(
            patch["plugins"],
            json!({ "entries": { "memory-core": { "config": { "dreaming": { "enabled": false } } } } })
        );
        assert!(reindex);
        assert_eq!(memory_patch(&w, &settled), None);
        assert!(
            !memory_patch(
                &w,
                &Configured {
                    dreaming: true,
                    ..settled.clone()
                }
            )
            .expect("p")
            .1
        );
        let (rotated, ri) = memory_patch(
            &w,
            &Configured {
                api_key: Some("vck-cc-included-OLD".into()),
                ..settled.clone()
            },
        )
        .expect("p");
        assert_eq!(
            rotated["memory"]["search"]["remote"],
            json!({ "baseUrl": want.base_url, "apiKey": want.api_key })
        );
        assert!(!ri, "a new key is not a new set of vectors");
        let (cleared, cr) = memory_patch(&Some(None), &settled).expect("p");
        assert_eq!(
            cleared["memory"],
            json!({ "search": { "provider": null, "model": null, "remote": null } })
        );
        assert_eq!(
            cleared["plugins"],
            json!({ "entries": { "memory-core": { "config": { "dreaming": { "enabled": null } } } } })
        );
        assert!(cr);
        assert_eq!(memory_patch(&Some(None), &none), None);
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    #[tokio::test]
    async fn memory_is_written_and_the_index_rebuilt_after_the_restart_with_the_ca() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        let memory = json!({ "provider": "openai-compatible", "model": "openai/text-embedding-3-small", "baseUrl": "https://ai-gateway.vercel.sh/v1", "apiKey": "vck-cc-included1", "dreaming": false });
        let mut body = apply_body();
        body["memory"] = memory.clone();
        let out = s.apply(&input(body)).await.expect("ok");
        assert!(out["applied"].as_array().expect("a").contains(&json!("memory")));
        let with_memory = gw
            .patches()
            .into_iter()
            .find(|p| p.get("memory").is_some())
            .expect("patch");
        assert_eq!(
            with_memory["memory"]["search"]["remote"],
            json!({ "baseUrl": memory["baseUrl"], "apiKey": memory["apiKey"] })
        );
        assert_eq!(
            with_memory["plugins"]["entries"]["memory-core"]["config"]["dreaming"]["enabled"],
            json!(false)
        );
        settle().await;
        let calls = r.runner.calls();
        let reindex = calls
            .iter()
            .find(|c| c.args == ["memory", "index", "--force"])
            .expect("rebuilt");
        assert_eq!(r.restarts.load(Ordering::SeqCst), 1);
        assert_eq!(
            reindex.env.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some(r.dir.path().join("mitm-ca.crt").to_str().expect("p"))
        );
        // The paste calls come before the rebuild, which comes after the restart in apply's order.
        assert_eq!(calls.last().expect("last").args, ["memory", "index", "--force"]);
    }

    #[tokio::test]
    async fn a_failed_rebuild_is_kept_on_disk_reported_and_retried() {
        let gw = Fake::new();
        let r = rig(gw.clone());
        let s = service(&r);
        *r.fail.lock().expect("lock") = Some("memory index: sqlite-vec is not loaded\n".into());
        let memory = json!({ "provider": "openai-compatible", "model": "openai/text-embedding-3-small", "baseUrl": "https://ai-gateway.vercel.sh/v1", "apiKey": "vck-cc-included1", "dreaming": false });
        let body = json!({ "model": {}, "credentials": [], "remove": [], "memory": memory });
        s.apply(&input(body.clone())).await.expect("ok");
        settle().await;
        *r.fail.lock().expect("lock") = None;
        let file: Value =
            serde_json::from_str(&std::fs::read_to_string(r.dir.path().join("memory-index.json")).expect("file"))
                .expect("json");
        assert!(file["error"].as_str().expect("e").contains("sqlite-vec"));
        // A restarted agent still knows.
        let again = service(&r);
        assert!(
            again.status().await.expect("s")["memory"]["indexError"]
                .as_str()
                .expect("e")
                .contains("sqlite-vec")
        );
        // Nothing about the descriptor changed; only the remembered failure asks for the rebuild.
        *gw.config.lock().expect("lock") = json!({ "memory": { "search": { "provider": memory["provider"], "model": memory["model"], "remote": { "baseUrl": memory["baseUrl"], "apiKey": memory["apiKey"] } } }, "plugins": { "entries": { "memory-core": { "config": { "dreaming": { "enabled": false } } } } } });
        let before = r.runner.calls().len();
        s.apply(&input(body)).await.expect("ok");
        settle().await;
        assert!(
            r.runner.calls()[before..]
                .iter()
                .any(|c| c.args == ["memory", "index", "--force"]),
            "retried"
        );
        assert_eq!(s.status().await.expect("s")["memory"]["indexError"], Value::Null);
    }

    #[tokio::test]
    async fn status_and_models() {
        let gw = Fake::new();
        *gw.config.lock().expect("lock") = json!({
            "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol", "fallbacks": ["anthropic/claude-opus-5"] } } },
            "auth": { "profiles": { "openai:controlclaw": { "provider": "openai", "mode": "api_key" }, "anthropic:controlclaw": { "provider": "anthropic", "mode": "token" } } },
            "models": { "providers": { "openai-codex": { "api": "openai-chatgpt-responses" } } },
        });
        let r = rig(gw.clone());
        let s = service(&r);
        let st = s.status().await.expect("status");
        assert_eq!(
            st["model"],
            json!({ "primary": "openai/gpt-5.6-sol", "fallbacks": ["anthropic/claude-opus-5"] })
        );
        assert_eq!(st["providers"], json!(["anthropic", "openai", "openai-codex"]));
        assert_eq!(
            st["auth"],
            json!([{ "provider": "openai", "status": "ok", "profiles": 1 }])
        );
        assert_eq!(
            st["memory"],
            json!({ "provider": null, "model": null, "dreaming": true, "indexError": null })
        );
        let ids: Vec<Value> = s
            .models("openai")
            .await
            .expect("m")
            .iter()
            .map(|m| m["id"].clone())
            .collect();
        assert_eq!(ids, [json!("openai/gpt-5.6-sol"), json!("openai/gpt-5.4-mini")]);
    }

    #[tokio::test]
    async fn the_phones_reply_model_follows_the_primary_in_the_same_patch() {
        let gw = Fake::new();
        *gw.config.lock().expect("lock") = json!({ "plugins": { "entries": { "voice-call": { "config": { "twilio": { "authToken": "CC-TWILIO-abc" } } } } } });
        let r = rig(gw.clone());
        let s = LlmService::new(
            r.deps.clone(),
            None,
            None,
            Some(Arc::new(crate::phone::model::phone_model_entry)),
        )
        .with_bin("/fake/openclaw");
        s.apply(&input(
            json!({ "model": { "primary": "openai/gpt-5.6-sol", "fallbacks": [] }, "credentials": [], "remove": [] }),
        ))
        .await
        .expect("ok");
        let patch = gw.patches().pop().expect("patch");
        assert!(patch["plugins"]["entries"]["voice-call"].is_object(), "{patch}");
        // No phone on the box: no entry.
        *gw.config.lock().expect("lock") = json!({});
        s.apply(&input(
            json!({ "model": { "primary": "openai/gpt-5.6-sol", "fallbacks": [] }, "credentials": [], "remove": [] }),
        ))
        .await
        .expect("ok");
        assert!(gw.patches().pop().expect("patch").get("plugins").is_none());
    }

    #[tokio::test]
    async fn openclaw_down_is_not_running() {
        let gw = Fake::new();
        gw.connected.store(false, Ordering::SeqCst);
        let r = rig(gw.clone());
        let e = service(&r).apply(&input(apply_body())).await.expect_err("down");
        assert_eq!(e.message, "OpenClaw is not running on this box");
    }

    /// The real merge-patch fake, which refuses a shrinking list the way OpenClaw does.
    fn real(initial: Value) -> (FakeOpenClawConfig, Arc<FakeConfigGateway>) {
        let oc = FakeOpenClawConfig::new(initial, None, false);
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        gw.hook(|m, _| (m == "models.authStatus").then(|| Ok(json!({ "providers": [] }))));
        (oc, gw)
    }

    #[tokio::test]
    async fn prod_fallback_replaced_and_included_dropped_get_past_the_array_check() {
        let included = "controlclaw/anthropic/claude-sonnet-5@controlclaw:included";
        let (oc, gw) = real(json!({
            "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw", "fallbacks": [included] } } },
            "models": { "providers": { "controlclaw": included_block() } },
        }));
        let r = rig(gw);
        let s = service(&r);
        let openai = json!({ "provider": "openai", "kind": "api_key", "profileId": "openai:controlclaw", "value": "sk-cc-x", "model": "openai/gpt-5.6-sol@openai:controlclaw" });
        let anthropic = json!({ "provider": "anthropic", "kind": "api_key", "profileId": "anthropic:controlclaw", "value": "sk-ant-cc-x", "model": "anthropic/claude-opus-5@anthropic:controlclaw" });
        s.apply(&input(json!({ "model": { "primary": openai["model"], "fallbacks": [anthropic["model"]] }, "credentials": [openai, anthropic], "remove": [{ "provider": "controlclaw", "profileId": "controlclaw:included", "kind": "api_key", "providerBlock": true }] })))
            .await
            .expect("ok");
        assert_eq!(
            oc.config()["agents"]["defaults"]["model"]["fallbacks"],
            json!([anthropic["model"]])
        );
        assert_eq!(
            oc.config()["models"]["providers"].get("controlclaw"),
            None,
            "the included block is gone"
        );
        s.apply(&input(json!({ "model": { "primary": openai["model"], "fallbacks": [] }, "credentials": [openai], "remove": [{ "provider": "anthropic", "profileId": "anthropic:controlclaw", "kind": "api_key" }] })))
            .await
            .expect("ok");
        assert_eq!(oc.config()["agents"]["defaults"]["model"]["fallbacks"], json!([]));
        s.apply(&input(
            json!({ "model": { "primary": null, "fallbacks": [] }, "credentials": [], "remove": [] }),
        ))
        .await
        .expect("ok");
        assert_eq!(oc.config()["agents"]["defaults"].get("model"), None);
    }

    #[tokio::test]
    async fn a_shorter_plan_replaces_the_block_list_and_status_reports_the_compat() {
        let (oc, gw) = real(json!({ "models": { "providers": { "controlclaw": included_block() } } }));
        let r = rig(gw);
        let s = service(&r);
        let ids: Vec<Value> = included_block()["models"]
            .as_array()
            .expect("m")
            .iter()
            .map(|m| json!({ "id": m["id"], "compat": null }))
            .collect();
        assert_eq!(
            s.status().await.expect("s")["blocks"],
            json!([{ "provider": "controlclaw", "models": ids }])
        );
        let mut smaller = included_block();
        smaller["models"] = json!([{ "id": "moonshotai/kimi-k2.6", "name": "Kimi K2.6", "compat": { "supportsPromptCacheKey": true } }]);
        let refm = "controlclaw/moonshotai/kimi-k2.6@controlclaw:included";
        s.apply(&input(json!({ "model": { "primary": refm, "fallbacks": [] }, "credentials": [{ "provider": "controlclaw", "kind": "api_key", "profileId": "controlclaw:included", "value": "vck-cc-x", "model": refm, "providerBlock": smaller }], "remove": [] })))
            .await
            .expect("ok");
        assert_eq!(
            oc.config()["models"]["providers"]["controlclaw"]["models"],
            smaller["models"]
        );
        assert_eq!(
            s.status().await.expect("s")["blocks"],
            json!([{ "provider": "controlclaw", "models": [{ "id": "moonshotai/kimi-k2.6", "compat": { "supportsPromptCacheKey": true } }] }])
        );
    }
}
