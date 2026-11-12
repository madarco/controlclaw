//! The sync that writes the proxy's config (`sync.ts`, `runSync` and its helpers in `index.ts`):
//! the sealed record from the control plane, opened with the box key, then the egress rules, the
//! webhook registrations and the identity map, then everything this firewall holds itself: who is
//! on the tailnet, under an emergency stop or in an update window, each module's credentials, and
//! the residential exit. Written whole into `/run/mitm/config`, a tmpfs, so secrets stay in RAM.
//!
//! Byte for byte as the TS writes them: `JSON.stringify(v, null, 2)`, `.<name>.tmp` then rename,
//! 0600, keys in the order they came.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use cc_contracts::files::FileSpec;
use cc_crypto::secret_store::Ids;
use cc_http::BoxFuture;
use serde_json::{Map, Value};

use super::env::CoreEnv;
use super::identities::{Agents, vm_id_of};
use super::store_client::StoreClient;
use crate::app::App;

/// The proxy config: the opened record's object, with the fields the sync sets.
pub type ProxyConfig = Map<String, Value>;

/// Who is under an emergency stop, from the kill store (C4).
pub trait KillLocks: Send + Sync {
    /// `lockedVmIds`: which of `vm_ids` are locked (all of them when the whole organization is).
    fn locked_vm_ids(&self, vm_ids: &[String]) -> Vec<String>;
    /// `codeWindows`: until when (epoch seconds) a locked box may still reach its channel.
    fn code_windows(&self) -> Map<String, Value>;
}

type Hook<T> = OnceLock<Arc<T>>;
type WebhookSync = dyn Fn(Value) -> BoxFuture<Result<(), String>> + Send + Sync;
type Rows = Result<Vec<Value>, String>;
/// The reply's `auto_approve`, for the Auto approve rules (`auto_approve.rs`).
type AutoApproveSync = dyn Fn(Option<&Value>) + Send + Sync;

/// What the later parts of the core put into the config. Each is set once, when its module starts.
///
/// These, and every `CredentialContributor`, are called while the sync holds its lock on the last
/// config: never call into the `Syncer` (a sync, `replace_credentials`) from one of them, and never
/// hold one of your own locks that a call into the `Syncer` could also be waiting on.
#[derive(Default)]
pub struct SyncHooks {
    /// `tailscale.enabledVmIds()`.
    pub tailscale: Hook<dyn Fn() -> Vec<String> + Send + Sync>,
    pub kill: Hook<dyn KillLocks>,
    /// `updates.windows()`: vm id to the end of its update window (epoch seconds).
    pub update_windows: Hook<dyn Fn() -> Map<String, Value> + Send + Sync>,
    /// `exitFirewall.exitConfig()`.
    pub exit_config: Hook<dyn Fn() -> Value + Send + Sync>,
    /// `webhook.sync` with the control plane's half of the registrations.
    pub webhook_sync: Hook<WebhookSync>,
    /// The reply's `auto_approve` (None when the control plane does not send it).
    pub auto_approve: Hook<AutoApproveSync>,
    /// Whether the Auto approve store was seeded: the rules request says so, and a firewall whose
    /// store was lost or never seeded gets the console's copy again.
    pub auto_approve_seeded: Hook<dyn Fn() -> bool + Send + Sync>,
}

pub struct Syncer {
    pub app: Arc<App>,
    pub env: CoreEnv,
    pub client: StoreClient,
    pub agents: Arc<Agents>,
    pub hooks: SyncHooks,
    ids: Ids,
    dir: PathBuf,
    /// The config the last successful sync wrote. Holds secrets, so it stays in memory; used to
    /// put a lockdown or an update window into the proxy when the control plane cannot be reached.
    last: Mutex<Option<ProxyConfig>>,
    /// The control plane's own credentials in `last`, before this box's modules added theirs:
    /// what a credentials change rebuilds from when the control plane cannot be reached. Taken
    /// after `last`, never before.
    console_creds: Mutex<Option<Value>>,
    /// A standalone firewall's syncs, one at a time: the panel wakes one while the timer's may be
    /// running, and the older must not write its rules after the newer.
    standalone_runs: tokio::sync::Mutex<()>,
    /// The AI review settings from the last policy (`policy.ai`), as sent.
    ai: RwLock<Value>,
}

/// `[...a, ...b]` where `a` may be missing.
fn spread(existing: Option<&Value>, more: Vec<Value>) -> Result<Vec<Value>, String> {
    let mut out = match existing {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("cfg.credentials is not iterable".into()),
    };
    out.extend(more);
    Ok(out)
}

/// `(rows ?? []).map(…)`: anything but a list (or nothing) throws in the TS, failing the sync.
fn rows_of(v: Option<&Value>) -> Result<Vec<Value>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(_) => Err("identities.map is not a function".into()),
    }
}

fn array_or_empty(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

/// `({ locked, code_until, ...i }) => i` on one row of the map.
fn without(row: &Value, keys: &[&str]) -> Result<Map<String, Value>, String> {
    match row {
        Value::Object(o) => Ok(o
            .iter()
            .filter(|(k, _)| !keys.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()),
        Value::Null => Err("Cannot destructure 'i' as it is null.".into()),
        _ => Ok(Map::new()),
    }
}

// The publishers are the kill switch's (C4) and the updates' (C6); `replace_credentials` is
// for secrets and logins (W4, W5).
#[allow(dead_code)]
impl Syncer {
    pub fn new(app: Arc<App>, env: CoreEnv, client: StoreClient, agents: Arc<Agents>) -> Self {
        Self {
            ids: Ids {
                org_id: app.config.org_id.clone(),
                box_id: app.config.box_id.clone(),
            },
            dir: app.config.proxy_config_dir.clone(),
            app,
            env,
            client,
            agents,
            hooks: SyncHooks::default(),
            last: Mutex::new(None),
            console_creds: Mutex::new(None),
            standalone_runs: tokio::sync::Mutex::new(()),
            ai: RwLock::new(Value::Null),
        }
    }

    /// `RULES_URL`, with `auto_approve=seeded|unseeded` on a console firewall (a standalone one seeds
    /// itself).
    fn rules_request_url(&self) -> String {
        let url = &self.env.rules_url;
        match self.hooks.auto_approve_seeded.get() {
            Some(seeded) if self.app.config.mode.saas() && (url.starts_with("http") || url.starts_with("local:")) => {
                let sep = if url.contains('?') { '&' } else { '?' };
                format!(
                    "{url}{sep}auto_approve={}",
                    if seeded() { "seeded" } else { "unseeded" }
                )
            }
            _ => url.clone(),
        }
    }

    /// The AI review settings the last sync read (`aiSettings`), parsed.
    pub fn ai_settings(&self) -> Option<cc_llm::AiSettings> {
        cc_llm::AiSettings::parse(&self.ai.read().map(|a| a.clone()).unwrap_or(Value::Null))
    }

    /// The config the last sync wrote (`lastProxyConfig`).
    pub fn last(&self) -> Option<ProxyConfig> {
        self.lock_last().clone()
    }

    /// `runSync`. Syncs are not queued behind each other (an emergency stop must not wait for a
    /// sync stuck on the control plane), as in the TS; what this box holds itself is read and
    /// written under the `last` lock, so a write in between (a revoked secret) is never undone by
    /// an older snapshot.
    pub async fn run(&self) -> Result<(), String> {
        // Not in SaaS mode (see above); a standalone firewall's control plane is this process.
        let _one = match self.app.config.mode.saas() {
            true => None,
            false => Some(self.standalone_runs.lock().await),
        };
        let record = self.client.fetch_record(&self.env.store_url).await?;
        let mut cfg: ProxyConfig = match &record {
            Some(r) => {
                let plain =
                    cc_crypto::secret_store::open_with_box_key(r, &self.app.box_key, &self.ids).map_err(|e| e.0)?;
                match serde_json::from_str::<Value>(&plain).map_err(|e| e.to_string())? {
                    Value::Object(o) => o,
                    _ => return Err("the store record is not an object".into()),
                }
            }
            None => {
                let mut m = Map::new();
                m.insert("credentials".into(), Value::Array(Vec::new()));
                m.insert("rules".into(), Value::Array(Vec::new()));
                m
            }
        };

        if !self.env.rules_url.is_empty() {
            // A standalone firewall's rules file that is gone, does not parse or holds no list of
            // rules is not "no rules": the sync fails, so the proxy keeps the last rules it has, or,
            // with none yet, has no rules file and refuses every request.
            let standalone_file = self
                .env
                .rules_url
                .strip_prefix("file:")
                .filter(|_| self.app.config.mode.standalone());
            // Written as it came, a list or not (`cfg.rules = policy.rules`).
            let (rules, ai, auto) = match standalone_file {
                Some(path) => read_rules_file(path.strip_prefix("//").unwrap_or(path))?,
                None => self.client.fetch_policy(&self.rules_request_url()).await?,
            };
            cfg.insert("rules".into(), rules);
            if let Some(f) = self.hooks.auto_approve.get() {
                f(auto.as_ref());
            }
            if let Ok(mut a) = self.ai.write() {
                *a = ai;
            }
        }
        // The control plane's half of the webhook registrations, through `webhook.sync`, which
        // enforces what a sync may change. A failure here does not fail the sync.
        if !self.env.webhooks_url.is_empty()
            && let Some(sync) = self.hooks.webhook_sync.get()
        {
            let done = match self.client.fetch_list(&self.env.webhooks_url, "hooks").await {
                Ok(hooks) => sync(hooks).await,
                Err(e) => Err(e),
            };
            if let Err(e) = done {
                tracing::error!("[webhooks] could not pull the registration list: {e}");
            }
        }
        if !self.env.identities_url.is_empty() {
            let rows = self.client.fetch_list(&self.env.identities_url, "identities").await?;
            cfg.insert("identities".into(), rows.clone());
            let list = rows.as_array().cloned().unwrap_or_default();
            self.agents.set(&list);
            // The TS maps over the map next; anything but a list fails the sync there, and the
            // files the proxy has stay as they were.
            if !rows.is_array() {
                return Err("cfg.identities.map is not a function".into());
            }
        }
        let mut last = self.lock_last();
        let console_creds = cfg.get("credentials").cloned();
        // What this box holds itself, read under the lock. Another part's hook that panics fails
        // this sync only: the lock is not poisoned and the proxy keeps its files.
        let local = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.local(&mut cfg)));
        match local {
            Ok(r) => r?,
            Err(_) => return Err("a module's part of the config failed".into()),
        }
        write_proxy_config(&self.dir, &cfg).map_err(|e| e.to_string())?;
        if let Some(c) = cfg.get("credentials") {
            cc_crypto::enc_file::remember_encrypted_secrets(c, false);
        }
        *last = Some(cfg.clone());
        *self.console_creds.lock().unwrap_or_else(|e| e.into_inner()) = console_creds;
        drop(last);
        let ids = array_or_empty(cfg.get("identities"));
        let locked = ids
            .iter()
            .filter(|i| i.get("locked") == Some(&Value::Bool(true)))
            .count();
        let ai = match self.ai_settings() {
            Some(s) => format!(
                "{}/{} (checks {}, log review {})",
                s.provider.as_str(),
                s.model,
                if s.checks { "on" } else { "off" },
                if s.log_review { "on" } else { "off" }
            ),
            None => "off".into(),
        };
        let exit_on = cfg.get("exit").and_then(|e| e.get("enabled")).is_some_and(js_truthy);
        tracing::info!(
            "[mitm-agent] synced v{}: {} creds, {} rules, {} identities{}, ai {ai}, residential exit {}",
            record.as_ref().map(|r| r.version).unwrap_or(0),
            length(cfg.get("credentials")),
            length(cfg.get("rules")),
            ids.len(),
            if locked > 0 {
                format!(" ({locked} under an emergency stop)")
            } else {
                String::new()
            },
            if exit_on { "on" } else { "off" }
        );
        Ok(())
    }

    /// The parts of the config this box holds itself (`runSync` after the fetches): the tailnet,
    /// the emergency stop, the update windows, each module's credentials, the exit.
    fn local(&self, cfg: &mut ProxyConfig) -> Result<(), String> {
        // Who is on the owner's tailnet, from this box's own store: the firewall took the
        // confirmation, so the firewall says who the hole is for.
        // Until the Tailscale module runs nobody is on it: a flag the control plane sent is never
        // passed on, or the proxy would let that agent through to `*.tailscale.com` uninspected.
        let rows = self.with_tailscale(cfg.get("identities"))?;
        cfg.insert("identities".into(), Value::Array(rows));
        let rows = self.with_kill_switch(cfg.get("identities"))?;
        cfg.insert("identities".into(), Value::Array(rows));
        let rows = self.with_update_windows(cfg.get("identities"))?;
        cfg.insert("identities".into(), Value::Array(rows));
        // Which boxes trust this firewall's CA for the control plane, from this box's own
        // observation (`cp_inspect`); a value the control plane sent is dropped.
        let rows = self.app.cp_inspect.apply(&rows_of(cfg.get("identities"))?);
        cfg.insert("identities".into(), Value::Array(rows));
        // The organisation, for the proxy's backup check (`<org id>/…` keys): ORG_ID, which a
        // ready-pool claim sets, not MITM_TENANT, which a claim leaves as it was.
        cfg.insert("orgId".into(), Value::String(self.app.config.org_id.clone()));

        self.with_contributors(cfg)?;
        // The residential exit, from this box's store: it carries the upstream password, which the
        // control plane has never seen. Without one every residential rule fails closed.
        let exit = match self.hooks.exit_config.get() {
            Some(f) => f(),
            None => serde_json::json!({"enabled": false}),
        };
        cfg.insert("exit".into(), exit);
        Ok(())
    }

    /// Each module's credentials after the control plane's, the search keys last.
    fn with_contributors(&self, cfg: &mut ProxyConfig) -> Result<(), String> {
        let mut appended = false;
        let mut creds = Vec::new();
        for c in self.app.contracts.credentials.sorted() {
            if c.order() == crate::contracts::CredentialOrder::Search {
                continue;
            }
            appended = true;
            creds.extend(c.credentials());
        }
        if appended {
            let all = spread(cfg.get("credentials"), creds)?;
            cfg.insert("credentials".into(), Value::Array(all));
        }
        if let Some(search) = self
            .app
            .contracts
            .credentials
            .sorted()
            .into_iter()
            .find(|c| c.order() == crate::contracts::CredentialOrder::Search)
        {
            let all = spread(cfg.get("credentials"), search.credentials())?;
            cfg.insert("credentials".into(), Value::Array(all));
        }

        Ok(())
    }

    fn lock_last(&self) -> std::sync::MutexGuard<'_, Option<ProxyConfig>> {
        self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The `tailscale` flag on every row, from this box's own store.
    fn with_tailscale(&self, identities: Option<&Value>) -> Result<Vec<Value>, String> {
        let joined = self.hooks.tailscale.get().map(|enabled| enabled()).unwrap_or_default();
        rows_of(identities)?
            .iter()
            .map(|i| {
                let mut row = without(i, &[])?;
                let on = joined.contains(&vm_id_of(&row));
                row.insert("tailscale".into(), Value::Bool(on));
                Ok(Value::Object(row))
            })
            .collect()
    }

    /// `withKillSwitch`: `locked` (and `code_until`) from the kill store; whatever the control
    /// plane put there is dropped, so nothing it sends can cut an agent off or let one back out.
    pub fn with_kill_switch(&self, identities: Option<&Value>) -> Result<Vec<Value>, String> {
        let entries = rows_of(identities)?
            .iter()
            .map(|i| without(i, &["locked", "code_until"]))
            .collect::<Result<Vec<_>, String>>()?;
        let Some(kill) = self.hooks.kill.get() else {
            return Ok(entries.into_iter().map(Value::Object).collect());
        };
        let ids: Vec<String> = entries.iter().map(vm_id_of).collect();
        let locked = kill.locked_vm_ids(&ids);
        let windows = kill.code_windows();
        Ok(entries
            .into_iter()
            .map(|mut i| {
                let vm_id = vm_id_of(&i);
                if locked.contains(&vm_id) {
                    i.insert("locked".into(), Value::Bool(true));
                    if let Some(until) = windows.get(&vm_id).filter(|v| js_truthy(v)) {
                        i.insert("code_until".into(), until.clone());
                    }
                }
                Value::Object(i)
            })
            .collect())
    }

    /// `withUpdateWindows`: each box's update deadline from this box's own state.
    pub fn with_update_windows(&self, identities: Option<&Value>) -> Result<Vec<Value>, String> {
        let open = self.hooks.update_windows.get().map(|f| f()).unwrap_or_default();
        rows_of(identities)?
            .iter()
            .map(|i| {
                let mut row = without(i, &["update_until"])?;
                if let Some(until) = open.get(&vm_id_of(&row)).filter(|v| js_truthy(v)) {
                    row.insert("update_until".into(), until.clone());
                }
                Ok(Value::Object(row))
            })
            .collect()
    }

    /// Write `cfg` with its identities rewritten by `f`, and keep it (the fallback when a sync
    /// cannot run: nothing in it came from the failed request).
    fn rewrite_last(&self, f: impl Fn(&Self, Option<&Value>) -> Rows) -> Result<(), String> {
        let mut last = self.lock_last();
        let Some(cfg) = last.as_mut() else {
            return Err("no config written yet".into());
        };
        let rows = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self, cfg.get("identities"))))
            .map_err(|_| "a module's part of the config failed".to_string())??;
        cfg.insert("identities".into(), Value::Array(rows));
        write_proxy_config(&self.dir, cfg).map_err(|e| e.to_string())
    }

    /// A box newly recorded in `cp_inspect`: the last config's identity map rewritten with it.
    pub fn publish_cp_inspect(&self) -> Result<(), String> {
        self.rewrite_last(|s, ids| Ok(s.app.cp_inspect.apply(&rows_of(ids)?)))
    }

    /// `publishKillSwitch`: a full sync, or the last config with the lockdown applied when the
    /// control plane cannot be reached. An emergency stop must not fail because a rules fetch did.
    pub async fn publish_kill_switch(&self) -> Result<(), String> {
        if let Err(e) = self.run().await {
            if self.last().is_none() {
                return Err(e);
            }
            tracing::error!("[mitm-agent] sync failed ({e}); writing the emergency stop into the last config");
            self.rewrite_last(|s, ids| s.with_kill_switch(ids))?;
        }
        Ok(())
    }

    /// A full sync, or the last config with what this box holds itself rewritten when the control
    /// plane cannot be reached: the tailnet, the stop and the update windows on the rows, and the
    /// exit. For a Tailscale or exit change, which must reach the proxy whether or not the
    /// control plane answers (the TS only ran a sync).
    pub async fn publish_local(&self) -> Result<(), String> {
        if let Err(e) = self.run().await {
            if self.last().is_none() {
                return Err(e);
            }
            tracing::error!(
                "[mitm-agent] sync failed ({e}); writing this firewall's own settings into the last config"
            );
            self.rewrite_last(|s, ids| {
                let rows = s.with_tailscale(ids)?;
                let rows = s.with_kill_switch(Some(&Value::Array(rows)))?;
                s.with_update_windows(Some(&Value::Array(rows)))
            })?;
            let exit = match self.hooks.exit_config.get() {
                Some(f) => f(),
                None => serde_json::json!({"enabled": false}),
            };
            let mut last = self.lock_last();
            if let Some(cfg) = last.as_mut() {
                cfg.insert("exit".into(), exit);
                write_proxy_config(&self.dir, cfg).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// `onCredentialsChanged`, its first half: write the credentials again at once, from the last
    /// config (the control plane's credentials, then every module's as they are now), before any
    /// sync. A login or secret taken away leaves the proxy now, whether or not the control plane
    /// answers; the caller then runs a sync and only logs its failure. With no config written yet
    /// (a restart with the control plane down), `credentials.json` as it is on disk, with the
    /// website logins (`login_id`) replaced by the ones that exist now.
    pub fn write_credentials_now(&self) -> Result<(), String> {
        let mut last = self.lock_last();
        let Some(cfg) = last.as_mut() else {
            drop(last);
            return self.rewrite_logins_on_disk();
        };
        let console = self.console_creds.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut next = cfg.clone();
        match console {
            Some(c) => next.insert("credentials".into(), c),
            None => next.remove("credentials"),
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.with_contributors(&mut next)))
            .map_err(|_| "a module's credentials failed".to_string())??;
        write_proxy_config(&self.dir, &next).map_err(|e| e.to_string())?;
        if let Some(c) = next.get("credentials") {
            cc_crypto::enc_file::remember_encrypted_secrets(c, false);
        }
        *cfg = next;
        Ok(())
    }

    /// No sync since the start: the logins in the file the proxy reads are put right on their own.
    /// Nothing else in it is known to be this box's, so the rest stays until a sync.
    fn rewrite_logins_on_disk(&self) -> Result<(), String> {
        let path = self.dir.join(FileSpec::CREDENTIALS.name);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(());
        };
        let Ok(Value::Array(on_disk)) = serde_json::from_str::<Value>(&text) else {
            return Err("credentials.json is not a list".into());
        };
        let is_login = |c: &Value| c.get("login_id").is_some_and(js_truthy);
        let logins: Vec<Value> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.app
                .contracts
                .credentials
                .sorted()
                .iter()
                .flat_map(|c| c.credentials())
                .filter(is_login)
                .collect()
        }))
        .map_err(|_| "a module's credentials failed".to_string())?;
        let mut creds: Vec<Value> = on_disk.into_iter().filter(|c| !is_login(c)).collect();
        creds.extend(logins);
        let creds = Value::Array(creds);
        cc_contracts::write_atomic(&self.dir, &FileSpec::CREDENTIALS, &creds).map_err(|e| e.to_string())?;
        cc_crypto::enc_file::remember_encrypted_secrets(&creds, false);
        Ok(())
    }

    /// `publishUpdateWindows`: the same for an update window opening or closing.
    pub async fn publish_update_windows(&self) -> Result<(), String> {
        if let Err(e) = self.run().await {
            if self.last().is_none() {
                return Err(e);
            }
            tracing::error!("[mitm-agent] sync failed ({e}); writing the update windows into the last config");
            self.rewrite_last(|s, ids| s.with_update_windows(ids))?;
        }
        Ok(())
    }

    /// A module's credentials changed and must leave the proxy now, whether or not the control
    /// plane answers (secrets, logins): replace only that module's entries in the last config.
    /// With no config written yet, a full sync. `mine` is read under the lock, so an older list
    /// is never written after a newer one.
    pub async fn replace_credentials(
        &self,
        is_mine: impl Fn(&Value) -> bool,
        mine: impl FnOnce() -> Vec<Value>,
    ) -> Result<(), String> {
        {
            let mut last = self.lock_last();
            if let Some(cfg) = last.as_mut() {
                let mine = std::panic::catch_unwind(std::panic::AssertUnwindSafe(mine))
                    .map_err(|_| "a module's credentials failed".to_string())?;
                let mut creds: Vec<Value> = array_or_empty(cfg.get("credentials"))
                    .into_iter()
                    .filter(|c| !is_mine(c))
                    .collect();
                creds.extend(mine);
                cfg.insert("credentials".into(), Value::Array(creds));
                return write_proxy_config(&self.dir, cfg).map_err(|e| e.to_string());
            }
        }
        self.run().await
    }
}

/// JavaScript truthiness of a JSON value.
/// A standalone firewall's panel changed its rules or AI settings: sync now, not at the next tick.
pub static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

pub fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// `.length` of an array, as the log line counts it (0 for anything else).
fn length(v: Option<&Value>) -> usize {
    v.and_then(Value::as_array).map(Vec::len).unwrap_or(0)
}

/// `writeProxyConfig`: the four files, in the TS order.
/// `org.json`, written as the TS's `writeAtomic` writes the other proxy files.
const ORG_FILE: FileSpec = FileSpec {
    name: "org.json",
    tmp: cc_contracts::files::TmpName::HiddenPrefix,
    pretty: true,
    mode: 0o600,
};

pub fn write_proxy_config(dir: &std::path::Path, cfg: &ProxyConfig) -> std::io::Result<()> {
    let or = |key: &str, default: Value| match cfg.get(key) {
        None | Some(Value::Null) => default,
        Some(v) => v.clone(),
    };
    cc_contracts::write_atomic(
        dir,
        &FileSpec::CREDENTIALS,
        &or("credentials", Value::Array(Vec::new())),
    )?;
    cc_contracts::write_atomic(dir, &FileSpec::RULES, &or("rules", Value::Array(Vec::new())))?;
    cc_contracts::write_atomic(dir, &FileSpec::IDENTITIES, &or("identities", Value::Array(Vec::new())))?;
    cc_contracts::write_atomic(dir, &FileSpec::EXIT, &or("exit", serde_json::json!({"enabled": false})))?;
    // `org.json` for the proxy. No ORG_ID (an unclaimed pool firewall) means no organisation: the
    // file goes, so a previous one's id cannot let its archives through.
    let org = dir.join("org.json");
    match cfg.get("orgId").and_then(Value::as_str).filter(|o| !o.is_empty()) {
        Some(o) => cc_contracts::write_atomic(dir, &ORG_FILE, &serde_json::json!({"org_id": o})),
        None => match std::fs::remove_file(&org) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
    }
}

/// A standalone firewall's own rules file, read once: a list of rules, or `{"rules": [...], "ai"?}`.
/// Anything else (missing, not JSON, `{}`, `{"rules": null}`, a misspelled key) is the reason the
/// sync fails; an empty list is the way to allow every host. The rules, the AI settings and the
/// Auto approve part, which a file does not need (a standalone firewall keeps those itself).
pub fn read_rules_file(path: &str) -> Result<(Value, Value, Option<Value>), String> {
    let keep = "the proxy keeps its last rules, or with none refuses every request";
    let text = std::fs::read_to_string(path).map_err(|e| format!("the rules file {path}: {e}: {keep}"))?;
    let v: Value =
        serde_json::from_str(&text).map_err(|e| format!("the rules file {path} is not JSON ({e}): {keep}"))?;
    match v {
        Value::Array(_) => Ok((v, Value::Null, None)),
        Value::Object(mut o) if o.get("rules").is_some_and(Value::is_array) => {
            let rules = o.remove("rules").unwrap_or_default();
            let auto = o.remove(cc_contracts::auto_approve::REPLY_KEY);
            Ok((rules, o.remove("ai").unwrap_or(Value::Null), auto))
        }
        _ => Err(format!(
            "the rules file {path} has no list of rules (a list, or {{\"rules\": [...]}}): {keep}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `org.json` from ORG_ID for the proxy's backup check; gone when there is none.
    #[test]
    fn org_json_follows_the_org_id() {
        let d = tempfile::tempdir().expect("dir");
        let mut cfg = ProxyConfig::new();
        cfg.insert("orgId".into(), json!("org1"));
        write_proxy_config(d.path(), &cfg).expect("write");
        let read = || std::fs::read_to_string(d.path().join("org.json")).ok();
        assert_eq!(
            read().map(|t| serde_json::from_str::<Value>(&t).expect("json")),
            Some(json!({"org_id": "org1"}))
        );
        cfg.insert("orgId".into(), json!(""));
        write_proxy_config(d.path(), &cfg).expect("write");
        assert_eq!(read(), None);
        write_proxy_config(d.path(), &cfg).expect("a missing file stays missing");
    }

    #[test]
    fn writes_what_the_ts_writes() {
        let d = tempfile::tempdir().expect("dir");
        let mut cfg = Map::new();
        cfg.insert("credentials".into(), json!([{"placeholder": "x", "secret": "y"}]));
        cfg.insert("rules".into(), json!([]));
        write_proxy_config(d.path(), &cfg).expect("write");
        let read = |n: &str| std::fs::read_to_string(d.path().join(n)).expect("read");
        assert_eq!(
            read("credentials.json"),
            "[\n  {\n    \"placeholder\": \"x\",\n    \"secret\": \"y\"\n  }\n]"
        );
        assert_eq!(read("rules.json"), "[]");
        assert_eq!(read("identities.json"), "[]");
        assert_eq!(read("exit.json"), "{\n  \"enabled\": false\n}");
    }

    struct Mine(std::sync::Mutex<Vec<Value>>);

    impl crate::contracts::CredentialContributor for Mine {
        fn order(&self) -> crate::contracts::CredentialOrder {
            crate::contracts::CredentialOrder::Logins
        }
        fn credentials(&self) -> Vec<Value> {
            self.0.lock().expect("l").clone()
        }
    }

    #[tokio::test]
    async fn a_credential_taken_away_leaves_the_proxy_without_the_control_plane() {
        let d = tempfile::tempdir().expect("dir");
        let app = crate::integrations::testing::app(d.path());
        let mine = Arc::new(Mine(std::sync::Mutex::new(vec![
            json!({"placeholder": "login-1", "login_id": "l1"}),
            json!({"placeholder": "login-2", "login_id": "l2"}),
        ])));
        app.contracts.credentials.add(mine.clone());
        let ids = d.path().join("identities.json");
        std::fs::write(&ids, "[]").expect("w");
        let mut env = CoreEnv::from_env(&app.config.proxy_config_dir);
        env.store_url = format!("file:{}", d.path().join("store.json").display());
        env.rules_url = String::new();
        env.webhooks_url = String::new();
        env.identities_url = format!("file:{}", ids.display());
        let client = || StoreClient {
            http: app.http.clone(),
            keys: app.keys.clone(),
            token: false,
        };
        let sync = Syncer::new(app.clone(), env.clone(), client(), Arc::new(Agents::default()));
        let file = app.config.proxy_config_dir.join("credentials.json");
        let creds = || std::fs::read_to_string(&file).expect("read");
        sync.run().await.expect("sync");
        assert!(creds().contains("login-1") && creds().contains("login-2"));

        // Taken away while the control plane cannot be reached: written before any sync.
        std::fs::write(&ids, "not json").expect("w");
        mine.0.lock().expect("l").remove(0);
        sync.write_credentials_now().expect("write");
        assert!(!creds().contains("login-1") && creds().contains("login-2"));
        assert!(
            sync.last()
                .is_some_and(|c| c["credentials"].as_array().is_some_and(|a| a.len() == 1))
        );
        assert!(sync.run().await.is_err(), "the sync after it still fails");
        assert!(!creds().contains("login-1"));

        // After a restart, nothing synced yet and the control plane still down: the file on disk,
        // its logins put right, anything else left as it was.
        let mut on_disk: Vec<Value> = serde_json::from_str(&creds()).expect("json");
        on_disk.push(json!({"placeholder": "console-1"}));
        std::fs::write(&file, serde_json::to_string(&on_disk).expect("s")).expect("w");
        mine.0.lock().expect("l").clear();
        let restarted = Syncer::new(app.clone(), env, client(), Arc::new(Agents::default()));
        restarted.write_credentials_now().expect("write");
        assert!(!creds().contains("login-2") && creds().contains("console-1"));
    }

    #[test]
    fn strips_keys_in_place() {
        let row = json!({"vm_id": "a", "locked": true, "x": 1, "code_until": 5});
        let out = without(&row, &["locked", "code_until"]).expect("row");
        assert_eq!(Value::Object(out), json!({"vm_id": "a", "x": 1}));
        assert!(without(&Value::Null, &[]).is_err());
        assert_eq!(without(&json!(3), &[]).expect("row"), Map::new());
    }
}
