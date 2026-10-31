//! Phone setup (`PhoneService` in `phone.ts`, `phone-setup.ts`): install and patch the pinned
//! voice-call plugin, write its config through the gateway's write queue, restart OpenClaw, and
//! wait until the plugin answers a signed status callback.
//!
//! An apply returns at once with a `pending` record; the work runs in the background, one apply at
//! a time. A newer apply replaces the record the firewall sees; the older one finishes unseen.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine;
use cc_http::BoxFuture;
use cc_openclaw::config_queue::{ConfigWriter, GATEWAY_READ, PatchOptions, config_active};
use cc_proc::{Cmd, Runner};
use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha512};

use super::apply::{
    PHONE_INTEGRITY, PHONE_PACKAGE, phone_config, phone_config_matches, stream_binding, trusted_phone_install,
};
use super::history::now_ms;
use super::model::phone_response_model;
use super::stream::StreamBinding;

/// OpenClaw waits up to ten minutes for its lifecycle lease. Leave bounded time to install after
/// acquiring it; never delete or steal another operation's lease.
pub const PHONE_PLUGIN_INSTALL: Duration = Duration::from_secs(15 * 60);
const CONFIG_PATCH_RESTART: Duration = Duration::from_secs(45);

/// Why a setup failed, as the fixed codes of `@controlclaw/phone`; `Other` is any other failure,
/// which the step it happened in names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupError {
    Code(&'static str),
    Other(String),
}

impl SetupError {
    fn code(&self) -> &'static str {
        match self {
            SetupError::Code(c) => c,
            SetupError::Other(_) => "phone_setup_failed",
        }
    }
}

/// `phoneSetupStep`: a failure in the step is its code, unless it already has one.
fn step<T>(code: &'static str, r: Result<T, SetupError>) -> Result<T, SetupError> {
    r.map_err(|e| match e {
        SetupError::Code(c) => SetupError::Code(c),
        SetupError::Other(_) => SetupError::Code(code),
    })
}

static LEASE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)OPENCLAW_STATE_LEASE_HELD|plugin lifecycle lease[^\n]*held by").expect("regex"));

/// `runPhonePluginMutation`: an OpenClaw plugin command, failing only with a fixed code, never
/// with what the command printed.
pub async fn run_plugin_mutation(runner: &dyn Runner, args: &[&str]) -> Result<String, SetupError> {
    let cmd = Cmd::new("/usr/bin/openclaw")
        .args(args.iter().copied())
        .timeout(PHONE_PLUGIN_INSTALL);
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(out.stdout_str()),
        Ok(out) => {
            let text = format!("{}\n{}", out.stderr_str(), out.stdout_str());
            Err(SetupError::Code(if LEASE.is_match(&text) {
                "plugin_busy"
            } else {
                "plugin_install_failed"
            }))
        }
        Err(e) => Err(SetupError::Code(if LEASE.is_match(&e.to_string()) {
            "plugin_busy"
        } else {
            "plugin_install_failed"
        })),
    }
}

/// A command whose failure is just a failure (`defaultExec` rejecting).
async fn exec(runner: &dyn Runner, cmd: Cmd) -> Result<String, SetupError> {
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(out.stdout_str()),
        Ok(out) => Err(SetupError::Other(out.stderr_str())),
        Err(e) => Err(SetupError::Other(e.to_string())),
    }
}

/// Setup failures a busy or restarting OpenClaw causes; worth a retry once an update settles.
pub const TRANSIENT: &[&str] = &[
    "plugin_busy",
    "plugin_install_failed",
    "gateway_unavailable",
    "activation_timeout",
    "listener_unavailable",
];

pub type WriterFn = Arc<dyn Fn() -> Option<Arc<ConfigWriter>> + Send + Sync>;
pub type HookFn = Arc<dyn Fn() -> BoxFuture<Result<(), SetupError>> + Send + Sync>;
pub type ProbeFn = Arc<dyn Fn(Value) -> BoxFuture<bool> + Send + Sync>;

/// What settling reads (`settleAfterUpdate` in index.ts): the agent Update's status, and whether
/// OpenClaw's gateway answers.
#[derive(Clone)]
pub struct Settle {
    pub update: Arc<dyn Fn() -> Value + Send + Sync>,
    pub gateway_ready: Arc<dyn Fn(Duration) -> BoxFuture<bool> + Send + Sync>,
    /// How to wait; tokio's clock when `None` (a test passes its own).
    pub sleep: Option<SleepFn>,
}

pub type SleepFn = Arc<dyn Fn(Duration) -> BoxFuture<()> + Send + Sync>;

/// A setup that newer settings replaced while it waited out an Update.
const REPLACED: &str = "Replaced by newer settings";

/// Ends once an apply other than `id` has started.
async fn until_replaced(mut current: tokio::sync::watch::Receiver<u64>, id: u64) {
    let _ = current.wait_for(|c| *c != id).await;
}

/// What the service uses; tests replace the parts that reach outside.
pub struct Deps {
    /// The gateway's write queue, read at each apply (W6 fills the slot after this registers).
    pub writer: WriterFn,
    pub runner: Arc<dyn Runner>,
    /// `runAction("restart")` for the unit in `CC_SERVICE`.
    pub restart: Arc<dyn Fn() -> BoxFuture<()> + Send + Sync>,
    /// Stands in for the plugin install (tests).
    pub install: Option<HookFn>,
    /// Stands in for the signed status callback (tests).
    pub probe: Option<ProbeFn>,
    /// Settings that became active, for the call history (`onActive`).
    pub on_active: Arc<dyn Fn(Map<String, Value>) + Send + Sync>,
    pub adapter_manifest: PathBuf,
    pub admission_dir: PathBuf,
    /// How long setup waits for the plugin to run the new config, and how often it looks.
    pub activation: Duration,
    pub poll: Duration,
    /// Waits out a running Update before applying, and retries what it broke (D16).
    pub settle: Option<Settle>,
}

impl Deps {
    pub fn new(
        writer: WriterFn,
        runner: Arc<dyn Runner>,
        restart: Arc<dyn Fn() -> BoxFuture<()> + Send + Sync>,
    ) -> Self {
        Self {
            writer,
            runner,
            restart,
            install: None,
            probe: None,
            on_active: Arc::new(|_| {}),
            adapter_manifest: "/opt/controlclaw/meeting-voice/openclaw.plugin.json".into(),
            admission_dir: "/usr/lib/node_modules/openclaw/dist".into(),
            activation: Duration::from_secs(300),
            poll: Duration::from_secs(2),
            settle: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Record {
    id: u64,
    generation: String,
    status: &'static str,
    error: Option<&'static str>,
}

impl Record {
    fn json(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("generation".into(), json!(self.generation));
        m.insert("status".into(), json!(self.status));
        if let Some(e) = self.error {
            m.insert("error".into(), json!(e));
        }
        m
    }
}

#[derive(Default)]
struct State {
    last: Option<Record>,
    /// `JSON.stringify(input)` of the apply that made `last`.
    last_input: String,
    /// The classic reply model the last apply wrote.
    reply_model: Option<String>,
    next_id: u64,
}

pub struct PhoneService {
    deps: Deps,
    state: Mutex<State>,
    /// One apply at a time, in the order they came (`this.serial`).
    serial: tokio::sync::Mutex<()>,
    /// The id of the last apply started, so a waiting apply wakes as soon as it is replaced.
    current: tokio::sync::watch::Sender<u64>,
}

impl PhoneService {
    pub fn new(deps: Deps) -> Arc<Self> {
        Arc::new(Self {
            deps,
            state: Mutex::default(),
            serial: tokio::sync::Mutex::new(()),
            current: tokio::sync::watch::Sender::new(0),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The last apply's record, for `/phone/status`.
    pub fn status(&self) -> Option<Map<String, Value>> {
        self.state().last.as_ref().map(Record::json)
    }

    /// Settings are active (the record says so); the page list reads it (`AgentPages`).
    pub fn active(&self) -> bool {
        self.state().last.as_ref().is_some_and(|r| r.status == "active")
    }

    /// The settings the stream relay checks against, while they are active (`streamBinding`).
    pub fn stream_binding(&self) -> Option<StreamBinding> {
        let st = self.state();
        if st.last.as_ref()?.status != "active" {
            return None;
        }
        let input: Value = serde_json::from_str(&st.last_input).ok()?;
        input["placeholder"].is_string().then(|| stream_binding(&input))
    }

    /// Start an apply; the record as it is now. The same pending settings again are not run twice.
    pub fn start(self: &Arc<Self>, input: Value) -> Map<String, Value> {
        let encoded = serde_json::to_string(&input).unwrap_or_default();
        let record = {
            let mut st = self.state();
            if let Some(last) = &st.last
                && last.status == "pending"
                && st.last_input == encoded
            {
                return last.json();
            }
            st.next_id += 1;
            let record = Record {
                id: st.next_id,
                generation: input["generation"].as_str().unwrap_or_default().to_string(),
                status: "pending",
                error: None,
            };
            st.last = Some(record.clone());
            st.last_input = encoded.clone();
            self.current.send_replace(record.id);
            record
        };
        let me = self.clone();
        let id = record.id;
        tokio::spawn(async move {
            let result = {
                let _turn = me.serial.lock().await;
                me.apply_settled(&input, id).await
            };
            let (note, failed, replaced) = {
                let mut st = me.state();
                let reply = st.reply_model.clone();
                // A newer apply may have replaced this record: then its outcome is not what the
                // firewall reads, but the settings did run, so the call history still notes them.
                let current = st.last.as_mut().filter(|r| r.id == id);
                let replaced = current.is_none();
                match &result {
                    Ok(()) => {
                        if let Some(last) = current {
                            last.status = "active";
                        }
                        (
                            input["placeholder"].is_string().then(|| settings_note(&input, reply)),
                            None,
                            replaced,
                        )
                    }
                    Err(e) => {
                        if let Some(last) = current {
                            last.status = "failed";
                            last.error = Some(e.code());
                        }
                        (None, Some(e.code()), replaced)
                    }
                }
            };
            if let Some(note) = note {
                (me.deps.on_active)(note);
            }
            match failed {
                // Rust only: a setup a newer apply replaced is not a failure in the log.
                Some(_) if replaced => tracing::info!("[phone] setup replaced by newer settings"),
                Some(code) => tracing::warn!("[phone] setup failed: {code}"),
                None => {}
            }
        });
        record.json()
    }

    /// `applyAfterUpdate` around the apply when settling is set up: the record stays pending
    /// while it waits and retries, so the firewall's reconcile does not mark it failed and stop.
    ///
    /// Rust only: replaced means a newer apply started after this one (its record is the last),
    /// so the same settings pushed again after others (A, B, A) replace the first A; the TS
    /// compared the settings and let the first A count as current again. And the waits between
    /// tries (the 60 s pause, the gateway wait) end as soon as this apply is replaced, where the TS
    /// sat them out with newer settings queued behind.
    async fn apply_settled(self: &Arc<Self>, input: &Value, id: u64) -> Result<(), SetupError> {
        let Some(settle) = &self.deps.settle else {
            return self.apply(input).await;
        };
        let update = settle.update.clone();
        let superseded = || *self.current.borrow() != id;
        let (base_sleep, base_ready) = (settle.sleep.clone(), settle.gateway_ready.clone());
        let rx = self.current.subscribe();
        let sleep = move |d: Duration| -> BoxFuture<()> {
            let (base, rx) = (base_sleep.clone(), rx.clone());
            Box::pin(async move {
                let wait: BoxFuture<()> = match base {
                    Some(f) => f(d),
                    None => Box::pin(tokio::time::sleep(d)),
                };
                tokio::select! {
                    () = wait => {}
                    () = until_replaced(rx, id) => {}
                }
            })
        };
        let rx = self.current.subscribe();
        // `when_connected` waits on a watch receiver: dropping it midway leaves nothing behind.
        let ready = move |d: Duration| -> BoxFuture<bool> {
            let (base, rx) = (base_ready.clone(), rx.clone());
            Box::pin(async move {
                tokio::select! {
                    ok = base(d) => ok,
                    () = until_replaced(rx, id) => false,
                }
            })
        };
        let options = crate::platform::settle::SettleOptions {
            update: update.as_ref(),
            gateway_ready: Some(&ready),
            superseded: Some(&superseded),
            sleep: Some(&sleep),
            // The wall clock: settle compares it with the Update's `at` for its window, so a
            // monotonic clock here would make every finished Update look recent.
            now: None,
        };
        crate::platform::settle::apply_after_update(
            || self.apply(input),
            &options,
            |e: &SetupError| TRANSIENT.contains(&e.code()),
            |attempt| tracing::warn!("[phone] setup failed during an agent update; retry {attempt} after it settles"),
        )
        .await
        .map_err(|e| match e {
            crate::platform::settle::Settled::Failed(e) => e,
            crate::platform::settle::Settled::Superseded => SetupError::Other(REPLACED.into()),
        })
    }

    async fn install(&self) -> Result<(), SetupError> {
        if let Some(install) = &self.deps.install {
            return install().await;
        }
        let runner = self.deps.runner.as_ref();
        let version = exec(
            runner,
            Cmd::new("/usr/bin/openclaw")
                .arg("--version")
                .timeout(Duration::from_secs(30)),
        )
        .await?;
        static VERSION: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"\b([0-9]{4})\.([0-9]+)\.([0-9]+)\b").expect("regex"));
        let ok = VERSION.captures(&version).is_some_and(|c| {
            let n = |i: usize| c[i].parse::<i64>().unwrap_or(0);
            n(1) * 10000 + n(2) * 100 + n(3) >= 20260907
        });
        if !ok {
            return Err(SetupError::Code("openclaw_version"));
        }
        let receipt = || async {
            let out = exec(
                runner,
                Cmd::new("/usr/bin/openclaw")
                    .args(["plugins", "info", "voice-call", "--json"])
                    .timeout(Duration::from_secs(60)),
            )
            .await?;
            let at = out.find('{').ok_or_else(|| SetupError::Other("no JSON".into()))?;
            serde_json::from_str::<Value>(&out[at..]).map_err(|e| SetupError::Other(e.to_string()))
        };
        let mut existing = false;
        // Anything that goes wrong with the existing install, a patch that does not apply
        // included, falls through to a fresh one (the TS's `catch` around this block).
        if let Ok(info) = receipt().await {
            existing = true;
            if trusted_phone_install(&info) && patch(&info).is_ok() {
                return Ok(());
            }
        }
        let dir = tempfile::Builder::new()
            .prefix("cc-phone-")
            .tempdir()
            .map_err(|e| SetupError::Other(e.to_string()))?;
        let packed = exec(
            runner,
            Cmd::new("npm")
                .args([
                    "pack",
                    PHONE_PACKAGE,
                    "--ignore-scripts",
                    "--json",
                    "--pack-destination",
                ])
                .arg(dir.path().display().to_string())
                .timeout(Duration::from_secs(180)),
        )
        .await?;
        let rows: Value = serde_json::from_str(&packed).map_err(|e| SetupError::Other(e.to_string()))?;
        static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9.-]+\.tgz$").expect("regex"));
        let name = rows
            .get(0)
            .and_then(|r| r.get("filename"))
            .and_then(Value::as_str)
            .filter(|n| NAME.is_match(n))
            .ok_or(SetupError::Code("plugin_integrity"))?;
        let archive = std::fs::read(dir.path().join(name)).map_err(|e| SetupError::Other(e.to_string()))?;
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&archive))
        );
        if !cc_crypto::ct_eq(integrity.as_bytes(), PHONE_INTEGRITY.as_bytes()) {
            return Err(SetupError::Code("plugin_integrity"));
        }
        if existing {
            run_plugin_mutation(runner, &["plugins", "disable", "voice-call"]).await?;
        }
        run_plugin_mutation(
            runner,
            &[
                "plugins",
                "install",
                PHONE_PACKAGE,
                "--pin",
                "--no-enable",
                "--force",
                "--accept-capabilities",
            ],
        )
        .await?;
        let installed = receipt().await?;
        if !trusted_phone_install(&installed) {
            return Err(SetupError::Code("plugin_integrity"));
        }
        step("plugin_integrity", patch(&installed))
    }

    async fn when_connected(&self, writer: &ConfigWriter, timeout: Duration) -> bool {
        let gw = writer.gateway();
        if gw.connected() {
            return true;
        }
        if let Some(mut rx) = gw.connection_state() {
            return tokio::time::timeout(timeout, rx.wait_for(|c| *c))
                .await
                .is_ok_and(|r| r.is_ok());
        }
        let deadline = tokio::time::Instant::now() + timeout;
        while !gw.connected() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        gw.connected()
    }

    async fn apply(&self, input: &Value) -> Result<(), SetupError> {
        // Fail closed: no gateway, no setup (TS `client` null).
        let Some(writer) = (self.deps.writer)() else {
            return Err(SetupError::Code("gateway_unavailable"));
        };
        let placeholder = input["placeholder"].is_string();
        let speech = input.get("speech").is_some_and(|s| !s.is_null());
        if placeholder && speech {
            let manifest = std::fs::read_to_string(&self.deps.adapter_manifest)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .ok_or(SetupError::Code("voice_adapter_missing"))?;
            let providers = manifest
                .pointer("/contracts/realtimeVoiceProviders")
                .and_then(Value::as_array);
            if !providers.is_some_and(|p| p.iter().any(|x| x == "cc-phone-voice")) {
                return Err(SetupError::Code("voice_adapter_missing"));
            }
            super::compat::resolve_admission(&self.deps.admission_dir)
                .map_err(|_| SetupError::Code("runtime_unsupported"))?;
        }
        if placeholder {
            step("plugin_install_failed", self.install().await)?;
        }
        if !self.when_connected(&writer, Duration::from_secs(90)).await {
            return Err(SetupError::Code("gateway_unavailable"));
        }
        let gw = writer.gateway().clone();
        let snapshot = gw
            .call("config.get", json!({}), GATEWAY_READ)
            .await
            .map_err(|_| SetupError::Code("gateway_unavailable"))?;
        let hash = snapshot
            .get("hash")
            .and_then(Value::as_str)
            .filter(|h| !h.is_empty())
            .ok_or(SetupError::Code("gateway_unavailable"))?
            .to_string();
        let config = snapshot.get("config").cloned().unwrap_or(Value::Null);
        let main = config
            .pointer("/agents/list")
            .and_then(Value::as_array)
            .and_then(|l| l.iter().find(|a| a.get("id").and_then(Value::as_str) == Some("main")))
            .and_then(|a| a.get("model"))
            .filter(|m| !m.is_null());
        let model = main.or_else(|| config.pointer("/agents/defaults/model"));
        let primary = match model {
            Some(Value::String(s)) => Some(s.clone()),
            Some(m) => m.get("primary").and_then(Value::as_str).map(String::from),
            None => None,
        }
        .filter(|p| !p.is_empty());
        if placeholder && primary.is_none() {
            return Err(SetupError::Code("model_missing"));
        }
        let reply = match (&primary, placeholder) {
            (Some(p), true) if speech => Some(p.clone()),
            (Some(p), true) => Some(phone_response_model(&config, p).map_err(SetupError::Other)?),
            _ => None,
        };
        self.state().reply_model = reply.clone();
        let entry = if placeholder {
            phone_config(input, reply.as_deref().unwrap_or_default())
        } else {
            json!({"enabled": false, "config": null})
        };
        let mut plugins = Map::new();
        let mut entries = Map::new();
        entries.insert("voice-call".into(), entry.clone());
        if placeholder && speech {
            entries.insert("cc-meeting-voice".into(), json!({"enabled": true}));
        }
        plugins.insert("entries".into(), Value::Object(entries));
        if placeholder && speech {
            let mut paths: Vec<Value> = config
                .pointer("/plugins/load/paths")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            paths.push(json!("/opt/controlclaw/meeting-voice"));
            plugins.insert("load".into(), json!({"paths": unique(paths)}));
        }
        // `[...allow, ...]` on an `allow` that is not a list throws inside the TS's `try` around
        // the patch: no write, and setup goes on to the restart and the wait.
        let mut writable = true;
        if placeholder
            && let Some(allow) = config
                .pointer("/plugins/allow")
                .filter(|a| super::model::truthy(Some(a)))
        {
            match allow.as_array() {
                Some(list) => {
                    let mut list = list.clone();
                    list.push(json!("voice-call"));
                    if speech {
                        list.push(json!("cc-meeting-voice"));
                    }
                    plugins.insert("allow".into(), Value::Array(unique(list)));
                }
                None => writable = false,
            }
        }
        let mut patch = Map::new();
        patch.insert("plugins".into(), Value::Object(plugins));
        let opts = PatchOptions {
            base_hash: Some(hash),
            snapshot: Some(snapshot.clone()),
            read_timeout: Some(GATEWAY_READ),
            // OpenClaw refuses a patch that drops array entries unless the path is named: removing
            // a caller, or a wake name, would otherwise leave the old settings in place.
            replace_paths: vec![
                "plugins.entries.voice-call.config.allowFrom".into(),
                "plugins.entries.voice-call.config.realtime.providers.cc-phone-voice.wake.words".into(),
            ],
            ..PatchOptions::new(CONFIG_PATCH_RESTART)
        };
        // A saved config can time out during the plugin's restart; it is verified below.
        if writable {
            let _ = writer.patch(&patch, opts).await;
        }
        (self.deps.restart)().await;
        let until = tokio::time::Instant::now() + self.deps.activation;
        let mut configured = false;
        while tokio::time::Instant::now() < until {
            if self.when_connected(&writer, Duration::from_secs(5)).await
                && let Ok(live) = gw.call("config.get", json!({}), GATEWAY_READ).await
            {
                let e = live.pointer("/config/plugins/entries/voice-call");
                let matches = if placeholder {
                    phone_config_matches(e, &entry)
                } else {
                    e.and_then(|e| e.get("enabled")) == Some(&json!(false))
                };
                if config_active(&live) == Some(true) && matches {
                    if !placeholder {
                        return Ok(());
                    }
                    configured = true;
                    let ready = match &self.deps.probe {
                        Some(p) => p(input.clone()).await,
                        None => probe_phone(input).await,
                    };
                    if ready {
                        return Ok(());
                    }
                }
            }
            tokio::time::sleep(self.deps.poll).await;
        }
        Err(SetupError::Code(if configured {
            "listener_unavailable"
        } else {
            "activation_timeout"
        }))
    }
}

fn patch(info: &Value) -> Result<(), SetupError> {
    let path = info
        .pointer("/install/installPath")
        .and_then(Value::as_str)
        .ok_or_else(|| SetupError::Other("no install path".into()))?;
    super::compat::patch_plugin(std::path::Path::new(path)).map_err(SetupError::Other)
}

/// `[...new Set(list)]`.
fn unique(list: Vec<Value>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for v in list {
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// The call history's note of the settings that became active (`SettingsNote`).
fn settings_note(input: &Value, reply: Option<String>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("at".into(), json!(now_ms()));
    let speech = input.get("speech").filter(|s| !s.is_null());
    m.insert("realtime".into(), json!(speech.is_some()));
    if let Some(p) = speech.and_then(|s| s.get("provider")) {
        m.insert("provider".into(), p.clone());
    }
    if let Some(p) = speech.and_then(|s| s.get("model")) {
        m.insert("model".into(), p.clone());
    }
    if let Some(r) = reply {
        m.insert("replyModel".into(), json!(r));
    }
    m
}

/// `probePhone`: a signed "completed" status callback from the number to itself; ready when the
/// plugin answers it with TwiML.
pub async fn probe_phone(input: &Value) -> bool {
    probe_at(input, "http://127.0.0.1:8789").await
}

pub async fn probe_at(input: &Value, base: &str) -> bool {
    let s = |k: &str| input[k].as_str().unwrap_or_default().to_string();
    let query = format!("?type=status&callId={}", hex::encode(rand::random::<[u8; 16]>()));
    let params = [
        ("AccountSid", s("accountSid")),
        ("CallSid", format!("CA{}", hex::encode(rand::random::<[u8; 16]>()))),
        ("CallStatus", "completed".to_string()),
        ("Direction", "outbound-api".to_string()),
        ("From", s("fromNumber")),
        ("To", s("fromNumber")),
    ];
    // Twilio's signature: the URL, then each parameter name and value, sorted by name.
    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let signed = format!(
        "{}{query}{}",
        s("publicUrl"),
        sorted.iter().map(|(k, v)| format!("{k}{v}")).collect::<String>()
    );
    let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(s("placeholder").as_bytes()) else {
        return false;
    };
    mac.update(signed.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())))
        .finish();
    // `fetch` takes no proxy from the environment; neither does this loopback call.
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return false;
    };
    let Ok(res) = client
        .post(format!("{base}/voice/webhook{query}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-twilio-signature", signature)
        .body(body)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    else {
        return false;
    };
    // `redirect: "error"`: a redirect is a failure.
    if res.status().as_u16() != 200 {
        return false;
    }
    static RESPONSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<Response[\s/>]").expect("regex"));
    res.text().await.is_ok_and(|t| RESPONSE.is_match(&t))
}

#[cfg(test)]
mod tests;
