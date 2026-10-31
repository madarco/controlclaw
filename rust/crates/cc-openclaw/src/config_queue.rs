//! Every config write the vm-agent makes, and the watcher that makes a saved write an active one.
//!
//! A port of `patchConfig`, `withConfigWrite`, `withConfigFileWrite` and the `replacePaths`
//! computation in `packages/vm-agent/src/gateway.ts`, and of `ConfigActivation` in
//! `config-activation.ts`. The waits, their order and the log lines are the TS ones.
//!
//! - One write at a time per gateway ([`ConfigWriter`]; the TS keeps one queue per gateway object).
//!   OpenClaw answers a write only once it has applied it, and drops that apply ("superseded") when
//!   another write is saved first (T-180). The queue is held for the write itself, not for the waits
//!   after a saved write.
//! - Around a gateway restart (T-103): a write saved behind a pending restart is done once the
//!   gateway is back; a write the gateway never took is sent once more against a fresh hash.
//! - Superseded (T-180): done once `config.get` shows the gateway runs the saved config.
//! - Stale base hash: sent once more, but only when the parts of the config the patch writes are
//!   what they were in the snapshot it was built from.
//! - [`ConfigActivation`] (T-111): after writes go quiet, a gateway still running behind its saved
//!   config is restarted, with a cooldown and at most three restarts in 30 minutes.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::future::Shared;
use serde_json::{Map, Value, json};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::time::Instant;

use crate::messages::{is_persisted_pending_restart, is_persisted_superseded, is_restart_window, is_stale_base_hash};
use crate::{ConfigWritePhase, DEFAULT_CALL_TIMEOUT, GatewayClient, GatewayError, GatewayEvent};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// Where a log line goes. The default writes `[gateway] <line>`, as the TS `console.log` did.
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

/// How long `patch` waits for a gateway restart to begin once OpenClaw has said one is coming, and
/// then for the gateway to be back. Measured on a CX23 with OpenClaw 2026.9.7: the restart starts
/// 3 s after the answer and the gateway is serving again 25 s later.
pub const RESTART_BEGIN_WAIT: Duration = Duration::from_secs(15);
pub const RESTART_BACK_WAIT: Duration = Duration::from_secs(90);
/// How long `patch` waits for a superseded write to become active.
pub const SUPERSEDED_ACTIVE_WAIT: Duration = Duration::from_secs(120);
pub const SUPERSEDED_POLL: Duration = Duration::from_secs(1);
/// How long a CLI command's file write may take to be applied before the next write goes in.
pub const CLI_SETTLE: Duration = Duration::from_secs(15);
/// The least a write with a budget waits in the queue before going in beside the writes ahead.
pub const MIN_QUEUE_WAIT: Duration = Duration::from_secs(5);
/// A plain gateway read (`GATEWAY_READ_MS` in budgets.ts).
pub const GATEWAY_READ: Duration = Duration::from_secs(10);

/// What the queue needs from a gateway connection. [`GatewayClient`] has all of it; a test fake may
/// have only `call` and `connected`, and then waits by polling `connected`.
pub trait ConfigGateway: Send + Sync + 'static {
    fn connected(&self) -> bool;
    fn call(&self, method: &str, params: Value, timeout: Duration) -> BoxFuture<'_, Result<Value, GatewayError>>;
    /// Changes of `connected` (`whenConnected`, `onDisconnected`). None: poll.
    fn connection_state(&self) -> Option<watch::Receiver<bool>> {
        None
    }
    /// Gateway broadcasts (`config.changed`). None: the gateway sends none.
    fn events(&self) -> Option<broadcast::Receiver<GatewayEvent>> {
        None
    }
}

impl ConfigGateway for GatewayClient {
    fn connected(&self) -> bool {
        GatewayClient::connected(self)
    }
    fn call(&self, method: &str, params: Value, timeout: Duration) -> BoxFuture<'_, Result<Value, GatewayError>> {
        let method = method.to_string();
        Box::pin(async move { GatewayClient::call(self, &method, params, timeout).await })
    }
    fn connection_state(&self) -> Option<watch::Receiver<bool>> {
        Some(GatewayClient::connection_state(self))
    }
    fn events(&self) -> Option<broadcast::Receiver<GatewayEvent>> {
        Some(GatewayClient::events(self))
    }
}

/// Why a config write failed. The text is what the TS threw, which callers show and compare.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// OpenClaw's own refusal, or the client's ("gateway not connected").
    #[error("{0}")]
    Gateway(#[from] GatewayError),
    #[error("OpenClaw returned no config hash")]
    NoHash,
    #[error("The config was saved but the agent did not come back after restarting.")]
    NotBack { cause: GatewayError },
    #[error("The config was saved but the agent has not applied it yet.")]
    NotActive { cause: GatewayError },
}

/// `patchConfig`'s options.
#[derive(Clone, Default)]
pub struct PatchOptions {
    /// The hash of the `config.get` the patch was built from.
    pub base_hash: Option<String>,
    /// The `config.get` answer `base_hash` came from.
    pub snapshot: Option<Value>,
    pub timeout: Duration,
    pub read_timeout: Option<Duration>,
    /// Extra paths to replace outright. The ones the patch shrinks are added on their own.
    pub replace_paths: Vec<String>,
    pub log: Option<LogFn>,
    /// Test hook: how long a superseded write may take to become active.
    pub active_wait: Option<Duration>,
    /// How long the caller's route has for this write, from the call (see `patchConfig`).
    pub budget: Option<Duration>,
}

impl PatchOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Self::default()
        }
    }
}

/// `withConfigWrite`'s and `withConfigFileWrite`'s options.
#[derive(Clone, Default)]
pub struct QueueOptions {
    pub max_queue_wait: Option<Duration>,
    pub log: Option<LogFn>,
    /// `withConfigFileWrite` only: how long the queue is held for `config.changed` (`CLI_SETTLE`).
    pub settle: Option<Duration>,
}

fn log_line(log: &Option<LogFn>, line: &str) {
    match log {
        Some(f) => f(line),
        None => tracing::info!("[gateway] {line}"),
    }
}

type Tail = Shared<BoxFuture<'static, ()>>;

fn done_tail() -> Tail {
    let f: BoxFuture<'static, ()> = Box::pin(async {});
    f.shared()
}

/// One gateway's config writes. Every writer in the agent shares one (an `Arc`), as the TS shares
/// the `writeQueues` entry of one `GatewayClient`.
pub struct ConfigWriter {
    gw: Arc<dyn ConfigGateway>,
    tail: Mutex<Tail>,
}

/// What is left to wait for once the queue is let go.
enum Afterwards {
    PendingRestart(GatewayError),
    Superseded(GatewayError),
}

impl ConfigWriter {
    pub fn new(gw: Arc<dyn ConfigGateway>) -> Self {
        Self {
            gw,
            tail: Mutex::new(done_tail()),
        }
    }

    pub fn gateway(&self) -> &Arc<dyn ConfigGateway> {
        &self.gw
    }

    /// Take a place in the queue: the turn to wait for, and the sender that lets the next writer go
    /// (dropped when this write is done, also when its future is dropped).
    fn enqueue(&self) -> (Tail, oneshot::Sender<()>) {
        let (tx, rx) = oneshot::channel::<()>();
        let mut tail = lock(&self.tail);
        let prev = tail.clone();
        let before = prev.clone();
        // The next write waits for this one and for everything this one may have stopped waiting for.
        let next: BoxFuture<'static, ()> = Box::pin(async move {
            before.await;
            let _ = rx.await;
        });
        *tail = next.shared();
        (prev, tx)
    }

    /// `withConfigWrite`: run `write` in the gateway's config write queue.
    pub async fn write<T, F, Fut>(&self, write: F, opts: QueueOptions) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let (turn, done) = self.enqueue();
        queue_turn(turn, &opts).await;
        let out = write().await;
        drop(done);
        out
    }

    /// `withConfigFileWrite`: `write` is an OpenClaw CLI command that writes the config file. The
    /// caller has its answer when the command exits; the queue is held until the gateway broadcasts
    /// `config.changed` (at most `CLI_SETTLE`), or, for a gateway that sends no events, until
    /// `config.get` shows the config active. Nothing is held when the command failed or the gateway
    /// is down.
    pub async fn file_write<T, E, F, Fut>(&self, write: F, opts: QueueOptions) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let (turn, done) = self.enqueue();
        queue_turn(turn, &opts).await;
        // Subscribed before the command runs, so a broadcast it causes is not missed.
        let events = self.gw.events();
        let value = match write().await {
            Ok(v) => v,
            Err(e) => {
                drop(done);
                return Err(e);
            }
        };
        if !self.gw.connected() {
            drop(done);
            return Ok(value);
        }
        let settle = opts.settle.unwrap_or(CLI_SETTLE);
        let gw = self.gw.clone();
        tokio::spawn(async move {
            match events {
                Some(mut rx) => {
                    let changed = async {
                        loop {
                            match rx.recv().await {
                                Ok(e) if e.event == "config.changed" => return,
                                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                                Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
                            }
                        }
                    };
                    let _ = tokio::time::timeout(settle, changed).await;
                }
                None => {
                    await_active(gw.as_ref(), None, settle).await;
                }
            }
            drop(done);
        });
        Ok(value)
    }

    /// `patchConfig`: every config write this agent makes. `patch` is a merge patch, so sending it
    /// again means the same thing it meant the first time.
    pub async fn patch(&self, patch: &Map<String, Value>, opts: PatchOptions) -> Result<(), ConfigError> {
        let deadline = opts.budget.map(|b| Instant::now() + b);
        // What the queue may take of the budget: whatever the write itself does not need.
        let max_queue_wait = opts.budget.map(|b| MIN_QUEUE_WAIT.max(b.saturating_sub(opts.timeout)));
        let q = QueueOptions {
            max_queue_wait,
            log: opts.log.clone(),
            settle: None,
        };
        // The write runs in its own task, holding the queue until OpenClaw answers it: a caller
        // that stops waiting (its route timed out, the client went away) must not let the next
        // write in while this one is still being applied, or it is superseded with nobody holding
        // the answer (T-180).
        let (turn, done) = self.enqueue();
        let (gw, patch_owned, o) = (self.gw.clone(), patch.clone(), opts.clone());
        let task = tokio::spawn(async move {
            queue_turn(turn, &q).await;
            let r = send_patch(gw.as_ref(), &patch_owned, &o).await;
            drop(done);
            r
        });
        let afterwards = match task.await {
            Ok(r) => r?,
            Err(e) => return Err(ConfigError::Gateway(GatewayError::Send(e.to_string()))),
        };
        let Some(afterwards) = afterwards else {
            return Ok(());
        };
        let gw = self.gw.as_ref();
        match afterwards {
            Afterwards::PendingRestart(cause) => {
                let left = remaining(deadline);
                if await_restart(gw, left).await {
                    return Ok(());
                }
                if left.is_some() {
                    saved_not_active(&opts.log);
                    return Ok(());
                }
                Err(ConfigError::NotBack { cause })
            }
            Afterwards::Superseded(cause) => {
                let left = remaining(deadline);
                let wait = opts.active_wait.unwrap_or(SUPERSEDED_ACTIVE_WAIT);
                let wait = left.map_or(wait, |l| wait.min(l));
                if await_active(gw, opts.read_timeout, wait).await {
                    log_line(&opts.log, "the saved config is active");
                    return Ok(());
                }
                if left.is_some() {
                    saved_not_active(&opts.log);
                    return Ok(());
                }
                Err(ConfigError::NotActive { cause })
            }
        }
    }
}

/// The queue's turn, or, after `max_queue_wait`, a turn anyway: a caller whose route would time out
/// before the writes ahead of it are done goes in beside them.
async fn queue_turn(turn: Tail, opts: &QueueOptions) {
    let Some(max) = opts.max_queue_wait else {
        turn.await;
        return;
    };
    if tokio::time::timeout(max, turn).await.is_err() {
        log_line(
            &opts.log,
            "config writes ahead of this one are still running; going in beside them to stay within the caller's time",
        );
    }
}

/// What is left of the caller's budget, or None when it gave none.
fn remaining(deadline: Option<Instant>) -> Option<Duration> {
    deadline.map(|d| d.saturating_duration_since(Instant::now()))
}

/// The caller's time is up and the write is saved: done, and `ConfigActivation` takes it from here.
fn saved_not_active(log: &Option<LogFn>) {
    log_line(
        log,
        "config write saved but not active yet, and the caller's time is up; the agent applies it on its own",
    );
}

struct Basis {
    hash: String,
    configs: Vec<Value>,
}

struct Snapshot {
    hash: String,
    configs: Vec<Value>,
    snapshot: Value,
}

enum Rebased {
    Fresh(Basis),
    Landed,
}

/// The write itself. Returns what is left to wait for once the queue is let go, if anything.
async fn send_patch(
    gw: &dyn ConfigGateway,
    patch: &Map<String, Value>,
    opts: &PatchOptions,
) -> Result<Option<Afterwards>, ConfigError> {
    let patch_value = Value::Object(patch.clone());
    let raw = patch_value.to_string();
    let log = &opts.log;
    let mut basis = match (&opts.base_hash, &opts.snapshot) {
        (Some(h), Some(s)) if !h.is_empty() => Some(Basis {
            hash: h.clone(),
            configs: snapshot_configs(s),
        }),
        _ => None,
    };
    let mut restart_retried = false;
    let mut stale_retried = false;
    let mut sent = false;
    loop {
        let current = match basis.take() {
            Some(b) => b,
            None => match read_snapshot(gw, opts.read_timeout).await {
                // A caller's own hash with no snapshot: only the lists are worked out from this read.
                Ok(read) => match &opts.base_hash {
                    Some(h) if !h.is_empty() && !sent => Basis {
                        hash: h.clone(),
                        configs: read.configs,
                    },
                    _ => Basis {
                        hash: read.hash,
                        configs: read.configs,
                    },
                },
                Err(err) => {
                    // The queue is let go while an announced restart is waited out, so the next
                    // write can find the gateway gone before its first read.
                    if rides_out_restart(gw, &err, &mut restart_retried, log).await? {
                        continue;
                    }
                    return Err(err);
                }
            },
        };
        let mut replace: Vec<String> = Vec::new();
        for p in opts.replace_paths.iter().cloned().chain(
            current
                .configs
                .iter()
                .flat_map(|c| array_replace_paths(c, &patch_value)),
        ) {
            if !replace.contains(&p) {
                replace.push(p);
            }
        }
        let mut params = json!({ "raw": raw, "baseHash": current.hash });
        if !replace.is_empty() {
            params["replacePaths"] = json!(replace);
        }
        sent = true;
        let err = match gw.call("config.patch", params, opts.timeout).await {
            Ok(_) => return Ok(None),
            Err(e) => e,
        };
        let message = err.to_string();
        if is_persisted_pending_restart(&message) {
            log_line(
                log,
                "config write saved; waiting for the gateway restart it is queued behind",
            );
            return Ok(Some(Afterwards::PendingRestart(err)));
        }
        if is_persisted_superseded(&message) {
            log_line(
                log,
                "config write saved, but a newer write took over its apply; waiting for the gateway to run the saved config",
            );
            return Ok(Some(Afterwards::Superseded(err)));
        }
        let err = ConfigError::Gateway(err);
        if rides_out_restart(gw, &err, &mut restart_retried, log).await? {
            match rebased(gw, patch, opts, err).await? {
                Rebased::Landed => {
                    log_line(log, "the gateway had saved this write before it went away");
                    return Ok(None);
                }
                Rebased::Fresh(b) => basis = Some(b),
            }
            continue;
        }
        if !stale_retried && is_stale_base_hash(&message) {
            stale_retried = true;
            match rebased(gw, patch, opts, err).await? {
                Rebased::Landed => return Ok(None),
                Rebased::Fresh(b) => basis = Some(b),
            }
            log_line(
                log,
                "the config changed under this write, not where it writes; sending it again against the new file",
            );
            continue;
        }
        return Err(err);
    }
}

/// The gateway is restarting (its socket down, or saying so): wait for it once, then go again.
/// `Err` when it did not come back.
async fn rides_out_restart(
    gw: &dyn ConfigGateway,
    err: &ConfigError,
    retried: &mut bool,
    log: &Option<LogFn>,
) -> Result<bool, ConfigError> {
    if *retried || !is_restart_window(&err.to_string()) {
        return Ok(false);
    }
    *retried = true;
    log_line(
        log,
        "config write landed while the gateway was restarting; sending it again once it is back",
    );
    if !when_back(gw, RESTART_BACK_WAIT).await {
        return Err(err.clone());
    }
    Ok(true)
}

/// A fresh read to send the write again against; `Landed` when the file already holds what the
/// patch writes; or `err` when the patch was built from a read and the parts it writes have changed.
async fn rebased(
    gw: &dyn ConfigGateway,
    patch: &Map<String, Value>,
    opts: &PatchOptions,
    err: ConfigError,
) -> Result<Rebased, ConfigError> {
    let fresh = read_snapshot(gw, opts.read_timeout).await?;
    let as_basis = |s: Snapshot| {
        Rebased::Fresh(Basis {
            hash: s.hash,
            configs: s.configs,
        })
    };
    if opts.base_hash.as_deref().is_none_or(str::is_empty) {
        return Ok(as_basis(fresh));
    }
    if let Some(before) = &opts.snapshot
        && patched_parts_unchanged(before, &fresh.snapshot, patch)
    {
        return Ok(as_basis(fresh));
    }
    if patch_holds(&fresh.snapshot, patch) {
        return Ok(Rebased::Landed);
    }
    Err(err)
}

/// Whether the config already says what `patch` writes, in the file or the resolved config.
pub fn patch_holds(snapshot: &Value, patch: &Map<String, Value>) -> bool {
    holds(&snapshot["parsed"], patch) || holds(&snapshot["config"], patch)
}

fn holds(config: &Value, patch: &Map<String, Value>) -> bool {
    let Value::Object(config) = config else {
        return false;
    };
    patch.iter().all(|(key, value)| match value {
        Value::Null => config.get(key).is_none(),
        Value::Object(v) => holds(config.get(key).unwrap_or(&Value::Null), v),
        _ => config.get(key) == Some(value),
    })
}

/// Whether every value `patch` writes, or writes into, is the same in both reads.
pub fn patched_parts_unchanged(before: &Value, after: &Value, patch: &Map<String, Value>) -> bool {
    touched_equal(&before["config"], &after["config"], patch)
        && touched_equal(&before["parsed"], &after["parsed"], patch)
}

fn touched_equal(a: &Value, b: &Value, patch: &Map<String, Value>) -> bool {
    let empty = Map::new();
    let ra = a.as_object().unwrap_or(&empty);
    let rb = b.as_object().unwrap_or(&empty);
    patch
        .iter()
        .all(|(key, value)| match (value, ra.get(key), rb.get(key)) {
            (Value::Object(v), Some(x @ Value::Object(_)), Some(y @ Value::Object(_))) => touched_equal(x, y, v),
            (_, x, y) => x == y,
        })
}

/// `snapshotConfigs`: the resolved config and the file, where they are objects.
fn snapshot_configs(snapshot: &Value) -> Vec<Value> {
    [&snapshot["config"], &snapshot["parsed"]]
        .into_iter()
        .filter(|c| c.is_object())
        .cloned()
        .collect()
}

async fn read_snapshot(gw: &dyn ConfigGateway, timeout: Option<Duration>) -> Result<Snapshot, ConfigError> {
    let snapshot = gw
        .call("config.get", json!({}), timeout.unwrap_or(DEFAULT_CALL_TIMEOUT))
        .await?;
    let hash = match snapshot.get("hash") {
        Some(Value::String(h)) if !h.is_empty() => h.clone(),
        _ => return Err(ConfigError::NoHash),
    };
    Ok(Snapshot {
        hash,
        configs: snapshot_configs(&snapshot),
        snapshot,
    })
}

fn is_id_entry(v: &Value) -> bool {
    matches!(v.get("id"), Some(Value::String(s)) if !s.is_empty()) && v.is_object()
}

/// `arrayReplacePaths`: the array paths a merge patch takes entries out of, which OpenClaw's
/// `config.patch` refuses unless each one is named in `replacePaths`. Mirrors OpenClaw's rules, so
/// it names no more than OpenClaw would ask for.
pub fn array_replace_paths(current: &Value, patch: &Value) -> Vec<String> {
    replace_paths_at(current, patch, "")
}

fn replace_paths_at(current: &Value, patch: &Value, path: &str) -> Vec<String> {
    let (Value::Object(patch), Value::Object(current)) = (patch, current) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, value) in patch {
        if key == "__proto__" || key == "constructor" || key == "prototype" {
            continue;
        }
        let at = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        let base = current.get(key).unwrap_or(&Value::Null);
        if let Value::Array(base) = base {
            let Value::Array(value) = value else {
                out.push(at);
                continue;
            };
            if base.iter().all(is_id_entry) {
                for entry in value {
                    if !is_id_entry(entry) {
                        continue;
                    }
                    // `new Map(base.map(...))`: the last entry with an id wins.
                    if let Some(b) = base.iter().rev().find(|e| e["id"] == entry["id"]) {
                        out.extend(replace_paths_at(b, entry, &format!("{at}[]")));
                    }
                }
            } else if !keeps_entries(base, value) {
                out.push(at);
            }
            continue;
        }
        if base.is_object() && !value.is_object() {
            out.extend(arrays_under(base, &at));
            continue;
        }
        if value.is_object() {
            out.extend(replace_paths_at(base, value, &at));
        }
    }
    out
}

fn keeps_entries(base: &[Value], next: &[Value]) -> bool {
    let mut left: Vec<&Value> = next.iter().collect();
    for entry in base {
        match left.iter().position(|e| *e == entry) {
            Some(i) => {
                left.remove(i);
            }
            None => return false,
        }
    }
    true
}

fn arrays_under(base: &Value, path: &str) -> Vec<String> {
    match base {
        Value::Array(_) => vec![path.to_string()],
        Value::Object(m) => m
            .iter()
            .flat_map(|(k, v)| arrays_under(v, &format!("{path}.{k}")))
            .collect(),
        _ => Vec::new(),
    }
}

/// True once connected (at once if already), false after `timeout`.
pub async fn when_back(gw: &dyn ConfigGateway, timeout: Duration) -> bool {
    if let Some(mut rx) = gw.connection_state() {
        return tokio::time::timeout(timeout, rx.wait_for(|c| *c))
            .await
            .is_ok_and(|r| r.is_ok());
    }
    let deadline = Instant::now() + timeout;
    while !gw.connected() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    gw.connected()
}

/// Whether the gateway runs the saved config, from a `config.get` answer. None when it cannot be
/// told: an OpenClaw without the two hashes, or a config file that does not validate.
pub fn config_active(snapshot: &Value) -> Option<bool> {
    let text = |k: &str| match snapshot.get(k) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let saved = text("configRevisionHash")?;
    let applied = text("appliedConfigHash")?;
    Some(saved == applied)
}

/// Wait until the gateway runs the saved config. An OpenClaw that reports neither hash cannot be
/// checked, and the write is saved, so that counts as done. The vm-agent's ready waits on it too.
pub async fn await_active(gw: &dyn ConfigGateway, read_timeout: Option<Duration>, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if gw.connected()
            && let Ok(s) = gw
                .call("config.get", json!({}), read_timeout.unwrap_or(DEFAULT_CALL_TIMEOUT))
                .await
            && config_active(&s) != Some(false)
        {
            return true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        if !gw.connected() {
            when_back(gw, left).await;
        } else {
            tokio::time::sleep(SUPERSEDED_POLL.min(left)).await;
        }
    }
}

/// Wait for a restart OpenClaw has announced: the socket drops, then the handshake is done again.
/// A restart that never begins is fine too, as long as the gateway still answers.
async fn await_restart(gw: &dyn ConfigGateway, wait: Option<Duration>) -> bool {
    let deadline = Instant::now() + wait.unwrap_or(RESTART_BEGIN_WAIT + RESTART_BACK_WAIT);
    if gw.connected()
        && let Some(mut rx) = gw.connection_state()
    {
        rx.borrow_and_update();
        let begin = wait.map_or(RESTART_BEGIN_WAIT, |w| RESTART_BEGIN_WAIT.min(w));
        // Connected now, so the next change is the drop.
        let _ = tokio::time::timeout(begin, rx.changed()).await;
    }
    when_back(
        gw,
        RESTART_BACK_WAIT.min(deadline.saturating_duration_since(Instant::now())),
    )
    .await
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- ConfigActivation (config-activation.ts, T-111) ----

/// Quiet time after the last write before the hashes are compared at all.
pub const ACTIVATION_SETTLE: Duration = Duration::from_secs(5);
/// How long the gateway may stay up and behind before it is restarted.
pub const ACTIVATION_GRACE: Duration = Duration::from_secs(40);
pub const ACTIVATION_POLL: Duration = Duration::from_secs(2);
/// A gateway that stays down this long is stopped, not restarting: stop watching.
pub const ACTIVATION_DOWN: Duration = Duration::from_secs(120);
/// After a forced restart that did not help, no other one for this long.
pub const RESTART_COOLDOWN: Duration = Duration::from_secs(10 * 60);
/// And never more than this many in `RESTART_WINDOW`, whatever was written in between.
pub const MAX_FORCED_RESTARTS: usize = 3;
pub const RESTART_WINDOW: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    Active,
    Restarted,
    Unknown,
    Down,
    Stuck,
}

/// `systemctl restart openclaw`; the error is logged.
pub type RestartFn = Arc<dyn Fn() -> BoxFuture<'static, Result<(), String>> + Send + Sync>;
/// Whether OpenClaw has said lately that it is holding its restart back for work in flight.
pub type DeferredFn = Arc<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync>;

pub struct ActivationOptions {
    pub gateway: Arc<dyn ConfigGateway>,
    pub restart_service: RestartFn,
    pub restart_deferred: Option<DeferredFn>,
    pub log: Option<LogFn>,
    pub settle: Duration,
    pub grace: Duration,
    pub poll: Duration,
    pub down: Duration,
    pub cooldown: Duration,
}

impl ActivationOptions {
    pub fn new(gateway: Arc<dyn ConfigGateway>, restart_service: RestartFn) -> Self {
        Self {
            gateway,
            restart_service,
            restart_deferred: None,
            log: None,
            settle: ACTIVATION_SETTLE,
            grace: ACTIVATION_GRACE,
            poll: ACTIVATION_POLL,
            down: ACTIVATION_DOWN,
            cooldown: RESTART_COOLDOWN,
        }
    }
}

struct ActivationState {
    in_flight: usize,
    last_change_at: Instant,
    /// Bumped on every change and reconnect.
    changes: u64,
    /// Bumped on writes only.
    writes: u64,
    /// `writes` when the last forced restart was run.
    writes_at_restart: Option<u64>,
    timer: Option<tokio::task::JoinHandle<()>>,
    /// Bumped on every schedule: a timer whose sleep ended after a newer one was set (an abort that
    /// came too late to stop it) is not the current one and starts nothing.
    timer_generation: u64,
    running: bool,
    last_restart_at: Option<Instant>,
    forced_restarts: Vec<Instant>,
    waiters: Vec<oneshot::Sender<ActivationOutcome>>,
}

/// `ConfigActivation`: makes "settings written" end in "settings active". Cheap to clone.
#[derive(Clone)]
pub struct ConfigActivation {
    opts: Arc<ActivationOptions>,
    state: Arc<Mutex<ActivationState>>,
}

impl ConfigActivation {
    pub fn new(opts: ActivationOptions) -> Self {
        Self {
            opts: Arc::new(opts),
            state: Arc::new(Mutex::new(ActivationState {
                in_flight: 0,
                last_change_at: Instant::now(),
                changes: 0,
                writes: 0,
                writes_at_restart: None,
                timer: None,
                timer_generation: 0,
                running: false,
                last_restart_at: None,
                forced_restarts: Vec::new(),
                waiters: Vec::new(),
            })),
        }
    }

    /// The TS wiring in index.ts: every config write sent through `client`, its `config.changed`
    /// broadcasts and its reconnects. Runs until the client is dropped.
    pub fn follow(&self, client: &GatewayClient) {
        let mut writes = client.config_writes();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                match writes.recv().await {
                    Ok(ConfigWritePhase::Start) => me.write_started(),
                    Ok(ConfigWritePhase::End) => me.write_ended(),
                    // Missed starts and ends: the count cannot be trusted, so start it over.
                    Err(broadcast::error::RecvError::Lagged(_)) => me.resync(),
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        let mut events = client.events();
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    // A lag may have taken a `config.changed` with it.
                    Ok(e) if e.event == "config.changed" => me.changed(),
                    Err(broadcast::error::RecvError::Lagged(_)) => me.changed(),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        let mut conn = client.connection_state();
        let me = self.clone();
        tokio::spawn(async move {
            let mut was = *conn.borrow_and_update();
            while conn.changed().await.is_ok() {
                let now = *conn.borrow_and_update();
                if now && !was {
                    me.reconnected();
                }
                was = now;
            }
        });
    }

    /// A `config.patch` (or `.apply` / `.set`) was sent. No verdict while one is in flight.
    pub fn write_started(&self) {
        lock(&self.state).in_flight += 1;
        self.changed();
    }

    /// Writes were missed (a lagged subscription): none is counted as in flight any more, and the
    /// config counts as changed.
    pub fn resync(&self) {
        lock(&self.state).in_flight = 0;
        self.changed();
    }

    pub fn write_ended(&self) {
        {
            let mut s = lock(&self.state);
            s.in_flight = s.in_flight.saturating_sub(1);
        }
        self.changed();
    }

    /// The config changed some other way: the gateway's `config.changed`, which covers the CLI.
    pub fn changed(&self) {
        lock(&self.state).writes += 1;
        self.poke();
    }

    /// The socket to the gateway came back. Worth a look, but it is not a write.
    pub fn reconnected(&self) {
        self.poke();
    }

    fn poke(&self) {
        let mut s = lock(&self.state);
        s.last_change_at = Instant::now();
        s.changes += 1;
        if !s.running {
            self.schedule(&mut s);
        }
    }

    /// The outcome of the next check to finish. For tests and logs.
    pub fn next_verdict(&self) -> oneshot::Receiver<ActivationOutcome> {
        let (tx, rx) = oneshot::channel();
        lock(&self.state).waiters.push(tx);
        rx
    }

    pub fn stop(&self) {
        if let Some(t) = lock(&self.state).timer.take() {
            t.abort();
        }
    }

    fn schedule(&self, s: &mut ActivationState) {
        if let Some(t) = s.timer.take() {
            t.abort();
        }
        s.timer_generation += 1;
        let generation = s.timer_generation;
        let me = self.clone();
        let settle = self.opts.settle;
        s.timer = Some(tokio::spawn(async move {
            tokio::time::sleep(settle).await;
            me.start(generation);
        }));
    }

    /// One check at a time: the TS watcher is single-threaded, so a timer could never fire while a
    /// check ran. Here a stale timer, or one firing during a check, does nothing; the running
    /// check reschedules itself when changes came in meanwhile.
    fn start(&self, generation: u64) {
        let seen = {
            let mut s = lock(&self.state);
            if s.running || s.timer_generation != generation {
                return;
            }
            s.timer = None;
            s.running = true;
            s.changes
        };
        let me = self.clone();
        tokio::spawn(async move {
            let outcome = me.check().await;
            let mut s = lock(&me.state);
            s.running = false;
            // A write that landed after the last read is not covered by this verdict.
            if s.changes != seen {
                me.schedule(&mut s);
            }
            for w in s.waiters.drain(..) {
                let _ = w.send(outcome);
            }
        });
    }

    fn log(&self, line: &str) {
        match &self.opts.log {
            Some(f) => f(line),
            None => tracing::info!("{line}"),
        }
    }

    async fn check(&self) -> ActivationOutcome {
        let gw = self.opts.gateway.as_ref();
        // When the gateway was first seen up, settled and behind, with no change since.
        let mut behind_since: Option<Instant> = None;
        let mut down_since: Option<Instant> = None;
        let mut changes_at_behind = lock(&self.state).changes;
        loop {
            let now = Instant::now();
            let (in_flight, last_change_at) = {
                let s = lock(&self.state);
                (s.in_flight, s.last_change_at)
            };
            if in_flight > 0 || now.duration_since(last_change_at) < self.opts.settle {
                behind_since = None;
                tokio::time::sleep(self.opts.poll).await;
                continue;
            }
            if !gw.connected() {
                // Restarting, which is how a write that needs it gets applied; or stopped on purpose.
                behind_since = None;
                let since = *down_since.get_or_insert(now);
                if now.duration_since(since) >= self.opts.down {
                    return ActivationOutcome::Down;
                }
                tokio::time::sleep(self.opts.poll).await;
                continue;
            }
            down_since = None;
            let active = match gw.call("config.get", json!({}), GATEWAY_READ).await {
                Ok(s) => config_active(&s),
                Err(_) => {
                    tokio::time::sleep(self.opts.poll).await;
                    continue;
                }
            };
            let Some(active) = active else {
                return ActivationOutcome::Unknown;
            };
            if active {
                // The last forced restart (if any) worked, so a later drop is a new incident.
                lock(&self.state).last_restart_at = None;
                if let Some(since) = behind_since {
                    self.log(&format!(
                        "[config] OpenClaw applied the saved settings after {} s",
                        since.elapsed().as_secs_f64().round()
                    ));
                }
                return ActivationOutcome::Active;
            }
            let changes = lock(&self.state).changes;
            if behind_since.is_none() || changes != changes_at_behind {
                behind_since = Some(Instant::now());
                changes_at_behind = changes;
            }
            let since = behind_since.unwrap_or_else(Instant::now);
            if since.elapsed() < self.opts.grace {
                tokio::time::sleep(self.opts.poll).await;
                continue;
            }
            if let Some(deferred) = &self.opts.restart_deferred
                && deferred().await
            {
                self.log("[config] OpenClaw is holding its restart back for work in flight; waiting for it");
                behind_since = Some(Instant::now());
                tokio::time::sleep(self.opts.poll).await;
                continue;
            }
            {
                let mut s = lock(&self.state);
                let recent = s.last_restart_at.is_some_and(|at| at.elapsed() < self.opts.cooldown);
                if recent && s.writes_at_restart == Some(s.writes) {
                    drop(s);
                    self.log("[config] OpenClaw is still not running its saved settings, and it was restarted for that a moment ago; leaving it");
                    return ActivationOutcome::Stuck;
                }
                s.forced_restarts.retain(|at| at.elapsed() < RESTART_WINDOW);
                if s.forced_restarts.len() >= MAX_FORCED_RESTARTS {
                    drop(s);
                    self.log(&format!(
                        "[config] OpenClaw is still not running its saved settings after {MAX_FORCED_RESTARTS} restarts from here; leaving it"
                    ));
                    return ActivationOutcome::Stuck;
                }
            }
            if !gw.connected() {
                continue; // went down by itself while we decided: let it come back
            }
            self.log(&format!(
                "[config] OpenClaw has run behind its saved settings for {} s (its own restart was dropped); restarting it",
                since.elapsed().as_secs_f64().round()
            ));
            {
                let mut s = lock(&self.state);
                let at = Instant::now();
                s.last_restart_at = Some(at);
                s.forced_restarts.push(at);
                s.writes_at_restart = Some(s.writes);
            }
            if let Err(e) = (self.opts.restart_service)().await {
                self.log(&format!("[config] restart failed: {e}"));
                return ActivationOutcome::Stuck;
            }
            return ActivationOutcome::Restarted;
        }
    }
}

// ---- fake-openclaw-config.ts ----

/// OpenClaw's `config.patch` as 2026.9.8/9 implements it (`applyMergePatch` with
/// `mergeObjectArraysById`, `rejectDestructiveArrayPatchWithoutIntent`), and its apply as 2026.9.34
/// does it (superseded when another write is saved first). Kept apart from the agent's own
/// `array_replace_paths`, which is checked against it, so the two share no code.
#[cfg(any(test, feature = "fake"))]
pub mod fake_config {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Map, Value, json};
    use tokio::sync::{broadcast, oneshot};

    use super::{BoxFuture, ConfigGateway, lock};
    use crate::{GatewayError, GatewayEvent};

    pub const SUPERSEDED_MESSAGE: &str = "config.patch persisted but was not applied to the active Gateway (superseded); run config.get, then use config.apply to reapply the saved config or restart the Gateway";

    fn is_id_entry(v: &Value) -> bool {
        v.is_object() && matches!(v.get("id"), Some(Value::String(s)) if !s.is_empty())
    }

    fn join(p: &str, k: &str) -> String {
        if p.is_empty() {
            k.to_string()
        } else {
            format!("{p}.{k}")
        }
    }

    pub fn merge(base: &Value, patch: &Value, replace: &HashSet<String>, path: &str) -> Value {
        let Value::Object(patch) = patch else {
            return patch.clone();
        };
        let mut out = base.as_object().cloned().unwrap_or_default();
        for (key, value) in patch {
            let at = join(path, key);
            if value.is_null() {
                out.remove(key);
                continue;
            }
            if let (Some(Value::Array(cur)), Value::Array(value)) = (out.get(key), value)
                && !replace.contains(&at)
                && cur.iter().all(is_id_entry)
            {
                let mut merged = cur.clone();
                for entry in value {
                    let i = if is_id_entry(entry) {
                        merged.iter().position(|m| m["id"] == entry["id"])
                    } else {
                        None
                    };
                    match i {
                        None => merged.push(entry.clone()),
                        Some(i) => merged[i] = merge(&merged[i], entry, replace, &format!("{at}[]")),
                    }
                }
                out.insert(key.clone(), Value::Array(merged));
                continue;
            }
            let next = if value.is_object() {
                merge(out.get(key).unwrap_or(&Value::Null), value, replace, &at)
            } else {
                value.clone()
            };
            out.insert(key.clone(), next);
        }
        Value::Object(out)
    }

    fn arrays_under(base: &Value, path: &str) -> Vec<String> {
        match base {
            Value::Array(_) => vec![path.to_string()],
            Value::Object(m) => m.iter().flat_map(|(k, v)| arrays_under(v, &join(path, k))).collect(),
            _ => Vec::new(),
        }
    }

    fn preserves(base: &[Value], merged: &[Value]) -> bool {
        let mut left: Vec<&Value> = merged.iter().collect();
        for b in base {
            match left.iter().position(|m| *m == b) {
                Some(i) => {
                    left.remove(i);
                }
                None => return false,
            }
        }
        true
    }

    fn destructive(base: &Value, patch: &Value, merged: &Value, path: &str) -> Vec<String> {
        let (Value::Object(patch), Value::Object(base)) = (patch, base) else {
            return Vec::new();
        };
        let empty = Map::new();
        let m = merged.as_object().unwrap_or(&empty);
        let mut out = Vec::new();
        for (key, value) in patch {
            let at = join(path, key);
            let b = base.get(key).unwrap_or(&Value::Null);
            let mv = m.get(key).unwrap_or(&Value::Null);
            if let Value::Array(b) = b {
                let Value::Array(pv) = value else {
                    out.push(at);
                    continue;
                };
                if let Value::Array(mv) = mv {
                    if b.iter().all(is_id_entry) {
                        let ids: Vec<&Value> = mv.iter().filter(|e| is_id_entry(e)).map(|e| &e["id"]).collect();
                        if !b.iter().all(|e| ids.contains(&&e["id"])) {
                            out.push(at);
                            continue;
                        }
                        for pe in pv {
                            if !is_id_entry(pe) {
                                continue;
                            }
                            let be = b.iter().find(|e| e["id"] == pe["id"]);
                            let me = mv.iter().filter(|e| is_id_entry(e)).rev().find(|e| e["id"] == pe["id"]);
                            if let (Some(be), Some(me)) = (be, me) {
                                out.extend(destructive(be, pe, me, &format!("{at}[]")));
                            }
                        }
                    } else if !preserves(b, mv) {
                        out.push(at);
                        continue;
                    }
                }
            } else if b.is_object() && !value.is_object() {
                out.extend(arrays_under(b, &at));
                continue;
            }
            if value.is_object() {
                out.extend(destructive(b, value, mv, &at));
            }
        }
        out
    }

    #[derive(Debug, Clone, Default)]
    pub struct FakeState {
        pub config: Value,
        pub hash: u64,
        pub applied: u64,
        pub stuck: bool,
        pub patches: Vec<(Value, Vec<String>)>,
        /// Every `config.patch` answer, in order: "ok", "superseded", "stale" or "refused".
        pub answers: Vec<String>,
    }

    struct Inner {
        state: FakeState,
        /// The apply under way: its generation and whoever waits for its answer.
        applying: Option<(u64, oneshot::Sender<Result<(), String>>)>,
        generation: u64,
        observed: (u64, Value),
    }

    /// A gateway whose `config.patch` behaves like OpenClaw's, over a config the test can read back.
    #[derive(Clone)]
    pub struct FakeOpenClawConfig {
        inner: Arc<Mutex<Inner>>,
        apply: Option<Duration>,
        watcher_cache: bool,
        accepted: broadcast::Sender<GatewayEvent>,
    }

    impl FakeOpenClawConfig {
        pub fn new(initial: Value, apply: Option<Duration>, watcher_cache: bool) -> Self {
            let initial = if initial.is_object() { initial } else { json!({}) };
            Self {
                inner: Arc::new(Mutex::new(Inner {
                    state: FakeState {
                        config: initial.clone(),
                        hash: 1,
                        applied: 1,
                        ..FakeState::default()
                    },
                    applying: None,
                    generation: 0,
                    observed: (1, initial),
                })),
                apply,
                watcher_cache,
                accepted: broadcast::channel(64).0,
            }
        }

        pub fn state(&self) -> FakeState {
            lock(&self.inner).state.clone()
        }

        pub fn config(&self) -> Value {
            lock(&self.inner).state.config.clone()
        }

        pub fn set_stuck(&self, stuck: bool) {
            lock(&self.inner).state.stuck = stuck;
        }

        /// `config.changed`, broadcast once a revision is accepted.
        pub fn events(&self) -> broadcast::Receiver<GatewayEvent> {
            self.accepted.subscribe()
        }

        fn accept(&self, inner: &mut Inner, revision: u64) {
            inner.state.applied = revision;
            let _ = self.accepted.send(GatewayEvent {
                event: "config.changed".into(),
                payload: Value::Null,
            });
        }

        /// Start applying `revision`, superseding an apply still under way. None when applies are instant.
        fn start_apply(&self, inner: &mut Inner, revision: u64) -> Option<oneshot::Receiver<Result<(), String>>> {
            inner.observed = (inner.state.hash, inner.state.config.clone());
            if let Some((_, tx)) = inner.applying.take() {
                let _ = tx.send(Err(SUPERSEDED_MESSAGE.to_string()));
            }
            let Some(ms) = self.apply else {
                self.accept(inner, revision);
                return None;
            };
            let (tx, rx) = oneshot::channel();
            inner.generation += 1;
            let generation = inner.generation;
            inner.applying = Some((generation, tx));
            let me = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(ms).await;
                let mut inner = lock(&me.inner);
                match inner.applying.take() {
                    Some((g, tx)) if g == generation => {
                        if inner.state.stuck {
                            let _ = tx.send(Err(SUPERSEDED_MESSAGE.to_string()));
                            return;
                        }
                        me.accept(&mut inner, revision);
                        let _ = tx.send(Ok(()));
                    }
                    other => inner.applying = other,
                }
            });
            Some(rx)
        }

        /// `config.get`: the resolved config and the file, as OpenClaw answers.
        pub fn get(&self) -> Value {
            let inner = lock(&self.inner);
            let (hash, config) = if self.watcher_cache {
                inner.observed.clone()
            } else {
                (inner.state.hash, inner.state.config.clone())
            };
            json!({
                "hash": format!("h{hash}"),
                "config": config,
                "parsed": config,
                "configRevisionHash": format!("r{hash}"),
                "appliedConfigHash": format!("r{}", inner.state.applied),
            })
        }

        /// Another writer saves the file: OpenClaw itself, or its CLI. `detect` is how long the
        /// gateway's file watcher takes to see it.
        pub fn external_write(&self, patch: Value, detect: Duration) {
            let revision = {
                let mut inner = lock(&self.inner);
                inner.state.config = merge(&inner.state.config, &patch, &HashSet::new(), "");
                inner.state.hash += 1;
                inner.state.hash
            };
            if detect.is_zero() {
                let mut inner = lock(&self.inner);
                let _ = self.start_apply(&mut inner, revision);
            } else {
                let me = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(detect).await;
                    let mut inner = lock(&me.inner);
                    let _ = me.start_apply(&mut inner, revision);
                });
            }
        }

        /// `config.patch`: refuses like OpenClaw when a list would lose entries unnamed.
        pub async fn patch(&self, params: &Value) -> Result<Value, String> {
            let pending = {
                let mut inner = lock(&self.inner);
                if let Some(b) = params.get("baseHash")
                    && b.as_str() != Some(format!("h{}", inner.state.hash).as_str())
                {
                    inner.state.answers.push("stale".into());
                    return Err("config changed since last load; re-run config.get and retry".into());
                }
                let patch: Value = params["raw"]
                    .as_str()
                    .and_then(|r| serde_json::from_str(r).ok())
                    .unwrap_or(Value::Null);
                let named: Vec<String> = params["replacePaths"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                let replace: HashSet<String> = named
                    .iter()
                    .map(|r| r.trim().trim_end_matches("[]").to_string())
                    .collect();
                let merged = merge(&inner.state.config, &patch, &replace, "");
                let refused: Vec<String> = destructive(&inner.state.config, &patch, &merged, "")
                    .into_iter()
                    .filter(|p| !replace.contains(p))
                    .collect();
                if !refused.is_empty() {
                    inner.state.answers.push("refused".into());
                    return Err(format!(
                        "config.patch would remove entries from array path(s): {}. Pass replacePaths with the exact path(s) when this is intentional, or use config.apply for full-config replacement.",
                        refused.join(", ")
                    ));
                }
                inner.state.config = merged;
                inner.state.patches.push((patch, named));
                inner.state.hash += 1;
                let revision = inner.state.hash;
                match self.start_apply(&mut inner, revision) {
                    None => {
                        inner.state.answers.push("ok".into());
                        return Ok(json!({ "ok": true }));
                    }
                    Some(rx) => rx,
                }
            };
            let r = pending.await.unwrap_or_else(|_| Err(SUPERSEDED_MESSAGE.to_string()));
            let mut inner = lock(&self.inner);
            match r {
                Ok(()) => {
                    inner.state.answers.push("ok".into());
                    Ok(json!({ "ok": true }))
                }
                Err(e) => {
                    inner.state.answers.push("superseded".into());
                    Err(e)
                }
            }
        }
    }

    type Hook = Arc<dyn Fn(&str, &Value) -> Option<Result<Value, String>> + Send + Sync>;

    /// A [`ConfigGateway`] over a [`FakeOpenClawConfig`], with a hook a test can put in front of it.
    pub struct FakeConfigGateway {
        pub oc: FakeOpenClawConfig,
        pub connected: std::sync::atomic::AtomicBool,
        pub with_events: bool,
        hook: Mutex<Option<Hook>>,
    }

    impl FakeConfigGateway {
        pub fn new(oc: FakeOpenClawConfig, with_events: bool) -> Self {
            Self {
                oc,
                connected: std::sync::atomic::AtomicBool::new(true),
                with_events,
                hook: Mutex::new(None),
            }
        }

        pub fn set_connected(&self, up: bool) {
            self.connected.store(up, std::sync::atomic::Ordering::SeqCst);
        }

        /// Answer a call before the fake does; `None` lets it through.
        pub fn hook(&self, f: impl Fn(&str, &Value) -> Option<Result<Value, String>> + Send + Sync + 'static) {
            *lock(&self.hook) = Some(Arc::new(f));
        }
    }

    impl ConfigGateway for FakeConfigGateway {
        fn connected(&self) -> bool {
            self.connected.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn call(&self, method: &str, params: Value, _timeout: Duration) -> BoxFuture<'_, Result<Value, GatewayError>> {
            let method = method.to_string();
            Box::pin(async move {
                let hook = lock(&self.hook).clone();
                let r = match hook.and_then(|h| h(&method, &params)) {
                    Some(r) => r,
                    None => match method.as_str() {
                        "config.get" => Ok(self.oc.get()),
                        "config.patch" => self.oc.patch(&params).await,
                        other => Err(format!("unexpected {other}")),
                    },
                };
                r.map_err(|m| GatewayError::Remote {
                    code: None,
                    message: Some(m),
                })
            })
        }
        fn events(&self) -> Option<broadcast::Receiver<GatewayEvent>> {
            self.with_events.then(|| self.oc.events())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! gateway.test.ts (patchConfig), config-patch-race.test.ts, config-patch-sites.test.ts and
    //! config-activation.test.ts. Times are the TS tests' own, in milliseconds.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use serde_json::json;

    use super::fake_config::{FakeConfigGateway, FakeOpenClawConfig, SUPERSEDED_MESSAGE, merge};
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn quiet() -> Option<LogFn> {
        Some(Arc::new(|_: &str| {}))
    }

    fn lines() -> (Option<LogFn>, Arc<Mutex<Vec<String>>>) {
        let out = Arc::new(Mutex::new(Vec::new()));
        let o = out.clone();
        (Some(Arc::new(move |l: &str| lock(&o).push(l.to_string()))), out)
    }

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn opts(timeout: u64) -> PatchOptions {
        PatchOptions {
            log: quiet(),
            ..PatchOptions::new(ms(timeout))
        }
    }

    fn from_read(snapshot: &Value, timeout: u64) -> PatchOptions {
        PatchOptions {
            base_hash: snapshot["hash"].as_str().map(str::to_string),
            snapshot: Some(snapshot.clone()),
            ..opts(timeout)
        }
    }

    fn gateway_over(
        initial: Value,
        apply: Option<u64>,
        watcher_cache: bool,
        events: bool,
    ) -> (FakeOpenClawConfig, Arc<FakeConfigGateway>) {
        let oc = FakeOpenClawConfig::new(initial, apply.map(ms), watcher_cache);
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), events));
        (oc, gw)
    }

    fn writer(gw: &Arc<FakeConfigGateway>) -> ConfigWriter {
        ConfigWriter::new(gw.clone())
    }

    fn telegram() -> Map<String, Value> {
        obj(json!({ "channels": { "telegram": { "enabled": true, "botToken": "123:abc", "dmPolicy": "pairing" } } }))
    }
    fn console_mcp() -> Map<String, Value> {
        obj(json!({ "mcp": { "servers": { "controlclaw": { "url": "http://127.0.0.1:3100/mcp" } } } }))
    }
    fn paste_token() -> Value {
        json!({ "auth": { "profiles": { "controlclaw:included": { "provider": "controlclaw" } } } })
    }

    fn answers(oc: &FakeOpenClawConfig) -> Vec<String> {
        oc.state().answers
    }

    // ---- config-patch-race.test.ts (T-180) ----

    #[tokio::test]
    async fn the_fake_supersedes_the_first_of_two_writers_that_do_not_wait() {
        let (oc, gw) = gateway_over(json!({}), Some(30), false, false);
        let first = gw.call(
            "config.patch",
            json!({ "raw": Value::Object(telegram()).to_string(), "baseHash": "h1" }),
            ms(1000),
        );
        let second = gw.call(
            "config.patch",
            json!({ "raw": Value::Object(console_mcp()).to_string(), "baseHash": "h2" }),
            ms(1000),
        );
        let (a, b) = tokio::join!(first, second);
        assert!(is_persisted_superseded(&a.unwrap_err().to_string()));
        b.unwrap();
        assert_eq!(answers(&oc), ["superseded", "ok"]);
        assert_eq!(
            oc.config()["channels"]["telegram"],
            telegram()["channels"]["telegram"],
            "still in the file"
        );
    }

    #[tokio::test]
    async fn writers_on_one_gateway_go_one_at_a_time() {
        let (oc, gw) = gateway_over(json!({}), Some(30), false, false);
        let w = writer(&gw);
        let snapshot = oc.get();
        let (tg, mcp) = (telegram(), console_mcp());
        let (a, b) = tokio::join!(
            w.patch(&tg, from_read(&snapshot, 1000)),
            w.patch(&mcp, from_read(&snapshot, 1000)),
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(answers(&oc), ["ok", "stale", "ok"], "no supersede");
        assert_eq!(oc.config()["channels"]["telegram"], telegram()["channels"]["telegram"]);
        assert!(oc.config()["mcp"]["servers"]["controlclaw"].is_object());
        let s = oc.state();
        assert_eq!(s.applied, s.hash, "the gateway runs the saved config");
    }

    #[tokio::test]
    async fn a_write_whose_parts_another_writer_changed_is_refused_not_replayed() {
        let (oc, gw) = gateway_over(
            json!({ "plugins": { "entries": { "voice-call": { "config": { "model": "a", "allowFrom": ["+1"] } } } } }),
            Some(5),
            false,
            false,
        );
        let w = writer(&gw);
        let snapshot = oc.get();
        let phone =
            obj(json!({ "plugins": { "entries": { "voice-call": { "config": { "allowFrom": ["+1", "+2"] } } } } }));
        let llm = obj(
            json!({ "plugins": { "entries": { "voice-call": { "config": { "model": "b", "allowFrom": ["+1"] } } } } }),
        );
        let (a, b) = tokio::join!(
            w.patch(&phone, from_read(&snapshot, 1000)),
            w.patch(&llm, from_read(&snapshot, 1000))
        );
        a.unwrap();
        assert!(b.unwrap_err().to_string().contains("config changed since last load"));
        assert_eq!(
            oc.config()["plugins"]["entries"]["voice-call"],
            json!({ "config": { "model": "a", "allowFrom": ["+1", "+2"] } }),
            "the caller is not lost"
        );
    }

    #[tokio::test]
    async fn the_queue_is_let_go_while_a_superseded_write_waits() {
        let (oc, gw) = gateway_over(json!({}), Some(200), false, false);
        let w = Arc::new(writer(&gw));
        let o = oc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ms(20)).await;
            o.external_write(
                json!({ "plugins": { "entries": { "telegram": { "enabled": true } } } }),
                Duration::ZERO,
            );
        });
        let order = Arc::new(Mutex::new(Vec::new()));
        let (w1, o1) = (w.clone(), order.clone());
        let first = tokio::spawn(async move {
            w1.patch(&telegram(), opts(1000)).await.unwrap();
            lock(&o1).push("telegram");
        });
        tokio::time::sleep(ms(60)).await;
        let (w2, o2) = (w.clone(), order.clone());
        let second = tokio::spawn(async move {
            w2.patch(&console_mcp(), opts(1000)).await.unwrap();
            lock(&o2).push("mcp");
        });
        first.await.unwrap();
        second.await.unwrap();
        assert_eq!(*lock(&order), ["mcp", "telegram"]);
    }

    #[tokio::test]
    async fn a_caller_that_stops_waiting_keeps_the_queue_until_its_write_is_answered() {
        let (oc, gw) = gateway_over(json!({}), Some(150), false, false);
        let w = writer(&gw);
        // The route gives up long before OpenClaw answers.
        let tg = telegram();
        let gave_up = tokio::time::timeout(ms(20), w.patch(&tg, opts(2000))).await;
        assert!(gave_up.is_err());
        w.patch(&console_mcp(), opts(2000)).await.unwrap();
        assert_eq!(answers(&oc), ["ok", "ok"], "the first write was not superseded");
    }

    #[tokio::test]
    async fn a_cli_write_waits_for_the_write_being_applied() {
        let (oc, gw) = gateway_over(json!({}), Some(100), false, false);
        let w = Arc::new(writer(&gw));
        let w1 = w.clone();
        let tg = tokio::spawn(async move { w1.patch(&telegram(), opts(2000)).await });
        tokio::time::sleep(ms(10)).await;
        let o = oc.clone();
        w.write(
            || async move { o.external_write(paste_token(), Duration::ZERO) },
            QueueOptions::default(),
        )
        .await;
        tg.await.unwrap().unwrap();
        assert_eq!(answers(&oc), ["ok"], "the Telegram write was not superseded");
    }

    #[tokio::test]
    async fn file_write_holds_the_next_write_until_the_cli_file_is_applied() {
        let (raced, rgw) = gateway_over(json!({}), Some(100), false, false);
        let rw = writer(&rgw);
        let r = raced.clone();
        rw.write(
            || async move { r.external_write(paste_token(), ms(50)) },
            QueueOptions::default(),
        )
        .await;
        let hash = raced.get()["hash"].clone();
        let e = rgw
            .call(
                "config.patch",
                json!({ "raw": Value::Object(telegram()).to_string(), "baseHash": hash }),
                ms(1000),
            )
            .await
            .unwrap_err();
        assert!(is_persisted_superseded(&e.to_string()));

        let (oc, gw) = gateway_over(json!({}), Some(100), false, false);
        let w = writer(&gw);
        let o = oc.clone();
        let q = QueueOptions {
            settle: Some(ms(2000)),
            ..QueueOptions::default()
        };
        w.file_write(
            || async move {
                o.external_write(paste_token(), ms(50));
                Ok::<_, ()>(())
            },
            q,
        )
        .await
        .unwrap();
        w.patch(&telegram(), opts(2000)).await.unwrap();
        assert_eq!(answers(&oc), ["ok"]);
    }

    #[tokio::test]
    async fn a_write_sent_again_after_a_restart_is_refused_when_its_parts_changed() {
        let (oc, gw) = gateway_over(
            json!({ "plugins": { "entries": { "voice-call": { "config": { "allowFrom": ["+1"] } } } } }),
            Some(5),
            false,
            false,
        );
        let snapshot = oc.get();
        let first = AtomicBool::new(true);
        let o = oc.clone();
        gw.hook(move |m, _| {
            if m == "config.patch" && first.swap(false, Ordering::SeqCst) {
                o.external_write(
                    json!({ "plugins": { "entries": { "voice-call": { "config": { "allowFrom": ["+1", "+2"] } } } } }),
                    Duration::ZERO,
                );
                return Some(Err("config.patch unavailable during gateway restart".into()));
            }
            None
        });
        let patch = obj(
            json!({ "plugins": { "entries": { "voice-call": { "config": { "allowFrom": ["+1"], "model": "b" } } } } }),
        );
        let e = writer(&gw).patch(&patch, from_read(&snapshot, 1000)).await.unwrap_err();
        assert!(e.to_string().contains("unavailable during gateway restart"));
        assert_eq!(
            oc.config()["plugins"]["entries"]["voice-call"]["config"]["allowFrom"],
            json!(["+1", "+2"])
        );
    }

    #[tokio::test]
    async fn superseded_by_openclaw_itself_is_waited_for_and_not_sent_twice() {
        let (oc, gw) = gateway_over(json!({}), Some(200), false, false);
        let o = oc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ms(20)).await;
            o.external_write(
                json!({ "plugins": { "entries": { "telegram": { "enabled": true } } } }),
                Duration::ZERO,
            );
        });
        let (log, out) = lines();
        writer(&gw)
            .patch(
                &telegram(),
                PatchOptions {
                    log,
                    ..PatchOptions::new(ms(1000))
                },
            )
            .await
            .unwrap();
        assert_eq!(answers(&oc), ["superseded"], "one config.patch, answered superseded");
        let s = oc.state();
        assert_eq!(s.applied, s.hash, "returned only once the saved config was active");
        assert_eq!(oc.config()["channels"]["telegram"], telegram()["channels"]["telegram"]);
        assert!(lock(&out).iter().any(|l| l.contains("newer write took over")));
    }

    #[tokio::test]
    async fn superseded_and_never_active_says_the_config_was_saved() {
        let (oc, gw) = gateway_over(json!({}), Some(20), false, false);
        oc.set_stuck(true);
        let o = PatchOptions {
            active_wait: Some(ms(100)),
            ..opts(1000)
        };
        let e = writer(&gw).patch(&telegram(), o).await.unwrap_err();
        assert!(e.to_string().contains("saved but the agent has not applied it yet"));
    }

    #[tokio::test]
    async fn a_file_changed_elsewhere_since_the_read_is_written_again_against_the_new_hash() {
        let (oc, gw) = gateway_over(json!({}), Some(5), false, false);
        let snapshot = oc.get();
        oc.external_write(
            json!({ "plugins": { "entries": { "telegram": { "enabled": true } } } }),
            Duration::ZERO,
        );
        tokio::time::sleep(ms(10)).await;
        writer(&gw)
            .patch(&telegram(), from_read(&snapshot, 1000))
            .await
            .unwrap();
        assert_eq!(answers(&oc), ["stale", "ok"]);
    }

    #[test]
    fn the_superseded_answer_is_told_apart() {
        assert!(is_persisted_superseded(SUPERSEDED_MESSAGE));
        assert!(!is_persisted_superseded(
            "config.patch persisted but was not applied to the active Gateway (failed); run config.get"
        ));
        assert!(!is_persisted_superseded(
            "config.patch persisted and was accepted for restart"
        ));
    }

    #[tokio::test]
    async fn a_write_saved_before_the_socket_dropped_is_done() {
        // Applies at once here, so the hook can save synchronously before the answer is lost.
        let (oc, gw) = gateway_over(
            json!({ "plugins": { "entries": { "voice-call": { "config": { "model": "a" } } } } }),
            None,
            false,
            false,
        );
        let snapshot = oc.get();
        let first = AtomicBool::new(true);
        let o = oc.clone();
        gw.hook(move |m, p| {
            if m == "config.patch" && first.swap(false, Ordering::SeqCst) {
                let saved = o.patch(p).now_or_never();
                assert!(matches!(saved, Some(Ok(_))));
                return Some(Err("gateway disconnected".into()));
            }
            None
        });
        let patch = obj(json!({ "plugins": { "entries": { "voice-call": { "config": { "model": "b" } } } } }));
        writer(&gw).patch(&patch, from_read(&snapshot, 1000)).await.unwrap();
        assert_eq!(oc.state().patches.len(), 1, "saved once, not sent again");
        assert_eq!(
            oc.config()["plugins"]["entries"]["voice-call"],
            json!({ "config": { "model": "b" } })
        );
    }

    #[tokio::test]
    async fn the_first_read_waits_out_a_restarting_gateway() {
        let (oc, gw) = gateway_over(json!({}), Some(5), false, false);
        gw.set_connected(false);
        let g = gw.clone();
        gw.hook(move |_, _| (!g.connected()).then(|| Err("gateway not connected".into())));
        let g = gw.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ms(100)).await;
            g.set_connected(true);
        });
        writer(&gw).patch(&telegram(), opts(1000)).await.unwrap();
        assert_eq!(answers(&oc), ["ok"]);
    }

    #[tokio::test]
    async fn file_write_answers_at_once_and_holds_the_queue_until_accepted() {
        let (oc, gw) = gateway_over(json!({}), Some(150), false, true);
        let w = Arc::new(writer(&gw));
        let started = Instant::now();
        let o = oc.clone();
        let q = QueueOptions {
            settle: Some(ms(2000)),
            ..QueueOptions::default()
        };
        w.file_write(
            || async move {
                o.external_write(paste_token(), ms(50));
                Ok::<_, ()>(())
            },
            q,
        )
        .await
        .unwrap();
        let answered = started.elapsed();
        let patch_at = w.write(|| async { started.elapsed() }, QueueOptions::default()).await;
        assert!(answered < ms(40), "answered at once ({answered:?})");
        assert!(
            patch_at >= ms(190),
            "the next write waited for config.changed ({patch_at:?})"
        );
        assert!(patch_at < ms(1000), "and not the whole settle time");
    }

    #[tokio::test]
    async fn file_write_waits_for_config_changed_not_a_cached_config_get() {
        let (polled, pgw) = gateway_over(json!({}), Some(150), true, false);
        let pw = writer(&pgw);
        let p = polled.clone();
        let q = QueueOptions {
            settle: Some(ms(2000)),
            ..QueueOptions::default()
        };
        pw.file_write(
            || async move {
                p.external_write(paste_token(), ms(50));
                Ok::<_, ()>(())
            },
            q.clone(),
        )
        .await
        .unwrap();
        tokio::time::sleep(ms(5)).await;
        let hash = format!("h{}", polled.state().hash);
        let e = pgw
            .call(
                "config.patch",
                json!({ "raw": Value::Object(telegram()).to_string(), "baseHash": hash }),
                ms(1000),
            )
            .await
            .unwrap_err();
        assert!(
            is_persisted_superseded(&e.to_string()),
            "polling config.get let the next write in too early"
        );

        let (oc, gw) = gateway_over(json!({}), Some(150), true, true);
        let w = writer(&gw);
        let o = oc.clone();
        w.file_write(
            || async move {
                o.external_write(paste_token(), ms(50));
                Ok::<_, ()>(())
            },
            q,
        )
        .await
        .unwrap();
        w.write(|| async {}, QueueOptions::default()).await;
        w.patch(&telegram(), opts(2000)).await.unwrap();
        assert_eq!(answers(&oc), ["ok"]);
    }

    #[tokio::test]
    async fn file_write_does_not_wait_when_the_gateway_is_down_after_the_cli() {
        let (oc, gw) = gateway_over(json!({}), Some(150), false, true);
        let w = writer(&gw);
        let started = Instant::now();
        let (o, g) = (oc.clone(), gw.clone());
        w.file_write(
            || async move {
                o.external_write(paste_token(), ms(50));
                g.set_connected(false);
                Ok::<_, ()>(())
            },
            QueueOptions::default(),
        )
        .await
        .unwrap();
        gw.set_connected(true);
        w.write(|| async {}, QueueOptions::default()).await;
        assert!(
            started.elapsed() < ms(100),
            "the queue moved on at once ({:?})",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn pairing_approve_goes_in_beside_a_long_write_ahead() {
        let (oc, gw) = gateway_over(json!({}), Some(600), false, false);
        let w = Arc::new(writer(&gw));
        let w1 = w.clone();
        let tg = tokio::spawn(async move { w1.patch(&telegram(), opts(2000)).await });
        tokio::time::sleep(ms(10)).await;
        let started = Instant::now();
        let q = QueueOptions {
            max_queue_wait: Some(ms(50)),
            settle: Some(Duration::ZERO),
            log: quiet(),
        };
        let ran_at = w
            .file_write(|| async { Ok::<_, ()>(started.elapsed()) }, q)
            .await
            .unwrap();
        assert!(
            ran_at >= ms(45) && ran_at < ms(300),
            "ran after the bounded wait ({ran_at:?})"
        );
        tg.await.unwrap().unwrap();
        assert!(answers(&oc).contains(&"ok".to_string()));
    }

    // ---- gateway.test.ts: patchConfig around a restart (T-103) ----

    const PERSISTED: &str = "config.patch persisted and updated the active Gateway, but a recovery restart is required; wait for the Gateway to restart, then run config.get to confirm the active revision";

    /// Answers `config.patch` from a script, and can drop and come back.
    struct Scripted {
        answers: Mutex<Vec<Option<String>>>,
        calls: Mutex<Vec<(String, Value)>>,
        hash: AtomicUsize,
        conn: watch::Sender<bool>,
    }

    impl Scripted {
        fn new(answers: Vec<Option<&str>>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers.into_iter().map(|a| a.map(str::to_string)).collect()),
                calls: Mutex::new(Vec::new()),
                hash: AtomicUsize::new(0),
                conn: watch::channel(true).0,
            })
        }
        fn restart(self: &Arc<Self>, after: u64, back: u64) {
            let me = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(ms(after)).await;
                me.conn.send_replace(false);
                tokio::time::sleep(ms(back)).await;
                me.conn.send_replace(true);
            });
        }
        fn patches(&self) -> Vec<Value> {
            lock(&self.calls)
                .iter()
                .filter(|(m, _)| m == "config.patch")
                .map(|(_, p)| p.clone())
                .collect()
        }
    }

    impl ConfigGateway for Scripted {
        fn connected(&self) -> bool {
            *self.conn.borrow()
        }
        fn call(&self, method: &str, params: Value, _t: Duration) -> BoxFuture<'_, Result<Value, GatewayError>> {
            lock(&self.calls).push((method.to_string(), params));
            let r = if method == "config.get" {
                Ok(json!({ "hash": format!("h{}", self.hash.fetch_add(1, Ordering::SeqCst) + 1) }))
            } else {
                let mut a = lock(&self.answers);
                match if a.is_empty() { None } else { a.remove(0) } {
                    Some(m) => Err(GatewayError::Remote {
                        code: None,
                        message: Some(m),
                    }),
                    None => Ok(json!({ "ok": true })),
                }
            };
            Box::pin(async move { r })
        }
        fn connection_state(&self) -> Option<watch::Receiver<bool>> {
            Some(self.conn.subscribe())
        }
    }

    #[tokio::test]
    async fn saved_behind_a_pending_restart_is_done_once_back_and_not_sent_twice() {
        let gw = Scripted::new(vec![Some(PERSISTED)]);
        gw.restart(20, 30);
        let started = Instant::now();
        let o = PatchOptions {
            base_hash: Some("h0".into()),
            ..opts(1000)
        };
        ConfigWriter::new(gw.clone())
            .patch(&obj(json!({ "channels": { "telegram": { "enabled": true } } })), o)
            .await
            .unwrap();
        assert!(started.elapsed() >= ms(45), "it waited for the restart to finish");
        assert!(gw.connected());
        assert_eq!(gw.patches().len(), 1);
    }

    #[tokio::test]
    async fn landed_in_the_restart_window_is_sent_again_against_a_fresh_hash() {
        let gw = Scripted::new(vec![Some("config.patch unavailable during gateway restart")]);
        gw.restart(0, 10);
        let o = PatchOptions {
            base_hash: Some("h0".into()),
            snapshot: Some(json!({ "hash": "h0" })),
            ..opts(1000)
        };
        ConfigWriter::new(gw.clone())
            .patch(&obj(json!({ "memory": { "search": { "model": "m" } } })), o)
            .await
            .unwrap();
        let hashes: Vec<Value> = gw.patches().iter().map(|p| p["baseHash"].clone()).collect();
        assert_eq!(
            hashes,
            [json!("h0"), json!("h1")],
            "the retry read the config again for its hash"
        );
    }

    #[tokio::test]
    async fn other_refusals_are_the_callers_and_a_second_restart_window_is_not_retried() {
        let gw = Scripted::new(vec![Some("invalid config: channels.telegram.botToken")]);
        let o = PatchOptions {
            base_hash: Some("h0".into()),
            ..opts(1000)
        };
        let e = ConfigWriter::new(gw)
            .patch(&obj(json!({ "a": 1 })), o)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("invalid config"));
        let gw = Scripted::new(vec![Some("gateway disconnected"), Some("gateway disconnected")]);
        let o = PatchOptions {
            base_hash: Some("h0".into()),
            snapshot: Some(json!({ "hash": "h0" })),
            ..opts(1000)
        };
        let e = ConfigWriter::new(gw.clone())
            .patch(&obj(json!({ "a": 1 })), o)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("gateway disconnected"));
        assert_eq!(gw.patches().len(), 2);
    }

    #[test]
    fn the_two_openclaw_answers_are_told_apart() {
        assert!(is_persisted_pending_restart(PERSISTED));
        assert!(is_persisted_pending_restart(
            "config.patch persisted and was accepted for restart; wait for the Gateway to restart"
        ));
        assert!(!is_persisted_pending_restart(
            "config.patch persisted but was not applied to the active Gateway (failed)"
        ));
        assert!(is_restart_window(
            "audit.activity.list unavailable during gateway restart"
        ));
        assert!(!is_restart_window(PERSISTED));
    }

    // ---- config-patch-sites.test.ts ----

    fn agent_config() -> Value {
        json!({
            "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw", "fallbacks": ["controlclaw/anthropic/claude-sonnet-5@controlclaw:controlclaw"] } } },
            "models": { "providers": { "controlclaw": included_block() } },
            "plugins": {
                "allow": ["telegram", "voice-call", "google-meet"],
                "entries": {
                    "voice-call": { "enabled": true, "config": {
                        "allowFrom": ["+15550001", "+15550002"],
                        "realtime": { "providers": { "cc-phone-voice": { "wake": { "enabled": true, "words": ["Nova", "hey Nova"] } } } }
                    } },
                    "google-meet": { "enabled": true, "config": { "realtime": { "providers": { "cc-meeting-voice": { "wake": { "enabled": true, "words": ["Nova", "Orbit"] } } } } } },
                    "brave": { "enabled": true, "config": { "webSearch": { "apiKey": "cc-search-x", "includeDomains": ["example.com"] } } }
                }
            },
            "channels": {
                "telegram": { "enabled": true, "botToken": "cc-tg-x", "dmPolicy": "pairing", "allowFrom": ["111", "222"] },
                "agentmail": { "inboxId": "agent@agentmail.to", "dmPolicy": "allowlist", "allowFrom": ["owner@example.com", "pa@example.com"] },
                "clickclack": { "enabled": true, "allowFrom": ["*", "bot-a", "bot-b"] }
            },
            "mcp": { "servers": {
                "cc-brain": { "url": "https://brain.example/mcp", "transport": "streamable-http", "tools": ["search", "read"] },
                "controlclaw-apps": { "url": "http://127.0.0.1:3111/mcp", "transport": "streamable-http", "tools": ["execute_action"] }
            } }
        })
    }

    fn included_block() -> Value {
        json!({
            "baseUrl": "https://ai-gateway.vercel.sh/v1",
            "api": "openai-completions",
            "models": [
                { "id": "anthropic/claude-sonnet-5", "name": "Claude Sonnet 5" },
                { "id": "openai/gpt-5.6-sol", "name": "GPT-5.6 Sol" }
            ]
        })
    }

    fn sites() -> Vec<(&'static str, Value, &'static str, Value)> {
        // (site, patch, pointer to check, expected value there; Null = absent)
        vec![
            (
                "llm: replace the fallback",
                json!({ "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw", "fallbacks": ["anthropic/claude-opus-5@anthropic:controlclaw"] } } } }),
                "/agents/defaults/model/fallbacks",
                json!(["anthropic/claude-opus-5@anthropic:controlclaw"]),
            ),
            (
                "llm: remove the fallback and the included block",
                json!({ "models": { "providers": { "controlclaw": null } }, "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw", "fallbacks": [] } } } }),
                "/models/providers/controlclaw",
                Value::Null,
            ),
            (
                "llm: no model at all",
                json!({ "agents": { "defaults": { "model": null } } }),
                "/agents/defaults/model",
                Value::Null,
            ),
            // channelBlock({ remove: true }) is null.
            (
                "channels: remove Telegram",
                json!({ "channels": { "telegram": null } }),
                "/channels/telegram",
                Value::Null,
            ),
            (
                "channels: Team chat loses a peer",
                json!({ "channels": { "clickclack": { "allowFrom": ["*", "bot-a"] } } }),
                "/channels/clickclack/allowFrom",
                json!(["*", "bot-a"]),
            ),
            (
                "agentmail: a sender taken off",
                json!({ "channels": { "agentmail": { "allowFrom": ["owner@example.com"] } } }),
                "/channels/agentmail/allowFrom",
                json!(["owner@example.com"]),
            ),
            (
                "agentmail: inbox forgotten",
                json!({ "channels": { "agentmail": null } }),
                "/channels/agentmail",
                Value::Null,
            ),
            (
                "phone: turned off",
                json!({ "plugins": { "entries": { "voice-call": { "enabled": false, "config": null } } } }),
                "/plugins/entries/voice-call/config",
                Value::Null,
            ),
            (
                "meetings: a wake name removed",
                json!({ "plugins": { "entries": { "google-meet": { "config": { "realtime": { "providers": { "cc-meeting-voice": { "wake": { "enabled": true, "words": ["Nova"] } } } } } } } } }),
                "/plugins/entries/google-meet/config/realtime/providers/cc-meeting-voice/wake/words",
                json!(["Nova"]),
            ),
            (
                "search: our plugin's entry cleared",
                json!({ "plugins": { "entries": { "brave": null } }, "tools": { "web": { "search": { "provider": null } } } }),
                "/plugins/entries/brave",
                Value::Null,
            ),
            (
                "mcp: a server removed",
                json!({ "mcp": { "servers": { "cc-brain": null } } }),
                "/mcp/servers/cc-brain",
                Value::Null,
            ),
            (
                "connectors: the connectors server removed",
                json!({ "mcp": { "servers": { "controlclaw": null, "controlclaw-apps": null } } }),
                "/mcp/servers/controlclaw-apps",
                Value::Null,
            ),
        ]
    }

    #[tokio::test]
    async fn every_site_is_refused_as_written_and_goes_through_patch() {
        for (site, patch, at, want) in sites() {
            let bare = FakeOpenClawConfig::new(agent_config(), None, false);
            let e = bare
                .patch(&json!({ "raw": patch.to_string(), "baseHash": "h1" }))
                .await
                .unwrap_err();
            assert!(
                e.contains("would remove entries from array path(s)"),
                "{site}: OpenClaw refuses it as written"
            );
            let (oc, gw) = gateway_over(agent_config(), None, false, false);
            writer(&gw).patch(&obj(patch), opts(1000)).await.unwrap();
            assert_eq!(oc.config().pointer(at).cloned().unwrap_or(Value::Null), want, "{site}");
        }
    }

    #[test]
    fn patches_that_shrink_nothing_name_nothing() {
        for patch in [
            json!({ "plugins": { "entries": { "telegram": { "enabled": true } } } }),
            json!({ "hooks": { "enabled": true, "token": "t", "path": "/hooks", "allowRequestSessionKey": false } }),
            json!({ "plugins": { "allow": ["telegram", "voice-call", "google-meet", "cc-meeting-voice"] } }),
            json!({ "mcp": { "servers": { "cc-console": { "url": "http://10.0.0.2:3200/mcp", "transport": "streamable-http" } } } }),
            json!({ "agents": { "defaults": { "model": { "primary": "openai/gpt-5.6-sol@openai:controlclaw", "fallbacks": ["controlclaw/anthropic/claude-sonnet-5@controlclaw:controlclaw"] } } } }),
        ] {
            assert!(array_replace_paths(&agent_config(), &patch).is_empty(), "{patch}");
        }
    }

    #[test]
    fn array_replace_paths_names_exactly_what_openclaw_asks_for() {
        let s = sites();
        assert_eq!(
            array_replace_paths(&agent_config(), &s[0].1),
            ["agents.defaults.model.fallbacks"]
        );
        let mut two = array_replace_paths(&agent_config(), &s[1].1);
        two.sort();
        assert_eq!(
            two,
            ["agents.defaults.model.fallbacks", "models.providers.controlclaw.models"]
        );
        let mut phone = array_replace_paths(
            &agent_config(),
            &json!({ "plugins": { "entries": { "voice-call": { "enabled": false, "config": null } } } }),
        );
        phone.sort();
        assert_eq!(
            phone,
            [
                "plugins.entries.voice-call.config.allowFrom",
                "plugins.entries.voice-call.config.realtime.providers.cc-phone-voice.wake.words"
            ]
        );
        let first_model = included_block()["models"][0].clone();
        assert!(
            array_replace_paths(
                &agent_config(),
                &json!({ "models": { "providers": { "controlclaw": { "models": [first_model] } } } })
            )
            .is_empty()
        );
        assert!(
            array_replace_paths(
                &agent_config(),
                &json!({ "channels": { "telegram": { "allowFrom": ["222", "111"] } } })
            )
            .is_empty()
        );
        assert!(array_replace_paths(&json!({}), &s[1].1).is_empty());
    }

    #[tokio::test]
    async fn a_retried_write_names_the_lists_against_the_config_it_reads_again() {
        let (oc, gw) = gateway_over(agent_config(), None, false, false);
        let first = AtomicBool::new(true);
        gw.hook(move |m, _| {
            (m == "config.patch" && first.swap(false, Ordering::SeqCst)).then(|| Err("gateway disconnected".into()))
        });
        let o = PatchOptions {
            base_hash: Some("h1".into()),
            snapshot: Some(oc.get()),
            ..opts(1000)
        };
        writer(&gw).patch(&obj(sites()[0].1.clone()), o).await.unwrap();
        assert_eq!(
            oc.config()["agents"]["defaults"]["model"]["fallbacks"],
            json!(["anthropic/claude-opus-5@anthropic:controlclaw"])
        );
    }

    #[test]
    fn the_fake_merges_lists_of_ids_by_id() {
        let base = json!({ "a": [{ "id": "x", "v": 1 }] });
        let out = merge(
            &base,
            &json!({ "a": [{ "id": "x", "w": 2 }, { "id": "y" }] }),
            &Default::default(),
            "",
        );
        assert_eq!(out, json!({ "a": [{ "id": "x", "v": 1, "w": 2 }, { "id": "y" }] }));
    }

    // ---- config-activation.test.ts (T-111) ----

    const SAVED: &str = "rev-saved";
    const OLD: &str = "rev-old";

    /// A gateway whose `config.get` reports saved vs applied, and a restart that applies.
    struct BoxFake {
        connected: AtomicBool,
        saved: Mutex<String>,
        applied: Mutex<String>,
        reads: AtomicUsize,
        restarts: AtomicUsize,
        restart_applies: bool,
        no_hashes: AtomicBool,
        /// Run after the next read is answered (once).
        after_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl BoxFake {
        fn new(applied: &str, restart_applies: bool) -> Arc<Self> {
            Arc::new(Self {
                connected: AtomicBool::new(true),
                saved: Mutex::new(SAVED.into()),
                applied: Mutex::new(applied.into()),
                reads: AtomicUsize::new(0),
                restarts: AtomicUsize::new(0),
                restart_applies,
                no_hashes: AtomicBool::new(false),
                after_read: Mutex::new(None),
            })
        }
        fn set_saved(&self, s: &str) {
            *lock(&self.saved) = s.into();
        }
        fn restarts(&self) -> usize {
            self.restarts.load(Ordering::SeqCst)
        }
    }

    impl ConfigGateway for BoxFake {
        fn connected(&self) -> bool {
            self.connected.load(Ordering::SeqCst)
        }
        fn call(&self, method: &str, _p: Value, _t: Duration) -> BoxFuture<'_, Result<Value, GatewayError>> {
            assert_eq!(method, "config.get");
            self.reads.fetch_add(1, Ordering::SeqCst);
            let r = if self.no_hashes.load(Ordering::SeqCst) {
                json!({ "hash": "raw" })
            } else {
                json!({ "hash": "raw", "configRevisionHash": *lock(&self.saved), "appliedConfigHash": *lock(&self.applied) })
            };
            if let Some(f) = lock(&self.after_read).take() {
                f();
            }
            Box::pin(async move { Ok(r) })
        }
    }

    fn watcher(b: &Arc<BoxFake>, deferred: Option<Arc<AtomicBool>>) -> (ConfigActivation, Arc<Mutex<Vec<String>>>) {
        let (log, out) = lines();
        let bb = b.clone();
        let restart: RestartFn = Arc::new(move || {
            bb.restarts.fetch_add(1, Ordering::SeqCst);
            if bb.restart_applies {
                let s = lock(&bb.saved).clone();
                *lock(&bb.applied) = s;
            }
            Box::pin(async { Ok(()) })
        });
        let mut o = ActivationOptions::new(b.clone(), restart);
        o.log = log;
        o.settle = ms(20);
        o.grace = ms(60);
        o.poll = ms(5);
        o.down = ms(200);
        o.restart_deferred = deferred.map(|d| -> DeferredFn {
            Arc::new(move || {
                let v = d.load(Ordering::SeqCst);
                Box::pin(async move { v })
            })
        });
        (ConfigActivation::new(o), out)
    }

    async fn verdict(w: &ConfigActivation) -> ActivationOutcome {
        w.next_verdict().await.unwrap()
    }

    #[test]
    fn config_active_compares_saved_with_applied() {
        assert_eq!(
            config_active(&json!({ "configRevisionHash": "a", "appliedConfigHash": "a" })),
            Some(true)
        );
        assert_eq!(
            config_active(&json!({ "configRevisionHash": "a", "appliedConfigHash": "b" })),
            Some(false)
        );
        assert_eq!(config_active(&json!({ "hash": "a" })), None);
        assert_eq!(
            config_active(&json!({ "configRevisionHash": null, "appliedConfigHash": "b" })),
            None
        );
        assert_eq!(config_active(&Value::Null), None);
    }

    #[tokio::test]
    async fn applied_on_its_own_causes_no_restart() {
        let b = BoxFake::new(SAVED, true);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_started();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        assert_eq!(b.restarts(), 0);
    }

    #[tokio::test]
    async fn left_behind_is_restarted_once_the_grace_runs_out() {
        let b = BoxFake::new(OLD, true);
        let (w, out) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_started();
        w.write_ended();
        let started = Instant::now();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        assert_eq!(b.restarts(), 1);
        assert!(started.elapsed() >= ms(80), "waited the settle and the grace first");
        assert!(lock(&out).join("\n").contains("restarting it"));
    }

    #[tokio::test]
    async fn several_writes_in_a_row_end_in_one_restart() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        for _ in 0..4 {
            w.write_started();
            w.write_ended();
            tokio::time::sleep(ms(8)).await;
        }
        let v = w.next_verdict();
        w.changed();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        let v = w.next_verdict();
        w.reconnected();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        assert_eq!(b.restarts(), 1);
    }

    #[tokio::test]
    async fn no_verdict_while_a_write_is_in_flight() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        w.write_started();
        tokio::time::sleep(ms(150)).await;
        assert_eq!(b.reads.load(Ordering::SeqCst), 0);
        assert_eq!(b.restarts(), 0);
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
    }

    #[tokio::test]
    async fn a_gateway_restarting_by_itself_is_waited_for() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        tokio::time::sleep(ms(25)).await;
        b.connected.store(false, Ordering::SeqCst);
        tokio::time::sleep(ms(100)).await;
        *lock(&b.applied) = SAVED.into();
        b.connected.store(true, Ordering::SeqCst);
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        assert_eq!(b.restarts(), 0);
    }

    #[tokio::test]
    async fn a_write_during_the_grace_starts_the_clock_again() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        w.write_ended();
        tokio::time::sleep(ms(60)).await;
        w.write_started();
        w.write_ended();
        tokio::time::sleep(ms(40)).await;
        assert_eq!(b.restarts(), 0);
        assert_eq!(verdict(&w).await, ActivationOutcome::Restarted);
        assert_eq!(b.restarts(), 1);
    }

    #[tokio::test]
    async fn a_stopped_openclaw_is_never_started() {
        let b = BoxFake::new(OLD, true);
        b.connected.store(false, Ordering::SeqCst);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Down);
        assert_eq!(b.restarts(), 0);
        assert_eq!(b.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_restart_that_does_not_fix_it_is_not_repeated_in_the_cooldown() {
        let b = BoxFake::new(OLD, false);
        let (w, out) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        let v = w.next_verdict();
        w.reconnected();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Stuck);
        assert_eq!(b.restarts(), 1);
        assert!(lock(&out).join("\n").contains("leaving it"));
    }

    #[tokio::test]
    async fn no_hashes_is_left_alone() {
        let b = BoxFake::new(OLD, true);
        b.no_hashes.store(true, Ordering::SeqCst);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Unknown);
        assert_eq!(b.restarts(), 0);
    }

    #[tokio::test]
    async fn a_write_while_a_check_finishes_gets_a_check_of_its_own() {
        let b = BoxFake::new(SAVED, true);
        let (w, _) = watcher(&b, None);
        let (bb, ww) = (b.clone(), w.clone());
        *lock(&b.after_read) = Some(Box::new(move || {
            bb.set_saved("rev-newer");
            ww.changed();
        }));
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        assert_eq!(verdict(&w).await, ActivationOutcome::Restarted);
        assert_eq!(*lock(&b.applied), "rev-newer");
    }

    #[tokio::test]
    async fn a_restart_that_worked_does_not_hold_back_the_next() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        let v = w.next_verdict();
        w.reconnected();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        b.set_saved("rev-later");
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        assert_eq!(b.restarts(), 2);
    }

    #[tokio::test]
    async fn a_write_right_after_a_forced_restart_is_a_new_incident() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        w.reconnected();
        b.set_saved("rev-later");
        w.write_ended();
        // The reconnect's check and the write's check share one run; take the one after the write.
        let mut last = verdict(&w).await;
        if last == ActivationOutcome::Active {
            last = verdict(&w).await;
        }
        assert_eq!(last, ActivationOutcome::Restarted);
        assert_eq!(b.restarts(), 2);
    }

    #[tokio::test]
    async fn a_restart_held_back_for_work_in_flight_is_waited_for() {
        let b = BoxFake::new(OLD, true);
        let deferred = Arc::new(AtomicBool::new(true));
        let (w, out) = watcher(&b, Some(deferred.clone()));
        let v = w.next_verdict();
        w.write_ended();
        tokio::time::sleep(ms(20 + 60 * 3)).await;
        assert_eq!(b.restarts(), 0);
        assert!(lock(&out).join("\n").contains("holding its restart back"));
        deferred.store(false, Ordering::SeqCst);
        *lock(&b.applied) = SAVED.into();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        assert_eq!(b.restarts(), 0);
    }

    #[tokio::test]
    async fn a_deferral_that_went_quiet_is_a_dropped_restart() {
        let b = BoxFake::new(OLD, true);
        let deferred = Arc::new(AtomicBool::new(true));
        let (w, _) = watcher(&b, Some(deferred.clone()));
        let v = w.next_verdict();
        w.write_ended();
        tokio::time::sleep(ms(100)).await;
        deferred.store(false, Ordering::SeqCst);
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        assert_eq!(b.restarts(), 1);
    }

    #[tokio::test]
    async fn a_timer_firing_during_a_check_or_a_stale_one_starts_nothing() {
        let b = BoxFake::new(OLD, true);
        let (w, _) = watcher(&b, None);
        let v = w.next_verdict();
        w.write_ended();
        let current = lock(&w.state).timer_generation;
        // The current timer and one that slept through its abort both fire.
        w.start(current);
        w.start(current);
        w.start(current - 1);
        assert_eq!(v.await.unwrap(), ActivationOutcome::Restarted);
        tokio::time::sleep(ms(150)).await;
        assert_eq!(b.restarts(), 1, "one check, one restart");
    }

    #[tokio::test]
    async fn never_more_than_three_forced_restarts_in_the_window() {
        let b = BoxFake::new(OLD, false);
        let (w, out) = watcher(&b, None);
        let mut outcomes = Vec::new();
        for i in 0..4 {
            b.set_saved(&format!("rev-{i}"));
            let v = w.next_verdict();
            w.write_ended();
            outcomes.push(v.await.unwrap());
        }
        use ActivationOutcome::*;
        assert_eq!(outcomes, [Restarted, Restarted, Restarted, Stuck]);
        assert_eq!(b.restarts(), 3);
        assert!(lock(&out).join("\n").contains("after 3 restarts from here"));
    }

    // ---- with the real client and the fake gateway ----

    #[tokio::test]
    async fn the_client_is_a_config_gateway_and_activation_follows_its_writes() {
        use crate::fake::FakeGateway;
        let fake = FakeGateway::start("tok").await.unwrap();
        fake.reply(
            "config.get",
            json!({ "hash": "h1", "configRevisionHash": "r1", "appliedConfigHash": "r1" }),
        );
        fake.reply("config.patch", json!({ "ok": true }));
        let mut o = crate::GatewayOptions::new(fake.url(), "tok");
        o.min_backoff = ms(20);
        let client = GatewayClient::new(o);
        client.start();
        assert!(client.when_connected(Duration::from_secs(5)).await);
        let restarts = Arc::new(AtomicUsize::new(0));
        let r = restarts.clone();
        let mut ao = ActivationOptions::new(
            Arc::new(client.clone()),
            Arc::new(move || {
                r.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }),
        );
        ao.settle = ms(20);
        ao.poll = ms(5);
        ao.log = quiet();
        let act = ConfigActivation::new(ao);
        act.follow(&client);
        let v = act.next_verdict();
        let w = ConfigWriter::new(Arc::new(client.clone()));
        w.patch(&obj(json!({ "a": 1 })), opts(1000)).await.unwrap();
        assert_eq!(v.await.unwrap(), ActivationOutcome::Active);
        let sent = fake.calls("config.patch");
        assert_eq!(sent, [json!({ "raw": "{\"a\":1}", "baseHash": "h1" })]);
        assert_eq!(restarts.load(Ordering::SeqCst), 0);
        client.stop();
    }
}

/// The config queue against a real OpenClaw gateway (W6 brief: two writers at once, a restart
/// window, a restart taken over by the next one, a stale base hash). Ignored by default. Only ever
/// against a THROWAWAY gateway (`openclaw gateway --dev` with its own `HOME`): the tests leave their
/// values behind (skill switches, a wide-area discovery domain, a custom bind host) and restart it.
///
/// ```text
/// HOME=$(mktemp -d) openclaw gateway --dev --allow-unconfigured --port 18999 --auth token --token t &
/// CC_REAL_OPENCLAW_PORT=18999 CC_REAL_OPENCLAW_TOKEN=t cargo test -p cc-openclaw real_openclaw -- --ignored
/// ```
///
/// Each run writes values of its own, so a second run against the same gateway changes the config
/// again (OpenClaw does nothing for a write that changes nothing). In 2026.9.7 most keys are
/// hot-reloaded; `discovery.wideArea` and `gateway.customBindHost` restart the gateway.
#[cfg(test)]
mod real_openclaw {
    use super::*;
    use crate::client::{GatewayClient, GatewayOptions};

    const WRITE: Duration = Duration::from_secs(120);

    /// One test at a time: they share the gateway, and a restart in one would move another's base.
    static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A connected writer, and the client, stopped when the test ends however it ends.
    struct Rig {
        client: Arc<GatewayClient>,
        w: Arc<ConfigWriter>,
        _one: tokio::sync::MutexGuard<'static, ()>,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.client.stop();
        }
    }

    async fn rig() -> Rig {
        let one = ONE_AT_A_TIME.lock().await;
        let port: u16 = std::env::var("CC_REAL_OPENCLAW_PORT")
            .expect("CC_REAL_OPENCLAW_PORT")
            .parse()
            .expect("port");
        let token = std::env::var("CC_REAL_OPENCLAW_TOKEN").expect("CC_REAL_OPENCLAW_TOKEN");
        let client = Arc::new(GatewayClient::new(GatewayOptions::local(port, token)));
        client.start();
        assert!(
            client.when_connected(Duration::from_secs(60)).await,
            "the gateway answers"
        );
        let w = Arc::new(ConfigWriter::new(client.clone()));
        Rig { client, w, _one: one }
    }

    /// A value no earlier run wrote.
    fn nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    fn patch(v: Value) -> Map<String, Value> {
        v.as_object().cloned().expect("object")
    }

    fn skill(name: &str, enabled: bool) -> Map<String, Value> {
        patch(json!({ "skills": { "entries": { name: { "enabled": enabled } } } }))
    }

    async fn write(r: &Rig, p: &Map<String, Value>) {
        r.w.patch(p, PatchOptions::new(WRITE)).await.expect("write");
    }

    /// Whether the gateway's config now says what `p` writes.
    async fn holds(r: &Rig, p: &Map<String, Value>) -> bool {
        let read = read_snapshot(r.w.gateway().as_ref(), None).await.expect("config.get");
        patch_holds(&read.snapshot, p)
    }

    #[tokio::test]
    #[ignore]
    async fn real_openclaw_two_writers_at_once_both_land() {
        let r = rig().await;
        // From the other state, so each write really changes the file.
        write(&r, &skill("apple-notes", true)).await;
        write(&r, &skill("apple-reminders", true)).await;
        let (a, b) = (r.w.clone(), r.w.clone());
        let (ra, rb) = tokio::join!(
            async move { a.patch(&skill("apple-notes", false), PatchOptions::new(WRITE)).await },
            async move {
                b.patch(&skill("apple-reminders", false), PatchOptions::new(WRITE))
                    .await
            },
        );
        ra.expect("first writer");
        rb.expect("second writer");
        assert!(holds(&r, &skill("apple-notes", false)).await);
        assert!(holds(&r, &skill("apple-reminders", false)).await);
    }

    #[tokio::test]
    #[ignore]
    async fn real_openclaw_a_write_sent_while_the_gateway_restarts_lands_after_it() {
        let r = rig().await;
        write(&r, &skill("apple-notes", true)).await;
        // Someone else restarts the gateway: a raw `config.patch` of a restarting key, outside the
        // queue, so the queue's write goes out into the restart.
        let read = read_snapshot(r.w.gateway().as_ref(), None).await.expect("config.get");
        let domain = format!("w6-{}.test", nonce());
        let raw = json!({ "discovery": { "wideArea": { "domain": domain } } }).to_string();
        let _ =
            r.w.gateway()
                .call(
                    "config.patch",
                    json!({ "raw": raw, "baseHash": read.hash }),
                    Duration::from_secs(30),
                )
                .await;
        write(&r, &skill("apple-notes", false)).await;
        assert!(holds(&r, &skill("apple-notes", false)).await);
        assert!(holds(&r, &patch(json!({ "discovery": { "wideArea": { "domain": domain } } }))).await);
    }

    #[tokio::test]
    #[ignore]
    async fn real_openclaw_two_restarting_writes_back_to_back_both_become_active() {
        let r = rig().await;
        let n = nonce();
        let domain = patch(json!({ "discovery": { "wideArea": { "domain": format!("w6-{n}.test") } } }));
        let host = patch(json!({ "gateway": { "customBindHost": format!("127.0.0.{}", 2 + (n % 250)) } }));
        // Both restart the gateway; the second can take over the first's restart. Each ends active.
        let (a, b, d, h) = (r.w.clone(), r.w.clone(), domain.clone(), host.clone());
        let (ra, rb) = tokio::join!(async move { a.patch(&d, PatchOptions::new(WRITE)).await }, async move {
            b.patch(&h, PatchOptions::new(WRITE)).await
        },);
        ra.expect("first restarting write");
        rb.expect("second restarting write");
        assert!(holds(&r, &domain).await);
        assert!(holds(&r, &host).await);
    }

    /// The base hash and snapshot of the config as it is now.
    async fn base(r: &Rig) -> PatchOptions {
        let read = read_snapshot(r.w.gateway().as_ref(), None).await.expect("config.get");
        let mut opts = PatchOptions::new(WRITE);
        opts.base_hash = Some(read.hash);
        opts.snapshot = Some(read.snapshot);
        opts
    }

    #[tokio::test]
    #[ignore]
    async fn real_openclaw_a_stale_base_hash_is_rebased_when_its_own_parts_did_not_move() {
        let r = rig().await;
        // The block exists before the base is read (a part that appears counts as moved, in both
        // builds), and the value this write sets is not there yet.
        write(&r, &skill("apple-notes", true)).await;
        write(&r, &skill("apple-reminders", false)).await;
        let opts = base(&r).await;
        // Someone else writes meanwhile: the hash moves, but not the part this write changes.
        write(&r, &skill("apple-reminders", true)).await;
        r.w.patch(&skill("apple-notes", false), opts)
            .await
            .expect("the write from the old base");
        assert!(
            holds(&r, &skill("apple-notes", false)).await,
            "the write was sent again"
        );
        assert!(
            holds(&r, &skill("apple-reminders", true)).await,
            "the other write is kept"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn real_openclaw_a_stale_base_hash_is_refused_when_its_own_part_moved() {
        let r = rig().await;
        write(&r, &skill("apple-notes", true)).await;
        let opts = base(&r).await;
        // Someone else changes the very value this write was built from.
        write(&r, &skill("apple-notes", false)).await;
        let err =
            r.w.patch(&skill("apple-notes", true), opts)
                .await
                .expect_err("sending it would undo the other write");
        assert!(err.to_string().contains("config changed since last load"), "{err}");
        assert!(holds(&r, &skill("apple-notes", false)).await, "the other write stands");
    }
}
