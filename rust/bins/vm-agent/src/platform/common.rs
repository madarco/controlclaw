//! What the prefixed route groups share (`/llm/`, `/search/`, `/channels/`, ...): the split
//! between firewall writes and reads either side may make, the OpenClaw CLI, the gateway and its
//! config, and the error answers.

use std::sync::Arc;
use std::time::Duration;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Req, Resp, send_json};
use cc_openclaw::ConfigWriter;
use cc_proc::Cmd;
use serde_json::{Map, Value, json};

pub use super::openclaw::exec_failure_line;
use crate::app::App;

/// Ids of providers and plugins (`PROVIDER_RE` in routes/llm.ts, `ID_RE` in routes/search.ts).
pub static ID_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)^[a-z0-9][a-z0-9_-]{0,40}$").expect("regex"));
/// An https URL with a plain path. JavaScript's `\w` is ASCII, so it is spelled out.
pub static HTTPS_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)^https://[a-z0-9.-]+(/[A-Za-z0-9_./-]*)?$").expect("regex"));

/// The firewall's address on the organization's private network (`10.x.x.x`).
pub static PRIVATE_IP: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^10\.(?:\d{1,3}\.){2}\d{1,3}$").expect("regex"));

/// `readJsonBody`'s default limit.
pub const BODY_LIMIT: usize = 16_384;
/// The OpenClaw CLI.
pub const OPENCLAW_BIN: &str = "/usr/bin/openclaw";
/// `GATEWAY_READ_MS`.
pub const GATEWAY_READ: Duration = Duration::from_secs(10);
/// `CONFIG_PATCH_MS`, `CONFIG_PATCH_RESTART_MS`.
pub const CONFIG_PATCH: Duration = Duration::from_secs(20);
pub const CONFIG_PATCH_RESTART: Duration = Duration::from_secs(45);
pub const NOT_RUNNING: &str = "OpenClaw is not running on this box";

/// `patchRestartsGateway` (budgets.ts).
pub fn patch_restarts_gateway(patch: &Map<String, Value>) -> bool {
    ["channels", "plugins", "models", "memory"]
        .iter()
        .any(|k| patch.contains_key(*k))
}

/// Who called, once the token was taken.
pub enum Caller {
    /// The org firewall, with the body its token named (or `NotRead` for a read).
    Firewall(FirewallBody),
    Console,
}

/// The TS pattern `write ? verifyMitmRequest : (verifyMitmRequest ?? verifyRequest)`: a POST
/// needs the firewall's token for `purpose`; anything else takes the firewall's first, then the
/// console's (which is still held to its route list). None when neither is taken.
pub async fn caller(app: &App, req: Req, purpose: &str, limit: usize) -> (http::request::Parts, Option<Caller>) {
    let write = req.method() == hyper::Method::POST;
    let read = if write { ReadBody::Json { limit } } else { ReadBody::No };
    match cc_http::firewall_request(&app.firewall_auth, req, purpose, 0, read).await {
        FirewallRequest::Accepted { parts, body, .. } => (parts, Some(Caller::Firewall(body))),
        FirewallRequest::Refused { parts, .. } => {
            if write {
                return (parts, None);
            }
            let target = parts
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .to_string();
            let ok = app
                .console_auth
                .verify(parts.method.as_str(), &target, cc_http::header(&parts, "authorization"))
                .is_some();
            (parts, ok.then_some(Caller::Console))
        }
    }
}

/// A route's error, as the TS routes answer a thrown one: 503 when OpenClaw is down, else 500.
pub fn fail(message: &str, extra: Option<(&str, Value)>) -> Resp {
    let lower = message.to_lowercase();
    let status = if lower.contains("not running") || lower.contains("not connected") {
        503
    } else {
        500
    };
    let mut body = json!({ "ok": false, "error": message });
    if let Some((k, v)) = extra {
        body[k] = v;
    }
    send_json(status, &body)
}

pub fn not_found() -> Resp {
    send_json(404, &json!({ "error": "Not found" }))
}

/// What every OpenClaw-facing service needs, apart from the app, so tests can hand in fakes: the
/// config queue (its gateway is the one OpenClaw connection), the command runner, `HOME`, the
/// restart hook (`runAction("restart")`) and where log lines go.
#[derive(Clone)]
pub struct Deps {
    pub writer: Arc<dyn Fn() -> Option<Arc<ConfigWriter>> + Send + Sync>,
    pub runner: Arc<dyn cc_proc::Runner>,
    pub home: std::path::PathBuf,
    pub restart: Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
    /// The OpenClaw CLI: [`OPENCLAW_BIN`] on a managed box, the one discovery found otherwise.
    pub bin: String,
    /// Whether OpenClaw's service is down, for [`Self::gateway_or_restarting`]. None: ask the
    /// managed box's `openclaw` unit.
    pub unit_down: Option<Arc<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync>>,
    /// Run CLI writes with OpenClaw's gateway stopped, then start it again: see [`OfflineRun`].
    pub offline: OfflineRun,
}

/// One write through OpenClaw's CLI: its arguments, what goes on stdin, how long it may take.
#[derive(Clone, Debug, PartialEq)]
pub struct CliWrite {
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub timeout: Duration,
}

/// What an [`OfflineRun`] did: each write's result, in order, and whether OpenClaw started again.
#[derive(Debug)]
pub struct Offline {
    pub results: Vec<Result<String, String>>,
    pub started: Result<(), String>,
}

/// From OpenClaw 2026.11, a running gateway owns the credential store: `models auth paste-token`,
/// `models auth logout` and `paste-api-key --profile-id` are refused while it runs ("stop the
/// Gateway through its service owner"). This stops it the way it runs, makes the writes with the
/// CLI given, and starts it again, as one unit action. An error when the gateway was not stopped
/// (nothing was written).
pub type OfflineRun =
    Arc<dyn Fn(Deps, String, Vec<CliWrite>) -> cc_http::BoxFuture<Result<Offline, String>> + Send + Sync>;

/// An [`OfflineRun`] that stops nothing, for tests that make no credential writes.
#[cfg(test)]
pub fn no_offline() -> OfflineRun {
    Arc::new(|_, _, _| Box::pin(async { Err("not in this test".to_string()) }))
}

/// The CLI's refusal of a write while the gateway runs ([`OfflineRun`]).
pub static NEEDS_GATEWAY_STOPPED: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)stop the gateway through its service owner").expect("regex"));

impl Deps {
    /// The agent's own: the `openclaw` slot, the app's runner, `systemctl restart openclaw`.
    /// Holds the app weakly: the services live in the app's own `platform` slot.
    pub fn of(app: &Arc<App>) -> Self {
        if let Some(um) = &app.unmanaged {
            return Self::unmanaged(app, um);
        }
        let a = Arc::downgrade(app);
        let (runner, service) = (app.runner.clone(), app.config.service.clone());
        Self {
            writer: Arc::new(move || a.upgrade()?.contracts.openclaw.get().map(|o| o.config.clone())),
            runner: app.runner.clone(),
            home: app.config.home.clone(),
            restart: Arc::new(move || {
                let (runner, service) = (runner.clone(), service.clone());
                Box::pin(async move { super::openclaw::run_action(runner.as_ref(), "restart", &service).await })
            }),
            log: Arc::new(|l| tracing::info!("{l}")),
            bin: OPENCLAW_BIN.to_string(),
            unit_down: None,
            offline: {
                let service = app.config.service.clone();
                Arc::new(move |deps, bin, writes| {
                    let service = service.clone();
                    Box::pin(async move { super::openclaw::offline_writes(&deps, &service, &bin, writes).await })
                })
            },
        }
    }

    /// An unmanaged agent's: the CLI writer, the CLI discovery found, the gateway restarted the
    /// way it runs.
    fn unmanaged(app: &Arc<App>, um: &Arc<crate::unmanaged::Unmanaged>) -> Self {
        let (a, w, u) = (Arc::downgrade(app), Arc::downgrade(um), Arc::downgrade(um));
        let down = Arc::downgrade(app);
        let du = Arc::downgrade(um);
        Self {
            writer: Arc::new(move || w.upgrade()?.writer.get().cloned()),
            runner: app.runner.clone(),
            home: app.config.home.clone(),
            restart: Arc::new(move || {
                let (a, u) = (a.clone(), u.clone());
                Box::pin(async move {
                    let (Some(app), Some(um)) = (a.upgrade(), u.upgrade()) else {
                        return Err(NOT_RUNNING.to_string());
                    };
                    crate::unmanaged::restart(&app, &um).await
                })
            }),
            log: Arc::new(|l| tracing::info!("{l}")),
            // The wrapper discovery keeps pointing at the CLI it found.
            bin: crate::unmanaged::discover::wrapper_path(&um.state_dir)
                .to_string_lossy()
                .into_owned(),
            unit_down: Some(Arc::new(move || {
                let (a, u) = (down.clone(), du.clone());
                Box::pin(async move {
                    let (Some(app), Some(um)) = (a.upgrade(), u.upgrade()) else {
                        return true;
                    };
                    crate::unmanaged::is_down(&app, &um).await
                })
            })),
            offline: {
                let (a, u) = (Arc::downgrade(app), Arc::downgrade(um));
                Arc::new(move |deps, bin, writes| {
                    let (a, u) = (a.clone(), u.clone());
                    Box::pin(async move {
                        let (Some(app), Some(um)) = (a.upgrade(), u.upgrade()) else {
                            return Err(NOT_RUNNING.to_string());
                        };
                        crate::unmanaged::offline_writes(&app, &um, &deps, &bin, writes).await
                    })
                })
            },
        }
    }

    pub fn log(&self, line: &str) {
        (self.log)(line)
    }

    /// The config queue when OpenClaw's gateway is connected; the TS's "not running" otherwise.
    pub fn gateway(&self) -> Result<Arc<ConfigWriter>, String> {
        match (self.writer)() {
            Some(w) if w.gateway().connected() => Ok(w),
            _ => Err(NOT_RUNNING.to_string()),
        }
    }

    /// [`Self::gateway`], or the writer while OpenClaw is only restarting: it restarts itself for
    /// some settings (the first model's `memory.search` takes it down for about 16 s), and a channel
    /// connected in that window was refused as "not running" (W1, 2026-10-29). A unit that is down
    /// (inactive or failed) is refused at once, as before. The TS refuses in both cases; fixed in
    /// Rust. The caller waits with [`Self::gateway_back`].
    pub async fn gateway_or_restarting(&self) -> Result<Arc<ConfigWriter>, String> {
        if let Ok(w) = self.gateway() {
            return Ok(w);
        }
        let Some(w) = self.client() else {
            return Err(NOT_RUNNING.to_string());
        };
        if let Some(down) = &self.unit_down {
            if tokio::time::timeout(Duration::from_secs(3), down()).await == Ok(true) {
                return Err(NOT_RUNNING.to_string());
            }
            return Ok(w);
        }
        let unit = tokio::time::timeout(Duration::from_secs(3), super::health_summary::openclaw_unit(self)).await;
        if matches!(unit, Ok(Some(u)) if u.down_for.is_some()) {
            return Err(NOT_RUNNING.to_string());
        }
        Ok(w)
    }

    /// Up to `wait` for the gateway to be connected again; then [`Self::gateway`].
    pub async fn gateway_back(&self, wait: Duration) -> Result<Arc<ConfigWriter>, String> {
        if let Some(w) = self.client() {
            cc_openclaw::config_queue::when_back(w.gateway().as_ref(), wait).await;
        }
        self.gateway()
    }

    /// The writer whether or not it is connected (`this.opts.client` in the TS).
    pub fn client(&self) -> Option<Arc<ConfigWriter>> {
        (self.writer)()
    }

    pub async fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let w = self.gateway()?;
        w.gateway()
            .call(method, params, timeout)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn read_config(&self) -> Result<Snapshot, String> {
        let raw = self.call("config.get", json!({}), GATEWAY_READ).await?;
        snapshot(raw)
    }

    /// `defaultExec`, with `execFailureLine` as the error: a CLI run as the box user, `HOME` set.
    pub async fn exec(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        stdin: Option<String>,
        env: &[(&str, String)],
    ) -> Result<String, String> {
        let mut cmd = Cmd::new(program)
            .args(args.iter().copied())
            .timeout(timeout)
            .env("HOME", self.home.to_string_lossy().to_string());
        for (k, v) in env {
            cmd = cmd.env(*k, v.clone());
        }
        // Node's execFile always opens stdin and ends it, with the data when there is some.
        cmd = cmd.stdin(stdin.unwrap_or_default());
        match self.runner.run(cmd).await {
            Ok(out) if out.success() => Ok(out.stdout_str()),
            Ok(out) => {
                let message = format!("Command failed: {program} {}", args.join(" "));
                Err(exec_failure_line(&out.stderr_str(), &out.stdout_str(), &message))
            }
            Err(e) => Err(exec_failure_line("", "", &spawn_message(program, &e))),
        }
    }

    pub async fn restart(&self) -> Result<(), String> {
        (self.restart)().await
    }
}

/// Node's message for a program that could not be started (`spawn <program> ENOENT`), which the
/// TS passes on through `execFailureLine`.
pub fn spawn_message(program: &str, e: &cc_proc::RunError) -> String {
    let cc_proc::RunError::Spawn(io) = e;
    let code = match io.kind() {
        std::io::ErrorKind::NotFound => "ENOENT",
        std::io::ErrorKind::PermissionDenied => "EACCES",
        _ => return e.to_string(),
    };
    format!("spawn {program} {code}")
}

/// A `config.get`: its hash, the file as parsed (else the resolved config), and the whole answer.
pub struct Snapshot {
    pub hash: String,
    pub config: Map<String, Value>,
    pub raw: Value,
}

pub fn snapshot(raw: Value) -> Result<Snapshot, String> {
    let hash = match raw.get("hash") {
        Some(Value::String(h)) if !h.is_empty() => h.clone(),
        _ => return Err("OpenClaw returned no config hash".into()),
    };
    let config = config_of(&raw);
    Ok(Snapshot { hash, config, raw })
}

/// `snapshot.parsed ?? snapshot.config ?? {}`, then `{}` unless it is an object. For a read that
/// writes nothing back, so needs no hash.
pub fn config_of(raw: &Value) -> Map<String, Value> {
    let pick = match raw.get("parsed") {
        Some(v) if !v.is_null() => Some(v),
        _ => raw.get("config").filter(|v| !v.is_null()),
    };
    pick.and_then(Value::as_object).cloned().unwrap_or_default()
}

/// JavaScript's `s.slice(0, n)`: `n` UTF-16 units.
pub fn js_slice(s: &str, n: usize) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(n).collect::<Vec<u16>>())
}

/// A flag set for as long as this lives, cleared also when the future holding it is dropped
/// (the TS's `finally`).
pub struct Flag<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> Flag<'a> {
    pub fn on(f: &'a std::sync::atomic::AtomicBool) -> Self {
        f.store(true, std::sync::atomic::Ordering::SeqCst);
        Self(f)
    }

    /// Set it unless it is set already: None when somebody else holds it.
    pub fn take(f: &'a std::sync::atomic::AtomicBool) -> Option<Self> {
        (!f.swap(true, std::sync::atomic::Ordering::SeqCst)).then_some(Self(f))
    }
}

impl Drop for Flag<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A number as `JSON.stringify` writes it: a whole number without `.0`.
pub fn js_number(f: f64) -> Value {
    // `JSON.stringify` writes every whole number below 1e21 in full; serde's float writer would
    // write `1e16`. The integer types cover all but the top of that range.
    if f.is_finite() && f.fract() == 0.0 && (0.0..1.8e19).contains(&f) {
        json!(f as u64)
    } else if f.is_finite() && f.fract() == 0.0 && f < 0.0 && f > -9.2e18 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

/// `str()`: a non-empty string.
pub fn text(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// `a?.b?.c` over JSON objects.
pub fn at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |cur, k| cur.as_object()?.get(*k))
}

pub fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_written_as_json_stringify_writes_them() {
        let w = |f: f64| js_number(f).to_string();
        assert_eq!(w(50.0), "50");
        assert_eq!(w(41.5), "41.5");
        assert_eq!(w(1e16), "10000000000000000");
        assert_eq!(w(-3.0), "-3");
    }

    #[test]
    fn a_read_needs_no_hash() {
        let raw = json!({ "config": { "mcp": { "servers": { "x": {} } } } });
        assert!(snapshot(raw.clone()).is_err());
        assert!(config_of(&raw).contains_key("mcp"));
        assert!(config_of(&json!({ "parsed": null, "config": 3 })).is_empty());
    }
}
