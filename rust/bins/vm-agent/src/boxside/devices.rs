//! The devices paired with this box's OpenClaw gateway, the Mac app mostly (`devices.ts`,
//! `routes/devices.ts`). The read takes either token; approving, rejecting and removing come only
//! from the org firewall (`devices`), because approving hands a device operator control of the
//! agent. The gateway socket (W6's client) is used when it is up; `openclaw devices … --json` is the
//! fallback, single-flighted, as it is a 240 MB process.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cc_http::{FirewallBody, Req, Resp};
use cc_proc::Runner;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use serde_json::{Map, Value, json};

use super::exec::{exec, failure_line};
use super::web::{self, send_json};

/// `DEVICES_LIST_MS` (`GATEWAY_READ_MS`).
const LIST_MS: Duration = Duration::from_secs(10);
const LIST_CLI_MS: Duration = Duration::from_secs(8);
const LIST_TOTAL_MS: Duration = Duration::from_secs(18);
/// `DEVICES_ACTION_MS` (`CONFIG_PATCH_MS`).
const ACTION_MS: Duration = Duration::from_secs(20);
const ACTION_CLI_MS: Duration = Duration::from_secs(45);
/// `LIST_CACHE_MS`. The TS also has a 2 s `LIST_ERROR_CACHE_MS`, which never applies: a failed
/// listing resolves with its `error` filled in rather than rejecting, so `Once` keeps it 4 s too.
const LIST_CACHE: Duration = Duration::from_secs(4);
const CLI_ATTEMPTS: usize = 3;
const CLI_RETRY: [Duration; 2] = [Duration::from_millis(400), Duration::from_millis(1200)];

fn s(v: Option<&Value>) -> Value {
    v.and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| Value::String(s.into()))
        .unwrap_or(Value::Null)
}

fn n(v: Option<&Value>) -> Value {
    v.and_then(Value::as_f64)
        .filter(|f| f.is_finite())
        .and_then(|_| v.cloned())
        .unwrap_or(Value::Null)
}

fn strings(v: Option<&Value>) -> Value {
    Value::Array(
        v.and_then(Value::as_array)
            .map(|a| a.iter().filter(|x| x.is_string()).cloned().collect())
            .unwrap_or_default(),
    )
}

fn or(a: Value, b: Value) -> Value {
    if a.is_null() { b } else { a }
}

/// `toPending`: a request without an id is not offered.
pub fn to_pending(r: &Map<String, Value>) -> Option<Value> {
    let request_id = s(r.get("requestId"));
    let device_id = s(r.get("deviceId"));
    if request_id.is_null() || device_id.is_null() {
        return None;
    }
    Some(json!({
        "requestId": request_id,
        "deviceId": device_id,
        "displayName": s(r.get("displayName")),
        "platform": s(r.get("platform")),
        "deviceFamily": s(r.get("deviceFamily")),
        "clientId": s(r.get("clientId")),
        "clientMode": s(r.get("clientMode")),
        "role": s(r.get("role")),
        "scopes": strings(r.get("scopes")),
        "remoteIp": s(r.get("remoteIp")),
        "at": or(n(r.get("ts")), n(r.get("refreshedAtMs"))),
    }))
}

/// `toPaired`: a paired device, minus its tokens.
pub fn to_paired(r: &Map<String, Value>) -> Option<Value> {
    let device_id = s(r.get("deviceId"));
    if device_id.is_null() {
        return None;
    }
    Some(json!({
        "deviceId": device_id,
        "displayName": s(r.get("displayName")),
        "label": s(r.get("operatorLabel")),
        "platform": s(r.get("platform")),
        "deviceFamily": s(r.get("deviceFamily")),
        "clientId": s(r.get("clientId")),
        "clientMode": s(r.get("clientMode")),
        "role": s(r.get("role")),
        "scopes": strings(r.get("scopes")),
        "approvedVia": s(r.get("approvedVia")),
        "browserOrigin": s(r.get("browserOrigin")),
        "connected": r.get("connected") == Some(&Value::Bool(true)),
        "approvedAt": or(n(r.get("approvedAtMs")), n(r.get("createdAtMs"))),
        "lastSeenAt": n(r.get("lastSeenAtMs")),
    }))
}

fn rows(v: Option<&Value>, f: fn(&Map<String, Value>) -> Option<Value>) -> Vec<Value> {
    let empty = Map::new();
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|r| f(r.as_object().unwrap_or(&empty))).collect())
        .unwrap_or_default()
}

fn parse_list(payload: &Value) -> (Vec<Value>, Vec<Value>) {
    (
        rows(payload.get("pending"), to_pending),
        rows(payload.get("paired"), to_paired),
    )
}

/// `looksBusy`: OpenClaw restarting or its state db held, as against a command that failed.
fn looks_busy(m: &str) -> bool {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(EBUSY|EAGAIN|ECONNREFUSED|SQLITE_BUSY)\b|database is locked|gateway (is )?(not (running|connected)|unavailable|starting|restarting)|connection refused|socket hang up|disconnected").expect("regex")
    });
    RE.is_match(m)
}

type Listing = Shared<BoxFuture<'static, Value>>;

/// `Once` for the listing: one read at a time, reused for a few seconds, not kept past a write.
#[derive(Default)]
struct Cache {
    /// When the read that found it started, and what it found.
    entry: Option<(Instant, Value)>,
    running: Option<(u64, Listing)>,
    runs: u64,
    epoch: u64,
}

/// Ends a run whoever is still waiting for it: kept when no write came since it started, and
/// out of `running` even when the read panicked.
struct Settle {
    cache: Arc<Mutex<Cache>>,
    run: u64,
    epoch: u64,
    started: Instant,
    value: Option<Value>,
}

impl Drop for Settle {
    fn drop(&mut self) {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if c.running.as_ref().is_some_and(|(r, _)| *r == self.run) {
            c.running = None;
        }
        if let Some(v) = self.value.take()
            && c.epoch == self.epoch
        {
            c.entry = Some((self.started, v));
        }
    }
}

pub struct Devices {
    runner: Arc<dyn Runner>,
    gateway: Arc<dyn Fn() -> Option<cc_openclaw::GatewayClient> + Send + Sync>,
    cache: Arc<Mutex<Cache>>,
    list_cache: Duration,
}

impl Devices {
    pub fn new(
        runner: Arc<dyn Runner>,
        gateway: Arc<dyn Fn() -> Option<cc_openclaw::GatewayClient> + Send + Sync>,
    ) -> Self {
        Self {
            runner,
            gateway,
            cache: Arc::new(Mutex::new(Cache::default())),
            list_cache: LIST_CACHE,
        }
    }

    #[cfg(test)]
    pub fn uncached(mut self) -> Self {
        self.list_cache = Duration::ZERO;
        self
    }

    /// Pending and paired devices, single-flighted and reused for a few seconds.
    pub async fn list(self: &Arc<Self>) -> Value {
        let fut = {
            let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, v)) = &c.entry
                && at.elapsed() < self.list_cache
            {
                return v.clone();
            }
            if let Some((_, f)) = &c.running {
                f.clone()
            } else {
                c.runs += 1;
                let mut settle = Settle {
                    cache: self.cache.clone(),
                    run: c.runs,
                    epoch: c.epoch,
                    // Dated from when the read started, as `Once` does.
                    started: Instant::now(),
                    value: None,
                };
                let me = self.clone();
                let task = tokio::spawn(async move {
                    let v = me.read_list().await;
                    settle.value = Some(v.clone());
                    drop(settle);
                    v
                });
                let f: Listing = async move {
                    task.await.unwrap_or_else(|_| {
                        json!({"pending": [], "paired": [], "error": {"busy": false, "message": "The agent could not list its paired devices."}})
                    })
                }
                .boxed()
                .shared();
                c.running = Some((c.runs, f.clone()));
                f
            }
        };
        fut.await
    }

    /// `Once.invalidate`: the cached answer goes and a read in flight may not keep its own. The
    /// read itself is left running, and a caller in the meantime joins it.
    fn invalidate(&self) {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        c.entry = None;
        c.epoch += 1;
    }

    pub async fn approve(&self, request_id: &str) -> Result<Value, String> {
        let r = self
            .call_both(
                "device.pair.approve",
                json!({"requestId": request_id}),
                &["approve", request_id],
            )
            .await?;
        self.invalidate();
        let device_id = r
            .get("deviceId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                r.get("device")
                    .and_then(|d| d.get("deviceId"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .map(str::to_string);
        tracing::info!(
            "[devices] approved request {request_id}{}",
            device_id
                .as_deref()
                .map(|d| format!(" as device {d}"))
                .unwrap_or_default()
        );
        Ok(json!({"ok": true, "deviceId": device_id}))
    }

    pub async fn reject(&self, request_id: &str) -> Result<Value, String> {
        self.call_both(
            "device.pair.reject",
            json!({"requestId": request_id}),
            &["reject", request_id],
        )
        .await?;
        self.invalidate();
        tracing::info!("[devices] rejected request {request_id}");
        Ok(json!({"ok": true}))
    }

    pub async fn remove(&self, device_id: &str) -> Result<Value, String> {
        self.call_both(
            "device.pair.remove",
            json!({"deviceId": device_id}),
            &["remove", device_id],
        )
        .await?;
        self.invalidate();
        tracing::info!("[devices] removed device {device_id}");
        Ok(json!({"ok": true}))
    }

    /// One write, over the socket when it is up, else through the CLI. Never retried: an approval
    /// consumes the request.
    async fn call_both(&self, method: &str, params: Value, argv: &[&str]) -> Result<Value, String> {
        if let Some(c) = (self.gateway)().filter(|c| c.connected()) {
            return c.call(method, params, ACTION_MS).await.map_err(|e| e.to_string());
        }
        self.cli(argv, ACTION_CLI_MS).await
    }

    async fn read_list(&self) -> Value {
        let deadline = Instant::now() + LIST_TOTAL_MS;
        let left = || deadline.saturating_duration_since(Instant::now());
        let mut last = String::new();
        let mut bridge_failed = false;
        if let Some(c) = (self.gateway)().filter(|c| c.connected()) {
            match c.call("device.pair.list", json!({}), LIST_MS.min(left())).await {
                Ok(payload) => {
                    let (pending, paired) = parse_list(&payload);
                    return json!({"pending": pending, "paired": paired, "error": null});
                }
                Err(e) => {
                    bridge_failed = true;
                    last = e.to_string();
                    tracing::info!("[devices] device.pair.list over the bridge failed: {last}");
                }
            }
        }
        let mut tries = 0;
        for attempt in 0..CLI_ATTEMPTS {
            if attempt > 0 {
                let backoff = CLI_RETRY.get(attempt - 1).copied().unwrap_or(Duration::from_secs(1));
                if left() <= backoff {
                    break;
                }
                tokio::time::sleep(backoff).await;
            }
            let budget = LIST_CLI_MS.min(left());
            if budget.is_zero() {
                break;
            }
            tries += 1;
            match self.cli(&["list"], budget).await {
                Ok(payload) => {
                    let (pending, paired) = parse_list(&payload);
                    return json!({"pending": pending, "paired": paired, "error": null});
                }
                Err(e) => last = e,
            }
        }
        let busy = bridge_failed || looks_busy(&last);
        tracing::info!(
            "[devices] listing failed after {tries} {}: {last}",
            if tries == 1 { "try" } else { "tries" }
        );
        let error = if busy {
            json!({"busy": true, "message": "The agent is busy right now, so its paired devices could not be read."})
        } else {
            json!({"busy": false, "message": format!("The agent could not list its paired devices: {last}")})
        };
        json!({"pending": [], "paired": [], "error": error})
    }

    /// `openclaw devices <argv> --json`; the JSON is found after the CLI's banner.
    async fn cli(&self, argv: &[&str], timeout: Duration) -> Result<Value, String> {
        // Always this path: the TS's `openclawBin` option is never set (only the sign-in shim reads
        // `OPENCLAW_BIN`).
        let bin = "/usr/bin/openclaw".to_string();
        let mut args = vec!["devices"];
        args.extend_from_slice(argv);
        args.push("--json");
        let out = exec(self.runner.as_ref(), &bin, &args, timeout, None)
            .await
            .map_err(|e| failure_line(&e))?;
        let start = out.stdout.find('{').ok_or("the openclaw CLI printed no JSON")?;
        serde_json::from_str(&out.stdout[start..]).map_err(|e| e.to_string())
    }
}

/// `ID_RE`: ids come from OpenClaw and go straight back to it.
fn id_of(b: &Map<String, Value>, field: &str) -> Option<String> {
    let v = b.get(field)?.as_str()?;
    let bytes = v.as_bytes();
    let ok = (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'));
    ok.then(|| v.to_string())
}

/// `handleDevices`.
pub async fn handle(app: &crate::app::App, devices: &Arc<Devices>, req: Req) -> Resp {
    let write = req.method() == http::Method::POST;
    let (parts, body) =
        match web::firewall_or_console(app, req, "devices", "device approvals must come from the org firewall").await {
            Ok(r) => r,
            Err(r) => return *r,
        };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    if pathname == "/devices" && parts.method == http::Method::GET {
        return send_json(200, &devices.list().await, &[]);
    }
    if !write {
        return send_json(404, &json!({"error": "Not found"}), &[]);
    }
    let FirewallBody::Json(b) = &body else {
        return send_json(400, &json!({"ok": false, "error": "Invalid JSON body"}), &[]);
    };
    let result = match pathname.as_str() {
        "/devices/approve" | "/devices/reject" => {
            let Some(id) = id_of(b, "requestId") else {
                return send_json(400, &json!({"ok": false, "error": "requestId required"}), &[]);
            };
            if pathname.ends_with("approve") {
                devices.approve(&id).await
            } else {
                devices.reject(&id).await
            }
        }
        "/devices/remove" => {
            let Some(id) = id_of(b, "deviceId") else {
                return send_json(400, &json!({"ok": false, "error": "deviceId required"}), &[]);
            };
            devices.remove(&id).await
        }
        _ => return send_json(404, &json!({"error": "Not found"}), &[]),
    };
    match result {
        Ok(v) => send_json(200, &v, &[]),
        Err(e) => send_json(500, &json!({"ok": false, "error": e}), &[]),
    }
}

#[cfg(test)]
mod tests;
