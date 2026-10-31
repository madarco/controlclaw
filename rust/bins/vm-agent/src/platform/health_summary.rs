//! `/health/*`, the box side of the health check (`routes/health-summary.ts`).
//!
//! `GET /health/summary` takes the console's token or the org firewall's (purpose `health`).
//! `POST /health/model` takes the console's token only: it asks OpenClaw's gateway to send the
//! primary model's provider one tiny request (`models.probe`). Both answer with states, numbers,
//! versions and fixed reason codes only: no log line, process list or error text leaves the box.
//!
//! `GET /health/patches` (console token) says whether ControlClaw's patches and add-ons match the
//! OpenClaw this box runs (`patch_check.rs`).

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use cc_http::{FirewallRequest, ReadBody, Router, send_json};
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{Deps, js_number, js_slice};
use super::time::now_ms;
use crate::app::App;
use crate::stages;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// `config.get` for a health read (`PROBE_TIMEOUT_MS * 2`).
pub const CONFIG_READ_TIMEOUT: Duration = Duration::from_secs(6);
/// How long OpenClaw gives the provider to answer the model test (`models.probe` clamps it to 5-60 s).
pub const MODEL_PROBE_TIMEOUT_MS: u64 = 30_000;
/// A ChatGPT sign-in (Codex) is slower on first use. Just under OpenClaw's 60 s ceiling.
pub const SLOW_START_MODEL_PROBE_TIMEOUT_MS: u64 = 55_000;
/// A tool call running this long is reported.
pub const STALLED_AFTER_MS: i64 = 15 * 60_000;

/// The watchdog's last findings (G6b): whether OpenClaw's `/healthz` answered, and the outbound probe.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WatchStatus {
    pub gateway_answers: Option<bool>,
    pub outbound: Option<bool>,
    pub jammed: bool,
}

/// The oldest unfinished tool call or run (`stall.ts`, G6b/G6c).
#[derive(Debug, Clone, PartialEq)]
pub struct Stalled {
    pub kind: &'static str,
    pub name: Option<String>,
    pub started_at: i64,
}

pub type WatchFn = Arc<dyn Fn() -> Option<WatchStatus> + Send + Sync>;
pub type StalledFn = Arc<dyn Fn(i64, i64) -> Option<Stalled> + Send + Sync>;

/// The fullest of `/` and the volume OpenClaw's home is on: `{usedPct, freeBytes, totalBytes, volume}`.
/// Two paths on one volume count once; a path that cannot be read is left out.
pub fn disk_of(paths: &[PathBuf]) -> Option<Value> {
    let mut seen = Vec::new();
    let mut fullest: Option<(f64, Value)> = None;
    for path in paths {
        let Ok(m) = std::fs::metadata(path) else { continue };
        if seen.contains(&m.dev()) {
            continue;
        }
        seen.push(m.dev());
        let Ok(s) = rustix::fs::statfs(path) else { continue };
        let bsize = s.f_bsize as f64;
        let total = s.f_blocks as f64 * bsize;
        let free = s.f_bavail as f64 * bsize;
        // As `df` counts it: what is used, out of that plus what a service may still write.
        let used = (s.f_blocks as f64 - s.f_bfree as f64) * bsize;
        if total <= 0.0 || used + free <= 0.0 {
            continue;
        }
        let used_pct = (used / (used + free) * 1000.0).round() / 10.0;
        if fullest.as_ref().is_none_or(|(p, _)| used_pct > *p) {
            let volume = if path.as_os_str() == "/" { "system" } else { "data" };
            fullest = Some((
                used_pct,
                json!({ "usedPct": js_number(used_pct), "freeBytes": js_number(free), "totalBytes": js_number(total), "volume": volume }),
            ));
        }
    }
    fullest.map(|f| f.1)
}

/// `/` and `$HOME/.openclaw`.
pub fn disk_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into());
    vec![PathBuf::from("/"), PathBuf::from(home).join(".openclaw")]
}

fn meminfo(key: &str) -> Option<f64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with(key))?;
    let kb: f64 = line[key.len()..]
        .trim_start_matches(':')
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kb * 1024.0)
}

/// `os.totalmem()` (MemTotal).
pub fn total_mem() -> Option<f64> {
    meminfo("MemTotal")
}

/// Used is the total less what is available (`os.freemem()` reads MemAvailable), as a percentage.
pub fn memory_used_pct(total: f64) -> Option<f64> {
    let free = meminfo("MemAvailable")?;
    (total > 0.0).then(|| ((total - free) / total * 1000.0).round() / 10.0)
}

/// `os.loadavg()[0]`, to two places.
pub fn load1() -> Option<f64> {
    let t = std::fs::read_to_string("/proc/loadavg").ok()?;
    let l: f64 = t.split_whitespace().next()?.parse().ok()?;
    Some((l * 100.0).round() / 100.0)
}

/// `os.cpus().length`.
fn cpus() -> usize {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|t| t.lines().filter(|l| l.starts_with("processor")).count())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

fn uptime_s() -> Option<i64> {
    let t = std::fs::read_to_string("/proc/uptime").ok()?;
    let s: f64 = t.split_whitespace().next()?.parse().ok()?;
    Some(s.floor() as i64)
}

/// A probe: `{ok, ms, reason?}`. A probe that answers false is `refused`, as in the TS.
fn probe(ok: Result<bool, &'static str>, start: Instant) -> Value {
    let ms = start.elapsed().as_millis() as i64;
    match ok {
        Ok(true) => json!({ "ok": true, "ms": ms }),
        Ok(false) => json!({ "ok": false, "ms": ms, "reason": "refused" }),
        Err(reason) => json!({ "ok": false, "ms": ms, "reason": reason }),
    }
}

async fn dns_probe(host: &str) -> Value {
    let start = Instant::now();
    let r = match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host((host, 0))).await {
        Err(_) => Err("timeout"),
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => {
            // getaddrinfo's words for ENOTFOUND / ENODATA.
            let m = e.to_string().to_lowercase();
            Err(
                if m.contains("not known") || m.contains("no address") || m.contains("no such host") {
                    "not_found"
                } else {
                    "error"
                },
            )
        }
    };
    probe(r, start)
}

/// A TCP connect: true when it connected within the time (`egress.ts` `probe`).
pub async fn tcp_probe(host: &str, port: u16, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await,
        Ok(Ok(_))
    )
}

async fn ntp_synced(deps: &Deps) -> Option<bool> {
    let out = deps
        .exec(
            "timedatectl",
            &["show", "-p", "NTPSynchronized", "--value"],
            PROBE_TIMEOUT,
            None,
            &[],
        )
        .await
        .ok()?;
    match out.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// OpenClaw's unit as systemd has it (`openClawUnit`): its state, and how long it has been in it.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    pub state: String,
    pub loaded: bool,
    pub enabled: bool,
    /// Ms it has been `active`; None in any other state.
    pub active_for: Option<f64>,
    /// Ms it has been `inactive` or `failed`; None in any other state. A unit that has not run since
    /// boot has been down since boot.
    pub down_for: Option<f64>,
}

/// `systemctl show` output read at `now_us` on the monotonic clock systemd stamps with.
pub fn parse_unit(out: &str, now_us: f64) -> Unit {
    let prop = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
            .unwrap_or_default()
    };
    // `Number(prop(name)) || 0`.
    let stamp = |name: &str| {
        prop(name)
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite())
            .unwrap_or(0.0)
    };
    let since = |name: &str| (now_us - stamp(name)).max(0.0) / 1000.0;
    let state = prop("ActiveState").to_string();
    Unit {
        loaded: prop("LoadState") == "loaded",
        enabled: prop("UnitFileState") == "enabled",
        active_for: (state == "active" && stamp("ActiveEnterTimestampMonotonic") != 0.0)
            .then(|| since("ActiveEnterTimestampMonotonic")),
        down_for: (state == "inactive" || state == "failed").then(|| since("InactiveEnterTimestampMonotonic")),
        state,
    }
}

/// `openClawUnit`; None when systemd did not answer.
pub async fn openclaw_unit(deps: &Deps) -> Option<Unit> {
    let out = deps
        .exec(
            "systemctl",
            &[
                "show",
                "openclaw",
                "-p",
                "LoadState",
                "-p",
                "UnitFileState",
                "-p",
                "ActiveState",
                "-p",
                "ActiveEnterTimestampMonotonic",
                "-p",
                "InactiveEnterTimestampMonotonic",
            ],
            Duration::from_secs(5),
            None,
            &[],
        )
        .await
        .ok()?;
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let now_us = t.tv_sec as f64 * 1e6 + (t.tv_nsec / 1000) as f64;
    Some(parse_unit(&out, now_us))
}

/// Milliseconds OpenClaw's unit has been active; None while it is not.
pub async fn openclaw_active_for(deps: &Deps) -> Option<f64> {
    openclaw_unit(deps).await?.active_for
}

/// `openClawDownFor`: ms OpenClaw's unit has been `inactive` or `failed`. None in any other state,
/// on a pool box nobody has claimed, and while the unit is not loaded and enabled: on a new box the
/// role enables it only where it starts it, at the end of the OpenClaw step, once its model and
/// channels are in place.
pub async fn openclaw_down_for(deps: &Deps, pool_unclaimed: bool) -> Option<f64> {
    if pool_unclaimed {
        return None;
    }
    let unit = openclaw_unit(deps).await?;
    if unit.loaded && unit.enabled {
        unit.down_for
    } else {
        None
    }
}

/// `controlPlaneHost`: the console's host name.
pub fn control_plane_host(app: &App) -> Option<String> {
    let base = super::gateway::saas_base_url(app)?;
    url::Url::parse(&base).ok()?.host_str().map(str::to_string)
}

fn proxy_port() -> u16 {
    std::env::var("MITM_PROXY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
}

/// `healthSummary`.
pub async fn health_summary(app: &Arc<App>) -> Value {
    let deps = Deps::of(app);
    let host = control_plane_host(app);
    let mitm = app.keys.read("mitm_box_private_ip").filter(|v| !v.is_empty());
    let connected = app.contracts.openclaw.get().map(|o| o.client.connected());
    let paths = disk_paths();
    let (disk, synced, dns, egress, active_for, state) = tokio::join!(
        async {
            tokio::task::spawn_blocking(move || disk_of(&paths))
                .await
                .ok()
                .flatten()
        },
        ntp_synced(&deps),
        async {
            match &host {
                Some(h) => Some(dns_probe(h).await),
                None => None,
            }
        },
        async {
            match &mitm {
                Some(ip) => {
                    let start = Instant::now();
                    Some(probe(
                        Ok(tcp_probe(ip.trim(), proxy_port(), PROBE_TIMEOUT).await),
                        start,
                    ))
                }
                None => None,
            }
        },
        openclaw_active_for(&deps),
        super::state::current(app.runner.as_ref(), &app.config.service, connected),
    );
    let total = total_mem().unwrap_or(0.0);
    let now = now_ms();
    let p = app.contracts.platform.get();
    let watch = p.as_ref().and_then(|p| p.watchdog.get().cloned()).and_then(|w| w());
    let mut openclaw = json!({ "state": state, "gateway": connected });
    if let Some(w) = &watch {
        openclaw["answers"] = json!(w.gateway_answers);
    }
    let cpu = p
        .as_ref()
        .and_then(|p| p.cpu.get().map(|c| c.report()))
        .unwrap_or(Value::Null);
    let mut out = json!({
        "ok": true,
        "now": now,
        "openclaw": openclaw,
        "disk": disk,
        "memory": { "usedPct": memory_used_pct(total).map(js_number), "totalBytes": js_number(total) },
        "cpu": cpu,
        "load1": load1().map(js_number),
        "cpus": cpus(),
        "clock": { "ntpSynced": synced },
        "dns": dns,
        "egress": egress,
        "rebootRequired": std::path::Path::new("/var/run/reboot-required").exists(),
    });
    let o = out.as_object_mut().expect("object");
    if let Some(w) = &watch {
        o.insert(
            "outbound".into(),
            match w.outbound {
                None => Value::Null,
                Some(ok) => json!({ "ok": ok, "jammed": w.jammed }),
            },
        );
    }
    o.insert("uptimeS".into(), json!(uptime_s()));
    o.insert(
        "openclawSince".into(),
        match active_for {
            Some(ms) => json!((now as f64 - ms).round() as i64),
            None => Value::Null,
        },
    );
    // Until the stall tracker is in (G6b/G6c) nothing is known to be stuck.
    let stalled = p
        .as_ref()
        .and_then(|p| p.stalled.get().cloned())
        .and_then(|f| f(now, STALLED_AFTER_MS));
    o.insert(
        "stalled".into(),
        match stalled {
            Some(s) => json!({
                "kind": s.kind,
                "name": s.name.map(|n| js_slice(&n, 80)),
                "minutes": (now - s.started_at).div_euclid(60_000),
            }),
            None => Value::Null,
        },
    );
    out
}

/// `provider/model[@provider:profile]` → `provider`; None when no primary model is set.
pub fn provider_of(primary: Option<&str>) -> Option<String> {
    let p = primary?;
    let i = p.find('/')?;
    Some(p[..i].trim().to_string()).filter(|s| !s.is_empty())
}

static SLOW_PROFILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)chatgpt|codex").expect("regex"));
static UNSUPPORTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)unknown method|not found|INVALID_REQUEST").expect("regex"));
static TIMED_OUT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)timed? ?out").expect("regex"));
const MODEL_STATUSES: [&str; 6] = ["auth", "billing", "rate_limit", "timeout", "format", "no_model"];

/// Whether the primary model runs on a ChatGPT sign-in (Codex), whose runtime is slow to start.
pub fn slow_start_model(primary: Option<&str>) -> bool {
    let Some(p) = primary else { return false };
    let profile = p.find('@').map(|i| &p[i + 1..]).unwrap_or("");
    SLOW_PROFILE.is_match(profile) || provider_of(Some(p)).as_deref() == Some("openai-codex")
}

fn primary_of(config: &Map<String, Value>) -> Option<String> {
    let model = super::common::at(&Value::Object(config.clone()), &["agents", "defaults", "model"])?.clone();
    match model {
        Value::String(s) => Some(s),
        Value::Object(o) => o.get("primary").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// `modelProbe`.
pub async fn model_probe(deps: &Deps) -> Value {
    let primary = match deps.call("config.get", json!({}), CONFIG_READ_TIMEOUT).await {
        Ok(raw) => primary_of(&super::common::config_of(&raw)),
        Err(_) => return json!({ "ok": false, "provider": null, "reason": "no_gateway" }),
    };
    let Some(provider) = provider_of(primary.as_deref()) else {
        return json!({ "ok": false, "provider": null, "reason": "no_model" });
    };
    let slow = slow_start_model(primary.as_deref());
    let timeout_ms = if slow {
        SLOW_START_MODEL_PROBE_TIMEOUT_MS
    } else {
        MODEL_PROBE_TIMEOUT_MS
    };
    let tag = |mut v: Value| {
        if slow {
            v["slowStart"] = json!(true);
        }
        v
    };
    match deps
        .call(
            "models.probe",
            json!({ "provider": provider, "timeoutMs": timeout_ms }),
            Duration::from_millis(timeout_ms + 5000),
        )
        .await
    {
        Ok(r) if r.get("status").and_then(Value::as_str) == Some("ok") => {
            let mut v = json!({ "ok": true, "provider": provider });
            if let Some(ms) = r.get("latencyMs").filter(|m| m.is_number()) {
                v["ms"] = ms.clone();
            }
            tag(v)
        }
        Ok(r) => {
            let status = r
                .get("status")
                .and_then(Value::as_str)
                .filter(|s| MODEL_STATUSES.contains(s));
            tag(json!({ "ok": false, "provider": provider, "reason": status.unwrap_or("unknown") }))
        }
        Err(msg) => {
            // An OpenClaw without the method answers "unknown method"; our own wait running out is a
            // timeout; anything else is a failed probe.
            let reason = if UNSUPPORTED.is_match(&msg) {
                "unsupported"
            } else if TIMED_OUT.is_match(&msg) {
                "timeout"
            } else {
                "unknown"
            };
            tag(json!({ "ok": false, "provider": provider, "reason": reason }))
        }
    }
}

/// `/health/summary` and `/health/model`, before the console's gate: each takes its own token.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.prefix(stages::PREFIXED, "/health/", move |req, _| {
        let app = a.clone();
        async move {
            let path = cc_http::pathname(&req.uri().to_string());
            let method = req.method().clone();
            let target = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            if path == "/health/summary" && method == Method::GET {
                let (parts, refused) =
                    match cc_http::firewall_request(&app.firewall_auth, req, "health", 0, ReadBody::No).await {
                        FirewallRequest::Accepted { .. } => return send_json(200, &health_summary(&app).await),
                        FirewallRequest::Refused { parts, reason } => (parts, reason),
                    };
                if app
                    .console_auth
                    .verify(parts.method.as_str(), &target, cc_http::header(&parts, "authorization"))
                    .is_none()
                {
                    // Named, so the health check can say it too; one of a fixed list of words.
                    let error = match refused {
                        Some(r) => format!("the firewall's token was refused ({})", r.as_str()),
                        None => "Unauthorized".into(),
                    };
                    return send_json(401, &json!({ "error": error }));
                }
                return send_json(200, &health_summary(&app).await);
            }
            if path == "/health/patches" && method == Method::GET {
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok());
                if app.console_auth.verify(method.as_str(), &target, auth).is_none() {
                    return send_json(401, &json!({ "error": "Unauthorized" }));
                }
                return send_json(200, &super::patch_check::patch_report_here(&Deps::of(&app)).await);
            }
            if path == "/health/model" && method == Method::POST {
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok());
                if app.console_auth.verify(method.as_str(), &target, auth).is_none() {
                    return send_json(401, &json!({ "error": "Unauthorized" }));
                }
                return send_json(200, &model_probe(&Deps::of(&app)).await);
            }
            send_json(404, &json!({ "error": "Not found" }))
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provider_and_whether_it_is_slow_to_start() {
        assert_eq!(
            provider_of(Some("openai/gpt-5@openai:controlclaw")),
            Some("openai".into())
        );
        assert_eq!(provider_of(Some("no-slash")), None);
        assert_eq!(provider_of(Some(" /x")), None);
        assert!(slow_start_model(Some("openai/gpt-5.6-sol@openai:controlclaw-chatgpt")));
        assert!(slow_start_model(Some("openai-codex/gpt-5")));
        assert!(!slow_start_model(Some("openai/gpt-5@openai:controlclaw")));
        assert!(!slow_start_model(None));
    }

    #[test]
    fn the_unit_as_systemd_shows_it() {
        let show = |state: &str, file: &str, active: &str, inactive: &str| {
            format!(
                "LoadState=loaded\nUnitFileState={file}\nActiveState={state}\nActiveEnterTimestampMonotonic={active}\nInactiveEnterTimestampMonotonic={inactive}\n"
            )
        };
        let u = parse_unit(&show("active", "enabled", "1000000", "0"), 61_000_000.0);
        assert_eq!(
            (u.active_for, u.down_for, u.loaded, u.enabled),
            (Some(60_000.0), None, true, true)
        );
        // Stopped two minutes ago, by a unit file that is not enabled.
        let u = parse_unit(&show("inactive", "disabled", "1000000", "1000000"), 121_000_000.0);
        assert_eq!((u.active_for, u.down_for, u.enabled), (None, Some(120_000.0), false));
        // Failed, and never stopped since boot: down since boot.
        assert_eq!(
            parse_unit(&show("failed", "enabled", "0", "0"), 5_000_000.0).down_for,
            Some(5_000.0)
        );
        // Starting, stopping, or waiting for systemd to start it again: neither.
        let u = parse_unit(&show("activating", "enabled", "0", "1"), 5_000_000.0);
        assert_eq!((u.active_for, u.down_for), (None, None));
        // Active with no stamp is not judged.
        assert_eq!(
            parse_unit(&show("active", "enabled", "0", "0"), 5_000_000.0).active_for,
            None
        );
        let none = parse_unit("LoadState=not-found\nActiveState=inactive\n", 1_000.0);
        assert!(!none.loaded && !none.enabled);
    }

    #[test]
    fn the_root_disk_is_read() {
        let d = disk_of(&[PathBuf::from("/"), PathBuf::from("/")]).expect("root");
        assert_eq!(d["volume"], json!("system"));
        assert!(d["totalBytes"].as_f64().is_some_and(|t| t > 0.0));
        assert!(disk_of(&[PathBuf::from("/no/such/path")]).is_none());
    }

    #[test]
    fn the_primary_from_either_form() {
        let c = |v: Value| v.as_object().cloned().expect("o");
        assert_eq!(
            primary_of(&c(json!({ "agents": { "defaults": { "model": "a/b" } } }))),
            Some("a/b".into())
        );
        assert_eq!(
            primary_of(&c(
                json!({ "agents": { "defaults": { "model": { "primary": "a/c" } } } })
            )),
            Some("a/c".into())
        );
        assert_eq!(primary_of(&c(json!({}))), None);
    }
}
