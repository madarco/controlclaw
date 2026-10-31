//! Firewall Doctor's only way to change the firewall (`fw-doctor-tools.ts`, docs/plans/doctor-rescue.md
//! Phase 2). The coding agent runs as `ccdoctor`, with no sudo, in a unit that cannot gain
//! privileges. It calls `cc-fwdoctor <verb> [arg]`, a small client that posts to the loopback
//! listener (`loopback.rs`) with the session's own token. Here the verb is checked against a fixed
//! list and run: reads through the Logs page's reader (W3's `FwLogs`), changes through the root
//! helper `cc-fw-repair` that only this daemon's account may call, and a retried update through the
//! self-update service (W3's `SelfUpdate`). Every answer is masked like the Logs page before the
//! coding agent, and so its provider, sees it.
//!
//! There is no shell, no file write and no read of the state directory or keys. A broken rendered
//! config is repaired by rendering it again (`update-retry`), not by editing it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncReadExt;

use cc_http::BoxFuture;

use super::loopback::{self, LoopbackTools, ToolAnswer};
use crate::integrations::connectors::firewall::js_slice;
use crate::integrations::js;

/// Services a repair may restart or clear. The names are the Logs page's (`FW_SERVICES`).
pub const FW_REPAIR_SERVICES: &[&str] = &["proxy", "caddy", "dnsmasq", "tang", "disk", "team-chat", "chrony"];
const LOG_SERVICES: &[&str] = &[
    "mitm-agent",
    "proxy",
    "caddy",
    "dnsmasq",
    "tang",
    "disk",
    "team-chat",
    "chrony",
    "tailscale",
    "update",
];
const CHECKS: &[&str] = &["caddy", "dnsmasq"];
const CLEANS: &[&str] = &["journal", "apt", "tmp"];
const RANGES: &[&str] = &["15m", "1h", "24h"];
const MAX_OUTPUT: usize = 60_000;
pub const FW_REPAIR_HELPER: &str = "/usr/local/bin/cc-fw-repair";
pub const FW_DOCTOR_CLIENT: &str = "/usr/local/bin/cc-fwdoctor";

pub fn help() -> String {
    format!(
        "cc-fwdoctor <command> [argument]

  status                       service states, failed units, disk use and the last update
  logs <service> [15m|1h|24h]  that service's journal (default 1h)
                               services: {}
  update-log                   the last update or provisioning run
  check caddy|dnsmasq          validate the rendered configuration
  restart <service>            restart one service: {}
  reset-failed <service>       clear a service's failed state (same list)
  disk                         the largest directories under the paths that fill up
  clean journal|apt|tmp        free space: vacuum the journal, apt's cache, old temporary files
  secure-mount                 mount the firewall's encrypted state (cc-secure mount)
  update-retry                 run the firewall update again: it installs the current release and writes
                               every configuration fresh. Once per session. If it restarts the firewall
                               software, this repair session ends.",
        LOG_SERVICES.join(", "),
        FW_REPAIR_SERVICES.join(", ")
    )
}

/// A refused or failed helper run (`FwRepairError`): its one `cc-fw-repair: ` line, and what it
/// printed before failing (caddy's own error, say). `output` is None for a plain failure.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairError {
    pub message: String,
    pub output: Option<String>,
}

/// `repair(verb, arg)`: `sudo -n cc-fw-repair <verb> [arg]`, its stdout.
pub type RepairFn = Arc<dyn Fn(&'static str, Option<String>) -> BoxFuture<Result<String, RepairError>> + Send + Sync>;
/// `logs.read({range, service})`: the `FwLogsResponse` as JSON.
pub type LogsFn = Arc<dyn Fn(&'static str, String) -> BoxFuture<Result<Value, String>> + Send + Sync>;

pub struct Options {
    pub logs: LogsFn,
    pub repair: RepairFn,
    /// Starts `cc-reprovision`; what to tell the coding agent. At most once a session.
    pub update: Arc<dyn Fn() -> String + Send + Sync>,
    /// Masks every secret this firewall holds.
    pub redact: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

/// A value as a JavaScript template literal writes it.
fn t(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Number(n) => n.as_f64().map(js::number).unwrap_or_default(),
        Value::Bool(b) => b.to_string(),
        Value::Array(a) => a
            .iter()
            .map(|x| if x.is_null() { String::new() } else { t(x) })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

fn format_logs(r: &Value) -> String {
    if truthy(&r["warning"]) {
        return t(&r["warning"]);
    }
    if let Some(run) = r.get("run").filter(|v| truthy(v)) {
        let lines: Vec<String> = run.as_array().map(|a| a.iter().map(t).collect()).unwrap_or_default();
        let text = lines.join("\n");
        return if text.is_empty() {
            "The last update run wrote nothing.".into()
        } else {
            text
        };
    }
    let lines: Vec<String> = r["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|l| {
            format!(
                "{} {} {} {}",
                t(&l["time"]),
                t(&l["service"]),
                t(&l["level"]),
                t(&l["message"])
            )
        })
        .collect();
    let text = lines.join("\n");
    let text = if text.is_empty() {
        "No journal lines in this window.".to_string()
    } else {
        text
    };
    if truthy(&r["truncated"]) {
        format!("{text}\n(older lines cut)")
    } else {
        text
    }
}

/// What each service is for, so a stopped DNS is not read as an optional extra.
fn format_services(r: &Value) -> String {
    let rows: Vec<String> = r["services"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            let id = t(&s["id"]);
            let pad = 11usize.saturating_sub(id.encode_utf16().count());
            let result = &s["result"];
            format!(
                "{id}{} {}/{}{}{}{} - {}",
                " ".repeat(pad),
                t(&s["active"]),
                t(&s["sub"]),
                if truthy(result) && result != "success" {
                    format!(" result={}", t(result))
                } else {
                    String::new()
                },
                if truthy(&s["restarts"]) {
                    format!(" restarts={}", t(&s["restarts"]))
                } else {
                    String::new()
                },
                if truthy(&s["optional"]) {
                    " (optional)"
                } else {
                    " (required)"
                },
                t(&s["about"]),
            )
        })
        .collect();
    let update = if truthy(&r["update"]) {
        format!("\nlast update: {}", js::stringify(&r["update"]))
    } else {
        String::new()
    };
    format!("{}{update}", rows.join("\n"))
}

fn one_of(list: &[&'static str], v: Option<&str>) -> Option<&'static str> {
    v.and_then(|v| list.iter().find(|x| **x == v).copied())
}

/// `runFwDoctorCommand`: one verb, run and masked. The listener below is the only caller on a box.
pub async fn run_command(opts: &Options, verb: &str, arg: Option<&str>, extra: Option<&str>) -> ToolAnswer {
    let done = |text: &str, ok: bool| ToolAnswer::new(ok, js_slice(&(opts.redact)(text), MAX_OUTPUT));
    let failed = |e: Failure| {
        // The helper's own message is a fixed line written for this purpose; anything else stays generic.
        let (message, output) = match e {
            Failure::Repair(r) if r.message.starts_with("cc-fw-repair: ") => (r.message, r.output),
            Failure::Repair(r) => ("The command failed on the firewall.".into(), r.output),
            Failure::Other | Failure::Refused(_) => ("The command failed on the firewall.".to_string(), None),
        };
        let output = output
            .map(|o| js::trim(&o).to_string())
            .filter(|o| !o.is_empty())
            .map(|o| format!("{o}\n"))
            .unwrap_or_default();
        done(&format!("{output}{message}"), false)
    };
    let repair = |verb: &'static str, arg: Option<&str>| (opts.repair)(verb, arg.map(String::from));
    let r: Result<String, Failure> = async {
        match verb {
            "help" => Ok(help()),
            "status" => {
                let (states, host) = tokio::join!((opts.logs)("1h", "all".into()), repair("status", None));
                // The helper's own `cc-fw-repair:` line is what the TS's catch reports.
                let host = host.map_err(Failure::Repair)?;
                let states = states.map_err(|_| Failure::Other)?;
                Ok(format!("{}\n\n{host}", format_services(&states)))
            }
            "logs" => {
                let Some(service) = one_of(LOG_SERVICES, arg) else {
                    return Err(Failure::Refused(format!(
                        "Unknown service. One of: {}",
                        LOG_SERVICES.join(", ")
                    )));
                };
                let range = one_of(RANGES, extra).unwrap_or("1h");
                let r = (opts.logs)(range, service.into()).await.map_err(|_| Failure::Other)?;
                Ok(format_logs(&r))
            }
            "update-log" => {
                let r = (opts.logs)("24h", "run".into()).await.map_err(|_| Failure::Other)?;
                Ok(format_logs(&r))
            }
            "check" => {
                let Some(a) = one_of(CHECKS, arg) else {
                    return Err(Failure::Refused("check takes caddy or dnsmasq.".into()));
                };
                repair("check", Some(a)).await.map_err(Failure::Repair)
            }
            "restart" | "reset-failed" => {
                let Some(a) = one_of(FW_REPAIR_SERVICES, arg) else {
                    return Err(Failure::Refused(format!(
                        "Unknown service. One of: {}",
                        FW_REPAIR_SERVICES.join(", ")
                    )));
                };
                let v = if verb == "restart" { "restart" } else { "reset-failed" };
                repair(v, Some(a)).await.map_err(Failure::Repair)
            }
            "disk" => repair("disk", None).await.map_err(Failure::Repair),
            "clean" => {
                let Some(a) = one_of(CLEANS, arg) else {
                    return Err(Failure::Refused("clean takes journal, apt or tmp.".into()));
                };
                repair("clean", Some(a)).await.map_err(Failure::Repair)
            }
            "secure-mount" => repair("secure-mount", None).await.map_err(Failure::Repair),
            "update-retry" => Ok((opts.update)()),
            _ => Err(Failure::Refused(format!("Unknown command.\n\n{}", help()))),
        }
    }
    .await;
    match r {
        Ok(text) => done(&text, true),
        Err(Failure::Refused(text)) => done(&text, false),
        Err(e) => failed(e),
    }
}

enum Failure {
    /// A refusal written here, answered as it is.
    Refused(String),
    Repair(RepairError),
    Other,
}

/// `FwDoctorTools`: the loopback listener for one Firewall Doctor session.
pub fn listener(opts: Arc<Options>, active: Arc<dyn Fn() -> bool + Send + Sync>) -> Arc<LoopbackTools> {
    // `update-retry` runs once a session: each run restarts services the whole organization uses.
    let updated = Arc::new(AtomicBool::new(false));
    LoopbackTools::new(loopback::Options {
        active,
        help: help(),
        what: None,
        arg_max: None,
        run: Arc::new(move |verb, arg, extra| {
            let (opts, updated) = (opts.clone(), updated.clone());
            Box::pin(async move {
                if verb == "update-retry" && updated.swap(true, Ordering::SeqCst) {
                    return ToolAnswer::new(
                        false,
                        "The update already ran in this session. Follow it on the Firewall page, or start a new session.",
                    );
                }
                run_command(&opts, &verb, arg.as_deref(), extra.as_deref()).await
            })
        }),
    })
}

/// `runFwRepair`: the root helper, with no shell. Its one fixed `cc-fw-repair: ` line on stderr is
/// the only part of stderr passed on.
pub fn local_repair(helper: String) -> RepairFn {
    Arc::new(move |verb, arg| {
        let helper = helper.clone();
        Box::pin(async move {
            let mut args = vec!["-n".to_string(), helper, verb.to_string()];
            args.extend(arg);
            let fail = |stderr: &[u8], stdout: &[u8]| RepairError {
                message: String::from_utf8_lossy(stderr)
                    .split('\n')
                    .find(|l| l.starts_with("cc-fw-repair: "))
                    .unwrap_or("cc-fw-repair: the command failed.")
                    .to_string(),
                output: Some(String::from_utf8_lossy(stdout).into_owned()),
            };
            let mut child = tokio::process::Command::new("sudo")
                .args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| fail(b"", b""))?;
            let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
                return Err(fail(b"", b""));
            };
            // `maxBuffer` and `timeout`: past 4 MiB on either stream or 120 s, execFile stops the
            // helper with SIGTERM, which sudo passes on (a SIGKILL of sudo would leave it running).
            let read = async {
                let (mut o, mut e) = (Vec::new(), Vec::new());
                let (mut bo, mut be) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
                let (mut o_done, mut e_done) = (false, false);
                while !(o_done && e_done) {
                    tokio::select! {
                        n = out.read(&mut bo), if !o_done => match n {
                            Ok(0) | Err(_) => o_done = true,
                            Ok(n) => o.extend_from_slice(&bo[..n]),
                        },
                        n = err.read(&mut be), if !e_done => match n {
                            Ok(0) | Err(_) => e_done = true,
                            Ok(n) => e.extend_from_slice(&be[..n]),
                        },
                    }
                    if o.len() > MAX_BUFFER || e.len() > MAX_BUFFER {
                        return (o, e, false);
                    }
                }
                (o, e, true)
            };
            // A timeout reads as nothing, not whole.
            // The 120 s cover the helper's whole run: one that closes its streams and keeps running is
            // stopped too, rather than holding the one-command slot.
            let run = async {
                let (o, e, whole) = read.await;
                if !whole {
                    return (o, e, None);
                }
                let status = child.wait().await.ok();
                (o, e, Some(status))
            };
            let (o, e, status) = tokio::time::timeout(Duration::from_secs(120), run)
                .await
                .unwrap_or_default();
            match status {
                Some(Some(s)) if s.success() => Ok(String::from_utf8_lossy(&o).into_owned()),
                Some(_) => Err(fail(&e, &o)),
                None => {
                    super::runner::terminate(&mut child, Duration::from_secs(5)).await;
                    Err(fail(&e, &o))
                }
            }
        })
    })
}

const MAX_BUFFER: usize = 4 * 1024 * 1024;

#[cfg(test)]
mod tests;
