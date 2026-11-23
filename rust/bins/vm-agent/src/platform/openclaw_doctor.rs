//! Run OpenClaw doctor (`POST` and `GET /openclaw/doctor`; controlclaw
//! `apps/saas/docs/features/agent-doctor.md`, "Run OpenClaw doctor"). The repair the role makes after
//! an upgrade (T-107), on demand: the gateway stopped as an on-purpose stop, so the watchdog leaves it
//! alone, `openclaw doctor --fix --non-interactive` with the proxy's CA (it checks the plugins against
//! npm), at most 15 minutes, and the gateway started again. `--non-interactive` applies only the safe
//! migrations, and it runs as this box's user, who can run it anyway: so the console's token is
//! enough, as for Restart.
//!
//! One run at a time, in the background: it can take minutes, and the console polls `GET`. The last
//! run is kept in `STATE_DIR/openclaw-doctor.json`, so it is still there after this agent restarts.
//! The output is masked like the Logs page before it leaves the box, and cut to its end.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use cc_http::{Router, json};
use hyper::Method;
use regex::Regex;
use serde_json::{Value, json as j};

use super::common::{CliWrite, Deps};
use super::time::{iso_ms, now_ms};
use crate::app::App;
use crate::stages;

/// `timeout 900`, as the role runs it.
pub const DOCTOR_TIMEOUT: Duration = Duration::from_secs(900);
/// What the console is shown: the end of the output, which is where the result is.
pub const OUTPUT_MAX: usize = 32 * 1024;
const FILE: &str = "openclaw-doctor.json";

/// The run going on, if any: a second POST meanwhile answers with it instead of starting another.
static RUNNING: Mutex<bool> = Mutex::new(false);

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new("\x1b\\[[0-9;?]*[A-Za-z]").expect("regex"));

fn path(app: &App) -> PathBuf {
    app.config.state_dir.join(FILE)
}

fn save(path: &Path, run: &Value) {
    if let Err(e) = cc_store::write_atomic(path, run.to_string().as_bytes(), 0o600, cc_store::TmpName::HiddenPrefix) {
        tracing::error!("[openclaw-doctor] could not save the run: {e}");
    }
}

/// The last run as saved; one saved as running that is not running here was cut short by a restart
/// of this agent.
pub fn last(path: &Path, running_here: bool) -> Option<Value> {
    let mut run: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    if run["phase"] == "running" && !running_here {
        run["phase"] = j!("failed");
        run["error"] = j!("The agent restarted while OpenClaw doctor ran. Check that OpenClaw is running.");
    }
    Some(run)
}

/// Colours out, the box's secrets masked, the last `OUTPUT_MAX` bytes on a line boundary.
pub fn clean(raw: &str, redact: &dyn Fn(&str) -> String) -> String {
    let text = redact(&ANSI.replace_all(raw, ""));
    if text.len() <= OUTPUT_MAX {
        return text.trim_end().to_string();
    }
    let mut cut = text.len() - OUTPUT_MAX;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    let tail = &text[cut..];
    let tail = tail.split_once('\n').map_or(tail, |(_, rest)| rest);
    format!("[…the start is left out]\n{}", tail.trim_end())
}

/// What one finished run says: the doctor's result, then whether OpenClaw was started again.
pub fn outcome(
    started_at: &str,
    result: Result<super::common::Offline, String>,
    redact: &dyn Fn(&str) -> String,
) -> Value {
    let ended = iso_ms(now_ms());
    match result {
        // The gateway did not stop: nothing ran.
        Err(e) => {
            j!({ "phase": "failed", "startedAt": started_at, "endedAt": ended, "ok": false, "started": true, "error": e, "output": "" })
        }
        Ok(off) => {
            let (ok, raw) = match off.results.into_iter().next() {
                Some(Ok(out)) => (true, out),
                Some(Err(out)) => (false, out),
                None => (false, String::new()),
            };
            let started = off.started.is_ok();
            let error = match (&off.started, ok) {
                (Err(e), _) => Some(format!("OpenClaw did not start again: {e}")),
                (Ok(()), false) => Some("OpenClaw doctor did not finish cleanly. Read its output.".to_string()),
                _ => None,
            };
            j!({
                "phase": if ok && started { "done" } else { "failed" },
                "startedAt": started_at,
                "endedAt": ended,
                "ok": ok,
                "started": started,
                "error": error,
                "output": clean(&raw, redact),
            })
        }
    }
}

/// The write the run makes: the role's command, with the proxy's CA when the box has one.
pub fn doctor_write(ca: Option<&Path>) -> CliWrite {
    let mut w = CliWrite::new(&["doctor", "--fix", "--non-interactive"], None, DOCTOR_TIMEOUT);
    if let Some(ca) = ca.filter(|c| c.exists()) {
        w.env.push(("NODE_EXTRA_CA_CERTS", ca.to_string_lossy().into_owned()));
    }
    w.whole_output = true;
    w
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.exact(stages::CONSOLE, Method::GET, "/openclaw/doctor", move |_, _| {
        let app = a.clone();
        async move {
            let here = *RUNNING.lock().unwrap_or_else(|e| e.into_inner());
            json(200, &j!({ "ok": true, "run": last(&path(&app), here) }))
        }
    });
    let a = app.clone();
    router.exact(stages::CONSOLE, Method::POST, "/openclaw/doctor", move |_, _| {
        let app = a.clone();
        async move {
            // A Stop someone asked for (the console's, the emergency stop) stands: the run would end
            // by starting OpenClaw again.
            let stopped = match &app.unmanaged {
                Some(um) => crate::unmanaged::is_down(&app, um).await,
                None => super::stop_mark::STOP_MARK.stopped_on_purpose(now_ms()),
            };
            if stopped {
                return json(409, &j!({ "ok": false, "error": "OpenClaw is stopped. Start it first, then run OpenClaw doctor.", "stopped": true }));
            }
            {
                let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
                if *running {
                    return json(409, &j!({ "ok": false, "error": "OpenClaw doctor is already running on this agent.", "run": last(&path(&app), true) }));
                }
                *running = true;
            }
            let started_at = iso_ms(now_ms());
            let run = j!({ "phase": "running", "startedAt": started_at, "endedAt": null, "ok": null, "started": null, "error": null, "output": "" });
            save(&path(&app), &run);
            tracing::info!("[openclaw-doctor] started");
            let bg = app.clone();
            tokio::spawn(async move {
                let deps = Deps::of(&bg);
                // A managed box's CA; an unmanaged one's OpenClaw has its own trust.
                let ca = bg.unmanaged.is_none().then(|| bg.config.keys_dir.join("mitm-ca.crt"));
                let write = doctor_write(ca.as_deref());
                let result = (deps.offline)(deps.clone(), deps.bin.clone(), vec![write]).await;
                let redaction = crate::boxside::logs::Redaction::load(&bg.config.keys_dir);
                let done = outcome(&started_at, result, &|t| redaction.redact(t));
                tracing::info!("[openclaw-doctor] ended: {}", done["phase"]);
                save(&path(&bg), &done);
                *RUNNING.lock().unwrap_or_else(|e| e.into_inner()) = false;
            });
            json(202, &j!({ "ok": true, "run": run }))
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::common::Offline;

    fn same(t: &str) -> String {
        t.to_string()
    }

    #[test]
    fn the_role_command_with_the_ca_only_when_there_is_one() {
        let dir = tempfile::tempdir().expect("dir");
        let ca = dir.path().join("mitm-ca.crt");
        let w = doctor_write(Some(&ca));
        assert_eq!(w.args, ["doctor", "--fix", "--non-interactive"]);
        assert_eq!(w.timeout, Duration::from_secs(900));
        assert!(w.whole_output);
        assert!(w.env.is_empty(), "no CA file, no variable");
        std::fs::write(&ca, "pem").expect("write");
        let w = doctor_write(Some(&ca));
        assert_eq!(w.env, vec![("NODE_EXTRA_CA_CERTS", ca.to_string_lossy().into_owned())]);
        assert!(doctor_write(None).env.is_empty());
    }

    #[test]
    fn a_clean_run_is_done_and_a_failed_one_keeps_its_output() {
        let ok = outcome(
            "t0",
            Ok(Offline {
                results: vec![Ok("\x1b[32mAll good\x1b[0m\n".into())],
                started: Ok(()),
            }),
            &same,
        );
        assert_eq!(ok["phase"], "done");
        assert_eq!(ok["output"], "All good");
        assert_eq!(ok["error"], Value::Null);

        let bad = outcome(
            "t0",
            Ok(Offline {
                results: vec![Err("migrating…\n[exit code 1]\n".into())],
                started: Ok(()),
            }),
            &same,
        );
        assert_eq!(bad["phase"], "failed");
        assert_eq!(bad["ok"], false);
        assert_eq!(bad["started"], true);
        assert!(bad["output"].as_str().expect("a string").contains("[exit code 1]"));

        let down = outcome(
            "t0",
            Ok(Offline {
                results: vec![Ok("fine".into())],
                started: Err("Job failed".into()),
            }),
            &same,
        );
        assert_eq!(down["phase"], "failed");
        assert_eq!(down["started"], false);
        assert!(
            down["error"]
                .as_str()
                .expect("a string")
                .contains("did not start again")
        );

        let never = outcome("t0", Err("OpenClaw did not stop to save it: x".into()), &same);
        assert_eq!(never["phase"], "failed");
        assert_eq!(never["output"], "");
    }

    #[test]
    fn the_output_is_masked_and_cut_to_its_end() {
        let masked = clean("token abcdefgh12345678 here", &|t| {
            t.replace("abcdefgh12345678", "[redacted]")
        });
        assert_eq!(masked, "token [redacted] here");
        let long = format!("{}\nlast line", "x".repeat(OUTPUT_MAX * 2));
        let cut = clean(&long, &same);
        assert!(cut.starts_with("[…the start is left out]"));
        assert!(cut.ends_with("last line"));
        assert!(cut.len() <= OUTPUT_MAX + 40);
    }

    #[test]
    fn a_run_saved_as_running_after_a_restart_reads_as_cut_short() {
        let dir = tempfile::tempdir().expect("dir");
        let p = dir.path().join(FILE);
        assert!(last(&p, false).is_none());
        save(&p, &j!({ "phase": "running", "startedAt": "t0" }));
        assert_eq!(last(&p, true).expect("saved")["phase"], "running");
        let cut = last(&p, false).expect("saved");
        assert_eq!(cut["phase"], "failed");
        assert!(cut["error"].as_str().expect("a string").contains("restarted"));
    }
}
