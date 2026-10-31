//! Start, stop, restart and status of the OpenClaw unit (`packages/vm-agent/src/routes/openclaw.ts`),
//! and the console's template poke (index.ts).

use std::sync::Arc;
use std::time::Duration;

use cc_http::{Router, json};
use cc_proc::{Cmd, Runner};
use hyper::Method;
use serde_json::{Value, json as j};

use std::sync::LazyLock;

use regex::Regex;

use super::state::{is_active, run_state};
use crate::app::App;
use crate::stages;

const EXEC_TIMEOUT: Duration = Duration::from_secs(5);
/// `SERVICE_ACTION_MS` in `budgets.ts`.
const ACTION_TIMEOUT: Duration = Duration::from_secs(90);

/// `runStatusSummary`: the last lines of `systemctl status`, or what it printed before failing.
async fn status_summary(runner: &dyn Runner, service: &str) -> String {
    let cmd = Cmd::new("systemctl")
        .args(["status", service, "--no-pager", "-n", "5"])
        .timeout(EXEC_TIMEOUT);
    match runner.run(cmd).await {
        Ok(out) if out.success() || !out.stdout.is_empty() => out.stdout_str().trim().to_string(),
        _ => "status unavailable".to_string(),
    }
}

/// One start, stop or restart of the unit at a time, whoever asks (the console, the watchdog, a
/// heal, the emergency stop): Node ran them one after another on its one thread.
pub static UNIT_ACTIONS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `runActionAsync`: `sudo -n systemctl <action> <service>`; the error is the failure's first line.
/// Noted first (`stop_mark.rs`): a stop is on purpose, a start or a restart clears that.
pub async fn run_action(runner: &dyn Runner, action: &str, service: &str) -> Result<(), String> {
    super::stop_mark::STOP_MARK.note(action, None);
    let _one = UNIT_ACTIONS.lock().await;
    let cmd = Cmd::sudo("systemctl").args([action, service]).timeout(ACTION_TIMEOUT);
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(()),
        Ok(out) => Err(exec_failure_line(
            &out.stderr_str(),
            &out.stdout_str(),
            if out.timed_out { "timed out" } else { "Command failed" },
        )),
        Err(e) => Err(exec_failure_line("", "", &e.to_string())),
    }
}

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new("\x1b\\[[0-9;]*m").expect("regex"));

/// `execFailureLine` (exec.ts): the last non-empty line of stderr, else stdout, else the error
/// message, ANSI colours stripped; "command failed" when there is none.
pub fn exec_failure_line(stderr: &str, stdout: &str, message: &str) -> String {
    let text = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        message
    };
    let clean = ANSI.replace_all(text, "");
    clean
        .trim()
        .split('\n')
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or("command failed")
        .to_string()
}

/// `POST /templates/poke`: the console has a preview or an apply waiting. Carries nothing; the
/// agent asks the console itself.
pub fn register_poke(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.exact(stages::CONSOLE, Method::POST, "/templates/poke", move |_, _| {
        let app = app.clone();
        async move {
            if let Some(poke) = app
                .contracts
                .platform
                .get()
                .and_then(|p| p.templates_poke.get().cloned())
            {
                poke();
            }
            cc_http::send_json(202, &j!({ "ok": true }))
        }
    });
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    for action in ["start", "stop", "restart"] {
        let app = app.clone();
        let path: &'static str = match action {
            "start" => "/start",
            "stop" => "/stop",
            _ => "/restart",
        };
        router.exact(stages::CONSOLE, Method::POST, path, move |_, _| {
            let app = app.clone();
            async move {
                // Leave a meeting first (index.ts), through W8's `MeetingControl`. Never a reason not to stop.
                if action != "start"
                    && let Some(meeting) = app.contracts.meeting.get()
                    && meeting.stop().await.is_err()
                {
                    tracing::error!("[meetings] cleanup incomplete during {action}");
                }
                let service = app.config.service.clone();
                let result = run_action(app.runner.as_ref(), action, &service).await;
                let status = is_active(app.runner.as_ref(), &service).await;
                let summary = status_summary(app.runner.as_ref(), &service).await;
                let ok = result.is_ok();
                json(
                    if ok { 200 } else { 500 },
                    &j!({
                        "ok": ok,
                        "action": action,
                        "active": status == "active",
                        "status": status,
                        "message": match result { Ok(()) => summary, Err(e) => e },
                    }),
                )
            }
        });
    }
    let app = app.clone();
    router.exact(stages::CONSOLE, Method::GET, "/status", move |_, _| {
        let app = app.clone();
        async move {
            let service = app.config.service.clone();
            let runner = app.runner.as_ref();
            let (status, summary) = tokio::join!(is_active(runner, &service), status_summary(runner, &service));
            // A brain passes no gateway (`gbrain.ts`); its state is the unit's.
            let connected = if super::is_brain(&app) {
                None
            } else {
                app.contracts.openclaw.get().map(|o| o.client.connected())
            };
            let state = run_state(runner, &service, &status, connected).await;
            let mut body = serde_json::Map::new();
            body.insert("ok".into(), j!(true));
            body.insert("action".into(), j!("status"));
            body.insert("active".into(), j!(status == "active"));
            body.insert("status".into(), j!(status));
            body.insert("state".into(), j!(state));
            if let Some(c) = connected {
                body.insert("gateway".into(), j!(c));
            }
            body.insert("message".into(), j!(summary));
            let fingerprint = super::doctor::status(std::path::Path::new(super::doctor::DOCTOR_KEY_FILE));
            body.insert(
                "software".into(),
                super::box_software(&app, Some(fingerprint.as_deref())),
            );
            body.insert("doctor".into(), j!({ "fingerprint": fingerprint }));
            // A count, not the detail (`drive.summary()`); not on a brain.
            if !super::is_brain(&app)
                && let Some(drive) = app.contracts.box_setup.get().and_then(|b| b.drive_summary())
            {
                body.insert("drive".into(), drive);
            }
            json(200, &Value::Object(body))
        }
    });
}

#[cfg(test)]
mod tests {
    use super::exec_failure_line;

    #[test]
    fn the_last_line_of_the_failure_without_colours() {
        assert_eq!(
            exec_failure_line("Job failed.\n\x1b[31mSee journalctl\x1b[0m\n\n", "", "x"),
            "See journalctl"
        );
        assert_eq!(exec_failure_line("", "out line\n", "x"), "out line");
        assert_eq!(
            exec_failure_line("", "", "Command failed: sudo"),
            "Command failed: sudo"
        );
        assert_eq!(exec_failure_line("  \n ", "", "x"), "command failed");
    }
}
