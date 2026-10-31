//! `/kill/*`, the box side of the emergency stop (`routes/kill.ts`). Only the firewall's token with
//! purpose `kill`, not even the control plane's (which has `/stop`). Stateless on purpose: the
//! firewall holds the state and applies it again every minute, so a box that reboots is stopped
//! again within the minute. `POST /kill/apply {locked}` answers with what OpenClaw is now.

use std::sync::Arc;
use std::time::Duration;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, send_json};
use cc_proc::Cmd;
use hyper::Method;
use serde_json::{Value, json};

use crate::app::App;
use crate::stages;

/// `ACTION_TIMEOUT_MS`.
const ACTION_TIMEOUT: Duration = Duration::from_secs(90);

/// `runAction`, the sync one the emergency stop uses: `sudo systemctl` without `-n` (the TS's
/// command; the box's sudoers line has NOPASSWD), and the error is all of stderr, or Node's
/// "Command failed: …". Not `openclaw::run_action`, whose `-n` and last-line error are the async
/// one's: the firewall reports this message as it is.
pub async fn run_action_sync(runner: &dyn cc_proc::Runner, action: &str, service: &str) -> Result<(), String> {
    super::stop_mark::STOP_MARK.note(action, None);
    let cmd = Cmd::new("sudo")
        .args(["systemctl", action, service])
        .timeout(ACTION_TIMEOUT);
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(()),
        Ok(out) => {
            let stderr = out.stderr_str();
            Err(if stderr.trim().is_empty() {
                format!("Command failed: sudo systemctl {action} {service}")
            } else {
                stderr.trim().to_string()
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.prefix(stages::PREFIXED, "/kill/", move |req, _| {
        let app = a.clone();
        async move {
            let read = if req.method() == Method::POST {
                ReadBody::Json { limit: 16_384 }
            } else {
                ReadBody::No
            };
            let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "kill", 0, read).await {
                FirewallRequest::Accepted { parts, body, .. } => (parts, body),
                FirewallRequest::Refused { .. } => {
                    return send_json(
                        401,
                        &json!({ "error": "an emergency stop must come from the org firewall" }),
                    );
                }
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            let active = |app: &Arc<App>| {
                let app = app.clone();
                async move {
                    match &app.unmanaged {
                        // Starting counts as up: a gateway that is not answering yet is not stopped.
                        Some(um) => !crate::unmanaged::is_down(&app, um).await,
                        None => super::state::is_active(app.runner.as_ref(), &app.config.service).await == "active",
                    }
                }
            };
            if path == "/kill/status" && parts.method == Method::GET {
                return send_json(200, &json!({ "ok": true, "active": active(&app).await }));
            }
            if path != "/kill/apply" || parts.method != Method::POST {
                return send_json(404, &json!({ "error": "Not found" }));
            }
            let locked = match &body {
                FirewallBody::Json(b) => b.get("locked").and_then(Value::as_bool),
                _ => None,
            };
            let Some(locked) = locked else {
                return send_json(400, &json!({ "ok": false, "error": "locked must be a boolean" }));
            };
            // The action and its readback in one turn of the unit's lock: no restart by the console
            // or the watchdog lands in between, as none could on Node's one thread.
            let _one = super::openclaw::UNIT_ACTIONS.lock().await;
            // `systemctl stop` on a stopped unit does nothing: the every-minute reconcile is cheap.
            let action = if locked { "stop" } else { "start" };
            let result = match &app.unmanaged {
                // The way this OpenClaw runs (systemd, Docker, pm2, a process), not our unit.
                Some(um) => {
                    if locked {
                        um.restarts.stopped();
                    }
                    let r = crate::unmanaged::supervisor::act(app.runner.as_ref(), &um.install(), action).await;
                    crate::unmanaged::after_act(&app, um, action);
                    r
                }
                None => run_action_sync(app.runner.as_ref(), action, &app.config.service).await,
            };
            let now_active = active(&app).await;
            // The truth, not the ask: a stop that "worked" while the unit is still up is a failure.
            let ok = result.is_ok() && now_active == !locked;
            let answer = json!({
                "ok": ok,
                "locked": locked,
                "active": now_active,
                "message": result.err().unwrap_or_default(),
            });
            send_json(if ok { 200 } else { 500 }, &answer)
        }
    });
}
