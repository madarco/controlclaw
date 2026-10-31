//! In-place updates (`update.ts`, `routes/update.ts`): what `cc-reprovision` reports in
//! `state/update.json`, and `/update` to start one. The run is `sudo systemd-run cc-reprovision`
//! with no arguments: what is pulled is pinned in root-owned `/etc/controlclaw/update.conf`, so
//! this process can trigger *the* update and nothing more. Starting one needs the firewall's token
//! (it holds the person's code); reading the status takes the console's too.

use std::path::Path;

use serde_json::{Value, json};

use super::time::{date_parse, now_ms};

/// A run that stopped reporting for this long is not still running.
const STALE_MS: i64 = 45 * 60_000;

pub fn running_phase(phase: &str) -> bool {
    matches!(phase, "resolving" | "installing" | "running")
}

/// `UpdateService.status()`: `{phase, detail, ref, at, reboot?}`, idle when the file is missing
/// or not JSON, failed when a run stopped reporting.
pub fn status(path: &Path) -> Value {
    let idle = json!({ "phase": "idle", "detail": null, "ref": null, "at": null });
    let Ok(raw) = std::fs::read_to_string(path) else {
        return idle;
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
        return idle;
    };
    let text = |k: &str| parsed.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let phase = parsed
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("idle")
        .to_string();
    let at = parsed.get("at").and_then(Value::as_str).map(str::to_string);
    let mut status = json!({ "phase": phase, "detail": text("detail"), "ref": text("ref"), "at": at });
    if parsed.get("reboot") == Some(&json!(true)) {
        status["reboot"] = json!(true);
    }
    if running_phase(&phase)
        && let Some(t) = at.as_deref().and_then(date_parse)
        && now_ms() - t > STALE_MS
    {
        status["phase"] = json!("failed");
        status["detail"] = json!("The update stopped reporting. Check the agent's logs.");
    }
    status
}

/// `updateRunning(update.status())`.
pub fn running(path: &Path) -> bool {
    status(path)["phase"].as_str().is_some_and(running_phase)
}

/// Where `cc-reprovision` writes its progress (`STATE_DIR/update.json`): one place for every reader.
pub fn state_path(app: &crate::app::App) -> std::path::PathBuf {
    app.config.state_dir.join("update.json")
}

pub const UPDATE_CONF: &str = "/etc/controlclaw/update.conf";

/// `conf()`: `KEY=value` lines; None without an `ANSIBLE_REPO` (a box from before in-place updates).
pub fn pinned(conf: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(conf) else {
        return false;
    };
    // `/^([A-Z_]+)=(.*)$/` per line; a later line wins, and the repo must not be empty.
    let mut repo = None;
    for line in raw.split('\n') {
        if let Some((k, v)) = line.trim().split_once('=')
            && k == "ANSIBLE_REPO"
        {
            repo = Some(v.to_string());
        }
    }
    repo.is_some_and(|r| !r.is_empty())
}

/// What starts the detached run; a test stands in for it.
pub type Spawn = Box<dyn Fn(&str, &[String]) -> Result<(), String> + Send + Sync>;

/// `detach`: its own process group, nothing attached, so the restart the run makes does not end it.
/// A binary that is missing is logged, as Node reports it after the fact.
pub fn detach(file: &str, args: &[String]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let child = std::process::Command::new(file)
        .args(args)
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match child {
        Ok(mut c) => {
            // Reaped when it ends; nothing waits on it.
            std::thread::spawn(move || {
                let _ = c.wait();
            });
        }
        // Rust knows at once what Node learns later: a run that did not start is not "starting".
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

/// `UpdateService.start`: a run unless one is going. Err is the message the route answers 500 with.
pub fn start(state: &Path, conf: &Path, mode_auto: Option<i64>, spawn: &Spawn) -> Result<Value, String> {
    // One at a time: the status read and the launch are one step, as on Node's one thread.
    static STARTING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = STARTING.lock().unwrap_or_else(|e| e.into_inner());
    if !pinned(conf) {
        return Err("This agent was created before in-place updates; it has to be rebuilt instead.".into());
    }
    let current = status(state);
    if current["phase"].as_str().is_some_and(running_phase) {
        return Ok(json!({ "ok": true, "status": current }));
    }
    let mut args: Vec<String> = vec![
        "/usr/bin/systemd-run".into(),
        "--unit=cc-reprovision".into(),
        "--collect".into(),
    ];
    if let Some(deadline) = mode_auto {
        if deadline <= now_ms().div_euclid(1000) {
            return Err("The automatic update window has closed.".into());
        }
        args.push("--setenv=CC_UPDATE_MODE=auto".into());
        args.push(format!("--setenv=CC_UPDATE_DEADLINE={deadline}"));
    }
    args.push("/usr/local/bin/cc-reprovision".into());
    spawn("sudo", &args).map_err(|e| format!("The update could not be started: {e}"))?;
    tracing::info!("[update] started cc-reprovision");
    Ok(
        json!({ "ok": true, "status": { "phase": "resolving", "detail": "Starting…", "ref": null, "at": super::time::iso_ms(now_ms()) } }),
    )
}

/// `Number.isSafeInteger`.
fn safe_integer(v: &Value) -> Option<i64> {
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

/// `GET /update` and `POST /update` on `stage` (the agent box's prefixed stage; W8's brain box
/// serves the same route).
pub fn register_on(router: &mut cc_http::Router, app: &std::sync::Arc<crate::app::App>, stage: &str) {
    use cc_http::{FirewallBody, FirewallRequest, ReadBody, send_json};
    use hyper::Method;
    let a = app.clone();
    router.route(
        stage,
        |_, p| p == "/update",
        move |req, _| {
            let app = a.clone();
            async move {
                let write = req.method() == Method::POST;
                // Bytes were sent: a declared length, or any transfer coding (chunked has no length).
                let sent = req.headers().contains_key("transfer-encoding")
                    || req
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .is_some_and(|n| n > 0);
                // A write needs the firewall's token, read here with what it was signed over; a
                // read takes it, else the console's.
                let (parts, body, signed_body) = if write {
                    match cc_http::firewall_request(
                        &app.firewall_auth,
                        req,
                        "update",
                        0,
                        ReadBody::Json { limit: 16_384 },
                    )
                    .await
                    {
                        FirewallRequest::Accepted { parts, accepted, body } => {
                            (parts, Some(body), accepted.body_sha256.is_some())
                        }
                        FirewallRequest::Refused { .. } => {
                            return send_json(401, &json!({ "error": "an update must come from the org firewall" }));
                        }
                    }
                } else {
                    let (parts, who) = super::common::caller(&app, req, "update", 16_384).await;
                    if who.is_none() {
                        return send_json(401, &json!({ "error": "Unauthorized" }));
                    }
                    (parts, None, false)
                };
                let state = state_path(&app);
                let conf = Path::new(UPDATE_CONF);
                if parts.method == Method::GET {
                    let mut out = json!({ "ok": true, "automatic": true, "pinned": pinned(conf) });
                    if let (Some(o), Value::Object(st)) = (out.as_object_mut(), status(&state)) {
                        o.extend(st);
                    }
                    return send_json(200, &out);
                }
                if parts.method != Method::POST {
                    return send_json(404, &json!({ "error": "Not found" }));
                }
                let body = match body {
                    Some(FirewallBody::Json(b)) => Some(b),
                    _ => None,
                };
                // Not JSON, too big, or not the body the token named: refused whenever one was sent,
                // and whenever the token was signed over a body (a token for an automatic run must
                // not start a manual one with no body). The firewall always sends a JSON body (`{}`
                // for a manual run), so a refused one is never a request it made. Read here and not
                // through `common::caller`, which does not pass on what the token was signed over.
                if body.is_none() && (sent || signed_body) {
                    return send_json(400, &json!({ "error": "Invalid update body" }));
                }
                let mode = body.as_ref().and_then(|b| b.get("mode"));
                let deadline = body.as_ref().and_then(|b| b.get("deadline")).and_then(safe_integer);
                let auto = mode == Some(&json!("auto"));
                if (mode.is_some() && !auto) || (auto && deadline.is_none()) {
                    return send_json(400, &json!({ "error": "Invalid update mode or deadline" }));
                }
                let spawn: Spawn = Box::new(detach);
                match start(&state, conf, if auto { deadline } else { None }, &spawn) {
                    Ok(v) => send_json(200, &v),
                    Err(e) => send_json(500, &json!({ "ok": false, "error": e })),
                }
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_is_the_last_repo_line_and_a_failed_launch_is_an_error() {
        let d = tempfile::tempdir().expect("dir");
        let conf = d.path().join("update.conf");
        std::fs::write(&conf, "ANSIBLE_REPO=https://x\nANSIBLE_REPO=\n").expect("w");
        assert!(!pinned(&conf), "cleared later in the file");
        std::fs::write(&conf, "ANSIBLE_REPO=\nANSIBLE_REPO=https://x\n").expect("w");
        assert!(pinned(&conf));
        assert!(detach("/no/such/binary", &[]).is_err());
        let state = d.path().join("update.json");
        std::fs::write(
            &state,
            json!({ "phase": "running", "at": "2020-01-01T00:00:00+00:00" }).to_string(),
        )
        .expect("w");
        assert_eq!(status(&state)["phase"], json!("failed"), "an offset time is read too");
    }

    #[test]
    fn a_run_starts_only_with_a_pin_and_not_twice() {
        let d = tempfile::tempdir().expect("dir");
        let (state, conf) = (d.path().join("update.json"), d.path().join("update.conf"));
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
        let c = calls.clone();
        let spawn: Spawn = Box::new(move |f, a| {
            let mut line = vec![f.to_string()];
            line.extend(a.iter().cloned());
            c.lock().expect("l").push(line);
            Ok(())
        });
        assert!(start(&state, &conf, None, &spawn).is_err(), "no pin: rebuilt instead");
        std::fs::write(&conf, "ANSIBLE_REPO=https://x\nANSIBLE_REF=main\n").expect("w");
        let v = start(&state, &conf, None, &spawn).expect("started");
        assert_eq!(v["status"]["phase"], json!("resolving"));
        assert_eq!(
            calls.lock().expect("l")[0],
            [
                "sudo",
                "/usr/bin/systemd-run",
                "--unit=cc-reprovision",
                "--collect",
                "/usr/local/bin/cc-reprovision"
            ]
        );
        assert_eq!(
            start(&state, &conf, Some(1), &spawn).expect_err("closed"),
            "The automatic update window has closed."
        );
        std::fs::write(
            &state,
            json!({ "phase": "installing", "at": super::super::time::iso_ms(now_ms()) }).to_string(),
        )
        .expect("w");
        assert_eq!(
            start(&state, &conf, None, &spawn).expect("running")["status"]["phase"],
            json!("installing")
        );
        assert_eq!(calls.lock().expect("l").len(), 1);
    }

    #[test]
    fn reads_the_progress_file() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("update.json");
        assert_eq!(status(&p)["phase"], "idle");
        std::fs::write(&p, "not json").expect("w");
        assert_eq!(status(&p)["phase"], "idle");
        std::fs::write(
            &p,
            json!({ "phase": "running", "at": super::super::time::now_iso(), "detail": "" }).to_string(),
        )
        .expect("w");
        assert!(running(&p));
        assert_eq!(status(&p)["detail"], Value::Null);
        std::fs::write(
            &p,
            json!({ "phase": "installing", "at": "2020-01-01T00:00:00Z" }).to_string(),
        )
        .expect("w");
        assert_eq!(status(&p)["phase"], "failed");
        assert!(!running(&p));
        std::fs::write(&p, json!({ "phase": "done", "reboot": true }).to_string()).expect("w");
        assert_eq!(
            status(&p),
            json!({ "phase": "done", "detail": null, "ref": null, "at": null, "reboot": true })
        );
    }
}
