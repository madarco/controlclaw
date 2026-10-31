//! Re-provisioning this firewall (`self-update.ts`): `cc-reprovision` run detached under
//! `systemd-run` (the run restarts this process), its progress read back from the state file it
//! writes. What it pulls is pinned in the root-owned `/etc/controlclaw/update.conf`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use serde_json::{Value, json};

use super::consent::iso;
use super::now_ms;

/// A run that stopped reporting for this long is not running any more.
const STALE_MS: u64 = 45 * 60_000;
/// Silence past this after a launch means the script never ran.
const LAUNCH_GRACE_MS: u64 = 2 * 60_000;
const RUNNING: &[&str] = &["resolving", "installing", "running"];

/// `UpdateStatus`, as the beat carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub phase: String,
    pub detail: Option<String>,
    pub r#ref: Option<String>,
    pub at: Option<String>,
    pub reboot: bool,
}

impl Status {
    fn idle() -> Self {
        Self {
            phase: "idle".into(),
            detail: None,
            r#ref: None,
            at: None,
            reboot: false,
        }
    }
    pub fn to_json(&self) -> Value {
        let mut v = json!({"phase": self.phase, "detail": self.detail, "ref": self.r#ref, "at": self.at});
        if self.reboot {
            v["reboot"] = json!(true);
        }
        v
    }
    pub fn running(&self) -> bool {
        RUNNING.contains(&self.phase.as_str())
    }
}

pub struct SelfUpdate {
    state_path: PathBuf,
    conf_path: PathBuf,
    runner: Arc<dyn Runner>,
    /// When this process last launched a run. In memory on purpose: the run restarts this process.
    launched_at: Mutex<Option<u64>>,
    /// Held from the "is one running" check to the launch: two callers at once launch one run.
    starting: Mutex<()>,
}

impl SelfUpdate {
    pub fn new(state_path: PathBuf, conf_path: PathBuf, runner: Arc<dyn Runner>) -> Self {
        Self {
            state_path,
            conf_path,
            runner,
            launched_at: Mutex::new(None),
            starting: Mutex::new(()),
        }
    }

    /// Whether this box was provisioned with an update pin (`ANSIBLE_REPO` in the conf).
    pub fn pinned(&self) -> bool {
        let Ok(raw) = std::fs::read_to_string(&self.conf_path) else {
            return false;
        };
        // `^([A-Z_]+)=(.*)$` per trimmed line, the last one winning.
        let mut repo = None;
        for line in raw.split('\n') {
            if let Some((k, v)) = line.trim().split_once('=')
                && !k.is_empty()
                && k.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                && k == "ANSIBLE_REPO"
            {
                repo = Some(v.to_string());
            }
        }
        repo.is_some_and(|r| !r.is_empty())
    }

    fn read_state(&self) -> Status {
        let Ok(raw) = std::fs::read_to_string(&self.state_path) else {
            return Status::idle();
        };
        let Ok(Value::Object(p)) = serde_json::from_str::<Value>(&raw) else {
            return Status::idle();
        };
        let s = |k: &str| {
            p.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Status {
            phase: p.get("phase").and_then(Value::as_str).unwrap_or("idle").to_string(),
            detail: s("detail"),
            r#ref: s("ref"),
            at: p.get("at").and_then(Value::as_str).map(str::to_string),
            reboot: p.get("reboot") == Some(&Value::Bool(true)),
        }
    }

    pub fn status(&self) -> Status {
        let status = self.read_state();
        let now = now_ms();
        let at_ms = |s: &Status| s.at.as_deref().and_then(super::ssh::parse_iso_ms);
        // What the file says from before our launch belongs to the previous run.
        if let Some(launched) = *self.launched_at.lock().unwrap_or_else(|e| e.into_inner()) {
            let for_this_run = at_ms(&status).is_some_and(|a| a >= launched as f64);
            if !for_this_run {
                if now.saturating_sub(launched) > LAUNCH_GRACE_MS {
                    return Status {
                        phase: "failed".into(),
                        detail: Some("The update never started. Check the firewall's logs.".into()),
                        r#ref: None,
                        at: Some(iso(launched)),
                        reboot: false,
                    };
                }
                return Status {
                    phase: "resolving".into(),
                    detail: Some("Starting…".into()),
                    r#ref: None,
                    at: Some(iso(launched)),
                    reboot: false,
                };
            }
        }
        // `now - Date.parse(at) > STALE_MS`: false for an unreadable time, as NaN compares.
        if status.running() && at_ms(&status).is_some_and(|a| now as f64 - a > STALE_MS as f64) {
            return Status {
                phase: "failed".into(),
                detail: Some("The update stopped reporting. Check the firewall's logs.".into()),
                ..status
            };
        }
        status
    }

    /// `start`: launch a run unless one is going; returns at once.
    pub fn start(&self, auto: bool, deadline: Option<f64>) -> Result<Status, String> {
        if !self.pinned() {
            return Err("This firewall was created before in-place updates; it has to be rebuilt instead.".into());
        }
        let _one = self.starting.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.status();
        if current.running() {
            return Ok(current);
        }
        let launched = now_ms();
        let mut args: Vec<String> = vec![
            "/usr/bin/systemd-run".into(),
            "--unit=cc-reprovision".into(),
            "--collect".into(),
        ];
        if auto {
            let ok = deadline.is_some_and(|d| {
                d.fract() == 0.0 && d.abs() <= 9_007_199_254_740_991.0 && d > (now_ms() / 1000) as f64
            });
            if !ok {
                return Err("The automatic update window has closed.".into());
            }
            args.push("--setenv=CC_UPDATE_MODE=auto".into());
            args.push(format!(
                "--setenv=CC_UPDATE_DEADLINE={}",
                deadline.unwrap_or_default() as i64
            ));
        }
        args.push("/usr/local/bin/cc-reprovision".into());
        // Detached: a failure to launch is logged, and the state file's silence reports it.
        let runner = self.runner.clone();
        tokio::spawn(async move {
            let cmd = Cmd::new("sudo").args(args).timeout(Duration::from_secs(60));
            match runner.run(cmd).await {
                Ok(o) if o.success() => {}
                Ok(o) => tracing::error!(
                    "[firewall-update] could not start cc-reprovision: {}",
                    o.stderr_str().trim()
                ),
                Err(e) => tracing::error!("[firewall-update] could not start cc-reprovision: {e}"),
            }
        });
        *self.launched_at.lock().unwrap_or_else(|e| e.into_inner()) = Some(launched);
        tracing::info!("[firewall-update] started cc-reprovision");
        Ok(Status {
            phase: "resolving".into(),
            detail: Some("Starting…".into()),
            r#ref: None,
            at: Some(iso(launched)),
            reboot: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pin_state_and_launch() {
        let dir = tempfile::tempdir().expect("dir");
        let (state, conf) = (dir.path().join("update.json"), dir.path().join("update.conf"));
        let runner = Arc::new(cc_proc::RecordingRunner::new());
        runner.answer(&["sudo"], cc_proc::ok(""));
        let s = SelfUpdate::new(state.clone(), conf.clone(), runner.clone());
        assert!(!s.pinned());
        assert_eq!(
            s.start(false, None).expect_err("no pin"),
            "This firewall was created before in-place updates; it has to be rebuilt instead."
        );
        std::fs::write(&conf, "ANSIBLE_REPO=https://x/y\nANSIBLE_REF=main\n").expect("conf");
        assert!(s.pinned());
        assert_eq!(s.status(), Status::idle());
        std::fs::write(
            &state,
            r#"{"phase":"done","detail":"","ref":"abc","at":"2020-01-01T00:00:00.000Z"}"#,
        )
        .expect("state");
        assert_eq!(s.status().phase, "done");
        assert_eq!(
            s.start(true, Some(1.0)).expect_err("closed"),
            "The automatic update window has closed."
        );
        let st = s.start(false, None).expect("start");
        assert_eq!(st.phase, "resolving");
        // The old `done` is the previous run's.
        assert_eq!(s.status().phase, "resolving");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let calls = runner.calls();
        assert_eq!(calls[0].program, "sudo");
        assert_eq!(
            calls[0].args,
            vec![
                "/usr/bin/systemd-run",
                "--unit=cc-reprovision",
                "--collect",
                "/usr/local/bin/cc-reprovision"
            ]
        );
    }
}
