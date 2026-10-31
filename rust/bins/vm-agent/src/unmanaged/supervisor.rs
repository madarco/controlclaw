//! Start, stop and restart an OpenClaw gateway the way it runs, and say whether it does. The agent
//! runs as OpenClaw's own user: no sudo. A systemd user unit is restarted through `openclaw gateway`
//! (which drains its work first) and started and stopped by systemd; a container through Docker; pm2
//! through pm2.

use std::time::Duration;

use cc_proc::{Cmd, Runner};

use super::discover::{Install, Runs};

/// A restart drains the gateway's work first; systemd allows 330 s, OpenClaw uses less.
const ACTION_TIMEOUT: Duration = Duration::from_secs(120);
const QUICK: Duration = Duration::from_secs(5);
pub const HEALTHZ_TIMEOUT: Duration = Duration::from_secs(2);

/// `systemctl --user` from a service needs the user's runtime dir, which a system unit with
/// `User=` does not set.
fn user_bus(cmd: Cmd) -> Cmd {
    if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        return cmd;
    }
    let uid = rustix::process::getuid().as_raw();
    cmd.env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"))
}

/// The command for `action` (`start`, `stop` or `restart`), or why there is none.
pub fn action_cmd(install: &Install, action: &str) -> Result<Cmd, String> {
    let cli = || {
        install
            .cli
            .clone()
            .ok_or_else(|| "OpenClaw is not installed here".to_string())
    };
    let cmd = match &install.runs {
        Runs::Docker { container } => Cmd::new("docker").args([action, "--", container.as_str()]),
        // pm2 takes no `--` (it then names no process): a name that reads as an option is refused.
        Runs::Pm2 { name } if name.starts_with('-') => return Err(format!("{name:?} is not a pm2 process name")),
        Runs::Pm2 { name } => Cmd::new("pm2").args([action, name.as_str()]),
        Runs::Process { .. } if action == "start" => {
            return Err("OpenClaw was started by hand here; start it again the same way".into());
        }
        // A system unit needs root: through sudo, which the owner sets up for this one unit (the
        // refusal is shown when they did not).
        Runs::SystemdSystem { unit } => Cmd::sudo("systemctl").args([action, "--", unit.as_str()]),
        // `openclaw gateway stop` refuses when nobody is at a terminal (OpenClaw 2026.10: "This stops
        // the operator's running gateway service", unless `--force`), and `gateway start` waits for
        // the gateway longer than the firewall's call: systemd stops and starts its unit.
        Runs::SystemdUser { unit } if action != "restart" => {
            user_bus(Cmd::new("systemctl").args(["--user", action, "--", unit.as_str()]))
        }
        Runs::SystemdUser { .. } | Runs::Process { .. } | Runs::NotRunning => {
            user_bus(Cmd::new(cli()?).args(["gateway", action]))
        }
        Runs::NotFound => return Err("OpenClaw is not installed here".into()),
    };
    Ok(cmd.timeout(ACTION_TIMEOUT))
}

/// Run `action`; the error is the command's last line of output.
pub async fn act(runner: &dyn Runner, install: &Install, action: &str) -> Result<(), String> {
    act_timed(runner, install, action).await.map_err(|f| f.message)
}

/// Why an action failed, and whether it was only slower than [`ACTION_TIMEOUT`]: a restart that
/// drains OpenClaw's work (up to 330 s with a Telegram bot on) goes on after the command is gone.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub message: String,
    pub timed_out: bool,
}

/// [`act`], saying whether the command timed out.
pub async fn act_timed(runner: &dyn Runner, install: &Install, action: &str) -> Result<(), Failure> {
    let failed = |message: String, timed_out| Failure { message, timed_out };
    let cmd = action_cmd(install, action).map_err(|m| failed(m, false))?;
    let program = cmd.program.clone();
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(()),
        Ok(out) => Err(failed(
            crate::platform::common::exec_failure_line(
                &out.stderr_str(),
                &out.stdout_str(),
                if out.timed_out { "timed out" } else { "Command failed" },
            ),
            out.timed_out,
        )),
        Err(e) => Err(failed(crate::platform::common::spawn_message(&program, &e), false)),
    }
}

/// What the service manager says: `Some(true)` up, `Some(false)` down, None when it is not the
/// one to ask (the gateway's own health then decides).
pub async fn manager_up(runner: &dyn Runner, install: &Install) -> Option<bool> {
    let cmd = match &install.runs {
        Runs::SystemdUser { unit } => {
            user_bus(Cmd::new("systemctl").args(["--user", "is-active", "--", unit.as_str()]))
        }
        Runs::SystemdSystem { unit } => Cmd::new("systemctl").args(["is-active", "--", unit.as_str()]),
        Runs::Docker { container } => {
            Cmd::new("docker").args(["inspect", "-f", "{{.State.Status}}", "--", container.as_str()])
        }
        Runs::NotRunning | Runs::NotFound => return Some(false),
        Runs::Pm2 { .. } | Runs::Process { .. } => return None,
    };
    let out = runner.run(cmd.timeout(QUICK)).await.ok()?;
    let word = out.stdout_str().trim().to_string();
    match word.as_str() {
        "active" | "running" | "reloading" | "activating" => Some(true),
        "" => None,
        _ => Some(false),
    }
}

/// The state in the managed agent's words: `running`, `starting`, `stopped`.
pub fn state(manager: Option<bool>, answers: bool) -> &'static str {
    match (manager, answers) {
        (_, true) => "running",
        (Some(true), false) => "starting",
        (Some(false), false) | (None, false) => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use cc_proc::{RecordingRunner, exit, ok};

    use super::*;

    fn install(runs: Runs) -> Install {
        Install {
            cli: Some("/x/openclaw".into()),
            version: None,
            config_file: None,
            state_dir: None,
            container_state_dir: None,
            runs,
            gateway_port: 18789,
        }
    }

    fn line(c: &Cmd) -> Vec<String> {
        std::iter::once(c.program.clone()).chain(c.args.clone()).collect()
    }

    #[test]
    fn commands_per_kind() {
        let user = install(Runs::SystemdUser { unit: "u".into() });
        assert_eq!(
            line(&action_cmd(&user, "restart").expect("cmd")),
            ["/x/openclaw", "gateway", "restart"]
        );
        assert_eq!(
            line(&action_cmd(&user, "stop").expect("cmd")),
            ["systemctl", "--user", "stop", "--", "u"]
        );
        let docker = install(Runs::Docker { container: "c".into() });
        assert_eq!(
            line(&action_cmd(&docker, "stop").expect("cmd")),
            ["docker", "stop", "--", "c"]
        );
        let system = install(Runs::SystemdSystem {
            unit: "oc.service".into(),
        });
        assert_eq!(
            line(&action_cmd(&system, "restart").expect("cmd")),
            ["sudo", "-n", "systemctl", "restart", "--", "oc.service"]
        );
        let pm2 = install(Runs::Pm2 { name: "p".into() });
        assert_eq!(line(&action_cmd(&pm2, "start").expect("cmd")), ["pm2", "start", "p"]);
        assert!(action_cmd(&install(Runs::Pm2 { name: "-s".into() }), "start").is_err());
        let by_hand = install(Runs::Process { pid: Some(1) });
        assert!(action_cmd(&by_hand, "start").is_err());
        assert_eq!(
            line(&action_cmd(&by_hand, "restart").expect("cmd")),
            ["/x/openclaw", "gateway", "restart"]
        );
        assert!(action_cmd(&install(Runs::NotFound), "restart").is_err());
    }

    #[tokio::test]
    async fn the_manager_is_asked_where_there_is_one() {
        let r = RecordingRunner::new();
        r.answer(&["systemctl", "--user", "is-active"], ok("active\n"));
        r.answer(&["docker", "inspect"], ok("exited\n"));
        assert_eq!(
            manager_up(&r, &install(Runs::SystemdUser { unit: "u".into() })).await,
            Some(true)
        );
        assert_eq!(
            manager_up(&r, &install(Runs::Docker { container: "c".into() })).await,
            Some(false)
        );
        assert_eq!(manager_up(&r, &install(Runs::Pm2 { name: "p".into() })).await, None);
        r.answer(&["systemctl", "is-active"], exit(3, "inactive\n"));
        assert_eq!(
            manager_up(&r, &install(Runs::SystemdSystem { unit: "s".into() })).await,
            Some(false)
        );
    }

    #[tokio::test]
    async fn a_failed_restart_says_why() {
        let r = RecordingRunner::new();
        r.answer(
            &["docker", "restart"],
            cc_proc::Output {
                code: Some(1),
                stderr: b"Error response from daemon: No such container: c\n".to_vec(),
                ..Default::default()
            },
        );
        let e = act(&r, &install(Runs::Docker { container: "c".into() }), "restart")
            .await
            .expect_err("fails");
        assert_eq!(e, "Error response from daemon: No such container: c");
    }

    #[test]
    fn states() {
        assert_eq!(state(Some(true), true), "running");
        assert_eq!(state(None, true), "running");
        assert_eq!(state(Some(true), false), "starting");
        assert_eq!(state(Some(false), false), "stopped");
    }
}
