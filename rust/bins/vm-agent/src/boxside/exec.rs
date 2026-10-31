//! `defaultExec` (exec.ts) over the `cc_proc` runner: a command that exits 0 gives its output, any
//! other end is an error that still carries what it printed, as `execFile` hands it over.

use std::time::Duration;

use cc_proc::{Cmd, Runner};

#[derive(Debug, Clone, Default)]
pub struct ExecOk {
    pub stdout: String,
    /// What `execFile` hands back with stdout; nothing here reads it yet.
    #[allow(dead_code)]
    pub stderr: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExecErr {
    /// `ENOENT`: the program is not there.
    pub not_found: bool,
    /// Killed by the timeout (`err.killed`); nothing here reads it yet.
    #[allow(dead_code)]
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    /// `err.message`'s first line (`Command failed: …`, `spawn … ENOENT`).
    pub message: String,
}

pub async fn exec(
    runner: &dyn Runner,
    program: &str,
    args: &[&str],
    timeout: Duration,
    stdin: Option<&str>,
) -> Result<ExecOk, ExecErr> {
    exec_for(runner, program, args, Some(timeout), stdin).await
}

/// `execFile` with no `timeout` option (`None`): it runs until it ends.
pub async fn exec_for(
    runner: &dyn Runner,
    program: &str,
    args: &[&str],
    timeout: Option<Duration>,
    stdin: Option<&str>,
) -> Result<ExecOk, ExecErr> {
    let mut cmd = Cmd::new(program).args(args.iter().copied()).env(
        "HOME",
        std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into()),
    );
    if let Some(t) = timeout {
        cmd = cmd.timeout(t);
    }
    if let Some(s) = stdin {
        cmd = cmd.stdin(s.as_bytes().to_vec());
    }
    let line = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(ExecOk {
            stdout: out.stdout_str(),
            stderr: out.stderr_str(),
        }),
        Ok(out) => Err(ExecErr {
            not_found: false,
            timed_out: out.timed_out,
            stdout: out.stdout_str(),
            stderr: out.stderr_str(),
            message: format!("Command failed: {line}"),
        }),
        Err(cc_proc::RunError::Spawn(e)) => Err(ExecErr {
            not_found: e.kind() == std::io::ErrorKind::NotFound,
            message: if e.kind() == std::io::ErrorKind::NotFound {
                format!("spawn {program} ENOENT")
            } else {
                format!("spawn {program} {e}")
            },
            ..ExecErr::default()
        }),
    }
}

/// `execFailureLine`: the last non-empty line of a failed command's output, ANSI stripped.
pub fn failure_line(e: &ExecErr) -> String {
    let text = if !e.stderr.is_empty() {
        &e.stderr
    } else if !e.stdout.is_empty() {
        &e.stdout
    } else {
        &e.message
    };
    let re = regex::Regex::new("\x1b\\[[0-9;]*m").expect("regex");
    let text = re.replace_all(text, "");
    text.trim()
        .split('\n')
        .rfind(|l| !l.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "command failed".into())
}

/// `runAction("restart")` (routes/openclaw.ts): `sudo systemctl restart <service>`, 30 s
/// (`SERVICE_ACTION_MS`); the error is stderr, else the command's message.
pub async fn restart_service(runner: &dyn Runner, service: &str) -> Result<(), String> {
    crate::platform::stop_mark::STOP_MARK.note("restart", None);
    match exec(
        runner,
        "sudo",
        &["systemctl", "restart", service],
        Duration::from_secs(30),
        None,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(e) if !e.stderr.trim().is_empty() => Err(e.stderr.trim().to_string()),
        Err(e) => Err(e.message),
    }
}
