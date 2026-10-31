//! Running other programs: the sudo helpers, `systemctl`, `journalctl`, the OpenClaw CLI and the
//! rest (appendix B §3, D §3). Every call goes through a [`Runner`], so tests and the conformance
//! rig can record what would have run and answer for it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;

/// One command: a program and its arguments, never a shell string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    /// Added to the inherited environment.
    pub env: BTreeMap<String, String>,
    /// When set, the child gets only these variables (`env_clear`), as `execFile` with `env` does.
    pub clear_env: bool,
    pub timeout: Option<Duration>,
    /// The most bytes read from stdout, and from stderr: past it the child is killed and the run
    /// fails (code `None`). None: all of it, as before.
    pub max_output: Option<usize>,
}

impl Cmd {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            ..Default::default()
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// [`Cmd::max_output`].
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output = Some(bytes);
        self
    }

    /// `sudo -n <program> <args>`, the way the agents call their root helpers.
    pub fn sudo(program: impl Into<String>) -> Self {
        Self::new("sudo").arg("-n").arg(program)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    /// `None` when the process was killed (timeout or signal).
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug)]
pub enum RunError {
    /// The program could not be started (`ENOENT` and the like).
    Spawn(std::io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(e) => write!(f, "could not start: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    async fn run(&self, cmd: Cmd) -> Result<Output, RunError>;
}

/// Runs for real, with `tokio::process`. A timeout kills the child, as Node's `timeout` option does.
#[derive(Debug, Default, Clone)]
pub struct SystemRunner;

#[async_trait::async_trait]
impl Runner for SystemRunner {
    async fn run(&self, cmd: Cmd) -> Result<Output, RunError> {
        let mut c = tokio::process::Command::new(&cmd.program);
        c.args(&cmd.args)
            .stdin(if cmd.stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if cmd.clear_env {
            c.env_clear();
        }
        c.envs(&cmd.env);
        let mut child = c.spawn().map_err(RunError::Spawn)?;
        // Stdin is written while the output is read, and both count against the timeout: a child
        // that writes before it has read all its input would otherwise block both sides for good.
        let feed = child.stdin.take().zip(cmd.stdin).map(|(mut sin, data)| {
            tokio::spawn(async move {
                // A child that exits without reading its stdin is not an error here.
                let _ = sin.write_all(&data).await;
            })
        });
        let cap = cmd.max_output;
        let wait = async {
            let out = match cap {
                None => child.wait_with_output().await,
                Some(cap) => capped_output(child, cap).await,
            };
            if let Some(f) = feed {
                f.abort();
            }
            out
        };
        let out = match cmd.timeout {
            Some(t) => match tokio::time::timeout(t, wait).await {
                Ok(r) => r,
                Err(_) => {
                    return Ok(Output {
                        code: None,
                        timed_out: true,
                        ..Default::default()
                    });
                }
            },
            None => wait.await,
        }
        .map_err(RunError::Spawn)?;
        Ok(Output {
            code: out.status.code(),
            stdout: out.stdout,
            stderr: out.stderr,
            timed_out: false,
        })
    }
}

/// `wait_with_output` reading at most `cap` bytes of stdout and of stderr: a child that writes more
/// is killed, and the run fails with what was read and a note on stderr.
async fn capped_output(mut child: tokio::process::Child, cap: usize) -> std::io::Result<std::process::Output> {
    use tokio::io::AsyncReadExt;
    async fn read(r: Option<impl tokio::io::AsyncRead + Unpin>, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
        let mut buf = Vec::new();
        if let Some(r) = r {
            r.take(cap as u64 + 1).read_to_end(&mut buf).await?;
        }
        let over = buf.len() > cap;
        buf.truncate(cap);
        Ok((buf, over))
    }
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let (out_f, err_f) = (read(out, cap), read(err, cap));
    tokio::pin!(out_f, err_f);
    let (mut o, mut e) = (None, None);
    // The first stream past the cap kills the child at once: the other then ends too.
    while o.is_none() || e.is_none() {
        tokio::select! {
            r = &mut out_f, if o.is_none() => {
                let r = r?;
                if r.1 { let _ = child.start_kill(); }
                o = Some(r);
            }
            r = &mut err_f, if e.is_none() => {
                let r = r?;
                if r.1 { let _ = child.start_kill(); }
                e = Some(r);
            }
        }
    }
    let ((stdout, over_out), (mut stderr, over_err)) = (o.unwrap_or_default(), e.unwrap_or_default());
    if over_out || over_err {
        let status = child.wait().await?;
        stderr.extend_from_slice(format!("\n[output over {cap} bytes: stopped]").as_bytes());
        // Killed for its output: a failure whatever it would have exited with.
        let status = if status.success() { killed() } else { status };
        return Ok(std::process::Output { status, stdout, stderr });
    }
    let status = child.wait().await?;
    Ok(std::process::Output { status, stdout, stderr })
}

/// An exit status that is not success (killed by a signal).
fn killed() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(9)
}

type Answer = Box<dyn Fn(&Cmd) -> Option<Output> + Send + Sync>;

/// Records every command and answers from a list of rules, first match wins. A command no rule
/// answers fails to start, so a test never runs something real by accident.
#[derive(Clone, Default)]
pub struct RecordingRunner {
    calls: Arc<Mutex<Vec<Cmd>>>,
    rules: Arc<Mutex<Vec<Answer>>>,
}

impl RecordingRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer every command whose program and leading args match `prefix`.
    pub fn answer(&self, prefix: &[&str], out: Output) {
        let prefix: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
        self.answer_with(move |c| {
            let line: Vec<&String> = std::iter::once(&c.program).chain(c.args.iter()).collect();
            (line.len() >= prefix.len() && line.iter().zip(&prefix).all(|(a, b)| *a == b)).then(|| out.clone())
        });
    }

    pub fn answer_with(&self, f: impl Fn(&Cmd) -> Option<Output> + Send + Sync + 'static) {
        if let Ok(mut r) = self.rules.lock() {
            r.push(Box::new(f));
        }
    }

    pub fn calls(&self) -> Vec<Cmd> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl Runner for RecordingRunner {
    async fn run(&self, cmd: Cmd) -> Result<Output, RunError> {
        if let Ok(mut c) = self.calls.lock() {
            c.push(cmd.clone());
        }
        let answer = self
            .rules
            .lock()
            .ok()
            .and_then(|rules| rules.iter().find_map(|r| r(&cmd)));
        answer.ok_or_else(|| RunError::Spawn(std::io::Error::new(std::io::ErrorKind::NotFound, cmd.program.clone())))
    }
}

/// `ok("text")`: exit 0 with that stdout.
pub fn ok(stdout: &str) -> Output {
    Output {
        code: Some(0),
        stdout: stdout.as_bytes().to_vec(),
        ..Default::default()
    }
}

/// Exit with `code` and that stdout, as `systemctl is-active` does for a stopped unit.
pub fn exit(code: i32, stdout: &str) -> Output {
    Output {
        code: Some(code),
        stdout: stdout.as_bytes().to_vec(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    /// A child that writes past the cap is killed and the run fails, with at most the cap kept.
    #[tokio::test]
    async fn output_past_the_cap_kills_the_child() {
        use super::*;
        let r = SystemRunner;
        let out = r
            .run(
                Cmd::new("sh")
                    .args(["-c", "head -c 5000000 /dev/zero"])
                    .max_output(1000),
            )
            .await
            .expect("ran");
        assert!(!out.success());
        assert_eq!(out.stdout.len(), 1000);
        assert!(out.stderr_str().contains("over 1000 bytes"));
        // Past the cap on stdout while stderr stays open (and SIGPIPE ignored): still ended at once.
        let held = r
            .run(
                Cmd::new("sh")
                    .args(["-c", "trap '' PIPE; head -c 5000000 /dev/zero; sleep 30"])
                    .max_output(1000)
                    .timeout(Duration::from_secs(10)),
            )
            .await
            .expect("ran");
        assert!(!held.timed_out, "killed for its output, not timed out");
        let ok = r
            .run(Cmd::new("sh").args(["-c", "printf abc"]).max_output(1000))
            .await
            .expect("ran");
        assert!(ok.success());
        assert_eq!(ok.stdout_str(), "abc");
        let err = r
            .run(
                Cmd::new("sh")
                    .args(["-c", "head -c 5000000 /dev/zero >&2"])
                    .max_output(1000),
            )
            .await
            .expect("ran");
        assert!(!err.success(), "stderr is capped too");
    }

    use super::*;

    #[tokio::test]
    async fn system_runner_runs_and_times_out() {
        let out = SystemRunner
            .run(Cmd::new("sh").args(["-c", "cat; echo err >&2"]).stdin("hi"))
            .await
            .expect("run");
        assert!(out.success());
        assert_eq!(out.stdout_str(), "hi");
        assert_eq!(out.stderr_str(), "err\n");
        let slow = SystemRunner
            .run(Cmd::new("sleep").arg("5").timeout(Duration::from_millis(100)))
            .await
            .expect("run");
        assert!(slow.timed_out && slow.code.is_none());
        assert!(SystemRunner.run(Cmd::new("/nonexistent/x")).await.is_err());
        // A child that answers before reading a large stdin, and never reads the rest: no deadlock.
        let big = vec![b'x'; 1 << 20];
        let quick = SystemRunner
            .run(
                Cmd::new("sh")
                    .args(["-c", "head -c 10 >/dev/null; yes | head -c 200000"])
                    .stdin(big)
                    .timeout(Duration::from_secs(10)),
            )
            .await
            .expect("run");
        assert!(!quick.timed_out && quick.stdout.len() == 200_000);
    }

    #[tokio::test]
    async fn recording_runner_answers_and_records() {
        let r = RecordingRunner::new();
        r.answer(&["systemctl", "is-active"], exit(3, "inactive\n"));
        let out = r
            .run(Cmd::new("systemctl").args(["is-active", "openclaw"]))
            .await
            .expect("answered");
        assert_eq!(out.code, Some(3));
        assert!(r.run(Cmd::new("rm")).await.is_err());
        assert_eq!(r.calls().len(), 2);
    }
}
