//! Running a Doctor turn (`doctor-runner.ts`): `sudo -n /usr/local/bin/cc-doctor-run <session> <cli>
//! <mode>` with the whole input on stdin. No shell interpolation; the private key and the provider's
//! credentials travel only over stdin. The CLI's stderr can hold credentials, so it is never read.

use std::collections::BTreeMap;
use std::process::Stdio;

use cc_http::BoxFuture;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sockets {
    pub tools: String,
    pub model: String,
}

/// What `cc-doctor-run` reads on stdin, in the TS's field order.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunInput {
    pub session_id: String,
    pub cli: String,
    pub mode: String,
    pub ssh_private_key: String,
    pub env: BTreeMap<String, String>,
    pub model: String,
    pub provider: String,
    pub problem: String,
    /// The proposal's whole target, as the TS passes it (`vmId`, `name`, `hostname`, `privateIp`,
    /// `sshHostKey`, `keyReady`, `kind`).
    pub agent: serde_json::Value,
    /// `firewall` or `check`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sockets: Option<Sockets>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_id: Option<String>,
    pub seconds: i64,
}

pub type Output = Box<dyn FnMut(&str) + Send>;

/// Runs the spawn it is handed only while the turn is still the session's, under the session's
/// lock, so a stop that moves the session on lands wholly before the unit starts or wholly after.
pub type Admit = Box<dyn FnOnce(&mut dyn FnMut() -> bool) -> bool + Send>;

pub trait DoctorRunner: Send + Sync {
    /// One turn: the CLI's stdout handed to `output` as it comes. An error is a fixed sentence.
    fn run(&self, input: RunInput, output: Output, admit: Admit) -> BoxFuture<Result<(), String>>;
    fn stop(&self, id: &str, pause: bool) -> BoxFuture<Result<(), String>>;
}

pub struct LocalRunner;

impl LocalRunner {
    /// A daemon restart revokes in-memory consent and its old session units together.
    pub async fn reset(&self) -> Result<(), String> {
        self.stop("--all", false).await
    }
}

impl DoctorRunner for LocalRunner {
    fn run(&self, input: RunInput, mut output: Output, admit: Admit) -> BoxFuture<Result<(), String>> {
        Box::pin(async move {
            let failed = || "The doctor turn failed. Check the firewall software and selected model.".to_string();
            let text = serde_json::to_string(&input).map_err(|_| failed())?;
            let mut command = tokio::process::Command::new("sudo");
            command
                .args([
                    "-n",
                    "/usr/local/bin/cc-doctor-run",
                    &input.session_id,
                    &input.cli,
                    &input.mode,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let mut spawned = None;
            // Not admitted: the session moved on, and the turn's result is not read.
            admit(&mut || {
                spawned = command.spawn().ok();
                spawned.is_some()
            });
            let Some(mut child) = spawned else {
                return Err("The doctor runner could not start.".to_string());
            };
            // Written beside the read below: a unit that prints before it has read all of a large
            // input must not stall both sides.
            let writer = child.stdin.take().map(|mut stdin| {
                tokio::spawn(async move {
                    let _ = stdin.write_all(text.as_bytes()).await;
                })
            });
            if let Some(mut out) = child.stdout.take() {
                let mut buf = vec![0u8; 64 * 1024];
                let mut carry: Vec<u8> = Vec::new();
                loop {
                    match out.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // Whole characters only: a chunk may split one, as `setEncoding("utf8")` keeps it.
                            carry.extend_from_slice(&buf[..n]);
                            let cut = match std::str::from_utf8(&carry) {
                                Ok(_) => carry.len(),
                                Err(e) => e.valid_up_to(),
                            };
                            if cut > 0 {
                                output(&String::from_utf8_lossy(&carry[..cut]));
                                carry.drain(..cut);
                            }
                        }
                    }
                }
                if !carry.is_empty() {
                    output(&String::from_utf8_lossy(&carry));
                }
            }
            if let Some(w) = writer {
                w.abort();
            }
            match child.wait().await {
                Ok(s) if s.success() => Ok(()),
                _ => Err(failed()),
            }
        })
    }

    fn stop(&self, id: &str, pause: bool) -> BoxFuture<Result<(), String>> {
        let id = id.to_string();
        Box::pin(async move {
            let mut args = vec!["-n".to_string(), "/usr/local/bin/cc-doctor-stop".into(), id];
            if pause {
                args.push("pause".into());
            }
            let s = tokio::process::Command::new("sudo")
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map_err(|_| "The doctor runner could not stop.".to_string())?;
            if s.success() {
                Ok(())
            } else {
                Err("The doctor runner could not stop.".into())
            }
        })
    }
}

/// Node's `child.kill("SIGTERM")`, then SIGKILL once `grace` has passed: sudo passes a SIGTERM on to
/// the helper it runs, while a SIGKILL of sudo would leave the helper running.
pub async fn terminate(child: &mut tokio::process::Child, grace: std::time::Duration) {
    if let Some(pid) = child.id() {
        let _ = tokio::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
}
