//! The config queue's gateway for an OpenClaw we did not install, through its CLI only: writes are
//! `openclaw config patch --stdin` (the same merge patch the gateway's `config.patch` takes), every
//! other call is `openclaw gateway call <method>`, which signs in with OpenClaw's own settings. The
//! agent holds no gateway token and reads no file of OpenClaw's. The running gateway picks a written
//! file up by itself, and restarts itself for the settings that need it.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cc_openclaw::GatewayError;
use cc_openclaw::config_queue::{BoxFuture, ConfigGateway};
use cc_proc::{Cmd, Runner};
use serde_json::{Value, json};

use super::discover::json_out;

/// How often the gateway's health is probed for `connected`.
pub const PROBE_EVERY: Duration = Duration::from_secs(5);
/// A CLI start costs a few seconds on a small box (`config patch` measured at 7 s on a CX33).
const LEAST_CLI_TIME: Duration = Duration::from_secs(30);

pub struct CliGateway {
    runner: Arc<dyn Runner>,
    cli: String,
    home: PathBuf,
    /// The gateway's port, read at every probe: a later discovery may find another.
    port: Box<dyn Fn() -> u16 + Send + Sync>,
    up: AtomicBool,
}

impl CliGateway {
    pub fn new(
        runner: Arc<dyn Runner>,
        cli: String,
        home: PathBuf,
        port: impl Fn() -> u16 + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            runner,
            cli,
            home,
            port: Box::new(port),
            up: AtomicBool::new(false),
        })
    }

    /// Probe now, then every [`PROBE_EVERY`] while the gateway is held somewhere.
    pub fn start_probe(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut every = tokio::time::interval(PROBE_EVERY);
            loop {
                every.tick().await;
                let Some(gw) = weak.upgrade() else { return };
                gw.probe().await;
            }
        });
    }

    pub async fn probe(&self) -> bool {
        let up = crate::platform::watchdog::gateway_healthz((self.port)(), super::supervisor::HEALTHZ_TIMEOUT).await;
        self.up.store(up, Ordering::Relaxed);
        up
    }

    fn cmd(&self, args: &[&str], timeout: Duration) -> Cmd {
        Cmd::new(&self.cli)
            .args(args.iter().copied())
            .env("HOME", self.home.to_string_lossy().to_string())
            .timeout(timeout.max(LEAST_CLI_TIME))
    }

    async fn run(&self, cmd: Cmd) -> Result<String, GatewayError> {
        match self.runner.run(cmd).await {
            Ok(out) if out.success() => Ok(out.stdout_str()),
            Ok(out) => Err(GatewayError::Remote {
                code: None,
                message: Some(crate::platform::common::exec_failure_line(
                    &out.stderr_str(),
                    &out.stdout_str(),
                    if out.timed_out { "timed out" } else { "Command failed" },
                )),
            }),
            Err(e) => Err(GatewayError::Send(crate::platform::common::spawn_message(
                &self.cli, &e,
            ))),
        }
    }

    async fn patch(&self, params: &Value, timeout: Duration) -> Result<Value, GatewayError> {
        let raw = params
            .get("raw")
            .and_then(Value::as_str)
            .ok_or_else(|| GatewayError::Send("config.patch without a patch".into()))?;
        let cmd = self
            .cmd(&["config", "patch", "--stdin"], timeout)
            .stdin(raw.as_bytes().to_vec());
        self.run(cmd).await?;
        Ok(json!({ "ok": true }))
    }

    async fn rpc(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, GatewayError> {
        // As the websocket client: no call while the gateway is down, so the queue waits it out.
        if !self.up.load(Ordering::Relaxed) && !self.probe().await {
            return Err(GatewayError::NotConnected);
        }
        let ms = timeout.as_millis().to_string();
        let params = params.to_string();
        let cmd = self.cmd(
            &[
                "gateway",
                "call",
                method,
                "--params",
                &params,
                "--json",
                "--timeout",
                &ms,
            ],
            timeout + Duration::from_secs(15),
        );
        let out = self.run(cmd).await?;
        json_out(&out).ok_or_else(|| GatewayError::Remote {
            code: None,
            message: Some(format!("gateway call {method} printed no JSON")),
        })
    }
}

impl ConfigGateway for CliGateway {
    fn connected(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }

    fn call(&self, method: &str, params: Value, timeout: Duration) -> BoxFuture<'_, Result<Value, GatewayError>> {
        let method = method.to_string();
        Box::pin(async move {
            if method == "config.patch" {
                self.patch(&params, timeout).await
            } else {
                self.rpc(&method, params, timeout).await
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use cc_proc::{Output, RecordingRunner, ok};

    use super::*;

    fn gateway(r: &RecordingRunner, up: bool) -> Arc<CliGateway> {
        let gw = CliGateway::new(Arc::new(r.clone()), "/x/openclaw".into(), "/home/u".into(), || 1);
        gw.up.store(up, Ordering::Relaxed);
        gw
    }

    #[tokio::test]
    async fn a_patch_is_written_by_the_cli_from_stdin() {
        let r = RecordingRunner::new();
        r.answer(
            &["/x/openclaw", "config", "patch", "--stdin"],
            ok("Applied 1 config update(s).\n"),
        );
        let gw = gateway(&r, false);
        let raw = r#"{"agents":{"defaults":{"model":{"primary":"openai/gpt-5.4"}}}}"#;
        let v = gw
            .call(
                "config.patch",
                json!({"raw": raw, "baseHash": "h"}),
                Duration::from_secs(20),
            )
            .await
            .expect("patched");
        assert_eq!(v, json!({"ok": true}));
        let c = &r.calls()[0];
        assert_eq!(c.stdin.as_deref(), Some(raw.as_bytes()));
        assert_eq!(c.env.get("HOME").map(String::as_str), Some("/home/u"));
    }

    #[tokio::test]
    async fn a_refused_patch_says_why() {
        let r = RecordingRunner::new();
        r.answer(
            &["/x/openclaw", "config", "patch"],
            Output {
                code: Some(1),
                stderr: b"Config invalid: channels.telegram.botToken: expected string\nNo settings were saved.\n"
                    .to_vec(),
                ..Default::default()
            },
        );
        let e = gateway(&r, true)
            .call("config.patch", json!({"raw": "{}"}), Duration::from_secs(20))
            .await
            .expect_err("refused");
        assert_eq!(e.to_string(), "No settings were saved.");
    }

    #[tokio::test]
    async fn other_calls_go_through_gateway_call() {
        let r = RecordingRunner::new();
        r.answer(
            &["/x/openclaw", "gateway", "call", "config.get"],
            ok(r#"{"hash":"h1","parsed":{}}"#),
        );
        let v = gateway(&r, true)
            .call("config.get", json!({}), Duration::from_secs(10))
            .await
            .expect("read");
        assert_eq!(v["hash"], "h1");
        let c = &r.calls()[0];
        assert_eq!(
            c.args,
            [
                "gateway",
                "call",
                "config.get",
                "--params",
                "{}",
                "--json",
                "--timeout",
                "10000"
            ]
        );
    }

    #[tokio::test]
    async fn a_call_while_the_gateway_is_down_is_not_connected() {
        let r = RecordingRunner::new();
        // Port 1: nothing answers the probe.
        let e = gateway(&r, false)
            .call("config.get", json!({}), Duration::from_secs(10))
            .await
            .expect_err("down");
        assert_eq!(e, GatewayError::NotConnected);
        assert!(r.calls().is_empty());
    }
}
