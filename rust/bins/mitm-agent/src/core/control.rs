//! The firewall's control channel (`packages/mitm-agent/src/firewall-control.ts`). The console
//! cannot reach this box, so every few seconds it posts a heartbeat to
//! `POST /api/vm-agent/firewall` and gets back at most one command. `start|stop|restart` run
//! `sudo systemctl <action> controlclaw-mitmproxy`; any other action goes to the handler a
//! workstream registered for it ([`Commands::handle`]). Results ride the next beat, which is sent
//! as soon as a command finishes. At most once, nothing persisted: a crash mid-command leaves it to
//! go stale in the console.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cc_http::BoxFuture;
use cc_proc::{Cmd, Runner};
use serde_json::{Map, Value};
use tokio::sync::Notify;

use crate::commands::{CommandOutcome, CommandResult, Commands};

/// Matches `firewallHeartbeatSchema`'s cap on the console: a beat with more is refused whole.
const MAX_RESULTS_PER_BEAT: usize = 20;
const IS_ACTIVE_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_ACTIONS: &[&str] = &["start", "stop", "restart"];

static FIRST_BEAT: Mutex<Option<BoxFuture<()>>> = Mutex::new(None);

/// Something the first beat waits for (the CA publish, bounded by its caller).
pub fn before_first_beat(f: BoxFuture<()>) {
    if let Ok(mut slot) = FIRST_BEAT.lock() {
        *slot = Some(f);
    }
}

pub struct ControlOptions {
    pub firewall_url: String,
    pub agent_version: String,
    /// `controlclaw-mitmproxy`.
    pub service: String,
    pub action_timeout: Duration,
}

struct Inner {
    pending: Vec<CommandResult>,
    in_flight: bool,
    backoff: Duration,
    next_attempt: Option<Instant>,
    down: bool,
}

pub struct FirewallControl {
    opts: ControlOptions,
    commands: Commands,
    runner: Arc<dyn Runner>,
    console: cc_client::ConsoleClient,
    started: Instant,
    inner: Mutex<Inner>,
    /// Woken when a command finishes, so its result goes out at once.
    soon: Notify,
}

impl FirewallControl {
    pub fn new(
        opts: ControlOptions,
        commands: Commands,
        runner: Arc<dyn Runner>,
        console: cc_client::ConsoleClient,
    ) -> Arc<Self> {
        Arc::new(Self {
            opts,
            commands,
            runner,
            console,
            started: Instant::now(),
            inner: Mutex::new(Inner {
                pending: Vec::new(),
                in_flight: false,
                backoff: Duration::ZERO,
                next_attempt: None,
                down: false,
            }),
            soon: Notify::new(),
        })
    }

    /// Beat every `every`, and at once after each command (`beatSoon`).
    pub async fn run(self: Arc<Self>, every: Duration) {
        let first = FIRST_BEAT.lock().ok().and_then(|mut f| f.take());
        if let Some(wait) = first {
            wait.await;
        }
        loop {
            self.clone().tick().await;
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = self.soon.notified() => {}
            }
        }
    }

    /// `systemctl is-active` exits non-zero when the unit is not active; the word is still on stdout.
    pub async fn proxy_status(&self) -> &'static str {
        let cmd = Cmd::new("systemctl")
            .args(["is-active", &self.opts.service])
            .timeout(IS_ACTIVE_TIMEOUT);
        let out = self.runner.run(cmd).await.map(|o| o.stdout_str()).unwrap_or_default();
        match out.trim() {
            "active" | "activating" | "reloading" => "active",
            "failed" => "failed",
            _ => "inactive",
        }
    }

    /// One heartbeat; a returned command runs in the background and reports on a beat of its own.
    pub async fn tick(self: Arc<Self>) {
        {
            let Ok(mut i) = self.inner.lock() else { return };
            if i.in_flight || i.next_attempt.is_some_and(|t| Instant::now() < t) {
                return;
            }
            i.in_flight = true;
        }
        let command = self.beat().await;
        if let Ok(mut i) = self.inner.lock() {
            i.in_flight = false;
        }
        if let Some((id, action, payload)) = command {
            let me = self.clone();
            tokio::spawn(async move {
                let result = me.execute(&id, &action, payload).await;
                if let Ok(mut i) = me.inner.lock() {
                    i.pending.push(result);
                }
                me.soon.notify_one();
            });
        }
    }

    async fn execute(&self, id: &str, action: &str, payload: Map<String, Value>) -> CommandResult {
        if SERVICE_ACTIONS.contains(&action) {
            return self.run_service(id, action).await;
        }
        let Some(handler) = self.commands.handler(action) else {
            tracing::info!("[firewall] unknown command {action} ({id})");
            return CommandResult::from_outcome(
                id,
                CommandOutcome::failed("failed", format!("unknown command {action}")),
            );
        };
        tracing::info!("[firewall] {action} (command {id})");
        CommandResult::from_outcome(id, crate::commands::run(handler, action, payload).await)
    }

    async fn run_service(&self, id: &str, action: &str) -> CommandResult {
        tracing::info!("[firewall] {action} {} (command {id})", self.opts.service);
        let cmd = Cmd::new("sudo")
            .args(["systemctl", action, &self.opts.service])
            .timeout(self.opts.action_timeout);
        match self.runner.run(cmd).await {
            Ok(out) if out.success() => {
                let status = self.proxy_status().await;
                let ok = if action == "stop" {
                    status != "active"
                } else {
                    status == "active"
                };
                let message = if ok {
                    String::new()
                } else {
                    format!("service is {status} after {action}")
                };
                CommandResult {
                    command_id: id.into(),
                    ok,
                    status: status.into(),
                    message,
                    data: None,
                }
            }
            other => {
                let message = match other {
                    Ok(out) if !out.stderr.is_empty() => out.stderr_str(),
                    Ok(out) if out.timed_out => "spawnSync /bin/sh ETIMEDOUT".to_string(),
                    Ok(out) => format!(
                        "Command failed: sudo systemctl {action} {} (exit {:?})",
                        self.opts.service, out.code
                    ),
                    Err(e) => e.to_string(),
                };
                let message: String = message.trim().chars().take(500).collect();
                tracing::info!("[firewall] {action} failed: {message}");
                let status = self.proxy_status().await;
                CommandResult {
                    command_id: id.into(),
                    ok: false,
                    status: status.into(),
                    message,
                    data: None,
                }
            }
        }
    }

    async fn beat(&self) -> Option<(String, String, Map<String, Value>)> {
        let results: Vec<CommandResult> = {
            let mut i = self.inner.lock().ok()?;
            i.pending.extend(self.commands.drain_reports());
            // A snapshot, capped: a result that lands while this beat is in flight goes on the next.
            i.pending.iter().take(MAX_RESULTS_PER_BEAT).cloned().collect()
        };
        let mut body = Map::new();
        body.insert("proxy".into(), Value::from(self.proxy_status().await));
        body.insert("agent_version".into(), Value::from(self.opts.agent_version.clone()));
        body.insert(
            "uptime_s".into(),
            Value::from(self.started.elapsed().as_secs_f64().round() as u64),
        );
        body.extend(self.commands.beat_fields());
        if !results.is_empty() {
            body.insert("results".into(), serde_json::to_value(&results).unwrap_or_default());
        }
        let answer = self
            .console
            .post_json(&self.opts.firewall_url, &Value::Object(body), Duration::from_secs(30))
            .await;
        let answer = match answer {
            Ok(a) if (200..300).contains(&a.status) => a,
            Ok(a) => {
                self.fail(&format!("HTTP {}", a.status));
                return None;
            }
            Err(e) => {
                // A request error's text names the URL; only the kind of failure is logged.
                let why = match e {
                    cc_client::ClientError::Http(h) => h.without_url().to_string(),
                    other => other.to_string(),
                };
                self.fail(&format!("unreachable ({why})"));
                return None;
            }
        };
        if let Ok(mut i) = self.inner.lock() {
            i.pending.retain(|r| !results.contains(r));
            if i.down {
                tracing::info!("[firewall] control channel back");
                i.down = false;
            }
            i.backoff = Duration::ZERO;
            i.next_attempt = None;
        }
        let c = answer.body.get("command")?.as_object()?;
        let id = c.get("id")?.as_str()?.to_string();
        let action = c.get("action")?.as_str()?.to_string();
        let payload = c.get("payload").and_then(Value::as_object).cloned().unwrap_or_default();
        Some((id, action, payload))
    }

    fn fail(&self, reason: &str) {
        let Ok(mut i) = self.inner.lock() else { return };
        i.backoff = if i.backoff.is_zero() {
            Duration::from_secs(5)
        } else {
            (i.backoff * 2).min(Duration::from_secs(60))
        };
        i.next_attempt = Some(Instant::now() + i.backoff);
        if !i.down {
            tracing::info!("[firewall] control channel down: {reason}; retrying");
            i.down = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_auth::keys::KeysDir;
    use cc_client::{ConsoleClient, HttpClient};
    use cc_proc::{RecordingRunner, ok};
    use cc_testkit::{BoxKeys, FakeConsole};
    use serde_json::json;

    async fn control(console: &FakeConsole, commands: Commands) -> (tempfile::TempDir, Arc<FirewallControl>) {
        let d = tempfile::tempdir().expect("dir");
        BoxKeys::write(&d.path().join("keys"), "fw_1", "fw.example").expect("keys");
        let runner = RecordingRunner::new();
        runner.answer(&["systemctl", "is-active"], ok("active\n"));
        let http = HttpClient::new(true).expect("http");
        let c = FirewallControl::new(
            ControlOptions {
                firewall_url: console.url("/api/vm-agent/firewall"),
                agent_version: "0.1.0".into(),
                service: "controlclaw-mitmproxy".into(),
                action_timeout: Duration::from_secs(5),
            },
            commands,
            Arc::new(runner),
            ConsoleClient::new(KeysDir::new(d.path().join("keys")), http),
        );
        (d, c)
    }

    fn beats(console: &FakeConsole) -> Vec<Value> {
        console
            .received()
            .into_iter()
            .filter(|r| r.path == "/api/vm-agent/firewall")
            .map(|r| r.body)
            .collect()
    }

    #[tokio::test]
    async fn at_most_twenty_results_a_beat_and_the_rest_on_the_next() {
        let console = FakeConsole::start().await.expect("console");
        let mut commands = Commands::default();
        let once = Mutex::new(true);
        commands.reports(move || {
            let mut first = once.lock().expect("lock");
            if !*first {
                return Vec::new();
            }
            *first = false;
            (0..25)
                .map(|i| CommandResult::from_outcome(&format!("r{i}"), CommandOutcome::done("x")))
                .collect()
        });
        let (_d, c) = control(&console, commands).await;
        c.clone().tick().await;
        c.clone().tick().await;
        let b = beats(&console);
        assert_eq!(b[0]["results"].as_array().map(Vec::len), Some(20));
        assert_eq!(b[1]["results"].as_array().map(Vec::len), Some(5));
        assert_eq!(b[1]["results"][0]["command_id"], json!("r20"));
        c.clone().tick().await;
        assert!(beats(&console)[2].get("results").is_none());
    }

    #[tokio::test]
    async fn a_failed_beat_keeps_its_results_and_backs_off() {
        let console = FakeConsole::start().await.expect("console");
        console.answer(
            "/api/vm-agent/firewall",
            vec![(500, json!({})), (200, json!({"command": null}))],
        );
        let mut commands = Commands::default();
        let once = Mutex::new(true);
        commands.reports(move || {
            let mut first = once.lock().expect("lock");
            if !std::mem::replace(&mut *first, false) {
                return Vec::new();
            }
            vec![CommandResult::from_outcome("r1", CommandOutcome::done("x"))]
        });
        let (_d, c) = control(&console, commands).await;
        c.clone().tick().await;
        // Inside the 5 s backoff: no beat at all.
        c.clone().tick().await;
        assert_eq!(beats(&console).len(), 1);
        if let Ok(mut i) = c.inner.lock() {
            i.next_attempt = None;
        }
        c.clone().tick().await;
        let b = beats(&console);
        assert_eq!(b.len(), 2);
        assert_eq!(b[1]["results"][0]["command_id"], json!("r1"));
    }
}
