//! The firewall's heartbeat commands: what each workstream registers (handlers by action name, the
//! fields every beat carries, the reports a module makes by itself) and the shapes the console
//! reads back. W0 owns this file; W3's `core/control.rs` runs the channel that uses it.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use cc_http::BoxFuture;
use serde::Serialize;
use serde_json::{Map, Value};

/// What the control channel puts on every beat itself (`firewall-control.ts` `beat`).
const RESERVED_BEAT_KEYS: &[&str] = &["proxy", "agent_version", "uptime_s", "results"];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CommandOutcome {
    pub ok: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, Value>>,
}

impl CommandOutcome {
    pub fn done(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            status: "done".into(),
            message: Some(message.into()),
            data: None,
        }
    }

    pub fn failed(status: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            status: status.into(),
            message: Some(message.into()),
            data: None,
        }
    }
}

/// One result as the beat carries it: `{command_id, ok, status, message, data?}`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CommandResult {
    pub command_id: String,
    pub ok: bool,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, Value>>,
}

impl CommandResult {
    pub fn from_outcome(id: &str, o: CommandOutcome) -> Self {
        Self {
            command_id: id.to_string(),
            ok: o.ok,
            status: o.status,
            message: o.message.unwrap_or_default(),
            data: o.data,
        }
    }
}

pub type CommandHandler = Arc<dyn Fn(Map<String, Value>) -> BoxFuture<CommandOutcome> + Send + Sync>;

/// Run one command's handler as every caller must: the payload's secrets remembered first (a
/// proposal may hold them only in memory, and Doctor's and the AI review's redaction must know
/// them), inside the payload's `requestedVia` scope, and in a task of its own, so a handler that
/// panics is a failed command and not a dead caller. The control channel and a standalone
/// firewall's local API both run commands through this.
pub async fn run(handler: CommandHandler, action: &str, payload: Map<String, Value>) -> CommandOutcome {
    remember(&payload);
    let via = crate::core::requested_via::from_payload(&payload);
    outcome(
        action,
        tokio::spawn(crate::core::requested_via::scope(via, handler(payload))).await,
    )
}

/// [`run`] for a standalone firewall's signed-in admin (`cc-local`'s API): no code goes to anyone;
/// the code a proposal is held for comes back with the outcome, for the API to confirm with. A
/// `requestedVia` in the payload is dropped: the admin is not an MCP app.
pub async fn run_as_admin(
    handler: CommandHandler,
    action: &str,
    mut payload: Map<String, Value>,
) -> (CommandOutcome, Option<String>) {
    payload.remove("requestedVia");
    remember(&payload);
    match tokio::spawn(crate::core::requested_via::as_local_admin(handler(payload))).await {
        Ok((o, code)) => (o, code),
        Err(e) => (outcome(action, Err(e)), None),
    }
}

fn remember(payload: &Map<String, Value>) {
    cc_crypto::enc_file::remember_encrypted_secrets(&Value::Object(payload.clone()), false);
}

fn outcome(action: &str, joined: Result<CommandOutcome, tokio::task::JoinError>) -> CommandOutcome {
    match joined {
        Ok(outcome) => outcome,
        Err(e) => {
            let message: String = format!("{e}").chars().take(500).collect();
            tracing::info!("[firewall] {action} failed: {message}");
            CommandOutcome::failed("failed", message)
        }
    }
}
type StatusFn = Box<dyn Fn() -> Map<String, Value> + Send + Sync>;
type ReportsFn = Box<dyn Fn() -> Vec<CommandResult> + Send + Sync>;

/// What the workstreams register: command handlers by action name, the fields each adds to every
/// beat (`status`), and the reports they make on their own (`extraResults`, drained each beat).
#[derive(Default)]
pub struct Commands {
    handlers: HashMap<String, CommandHandler>,
    status: Vec<(Vec<&'static str>, StatusFn)>,
    undeclared_said: std::sync::Mutex<std::collections::HashSet<String>>,
    reports: Vec<ReportsFn>,
}

impl Commands {
    /// Register `action`. Two handlers for one action is a wiring mistake and stops the start.
    pub fn handle<F, Fut>(&mut self, action: &str, f: F)
    where
        F: Fn(Map<String, Value>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = CommandOutcome> + Send + 'static,
    {
        let h: CommandHandler = Arc::new(move |p| Box::pin(f(p)));
        assert!(
            self.handlers.insert(action.to_string(), h).is_none(),
            "command {action} registered twice"
        );
    }

    /// Fields every beat carries. `keys` are the top-level keys `f` returns: two parts claiming
    /// one key is a wiring mistake (the later would overwrite the earlier) and stops the start. A key
    /// `f` returns but did not declare is left out of the beat and logged.
    pub fn status(&mut self, keys: &[&'static str], f: impl Fn() -> Map<String, Value> + Send + Sync + 'static) {
        for k in keys {
            assert!(
                !RESERVED_BEAT_KEYS.contains(k),
                "beat key {k} is the control channel's own"
            );
            assert!(
                !self.status.iter().any(|(ks, _)| ks.contains(k)),
                "beat key {k} registered twice"
            );
        }
        self.status.push((keys.to_vec(), Box::new(f)));
    }

    pub fn reports(&mut self, f: impl Fn() -> Vec<CommandResult> + Send + Sync + 'static) {
        self.reports.push(Box::new(f));
    }

    pub(crate) fn handler(&self, action: &str) -> Option<CommandHandler> {
        self.handlers.get(action).cloned()
    }

    pub(crate) fn drain_reports(&self) -> Vec<CommandResult> {
        self.reports.iter().flat_map(|f| f()).collect()
    }

    /// Every part's beat fields, only the keys each declared.
    pub(crate) fn beat_fields(&self) -> Map<String, Value> {
        let mut out = Map::new();
        for (keys, f) in &self.status {
            for (k, v) in f() {
                if keys.contains(&k.as_str()) {
                    out.insert(k, v);
                } else if let Ok(mut said) = self.undeclared_said.lock()
                    && said.insert(k.clone())
                {
                    // Once per key: a wiring mistake, not something to repeat every beat.
                    tracing::error!("[firewall] beat field {k} was not declared; left out");
                }
            }
        }
        out
    }

    /// Every beat key the parts declared.
    pub fn beat_keys(&self) -> Vec<&'static str> {
        let mut k: Vec<&'static str> = self.status.iter().flat_map(|(ks, _)| ks.iter().copied()).collect();
        k.sort_unstable();
        k
    }

    pub fn actions(&self) -> Vec<String> {
        let mut a: Vec<String> = self.handlers.keys().cloned().collect();
        a.sort();
        a
    }
}
