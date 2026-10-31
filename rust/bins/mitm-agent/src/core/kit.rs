//! What the W3 command modules share around a consent code: where codes can go, and the
//! `awaiting_code` / `applied` outcomes in the TS shapes.

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::commands::CommandOutcome;
use crate::contracts::{CodeRoute, CodeRouteSource, CodeSent, ModuleCodes};

pub type Routes = Arc<dyn Fn() -> Option<Arc<dyn CodeRouteSource>> + Send + Sync>;

/// The shared consent instance and the channels' routes, as each module holds them.
#[derive(Clone)]
pub struct Kit {
    pub consent: Arc<dyn ModuleCodes>,
    pub routes: Routes,
}

/// `channelsReady` false (or no channels module): the answer to "is anyone approved" is unknown.
pub const CHANNELS_UNREADABLE: &str =
    "Your firewall cannot read its channel list right now, so it cannot ask you to confirm. Try again shortly.";

impl Kit {
    /// The routes, or `None` when the channel list cannot be read (fail closed, never first use).
    pub fn routes(&self) -> Option<Vec<CodeRoute>> {
        let source = (self.routes)().filter(|r| r.ready())?;
        Some(source.routes())
    }

    /// `agentAllowedCount()`, `None` when not known (SSH and the updates use it).
    pub fn agent_allowed(&self) -> Option<u32> {
        (self.routes)().and_then(|r| r.agent_allowed_count())
    }
}

pub fn ok(status: &str, data: Map<String, Value>) -> CommandOutcome {
    CommandOutcome {
        ok: true,
        status: status.into(),
        message: None,
        data: Some(data),
    }
}

pub fn fail(status: &str, message: impl Into<String>, data: Map<String, Value>) -> CommandOutcome {
    CommandOutcome {
        ok: false,
        status: status.into(),
        message: Some(message.into()),
        data: Some(data),
    }
}

/// `{...data, sentVia, expiresAt, attemptsLeft}` (and the recovery challenge when there is one),
/// or the send's failure.
pub fn awaiting(sent: CodeSent, mut data: Map<String, Value>) -> CommandOutcome {
    match &sent {
        CodeSent::Failed { message } => fail("failed", message.clone(), data),
        CodeSent::Sent { .. } => {
            data.extend(sent.awaiting_code_data().unwrap_or_default());
            ok("awaiting_code", data)
        }
    }
}

/// A payload's string, `None` for anything else or an empty one (`str` in the TS modules).
pub fn text(p: &Map<String, Value>, k: &str) -> Option<String> {
    p.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn obj(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
}

pub fn null_or(v: Option<String>) -> Value {
    v.map(Value::String).unwrap_or(Value::Null)
}

/// `execFile`'s outcome: stdout on a zero exit; otherwise `Command failed: <cmd>\n<stderr>`, as the
/// TS error message reads.
pub async fn run_ok(runner: &dyn cc_proc::Runner, cmd: cc_proc::Cmd) -> Result<String, String> {
    let line = std::iter::once(cmd.program.clone())
        .chain(cmd.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(out.stdout_str()),
        Ok(out) => Err(format!("Command failed: {line}\n{}", out.stderr_str())),
        Err(e) => Err(e.to_string()),
    }
}
