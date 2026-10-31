//! One channel write to an agent box (`POST /channels/apply`), and how it ended
//! (`channel-apply.ts`). Turning a channel on restarts OpenClaw's gateway inside the config patch,
//! so the call can end before the write does: the write carries an id, and when the answer does not
//! arrive the box is asked how that id ended. Only a box that says it failed, or a refusal that
//! arrives in time, is a failure; everything else is `unconfirmed`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::channels::agent::{AGENT_CALL_MS, AgentCalls, CHANNELS_APPLY_MS, Target};

/// `budgets.ts`.
pub const COMMAND_BUDGET_MS: i64 = 100_000;
pub const CONFIRM_APPLY_MS: i64 = 30_000;
pub const CONFIRM_POLL_MS: i64 = 2_000;
pub const CONFIRM_MIN_MS: i64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    Unconfirmed,
}

pub type Now = Arc<dyn Fn() -> i64 + Send + Sync>;

/// `deadline()`: `COMMAND_BUDGET_MS` from the start of a command, and what is left of it.
#[derive(Clone)]
pub struct Deadline {
    pub at: i64,
    now: Now,
}

impl Deadline {
    pub fn new(now: Now) -> Self {
        Self {
            at: now() + COMMAND_BUDGET_MS,
            now,
        }
    }

    /// Milliseconds left, never negative.
    pub fn left(&self) -> i64 {
        (self.at - (self.now)()).max(0)
    }

    /// `ms`, or whatever is left of the budget if that is less.
    pub fn within(&self, ms: i64) -> i64 {
        ms.min(self.left())
    }
}

pub type Sleep = Arc<dyn Fn(Duration) -> cc_http::BoxFuture<()> + Send + Sync>;

pub struct ChannelWriter {
    pub agent: Arc<dyn AgentCalls>,
    pub now: Now,
    pub make_apply_id: Arc<dyn Fn() -> String + Send + Sync>,
    pub sleep: Sleep,
}

impl ChannelWriter {
    /// Write `body` (one channel, `kind` names it) to `target` and settle how it ended. An error on
    /// a refusal that arrived in time, or on a box that reports the write failed.
    pub async fn write(
        &self,
        target: &Target,
        kind: &str,
        mut body: Value,
        dl: Option<&Deadline>,
    ) -> Result<ApplyOutcome, String> {
        let apply_id = (self.make_apply_id)();
        body["applyId"] = json!(apply_id);
        // Capped by the command's deadline too, leaving `CONFIRM_MIN_MS` for the confirm.
        let timeout = dl.map(|d| {
            Duration::from_millis(CHANNELS_APPLY_MS.min(CONFIRM_MIN_MS.max(d.left() - CONFIRM_MIN_MS) as u64))
        });
        match self.agent.post(target, "/channels/apply", body, timeout).await {
            // An older agent bundle answers without a status at all; that answer IS the confirmation.
            Ok(r) if r.get("status").and_then(Value::as_str) != Some("pending") => return Ok(ApplyOutcome::Applied),
            Ok(_) => tracing::info!(
                "[channels] {kind} on {} is still being written; asking the box how it ends",
                target.vm_id
            ),
            Err(e) if !e.timed_out => return Err(e.message),
            Err(_) => tracing::info!(
                "[channels] {} did not answer the {kind} write in time; asking the box how it ended",
                target.vm_id
            ),
        }
        self.confirm(target, kind, &apply_id, dl).await
    }

    /// Ask a box how the write named by `apply_id` ended, until it says or the budget runs out.
    pub async fn confirm(
        &self,
        target: &Target,
        kind: &str,
        apply_id: &str,
        dl: Option<&Deadline>,
    ) -> Result<ApplyOutcome, String> {
        let now = || (self.now)();
        let budget = dl.map_or(CONFIRM_APPLY_MS, |d| d.within(CONFIRM_APPLY_MS));
        let until = now() + budget;
        // Bounded by attempts as well as the clock: a test clock that stands still cannot spin.
        let attempts = 1.max((budget + CONFIRM_POLL_MS - 1) / CONFIRM_POLL_MS);
        for asked in 0..attempts {
            if asked > 0 {
                if now() >= until {
                    break;
                }
                let wait = CONFIRM_POLL_MS.min((until - now()).max(0));
                (self.sleep)(Duration::from_millis(wait as u64)).await;
            }
            let left = until - now();
            if left <= 0 {
                break;
            }
            let status = match self
                .agent
                .get(
                    target,
                    "/channels/status",
                    Some(Duration::from_millis(AGENT_CALL_MS.min(left as u64))),
                )
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::info!(
                        "[channels] could not read {} to confirm the {kind} write: {}",
                        target.vm_id,
                        e.message
                    );
                    continue;
                }
            };
            let record = status
                .get("channels")
                .and_then(|c| c.get(kind))
                .and_then(|c| c.get("lastApply"))
                .filter(|r| r.is_object());
            let Some(record) = record.filter(|r| r.get("id").and_then(Value::as_str) == Some(apply_id)) else {
                tracing::info!(
                    "[channels] {} has no record of the {kind} write {apply_id}",
                    target.vm_id
                );
                return Ok(ApplyOutcome::Unconfirmed);
            };
            match record.get("state").and_then(Value::as_str) {
                Some("applied") => {
                    tracing::info!("[channels] {} confirms the {kind} write landed", target.vm_id);
                    return Ok(ApplyOutcome::Applied);
                }
                Some("failed") => {
                    return Err(record
                        .get("error")
                        .and_then(Value::as_str)
                        .filter(|e| !e.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("the agent could not apply {kind}")));
                }
                _ => {}
            }
        }
        tracing::info!(
            "[channels] {} had not finished the {kind} write inside the budget",
            target.vm_id
        );
        Ok(ApplyOutcome::Unconfirmed)
    }
}
