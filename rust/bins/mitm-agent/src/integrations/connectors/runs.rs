//! Ships OpenConnector's run log to the console's `POST /api/vm-agent/activity`
//! (`connector-runs.ts`), so a connector call shows up on the Activity page. A connector call
//! leaves from this box, not from the agent, so the run record is the only place it appears, and
//! the runtime token it was made with is what ties it to an agent.
//!
//! Delivery is at-least-once and the ingest dedupes on the run id, so a cursor that goes backwards
//! costs nothing.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::runtime::ConnectorRuntime;
use crate::integrations::js;

const DEFAULT_BATCH: usize = 50;

/// Runtime token id → the agent that holds it.
pub type AgentForToken = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// One run as the console's Activity takes it.
pub fn to_run_record(run: &Value, vm_id: Option<&str>) -> Option<Value> {
    let id = run.get("id").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let started = run.get("startedAt").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let at = js::parse_iso(started)?;
    let s = |k: &str| run.get(k).and_then(Value::as_str);
    Some(json!({
        "source": "connector_run",
        "run_id": id,
        "ts": at as f64 / 1000.0,
        "vm_id": vm_id,
        "service": s("service").unwrap_or(""),
        "action_id": s("actionId").unwrap_or(""),
        "caller": s("caller"),
        "ok": run.get("ok") == Some(&Value::Bool(true)),
        // Rounded: the ingest schema is an integer, and one fractional value would fail the whole batch.
        "duration_ms": run.get("durationMs").and_then(Value::as_f64).map(|d| json!(d.round() as i64)).unwrap_or(Value::Null),
        "error_code": s("errorCode"),
    }))
}

struct State {
    since: Option<String>,
    in_flight: bool,
    backoff_ms: i64,
    /// The last failure said, so a runtime that stays down is one line, not one per retry.
    failing: Option<String>,
    next_attempt_at: i64,
}

pub struct RunShipper {
    runtime: ConnectorRuntime,
    console: cc_client::ConsoleClient,
    activity_url: String,
    agent_for_token: AgentForToken,
    state_path: PathBuf,
    state: Mutex<State>,
}

impl RunShipper {
    pub fn new(
        runtime: ConnectorRuntime,
        console: cc_client::ConsoleClient,
        activity_url: String,
        agent_for_token: AgentForToken,
        state_path: PathBuf,
    ) -> Self {
        let since = cc_store::read_json::<Value>(&state_path)
            .and_then(|v| v.get("since").and_then(Value::as_str).map(str::to_string));
        Self {
            runtime,
            console,
            activity_url,
            agent_for_token,
            state_path,
            state: Mutex::new(State {
                since,
                in_flight: false,
                backoff_ms: 0,
                failing: None,
                next_attempt_at: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The number of records shipped.
    pub async fn tick(&self) -> usize {
        let since = {
            let mut st = self.lock();
            if st.in_flight || js::now_ms() < st.next_attempt_at {
                return 0;
            }
            st.in_flight = true;
            st.since.clone()
        };
        let r = self.ship(since).await;
        let mut st = self.lock();
        st.in_flight = false;
        match r {
            Ok((n, newest)) => {
                if st.failing.take().is_some() {
                    tracing::info!("[connectors] run shipping works again");
                }
                // Working again: the next failure starts from the shortest wait.
                st.backoff_ms = 0;
                if let Some(newest) = newest {
                    st.since = Some(newest.clone());
                    let text = js::stringify(&json!({"since": newest}));
                    if let Some(dir) = self.state_path.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    let _ = cc_store::write_atomic(&self.state_path, text.as_bytes(), 0o600, cc_store::TmpName::Suffix);
                }
                n
            }
            Err(e) => {
                st.backoff_ms = if st.backoff_ms > 0 {
                    (st.backoff_ms * 2).min(60_000)
                } else {
                    5000
                };
                st.next_attempt_at = js::now_ms() + st.backoff_ms;
                // Said when shipping starts failing, not on every retry; "works again" ends it.
                if st.failing.is_none() {
                    tracing::info!("[connectors] run ship failed ({e}); retrying until it works");
                    st.failing = Some(e);
                }
                0
            }
        }
    }

    async fn ship(&self, since: Option<String>) -> Result<(usize, Option<String>), String> {
        let runs = self.runtime.runs(DEFAULT_BATCH).await.map_err(|e| e.message)?;
        let since_ms = since.as_deref().and_then(js::parse_iso).unwrap_or(0);
        let fresh: Vec<&Value> = runs
            .iter()
            .filter(|r| {
                r.get("startedAt")
                    .and_then(Value::as_str)
                    .and_then(js::parse_iso)
                    .is_some_and(|t| t > since_ms)
            })
            .collect();
        if fresh.is_empty() {
            return Ok((0, None));
        }
        let records: Vec<Value> = fresh
            .iter()
            .filter_map(|r| {
                let vm = r
                    .get("runtimeTokenId")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .and_then(|t| (self.agent_for_token)(t));
                to_run_record(r, vm.as_deref())
            })
            .collect();
        if records.is_empty() {
            return Ok((0, None));
        }
        let res = self
            .console
            .post_json(
                &self.activity_url,
                &json!({"records": records}),
                Duration::from_secs(30),
            )
            .await
            .map_err(crate::integrations::client_error)?;
        if res.status == 400 || res.status == 413 {
            // Malformed for this server: it will never take it, so move the cursor past it.
            tracing::info!(
                "[connectors] run batch rejected (HTTP {}); skipping {} record(s)",
                res.status,
                records.len()
            );
        } else if !(200..300).contains(&res.status) {
            return Err(format!("HTTP {}", res.status));
        }
        let newest = fresh
            .iter()
            .filter_map(|r| r.get("startedAt").and_then(Value::as_str).and_then(js::parse_iso))
            .fold(since_ms, i64::max);
        Ok((records.len(), Some(js::iso(newest))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_record_has_metadata_only_and_an_integer_duration() {
        let run = json!({"id": "run_1", "service": "github", "actionId": "github.get_user", "caller": "mcp",
            "startedAt": "2026-10-28T10:00:00.500Z", "durationMs": 12.6, "ok": true, "runtimeTokenId": "t1",
            "inputSummary": "secret?"});
        let rec = to_run_record(&run, Some("vm-a")).expect("record");
        assert_eq!(
            rec,
            json!({"source": "connector_run", "run_id": "run_1", "ts": 1_793_181_600.5, "vm_id": "vm-a",
                "service": "github", "action_id": "github.get_user", "caller": "mcp", "ok": true,
                "duration_ms": 13, "error_code": null})
        );
        assert!(to_run_record(&json!({"id": "x"}), None).is_none());
        assert!(to_run_record(&json!({"id": "x", "startedAt": "nope"}), None).is_none());
    }
}
