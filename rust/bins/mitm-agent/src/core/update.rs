//! Updating an agent box in place (`update.ts`). An update makes the box run new code as root, so
//! it takes a code like a credential does; the summary is written here. While a box updates, the
//! proxy lets it reach the package hosts: a window opens just before the box is told to start and
//! closes when the box reports the run finished, or after an hour.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget};
use super::code_message::CodeParts;
use super::identities::Agents;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE_PREFIX: &str = "update:";
/// The longest a window stays open: the box's own stale limit (45 minutes) and a margin.
pub const UPDATE_WINDOW_MS: u64 = 60 * 60_000;
/// How often an open window asks its box whether the run has finished.
pub const UPDATE_POLL_MS: u64 = 30_000;

/// Rewrites the proxy config so the windows match `windows()` (`publishUpdateWindows`).
pub type OnWindowsChanged = Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>;

#[derive(Debug, Clone)]
struct Window {
    target: AgentTarget,
    opened_at: u64,
    until: u64,
    saw_running: bool,
}

#[derive(Debug, Clone)]
struct Proposal {
    change_id: String,
    vm_id: String,
    name: String,
    hostname: String,
}

impl Proposal {
    fn target(&self) -> AgentTarget {
        AgentTarget::new(&self.vm_id, &self.hostname)
    }
    fn to_json(&self) -> Value {
        json!({"changeId": self.change_id, "agent": {"vmId": self.vm_id, "name": self.name, "hostname": self.hostname}})
    }
}

/// `parseProposal` (also reads one back after its code).
fn parse(p: &Map<String, Value>) -> Result<Proposal, String> {
    let empty = Map::new();
    let a = p.get("agent").and_then(Value::as_object).unwrap_or(&empty);
    let (Some(change_id), Some(vm_id), Some(hostname)) = (text(p, "changeId"), text(a, "vmId"), text(a, "hostname"))
    else {
        return Err("malformed update.propose payload".into());
    };
    Ok(Proposal {
        change_id,
        name: text(a, "name").unwrap_or_else(|| vm_id.clone()),
        vm_id,
        hostname,
    })
}

/// `summarize`: names the box, because that is the decision.
pub fn summarize(name: &str) -> String {
    format!("Update the software on {name}")
}

/// What `update.post` sends: `{}` for a manual run, `{mode: "auto", deadline}` for a nightly one.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub auto: bool,
    pub deadline: Option<u64>,
}

impl RunOptions {
    fn body(&self) -> Value {
        let mut m = Map::new();
        if self.auto {
            m.insert("mode".into(), json!("auto"));
        }
        if let Some(d) = self.deadline {
            m.insert("deadline".into(), json!(d));
        }
        Value::Object(m)
    }
}

pub struct Updates {
    agent: AgentClient,
    kit: Kit,
    agents: Arc<Agents>,
    on_windows_changed: OnWindowsChanged,
    open: Mutex<HashMap<String, Window>>,
    /// Whether the poll loop runs.
    polling: Mutex<bool>,
}

impl Updates {
    pub fn new(agent: AgentClient, kit: Kit, agents: Arc<Agents>, on_windows_changed: OnWindowsChanged) -> Self {
        Self {
            agent,
            kit,
            agents,
            on_windows_changed,
            open: Mutex::new(HashMap::new()),
            polling: Mutex::new(false),
        }
    }

    fn open(&self) -> std::sync::MutexGuard<'_, HashMap<String, Window>> {
        self.open.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `windows`: vm id to the window's end in epoch seconds. Only this process opens one.
    pub fn windows(&self) -> Map<String, Value> {
        let now = now_ms();
        self.open()
            .iter()
            .filter(|(_, w)| w.until > now)
            .map(|(vm, w)| (vm.clone(), json!(w.until / 1000)))
            .collect()
    }

    async fn open_window(self: &Arc<Self>, target: &AgentTarget) -> Result<(), String> {
        let opened_at = now_ms();
        self.open().insert(
            target.vm_id.clone(),
            Window {
                target: target.clone(),
                opened_at,
                until: opened_at + UPDATE_WINDOW_MS,
                saw_running: false,
            },
        );
        if (self.on_windows_changed)().await.is_err() {
            // The run would fail at its first download; refused here instead.
            self.open().remove(&target.vm_id);
            return Err("Your firewall could not prepare for the update. Try again shortly.".into());
        }
        let start = {
            let mut p = self.polling.lock().unwrap_or_else(|e| e.into_inner());
            !std::mem::replace(&mut *p, true)
        };
        if start {
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(UPDATE_POLL_MS)).await;
                    me.poll_windows().await;
                    let mut p = me.polling.lock().unwrap_or_else(|e| e.into_inner());
                    if me.open().is_empty() {
                        *p = false;
                        break;
                    }
                }
            });
        }
        Ok(())
    }

    async fn close_window(&self, vm_id: &str, why: &str) {
        if self.open().remove(vm_id).is_none() {
            return;
        }
        tracing::info!("[update] window closed for {vm_id} ({why})");
        if let Err(e) = (self.on_windows_changed)().await {
            // The deadline in the proxy config still closes it.
            tracing::info!("[update] could not resync after closing the window for {vm_id}: {e}");
        }
    }

    /// `pollWindows`: a finished phase counts once the run was seen running, or when it was
    /// written after the window opened (the state file still holds the previous run until then).
    pub async fn poll_windows(&self) {
        let now = now_ms();
        let all: Vec<(String, Window)> = self.open().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (vm, w) in all {
            if w.until <= now {
                self.close_window(&vm, "deadline").await;
                continue;
            }
            let Ok(status) = self.agent.get(&w.target, "/update").await else {
                continue;
            };
            let phase = status
                .get("phase")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if ["resolving", "installing", "running"].contains(&phase.as_str()) {
                if let Some(x) = self.open().get_mut(&vm) {
                    x.saw_running = true;
                }
                continue;
            }
            if phase != "done" && phase != "failed" {
                continue;
            }
            let at = status
                .get("at")
                .and_then(Value::as_str)
                .and_then(super::ssh::parse_iso_ms);
            let saw = self.open().get(&vm).is_some_and(|x| x.saw_running);
            if saw || at.is_some_and(|a| a > w.opened_at as f64) {
                self.close_window(&vm, &format!("run {phase}")).await;
            }
        }
    }

    async fn apply(
        self: &Arc<Self>,
        target: &AgentTarget,
        name: &str,
        options: &RunOptions,
    ) -> Result<Map<String, Value>, String> {
        if options.auto {
            let support = self.agent.get(target, "/update").await.map_err(|e| e.to_string())?;
            // Old daemons ignore POST bodies and would run a manual update.
            if support.get("automatic") != Some(&Value::Bool(true)) {
                return Err("Update this box manually once before enabling its nightly updates.".into());
            }
        }
        // The window first: the run's first download follows within seconds.
        self.open_window(target).await?;
        let r = match self.agent.post(target, "/update", &options.body()).await {
            Ok(r) => r,
            Err(e) => {
                self.close_window(&target.vm_id, "the box did not start the run").await;
                return Err(e.to_string());
            }
        };
        tracing::info!("[update] started on {name}");
        let phase = r
            .get("status")
            .and_then(|s| s.get("phase"))
            .filter(|p| !p.is_null())
            .cloned()
            .unwrap_or(json!("resolving"));
        Ok(obj(&[("vmId", json!(target.vm_id)), ("phase", phase)]))
    }

    /// `applyToTarget`: a run for a batch whose code was already confirmed (update-all). No consent
    /// check here; only the batch calls it, after claiming the box from a grant a code wrote.
    pub async fn apply_to_target(
        self: &Arc<Self>,
        target: &AgentTarget,
        name: &str,
        options: &RunOptions,
    ) -> Result<Map<String, Value>, String> {
        self.apply(target, name, options).await
    }

    pub async fn propose(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize(&p.name);
        let data = obj(&[("changeId", json!(p.change_id)), ("summary", json!(summary))]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        let scope = format!("{SCOPE_PREFIX}{}", p.vm_id);
        if routes.is_empty() {
            self.kit.consent.forget(&scope);
            return match self.apply(&p.target(), &p.name, &RunOptions::default()).await {
                Ok(applied) => {
                    let mut d = data;
                    d.extend(applied);
                    d.insert("tofu".into(), json!(true));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        // The first part names the agent as this firewall has it on record.
        let parts = self.agents.record_name(&p.vm_id).map(|n| CodeParts {
            ask: format!("Update the software on the agent {n}"),
            ..Default::default()
        });
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope,
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: p.name.clone(),
                summary,
                routes,
                parts,
                recovery: true,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[update] code sent for {} via {sent_via}", p.name);
        }
        awaiting(sent, data)
    }

    pub async fn confirm(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(vm_id)) = (text(&payload, "changeId"), text(&payload, "vmId")) else {
            return CommandOutcome::failed("failed", "malformed update.confirm payload");
        };
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self
            .kit
            .consent
            .verify(&format!("{SCOPE_PREFIX}{vm_id}"), &change_id, &code)
        {
            CodeCheck::Expired => fail("expired", "No update is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().and_then(|o| parse(o).ok()) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                match self.apply(&p.target(), &p.name, &RunOptions::default()).await {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize(&p.name)));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        if let Some(vm) = text(&payload, "vmId") {
            self.kit
                .consent
                .cancel(&format!("{SCOPE_PREFIX}{vm}"), change_id.as_deref());
        }
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals() {
        let p = parse(
            json!({"changeId": "c", "agent": {"vmId": "v", "hostname": "h"}})
                .as_object()
                .expect("o"),
        )
        .expect("ok");
        assert_eq!(p.name, "v");
        assert_eq!(summarize(&p.name), "Update the software on v");
        assert!(parse(json!({"changeId": "c"}).as_object().expect("o")).is_err());
        assert_eq!(
            RunOptions {
                auto: true,
                deadline: Some(5)
            }
            .body(),
            json!({"mode": "auto", "deadline": 5})
        );
        assert_eq!(RunOptions::default().body(), json!({}));
    }
}
