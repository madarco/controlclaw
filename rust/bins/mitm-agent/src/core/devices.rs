//! Letting a device drive an agent (`mac-devices.ts`): approve, reject or remove an OpenClaw Mac
//! app, confirmed with a code. No store: OpenClaw's gateway on the box owns the device list.

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget, DEVICE_APPROVE_MS};
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, null_or, obj, ok, text};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE_PREFIX: &str = "devices:";

#[derive(Debug, Clone, PartialEq)]
struct Proposal {
    change_id: String,
    kind: String,
    target_id: String,
    target_label: Option<String>,
    vm_id: String,
    name: String,
    hostname: String,
}

/// `parseProposal`.
fn parse(p: &Map<String, Value>) -> Result<Proposal, String> {
    let kind = p
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| ["approve", "reject", "remove"].contains(k));
    let empty = Map::new();
    let agent = p.get("agent").and_then(Value::as_object).unwrap_or(&empty);
    let (Some(change_id), Some(kind), Some(target_id), Some(vm_id), Some(hostname)) = (
        text(p, "changeId"),
        kind,
        text(p, "targetId"),
        text(agent, "vmId"),
        text(agent, "hostname"),
    ) else {
        return Err("malformed devices.propose payload".into());
    };
    Ok(Proposal {
        change_id,
        kind: kind.into(),
        target_id,
        target_label: text(p, "targetLabel"),
        name: text(agent, "name").unwrap_or_else(|| vm_id.clone()),
        vm_id,
        hostname,
    })
}

impl Proposal {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id, "kind": self.kind, "targetId": self.target_id, "targetLabel": self.target_label,
            "agent": {"vmId": self.vm_id, "name": self.name, "hostname": self.hostname},
        })
    }
}

/// `summarize`, mirrored in the console's `summarizeDeviceChange`.
fn summarize(p: &Proposal) -> String {
    let what = p.target_label.clone().unwrap_or_else(|| "an unnamed device".into());
    match p.kind.as_str() {
        "approve" => format!("Let {what} control {}", p.name),
        "reject" => format!("Refuse {what} access to {}", p.name),
        _ => format!("Cut {what} off from {}", p.name),
    }
}

pub struct Devices {
    agent: AgentClient,
    kit: Kit,
}

impl Devices {
    pub fn new(agent: AgentClient, kit: Kit) -> Self {
        Self { agent, kit }
    }

    async fn apply(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let (path, body) = match p.kind.as_str() {
            "approve" => ("/devices/approve", json!({"requestId": p.target_id})),
            "reject" => ("/devices/reject", json!({"requestId": p.target_id})),
            _ => ("/devices/remove", json!({"deviceId": p.target_id})),
        };
        let r = self
            .agent
            .post_within(&AgentTarget::new(&p.vm_id, &p.hostname), path, &body, DEVICE_APPROVE_MS)
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!("[devices] {} {} on {}", p.kind, p.target_id, p.name);
        Ok(obj(&[
            ("vmId", json!(p.vm_id)),
            ("targetId", json!(p.target_id)),
            ("deviceId", null_or(text(&r, "deviceId"))),
        ]))
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize(&p);
        let data = obj(&[("changeId", json!(p.change_id)), ("summary", json!(summary))]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        let scope = format!("{SCOPE_PREFIX}{}", p.vm_id);
        if routes.is_empty() {
            self.kit.consent.forget(&scope);
            return match self.apply(&p).await {
                Ok(applied) => {
                    let mut d = data;
                    d.extend(applied);
                    d.insert("tofu".into(), json!(true));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
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
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[devices] code sent for {} on {} via {sent_via}", p.kind, p.name);
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(vm_id)) = (text(&payload, "changeId"), text(&payload, "vmId")) else {
            return CommandOutcome::failed("failed", "malformed devices.confirm payload");
        };
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self
            .kit
            .consent
            .verify(&format!("{SCOPE_PREFIX}{vm_id}"), &change_id, &code)
        {
            CodeCheck::Expired => fail("expired", "No change is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().and_then(|o| parse(o).ok()) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                match self.apply(&p).await {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize(&p)));
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
        ok("cancelled", obj(&[("changeId", null_or(change_id))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_and_summaries() {
        let p = |v: Value| parse(v.as_object().expect("obj"));
        assert_eq!(
            p(json!({"changeId": "c", "kind": "x"})).expect_err("e"),
            "malformed devices.propose payload"
        );
        let a = p(json!({"changeId": "c", "kind": "approve", "targetId": "r1", "targetLabel": "Anna's Mac", "agent": {"vmId": "v", "hostname": "h", "name": "atlas"}})).expect("ok");
        assert_eq!(summarize(&a), "Let Anna's Mac control atlas");
        assert_eq!(parse(a.to_json().as_object().expect("obj")).expect("back"), a);
        let r =
            p(json!({"changeId": "c", "kind": "remove", "targetId": "d1", "agent": {"vmId": "v", "hostname": "h"}}))
                .expect("ok");
        assert_eq!(summarize(&r), "Cut an unnamed device off from v");
    }
}
