//! Putting an agent box on the owner's own Tailscale network (`tailscale.ts`,
//! `tailscale-store.ts`). Confirmed with a code; the auth key rides one command to the box and is
//! never stored. The store says which boxes may reach `*.tailscale.com` through the proxy.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget};
use super::consent::iso;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE_PREFIX: &str = "tailscale:";

pub type OnChanged = Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>;

#[derive(Debug, Clone, PartialEq)]
struct Proposal {
    change_id: String,
    join: bool,
    ssh: bool,
    vm_id: String,
    name: String,
    hostname: String,
    tailnet_hostname: String,
    auth_key: Option<String>,
}

/// `parseProposal`.
fn parse(p: &Map<String, Value>) -> Result<Proposal, String> {
    let change_id = text(p, "changeId");
    let kind = p.get("kind").and_then(Value::as_str);
    let join = match kind {
        Some("join") => Some(true),
        Some("leave") => Some(false),
        _ => None,
    };
    let empty = Map::new();
    let agent = p.get("agent").and_then(Value::as_object).unwrap_or(&empty);
    let (vm_id, hostname) = (text(agent, "vmId"), text(agent, "hostname"));
    let (Some(change_id), Some(join), Some(vm_id), Some(hostname)) = (change_id, join, vm_id, hostname) else {
        return Err("malformed tailscale.propose payload".into());
    };
    let auth_key = text(p, "authKey");
    if join && auth_key.is_none() {
        return Err("a join needs an auth key".into());
    }
    let name = text(agent, "name").unwrap_or_else(|| vm_id.clone());
    Ok(Proposal {
        change_id,
        join,
        ssh: p.get("ssh") == Some(&Value::Bool(true)),
        tailnet_hostname: text(agent, "tailnetHostname")
            .or_else(|| text(agent, "name"))
            .unwrap_or_else(|| vm_id.clone()),
        vm_id,
        name,
        hostname,
        auth_key,
    })
}

impl Proposal {
    fn to_json(&self) -> Value {
        let mut m = obj(&[
            ("changeId", json!(self.change_id)),
            ("kind", json!(if self.join { "join" } else { "leave" })),
            ("ssh", json!(self.ssh)),
            (
                "agent",
                json!({"vmId": self.vm_id, "name": self.name, "hostname": self.hostname, "tailnetHostname": self.tailnet_hostname}),
            ),
        ]);
        if let Some(k) = &self.auth_key {
            m.insert("authKey".into(), json!(k));
        }
        Value::Object(m)
    }
}

/// `summarize`, mirrored in the console's `summarizeChange`.
fn summarize(p: &Proposal) -> String {
    if p.join {
        format!(
            "Put {} on your Tailscale network{}",
            p.name,
            if p.ssh { ", with Tailscale SSH" } else { "" }
        )
    } else {
        format!("Take {} off your Tailscale network", p.name)
    }
}

pub struct Tailscale {
    path: PathBuf,
    box_key: String,
    aad: String,
    /// `{version: 1, agents: {vmId: {name, hostname, ssh, node, joinedAt}}}`.
    store: Mutex<Map<String, Value>>,
    agent: AgentClient,
    kit: Kit,
    on_changed: OnChanged,
}

fn empty_store() -> Map<String, Value> {
    obj(&[("version", json!(1)), ("agents", json!({}))])
}

impl Tailscale {
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: Kit,
        on_changed: OnChanged,
    ) -> Self {
        let aad = format!("{org}:{box_id}:tailscale");
        let log = |l: &str| tracing::error!("{l}");
        let store = match cc_crypto::enc_file::load_store_or_empty("tailscale", &path, box_key, &aad, &log) {
            Some(Value::Object(o))
                if o.get("version").and_then(Value::as_f64) == Some(1.0)
                    && o.get("agents").is_some_and(Value::is_object) =>
            {
                o
            }
            _ => empty_store(),
        };
        Self {
            path,
            box_key: box_key.into(),
            aad,
            store: Mutex::new(store),
            agent,
            kit,
            on_changed,
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st();
        self.save(&s).expect("save");
    }

    fn st(&self) -> std::sync::MutexGuard<'_, Map<String, Value>> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn agents(st: &mut Map<String, Value>) -> &mut Map<String, Value> {
        if !st.get("agents").is_some_and(Value::is_object) {
            st.insert("agents".into(), json!({}));
        }
        st.get_mut("agents").and_then(Value::as_object_mut).expect("set above")
    }

    /// A store that cannot be written fails the command (the TS throws): the passthrough must
    /// never be open for a box the store does not have, or closed for one it does.
    fn save(&self, st: &Map<String, Value>) -> Result<(), String> {
        cc_crypto::enc_file::save_store(
            "tailscale",
            &self.path,
            &Value::Object(st.clone()),
            &self.box_key,
            &self.aad,
        )
        .map_err(|e| format!("The Tailscale settings could not be saved on your firewall: {e}"))
    }

    /// `enabledVmIds`: the boxes the proxy lets reach Tailscale.
    pub fn enabled_vm_ids(&self) -> Vec<String> {
        self.st()
            .get("agents")
            .and_then(Value::as_object)
            .map(|a| a.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// `summary`: what the console may see; no key, because there is none.
    pub fn summary(&self) -> Vec<Value> {
        self.st()
            .get("agents")
            .and_then(Value::as_object)
            .map(|a| {
                a.iter()
                    .map(|(vm, x)| json!({"vmId": vm, "name": x.get("name"), "ssh": x.get("ssh"), "node": x.get("node")}))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn apply(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let t = AgentTarget::new(&p.vm_id, &p.hostname);
        if !p.join {
            // The box first: `tailscale logout` needs the passthrough this then closes.
            self.agent
                .post(&t, "/tailscale/logout", &json!({}))
                .await
                .map_err(|e| e.to_string())?;
            {
                let mut st = self.st();
                Self::agents(&mut st).shift_remove(&p.vm_id);
                self.save(&st)?;
            }
            (self.on_changed)().await?;
            tracing::info!("[tailscale] {} left the tailnet", p.name);
            return Ok(obj(&[
                ("vmId", json!(p.vm_id)),
                ("ssh", json!(false)),
                ("node", Value::Null),
            ]));
        }
        // The passthrough before the box dials out.
        {
            let mut st = self.st();
            Self::agents(&mut st).insert(
                p.vm_id.clone(),
                json!({"name": p.name, "hostname": p.hostname, "ssh": p.ssh, "node": null, "joinedAt": iso(now_ms())}),
            );
            self.save(&st)?;
        }
        (self.on_changed)().await?;
        let body = json!({"authKey": p.auth_key, "ssh": p.ssh, "hostname": p.tailnet_hostname});
        let r = match self.agent.post(&t, "/tailscale/apply", &body).await {
            Ok(r) => r,
            Err(e) => {
                // A node may have registered before the failure: log it out, then close the hole.
                let _ = self.agent.post(&t, "/tailscale/logout", &json!({})).await;
                {
                    let mut st = self.st();
                    Self::agents(&mut st).shift_remove(&p.vm_id);
                    self.save(&st)?;
                }
                (self.on_changed)().await?;
                return Err(e.to_string());
            }
        };
        let s = |v: Option<&Value>| v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
        let node_raw = r.get("node").and_then(Value::as_object).cloned().unwrap_or_default();
        let node = json!({"name": s(node_raw.get("name")), "ip": s(node_raw.get("ip"))});
        let ssh = r.get("ssh") == Some(&Value::Bool(true));
        {
            let mut st = self.st();
            if let Some(e) = Self::agents(&mut st).get_mut(&p.vm_id).and_then(Value::as_object_mut) {
                e.insert("node".into(), node.clone());
                e.insert("ssh".into(), json!(ssh));
            }
            self.save(&st)?;
        }
        let shown = node["name"]
            .as_str()
            .or(node["ip"].as_str())
            .unwrap_or("an unnamed node")
            .to_string();
        tracing::info!(
            "[tailscale] {} joined as {shown} (ssh {})",
            p.name,
            if ssh { "on" } else { "off" }
        );
        Ok(obj(&[("vmId", json!(p.vm_id)), ("ssh", json!(ssh)), ("node", node)]))
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
            tracing::info!(
                "[tailscale] code sent for {} on {} via {sent_via}",
                if p.join { "join" } else { "leave" },
                p.name
            );
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(vm_id)) = (text(&payload, "changeId"), text(&payload, "vmId")) else {
            return CommandOutcome::failed("failed", "malformed tailscale.confirm payload");
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
        // The pending proposal holds the auth key in memory; cancelling drops it with the code.
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
        let p = |v: Value| parse(v.as_object().expect("obj"));
        assert_eq!(
            p(json!({"changeId": "c", "kind": "join"})).expect_err("x"),
            "malformed tailscale.propose payload"
        );
        assert_eq!(
            p(json!({"changeId": "c", "kind": "join", "agent": {"vmId": "v", "hostname": "h"}})).expect_err("key"),
            "a join needs an auth key"
        );
        let j = p(json!({"changeId": "c", "kind": "join", "ssh": true, "authKey": "tskey", "agent": {"vmId": "v", "hostname": "h", "name": "atlas"}})).expect("ok");
        assert_eq!(summarize(&j), "Put atlas on your Tailscale network, with Tailscale SSH");
        assert_eq!(j.tailnet_hostname, "atlas");
        assert_eq!(parse(j.to_json().as_object().expect("obj")).expect("back"), j);
        let l = p(json!({"changeId": "c", "kind": "leave", "agent": {"vmId": "v", "hostname": "h"}})).expect("ok");
        assert_eq!(summarize(&l), "Take v off your Tailscale network");
    }
}
