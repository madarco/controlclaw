//! Which agents may use the organization's brain (`gbrain.ts`). Connecting (or widening to read
//! and write) takes a code; narrowing and disconnecting do not. The boxes' addresses come from the
//! proxy's identity map, never from the command. The emergency stop reaches the brain as a lock on
//! its gate, and `reconcile` makes the gate match the store every five minutes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget, GBRAIN_APPLY_MS, GBRAIN_CONNECT_MS};
use super::consent::iso;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE_PREFIX: &str = "gbrain:";
pub const GBRAIN_GATE_PORT: u16 = 3131;
pub const GBRAIN_RECONCILE_MS: u64 = 5 * 60_000;

/// The proxy's identity map, brain and agents both.
pub type Boxes = Arc<dyn Fn() -> Vec<Value> + Send + Sync>;
/// The kill switch's lock: `(all, vmIds)`.
pub type Lock = Arc<dyn Fn() -> (bool, Vec<String>) + Send + Sync>;

#[derive(Debug, Clone, PartialEq)]
struct BoxRef {
    vm_id: String,
    ip: String,
    name: String,
    hostname: String,
}

impl BoxRef {
    fn target(&self) -> AgentTarget {
        AgentTarget::new(&self.vm_id, &self.hostname)
    }
    fn to_json(&self) -> Value {
        json!({"vmId": self.vm_id, "ip": self.ip, "name": self.name, "hostname": self.hostname})
    }
    fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            vm_id: text(o, "vmId")?,
            ip: text(o, "ip")?,
            name: text(o, "name")?,
            hostname: text(o, "hostname")?,
        })
    }
}

fn name_of<'a>(c: &'a Value, vm: &'a str) -> &'a str {
    c.get("name").and_then(Value::as_str).unwrap_or(vm)
}

fn brain_url(ip: &str) -> String {
    format!("http://{ip}:{GBRAIN_GATE_PORT}/mcp")
}

/// `summarize`.
fn summarize(rescope: bool, scope: &str, agent: &str) -> String {
    match (rescope, scope == "read_write") {
        (true, true) => format!("Let {agent} write to your organization's brain as well as read it"),
        (true, false) => format!("Make {agent} read-only on your organization's brain"),
        (false, true) => format!(
            "Connect {agent} to your organization's brain (read and write). It will see what your other agents saved"
        ),
        (false, false) => {
            format!("Let {agent} read your organization's brain. It will see what your other agents saved")
        }
    }
}

fn empty_store() -> Map<String, Value> {
    obj(&[
        ("version", json!(1)),
        ("brain", Value::Null),
        ("connections", json!({})),
    ])
}

struct State {
    store: Map<String, Value>,
    pushed_lock: Option<String>,
}

pub struct Brain {
    path: PathBuf,
    box_key: String,
    aad: String,
    state: Mutex<State>,
    agent: AgentClient,
    kit: Kit,
    boxes: Boxes,
    lock: Lock,
    /// One push of the lock at a time, and one reconcile.
    lock_chain: tokio::sync::Mutex<()>,
    reconciling: tokio::sync::Mutex<()>,
    running: tokio::sync::Mutex<()>,
}

impl Brain {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: Kit,
        boxes: Boxes,
        lock: Lock,
    ) -> Self {
        let aad = format!("{org}:{box_id}:gbrain");
        let log = |l: &str| tracing::error!("{l}");
        let store = match cc_crypto::enc_file::load_store_or_empty("gbrain", &path, box_key, &aad, &log) {
            Some(Value::Object(o))
                if o.get("version").and_then(Value::as_f64) == Some(1.0)
                    && o.get("connections").is_some_and(super::sync::js_truthy) =>
            {
                obj(&[
                    ("version", json!(1)),
                    ("brain", o.get("brain").cloned().unwrap_or(Value::Null)),
                    ("connections", o.get("connections").cloned().unwrap_or(json!({}))),
                ])
            }
            _ => empty_store(),
        };
        Self {
            path,
            box_key: box_key.into(),
            aad,
            state: Mutex::new(State {
                store,
                pushed_lock: None,
            }),
            agent,
            kit,
            boxes,
            lock,
            lock_chain: tokio::sync::Mutex::new(()),
            reconciling: tokio::sync::Mutex::new(()),
            running: tokio::sync::Mutex::new(()),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st().store.clone();
        self.save(&s);
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, store: &Map<String, Value>) {
        if let Err(e) = cc_crypto::enc_file::save_store(
            "gbrain",
            &self.path,
            &Value::Object(store.clone()),
            &self.box_key,
            &self.aad,
        ) {
            tracing::error!("[gbrain] could not save the store: {e}");
        }
    }

    fn brain(&self) -> Option<(String, String)> {
        let st = self.st();
        let b = st.store.get("brain")?.as_object()?;
        Some((text(b, "vmId")?, text(b, "ip")?))
    }

    fn connections(&self) -> Map<String, Value> {
        self.st()
            .store
            .get("connections")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    }

    fn set_connections(st: &mut State, c: Map<String, Value>) {
        st.store.insert("connections".into(), Value::Object(c));
    }

    /// `summary`.
    pub fn summary(&self) -> Value {
        json!({"brain": self.brain().map(|b| b.0), "connections": self.connections().len()})
    }

    fn row(&self, vm_id: &str) -> Option<Map<String, Value>> {
        (self.boxes)()
            .into_iter()
            .filter_map(|b| b.as_object().cloned())
            .find(|b| b.get("vm_id").and_then(Value::as_str) == Some(vm_id))
    }

    /// `box`: from the identity map, with an address.
    fn find(&self, vm_id: &str, brain: bool) -> Result<BoxRef, String> {
        let what = if brain { "The brain" } else { "That agent" };
        let role = if brain { "gbrain" } else { "openclaw" };
        let row = self.row(vm_id).filter(|r| {
            let r_role = match r.get("role") {
                None | Some(Value::Null) => "openclaw".to_string(),
                Some(v) => super::activity_sanitize::js_string(Some(v)),
            };
            r_role == role
        });
        let Some(row) = row else {
            return Err(format!(
                "{what} is not known to your firewall yet. Try again in a minute."
            ));
        };
        let (Some(ip), Some(hostname)) = (text(&row, "private_ip"), text(&row, "hostname")) else {
            return Err(format!(
                "{what} has no private address yet. Try again once it is running."
            ));
        };
        Ok(BoxRef {
            vm_id: vm_id.into(),
            ip,
            name: text(&row, "name").unwrap_or_else(|| vm_id.to_string()),
            hostname,
        })
    }

    async fn apply(&self, scope: &str, agent: &BoxRef, brain: &BoxRef) -> Result<Map<String, Value>, String> {
        // A different brain from the one on record: what was confirmed for the old one is gone.
        {
            let mut st = self.st();
            let other = st
                .store
                .get("brain")
                .and_then(|b| b.get("vmId"))
                .and_then(Value::as_str)
                .is_some_and(|v| v != brain.vm_id);
            if other {
                st.store = empty_store();
            }
        }
        let had = self.connections().contains_key(&agent.vm_id);
        self.agent
            .post_within(
                &brain.target(),
                "/gbrain/connect",
                &json!({"vmId": agent.vm_id, "ip": agent.ip, "scope": scope}),
                GBRAIN_CONNECT_MS,
            )
            .await
            .map_err(|e| e.to_string())?;
        let same_brain = self.brain().is_some_and(|(v, ip)| v == brain.vm_id && ip == brain.ip);
        if !had || !same_brain {
            self.agent
                .post_within(
                    &agent.target(),
                    "/gbrain/apply",
                    &json!({"url": brain_url(&brain.ip)}),
                    GBRAIN_APPLY_MS,
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        {
            let mut st = self.st();
            if st.store.get("brain").is_none_or(Value::is_null) {
                st.store
                    .insert("brain".into(), json!({"vmId": brain.vm_id, "ip": brain.ip}));
            }
            let mut c = st
                .store
                .get("connections")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            c.insert(
                agent.vm_id.clone(),
                json!({"scope": scope, "ip": agent.ip, "name": agent.name, "at": iso(now_ms())}),
            );
            Self::set_connections(&mut st, c);
            let s = st.store.clone();
            self.save(&s);
        }
        tracing::info!("[gbrain] {} connected to the brain ({scope})", agent.name);
        Ok(obj(&[
            ("agentVmId", json!(agent.vm_id)),
            ("brainVmId", json!(brain.vm_id)),
            ("scope", json!(scope)),
            ("agentPrivateIp", json!(agent.ip)),
        ]))
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let scope = payload
            .get("scope")
            .and_then(Value::as_str)
            .filter(|s| *s == "read" || *s == "read_write");
        let (Some(change_id), Some(agent_vm), Some(brain_vm), Some(scope)) = (
            text(&payload, "changeId"),
            text(&payload, "agentVmId"),
            text(&payload, "brainVmId"),
            scope,
        ) else {
            return CommandOutcome::failed("failed", "malformed gbrain.propose payload");
        };
        let _one = self.running.lock().await;
        let mut data = obj(&[("changeId", json!(change_id))]);
        let (agent, brain) = match (self.find(&agent_vm, false), self.find(&brain_vm, true)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => return fail("failed", e, data),
        };
        let current = if self.brain().is_some_and(|b| b.0 == brain_vm) {
            self.connections().get(&agent_vm).cloned()
        } else {
            None
        };
        let rescope = current.is_some();
        let summary = summarize(rescope, scope, &agent.name);
        data.insert("summary".into(), json!(summary));
        let key = format!("{SCOPE_PREFIX}{agent_vm}");
        // Nothing to widen: the same scope, or narrowing to read only.
        if let Some(c) = &current
            && (c.get("scope").and_then(Value::as_str) == Some(scope) || scope == "read")
        {
            self.kit.consent.forget(&key);
            return match self.apply(scope, &agent, &brain).await {
                Ok(applied) => {
                    data.extend(applied);
                    data.insert("tofu".into(), json!(false));
                    ok("applied", data)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            self.kit.consent.forget(&key);
            return match self.apply(scope, &agent, &brain).await {
                Ok(applied) => {
                    data.extend(applied);
                    data.insert("tofu".into(), json!(true));
                    ok("applied", data)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        let proposal = json!({"changeId": change_id, "kind": if rescope { "rescope" } else { "connect" }, "scope": scope, "agent": agent.to_json(), "brain": brain.to_json()});
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: key,
                change_id,
                proposal,
                agent_name: agent.name.clone(),
                summary,
                routes,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[gbrain] code sent to connect {} via {sent_via}", agent.name);
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(agent_vm)) = (text(&payload, "changeId"), text(&payload, "agentVmId")) else {
            return CommandOutcome::failed("failed", "malformed gbrain.confirm payload");
        };
        let _one = self.running.lock().await;
        let data = obj(&[("changeId", json!(change_id))]);
        let code = text(&payload, "code").unwrap_or_default();
        match self
            .kit
            .consent
            .verify(&format!("{SCOPE_PREFIX}{agent_vm}"), &change_id, &code)
        {
            CodeCheck::Expired => fail("expired", "No change is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let parts = (
                    proposal.get("agent").and_then(BoxRef::from_json),
                    proposal.get("brain").and_then(BoxRef::from_json),
                    proposal.get("scope").and_then(Value::as_str),
                );
                let (Some(agent), Some(brain), Some(scope)) = parts else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                let rescope = proposal.get("kind").and_then(Value::as_str) == Some("rescope");
                match self.apply(scope, &agent, &brain).await {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize(rescope, scope, &agent.name)));
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
        if let Some(vm) = text(&payload, "agentVmId") {
            self.kit
                .consent
                .cancel(&format!("{SCOPE_PREFIX}{vm}"), change_id.as_deref());
        }
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }

    /// `gbrain.disconnect`: no code. Out of the store first; reconcile finishes what fails here.
    pub async fn disconnect(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(vm) = text(&payload, "agentVmId") else {
            return CommandOutcome::failed("failed", "malformed gbrain.disconnect payload");
        };
        let _one = self.running.lock().await;
        self.kit.consent.forget(&format!("{SCOPE_PREFIX}{vm}"));
        let had = {
            let mut st = self.st();
            let mut c = st
                .store
                .get("connections")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let had = c.shift_remove(&vm);
            Self::set_connections(&mut st, c);
            let s = st.store.clone();
            self.save(&s);
            had
        };
        let mut errors = Vec::new();
        if let Some((brain_vm, _)) = self.brain() {
            let r = match self.find(&brain_vm, true) {
                Ok(b) => self
                    .agent
                    .post_within(
                        &b.target(),
                        "/gbrain/disconnect",
                        &json!({"vmId": vm}),
                        GBRAIN_CONNECT_MS,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            if let Err(e) = r {
                errors.push(format!("brain: {e}"));
            }
        }
        if let Some(host) = self.row(&vm).and_then(|r| text(&r, "hostname"))
            && let Err(e) = self
                .agent
                .post_within(
                    &AgentTarget::new(&vm, &host),
                    "/gbrain/apply",
                    &json!({"remove": true}),
                    GBRAIN_APPLY_MS,
                )
                .await
        {
            errors.push(format!("agent: {e}"));
        }
        let name = had
            .as_ref()
            .and_then(|h| h.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(&vm)
            .to_string();
        tracing::info!(
            "[gbrain] {name} disconnected from the brain{}",
            if errors.is_empty() {
                String::new()
            } else {
                format!(" (to finish on the next reconcile: {})", errors.join("; "))
            }
        );
        ok(
            "applied",
            obj(&[
                ("agentVmId", json!(vm)),
                ("removed", json!(had.is_some())),
                ("pending", json!(!errors.is_empty())),
            ]),
        )
    }

    fn desired_lock(&self) -> (bool, Vec<String>) {
        let (all, mut ids) = (self.lock)();
        ids.sort();
        ids.dedup();
        (all, ids)
    }

    fn brain_vm(&self) -> Option<String> {
        let stored = self
            .st()
            .store
            .get("brain")
            .and_then(|b| b.get("vmId"))
            .and_then(Value::as_str)
            .map(str::to_string);
        stored.or_else(|| {
            (self.boxes)()
                .into_iter()
                .find(|b| b.get("role").and_then(Value::as_str) == Some("gbrain"))
                .and_then(|b| b.get("vm_id").and_then(Value::as_str).map(str::to_string))
        })
    }

    /// `syncLock`: push the emergency stop to the brain's gate when it differs from what it holds.
    pub async fn sync_lock(&self) -> Result<(), String> {
        let _one = self.lock_chain.lock().await;
        let Some(brain_vm) = self.brain_vm() else { return Ok(()) };
        let (all, ids) = self.desired_lock();
        let want = json!({"all": all, "vmIds": ids});
        let key = format!("{brain_vm}|{want}");
        if self.st().pushed_lock.as_deref() == Some(key.as_str()) {
            return Ok(());
        }
        let brain = self.find(&brain_vm, true)?;
        self.agent
            .post_within(&brain.target(), "/gbrain/lock", &want, GBRAIN_CONNECT_MS)
            .await
            .map_err(|e| e.to_string())?;
        self.st().pushed_lock = Some(key);
        tracing::info!(
            "[gbrain] brain gate lock: {}",
            if all {
                "every agent".to_string()
            } else if ids.is_empty() {
                "none".to_string()
            } else {
                ids.join(", ")
            }
        );
        Ok(())
    }

    async fn remove_from_agent(&self, vm: &str) -> Result<(), String> {
        let Some(host) = self.row(vm).and_then(|r| text(&r, "hostname")) else {
            return Ok(());
        };
        self.agent
            .post_within(
                &AgentTarget::new(vm, &host),
                "/gbrain/apply",
                &json!({"remove": true}),
                GBRAIN_APPLY_MS,
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// `reconcile`: the gate matches the store; only removes access or re-points confirmed access.
    pub async fn reconcile(&self) -> Result<(), String> {
        let Ok(_one) = self.reconciling.try_lock() else {
            return Ok(());
        };
        let boxes = (self.boxes)();
        if boxes.is_empty() {
            return Ok(());
        }
        let stored = self.brain();
        let brain_row = boxes
            .iter()
            .find(|b| b.get("role").and_then(Value::as_str) == Some("gbrain"))
            .cloned();
        let row_vm = brain_row
            .as_ref()
            .and_then(|b| b.get("vm_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some((svm, _)) = &stored
            && row_vm.as_deref() != Some(svm.as_str())
        {
            let conns = self.connections();
            for (vm, c) in &conns {
                if let Err(e) = self.remove_from_agent(vm).await {
                    tracing::info!("[gbrain] could not take the brain off {}: {e}", name_of(c, vm));
                }
            }
            tracing::info!(
                "[gbrain] the brain {svm} is gone; dropped {} connection(s)",
                conns.len()
            );
            let mut st = self.st();
            st.store = empty_store();
            let s = st.store.clone();
            self.save(&s);
            st.pushed_lock = None;
            return Ok(());
        }
        let (Some((svm, sip)), Some(_)) = (stored, brain_row) else {
            return Ok(());
        };
        let brain = self.find(&svm, true)?;
        let mut changed = false;
        let mut conns = self.connections();
        let gone: Vec<String> = conns
            .keys()
            .filter(|vm| {
                !boxes.iter().any(|b| {
                    b.get("vm_id").and_then(Value::as_str) == Some(vm.as_str())
                        && b.get("role").and_then(Value::as_str).unwrap_or("openclaw") == "openclaw"
                })
            })
            .cloned()
            .collect();
        for vm in &gone {
            tracing::info!(
                "[gbrain] {} is gone; disconnecting it",
                conns.get(vm).map_or(vm.as_str(), |c| name_of(c, vm))
            );
            conns.shift_remove(vm);
            changed = true;
        }
        let mut new_brain = None;
        if brain.ip != sip {
            let mut all = true;
            for (vm, c) in &conns {
                let r = match self.find(vm, false) {
                    Ok(a) => self
                        .agent
                        .post_within(
                            &a.target(),
                            "/gbrain/apply",
                            &json!({"url": brain_url(&brain.ip)}),
                            GBRAIN_APPLY_MS,
                        )
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e),
                };
                if let Err(e) = r {
                    all = false;
                    tracing::info!(
                        "[gbrain] could not re-point {} at the brain's new address: {e}",
                        name_of(c, vm)
                    );
                }
            }
            if all {
                new_brain = Some(json!({"vmId": brain.vm_id, "ip": brain.ip}));
                changed = true;
            }
        }
        if changed {
            // Into the live store: a connection confirmed during the calls above stays.
            let mut st = self.st();
            let mut live = st
                .store
                .get("connections")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            live.retain(|vm, _| !gone.contains(vm));
            Self::set_connections(&mut st, live);
            if let Some(b) = new_brain {
                st.store.insert("brain".into(), b);
            }
            let s = st.store.clone();
            self.save(&s);
        }
        let r = self
            .agent
            .get_within(&brain.target(), "/gbrain/connections", GBRAIN_CONNECT_MS)
            .await
            .map_err(|e| e.to_string())?;
        let entries: Vec<Map<String, Value>> = r
            .get("connections")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(|e| e.as_object().cloned()).collect())
            .unwrap_or_default();
        if let Some(rep) = r.get("lock").and_then(Value::as_object) {
            let mut ids: Vec<String> = rep
                .get("vmIds")
                .and_then(Value::as_array)
                .map(|l| l.iter().map(|x| super::activity_sanitize::js_string(Some(x))).collect())
                .unwrap_or_default();
            ids.sort();
            if (rep.get("all") == Some(&Value::Bool(true)), ids) != self.desired_lock() {
                self.st().pushed_lock = None;
            }
        }
        let gate: Vec<(String, Map<String, Value>)> = entries
            .into_iter()
            .map(|e| (super::activity_sanitize::js_string(e.get("vmId")), e))
            .collect();
        for (vm, _) in &gate {
            if !conns.contains_key(vm) {
                self.agent
                    .post_within(
                        &brain.target(),
                        "/gbrain/disconnect",
                        &json!({"vmId": vm}),
                        GBRAIN_CONNECT_MS,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                tracing::info!("[gbrain] removed {vm} from the brain's gate: it is not connected");
            }
        }
        for (vm, c) in &conns {
            let Ok(agent) = self.find(vm, false) else { continue };
            let scope = c.get("scope").and_then(Value::as_str).unwrap_or("read").to_string();
            let on = gate.iter().find(|(v, _)| v == vm).map(|(_, e)| e);
            if on.is_some_and(|e| {
                e.get("ip").and_then(Value::as_str) == Some(agent.ip.as_str())
                    && e.get("scope").and_then(Value::as_str) == Some(scope.as_str())
            }) {
                continue;
            }
            self.agent
                .post_within(
                    &brain.target(),
                    "/gbrain/connect",
                    &json!({"vmId": vm, "ip": agent.ip, "scope": scope}),
                    GBRAIN_CONNECT_MS,
                )
                .await
                .map_err(|e| e.to_string())?;
            if c.get("ip").and_then(Value::as_str) != Some(agent.ip.as_str()) {
                let mut st = self.st();
                let mut all = st
                    .store
                    .get("connections")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                if let Some(entry) = all.get_mut(vm).and_then(Value::as_object_mut) {
                    entry.insert("ip".into(), json!(agent.ip));
                }
                Self::set_connections(&mut st, all);
                let s = st.store.clone();
                self.save(&s);
            }
            tracing::info!(
                "[gbrain] re-applied {}'s connection on the brain's gate",
                name_of(c, vm)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries() {
        assert_eq!(
            summarize(false, "read", "atlas"),
            "Let atlas read your organization's brain. It will see what your other agents saved"
        );
        assert_eq!(
            summarize(true, "read", "atlas"),
            "Make atlas read-only on your organization's brain"
        );
        assert_eq!(brain_url("10.0.0.9"), "http://10.0.0.9:3131/mcp");
    }
}
