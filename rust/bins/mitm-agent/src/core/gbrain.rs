//! Which agents may use the organization's brain (`gbrain.ts`). Connecting (or widening to read
//! and write) takes a code; narrowing and disconnecting do not. The boxes' addresses come from the
//! proxy's identity map, never from the command. The emergency stop reaches the brain as a lock on
//! its gate, and `reconcile` makes the gate match the store every five minutes.
//!
//! On a standalone firewall (docs/plans/standalone-brain.md B) the agents are not on a network the
//! brain shares: their `gbrain` MCP entry is this firewall's tools gate (`/brain/mcp` on 3940), which
//! relays each call to the brain (`integrations/tools_gate.rs`). The admin's own lock (`gbrain.lock`)
//! takes every agent off the brain on top of the emergency stop, and `gbrain.read|status|model`
//! serve the panel. Outside AI apps stay the SaaS's.
//!
//! Outside AI apps (T-219, `gbrain.client.*`) are the same idea on the brain's public MCP address:
//! approving an app's sign-in, widening it to read and write or moving its end date later takes a
//! code; narrowing and removing do not. The app's name and site come from the brain, not from the
//! command, and the code message keeps them apart from the firewall's own words.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget, GBRAIN_APPLY_MS, GBRAIN_CONNECT_MS};
use super::code_message::{CodeParts, TypedLine};
use super::consent::iso;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE_PREFIX: &str = "gbrain:";
const CLIENT_SCOPE_PREFIX: &str = "gbrain-client:";
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
            // A standalone firewall's boxes have none (it calls them at their paired address).
            hostname: o
                .get("hostname")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

fn name_of<'a>(c: &'a Value, vm: &'a str) -> &'a str {
    c.get("name").and_then(Value::as_str).unwrap_or(vm)
}

fn brain_url(ip: &str) -> String {
    format!("http://{ip}:{GBRAIN_GATE_PORT}/mcp")
}

use crate::integrations::tools_gate::{BRAIN_PATH as GATE_BRAIN_PATH, CONTROLPLANE_MCP_GATE_PORT as TOOLS_GATE_PORT};
/// The brain's console routes a standalone firewall calls (`/health`, `/brain/model`).
const CONSOLE_MS: u64 = 5_000;
/// The panel's read of the brain's gate: the page polls it, so a brain that is down is said quickly.
const READ_MS: u64 = 5_000;
/// A model change: five `gbrain config set` and a restart, on the brain.
const MODEL_MS: u64 = 100_000;

/// Where agents reach the brain: the SaaS's private network, or a standalone firewall's gate.
#[derive(Debug, Clone, PartialEq)]
enum Reach {
    Private,
    /// The tools gate's address (`CONNECTOR_GATE_BIND`), when there is one.
    Gate(Option<String>),
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
        ("clients", json!({})),
        ("locked", json!(false)),
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
    reach: Reach,
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
                    ("clients", o.get("clients").cloned().unwrap_or(json!({}))),
                    ("locked", json!(o.get("locked") == Some(&json!(true)))),
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
            reach: Reach::Private,
            lock_chain: tokio::sync::Mutex::new(()),
            reconciling: tokio::sync::Mutex::new(()),
            running: tokio::sync::Mutex::new(()),
        }
    }

    /// A standalone firewall: agents reach the brain on this firewall's tools gate at `gate` (its
    /// `CONNECTOR_GATE_BIND`), and the firewall calls the boxes at their paired address.
    pub fn standalone(mut self, gate: Option<String>) -> Self {
        self.reach = Reach::Gate(gate.filter(|g| !g.is_empty()));
        self
    }

    fn is_standalone(&self) -> bool {
        matches!(self.reach, Reach::Gate(_))
    }

    /// The `gbrain` MCP entry an agent gets.
    fn agent_url(&self, brain_ip: &str) -> Result<String, String> {
        match &self.reach {
            Reach::Private => Ok(brain_url(brain_ip)),
            Reach::Gate(Some(g)) => Ok(format!("http://{g}:{TOOLS_GATE_PORT}{GATE_BRAIN_PATH}")),
            Reach::Gate(None) => Err(
                "Agents reach the brain through this firewall's tools gate, which is off: set CONNECTOR_GATE_BIND."
                    .into(),
            ),
        }
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

    fn clients(&self) -> Map<String, Value> {
        self.st()
            .store
            .get("clients")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    }

    /// `summary`.
    pub fn summary(&self) -> Value {
        json!({"brain": self.brain().map(|b| b.0), "connections": self.connections().len(), "clients": self.clients().len()})
    }

    fn row(&self, vm_id: &str) -> Option<Map<String, Value>> {
        (self.boxes)()
            .into_iter()
            .filter_map(|b| b.as_object().cloned())
            .find(|b| b.get("vm_id").and_then(Value::as_str) == Some(vm_id))
    }

    /// The hostname an agent's calls are signed for: the map's; on a standalone firewall, which
    /// calls its agents at their paired address, none is needed while the agent is in the map.
    fn agent_host(&self, vm_id: &str) -> Option<String> {
        let row = self.row(vm_id)?;
        text(&row, "hostname").or_else(|| self.is_standalone().then(String::new))
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
        // A standalone firewall calls a box only at its paired address: an agent paired across a
        // network in host or proxy mode has none.
        if self.is_standalone() && text(&row, "agent_addr").is_none() {
            return Err(format!(
                "{what} cannot be reached by your firewall: connect it in remote mode, or on the firewall's own machine."
            ));
        }
        // A standalone firewall calls its boxes at their paired address, not a hostname.
        let hostname = text(&row, "hostname").or_else(|| self.is_standalone().then(String::new));
        let (Some(ip), Some(hostname)) = (text(&row, "private_ip"), hostname) else {
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
        let url = self.agent_url(&brain.ip)?;
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
                .post_within(&agent.target(), "/gbrain/apply", &json!({"url": url}), GBRAIN_APPLY_MS)
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
        if let Some(id) = text(&payload, "clientId") {
            self.kit
                .consent
                .cancel(&format!("{CLIENT_SCOPE_PREFIX}{id}"), change_id.as_deref());
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
        if let Some(host) = self.agent_host(&vm)
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
        let all = all || self.admin_locked();
        ids.sort();
        ids.dedup();
        (all, ids)
    }

    pub fn brain_vm(&self) -> Option<String> {
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

    /// The admin's own lock (`gbrain.lock`, a standalone firewall's panel): every agent off the
    /// brain, connections kept.
    pub fn admin_locked(&self) -> bool {
        self.st().store.get("locked") == Some(&json!(true))
    }

    /// `gbrain.lock {locked}`: no code, as the emergency stop. Pushed to the brain at once.
    pub async fn set_admin_lock(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(locked) = payload.get("locked").and_then(Value::as_bool) else {
            return CommandOutcome::failed("failed", "malformed gbrain.lock payload");
        };
        {
            let mut st = self.st();
            st.store.insert("locked".into(), json!(locked));
            let s = st.store.clone();
            self.save(&s);
        }
        tracing::info!(
            "[gbrain] {} by the admin",
            if locked {
                "every agent locked out of the brain"
            } else {
                "the brain unlocked"
            }
        );
        let pushed = self.sync_lock().await;
        let mut data = obj(&[("locked", json!(locked)), ("pushed", json!(pushed.is_ok()))]);
        if let Err(e) = pushed {
            // The firewall's gate refuses at once anyway; the brain gets it on the next reconcile.
            tracing::info!("[gbrain] the brain did not take the lock yet: {e}");
            data.insert("pending".into(), json!(e));
        }
        ok("applied", data)
    }

    /// What the tools gate asks before relaying an agent's call: the brain's vm id, or why not.
    /// The emergency stop and the admin's lock are checked here too, before anything is sent.
    pub fn relay_for(&self, agent_vm: &str) -> Result<String, &'static str> {
        let Some((brain_vm, _)) = self.brain() else {
            return Err("not connected");
        };
        if !self.connections().contains_key(agent_vm) {
            return Err("not connected");
        }
        let (all, ids) = self.desired_lock();
        if all || ids.iter().any(|v| v == agent_vm) {
            return Err("locked");
        }
        Ok(brain_vm)
    }

    /// How long the brain may take to start answering a relayed call (it then streams).
    pub const RELAY_CONNECT_MS: u64 = 600_000;

    /// `gbrain.read`: the brain on record, the connections, the locks, and what the brain's gate
    /// holds when it answers. No tokens: the brain never sends them.
    pub async fn read(&self) -> CommandOutcome {
        let brain_vm = self.brain_vm();
        let (stop_all, stop_ids) = (self.lock)();
        let mut data = obj(&[
            ("brain", json!(brain_vm)),
            ("connections", Value::Object(self.connections())),
            ("locked", json!(self.admin_locked())),
            ("stopped", json!({"all": stop_all, "vmIds": stop_ids})),
            ("gateUrl", self.agent_url("").map_or(Value::Null, Value::String)),
        ]);
        if let Some(vm) = brain_vm
            && let Ok(b) = self.find(&vm, true)
        {
            match self.agent.get_within(&b.target(), "/gbrain/connections", READ_MS).await {
                Ok(r) => {
                    data.insert("gate".into(), Value::Object(r));
                }
                Err(e) => {
                    data.insert("gateError".into(), json!(e.to_string()));
                }
            }
        }
        ok("read", data)
    }

    /// `gbrain.status`: the brain's own `/health` (GBrain and Postgres), as its console would read it.
    pub async fn status(&self) -> CommandOutcome {
        let Some(vm) = self.brain_vm() else {
            return CommandOutcome::failed("failed", "There is no brain paired with this firewall.");
        };
        let b = match self.find(&vm, true) {
            Ok(b) => b,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        match self
            .agent
            .console_within(&b.target(), "GET", "/health", None, CONSOLE_MS)
            .await
        {
            Ok(r) => ok("read", obj(&[("brain", json!(vm)), ("health", Value::Object(r))])),
            Err(e) => CommandOutcome::failed("failed", e.to_string()),
        }
    }

    /// `gbrain.model {model}`: the brain's model, on the brain's own console route.
    pub async fn model(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(model) = text(&payload, "model") else {
            return CommandOutcome::failed("failed", "malformed gbrain.model payload");
        };
        let Some(vm) = self.brain_vm() else {
            return CommandOutcome::failed("failed", "There is no brain paired with this firewall.");
        };
        let b = match self.find(&vm, true) {
            Ok(b) => b,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        match self
            .agent
            .console_within(
                &b.target(),
                "POST",
                "/brain/model",
                Some(&json!({"model": model})),
                MODEL_MS,
            )
            .await
        {
            Ok(r) => ok("applied", r),
            Err(e) => CommandOutcome::failed("failed", e.to_string()),
        }
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
        let Some(host) = self.agent_host(vm) else {
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
        if !self.is_standalone()
            && let Err(e) = self.reconcile_clients(&brain).await
        {
            tracing::info!("[gbrain] could not check the brain's outside apps: {e}");
        }
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
        if brain.ip != sip && self.is_standalone() {
            // The agents' entry is this firewall's gate, which follows the brain by itself.
            new_brain = Some(json!({"vmId": brain.vm_id, "ip": brain.ip}));
            changed = true;
        } else if brain.ip != sip {
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

/// An outside app's id: the console's `brain_client.id`.
fn client_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 48 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn ms_of(v: Option<&Value>) -> Option<i64> {
    v.and_then(Value::as_str)
        .and_then(super::ssh::parse_iso_ms)
        .map(|m| m as i64)
}

/// `read and write, until 2026-12-31` / `read only, no end date`.
fn client_access(scope: &str, until: Option<&str>) -> String {
    format!(
        "{}, {}",
        if scope == "read_write" {
            "read and write"
        } else {
            "read only"
        },
        until
            .map(|u| format!("until {}", u.get(..10).unwrap_or(u)))
            .unwrap_or_else(|| "no end date".into())
    )
}

/// The firewall's own line for an outside app's change. `name` is the app's, as the brain has it.
fn summarize_client(rescope: bool, scope: &str, until: Option<&str>, name: &str) -> String {
    let access = client_access(scope, until);
    if rescope {
        format!("Change the app {name}'s access to your organization's brain: {access}")
    } else {
        format!("Connect the app {name} to your organization's brain ({access}). It will see everything in the brain")
    }
}

/// Whether going from `current` to (`scope`, `until`) gives the app more than it has: a new app,
/// read only to read and write, or a later end date (none is the latest).
fn client_widens(current: Option<&Value>, scope: &str, until: Option<i64>) -> bool {
    let Some(c) = current else { return true };
    if scope == "read_write" && c.get("scope").and_then(Value::as_str) != Some("read_write") {
        return true;
    }
    match (ms_of(c.get("expiresAt")), until) {
        (Some(_), None) => true,
        (Some(cur), Some(new)) => new > cur,
        (None, _) => false,
    }
}

impl Brain {
    fn set_clients(st: &mut State, c: Map<String, Value>) {
        st.store.insert("clients".into(), Value::Object(c));
    }

    /// What the brain says about a waiting sign-in: the app's name and the site it returns to.
    async fn client_request(&self, brain: &BoxRef, req: &str) -> Result<(String, String), String> {
        let r = self
            .agent
            .post_within(
                &brain.target(),
                "/gbrain/clients/request",
                &json!({"req": req}),
                GBRAIN_CONNECT_MS,
            )
            .await
            .map_err(|e| e.to_string())?;
        let info = r
            .get("request")
            .and_then(Value::as_object)
            .ok_or("The brain has no such sign-in.")?;
        Ok((
            text(info, "name").unwrap_or_else(|| "MCP client".into()),
            text(info, "site").unwrap_or_default(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn client_apply(
        &self,
        id: &str,
        req: Option<&str>,
        approval: Option<&str>,
        scope: &str,
        until: Option<&str>,
        name: &str,
        site: &str,
        person: Option<&str>,
        brain: &BoxRef,
    ) -> Result<Map<String, Value>, String> {
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
        self.agent
            .post_within(
                &brain.target(),
                "/gbrain/clients/connect",
                &json!({"id": id, "req": req, "approval": approval, "scope": scope, "expiresAt": until}),
                GBRAIN_CONNECT_MS,
            )
            .await
            .map_err(|e| e.to_string())?;
        {
            let mut st = self.st();
            if st.store.get("brain").is_none_or(Value::is_null) {
                st.store
                    .insert("brain".into(), json!({"vmId": brain.vm_id, "ip": brain.ip}));
            }
            let mut c = st
                .store
                .get("clients")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            c.insert(
                id.into(),
                json!({"scope": scope, "expiresAt": until, "name": name, "site": site, "person": person, "at": iso(now_ms())}),
            );
            Self::set_clients(&mut st, c);
            let s = st.store.clone();
            self.save(&s);
        }
        tracing::info!(
            "[gbrain] the app {name} may use the brain ({})",
            client_access(scope, until)
        );
        Ok(obj(&[
            ("clientId", json!(id)),
            ("brainVmId", json!(brain.vm_id)),
            ("scope", json!(scope)),
            ("expiresAt", json!(until)),
            ("name", json!(name)),
            ("site", json!(site)),
        ]))
    }

    /// `gbrain.client.propose`: approve an app's sign-in (`req`), or change an app's scope or end
    /// date. A sign-in always takes a code (it hands the brain to whoever holds the app's side of
    /// it), and so does any widening.
    pub async fn client_propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let scope = payload
            .get("scope")
            .and_then(Value::as_str)
            .filter(|s| *s == "read" || *s == "read_write");
        let (Some(change_id), Some(id), Some(brain_vm), Some(scope)) = (
            text(&payload, "changeId"),
            text(&payload, "clientId").filter(|i| client_id_ok(i)),
            text(&payload, "brainVmId"),
            scope,
        ) else {
            return CommandOutcome::failed("failed", "malformed gbrain.client.propose payload");
        };
        let req = text(&payload, "req").filter(|r| r.len() <= 64);
        // With a sign-in: sha256 of the secret only the Connect page that asked holds. The brain
        // gives the one-time code only to a browser that shows it.
        let approval = text(&payload, "approval")
            .filter(|a| a.len() == 64 && a.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        if req.is_some() && approval.is_none() {
            return CommandOutcome::failed("failed", "malformed gbrain.client.propose payload: approval");
        }
        let until_ms = ms_of(payload.get("expiresAt"));
        if payload.get("expiresAt").is_some_and(|v| !v.is_null()) && until_ms.is_none() {
            return CommandOutcome::failed("failed", "expiresAt must be an ISO time");
        }
        let until = until_ms.map(|m| iso(m.max(0) as u64));
        let person = text(&payload, "person").map(|p| p.chars().take(80).collect::<String>());
        let _one = self.running.lock().await;
        let mut data = obj(&[("changeId", json!(change_id))]);
        let brain = match self.find(&brain_vm, true) {
            Ok(b) => b,
            Err(e) => return fail("failed", e, data),
        };
        let current = if self.brain().is_none_or(|b| b.0 == brain_vm) {
            self.clients().get(&id).cloned()
        } else {
            None
        };
        let (name, site) = match (&req, &current) {
            (Some(r), _) => match self.client_request(&brain, r).await {
                Ok(x) => x,
                Err(e) => return fail("failed", e, data),
            },
            (None, Some(c)) => (
                c.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("MCP client")
                    .to_string(),
                c.get("site").and_then(Value::as_str).unwrap_or_default().to_string(),
            ),
            (None, None) => return fail("failed", "That app is not connected to the brain.", data),
        };
        let rescope = req.is_none();
        let summary = summarize_client(rescope, scope, until.as_deref(), &name);
        data.insert("summary".into(), json!(summary));
        data.insert("name".into(), json!(name));
        data.insert("site".into(), json!(site));
        let key = format!("{CLIENT_SCOPE_PREFIX}{id}");
        // Narrowing only: never on trust, as an app is never let in or widened without a code.
        let apply = || {
            let (name, site, person, until, req, approval) = (
                name.clone(),
                site.clone(),
                person.clone(),
                until.clone(),
                req.clone(),
                approval.clone(),
            );
            let (id, brain) = (id.clone(), brain.clone());
            let mut data = data.clone();
            async move {
                match self
                    .client_apply(
                        &id,
                        req.as_deref(),
                        approval.as_deref(),
                        scope,
                        until.as_deref(),
                        &name,
                        &site,
                        person.as_deref(),
                        &brain,
                    )
                    .await
                {
                    Ok(applied) => {
                        data.extend(applied);
                        data.insert("tofu".into(), json!(false));
                        ok("applied", data)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        };
        if req.is_none() && !client_widens(current.as_ref(), scope, until_ms) {
            self.kit.consent.forget(&key);
            return apply().await;
        }
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            // Unlike an agent's first change, an app is never let in or widened on trust: whoever
            // holds its side of the sign-in would get the brain with nobody having seen a code.
            let why = if req.is_some() {
                "Your firewall has nowhere to send a code. Connect Telegram, Slack or email to it first, then sign in from the app again."
            } else {
                "Your firewall has nowhere to send a code, so the app's access can only be narrowed (Read only, an earlier end date) or removed. Connect Telegram, Slack or email to it to widen it."
            };
            return fail("failed", why, data);
        }
        let proposal = json!({
            "changeId": change_id, "kind": if rescope { "rescope" } else { "connect" }, "clientId": id,
            "req": req, "approval": approval, "scope": scope, "expiresAt": until, "name": name, "site": site, "person": person,
            "brain": brain.to_json(),
        });
        // The name is the app's own choice at registration and the person is the console's word:
        // shown as what they claim, not as fact.
        let mut typed = vec![TypedLine {
            label: "Calls itself".into(),
            text: name.clone(),
            more: None,
        }];
        if !site.is_empty() {
            typed.push(TypedLine {
                label: "Signs in from".into(),
                text: site.clone(),
                more: None,
            });
        }
        if let Some(p) = &person {
            typed.push(TypedLine {
                label: "Asked for in the console by".into(),
                text: p.clone(),
                more: None,
            });
        }
        let ask = if rescope {
            format!(
                "Change an outside AI app's access to your organization's brain: {}.",
                client_access(scope, until.as_deref())
            )
        } else {
            format!(
                "Connect an outside AI app to your organization's brain ({}). It will see everything in the brain.",
                client_access(scope, until.as_deref())
            )
        };
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: key,
                change_id,
                proposal,
                agent_name: "your brain".into(),
                summary,
                routes,
                parts: Some(CodeParts {
                    ask,
                    typed,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[gbrain] code sent to connect an outside app via {sent_via}");
        }
        awaiting(sent, data)
    }

    pub async fn client_confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(id)) = (text(&payload, "changeId"), text(&payload, "clientId")) else {
            return CommandOutcome::failed("failed", "malformed gbrain.client.confirm payload");
        };
        let _one = self.running.lock().await;
        let data = obj(&[("changeId", json!(change_id))]);
        let code = text(&payload, "code").unwrap_or_default();
        match self
            .kit
            .consent
            .verify(&format!("{CLIENT_SCOPE_PREFIX}{id}"), &change_id, &code)
        {
            CodeCheck::Expired => fail("expired", "No change is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let p = |k: &str| proposal.get(k).and_then(Value::as_str).map(String::from);
                let (Some(brain), Some(scope), Some(name)) =
                    (proposal.get("brain").and_then(BoxRef::from_json), p("scope"), p("name"))
                else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                let (req, approval, until, site, person) = (
                    p("req"),
                    p("approval"),
                    p("expiresAt"),
                    p("site").unwrap_or_default(),
                    p("person"),
                );
                match self
                    .client_apply(
                        &id,
                        req.as_deref(),
                        approval.as_deref(),
                        &scope,
                        until.as_deref(),
                        &name,
                        &site,
                        person.as_deref(),
                        &brain,
                    )
                    .await
                {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert(
                            "summary".into(),
                            json!(summarize_client(req.is_none(), &scope, until.as_deref(), &name)),
                        );
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    /// `gbrain.client.disconnect`: no code. Out of the store first; reconcile finishes what fails.
    pub async fn client_disconnect(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(id) = text(&payload, "clientId").filter(|i| client_id_ok(i)) else {
            return CommandOutcome::failed("failed", "malformed gbrain.client.disconnect payload");
        };
        let _one = self.running.lock().await;
        self.kit.consent.forget(&format!("{CLIENT_SCOPE_PREFIX}{id}"));
        let had = {
            let mut st = self.st();
            let mut c = st
                .store
                .get("clients")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let had = c.shift_remove(&id);
            Self::set_clients(&mut st, c);
            let s = st.store.clone();
            self.save(&s);
            had
        };
        let mut pending = false;
        if let Some((brain_vm, _)) = self.brain() {
            let r = match self.find(&brain_vm, true) {
                Ok(b) => self
                    .agent
                    .post_within(
                        &b.target(),
                        "/gbrain/clients/disconnect",
                        &json!({"id": id}),
                        GBRAIN_CONNECT_MS,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            if let Err(e) = r {
                pending = true;
                tracing::info!(
                    "[gbrain] the app {id} is off the store; the brain will be told on the next reconcile: {e}"
                );
            }
        }
        ok(
            "applied",
            obj(&[
                ("clientId", json!(id)),
                ("removed", json!(had.is_some())),
                ("pending", json!(pending)),
            ]),
        )
    }

    /// The brain's apps match the store: any it has that the store lacks are removed, and any whose
    /// access is wider there than here is narrowed. Never widens and never adds.
    async fn reconcile_clients(&self, brain: &BoxRef) -> Result<(), String> {
        // Not while an app is being approved: between the brain's connect and the store's write,
        // the new app would look like one to remove.
        let _one = self.running.lock().await;
        let r = self
            .agent
            .get_within(&brain.target(), "/gbrain/clients", GBRAIN_CONNECT_MS)
            .await
            .map_err(|e| e.to_string())?;
        let on_brain: Vec<Map<String, Value>> = r
            .get("clients")
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(|e| e.as_object().cloned()).collect())
            .unwrap_or_default();
        let store = self.clients();
        for e in on_brain {
            let Some(id) = text(&e, "id") else { continue };
            match store.get(&id) {
                None => {
                    self.agent
                        .post_within(
                            &brain.target(),
                            "/gbrain/clients/disconnect",
                            &json!({"id": id}),
                            GBRAIN_CONNECT_MS,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    tracing::info!("[gbrain] removed the app {id} from the brain: it is not connected");
                }
                Some(want) => {
                    let scope = want.get("scope").and_then(Value::as_str).unwrap_or("read");
                    let until = ms_of(want.get("expiresAt"));
                    // Wider on the brain than here: put the store's access back.
                    let brain_side = json!({"scope": e.get("scope").cloned().unwrap_or(Value::Null), "expiresAt": e.get("expiresAt").cloned().unwrap_or(Value::Null)});
                    let wider = client_widens(
                        Some(&json!({"scope": scope, "expiresAt": want.get("expiresAt")})),
                        brain_side["scope"].as_str().unwrap_or("read"),
                        ms_of(brain_side.get("expiresAt")),
                    );
                    if wider {
                        self.agent
                            .post_within(
                                &brain.target(),
                                "/gbrain/clients/connect",
                                &json!({"id": id, "scope": scope, "expiresAt": until.map(|m| iso(m.max(0) as u64))}),
                                GBRAIN_CONNECT_MS,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                        tracing::info!("[gbrain] narrowed the app {id} on the brain back to {scope}");
                    }
                }
            }
        }
        Ok(())
    }
}

impl crate::contracts::BrainRelay for Brain {
    fn relay_for(&self, agent_vm: &str) -> Result<String, &'static str> {
        Brain::relay_for(self, agent_vm)
    }

    fn scope_of(&self, agent_vm: &str) -> Option<String> {
        self.connections()
            .get(agent_vm)
            .and_then(|c| c.get("scope"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    fn send(
        &self,
        brain_vm: String,
        agent_vm: String,
        method: String,
        headers: Vec<(&'static str, http::HeaderValue)>,
        body: bytes::Bytes,
    ) -> cc_http::BoxFuture<Result<reqwest::Response, String>> {
        let agent = self.agent.clone();
        Box::pin(async move {
            agent
                .relay_brain(&brain_vm, &agent_vm, &method, &headers, body, Self::RELAY_CONNECT_MS)
                .await
                .map_err(|e| e.to_string())
        })
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
