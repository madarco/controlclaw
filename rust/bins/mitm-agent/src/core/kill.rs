//! The kill switch, firewall side (`kill.ts`, `kill-store.ts`). The store says which agents are
//! under an emergency stop (or the whole organization); the sync turns it into the `locked` flag
//! the proxy checks on every connection, so nothing on the agent box is asked. Stopping OpenClaw
//! on the boxes is best effort, re-applied every minute.
//!
//! Engaging never needs a code (it only restricts). Releasing does, and when every agent is
//! stopped a release opens a window on one agent, its channel hosts only, for the life of the code.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget, KILL_WINDOW_RETRY_MS, KILL_WINDOW_SEND_MS};
use super::consent::{CODE_TTL_MS, iso};
use super::kit::{CHANNELS_UNREADABLE, awaiting, fail, ok};
use super::now_ms;
use super::sync::KillLocks;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRouteSource, CodeSender, CodeSent, ModuleCodes};

const SCOPE_ORG: &str = "kill:org";
const SCOPE_PREFIX: &str = "kill:agent:";
/// How often a locked box is checked and stopped again (a reboot starts OpenClaw).
pub const KILL_RECONCILE_MS: u64 = 60_000;

/// The store (`KillStore`), kept as JSON so fields this build does not know survive.
#[derive(Debug, Clone)]
struct Store(Map<String, Value>);

impl Store {
    fn empty() -> Self {
        Self(
            json!({"version": 1, "org": null, "agents": {}, "codeWindow": null})
                .as_object()
                .cloned()
                .unwrap_or_default(),
        )
    }

    /// `loadKillStore`: anything but a version-1 store with an `agents` map is an empty store (as
    /// the TS: an unreadable store has already been kept aside by `load_store_or_empty`), and only
    /// the four fields the TS keeps are kept.
    fn parse(v: Option<Value>) -> Self {
        let Some(Value::Object(o)) = v else {
            return Self::empty();
        };
        if o.get("version").and_then(Value::as_f64) != Some(1.0) || !o.get("agents").is_some_and(super::sync::js_truthy)
        {
            return Self::empty();
        }
        let mut s = Map::new();
        s.insert("version".into(), json!(1));
        s.insert("org".into(), o.get("org").cloned().unwrap_or(Value::Null));
        s.insert("agents".into(), o.get("agents").cloned().unwrap_or(json!({})));
        s.insert("codeWindow".into(), o.get("codeWindow").cloned().unwrap_or(Value::Null));
        Self(s)
    }

    fn org(&self) -> Option<&Map<String, Value>> {
        self.0.get("org").and_then(Value::as_object)
    }

    fn agents(&self) -> Map<String, Value> {
        self.0
            .get("agents")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    }

    fn agents_mut(&mut self) -> &mut Map<String, Value> {
        if !self.0.get("agents").is_some_and(Value::is_object) {
            self.0.insert("agents".into(), json!({}));
        }
        self.0
            .get_mut("agents")
            .and_then(Value::as_object_mut)
            .expect("an object, just set")
    }

    fn window(&self) -> Option<(String, f64)> {
        let w = self.0.get("codeWindow")?.as_object()?;
        Some((w.get("vmId")?.as_str()?.to_string(), w.get("until")?.as_f64()?))
    }
}

/// An agent as a command names it (`KillAgentRef`).
#[derive(Debug, Clone, PartialEq)]
struct Ref {
    vm_id: String,
    name: String,
    hostname: String,
}

#[derive(Debug, Clone, PartialEq)]
struct Proposal {
    change_id: String,
    engage: bool,
    org: bool,
    vm_id: Option<String>,
    agents: Vec<Ref>,
}

fn nonempty(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

fn parse_agents(p: &Map<String, Value>) -> Vec<Ref> {
    p.get("agents")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(|a| {
                    let a = a.as_object()?;
                    let vm_id = nonempty(a.get("vmId"))?;
                    let hostname = nonempty(a.get("hostname"))?;
                    Some(Ref {
                        name: nonempty(a.get("name")).unwrap_or_else(|| vm_id.clone()),
                        vm_id,
                        hostname,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `parseProposal`: a malformed payload is an error, as the TS throws.
fn parse_proposal(p: &Map<String, Value>, engage: bool) -> Result<Proposal, String> {
    let kind = if engage { "engage" } else { "release" };
    let change_id = nonempty(p.get("changeId")).ok_or_else(|| format!("malformed kill.{kind} payload"))?;
    let scope = p.get("scope").and_then(Value::as_str);
    if scope != Some("org") && scope != Some("agent") {
        return Err(format!("malformed kill.{kind} payload"));
    }
    let org = scope == Some("org");
    let vm_id = nonempty(p.get("vmId"));
    if !org && vm_id.is_none() {
        return Err("an agent-scoped emergency stop has to name the agent".into());
    }
    Ok(Proposal {
        change_id,
        engage,
        org,
        vm_id: if org { None } else { vm_id },
        agents: parse_agents(p),
    })
}

impl Proposal {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id, "kind": if self.engage { "engage" } else { "release" },
            "scope": if self.org { "org" } else { "agent" }, "vmId": self.vm_id,
            "agents": self.agents.iter().map(|a| json!({"vmId": a.vm_id, "name": a.name, "hostname": a.hostname})).collect::<Vec<_>>(),
        })
    }

    fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let mut p = parse_proposal(o, o.get("kind")?.as_str()? == "engage").ok()?;
        p.agents = parse_agents(o);
        Some(p)
    }
}

/// `summarize`: the one line the person reads, mirrored in the console's `summarizeKillChange`.
fn summarize(p: &Proposal) -> String {
    let name = (!p.org).then(|| {
        p.agents
            .iter()
            .find(|a| Some(&a.vm_id) == p.vm_id.as_ref())
            .map(|a| a.name.clone())
            .unwrap_or_else(|| "this agent".into())
    });
    match (p.engage, name) {
        (true, Some(n)) => format!("Emergency stop on {n}"),
        (true, None) => "Emergency stop on every agent".into(),
        (false, Some(n)) => format!("Lift the emergency stop on {n}"),
        (false, None) => "Lift the emergency stop on every agent".into(),
    }
}

fn scope_key(org: bool, vm_id: Option<&str>) -> String {
    if org {
        SCOPE_ORG.into()
    } else {
        format!("{SCOPE_PREFIX}{}", vm_id.unwrap_or("null"))
    }
}

/// What one box did (`KillAgentOutcome`).
fn agent_outcome(r: &Ref, stopped: bool, error: Option<String>) -> Value {
    json!({"vmId": r.vm_id, "name": r.name, "stopped": stopped, "error": error})
}

pub type OnLockedChanged = Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>;

pub struct Kill {
    path: PathBuf,
    box_key: String,
    aad: String,
    store: Mutex<Store>,
    /// The last `agents` a command carried, for the reconcile's hostnames.
    known: Mutex<HashMap<String, Ref>>,
    agent: AgentClient,
    consent: Arc<dyn ModuleCodes>,
    routes: Arc<dyn Fn() -> Option<Arc<dyn CodeRouteSource>> + Send + Sync>,
    on_locked_changed: OnLockedChanged,
    /// One command at a time: they read and write the store around calls to the boxes.
    running: tokio::sync::Mutex<()>,
    /// Bumped by every engage: a release still sending its code stops when it moved.
    stops: AtomicU64,
}

impl Kill {
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: super::kit::Kit,
        on_locked_changed: OnLockedChanged,
    ) -> Self {
        let aad = format!("{org}:{box_id}:kill");
        let log = |l: &str| tracing::error!("{l}");
        let store = Store::parse(cc_crypto::enc_file::load_store_or_empty(
            "kill", &path, box_key, &aad, &log,
        ));
        Self {
            path,
            box_key: box_key.into(),
            aad,
            store: Mutex::new(store),
            known: Mutex::new(HashMap::new()),
            agent,
            consent: kit.consent,
            routes: kit.routes,
            on_locked_changed,
            running: tokio::sync::Mutex::new(()),
            stops: AtomicU64::new(0),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st();
        self.save(&s).expect("save");
    }

    fn st(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A store that cannot be written fails the command, as `saveStore` throwing does: a stop
    /// that is not on disk would be gone after a restart.
    fn save(&self, s: &Store) -> Result<(), String> {
        cc_crypto::enc_file::save_store(
            "kill",
            &self.path,
            &Value::Object(s.0.clone()),
            &self.box_key,
            &self.aad,
        )
        .map_err(|e| format!("The emergency stop could not be saved on your firewall: {e}"))
    }

    fn note(&self, agents: &[Ref]) {
        if let Ok(mut k) = self.known.lock() {
            for a in agents {
                k.insert(a.vm_id.clone(), a.clone());
            }
        }
    }

    fn known(&self, vm_id: &str) -> Option<Ref> {
        self.known.lock().ok()?.get(vm_id).cloned()
    }

    /// The box as a command named it, or by its id alone: the agent client finds its address in
    /// the identity map, so a box no command named since a restart is still reached.
    fn reach(&self, vm_id: &str) -> Ref {
        self.known(vm_id).unwrap_or_else(|| Ref {
            vm_id: vm_id.into(),
            name: vm_id.into(),
            hostname: String::new(),
        })
    }

    /// `orgStopped`.
    pub fn org_stopped(&self) -> bool {
        self.st().org().is_some()
    }

    /// Any emergency stop on: the organization's or one agent's.
    pub fn any_stopped(&self) -> bool {
        let st = self.st();
        st.org().is_some() || !st.agents().is_empty()
    }

    /// `summary`: who is stopped, since when, and how.
    pub fn summary(&self) -> Value {
        let st = self.st();
        let agents: Vec<Value> = st
            .agents()
            .iter()
            .map(|(vm, a)| json!({"vmId": vm, "name": a.get("name"), "source": a.get("source"), "at": a.get("at")}))
            .collect();
        json!({"org": st.org().map(|o| json!({"at": o.get("at")})), "agents": agents})
    }

    /// The boxes a proposal is about: one, or every one the control plane named.
    fn targets(&self, p: &Proposal) -> Vec<Ref> {
        if p.org {
            return p.agents.clone();
        }
        let vm = p.vm_id.clone().unwrap_or_default();
        let mut out: Vec<Ref> = p.agents.iter().filter(|a| a.vm_id == vm).cloned().collect();
        if out.is_empty()
            && let Some(k) = self.known(&vm)
        {
            out.push(k);
        }
        out
    }

    async fn was_running(&self, r: &Ref) -> bool {
        match self
            .agent
            .get(&AgentTarget::new(&r.vm_id, &r.hostname), "/kill/status")
            .await
        {
            Ok(s) => s.get("active") == Some(&Value::Bool(true)),
            Err(_) => true,
        }
    }

    async fn set_openclaw(&self, r: &Ref, locked: bool) -> Value {
        match self
            .agent
            .post(
                &AgentTarget::new(&r.vm_id, &r.hostname),
                "/kill/apply",
                &json!({"locked": locked}),
            )
            .await
        {
            Ok(res) => {
                let active = res.get("active") == Some(&Value::Bool(true));
                let error = if res.get("ok") == Some(&Value::Bool(true)) {
                    None
                } else {
                    Some(nonempty(res.get("message")).unwrap_or_else(|| "the box could not change the service".into()))
                };
                agent_outcome(r, !active, error)
            }
            Err(e) => {
                let m = e.to_string();
                agent_outcome(
                    r,
                    false,
                    Some(String::from_utf16_lossy(
                        &m.encode_utf16().take(200).collect::<Vec<_>>(),
                    )),
                )
            }
        }
    }

    async fn open_code_window(&self, r: &Ref) -> Result<(), String> {
        let until = (now_ms() + CODE_TTL_MS).div_ceil(1000);
        {
            let mut st = self.st();
            st.0.insert("codeWindow".into(), json!({"vmId": r.vm_id, "until": until}));
            self.save(&st)?;
        }
        // Egress first, then the process: OpenClaw dials its channel as it comes up.
        (self.on_locked_changed)().await?;
        self.set_openclaw(r, false).await;
        tracing::info!(
            "[kill] {} may reach its channel for ten minutes, to carry the code",
            r.name
        );
        Ok(())
    }

    async fn close_code_window(&self) -> Result<(), String> {
        let (vm, still) = {
            let mut st = self.st();
            let Some((vm, _)) = st.window() else { return Ok(()) };
            st.0.insert("codeWindow".into(), Value::Null);
            self.save(&st)?;
            let still = st.org().is_some() || st.agents().contains_key(&vm);
            (vm, still)
        };
        if still {
            self.set_openclaw(&self.reach(&vm), true).await;
        }
        (self.on_locked_changed)().await?;
        tracing::info!("[kill] the code window is closed");
        Ok(())
    }

    /// Cut the agents off (store, then the proxy) before anything waits on a box; then read which
    /// were running and stop OpenClaw on them, all at once. (The TS read the statuses first.)
    async fn apply_engage(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let targets = self.targets(p);
        self.note(&p.agents);
        let at = iso(now_ms());
        // Unknown counts as running (a release then starts it); the answers below refine it.
        let assumed: Map<String, Value> = targets.iter().map(|r| (r.vm_id.clone(), json!(true))).collect();
        let vm = p.vm_id.clone().unwrap_or_default();
        {
            let mut st = self.st();
            if p.org {
                st.0.insert("org".into(), json!({"at": at, "wasRunning": assumed}));
            } else {
                let name = targets.first().map(|r| r.name.clone()).unwrap_or_else(|| vm.clone());
                st.agents_mut().insert(
                    vm.clone(),
                    json!({"name": name, "source": "agent", "wasRunning": true, "at": at}),
                );
            }
            self.save(&st)?;
        }
        (self.on_locked_changed)().await?;
        tracing::info!("[kill] {} — egress is cut off", summarize(p));
        let answers = futures_util::future::join_all(targets.iter().map(|r| self.was_running(r))).await;
        let stopped: Vec<&str> = targets
            .iter()
            .zip(&answers)
            .filter(|(_, running)| !**running)
            .map(|(r, _)| r.vm_id.as_str())
            .collect();
        if !stopped.is_empty() {
            let mut st = self.st();
            // Only into the stop this command wrote: another one may have replaced it meanwhile.
            let stop = if p.org {
                st.0.get_mut("org")
            } else {
                st.0.get_mut("agents").and_then(|a| a.get_mut(&vm))
            };
            if let Some(stop) = stop.filter(|s| s.get("at").and_then(Value::as_str) == Some(at.as_str())) {
                for v in &stopped {
                    if p.org {
                        if let Some(w) = stop.get_mut("wasRunning").and_then(Value::as_object_mut) {
                            w.insert((*v).to_string(), json!(false));
                        }
                    } else if *v == vm {
                        stop["wasRunning"] = json!(false);
                    }
                }
                if let Err(e) = self.save(&st) {
                    // The stop itself is on disk; only "was it running" is lost, which reads as running.
                    tracing::error!("[kill] {e}");
                }
            }
        }
        let outcomes: Vec<Value> =
            futures_util::future::join_all(targets.iter().map(|r| self.set_openclaw(r, true))).await;
        let failed: Vec<String> = outcomes
            .iter()
            .filter(|o| !o["error"].is_null())
            .map(|o| {
                format!(
                    "{} ({})",
                    o["name"].as_str().unwrap_or_default(),
                    o["error"].as_str().unwrap_or_default()
                )
            })
            .collect();
        if !failed.is_empty() {
            tracing::info!(
                "[kill] {} box(es) did not confirm OpenClaw stopped: {}",
                failed.len(),
                failed.join(", ")
            );
        }
        let mut m = Map::new();
        m.insert("scope".into(), json!(if p.org { "org" } else { "agent" }));
        m.insert("vmId".into(), json!(p.vm_id));
        m.insert("at".into(), json!(at));
        m.insert("agents".into(), Value::Array(outcomes));
        Ok(m)
    }

    /// Put it back: OpenClaw first for the boxes that were running, then the lockdown comes off.
    async fn apply_release(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let targets = self.targets(p);
        self.note(&p.agents);
        let (org_running, own, org_on) = {
            let st = self.st();
            let org_running = st
                .org()
                .and_then(|o| o.get("wasRunning"))
                .and_then(Value::as_object)
                .cloned();
            (org_running, st.agents(), st.org().is_some())
        };
        let was_running = |vm: &str| -> bool {
            if p.org {
                org_running
                    .as_ref()
                    .and_then(|w| w.get(vm))
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            } else {
                own.get(vm)
                    .and_then(|a| a.get("wasRunning"))
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
            }
        };
        // A per-agent release under the org-wide stop changes nothing about its egress.
        let still_locked = !p.org && org_on;
        let mut outcomes = Vec::new();
        for r in &targets {
            if p.org && own.contains_key(&r.vm_id) {
                continue;
            }
            if still_locked || !was_running(&r.vm_id) {
                outcomes.push(agent_outcome(r, true, None));
                continue;
            }
            outcomes.push(self.set_openclaw(r, false).await);
        }
        {
            let mut st = self.st();
            if p.org {
                st.0.insert("org".into(), Value::Null);
            } else if let Some(vm) = &p.vm_id {
                st.agents_mut().shift_remove(vm);
            }
            self.save(&st)?;
        }
        (self.on_locked_changed)().await?;
        if still_locked {
            tracing::info!(
                "[kill] {}, but the whole organisation is still stopped, so it stays cut off",
                summarize(p)
            );
        } else {
            tracing::info!("[kill] {} — the agents are back", summarize(p));
        }
        let mut m = Map::new();
        m.insert("scope".into(), json!(if p.org { "org" } else { "agent" }));
        m.insert("vmId".into(), json!(p.vm_id));
        m.insert("stillLocked".into(), json!(still_locked));
        m.insert("agents".into(), Value::Array(outcomes));
        Ok(m)
    }

    fn base(p: &Proposal) -> Map<String, Value> {
        let mut d = Map::new();
        d.insert("changeId".into(), json!(p.change_id));
        d.insert("summary".into(), json!(summarize(p)));
        d.insert("scope".into(), json!(if p.org { "org" } else { "agent" }));
        d.insert("vmId".into(), json!(p.vm_id));
        d
    }

    /// `kill.engage`: applies at once; drops a pending release and closes its window.
    pub async fn engage(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse_proposal(&payload, true) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        // Before the lock: a release still sending its code sees it and stops.
        self.stops.fetch_add(1, Ordering::SeqCst);
        let _one = self.running.lock().await;
        self.consent.forget(&scope_key(p.org, p.vm_id.as_deref()));
        // The stop first; a code window that will not close must not hold it up or block it.
        let applied = match self.apply_engage(&p).await {
            Ok(a) => a,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        if let Err(e) = self.close_code_window().await {
            tracing::error!("[kill] the code window did not close after the stop: {e}");
        }
        let mut d = Map::new();
        d.insert("changeId".into(), json!(p.change_id));
        d.insert("summary".into(), json!(summarize(&p)));
        d.extend(applied);
        ok("applied", d)
    }

    /// `kill.release`: a code (first use when nobody is approved; refused when nobody can be asked).
    pub async fn release(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse_proposal(&payload, false) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize(&p);
        let data = Self::base(&p);
        self.note(&p.agents);
        let stops = self.stops.load(Ordering::SeqCst);
        let Some(source) = (self.routes)().filter(|r| r.ready()) else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        let routes = source.routes();
        let key = scope_key(p.org, p.vm_id.as_deref());
        if routes.is_empty() {
            // Only the apply is serialized: the send loop below must never hold up a stop.
            let _one = self.running.lock().await;
            self.consent.forget(&key);
            let mut d = data;
            match self.apply_release(&p).await {
                Ok(a) => d.extend(a),
                Err(e) => return CommandOutcome::failed("failed", e),
            }
            d.insert("tofu".into(), json!(true));
            return ok("applied", d);
        }
        let agent_name = if p.org {
            "your agents".to_string()
        } else {
            self.targets(&p)
                .first()
                .map(|r| r.name.clone())
                .unwrap_or_else(|| "your agent".into())
        };
        let locked: Vec<String> = self.locked_vm_ids(&p.agents.iter().map(|a| a.vm_id.clone()).collect::<Vec<_>>());
        let mut ordered = routes.clone();
        ordered.sort_by_key(|r| locked.contains(&r.vm_id));
        let mut sent = CodeSent::Failed {
            message: "No approved channel could be reached.".into(),
        };
        let wait_until = now_ms() + KILL_WINDOW_SEND_MS;
        // An engage while this sends: no window, no code; whatever was sent is withdrawn.
        let stopped = || self.stops.load(Ordering::SeqCst) != stops;
        let withdrawn = |data: Map<String, Value>| {
            fail(
                "failed",
                "An emergency stop was engaged while the code was being sent, so nothing will be released.",
                data,
            )
        };
        for route in ordered {
            if stopped() {
                self.consent.forget(&key);
                return withdrawn(data);
            }
            let dev = route.senders.contains(&CodeSender::Dev);
            let needs_window = !dev && locked.contains(&route.vm_id);
            if needs_window {
                let r = self
                    .known(&route.vm_id)
                    .or_else(|| p.agents.iter().find(|a| a.vm_id == route.vm_id).cloned())
                    .unwrap_or_else(|| self.reach(&route.vm_id));
                if let Err(e) = self.open_code_window(&r).await {
                    return CommandOutcome::failed("failed", e);
                }
            }
            let req = CodeAsk {
                scope: key.clone(),
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: agent_name.clone(),
                summary: summary.clone(),
                routes: vec![route.clone()],
                ..Default::default()
            };
            sent = self.consent.send(req.clone()).await;
            // The window just started OpenClaw, whose gateway is not up for some seconds.
            while needs_window
                && !stopped()
                && matches!(&sent, CodeSent::Failed { message } if message.to_lowercase().contains("not running"))
                && now_ms() + KILL_WINDOW_RETRY_MS <= wait_until
            {
                tokio::time::sleep(std::time::Duration::from_millis(KILL_WINDOW_RETRY_MS)).await;
                sent = self.consent.send(req.clone()).await;
            }
            if stopped() {
                self.consent.forget(&key);
                if needs_window && let Err(e) = self.close_code_window().await {
                    tracing::error!("[kill] the code window did not close after the stop: {e}");
                }
                return withdrawn(data);
            }
            if matches!(sent, CodeSent::Sent { .. }) {
                break;
            }
            if needs_window && let Err(e) = self.close_code_window().await {
                return CommandOutcome::failed("failed", e);
            }
        }
        if let CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[kill] code sent to lift the emergency stop via {sent_via}");
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = nonempty(payload.get("changeId")) else {
            return CommandOutcome::failed("failed", "malformed kill.confirm payload");
        };
        let org = payload.get("scope").and_then(Value::as_str) != Some("agent");
        let vm_id = nonempty(payload.get("vmId"));
        if !org && vm_id.is_none() {
            return CommandOutcome::failed("failed", "malformed kill.confirm payload");
        }
        let _one = self.running.lock().await;
        let key = scope_key(org, vm_id.as_deref());
        let mut data = Map::new();
        data.insert("changeId".into(), json!(change_id));
        data.insert("scope".into(), json!(if org { "org" } else { "agent" }));
        data.insert("vmId".into(), json!(vm_id));
        let code = nonempty(payload.get("code")).unwrap_or_default();
        match self.consent.verify(&key, &change_id, &code) {
            CodeCheck::Expired => {
                if let Err(e) = self.close_code_window().await {
                    return CommandOutcome::failed("failed", e);
                }
                fail("expired", "No change is waiting for a code, or the code expired.", data)
            }
            CodeCheck::Wrong { tries_left } => {
                if tries_left == 0
                    && let Err(e) = self.close_code_window().await
                {
                    return CommandOutcome::failed("failed", e);
                }
                data.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", data)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = Proposal::from_json(&proposal) else {
                    return fail("failed", "That change could not be read.", data);
                };
                {
                    let mut st = self.st();
                    st.0.insert("codeWindow".into(), Value::Null);
                    if let Err(e) = self.save(&st) {
                        return CommandOutcome::failed("failed", e);
                    }
                }
                match self.apply_release(&p).await {
                    Ok(a) => data.extend(a),
                    Err(e) => return CommandOutcome::failed("failed", e),
                }
                data.insert("summary".into(), json!(summarize(&p)));
                data.insert("sentVia".into(), json!(sent_via));
                data.insert("tofu".into(), json!(false));
                ok("applied", data)
            }
        }
    }

    pub async fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = nonempty(payload.get("changeId"));
        let org = payload.get("scope").and_then(Value::as_str) != Some("agent");
        let vm_id = nonempty(payload.get("vmId"));
        let _one = self.running.lock().await;
        if self
            .consent
            .cancel(&scope_key(org, vm_id.as_deref()), change_id.as_deref())
            && let Err(e) = self.close_code_window().await
        {
            return CommandOutcome::failed("failed", e);
        }
        let mut d = Map::new();
        d.insert("changeId".into(), json!(change_id));
        ok("cancelled", d)
    }

    /// Stop OpenClaw again on every locked box that came back running (a reboot), every minute.
    pub async fn reconcile(&self, identity_vm_ids: &[String]) {
        let locked = self.locked_vm_ids(identity_vm_ids);
        if locked.is_empty() {
            return;
        }
        let windows = self.code_windows();
        for vm in locked {
            if windows.contains_key(&vm) {
                continue;
            }
            // Every locked box, named by a command or not: after a restart nothing has been.
            let r = self.reach(&vm);
            let t = AgentTarget::new(&vm, &r.hostname);
            let checked = async {
                let s = self.agent.get(&t, "/kill/status").await?;
                if s.get("active") != Some(&Value::Bool(true)) {
                    return Ok(());
                }
                tracing::info!(
                    "[kill] {} came back running under an emergency stop; stopping it again",
                    r.name
                );
                self.agent
                    .post(&t, "/kill/apply", &json!({"locked": true}))
                    .await
                    .map(|_| ())
            };
            if let Err(e) = checked.await {
                tracing::info!("[kill] could not re-check {}: {e}", r.name);
            }
        }
    }
}

impl KillLocks for Kill {
    /// `lockedVmIds`: every box in the map while the whole organization is stopped.
    fn locked_vm_ids(&self, vm_ids: &[String]) -> Vec<String> {
        let st = self.st();
        let own: Vec<String> = st.agents().keys().cloned().collect();
        if st.org().is_none() {
            return own;
        }
        let mut out: Vec<String> = Vec::new();
        for v in vm_ids.iter().chain(own.iter()) {
            if !out.contains(v) {
                out.push(v.clone());
            }
        }
        out
    }

    /// `codeWindows`: the open window, gone the moment it lapses.
    fn code_windows(&self) -> Map<String, Value> {
        let mut m = Map::new();
        if let Some((vm, until)) = self.st().window()
            && until * 1000.0 > now_ms() as f64
        {
            m.insert(vm, super::ingress::num(until));
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_load_as_the_ts_loads_them() {
        assert_eq!(Store::parse(None).0, Store::empty().0);
        assert_eq!(
            Store::parse(Some(json!({"version": 2, "agents": {}}))).0,
            Store::empty().0
        );
        assert_eq!(Store::parse(Some(json!({"version": 1}))).0, Store::empty().0);
        let s = Store::parse(Some(
            json!({"version": 1, "agents": {"vm_1": {"name": "a"}}, "extra": 1}),
        ));
        assert_eq!(
            Value::Object(s.0),
            json!({"version": 1, "org": null, "agents": {"vm_1": {"name": "a"}}, "codeWindow": null})
        );
    }

    #[test]
    fn proposals_and_summaries() {
        let p = |v: Value| parse_proposal(v.as_object().expect("obj"), true);
        assert_eq!(
            p(json!({"scope": "org"})).expect_err("id"),
            "malformed kill.engage payload"
        );
        assert_eq!(
            p(json!({"changeId": "c", "scope": "x"})).expect_err("scope"),
            "malformed kill.engage payload"
        );
        assert_eq!(
            p(json!({"changeId": "c", "scope": "agent"})).expect_err("vm"),
            "an agent-scoped emergency stop has to name the agent"
        );
        let a = p(json!({"changeId": "c", "scope": "agent", "vmId": "vm_1", "agents": [{"vmId": "vm_1", "name": "atlas", "hostname": "a"}, {"vmId": "x"}]})).expect("ok");
        assert_eq!(a.agents.len(), 1);
        assert_eq!(summarize(&a), "Emergency stop on atlas");
        let back = Proposal::from_json(&a.to_json()).expect("back");
        assert_eq!(back, a);
        let o = parse_proposal(
            json!({"changeId": "c", "scope": "org"}).as_object().expect("obj"),
            false,
        )
        .expect("ok");
        assert_eq!(summarize(&o), "Lift the emergency stop on every agent");
    }

    #[test]
    fn the_store_survives_a_round_trip_with_fields_it_does_not_know() {
        let s = Store::parse(Some(
            json!({"version": 1, "org": null, "agents": {"vm_1": {"name": "a", "source": "agent", "wasRunning": true, "at": "t", "later": 1}}, "future": 2}),
        ));
        assert_eq!(s.agents()["vm_1"]["later"], 1);
        assert!(
            Store::parse(Some(json!({"version": 2, "agents": {}})))
                .agents()
                .is_empty()
        );
    }
}
