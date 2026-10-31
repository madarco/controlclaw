//! The agents this firewall serves (`identities.ts` and the identity half of `index.ts`): the map
//! the control plane sends, checked once before anything reads a row, split into agents (OpenClaw
//! boxes) and the boxes a browser can open (agents and the organization's brain).
//!
//! A call to an agent goes to the address in this map, or, when the map lacks the agent (a restart
//! with the control plane out of reach), to the hostname pinned when it first appeared (the access
//! module's pins). Never to an address a command names.

use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{Map, Value};

use crate::contracts::{AgentIdentity, AgentRoute, IdentityMap};

/// One row as `parseIdentities` keeps it: `vm_id` always a valid id, `name`, `hostname`,
/// `access_hostname` and `role` only when well formed, every other field passed on.
pub type Identity = Map<String, Value>;

static VM_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("regex"));
static PLAIN_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,62}$").expect("regex"));
static HOST_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$").expect("regex"));
static ROLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z]{1,20}$").expect("regex"));

/// `String(n)` for the numbers an id can be.
pub fn js_number_string(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e21 {
        return format!("{f:.0}");
    }
    f.to_string()
}

/// `String(i.vm_id)` as the TS reads a row's id (a missing one is `"undefined"`).
pub fn vm_id_of(row: &Map<String, Value>) -> String {
    match row.get("vm_id") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => js_number_string(n),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Null) => "null".into(),
        None => "undefined".into(),
        Some(other) => other.to_string(),
    }
}

/// `parseIdentities`.
pub fn parse_identities(rows: &[Value]) -> Vec<Identity> {
    let mut out = Vec::new();
    for raw in rows {
        let Some(r) = raw.as_object() else { continue };
        let id = match r.get("vm_id") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => js_number_string(n),
            _ => String::new(),
        };
        if !VM_ID.is_match(&id) {
            continue;
        }
        let mut row = Map::new();
        for (k, v) in r {
            match k.as_str() {
                "name" | "hostname" | "access_hostname" | "role" => {}
                "vm_id" => {
                    row.insert(k.clone(), Value::String(id.clone()));
                }
                _ => {
                    row.insert(k.clone(), v.clone());
                }
            }
        }
        let checked: [(&str, &Regex); 4] = [
            ("name", &PLAIN_NAME),
            ("hostname", &HOST_NAME),
            ("access_hostname", &HOST_NAME),
            ("role", &ROLE),
        ];
        for (key, re) in checked {
            if let Some(Value::String(s)) = r.get(key)
                && re.is_match(s)
            {
                row.insert(key.into(), Value::String(s.clone()));
            }
        }
        out.push(row);
    }
    out
}

fn role(i: &Identity) -> &str {
    i.get("role").and_then(Value::as_str).unwrap_or("openclaw")
}

/// `splitIdentities`: agents are OpenClaw boxes; browser boxes are agents and the brain.
pub fn split_identities(rows: &[Identity]) -> (Vec<Identity>, Vec<Identity>) {
    let agents = rows.iter().filter(|i| role(i) == "openclaw").cloned().collect();
    let browser = rows
        .iter()
        .filter(|i| role(i) == "openclaw" || role(i) == "gbrain")
        .cloned()
        .collect();
    (agents, browser)
}

pub fn str_field<'a>(i: &'a Identity, key: &str) -> Option<&'a str> {
    i.get(key).and_then(Value::as_str)
}

/// The hostname an agent was pinned to at first sight (the access module, C3), by vm id.
pub type PinnedHost = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
/// Run after every read of the map with the agents and the browser boxes (agents and the brain):
/// pins read the second, first-seen times and Doctor keys the first.
pub type OnIdentities = Arc<dyn Fn(&[Identity], &[Identity]) + Send + Sync>;

struct Learn {
    at: Option<Instant>,
}

/// Every look at the map, the last one kept.
pub struct Agents {
    agents: RwLock<Vec<Identity>>,
    browser: RwLock<Vec<Identity>>,
    synced: std::sync::atomic::AtomicBool,
    pinned: RwLock<Option<PinnedHost>>,
    listeners: RwLock<Vec<OnIdentities>>,
    learn: tokio::sync::Mutex<Learn>,
    /// A standalone firewall: calls go to each agent's `agent_addr`, the vm-agent itself.
    direct: std::sync::atomic::AtomicBool,
}

/// `LEARN_GAP_MS`: a call to an unknown agent looks at the map at most this often.
const LEARN_GAP: Duration = Duration::from_secs(3);

impl Default for Agents {
    fn default() -> Self {
        Self {
            agents: RwLock::new(Vec::new()),
            browser: RwLock::new(Vec::new()),
            synced: std::sync::atomic::AtomicBool::new(false),
            pinned: RwLock::new(None),
            listeners: RwLock::new(Vec::new()),
            learn: tokio::sync::Mutex::new(Learn { at: None }),
            direct: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

// Read by the agent client (C2) and by W4 and W5.
#[allow(dead_code)]
impl Agents {
    /// Take a fresh map from the control plane (rows as it sent them).
    pub fn set(&self, rows: &[Value]) {
        let (agents, browser) = split_identities(&parse_identities(rows));
        if let Ok(mut a) = self.agents.write() {
            *a = agents.clone();
        }
        if let Ok(mut b) = self.browser.write() {
            *b = browser.clone();
        }
        self.synced.store(true, std::sync::atomic::Ordering::SeqCst);
        let listeners = self.listeners.read().map(|l| l.clone()).unwrap_or_default();
        for f in listeners {
            // One part's listener that panics does not stop the others or the sync.
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&agents, &browser))).is_err() {
                tracing::error!("[agents] a listener on the identity map failed");
            }
        }
    }

    /// The OpenClaw agents (`identities`).
    pub fn agents(&self) -> Vec<Identity> {
        self.agents.read().map(|a| a.clone()).unwrap_or_default()
    }

    /// Agents and the brain (`browserIdentities`).
    pub fn browser_boxes(&self) -> Vec<Identity> {
        self.browser.read().map(|a| a.clone()).unwrap_or_default()
    }

    /// `identitiesSynced`.
    pub fn synced(&self) -> bool {
        self.synced.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_pinned(&self, f: PinnedHost) {
        if let Ok(mut p) = self.pinned.write() {
            *p = Some(f);
        }
    }

    pub fn on_identities(&self, f: OnIdentities) {
        if let Ok(mut l) = self.listeners.write() {
            l.push(f);
        }
    }

    fn pinned_host(&self, vm_id: &str) -> Option<String> {
        let f = self.pinned.read().ok()?.clone()?;
        f(vm_id)
    }

    /// `agentHostFor`: the map's hostname (lower-cased), else the pinned one.
    pub fn host_for(&self, vm_id: &str) -> Option<String> {
        let from_map = self
            .browser
            .read()
            .ok()
            .and_then(|b| b.iter().find(|i| vm_id_of(i) == vm_id).cloned())
            .and_then(|i| str_field(&i, "hostname").map(str::to_lowercase));
        from_map.or_else(|| self.pinned_host(vm_id).filter(|h| !h.is_empty()))
    }

    /// Call agents at their `agent_addr` (a standalone firewall, whose control plane is its own).
    pub fn set_direct(&self, on: bool) {
        self.direct.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    /// Where a call to a box's vm-agent goes: on a standalone firewall the map's `agent_addr`
    /// (an `ip:port`), else its hostname over HTTPS ([`Self::host_for`]).
    pub fn route_for(&self, vm_id: &str) -> Option<AgentRoute> {
        if self.direct.load(std::sync::atomic::Ordering::SeqCst) {
            let addr = self
                .browser
                .read()
                .ok()
                .and_then(|b| b.iter().find(|i| vm_id_of(i) == vm_id).cloned())
                .and_then(|i| str_field(&i, "agent_addr").and_then(|a| a.parse().ok()));
            if let Some(addr) = addr {
                return Some(AgentRoute::direct(addr));
            }
        }
        self.host_for(vm_id).map(AgentRoute::https)
    }

    /// `movedAgents`: agents the map now names at another address than the pinned one.
    pub fn moved(&self) -> Vec<Value> {
        self.browser_boxes()
            .iter()
            .filter_map(|i| {
                let vm_id = vm_id_of(i);
                let pinned = self.pinned_host(&vm_id).filter(|p| !p.is_empty())?;
                let now = str_field(i, "hostname").filter(|h| !h.is_empty())?.to_lowercase();
                (pinned != now).then(|| serde_json::json!({"vm_id": vm_id, "pinned": pinned, "now": now}))
            })
            .take(50)
            .collect()
    }

    /// `agentRecordName`: an agent's name from the last sync, when it is a plain name.
    pub fn record_name(&self, vm_id: &str) -> Option<String> {
        let agents = self.agents.read().ok()?;
        let name = agents.iter().find(|i| vm_id_of(i) == vm_id)?.get("name")?.as_str()?;
        PLAIN_NAME.is_match(name).then(|| name.to_string())
    }

    /// The agent's `name` from the last sync, whatever it is.
    pub fn name_of(&self, vm_id: &str) -> Option<String> {
        let agents = self.agents.read().ok()?;
        Some(str_field(agents.iter().find(|i| vm_id_of(i) == vm_id)?, "name")?.to_string())
    }

    /// `learnAgents`: one look at the map for an agent this firewall does not know yet, at most
    /// every [`LEARN_GAP`], calls that miss together sharing it.
    pub async fn learn(&self, fetch: impl std::future::Future<Output = Result<Value, String>>) {
        let mut learn = self.learn.lock().await;
        if learn.at.is_some_and(|t| t.elapsed() < LEARN_GAP) {
            return;
        }
        match fetch.await {
            // `parseIdentities` reads anything but a list as no rows.
            Ok(rows) => self.set(rows.as_array().map(Vec::as_slice).unwrap_or_default()),
            Err(e) => tracing::error!("[agents] could not look for a new agent: {e}"),
        }
        learn.at = Some(Instant::now());
    }
}

/// The map as other workstreams read it (`contracts::IdentityMap`).
pub struct IdentityView(pub Arc<Agents>);

impl IdentityMap for IdentityView {
    fn agents(&self) -> Vec<AgentIdentity> {
        self.0.agents().iter().map(to_contract).collect()
    }

    fn agent(&self, vm_id: &str) -> Option<AgentIdentity> {
        self.0.agents().iter().find(|i| vm_id_of(i) == vm_id).map(to_contract)
    }

    fn host_for(&self, vm_id: &str) -> Option<String> {
        self.0.host_for(vm_id)
    }

    fn route_for(&self, vm_id: &str) -> Option<AgentRoute> {
        self.0.route_for(vm_id)
    }
}

fn to_contract(i: &Identity) -> AgentIdentity {
    AgentIdentity {
        vm_id: vm_id_of(i),
        private_ip: str_field(i, "private_ip").unwrap_or_default().to_string(),
        hostname: str_field(i, "hostname").map(str::to_string),
        name: str_field(i, "name").map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The route: a hostname over HTTPS, unless the firewall is standalone and the row has a
    /// well-formed `agent_addr`.
    #[test]
    fn a_route_is_the_hostname_unless_standalone() {
        let agents = Agents::default();
        agents.set(&[
            json!({"vm_id": "vm_1", "private_ip": "10.0.0.2", "hostname": "a.example", "agent_addr": "10.0.0.2:3100"}),
            json!({"vm_id": "vm_2", "private_ip": "10.0.0.3", "agent_addr": "10.0.0.3:3100/x"}),
        ]);
        let https = AgentRoute::https("a.example".into());
        assert_eq!(https.base, "https://a.example/__cc/agent");
        assert_eq!(agents.route_for("vm_1"), Some(https.clone()));
        assert_eq!(agents.route_for("vm_2"), None);
        agents.set_direct(true);
        assert_eq!(
            agents.route_for("vm_1"),
            Some(AgentRoute {
                host: "10.0.0.2".into(),
                base: "http://10.0.0.2:3100".into()
            })
        );
        assert_eq!(agents.route_for("vm_2"), None, "not an ip:port");
    }

    /// `learnAgents`: an agent created seconds ago is found at once, by one look shared by the
    /// calls that missed together, and not looked for again within the gap.
    #[tokio::test]
    async fn an_unknown_agent_is_looked_up_once_more() {
        let agents = Arc::new(Agents::default());
        agents.set(&[json!({"vm_id": "vm_1", "private_ip": "10.0.0.2", "hostname": "a.example"})]);
        assert!(agents.host_for("vm_2").is_none());
        let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let look = |f: Arc<std::sync::atomic::AtomicUsize>| async move {
            f.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(json!([
                {"vm_id": "vm_1", "private_ip": "10.0.0.2", "hostname": "a.example"},
                {"vm_id": "vm_2", "private_ip": "10.0.0.3", "hostname": "b.example"},
            ]))
        };
        tokio::join!(agents.learn(look(fetches.clone())), agents.learn(look(fetches.clone())));
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(agents.host_for("vm_2").as_deref(), Some("b.example"));
        agents.learn(look(fetches.clone())).await;
        assert_eq!(
            fetches.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "not again within the gap"
        );
    }

    /// Every agent client reaches the brain (`agentHostFor`), while `agents()` stays OpenClaw only.
    #[test]
    fn the_view_finds_the_brains_host_but_does_not_list_it_as_an_agent() {
        let agents = Arc::new(Agents::default());
        agents.set(&[
            json!({"vm_id": "vm_1", "private_ip": "10.0.0.2", "hostname": "a.example"}),
            json!({"vm_id": "vm_b", "private_ip": "10.0.0.9", "hostname": "brain.example", "role": "gbrain"}),
        ]);
        agents.set_pinned(Arc::new(|vm: &str| {
            (vm == "vm_gone").then(|| "gone.example".to_string())
        }));
        let view = IdentityView(agents);
        assert_eq!(view.host_for("vm_b").as_deref(), Some("brain.example"));
        assert_eq!(view.host_for("vm_1").as_deref(), Some("a.example"));
        assert_eq!(view.host_for("vm_gone").as_deref(), Some("gone.example"));
        assert!(view.agent("vm_b").is_none());
        assert_eq!(view.agents().len(), 1);
    }

    #[test]
    fn rows_are_checked() {
        let rows = vec![
            json!({"vm_id": "vm_1", "private_ip": "10.0.0.2", "name": "alpha", "hostname": "a.example", "extra": 1}),
            json!({"vm_id": 42, "name": "Bad Name", "hostname": "x\ny", "role": "gbrain"}),
            json!({"vm_id": "bad id"}),
            json!("nope"),
            json!({"name": "no-id"}),
        ];
        let parsed = parse_identities(&rows);
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            Value::Object(parsed[0].clone()),
            json!({"vm_id": "vm_1", "private_ip": "10.0.0.2", "extra": 1, "name": "alpha", "hostname": "a.example"})
        );
        assert_eq!(
            Value::Object(parsed[1].clone()),
            json!({"vm_id": "42", "role": "gbrain"})
        );
        let keys: Vec<&String> = parsed[0].keys().collect();
        assert_eq!(keys, ["vm_id", "private_ip", "extra", "name", "hostname"]);
        let (agents, browser) = split_identities(&parsed);
        assert_eq!(agents.len(), 1);
        assert_eq!(browser.len(), 2);
    }

    #[test]
    fn host_and_names() {
        let a = Agents::default();
        a.set(&[
            json!({"vm_id": "vm_1", "hostname": "a.example", "name": "alpha"}),
            json!({"vm_id": "vm_2", "role": "gbrain", "hostname": "b.example"}),
        ]);
        assert!(a.synced());
        assert_eq!(a.host_for("vm_1").as_deref(), Some("a.example"));
        assert_eq!(a.host_for("vm_2").as_deref(), Some("b.example"));
        assert_eq!(a.host_for("vm_3"), None);
        a.set_pinned(Arc::new(|vm| {
            (vm == "vm_3" || vm == "vm_1").then(|| "pinned.example".to_string())
        }));
        assert_eq!(a.host_for("vm_3").as_deref(), Some("pinned.example"));
        assert_eq!(
            a.moved(),
            vec![json!({"vm_id": "vm_1", "pinned": "pinned.example", "now": "a.example"})]
        );
        assert_eq!(a.record_name("vm_1").as_deref(), Some("alpha"));
        assert_eq!(a.record_name("vm_2"), None);
    }
}
