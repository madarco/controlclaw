//! The firewall's half of the health check (`health.ts`). Once a minute it reads
//! `GET /health/summary` on every agent over the route every push takes and keeps when each last
//! answered (`agents_reach` on the beat). `health.probe {vmId}` does the same read for one agent at
//! once, for the Check dialog. The summary is copied field by field so nothing else rides along.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use super::now_ms;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentError, AgentTarget, NetError};
use super::identities::{Agents, str_field, vm_id_of};
use crate::commands::CommandOutcome;

pub const HEALTH_REACH_MS: u64 = 60_000;
const PROBE_TIMEOUT_MS: u64 = 8_000;

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    pub reachable: bool,
    pub ms: u64,
    pub error: Option<&'static str>,
    pub outdated: bool,
    pub refused: Option<String>,
    pub summary: Option<Value>,
}

impl ProbeOutcome {
    /// `{reachable, ms, error, outdated, refused?, summary}` in the TS order.
    fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("reachable".into(), json!(self.reachable));
        m.insert("ms".into(), json!(self.ms));
        m.insert("error".into(), json!(self.error));
        m.insert("outdated".into(), json!(self.outdated));
        if let Some(r) = &self.refused {
            m.insert("refused".into(), json!(r));
        }
        m.insert("summary".into(), self.summary.clone().unwrap_or(Value::Null));
        m
    }
}

/// Whether the agent's own service answered, even to refuse (`agentAnswered`): an older vm-agent
/// refuses `/health/summary` with a 401 or 404, which still proves the box is up.
pub fn agent_answered(e: &AgentError) -> bool {
    e.status().is_some_and(|s| (400..500).contains(&s))
}

/// `reachErrorOf`.
pub fn reach_error_of(e: &AgentError) -> &'static str {
    if e.is_timeout() {
        return "timeout";
    }
    // Caddy on the box answers 502/503/504 when the service behind it is down.
    if e.status().is_some_and(|s| s >= 500) {
        return "service_down";
    }
    match e {
        AgentError::Network(NetError::Refused) => "refused",
        AgentError::Network(NetError::Dns) => "dns",
        AgentError::Network(NetError::Tls) => "tls",
        AgentError::Network(NetError::Timeout) => "timeout",
        _ => "error",
    }
}

static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z_]{1,32}$").expect("regex"));
static REFUSED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^agent 401: the firewall's token was refused \(([a-z-]{1,24})\)").expect("regex"));

fn num(v: Option<&Value>) -> Value {
    match v {
        Some(Value::Number(n)) if n.as_f64().is_some_and(f64::is_finite) => Value::Number(n.clone()),
        _ => Value::Null,
    }
}

fn boolean(v: Option<&Value>) -> Value {
    match v {
        Some(Value::Bool(b)) => Value::Bool(*b),
        _ => Value::Null,
    }
}

fn word(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(s)) if WORD.is_match(s) => Value::String(s.clone()),
        _ => Value::Null,
    }
}

/// `obj`: any object, arrays included (`typeof [] === "object"`).
fn obj(v: Option<&Value>) -> Option<Map<String, Value>> {
    match v {
        Some(Value::Object(o)) => Some(o.clone()),
        Some(Value::Array(_)) => Some(Map::new()),
        _ => None,
    }
}

fn probe_of(v: Option<&Value>) -> Value {
    match obj(v) {
        Some(p) => {
            json!({"ok": p.get("ok") == Some(&Value::Bool(true)), "ms": num(p.get("ms")), "reason": word(p.get("reason"))})
        }
        None => Value::Null,
    }
}

/// `cleanSummary`: the agent's summary field by field; anything it adds later is dropped.
pub fn clean_summary(raw: &Map<String, Value>) -> Value {
    let oc = obj(raw.get("openclaw"));
    let disk = obj(raw.get("disk"));
    let mem = obj(raw.get("memory"));
    let clock = obj(raw.get("clock"));
    json!({
        "now": num(raw.get("now")),
        "openclaw": oc.map(|o| json!({"state": word(o.get("state")), "gateway": boolean(o.get("gateway"))})),
        "disk": disk.map(|d| json!({"usedPct": num(d.get("usedPct")), "freeBytes": num(d.get("freeBytes"))})),
        "memory": mem.map(|m| json!({"usedPct": num(m.get("usedPct")), "totalBytes": num(m.get("totalBytes"))})),
        "load1": num(raw.get("load1")),
        "cpus": num(raw.get("cpus")),
        "clock": clock.map(|c| json!({"ntpSynced": boolean(c.get("ntpSynced"))})),
        "dns": probe_of(raw.get("dns")),
        "egress": probe_of(raw.get("egress")),
        "rebootRequired": boolean(raw.get("rebootRequired")),
    })
}

#[derive(Debug, Clone)]
struct Reach {
    ok: bool,
    at: u64,
    last_ok_at: Option<u64>,
    down_since: Option<u64>,
    error: Option<&'static str>,
    ms: u64,
}

pub struct HealthFirewall {
    agent: AgentClient,
    agents: Arc<Agents>,
    /// Insertion order, as the TS `Map` keeps it.
    reach: Mutex<(Vec<String>, HashMap<String, Reach>)>,
}

impl HealthFirewall {
    pub fn new(agent: AgentClient, agents: Arc<Agents>) -> Self {
        Self {
            agent,
            agents,
            reach: Mutex::new((Vec::new(), HashMap::new())),
        }
    }

    pub async fn probe(&self, target: &AgentTarget) -> ProbeOutcome {
        let start = Instant::now();
        let r = self.agent.get_within(target, "/health/summary", PROBE_TIMEOUT_MS).await;
        let ms = start.elapsed().as_millis() as u64;
        match r {
            Ok(raw) => ProbeOutcome {
                reachable: true,
                ms,
                error: None,
                outdated: false,
                refused: None,
                summary: Some(clean_summary(&raw)),
            },
            Err(e) => {
                let text = e.to_string();
                if let Some(c) = REFUSED.captures(&text) {
                    return ProbeOutcome {
                        reachable: true,
                        ms,
                        error: None,
                        outdated: false,
                        refused: Some(c[1].to_string()),
                        summary: None,
                    };
                }
                if agent_answered(&e) {
                    return ProbeOutcome {
                        reachable: true,
                        ms,
                        error: None,
                        outdated: true,
                        refused: None,
                        summary: None,
                    };
                }
                ProbeOutcome {
                    reachable: false,
                    ms,
                    error: Some(reach_error_of(&e)),
                    outdated: false,
                    refused: None,
                    summary: None,
                }
            }
        }
    }

    fn record(&self, vm_id: &str, r: &ProbeOutcome) {
        let Ok(mut guard) = self.reach.lock() else { return };
        let (order, map) = &mut *guard;
        let now = now_ms();
        let prev = map.get(vm_id).cloned();
        let entry = Reach {
            ok: r.reachable,
            at: now,
            last_ok_at: if r.reachable {
                Some(now)
            } else {
                prev.as_ref().and_then(|p| p.last_ok_at)
            },
            down_since: if r.reachable {
                None
            } else {
                match &prev {
                    Some(p) if !p.ok => p.down_since,
                    _ => Some(now),
                }
            },
            error: r.error,
            ms: r.ms,
        };
        if map.insert(vm_id.to_string(), entry).is_none() {
            order.push(vm_id.to_string());
        }
    }

    /// The agents a probe can reach: the ones with a hostname on record.
    fn targets(&self) -> Vec<AgentTarget> {
        self.agents
            .agents()
            .iter()
            .filter_map(|i| {
                let h = str_field(i, "hostname").filter(|h| !h.is_empty())?;
                Some(AgentTarget::new(vm_id_of(i), h))
            })
            .collect()
    }

    fn known(&self, vm_id: &str) -> Option<AgentTarget> {
        self.targets().into_iter().find(|t| t.vm_id == vm_id)
    }

    /// Every agent once (`tick`), every `HEALTH_REACH_MS`.
    pub async fn tick(&self) {
        let agents = self.targets();
        let live: std::collections::HashSet<&str> = agents.iter().map(|a| a.vm_id.as_str()).collect();
        if let Ok(mut guard) = self.reach.lock() {
            let (order, map) = &mut *guard;
            order.retain(|id| live.contains(id.as_str()));
            map.retain(|id, _| live.contains(id.as_str()));
        }
        // Each agent recorded when it answers, not when the slowest one does.
        let probes = agents.iter().map(|a| async move {
            let r = self.probe(a).await;
            self.record(&a.vm_id, &r);
        });
        futures_util::future::join_all(probes).await;
    }

    /// For the heartbeat (`agents_reach`); empty until the first round.
    pub fn summary(&self) -> Vec<Value> {
        let Ok(guard) = self.reach.lock() else {
            return Vec::new();
        };
        let (order, map) = &*guard;
        order
            .iter()
            .filter_map(|id| {
                let r = map.get(id)?;
                Some(json!({"vm_id": id, "ok": r.ok, "at": r.at, "last_ok_at": r.last_ok_at, "down_since": r.down_since, "error": r.error, "ms": r.ms}))
            })
            .collect()
    }

    /// `health.probe`.
    pub async fn probe_command(&self, payload: Map<String, Value>) -> CommandOutcome {
        let vm_id = payload
            .get("vmId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Some(target) = self.known(&vm_id) else {
            let mut data = Map::new();
            data.insert("vmId".into(), json!(vm_id));
            data.insert("known".into(), json!(false));
            return CommandOutcome {
                ok: false,
                status: "failed".into(),
                message: Some("This firewall does not know that agent.".into()),
                data: Some(data),
            };
        };
        let r = self.probe(&target).await;
        self.record(&vm_id, &r);
        let mut data = Map::new();
        data.insert("vmId".into(), json!(vm_id));
        data.insert("known".into(), json!(true));
        data.extend(r.to_map());
        CommandOutcome {
            ok: true,
            status: "done".into(),
            message: None,
            data: Some(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_are_copied_field_by_field() {
        let raw = json!({"now": 5, "openclaw": {"state": "running", "gateway": true, "secret": 1}, "disk": {"usedPct": 40.5, "freeBytes": "x"}, "memory": [], "load1": "high", "cpus": 2, "clock": null, "dns": {"ok": true, "ms": 3, "reason": "Bad Reason"}, "egress": {"ok": "yes"}, "rebootRequired": false, "extra": "dropped"});
        assert_eq!(
            clean_summary(raw.as_object().expect("obj")),
            json!({"now": 5, "openclaw": {"state": "running", "gateway": true}, "disk": {"usedPct": 40.5, "freeBytes": null}, "memory": {"usedPct": null, "totalBytes": null}, "load1": null, "cpus": 2, "clock": null, "dns": {"ok": true, "ms": 3, "reason": null}, "egress": {"ok": false, "ms": null, "reason": null}, "rebootRequired": false})
        );
    }

    #[test]
    fn errors_are_classified() {
        assert_eq!(reach_error_of(&AgentError::Timeout), "timeout");
        let s = |status: u16| AgentError::Status {
            status,
            message: format!("agent {status}: x"),
        };
        assert_eq!(reach_error_of(&s(502)), "service_down");
        assert!(agent_answered(&s(404)));
        assert!(!agent_answered(&s(503)));
        assert_eq!(reach_error_of(&AgentError::Network(NetError::Refused)), "refused");
        assert_eq!(reach_error_of(&AgentError::Other("x".into())), "error");
    }
}
