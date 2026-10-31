//! The asks for single calls a person approves (an app action, an MCP tool call), shared by the
//! connector gate and the MCP checks (`call-asks.ts`): one ask per exact call (its key), kept
//! across a restart, and an approval used once, by one copy of the call at a time.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::integrations::js;

/// An ask nobody answered in this long is asked again under a new id; its approval is kept as long.
pub const ASK_KEEP_MS: i64 = 24 * 60 * 60_000;
/// A retried call waits this long for an approval the bridge is about to write (it polls every 3 s).
pub const GRANT_WAIT_MS: i64 = 6_000;
/// Asks one agent may have waiting: more push out its own oldest, never another agent's.
pub const ASKS_PER_AGENT: usize = 50;
pub const ASKS_IN_ALL: usize = 2000;

/// The permission path (`permissions.ts`, `grants.ts`): file an ask, and use its approval once.
pub trait Asks: Send + Sync {
    fn ask(&self, rec: Value) -> Result<(), String>;
    fn granted(&self, permission_id: &str) -> bool;
    fn consume(&self, permission_id: &str);
}

/// The asks the TS files: a line in `PENDING_PATH` for the bridge, approvals from W3's grants.
pub struct PendingFile {
    pub path: PathBuf,
    pub app: Arc<crate::app::App>,
}

impl Asks for PendingFile {
    fn ask(&self, rec: Value) -> Result<(), String> {
        cc_store::append_jsonl(&self.path, &rec, 0o640).map_err(|e| e.to_string())
    }
    fn granted(&self, id: &str) -> bool {
        self.app.contracts.grants.get().is_some_and(|g| g.active(id))
    }
    fn consume(&self, id: &str) {
        if let Some(g) = self.app.contracts.grants.get() {
            g.consume(id);
        }
    }
}

/// The same id the proxy and the email rules compute for a scope (`permission_id_for` in addon.py).
pub fn permission_id_for(scope: &str) -> String {
    let h = hex::encode(Sha256::digest(scope.as_bytes()));
    format!("perm_{}", &h[..32])
}

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    pid: String,
    asked_at: f64,
    line: Option<String>,
    vm_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Approval {
    pub key: String,
    pub pid: String,
    pub line: Option<String>,
}

/// An approval marked used while a hold is made (`take`).
pub struct Taken {
    key: String,
    pid: String,
}

pub struct Filed {
    pub pid: String,
    pub summary: String,
    pub expires_at: String,
}

struct State {
    /// In insertion order, as the TS `Map` keeps them.
    asked: Vec<(String, Entry)>,
    /// Approvals a call is using right now: one approval runs one call.
    in_flight: HashSet<String>,
    /// Approvals marked used while a hold is made.
    taken: HashSet<String>,
}

pub struct CallAsks {
    asks: Option<Arc<dyn Asks>>,
    state_path: Option<PathBuf>,
    label: String,
    grant_wait_ms: i64,
    state: Mutex<State>,
    now: fn() -> i64,
}

impl CallAsks {
    pub fn new(asks: Option<Arc<dyn Asks>>, state_path: Option<PathBuf>, label: &str, grant_wait_ms: i64) -> Self {
        let asked = state_path.as_deref().map(load).unwrap_or_default();
        Self {
            asks,
            state_path,
            label: label.to_string(),
            grant_wait_ms,
            state: Mutex::new(State {
                asked,
                in_flight: HashSet::new(),
                taken: HashSet::new(),
            }),
            now: js::now_ms,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether anyone can be asked at all.
    pub fn enabled(&self) -> bool {
        self.asks.is_some()
    }

    fn save(&self, st: &State) {
        let Some(path) = &self.state_path else { return };
        let list: Vec<Value> = st
            .asked
            .iter()
            .map(|(k, e)| {
                let mut o = Map::new();
                o.insert("pid".into(), json!(e.pid));
                o.insert("askedAt".into(), json!(e.asked_at));
                if let Some(l) = &e.line {
                    o.insert("line".into(), json!(l));
                }
                if let Some(v) = &e.vm_id {
                    o.insert("vmId".into(), json!(v));
                }
                json!([k, o])
            })
            .collect();
        let text = js::stringify(&Value::Array(list));
        if let Err(e) = cc_store::write_atomic(path, text.as_bytes(), 0o600, cc_store::TmpName::Suffix) {
            tracing::info!("[{}] could not keep the asks: {e}", self.label);
        }
    }

    /// The approval for this exact call, when a person gave it. Waits a moment for one the bridge
    /// is about to write. Finding it and marking it in flight happen under one lock.
    pub async fn approval_for(&self, key: &str) -> Option<Approval> {
        let asks = self.asks.as_ref()?;
        let until = (self.now)() + self.grant_wait_ms;
        loop {
            {
                let mut st = self.lock();
                let a = st.asked.iter().find(|(k, _)| k == key).map(|(_, e)| e.clone())?;
                // In flight: another copy of this call is using it. That one runs; this one is asked again.
                if st.in_flight.contains(&a.pid) || st.taken.contains(&a.pid) {
                    return None;
                }
                if asks.granted(&a.pid) {
                    st.in_flight.insert(a.pid.clone());
                    return Some(Approval {
                        key: key.to_string(),
                        pid: a.pid,
                        line: a.line,
                    });
                }
            }
            if (self.now)() >= until {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// An approval used up: the call it was for is being sent, or held with it.
    pub fn use_approval(&self, a: &Approval) {
        if let Some(asks) = &self.asks {
            asks.consume(&a.pid);
        }
        let mut st = self.lock();
        st.in_flight.remove(&a.pid);
        st.taken.remove(&a.pid);
        st.asked.retain(|(k, _)| *k != a.key);
        self.save(&st);
    }

    /// Mark an approval used before something that may not come back (a hold being made): no copy
    /// of the call can use it from here, and the ask stays the one a copy is told about.
    /// `put_back` undoes it when nothing used it after all; `drop_taken` ends it for good when the
    /// request ended in between, so the next call is asked again.
    /// The caller holds what this returns in a guard that calls `put_back` or `drop_taken`, also when
    /// its wait is cancelled (the connector gate's `TakenGuard`, the MCP checks' `Taken`).
    #[must_use = "hold it in a guard, or the approval stays taken"]
    pub fn take(&self, a: &Approval) -> Taken {
        self.lock().taken.insert(a.pid.clone());
        Taken {
            key: a.key.clone(),
            pid: a.pid.clone(),
        }
    }

    pub fn put_back(&self, t: &Taken) {
        self.lock().taken.remove(&t.pid);
    }

    pub fn drop_taken(&self, t: &Taken) {
        let mut st = self.lock();
        st.taken.remove(&t.pid);
        st.asked.retain(|(k, _)| *k != t.key);
        self.save(&st);
    }

    /// A call refused after its approval was found: the approval stays its retry's.
    pub fn release(&self, pid: &str) {
        self.lock().in_flight.remove(pid);
    }

    /// The Activity line of the call's first ask, so the next one takes its place.
    pub fn line_of(&self, key: &str) -> Option<String> {
        self.lock()
            .asked
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, e)| e.line.clone())
    }

    pub fn set_line(&self, key: &str, line: &str) {
        let mut st = self.lock();
        let mut changed = false;
        if let Some((_, e)) = st.asked.iter_mut().find(|(k, _)| k == key)
            && e.line.is_none()
        {
            e.line = Some(line.to_string());
            changed = true;
        }
        if changed {
            self.save(&st);
        }
    }

    /// The ask for one call: the one filed already, or a new one with a fresh id, so an approval is
    /// for one call. None when it could not be filed. `ask` is the record without the fields made here.
    pub fn file(
        &self,
        key: &str,
        vm_id: &str,
        scope_base: &str,
        summary: &str,
        ask: Map<String, Value>,
    ) -> Option<Filed> {
        let now = (self.now)();
        let expires = |at: f64| js::iso(at as i64 + ASK_KEEP_MS);
        let mut st = self.lock();
        st.asked
            .retain(|(_, v)| (now as f64 - v.asked_at) <= ASK_KEEP_MS as f64);
        if let Some((_, had)) = st.asked.iter().find(|(k, _)| k == key) {
            return Some(Filed {
                pid: had.pid.clone(),
                summary: summary.to_string(),
                expires_at: expires(had.asked_at),
            });
        }
        let asks = self.asks.as_ref()?;
        let scope = format!("{scope_base} #{}", hex::encode(rand::random::<[u8; 6]>()));
        let pid = permission_id_for(&scope);
        let asked_at = now as f64;
        let mut rec = Map::new();
        rec.insert("summary".into(), json!(summary));
        rec.extend(ask);
        rec.insert("permission_id".into(), json!(pid));
        rec.insert("vm_id".into(), json!(vm_id));
        rec.insert("scope".into(), json!(scope));
        rec.insert("kind".into(), json!("app_call"));
        rec.insert("expires_at".into(), json!(expires(asked_at)));
        if let Err(e) = asks.ask(Value::Object(rec)) {
            tracing::info!("[{}] could not file an ask: {e}", self.label);
            return None;
        }
        // One agent's asks push out only its own oldest, never another agent's.
        let own: Vec<String> = st
            .asked
            .iter()
            .filter(|(_, v)| v.vm_id.as_deref() == Some(vm_id))
            .map(|(k, _)| k.clone())
            .collect();
        if own.len() >= ASKS_PER_AGENT {
            let oldest = own[0].clone();
            st.asked.retain(|(k, _)| *k != oldest);
        }
        st.asked.push((
            key.to_string(),
            Entry {
                pid: pid.clone(),
                asked_at,
                line: None,
                vm_id: Some(vm_id.to_string()),
            },
        ));
        // And all of them together stay bounded (entries from before `vmId` was kept have no agent).
        if st.asked.len() > ASKS_IN_ALL {
            st.asked.remove(0);
        }
        self.save(&st);
        Some(Filed {
            pid,
            summary: summary.to_string(),
            expires_at: expires(asked_at),
        })
    }
}

fn load(path: &std::path::Path) -> Vec<(String, Entry)> {
    let Some(Value::Array(list)) = cc_store::read_json::<Value>(path) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|e| {
            let pair = e.as_array()?;
            let key = pair.first()?.as_str()?;
            let v = pair.get(1)?;
            let pid = v.get("pid")?.as_str()?;
            let asked_at = v.get("askedAt")?.as_f64()?;
            Some((
                key.to_string(),
                Entry {
                    pid: pid.to_string(),
                    asked_at,
                    line: v.get("line").and_then(Value::as_str).map(str::to_string),
                    vm_id: v.get("vmId").and_then(Value::as_str).map(str::to_string),
                },
            ))
        })
        .collect()
}
