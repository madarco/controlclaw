//! When this firewall first saw each agent box in its identity map (T-103, `new-agents.ts`).
//!
//! One thing reads it: a new agent's first model. Binding a model credential the organisation has
//! already approved to an agent created a few minutes ago needs no second code
//! (`Llm::new_agent_bind`), and "a few minutes ago" has to be something the firewall observed, not
//! something the control plane says. The clock starts when an agent first appears in a sync after
//! this process started, and nothing is persisted.
//!
//! Every agent present in the FIRST sync is the baseline and never counts as new. Failing towards a
//! code is the right way round.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const NEW_AGENT_WINDOW_MS: i64 = 30 * 60_000;

#[derive(Default)]
struct Seen {
    seen: HashMap<String, Option<i64>>,
    current: HashSet<String>,
    baselined: bool,
}

pub struct AgentFirstSeen {
    inner: Mutex<Seen>,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Default for AgentFirstSeen {
    fn default() -> Self {
        Self::new(Box::new(super::now_ms))
    }
}

impl AgentFirstSeen {
    pub fn new(now: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            inner: Mutex::new(Seen::default()),
            now,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every vm id in one sync of the identity map.
    pub fn observe<I: IntoIterator<Item = String>>(&self, vm_ids: I) {
        let now = (self.now)();
        let mut s = self.lock();
        let at = s.baselined.then_some(now);
        s.current = vm_ids.into_iter().collect();
        let ids: Vec<String> = s.current.iter().cloned().collect();
        for id in ids {
            s.seen.entry(id).or_insert(at);
        }
        s.baselined = true;
    }

    /// In the latest identity map: a deleted agent's bindings approve nothing.
    pub fn is_live(&self, vm_id: &str) -> bool {
        self.lock().current.contains(vm_id)
    }

    /// When this agent first appeared, or `None` when it was in the baseline or never seen.
    pub fn first_seen_at(&self, vm_id: &str) -> Option<i64> {
        self.lock().seen.get(vm_id).copied().flatten()
    }

    /// First seen after the baseline, and no longer ago than the window.
    pub fn is_new(&self, vm_id: &str) -> bool {
        self.is_new_within(vm_id, NEW_AGENT_WINDOW_MS)
    }

    pub fn is_new_within(&self, vm_id: &str, window_ms: i64) -> bool {
        self.first_seen_at(vm_id)
            .is_some_and(|at| (self.now)() - at <= window_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_first_sync_is_the_baseline_and_later_agents_are_new_for_the_window() {
        let clock = Arc::new(AtomicI64::new(1_000_000));
        let c = clock.clone();
        let seen = AgentFirstSeen::new(Box::new(move || c.load(Ordering::SeqCst)));
        assert!(!seen.is_new("vm-old"), "nothing is new before the first sync");
        seen.observe(ids(&["vm-old"]));
        assert!(!seen.is_new("vm-old"), "the baseline never counts as new");
        assert!(seen.is_live("vm-old"));
        clock.fetch_add(1000, Ordering::SeqCst);
        seen.observe(ids(&["vm-old", "vm-new"]));
        assert!(seen.is_new("vm-new"));
        assert_eq!(seen.first_seen_at("vm-new"), Some(1_001_000));
        clock.fetch_add(NEW_AGENT_WINDOW_MS, Ordering::SeqCst);
        assert!(seen.is_new("vm-new"), "the window is inclusive");
        clock.fetch_add(1, Ordering::SeqCst);
        assert!(!seen.is_new("vm-new"));
        seen.observe(ids(&["vm-new"]));
        assert!(!seen.is_live("vm-old"), "gone from the map, not live");
        assert!(!seen.is_new("vm-never"));
    }
}
