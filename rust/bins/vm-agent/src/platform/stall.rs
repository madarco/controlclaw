//! Which tool calls and runs OpenClaw has started and not finished, from its audit ledger
//! (`stall.ts`). A call that hangs has `started` and never `finished`, and nothing else says so; the
//! health check reads `oldest()` and says how long it has been.
//!
//! A gateway that exits never writes the ends of its calls, so `reset()` is called on every new
//! connection to the gateway; a `started` from before it is not taken up again. A call waiting for
//! its owner's approval is not stuck: `waiting()` is called while an approval is open.

use indexmap_lite::OrderedMap;
use serde_json::Value;

use super::health_summary::Stalled;

/// More than this many open entries means ends are being missed; the oldest are dropped.
const MAX_OPEN: usize = 500;

#[derive(Default)]
pub struct StallTracker {
    open: OrderedMap<Stalled>,
    last_event_at: i64,
    reset_at: i64,
    waited_until: i64,
}

impl StallTracker {
    /// Feed ledger events (`{kind, status, toolCallId, runId, toolName, occurredAt}`) in sequence order.
    pub fn record(&mut self, events: &[Value]) {
        for ev in events {
            let kind = ev.get("kind").and_then(Value::as_str);
            let id = |k: &str| ev.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
            let key = match kind {
                Some("tool_action") => id("toolCallId").map(|i| format!("tool:{i}")),
                Some("agent_run") => id("runId").map(|i| format!("run:{i}")),
                _ => None,
            };
            let (Some(key), Some(at)) = (key, ev.get("occurredAt").and_then(Value::as_f64)) else {
                continue;
            };
            let at = at as i64;
            self.last_event_at = self.last_event_at.max(at);
            if ev.get("status").and_then(Value::as_str) == Some("started") {
                if at < self.reset_at {
                    continue;
                }
                let tool = kind == Some("tool_action");
                self.open.set(
                    key,
                    Stalled {
                        kind: if tool { "tool" } else { "run" },
                        name: if tool { id("toolName").map(str::to_string) } else { None },
                        started_at: at,
                    },
                );
                if self.open.len() > MAX_OPEN {
                    self.open.pop_front();
                }
            } else {
                self.open.remove(&key);
            }
        }
    }

    pub fn reset(&mut self, now: i64) {
        self.open.clear();
        self.reset_at = now;
    }

    /// An approval is open at `now`: whatever is running may be waiting for it.
    pub fn waiting(&mut self, now: i64) {
        self.waited_until = self.waited_until.max(now);
    }

    /// The tool call running longest, if it has for `min_ms`; else a run that has, when the ledger
    /// has also been silent for `min_ms` (a run that is still calling tools is working).
    pub fn oldest(&self, now: i64, min_ms: i64) -> Option<Stalled> {
        let (mut tool, mut run): (Option<Stalled>, Option<Stalled>) = (None, None);
        for opened in self.open.values() {
            // Time spent waiting for an approval is not time spent running.
            let mut s = opened.clone();
            if s.started_at < self.waited_until {
                s.started_at = self.waited_until;
            }
            if now - s.started_at < min_ms {
                continue;
            }
            let slot = if s.kind == "tool" { &mut tool } else { &mut run };
            if slot.as_ref().is_none_or(|o| s.started_at < o.started_at) {
                *slot = Some(s);
            }
        }
        tool.or_else(|| run.filter(|_| now - self.last_event_at >= min_ms))
    }
}

/// A map that keeps insertion order, as a JS `Map` does (a re-set key keeps its place).
mod indexmap_lite {
    use std::collections::{BTreeMap, HashMap};

    pub struct OrderedMap<V> {
        by_key: HashMap<String, (u64, V)>,
        order: BTreeMap<u64, String>,
        next: u64,
    }

    impl<V> Default for OrderedMap<V> {
        fn default() -> Self {
            Self {
                by_key: HashMap::new(),
                order: BTreeMap::new(),
                next: 0,
            }
        }
    }

    impl<V> OrderedMap<V> {
        pub fn set(&mut self, key: String, v: V) {
            if let Some(e) = self.by_key.get_mut(&key) {
                e.1 = v;
                return;
            }
            self.next += 1;
            self.order.insert(self.next, key.clone());
            self.by_key.insert(key, (self.next, v));
        }
        pub fn remove(&mut self, key: &str) {
            if let Some((i, _)) = self.by_key.remove(key) {
                self.order.remove(&i);
            }
        }
        pub fn pop_front(&mut self) {
            if let Some((_, k)) = self.order.pop_first() {
                self.by_key.remove(&k);
            }
        }
        pub fn len(&self) -> usize {
            self.by_key.len()
        }
        pub fn clear(&mut self) {
            self.by_key.clear();
            self.order.clear();
        }
        pub fn values(&self) -> impl Iterator<Item = &V> {
            self.order.values().filter_map(|k| self.by_key.get(k).map(|e| &e.1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(id: &str, status: &str, at: i64) -> Value {
        json!({ "kind": "tool_action", "toolCallId": id, "toolName": "browser", "status": status, "occurredAt": at })
    }

    #[test]
    fn an_unfinished_call_is_the_oldest_once_it_is_old_enough() {
        let mut t = StallTracker::default();
        t.record(&[
            tool("a", "started", 0),
            tool("b", "started", 10),
            tool("b", "succeeded", 20),
        ]);
        assert_eq!(t.oldest(50, 100), None);
        let s = t.oldest(200, 100).expect("stalled");
        assert_eq!((s.kind, s.name.as_deref(), s.started_at), ("tool", Some("browser"), 0));
    }

    #[test]
    fn a_reset_drops_what_was_open_and_ignores_older_starts() {
        let mut t = StallTracker::default();
        t.record(&[tool("a", "started", 0)]);
        t.reset(100);
        t.record(&[tool("a", "started", 50)]);
        assert_eq!(t.oldest(1000, 100), None);
    }

    #[test]
    fn waiting_for_an_approval_is_not_running() {
        let mut t = StallTracker::default();
        t.record(&[tool("a", "started", 0)]);
        t.waiting(500);
        assert_eq!(t.oldest(550, 100), None);
        assert_eq!(t.oldest(700, 100).expect("s").started_at, 500);
    }

    #[test]
    fn a_run_counts_only_when_the_ledger_is_silent() {
        let mut t = StallTracker::default();
        t.record(&[
            json!({ "kind": "agent_run", "runId": "r", "status": "started", "occurredAt": 0 }),
            tool("x", "started", 900),
            tool("x", "succeeded", 950),
        ]);
        assert_eq!(t.oldest(1000, 100), None);
        assert_eq!(t.oldest(1100, 100).expect("run").kind, "run");
    }
}
