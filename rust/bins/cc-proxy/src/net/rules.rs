//! `rules.json` as the addon reads it: entry by entry, each field tested where it is used.
//!
//! The typed `cc_contracts::rules::Rule` takes the whole file or none of it, so one entry with an
//! odd field (a `match_port` written as `"5432"`, which Python's `int()` takes) would cost every
//! rule. The addon reads each field with `.get()`; this keeps each rule and decides per field, and
//! where the addon would raise on a field, the rule matches nothing (the addon's callers catch the
//! error and do not let the connection through).

use std::sync::{Arc, Mutex, PoisonError};

use cc_contracts::{MissingPolicy, MtimeCache, OnError};
use serde_json::Value;

use crate::net::hosts::host_matches;

/// A rule's `match_port`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    /// Absent or null: any port.
    Any,
    Port(i64),
    /// Present but not something `int()` takes: the rule matches nothing.
    Invalid,
}

/// One rule, with each field as the addon's use of it reads it. `raw` is the entry as written,
/// for what later steps read from it.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleView {
    pub raw: Value,
    pub id: Option<String>,
    pub name: Option<String>,
    /// `rule.get("effect", "allow")` where it decides; `None` when absent or not a string.
    pub effect: Option<String>,
    /// `rule.get("priority", 1000)`.
    pub priority: f64,
    /// `None`: absent. `Some(None)`: present but not a string (matches nothing).
    pub match_domain: Option<Option<String>>,
    pub match_port: PortSpec,
    /// `None`: org-wide. `Some(v)`: only for the agent whose id equals `v` (a non-string never does).
    pub vm_id: Option<Value>,
}

impl RuleView {
    pub fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let text = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            raw: v.clone(),
            id: text("id"),
            name: text("name"),
            effect: text("effect"),
            // Sorted on the value as written (`r.get("priority", 1000)`): 1.5 stays 1.5.
            priority: match obj.get("priority") {
                None | Some(Value::Null) => 1000.0,
                Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()).unwrap_or(f64::MAX),
                Some(Value::Bool(b)) => f64::from(u8::from(*b)),
                // A number written as text keeps its place: a block rule must not sort last.
                Some(Value::String(s)) => s
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite())
                    .unwrap_or(f64::MAX),
                Some(_) => f64::MAX,
            },
            match_domain: obj
                .get("match_domain")
                .filter(|v| !v.is_null())
                .map(|v| v.as_str().map(str::to_owned)),
            match_port: match obj.get("match_port") {
                None | Some(Value::Null) => PortSpec::Any,
                Some(p) => py_int(p).map_or(PortSpec::Invalid, PortSpec::Port),
            },
            vm_id: obj.get("vm_id").filter(|v| !v.is_null()).cloned(),
        })
    }

    /// `_rule_applies_to_vm`: org-wide, or this agent's.
    pub fn applies_to(&self, vm_id: Option<&str>) -> bool {
        match &self.vm_id {
            None => true,
            Some(Value::String(rv)) => Some(rv.as_str()) == vm_id,
            Some(_) => false,
        }
    }

    /// The rule's domain matches `host`; `default` is what an absent `match_domain` means
    /// (`*` for website rules, nothing for tunnels).
    pub fn domain_matches(&self, host: &str, default: &str) -> bool {
        match &self.match_domain {
            None => host_matches(default, host),
            Some(Some(d)) => host_matches(d, host),
            Some(None) => false,
        }
    }

    /// `mp is not None and port is not None and int(mp) != int(port)` rejects.
    pub fn port_matches(&self, port: Option<u16>) -> bool {
        match (self.match_port, port) {
            (PortSpec::Invalid, _) => false,
            (PortSpec::Port(mp), Some(p)) => mp == i64::from(p),
            _ => true,
        }
    }
}

/// Python's `int(x)` for a JSON value: integers, floats cut toward zero, booleans, and strings of
/// an integer (with spaces around). Anything else raises in Python and is `None` here.
pub fn py_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i64)),
        Value::Bool(b) => Some(i64::from(*b)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The file as read, and the rules made from it.
type Parsed = (Arc<Vec<Value>>, Arc<Vec<RuleView>>);

/// `rules.json`, re-read when its mtime changes (`_Cache`: a missing or broken file keeps the last
/// good list).
pub struct Rules {
    file: MtimeCache<Vec<Value>>,
    parsed: Mutex<Parsed>,
    /// Whether `rules.json` has been read whole since the proxy started. Until it has (a cold
    /// start: the agent has not synced yet, `/run` is empty after a reboot), nothing is allowed.
    loaded: std::sync::atomic::AtomicBool,
}

impl Rules {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            file: MtimeCache::new(path, MissingPolicy::Keep, OnError::KeepLast),
            parsed: Mutex::new((Arc::new(Vec::new()), Arc::new(Vec::new()))),
            loaded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Whether the rules were ever read: once `rules.json` has parsed, a later missing or broken
    /// file keeps the last good list (as the addon's `_Cache`), so this stays true.
    pub fn loaded(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.loaded.load(Ordering::Relaxed) {
            return true;
        }
        let ok = std::fs::read(self.file.path())
            .ok()
            .is_some_and(|b| serde_json::from_slice::<Vec<Value>>(&b).is_ok());
        if ok {
            self.loaded.store(true, Ordering::Relaxed);
        }
        ok
    }

    /// Every entry that is an object, in file order.
    pub fn get(&self) -> Arc<Vec<RuleView>> {
        let raw = self.file.get();
        let mut p = self.parsed.lock().unwrap_or_else(PoisonError::into_inner);
        if !Arc::ptr_eq(&p.0, &raw) {
            let rules = raw.iter().filter_map(RuleView::from_value).collect();
            *p = (raw, Arc::new(rules));
        }
        p.1.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(v: Value) -> RuleView {
        RuleView::from_value(&v).unwrap_or_else(|| RuleView::from_value(&json!({})).expect("empty rule"))
    }

    #[test]
    fn reads_fields_as_the_addon_uses_them() {
        let r = rule(json!({"match_port": "5432", "priority": 5, "vm_id": "a"}));
        assert!(r.port_matches(Some(5432)));
        assert!(!r.port_matches(Some(5433)));
        assert!(r.port_matches(None));
        assert!(r.applies_to(Some("a")));
        assert!(!r.applies_to(Some("b")));
        assert!(!r.applies_to(None));
        assert!((r.priority - 5.0).abs() < f64::EPSILON);
        assert!((rule(json!({"priority": "1"})).priority - 1.0).abs() < f64::EPSILON);
        assert!((rule(json!({"priority": 1.5})).priority - 1.5).abs() < f64::EPSILON);
        // A port int() would refuse: the rule matches nothing, whatever the port.
        let bad = rule(json!({"match_port": "https"}));
        assert!(!bad.port_matches(Some(443)));
        assert!(!bad.port_matches(None));
        assert!(rule(json!({"match_port": 443.7})).port_matches(Some(443)));
        // A vm_id that is not a string applies to nobody; null is org-wide.
        assert!(!rule(json!({"vm_id": 7})).applies_to(Some("7")));
        assert!(rule(json!({"vm_id": null})).applies_to(Some("x")));
        // match_domain: absent takes the caller's default, a non-string matches nothing.
        assert!(rule(json!({})).domain_matches("a.example", "*"));
        assert!(!rule(json!({})).domain_matches("a.example", ""));
        assert!(!rule(json!({"match_domain": 5})).domain_matches("a.example", "*"));
        assert!(rule(json!({"match_domain": "*.example"})).domain_matches("a.example", ""));
    }

    #[test]
    fn one_odd_entry_costs_nothing_else() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("rules.json");
        std::fs::write(
            &path,
            r#"[{"name":"a","match_port":"x"}, 5, {"name":"b","priority":"hi"}]"#,
        )?;
        let rules = Rules::new(&path).get();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].name.as_deref(), Some("b"));
        Ok(())
    }
}
