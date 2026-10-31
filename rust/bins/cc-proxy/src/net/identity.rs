//! The identity map as the addon reads it: entry by entry, each field checked where it is used.
//!
//! `cc_contracts::identities` is the typed shape the agent writes, but a typed parse takes the
//! whole file or none of it, and one entry with a field of the wrong type would then cost every
//! agent its identity, and with it the emergency stop. The addon reads each field with `.get()`
//! and tests it where it is used (`is True`, `float(... or 0)`), so a bad field only costs its own
//! entry that one flag. This does the same.

use std::sync::{Arc, Mutex, PoisonError};

use cc_contracts::{MissingPolicy, MtimeCache, OnError};
use serde_json::Value;

/// One entry, with each flag as the addon's test reads it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ident {
    pub vm_id: Option<String>,
    pub private_ip: Option<String>,
    /// `ent.get("tailscale") is True`.
    pub tailscale: bool,
    /// `ent.get("locked") is True`.
    pub locked: bool,
    /// `ent.get("cp_inspect") is True`: the firewall agent has seen this box confirm it trusts the
    /// firewall's CA, so its control-plane and backup traffic is inspected (else passed through).
    pub cp_inspect: bool,
    /// `float(ent.get("code_until") or 0)`; 0 when it is not a number.
    pub code_until: f64,
    /// `float(ent.get("update_until") or 0)`; 0 when it is not a number.
    pub update_until: f64,
}

impl Ident {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let text = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_owned);
        let flag = |k: &str| obj.get(k) == Some(&Value::Bool(true));
        Some(Self {
            vm_id: text("vm_id"),
            private_ip: text("private_ip"),
            tailscale: flag("tailscale"),
            locked: flag("locked"),
            cp_inspect: flag("cp_inspect"),
            code_until: py_float(obj.get("code_until")),
            update_until: py_float(obj.get("update_until")),
        })
    }
}

/// Python's `float(x or 0)` for a deadline, with a failure read as 0 ("no window"), as the addon's
/// `except (TypeError, ValueError): return False` does.
pub fn py_float(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::Bool(true)) => 1.0,
        Some(Value::String(s)) if !s.is_empty() => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// The file as read, and the entries made from it.
type Parsed = (Arc<Vec<Value>>, Arc<Vec<Ident>>);

/// `identities.json`, re-read when its mtime changes (addon.py `_Cache`: a missing or broken file
/// keeps the last good map).
pub struct Identities {
    file: MtimeCache<Vec<Value>>,
    parsed: Mutex<Parsed>,
}

impl Identities {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            file: MtimeCache::new(path, MissingPolicy::Keep, OnError::KeepLast),
            parsed: Mutex::new((Arc::new(Vec::new()), Arc::new(Vec::new()))),
        }
    }

    /// Every entry that is an object, in file order.
    pub fn get(&self) -> Arc<Vec<Ident>> {
        let raw = self.file.get();
        let mut p = self.parsed.lock().unwrap_or_else(PoisonError::into_inner);
        if !Arc::ptr_eq(&p.0, &raw) {
            let idents = raw.iter().filter_map(Ident::from_value).collect();
            *p = (raw, Arc::new(idents));
        }
        p.1.clone()
    }

    /// `vm_id_for_ip`: the first entry whose `private_ip` is the source address.
    pub fn vm_id_for_ip(&self, ip: &str) -> Option<String> {
        if ip.is_empty() {
            return None;
        }
        self.get()
            .iter()
            .find(|e| e.private_ip.as_deref() == Some(ip))
            .and_then(|e| e.vm_id.clone())
    }

    /// The first entry for this agent, as the addon's loops find it.
    pub fn for_vm(&self, vm_id: Option<&str>) -> Option<Ident> {
        let vm_id = vm_id.filter(|v| !v.is_empty())?;
        self.get().iter().find(|e| e.vm_id.as_deref() == Some(vm_id)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_field_costs_only_its_own_flag() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("identities.json");
        std::fs::write(
            &path,
            r#"[{"private_ip":"10.0.0.3","vm_id":"a","locked":true,"code_until":"1e12"},
                {"private_ip":"10.0.0.4","vm_id":"b","tailscale":"true","update_until":"soon"},
                "not an object",
                {"private_ip":"10.0.0.5","vm_id":7}]"#,
        )?;
        let ids = Identities::new(&path);
        assert_eq!(ids.vm_id_for_ip("10.0.0.3").as_deref(), Some("a"));
        assert_eq!(ids.vm_id_for_ip("10.0.0.4").as_deref(), Some("b"));
        assert_eq!(ids.vm_id_for_ip("10.0.0.5"), None);
        let a = ids.for_vm(Some("a")).ok_or("a")?;
        assert!(a.locked);
        assert!(a.code_until > 1e11);
        let b = ids.for_vm(Some("b")).ok_or("b")?;
        assert!(!b.tailscale, "only a real true counts");
        assert!(b.update_until.abs() < f64::EPSILON);
        assert!(ids.for_vm(None).is_none());
        Ok(())
    }
}
