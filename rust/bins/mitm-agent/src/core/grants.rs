//! The proxy's `grants.json` (`grants.ts`): permission ids that may pass an Ask rule until
//! `expires_at` (epoch seconds). People's approvals (the permission bridge) and the AI's (the
//! judge, `by: "ai"`) go through this one store, so neither overwrites the other's. Written
//! atomically; the proxy reloads it when its mtime changes.

use std::path::PathBuf;
use std::sync::Mutex;

use cc_contracts::files::FileSpec;
use serde_json::{Map, Value, json};

pub struct GrantStore {
    path: PathBuf,
    grants: Mutex<Map<String, Value>>,
}

fn expires_at(g: &Value) -> f64 {
    g.get("expires_at").and_then(Value::as_f64).unwrap_or(f64::NAN)
}

// `get`, `entries` and `size` are for the AI judge (W4) and the gates (W5).
#[allow(dead_code)]
impl GrantStore {
    pub fn new(path: PathBuf) -> Self {
        let grants = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        Self {
            path,
            grants: Mutex::new(grants),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Map<String, Value>> {
        self.grants.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, id: &str) -> Option<Value> {
        self.lock().get(id).cloned()
    }

    /// Whether `id` has a grant that has not expired at `now`.
    pub fn active(&self, id: &str, now: u64) -> bool {
        self.lock().get(id).is_some_and(|g| expires_at(g) > now as f64)
    }

    pub fn entries(&self) -> Vec<(String, Value)> {
        self.lock().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub fn set(&self, id: &str, expires: u64, scope: &str, by_ai: bool) {
        let mut g = self.lock();
        let mut grant = json!({"expires_at": expires, "scope": scope});
        if by_ai && let Some(o) = grant.as_object_mut() {
            o.insert("by".into(), json!("ai"));
        }
        g.insert(id.to_string(), grant);
        self.save(&g);
    }

    pub fn delete(&self, id: &str) {
        let mut g = self.lock();
        if g.shift_remove(id).is_some() {
            self.save(&g);
        }
    }

    /// Drop expired grants so the file does not grow for ever.
    pub fn prune(&self, now: u64) {
        let mut g = self.lock();
        let before = g.len();
        g.retain(|_, v| expires_at(v) > now as f64);
        if g.len() != before {
            self.save(&g);
        }
    }

    pub fn size(&self) -> usize {
        self.lock().len()
    }

    /// `JSON.stringify(grants, null, 2)` to `.<name>.tmp`, then renamed (`FileSpec::GRANTS`).
    fn save(&self, g: &Map<String, Value>) {
        let spec = FileSpec::GRANTS;
        let written = serde_json::to_vec_pretty(g)
            .map_err(std::io::Error::other)
            .and_then(|data| cc_store::write_atomic(&self.path, &data, spec.mode, spec.tmp));
        if let Err(e) = written {
            tracing::error!("[perm] could not write {}: {e}", self.path.display());
        }
    }
}

/// Epoch seconds now (`Math.floor(Date.now() / 1000)`).
pub fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_expire_and_are_written() {
        let d = tempfile::tempdir().expect("dir");
        let path = d.path().join("grants.json");
        let s = GrantStore::new(path.clone());
        s.set("p1", 100, "GET x", false);
        s.set("p2", 50, "EMAIL a", true);
        assert!(s.active("p1", 99));
        assert!(!s.active("p1", 100));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "{\n  \"p1\": {\n    \"expires_at\": 100,\n    \"scope\": \"GET x\"\n  },\n  \"p2\": {\n    \"expires_at\": 50,\n    \"scope\": \"EMAIL a\",\n    \"by\": \"ai\"\n  }\n}"
        );
        s.prune(60);
        assert_eq!(s.size(), 1);
        assert_eq!(GrantStore::new(path).size(), 1);
        s.delete("p1");
        s.delete("p1");
        assert_eq!(s.size(), 0);
    }
}
