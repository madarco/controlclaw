//! What this box knows about Opens through its firewall (`access-state.ts`): where the firewall is,
//! and which enrolled browsers were revoked. Both arrive only in firewall-signed pushes
//! (`access_push.rs`) and neither is secret, so it is a plain JSON file, `<STATE_DIR>/access.json`.
//!
//! A revoked id is kept for `REVOKED_KEEP_MS`, the longest a session can live; after that no
//! session naming it can still be valid.

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{Map, Value};

pub const REVOKED_KEEP_MS: i64 = 12 * 60 * 60_000;

#[derive(Debug, Clone, Default)]
struct State {
    /// `firewallOrigin`.
    firewall_origin: Option<String>,
    /// deviceId -> when it was revoked (ms).
    revoked: Map<String, Value>,
    /// Fields a newer build wrote; kept on every write.
    extra: Map<String, Value>,
}

pub struct AccessState {
    path: PathBuf,
    /// Read once from disk, then kept (`cache` in the TS).
    cache: Mutex<Option<State>>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `https://` and a DNS name, nothing else: no path, no port, no userinfo (`validFirewallOrigin`).
pub fn valid_firewall_origin(origin: &str) -> bool {
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |l: &&str| {
        let b = l.as_bytes();
        !b.is_empty()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    };
    labels.len() >= 2 && labels.iter().all(label_ok) && origin.len() <= 261
}

impl AccessState {
    pub fn new(state_dir: &std::path::Path) -> Self {
        Self {
            path: state_dir.join("access.json"),
            cache: Mutex::new(None),
        }
    }

    fn load(&self, cache: &mut Option<State>) -> State {
        if let Some(s) = cache {
            return s.clone();
        }
        let state = std::fs::read(&self.path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
            .and_then(|v| match v {
                Value::Object(mut m) => {
                    let origin = match m.remove("firewallOrigin") {
                        Some(Value::String(s)) if valid_firewall_origin(&s) => Some(s),
                        _ => None,
                    };
                    let revoked = match m.remove("revoked") {
                        Some(Value::Object(r)) => r,
                        _ => Map::new(),
                    };
                    Some(State {
                        firewall_origin: origin,
                        revoked,
                        extra: m,
                    })
                }
                _ => None,
            })
            .unwrap_or_default();
        *cache = Some(state.clone());
        state
    }

    /// The cache moves on only when the file was written, so a box never says it revoked what a
    /// restart would forget.
    fn save(&self, cache: &mut Option<State>, state: State) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut out = Map::new();
        out.insert(
            "firewallOrigin".into(),
            state.firewall_origin.clone().map(Value::String).unwrap_or(Value::Null),
        );
        out.insert("revoked".into(), Value::Object(state.revoked.clone()));
        for (k, v) in &state.extra {
            out.entry(k.clone()).or_insert_with(|| v.clone());
        }
        let raw = serde_json::to_vec(&Value::Object(out)).unwrap_or_default();
        if let Err(e) = cc_store::write_atomic(&self.path, &raw, 0o600, cc_store::TmpName::Suffix) {
            tracing::error!("[access] could not save {}: {e}", self.path.display());
            return Err(e);
        }
        *cache = Some(state);
        Ok(())
    }

    pub fn firewall_origin(&self) -> Option<String> {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        self.load(&mut c).firewall_origin
    }

    pub fn set_firewall_origin(&self, origin: &str) -> std::io::Result<()> {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = self.load(&mut c);
        if state.firewall_origin.as_deref() == Some(origin) {
            return Ok(());
        }
        state.firewall_origin = Some(origin.to_string());
        self.save(&mut c, state)
    }

    pub fn revoke_devices(&self, ids: &[String], now: i64) -> std::io::Result<()> {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = self.load(&mut c);
        let mut revoked = prune(&state.revoked, now);
        for id in ids {
            revoked.insert(id.clone(), Value::from(now));
        }
        state.revoked = revoked;
        self.save(&mut c, state)
    }

    /// Forget every revoked id: after the session secret was rotated, which ends them all anyway.
    pub fn clear_revoked(&self) -> std::io::Result<()> {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = self.load(&mut c);
        state.revoked = Map::new();
        self.save(&mut c, state)
    }

    pub fn is_revoked(&self, device_id: &str, now: i64) -> bool {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let state = self.load(&mut c);
        // `typeof at === "number"`: any JSON number, fractions included.
        state
            .revoked
            .get(device_id)
            .and_then(Value::as_f64)
            .is_some_and(|at| (now as f64) - at < REVOKED_KEEP_MS as f64)
    }
}

fn prune(revoked: &Map<String, Value>, now: i64) -> Map<String, Value> {
    revoked
        .iter()
        .filter(|(_, at)| at.as_f64().is_some_and(|at| (now as f64) - at < REVOKED_KEEP_MS as f64))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert!(valid_firewall_origin("https://fw-1.example.com"));
        assert!(valid_firewall_origin("https://a.b"));
        for bad in [
            "http://fw.example.com",
            "https://fw.example.com/",
            "https://fw.example.com:443",
            "https://user@fw.example.com",
            "https://localhost",
            "https://-fw.example.com",
            "https://FW.example.com",
            "https://fw..example.com",
        ] {
            assert!(!valid_firewall_origin(bad), "{bad}");
        }
    }

    #[test]
    fn revoke_prune_clear_and_reload() {
        let dir = tempfile::tempdir().expect("dir");
        let s = AccessState::new(dir.path());
        assert_eq!(s.firewall_origin(), None);
        s.set_firewall_origin("https://fw.example.com").expect("save");
        s.revoke_devices(&["d1".into()], 1_000).expect("save");
        assert!(s.is_revoked("d1", 1_000 + REVOKED_KEEP_MS - 1));
        assert!(!s.is_revoked("d1", 1_000 + REVOKED_KEEP_MS));
        s.revoke_devices(&["d2".into()], 1_000 + REVOKED_KEEP_MS).expect("save");
        let raw: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("access.json")).expect("file")).expect("json");
        assert_eq!(
            raw,
            serde_json::json!({"firewallOrigin": "https://fw.example.com", "revoked": {"d2": 1_000 + REVOKED_KEEP_MS}})
        );
        let again = AccessState::new(dir.path());
        assert_eq!(again.firewall_origin().as_deref(), Some("https://fw.example.com"));
        again.clear_revoked().expect("save");
        assert!(!again.is_revoked("d2", 1_000 + REVOKED_KEEP_MS));
    }

    #[test]
    fn a_bad_origin_on_disk_reads_as_none_and_unknown_fields_survive() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("access.json"),
            r#"{"firewallOrigin":"http://x.y","revoked":{},"later":1}"#,
        )
        .expect("write");
        let s = AccessState::new(dir.path());
        assert_eq!(s.firewall_origin(), None);
        s.set_firewall_origin("https://fw.example.com").expect("save");
        let raw: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("access.json")).expect("file")).expect("json");
        assert_eq!(raw["later"], 1);
    }
}

#[cfg(test)]
mod write_failure {
    use super::*;

    #[test]
    fn a_revoke_that_was_not_written_is_not_remembered() {
        let dir = tempfile::tempdir().expect("dir");
        let state_dir = dir.path().join("state");
        let s = AccessState::new(&state_dir);
        // A file where the folder should be: the write fails.
        std::fs::write(&state_dir, "x").expect("block");
        assert!(s.revoke_devices(&["d1".into()], 1_000).is_err());
        assert!(!s.is_revoked("d1", 1_000));
    }
}
