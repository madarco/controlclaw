//! The agent boxes this firewall has seen run the release that trusts its CA for the control plane
//! and the backup store (`cp-inspect.ts`, main #564; docs/ops/t-sni-passthrough.md). The proxy
//! inspects those two only for these boxes (`cp_inspect` in the identity map) and passes them
//! through for the others, so an organisation that updates its firewall before its agents does not
//! cut the agents off.
//!
//! The signal is the box confirming, on the 3940 gate (`GET /ca?installed=<sha256>`), that it
//! installed this firewall's current CA. It is this firewall's own observation, never something the
//! control plane says (a `cp_inspect` it sends is dropped), and it is never taken back.
//!
//! The list is read from its file at every use, so the pool refresh, which has no `App`, sees a box
//! the gate recorded.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde_json::Value;

pub const DEFAULT_PATH: &str = "/opt/controlclaw/state/cp-inspect.json";

pub struct CpInspect {
    path: PathBuf,
    /// The boxes recorded by this process, kept even when the file could not be saved (as the TS
    /// keeps its set); one writer at a time, so two boxes recorded at once both stay in the file.
    added: Mutex<Vec<String>>,
    /// Called once a box is newly recorded: the core rewrites the proxy's identity map.
    pub on_new: OnceLock<Arc<dyn Fn() + Send + Sync>>,
}

impl CpInspect {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            added: Mutex::new(Vec::new()),
            on_new: OnceLock::new(),
        }
    }

    /// From `CP_INSPECT_PATH`, else [`DEFAULT_PATH`].
    pub fn from_env() -> Self {
        Self::new(Path::new(
            &std::env::var("CP_INSPECT_PATH").unwrap_or_else(|_| DEFAULT_PATH.to_owned()),
        ))
    }

    /// The recorded boxes, in the order they were recorded: the file's (a missing or broken file is
    /// none), then any this process recorded that the file does not hold.
    pub fn ids(&self) -> Vec<String> {
        let mut ids = read(&self.path);
        for a in self.added.lock().unwrap_or_else(PoisonError::into_inner).iter() {
            if !ids.contains(a) {
                ids.push(a.clone());
            }
        }
        ids
    }

    pub fn has(&self, vm_id: &str) -> bool {
        self.ids().iter().any(|i| i == vm_id)
    }

    /// Record a box. True when it is new (the identity map needs rewriting; `on_new` has been
    /// called). A box that cannot be saved is still reported new, as the TS does, and logged.
    pub fn add(&self, vm_id: &str) -> bool {
        {
            let mut added = self.added.lock().unwrap_or_else(PoisonError::into_inner);
            let mut ids = read(&self.path);
            if ids.iter().any(|i| i == vm_id) || added.iter().any(|i| i == vm_id) {
                return false;
            }
            added.push(vm_id.to_owned());
            for a in added.iter() {
                if !ids.contains(a) {
                    ids.push(a.clone());
                }
            }
            if let Err(e) = save(&self.path, &ids) {
                tracing::error!("[cp-inspect] could not save: {e}");
            }
        }
        if let Some(f) = self.on_new.get() {
            f();
        }
        true
    }

    /// The identity map with `cp_inspect` set from this list, and any the control plane sent
    /// dropped.
    pub fn apply(&self, identities: &[Value]) -> Vec<Value> {
        let ids = self.ids();
        identities
            .iter()
            .map(|row| {
                let Value::Object(o) = row else { return row.clone() };
                let mut o = o.clone();
                o.remove("cp_inspect");
                // `String(i.vm_id)`: a number or another value is compared as its text.
                let vm = match o.get("vm_id") {
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => "undefined".into(),
                };
                if ids.contains(&vm) {
                    o.insert("cp_inspect".into(), Value::Bool(true));
                }
                Value::Object(o)
            })
            .collect()
    }
}

fn read(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<Value>>(&t).ok())
        .map(|v| v.into_iter().filter_map(|i| i.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

fn save(path: &Path, ids: &[String]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string(ids)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn records_once_and_marks_only_its_own() -> Result<(), Box<dyn std::error::Error>> {
        let d = tempfile::tempdir()?;
        let s = CpInspect::new(&d.path().join("state/cp-inspect.json"));
        let rewrites = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let r = rewrites.clone();
        let _ = s.on_new.set(Arc::new(move || {
            r.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        assert!(!s.has("vm-1"));
        assert!(s.add("vm-1"));
        assert!(!s.add("vm-1"));
        assert_eq!(rewrites.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Another instance on the same file (the pool refresh) sees it.
        let other = CpInspect::new(&d.path().join("state/cp-inspect.json"));
        assert!(other.has("vm-1"));
        let rows = other.apply(&[
            json!({"vm_id": "vm-1", "private_ip": "10.0.0.3"}),
            json!({"vm_id": "vm-2", "cp_inspect": true}),
            json!("not an object"),
        ]);
        assert_eq!(rows[0]["cp_inspect"], json!(true));
        assert!(
            rows[1].get("cp_inspect").is_none(),
            "the control plane's value is dropped"
        );
        assert_eq!(rows[2], json!("not an object"));
        Ok(())
    }
}
