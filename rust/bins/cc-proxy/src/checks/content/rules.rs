//! `content-rules.json`, re-read when its `(mtime_ns, size)` changes (addon.py `content_rules`), and
//! the marker `content-own.json`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::engine::{Rule, core_secrets_rule};

/// The rules cannot be known (no file, a broken one, a store the firewall could not open): every
/// check refuses.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct Unreadable(pub String);

type Key = (u128, u64);

pub struct RuleFile {
    path: PathBuf,
    /// The rules with the core rule first, shared: a check takes the `Arc`, not a copy.
    cache: Mutex<Option<(Key, Arc<Vec<Rule>>)>>,
}

impl RuleFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
        }
    }

    /// The organization's rules with the core rule first, or why they cannot be known. The file is
    /// on a tmpfs and small; a stat per check is what the addon does too.
    pub fn rules(&self) -> Result<Arc<Vec<Rule>>, Unreadable> {
        // No file is not "no rules": the folder is a tmpfs, so after a reboot the proxy starts
        // before the mitm-agent has written it, and a mitm-agent that failed never writes it.
        let meta = std::fs::metadata(&self.path).map_err(|e| Unreadable(e.to_string()))?;
        let key = (mtime_ns(&meta), meta.len());
        let mut cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.as_ref().is_none_or(|(k, _)| *k != key) {
            let raw = std::fs::read(&self.path).map_err(|e| Unreadable(e.to_string()))?;
            let doc: Value = serde_json::from_slice(&raw).map_err(|e| Unreadable(e.to_string()))?;
            if doc.get("unreadable") == Some(&Value::Bool(true)) {
                return Err(Unreadable("the firewall could not read its content rules".into()));
            }
            let rules = doc
                .get("rules")
                .filter(|_| is_version_1(&doc))
                .and_then(Value::as_array)
                .and_then(|list| list.iter().map(Rule::from_json).collect::<Option<Vec<_>>>())
                .ok_or_else(|| Unreadable("the rule file is not in the expected shape".into()))?;
            let mut all = vec![core_secrets_rule()];
            all.extend(rules);
            *cache = Some((key, Arc::new(all)));
        }
        Ok(cache.as_ref().map(|(_, r)| r.clone()).unwrap_or_default())
    }

    /// `rules`, waiting up to `limit` for them to be known (`content_rules_wait`).
    pub async fn rules_wait(&self, limit: Duration) -> Result<Arc<Vec<Rule>>, Unreadable> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            match self.rules() {
                Ok(r) => return Ok(r),
                Err(e) if tokio::time::Instant::now() >= deadline => return Err(e),
                Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }
}

/// `doc.get("version") == 1`: Python's `==` takes `1.0` and `true` too.
fn is_version_1(doc: &Value) -> bool {
    match doc.get("version") {
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

fn mtime_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

/// `content-own.json`: whether the mitm-agent says it remembers a text it had an agent send.
pub struct OwnMarker {
    path: PathBuf,
    /// (the marker's mtime, until when it says to ask)
    last: Mutex<(u128, f64)>,
}

impl OwnMarker {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            last: Mutex::new((0, 0.0)),
        }
    }

    pub fn fresh(&self) -> bool {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return false;
        };
        let mtime = mtime_ns(&meta);
        let mut last = self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if mtime != last.0 {
            *last = (mtime, read_until(&self.path));
        }
        now() <= last.1
    }
}

/// `float(json.load(fh)["until"])`; anything wrong is 0.
fn read_until(path: &Path) -> f64 {
    let Ok(raw) = std::fs::read(path) else { return 0.0 };
    let Ok(doc) = serde_json::from_slice::<Value>(&raw) else {
        return 0.0;
    };
    match doc.get("until") {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write");
        // A new mtime each time, as the addon's tests force with os.utime.
        let f = std::fs::File::options().write(true).open(path).expect("open");
        let t = SystemTime::now() + Duration::from_millis(rand_ms());
        f.set_modified(t).expect("mtime");
    }

    fn rand_ms() -> u64 {
        u64::from(uuid::Uuid::new_v4().as_bytes()[0]) * 1000 + 1
    }

    #[test]
    fn no_file_and_a_broken_file_are_not_no_rules() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("content-rules.json");
        let f = RuleFile::new(path.clone());
        assert!(f.rules().is_err(), "no file must not read as no rules");
        write(
            &path,
            r#"{"version": 1, "rules": [{"id": "w", "name": "w", "direction": "out", "channels": ["telegram"], "patterns": ["customer list"], "detectors": [], "action": "block", "reason": "r"}]}"#,
        );
        let rules = f.rules().expect("rules");
        assert_eq!(
            rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["core-leaking-secrets", "w"]
        );
        write(&path, r#"{"version": 1, "rules": [{"id": "x"}]}"#);
        assert!(f.rules().is_err(), "a broken rule file must not read as no rules");
        write(&path, r#"{"version": 1, "rules": [], "unreadable": true}"#);
        assert_eq!(
            f.rules().map_err(|e| e.0).err().as_deref(),
            Some("the firewall could not read its content rules")
        );
        write(&path, r#"{"version": 2, "rules": []}"#);
        assert!(f.rules().is_err());
        write(&path, r#"{"version": 1.0, "rules": []}"#);
        assert_eq!(f.rules().expect("1.0 == 1").len(), 1);
    }

    #[test]
    fn the_own_marker() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("content-own.json");
        let m = OwnMarker::new(path.clone());
        assert!(!m.fresh());
        write(&path, &format!(r#"{{"until": {}}}"#, now() + 60.0));
        assert!(m.fresh());
        write(&path, &format!(r#"{{"until": {}}}"#, now() - 1.0));
        assert!(!m.fresh());
        write(&path, "not json");
        assert!(!m.fresh());
    }
}
