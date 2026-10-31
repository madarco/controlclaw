//! The traffic log (`traffic.jsonl`): one JSON line per record, appended, rotated to `<path>.1`
//! past `MITM_LOG_MAX_BYTES` (addon.py `_log`). The mitm-agent appends to the same file and ships
//! it, so every record is one `write` of one whole line. Owner: W1.
//!
//! It also keeps each agent's last 20 records (addon.py `_remember`), which the inline AI review
//! sends the judge as what the agent was doing just before.

pub mod record;

use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cc_contracts::Num;
use cc_contracts::traffic::TrafficRecord;

pub struct TrafficLog {
    path: Option<PathBuf>,
    max_bytes: u64,
    // One writer at a time, so the size check and the rename cannot interleave.
    lock: Mutex<()>,
    recent: Mutex<HashMap<Option<String>, VecDeque<serde_json::Value>>>,
}

/// How many records per agent the judge is sent (addon.py `AI_RECENT`).
const RECENT: usize = 20;

impl TrafficLog {
    pub fn new(path: Option<PathBuf>, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes,
            lock: Mutex::new(()),
            recent: Mutex::new(HashMap::new()),
        }
    }

    /// This agent's last records, oldest first, with the fields the judge reads.
    pub fn recent(&self, vm_id: Option<&str>) -> Vec<serde_json::Value> {
        let r = self.recent.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        r.get(&vm_id.map(str::to_owned))
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// addon.py `_remember`: a record with a host, its non-null `ts` (whole seconds), `method`,
    /// `host`, `path`, `effect`, `status` and `bytes_out`.
    fn remember(&self, rec: &serde_json::Value) {
        let Some(obj) = rec.as_object() else { return };
        if obj
            .get("host")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return;
        }
        let mut keep = serde_json::Map::new();
        for k in ["ts", "method", "host", "path", "effect", "status", "bytes_out"] {
            if let Some(v) = obj.get(k).filter(|v| !v.is_null()) {
                keep.insert(k.into(), v.clone());
            }
        }
        let ts = keep.get("ts").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
        keep.insert("ts".into(), (ts.trunc() as i64).into());
        let vm = obj.get("vm_id").and_then(serde_json::Value::as_str).map(str::to_owned);
        let mut r = self.recent.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = r.entry(vm).or_default();
        if list.len() == RECENT {
            list.pop_front();
        }
        list.push_back(serde_json::Value::Object(keep));
    }

    /// Append one record. A failure is logged and dropped: the request it describes has already
    /// been decided, and a full disk must not turn into refused traffic.
    pub fn append(&self, rec: &TrafficRecord) {
        let Ok(value) = serde_json::to_value(rec) else { return };
        self.append_value(&value);
    }

    /// Append a record built as JSON (the residential records keep the addon's key order). It must
    /// carry `rule_id` when it has an effect, as `_log` sets it.
    pub fn append_value(&self, value: &serde_json::Value) {
        self.remember(value);
        // As `json.dumps(record, ensure_ascii=False)` writes it: readers grep these lines.
        let line = crate::http::answer::py_json_utf8(value);
        tracing::info!("[mitm] {line}");
        let Some(path) = &self.path else { return };
        let _guard = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if fs::metadata(path).is_ok_and(|m| m.len() >= self.max_bytes) {
            let mut rotated = path.clone().into_os_string();
            rotated.push(".1");
            let _ = fs::rename(path, rotated);
        }
        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()));
        if let Err(e) = result {
            tracing::warn!("[mitm] log write failed: {e}");
        }
    }
}

/// The flow id of a connection `server_connect` refused (addon.py `_non_routable_record`):
/// `nr_` and 24 hex digits of a hash over the time, host and port.
pub fn non_routable_flow_id(host: &str, port: u16) -> String {
    use sha2::{Digest, Sha256};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let digest = Sha256::digest(format!("{ts}{host}{port}").as_bytes());
    format!("nr_{}", &hex::encode(digest)[..24])
}

/// Now, in epoch seconds with a fraction, as `time.time()` writes it.
pub fn now() -> Num {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    Num::from_f64(secs).unwrap_or_default()
}

/// Lines logged once each, at most [`Once::MAX`] of them: for lines made from what an agent sent
/// (its ClientHello, its HTTP/2 preface), so neither memory nor the log grows with them.
pub struct Once(Mutex<Option<std::collections::HashSet<String>>>);

impl Once {
    pub const MAX: usize = 64;
    /// Longest line kept, in characters.
    const LINE: usize = 400;

    pub const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// `line`, cut to its first 400 characters, if it was not logged before and the cap is not
    /// reached: the caller logs it.
    pub fn first(&self, line: &str) -> Option<String> {
        let line = crate::net::target::truncate(line, Self::LINE);
        let mut seen = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let seen = seen.get_or_insert_default();
        (seen.len() < Self::MAX && seen.insert(line.clone())).then_some(line)
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}
