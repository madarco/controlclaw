//! The AI review's history (`ai/trace-store.ts`): one record per model call of the review and the
//! scan, with what was sent, what came back and the explanation. Encrypted under the box key, one
//! file per agent per UTC day, kept seven days, never backed up and never sent to the console.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const TRACE_RETENTION_MS: i64 = 7 * 24 * 60 * 60_000;
const RUNS_PER_FILE: usize = 500;
const FILE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Traffic the proxy could not tie to an agent is filed under this name.
pub const NO_AGENT: &str = "unknown-agent";
/// `MAX_EVENT_TEXT` in `doctor-stream.ts`.
const MAX_EVENT_TEXT: usize = 16_000;

fn id_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]{8,80}$").expect("regex"))
}

fn day_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").expect("regex"))
}

/// One event of a run (`DoctorEvent`): `{seq, kind, text, title?}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub seq: u64,
    pub kind: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiReviewRun {
    pub run_id: String,
    pub vm_id: Option<String>,
    /// `review` or `scan`.
    pub kind: String,
    /// ms
    pub at: i64,
    pub provider: Option<String>,
    pub model: Option<String>,
    /// `finding`, `clear`, `repeat`, `no_answer`, `capped`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub events: Vec<TraceEvent>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// `summary`, `list` and `get` are the history page's (`history.rs`).
impl AiReviewRun {
    /// The run without its events, as the list shows it.
    pub fn summary(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.remove("events");
        }
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TraceFile {
    vm_id: String,
    day: String,
    runs: Vec<AiReviewRun>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Where the review hands each run. Recording never fails a review.
pub trait TraceSink: Send + Sync {
    fn record(&self, run: AiReviewRun);
}

/// `redactSecrets` + `redactDoctorText`: every known secret value replaced, longest first, then the
/// text capped.
pub fn redact_doctor_text(text: &str, secrets: &[String]) -> String {
    let mut list: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
    list.sort_by_key(|s| std::cmp::Reverse(s.encode_utf16().count()));
    list.dedup();
    let mut out = text.to_string();
    for s in list {
        out = out.replace(s.as_str(), "[REDACTED]");
    }
    let units: Vec<u16> = out.encode_utf16().collect();
    if units.len() > MAX_EVENT_TEXT {
        format!(
            "{}\n[output truncated]",
            String::from_utf16_lossy(&units[..MAX_EVENT_TEXT])
        )
    } else {
        out
    }
}

pub struct AiReviewTraceStore {
    dir: PathBuf,
    box_key: String,
    org_id: String,
    box_id: String,
    secrets: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// One writer at a time: a record is a read, a change and a write of the day's file.
    lock: Mutex<()>,
}

fn day_of(ms: i64) -> String {
    cc_crypto::store_health::iso_from_millis(ms)[..10].to_string()
}

impl AiReviewTraceStore {
    pub fn new(
        dir: PathBuf,
        box_key: &str,
        org_id: &str,
        box_id: &str,
        secrets: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let s = Self {
            dir,
            box_key: box_key.into(),
            org_id: org_id.into(),
            box_id: box_id.into(),
            secrets,
            now,
            lock: Mutex::new(()),
        };
        s.prune()?;
        Ok(s)
    }

    fn agent(vm_id: Option<&str>) -> Result<String, String> {
        let id = vm_id.unwrap_or(NO_AGENT);
        if !id_re().is_match(id) {
            return Err("Invalid agent.".into());
        }
        Ok(id.to_string())
    }

    fn path(&self, agent: &str, day: &str) -> Result<PathBuf, String> {
        if !id_re().is_match(agent) || !day_re().is_match(day) {
            return Err("Invalid trace file.".into());
        }
        Ok(self.dir.join(format!("{agent}.{day}.enc")))
    }

    fn aad(&self, agent: &str, day: &str) -> String {
        format!("{}:{}:ai-review:trace:{agent}:{day}", self.org_id, self.box_id)
    }

    fn load(&self, agent: &str, day: &str) -> Result<Option<TraceFile>, String> {
        let path = self.path(agent, day)?;
        let v =
            cc_crypto::enc_file::load_encrypted_json(&path, &self.box_key, &self.aad(agent, day)).map_err(|e| e.0)?;
        match v {
            None => Ok(None),
            Some(v) => serde_json::from_value(v).map(Some).map_err(|e| e.to_string()),
        }
    }

    fn try_record(&self, run: AiReviewRun) -> Result<(), String> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let agent = Self::agent(run.vm_id.as_deref())?;
        let day = day_of(run.at);
        // Unreadable under this key: start the day over.
        let mut file = self.load(&agent, &day).ok().flatten().unwrap_or_else(|| TraceFile {
            vm_id: agent.clone(),
            day: day.clone(),
            runs: vec![],
            extra: Map::new(),
        });
        let secrets = (self.secrets)();
        let mut clean = run;
        for e in &mut clean.events {
            e.text = redact_doctor_text(&e.text, &secrets);
        }
        // A batch whose findings failed to post is judged again: same finding id, one run.
        file.runs.retain(|r| r.run_id != clean.run_id);
        file.runs.push(clean);
        // Over a cap: drop the oldest runs that found nothing first.
        let sizes: Vec<usize> = file
            .runs
            .iter()
            .map(|r| serde_json::to_string(r).map(|s| s.len()).unwrap_or(0))
            .collect();
        let mut total: usize = sizes.iter().sum();
        let mut count = file.runs.len();
        let mut dropped = vec![false; file.runs.len()];
        let last = file.runs.len() - 1;
        for findings in [false, true] {
            for i in 0..file.runs.len() {
                if !(count > 1 && (count > RUNS_PER_FILE || total > FILE_MAX_BYTES)) {
                    break;
                }
                if dropped[i] || (file.runs[i].outcome == "finding") != findings || i == last {
                    continue;
                }
                dropped[i] = true;
                total -= sizes[i];
                count -= 1;
            }
        }
        let mut i = 0;
        file.runs.retain(|_| {
            let keep = !dropped[i];
            i += 1;
            keep
        });
        let value = serde_json::to_value(&file).map_err(|e| e.to_string())?;
        cc_crypto::enc_file::save_encrypted_json(
            &self.path(&agent, &day)?,
            &value,
            &self.box_key,
            &self.aad(&agent, &day),
        )
        .map_err(|e| e.0)
    }

    /// This agent's days on disk, newest first, inside retention.
    fn days(&self, agent: &str) -> Vec<String> {
        let oldest = day_of((self.now)() - TRACE_RETENTION_MS);
        let prefix = format!("{agent}.");
        let mut days: Vec<String> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|f| f.starts_with(&prefix) && f.ends_with(".enc"))
            .map(|f| f[prefix.len()..f.len() - 4].to_string())
            .filter(|d| day_re().is_match(d) && *d >= oldest)
            .collect();
        days.sort();
        days.reverse();
        days
    }

    /// Runs newest first, without their events. `before` (ms) pages; `findings` keeps only runs
    /// that posted one.
    pub fn list(
        &self,
        vm_id: Option<&str>,
        before: Option<i64>,
        findings: bool,
        limit: usize,
    ) -> Result<Vec<Value>, String> {
        let agent = Self::agent(vm_id)?;
        let limit = limit.clamp(1, 200);
        let min_at = (self.now)() - TRACE_RETENTION_MS;
        let mut out = Vec::new();
        for day in self.days(&agent) {
            let Ok(Some(file)) = self.load(&agent, &day) else {
                continue;
            };
            let mut runs: Vec<&AiReviewRun> = file
                .runs
                .iter()
                .filter(|r| r.at > min_at && before.is_none_or(|b| r.at < b) && (!findings || r.outcome == "finding"))
                .collect();
            runs.sort_by_key(|r| std::cmp::Reverse(r.at));
            for r in runs {
                out.push(r.summary());
                if out.len() >= limit {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    pub fn get(&self, vm_id: Option<&str>, run_id: &str) -> Result<Option<AiReviewRun>, String> {
        let agent = Self::agent(vm_id)?;
        if !id_re().is_match(run_id) {
            return Ok(None);
        }
        let min_at = (self.now)() - TRACE_RETENTION_MS;
        for day in self.days(&agent) {
            if let Ok(Some(file)) = self.load(&agent, &day)
                && let Some(hit) = file.runs.into_iter().find(|r| r.run_id == run_id)
            {
                return Ok((hit.at > min_at).then_some(hit));
            }
        }
        Ok(None)
    }

    /// Drop days past retention, and leftover temp files. Runs at start and once a day.
    pub fn prune(&self) -> std::io::Result<()> {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re =
            RE.get_or_init(|| Regex::new(r"^([A-Za-z0-9_-]{8,80})\.(\d{4}-\d{2}-\d{2})\.enc(\.tmp)?$").expect("regex"));
        let oldest = day_of((self.now)() - TRACE_RETENTION_MS);
        for entry in std::fs::read_dir(&self.dir)?.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Some(m) = re.captures(&name) else { continue };
            if m.get(3).is_some() || m[2] < *oldest {
                match std::fs::remove_file(entry.path()) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

impl TraceSink for AiReviewTraceStore {
    fn record(&self, run: AiReviewRun) {
        if let Err(e) = self.try_record(run) {
            tracing::error!("[ai] trace: not recorded: {e}");
        }
    }
}
