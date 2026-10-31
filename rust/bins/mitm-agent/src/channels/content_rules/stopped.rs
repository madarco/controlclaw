//! What the content rules stopped (`content-stopped.ts`): each block and hold, with the rule's name
//! and reason as they were then, and the text, for the firewall's own Content rules page. Encrypted
//! under the box key, one file per UTC day, kept seven days, never backed up and never sent to the
//! control plane. The console gets metadata only, from the audit file.
//!
//! A text a rule with the secrets detector stopped is not kept: the page would be one more place
//! the key lives.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::channels::js::{js_len, js_slice};

pub const STOPPED_RETENTION_MS: i64 = 7 * 24 * 60 * 60_000;
/// Of each text, this much is kept.
pub const STOPPED_TEXT_MAX: usize = 2000;
const PER_FILE: usize = 500;
const FILE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Messages coming in that are kept, per agent and minute. Past this they are counted, without
/// their text, in one entry for the minute.
pub const STOPPED_IN_PER_MINUTE: u32 = 20;

static DAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}$").expect("regex"));
static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,40}$").expect("regex"));
static FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^stopped\.(\d{4}-\d{2}-\d{2})\.enc(\.tmp)?$").expect("regex"));

/// A rule as a record names it, as it was then. `ai`: the AI check found it, or could not run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleBrief {
    pub id: String,
    pub name: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<String>,
}

/// One entry. `outcome` is what became of a hold: `waiting`, `sent`, `not_sent`, `expired`,
/// `send_failed`, `restarted`, or why it was stopped instead (`nobody_asked`, `too_many`,
/// `refused`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoppedEntry {
    pub id: String,
    /// ms
    pub at: i64,
    pub rule: RuleBrief,
    pub channel: String,
    pub direction: String,
    pub action: String,
    #[serde(rename = "vmId")]
    pub vm_id: Option<String>,
    /// `None` when not kept: `withheld` says why.
    pub text: Option<String>,
    pub cut: bool,
    /// `secret`: the rule looks for secrets. `flood`: more came in that minute than are kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What `record` takes.
#[derive(Debug, Clone, PartialEq)]
pub struct NewStopped {
    pub rule: RuleBrief,
    pub channel: String,
    pub direction: String,
    pub action: String,
    pub vm_id: Option<String>,
    pub text: Option<String>,
    pub withheld: Option<String>,
    pub outcome: Option<String>,
    pub id: Option<String>,
    /// When it happened (ms), which picks its day; now when `None`. A hold passes the time it
    /// settles it by, so both name the same day.
    pub at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoppedFile {
    day: String,
    entries: Vec<StoppedEntry>,
}

struct Bucket {
    minute: i64,
    kept: u32,
    over: u32,
    last: NewStopped,
}

#[derive(Default)]
struct Inner {
    /// Ids recorded lately, so a message the agent reads again is not kept twice across days.
    recent: HashSet<String>,
    recent_order: VecDeque<String>,
    /// Messages coming in, per agent, in the current minute.
    incoming: HashMap<String, Bucket>,
    incoming_order: Vec<String>,
}

pub struct ContentStoppedStore {
    dir: PathBuf,
    box_key: String,
    org_id: String,
    box_id: String,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    inner: Mutex<Inner>,
}

fn day_of(ms: i64) -> String {
    cc_crypto::store_health::iso_from_millis(ms)[..10].to_string()
}

fn random_id() -> String {
    let mut b = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

impl ContentStoppedStore {
    pub fn new(
        dir: PathBuf,
        box_key: &str,
        org_id: &str,
        box_id: &str,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> std::io::Result<Self> {
        {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(&dir)?;
        }
        let s = Self {
            dir,
            box_key: box_key.into(),
            org_id: org_id.into(),
            box_id: box_id.into(),
            now,
            inner: Mutex::new(Inner::default()),
        };
        s.prune()?;
        Ok(s)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn path(&self, day: &str) -> Result<PathBuf, String> {
        if !DAY.is_match(day) {
            return Err("Invalid day.".into());
        }
        Ok(self.dir.join(format!("stopped.{day}.enc")))
    }

    fn aad(&self, day: &str) -> String {
        format!("{}:{}:content-rules:stopped:{day}", self.org_id, self.box_id)
    }

    fn load(&self, day: &str) -> Result<Option<StoppedFile>, String> {
        let v = cc_crypto::enc_file::load_encrypted_json(&self.path(day)?, &self.box_key, &self.aad(day))
            .map_err(|e| e.0)?;
        v.map(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
            .transpose()
    }

    fn save(&self, file: &StoppedFile) -> Result<(), String> {
        let v = serde_json::to_value(file).map_err(|e| e.to_string())?;
        cc_crypto::enc_file::save_encrypted_json(&self.path(&file.day)?, &v, &self.box_key, &self.aad(&file.day))
            .map_err(|e| e.0)
    }

    /// Record one; its id, or `None` when it could not be written. Recording never fails a check.
    /// An id already recorded (a message the agent polls, which the audit names the same way each
    /// time) is not kept again.
    pub fn record(&self, entry: NewStopped) -> Option<String> {
        let mut inner = self.lock();
        let at = entry.at.unwrap_or_else(|| (self.now)());
        let id = entry.id.clone().filter(|i| ID.is_match(i)).unwrap_or_else(random_id);
        if inner.recent.contains(&id) {
            return Some(id);
        }
        self.flush_incoming(&mut inner, at);
        if entry.direction == "in" {
            let key = entry.vm_id.clone().unwrap_or_default();
            let minute = at.div_euclid(60_000);
            match inner.incoming.get_mut(&key) {
                Some(b) if b.minute == minute => {
                    if b.kept >= STOPPED_IN_PER_MINUTE {
                        b.over += 1;
                        b.last = entry;
                        return None;
                    }
                    b.kept += 1;
                }
                _ => {
                    if !inner.incoming.contains_key(&key) {
                        inner.incoming_order.push(key.clone());
                    }
                    inner.incoming.insert(
                        key,
                        Bucket {
                            minute,
                            kept: 1,
                            over: 0,
                            last: entry.clone(),
                        },
                    );
                }
            }
        }
        match self.write(&mut inner, entry, id, at) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::error!("[content-rules] stopped: not recorded: {e}");
                None
            }
        }
    }

    /// Minutes that are over, with messages only counted: one entry each, without text.
    fn flush_incoming(&self, inner: &mut Inner, at: i64) {
        let minute = at.div_euclid(60_000);
        let keys: Vec<String> = inner.incoming_order.clone();
        for key in keys {
            let Some(b) = inner.incoming.get(&key) else { continue };
            if b.minute == minute {
                continue;
            }
            let Some(b) = inner.incoming.remove(&key) else { continue };
            inner.incoming_order.retain(|k| *k != key);
            if b.over == 0 {
                continue;
            }
            let last = NewStopped {
                text: None,
                withheld: Some("flood".into()),
                outcome: None,
                at: None,
                ..b.last
            };
            if let Err(e) = self.write_counted(inner, last, b.over, b.minute * 60_000 + 59_999) {
                tracing::error!("[content-rules] stopped: a count was not recorded: {e}");
            }
        }
    }

    fn write_counted(&self, inner: &mut Inner, entry: NewStopped, count: u32, at: i64) -> Result<String, String> {
        self.write_entry(inner, entry, random_id(), at, Some(count))
    }

    fn write(&self, inner: &mut Inner, entry: NewStopped, id: String, at: i64) -> Result<String, String> {
        self.write_entry(inner, entry, id, at, None)
    }

    fn write_entry(
        &self,
        inner: &mut Inner,
        entry: NewStopped,
        id: String,
        at: i64,
        count: Option<u32>,
    ) -> Result<String, String> {
        let day = day_of(at);
        let kept = if entry.withheld.is_some() {
            None
        } else {
            entry.text.clone()
        };
        let clean = StoppedEntry {
            id: id.clone(),
            at,
            rule: entry.rule,
            channel: entry.channel,
            direction: entry.direction,
            action: entry.action,
            vm_id: entry.vm_id,
            cut: kept.as_deref().is_some_and(|t| js_len(t) > STOPPED_TEXT_MAX),
            text: kept.map(|t| js_slice(&t, STOPPED_TEXT_MAX)),
            withheld: entry.withheld,
            count,
            outcome: entry.outcome,
            extra: Map::new(),
        };
        // Unreadable under this key: start the day over.
        let mut file = self.load(&day).ok().flatten().unwrap_or(StoppedFile {
            day: day.clone(),
            entries: vec![],
        });
        if file.entries.iter().any(|e| e.id == id) {
            return Ok(id);
        }
        file.entries.push(clean);
        // Over a cap: the oldest of the day go first, but never a hold still waiting (its outcome is
        // still to be written on it).
        // Sized once, then less each entry taken out (its JSON and a comma).
        let mut size = serde_json::to_string(&file).map_or(0, |s| s.len());
        let mut newest = file.entries.len() - 1;
        while file.entries.len() > PER_FILE || size > FILE_MAX_BYTES {
            let Some(oldest) = file
                .entries
                .iter()
                .enumerate()
                .position(|(i, e)| e.outcome.as_deref() != Some("waiting") && i != newest)
            else {
                break;
            };
            let gone = file.entries.remove(oldest);
            size = size.saturating_sub(serde_json::to_string(&gone).map_or(0, |s| s.len() + 1));
            newest -= 1;
        }
        self.save(&file)?;
        inner.recent.insert(id.clone());
        inner.recent_order.push_back(id.clone());
        if inner.recent.len() > 5000
            && let Some(old) = inner.recent_order.pop_front()
        {
            inner.recent.remove(&old);
        }
        Ok(id)
    }

    /// What became of a hold, on the entry recorded when it was held (`at` finds its day).
    pub fn settle(&self, id: &str, at: i64, outcome: &str) {
        let _inner = self.lock();
        let day = day_of(at);
        let r = (|| {
            let Some(mut file) = self.load(&day)? else {
                return Ok(());
            };
            let Some(entry) = file.entries.iter_mut().find(|e| e.id == id) else {
                return Ok(());
            };
            entry.outcome = Some(outcome.into());
            self.save(&file)
        })();
        if let Err(e) = r {
            tracing::error!("[content-rules] stopped: outcome not recorded: {e}");
        }
    }

    /// Every hold still `waiting` gets this outcome: at start, since holds live in memory.
    pub fn settle_waiting(&self, outcome: &str) {
        let _inner = self.lock();
        for day in self.days() {
            let r = (|| {
                let Some(mut file) = self.load(&day)? else {
                    return Ok(());
                };
                let mut any = false;
                for e in file
                    .entries
                    .iter_mut()
                    .filter(|e| e.outcome.as_deref() == Some("waiting"))
                {
                    e.outcome = Some(outcome.into());
                    any = true;
                }
                if any { self.save(&file) } else { Ok(()) }
            })();
            if let Err(e) = r {
                tracing::error!("[content-rules] stopped: outcomes not recorded: {e}");
            }
        }
    }

    /// The days on disk inside retention, newest first.
    fn days(&self) -> Vec<String> {
        let oldest = day_of((self.now)() - STOPPED_RETENTION_MS);
        let mut days: Vec<String> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let c = FILE.captures(&name)?;
                (c.get(2).is_none()).then(|| c[1].to_string())
            })
            .filter(|d| *d >= oldest)
            .collect();
        days.sort();
        days.reverse();
        days
    }

    /// Newest first (ties by id). `before` (ms) and `before_id`, the last entry of a page, page on.
    pub fn list(&self, before: Option<i64>, before_id: Option<&str>, limit: Option<usize>) -> Vec<StoppedEntry> {
        let mut inner = self.lock();
        let now = (self.now)();
        self.flush_incoming(&mut inner, now);
        let limit = limit.unwrap_or(50).clamp(1, 200);
        let min_at = now - STOPPED_RETENTION_MS;
        let mut out = Vec::new();
        for day in self.days() {
            let Ok(file) = self.load(&day) else { continue };
            let older = |e: &StoppedEntry| match before {
                None => true,
                Some(b) => e.at < b || (e.at == b && before_id.is_some_and(|id| e.id.as_str() < id)),
            };
            let mut entries: Vec<StoppedEntry> = file
                .map(|f| f.entries)
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.at > min_at && older(e))
                .collect();
            entries.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| b.id.cmp(&a.id)));
            for e in entries {
                out.push(e);
                if out.len() >= limit {
                    return out;
                }
            }
        }
        out
    }

    /// Drop days past retention, and leftover temp files. Runs at start and once a day.
    pub fn prune(&self) -> std::io::Result<()> {
        // Under the lock: a save in progress writes `<day>.enc.tmp`, which this would take away.
        let _inner = self.lock();
        let oldest = day_of((self.now)() - STOPPED_RETENTION_MS);
        for entry in std::fs::read_dir(&self.dir)?.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Some(c) = FILE.captures(&name) else { continue };
            if c.get(2).is_none() && c[1] >= *oldest {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
