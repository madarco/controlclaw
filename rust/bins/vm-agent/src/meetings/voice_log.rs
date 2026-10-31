//! What the meeting voice adapter leaves for this vm-agent (`meeting-voice-log.ts`, gpt-live plan,
//! D8/D11), in `~/.openclaw/cc-voice/` (the adapter's record.js; both run as the same user):
//!
//! - `meeting.jsonl`: one line per finished voice session (`usage`), per line of the conversation
//!   (`line`), per woken session's end (`session`), per request asked by voice and not done
//!   (`request`), and a request to leave (`leave`).
//! - `lease.json`, written here: how many voice sessions the firewall allows in this meeting, the
//!   owner's chat for reminders, the meeting's id, and whether it may drive a full agent run
//!   (`full`) or present its browser (`present`).
//! - `tasks/<meeting id>.json`: the requests handed to a full agent run, read field by field for the
//!   Meetings page.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::js::{head16, safe_int};
use crate::phone::history::parse_iso;

const MAX_READ: u64 = 4 * 1024 * 1024;
const MAX_TASKS: usize = 20;
const MAX_FOLLOW_UPS: usize = 20;
static MEETING_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").expect("regex"));
static TASK_SESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^agent:main:meeting-[a-z0-9-]{1,80}$").expect("regex"));
static REASON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z_]{1,20}$").expect("regex"));
static TELEGRAM_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]{3,20}$").expect("regex"));

/// `String(v ?? "")`.
fn js_text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The owner's direct chat for reminders set in a meeting: the first Telegram sender this box
/// approved on the firewall's behalf (`ownerChat`). Never a group or another channel.
pub fn owner_chat(approved: &[(String, String, String)]) -> Option<Value> {
    approved
        .iter()
        .filter(|(kind, sender, _)| kind == "telegram" && TELEGRAM_ID.is_match(sender))
        .min_by(|a, b| {
            let t = |x: &String| parse_iso(x).unwrap_or(f64::NAN);
            t(&a.2).total_cmp(&t(&b.2))
        })
        .map(|(_, sender, _)| json!({"channel": "telegram", "to": sender}))
}

/// The meeting a lease is for (`{id, full, present}`).
#[derive(Debug, Clone, Default)]
pub struct LeaseMeeting {
    pub id: Option<String>,
    pub full: bool,
    pub present: bool,
}

pub struct MeetingVoiceLog {
    pub dir: PathBuf,
    offset: Mutex<u64>,
}

impl MeetingVoiceLog {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            offset: Mutex::new(0),
        }
    }

    fn file(&self) -> PathBuf {
        self.dir.join("meeting.jsonl")
    }

    fn lease(&self) -> PathBuf {
        self.dir.join("lease.json")
    }

    /// A meeting starts: a fresh log, and the firewall's session allowance for it.
    pub fn start(&self, wake_sessions: i64, owner: Option<Value>, meeting: &LeaseMeeting) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        cc_store::write_file(&self.file(), b"", 0o600)?;
        *self.offset.lock().unwrap_or_else(|e| e.into_inner()) = 0;
        let mut lease = Map::new();
        lease.insert("wakeSessions".into(), json!(wake_sessions));
        if let Some(o) = owner {
            lease.insert("owner".into(), o);
        }
        if let Some(id) = meeting.id.as_ref().filter(|i| !i.is_empty()) {
            lease.insert("meetingId".into(), json!(id));
        }
        if meeting.full {
            lease.insert("full".into(), json!(true));
        }
        if meeting.present {
            lease.insert("present".into(), json!(true));
        }
        lease.insert("at".into(), json!(crate::platform::time::now_iso()));
        cc_store::write_json_atomic(&self.lease(), &Value::Object(lease), 0o600, cc_store::TmpName::Suffix)
    }

    /// The meeting ended: no more lease, and any stage tab left showing is closed.
    pub fn end(&self) {
        let _ = std::fs::remove_file(self.lease());
        close_stage_tabs_later();
    }

    /// The meeting in progress may no longer drive a full agent (the settings changed under it).
    pub fn drop_full(&self) {
        self.drop_field("full");
    }

    /// The meeting in progress may no longer present: the adapter stops presenting.
    pub fn drop_present(&self) {
        self.drop_field("present");
        close_stage_tabs_later();
    }

    fn drop_field(&self, field: &str) {
        let Ok(raw) = std::fs::read(self.lease()) else { return };
        let Ok(Value::Object(mut v)) = serde_json::from_slice::<Value>(&raw) else {
            return;
        };
        if v.get(field) != Some(&json!(true)) {
            return;
        }
        v.remove(field);
        let _ = cc_store::write_json_atomic(&self.lease(), &Value::Object(v), 0o600, cc_store::TmpName::Suffix);
    }

    /// The full agent runs a meeting started; empty when it had none.
    pub fn tasks(&self, meeting_id: &str) -> Vec<Value> {
        read_tasks(&self.dir, meeting_id)
    }

    /// A meeting was deleted: its tasks go with it.
    pub fn forget_tasks(&self, meeting_id: &str) {
        if MEETING_ID.is_match(meeting_id) {
            let _ = std::fs::remove_file(self.dir.join("tasks").join(format!("{meeting_id}.json")));
        }
    }

    /// New complete entries since the last read.
    pub fn read(&self) -> Vec<Value> {
        let Ok(mut f) = std::fs::File::open(self.file()) else {
            return Vec::new();
        };
        let mut offset = self.offset.lock().unwrap_or_else(|e| e.into_inner());
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        if size < *offset {
            *offset = 0;
        }
        let length = (size - *offset).min(MAX_READ);
        if length == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; length as usize];
        if f.seek(SeekFrom::Start(*offset)).is_err() || f.read_exact(&mut buf).is_err() {
            return Vec::new();
        }
        let Some(end) = buf.iter().rposition(|b| *b == b'\n') else {
            return Vec::new();
        };
        *offset += end as u64 + 1;
        let mut out = Vec::new();
        for line in String::from_utf8_lossy(&buf[..end]).split('\n') {
            let Ok(Value::Object(e)) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(at) = e.get("at").and_then(Value::as_str).filter(|a| parse_iso(a).is_some()) else {
                continue;
            };
            let kind = e.get("kind").and_then(Value::as_str);
            let text = e.get("text").and_then(Value::as_str);
            let nonblank = text.is_some_and(|t| !t.trim().is_empty());
            match kind {
                Some("usage") => {
                    if let Some(sec) = e
                        .get("seconds")
                        .and_then(Value::as_f64)
                        .filter(|s| (0.0..=86_400.0).contains(s))
                    {
                        out.push(json!({"at": at, "kind": "usage", "family": head16(&js_text(e.get("family")), 20), "seconds": (sec + 0.5).floor() as i64}));
                    }
                }
                Some("line") => {
                    let role = e
                        .get("role")
                        .and_then(Value::as_str)
                        .filter(|r| *r == "assistant" || *r == "user");
                    if let (Some(role), true) = (role, nonblank) {
                        out.push(json!({"at": at, "kind": "line", "role": role, "text": head16(text.unwrap_or_default(), 4000)}));
                    }
                }
                Some("session") => {
                    if let Some(r) = e.get("reason").and_then(Value::as_str).filter(|r| REASON.is_match(r)) {
                        out.push(json!({"at": at, "kind": "session", "reason": r}));
                    }
                }
                Some("leave") => out.push(json!({"at": at, "kind": "leave"})),
                Some("request") if nonblank => {
                    let from = e
                        .get("from")
                        .and_then(Value::as_str)
                        .map(|f| head16(f, 80))
                        .unwrap_or_default();
                    out.push(json!({"at": at, "kind": "request", "from": from, "text": head16(text.unwrap_or_default(), 400)}));
                }
                _ => {}
            }
        }
        out
    }
}

/// Control characters as spaces, whitespace collapsed, at most `max` characters.
fn clean_text(v: Option<&Value>, max: usize) -> String {
    static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new("[\u{0}-\u{1f}\u{7f}]+").expect("regex"));
    let Some(s) = v.and_then(Value::as_str) else {
        return String::new();
    };
    let s = CONTROL.replace_all(s, " ");
    head16(s.split_whitespace().collect::<Vec<_>>().join(" ").trim(), max)
}

/// `new Date(v).toISOString()` for a time `Date.parse` takes.
fn clean_time(v: Option<&Value>) -> Option<String> {
    let ms = parse_iso(v?.as_str()?)?;
    Some(crate::platform::time::iso_ms(ms as i64))
}

/// The fields a task and a follow-up share, checked; `None` when its state or start is not valid.
fn task_fields(t: &Value, states: &[&str]) -> Option<Map<String, Value>> {
    let state = js_text(t.get("state"));
    if !t.is_object() || !states.contains(&state.as_str()) {
        return None;
    }
    let started = clean_time(t.get("startedAt"))?;
    let mut m = Map::new();
    m.insert("from".into(), json!(clean_text(t.get("from"), 80)));
    m.insert("text".into(), json!(clean_text(t.get("text"), 300)));
    m.insert("state".into(), json!(state));
    m.insert("startedAt".into(), json!(started));
    if let Some(ended) = clean_time(t.get("endedAt")) {
        m.insert("endedAt".into(), json!(ended));
    }
    let result = clean_text(t.get("result"), 600);
    if !result.is_empty() {
        m.insert("result".into(), json!(result));
    }
    Some(m)
}

/// What the adapter wrote for a meeting's tasks, checked field by field (`readTasks`).
pub fn read_tasks(dir: &Path, meeting_id: &str) -> Vec<Value> {
    if !MEETING_ID.is_match(meeting_id) {
        return Vec::new();
    }
    let Ok(raw) = std::fs::read(dir.join("tasks").join(format!("{meeting_id}.json"))) else {
        return Vec::new();
    };
    let Ok(Value::Array(list)) = serde_json::from_slice::<Value>(&raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for t in list.iter().take(MAX_TASKS) {
        let Some(fields) = task_fields(t, &["running", "done", "failed"]) else {
            continue;
        };
        let Some(n) = safe_int(t.get("n")) else { continue };
        let session = clean_text(t.get("session"), 120);
        if !TASK_SESSION.is_match(&session) {
            continue;
        }
        // Follow-ups, run in the task's session: the newest kept, one per number.
        let mut follow_ups: Vec<Value> = Vec::new();
        let mut seen: Vec<i64> = Vec::new();
        let ups = t
            .get("followUps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for u in ups.iter().skip(ups.len().saturating_sub(MAX_FOLLOW_UPS)) {
            let Some(up) = task_fields(u, &["queued", "running", "done", "failed", "left"]) else {
                continue;
            };
            let Some(k) = safe_int(u.get("k")).filter(|k| !seen.contains(k)) else {
                continue;
            };
            seen.push(k);
            let mut m = Map::new();
            m.insert("k".into(), json!(k));
            m.extend(up);
            follow_ups.push(Value::Object(m));
        }
        let mut m = Map::new();
        m.insert("n".into(), json!(n));
        m.extend(fields);
        m.insert("session".into(), json!(session));
        if !follow_ups.is_empty() {
            m.insert("followUps".into(), Value::Array(follow_ups));
        }
        out.push(Value::Object(m));
    }
    out
}

static TAB_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9]{1,64}$").expect("regex"));

/// `void closeStageTabs()`: in the background, when there is a runtime to run it on.
fn close_stage_tabs_later() {
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(close_stage_tabs("http://127.0.0.1:9223"));
    }
}

/// Presenting (docs/plans/meeting-present.md): close the "CC Stage" tabs the voice adapter opened
/// in the meeting browser, for when the adapter cannot. Never fails; how many were closed.
pub async fn close_stage_tabs(base: &str) -> usize {
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return 0;
    };
    let Ok(res) = client.get(format!("{base}/json/list")).send().await else {
        return 0;
    };
    let Ok(Value::Array(list)) = res.json::<Value>().await else {
        return 0;
    };
    let ids: Vec<String> = list
        .iter()
        .filter(|t| {
            t.get("type").and_then(Value::as_str) == Some("page")
                && t.get("title").and_then(Value::as_str) == Some("CC Stage")
        })
        .filter_map(|t| {
            t.get("id")
                .and_then(Value::as_str)
                .filter(|id| TAB_ID.is_match(id))
                .map(String::from)
        })
        .collect();
    for id in &ids {
        let _ = client.get(format!("{base}/json/close/{id}")).send().await;
    }
    ids.len()
}

/// Which wake names the local model can hear (D5); `local: false` when this box does not listen
/// for names itself.
pub async fn check_wake_names(runner: &dyn cc_proc::Runner, words: &[String], installed: bool) -> Value {
    let none = |local: bool| json!({"words": words, "heard": [], "unheard": [], "local": local});
    if !installed {
        return none(false);
    }
    let cmd = cc_proc::Cmd::new("/usr/bin/python3")
        .args(["/opt/controlclaw/meeting-voice/cc-wake.py", "--check"])
        .args(words.iter().cloned())
        .timeout(Duration::from_secs(30));
    let Ok(out) = runner.run(cmd).await else {
        return none(false);
    };
    if !out.success() {
        return none(false);
    }
    let Ok(parsed) = serde_json::from_slice::<Value>(&out.stdout) else {
        return none(false);
    };
    let heard: Vec<String> = parsed
        .get("heard")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|h| h.get("name").and_then(Value::as_str))
        .filter(|n| words.iter().any(|w| w == n))
        .map(String::from)
        .collect();
    let unheard: Vec<&String> = words.iter().filter(|w| !heard.contains(w)).collect();
    json!({"words": words, "heard": heard, "unheard": unheard, "local": true})
}

/// The adapter and its model are installed (`localWakeInstalled`).
pub fn local_wake_installed() -> bool {
    Path::new("/opt/controlclaw/meeting-voice/cc-wake.py").exists()
        && Path::new("/opt/controlclaw/cc-wake/model/conf/model.conf").exists()
}

#[cfg(test)]
mod tests;
