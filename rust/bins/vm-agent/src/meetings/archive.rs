//! The meetings archive and transcript cleanup (`meeting-notes.ts`): one JSON file per meeting
//! in `~/.openclaw/workspace/meetings/`, tombstones for deleted meetings outside the backed-up
//! home, and the erase of OpenClaw's own native meeting transcripts (pinned 2026.9.7 schema).
//!
//! Records are kept as JSON values, so fields this build does not know survive a write.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

/// One caption row: `{at, speaker, text, source?, updatedAt?}`.
pub type Caption = Map<String, Value>;

static UI_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:turn (?:on|off) (?:captions|microphone|camera)|(?:captions|microphone|camera) (?:on|off)|(?:(?:your )?(?:microphone|camera) is (?:on|off|muted)[.!]?\s*)+|you have joined the call\.(?:\s*(?:there (?:is|are) (?:one|[0-9]+) other (?:person|people) in the call|your (?:camera|microphone) is (?:off|on|muted)|your hand is (?:lowered|raised))\.)*|(?:arrow_downward\s*)?jump to bottom|(?:you(?:'re| are) using|use) captions|caption settings|change caption language|hide captions|mic_off|videocam_off)$")
        .expect("regex")
});
static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new("[\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}]").expect("regex"));
static TRAILING_STOP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[.!?…]+$").expect("regex"));

fn s(row: &Caption, k: &str) -> String {
    row.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// `Date.parse` of a caption time.
fn ms(t: &str) -> Option<f64> {
    crate::phone::history::parse_iso(t)
}

/// `cleanCaptions`: UI lines out, and adjacent rolling captions of one speaker consolidated,
/// keeping the first time and the latest observation time.
pub fn clean_captions(input: &[Caption]) -> Vec<Caption> {
    let mut out: Vec<Caption> = Vec::new();
    for row in input {
        let raw = s(row, "text");
        let text = CONTROL
            .replace_all(&raw, "")
            .split('\n')
            .map(str::trim)
            .filter(|l| !l.is_empty() && !UI_LINE.is_match(l))
            .collect::<Vec<_>>()
            .join(" ");
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.is_empty() || UI_LINE.is_match(&text) {
            continue;
        }
        let speaker = s(row, "speaker");
        let mut item = Map::new();
        item.insert("at".into(), row.get("at").cloned().unwrap_or(Value::Null));
        item.insert(
            "speaker".into(),
            json!(if speaker.is_empty() {
                "Unknown speaker".into()
            } else {
                speaker
            }),
        );
        item.insert("text".into(), json!(text));
        if let Some(src) = row.get("source").filter(|v| truthy(v)) {
            item.insert("source".into(), src.clone());
        }
        if let Some(u) = row.get("updatedAt").filter(|v| truthy(v)) {
            item.insert("updatedAt".into(), u.clone());
        }
        let when = |c: &Caption| {
            let t = c
                .get("updatedAt")
                .and_then(Value::as_str)
                .or_else(|| c.get("at").and_then(Value::as_str));
            t.and_then(ms)
        };
        if let Some(last) = out.last_mut() {
            let delta = match (when(&item), when(last)) {
                (Some(a), Some(b)) => a - b,
                _ => f64::NAN,
            };
            if last.get("speaker") == item.get("speaker") && delta.is_finite() && (0.0..=10_000.0).contains(&delta) {
                let previous = TRAILING_STOP.replace(&s(last, "text"), "").to_string();
                let current = TRAILING_STOP.replace(&text, "").to_string();
                let id = |c: &Caption| c.get("source").and_then(|v| v.get("id")).cloned();
                let same_source = last.contains_key("source") && item.contains_key("source") && id(last) == id(&item);
                let legacy = !last.contains_key("source") && !item.contains_key("source");
                let updated = item
                    .get("updatedAt")
                    .or_else(|| item.get("at"))
                    .cloned()
                    .unwrap_or(Value::Null);
                // Native IDs are replay-authority handles, not unique utterance IDs. Non-prefix
                // corrections are ambiguous; both statements are kept for the notes.
                if (legacy || same_source) && (current == previous || previous.starts_with(&format!("{current} "))) {
                    last.insert("updatedAt".into(), updated);
                    continue;
                }
                if (legacy || same_source) && current.starts_with(&format!("{previous} ")) {
                    last.insert("text".into(), json!(text));
                    last.insert("updatedAt".into(), updated);
                    if let Some(src) = item.get("source") {
                        last.insert("source".into(), src.clone());
                    }
                    continue;
                }
            }
        }
        out.push(item);
    }
    out
}

fn truthy(v: &Value) -> bool {
    crate::phone::model::truthy(Some(v))
}

/// `atomicJson`: `<path>.tmp` (0600), then a rename.
pub fn atomic_json(path: &Path, value: &Value) -> std::io::Result<()> {
    cc_store::write_json_atomic(path, value, 0o600, cc_store::TmpName::Suffix)
}

static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9-]{36}$").expect("regex"));
static FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9-]{36}\.json$").expect("regex"));

/// The meetings archive (`MeetingArchive`). Tombstones are outside the backed-up home; a restore
/// applies them before OpenClaw starts again.
pub struct MeetingArchive {
    pub root: PathBuf,
    pub tombstones: PathBuf,
}

impl MeetingArchive {
    pub fn new(root: &Path, tombstones: &Path) -> Self {
        let _ = std::fs::create_dir_all(root);
        let _ = std::fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        Self {
            root: root.to_path_buf(),
            tombstones: tombstones.to_path_buf(),
        }
    }

    fn filename(&self, id: &str) -> Result<PathBuf, String> {
        if !ID.is_match(id) {
            return Err("Invalid meeting".into());
        }
        Ok(self.root.join(format!("{id}.json")))
    }

    /// The deleted meetings and their native session ids, in the file's order.
    pub fn deleted(&self) -> Result<Map<String, Value>, String> {
        if !self.tombstones.exists() {
            return Ok(Map::new());
        }
        let raw = std::fs::read(&self.tombstones).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        Ok(v.as_object().cloned().unwrap_or_default())
    }

    /// Write a record, unless the meeting was deleted.
    pub fn save(&self, record: &Value) -> Result<bool, String> {
        let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
        if self.deleted()?.contains_key(id) {
            return Ok(false);
        }
        std::fs::create_dir_all(&self.root).map_err(|e| e.to_string())?;
        atomic_json(&self.filename(id)?, record).map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Every record not deleted, newest first.
    pub fn list(&self) -> Result<Vec<Value>, String> {
        let deleted = self.deleted()?;
        let Ok(dir) = std::fs::read_dir(&self.root) else {
            return Ok(Vec::new());
        };
        let mut out: Vec<Value> = Vec::new();
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !FILE.is_match(&name) {
                continue;
            }
            let raw = std::fs::read(e.path()).map_err(|e| e.to_string())?;
            let r: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            if !deleted.contains_key(r.get("id").and_then(Value::as_str).unwrap_or_default()) {
                out.push(r);
            }
        }
        // `b.startedAt.localeCompare(a.startedAt)`: ISO times compare as text.
        out.sort_by(|a, b| {
            let k = |v: &Value| {
                v.get("startedAt")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            k(b).cmp(&k(a))
        });
        Ok(out)
    }

    pub fn tombstone(&self, record: &Value) -> Result<(), String> {
        let pending = PathBuf::from(format!("{}.pending", self.tombstones.display()));
        atomic_json(&pending, &json!({"pending": true})).map_err(|e| e.to_string())?;
        let mut deleted = self.deleted()?;
        let id = record.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
        // `[...new Set([...(deleted[id] ?? []), ...record.sessionIds])]`, the key kept in place.
        let mut ids: Vec<Value> = deleted.get(&id).and_then(Value::as_array).cloned().unwrap_or_default();
        for s in record.get("sessionIds").and_then(Value::as_array).into_iter().flatten() {
            if !ids.contains(s) {
                ids.push(s.clone());
            }
        }
        deleted.insert(id, Value::Array(ids));
        atomic_json(&self.tombstones, &Value::Object(deleted)).map_err(|e| e.to_string())
    }

    pub fn deletion_pending(&self) -> bool {
        PathBuf::from(format!("{}.pending", self.tombstones.display())).exists()
    }

    pub fn deletion_finished(&self) {
        let _ = std::fs::remove_file(format!("{}.pending", self.tombstones.display()));
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        let path = self.filename(id)?;
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        }
    }
}

fn native_db(state_dir: &Path) -> PathBuf {
    state_dir.join("state").join("openclaw.sqlite")
}

/// `nativeMeetingIds`: OpenClaw's own meeting sessions, so deleting the whole archive also takes
/// those an interrupted join left.
pub fn native_meeting_ids(state_dir: &Path) -> Result<Vec<String>, String> {
    let file = native_db(state_dir);
    if !file.exists() {
        return Ok(Vec::new());
    }
    let db = rusqlite::Connection::open_with_flags(&file, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let has = db
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meeting_transcript_sessions'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !has {
        return Ok(Vec::new());
    }
    let mut q = db
        .prepare("SELECT DISTINCT session_id FROM meeting_transcript_sessions")
        .map_err(|e| e.to_string())?;
    q.query_map([], |r| r.get::<_, String>(0))
        .and_then(|rows| rows.collect())
        .map_err(|e| e.to_string())
}

static TRANSCRIPT_TABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^meeting_transcript_[a-z_]+$").expect("regex"));
static DATE_DIR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$").expect("regex"));

/// `eraseNativeMeetings`: those sessions' rows in OpenClaw's meeting tables (pinned 2026.9.7 schema,
/// child rows first) and their transcript exports. Only with the gateway stopped.
pub fn erase_native_meetings(state_dir: &Path, session_ids: &[String]) -> Result<(), String> {
    if session_ids.is_empty() {
        return Ok(());
    }
    let file = native_db(state_dir);
    if file.exists() {
        let db = rusqlite::Connection::open(&file).map_err(|e| e.to_string())?;
        let run = || -> Result<(), String> {
            db.execute_batch(
                "PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; BEGIN IMMEDIATE",
            )
            .map_err(|e| e.to_string())?;
            let mut tables: Vec<String> = {
                let mut q = db
                    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'meeting_transcript_%'")
                    .map_err(|e| e.to_string())?;
                q.query_map([], |r| r.get(0))
                    .and_then(|rows| rows.collect())
                    .map_err(|e| e.to_string())?
            };
            // Child rows first, even if an older database lacks cascades (a stable sort).
            tables.sort_by_key(|n| n == "meeting_transcript_sessions");
            for name in &tables {
                if !TRANSCRIPT_TABLE.is_match(name) {
                    return Err("Unexpected transcript schema".into());
                }
                let mut q = db
                    .prepare(&format!(r#"PRAGMA table_info("{name}")"#))
                    .map_err(|e| e.to_string())?;
                let has_session = q
                    .query_map([], |r| r.get::<_, String>(1))
                    .and_then(|rows| rows.collect::<Result<Vec<String>, _>>())
                    .map_err(|e| e.to_string())?
                    .iter()
                    .any(|c| c == "session_id");
                if !has_session {
                    continue;
                }
                for id in session_ids {
                    db.execute(&format!(r#"DELETE FROM "{name}" WHERE session_id = ?"#), [id])
                        .map_err(|e| e.to_string())?;
                }
            }
            db.execute_batch("COMMIT; VACUUM; PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(|e| e.to_string())
        };
        if let Err(e) = run() {
            let _ = db.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    let exports = state_dir.join("transcripts");
    let Ok(dates) = std::fs::read_dir(&exports) else {
        return Ok(());
    };
    let root = std::fs::canonicalize(&exports).map_err(|e| e.to_string())?;
    for date in dates.flatten() {
        let name = date.file_name().to_string_lossy().into_owned();
        if !date.file_type().is_ok_and(|t| t.is_dir()) || !DATE_DIR.is_match(&name) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(date.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let dir = entry.path();
            // `resolve(...)` stays inside the exports folder: a symlinked folder is not followed out.
            let real = std::fs::canonicalize(&dir).map_err(|e| e.to_string())?;
            if !real.starts_with(&root) || real == root {
                return Err("Invalid transcript export".into());
            }
            let metadata = dir.join("metadata.json");
            // No metadata: not an export to look at. Metadata that cannot be read fails the erase,
            // so it is tried again rather than reported done with the export still there.
            if !metadata.exists() {
                continue;
            }
            let raw = std::fs::read(&metadata).map_err(|e| e.to_string())?;
            let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            if v.get("sessionId")
                .and_then(Value::as_str)
                .is_some_and(|s| session_ids.iter().any(|x| x == s))
            {
                std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(text: &str, seconds: i64, speaker: &str) -> Caption {
        json!({"at": crate::platform::time::iso_ms(seconds * 1000), "speaker": speaker, "text": text})
            .as_object()
            .cloned()
            .expect("o")
    }

    fn src(text: &str, seconds: i64, id: &str, revision: i64, speaker: &str) -> Caption {
        let mut r = row(text, seconds, speaker);
        r.insert("source".into(), json!({"id": id, "revision": revision}));
        r
    }

    fn texts(rows: &[Caption]) -> Vec<String> {
        rows.iter().map(|r| s(r, "text")).collect()
    }

    #[test]
    fn ui_lines_and_incremental_captions_do_not_repeat() {
        let lines: Vec<Caption> = [
            "Turn on captions",
            "I will",
            "I will send",
            "I will send the report Friday",
            "I will send the report Friday",
        ]
        .iter()
        .enumerate()
        .map(|(i, t)| row(t, i as i64, "A"))
        .collect();
        assert_eq!(texts(&clean_captions(&lines)), ["I will send the report Friday"]);
        let mut more = lines.clone();
        let mut b = lines[4].clone();
        b.insert("speaker".into(), json!("B"));
        more.push(b);
        let mut late = lines[4].clone();
        late.insert("at".into(), json!(crate::platform::time::iso_ms(30_000)));
        more.push(late);
        assert_eq!(clean_captions(&more).len(), 3);
    }

    #[test]
    fn combined_device_announcements_are_removed() {
        let rows: Vec<Caption> = [
            "Your camera is off. Your microphone is off.",
            "Your camera is off.",
            "Your microphone is off.",
            "Alex will check why the camera is off by Friday.",
        ]
        .iter()
        .enumerate()
        .map(|(i, t)| row(t, i as i64, "Unknown speaker"))
        .collect();
        assert_eq!(
            texts(&clean_captions(&rows)),
            ["Alex will check why the camera is off by Friday."]
        );
    }

    #[test]
    fn deletion_blocks_late_notes_and_erases_native_rows_and_exports() {
        let root = tempfile::tempdir().expect("dir");
        let archive = MeetingArchive::new(&root.path().join("notes"), &root.path().join("deleted.json"));
        let record = json!({
            "id": "0b3e7d4e-7d6f-4a8e-9a1c-2f1e3d4c5b6a", "startedAt": "2026-10-02T10:00:00.000Z",
            "state": "complete", "sessionIds": ["session"], "transcript": [],
        });
        assert_eq!(archive.save(&record), Ok(true));
        archive.tombstone(&record).expect("tombstone");
        let mut late = record.clone();
        late["notes"] = json!("late completion");
        assert_eq!(archive.save(&late), Ok(false));
        assert!(archive.list().expect("list").is_empty());
        assert!(archive.deletion_pending());
        archive.deletion_finished();
        assert!(!archive.deletion_pending());

        std::fs::create_dir_all(root.path().join("state")).expect("dir");
        let db = rusqlite::Connection::open(root.path().join("state").join("openclaw.sqlite")).expect("db");
        db.execute_batch("CREATE TABLE meeting_transcript_sessions(session_id TEXT PRIMARY KEY); CREATE TABLE meeting_transcript_utterances(session_id TEXT REFERENCES meeting_transcript_sessions(session_id), text TEXT); INSERT INTO meeting_transcript_sessions VALUES ('session'), ('unrelated'); INSERT INTO meeting_transcript_utterances VALUES ('session', 'secret');")
            .expect("seed");
        drop(db);
        let dir = root.path().join("transcripts").join("2026-10-02").join("session");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("metadata.json"), r#"{"sessionId":"session"}"#).expect("meta");
        assert_eq!(native_meeting_ids(root.path()).expect("ids").len(), 2);
        erase_native_meetings(root.path(), &["session".into()]).expect("erase");
        assert!(!dir.exists());
        assert_eq!(native_meeting_ids(root.path()).expect("ids"), ["unrelated"]);
    }

    #[test]
    fn live_meet_announcements_and_navigation_stay_out() {
        let texts_in = [
            "You have joined the call. There is one other person in the call. Your camera is off. Your microphone is off. Your hand is lowered.",
            "arrow_downwardJump to bottom",
            "Hello! Can.",
            "Hello! Can you?",
            "Alex will investigate why you have joined the call twice by Friday.",
        ];
        let rows: Vec<Caption> = texts_in
            .iter()
            .enumerate()
            .map(|(i, t)| row(t, i as i64 * 2, "Alex"))
            .collect();
        assert_eq!(texts(&clean_captions(&rows)), [texts_in[3], texts_in[4]]);
    }

    #[test]
    fn rolling_captions_consolidate_without_erasing_reused_sources() {
        let mut cleaned = clean_captions(&[src("Please send the report.", 0, "one", 1, "Alex")]);
        for seconds in (5..=60).step_by(5) {
            let mut next = cleaned.clone();
            next.push(src("Please send the report.", seconds, "one", seconds, "Alex"));
            cleaned = clean_captions(&next);
        }
        let mut next = cleaned.clone();
        next.push(src("Please send the report tomorrow.", 65, "one", 66, "Alex"));
        cleaned = clean_captions(&next);
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0]["at"], json!(crate::platform::time::iso_ms(0)));
        assert_eq!(cleaned[0]["text"], "Please send the report tomorrow.");
        let mut fin = cleaned.clone();
        fin.extend([
            src("I agree.", 66, "two", 1, "Bob"),
            src("Please send the report tomorrow.", 67, "one", 68, "Alex"),
            src("Please send the report tomorrow.", 600, "one", 69, "Alex"),
            src("Cancel that appointment.", 601, "one", 70, "Alex"),
        ]);
        assert_eq!(
            clean_captions(&fin).len(),
            5,
            "separate turns, long gaps and unrelated same-ID text remain"
        );
        let corrected = clean_captions(&[
            src("We agreed that Alex will right to Marco.", 0, "three", 1, "Alex"),
            src(
                "We agreed that Alex will write to Marco tomorrow.",
                1,
                "three",
                2,
                "Alex",
            ),
        ]);
        assert_eq!(corrected.len(), 2, "ambiguous non-prefix speech must survive");
        let commitments = clean_captions(&[
            src("I will send the final report Monday.", 0, "four", 1, "Alex"),
            src("I will send the final invoice Tuesday.", 1, "four", 2, "Alex"),
        ]);
        assert_eq!(commitments.len(), 2);
    }
}
