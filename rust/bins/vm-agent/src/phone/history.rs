//! The vm-agent's own notes on phone calls (`PhoneCallLog` in `phone-history.ts`): which phone
//! settings were active when, and for each realtime stream whether it reached this box, why it was
//! refused or ended, and when the first audio went back to the caller. One small JSON file,
//! `<STATE_DIR>/phone-calls.json`, with no numbers and no speech.
//!
//! The file is kept as JSON values, so fields this build does not know survive a write and the
//! Node build can read what this one wrote.

use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde_json::{Map, Value, json};

const MAX_STREAMS: usize = 300;
const MAX_SETTINGS: usize = 50;
pub static SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^CA[0-9a-f]{32}$").expect("regex"));

/// `Date.parse` for the ISO forms it takes: `YYYY-MM-DD` (UTC), and `YYYY-MM-DDTHH:MM[:SS[.sss]]`
/// with `Z`, a `±HH:MM` offset, or none (the box's own zone, UTC on every box). Milliseconds, or
/// `None` where `Date.parse` gives NaN: a day the month does not have, hour 24 past midnight.
pub fn parse_iso(s: &str) -> Option<f64> {
    static ISO: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?(Z|[+-][0-9]{2}:[0-9]{2})?)?$")
            .expect("regex")
    });
    let c = ISO.captures(s)?;
    let n = |i: usize| c.get(i).map_or(0, |m| m.as_str().parse::<i64>().unwrap_or(0));
    let (y, mo, d, h, mi, sec) = (n(1), n(2), n(3), n(4), n(5), n(6));
    let ms = c
        .get(7)
        .map_or(0, |m| format!("{:0<3}", m.as_str())[..3].parse::<i64>().unwrap_or(0));
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    let midnight_24 = h == 24 && mi == 0 && sec == 0 && ms == 0;
    if !(1..=12).contains(&mo) || !(1..=days_in_month).contains(&d) || (h > 23 && !midnight_24) || mi > 59 || sec > 59 {
        return None;
    }
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * mm + 2) / 5 + d - 1;
    let days = era * 146_097 + doe - 719_468;
    let offset = match c.get(8).map(|m| m.as_str()) {
        Some("Z") | None => 0,
        Some(o) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o[1..3].parse::<i64>().unwrap_or(0) * 60 + o[4..6].parse::<i64>().unwrap_or(0))
        }
    };
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec - offset * 60) * 1000 + ms) as f64)
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A change to one stream's note (`Partial<StreamNote>`). Only the fields set are written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamPatch {
    pub at: Option<i64>,
    /// `connected` or `refused`.
    pub outcome: Option<&'static str>,
    /// The relay's refusal check (`refused reason=…`).
    pub reason: Option<String>,
    /// Set when the relay ended the stream because the local plugin refused, failed or closed it.
    pub local_code: Option<u16>,
    pub first_audio_at: Option<i64>,
    pub ended_at: Option<i64>,
}

impl StreamPatch {
    /// The fields in the order the TS object literals list them.
    fn entries(&self) -> Vec<(&'static str, Value)> {
        let mut out = Vec::new();
        if let Some(v) = self.at {
            out.push(("at", json!(v)));
        }
        if let Some(v) = self.outcome {
            out.push(("outcome", json!(v)));
        }
        if let Some(v) = &self.reason {
            out.push(("reason", json!(v)));
        }
        if let Some(v) = self.local_code {
            out.push(("localCode", json!(v)));
        }
        if let Some(v) = self.first_audio_at {
            out.push(("firstAudioAt", json!(v)));
        }
        if let Some(v) = self.ended_at {
            out.push(("endedAt", json!(v)));
        }
        out
    }
}

pub struct PhoneCallLog {
    file: PathBuf,
    data: Mutex<Map<String, Value>>,
}

fn empty() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("version".into(), json!(1));
    m.insert("streams".into(), json!({}));
    m.insert("settings".into(), json!([]));
    m
}

/// `raw?.version === 1 && raw.streams && Array.isArray(raw.settings)`.
fn usable(raw: &Value) -> bool {
    let truthy = |v: Option<&Value>| match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        _ => true,
    };
    raw.get("version").and_then(Value::as_f64) == Some(1.0)
        && truthy(raw.get("streams"))
        && raw.get("settings").is_some_and(Value::is_array)
}

impl PhoneCallLog {
    pub fn open(file: &Path) -> Self {
        let data = std::fs::read(file)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(usable)
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_else(empty);
        Self {
            file: file.to_path_buf(),
            data: Mutex::new(data),
        }
    }

    fn save(&self, data: &Map<String, Value>) {
        if let Err(e) = cc_store::write_json_atomic(&self.file, data, 0o600, cc_store::TmpName::Suffix) {
            tracing::warn!("[phone] call log not saved: {e}");
        }
    }

    /// Merge `patch` into the call's note (`stream(sid, patch)`).
    pub fn stream(&self, sid: &str, patch: &StreamPatch) {
        if !SID.is_match(sid) {
            return;
        }
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let streams = data.entry("streams").or_insert_with(|| json!({}));
        if !streams.is_object() {
            // A truthy non-object `streams` (an older or broken file): the TS writes keys onto it
            // and they are lost on save; start the map over instead of failing.
            *streams = json!({});
        }
        let Some(streams) = streams.as_object_mut() else { return };
        let prev = streams.get(sid).cloned();
        // A second upgrade for a call that is already streaming (a duplicate or a retry) may be
        // refused; that does not undo the stream that connected.
        if patch.outcome == Some("refused")
            && prev.as_ref().and_then(|p| p.get("outcome")).and_then(Value::as_str) == Some("connected")
        {
            return;
        }
        let mut note = match prev {
            Some(Value::Object(m)) => m,
            _ => {
                let mut m = Map::new();
                m.insert("at".into(), json!(now_ms()));
                m.insert("outcome".into(), json!("connected"));
                m
            }
        };
        for (k, v) in patch.entries() {
            note.insert(k.into(), v);
        }
        streams.insert(sid.into(), Value::Object(note));
        if streams.len() > MAX_STREAMS {
            // Oldest first; a note without a time sorts as the oldest. `total_cmp`, so an odd value
            // cannot upset the sort.
            let mut sids: Vec<(String, f64)> = streams
                .iter()
                .map(|(k, v)| (k.clone(), v.get("at").and_then(Value::as_f64).unwrap_or(0.0)))
                .collect();
            sids.sort_by(|a, b| a.1.total_cmp(&b.1));
            let excess = sids.len() - MAX_STREAMS;
            for (old, _) in sids.into_iter().take(excess) {
                streams.remove(&old);
            }
        }
        self.save(&data);
    }

    /// What the relay noted for one call.
    pub fn stream_for(&self, sid: Option<&str>) -> Option<Map<String, Value>> {
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        data.get("streams")?.get(sid?)?.as_object().cloned()
    }

    /// Note the settings that became active (`settings(note)`), unless they are the last ones.
    pub fn settings(&self, note: Map<String, Value>) {
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let mut list = data
            .get("settings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(last) = list.last() {
            let same = ["realtime", "provider", "model", "replyModel"]
                .iter()
                .all(|k| last.get(*k) == note.get(*k));
            if same {
                return;
            }
        }
        list.push(Value::Object(note));
        let start = list.len().saturating_sub(MAX_SETTINGS);
        data.insert("settings".into(), Value::Array(list.split_off(start)));
        self.save(&data);
    }

    /// The settings active at `t`; nothing for a call older than the first note (`settingsAt`).
    pub fn settings_at(&self, t: f64) -> Option<Map<String, Value>> {
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let mut found = None;
        for s in data.get("settings").and_then(Value::as_array).into_iter().flatten() {
            if s.get("at").and_then(Value::as_f64).is_some_and(|at| at <= t) {
                found = s.as_object().cloned();
            }
        }
        found
    }

    /// Drop the notes of these calls (`forget(sids)`).
    pub fn forget<'a>(&self, sids: impl IntoIterator<Item = Option<&'a str>>) {
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let Some(streams) = data.get_mut("streams").and_then(Value::as_object_mut) else {
            return;
        };
        let mut changed = false;
        for sid in sids.into_iter().flatten() {
            changed |= streams.remove(sid).is_some();
        }
        if changed {
            self.save(&data);
        }
    }
}

// ---- The voice-call plugin's call records -------------------------------------------------

const PLUGIN: &str = "voice-call";
const EVENTS: &str = "call-record-events";
const CHUNKS: &str = "call-record-event-chunks";
const TERMINAL: &[&str] = &[
    "completed",
    "hangup-user",
    "hangup-bot",
    "timeout",
    "error",
    "failed",
    "no-answer",
    "busy",
    "voicemail",
];
/// The newest calls the page lists. The plugin keeps far more snapshots than calls.
pub const HISTORY_LIMIT: usize = 200;

fn terminal(call: &Value) -> bool {
    call.get("state")
        .and_then(Value::as_str)
        .is_some_and(|s| TERMINAL.contains(&s))
}

pub(crate) fn num(call: &Value, k: &str) -> Option<f64> {
    call.get(k).and_then(Value::as_f64)
}

/// A call that has not ended, and started recently enough for that to be believable.
pub fn call_in_progress(call: &Value, now: f64) -> bool {
    !terminal(call) && num(call, "startedAt").is_some_and(|s| now - s < 2.0 * 3_600_000.0)
}

/// The plugin's readiness check (`probePhone`): a status callback from the number to itself. It
/// leaves a call record with nothing said; it is not a call.
pub fn is_setup_probe(call: &Value) -> bool {
    call.get("from") == call.get("to")
        && call
            .get("transcript")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

/// `parseRecord`: a snapshot's call (version 2 wraps it), with `transcript` always a list.
fn parse_record(text: &str) -> Option<Value> {
    let parsed: Value = serde_json::from_str(text).ok()?;
    let mut call = if parsed.get("version").and_then(Value::as_f64) == Some(2.0) {
        parsed.get("call")?.clone()
    } else {
        parsed
    };
    if !call.get("callId").is_some_and(Value::is_string) || !call.get("startedAt").is_some_and(Value::is_number) {
        return None;
    }
    if !call.get("transcript").is_some_and(Value::is_array) {
        call.as_object_mut()?.insert("transcript".into(), json!([]));
    }
    Some(call)
}

/// Every snapshot in write order, decoded; one with a missing chunk decodes to `None`.
fn read_events(db: &rusqlite::Connection) -> rusqlite::Result<Vec<(String, Option<Value>)>> {
    let mut events = db.prepare(
        "SELECT entry_key, value_json FROM plugin_state_entries WHERE plugin_id = ? AND namespace = ? ORDER BY created_at, entry_key",
    )?;
    let rows: Vec<(String, String)> = events
        .query_map([PLUGIN, EVENTS], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut chunk = db.prepare(
        "SELECT value_json FROM plugin_state_entries WHERE plugin_id = ? AND namespace = ? AND entry_key = ?",
    )?;
    let mut out = Vec::new();
    for (key, meta) in rows {
        let record = (|| {
            let meta: Value = serde_json::from_str(&meta).ok()?;
            let count = meta
                .get("chunkCount")
                .and_then(Value::as_i64)
                .filter(|c| (1..=64).contains(c))?;
            let mut bytes = Vec::new();
            for i in 0..count {
                let c: String = chunk
                    .query_row([PLUGIN, CHUNKS, &format!("{key}:chunk:{i:04}")], |r| r.get(0))
                    .ok()?;
                let v: Value = serde_json::from_str(&c).ok()?;
                if v.get("index").and_then(Value::as_i64) != Some(i) {
                    return None;
                }
                let data = v.get("dataBase64").and_then(Value::as_str)?;
                bytes.extend(base64_lenient(data));
            }
            parse_record(&String::from_utf8_lossy(&bytes))
        })();
        out.push((key, record));
    }
    Ok(out)
}

/// `Buffer.from(s, "base64")`: lenient about padding and stray characters, as Node is.
fn base64_lenient(s: &str) -> Vec<u8> {
    use base64::Engine;
    let clean: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_'))
        .collect();
    let mut clean = clean.replace('-', "+").replace('_', "/");
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(clean).unwrap_or_default()
}

fn has_table(db: &rusqlite::Connection) -> bool {
    db.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='plugin_state_entries'",
        [],
        |_| Ok(()),
    )
    .is_ok()
}

/// The latest snapshot of each call, in the order the calls first appeared (a JS `Map`).
fn latest(rows: &[(String, Option<Value>)]) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::HashMap<String, Value> = Default::default();
    for (_, record) in rows {
        let Some(r) = record else { continue };
        let id = r["callId"].as_str().unwrap_or_default().to_string();
        if !map.contains_key(&id) {
            order.push(id.clone());
        }
        map.insert(id, r.clone());
    }
    order.into_iter().filter_map(|id| map.remove(&id)).collect()
}

/// The voice-call plugin's call records, in its own state database (`PluginCallStore`):
/// `~/.openclaw/voice-calls/state/openclaw.sqlite`, OpenClaw's `plugin_state_entries`, one row per
/// snapshot of a call and its base64 chunks. Pinned to @openclaw/voice-call 2026.9.7.
pub struct PluginCallStore {
    file: PathBuf,
}

impl PluginCallStore {
    pub fn new(file: &Path) -> Self {
        Self {
            file: file.to_path_buf(),
        }
    }

    pub fn available(&self) -> bool {
        self.file.exists()
    }

    fn open(&self, read_only: bool) -> rusqlite::Result<rusqlite::Connection> {
        use rusqlite::OpenFlags;
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };
        let db = rusqlite::Connection::open_with_flags(&self.file, flags)?;
        db.busy_timeout(std::time::Duration::from_millis(5000))?;
        Ok(db)
    }

    /// The latest snapshot of each call, newest call first, without the setup probes.
    pub fn calls(&self) -> Result<Vec<Value>, String> {
        if !self.available() {
            return Ok(Vec::new());
        }
        let db = self.open(true).map_err(|e| e.to_string())?;
        if !has_table(&db) {
            return Ok(Vec::new());
        }
        let rows = read_events(&db).map_err(|e| e.to_string())?;
        let mut calls: Vec<Value> = latest(&rows).into_iter().filter(|c| !is_setup_probe(c)).collect();
        calls.sort_by(|a, b| {
            num(b, "startedAt")
                .unwrap_or(0.0)
                .total_cmp(&num(a, "startedAt").unwrap_or(0.0))
        });
        Ok(calls)
    }

    /// Remove every snapshot of the given calls (`None`: all ended calls). A call still in
    /// progress is never touched: the plugin restores live calls from these rows after a restart.
    /// Returns the calls removed with their provider SIDs, so the vm-agent's notes go too.
    pub fn remove(
        &self,
        ids: Option<&std::collections::HashSet<String>>,
    ) -> Result<Vec<(String, Option<String>)>, String> {
        if !self.available() {
            return Ok(Vec::new());
        }
        let db = self.open(false).map_err(|e| e.to_string())?;
        if !has_table(&db) {
            return Ok(Vec::new());
        }
        let run = || -> rusqlite::Result<Vec<Value>> {
            db.execute_batch("PRAGMA secure_delete=ON; BEGIN IMMEDIATE")?;
            let rows = read_events(&db)?;
            let doomed: Vec<Value> = latest(&rows)
                .into_iter()
                .filter(|c| ids.is_none_or(|ids| ids.contains(c["callId"].as_str().unwrap_or_default())) && terminal(c))
                .collect();
            let doomed_ids: Vec<&str> = doomed.iter().filter_map(|c| c["callId"].as_str()).collect();
            for (key, record) in &rows {
                let Some(r) = record else { continue };
                if !doomed_ids.contains(&r["callId"].as_str().unwrap_or_default()) {
                    continue;
                }
                db.execute(
                    "DELETE FROM plugin_state_entries WHERE plugin_id = ? AND namespace = ? AND entry_key = ?",
                    [PLUGIN, EVENTS, key.as_str()],
                )?;
                // `<key>:chunk:0000` … `<key>:chunk:9999`; ';' sorts right after ':'.
                db.execute(
                    "DELETE FROM plugin_state_entries WHERE plugin_id = ? AND namespace = ? AND entry_key >= ? AND entry_key < ?",
                    [PLUGIN, CHUNKS, &format!("{key}:chunk:"), &format!("{key}:chunk;")],
                )?;
            }
            db.execute_batch("COMMIT")?;
            Ok(doomed)
        };
        match run() {
            Ok(doomed) => {
                // Shrinks the WAL so the deleted text leaves the disk sooner; busy is fine.
                if !doomed.is_empty() {
                    let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                }
                Ok(doomed
                    .iter()
                    .map(|c| {
                        (
                            c["callId"].as_str().unwrap_or_default().to_string(),
                            c.get("providerCallId").and_then(Value::as_str).map(String::from),
                        )
                    })
                    .collect())
            }
            Err(_) => {
                let _ = db.execute_batch("ROLLBACK");
                Err("Could not delete the call records".into())
            }
        }
    }
}

/// Where both stores live on an agent box (`phoneHistoryPaths`).
pub fn plugin_db_path(openclaw_home: &Path) -> PathBuf {
    openclaw_home.join("voice-calls").join("state").join("openclaw.sqlite")
}

// ---- How each call ran ----------------------------------------------------------------------

/// `+14155550123` → `…0123`. Anything without four digits becomes `…`.
pub fn mask_phone_number(v: Option<&Value>) -> String {
    let text = match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    let digits: Vec<char> = text.chars().filter(char::is_ascii_digit).collect();
    if digits.len() >= 4 {
        format!("…{}", digits[digits.len() - 4..].iter().collect::<String>())
    } else {
        "…".into()
    }
}

/// `splitModel`: `provider/model[@profile]` into its provider and model.
fn split_model(r: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(r) = r.filter(|r| !r.is_empty()) else {
        return (None, None);
    };
    let bare = match r.rfind('@') {
        Some(at) => &r[..at],
        None => r,
    };
    match bare.find('/') {
        Some(slash) if slash > 0 => (Some(bare[..slash].into()), Some(bare[slash + 1..].into())),
        _ => (None, Some(bare.into())),
    }
}

fn local_fallback(code: i64) -> Value {
    use super::stream::close;
    if (4100..=4599).contains(&code) {
        json!({"reason": "plugin_refused", "detail": format!("HTTP {}", code - 4000)})
    } else if code == i64::from(close::LISTENER_UNAVAILABLE) {
        json!({"reason": "plugin_refused", "detail": "not listening"})
    } else if code == i64::from(close::TIMEOUT) {
        json!({"reason": "timeout"})
    } else if code == i64::from(close::TRANSPORT) {
        json!({"reason": "plugin_refused", "detail": "connection error"})
    } else {
        json!({"reason": "provider_error"})
    }
}

/// The voice sessions the adapter logged for phone calls (`VoiceUsage`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VoiceUsage {
    pub started_at: f64,
    pub seconds: f64,
}

fn js_round(f: f64) -> i64 {
    (f + 0.5).floor() as i64
}

/// One call as the page lists it (`summarizeCall`).
pub fn summarize_call(call: &Value, log: &PhoneCallLog, usage: &[VoiceUsage], now: f64) -> Map<String, Value> {
    let started = num(call, "startedAt").unwrap_or(0.0);
    let settings = log.settings_at(started);
    let stream = log.stream_for(call.get("providerCallId").and_then(Value::as_str));
    let active = !terminal(call);
    let transcript: Vec<Value> = call
        .get("transcript")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let ts = |t: &Value| t.get("timestamp").and_then(Value::as_f64);
    let spoke = !transcript.is_empty() || call.get("answeredAt").is_some_and(|v| !v.is_null());
    let s_get = |k: &str| stream.as_ref().and_then(|s| s.get(k)).cloned();
    let local_code = s_get("localCode").and_then(|v| v.as_i64());
    let first_audio = s_get("firstAudioAt").and_then(|v| v.as_f64());
    let local_closed = i64::from(super::stream::close::LOCAL_CLOSED);
    let (mut mode, mut fallback) = ("classic", Value::Null);
    let spoke_realtime = call
        .pointer("/metadata/recentTalkEvents")
        .and_then(Value::as_array)
        .is_some_and(|e| {
            e.iter()
                .any(|x| x.get("mode").and_then(Value::as_str) == Some("realtime"))
        });
    if s_get("outcome").and_then(|v| v.as_str().map(String::from)).as_deref() == Some("refused") {
        mode = "fallback";
        let mut f = Map::new();
        f.insert("reason".into(), json!("agent_refused"));
        if let Some(r) = s_get("reason").filter(|r| !r.is_null()) {
            f.insert("detail".into(), r);
        }
        fallback = Value::Object(f);
    } else if let Some(code) = local_code {
        if code == local_closed {
            // The plugin ended the stream. That is the normal end of a call (the caller hung
            // up), and a fallback only when the call went on in classic speech after it.
            let ended = s_get("endedAt").and_then(|v| v.as_f64()).unwrap_or(f64::INFINITY);
            let after = transcript.iter().any(|t| ts(t).is_some_and(|x| x > ended + 2000.0));
            mode = if after { "fallback" } else { "realtime" };
            if after {
                fallback = json!({"reason": if first_audio.is_some() { "dropped" } else { "provider_error" }});
            }
        } else {
            mode = "fallback";
            fallback = local_fallback(code);
        }
    } else if stream.is_some() || spoke_realtime {
        mode = "realtime";
    } else if settings
        .as_ref()
        .and_then(|s| s.get("realtime"))
        .and_then(Value::as_bool)
        == Some(true)
        && spoke
        && !active
    {
        mode = "fallback";
        fallback = json!({"reason": "never_connected"});
    }
    let tried = mode != "classic";
    let setting = |k: &str| {
        settings
            .as_ref()
            .and_then(|s| s.get(k))
            .and_then(Value::as_str)
            .map(String::from)
    };
    let (provider, model) = if tried {
        (setting("provider"), setting("model"))
    } else {
        split_model(setting("replyModel").as_deref())
    };
    let mut first_response: Option<f64> = None;
    let first_user = transcript
        .iter()
        .position(|t| t.get("speaker").and_then(Value::as_str) == Some("user"));
    let reply = first_user.and_then(|i| {
        transcript[i + 1..]
            .iter()
            .find(|t| t.get("speaker").and_then(Value::as_str) == Some("bot"))
    });
    if let (Some(i), Some(r)) = (first_user, reply) {
        first_response = Some((ts(r).unwrap_or(f64::NAN) - ts(&transcript[i]).unwrap_or(f64::NAN)).max(0.0));
    } else if let Some(fa) = first_audio.filter(|f| *f != 0.0) {
        first_response = Some((fa - s_get("at").and_then(|v| v.as_f64()).unwrap_or(f64::NAN)).max(0.0));
    }
    let mut errors: Vec<String> = Vec::new();
    if s_get("outcome").as_ref().and_then(Value::as_str) == Some("refused") {
        let reason = s_get("reason")
            .and_then(|r| r.as_str().map(String::from))
            .unwrap_or_else(|| "unknown".into());
        errors.push(format!("stream refused: {reason}"));
    }
    if let Some(code) = local_code.filter(|c| *c != local_closed) {
        errors.push(format!("stream closed: {code}"));
    }
    let apologies = transcript
        .iter()
        .filter(|t| {
            t.get("speaker").and_then(Value::as_str) == Some("bot")
                && t.get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|x| x.trim() == super::compat::no_reply_text())
        })
        .count();
    if apologies == 1 {
        errors.push("reply failed".into());
    } else if apologies > 1 {
        errors.push(format!("reply failed ×{apologies}"));
    }
    let end_reason = call.get("endReason").and_then(Value::as_str);
    if matches!(end_reason, Some("error" | "failed")) {
        errors.push(format!("call {}", end_reason.unwrap_or_default()));
    }
    let end = num(call, "endedAt");
    let duration = match end {
        None if active => Value::Null,
        None => json!(0),
        Some(e) => {
            let from = num(call, "answeredAt").unwrap_or(started);
            json!(js_round((e - from) / 1000.0).max(0))
        }
    };
    // The voice sessions that started during this call (the adapter's log; gpt-live plan, D11).
    let upto = end.unwrap_or(now) + 2000.0;
    let sessions: Vec<&VoiceUsage> = usage
        .iter()
        .filter(|u| u.started_at >= started - 2000.0 && u.started_at <= upto)
        .collect();
    let reply_model = if tried && setting("replyModel").is_some() {
        let (p, m) = split_model(setting("replyModel").as_deref());
        json!(format!("{}/{}", p.unwrap_or_default(), m.unwrap_or_default()))
    } else {
        Value::Null
    };
    let num_json = |v: Option<f64>| {
        v.map_or(
            Value::Null,
            |f| if f.fract() == 0.0 { json!(f as i64) } else { json!(f) },
        )
    };
    let mut out = Map::new();
    out.insert("id".into(), call.get("callId").cloned().unwrap_or(Value::Null));
    out.insert(
        "direction".into(),
        json!(if call.get("direction").and_then(Value::as_str) == Some("outbound") {
            "outbound"
        } else {
            "inbound"
        }),
    );
    out.insert("from".into(), json!(mask_phone_number(call.get("from"))));
    out.insert("to".into(), json!(mask_phone_number(call.get("to"))));
    out.insert(
        "startedAt".into(),
        call.get("startedAt").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "endedAt".into(),
        call.get("endedAt")
            .cloned()
            .filter(|v| !v.is_null())
            .unwrap_or(Value::Null),
    );
    out.insert("durationSeconds".into(), duration);
    out.insert("state".into(), call.get("state").cloned().unwrap_or(Value::Null));
    out.insert(
        "endReason".into(),
        call.get("endReason")
            .cloned()
            .filter(|v| !v.is_null())
            .unwrap_or(Value::Null),
    );
    out.insert("active".into(), json!(active));
    out.insert("mode".into(), json!(mode));
    out.insert("fallback".into(), fallback);
    out.insert("provider".into(), provider.map_or(Value::Null, Value::String));
    out.insert("model".into(), model.map_or(Value::Null, Value::String));
    out.insert("replyModel".into(), reply_model);
    out.insert("firstResponseMs".into(), num_json(first_response));
    out.insert("errors".into(), json!(errors));
    out.insert(
        "turns".into(),
        json!(
            transcript
                .iter()
                .filter(|t| t.get("speaker").and_then(Value::as_str) == Some("user"))
                .count()
        ),
    );
    out.insert(
        "voiceSeconds".into(),
        if sessions.is_empty() {
            Value::Null
        } else {
            num_json(Some(sessions.iter().map(|u| u.seconds).sum()))
        },
    );
    out
}

/// One call with its transcript (`callDetail`).
pub fn call_detail(call: &Value, log: &PhoneCallLog, usage: &[VoiceUsage], now: f64) -> Map<String, Value> {
    let mut out = summarize_call(call, log, usage, now);
    let transcript: Vec<Value> = call
        .get("transcript")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|t| t.get("isFinal") != Some(&json!(false)) && t.get("text").is_some_and(Value::is_string))
        .map(|t| {
            json!({
                "at": t.get("timestamp").cloned().unwrap_or(Value::Null),
                "speaker": if t.get("speaker").and_then(Value::as_str) == Some("user") { "caller" } else { "agent" },
                "text": t["text"],
            })
        })
        .collect();
    out.insert("transcript".into(), json!(transcript));
    out.insert(
        "transcriptTruncated".into(),
        json!(call.pointer("/metadata/voiceCallPersistence/transcriptTruncated") == Some(&json!(true))),
    );
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn sid(c: char) -> String {
        format!("CA{}", c.to_string().repeat(32))
    }

    #[test]
    fn notes_merge_and_a_refusal_never_undoes_a_connection() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("phone-calls.json");
        let log = PhoneCallLog::open(&file);
        log.stream(
            "not-a-sid",
            &StreamPatch {
                at: Some(1),
                ..Default::default()
            },
        );
        log.stream(
            &sid('a'),
            &StreamPatch {
                at: Some(10),
                outcome: Some("connected"),
                ..Default::default()
            },
        );
        log.stream(
            &sid('a'),
            &StreamPatch {
                at: Some(11),
                outcome: Some("refused"),
                reason: Some("concurrency".into()),
                ..Default::default()
            },
        );
        log.stream(
            &sid('a'),
            &StreamPatch {
                ended_at: Some(20),
                ..Default::default()
            },
        );
        let note = log.stream_for(Some(&sid('a'))).expect("note");
        assert_eq!(
            Value::Object(note),
            json!({"at": 10, "outcome": "connected", "endedAt": 20})
        );
        let raw: Value = serde_json::from_slice(&std::fs::read(&file).expect("file")).expect("json");
        assert_eq!(raw["version"], 1);
        assert_eq!(raw["streams"].as_object().map(|m| m.len()), Some(1));
        // Read back by a fresh log, as after a restart.
        let again = PhoneCallLog::open(&file);
        assert_eq!(
            again
                .stream_for(Some(&sid('a')))
                .and_then(|n| n.get("endedAt").cloned()),
            Some(json!(20))
        );
    }

    #[test]
    fn keeps_the_newest_300_streams_and_unknown_fields() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("phone-calls.json");
        std::fs::write(
            &file,
            r#"{"version":1,"streams":{},"settings":[],"extra":{"kept":true}}"#,
        )
        .expect("seed");
        let log = PhoneCallLog::open(&file);
        for i in 0..301 {
            let s = format!("CA{i:032x}");
            log.stream(
                &s,
                &StreamPatch {
                    at: Some(1000 + i),
                    outcome: Some("connected"),
                    ..Default::default()
                },
            );
        }
        let raw: Value = serde_json::from_slice(&std::fs::read(&file).expect("file")).expect("json");
        let streams = raw["streams"].as_object().expect("streams");
        assert_eq!(streams.len(), 300);
        assert!(!streams.contains_key(&format!("CA{:032x}", 0)));
        assert_eq!(raw["extra"], json!({"kept": true}));
    }

    #[test]
    fn notes_without_a_time_sort_as_the_oldest() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("phone-calls.json");
        let mut streams = serde_json::Map::new();
        for i in 0..300 {
            let at = if i % 7 == 0 {
                json!("not a time")
            } else {
                json!(1000 + i)
            };
            streams.insert(format!("CA{i:032x}"), json!({"at": at, "outcome": "connected"}));
        }
        std::fs::write(
            &file,
            json!({"version": 1, "streams": streams, "settings": []}).to_string(),
        )
        .expect("seed");
        let log = PhoneCallLog::open(&file);
        log.stream(
            &format!("CA{:032x}", 999),
            &StreamPatch {
                at: Some(5000),
                outcome: Some("connected"),
                ..Default::default()
            },
        );
        let raw: Value = serde_json::from_slice(&std::fs::read(&file).expect("file")).expect("json");
        let kept = raw["streams"].as_object().expect("streams");
        assert_eq!(kept.len(), 300);
        assert!(
            !kept.contains_key(&format!("CA{:032x}", 0)),
            "the one with no time went first"
        );
    }

    // ---- `phone-history.test.ts` ------------------------------------------------------------

    use base64::Engine;
    use std::collections::HashSet;

    const T: i64 = 1_791_139_338_000;
    pub(crate) const A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
    const B: &str = "bbbbbbbb-0000-4000-8000-000000000002";
    const C: &str = "cccccccc-0000-4000-8000-000000000003";

    fn csid(c: char) -> String {
        format!("CA{}", c.to_string().repeat(32))
    }

    pub(crate) fn rec(id: &str, over: Value) -> Value {
        let mut r = json!({
            "callId": id,
            "providerCallId": csid(id.chars().next().unwrap_or('0')),
            "direction": "inbound",
            "state": "completed",
            "from": "+19452774183",
            "to": "+18885551817",
            "startedAt": T,
            "answeredAt": T + 1_000,
            "endedAt": T + 41_000,
            "endReason": "completed",
            "transcript": [
                {"timestamp": T + 1_200, "speaker": "bot", "text": "Hello! How can I help you today?", "isFinal": true},
                {"timestamp": T + 7_000, "speaker": "user", "text": "What is two plus three?", "isFinal": true},
                {"timestamp": T + 8_900, "speaker": "bot", "text": "Five.", "isFinal": true},
            ],
        });
        for (k, v) in over.as_object().cloned().unwrap_or_default() {
            if v.is_null() {
                r.as_object_mut().expect("o").remove(&k);
            } else {
                r[k.as_str()] = v;
            }
        }
        r
    }

    /// A state database in the plugin's own format: snapshot rows plus base64 chunks (2026.9.7).
    pub(crate) fn plugin_db(dir: &Path, snapshots: &[Value]) -> PathBuf {
        let path = plugin_db_path(dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        let db = rusqlite::Connection::open(&path).expect("db");
        db.execute_batch("CREATE TABLE plugin_state_entries (plugin_id TEXT NOT NULL, namespace TEXT NOT NULL, entry_key TEXT NOT NULL, value_json TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, PRIMARY KEY (plugin_id, namespace, entry_key))")
            .expect("table");
        let put = |p: &str, n: &str, k: &str, v: &str, at: i64| {
            db.execute(
                "INSERT INTO plugin_state_entries VALUES (?, ?, ?, ?, ?, NULL)",
                rusqlite::params![p, n, k, v, at],
            )
            .expect("insert");
        };
        // Another plugin's rows must never be read or deleted.
        put("other", "call-record-events", "event:x", "{}", 1);
        for (n, call) in snapshots.iter().enumerate() {
            let n = n as i64;
            let key = format!(
                "event:{}:{n:06}:{}-{n}",
                radix36(1000 + n),
                call["callId"].as_str().unwrap_or_default()
            );
            let buf = json!({"version": 2, "call": call, "persistedAt": 1000 + n})
                .to_string()
                .into_bytes();
            let count = buf.len().div_ceil(40);
            for i in 0..count {
                let part = &buf[i * 40..((i + 1) * 40).min(buf.len())];
                let v = json!({"index": i, "dataBase64": base64::engine::general_purpose::STANDARD.encode(part)})
                    .to_string();
                put(
                    "voice-call",
                    "call-record-event-chunks",
                    &format!("{key}:chunk:{i:04}"),
                    &v,
                    1000 + n,
                );
            }
            let meta = json!({"chunkCount": count, "byteLength": buf.len(), "persistedAt": 1000 + n, "sequence": n})
                .to_string();
            put("voice-call", "call-record-events", &key, &meta, 1000 + n);
        }
        path
    }

    fn radix36(mut n: i64) -> String {
        let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut out = Vec::new();
        while n > 0 {
            out.push(digits[(n % 36) as usize]);
            n /= 36;
        }
        out.reverse();
        String::from_utf8(out).unwrap_or_default()
    }

    fn rows(path: &Path) -> Vec<(String, String, String)> {
        let db = rusqlite::Connection::open(path).expect("db");
        let mut q = db
            .prepare("SELECT plugin_id, namespace, entry_key FROM plugin_state_entries")
            .expect("q");
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("rows")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("rows")
    }

    #[test]
    fn reads_the_latest_snapshot_of_each_call_newest_first() {
        let dir = tempfile::tempdir().expect("dir");
        let path = plugin_db(
            dir.path(),
            &[
                rec(
                    C,
                    json!({"from": "+18885551817", "to": "+18885551817", "transcript": []}),
                ),
                rec(A, json!({"state": "active", "endedAt": null, "endReason": null})),
                rec(B, json!({"startedAt": T + 60_000})),
                rec(A, json!({})),
            ],
        );
        let calls = PluginCallStore::new(&path).calls().expect("calls");
        // phone.ts's readiness probe leaves a record from the number to itself; it is not a call.
        let seen: Vec<(String, String)> = calls
            .iter()
            .map(|c| {
                (
                    c["callId"].as_str().unwrap_or_default().into(),
                    c["state"].as_str().unwrap_or_default().into(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![(B.into(), "completed".into()), (A.into(), "completed".into())]
        );
        assert_eq!(
            PluginCallStore::new(&path.join("missing"))
                .calls()
                .expect("calls")
                .len(),
            0
        );
        assert!(call_in_progress(&rec(A, json!({"state": "active"})), T as f64 + 1000.0));
        assert!(!call_in_progress(
            &rec(A, json!({"state": "active"})),
            T as f64 + 3.0 * 3_600_000.0
        ));
    }

    #[test]
    fn how_each_call_ran_and_why_it_fell_back() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("phone-calls.json");
        let log = PhoneCallLog::open(&file);
        let note = |v: Value| v.as_object().cloned().expect("o");
        log.settings(note(json!({"at": T - 3_600_000, "realtime": true, "provider": "gateway", "model": "openai/gpt-realtime-1.5", "replyModel": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt"})));
        let p = |at: Option<i64>, outcome: Option<&'static str>| StreamPatch {
            at,
            outcome,
            ..Default::default()
        };
        let now = (T + 100_000_000) as f64;

        // Realtime that spoke: first audio 1.9 s after the stream arrived.
        log.stream(&csid('a'), &p(Some(T + 500), Some("connected")));
        log.stream(
            &csid('a'),
            &StreamPatch {
                first_audio_at: Some(T + 2_400),
                ..Default::default()
            },
        );
        let a = summarize_call(&rec(A, json!({"transcript": []})), &log, &[], now);
        assert_eq!(a["mode"], "realtime");
        assert_eq!(a["fallback"], Value::Null);
        assert_eq!(a["firstResponseMs"], 1_900);
        assert_eq!(a["provider"], "gateway");
        assert_eq!(a["model"], "openai/gpt-realtime-1.5");
        assert_eq!(a["replyModel"], "openai/gpt-5.6-sol");
        assert_eq!(a["from"], "…4183");
        assert_eq!(a["to"], "…1817");
        assert_eq!(a["durationSeconds"], 40);

        // The relay refused the stream (T-138), then classic answered and one reply failed.
        log.stream(
            &csid('b'),
            &StreamPatch {
                at: Some(T + 500),
                outcome: Some("refused"),
                reason: Some("clock_skew".into()),
                ..Default::default()
            },
        );
        let mut b = rec(B, json!({}));
        b["transcript"]
            .as_array_mut()
            .expect("t")
            .push(json!({"timestamp": T + 20_000, "speaker": "bot", "text": super::super::compat::no_reply_text()}));
        let b = summarize_call(&b, &log, &[], now);
        assert_eq!(b["mode"], "fallback");
        assert_eq!(
            b["fallback"],
            json!({"reason": "agent_refused", "detail": "clock_skew"})
        );
        assert_eq!(b["errors"], json!(["stream refused: clock_skew", "reply failed"]));
        assert_eq!(b["firstResponseMs"], 1_900);

        // The plugin refused the handed-over stream.
        log.stream(
            &csid('c'),
            &StreamPatch {
                at: Some(T + 500),
                outcome: Some("connected"),
                local_code: Some(super::super::stream::close::refused(401)),
                ..Default::default()
            },
        );
        assert_eq!(
            summarize_call(&rec(C, json!({})), &log, &[], now)["fallback"],
            json!({"reason": "plugin_refused", "detail": "HTTP 401"})
        );

        // Realtime expected, but no stream ever reached this box.
        let d = summarize_call(
            &rec(
                "dddddddd-0000-4000-8000-000000000004",
                json!({"providerCallId": csid('d')}),
            ),
            &log,
            &[],
            now,
        );
        assert_eq!(d["fallback"], json!({"reason": "never_connected"}));

        // The plugin closed a stream that had spoken, and the call carried on: dropped.
        let closed = super::super::stream::close::LOCAL_CLOSED;
        log.stream(
            &csid('e'),
            &StreamPatch {
                at: Some(T + 500),
                outcome: Some("connected"),
                first_audio_at: Some(T + 2_000),
                local_code: Some(closed),
                ended_at: Some(T + 5_000),
                ..Default::default()
            },
        );
        let e = summarize_call(
            &rec(
                "eeeeeeee-0000-4000-8000-000000000005",
                json!({"providerCallId": csid('e')}),
            ),
            &log,
            &[],
            now,
        );
        assert_eq!(e["fallback"], json!({"reason": "dropped"}));

        // The caller hung up during the greeting: nothing came after the plugin closed the stream.
        log.stream(
            &csid('7'),
            &StreamPatch {
                at: Some(T + 500),
                outcome: Some("connected"),
                local_code: Some(closed),
                ended_at: Some(T + 40_500),
                ..Default::default()
            },
        );
        let hung = summarize_call(
            &rec(
                "77777777-0000-4000-8000-000000000007",
                json!({"providerCallId": csid('7')}),
            ),
            &log,
            &[],
            now,
        );
        assert_eq!(hung["mode"], "realtime");
        assert_eq!(hung["fallback"], Value::Null);
        // The voice service closed before speaking and the call went on in classic speech.
        log.stream(
            &csid('8'),
            &StreamPatch {
                at: Some(T + 500),
                outcome: Some("connected"),
                local_code: Some(closed),
                ended_at: Some(T + 3_000),
                ..Default::default()
            },
        );
        let f8 = summarize_call(
            &rec(
                "88888888-0000-4000-8000-000000000008",
                json!({"providerCallId": csid('8')}),
            ),
            &log,
            &[],
            now,
        );
        assert_eq!(f8["fallback"], json!({"reason": "provider_error"}));
        // A refused duplicate upgrade does not undo the stream that connected.
        log.stream(
            &csid('a'),
            &StreamPatch {
                at: Some(T + 900),
                outcome: Some("refused"),
                reason: Some("ticket_used".into()),
                ..Default::default()
            },
        );
        assert_eq!(
            log.stream_for(Some(&csid('a'))).and_then(|n| n.get("outcome").cloned()),
            Some(json!("connected"))
        );

        // Before realtime was turned on, a call is classic and shows the classic model.
        log.settings(note(json!({"at": T + 3_600_000, "realtime": false, "replyModel": "controlclaw/anthropic/claude-haiku-4.5@controlclaw:included"})));
        let f = summarize_call(
            &rec(
                "ffffffff-0000-4000-8000-000000000006",
                json!({"providerCallId": csid('f'), "startedAt": T + 7_200_000}),
            ),
            &log,
            &[],
            now,
        );
        assert_eq!(f["mode"], "classic");
        assert_eq!(f["provider"], "controlclaw");
        assert_eq!(f["model"], "anthropic/claude-haiku-4.5");
        assert_eq!(f["replyModel"], Value::Null);

        // A call older than the first settings note is judged by the plugin's own record only.
        let old = rec(
            "99999999-0000-4000-8000-000000000009",
            json!({"providerCallId": csid('9'), "startedAt": T - 7_200_000}),
        );
        assert_eq!(summarize_call(&old, &log, &[], now)["mode"], "classic");
        let mut talked = old.clone();
        talked["metadata"] = json!({"recentTalkEvents": [{"mode": "realtime"}]});
        assert_eq!(summarize_call(&talked, &log, &[], now)["mode"], "realtime");

        // The notes survive a restart of the vm-agent (after the writer had its turn).
        let again = PhoneCallLog::open(&file);
        assert_eq!(
            again
                .stream_for(Some(&csid('b')))
                .and_then(|n| n.get("reason").cloned()),
            Some(json!("clock_skew"))
        );
        assert_eq!(
            again.settings_at(T as f64).and_then(|s| s.get("realtime").cloned()),
            Some(json!(true))
        );

        let detail = call_detail(&rec(B, json!({})), &log, &[], now);
        let speakers: Vec<&str> = detail["transcript"]
            .as_array()
            .expect("t")
            .iter()
            .filter_map(|t| t["speaker"].as_str())
            .collect();
        assert_eq!(speakers, ["agent", "caller", "agent"]);
        assert_eq!(detail["transcriptTruncated"], false);
        // Voice minutes: the sessions that started during the call.
        let usage = [
            VoiceUsage {
                started_at: (T + 1_000) as f64,
                seconds: 30.0,
            },
            VoiceUsage {
                started_at: (T + 90_000) as f64,
                seconds: 9.0,
            },
        ];
        assert_eq!(
            summarize_call(&rec(A, json!({})), &log, &usage, now)["voiceSeconds"],
            30
        );
        assert_eq!(
            summarize_call(&rec(A, json!({})), &log, &[], now)["voiceSeconds"],
            Value::Null
        );
        assert_eq!(mask_phone_number(Some(&json!("12"))), "…");
    }

    #[test]
    fn deletes_ended_calls_only_never_another_plugins_rows() {
        let dir = tempfile::tempdir().expect("dir");
        let live = rec(C, json!({"state": "active", "endedAt": null, "endReason": null}));
        let path = plugin_db(
            dir.path(),
            &[
                rec(A, json!({})),
                rec(A, json!({"endReason": "hangup-user"})),
                rec(B, json!({})),
                live,
            ],
        );
        let store = PluginCallStore::new(&path);
        let one: HashSet<String> = [A.to_string()].into();
        assert_eq!(
            store
                .remove(Some(&one))
                .expect("remove")
                .into_iter()
                .map(|r| r.0)
                .collect::<Vec<_>>(),
            [A]
        );
        let mut left: Vec<String> = store
            .calls()
            .expect("calls")
            .iter()
            .map(|c| c["callId"].as_str().unwrap_or_default().to_string())
            .collect();
        left.sort();
        assert_eq!(left, [B, C]);
        let live_one: HashSet<String> = [C.to_string()].into();
        assert!(
            store.remove(Some(&live_one)).expect("remove").is_empty(),
            "a live call is not deleted"
        );
        assert_eq!(
            store
                .remove(None)
                .expect("remove")
                .into_iter()
                .map(|r| r.0)
                .collect::<Vec<_>>(),
            [B]
        );
        assert_eq!(
            store
                .calls()
                .expect("calls")
                .iter()
                .map(|c| c["callId"].clone())
                .collect::<Vec<_>>(),
            [json!(C)]
        );
        let all = rows(&path);
        assert_eq!(all.iter().filter(|r| r.0 == "other").count(), 1);
        assert_eq!(
            all.iter()
                .filter(|r| r.0 == "voice-call" && r.1 == "call-record-events")
                .count(),
            1
        );
        let chunks: Vec<_> = all.iter().filter(|r| r.1 == "call-record-event-chunks").collect();
        assert!(
            !chunks.is_empty() && chunks.iter().all(|r| r.2.contains(C)),
            "no orphaned chunks of deleted calls"
        );
    }

    #[test]
    fn dates_as_date_parse_reads_them() {
        assert_eq!(parse_iso("2026-10-01T02:31:00.000Z"), Some(1_790_821_860_000.0));
        assert_eq!(
            parse_iso("2026-10-01T04:31:00+02:00"),
            parse_iso("2026-10-01T02:31:00Z")
        );
        assert_eq!(parse_iso("2026-10-01"), parse_iso("2026-10-01T00:00Z"));
        assert_eq!(parse_iso("2026-10-01T02:31:00"), parse_iso("2026-10-01T02:31:00Z"));
        assert_eq!(parse_iso("2026-10-01T24:00:00Z"), parse_iso("2026-10-02T00:00:00Z"));
        for bad in [
            "2026-02-31T00:00:00Z",
            "2026-10-01T24:30:00Z",
            "2026-13-01",
            "Oct 1 2026",
            "",
        ] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_call_log_stays_bounded_and_forgets_deleted_calls() {
        let dir = tempfile::tempdir().expect("dir");
        let log = PhoneCallLog::open(&dir.path().join("phone-calls.json"));
        let id = |i: i64| format!("CA{i:032x}");
        for i in 0..320 {
            log.stream(
                &id(i),
                &StreamPatch {
                    at: Some(i),
                    outcome: Some("connected"),
                    ..Default::default()
                },
            );
        }
        assert!(log.stream_for(Some(&id(0))).is_none());
        assert!(log.stream_for(Some(&id(319))).is_some());
        log.forget([Some(id(319).as_str())]);
        assert!(log.stream_for(Some(&id(319))).is_none());
        log.stream(
            "not-a-sid",
            &StreamPatch {
                at: Some(1),
                outcome: Some("connected"),
                ..Default::default()
            },
        );
        assert!(log.stream_for(Some("not-a-sid")).is_none());
    }
}
