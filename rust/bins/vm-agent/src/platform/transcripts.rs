//! OpenClaw's own database, read-only (`openclaw-transcripts.ts`): the session key's parts, a
//! message's text, each run's trigger, and the conversations for Download workspace (W7's
//! `transcripts` contract). One SQLite file per agent; each session window's transcript is in
//! `transcript_events`, one JSON event per row, sometimes zstd-compressed. Pinned to the 2026.9.7
//! schema: an unknown one gives no conversations rather than an error.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};

/// OpenClaw's internal sessions: never a person's conversation.
pub static INTERNAL_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i):(cron|subagent|heartbeat|hook|probe|acp)(:|$)").expect("regex"));
static MAIN_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^agent:[^:]+:main$").expect("regex"));
pub static AGENT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("regex"));

/// `openDb`: read-only, a 5 s busy wait.
pub fn open_db(file: &Path) -> rusqlite::Result<Connection> {
    let db = Connection::open_with_flags(file, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    db.busy_timeout(Duration::from_millis(5000))?;
    Ok(db)
}

pub fn has_tables(db: &Connection, names: &[&str]) -> bool {
    let Ok(mut st) = db.prepare("SELECT name FROM sqlite_master WHERE type='table'") else {
        return false;
    };
    let have: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default();
    names.iter().all(|n| have.iter().any(|h| h == n))
}

/// An agent's database under OpenClaw's home.
pub fn agent_db(openclaw_home: &Path, agent_id: &str) -> PathBuf {
    openclaw_home
        .join("agents")
        .join(agent_id)
        .join("agent")
        .join("openclaw-agent.sqlite")
}

/// `agent:main:telegram:direct:123` → channel telegram, chatType direct, peer 123.
pub fn parse_session_key(key: &str) -> (String, Option<String>, Option<String>) {
    let parts: Vec<&str> = key.split(':').collect();
    let rest = if parts.first() == Some(&"agent") {
        parts.get(2..).unwrap_or(&[])
    } else {
        &parts[..]
    };
    match rest.len() {
        0 => ("chat".into(), None, None),
        1 => (
            if rest[0] == "main" {
                "web chat".into()
            } else {
                rest[0].into()
            },
            None,
            None,
        ),
        2 => (rest[0].into(), None, Some(rest[1].into())),
        _ => (rest[0].into(), Some(rest[1].into()), Some(rest[2..].join(":"))),
    }
}

/// The text of a transcript message: `openclawDisplayContent ?? content`, its text parts joined.
pub fn message_text(message: &Map<String, Value>) -> String {
    let content = match message.get("openclawDisplayContent") {
        Some(v) if !v.is_null() => Some(v),
        _ => message.get("content"),
    };
    match content {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter(|p| p.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n\n")
            .trim()
            .to_string(),
        _ => String::new(),
    }
}

/// A run, as the ledger names it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunRef {
    pub run_id: String,
    pub session_key: Option<String>,
    pub agent_id: Option<String>,
}

/// Agent id, then each session key with its run ids, in the order first seen.
pub type ByAgent = Vec<(String, Vec<(String, Vec<String>)>)>;

/// The newest 20 windows of a session key.
pub fn session_ids(db: &Connection, key: &str) -> Vec<String> {
    let Ok(mut st) = db.prepare_cached(
        "SELECT session_id FROM session_windows WHERE session_key = ? ORDER BY updated_at DESC LIMIT 20",
    ) else {
        return Vec::new();
    };
    st.query_map([key], |r| r.get::<_, String>(0))
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
}

/// What started each run of a main session (`session.started`'s `trigger`: `heartbeat`, `user`, ...).
pub fn run_triggers(openclaw_home: &Path, runs: &[RunRef]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    // By agent, then key, in the order first seen.
    let mut by_agent: ByAgent = Vec::new();
    for r in runs {
        let Some(key) = r.session_key.as_deref().filter(|k| MAIN_KEY.is_match(k)) else {
            continue;
        };
        let agent = r
            .agent_id
            .clone()
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| key.split(':').nth(1).unwrap_or_default().to_string());
        if !AGENT_ID.is_match(&agent) {
            continue;
        }
        let i = by_agent.iter().position(|(a, _)| *a == agent).unwrap_or_else(|| {
            by_agent.push((agent.clone(), Vec::new()));
            by_agent.len() - 1
        });
        let keys = &mut by_agent[i].1;
        match keys.iter_mut().find(|(k, _)| k == key) {
            Some((_, ids)) if !ids.contains(&r.run_id) => ids.push(r.run_id.clone()),
            Some(_) => {}
            None => keys.push((key.to_string(), vec![r.run_id.clone()])),
        }
    }
    for (agent, keys) in by_agent {
        let file = agent_db(openclaw_home, &agent);
        if !file.exists() {
            continue;
        }
        let mut read = || -> rusqlite::Result<()> {
            let db = open_db(&file)?;
            if !has_tables(&db, &["session_windows", "trajectory_runtime_events"]) {
                return Ok(());
            }
            let mut started = db.prepare(
                "SELECT event_json FROM trajectory_runtime_events WHERE session_id = ? AND run_id = ? AND event_json LIKE '%\"session.started\"%' LIMIT 1",
            )?;
            for (key, run_ids) in &keys {
                let ids = session_ids(&db, key);
                for run_id in run_ids {
                    for sid in &ids {
                        // The row found ends the search, whatever is in it (the TS's `break`).
                        let ev = match started.query_row([sid, run_id], |r| r.get::<_, Option<String>>(0)) {
                            Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                            Ok(ev) => ev.unwrap_or_default(),
                            Err(_) => String::new(),
                        };
                        // A row cut at OpenClaw's field size limit: no trigger for this run.
                        if let Ok(v) = serde_json::from_str::<Value>(&ev)
                            && v.get("type").and_then(Value::as_str) == Some("session.started")
                            && let Some(t) = v.pointer("/data/trigger").and_then(Value::as_str)
                        {
                            out.insert(run_id.clone(), super::common::js_slice(t, 32));
                        }
                        break;
                    }
                }
            }
            Ok(())
        };
        if let Err(e) = read() {
            tracing::error!("[audit] run triggers: {e}");
        }
    }
    out
}

use rusqlite::types::Value as SqlValue;

fn sql_text(v: &SqlValue) -> Option<String> {
    match v {
        SqlValue::Text(t) => Some(t.clone()),
        _ => None,
    }
}

fn sql_number(v: &SqlValue) -> Option<f64> {
    match v {
        SqlValue::Integer(i) => Some(*i as f64),
        SqlValue::Real(f) => Some(*f),
        _ => None,
    }
}

/// What an agent says when there is nothing to say; never worth a line in a transcript.
const SILENT: [&str; 3] = ["HEARTBEAT_OK", "NO_REPLY", "ANNOUNCE_SKIP"];
static COMMAND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i-u)^/[a-z][a-zA-Z0-9_-]*$").expect("regex"));

/// Every agent database under OpenClaw's home, by agent id, in name order.
pub fn agent_databases(openclaw_home: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(openclaw_home.join("agents")) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = rd
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    ids.sort();
    ids.into_iter()
        .map(|id| {
            let db = agent_db(openclaw_home, &id);
            (id, db)
        })
        // An id OpenClaw could name: listed only what can be read back.
        .filter(|(id, db)| AGENT_ID.is_match(id) && db.exists())
        .collect()
}

fn label_of(entry_json: &str) -> Option<String> {
    let e: Value = serde_json::from_str(entry_json).ok()?;
    for k in ["label", "displayName", "subject"] {
        if let Some(v) = e.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()) {
            return Some(v.into());
        }
    }
    e.pointer("/origin/label")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// The conversations worth exporting, newest first, without their text. Internal sessions and
/// empty ones are left out (`listConversations`).
pub fn list_conversations(openclaw_home: &Path) -> Vec<Value> {
    let mut refs: Vec<(f64, Value)> = Vec::new();
    for (agent_id, file) in agent_databases(openclaw_home) {
        let read = || -> rusqlite::Result<Vec<(f64, Value)>> {
            let db = open_db(&file)?;
            if !has_tables(&db, &["session_windows", "transcript_events"]) {
                return Ok(Vec::new());
            }
            let mut labels = std::collections::HashMap::new();
            if has_tables(&db, &["session_nodes"]) {
                let mut st = db.prepare("SELECT session_key, entry_json FROM session_nodes")?;
                // One row that is not text is no label, not the end of the list.
                let rows = st.query_map([], |r| Ok((r.get::<_, SqlValue>(0)?, r.get::<_, SqlValue>(1)?)))?;
                for (k, e) in rows.filter_map(Result::ok) {
                    if let SqlValue::Text(k) = k {
                        labels.insert(k, sql_text(&e).and_then(|e| label_of(&e)));
                    }
                }
            }
            let mut rows = db.prepare(
                "SELECT w.session_id AS id, w.session_key AS key, w.created_at AS created,
                        COALESCE(SUM(COALESCE(e.event_utf8_bytes, LENGTH(e.event_json))), 0) AS bytes,
                        COUNT(e.seq) AS events
                   FROM session_windows w LEFT JOIN transcript_events e ON e.session_id = w.session_id
                  GROUP BY w.session_id ORDER BY w.created_at DESC",
            )?;
            let mut channels_of = db.prepare(
                "SELECT CASE WHEN json_valid(event_json) THEN json_extract(event_json, '$.message.__openclaw.transport.channel') END AS c, MIN(seq) AS first
                   FROM transcript_events WHERE session_id = ? AND event_json IS NOT NULL AND c IS NOT NULL
                  GROUP BY c ORDER BY first",
            )?;
            // Something a person said, decided in SQLite (a compressed row counts: it cannot be looked into).
            let mut spoken = db.prepare(
                "SELECT 1 FROM transcript_events WHERE session_id = ? AND (event_zstd IS NOT NULL OR (
                     CASE WHEN json_valid(event_json) THEN json_extract(event_json, '$.message.role') = 'user'
                       AND COALESCE(json_extract(event_json, '$.message.provenance.kind'), '') NOT LIKE 'internal%' END))
                  LIMIT 1",
            )?;
            // Each row on its own: a window with an odd column is left out, the others are listed.
            let all: Vec<(String, String, Option<f64>, f64, i64)> = rows
                .query_map([], |r| {
                    Ok((
                        r.get::<_, SqlValue>(0)?,
                        r.get::<_, SqlValue>(1)?,
                        r.get::<_, SqlValue>(2)?,
                        r.get::<_, SqlValue>(3)?,
                        r.get::<_, SqlValue>(4)?,
                    ))
                })?
                .filter_map(Result::ok)
                .filter_map(|(id, key, created, bytes, events)| {
                    Some((
                        sql_text(&id)?,
                        sql_text(&key)?,
                        sql_number(&created),
                        sql_number(&bytes).unwrap_or(0.0),
                        sql_number(&events)? as i64,
                    ))
                })
                .collect();
            let mut out = Vec::new();
            for (id, key, created, bytes, events) in all {
                if events == 0 || INTERNAL_KEY.is_match(&key) || spoken.query_row([&id], |_| Ok(())).is_err() {
                    continue;
                }
                let channels: Vec<String> = channels_of
                    .query_map([&id], |r| r.get::<_, rusqlite::types::Value>(0))?
                    .filter_map(Result::ok)
                    .filter_map(|v| match v {
                        rusqlite::types::Value::Text(t) if !t.is_empty() => Some(t),
                        _ => None,
                    })
                    .collect();
                out.push((
                    created.unwrap_or(f64::NEG_INFINITY),
                    serde_json::json!({
                        "agentId": agent_id, "db": file.to_string_lossy(), "sessionId": id, "sessionKey": key,
                        "createdAt": created.map_or(Value::Null, super::common::js_number), "label": labels.get(&key).cloned().flatten(),
                        "bytes": super::common::js_number(bytes), "channels": channels,
                    }),
                ));
            }
            Ok(out)
        };
        match read() {
            Ok(mut r) => refs.append(&mut r),
            Err(e) => tracing::error!("[export] conversations: {e}"),
        }
    }
    // Newest first; a stable sort keeps equal ones in reading order, as JS's does.
    refs.sort_by(|a, b| b.0.total_cmp(&a.0));
    refs.into_iter().map(|r| r.1).collect()
}

/// A decompressed event larger than this is unreadable: the database is the agent's to write, and
/// a small frame can claim gigabytes.
const MAX_EVENT_BYTES: usize = 32 * 1024 * 1024;

/// `zstdDecompressSync`: every frame in turn, skippable ones skipped, capped at `MAX_EVENT_BYTES`.
fn unzstd(mut input: &[u8]) -> Option<Vec<u8>> {
    use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
    use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
    use std::io::Read;
    let mut decoder = FrameDecoder::new();
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    while !input.is_empty() {
        match decoder.init(&mut input) {
            Ok(()) => {}
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
                input = input.get(length as usize..)?;
                continue;
            }
            Err(_) => return None,
        }
        loop {
            decoder
                .decode_blocks(&mut input, BlockDecodingStrategy::UptoBytes(1024 * 1024))
                .ok()?;
            loop {
                let n = decoder.read(&mut chunk).ok()?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
                if out.len() > MAX_EVENT_BYTES {
                    return None;
                }
            }
            if decoder.is_finished() {
                break;
            }
        }
    }
    Some(out)
}

/// `JSON.parse` keeps a lone surrogate escape (`"\ud83d"`, an emoji cut by `slice`); serde refuses
/// the whole text. Each lone one becomes U+FFFD so the rest of the event is read.
fn mend_surrogates(text: &str) -> String {
    let b = text.as_bytes();
    let hex4 = |i: usize| -> Option<u16> { u16::from_str_radix(text.get(i..i + 4)?, 16).ok() };
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut start = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        if b.get(i + 1) != Some(&b'u') {
            i += 2;
            continue;
        }
        let Some(u) = hex4(i + 2) else {
            i += 2;
            continue;
        };
        let paired = (0xD800..0xDC00).contains(&u)
            && b.get(i + 6) == Some(&b'\\')
            && b.get(i + 7) == Some(&b'u')
            && hex4(i + 8).is_some_and(|l| (0xDC00..0xE000).contains(&l));
        if paired {
            i += 12;
        } else if (0xD800..0xE000).contains(&u) {
            out.push_str(&text[start..i]);
            out.push_str("\\ufffd");
            i += 6;
            start = i;
        } else {
            i += 6;
        }
    }
    out.push_str(&text[start..]);
    out
}

/// A row's event: its JSON, or the zstd-compressed JSON. None when neither can be read.
fn decode_event(json: Option<String>, zstd: Option<Vec<u8>>) -> Option<Map<String, Value>> {
    let text = match (json, zstd) {
        (Some(j), _) => j,
        (None, Some(z)) => String::from_utf8_lossy(&unzstd(&z)?).into_owned(),
        _ => return None,
    };
    let parsed =
        serde_json::from_str::<Value>(&text).or_else(|_| serde_json::from_str::<Value>(&mend_surrogates(&text)));
    match parsed.ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn sender_of(message: &Map<String, Value>) -> Option<String> {
    let meta = message.get("__openclaw");
    [
        message.get("senderLabel"),
        message.get("senderName"),
        meta.and_then(|m| m.get("senderLabel")),
        meta.and_then(|m| m.get("senderName")),
    ]
    .into_iter()
    .flatten()
    .find_map(|v| v.as_str().filter(|s| !s.is_empty()).map(str::to_string))
}

/// Transcript events as a person reads them: who said what, and where a reset fell.
pub fn turns_from_events(events: &[Map<String, Value>]) -> Vec<Value> {
    let mut turns: Vec<Value> = Vec::new();
    let is_reset = |t: &Value| t.get("kind").and_then(Value::as_str) == Some("reset");
    for ev in events {
        let at = ev
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(super::run_titles::date_parse);
        let at_json = at.map_or(Value::Null, super::common::js_number);
        if ev.get("type").and_then(Value::as_str) == Some("reset") {
            if turns.last().is_some_and(|t| !is_reset(t)) {
                turns.push(serde_json::json!({ "kind": "reset", "at": at_json }));
            }
            continue;
        }
        let Some(message) = ev
            .get("message")
            .and_then(Value::as_object)
            .filter(|_| ev.get("type").and_then(Value::as_str) == Some("message"))
        else {
            continue;
        };
        let role = message.get("role").and_then(Value::as_str).unwrap_or("");
        if role != "user" && role != "assistant" {
            continue;
        }
        let meta = message.get("__openclaw");
        if message.get("display") == Some(&Value::Bool(false))
            || meta.and_then(|m| m.get("hidden")) == Some(&Value::Bool(true))
        {
            continue;
        }
        // Prompts OpenClaw writes to itself are not the person.
        if message
            .get("provenance")
            .and_then(|p| p.get("kind"))
            .and_then(Value::as_str)
            .is_some_and(|k| k.starts_with("internal"))
        {
            continue;
        }
        let text = message_text(message);
        if text.is_empty() || SILENT.contains(&text.as_str()) {
            continue;
        }
        // ControlClaw's own notices mirrored into the transcript (codes, warnings) are not the conversation.
        if role == "assistant"
            && message.get("model").and_then(Value::as_str) == Some("delivery-mirror")
            && text.starts_with("ControlClaw:")
        {
            continue;
        }
        if role == "user" && COMMAND.is_match(&text) {
            continue;
        }
        let when = match message.get("timestamp") {
            Some(v) if v.is_number() => v.clone(),
            _ => at_json,
        };
        // `sender: undefined` and no channel are left out, as JSON.stringify leaves them.
        let mut turn = Map::new();
        turn.insert("kind".into(), serde_json::json!("message"));
        turn.insert("at".into(), when);
        turn.insert("role".into(), serde_json::json!(role));
        turn.insert("text".into(), serde_json::json!(text));
        if let Some(s) = sender_of(message) {
            turn.insert("sender".into(), serde_json::json!(s));
        }
        if let Some(c) = meta
            .and_then(|m| m.pointer("/transport/channel"))
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
        {
            turn.insert("channel".into(), serde_json::json!(c));
        }
        let turn = Value::Object(turn);
        turns.push(turn);
    }
    while turns.last().is_some_and(is_reset) {
        turns.pop();
    }
    turns
}

/// One conversation in full; None when it holds nothing a person said or was told. The ref must be
/// one `list_conversations` gave: its database is the agent's own, under OpenClaw's home.
/// One `transcript_events` row: its JSON, or its compressed JSON.
type EventRow = (Option<String>, Option<Vec<u8>>);

pub fn read_conversation(openclaw_home: &Path, r: &Value) -> Option<Value> {
    let text = |k: &str| r.get(k).and_then(Value::as_str);
    let (agent_id, session_id) = (text("agentId")?, text("sessionId")?);
    let file = agent_db(openclaw_home, agent_id);
    if !AGENT_ID.is_match(agent_id) || text("db") != Some(file.to_string_lossy().as_ref()) {
        return None;
    }
    let read = || -> rusqlite::Result<Option<(String, Vec<EventRow>)>> {
        let db = open_db(&file)?;
        // The key is the window's own, not the ref's: an internal session is not read through a
        // ref that names another key.
        let Ok(key) = db.query_row(
            "SELECT session_key FROM session_windows WHERE session_id = ?",
            [session_id],
            |row| row.get::<_, String>(0),
        ) else {
            return Ok(None);
        };
        let mut st =
            db.prepare("SELECT event_json, event_zstd FROM transcript_events WHERE session_id = ? ORDER BY seq")?;
        // Every row or none: a read cut short is not a whole conversation (the TS's `.all()` throws).
        let rows = st
            .query_map([session_id], |row| {
                Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some((key, rows)))
    };
    let (key, rows) = match read() {
        Ok(Some(found)) => found,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!("[export] conversation: {e}");
            return None;
        }
    };
    if INTERNAL_KEY.is_match(&key) {
        return None;
    }
    let events: Vec<Map<String, Value>> = rows.into_iter().filter_map(|(j, z)| decode_event(j, z)).collect();
    let turns = turns_from_events(&events);
    let first = turns
        .iter()
        .find(|t| t.get("kind").and_then(Value::as_str) == Some("message"))?;
    let (channel, chat_type, peer) = parse_session_key(&key);
    let mut seen: Vec<String> = Vec::new();
    for t in &turns {
        if let Some(c) = t.get("channel").and_then(Value::as_str)
            && !seen.iter().any(|s| s == c)
        {
            seen.push(c.into());
        }
    }
    let started = match first.get("at") {
        Some(v) if v.as_f64().is_some_and(f64::is_finite) => v.clone(),
        _ => r.get("createdAt").cloned().unwrap_or(Value::Null),
    };
    Some(serde_json::json!({
        "agentId": agent_id, "sessionId": session_id, "sessionKey": key,
        "channels": if seen.is_empty() { vec![channel] } else { seen },
        "chatType": chat_type, "peer": peer, "label": r.get("label").cloned().unwrap_or(Value::Null),
        "startedAt": started, "turns": turns,
    }))
}

/// W7's `transcripts` contract.
pub struct BoxRecords {
    pub openclaw_home: PathBuf,
}

impl crate::contracts::Transcripts for BoxRecords {
    fn list(&self) -> Vec<Value> {
        list_conversations(&self.openclaw_home)
    }
    fn read(&self, conversation_ref: &Value) -> Option<Value> {
        read_conversation(&self.openclaw_home, conversation_ref)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_keys_name_the_channel() {
        let p = |k: &str| parse_session_key(k);
        assert_eq!(
            p("agent:main:telegram:direct:123"),
            ("telegram".into(), Some("direct".into()), Some("123".into()))
        );
        assert_eq!(p("agent:main:main"), ("web chat".into(), None, None));
        assert_eq!(p("agent:main"), ("chat".into(), None, None));
        assert_eq!(p("agent:main:slack:C1"), ("slack".into(), None, Some("C1".into())));
        assert!(INTERNAL_KEY.is_match("agent:main:cron:x"));
        assert!(!INTERNAL_KEY.is_match("agent:main:main"));
    }

    #[test]
    fn a_message_text_from_either_form() {
        let m = |v: Value| v.as_object().cloned().expect("o");
        assert_eq!(message_text(&m(json!({ "content": " hi " }))), "hi");
        assert_eq!(
            message_text(&m(
                json!({ "content": [{ "type": "text", "text": "a" }, { "type": "image" }, { "type": "text", "text": "b" }] })
            )),
            "a\n\nb"
        );
        assert_eq!(
            message_text(&m(json!({ "openclawDisplayContent": "shown", "content": "raw" }))),
            "shown"
        );
    }

    /// An agent database with the tables the readers use.
    pub fn agent_fixture(home: &Path, agent: &str) -> Connection {
        let file = agent_db(home, agent);
        std::fs::create_dir_all(file.parent().expect("dir")).expect("mk");
        let db = Connection::open(&file).expect("db");
        db.execute_batch(
            "CREATE TABLE session_windows (session_id TEXT, session_key TEXT, updated_at INTEGER, created_at INTEGER);
             CREATE TABLE trajectory_runtime_events (session_id TEXT, run_id TEXT, seq INTEGER, event_json TEXT);
             CREATE TABLE transcript_events (session_id TEXT, seq INTEGER, event_json TEXT, event_utf8_bytes INTEGER, event_zstd BLOB);
             CREATE TABLE session_nodes (session_key TEXT, entry_json TEXT);",
        )
        .expect("schema");
        db
    }

    #[test]
    fn a_runs_trigger_from_its_session_start() {
        let d = tempfile::tempdir().expect("dir");
        let db = agent_fixture(d.path(), "main");
        db.execute("INSERT INTO session_windows VALUES ('s1', 'agent:main:main', 2, 1)", [])
            .expect("w");
        db.execute(
            "INSERT INTO trajectory_runtime_events VALUES ('s1', 'r1', 1, ?)",
            [json!({ "type": "session.started", "data": { "trigger": "heartbeat" } }).to_string()],
        )
        .expect("e");
        drop(db);
        let run = |id: &str, key: &str| RunRef {
            run_id: id.into(),
            session_key: Some(key.into()),
            agent_id: None,
        };
        let t = run_triggers(
            d.path(),
            &[run("r1", "agent:main:main"), run("r2", "agent:main:telegram:direct:1")],
        );
        assert_eq!(t.get("r1").map(String::as_str), Some("heartbeat"));
        assert!(!t.contains_key("r2"), "only a main session is looked up");
    }

    #[test]
    fn conversations_listed_and_read_as_a_person_reads_them() {
        let d = tempfile::tempdir().expect("dir");
        let db = agent_fixture(d.path(), "main");
        let ev = |e: Value| e.to_string();
        let ins = |sid: &str, seq: i64, json: Option<String>, zstd: Option<Vec<u8>>| {
            db.execute(
                "INSERT INTO transcript_events (session_id, seq, event_json, event_utf8_bytes, event_zstd) VALUES (?, ?, ?, NULL, ?)",
                rusqlite::params![sid, seq, json, zstd],
            )
            .expect("ins");
        };
        db.execute(
            "INSERT INTO session_windows VALUES ('s1', 'agent:main:telegram:direct:7', 2, 100)",
            [],
        )
        .expect("w");
        db.execute(
            "INSERT INTO session_windows VALUES ('s2', 'agent:main:cron:nightly', 3, 200)",
            [],
        )
        .expect("w");
        db.execute(
            "INSERT INTO session_nodes VALUES ('agent:main:telegram:direct:7', ?)",
            [json!({ "origin": { "label": "Ada" } }).to_string()],
        )
        .expect("n");
        let user = |text: &str, ts: i64| json!({ "type": "message", "message": { "role": "user", "content": text, "timestamp": ts, "__openclaw": { "senderName": "Ada", "transport": { "channel": "telegram" } } } });
        ins("s1", 1, Some(ev(user("Book a table", 1000))), None);
        let reply = json!({ "type": "message", "message": { "role": "assistant", "content": [{ "type": "text", "text": "Done." }], "timestamp": 2000 } });
        let packed = ruzstd::encoding::compress_to_vec(
            reply.to_string().as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        ins("s1", 2, None, Some(packed));
        ins(
            "s1",
            3,
            Some(ev(
                json!({ "type": "message", "message": { "role": "assistant", "content": "ControlClaw: your code is 1234", "model": "delivery-mirror" } }),
            )),
            None,
        );
        ins(
            "s1",
            4,
            Some(ev(json!({ "type": "reset", "timestamp": "1970-01-01T00:00:03Z" }))),
            None,
        );
        ins("s1", 5, Some(ev(user("/new", 4000))), None);
        ins(
            "s1",
            6,
            Some(ev(
                json!({ "type": "message", "message": { "role": "assistant", "content": "HEARTBEAT_OK" } }),
            )),
            None,
        );
        ins("s2", 1, Some(ev(user("job", 1))), None);
        drop(db);
        let list = list_conversations(d.path());
        assert_eq!(list.len(), 1, "the cron session is internal");
        let r = &list[0];
        assert_eq!(r["label"], json!("Ada"));
        assert_eq!(r["channels"], json!(["telegram"]));
        assert_eq!(r["createdAt"], json!(100));
        let c = read_conversation(d.path(), r).expect("conversation");
        assert_eq!(
            c["turns"],
            json!([
                { "kind": "message", "at": 1000, "role": "user", "text": "Book a table", "sender": "Ada", "channel": "telegram" },
                { "kind": "message", "at": 2000, "role": "assistant", "text": "Done." },
            ]),
            "the compressed reply is read; the notice, the trailing reset, the command and the silent reply are not"
        );
        assert_eq!(
            (c["chatType"].clone(), c["peer"].clone(), c["startedAt"].clone()),
            (json!("direct"), json!("7"), json!(1000))
        );
        let mut other = r.clone();
        other["db"] = json!("/etc/passwd");
        assert!(
            read_conversation(d.path(), &other).is_none(),
            "only the agent's own database"
        );
    }

    #[test]
    fn an_emoji_cut_in_half_does_not_lose_the_event() {
        let raw = r#"{"type":"message","message":{"role":"user","content":"hi \ud83d","x":"\\ud83d"}}"#;
        let e = decode_event(Some(raw.into()), None).expect("read");
        assert_eq!(e["message"]["content"], json!("hi \u{fffd}"));
        assert_eq!(
            e["message"]["x"],
            json!("\\ud83d"),
            "an escaped backslash is not an escape"
        );
        assert_eq!(
            mend_surrogates(r#""\ud83d\ude00""#),
            r#""\ud83d\ude00""#,
            "a whole pair is kept"
        );
    }

    #[test]
    fn frames_are_read_in_turn_and_a_huge_one_is_refused() {
        let enc = |t: &[u8]| ruzstd::encoding::compress_to_vec(t, ruzstd::encoding::CompressionLevel::Fastest);
        let mut two = enc(br#"{"a":"#);
        two.extend(enc(br#"1}"#));
        assert_eq!(decode_event(None, Some(two)).expect("both frames")["a"], json!(1));
        let mut skip = vec![0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 9, 9, 9];
        skip.extend(enc(br#"{"b":2}"#));
        assert_eq!(decode_event(None, Some(skip)).expect("skippable first")["b"], json!(2));
        let big = enc(&vec![b' '; MAX_EVENT_BYTES + 1]);
        assert!(unzstd(&big).is_none());
    }

    #[test]
    fn a_ref_cannot_name_another_key_for_an_internal_window() {
        let d = tempfile::tempdir().expect("dir");
        let db = agent_fixture(d.path(), "main");
        db.execute(
            "INSERT INTO session_windows VALUES ('c1', 'agent:main:cron:x', 1, 1)",
            [],
        )
        .expect("w");
        db.execute(
            "INSERT INTO transcript_events (session_id, seq, event_json) VALUES ('c1', 1, ?)",
            [json!({ "type": "message", "message": { "role": "user", "content": "secret job" } }).to_string()],
        )
        .expect("e");
        drop(db);
        let forged = json!({ "agentId": "main", "db": agent_db(d.path(), "main").to_string_lossy(), "sessionId": "c1", "sessionKey": "agent:main:telegram:direct:7" });
        assert!(read_conversation(d.path(), &forged).is_none());
    }

    /// `CC_PARITY_HOME=<dir> cargo test -p vm-agent parity_print -- --ignored --nocapture`: the list
    /// and every conversation of that home, to compare with the TS on the same fixture.
    #[test]
    #[ignore]
    fn parity_print() {
        let home = PathBuf::from(std::env::var("CC_PARITY_HOME").expect("CC_PARITY_HOME"));
        let list = list_conversations(&home);
        let read: Vec<Value> = list
            .iter()
            .map(|r| read_conversation(&home, r).unwrap_or(Value::Null))
            .collect();
        println!("PARITY {}", json!({ "list": list, "read": read }));
    }
}
