//! What each OpenClaw run was asked to do, for the console's timeline and Doing now
//! (`run-titles.ts`). The prompt is the `prompt.submitted` event in `trajectory_runtime_events`;
//! `clean_prompt` takes off what OpenClaw put around the person's words. Read a few rows per run,
//! never whole transcripts. Only the title (80 characters), and while the Home tab is open the
//! request (300) and the sender's name, leave the box.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::common::js_slice;
use super::transcripts::{
    AGENT_ID, ByAgent, INTERNAL_KEY, RunRef, agent_db, has_tables, message_text, open_db, session_ids,
};

pub const TITLE_MAX: usize = 80;
pub const REQUEST_MAX: usize = 300;
/// How much of a prompt is read out of the database: the title needs its first line.
const PROMPT_READ_MAX: usize = 4000;

const QUEUED_MARKER: &str = "[Queued user message from a previous active turn";
const CTX_MARKER: &str = "⟦openclaw:ctx⟧";

fn re(p: &str) -> Regex {
    Regex::new(p).expect("regex")
}

static LEADING_TIMESTAMP: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\[[A-Za-z]{3} [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}[^\]]*\] *"));
static DELIVERY_HINT: LazyLock<Regex> = LazyLock::new(|| re(r"^Delivery: .*`message` tool"));
static HEARTBEAT_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(Read HEARTBEAT\.md if it exists|Follow the heartbeat monitor scratch context)"));
// ASCII classes, as a JS regex without the `u` flag reads them.
static SYSTEM_PROMPT: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^\[System(?-u:\b)"));
static COMMAND: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^/[a-z][a-zA-Z0-9_-]*$"));
static SPACES: LazyLock<Regex> = LazyLock::new(|| re(r"\s+"));
static CUT_PROMPT: LazyLock<Regex> = LazyLock::new(|| re(r#""prompt"\s*:\s*"((?:[^"\\]|\\.)*\\?)"#));
static CUT_UNICODE: LazyLock<Regex> = LazyLock::new(|| re(r"\\u[0-9a-fA-F]{0,3}$"));

fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// JavaScript's `trim()`: whitespace and line ends, as `str::trim` takes them.
fn trim(s: &str) -> &str {
    s.trim()
}

/// Whether a run's prompt is OpenClaw's heartbeat poll.
pub fn is_heartbeat_prompt(raw: &str) -> bool {
    HEARTBEAT_PROMPT.is_match(&clean_prompt(raw))
}

/// The person's words out of a run's prompt (`cleanPrompt`).
pub fn clean_prompt(raw: &str) -> String {
    let text = raw.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = trim(lines[i]);
        if t == format!("Context: {CTX_MARKER}") {
            break;
        }
        if t.starts_with(QUEUED_MARKER) || DELIVERY_HINT.is_match(t) {
            i += 1;
            continue;
        }
        if t == "Context:"
            && lines.get(i + 1).map(|l| trim(l)) == Some("<active_memory_plugin>")
            && let Some(close) = (i + 1..lines.len()).find(|&j| trim(lines[j]) == "</active_memory_plugin>")
        {
            i = close + 1;
            continue;
        }
        if js_len(t) > js_len(CTX_MARKER) && t.ends_with(CTX_MARKER) {
            if lines.get(i + 1).map(|l| trim(l)) == Some("```json") {
                i = (i + 2..lines.len())
                    .find(|&j| trim(lines[j]) == "```")
                    .unwrap_or(lines.len());
            } else {
                while i + 1 < lines.len() && !trim(lines[i + 1]).is_empty() {
                    i += 1;
                }
            }
            i += 1;
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    let joined = out.join("\n");
    trim(&LEADING_TIMESTAMP.replace(trim(&joined), "")).to_string()
}

/// Cut to `max` UTF-16 units with an ellipsis, at a word when one is near the end.
fn cut(text: &str, max: usize) -> String {
    if js_len(text) <= max {
        return text.to_string();
    }
    let head = js_slice(text, max - 1);
    let space = head.rfind(' ').map(|b| js_len(&head[..b]));
    let kept = match space {
        Some(s) if (s as f64) > max as f64 * 0.6 => js_slice(&head, s),
        _ => head,
    };
    format!("{}…", kept.trim_end())
}

/// A run's title: the first line of what it was asked, cut to 80. None for OpenClaw talking to itself.
pub fn title_of(raw: &str) -> Option<String> {
    let text = clean_prompt(raw);
    if text.is_empty() || SYSTEM_PROMPT.is_match(&text) || HEARTBEAT_PROMPT.is_match(&text) {
        return None;
    }
    let first = text.split('\n').find(|l| !trim(l).is_empty())?;
    let first = trim(&SPACES.replace_all(first, " ")).to_string();
    // A bare command (`/new`, `/status`) is a button press, not a task.
    if COMMAND.is_match(&first) {
        return None;
    }
    Some(cut(&first, TITLE_MAX))
}

/// The request for Doing now: all of what it was asked, on one line, cut to 300.
pub fn request_of(raw: &str) -> Option<String> {
    let text = clean_prompt(raw);
    if text.is_empty() || SYSTEM_PROMPT.is_match(&text) {
        return None;
    }
    Some(cut(trim(&SPACES.replace_all(&text, " ")), REQUEST_MAX))
}

/// A JSON string body cut mid-escape (`…\`, `…\u00`) loses the unfinished escape, and only that.
pub fn drop_cut_escape(body: &str) -> String {
    let u = CUT_UNICODE.find(body).map(|m| m.start());
    let end = u.unwrap_or(body.len());
    let n = body[..end].bytes().rev().take_while(|b| *b == b'\\').count();
    match u {
        Some(_) if n % 2 == 0 => body[..end].to_string(),
        Some(_) => body.to_string(),
        None if n % 2 == 1 => body[..body.len() - 1].to_string(),
        None => body.to_string(),
    }
}

/// The prompt out of a `prompt.submitted` row, also from one OpenClaw cut at its size limit.
pub fn prompt_of_event(event_json: &str) -> Option<String> {
    match serde_json::from_str::<Value>(event_json) {
        Ok(ev) => {
            if ev.get("type").and_then(Value::as_str) != Some("prompt.submitted") {
                return None;
            }
            ev.pointer("/data/prompt")
                .and_then(Value::as_str)
                .map(|p| js_slice(p, PROMPT_READ_MAX))
        }
        Err(_) => {
            // Cut mid-way: the start of the prompt is still there, and the start is what is needed.
            let m = CUT_PROMPT.captures(event_json)?;
            let body = drop_cut_escape(m.get(1)?.as_str());
            let s: String = serde_json::from_str(&format!("\"{body}\"")).ok()?;
            Some(js_slice(&s, PROMPT_READ_MAX))
        }
    }
}

/// The runs grouped by agent and session key, each agent id checked before it names a path.
fn by_agent(runs: &[RunRef]) -> ByAgent {
    let mut out: ByAgent = Vec::new();
    for r in runs {
        let Some(key) = r.session_key.as_deref().filter(|k| !INTERNAL_KEY.is_match(k)) else {
            continue;
        };
        let from_key = if key.starts_with("agent:") {
            key.split(':').nth(1).unwrap_or("")
        } else {
            "main"
        };
        let agent = r
            .agent_id
            .clone()
            .filter(|a| !a.is_empty())
            .or_else(|| Some(from_key.to_string()).filter(|a| !a.is_empty()))
            .unwrap_or_else(|| "main".into());
        if !AGENT_ID.is_match(&agent) {
            continue;
        }
        let i = out.iter().position(|(a, _)| *a == agent).unwrap_or_else(|| {
            out.push((agent.clone(), Vec::new()));
            out.len() - 1
        });
        match out[i].1.iter_mut().find(|(k, _)| k == key) {
            Some((_, ids)) => ids.push(r.run_id.clone()),
            None => out[i].1.push((key.to_string(), vec![r.run_id.clone()])),
        }
    }
    out
}

/// Each run's prompt, raw, by run id. Internal sessions are not looked up.
pub fn run_prompts(openclaw_home: &Path, runs: &[RunRef]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (agent, keys) in by_agent(runs) {
        let file = agent_db(openclaw_home, &agent);
        if !file.exists() {
            continue;
        }
        let mut read = || -> rusqlite::Result<()> {
            let db = open_db(&file)?;
            if !has_tables(&db, &["session_windows", "trajectory_runtime_events"]) {
                return Ok(());
            }
            // Only the start of the row: a prompt can be long, and only its start is used.
            let mut submitted = db.prepare(&format!(
                "SELECT substr(event_json, 1, {}) AS ev FROM trajectory_runtime_events
                  WHERE session_id = ? AND run_id = ? AND event_json LIKE '%\"prompt.submitted\"%' ORDER BY seq LIMIT 1",
                PROMPT_READ_MAX * 2
            ))?;
            for (key, run_ids) in &keys {
                let ids = session_ids(&db, key);
                for run_id in run_ids {
                    for sid in &ids {
                        // The row found ends the search, whatever is in it (the TS's `break`).
                        match submitted.query_row([sid, run_id], |r| r.get::<_, Option<String>>(0)) {
                            Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                            Ok(Some(ev)) => {
                                if let Some(p) = prompt_of_event(&ev) {
                                    out.insert(run_id.clone(), p);
                                }
                            }
                            _ => {}
                        }
                        break;
                    }
                }
            }
            Ok(())
        };
        if let Err(e) = read() {
            tracing::error!("[audit] run prompts: {e}");
        }
    }
    out
}

/// Each run's title, and the runs whose prompt is OpenClaw's heartbeat poll.
pub fn run_titles(openclaw_home: &Path, runs: &[RunRef]) -> (HashMap<String, String>, HashSet<String>) {
    let (mut titles, mut heartbeats) = (HashMap::new(), HashSet::new());
    for (run_id, prompt) in run_prompts(openclaw_home, runs) {
        if is_heartbeat_prompt(&prompt) {
            heartbeats.insert(run_id.clone());
        }
        if let Some(t) = title_of(&prompt) {
            titles.insert(run_id, t);
        }
    }
    (titles, heartbeats)
}

/// Who asked a run and on which channel, and what their message said.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunAsker {
    pub sender: Option<String>,
    pub channel: Option<String>,
    pub text: Option<String>,
    pub at: Option<f64>,
}

static ISO: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(?:T([0-9]{2}:[0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?)?(Z|[+-][0-9]{2}:?[0-9]{2})?$",
    )
});

/// `Date.parse` for the ISO forms a transcript holds: any number of fraction digits (cut to ms), an
/// offset or `Z`, or none (UTC, the box's zone).
pub fn date_parse(s: &str) -> Option<f64> {
    let c = ISO.captures(s.trim())?;
    let frac = c.get(4).map_or("000".to_string(), |f| {
        format!("{:0<3}", &f.as_str()[..f.as_str().len().min(3)])
    });
    let canonical = format!(
        "{}T{}:{}.{frac}Z",
        &c[1],
        c.get(2).map_or("00:00", |m| m.as_str()),
        c.get(3).map_or("00", |m| m.as_str())
    );
    let at = super::time::parse_iso_z(&canonical)? as f64;
    let offset = match c.get(5).map(|m| m.as_str()) {
        None | Some("Z") => 0.0,
        Some(o) => {
            let sign = if o.starts_with('-') { -1.0 } else { 1.0 };
            let digits: String = o[1..].chars().filter(char::is_ascii_digit).collect();
            let (h, m): (f64, f64) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
            sign * (h * 3_600_000.0 + m * 60_000.0)
        }
    };
    Some(at - offset)
}

fn at_of(v: &rusqlite::types::Value) -> f64 {
    match v {
        rusqlite::types::Value::Integer(i) => *i as f64,
        rusqlite::types::Value::Real(f) => *f,
        rusqlite::types::Value::Text(s) => date_parse(s).unwrap_or(f64::NAN),
        _ => f64::NAN,
    }
}

/// The newest user message of the run's session written no later than 10 s after it started.
pub fn run_asker(openclaw_home: &Path, run: &RunRef, started_at: i64) -> RunAsker {
    let none = RunAsker::default();
    let Some((agent, keys)) = by_agent(std::slice::from_ref(run)).into_iter().next() else {
        return none;
    };
    let file = agent_db(openclaw_home, &agent);
    if !file.exists() {
        return none;
    }
    let read = || -> rusqlite::Result<RunAsker> {
        let db = open_db(&file)?;
        if !has_tables(&db, &["session_windows", "transcript_events"]) {
            return Ok(RunAsker::default());
        }
        let key = &keys[0].0;
        let ids = session_ids(&db, key);
        // The window the run is in, not the newest: after `/new` a run can still be going in the old one.
        let runs_table = has_tables(&db, &["trajectory_runtime_events"]);
        let has_run = |sid: &str| {
            runs_table
                && db
                    .prepare_cached(
                        "SELECT 1 FROM trajectory_runtime_events WHERE session_id = ? AND run_id = ? LIMIT 1",
                    )
                    .and_then(|mut st| st.query_row([sid, run.run_id.as_str()], |_| Ok(())))
                    .is_ok()
        };
        let Some(sid) = ids.iter().find(|s| has_run(s)).or(ids.first()) else {
            return Ok(RunAsker::default());
        };
        let mut st = db.prepare(
            "SELECT json_extract(event_json, '$.message.__openclaw.senderName') AS sender,
                    json_extract(event_json, '$.message.__openclaw.senderLabel') AS label,
                    json_extract(event_json, '$.message.__openclaw.transport.channel') AS channel,
                    json_extract(event_json, '$.message.timestamp') AS at,
                    substr(json_extract(event_json, '$.message'), 1, 20000) AS message
               FROM transcript_events
              WHERE session_id = ? AND event_json IS NOT NULL
                AND CASE WHEN json_valid(event_json) THEN json_extract(event_json, '$.message.role') = 'user' END
              ORDER BY seq DESC LIMIT 10",
        )?;
        type Row = (
            rusqlite::types::Value,
            rusqlite::types::Value,
            rusqlite::types::Value,
            rusqlite::types::Value,
            rusqlite::types::Value,
        );
        let rows: Vec<Row> = st
            .query_map([sid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .filter_map(Result::ok)
            .collect();
        // A message with no readable time cannot be placed against the run, so it is not taken.
        let Some(row) = rows.into_iter().find(|r| at_of(&r.3) <= (started_at + 10_000) as f64) else {
            return Ok(RunAsker::default());
        };
        let s = |v: &rusqlite::types::Value, max: usize| match v {
            rusqlite::types::Value::Text(t) if !t.trim().is_empty() => Some(js_slice(t.trim(), max)),
            _ => None,
        };
        let text = match &row.4 {
            // Cut at the read limit: the request comes from the prompt instead.
            rusqlite::types::Value::Text(m) => serde_json::from_str::<Value>(m)
                .ok()
                .and_then(|v| v.as_object().map(message_text))
                .and_then(|t| request_of(&t)),
            _ => None,
        };
        Ok(RunAsker {
            sender: s(&row.0, 80).or_else(|| s(&row.1, 80)),
            channel: s(&row.2, 32),
            text,
            at: Some(at_of(&row.3)).filter(|a| !a.is_nan()),
        })
    };
    read().unwrap_or_else(|e| {
        tracing::error!("[activity] run asker: {e}");
        none
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_persons_words_out_of_the_prompt() {
        let raw = "Conversation info ⟦openclaw:ctx⟧\n```json\n{\"a\":1}\n```\n[Thu 2026-10-23 10:02 GMT+2] Book a table for two\nDelivery: to send a message, use the `message` tool\nContext: ⟦openclaw:ctx⟧\ntrailing";
        assert_eq!(clean_prompt(raw), "Book a table for two");
        assert_eq!(title_of(raw).as_deref(), Some("Book a table for two"));
        assert_eq!(title_of("/new"), None);
        assert_eq!(title_of("[System] Your previous turn was interrupted"), None);
        assert!(is_heartbeat_prompt("Read HEARTBEAT.md if it exists and follow it"));
    }

    #[test]
    fn times_as_date_parse_reads_them() {
        assert_eq!(date_parse("1970-01-01T00:00:01Z"), Some(1000.0));
        assert_eq!(date_parse("1970-01-01T00:00:01.123456Z"), Some(1123.0));
        assert_eq!(date_parse("1970-01-01T02:00:00+02:00"), Some(0.0));
        assert_eq!(date_parse("1970-01-01"), Some(0.0));
        assert_eq!(date_parse("yesterday"), None);
        assert_eq!(
            title_of("/café").as_deref(),
            Some("/café"),
            "not a bare command for an ASCII regex"
        );
    }

    #[test]
    fn cut_at_a_word_with_an_ellipsis() {
        let long = "word ".repeat(30);
        let t = title_of(&long).expect("title");
        assert!(t.ends_with('…'));
        assert!(js_len(&t) <= TITLE_MAX);
        assert!(!t.contains("  "));
    }

    #[test]
    fn a_cut_row_still_gives_its_prompt() {
        assert_eq!(
            prompt_of_event(&json!({ "type": "prompt.submitted", "data": { "prompt": "hi" } }).to_string()).as_deref(),
            Some("hi")
        );
        assert_eq!(
            prompt_of_event(r#"{"type":"prompt.submitted","data":{"prompt":"hello é wor"#).as_deref(),
            Some("hello é wor")
        );
        assert_eq!(drop_cut_escape(r"abc\"), "abc");
        assert_eq!(drop_cut_escape(r"abc\\"), r"abc\\");
        assert_eq!(drop_cut_escape(r"abc\u00"), "abc");
        assert_eq!(drop_cut_escape(r"abc\\u00"), r"abc\\u00");
    }

    #[test]
    fn titles_and_askers_from_the_database() {
        let d = tempfile::tempdir().expect("dir");
        let db = super::super::transcripts::tests::agent_fixture(d.path(), "main");
        db.execute(
            "INSERT INTO session_windows VALUES ('s1', 'agent:main:telegram:direct:1', 2, 1)",
            [],
        )
        .expect("w");
        db.execute(
            "INSERT INTO trajectory_runtime_events VALUES ('s1', 'r1', 1, ?)",
            [json!({ "type": "prompt.submitted", "data": { "prompt": "Find me a flight" } }).to_string()],
        )
        .expect("e");
        db.execute(
            "INSERT INTO transcript_events (session_id, seq, event_json, event_utf8_bytes) VALUES ('s1', 1, ?, 0)",
            [json!({ "message": { "role": "user", "timestamp": 1000, "content": "Find me a flight", "__openclaw": { "senderName": "Ada", "transport": { "channel": "telegram" } } } }).to_string()],
        )
        .expect("m");
        drop(db);
        let run = RunRef {
            run_id: "r1".into(),
            session_key: Some("agent:main:telegram:direct:1".into()),
            agent_id: Some("main".into()),
        };
        let (titles, beats) = run_titles(d.path(), std::slice::from_ref(&run));
        assert_eq!(titles.get("r1").map(String::as_str), Some("Find me a flight"));
        assert!(beats.is_empty());
        let a = run_asker(d.path(), &run, 2000);
        assert_eq!(a.sender.as_deref(), Some("Ada"));
        assert_eq!(a.channel.as_deref(), Some("telegram"));
        assert_eq!(a.text.as_deref(), Some("Find me a flight"));
        assert_eq!(a.at, Some(1000.0));
        assert_eq!(
            run_asker(d.path(), &run, -20_000),
            RunAsker::default(),
            "a message after the run did not start it"
        );
    }
}
