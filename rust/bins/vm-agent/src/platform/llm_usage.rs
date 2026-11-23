//! Token usage for the console's AI usage page (apps/saas/docs/features/ai-usage.md). OpenClaw
//! writes each model call's usage on the assistant message it produced (`transcript_events`:
//! `message.provider`, `api`, `model`, `usage.{input,output,cacheRead,cacheWrite,cost}`). This adds
//! the messages written since the last pass to hourly buckets keyed by model and by the kind of
//! session (chat, scheduled, email, meeting, call, other), and sends the buckets that changed as
//! `llm_usage` records. A record is the bucket's total, so the console replaces its row: a batch
//! sent twice, or again after a restart, counts once. When OpenClaw names the run a message
//! belongs to, the run gets a total of its own (`llm_run_usage`), for "most expensive runs".
//!
//! Counts only: no text, no session key, no peer. State (a cursor per session, the last 48 hours
//! of buckets) is in `state/llm-usage.json`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{Flag, js_slice, lock};
use super::metrics::Post;
use super::time::now_ms;
use super::transcripts;

const HOUR_MS: i64 = 60 * 60 * 1000;
/// Buckets and runs older than this are neither read nor kept.
pub const LOOKBACK_MS: i64 = 48 * HOUR_MS;
const MAX_BATCH: usize = 200;
/// After a refused batch: the console needs a deploy, not a retry every pass.
const REFUSED_RETRY_MS: i64 = 30 * 60 * 1000;

static SCHEDULED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i):cron(:|$)").expect("regex"));
static HEARTBEAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i):heartbeat(:|$)").expect("regex"));
static MEETING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|:)meeting-[^:]+").expect("regex"));
static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i):voice:call(:|$)").expect("regex"));
static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|:)(agentmail|gmail|email)(:|$)").expect("regex"));

/// The kind of session a key names, as the console's run kinds read it (`sessions.ts`).
pub fn activity_of(session_key: &str) -> &'static str {
    if HEARTBEAT.is_match(session_key) {
        "heartbeat"
    } else if SCHEDULED.is_match(session_key) {
        "scheduled"
    } else if MEETING.is_match(session_key) {
        "meeting"
    } else if CALL.is_match(session_key) {
        "call"
    } else if EMAIL.is_match(session_key) {
        "email"
    } else if transcripts::INTERNAL_KEY.is_match(session_key) {
        "other"
    } else {
        "chat"
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Counts {
    pub calls: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    /// What OpenClaw priced the calls at, when it did.
    pub cost: Option<f64>,
}

impl Counts {
    fn add(&mut self, u: &Usage) {
        self.calls += 1;
        self.input += u.input;
        self.output += u.output;
        self.cache_read += u.cache_read;
        self.cache_write += u.cache_write;
        if let Some(c) = u.cost {
            self.cost = Some(self.cost.unwrap_or(0.0) + c);
        }
    }
}

/// One assistant message's usage, as OpenClaw normalized it.
#[derive(Debug, Clone, PartialEq)]
pub struct Usage {
    pub at: i64,
    pub provider: String,
    pub api: String,
    pub model: String,
    pub run_id: Option<String>,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub cost: Option<f64>,
}

fn n(v: Option<&Value>) -> u64 {
    v.and_then(Value::as_f64)
        .filter(|x| x.is_finite() && *x > 0.0)
        .map_or(0, |x| x as u64)
}

/// The usage on one transcript event, or None for anything that is not a priced model call.
pub fn usage_of(ev: &Map<String, Value>) -> Option<Usage> {
    if ev.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    let m = ev.get("message")?.as_object()?;
    if m.get("role").and_then(Value::as_str) != Some("assistant") {
        return None;
    }
    let u = m.get("usage")?.as_object()?;
    let (input, output) = (n(u.get("input")), n(u.get("output")));
    let (cache_read, cache_write) = (n(u.get("cacheRead")), n(u.get("cacheWrite")));
    // An initialized zero is not a measurement (an interrupted stream): nothing to count.
    if input + output + cache_read + cache_write == 0 {
        return None;
    }
    let at = ev
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(super::time::date_parse)
        .or_else(|| m.get("timestamp").and_then(Value::as_f64).map(|t| t as i64))?;
    let text = |k: &str, cap: usize| {
        m.get(k)
            .and_then(Value::as_str)
            .map(|s| js_slice(s, cap))
            .unwrap_or_default()
    };
    let cost = match u.get("cost") {
        Some(Value::Object(c)) => c.get("total").and_then(Value::as_f64),
        Some(v) => v.as_f64(),
        None => None,
    }
    .filter(|c| c.is_finite() && *c >= 0.0);
    let run_id = m
        .get("__openclaw")
        .and_then(|o| o.get("runId"))
        .or_else(|| ev.get("runId"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| js_slice(s, 128));
    let model = text("model", 160);
    Some(Usage {
        at,
        provider: Some(text("provider", 64))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into()),
        api: text("api", 64),
        model: if model.is_empty() { "unknown".into() } else { model },
        run_id,
        input,
        output,
        cache_read,
        cache_write,
        cost,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BucketKey {
    hour: i64,
    provider: String,
    api: String,
    model: String,
    activity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RunKey {
    run_id: String,
    provider: String,
    model: String,
}

#[derive(Debug, Clone, Default)]
struct Entry {
    counts: Counts,
    /// The newest call counted, for pruning a run.
    last_at: i64,
    dirty: bool,
}

#[derive(Debug, Default)]
pub struct State {
    /// `<agent>/<session_id>` → the last seq read.
    cursors: HashMap<String, i64>,
    buckets: BTreeMap<BucketKey, Entry>,
    runs: BTreeMap<RunKey, (Entry, String)>,
}

impl State {
    /// Counts one call. Too old to keep: left out.
    pub fn add(&mut self, u: &Usage, activity: &str, now: i64) {
        if now - u.at > LOOKBACK_MS {
            return;
        }
        let hour = u.at.min(now).div_euclid(HOUR_MS) * HOUR_MS;
        let k = BucketKey {
            hour,
            provider: u.provider.clone(),
            api: u.api.clone(),
            model: u.model.clone(),
            activity: activity.into(),
        };
        let e = self.buckets.entry(k).or_default();
        e.counts.add(u);
        e.last_at = e.last_at.max(u.at);
        e.dirty = true;
        if let Some(run) = &u.run_id {
            let k = RunKey {
                run_id: run.clone(),
                provider: u.provider.clone(),
                model: u.model.clone(),
            };
            let (e, act) = self
                .runs
                .entry(k)
                .or_insert_with(|| (Entry::default(), activity.into()));
            e.counts.add(u);
            e.last_at = e.last_at.max(u.at);
            e.dirty = true;
            *act = activity.into();
        }
    }

    fn prune(&mut self, now: i64, live: &HashSet<String>) {
        self.buckets.retain(|k, e| now - k.hour <= LOOKBACK_MS || e.dirty);
        self.runs.retain(|_, (e, _)| now - e.last_at <= LOOKBACK_MS || e.dirty);
        self.cursors.retain(|k, _| live.contains(k));
    }

    /// The records to send: every bucket and run that changed, up to `MAX_BATCH`.
    pub fn pending(&self) -> Vec<Value> {
        let buckets = self.buckets.iter().filter(|(_, e)| e.dirty).map(|(k, e)| {
            let c = &e.counts;
            json!({ "source": "llm_usage", "hour": k.hour, "provider": k.provider, "api": k.api, "model": k.model, "activity": k.activity,
                "calls": c.calls, "input": c.input, "output": c.output, "cache_read": c.cache_read, "cache_write": c.cache_write, "cost_usd": c.cost })
        });
        let runs = self.runs.iter().filter(|(_, (e, _))| e.dirty).map(|(k, (e, act))| {
            let c = &e.counts;
            json!({ "source": "llm_run_usage", "run_id": k.run_id, "provider": k.provider, "model": k.model, "activity": act, "at": e.last_at,
                "calls": c.calls, "input": c.input, "output": c.output, "cache_read": c.cache_read, "cache_write": c.cache_write })
        });
        buckets.chain(runs).take(MAX_BATCH).collect()
    }

    /// The records in `sent` reached the console: clean, unless counted again since.
    fn mark_sent(&mut self, sent: &[Value]) {
        for r in sent {
            let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let calls = r.get("calls").and_then(Value::as_u64).unwrap_or(0);
            if r.get("source").and_then(Value::as_str) == Some("llm_usage") {
                let k = BucketKey {
                    hour: r.get("hour").and_then(Value::as_i64).unwrap_or(0),
                    provider: s("provider"),
                    api: s("api"),
                    model: s("model"),
                    activity: s("activity"),
                };
                if let Some(e) = self.buckets.get_mut(&k).filter(|e| e.counts.calls == calls) {
                    e.dirty = false;
                }
            } else {
                let k = RunKey {
                    run_id: s("run_id"),
                    provider: s("provider"),
                    model: s("model"),
                };
                if let Some((e, _)) = self.runs.get_mut(&k).filter(|(e, _)| e.counts.calls == calls) {
                    e.dirty = false;
                }
            }
        }
    }

    fn load(path: &Path) -> Self {
        let Some(v) = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            return Self::default();
        };
        let mut st = Self::default();
        if let Some(Value::Object(c)) = v.get("cursors") {
            st.cursors = c.iter().filter_map(|(k, v)| Some((k.clone(), v.as_i64()?))).collect();
        }
        let counts = |b: &Value| Counts {
            calls: n(b.get("calls")),
            input: n(b.get("input")),
            output: n(b.get("output")),
            cache_read: n(b.get("cache_read")),
            cache_write: n(b.get("cache_write")),
            cost: b.get("cost").and_then(Value::as_f64),
        };
        let s = |b: &Value, k: &str| b.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        for b in v.get("buckets").and_then(Value::as_array).into_iter().flatten() {
            let k = BucketKey {
                hour: b.get("hour").and_then(Value::as_i64).unwrap_or(0),
                provider: s(b, "provider"),
                api: s(b, "api"),
                model: s(b, "model"),
                activity: s(b, "activity"),
            };
            let e = Entry {
                counts: counts(b),
                last_at: b.get("last_at").and_then(Value::as_i64).unwrap_or(k.hour),
                dirty: b.get("dirty").and_then(Value::as_bool).unwrap_or(true),
            };
            st.buckets.insert(k, e);
        }
        for b in v.get("runs").and_then(Value::as_array).into_iter().flatten() {
            let k = RunKey {
                run_id: s(b, "run_id"),
                provider: s(b, "provider"),
                model: s(b, "model"),
            };
            let e = Entry {
                counts: counts(b),
                last_at: b.get("last_at").and_then(Value::as_i64).unwrap_or(0),
                dirty: b.get("dirty").and_then(Value::as_bool).unwrap_or(true),
            };
            st.runs.insert(k, (e, s(b, "activity")));
        }
        st
    }

    fn save(&self, path: &Path) {
        let c = |e: &Entry| json!({ "calls": e.counts.calls, "input": e.counts.input, "output": e.counts.output, "cache_read": e.counts.cache_read, "cache_write": e.counts.cache_write, "cost": e.counts.cost, "last_at": e.last_at, "dirty": e.dirty });
        let buckets: Vec<Value> = self
            .buckets
            .iter()
            .map(|(k, e)| {
                let mut v = c(e);
                for (f, x) in [
                    ("provider", &k.provider),
                    ("api", &k.api),
                    ("model", &k.model),
                    ("activity", &k.activity),
                ] {
                    v[f] = json!(x);
                }
                v["hour"] = json!(k.hour);
                v
            })
            .collect();
        let runs: Vec<Value> = self
            .runs
            .iter()
            .map(|(k, (e, act))| {
                let mut v = c(e);
                v["run_id"] = json!(k.run_id);
                v["provider"] = json!(k.provider);
                v["model"] = json!(k.model);
                v["activity"] = json!(act);
                v
            })
            .collect();
        let body = json!({ "cursors": self.cursors, "buckets": buckets, "runs": runs });
        if let Err(e) = cc_store::write_atomic(path, body.to_string().as_bytes(), 0o600, cc_store::TmpName::Suffix) {
            tracing::warn!("[llm-usage] state not saved: {e}");
        }
    }
}

/// Reads what OpenClaw wrote since the cursors, into `state`. Off the runtime's threads.
pub fn scan(openclaw_home: &Path, state: &mut State, now: i64) {
    let mut live = HashSet::new();
    for (agent_id, file) in transcripts::agent_databases(openclaw_home) {
        let read = |state: &mut State, live: &mut HashSet<String>| -> rusqlite::Result<()> {
            let db = transcripts::open_db(&file)?;
            if !transcripts::has_tables(&db, &["session_windows", "transcript_events"]) {
                return Ok(());
            }
            let mut windows = db.prepare(
                "SELECT w.session_id, w.session_key, (SELECT MAX(e.seq) FROM transcript_events e WHERE e.session_id = w.session_id) FROM session_windows w",
            )?;
            let sessions: Vec<(String, String, Option<i64>)> = windows
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        r.get::<_, Option<i64>>(2)?,
                    ))
                })?
                .filter_map(Result::ok)
                .collect();
            let mut events = db.prepare("SELECT seq, event_json, event_zstd FROM transcript_events WHERE session_id = ? AND seq > ? ORDER BY seq")?;
            // Heartbeats run in the main session, which DMs share too: the run's trigger tells them apart.
            let mut started = if transcripts::has_tables(&db, &["trajectory_runtime_events"]) {
                Some(db.prepare(&transcripts::runtime_event_sql(&db, "session.started", None))?)
            } else {
                None
            };
            let mut heartbeat = HashMap::<String, bool>::new();
            for (session_id, key, max_seq) in sessions {
                let ck = format!("{agent_id}/{session_id}");
                live.insert(ck.clone());
                let from = state.cursors.get(&ck).copied().unwrap_or(-1);
                if max_seq.is_none_or(|m| m <= from) {
                    continue;
                };
                let activity = activity_of(&key);
                let rows = events.query_map(rusqlite::params![session_id, from], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                })?;
                let mut last = from;
                for (seq, j, z) in rows.filter_map(Result::ok) {
                    last = last.max(seq);
                    if let Some(u) = transcripts::decode_event(j, z).as_ref().and_then(usage_of) {
                        let beat = match (&u.run_id, started.as_mut()) {
                            (Some(run), Some(st)) if transcripts::is_main_key(&key) => {
                                *heartbeat.entry(run.clone()).or_insert_with(|| {
                                    transcripts::run_trigger(st, &session_id, run).as_deref() == Some("heartbeat")
                                })
                            }
                            _ => false,
                        };
                        state.add(&u, if beat { "heartbeat" } else { activity }, now);
                    }
                }
                state.cursors.insert(ck, last);
            }
            Ok(())
        };
        if let Err(e) = read(state, &mut live) {
            tracing::warn!("[llm-usage] {agent_id}: {e}");
            // A database that could not be read keeps its cursors for the next pass.
            live.extend(
                state
                    .cursors
                    .keys()
                    .filter(|k| k.starts_with(&format!("{agent_id}/")))
                    .cloned(),
            );
        }
    }
    state.prune(now, &live);
}

pub struct UsageShipper {
    openclaw_home: PathBuf,
    state_path: PathBuf,
    post: Post,
    next_attempt_at: Mutex<i64>,
    in_flight: AtomicBool,
}

impl UsageShipper {
    pub fn new(openclaw_home: PathBuf, state_path: PathBuf, post: Post) -> Self {
        Self {
            openclaw_home,
            state_path,
            post,
            next_attempt_at: Mutex::new(0),
            in_flight: AtomicBool::new(false),
        }
    }

    /// One pass: read, save, send what changed. How many records the console took.
    pub async fn tick(&self) -> usize {
        let now = now_ms();
        let Some(_flying) = Flag::take(&self.in_flight) else {
            return 0;
        };
        let (home, path) = (self.openclaw_home.clone(), self.state_path.clone());
        let Ok(mut state) = tokio::task::spawn_blocking(move || {
            let mut st = State::load(&path);
            scan(&home, &mut st, now);
            st.save(&path);
            st
        })
        .await
        else {
            return 0;
        };
        if now < *lock(&self.next_attempt_at) {
            return 0;
        }
        let mut sent = 0;
        loop {
            let records = state.pending();
            if records.is_empty() {
                break;
            }
            match (self.post)(json!({ "records": records })).await {
                Ok(s @ (400 | 413)) => {
                    // A console from before the usage sink: kept, and tried much later.
                    tracing::info!(
                        "[llm-usage] batch of {} refused with HTTP {s}; trying again later",
                        records.len()
                    );
                    *lock(&self.next_attempt_at) = now + REFUSED_RETRY_MS;
                    break;
                }
                Ok(s) if (200..300).contains(&s) => {
                    state.mark_sent(&records);
                    sent += records.len();
                    if records.len() < MAX_BATCH {
                        break;
                    }
                }
                Ok(s) => {
                    tracing::info!("[llm-usage] ship failed: HTTP {s}");
                    break;
                }
                Err(e) => {
                    tracing::info!("[llm-usage] ship failed: {e}");
                    break;
                }
            }
        }
        if sent > 0 {
            let path = self.state_path.clone();
            let _ = tokio::task::spawn_blocking(move || state.save(&path)).await;
        }
        sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(v: Value) -> Map<String, Value> {
        v.as_object().cloned().expect("object")
    }

    #[test]
    fn session_keys_become_kinds() {
        assert_eq!(activity_of("agent:main:telegram:direct:123"), "chat");
        assert_eq!(activity_of("agent:main:main"), "chat");
        assert_eq!(activity_of("agent:main:cron:abc:run:1"), "scheduled");
        assert_eq!(activity_of("agent:main:heartbeat"), "heartbeat");
        assert_eq!(activity_of("agent:main:cron:daily"), "scheduled");
        assert_eq!(activity_of("agent:main:meeting-x1-task-2"), "meeting");
        assert_eq!(activity_of("agent:main:voice:call:CA1"), "call");
        assert_eq!(activity_of("agent:main:agentmail:inbox:thread"), "email");
        assert_eq!(activity_of("agent:main:subagent:7"), "other");
    }

    #[test]
    fn an_assistant_message_gives_its_usage_and_nothing_else_does() {
        let m = ev(
            json!({ "type": "message", "timestamp": "2026-11-13T10:15:00.000Z", "message": {
            "role": "assistant", "provider": "controlclaw", "api": "openai-completions", "model": "moonshotai/kimi-k2.6",
            "usage": { "input": 1200, "output": 80, "cacheRead": 15000, "cacheWrite": 0, "totalTokens": 16280, "cost": { "total": 0.0042 } },
            "__openclaw": { "runId": "run-1" }, "content": [{ "type": "text", "text": "never read" }] } }),
        );
        let u = usage_of(&m).expect("usage");
        assert_eq!((u.input, u.output, u.cache_read, u.cache_write), (1200, 80, 15000, 0));
        assert_eq!(u.provider, "controlclaw");
        assert_eq!(u.model, "moonshotai/kimi-k2.6");
        assert_eq!(u.run_id.as_deref(), Some("run-1"));
        assert_eq!(u.cost, Some(0.0042));
        assert_eq!(u.at, 1_794_564_900_000);
        let user = ev(
            json!({ "type": "message", "timestamp": "2026-11-13T10:15:00.000Z", "message": { "role": "user", "usage": { "input": 5 } } }),
        );
        assert!(usage_of(&user).is_none());
        let zero = ev(
            json!({ "type": "message", "timestamp": "2026-11-13T10:15:00.000Z", "message": { "role": "assistant", "usage": { "input": 0, "output": 0 } } }),
        );
        assert!(usage_of(&zero).is_none(), "an interrupted stream is not a measurement");
    }

    #[test]
    fn calls_add_up_per_hour_and_a_sent_bucket_is_sent_again_only_when_it_grows() {
        let now = 1_763_030_000_000;
        let call = |at: i64, input: u64| Usage {
            at,
            provider: "openai".into(),
            api: "openai-codex-responses".into(),
            model: "gpt-5.5".into(),
            run_id: None,
            input,
            output: 10,
            cache_read: 0,
            cache_write: 0,
            cost: None,
        };
        let mut st = State::default();
        st.add(&call(now - 1000, 100), "chat", now);
        st.add(&call(now - 2000, 50), "chat", now);
        st.add(&call(now - LOOKBACK_MS - 1, 50), "chat", now);
        let p = st.pending();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0]["calls"], 2);
        assert_eq!(p[0]["input"], 150);
        assert_eq!(p[0]["activity"], "chat");
        st.mark_sent(&p);
        assert!(st.pending().is_empty());
        st.add(&call(now - 500, 1), "chat", now);
        assert_eq!(st.pending()[0]["calls"], 3, "the hour's total, not the difference");
    }

    #[test]
    fn the_state_survives_a_restart() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("llm-usage.json");
        let now = 1_763_030_000_000;
        let mut st = State::default();
        st.cursors.insert("main/s1".into(), 7);
        st.add(
            &Usage {
                at: now,
                provider: "anthropic".into(),
                api: String::new(),
                model: "claude-sonnet-5".into(),
                run_id: Some("r".into()),
                input: 3,
                output: 4,
                cache_read: 5,
                cache_write: 6,
                cost: Some(0.5),
            },
            "email",
            now,
        );
        st.save(&path);
        let back = State::load(&path);
        assert_eq!(back.cursors.get("main/s1"), Some(&7));
        let p = back.pending();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0]["cache_write"], 6);
        assert_eq!(p[1]["source"], "llm_run_usage");
        assert_eq!(p[1]["activity"], "email");
    }

    #[test]
    fn a_scan_reads_each_message_once() {
        let home = tempfile::tempdir().expect("dir");
        let dir = home.path().join("agents").join("main").join("agent");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let db = rusqlite::Connection::open(dir.join("openclaw-agent.sqlite")).expect("db");
        db.execute_batch(
            "CREATE TABLE session_windows (session_id TEXT, session_key TEXT, created_at INTEGER, updated_at INTEGER);
             CREATE TABLE transcript_events (session_id TEXT, seq INTEGER, event_json TEXT, event_zstd BLOB, created_at INTEGER);
             INSERT INTO session_windows VALUES ('s1', 'agent:main:telegram:direct:1', 0, 0);",
        )
        .expect("schema");
        let now = now_ms();
        let at = chrono_iso(now - 60_000);
        let msg = |seq: i64| {
            db.execute(
                "INSERT INTO transcript_events VALUES ('s1', ?, ?, NULL, 0)",
                rusqlite::params![seq, json!({ "type": "message", "timestamp": at, "message": { "role": "assistant", "provider": "controlclaw", "model": "m", "usage": { "input": 10, "output": 1 } } }).to_string()],
            )
            .expect("insert");
        };
        msg(1);
        msg(2);
        let mut st = State::default();
        scan(home.path(), &mut st, now);
        assert_eq!(st.pending()[0]["calls"], 2);
        scan(home.path(), &mut st, now);
        assert_eq!(st.pending()[0]["calls"], 2, "read again: nothing new");
        msg(3);
        scan(home.path(), &mut st, now);
        assert_eq!(st.pending()[0]["calls"], 3);
    }

    #[test]
    fn a_heartbeat_in_the_main_session_is_not_a_chat() {
        let home = tempfile::tempdir().expect("dir");
        let dir = home.path().join("agents").join("main").join("agent");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let db = rusqlite::Connection::open(dir.join("openclaw-agent.sqlite")).expect("db");
        db.execute_batch(
            "CREATE TABLE session_windows (session_id TEXT, session_key TEXT, created_at INTEGER, updated_at INTEGER);
             CREATE TABLE transcript_events (session_id TEXT, seq INTEGER, event_json TEXT, event_zstd BLOB, created_at INTEGER);
             CREATE TABLE trajectory_runtime_events (session_id TEXT, seq INTEGER, run_id TEXT, event_json TEXT);
             INSERT INTO session_windows VALUES ('s1', 'agent:main:main', 0, 0);",
        )
        .expect("schema");
        db.execute(
            "INSERT INTO trajectory_runtime_events VALUES ('s1', 1, 'r-beat', ?)",
            [json!({ "type": "session.started", "data": { "trigger": "heartbeat" } }).to_string()],
        )
        .expect("insert");
        let at = chrono_iso(now_ms() - 60_000);
        for (seq, run) in [(1, "r-beat"), (2, "r-dm")] {
            db.execute(
                "INSERT INTO transcript_events VALUES ('s1', ?, ?, NULL, 0)",
                rusqlite::params![seq, json!({ "type": "message", "timestamp": at, "message": { "role": "assistant", "provider": "controlclaw", "model": "m", "usage": { "input": 10, "output": 1 }, "__openclaw": { "runId": run } } }).to_string()],
            )
            .expect("insert");
        }
        let mut st = State::default();
        scan(home.path(), &mut st, now_ms());
        let p = st.pending();
        let kinds: Vec<_> = p
            .iter()
            .filter(|r| r["source"] == "llm_usage")
            .map(|r| r["activity"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(kinds.contains(&"heartbeat".to_string()), "{kinds:?}");
        assert!(kinds.contains(&"chat".to_string()), "{kinds:?}");
    }

    fn chrono_iso(ms: i64) -> String {
        super::super::time::iso_ms(ms)
    }
}
