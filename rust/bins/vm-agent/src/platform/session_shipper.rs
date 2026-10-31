//! When each meeting and phone call started and ended, for the console's timeline
//! (`session-shipper.ts`). OpenClaw's audit ledger does not cover them: a meeting the agent only
//! listens to makes no run at all. One record per session, times and a kind only: no title, no
//! names, no transcript. What was accepted is remembered in `state/sessions.sent.json`, so a
//! restart or a console that was away sends what it missed and nothing twice.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{Flag, js_slice, lock};
use super::metrics::Post;
use super::time::now_ms;

/// Sessions older than this are neither read nor remembered.
pub const SESSION_LOOKBACK_MS: i64 = 48 * 60 * 60 * 1000;
const MAX_BATCH: usize = 100;
/// After a refused batch: the console needs a deploy, not a retry every minute.
pub const REFUSED_RETRY_MS: i64 = 30 * 60 * 1000;

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub kind: &'static str,
    pub id: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

impl Session {
    fn key(&self) -> String {
        format!("{}:{}", self.kind, self.id)
    }

    /// `toRecord`.
    pub fn record(&self) -> Value {
        json!({ "source": "session", "kind": self.kind, "session_id": js_slice(&self.id, 128), "started_at": self.started_at, "ended_at": self.ended_at })
    }
}

/// A call as W8's phone service gives it (`callSessions`). Its start is the answer; the phone
/// service picks calls by when they were dialed, so the two 48-hour windows differ by the ring time,
/// as in the TS.
impl From<crate::contracts::CallSession> for Session {
    fn from(c: crate::contracts::CallSession) -> Self {
        Self {
            kind: "call",
            id: c.call_id,
            started_at: c.started_at,
            ended_at: c.ended_at,
        }
    }
}

/// The end each session was last sent with (None: sent while going), and when it started.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Sent {
    end: Option<i64>,
    at: i64,
}

/// What has to be sent: new sessions, and sessions whose end changed since they were sent.
fn pending(sessions: Vec<Session>, sent: &BTreeMap<String, Sent>) -> Vec<Session> {
    sessions
        .into_iter()
        .filter(|s| match sent.get(&s.key()) {
            None => true,
            Some(prev) => s.ended_at.is_some() && s.ended_at != prev.end,
        })
        .collect()
}

/// What the shipper reads: the sessions that started in the last `SESSION_LOOKBACK_MS`.
pub type Sessions = Box<dyn Fn(i64) -> cc_http::BoxFuture<Vec<Session>> + Send + Sync>;

pub struct SessionShipper {
    sessions: Sessions,
    state_path: PathBuf,
    post: Post,
    next_attempt_at: Mutex<i64>,
    in_flight: AtomicBool,
}

impl SessionShipper {
    pub fn new(sessions: Sessions, state_path: PathBuf, post: Post) -> Self {
        Self {
            sessions,
            state_path,
            post,
            next_attempt_at: Mutex::new(0),
            in_flight: AtomicBool::new(false),
        }
    }

    fn load(path: &Path) -> BTreeMap<String, Sent> {
        let Some(Value::Object(raw)) = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
        else {
            return BTreeMap::new();
        };
        raw.into_iter()
            .filter_map(|(k, v)| {
                let at = v.get("at")?.as_f64()? as i64;
                let end = match v.get("end")? {
                    Value::Null => None,
                    e => Some(e.as_f64()? as i64),
                };
                Some((k, Sent { end, at }))
            })
            .collect()
    }

    fn save(path: &Path, sent: &BTreeMap<String, Sent>) {
        let body: Map<String, Value> = sent
            .iter()
            .map(|(k, s)| (k.clone(), json!({ "end": s.end, "at": s.at })))
            .collect();
        if let Err(e) = cc_store::write_atomic(
            path,
            Value::Object(body).to_string().as_bytes(),
            0o600,
            cc_store::TmpName::Suffix,
        ) {
            tracing::warn!("[sessions] state not saved: {e}");
        }
    }

    /// Sends what is new or newly ended. How many sessions the console took.
    pub async fn tick(&self) -> usize {
        let now = now_ms();
        if now < *lock(&self.next_attempt_at) {
            return 0;
        }
        // Ticks are awaited one after another; the flag keeps the TS's guard for any other caller.
        let Some(_flying) = Flag::take(&self.in_flight) else {
            return 0;
        };
        // The state file is read and written off the runtime's threads.
        let path = self.state_path.clone();
        let mut sent = tokio::task::spawn_blocking(move || Self::load(&path))
            .await
            .unwrap_or_default();
        let mut todo = pending((self.sessions)(now).await, &sent);
        todo.truncate(MAX_BATCH);
        if !todo.is_empty() {
            let records: Vec<Value> = todo.iter().map(Session::record).collect();
            match (self.post)(json!({ "records": records })).await {
                // A console from before the session sink refuses the whole batch: kept, and tried
                // again much later, so the sessions of the meantime still arrive.
                Ok(s @ (400 | 413)) => {
                    tracing::info!(
                        "[sessions] batch of {} refused with HTTP {s}; trying again later",
                        records.len()
                    );
                    *lock(&self.next_attempt_at) = now + REFUSED_RETRY_MS;
                    return 0;
                }
                Ok(s) if !(200..300).contains(&s) => {
                    tracing::info!("[sessions] ship failed: HTTP {s}");
                    return 0;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::info!("[sessions] ship failed: {e}");
                    return 0;
                }
            }
        }
        for s in &todo {
            sent.insert(
                s.key(),
                Sent {
                    end: s.ended_at,
                    at: s.started_at,
                },
            );
        }
        sent.retain(|_, v| now - v.at <= SESSION_LOOKBACK_MS);
        let path = self.state_path.clone();
        let _ = tokio::task::spawn_blocking(move || Self::save(&path, &sent)).await;
        todo.len()
    }
}

static MEETING_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9-]{36}\.json$").expect("regex"));

/// What `meeting_sessions` read from each file, by name, so an unchanged file is not parsed again.
pub type MeetingFileCache = HashMap<String, (std::time::SystemTime, Option<Session>)>;

/// The agent's meetings that started in the last `lookback_ms`, from the meeting archive's JSON
/// files. Files not written in that time are not opened; an unchanged one is not read again.
pub fn meeting_sessions(dir: &Path, now: i64, lookback_ms: i64, cache: &mut MeetingFileCache) -> Vec<Session> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for e in rd.filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().into_owned();
        if !MEETING_FILE.is_match(&name) {
            continue;
        }
        // `statSync` follows a link: the target's time counts.
        let Ok(mtime) = std::fs::metadata(e.path()).and_then(|m| m.modified()) else {
            continue;
        };
        let mtime_ms = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        if now - mtime_ms > lookback_ms {
            continue;
        }
        seen.insert(name.clone());
        let entry = match cache.get(&name) {
            Some((m, s)) if *m == mtime => s.clone(),
            _ => {
                let s = read_meeting(&e.path());
                cache.insert(name, (mtime, s.clone()));
                s
            }
        };
        if let Some(s) = entry.filter(|s| now - s.started_at <= lookback_ms) {
            out.push(s);
        }
    }
    cache.retain(|k, _| seen.contains(k));
    out
}

/// One meeting file: None for a half-written file, or a meeting that never got in. Times are the
/// ISO forms the meetings service writes; another form (which `Date.parse` might read) is unread.
fn read_meeting(file: &Path) -> Option<Session> {
    let r: Value = serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
    let id = r.get("id")?.as_str()?;
    let started_at = super::time::date_parse(r.get("startedAt")?.as_str()?)?;
    let ended_at = r
        .get("endedAt")
        .and_then(Value::as_str)
        .and_then(super::time::date_parse);
    let state = r.get("state").and_then(Value::as_str);
    // Not in the call (yet, or ever): asking to be let in, or refused.
    if matches!(state, Some("joining" | "waiting")) {
        return None;
    }
    let spoke = r
        .get("transcript")
        .and_then(Value::as_array)
        .is_some_and(|t| !t.is_empty());
    if state == Some("failed") && !spoke {
        return None;
    }
    let done = matches!(state, Some("complete" | "failed"));
    Some(Session {
        kind: "meeting",
        id: id.into(),
        started_at,
        ended_at: ended_at.or(done.then_some(started_at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const H: i64 = 3_600_000;

    fn now() -> i64 {
        super::super::time::date_parse("2026-10-23T15:00:00Z").expect("t")
    }

    #[test]
    fn a_session_is_sent_when_first_seen_and_again_when_its_end_changes() {
        let sent = |end: Option<i64>, at: i64| BTreeMap::from([("meeting:m1".to_string(), Sent { end, at })]);
        let going = Session {
            kind: "meeting",
            id: "m1".into(),
            started_at: now() - H,
            ended_at: None,
        };
        let done = Session {
            ended_at: Some(now() - 30 * 60_000),
            ..going.clone()
        };
        assert_eq!(pending(vec![going.clone()], &BTreeMap::new()), vec![going.clone()]);
        assert_eq!(pending(vec![going.clone()], &sent(None, going.started_at)), vec![]);
        assert_eq!(
            pending(vec![done.clone()], &sent(None, going.started_at)),
            vec![done.clone()]
        );
        assert_eq!(
            pending(vec![done.clone()], &sent(done.ended_at, going.started_at)),
            vec![]
        );
        // A mode switch wrote an end, then the meeting went on and ended later: the new end is sent.
        let later = Session {
            ended_at: Some(now()),
            ..going.clone()
        };
        assert_eq!(
            pending(vec![later.clone()], &sent(done.ended_at, going.started_at)),
            vec![later]
        );
        // While it goes on again after an end was sent, nothing new is sent.
        assert_eq!(
            pending(vec![going.clone()], &sent(done.ended_at, going.started_at)),
            vec![]
        );
        // A call and a meeting with the same id are two sessions.
        assert_eq!(
            pending(vec![Session { kind: "call", ..done }], &sent(Some(1), 0)).len(),
            1
        );
    }

    fn touch(path: &Path, at: i64) {
        let f = std::fs::File::options().write(true).open(path).expect("open");
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(at as u64))
            .expect("mtime");
    }

    #[test]
    fn meetings_times_only_from_recent_files_and_one_that_never_got_in_is_left_out() {
        let d = tempfile::tempdir().expect("dir");
        let id = |n: u8| format!("00000000-0000-4000-8000-00000000000{n}");
        let iso = super::super::time::iso_ms;
        let write = |n: u8, mut r: Value| {
            let path = d.path().join(format!("{}.json", id(n)));
            r["id"] = json!(id(n));
            if r.get("transcript").is_none() {
                r["transcript"] = json!([]);
            }
            std::fs::write(&path, r.to_string()).expect("w");
            touch(&path, now() - 60_000);
            path
        };
        write(
            1,
            json!({ "startedAt": iso(now() - 2 * H), "endedAt": iso(now() - H), "state": "complete", "transcript": [{ "text": "secret words" }] }),
        );
        let two = write(2, json!({ "startedAt": iso(now() - 10 * 60_000), "state": "active" }));
        write(
            3,
            json!({ "startedAt": iso(now() - 5 * 60_000), "state": "failed", "error": "refused" }),
        );
        write(4, json!({ "startedAt": iso(now() - 60_000), "state": "waiting" }));
        let old = write(
            5,
            json!({ "startedAt": iso(now() - 72 * H), "endedAt": iso(now() - 72 * H), "state": "complete" }),
        );
        write(6, json!({ "startedAt": iso(now() - 3 * H), "state": "complete" }));
        std::fs::write(d.path().join("notes.txt"), "not a meeting").expect("w");
        let half = d.path().join(format!("{}.json", id(7)));
        std::fs::write(&half, "{ half written").expect("w");
        touch(&half, now() - 60_000);
        // An old file is not even opened.
        touch(&old, now() - 72 * H);
        let mut cache = MeetingFileCache::new();
        let mut got = meeting_sessions(d.path(), now(), SESSION_LOOKBACK_MS, &mut cache);
        got.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(
            got,
            vec![
                Session {
                    kind: "meeting",
                    id: id(1),
                    started_at: now() - 2 * H,
                    ended_at: Some(now() - H)
                },
                Session {
                    kind: "meeting",
                    id: id(2),
                    started_at: now() - 10 * 60_000,
                    ended_at: None
                },
                // Complete with no end written: a point at its start rather than a bar to now.
                Session {
                    kind: "meeting",
                    id: id(6),
                    started_at: now() - 3 * H,
                    ended_at: Some(now() - 3 * H)
                },
            ]
        );
        assert!(!format!("{got:?}").contains("secret"));
        assert!(
            meeting_sessions(
                &d.path().join("missing"),
                now(),
                SESSION_LOOKBACK_MS,
                &mut MeetingFileCache::new()
            )
            .is_empty()
        );
        // An unchanged file is not read again; a changed one is.
        std::fs::write(&two, "{ now unreadable").expect("w");
        touch(&two, now() - 60_000);
        assert!(
            meeting_sessions(d.path(), now(), SESSION_LOOKBACK_MS, &mut cache)
                .iter()
                .any(|s| s.id == id(2))
        );
        touch(&two, now() - 30_000);
        assert!(
            !meeting_sessions(d.path(), now(), SESSION_LOOKBACK_MS, &mut cache)
                .iter()
                .any(|s| s.id == id(2))
        );
    }

    #[tokio::test]
    async fn the_shipper_sends_remembers_resends_after_a_failure_and_waits_after_a_refusal() {
        let d = tempfile::tempdir().expect("dir");
        let now = now_ms();
        let live = Arc::new(Mutex::new(vec![Session {
            kind: "call",
            id: "c1".into(),
            started_at: now - 1000,
            ended_at: None,
        }]));
        let posts = Arc::new(Mutex::new(Vec::<Value>::new()));
        let status = Arc::new(Mutex::new(Ok::<u16, String>(503)));
        let (l, p, st) = (live.clone(), posts.clone(), status.clone());
        let shipper = SessionShipper::new(
            Box::new(move |_| {
                let v = lock(&l).clone();
                Box::pin(async move { v })
            }),
            d.path().join("sessions.sent.json"),
            Arc::new(move |body| {
                lock(&p).push(body);
                let r = lock(&st).clone();
                Box::pin(async move { r })
            }),
        );
        assert_eq!(shipper.tick().await, 0, "a failure is not remembered");
        *lock(&status) = Ok(200);
        assert_eq!(shipper.tick().await, 1, "and is sent again");
        assert_eq!(
            lock(&posts)[1]["records"][0],
            json!({ "source": "session", "kind": "call", "session_id": "c1", "started_at": now - 1000, "ended_at": null })
        );
        assert_eq!(shipper.tick().await, 0, "sent while going: not again");
        lock(&live)[0].ended_at = Some(now);
        *lock(&status) = Ok(400);
        assert_eq!(shipper.tick().await, 0);
        let asked = lock(&posts).len();
        assert_eq!(shipper.tick().await, 0);
        assert_eq!(lock(&posts).len(), asked, "refused: not asked again for half an hour");
        *lock(&shipper.next_attempt_at) = 0;
        *lock(&status) = Ok(200);
        assert_eq!(shipper.tick().await, 1, "the end goes once the console takes it");
        assert_eq!(shipper.tick().await, 0);
    }

    #[test]
    fn a_call_from_the_phone_service_is_a_call_session() {
        let c = crate::contracts::CallSession {
            call_id: "CA1".into(),
            started_at: 5,
            ended_at: None,
        };
        let s = Session::from(c);
        assert_eq!(
            s,
            Session {
                kind: "call",
                id: "CA1".into(),
                started_at: 5,
                ended_at: None
            }
        );
        assert_eq!(s.record()["kind"], json!("call"));
    }
}
