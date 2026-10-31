//! What the agent is doing right now, for Doing now on the console's Home tab (`activity-now.ts`).
//! `GET /activity/now`, console token only, read every 5 s while somebody has the tab open. Nothing
//! here is stored. The runs and tool calls come from OpenClaw's audit ledger, fed by the audit
//! shipper; the request and who asked come from OpenClaw's database, read when the route is asked.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, LazyLock};

use cc_http::{Router, send_json};
use hyper::Method;
use regex::Regex;
use serde_json::{Value, json};

use super::common::{js_slice, lock};
use super::transcripts::{INTERNAL_KEY, RunRef, parse_session_key};
use crate::app::App;
use crate::stages;

/// The model calls a generic `tool_call` tool that runs the real one: every call is there twice.
const WRAPPER_TOOL: &str = "tool_call";
pub const MAX_STEPS: usize = 12;
const MAX_OPEN_RUNS: usize = 50;
/// A run with no new event for this long is taken as gone.
pub const ABANDONED_AFTER_MS: i64 = 60 * 60_000;
const MAX_ENDED: usize = 200;
/// How long after a run starts its rows in OpenClaw's database are looked for again on each read.
const SETTLE_MS: i64 = 120_000;
/// How long before a run's start the message that started it can have been sent.
pub const FRESH_MESSAGE_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq)]
pub struct NowStep {
    pub name: String,
    pub status: String,
    pub started_at: i64,
}

/// What the route reads out of OpenClaw's database for a run; read once and kept on the run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunFacts {
    pub trigger: Option<String>,
    pub request: Option<String>,
    pub sender: Option<String>,
    pub channel: Option<String>,
    pub text: Option<String>,
    pub asker_read: bool,
}

#[derive(Debug, Clone)]
struct OpenRun {
    run_id: String,
    session_key: Option<String>,
    agent_id: Option<String>,
    started_at: i64,
    last_at: i64,
    /// By tool call id, in insertion order (a JS `Map`).
    steps: Vec<(String, NowStep)>,
    facts: RunFacts,
}

/// The runs going now, from the ledger events in sequence order.
#[derive(Default)]
pub struct NowTracker {
    runs: Vec<OpenRun>,
    ended: VecDeque<String>,
    reset_at: i64,
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty())
}

impl NowTracker {
    fn open(&mut self, ev: &Value, run_id: &str, at: i64) -> usize {
        self.runs.push(OpenRun {
            run_id: run_id.into(),
            session_key: s(ev, "sessionKey").map(str::to_string),
            agent_id: s(ev, "agentId").map(str::to_string),
            started_at: at,
            last_at: at,
            steps: Vec::new(),
            facts: RunFacts::default(),
        });
        if self.runs.len() > MAX_OPEN_RUNS {
            self.runs.remove(0);
        }
        self.runs.len() - 1
    }

    fn find(&self, run_id: &str) -> Option<usize> {
        self.runs.iter().position(|r| r.run_id == run_id)
    }

    pub fn record(&mut self, events: &[Value]) {
        for ev in events {
            let (Some(run_id), Some(at)) = (s(ev, "runId"), ev.get("occurredAt").and_then(Value::as_f64)) else {
                continue;
            };
            let at = at as i64;
            let ended = self.ended.iter().any(|e| e == run_id);
            if s(ev, "kind") == Some("agent_run") {
                if ev.get("status").and_then(Value::as_str) == Some("started") {
                    // A gateway that went away took this run with it: not taken up again.
                    if at < self.reset_at || ended {
                        continue;
                    }
                    match self.find(run_id) {
                        Some(i) => self.runs[i].started_at = self.runs[i].started_at.min(at),
                        None => {
                            self.open(ev, run_id, at);
                        }
                    }
                } else {
                    self.runs.retain(|r| r.run_id != run_id);
                    // A set: a run that writes several ends takes one place.
                    if !ended {
                        self.ended.push_back(run_id.into());
                    }
                    if self.ended.len() > MAX_ENDED {
                        self.ended.pop_front();
                    }
                }
                continue;
            }
            let (Some(call), Some(tool)) = (s(ev, "toolCallId"), s(ev, "toolName")) else {
                continue;
            };
            if s(ev, "kind") != Some("tool_action") || tool == WRAPPER_TOOL {
                continue;
            }
            // A run whose start this box did not see is taken up from its first tool call after that.
            let i = match self.find(run_id) {
                Some(i) => i,
                None if at < self.reset_at || ended => continue,
                None => self.open(ev, run_id, at),
            };
            let run = &mut self.runs[i];
            if run.session_key.is_none() {
                run.session_key = s(ev, "sessionKey").map(str::to_string);
            }
            run.last_at = run.last_at.max(at);
            let step = NowStep {
                name: js_slice(tool, 80),
                status: ev
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                started_at: at,
            };
            match run.steps.iter_mut().find(|(id, _)| id == call) {
                Some((_, prev)) => {
                    *prev = NowStep {
                        started_at: prev.started_at,
                        ..step
                    }
                }
                None => {
                    run.steps.push((call.into(), step));
                    if run.steps.len() > MAX_STEPS {
                        run.steps.remove(0);
                    }
                }
            }
        }
    }

    /// On every new connection to the gateway: what it was running may be gone.
    pub fn reset(&mut self, now: i64) {
        self.runs.clear();
        self.reset_at = now;
    }

    /// The runs going now, newest first, without OpenClaw's internal sessions. A run silent for
    /// `ABANDONED_AFTER_MS` is dropped, unless its session waits for an approval.
    fn current(&mut self, now: i64, waiting: &HashSet<String>) -> Vec<usize> {
        self.runs.retain(|r| {
            now - r.last_at <= ABANDONED_AFTER_MS || r.session_key.as_ref().is_some_and(|k| waiting.contains(k))
        });
        let mut out: Vec<usize> = (0..self.runs.len())
            .filter(|&i| {
                !self.runs[i]
                    .session_key
                    .as_ref()
                    .is_some_and(|k| INTERNAL_KEY.is_match(k))
            })
            .collect();
        // Newest first; a stable sort keeps insertion order between equals, as JS's does.
        out.sort_by(|a, b| self.runs[*b].started_at.cmp(&self.runs[*a].started_at));
        out
    }
}

/// Each run's trigger, by run id (`runTriggers`).
pub type TriggersRead = Box<dyn Fn(&[RunRef]) -> std::collections::HashMap<String, String> + Send + Sync>;
/// Who asked a run, and what their message said (`runAsker`).
pub type AskerRead = Box<dyn Fn(&RunRef, i64) -> super::run_titles::RunAsker + Send + Sync>;

/// What the route reads from the box.
pub struct NowDeps {
    pub triggers: TriggersRead,
    /// The request a run was given, cleaned; `Heartbeat` when it is OpenClaw's heartbeat prompt.
    pub request: Box<dyn Fn(&RunRef) -> Request + Send + Sync>,
    pub asker: AskerRead,
    pub approval_sessions: Box<dyn Fn() -> HashSet<String> + Send + Sync>,
    pub now: Box<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Text(String),
    Heartbeat,
    None,
}

const SELF_TRIGGERS: [&str; 2] = ["heartbeat", "cron"];

fn reference(r: &OpenRun) -> RunRef {
    RunRef {
        run_id: r.run_id.clone(),
        session_key: r.session_key.clone(),
        agent_id: r.agent_id.clone(),
    }
}

/// The newest run that somebody asked for, with its request, who asked and its steps. The tracker
/// is locked only between the database reads, never across one: the audit shipper feeds it.
pub fn activity_now(tracker: &std::sync::Mutex<NowTracker>, d: &NowDeps) -> Value {
    let now = (d.now)();
    let waiting = (d.approval_sessions)();
    let settled = |started_at: i64| now - started_at > SETTLE_MS;
    let null = || json!({ "ok": true, "now": now, "run": null });
    loop {
        let (ids, unknown): (Vec<String>, Vec<RunRef>) = {
            let mut t = lock(tracker);
            let runs = t.current(now, &waiting);
            let ids = runs.iter().map(|&i| t.runs[i].run_id.clone()).collect();
            let unknown = runs
                .iter()
                .filter(|&&i| t.runs[i].facts.trigger.is_none())
                .map(|&i| reference(&t.runs[i]))
                .collect();
            (ids, unknown)
        };
        if !unknown.is_empty() {
            let found = (d.triggers)(&unknown);
            let mut t = lock(tracker);
            for r in &unknown {
                let Some(i) = t.find(&r.run_id) else { continue };
                let run = &mut t.runs[i];
                if let Some(f) = found.get(&run.run_id) {
                    run.facts.trigger = Some(f.clone());
                } else if settled(run.started_at) {
                    run.facts.trigger = Some(String::new());
                }
            }
        }
        let picked = {
            let t = lock(tracker);
            ids.iter().find_map(|id| {
                let r = &t.runs[t.find(id)?];
                (!SELF_TRIGGERS.contains(&r.facts.trigger.as_deref().unwrap_or(""))).then(|| {
                    (
                        reference(r),
                        r.started_at,
                        r.facts.asker_read,
                        r.facts.request.is_some(),
                    )
                })
            })
        };
        let Some((r, started_at, asker_read, request_known)) = picked else {
            return null();
        };
        if !asker_read {
            let read = (d.asker)(&r, started_at);
            // A message sent well before the run did not start it (a heartbeat, a system turn).
            let asker = match read.at {
                Some(at) if started_at as f64 - at > FRESH_MESSAGE_MS as f64 => super::run_titles::RunAsker::default(),
                _ => read,
            };
            let mut t = lock(tracker);
            if let Some(i) = t.find(&r.run_id) {
                let f = &mut t.runs[i].facts;
                f.asker_read = asker.sender.is_some() || asker.channel.is_some() || settled(started_at);
                f.sender = asker.sender;
                f.channel = asker.channel;
                f.text = asker.text;
            }
        }
        if !request_known {
            let request = (d.request)(&r);
            let mut t = lock(tracker);
            if let Some(i) = t.find(&r.run_id) {
                let f = &mut t.runs[i].facts;
                if request == Request::Heartbeat && f.trigger.as_deref().is_none_or(str::is_empty) {
                    // A heartbeat whose trigger was not found: OpenClaw's own poll, not a request.
                    f.trigger = Some("heartbeat".into());
                    continue;
                }
                match request {
                    // A run OpenClaw says somebody started keeps that word over its prompt's look.
                    Request::Heartbeat => f.request = Some(String::new()),
                    Request::Text(text) => f.request = Some(text),
                    Request::None if settled(started_at) => f.request = Some(String::new()),
                    Request::None => {}
                }
            }
        }
        let t = lock(tracker);
        // Ended meanwhile: look again.
        let Some(i) = t.find(&r.run_id) else { continue };
        let run = &t.runs[i];
        let f = &run.facts;
        let key_channel = run.session_key.as_deref().map(channel_of_key);
        let request = f
            .request
            .clone()
            .filter(|x| !x.is_empty())
            .or_else(|| f.text.clone().filter(|x| !x.is_empty()));
        return json!({
            "ok": true,
            "now": now,
            "run": {
                "startedAt": run.started_at,
                "channel": f.channel.clone().or(key_channel),
                "sender": f.sender,
                "request": request,
                "steps": run.steps.iter().map(|(_, s)| json!({ "name": s.name, "status": s.status, "startedAt": s.started_at })).collect::<Vec<_>>(),
                "waitingApproval": run.session_key.as_ref().is_some_and(|k| waiting.contains(k)),
            },
        });
    }
}

static MEETING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|:)meeting-").expect("regex"));
static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i):voice:call(:|$)").expect("regex"));
static EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|:)agentmail(:|$)").expect("regex"));

/// What a session key says about the channel.
pub fn channel_of_key(key: &str) -> String {
    if MEETING.is_match(key) {
        return "meeting".into();
    }
    if CALL.is_match(key) {
        return "call".into();
    }
    if EMAIL.is_match(key) {
        return "email".into();
    }
    parse_session_key(key).0
}

/// `GET /activity/now`: the console's token only; 405 for any other method.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.route(
        stages::PREFIXED,
        |_, p| p == "/activity/now",
        move |req, _| {
            let app = a.clone();
            async move {
                if req.method() != Method::GET {
                    return send_json(405, &json!({ "error": "Method not allowed" }));
                }
                let target = req
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok());
                if app.console_auth.verify("GET", &target, auth).is_none() {
                    return send_json(401, &json!({ "error": "Unauthorized" }));
                }
                let Some(p) = app.contracts.platform.get() else {
                    return send_json(200, &json!({ "ok": true, "now": super::time::now_ms(), "run": null }));
                };
                let deps = now_deps(&app);
                let tracker = p.now_runs.clone();
                let answer = tokio::task::spawn_blocking(move || activity_now(&tracker, &deps)).await;
                send_json(
                    200,
                    &answer.unwrap_or_else(|_| json!({ "ok": true, "now": super::time::now_ms(), "run": null })),
                )
            }
        },
    );
}

/// The real reads: OpenClaw's database under `$HOME/.openclaw`, and the approvals bridge's sessions.
pub fn now_deps(app: &Arc<App>) -> NowDeps {
    let home = app.config.home.join(".openclaw");
    let (h1, h2, h3) = (home.clone(), home.clone(), home);
    let weak = Arc::downgrade(app);
    NowDeps {
        triggers: Box::new(move |runs| super::transcripts::run_triggers(&h1, runs)),
        request: Box::new(move |run| {
            match super::run_titles::run_prompts(&h2, std::slice::from_ref(run)).get(&run.run_id) {
                Some(p) if super::run_titles::is_heartbeat_prompt(p) => Request::Heartbeat,
                Some(p) => super::run_titles::request_of(p).map_or(Request::None, Request::Text),
                None => Request::None,
            }
        }),
        asker: Box::new(move |run, started| super::run_titles::run_asker(&h3, run, started)),
        approval_sessions: Box::new(move || {
            weak.upgrade()
                .and_then(|a| {
                    a.contracts
                        .platform
                        .get()
                        .and_then(|p| p.approval_sessions.get().cloned())
                })
                .map(|f| f())
                .unwrap_or_default()
        }),
        now: Box::new(super::time::now_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run(id: &str, status: &str, at: i64) -> Value {
        json!({ "kind": "agent_run", "runId": id, "status": status, "occurredAt": at, "sessionKey": "agent:main:telegram:direct:1", "agentId": "main" })
    }
    fn tool(id: &str, call: &str, name: &str, status: &str, at: i64) -> Value {
        json!({ "kind": "tool_action", "runId": id, "toolCallId": call, "toolName": name, "status": status, "occurredAt": at })
    }

    fn deps(now: i64, trigger: &'static str) -> NowDeps {
        NowDeps {
            triggers: Box::new(move |runs| {
                runs.iter()
                    .map(|r| (r.run_id.clone(), trigger.to_string()))
                    .collect::<HashMap<_, _>>()
            }),
            request: Box::new(|_| Request::Text("Book a table".into())),
            asker: Box::new(|_, _| super::super::run_titles::RunAsker {
                sender: Some("Ada".into()),
                channel: Some("telegram".into()),
                text: None,
                at: Some(1000.0),
            }),
            approval_sessions: Box::new(HashSet::new),
            now: Box::new(move || now),
        }
    }

    #[test]
    fn the_newest_asked_run_with_its_steps() {
        let t = std::sync::Mutex::new(NowTracker::default());
        lock(&t).record(&[
            run("r1", "started", 1000),
            tool("r1", "c1", "browser", "started", 1100),
            tool("r1", "c1", "browser", "succeeded", 1200),
            tool("r1", "w", WRAPPER_TOOL, "started", 1300),
        ]);
        let a = activity_now(&t, &deps(2000, "user"));
        assert_eq!(a["run"]["request"], json!("Book a table"));
        assert_eq!(a["run"]["sender"], json!("Ada"));
        assert_eq!(
            a["run"]["steps"],
            json!([{ "name": "browser", "status": "succeeded", "startedAt": 1100 }])
        );
        assert_eq!(a["run"]["waitingApproval"], json!(false));
        assert_eq!(
            activity_now(&t, &deps(2000, "heartbeat"))["run"]["request"],
            json!("Book a table"),
            "facts are read once"
        );
    }

    #[test]
    fn a_heartbeat_is_nobodys_request_and_an_ended_run_is_gone() {
        let t = std::sync::Mutex::new(NowTracker::default());
        lock(&t).record(&[run("r1", "started", 1000)]);
        assert_eq!(activity_now(&t, &deps(2000, "heartbeat"))["run"], Value::Null);
        lock(&t).record(&[
            run("r2", "started", 1500),
            run("r2", "succeeded", 1600),
            tool("r2", "c", "x", "started", 1700),
        ]);
        assert_eq!(
            activity_now(&t, &deps(2000, "user"))["run"],
            Value::Null,
            "r1 stays a heartbeat; r2 ended"
        );
    }

    #[test]
    fn a_reset_forgets_and_old_events_do_not_come_back() {
        let t = std::sync::Mutex::new(NowTracker::default());
        lock(&t).record(&[run("r1", "started", 1000)]);
        lock(&t).reset(5000);
        lock(&t).record(&[tool("r1", "c", "x", "started", 1100)]);
        assert_eq!(activity_now(&t, &deps(6000, "user"))["run"], Value::Null);
    }

    #[test]
    fn the_channel_from_the_key() {
        assert_eq!(channel_of_key("agent:main:meeting-abc"), "meeting");
        assert_eq!(channel_of_key("agent:main:voice:call:1"), "call");
        assert_eq!(channel_of_key("agent:main:agentmail:x"), "email");
        assert_eq!(channel_of_key("agent:main:main"), "web chat");
    }
}
