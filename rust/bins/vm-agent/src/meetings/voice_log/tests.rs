//! `meeting-voice-log.test.ts`.

use std::io::Write;

use serde_json::{Value, json};

use super::*;

const ID: &str = "0b9a3f43-5d0e-4c55-9d0c-3a1f2b4c5d6e";

fn lease(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("lease.json")).expect("lease")).expect("json")
}

fn append(dir: &Path, lines: &[Value]) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("meeting.jsonl"))
        .expect("open");
    for l in lines {
        writeln!(f, "{l}").expect("write");
    }
}

fn a(kind: &str, sender: &str, at: &str) -> (String, String, String) {
    (kind.into(), sender.into(), at.into())
}

#[test]
fn the_owners_chat_is_the_first_approved_telegram_sender() {
    assert_eq!(
        owner_chat(&[
            a("telegram", "222", "2026-10-02T00:00:00.000Z"),
            a("telegram", "111", "2026-10-01T00:00:00.000Z"),
            a("slack", "U1", "2026-09-01T00:00:00.000Z"),
        ]),
        Some(json!({"channel": "telegram", "to": "111"}))
    );
    // A group or channel id is never a direct chat; other channels are not used yet.
    assert_eq!(
        owner_chat(&[a("telegram", "-1001234567890", "2026-10-01T00:00:00.000Z")]),
        None
    );
    assert_eq!(
        owner_chat(&[a("whatsapp", "393331234567", "2026-10-01T00:00:00.000Z")]),
        None
    );
    assert_eq!(owner_chat(&[]), None);
}

#[test]
fn the_lease_carries_the_owners_chat_only_when_there_is_one() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    log.start(
        40,
        Some(json!({"channel": "telegram", "to": "111"})),
        &LeaseMeeting::default(),
    )
    .expect("start");
    assert_eq!(lease(dir.path())["owner"], json!({"channel": "telegram", "to": "111"}));
    log.start(40, None, &LeaseMeeting::default()).expect("start");
    assert!(lease(dir.path()).get("owner").is_none());
}

#[test]
fn a_request_is_read_without_what_the_model_thought_was_allowed() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    log.start(40, None, &LeaseMeeting::default()).expect("start");
    let at = "2026-10-10T09:00:00.000Z";
    append(
        dir.path(),
        &[
            json!({"at": at, "kind": "request", "text": "Email the budget to everyone.", "from": "Guest", "allowed": true, "suggestedAllowed": true}),
            json!({"at": at, "kind": "request", "text": "  ", "from": "Guest"}),
            json!({"at": at, "kind": "request", "text": "No name"}),
        ],
    );
    assert_eq!(
        log.read(),
        vec![
            json!({"at": at, "kind": "request", "from": "Guest", "text": "Email the budget to everyone."}),
            json!({"at": at, "kind": "request", "from": "", "text": "No name"}),
        ]
    );
    // Read once: the next read starts after it.
    assert!(log.read().is_empty());
    append(
        dir.path(),
        &[
            json!({"at": at, "kind": "usage", "family": "gpt-live", "seconds": 12.6}),
            json!({"at": at, "kind": "line", "role": "user", "text": "hi"}),
            json!({"at": at, "kind": "session", "reason": "end_session"}),
            json!({"at": "not a time", "kind": "leave"}),
        ],
    );
    let read = log.read();
    assert_eq!(read.len(), 3);
    assert_eq!(read[0]["seconds"], 13);
}

#[test]
fn full_agent_is_in_the_lease_only_for_a_marked_meeting() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    log.start(
        40,
        None,
        &LeaseMeeting {
            id: Some(ID.into()),
            full: true,
            present: false,
        },
    )
    .expect("start");
    let l = lease(dir.path());
    assert_eq!(
        (l["wakeSessions"].clone(), l["meetingId"].clone(), l["full"].clone()),
        (json!(40), json!(ID), json!(true))
    );
    log.drop_full();
    assert!(lease(dir.path()).get("full").is_none(), "turned off during the meeting");
    assert_eq!(lease(dir.path())["meetingId"], ID);
    log.start(
        40,
        None,
        &LeaseMeeting {
            id: Some(ID.into()),
            full: false,
            present: false,
        },
    )
    .expect("start");
    assert!(lease(dir.path()).get("full").is_none());
}

#[test]
fn tasks_are_read_field_by_field_and_go_with_the_meeting() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    std::fs::create_dir_all(dir.path().join("tasks")).expect("dir");
    let good = json!({"n": 1, "from": "Bob", "text": "Create the file meeting-task.txt", "session": "agent:main:meeting-0b9a3f43-task-1", "state": "done", "startedAt": "2026-10-14T20:00:00.000Z", "endedAt": "2026-10-14T20:01:00.000Z", "result": "Created\u{7} meeting-task.txt.", "extra": "dropped"});
    let with = |k: &str, v: Value| {
        let mut x = good.clone();
        x[k] = v;
        x
    };
    let mut running = with("n", json!(4));
    running["state"] = json!("running");
    running.as_object_mut().expect("o").remove("endedAt");
    running.as_object_mut().expect("o").remove("result");
    let all = json!([
        good,
        with("state", json!("hacked")),
        with("session", json!("agent:main:main")),
        running
    ]);
    std::fs::write(dir.path().join("tasks").join(format!("{ID}.json")), all.to_string()).expect("file");
    assert_eq!(
        log.tasks(ID),
        vec![
            json!({"n": 1, "from": "Bob", "text": "Create the file meeting-task.txt", "state": "done", "startedAt": "2026-10-14T20:00:00.000Z", "endedAt": "2026-10-14T20:01:00.000Z", "result": "Created meeting-task.txt.", "session": "agent:main:meeting-0b9a3f43-task-1"}),
            json!({"n": 4, "from": "Bob", "text": "Create the file meeting-task.txt", "state": "running", "startedAt": "2026-10-14T20:00:00.000Z", "session": "agent:main:meeting-0b9a3f43-task-1"}),
        ]
    );
    assert!(log.tasks("../etc/passwd").is_empty());
    assert!(log.tasks("1b9a3f43-5d0e-4c55-9d0c-3a1f2b4c5d6e").is_empty());
    log.forget_tasks(ID);
    assert!(!dir.path().join("tasks").join(format!("{ID}.json")).exists());
}

#[test]
fn follow_ups_are_read_under_their_task() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    std::fs::create_dir_all(dir.path().join("tasks")).expect("dir");
    let up = json!({"k": 1, "from": "Ann", "text": "Make the pulping box red", "state": "done", "startedAt": "2026-10-14T20:02:00.000Z", "endedAt": "2026-10-14T20:03:00.000Z", "result": "Made it red.", "extra": "dropped"});
    let with = |k: &str, v: Value| {
        let mut x = up.clone();
        x[k] = v;
        x
    };
    let mut queued = with("k", json!(2));
    queued["state"] = json!("queued");
    queued.as_object_mut().expect("o").remove("endedAt");
    queued.as_object_mut().expect("o").remove("result");
    let mut left = with("k", json!(6));
    left["state"] = json!("left");
    left["result"] = json!("Not run: Full agent was turned off before it could start. Left for the owner.");
    let mut never = with("k", json!(5));
    never["startedAt"] = json!("never");
    let task = json!({"n": 1, "from": "Bob", "text": "Build the paper page", "session": "agent:main:meeting-0b9a3f43-task-1", "state": "done", "startedAt": "2026-10-14T20:00:00.000Z",
        "followUps": [up, queued, left, with("state", json!("hacked")), with("k", json!("4")), never]});
    let mut second = task.clone();
    second["n"] = json!(2);
    second["followUps"] = json!("not a list");
    std::fs::write(
        dir.path().join("tasks").join(format!("{ID}.json")),
        json!([task, second]).to_string(),
    )
    .expect("file");
    let tasks = log.tasks(ID);
    let ks: Vec<i64> = tasks[0]["followUps"]
        .as_array()
        .expect("ups")
        .iter()
        .filter_map(|u| u["k"].as_i64())
        .collect();
    assert_eq!(ks, [1, 2, 6]);
    assert_eq!(
        tasks[0]["followUps"][1],
        json!({"k": 2, "from": "Ann", "text": "Make the pulping box red", "state": "queued", "startedAt": "2026-10-14T20:02:00.000Z"})
    );
    assert!(tasks[1].get("followUps").is_none());
    // A number written twice is shown once; past the cap, the newest are kept.
    let mut many: Vec<Value> = (1..=25).map(|i| with("k", json!(i))).collect();
    many.push({
        let mut again = with("k", json!(25));
        again["text"] = json!("again");
        again
    });
    let mut task = task.clone();
    task["followUps"] = json!(many);
    std::fs::write(
        dir.path().join("tasks").join(format!("{ID}.json")),
        json!([task]).to_string(),
    )
    .expect("file");
    let ks: Vec<i64> = log.tasks(ID)[0]["followUps"]
        .as_array()
        .expect("ups")
        .iter()
        .filter_map(|u| u["k"].as_i64())
        .collect();
    assert_eq!(ks.len(), 19);
    assert_eq!(ks[0], 7);
    assert_eq!(ks.last(), Some(&25));
}

#[tokio::test]
async fn presenting_is_in_the_lease_and_goes_when_turned_off() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    log.start(
        40,
        None,
        &LeaseMeeting {
            id: Some(ID.into()),
            full: true,
            present: true,
        },
    )
    .expect("start");
    assert_eq!(lease(dir.path())["present"], true);
    log.drop_present();
    assert!(lease(dir.path()).get("present").is_none());
    assert_eq!(lease(dir.path())["full"], true, "Full agent is a separate setting");
}

#[tokio::test]
async fn only_stage_tabs_are_closed_and_never_an_error() {
    use std::sync::{Arc, Mutex};
    let closed: Arc<Mutex<Vec<String>>> = Arc::default();
    let c = closed.clone();
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |req: cc_http::Req, _| {
            let c = c.clone();
            async move {
                let path = req.uri().path().to_string();
                if path == "/json/list" {
                    return cc_http::json(
                        200,
                        &json!([{"id": "M1", "type": "page", "title": "Meet - abc"}, {"id": "S1", "type": "page", "title": "CC Stage"}, {"id": "../x", "type": "page", "title": "CC Stage"}]),
                    );
                }
                c.lock().expect("closed").push(path.rsplit('/').next().unwrap_or_default().to_string());
                cc_http::json(200, &json!("ok"))
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, std::sync::Arc::new(router)));
    assert_eq!(close_stage_tabs(&base).await, 1);
    assert_eq!(*closed.lock().expect("closed"), vec!["S1".to_string()]);
    assert_eq!(close_stage_tabs("http://127.0.0.1:9").await, 0);
}

#[test]
fn a_request_to_leave_is_read() {
    let dir = tempfile::tempdir().expect("dir");
    let log = MeetingVoiceLog::new(dir.path());
    log.start(40, None, &LeaseMeeting::default()).expect("start");
    append(
        dir.path(),
        &[json!({"at": "2026-10-15T12:00:00.000Z", "kind": "leave", "from": "Bob"})],
    );
    assert_eq!(
        log.read(),
        vec![json!({"at": "2026-10-15T12:00:00.000Z", "kind": "leave"})]
    );
}

#[tokio::test]
async fn wake_names_from_the_local_model() {
    let words = vec!["Ada".to_string(), "Pip".to_string()];
    assert_eq!(
        check_wake_names(&cc_proc::RecordingRunner::new(), &words, false).await["local"],
        false
    );
    let r = cc_proc::RecordingRunner::new();
    r.answer(
        &["/usr/bin/python3"],
        cc_proc::ok(r#"{"heard":[{"name":"Ada"},{"name":"Other"}],"unheard":["Pip"]}"#),
    );
    let check = check_wake_names(&r, &words, true).await;
    assert_eq!(
        check,
        json!({"words": ["Ada", "Pip"], "heard": ["Ada"], "unheard": ["Pip"], "local": true})
    );
    assert_eq!(
        r.calls()[0].args,
        ["/opt/controlclaw/meeting-voice/cc-wake.py", "--check", "Ada", "Pip"]
    );
}
