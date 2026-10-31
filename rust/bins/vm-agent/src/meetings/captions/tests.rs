//! `meeting-captions.test.ts`, with a fake loopback debugger.

use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::*;

fn ok_row() -> Value {
    json!({"seq": 2, "id": "d1-b1.0", "rev": 1, "speaker": "Alice", "self": false, "text": "Hello", "final": true, "at": 1})
}

#[test]
fn rows_from_the_page_are_checked_and_bounded() {
    let with = |k: &str, v: Value| {
        let mut r = ok_row();
        r[k] = v;
        r
    };
    let mut three = with("seq", json!(3));
    three["id"] = json!("d1-b2.0");
    let mut long = with("speaker", json!("A".repeat(200)));
    long["seq"] = json!(9);
    let rows = parse_caption_events(&json!([
        three,
        ok_row(),
        with("id", json!("x")),
        with("text", json!("")),
        with("seq", json!(1.5)),
        null,
        "row",
        long
    ]));
    assert_eq!(rows.iter().map(|r| r.seq).collect::<Vec<_>>(), [2, 3, 9]);
    assert_eq!(rows[2].speaker.len(), 80);
    assert!(parse_caption_events(&json!({"seq": 1})).is_empty());
    assert!(caption_script().contains("__ccCap"));
    assert!(mic_script().contains("echoCancellation"));
}

#[test]
fn final_lines_go_to_captions_jsonl_emptied_when_a_meeting_starts() {
    let dir = tempfile::tempdir().expect("dir");
    let c = CaptionContext::new(dir.path());
    c.start().expect("start");
    c.add(&[(
        "2026-10-07T10:00:00.000Z".into(),
        "Alice".into(),
        "Launch moved to Thursday.".into(),
    )]);
    c.add(&[]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("captions.jsonl")).expect("f"),
        "{\"at\":\"2026-10-07T10:00:00.000Z\",\"speaker\":\"Alice\",\"text\":\"Launch moved to Thursday.\"}\n"
    );
    c.start().expect("start");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("captions.jsonl")).expect("f"),
        ""
    );
    c.end();
    assert!(!dir.path().join("captions.jsonl").exists());
}

#[test]
fn rows_reach_the_voice_adapter_as_they_arrive() {
    let dir = tempfile::tempdir().expect("dir");
    let c = CaptionContext::new(dir.path());
    c.start().expect("start");
    let at = crate::phone::history::parse_iso("2026-10-07T13:37:20.000Z").expect("t");
    let row = |id: &str, text: &str, is_final: bool, own: bool| CaptionEvent {
        seq: 1,
        id: id.into(),
        rev: 1,
        speaker: if own { "You".into() } else { "Ada Owner".into() },
        own,
        text: text.into(),
        is_final,
        at,
    };
    let live = || -> Vec<String> {
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("captions-live.json")).expect("f"))
                .expect("j");
        v["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .filter_map(|r| r["text"].as_str().map(String::from))
            .collect()
    };
    let first = "Hi, hello. We are here to determine the team's favorite snack. Leabot, what do";
    let full = "Hi, hello. We are here to determine the team's favorite snack. Leabot, what do you think?";
    c.rows(&[row("d1-b1.0", first, false, false)]);
    assert_eq!(live(), [first]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("captions.jsonl")).expect("f"),
        ""
    );
    c.rows(&[
        row("d1-b1.0", full, false, false),
        row("d1-b2.0", "I'm not sure.", false, true),
    ]);
    assert_eq!(live().len(), 1, "the agent's own captioned speech is left out");
    c.rows(&[row("d1-b1.0", full, true, false)]);
    assert!(live().is_empty());
    let done = std::fs::read_to_string(dir.path().join("captions.jsonl")).expect("f");
    assert!(done.contains("\"speaker\":\"Ada Owner\",\"text\":\"Hi, hello.") && done.contains("what do you think?"));
    c.end();
    assert!(!dir.path().join("captions-live.json").exists());
}

/// A fake debugger: `/json/list` over HTTP, and a page socket that answers every command (a
/// `flush` with one row) and records what was sent. The test pushes events through `push`.
struct Debugger {
    base: String,
    sent: Arc<Mutex<Vec<Value>>>,
    push: mpsc::UnboundedSender<Value>,
}

async fn debugger(targets: impl Fn(u16) -> Value + Send + Sync + 'static) -> Debugger {
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let ws_port = ws_listener.local_addr().expect("addr").port();
    let sent: Arc<Mutex<Vec<Value>>> = Arc::default();
    let (push, mut pushed) = mpsc::unbounded_channel::<Value>();
    let s = sent.clone();
    tokio::spawn(async move {
        let Ok((tcp, _)) = ws_listener.accept().await else {
            return;
        };
        let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else {
            return;
        };
        let (mut sink, mut stream) = ws.split();
        loop {
            tokio::select! {
                m = stream.next() => {
                    let Some(Ok(Message::Text(t))) = m else { return };
                    let msg: Value = serde_json::from_str(t.as_str()).expect("json");
                    s.lock().expect("sent").push(msg.clone());
                    let flush = msg["params"]["expression"].as_str().is_some_and(|e| e.contains("flush"));
                    let result = if flush {
                        json!({"result": {"value": json!([{"seq": 7, "id": "d1-b3.0", "rev": 2, "speaker": "Bob", "self": false, "text": "Last words.", "final": true, "at": 5}]).to_string()}})
                    } else { json!({}) };
                    let _ = sink.send(Message::text(json!({"id": msg["id"], "result": result}).to_string())).await;
                }
                e = pushed.recv() => {
                    match e {
                        Some(Value::Null) | None => { let _ = sink.send(Message::Close(None)).await; return; }
                        Some(e) => { let _ = sink.send(Message::text(e.to_string())).await; }
                    }
                }
            }
        }
    });
    let list = Arc::new(targets(ws_port));
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |_req, _| {
            let list = list.clone();
            async move { cc_http::json(200, &list) }
        },
    );
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", http.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(http, Arc::new(router)));
    Debugger { base, sent, push }
}

async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[tokio::test]
async fn the_tap_attaches_only_to_the_meetings_tab_and_reports_rows() {
    let d = debugger(|port| {
        json!([
            {"type": "page", "url": "https://meet.google.com/xyz-abcd-efg", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/OTHER")},
            {"type": "page", "url": "https://meet.google.com/abc-defg-hij?authuser=0", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/MEET")},
        ])
    })
    .await;
    let got: Arc<Mutex<Vec<CaptionEvent>>> = Arc::default();
    let g = got.clone();
    let tap = CaptionTap::with_debugger(
        "https://meet.google.com/abc-defg-hij",
        Arc::new(move |e| g.lock().expect("got").extend(e)),
        &d.base,
    );
    assert_eq!(tap.attach().await, Ok(true));
    // The last evaluate pulls what the page already holds.
    let methods: Vec<String> = d
        .sent
        .lock()
        .expect("s")
        .iter()
        .filter_map(|m| m["method"].as_str().map(String::from))
        .collect();
    assert_eq!(
        methods,
        [
            "Runtime.enable",
            "Runtime.addBinding",
            "Page.addScriptToEvaluateOnNewDocument",
            "Runtime.evaluate",
            "Runtime.evaluate"
        ]
    );
    assert!(
        d.sent.lock().expect("s").last().expect("m")["params"]["expression"]
            .as_str()
            .unwrap_or_default()
            .contains("since(")
    );
    let bind = |name: &str, payload: Value| json!({"method": "Runtime.bindingCalled", "params": {"name": name, "payload": payload.to_string()}});
    d.push.send(bind("__ccCap", json!([{"seq": 1, "id": "d1-b1.0", "rev": 1, "speaker": "Alice", "self": false, "text": "Hi all", "final": false, "at": 1}]))).expect("push");
    d.push.send(bind("other", json!([]))).expect("push");
    settle().await;
    assert_eq!(
        got.lock()
            .expect("g")
            .iter()
            .map(|e| e.text.clone())
            .collect::<Vec<_>>(),
        ["Hi all"]
    );
    tap.flush().await;
    assert_eq!(got.lock().expect("g").iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 7]);
    assert!(
        d.sent.lock().expect("s").last().expect("m")["params"]["expression"]
            .as_str()
            .unwrap_or_default()
            .contains(r#"flush(({"d1":1})[window.__ccCaps.doc]"#)
    );
    // The page reloaded: a new document numbers its rows from 1 again, under a new prefix.
    d.push.send(bind("__ccCap", json!([{"seq": 1, "id": "d2-b1.0", "rev": 1, "speaker": "Alice", "self": false, "text": "After the reload", "final": false, "at": 9}]))).expect("push");
    settle().await;
    assert_eq!(
        got.lock().expect("g").last().map(|e| e.text.clone()).as_deref(),
        Some("After the reload")
    );
    // The debugger connection dropped: no longer attached, so the next poll attaches again.
    assert!(tap.attached());
    d.push.send(Value::Null).expect("push");
    settle().await;
    assert!(!tap.attached());
    tap.close();
}

#[tokio::test]
async fn no_meet_tab_or_a_debugger_that_is_not_loopback_is_not_attached() {
    for targets in [
        json!([]),
        json!([{"type": "page", "url": "https://meet.google.com/abc-defg-hij", "webSocketDebuggerUrl": "ws://10.0.0.5:9223/devtools/page/X"}]),
    ] {
        let d = debugger(move |_| targets.clone()).await;
        let tap = CaptionTap::with_debugger("https://meet.google.com/abc-defg-hij", Arc::new(|_| {}), &d.base);
        assert_eq!(tap.attach().await, Ok(false));
    }
}

#[tokio::test]
async fn a_debugger_that_never_upgrades_does_not_hold_up_the_meeting() {
    // Takes the connection and says nothing.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = silent.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });
    let d = debugger(move |_| json!([{"type": "page", "url": "https://meet.google.com/abc-defg-hij", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/X")}])).await;
    let tap = CaptionTap::with_debugger("https://meet.google.com/abc-defg-hij", Arc::new(|_| {}), &d.base);
    let started = std::time::Instant::now();
    assert_eq!(tap.attach().await, Err("Caption tap timed out".into()));
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    assert!(!tap.attached());
}
