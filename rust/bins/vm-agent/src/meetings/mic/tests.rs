//! `meeting-mic.test.ts`, with a fake browser debugger (the real-Chrome cases stay on the TS side).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::*;

/// The browser: `/json/version` names a socket that answers every command (unless `mute`), records
/// what was sent, and takes events to push. Each new connection is counted.
struct Browser {
    base: String,
    sent: Arc<Mutex<Vec<Value>>>,
    push: Arc<Mutex<Option<mpsc::UnboundedSender<Value>>>>,
    connects: Arc<AtomicUsize>,
}

async fn browser(version: impl Fn(u16) -> Value + Send + Sync + 'static, mute: bool) -> Browser {
    let ws = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = ws.local_addr().expect("addr").port();
    let sent: Arc<Mutex<Vec<Value>>> = Arc::default();
    let push: Arc<Mutex<Option<mpsc::UnboundedSender<Value>>>> = Arc::default();
    let connects = Arc::new(AtomicUsize::new(0));
    let (s, p, c) = (sent.clone(), push.clone(), connects.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ws.accept().await {
            let Ok(sock) = tokio_tungstenite::accept_async(tcp).await else {
                continue;
            };
            c.fetch_add(1, Ordering::SeqCst);
            let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
            *p.lock().expect("push") = Some(tx);
            let s = s.clone();
            tokio::spawn(async move {
                let (mut sink, mut stream) = sock.split();
                loop {
                    tokio::select! {
                        m = stream.next() => {
                            let Some(Ok(Message::Text(t))) = m else { return };
                            let msg: Value = serde_json::from_str(t.as_str()).expect("json");
                            s.lock().expect("sent").push(msg.clone());
                            // A target named ERR has its commands refused.
                            let answer = if msg["sessionId"] == "ERR" {
                                json!({"id": msg["id"], "error": {"code": -32000, "message": "refused"}})
                            } else {
                                json!({"id": msg["id"], "result": {}})
                            };
                            if !mute {
                                let _ = sink.send(Message::text(answer.to_string())).await;
                            }
                        }
                        e = rx.recv() => match e {
                            Some(Value::Null) | None => { let _ = sink.send(Message::Close(None)).await; return; }
                            Some(e) => { let _ = sink.send(Message::text(e.to_string())).await; }
                        }
                    }
                }
            });
        }
    });
    let v = Arc::new(version(port));
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |_req, _| {
            let v = v.clone();
            async move { cc_http::json(200, &v) }
        },
    );
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", http.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(http, Arc::new(router)));
    Browser {
        base,
        sent,
        push,
        connects,
    }
}

fn loopback(port: u16) -> Value {
    json!({"webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/browser/X")})
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(60)).await;
}

fn methods(b: &Browser) -> Vec<(String, Option<String>)> {
    b.sent
        .lock()
        .expect("sent")
        .iter()
        .map(|m| {
            (
                m["method"].as_str().unwrap_or_default().to_string(),
                m["sessionId"].as_str().map(String::from),
            )
        })
        .collect()
}

#[tokio::test]
async fn every_page_is_set_up_before_it_runs() {
    let b = browser(loopback, false).await;
    let mic = MeetingMic::with(&b.base, Duration::from_millis(10));
    mic.start().await.expect("start");
    assert_eq!(methods(&b), [("Target.setAutoAttach".to_string(), None)]);
    assert_eq!(
        b.sent.lock().expect("s")[0]["params"],
        json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true})
    );
    b.sent.lock().expect("s").clear();
    let push = b.push.lock().expect("p").clone().expect("socket");
    push.send(json!({"method": "Target.attachedToTarget", "params": {"sessionId": "S1", "targetInfo": {"type": "page", "url": "https://meet.google.com/abc-defg-hij"}, "waitingForDebugger": true}})).expect("push");
    settle().await;
    let s1 = Some("S1".to_string());
    assert_eq!(
        methods(&b),
        [
            ("Page.enable".to_string(), s1.clone()),
            ("Page.addScriptToEvaluateOnNewDocument".to_string(), s1.clone()),
            ("Target.setAutoAttach".to_string(), s1.clone()),
            ("Runtime.runIfWaitingForDebugger".to_string(), s1)
        ]
    );
    assert_eq!(b.sent.lock().expect("s")[1]["params"]["source"], mic_script());
    b.sent.lock().expect("s").clear();
    // A worker is resumed without a script.
    push.send(
        json!({"method": "Target.attachedToTarget", "params": {"sessionId": "S2", "targetInfo": {"type": "worker"}}}),
    )
    .expect("push");
    settle().await;
    let names: Vec<String> = methods(&b).into_iter().map(|m| m.0).collect();
    assert_eq!(names, ["Target.setAutoAttach", "Runtime.runIfWaitingForDebugger"]);
    mic.close();
}

#[tokio::test]
async fn an_error_answer_resumes_the_page_and_two_starts_connect_once() {
    let b = browser(loopback, false).await;
    let mic = MeetingMic::with(&b.base, Duration::from_millis(10));
    let (a, c) = tokio::join!(mic.start(), mic.start());
    assert_eq!((a, c), (Ok(()), Ok(())));
    assert_eq!(b.connects.load(Ordering::SeqCst), 1);
    b.sent.lock().expect("s").clear();
    let push = b.push.lock().expect("p").clone().expect("socket");
    push.send(
        json!({"method": "Target.attachedToTarget", "params": {"sessionId": "ERR", "targetInfo": {"type": "page"}}}),
    )
    .expect("push");
    settle().await;
    let names: Vec<String> = methods(&b).into_iter().map(|m| m.0).collect();
    assert_eq!(
        names,
        [
            "Page.enable",
            "Page.addScriptToEvaluateOnNewDocument",
            "Target.setAutoAttach",
            "Runtime.runIfWaitingForDebugger"
        ]
    );
    mic.close();
}

#[tokio::test]
async fn only_the_loopback_debugger_and_a_dropped_connection_is_opened_again() {
    let wrong = browser(
        |_| json!({"webSocketDebuggerUrl": "ws://10.0.0.5:9223/devtools/browser/X"}),
        false,
    )
    .await;
    assert_eq!(
        MeetingMic::with(&wrong.base, Duration::from_millis(10)).start().await,
        Err("Meeting browser debugger not found".into())
    );
    // A debugger that never answers the setup is reported, not waited on forever.
    let mute = browser(loopback, true).await;
    let m = MeetingMic::with(&mute.base, Duration::from_millis(10));
    assert_eq!(m.start().await, Err("Meeting browser debugger did not answer".into()));
    m.close();
    let b = browser(loopback, false).await;
    let mic = MeetingMic::with(&b.base, Duration::from_millis(10));
    mic.start().await.expect("start");
    b.push
        .lock()
        .expect("p")
        .clone()
        .expect("socket")
        .send(Value::Null)
        .expect("drop");
    settle().await;
    settle().await;
    assert_eq!(b.connects.load(Ordering::SeqCst), 2);
    assert!(mic.connected());
    mic.close();
    assert!(!mic.connected());
}
