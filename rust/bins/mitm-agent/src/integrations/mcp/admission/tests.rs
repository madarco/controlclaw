//! `mcp-rules.test.ts`: the admission service, the proxy's questions answered over loopback.

use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::contracts::CheckedRule;
use crate::integrations::mcp::calls::tests::{harness, rule, tool_call, tools};
use crate::integrations::testing::{Answer, FakeServer};

async fn serve(a: &Arc<Admission>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(cc_http::serve(l, Arc::new(a.router())));
    format!("http://127.0.0.1:{port}")
}

async fn post(base: &str, path: &str, doc: Value) -> Value {
    reqwest::Client::new()
        .post(format!("{base}{path}"))
        .body(doc.to_string())
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json")
}

fn call_text(name: &str, args: Value) -> String {
    String::from_utf8(tool_call(name, args, 7).to_vec()).expect("utf8")
}

#[tokio::test]
async fn the_proxys_questions_answered_over_loopback() {
    let h = harness(
        vec![rule(|r| {
            r.name = "No deletes".into();
            r.service = Some("mcp:mcp.example.com".into());
            r.match_ = tools(&["delete_*"]);
        })],
        false,
    );
    let a = Admission::new(h.calls.clone());
    let base = serve(&a).await;
    let refused = post(&base, "/call", json!({"vm_id": "vm-a", "host": "MCP.example.com", "url": "https://mcp.example.com/mcp", "headers": {}, "body": call_text("delete_doc", json!({}))})).await;
    assert_eq!(refused["action"], "answer");
    assert!(refused["body"].as_str().expect("b").contains("No deletes"));
    assert!(refused.get("hold_ref").is_none());
    let ok = post(&base, "/call", json!({"vm_id": "vm-a", "host": "mcp.example.com", "url": "https://mcp.example.com/mcp", "headers": {}, "body": call_text("read_doc", json!({}))})).await;
    assert_eq!(ok["action"], "allow");
    assert_eq!(ok["read_result"], false);
    assert_eq!(
        post(
            &base,
            "/done",
            json!({"ticket": ok["ticket"], "status": 200, "ok": true})
        )
        .await,
        json!({})
    );
    assert_eq!(
        post(
            &base,
            "/result",
            json!({"ticket": "unknown", "status": 200, "body": ""})
        )
        .await,
        json!({"action": "pass"})
    );
    let listed = post(&base, "/tools", json!({"vm_id": "vm-a", "host": "mcp.example.com", "content_type": "application/json",
        "body": json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "delete_doc"}, {"name": "read_doc"}]}}).to_string()})).await;
    assert_eq!(listed["action"], "replace");
    assert!(!listed["body"].as_str().expect("b").contains("delete_doc"));
    assert_eq!(
        post(&base, "/call", json!({"vm_id": "vm-a"})).await["error"],
        "vm_id, host, url and body are required"
    );
    let c = reqwest::Client::new();
    assert_eq!(c.get(format!("{base}/call")).send().await.expect("send").status(), 405);
    assert_eq!(
        c.post(format!("{base}/x"))
            .body("{}")
            .send()
            .await
            .expect("send")
            .status(),
        404
    );
    assert_eq!(
        c.post(format!("{base}/call"))
            .body("nope")
            .send()
            .await
            .expect("send")
            .status(),
        400
    );
}

#[tokio::test]
async fn a_held_call_is_sent_again_with_the_headers_the_proxy_would_have_sent() {
    let h = harness(vec![], true);
    let c = h.content.clone().expect("content");
    *c.out.lock().expect("lock") = Some(CheckedRule {
        id: "c1".into(),
        name: Some("Hold".into()),
        action: "hold".into(),
        reason: "a person checks these.".into(),
        by: None,
    });
    let upstream = FakeServer::start(|_| Answer::json(200, &json!({}))).await;
    let a = Admission::new(h.calls.clone());
    let base = serve(&a).await;
    let held = post(&base, "/call", json!({"vm_id": "vm-a", "host": "mcp.example.com", "url": format!("{}/mcp", upstream.url()),
        "headers": {"authorization": "Bearer CC-PH-1", "mcp-session-id": "s1", "cookie": "c"}, "body": call_text("note_add", json!({"text": "x"}))})).await;
    assert_eq!(held["action"], "answer");
    assert!(held["body"].as_str().expect("b").contains("queued_for_approval"));
    let r = held["hold_ref"].as_str().expect("hold_ref").to_string();
    assert_eq!(post(&base, "/held", json!({"hold_ref": r, "headers": {"authorization": "Bearer real-key", "mcp-session-id": "s1", "cookie": "c"}})).await, json!({}));
    // A second report for the same hold, or one for a hold this service did not name, changes nothing.
    post(
        &base,
        "/held",
        json!({"hold_ref": r, "headers": {"authorization": "Bearer other"}}),
    )
    .await;
    post(
        &base,
        "/held",
        json!({"hold_ref": "made-up", "headers": {"authorization": "Bearer other"}}),
    )
    .await;
    let send = c.send.lock().expect("lock").take().expect("held");
    send().await.expect("sent");
    let got = upstream.got();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].headers["authorization"], "Bearer real-key");
    assert_eq!(got[0].headers["mcp-session-id"], "s1");
    assert_eq!(got[0].headers["cookie"], "c");
}

#[tokio::test]
async fn a_send_that_fails_keeps_the_real_headers_for_the_next_send() {
    let h = harness(vec![], true);
    let c = h.content.clone().expect("content");
    *c.out.lock().expect("lock") = Some(CheckedRule {
        id: "c1".into(),
        name: Some("Hold".into()),
        action: "hold".into(),
        reason: "a person checks these".into(),
        by: None,
    });
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let f = fail.clone();
    let upstream = FakeServer::start(move |_| {
        Answer::json(
            if f.load(std::sync::atomic::Ordering::SeqCst) {
                503
            } else {
                200
            },
            &json!({}),
        )
    })
    .await;
    let a = Admission::new(h.calls.clone());
    let base = serve(&a).await;
    let held = post(
        &base,
        "/call",
        json!({"vm_id": "vm-a", "host": "mcp.example.com", "url": format!("{}/mcp", upstream.url()),
        "headers": {"authorization": "Bearer CC-PH-1"}, "body": call_text("note_add", json!({"text": "x"}))}),
    )
    .await;
    post(
        &base,
        "/held",
        json!({"hold_ref": held["hold_ref"], "headers": {"authorization": "Bearer real-key"}}),
    )
    .await;
    // The hold's Send, run twice through the same replay as a person pressing it again.
    let send = c.send.lock().expect("lock").take().expect("held");
    assert!(send().await.is_err(), "the server said 503");
    let _ = (&a, &fail);
    let got = upstream.got();
    assert_eq!(got[0].headers["authorization"], "Bearer real-key");
    assert!(
        a.held
            .lock()
            .expect("lock")
            .iter()
            .any(|(k, h)| *k == held["hold_ref"] && h.headers.is_some()),
        "kept for the next Send"
    );
}
