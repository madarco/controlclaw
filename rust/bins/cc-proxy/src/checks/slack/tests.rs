//! Ported from test_content_rules_channels.py (Slack out, Socket Mode, the SDK's real shapes) and
//! test_content_policies.py (Slack in).

use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::checks::testkit::{Answer, Rig, rule};
use crate::flow::testing::request_flow;

const IBAN: &str = "GB82 WEST 1234 5698 7654 32";

fn rules(rig: &Rig) {
    rig.write_rules(json!([
        rule(
            "cust",
            "block",
            "out",
            &["customer list"],
            &[],
            &["slack", "email", "web"]
        ),
        rule("pay", "hold", "out", &[], &["iban"], &["slack", "email", "web"]),
        rule("watch", "log", "out", &["budget"], &[], &["slack", "email", "web"]),
        rule("salary", "block", "in", &["salary"], &[], &["slack", "email"]),
    ]));
}

fn call(host: &str, path: &str, verb: &str, body: &str, ctype: &str) -> Flow {
    let mut f = request_flow(verb, &format!("https://{host}{path}"), b"");
    let mut b = http::Request::builder()
        .method(verb)
        .uri(format!("https://{host}{path}"))
        .header("authorization", "Bearer __cc_slack_bot_conn1");
    if !ctype.is_empty() {
        b = b.header("content-type", ctype);
    }
    f.request = b.body(Bytes::from(body.to_owned())).ok();
    f.vm_id = Some("vm1".into());
    f.meta.insert(crate::checks::META_BODY_DECODED, json!(true));
    f
}

fn api(method: &str, body: Value) -> Flow {
    call(
        "slack.com",
        &format!("/api/{method}"),
        "POST",
        &pyjson::dumps(&body),
        "application/json",
    )
}

fn form(method: &str, body: &str) -> Flow {
    call(
        "slack.com",
        &format!("/api/{method}"),
        "POST",
        body,
        "application/x-www-form-urlencoded",
    )
}

async fn out(rig: &Rig, f: &mut Flow) -> Option<Value> {
    match SlackOut(rig.content.clone()).run(Hook::Request, f).await {
        Verdict::Continue => None,
        Verdict::Answer(r) => {
            assert_eq!(r.status(), 200, "Slack answers its errors with 200");
            Some(serde_json::from_slice(r.body()).unwrap_or(Value::Null))
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn message(doc: &Option<Value>) -> String {
    doc.as_ref()
        .and_then(|d| d["response_metadata"]["messages"][0].as_str())
        .unwrap_or("")
        .to_owned()
}

#[tokio::test]
async fn slack_out() {
    let rig = Rig::new().await;
    rules(&rig);
    assert!(
        out(
            &rig,
            &mut api("chat.postMessage", json!({"channel": "C1", "text": "hello"}))
        )
        .await
        .is_none()
    );
    let doc = out(
        &rig,
        &mut api(
            "chat.postMessage",
            json!({"channel": "C1", "text": "the customer list", "thread_ts": "1700000000.000100"}),
        ),
    )
    .await;
    assert_eq!(
        doc.as_ref().map(|d| (d["ok"].clone(), d["error"].clone())),
        Some((json!(false), json!("blocked_by_organization_rules")))
    );
    assert!(message(&doc).contains("cust reason"));
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice").pop(),
        Some(
            json!({"kind": "out", "channel": "slack", "chatId": "C1", "auth": "__cc_slack_bot_conn1", "vmId": "vm1", "reason": "cust reason", "threadTs": "1700000000.000100"})
        )
    );
    assert_eq!(
        rig.audit().pop().map(|a| (a["channel"].clone(), a["rule"].clone())),
        Some((json!("slack"), json!("cust")))
    );

    // The firewall's own code message goes while the marker is fresh.
    rig.write_file(
        "content-own.json",
        &format!(r#"{{"until": {}}}"#, crate::checks::content::rules::now() + 600.0),
    );
    rig.agent.answer("/own", Answer::json(200, json!({"rest": "\n"})));
    assert!(
        out(
            &rig,
            &mut api(
                "chat.postMessage",
                json!({"channel": "D1", "text": "```\nCode: 123 456 for the customer list rule\n```"})
            )
        )
        .await
        .is_none()
    );
    rig.agent
        .answer("/own", Answer::json(200, json!({"rest": "\nthe customer list"})));
    assert!(out(&rig, &mut api("chat.postMessage", json!({"channel": "D1", "text": "```\nCode: 123 456 for the customer list rule\n```\nthe customer list"}))).await.is_some());
    rig.write_file("content-own.json", r#"{"until": 0}"#);

    // Blocks, attachments as JSON in a form, the core rule.
    assert!(out(&rig, &mut api("chat.postMessage", json!({"channel": "C1", "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "see the customer list"}}]}))).await.is_some());
    let att = pyjson::dumps(&json!([{"fallback": "x", "fields": [{"title": "t", "value": "customer list"}]}]))
        .replace(' ', "+");
    assert!(
        out(
            &rig,
            &mut form("chat.postMessage", &format!("channel=C1&attachments={att}"))
        )
        .await
        .is_some()
    );
    let doc = out(
        &rig,
        &mut api(
            "chat.postMessage",
            json!({"channel": "C1", "text": "xoxb-1234567890-abcdefghij"}),
        ),
    )
    .await;
    assert!(message(&doc).contains("password, key or token"));
    // Reads pass; an odd path is refused.
    assert!(
        out(
            &rig,
            &mut call("slack.com", "/api/conversations.history?channel=C1", "GET", "", "")
        )
        .await
        .is_none()
    );
    assert!(
        out(&rig, &mut form("oauth.v2.access", "code=abc&client_id=1"))
            .await
            .is_none(),
        "a method name with digits"
    );
    assert!(
        out(
            &rig,
            &mut form("files.upload", "channels=C1&filetype=text&content=the+customer+list")
        )
        .await
        .is_some()
    );
    assert!(
        message(
            &out(
                &rig,
                &mut api("chat.postMessage/", json!({"channel": "C1", "text": "x"}))
            )
            .await
        )
        .contains("could not be checked")
    );

    // Hold: told it went, the body handed over as it was.
    rig.agent.answer(
        "/hold",
        Answer::json(200, json!({"ok": true, "holdId": "h1", "messageId": 1})),
    );
    let body = format!(
        "channel=C1&text=IBAN+{}&token=__cc_slack_bot_conn1",
        IBAN.replace(' ', "+")
    );
    let doc = out(&rig, &mut form("chat.postMessage", &body)).await.expect("held");
    assert_eq!((doc["ok"].clone(), doc["channel"].clone()), (json!(true), json!("C1")));
    assert!(doc["message"]["text"].as_str().is_some_and(|t| t.starts_with("IBAN")));
    let hold = rig.agent.calls("/hold").pop().unwrap_or_default();
    assert_eq!(
        (
            hold["channel"].as_str(),
            hold["method"].as_str(),
            hold["contentType"].as_str()
        ),
        (Some("slack"), Some("chat.postMessage"), Some("form"))
    );
    assert_eq!(
        (
            hold["chatId"].as_str(),
            hold["auth"].as_str(),
            hold["vmId"].as_str(),
            hold["body"].as_str()
        ),
        (
            Some("C1"),
            Some("__cc_slack_bot_conn1"),
            Some("vm1"),
            Some(body.as_str())
        )
    );
    assert_eq!(rig.audit().pop().map(|a| a["action"].clone()), Some(json!("hold")));
    assert!(
        message(
            &out(
                &rig,
                &mut api(
                    "chat.scheduleMessage",
                    json!({"channel": "C1", "text": format!("IBAN {IBAN}"), "post_at": 1})
                )
            )
            .await
        )
        .contains("could not be held")
    );
    rig.agent.answer("/hold", Answer::json(200, json!({"ok": false})));
    assert!(
        message(
            &out(
                &rig,
                &mut api(
                    "chat.postMessage",
                    json!({"channel": "C1", "text": format!("IBAN {IBAN}")})
                )
            )
            .await
        )
        .contains("nobody could be asked")
    );
    // An edit is held with its ts.
    rig.agent
        .answer("/hold", Answer::json(200, json!({"ok": true, "holdId": "h2"})));
    let doc = out(
        &rig,
        &mut api(
            "chat.update",
            json!({"channel": "C0123ABCD", "ts": "1792578000.123456", "text": format!("IBAN {IBAN}")}),
        ),
    )
    .await
    .expect("held");
    assert_eq!(
        (doc["ts"].as_str(), doc["text"].as_str()),
        (Some("1792578000.123456"), Some(&*format!("IBAN {IBAN}")))
    );

    // Incoming webhooks are Slack too.
    let mut f = call(
        "hooks.slack.com",
        "/services/T/B/x",
        "POST",
        r#"{"text": "the customer list"}"#,
        "application/json",
    );
    assert!(is_slack_out_flow(&f) && out(&rig, &mut f).await.is_some());
    // files.slack.com is not the API.
    assert!(!is_slack_out_flow(&call(
        "files.slack.com",
        "/upload/v1/abc",
        "POST",
        "x",
        "text/csv"
    )));
}

#[tokio::test]
async fn slack_out_as_the_sdk_sends_it() {
    let rig = Rig::new().await;
    rules(&rig);
    let blocks = pyjson::dumps(
        &json!([{"type": "rich_text", "block_id": "b1", "elements": [{"type": "rich_text_section", "elements": [
        {"type": "text", "text": "Here is the "}, {"type": "text", "text": "customer list", "style": {"bold": true}}]}]}]),
    );
    let sdk = format!(
        "channel=C0123ABCD&text=fallback&thread_ts=1792578000.123456&unfurl_links=false&blocks={}",
        enc(&blocks)
    );
    assert!(
        out(&rig, &mut form("chat.postMessage", &sdk)).await.is_some(),
        "rich_text inside blocks, form-encoded"
    );
    assert!(
        out(
            &rig,
            &mut form("files.getUploadURLExternal", "filename=list.csv&length=120")
        )
        .await
        .is_none()
    );
    let files = pyjson::dumps(&json!([{"id": "F1", "title": "the customer list"}]));
    assert!(
        out(
            &rig,
            &mut form(
                "files.completeUploadExternal",
                &format!("files={}&channel_id=C0123ABCD", enc(&files))
            )
        )
        .await
        .is_some()
    );
    let files = pyjson::dumps(&json!([{"id": "F1", "title": "report"}]));
    let b = format!(
        "files={}&channel_id=C0123ABCD&initial_comment={}",
        enc(&files),
        enc("key xoxp-1234567890-abcdefghij")
    );
    assert!(out(&rig, &mut form("files.completeUploadExternal", &b)).await.is_some());
    assert!(
        out(
            &rig,
            &mut call(
                "slack.com",
                "/api/conversations.replies?channel=C0123ABCD&ts=1792578000.123456",
                "GET",
                "",
                ""
            )
        )
        .await
        .is_none()
    );
    // Unknown rules: refused; a read with no text is not.
    rig.write_file("content-rules.json", "{");
    assert!(
        message(
            &out(
                &rig,
                &mut api("chat.postMessage", json!({"channel": "C1", "text": "hello"}))
            )
            .await
        )
        .contains("could not run")
    );
    assert!(
        out(&rig, &mut call("slack.com", "/api/auth.test", "GET", "", ""))
            .await
            .is_none()
    );
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else if b == b' ' {
                "+".into()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// ---- Socket Mode ----

async fn frame(rig: &Rig, doc: Value, direction: Direction) -> (bool, Vec<String>) {
    let mut f = request_flow("GET", "https://wss-primary.slack.com/link", b"");
    f.vm_id = Some("vm1".into());
    f.ws_frame = Some(WsFrame {
        direction,
        kind: FrameKind::Text,
        payload: Bytes::from(pyjson::dumps(&doc)),
    });
    let v = SlackSocket(rig.content.clone()).run(Hook::WsFrame, &mut f).await;
    let acks = f
        .inject
        .iter()
        .map(|w| String::from_utf8_lossy(&w.payload).into_owned())
        .collect();
    (matches!(v, Verdict::Drop), acks)
}

#[tokio::test]
async fn socket_mode() {
    let rig = Rig::new().await;
    rules(&rig);
    let ev = |id: &str, text: &str| json!({"envelope_id": id, "type": "events_api", "payload": {"event": {"type": "message", "channel": "C1", "user": "U1", "text": text}}});
    assert_eq!(frame(&rig, ev("e1", "hello"), Direction::In).await, (false, vec![]));
    assert_eq!(
        frame(&rig, ev("e2", "my salary is"), Direction::In).await,
        (true, vec![r#"{"envelope_id": "e2"}"#.to_owned()])
    );
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice").pop(),
        Some(
            json!({"kind": "in", "channel": "slack", "chatId": "C1", "userId": "U1", "vmId": "vm1", "reason": "salary reason"})
        )
    );
    let slash = json!({"envelope_id": "e3", "type": "slash_commands", "payload": {"command": "/ask", "text": "salary please", "channel_id": "C2", "user_id": "U2"}});
    assert!(frame(&rig, slash, Direction::In).await.0);
    let edited = json!({"envelope_id": "e4", "type": "events_api", "payload": {"event": {"type": "message", "subtype": "message_changed", "channel": "C1", "message": {"text": "salary now"}}}});
    assert!(
        frame(&rig, edited, Direction::In).await.0,
        "an edited message is read too"
    );
    assert!(
        !frame(&rig, ev("e5", &format!("sk-proj-{}", "A".repeat(40))), Direction::In)
            .await
            .0,
        "a person may send a key"
    );
    assert!(
        !frame(&rig, json!({"envelope_id": "e6", "type": "hello"}), Direction::In)
            .await
            .0
    );
    assert!(
        !frame(&rig, json!({"envelope_id": "e7", "text": "salary"}), Direction::Out)
            .await
            .0,
        "the agent's own frames pass"
    );
    let files = json!({"envelope_id": "e9", "payload": {"event": {"type": "message", "channel_type": "im", "user": "U1", "channel": "D1",
        "files": [{"id": "F1", "name": "salary review.pdf", "title": "salary review.pdf"}], "text": ""}}, "type": "events_api"});
    assert!(frame(&rig, files, Direction::In).await.0, "a file's title");
    assert!(
        !frame(
            &rig,
            json!({"type": "disconnect", "reason": "refresh_requested"}),
            Direction::In
        )
        .await
        .0
    );
    let buttons = json!({"envelope_id": "e10", "payload": {"type": "block_actions", "actions": [{"value": "salary review"}]}, "type": "interactive"});
    assert!(
        !frame(&rig, buttons, Direction::In).await.0,
        "a button's value is the agent's own wording, not read"
    );
    // A frame serde would refuse (a lone surrogate) is still read, as Python reads it.
    let mut f = request_flow("GET", "https://wss-primary.slack.com/link", b"");
    let raw = r#"{"envelope_id": "e12", "type": "events_api", "payload": {"event": {"type": "message", "text": "salary \ud83d"}}}"#;
    f.ws_frame = Some(WsFrame {
        direction: Direction::In,
        kind: FrameKind::Text,
        payload: Bytes::from(raw),
    });
    let v = SlackSocket(rig.content.clone()).run(Hook::WsFrame, &mut f).await;
    assert!(matches!(v, Verdict::Drop));
    // Rules unknown: held back, not acknowledged.
    rig.write_file("content-rules.json", "{");
    assert_eq!(frame(&rig, ev("e8", "hello"), Direction::In).await, (true, vec![]));
    // The AI could not judge: dropped, not acknowledged, the person told.
    let mut p = rule("pol", "block", "in", &[], &[], &["slack"]);
    p["policy"] = json!("salary");
    rig.write_rules(json!([p]));
    rig.judge
        .answer("/content", Answer::json(200, json!({"failed": true, "why": "cap"})));
    assert_eq!(frame(&rig, ev("e11", "hello"), Direction::In).await, (true, vec![]));
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice").pop().map(|n| n["failed"].clone()),
        Some(json!(true))
    );
}

// ---- host review of #539 (production's #561) ----

#[tokio::test]
async fn host_review_539_formatting_numbers_and_charsets() {
    let rig = Rig::new().await;
    rules(&rig);
    rig.write_rules(json!([
        rule("cust", "block", "out", &["customer list"], &[], &["slack"]),
        rule("card", "block", "out", &[], &["card"], &["slack"]),
        rule("salary", "block", "in", &["salary"], &[], &["slack"]),
    ]));
    // Formatting the chat undoes: a link's label, Markdown marks, an HTML entity.
    for t in [
        "the <https://x.y|cust>omer list",
        "the cust*om*er list",
        "the customer&#32;list",
    ] {
        let mut f = api("chat.postMessage", json!({"channel": "C1", "text": t}));
        assert!(out(&rig, &mut f).await.is_some(), "{t}");
    }
    let mut f = api(
        "chat.postMessage",
        json!({"channel": "C1", "text": "the customer story"}),
    );
    assert!(out(&rig, &mut f).await.is_none());
    // A number where a text goes is read as written.
    let mut f = call(
        "slack.com",
        "/api/chat.postMessage",
        "POST",
        r#"{"channel": "C1", "text": 4111111111111111}"#,
        "application/json",
    );
    assert!(out(&rig, &mut f).await.is_some());
    // Another charset, or a compressed body: not checked, so refused.
    for ctype in [
        "application/json; charset=latin-1",
        "application/json; charset=\"utf-16\"",
    ] {
        let mut f = call(
            "slack.com",
            "/api/chat.postMessage",
            "POST",
            r#"{"channel": "C1", "text": "hello"}"#,
            ctype,
        );
        assert!(out(&rig, &mut f).await.is_some(), "{ctype}");
    }
    let mut f = call(
        "slack.com",
        "/api/chat.postMessage",
        "POST",
        r#"{"channel": "C1", "text": "hello"}"#,
        "application/json; charset=UTF-8",
    );
    assert!(out(&rig, &mut f).await.is_none(), "UTF-8 in any case is read");
    // Coming in, through Socket Mode: a link's label.
    let ev = json!({"envelope_id": "e9", "type": "events_api", "payload": {"event": {"type": "message", "channel": "C1", "user": "U1", "text": "my <https://x|sal>ary"}}});
    assert!(frame(&rig, ev, Direction::In).await.0);
}

#[tokio::test]
async fn interactive_frames_are_read() {
    // What a person typed is read (the addon passed interactions unread; a difference on purpose).
    let rig = Rig::new().await;
    rules(&rig);
    let who = json!({"user": {"id": "U1", "name": "salary bot"}, "channel": {"id": "C1", "name": "salary-talk"}});
    let frame_of = |id: &str, p: &Value| json!({"envelope_id": id, "type": "interactive", "payload": p});
    // Typed into an input in a message.
    let mut press = who.clone();
    press["type"] = json!("block_actions");
    press["actions"] = json!([{"action_id": "a", "type": "plain_text_input", "value": "my salary is"}]);
    assert_eq!(
        frame(&rig, frame_of("i1", &press), Direction::In).await,
        (true, vec![r#"{"envelope_id": "i1"}"#.to_owned()])
    );
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice").pop(),
        Some(
            json!({"kind": "in", "channel": "slack", "chatId": "C1", "userId": "U1", "vmId": "vm1", "reason": "salary reason"})
        )
    );
    // A form sent: no channel, so the person is told directly.
    let form = json!({"type": "view_submission", "user": {"id": "U2"},
        "view": {"title": {"type": "plain_text", "text": "Salary review"},
                 "state": {"values": {"b": {"a": {"type": "plain_text_input", "value": "salary numbers"}}}}}});
    assert!(frame(&rig, frame_of("i2", &form), Direction::In).await.0);
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice").pop().map(|n| n["chatId"].clone()),
        Some(json!("U2"))
    );
    // A shortcut run on someone's message reads that message; on the agent's own, it does not.
    let shortcut = |by_bot: bool| {
        let mut m = json!({"type": "message", "text": "the salary list", "user": "U3"});
        if by_bot {
            m["bot_id"] = json!("B1");
        }
        json!({"type": "message_action", "user": {"id": "U1"}, "channel": {"id": "C1"}, "message": m})
    };
    assert!(frame(&rig, frame_of("i3", &shortcut(false)), Direction::In).await.0);
    assert!(!frame(&rig, frame_of("i4", &shortcut(true)), Direction::In).await.0);
    // The agent's own wording (a modal's title, a button's label and value) and names: not read.
    let mut plain = who;
    plain["type"] = json!("block_actions");
    plain["actions"] = json!([{"action_id": "a", "type": "button", "text": {"type": "plain_text", "text": "Discuss salary"}, "value": "salary"}]);
    plain["view"] = json!({"title": {"type": "plain_text", "text": "Salary"}, "state": {"values": {}}});
    assert_eq!(
        frame(&rig, frame_of("i5", &plain), Direction::In).await,
        (false, vec![])
    );
}
