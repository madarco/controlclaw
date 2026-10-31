//! Ported from test_content_rules.py (Telegram both ways, fail closed, hosts and addresses),
//! test_content_policies.py (Telegram) and test_telegram_taps.py.

use std::net::SocketAddr;

use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::checks::testkit::{Answer, Rig, rule};
use crate::checks::{META_EFFECT, META_RULE};
use crate::flow::{Destination, testing::request_flow};

const SEND: &str = "/bot123456:CC-TG-placeholder/sendMessage";
const UPDATES: &str = "/bot123456:CC-TG-placeholder/getUpdates";

fn tg(method: &str, path: &str, body: &str, ctype: &str) -> Flow {
    let mut f = request_flow(method, &format!("https://api.telegram.org{path}"), b"");
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://api.telegram.org{path}"));
    if !ctype.is_empty() {
        b = b.header("content-type", ctype);
    }
    f.request = b.body(Bytes::from(body.to_owned())).ok();
    f.meta.insert(crate::checks::META_BODY_DECODED, json!(true));
    f
}

fn send_json(v: Value) -> Flow {
    tg("POST", SEND, &pyjson::dumps(&v), "application/json")
}

fn text(t: &str) -> Flow {
    send_json(json!({"chat_id": 42, "text": t}))
}

async fn out(rig: &Rig, flow: &mut Flow) -> Option<(u16, Value)> {
    let step = TelegramOut {
        content: rig.content.clone(),
    };
    match step.run(Hook::Request, flow).await {
        Verdict::Continue => None,
        Verdict::Answer(r) => Some((
            r.status().as_u16(),
            serde_json::from_slice(r.body()).unwrap_or(Value::Null),
        )),
        other => panic!("unexpected {other:?}"),
    }
}

fn description(a: &Option<(u16, Value)>) -> String {
    a.as_ref()
        .and_then(|(_, b)| b["description"].as_str())
        .unwrap_or("")
        .to_owned()
}

fn rules_basic(rig: &Rig) {
    rig.write_rules(json!([
        rule("cust", "block", "out", &["customer list"], &[], &["telegram"]),
        rule("iban", "hold", "out", &[], &["iban"], &["telegram"]),
        rule("watch", "log", "out", &["budget"], &[], &["telegram"]),
    ]));
}

#[tokio::test]
async fn out_block_hold_log_and_notices() {
    let rig = Rig::new().await;
    rules_basic(&rig);
    assert!(out(&rig, &mut text("hello")).await.is_none());

    let mut f = text("Here is the customer list.");
    let a = out(&rig, &mut f).await;
    assert_eq!(a.as_ref().map(|a| a.0), Some(400));
    assert_eq!(
        a.map(|a| a.1),
        Some(
            json!({"ok": false, "error_code": 400, "description": "Bad Request: blocked by your organization's rules: cust reason"})
        )
    );
    assert_eq!(
        (f.meta[META_EFFECT].as_str(), f.meta[META_RULE].as_str()),
        (Some("block"), Some("content: cust"))
    );
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice"),
        vec![json!({"kind": "out", "botId": "123456", "chatId": "42", "vmId": "vm_test", "reason": "cust reason"})]
    );
    let line = rig.audit().pop().unwrap_or_default();
    assert_eq!(
        (line["rule"].as_str(), line["action"].as_str()),
        (Some("cust"), Some("block"))
    );
    assert_eq!(rig.agent.calls("/stopped")[0]["text"], "Here is the customer list.");
    assert_eq!(rig.agent.calls("/stopped")[0]["id"], line["id"]);

    // The core rule, with no organization rule about it.
    let a = out(&rig, &mut text(&format!("the key is sk-proj-{}", "Z".repeat(40)))).await;
    assert!(description(&a).contains("password, key or token"));

    // Hold: the agent is told it went.
    rig.agent.answer(
        "/hold",
        Answer::json(200, json!({"ok": true, "holdId": "h1", "messageId": 777})),
    );
    let a = out(&rig, &mut text("IBAN GB82 WEST 1234 5698 7654 32"))
        .await
        .expect("answered");
    assert_eq!(a.0, 200);
    assert_eq!(
        (
            a.1["ok"].clone(),
            a.1["result"]["message_id"].clone(),
            a.1["result"]["chat"].clone()
        ),
        (json!(true), json!(777), json!({"id": 42}))
    );
    let hold = rig.agent.calls("/hold").pop().unwrap_or_default();
    assert_eq!(
        (hold["method"].as_str(), hold["chatId"].as_str()),
        (Some("sendMessage"), Some("42"))
    );
    assert_eq!(
        hold["rule"],
        json!({"id": "iban", "name": "iban", "reason": "iban reason"})
    );
    assert!(hold["body"].as_str().is_some_and(|b| b.contains("\"text\": \"IBAN")));
    // Keys in the addon's order.
    assert_eq!(
        hold.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default(),
        ["key", "botId", "method", "body", "chatId", "vmId", "rule", "text"]
    );
    let line = rig.audit().pop().unwrap_or_default();
    assert_eq!(
        (line["action"].as_str(), line["hold"].as_str()),
        (Some("hold"), Some("h1"))
    );
    let stopped_before = rig.agent.calls("/stopped").len();

    // Nobody to ask, then the mitm-agent down: a block, and the hold cancelled by its key.
    rig.agent.answer("/hold", Answer::json(200, json!({"ok": false})));
    let a = out(&rig, &mut text("IBAN GB82 WEST 1234 5698 7654 32")).await;
    assert!(description(&a).contains("nobody could be asked"));
    rig.agent.answer("/hold", Answer::json(503, json!({})));
    let a = out(&rig, &mut text("IBAN GB82 WEST 1234 5698 7654 32")).await;
    assert_eq!(a.as_ref().map(|a| a.0), Some(400));
    let key = rig.agent.calls("/hold").pop().unwrap_or_default()["key"].clone();
    assert_eq!(rig.agent.calls("/cancel").pop().unwrap_or_default()["key"], key);
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/stopped").len(),
        stopped_before,
        "a hold is recorded by the mitm-agent, not as stopped"
    );

    // A form body cannot be resent as it was: stopped instead of held.
    let a = out(
        &rig,
        &mut tg(
            "POST",
            SEND,
            "chat_id=42&text=IBAN+GB82+WEST+1234+5698+7654+32",
            "application/x-www-form-urlencoded",
        ),
    )
    .await;
    assert!(description(&a).contains("could not be held"));

    // Log only: passes, recorded.
    assert!(out(&rig, &mut text("the budget is fine")).await.is_none());
    let line = rig.audit().pop().unwrap_or_default();
    assert_eq!(
        (line["rule"].as_str(), line["action"].as_str()),
        (Some("watch"), Some("log"))
    );

    // Captions and media groups are text too.
    let a = out(
        &rig,
        &mut tg(
            "POST",
            "/bot123456:x/sendPhoto",
            r#"{"chat_id": 42, "photo": "x", "caption": "customer list attached"}"#,
            "application/json",
        ),
    )
    .await;
    assert_eq!(a.map(|a| a.0), Some(400));
    let a = out(
        &rig,
        &mut tg(
            "POST",
            "/bot123456:x/sendMediaGroup",
            r#"{"chat_id": 42, "media": [{"type": "photo", "media": "x", "caption": "the customer list"}]}"#,
            "application/json",
        ),
    )
    .await;
    assert_eq!(a.map(|a| a.0), Some(400));
}

#[tokio::test]
async fn out_fails_closed() {
    let rig = Rig::new().await;
    // No file at all.
    let a = out(&rig, &mut text("hello")).await;
    assert!(description(&a).ends_with("the check could not run"));
    rig.write_file("content-rules.json", "not json");
    let a = out(&rig, &mut text("hello")).await;
    assert!(description(&a).contains("could not run"));
    rig.write_file("content-rules.json", r#"{"version": 1, "unreadable": true}"#);
    assert_eq!(out(&rig, &mut text("hello")).await.map(|a| a.0), Some(400));
    // A body that is not a JSON object, and a repeated key.
    rig.write_rules(json!([rule(
        "cust",
        "block",
        "out",
        &["customer list"],
        &[],
        &["telegram"]
    )]));
    let a = out(&rig, &mut tg("POST", SEND, "[1, 2]", "application/json")).await;
    assert!(description(&a).contains("could not run"));
    let a = out(
        &rig,
        &mut tg(
            "POST",
            SEND,
            r#"{"chat_id": 42, "text": "the customer list", "text": "hello"}"#,
            "application/json",
        ),
    )
    .await;
    assert!(
        description(&a).contains("could not run"),
        "a repeated JSON key is refused"
    );
    let line = rig.audit().pop().unwrap_or_default();
    assert_eq!(
        (line["rule"].as_str(), line["action"].as_str()),
        (Some("error"), Some("block"))
    );
}

#[tokio::test]
async fn text_anywhere_is_checked() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule(
        "cust",
        "block",
        "out",
        &["customer list"],
        &[],
        &["telegram"]
    )]));
    let key = format!("sk-proj-{}", "K".repeat(40));
    let cases: Vec<(&str, String, String, &str, &str)> = vec![
        ("GET", format!("{SEND}?chat_id=42&text={key}"), String::new(), "", "a GET with the key in the query"),
        ("POST", format!("{SEND}?text={key}"), r#"{"chat_id": 42, "text": "hello"}"#.into(), "application/json", "the query next to a clean body"),
        ("POST", "/bot123456:x/sendPoll".into(), r#"{"chat_id": 42, "question": "the customer list?", "options": ["a", "b"]}"#.into(), "application/json", "a poll question"),
        ("POST", "/bot123456:x/sendPoll".into(), format!(r#"{{"chat_id": 42, "question": "q", "options": [{{"text": "{key}"}}]}}"#), "application/json", "a poll option"),
        ("POST", "/bot123456:x/copyMessage".into(), r#"{"chat_id": 42, "from_chat_id": 1, "message_id": 2, "caption": "customer list"}"#.into(), "application/json", "a copied caption"),
        ("POST", "/bot123456:x/setMyDescription".into(), format!(r#"{{"description": "{key}"}}"#), "application/json", "a description"),
        ("POST", SEND.into(), format!("chat_id=42&text={key}&text=hello"), "application/x-www-form-urlencoded", "every value of a repeated form key"),
        ("POST", "/bot123456:x/sendMediaGroup".into(), format!("chat_id=42&media={}", r#"[{"type": "photo", "media": "x", "caption": "customer list"}]"#), "application/x-www-form-urlencoded", "JSON inside a form field"),
        ("POST", "/bot123456:x/sendPhoto".into(), "--B\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n42\r\n--B\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\ncustomer list\r\n--B--\r\n".into(), "multipart/form-data; boundary=B", "a multipart caption"),
    ];
    for (verb, path, body, ctype, why) in cases {
        let a = out(&rig, &mut tg(verb, &path, &body, ctype)).await;
        assert_eq!(a.map(|a| a.0), Some(400), "{why}");
    }
    // Chat ids and message ids are not text: a long number there is not a card number.
    rig.write_rules(json!([rule("card", "block", "out", &[], &["card"], &["telegram"])]));
    let f = &mut send_json(
        json!({"chat_id": 4111111111111111u64, "text": "hi", "reply_parameters": {"message_id": 4111111111111111u64}}),
    );
    assert!(out(&rig, f).await.is_none());
    // A call with query fields is not resent, so it is stopped.
    rig.write_rules(json!([rule("iban", "hold", "out", &[], &["iban"], &["telegram"])]));
    let a = out(
        &rig,
        &mut tg(
            "POST",
            &format!("{SEND}?parse_mode=HTML"),
            r#"{"chat_id": 42, "text": "IBAN GB82 WEST 1234 5698 7654 32"}"#,
            "application/json",
        ),
    )
    .await;
    assert!(description(&a).contains("could not be held"));
    assert!(rig.agent.calls("/hold").is_empty());

    // Padding cannot push a key out of reach.
    rig.write_rules(json!([]));
    let a = out(
        &rig,
        &mut send_json(json!({"chat_id": 42, "description": "x".repeat(70000), "text": key})),
    )
    .await;
    assert!(description(&a).contains("too long to check"));
    let a = out(
        &rig,
        &mut send_json(json!({"chat_id": 42, "description": "x".repeat(30000), "text": key})),
    )
    .await;
    assert!(description(&a).contains("password, key or token"));
    // NaN in JSON inside a form field does not hide the caption next to it.
    rig.write_rules(json!([rule(
        "cust",
        "block",
        "out",
        &["customer list"],
        &[],
        &["telegram"]
    )]));
    let media = r#"[{"type": "photo", "media": "x", "caption": "customer list", "n": NaN}]"#;
    let a = out(
        &rig,
        &mut tg(
            "POST",
            "/bot123456:x/sendMediaGroup",
            &format!("chat_id=42&media={media}"),
            "application/x-www-form-urlencoded",
        ),
    )
    .await;
    assert_eq!(a.map(|a| a.0), Some(400));
    rig.write_rules(json!([]));
    // Nested too deep is refused; deeper inside a string reads as the string.
    let mut deep = json!("x");
    for _ in 0..25 {
        deep = json!([deep]);
    }
    let a = out(&rig, &mut send_json(json!({"chat_id": 42, "text": deep}))).await;
    assert!(description(&a).contains("could not run"));
}

#[tokio::test]
async fn odd_paths_reads_and_other_calls() {
    let rig = Rig::new().await;
    rig.write_rules(json!([]));
    for odd in [
        "/bot123456:CC-TG-placeholder/sendMessage/",
        "/bot123456:CC-TG-placeholder/send%4Dessage",
        "/bot123456:CC-TG-placeholder//sendMessage",
    ] {
        let a = out(
            &rig,
            &mut tg("POST", odd, r#"{"chat_id": 1, "text": "hi"}"#, "application/json"),
        )
        .await;
        assert!(
            description(&a).contains("this Telegram call could not be checked"),
            "{odd}"
        );
    }
    assert_eq!(rig.audit().pop().unwrap_or_default()["detail"], "unmatched path");
    assert!(
        out(
            &rig,
            &mut tg("GET", "/file/bot123456:CC-TG-placeholder/photos/file_1.jpg", "", "")
        )
        .await
        .is_none(),
        "a download is a read"
    );
    assert!(out(&rig, &mut tg("POST", "/bot1:x/getMe", "", "")).await.is_none());
    assert!(
        out(
            &rig,
            &mut tg(
                "POST",
                "/bot1:x/GETCHAT",
                r#"{"chat_id": "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                "application/json"
            )
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn the_poll_waits_for_the_rules() {
    let rig = Rig::new().await;
    let a = out(&rig, &mut tg("POST", UPDATES, "{}", "application/json"))
        .await
        .expect("refused");
    assert_eq!(a.0, 429);
    assert_eq!(a.1["parameters"]["retry_after"], 5);
    assert_eq!(
        a.1["description"],
        "Too Many Requests: retry after 5 (the firewall is loading its rules)"
    );
    let line = rig.audit().pop().unwrap_or_default();
    assert_eq!(
        (
            line["action"].as_str(),
            line["direction"].as_str(),
            line["detail"].as_str()
        ),
        (Some("wait"), Some("in"), Some("rules unknown"))
    );
    rig.write_rules(json!([]));
    assert!(
        out(&rig, &mut tg("POST", UPDATES, "{}", "application/json"))
            .await
            .is_none(),
        "rules known: the poll goes"
    );
    assert!(
        out(&rig, &mut text("hello there")).await.is_none(),
        "nothing refused for want of org rules"
    );
}

// ---- in ----

fn msg(uid: i64, t: &str) -> Value {
    json!({"update_id": uid, "message": {"message_id": uid, "text": t, "chat": {"id": 7, "type": "private"}, "from": {"id": 7}}})
}

fn answered(raw: &str, path: &str) -> Flow {
    let mut f = tg("POST", path, "{}", "application/json");
    f.response = Some(crate::checks::raw_response(
        200,
        raw.as_bytes().to_vec(),
        "application/json",
    ));
    f
}

async fn incoming_of(rig: &Rig, batch: Value) -> Value {
    let mut f = answered(&pyjson::dumps(&json!({"ok": true, "result": batch})), UPDATES);
    run_in(rig, &mut f).await;
    serde_json::from_slice::<Value>(f.response.as_ref().map(|r| r.body().as_ref()).unwrap_or(b"null"))
        .unwrap_or_default()["result"]
        .clone()
}

async fn run_in(rig: &Rig, f: &mut Flow) {
    let taps = TelegramTaps {
        url: rig.buttons.url("/"),
    };
    let step = TelegramIn {
        content: rig.content.clone(),
    };
    taps.run(Hook::Response, f).await;
    step.run(Hook::Response, f).await;
}

#[tokio::test]
async fn in_blocked_messages_are_taken_out_and_the_offset_kept() {
    let rig = Rig::new().await;
    rig.write_rules(json!([
        rule("nope", "block", "in", &["forbidden topic"], &[], &["telegram"]),
        rule("both", "log", "both", &["budget"], &[], &["telegram"]),
    ]));
    let out = incoming_of(
        &rig,
        json!([msg(10, "hi"), msg(11, "about the forbidden topic"), msg(12, "hello")]),
    )
    .await;
    assert_eq!(
        out.as_array()
            .map(|a| a.iter().map(|u| u["update_id"].clone()).collect::<Vec<_>>()),
        Some(vec![json!(10), json!(12)])
    );
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice"),
        vec![json!({"kind": "in", "botId": "123456", "chatId": "7", "vmId": "vm_test", "reason": "nope reason"})]
    );
    // The last one blocked: its id stays, empty.
    let out = incoming_of(&rig, json!([msg(12, "hello"), msg(13, "forbidden topic again")])).await;
    assert_eq!(out, json!([msg(12, "hello"), {"update_id": 13}]));
    // A person may send the agent a key.
    let key = format!("sk-proj-{}", "Q".repeat(40));
    assert_eq!(incoming_of(&rig, json!([msg(14, &key)])).await, json!([msg(14, &key)]));
    let out = incoming_of(&rig, json!([msg(15, "the budget")])).await;
    assert_eq!(out.as_array().map(Vec::len), Some(1));
    let line = rig.audit().pop().unwrap_or_default();
    assert_eq!(
        (line["action"].as_str(), line["direction"].as_str()),
        (Some("log"), Some("in"))
    );
    // Too long to check on the way in: held back like a block.
    let out = incoming_of(&rig, json!([msg(30, &"y".repeat(70000)), msg(31, "hello")])).await;
    assert_eq!(out, json!([msg(31, "hello")]));
    // An answer that cannot be read is not passed on.
    let mut f = answered(
        r#"{"ok": true, "result": [ {"update_id": 40, "message": {"text": "forbidden topic""#,
        UPDATES,
    );
    run_in(&rig, &mut f).await;
    assert_eq!(
        f.response.map(|r| r.body().clone()),
        Some(Bytes::from_static(br#"{"ok": true, "result": []}"#))
    );
    // Rules unknown: nothing stripped, nothing moves the offset.
    rig.write_file("content-rules.json", "{");
    let photo = json!({"update_id": 18, "message": {"message_id": 18, "photo": [{"file_id": "x"}], "chat": {"id": 7}}});
    let out = incoming_of(
        &rig,
        json!([msg(16, "hi"), {"update_id": 17, "callback_query": {"id": "q", "data": "x"}}, photo]),
    )
    .await;
    assert_eq!(out, json!([]));
}

#[tokio::test]
async fn in_shapes_that_break_the_reader_hold_back_text() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule(
        "nope",
        "block",
        "in",
        &["forbidden topic"],
        &[],
        &["telegram"]
    )]));
    // A tap whose message's chat is not an object: the check fails, so only updates without
    // text go through.
    let odd =
        json!({"update_id": 2, "callback_query": {"id": "q", "data": "y", "message": {"text": "x", "chat": "seven"}}});
    let out = incoming_of(&rig, json!([msg(1, "hi"), odd])).await;
    assert_eq!(out, json!([{"update_id": 2}]));
    // Not a 200, or not getUpdates: left alone.
    let mut f = answered(
        &pyjson::dumps(&json!({"ok": true, "result": [msg(1, "forbidden topic")]})),
        SEND,
    );
    let before = f.response.as_ref().map(|r| r.body().clone());
    run_in(&rig, &mut f).await;
    assert_eq!(f.response.map(|r| r.body().clone()), before);
}

#[tokio::test]
async fn in_policies_judge_a_batch_at_once() {
    let rig = Rig::with_env(&[("MITM_CONTENT_POLICY_TIMEOUT", "0.5")]).await;
    let mut salary = rule("salary", "block", "both", &[], &[], &["*"]);
    salary["policy"] = json!("salary");
    rig.write_rules(json!([salary]));
    rig.judge.answer(
        "/content",
        Answer::json(200, json!({"matches": []})).delayed(std::time::Duration::from_secs(1)),
    );
    let batch: Vec<Value> = (0..6).map(|i| json!({"update_id": i, "message": {"chat": {"id": 42}, "from": {"id": 42}, "text": format!("hello {i}")}})).collect();
    let t = std::time::Instant::now();
    let out = incoming_of(&rig, Value::Array(batch)).await;
    assert!(
        t.elapsed() < std::time::Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(
        out,
        json!([{"update_id": 5}]),
        "all stopped (the AI could not answer); the last kept for its offset"
    );
    rig.settle().await;
    assert_eq!(
        rig.agent.calls("/notice").last().map(|n| n["failed"].clone()),
        Some(json!(true))
    );
}

// ---- hosts and addresses ----

#[test]
fn telegram_by_name() {
    for h in [
        "api.telegram.org",
        "API.Telegram.org",
        "api.telegram.org.",
        "Api.Telegram.Org.",
    ] {
        assert!(is_telegram_host(Some(h)), "{h}");
    }
    for h in [
        "api\u{3002}telegram\u{3002}org",
        "api\u{ff0e}telegram\u{ff0e}org",
        "api.telegram.org\u{3002}",
        "\u{ff21}\u{ff30}\u{ff29}.telegram.org",
    ] {
        assert!(is_telegram_host(Some(h)), "{h:?}");
    }
    for h in ["api.telegram.org.evil.com", "telegram.org", "api-telegram.org", ""] {
        assert!(!is_telegram_host(Some(h)), "{h}");
    }
    assert!(!is_telegram_host(None));
}

#[test]
fn telegram_by_address() {
    for ip in [
        "149.154.167.220",
        "91.108.4.1",
        "2001:67c:4e8:f004::9",
        "::ffff:149.154.167.220",
    ] {
        assert!(is_telegram_ip(ip.parse().expect("ip")), "{ip}");
    }
    for ip in ["93.184.216.34", "10.0.0.3", "::1", "::ffff:93.184.216.34"] {
        assert!(!is_telegram_ip(ip.parse().expect("ip")), "{ip}");
    }
}

fn by_ip(path: &str, name: &str, ip: &str) -> Flow {
    let mut f = request_flow("GET", &format!("https://{name}{path}"), b"");
    f.set_destination(Destination {
        name: name.into(),
        port: 443,
        addr: Some(SocketAddr::new(ip.parse().expect("ip"), 443)),
    });
    f
}

#[test]
fn telegram_by_address_is_the_bot_api_only() {
    assert!(
        !is_telegram_flow(&by_ip("/somechannel", "t.me", "149.154.167.99")),
        "a t.me link is a web page"
    );
    for (path, host) in [
        ("/", "web.telegram.org"),
        ("/k/", "web.telegram.org"),
        ("/apps", "telegram.org"),
        ("/s/somechannel", "t.me"),
    ] {
        assert!(!is_telegram_flow(&by_ip(path, host, "149.154.167.99")), "{path} {host}");
    }
    assert!(is_telegram_flow(&by_ip(
        "/bot123:x/sendMessage",
        "example.com",
        "149.154.167.220"
    )));
    assert!(is_telegram_flow(&by_ip(
        "/file/bot123:x/photos/a.jpg",
        "example.com",
        "149.154.167.220"
    )));
    assert!(
        is_telegram_flow(&by_ip("/somechannel", "api.telegram.org", "149.154.167.99")),
        "by name, any path"
    );
    assert!(is_telegram_flow(&by_ip(
        "/bot123:x/sendMessage",
        "example.com",
        "::ffff:149.154.167.220"
    )));
    assert!(!is_telegram_flow(&by_ip(
        "/bot123:x/sendMessage",
        "example.com",
        "93.184.216.34"
    )));
}

#[test]
fn an_unresolved_address_checks_the_bot_api() {
    let unresolved = |path: &str| {
        let mut f = request_flow("GET", &format!("https://example.com{path}"), b"");
        f.set_destination(Destination {
            name: "example.com".into(),
            port: 443,
            addr: None,
        });
        f
    };
    assert!(
        is_telegram_flow(&unresolved("/bot123:x/sendMessage")),
        "may resolve to Telegram"
    );
    assert!(!is_telegram_flow(&unresolved("/somechannel")));
}

#[tokio::test]
async fn a_lying_host_header_is_judged_by_the_destination() {
    let rig = Rig::new().await;
    rig.write_rules(json!([]));
    // The URL says Telegram, the connection goes elsewhere: not Telegram's check.
    let mut f = crate::flow::testing::lying_request_flow(
        "POST",
        "attacker.example",
        &format!("https://api.telegram.org{SEND}"),
        b"{}",
    );
    assert!(!is_telegram_flow(&f));
    assert!(out_step(&rig, &mut f).await);
    // The URL says somewhere else, the connection goes to Telegram: checked.
    let mut f = crate::flow::testing::lying_request_flow(
        "POST",
        "api.telegram.org",
        &format!("https://example.com{SEND}"),
        b"",
    );
    f.request = http::Request::builder()
        .method("POST")
        .uri(format!("https://example.com{SEND}"))
        .header("content-type", "application/json")
        .body(Bytes::from(format!(
            r#"{{"chat_id": 42, "text": "sk-proj-{}"}}"#,
            "H".repeat(40)
        )))
        .ok();
    f.meta.insert(crate::checks::META_BODY_DECODED, json!(true));
    assert!(!out_step(&rig, &mut f).await);
    assert_eq!(f.meta[META_RULE], "content: core-leaking-secrets");
}

/// Whether the out step let the flow go on.
async fn out_step(rig: &Rig, f: &mut Flow) -> bool {
    matches!(
        TelegramOut {
            content: rig.content.clone()
        }
        .run(Hook::Request, f)
        .await,
        Verdict::Continue
    )
}

// ---- taps ----

fn tap(uid: i64, data: &str) -> Value {
    json!({"update_id": uid, "callback_query": {"id": format!("q{uid}"), "data": data, "from": {"id": 1}, "message": {"message_id": 9, "chat": {"id": 1, "type": "private"}}}})
}

fn ours(uid: i64) -> Value {
    tap(uid, &format!("cc1:{}:47", "N".repeat(22)))
}

fn message(uid: i64) -> Value {
    json!({"update_id": uid, "message": {"message_id": uid, "text": "hello", "chat": {"id": 1, "type": "private"}}})
}

async fn taps_of(rig: &Rig, batch: Value, path: &str, status: u16) -> (Value, Vec<Value>) {
    let mut f = tg("POST", path, "{}", "application/json");
    f.response = Some(crate::checks::raw_response(
        status,
        pyjson::dumps(&json!({"ok": true, "result": batch})).into_bytes(),
        "application/json",
    ));
    let before = rig.buttons.calls("/").len();
    TelegramTaps {
        url: rig.buttons.url("/"),
    }
    .run(Hook::Response, &mut f)
    .await;
    rig.settle().await;
    let posted = rig.buttons.calls("/")[before..].to_vec();
    let body: Value =
        serde_json::from_slice(f.response.as_ref().map(|r| r.body().as_ref()).unwrap_or(b"null")).unwrap_or_default();
    (body["result"].clone(), posted)
}

#[tokio::test]
async fn taps_are_taken_out_and_handed_over() {
    let rig = Rig::new().await;
    let p = "/bot123456:AAsecrettokensecrettokensecret/getUpdates";
    let (out, posted) = taps_of(&rig, json!([message(10), ours(11), message(12)]), p, 200).await;
    assert_eq!(out, json!([message(10), message(12)]));
    assert_eq!(
        posted,
        vec![json!({"botId": "123456", "queries": [ours(11)["callback_query"]]})]
    );
    let (out, _) = taps_of(&rig, json!([message(12), ours(13)]), p, 200).await;
    assert_eq!(out, json!([message(12), {"update_id": 13}]));
    let (out, _) = taps_of(&rig, json!([ours(14)]), p, 200).await;
    assert_eq!(out, json!([{"update_id": 14}]));
    let (out, posted) = taps_of(&rig, json!([ours(15), ours(16), ours(17)]), p, 200).await;
    assert_eq!(out, json!([{"update_id": 17}]));
    assert_eq!(posted[0]["queries"].as_array().map(Vec::len), Some(3));
    // The agent's own buttons are its own.
    let theirs = tap(18, "openclaw:approve:1");
    let (out, posted) = taps_of(&rig, json!([theirs.clone()]), p, 200).await;
    assert_eq!((out, posted.len()), (json!([theirs]), 0));
    // Not getUpdates, not a 200: left alone.
    let (out, posted) = taps_of(&rig, json!([ours(19)]), "/bot123456:x/sendMessage", 200).await;
    assert_eq!((out, posted.len()), (json!([ours(19)]), 0));
    let (out, posted) = taps_of(&rig, json!([ours(19)]), p, 409).await;
    assert_eq!((out, posted.len()), (json!([ours(19)]), 0));
    // A query string does not hide it.
    let (out, _) = taps_of(&rig, json!([ours(20)]), &format!("{p}?offset=20&timeout=30"), 200).await;
    assert_eq!(out, json!([{"update_id": 20}]));
    assert_eq!(
        strip_taps(&json!({"ok": false, "description": "x"})),
        (json!({"ok": false, "description": "x"}), vec![])
    );
    assert_eq!(strip_taps(&json!([])), (json!([]), vec![]));
}

#[tokio::test]
async fn taps_on_another_host_are_left_alone() {
    let rig = Rig::new().await;
    let mut f = request_flow("POST", "https://evil.example.com/bot123456:x/getUpdates", b"{}");
    let body = pyjson::dumps(&json!({"ok": true, "result": [ours(19)]}));
    f.response = Some(crate::checks::raw_response(
        200,
        body.clone().into_bytes(),
        "application/json",
    ));
    TelegramTaps {
        url: rig.buttons.url("/"),
    }
    .run(Hook::Response, &mut f)
    .await;
    assert_eq!(f.response.map(|r| r.body().clone()), Some(Bytes::from(body)));
}

#[test]
fn chat_ids_as_python_writes_them() {
    assert_eq!(py_str(&json!(42)), "42");
    assert_eq!(py_str(&json!("@chan")), "@chan");
    assert_eq!(py_str(&json!(-100.0)), "-100.0");
    assert_eq!(py_str(&json!(true)), "True");
    assert_eq!(py_str(&json!(1e16)), "1e+16");
    assert_eq!(py_str(&json!(1.5e-5)), "1.5e-05");
    assert_eq!(py_str(&json!(0.0001)), "0.0001");
}

// ---- the host's review of #522: ways a message went past the check in the addon ----

#[tokio::test]
async fn host_review_ways_past_the_check() {
    let rig = Rig::new().await;
    rig.write_rules(json!([
        rule("cust", "block", "out", &["customer list"], &[], &["telegram"]),
        rule("card", "block", "out", &[], &["card"], &["telegram"]),
        rule("word", "block", "out", &["password"], &[], &["telegram"]),
    ]));
    let refused = |a: &Option<(u16, Value)>| a.as_ref().map(|a| a.0) == Some(400);
    // 1. A compressed body.
    let mut f = tg("POST", SEND, "chat_id=42&text=x", "application/x-www-form-urlencoded");
    if let Some(r) = f.request.as_mut() {
        r.headers_mut()
            .insert("content-encoding", http::HeaderValue::from_static("gzip"));
    }
    assert!(refused(&out(&rig, &mut f).await), "gzip");
    // ...and a body the plumbing has not marked decoded.
    let mut f = tg("POST", SEND, r#"{"chat_id": 42, "text": "hello"}"#, "application/json");
    f.meta.remove(crate::checks::META_BODY_DECODED);
    assert!(refused(&out(&rig, &mut f).await), "not decoded");
    // 2. Multipart that does not split cleanly.
    for (ct, body) in [
        (
            "multipart/form-data; boundary=\"B\"",
            "--B\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\ncustomer list\r\n--B--\r\n",
        ),
        (
            "multipart/form-data; boundary=B",
            "--B\r\nContent-Type: text/plain\r\nContent-Disposition: form-data; name=caption\r\n\r\ncustomer list\r\n--B--\r\n",
        ),
        (
            "multipart/form-data; boundary=B",
            "--B\r\nContent-Disposition: form-data; name=\"caption\"\r\ncustomer list\r\n--B--\r\n",
        ),
    ] {
        assert!(
            refused(&out(&rig, &mut tg("POST", "/bot1:x/sendPhoto", body, ct)).await),
            "{body}"
        );
    }
    // 3. A number where Telegram wants text.
    assert!(refused(
        &out(
            &rig,
            &mut tg(
                "POST",
                SEND,
                r#"{"chat_id": 42, "text": 4111111111111111}"#,
                "application/json"
            )
        )
        .await
    ));
    // 4. Too deep inside a JSON string.
    let mut deep = json!("x");
    for _ in 0..25 {
        deep = json!([deep]);
    }
    let markup = pyjson::dumps(&deep);
    assert!(refused(
        &out(
            &rig,
            &mut send_json(json!({"chat_id": 42, "text": "hi", "reply_markup": markup}))
        )
        .await
    ));
    // 5. What HTML and MarkdownV2 show.
    assert!(refused(
        &out(
            &rig,
            &mut send_json(json!({"chat_id": 42, "text": "customer&#32;list", "parse_mode": "HTML"}))
        )
        .await
    ));
    assert!(refused(
        &out(
            &rig,
            &mut send_json(json!({"chat_id": 42, "text": "pass<b></b>word", "parse_mode": "HTML"}))
        )
        .await
    ));
    assert!(refused(
        &out(
            &rig,
            &mut send_json(json!({"chat_id": 42, "text": "pass*word*", "parse_mode": "MarkdownV2"}))
        )
        .await
    ));
    assert!(refused(
        &out(
            &rig,
            &mut send_json(json!({"chat_id": 42, "text": "customer\\ list", "parse_mode": "MarkdownV2"}))
        )
        .await
    ));
    // 6. A form without a charset is UTF-8; a JSON type in capitals too.
    rig.write_rules(json!([rule("acc", "block", "out", &["caf\u{e9}"], &[], &["telegram"])]));
    assert!(refused(
        &out(
            &rig,
            &mut tg(
                "POST",
                SEND,
                "chat_id=42&text=caf\u{e9}",
                "application/x-www-form-urlencoded"
            )
        )
        .await
    ));
    assert!(refused(
        &out(
            &rig,
            &mut tg(
                "POST",
                SEND,
                "{\"chat_id\": 42, \"text\": \"caf\u{e9}\"}",
                "Application/Json"
            )
        )
        .await
    ));
    // 7. A webhook.
    let a = out(&rig, &mut send_json(json!({"url": "https://evil.example/hook"}))).await;
    assert!(a.is_none(), "sendMessage with a url field is not a webhook");
    let a = out(
        &rig,
        &mut tg(
            "POST",
            "/bot1:x/setWebhook",
            r#"{"url": "https://evil.example/hook"}"#,
            "application/json",
        ),
    )
    .await;
    assert!(description(&a).contains("webhook"));
    assert!(
        out(
            &rig,
            &mut tg("POST", "/bot1:x/setWebhook", r#"{"url": ""}"#, "application/json")
        )
        .await
        .is_none(),
        "clearing it goes"
    );
}

#[tokio::test]
async fn host_review_inbound_and_holds() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule(
        "nope",
        "block",
        "in",
        &["forbidden topic"],
        &[],
        &["telegram"]
    )]));
    // 8. The message replied to, the quote, a pinned message, an edited business message.
    for u in [
        json!({"update_id": 1, "message": {"text": "ok", "chat": {"id": 7}, "reply_to_message": {"text": "the forbidden topic"}}}),
        json!({"update_id": 1, "message": {"text": "ok", "chat": {"id": 7}, "quote": {"text": "the forbidden topic"}}}),
        json!({"update_id": 1, "message": {"chat": {"id": 7}, "pinned_message": {"caption": "the forbidden topic"}}}),
        json!({"update_id": 1, "edited_business_message": {"text": "the forbidden topic", "chat": {"id": 7}}}),
    ] {
        assert_eq!(
            incoming_of(&rig, json!([u.clone()])).await,
            json!([{"update_id": 1}]),
            "{u}"
        );
    }
    // 11. A NaN in an update does not stop the check.
    let mut f = answered(
        r#"{"ok": true, "result": [{"update_id": 3, "message": {"text": "the forbidden topic", "chat": {"id": 7}, "n": NaN}}]}"#,
        UPDATES,
    );
    run_in(&rig, &mut f).await;
    let doc: Value =
        serde_json::from_slice(f.response.as_ref().map(|r| r.body().as_ref()).unwrap_or(b"null")).unwrap_or_default();
    assert_eq!(doc["result"], json!([{"update_id": 3}]));
    // An answer the plumbing did not mark decoded is held back.
    let mut f = answered(
        r#"{"ok": true, "result": [{"update_id": 4, "message": {"text": "hello", "chat": {"id": 7}}}]}"#,
        UPDATES,
    );
    f.meta.remove(crate::checks::META_BODY_DECODED);
    run_in(&rig, &mut f).await;
    assert_eq!(
        f.response.map(|r| r.body().clone()),
        Some(Bytes::from_static(br#"{"ok": true, "result": []}"#))
    );
    // 9. A hold whose answer has no usable messageId is cancelled.
    rig.write_rules(json!([rule("iban", "hold", "out", &[], &["iban"], &["telegram"])]));
    rig.agent.answer(
        "/hold",
        Answer::json(200, json!({"ok": true, "holdId": "h1", "messageId": "abc"})),
    );
    let a = out(&rig, &mut text("IBAN GB82 WEST 1234 5698 7654 32")).await;
    assert_eq!(a.map(|a| a.0), Some(400));
    let key = rig.agent.calls("/hold").pop().unwrap_or_default()["key"].clone();
    assert_eq!(rig.agent.calls("/cancel"), vec![json!({"key": key})]);
}

#[test]
fn set_body_drops_the_transfer_encoding() {
    let mut r = crate::checks::raw_response(200, b"x".to_vec(), "application/json");
    r.headers_mut()
        .insert("transfer-encoding", http::HeaderValue::from_static("chunked"));
    r.headers_mut()
        .insert("content-encoding", http::HeaderValue::from_static("gzip"));
    crate::checks::set_body(&mut r, b"yy".to_vec());
    assert!(r.headers().get("transfer-encoding").is_none() && r.headers().get("content-encoding").is_none());
    assert_eq!(r.headers()["content-length"], "2");
}

#[tokio::test]
async fn a_held_body_is_the_text_that_was_checked() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule("iban", "hold", "out", &[], &["iban"], &["telegram"])]));
    rig.agent.answer(
        "/hold",
        Answer::json(200, json!({"ok": true, "holdId": "h1", "messageId": 5})),
    );
    let body = "{\"chat_id\": 42, \"text\": \"caf\u{e9} IBAN GB82 WEST 1234 5698 7654 32\"}";
    let mut f = tg("POST", SEND, body, "Application/Json");
    assert_eq!(out(&rig, &mut f).await.map(|a| a.0), Some(200));
    assert_eq!(rig.agent.calls("/hold").pop().unwrap_or_default()["body"], json!(body));
}

// ---- host review of #539 (production's #561) ----

#[tokio::test]
async fn host_review_539_telegram() {
    let rig = Rig::new().await;
    rules_basic(&rig);
    // A number where a text goes, as written (past 64 bits too).
    let out_of = |v: &str| tg("POST", SEND, v, "application/json");
    let mut f = out_of(r#"{"chat_id": 42, "text": 4111111111111111}"#);
    rig.write_rules(json!([rule("card", "block", "out", &[], &["card"], &["telegram"])]));
    assert!(out(&rig, &mut f).await.is_some());
    rules_basic(&rig);
    // JSON in a string that does not parse: read whole, escapes undone.
    let mut f = send_json(json!({"chat_id": 42, "reply_markup": "{\"text\": \"the cust\\u006fmer list\", \u{1}}"}));
    assert!(out(&rig, &mut f).await.is_some());
    // Formatting undone whatever the parse_mode says.
    for t in [
        "the [cust](http://a.b)omer list",
        "the cust\\_omer list",
        "the customer&#32;list",
    ] {
        let mut f = text(t);
        assert!(out(&rig, &mut f).await.is_some(), "{t}");
    }
    // Another charset: not checked, so refused.
    let mut f = tg(
        "POST",
        SEND,
        r#"{"chat_id": 42, "text": "hi"}"#,
        "application/json; charset=iso-8859-1",
    );
    assert!(out(&rig, &mut f).await.is_some());
    let mut f = out_of(r#"{"chat_id": 42, "text": "hi"}"#);
    assert!(out(&rig, &mut f).await.is_none());
    // setWebhook with any url, also a number; an empty one deletes it and goes.
    let hook = |b: &str| tg("POST", "/bot123456:CC-TG-placeholder/setWebhook", b, "application/json");
    for (b, stopped) in [
        (r#"{"url": 5}"#, true),
        (r#"{"url": "https://a.b"}"#, true),
        (r#"{"url": ""}"#, false),
    ] {
        let mut f = hook(b);
        assert_eq!(out(&rig, &mut f).await.is_some(), stopped, "{b}");
    }
}

#[test]
fn numbers_are_read_as_written() {
    let doc = crate::checks::json::loads_strict_raw_numbers(
        r#"{"text": [1.50, 12345678901234567890123, -0, 1e3, 7, true, null], "n": 2}"#,
    )
    .expect("json");
    let mut out = Vec::new();
    texts(&doc, false, &mut out, 0, &["text"]).expect("walk");
    assert_eq!(out, ["1.50", "12345678901234567890123", "-0", "1e3", "7"]);
    // In an answer to the agent, a number kept as written is a number again.
    let n = crate::checks::json::loads_strict_raw_numbers("[-100123.0, 1e3, 7]").expect("json");
    let plain: Vec<Value> = n
        .as_array()
        .into_iter()
        .flatten()
        .map(crate::checks::json::plain_number)
        .collect();
    assert_eq!(plain, vec![json!(-100123.0), json!(1000.0), json!(7)]);
}

#[tokio::test]
async fn host_review_539_incoming_reads_every_text_but_the_agents() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule(
        "nope",
        "block",
        "in",
        &["forbidden topic"],
        &[],
        &["telegram"]
    )]));
    let bot = json!({"id": 123456, "is_bot": true});
    // A poll, an inline query, a quote of someone else: read.
    for u in [
        json!({"update_id": 1, "poll": {"id": "p", "question": "the forbidden topic?"}}),
        json!({"update_id": 1, "inline_query": {"id": "q", "from": {"id": 7}, "query": "forbidden topic"}}),
        json!({"update_id": 1, "message": {"message_id": 1, "chat": {"id": 7}, "from": {"id": 7}, "text": "see",
               "reply_to_message": {"message_id": 0, "chat": {"id": 7}, "from": {"id": 8}, "text": "the forbidden topic"}}}),
    ] {
        assert_eq!(
            incoming_of(&rig, json!([u.clone()])).await,
            json!([{"update_id": 1}]),
            "{u}"
        );
    }
    // A reply to the agent's own message, quoting it: not read again. A sender's name: never.
    let reply = json!({"update_id": 1, "message": {"message_id": 1, "chat": {"id": 7}, "from": {"id": 7, "first_name": "forbidden topic"},
        "text": "ok", "quote": {"text": "the forbidden topic"},
        "reply_to_message": {"message_id": 0, "chat": {"id": 7}, "from": bot, "text": "the forbidden topic"}}});
    assert_eq!(incoming_of(&rig, json!([reply.clone()])).await, json!([reply]));
}

#[tokio::test]
async fn names_on_more_kinds_of_update_are_not_read() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule(
        "nope",
        "block",
        "in",
        &["forbidden topic"],
        &[],
        &["telegram"]
    )]));
    for u in [
        json!({"update_id": 1, "poll_answer": {"poll_id": "p", "voter_chat": {"id": -1, "title": "forbidden topic fans"}, "option_ids": [0]}}),
        json!({"update_id": 1, "message": {"message_id": 1, "chat": {"id": 7}, "from": {"id": 7},
               "chat_shared": {"request_id": 1, "chat_id": -2, "title": "forbidden topic"}}}),
    ] {
        assert_eq!(incoming_of(&rig, json!([u.clone()])).await, json!([u.clone()]), "{u}");
    }
}
