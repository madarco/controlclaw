//! Ported from test_email.py (send admission payloads, answers, AgentMail responses and websocket
//! events) and the email parts of test_content_rules_channels.py and test_content_policies.py.

use base64::Engine;
use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::checks::testkit::{Answer, FakeService, Rig, rule};
use crate::checks::{META_EFFECT, META_RECORD, META_RULE};
use crate::flow::testing::request_flow;
use crate::flow::{Direction, FrameKind, WsFrame};

const IBAN: &str = "GB82 WEST 1234 5698 7654 32";

struct Kit {
    rig: Rig,
    admission: FakeService,
    agentmail: FakeService,
    email: Arc<Email>,
}

async fn kit() -> Kit {
    let rig = Rig::new().await;
    let admission = FakeService::start().await.expect("admission");
    let agentmail = FakeService::start().await.expect("agentmail");
    let email = Arc::new(Email {
        content: rig.content.clone(),
        admission_url: admission.url("/"),
        pending: Pending::new(rig.dir.path().join("pending.jsonl")),
        agentmail_base: agentmail.url(""),
        creds: Arc::new(crate::checks::creds::Creds::new(
            rig.dir.path().join("credentials.json"),
        )),
        http: reqwest::Client::new(),
    });
    rig.write_rules(json!([]));
    Kit {
        rig,
        admission,
        agentmail,
        email,
    }
}

fn req(host: &str, path: &str, method: &str, body: &[u8], ctype: &str, headers: &[(&str, &str)]) -> Flow {
    let mut f = request_flow(method, &format!("https://{host}{path}"), b"");
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"));
    if !ctype.is_empty() {
        b = b.header("content-type", ctype);
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    f.request = b.body(Bytes::from(body.to_vec())).ok();
    f.vm_id = Some("vm-a".into());
    f.meta.insert(crate::checks::META_BODY_DECODED, json!(true));
    f
}

fn post(host: &str, path: &str, body: Value) -> Flow {
    req(
        host,
        path,
        "POST",
        pyjson::dumps(&body).as_bytes(),
        "application/json",
        &[],
    )
}

/// The request step: `None` when it went on, else the answer's status and JSON.
async fn run(k: &Kit, f: &mut Flow) -> Option<(u16, Value)> {
    match EmailRequest(k.email.clone()).run(Hook::Request, f).await {
        Verdict::Continue => None,
        Verdict::Answer(r) => Some((
            r.status().as_u16(),
            serde_json::from_slice(r.body()).unwrap_or(Value::Null),
        )),
        other => panic!("unexpected {other:?}"),
    }
}

fn allow(k: &Kit, id: &str) {
    k.admission.answer(
        "/",
        Answer::json(200, json!({"ok": true, "decision": "allow", "id": id})),
    );
}

fn reserves(k: &Kit) -> Vec<Value> {
    k.admission
        .calls("/")
        .into_iter()
        .filter(|c| c["action"] != "email.inbound")
        .collect()
}

const RAW_MESSAGE: &[u8] = b"From: me@x.com\r\nTo: Bob <bob@y.com>, c@z.com\r\nBcc: hidden@w.com\r\nSubject: private subject\r\n\r\nSECRET BODY TEXT\r\n";

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[tokio::test]
async fn agentmail_sends_are_admitted() {
    let k = kit().await;
    allow(&k, &"a".repeat(48));
    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/ana%40agentmail.to/messages/send",
        json!({"to": ["bob@y.com"], "cc": "c@z.com", "text": "body"}),
    );
    assert!(run(&k, &mut f).await.is_none());
    assert_eq!(f.meta[META_RESERVATION], json!("a".repeat(48)));
    assert_eq!(f.meta[META_SENT], json!(true));
    let call = &reserves(&k)[0];
    assert_eq!(
        call,
        &json!({"action": "email.reserve", "vmId": "vm-a", "provider": "agentmail", "to": ["bob@y.com"], "cc": "c@z.com", "bcc": null,
                "inboxId": "ana@agentmail.to", "op": "send"})
    );
    assert!(!call.to_string().contains("body"));

    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/ana%40agentmail.to/messages/%3Cm1%40x%3E/reply",
        json!({"text": "hi", "reply_all": true}),
    );
    run(&k, &mut f).await;
    let call = reserves(&k).pop().unwrap_or_default();
    assert_eq!(
        (call["op"].as_str(), call["messageId"].as_str()),
        (Some("reply_all"), Some("<m1@x>"))
    );
    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/ana%40agentmail.to/drafts/d1/send",
        json!({}),
    );
    run(&k, &mut f).await;
    let call = reserves(&k).pop().unwrap_or_default();
    assert_eq!(
        (call["op"].as_str(), call["draftId"].as_str()),
        (Some("draft_send"), Some("d1"))
    );

    // A Bcc smuggled in the headers map, and writes that are not on the known list.
    let before = reserves(&k).len();
    for (p, b) in [
        (
            "/v0/inboxes/a%40agentmail.to/messages/send",
            json!({"to": "bob@y.com", "headers": {"Bcc": "evil@x.com"}}),
        ),
        (
            "/v0/inboxes/a%40agentmail.to/drafts",
            json!({"to": "bob@y.com", "headers": {"Cc": "evil@x.com"}}),
        ),
    ] {
        let a = run(&k, &mut post(AGENTMAIL_API, p, b)).await.expect("refused");
        assert_eq!(a.1["reason"], "headers_refused");
    }
    assert!(
        run(
            &k,
            &mut post(
                AGENTMAIL_API,
                "/v0/inboxes/a%40agentmail.to/drafts",
                json!({"to": "x@y.com", "headers": {"X-Tag": "1"}})
            )
        )
        .await
        .is_none()
    );
    let a = run(
        &k,
        &mut post(AGENTMAIL_API, "/v0/webhooks", json!({"url": "https://evil"})),
    )
    .await
    .expect("refused");
    assert_eq!(
        (a.0, a.1["reason"].as_str(), a.1["error"].as_str()),
        (403, Some("unknown_write"), Some("email_refused"))
    );
    assert_eq!(a.1["message"], "This AgentMail operation is not allowed from an agent.");
    let mut f = req(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/m1",
        "PATCH",
        br#"{"add_labels": ["read"]}"#,
        "application/json",
        &[],
    );
    assert!(run(&k, &mut f).await.is_none());
    assert_eq!(reserves(&k).len(), before, "no admission call for any of these");
    for key in ["send_at", "sendAt", "scheduled_at"] {
        let a = run(
            &k,
            &mut post(
                AGENTMAIL_API,
                "/v0/inboxes/a%40agentmail.to/drafts",
                json!({"to": "x@y.com", key: "2030"}),
            ),
        )
        .await;
        assert_eq!(a.map(|a| a.1["reason"].clone()), Some(json!("scheduled_send")), "{key}");
    }
}

#[tokio::test]
async fn asks_blocks_and_an_admission_that_fails() {
    let k = kit().await;
    let two = json!([
        {"scope": "EMAIL agentmail:a@agentmail.to -> bob@y.com #2", "summary": "Send email to bob@y.com from a@agentmail.to", "recipient": "bob@y.com", "mailbox": "agentmail:a@agentmail.to"},
        {"scope": "EMAIL agentmail:a@agentmail.to -> c@z.com", "summary": "Send email to c@z.com from a@agentmail.to", "recipient": "c@z.com", "mailbox": "agentmail:a@agentmail.to"},
    ]);
    k.admission.answer(
        "/",
        Answer::json(200, json!({"ok": true, "decision": "ask", "asks": two})),
    );
    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"to": ["bob@y.com"], "cc": "c@z.com"}),
    );
    let (status, out) = run(&k, &mut f).await.expect("asked");
    let pids: Vec<String> = two
        .as_array()
        .map(|a| {
            a.iter()
                .map(|x| admission::permission_id_for(x["scope"].as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(status, 451);
    assert_eq!(out["permission_ids"], json!(pids));
    assert_eq!(out["recipients"], json!(["bob@y.com", "c@z.com"]));
    assert_eq!((out["resend"].as_str(), out.get("error")), (Some("manual"), None));
    let message = out["message"].as_str().unwrap_or("");
    assert!(
        pids.iter().all(|p| message.contains(p.as_str()))
            && message.contains("bob@y.com, c@z.com")
            && message.contains(&format!("cc-perm status {}", pids[0]))
    );
    assert_eq!(f.meta[META_EFFECT], "require_permission");
    assert_eq!(f.meta[META_RECORD]["permission_id"], json!(pids[0]));
    let pending: Vec<Value> = std::fs::read_to_string(k.rig.dir.path().join("pending.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let last = pending.last().cloned().unwrap_or_default();
    assert_eq!(
        (
            last["recipient"].as_str(),
            last["mailbox"].as_str(),
            last["vm_id"].as_str(),
            last["kind"].as_str()
        ),
        (
            Some("c@z.com"),
            Some("agentmail:a@agentmail.to"),
            Some("vm-a"),
            Some("email_recipient")
        )
    );
    assert_eq!(last["path"], "/v0/inboxes/{id}/messages/send");
    // Once per agent.
    for _ in 0..2 {
        let mut f = post(
            AGENTMAIL_API,
            "/v0/inboxes/a%40agentmail.to/messages/send",
            json!({"to": "bob@y.com"}),
        );
        f.vm_id = Some("vm-b".into());
        run(&k, &mut f).await;
    }
    let n = std::fs::read_to_string(k.rig.dir.path().join("pending.jsonl"))
        .unwrap_or_default()
        .lines()
        .count();
    assert_eq!(n, pending.len() + 2);

    // Gmail: Google's own error object too.
    k.admission.answer(
        "/",
        Answer::json(200, json!({"ok": true, "decision": "ask", "asks": [two[0].clone()]})),
    );
    let raw_ask = b64url(b"To: bob@y.com\r\n\r\nhi");
    let (status, out) = run(
        &k,
        &mut post(
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/send",
            json!({"raw": raw_ask}),
        ),
    )
    .await
    .expect("asked");
    assert_eq!(
        (status, out["reason"].as_str()),
        (451, Some("email_recipient_needs_approval"))
    );
    assert_eq!(out["error"]["code"], 451);
    assert_eq!(out["error"]["status"], "FAILED_PRECONDITION");
    assert_eq!(out["error"]["message"], out["message"]);
    assert_eq!(out["error"]["errors"][0]["reason"], "email_recipient_needs_approval");
    k.admission.answer(
        "/",
        Answer::json(200, json!({"ok": true, "decision": "block", "reason": "not_allowed"})),
    );
    let (status, out) = run(
        &k,
        &mut post(
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/send",
            json!({"raw": raw_ask}),
        ),
    )
    .await
    .expect("refused");
    assert_eq!(
        (
            status,
            out["reason"].as_str(),
            out["error"]["errors"][0]["reason"].as_str()
        ),
        (403, Some("not_allowed"), Some("email_refused"))
    );
    assert!(
        out["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("allowed list"))
    );
    k.admission.answer(
        "/",
        Answer::json(200, json!({"ok": true, "decision": "block", "reason": "hourly_limit"})),
    );
    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"to": "bob@y.com"}),
    );
    assert_eq!(
        run(&k, &mut f).await.map(|a| a.1["reason"].clone()),
        Some(json!("hourly_limit"))
    );
    assert_eq!(f.meta[META_RULE], "email");
    k.admission.answer("/", Answer::json(403, json!({"ok": false})));
    let a = run(
        &k,
        &mut post(
            AGENTMAIL_API,
            "/v0/inboxes/a%40agentmail.to/messages/send",
            json!({"to": "bob@y.com"}),
        ),
    )
    .await;
    assert_eq!(a.map(|a| a.1["reason"].clone()), Some(json!("email_rules_unavailable")));
}

#[tokio::test]
async fn gmail_sends() {
    let k = kit().await;
    allow(&k, &"b".repeat(48));
    let raw = b64url(RAW_MESSAGE);
    for host in [
        "gmail.googleapis.com",
        "www.googleapis.com",
        "gmail.mtls.googleapis.com",
    ] {
        assert!(
            run(
                &k,
                &mut post(
                    host,
                    "/gmail/v1/users/me/messages/send",
                    json!({"raw": raw, "threadId": "t1"})
                )
            )
            .await
            .is_none()
        );
        let c = reserves(&k).pop().unwrap_or_default();
        assert_eq!(
            (c["provider"].as_str(), c["op"].as_str()),
            (Some("gmail"), Some("send"))
        );
        let head = c["head"].as_str().unwrap_or("");
        assert!(head.contains("Bcc: hidden@w.com") && !head.contains("SECRET BODY"));
    }
    let mut f = req(
        "gmail.googleapis.com",
        "/upload/gmail/v1/users/me/messages/send?uploadType=media",
        "POST",
        RAW_MESSAGE,
        "message/rfc822",
        &[],
    );
    assert!(run(&k, &mut f).await.is_none());
    assert!(reserves(&k).pop().is_some_and(|c| {
        c["head"]
            .as_str()
            .is_some_and(|h| h.contains("To: Bob <bob@y.com>") && !h.contains("SECRET"))
    }));
    let mut multipart = b"--BND\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"threadId\":\"t1\"}\r\n--BND\r\nContent-Type: message/rfc822\r\n\r\n".to_vec();
    multipart.extend_from_slice(RAW_MESSAGE);
    multipart.extend_from_slice(b"\r\n--BND--\r\n");
    let mut f = req(
        "gmail.googleapis.com",
        "/upload/gmail/v1/users/me/messages/send?uploadType=multipart",
        "POST",
        &multipart,
        "multipart/related; boundary=\"BND\"",
        &[],
    );
    assert!(run(&k, &mut f).await.is_none());
    assert!(reserves(&k).pop().is_some_and(|c| {
        c["head"]
            .as_str()
            .is_some_and(|h| h.contains("hidden@w.com") && !h.contains("SECRET"))
    }));
    run(
        &k,
        &mut post(
            "gmail.googleapis.com",
            "/gmail/v1/users/me/drafts/send",
            json!({"id": "r-123"}),
        ),
    )
    .await;
    let c = reserves(&k).pop().unwrap_or_default();
    assert_eq!(
        (c["op"].as_str(), c["draftId"].as_str()),
        (Some("draft_send"), Some("r-123"))
    );
    run(
        &k,
        &mut post(
            "gmail.googleapis.com",
            "/gmail/v1/users/me/drafts/send",
            json!({"id": "r-1", "message": {"raw": raw}}),
        ),
    )
    .await;
    let c = reserves(&k).pop().unwrap_or_default();
    assert!(c.get("head").is_some() && c.get("draftId").is_none());

    let before = reserves(&k).len();
    let cases: Vec<(&str, &str, &str, Vec<u8>, &str)> = vec![
        (
            "gmail.googleapis.com",
            "/upload/gmail/v1/users/me/messages/send?uploadType=resumable",
            "POST",
            vec![],
            "unsupported_upload",
        ),
        (
            "gmail.googleapis.com",
            "/batch/gmail/v1",
            "POST",
            b"POST /gmail/v1/users/me/messages/send".to_vec(),
            "unsupported_upload",
        ),
        (
            "www.googleapis.com",
            "/batch",
            "POST",
            b"--b\r\nPOST /gmail/v1/users/me/messages/send\r\n".to_vec(),
            "unsupported_upload",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/settings/forwardingAddresses",
            "POST",
            br#"{"forwardingEmail": "evil@x.com"}"#.to_vec(),
            "forwarding_refused",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/settings/autoForwarding",
            "PUT",
            br#"{"enabled": true}"#.to_vec(),
            "forwarding_refused",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/settings/delegates",
            "POST",
            br#"{"delegateEmail": "evil@x.com"}"#.to_vec(),
            "forwarding_refused",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/settings/filters",
            "POST",
            br#"{"criteria": {}, "action": {"forward": "evil@x.com"}}"#.to_vec(),
            "forwarding_refused",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/import",
            "POST",
            pyjson::dumps(&json!({"raw": raw})).into_bytes(),
            "unknown_write",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/send",
            "POST",
            br#"{"threadId": "t"}"#.to_vec(),
            "unreadable_recipients",
        ),
        (
            "gmail.googleapis.com",
            "/gmail/v1/users/me/settings/forwardingAddresse%73",
            "POST",
            br#"{"forwardingEmail": "evil@x.com"}"#.to_vec(),
            "forwarding_refused",
        ),
    ];
    for (host, p, m, b, reason) in cases {
        let a = run(&k, &mut req(host, p, m, &b, "application/json", &[])).await;
        assert_eq!(a.map(|a| a.1["reason"].clone()), Some(json!(reason)), "{p}");
    }
    assert_eq!(reserves(&k).len(), before);
    assert!(
        run(
            &k,
            &mut post(
                "gmail.googleapis.com",
                "/gmail/v1/users/me/settings/filters",
                json!({"criteria": {"from": "x"}, "action": {"addLabelIds": ["L"]}})
            )
        )
        .await
        .is_none()
    );
    assert!(
        run(
            &k,
            &mut req("www.googleapis.com", "/drive/v3/files", "GET", b"", "", &[])
        )
        .await
        .is_none()
    );

    // Headers that do not end within the limit, and odd paths.
    let mut big = b"To: allowed@ok.com\r\nX-Pad: ".to_vec();
    big.extend(std::iter::repeat_n(b'a', 300_000));
    big.extend_from_slice(b"\r\nBcc: evil@x.com\r\n\r\nbody");
    let a = run(
        &k,
        &mut post(
            "gmail.googleapis.com",
            "/gmail/v1/users/me/messages/send",
            json!({"raw": b64url(&big)}),
        ),
    )
    .await;
    assert_eq!(a.map(|a| a.1["reason"].clone()), Some(json!("unreadable_recipients")));
    for odd in [
        "/gmail/v1/users/me/messages/%73end",
        "//gmail/v1/users/me/messages/send",
        "/gmail/v1/users/me/messages/send/",
    ] {
        let n = reserves(&k).len();
        assert!(
            run(&k, &mut post("gmail.googleapis.com", odd, json!({"raw": raw})))
                .await
                .is_none(),
            "{odd}"
        );
        assert_eq!(reserves(&k).len(), n + 1, "{odd}");
    }
    // Draft edits.
    k.admission
        .answer("/", Answer::json(200, json!({"ok": true, "draftOk": false})));
    let mut f = req(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/drafts/d1",
        "PATCH",
        br#"{"to": "evil@x.com"}"#,
        "application/json",
        &[],
    );
    assert_eq!(
        run(&k, &mut f).await.map(|a| a.1["reason"].clone()),
        Some(json!("draft_busy"))
    );
    assert_eq!(
        reserves(&k).pop(),
        Some(
            json!({"action": "email.draft_write", "provider": "agentmail", "inboxId": "a@agentmail.to", "draftId": "d1"})
        )
    );
    let mut f = req(
        "gmail.googleapis.com",
        "/gmail/v1/users/me/drafts/r-9",
        "PUT",
        pyjson::dumps(&json!({"message": {"raw": raw}})).as_bytes(),
        "application/json",
        &[],
    );
    assert!(run(&k, &mut f).await.is_some());
    assert_eq!(
        reserves(&k).pop(),
        Some(json!({"action": "email.draft_write", "provider": "gmail", "draftId": "r-9"}))
    );
    k.admission
        .answer("/", Answer::json(200, json!({"ok": true, "draftOk": true})));
    let mut f = req(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/drafts/d1",
        "PATCH",
        br#"{"subject": "x"}"#,
        "application/json",
        &[],
    );
    assert!(run(&k, &mut f).await.is_none());
}

#[tokio::test]
async fn the_settle_gives_a_refused_send_its_slot_back() {
    let k = kit().await;
    allow(&k, &"b".repeat(48));
    let mut f = post(
        "gmail.googleapis.com",
        "/gmail/v1/users/me/messages/send",
        json!({"raw": b64url(RAW_MESSAGE)}),
    );
    run(&k, &mut f).await;
    f.response = Some(crate::checks::raw_response(400, b"{}".to_vec(), "application/json"));
    EmailSettle(k.email.clone()).run(Hook::Response, &mut f).await;
    k.rig.settle().await;
    assert_eq!(
        reserves(&k).pop(),
        Some(json!({"action": "email.settle", "id": "b".repeat(48), "rejected": true}))
    );
}

// ---- AgentMail in --------------------------------------------------------------------------------

fn decide_like_the_test(k: &Kit, actions: Vec<Value>) {
    k.admission
        .answer("/", Answer::json(200, json!({"ok": true, "actions": actions})));
}

async fn respond(k: &Kit, path: &str, doc: Value) -> (u16, Value) {
    let mut f = req(AGENTMAIL_API, path, "GET", b"", "", &[]);
    f.response = Some(crate::checks::raw_response(
        200,
        pyjson::dumps(&doc).into_bytes(),
        "application/json",
    ));
    AgentMailResponse(k.email.clone()).run(Hook::Response, &mut f).await;
    let r = f.response.expect("a response");
    (
        r.status().as_u16(),
        serde_json::from_slice(r.body()).unwrap_or(Value::Null),
    )
}

fn base() -> Value {
    json!({"inbox_id": "a@agentmail.to", "thread_id": "t1"})
}

fn with(mut a: Value, b: Value) -> Value {
    if let (Some(a), Some(b)) = (a.as_object_mut(), b.as_object()) {
        a.extend(b.clone());
    }
    a
}

#[tokio::test]
async fn agentmail_answers_are_filtered() {
    let k = kit().await;
    decide_like_the_test(&k, vec![json!({"action": "hide", "reason": "not_allowed"})]);
    let (_, out) = respond(&k, "/v0/inboxes/a%40agentmail.to/messages/m1", with(base(), json!({"message_id": "m1", "from": "Evil <evil@x.com>", "labels": ["received"],
        "text": "SECRET", "html": "<b>SECRET</b>", "subject": "s", "attachments": [{"attachment_id": "x"}], "authentication_results": {"dmarc": "fail"}}))).await;
    assert!(out["labels"].as_array().is_some_and(|l| l.contains(&json!("blocked"))));
    assert_eq!(
        (out["text"].as_str(), out["html"].as_str(), out["subject"].as_str()),
        (Some(""), Some(""), Some(""))
    );
    assert_eq!(
        (out["attachments"].clone(), out["authentication_results"].clone()),
        (json!([]), json!({}))
    );

    decide_like_the_test(
        &k,
        vec![
            json!({"action": "hide"}),
            json!({"action": "strip"}),
            json!({"action": "keep"}),
        ],
    );
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/messages",
        json!({"count": 3, "messages": [
        with(base(), json!({"message_id": "m1", "from": "evil@x.com", "preview": "SECRET"})),
        with(base(), json!({"message_id": "m2", "from": "bob@y.com", "preview": "hello"})),
        with(base(), json!({"message_id": "m3", "from": "a@agentmail.to", "preview": "mine", "text": "t"}))]}),
    )
    .await;
    assert_eq!(
        out["messages"]
            .as_array()
            .map(|m| m.iter().map(|x| x["message_id"].clone()).collect::<Vec<_>>()),
        Some(vec![json!("m2"), json!("m3")])
    );
    assert_eq!(out["count"], 2);
    assert_eq!(
        (
            out["messages"][0]["preview"].as_str(),
            out["messages"][1]["preview"].as_str()
        ),
        (Some(""), Some("mine"))
    );

    decide_like_the_test(&k, vec![json!({"action": "strip"})]);
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/threads",
        json!({"threads": [with(base(), json!({"senders": ["bob@y.com"], "preview": "SECRET", "labels": []}))]}),
    )
    .await;
    assert_eq!(out["threads"][0]["preview"], "");

    // A thread: its messages first, then the thread.
    decide_like_the_test(
        &k,
        vec![
            json!({"action": "hide"}),
            json!({"action": "keep"}),
            json!({"action": "strip"}),
        ],
    );
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/threads/t1",
        with(
            base(),
            json!({"senders": ["evil@x.com", "bob@y.com"], "preview": "p", "messages": [
        with(base(), json!({"message_id": "m1", "from": "evil@x.com", "text": "SECRET"})),
        with(base(), json!({"message_id": "m2", "from": "bob@y.com", "text": "ok"}))]}),
        ),
    )
    .await;
    assert_eq!(out["messages"].as_array().map(|m| m.len()), Some(1));
    assert_eq!(
        (out["messages"][0]["message_id"].as_str(), out["preview"].as_str()),
        (Some("m2"), Some(""))
    );
    let thread_items = k.admission.calls("/").pop().unwrap_or_default();
    assert_eq!(
        thread_items["items"][2],
        json!({"kind": "thread", "senders": ["evil@x.com", "bob@y.com"], "labels": null})
    );

    // No answer from the firewall: nothing is shown.
    k.admission.answer("/", Answer::json(500, json!({"ok": false})));
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/messages",
        json!({"messages": [with(base(), json!({"message_id": "m2", "from": "bob@y.com", "preview": "x"}))]}),
    )
    .await;
    assert_eq!(out["messages"], json!([]));
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"message_id": "m9", "thread_id": "t9"}),
    )
    .await;
    assert_eq!(out, json!({"message_id": "m9", "thread_id": "t9"}));
}

#[tokio::test]
async fn attachments_are_judged_by_their_message() {
    let k = kit().await;
    decide_like_the_test(&k, vec![json!({"action": "hide", "reason": "not_allowed"})]);
    let mut f = req(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/m1/attachments/att1",
        "GET",
        b"",
        "",
        &[],
    );
    assert_eq!(
        run(&k, &mut f).await.map(|a| a.1["reason"].clone()),
        Some(json!("held_back"))
    );
    assert_eq!(
        k.admission.calls("/").pop().map(|c| c["items"].clone()),
        Some(json!([{"kind": "ref", "message_id": "m1"}]))
    );
    decide_like_the_test(&k, vec![json!({"action": "keep"})]);
    assert!(
        run(
            &k,
            &mut req(
                AGENTMAIL_API,
                "/v0/inboxes/a%40agentmail.to/messages/m2/attachments/x",
                "GET",
                b"",
                "",
                &[]
            )
        )
        .await
        .is_none()
    );
    let a = run(
        &k,
        &mut req(AGENTMAIL_API, "/v0/threads/t1/attachments/x", "GET", b"", "", &[]),
    )
    .await;
    assert_eq!(a.map(|a| a.1["reason"].clone()), Some(json!("thread_attachment")));
}

fn frame(event: Value, direction: Direction) -> Flow {
    let mut f = request_flow("GET", "https://ws.agentmail.to/v0", b"");
    f.ws_frame = Some(WsFrame {
        direction,
        kind: FrameKind::Text,
        payload: Bytes::from(pyjson::dumps(&event)),
    });
    f
}

async fn dropped(k: &Kit, event: Value, decision: &str, direction: Direction) -> bool {
    decide_like_the_test(k, vec![json!({"action": decision})]);
    let mut f = frame(event, direction);
    matches!(
        AgentMailSocket(k.email.clone()).run(Hook::WsFrame, &mut f).await,
        Verdict::Drop
    )
}

#[tokio::test]
async fn websocket_events() {
    let k = kit().await;
    let message = with(
        base(),
        json!({"message_id": "m1", "from": "bob@y.com", "labels": ["received"], "text": "hi", "authentication_results": {"dmarc": "pass"}}),
    );
    assert!(
        !dropped(
            &k,
            json!({"type": "event", "event_type": "message.received", "message": message}),
            "keep",
            Direction::In
        )
        .await
    );
    assert!(
        dropped(
            &k,
            json!({"type": "event", "event_type": "message.received", "message": message}),
            "hide",
            Direction::In
        )
        .await
    );
    let n = k.admission.calls("/").len();
    assert!(
        dropped(
            &k,
            json!({"type": "event", "event_type": "message.received.unauthenticated", "message": message}),
            "keep",
            Direction::In
        )
        .await
    );
    assert!(
        dropped(
            &k,
            json!({"type": "event", "event_type": "message.received.spam", "message": message}),
            "keep",
            Direction::In
        )
        .await
    );
    assert!(
        !dropped(
            &k,
            json!({"type": "event", "event_type": "message.sent", "message": message}),
            "keep",
            Direction::In
        )
        .await
    );
    assert_eq!(k.admission.calls("/").len(), n, "none of these was asked about");
    assert!(
        !dropped(
            &k,
            json!({"type": "subscribe", "event_types": ["message.received"]}),
            "keep",
            Direction::Out
        )
        .await
    );
    assert!(
        dropped(
            &k,
            json!({"type": "event", "event_type": "message.received", "message": {"oops": 1}}),
            "keep",
            Direction::In
        )
        .await
    );
    let mut f = request_flow("GET", "https://ws.agentmail.to/v0", b"");
    f.ws_frame = Some(WsFrame {
        direction: Direction::In,
        kind: FrameKind::Text,
        payload: Bytes::from_static(b"not json"),
    });
    assert!(matches!(
        AgentMailSocket(k.email.clone()).run(Hook::WsFrame, &mut f).await,
        Verdict::Drop
    ));
    // The content rules: a blocked message is dropped too.
    k.rig
        .write_rules(json!([rule("salary", "block", "in", &["salary"], &[], &["email"])]));
    let m = with(message.clone(), json!({"text": "about my salary"}));
    assert!(
        dropped(
            &k,
            json!({"type": "event", "event_type": "message.received", "message": m}),
            "keep",
            Direction::In
        )
        .await
    );
}

// ---- content rules on email ------------------------------------------------------------------------

fn channel_rules(k: &Kit) {
    k.rig.write_rules(json!([
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

async fn email_out(k: &Kit, f: &mut Flow) -> Option<(u16, Value)> {
    // The email rules let it through.
    allow(k, &"c".repeat(48));
    run(k, f).await
}

#[tokio::test]
async fn email_out_content_rules() {
    let k = kit().await;
    channel_rules(&k);
    let am = |p: &str, b: Value| post(AGENTMAIL_API, p, b);
    assert!(
        email_out(
            &k,
            &mut am(
                "/v0/inboxes/a%40agentmail.to/messages/send",
                json!({"to": ["x@y.com"], "subject": "hi", "text": "hello"})
            )
        )
        .await
        .is_none()
    );
    let mut f = am(
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"to": ["x@y.com"], "subject": "the Customer List", "text": "see"}),
    );
    let (status, doc) = email_out(&k, &mut f).await.expect("refused");
    assert_eq!(
        (status, doc["error"].as_str(), doc["reason"].as_str()),
        (403, Some("email_refused"), Some("content_rule"))
    );
    assert_eq!(doc["message"], "Blocked by your organization's rules: cust reason");
    assert_eq!(f.meta[META_RULE], "content: cust");
    assert!(
        email_out(
            &k,
            &mut am(
                "/v0/inboxes/a%40agentmail.to/messages/m1/reply",
                json!({"html": "<p>the <b>customer</b>&nbsp;list</p>"})
            )
        )
        .await
        .is_some(),
        "HTML read as text"
    );
    assert!(
        email_out(
            &k,
            &mut am(
                "/v0/inboxes/a%40agentmail.to/messages/m1/reply",
                json!({"html": "<p>the custom<b>er list</b></p>"})
            )
        )
        .await
        .is_some(),
        "an inline tag inside a word is read as a mail client shows it (#561)"
    );
    assert!(
        email_out(
            &k,
            &mut am(
                "/v0/inboxes/a%40agentmail.to/drafts",
                json!({"text": "the customer list"})
            )
        )
        .await
        .is_some(),
        "a draft is read when written"
    );
    let mut f = req(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/m1",
        "PATCH",
        br#"{"labels": ["x"]}"#,
        "application/json",
        &[],
    );
    assert!(email_out(&k, &mut f).await.is_none());
    let key = format!("key sk-ant-{}", "B".repeat(40));
    assert!(
        email_out(
            &k,
            &mut am(
                "/v0/inboxes/a%40agentmail.to/messages/send",
                json!({"to": ["x@y.com"], "text": key})
            )
        )
        .await
        .is_some()
    );

    // Hold: the agent is told it was sent.
    k.rig
        .agent
        .answer("/hold", Answer::json(200, json!({"ok": true, "holdId": "h7"})));
    let mut f = am(
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"to": ["x@y.com"], "subject": "pay", "text": format!("IBAN {IBAN}")}),
    );
    let (status, doc) = email_out(&k, &mut f).await.expect("held");
    assert_eq!(
        (status, doc.clone()),
        (200, json!({"message_id": "held-h7", "thread_id": "held-h7"}))
    );
    let hold = k.rig.agent.calls("/hold").pop().unwrap_or_default();
    assert_eq!(
        (hold["channel"].as_str(), hold["path"].as_str(), hold["chatId"].as_str()),
        (
            Some("email"),
            Some("/v0/inboxes/a%40agentmail.to/messages/send"),
            Some("a@agentmail.to")
        )
    );
    assert_eq!(
        hold.as_object().map(|o| o.keys().next_back().cloned()),
        Some(Some("key".to_owned())),
        "the key comes last here"
    );
    let a = email_out(
        &k,
        &mut am(
            "/v0/inboxes/a%40agentmail.to/drafts",
            json!({"text": format!("IBAN {IBAN}")}),
        ),
    )
    .await;
    assert!(a.is_some_and(|a| a.0 == 403 && a.1["message"].as_str().is_some_and(|m| m.contains("could not be held"))));
    email_out(
        &k,
        &mut am(
            "/v0/inboxes/a%40agentmail.to/messages/send",
            json!({"to": ["x@y.com"], "subject": "hi", "text": "hi", "html": format!("<p>pay {IBAN}</p>")}),
        ),
    )
    .await;
    let hold = k.rig.agent.calls("/hold").pop().unwrap_or_default();
    assert!(
        hold["text"]
            .as_str()
            .is_some_and(|t| t.starts_with("hi") && t.contains("GB82 WEST"))
    );

    // Gmail.
    let raw_mime = |subject: &str, body: &str, html: Option<&str>| {
        let mut m = format!("To: x@y.com\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n");
        match html {
            Some(h) => m.push_str(&format!("Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n{body}\r\n--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n", base64::engine::general_purpose::STANDARD.encode(h))),
            None => m.push_str(&format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{body}")),
        }
        b64url(m.as_bytes())
    };
    let gm = |p: &str, b: Value| post("gmail.googleapis.com", p, b);
    assert!(
        email_out(
            &k,
            &mut gm(
                "/gmail/v1/users/me/messages/send",
                json!({"raw": raw_mime("hi", "hello", None)})
            )
        )
        .await
        .is_none()
    );
    let a = email_out(
        &k,
        &mut gm(
            "/gmail/v1/users/me/messages/send",
            json!({"raw": raw_mime("hi", "hello", Some("<p>the customer list</p>"))}),
        ),
    )
    .await;
    assert_eq!(
        a.map(|a| a.1["reason"].clone()),
        Some(json!("content_rule")),
        "a base64 HTML part"
    );
    assert!(
        email_out(
            &k,
            &mut gm(
                "/gmail/v1/users/me/drafts",
                json!({"message": {"raw": raw_mime("the customer list", "x", None)}})
            )
        )
        .await
        .is_some()
    );
    assert!(
        email_out(&k, &mut gm("/gmail/v1/users/me/drafts/send", json!({"id": "r1"})))
            .await
            .is_none()
    );
    let a = email_out(
        &k,
        &mut gm(
            "/gmail/v1/users/me/messages/send",
            json!({"raw": raw_mime("pay", &format!("IBAN {IBAN}"), None)}),
        ),
    )
    .await;
    assert!(
        a.is_some_and(|a| a.1["message"].as_str().is_some_and(|m| m.contains("could not be held"))),
        "a Gmail send is not held yet"
    );
    for q in ["?uploadType=resumable", "?uploadType=resumable&upload_id=x", ""] {
        let mut f = req(
            "gmail.googleapis.com",
            &format!("/upload/gmail/v1/users/me/drafts{q}"),
            "POST",
            b"To: x@y.com\r\nSubject: hi\r\n\r\nhello",
            "message/rfc822",
            &[],
        );
        assert_eq!(email_out(&k, &mut f).await.map(|a| a.0), Some(403), "{q}");
    }
}

#[tokio::test]
async fn a_forward_is_checked_with_the_mail_it_carries() {
    let k = kit().await;
    channel_rules(&k);
    std::fs::write(
        k.rig.dir.path().join("credentials.json"),
        r#"[{"placeholder": "am-key", "match_domain": "api.agentmail.to", "secret": "real-key", "vm_id": "vm-a"}]"#,
    )
    .expect("creds");
    let fwd = |b: Value| {
        req(
            AGENTMAIL_API,
            "/v0/inboxes/a%40agentmail.to/messages/m1/forward",
            "POST",
            pyjson::dumps(&b).as_bytes(),
            "application/json",
            &[("authorization", "Bearer am-key")],
        )
    };
    k.agentmail.answer(
        "/v0/inboxes/a@agentmail.to/messages/m1",
        Answer::json(
            200,
            json!({"message_id": "m1", "subject": "Q3", "text": "attached: the customer list"}),
        ),
    );
    let a = email_out(&k, &mut fwd(json!({"to": ["x@y.com"]}))).await;
    assert!(a.is_some_and(|a| a.0 == 403 && a.1["message"].as_str().is_some_and(|m| m.contains("cust reason"))));
    k.agentmail.answer(
        "/v0/inboxes/a@agentmail.to/messages/m1",
        Answer::json(200, json!({"message_id": "m1", "subject": "Lunch", "text": "noon?"})),
    );
    assert!(
        email_out(&k, &mut fwd(json!({"to": ["x@y.com"], "text": "fyi"})))
            .await
            .is_none()
    );
    k.agentmail
        .answer("/v0/inboxes/a@agentmail.to/messages/m1", Answer::json(503, json!({})));
    let a = email_out(&k, &mut fwd(json!({"to": ["x@y.com"]}))).await;
    assert!(a.is_some_and(|a| a.0 == 403 && a.1["message"].as_str().is_some_and(|m| m.contains("could not run"))));
}

#[tokio::test]
async fn agentmail_in_content_rules() {
    let k = kit().await;
    channel_rules(&k);
    let keep = |n: usize| (0..n).map(|_| json!({"action": "keep"})).collect::<Vec<_>>();
    decide_like_the_test(&k, keep(1));
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/messages/m1",
        with(
            base(),
            json!({"message_id": "m1", "subject": "about my salary", "text": "x", "labels": ["received"]}),
        ),
    )
    .await;
    assert!(out["labels"].as_array().is_some_and(|l| l.contains(&json!("blocked"))) && out["subject"] == "");
    decide_like_the_test(&k, keep(2));
    let (_, out) = respond(&k, "/v0/inboxes/a%40agentmail.to/messages", json!({"count": 2, "messages": [with(base(), json!({"message_id": "m1", "preview": "salary"})), with(base(), json!({"message_id": "m2", "preview": "hello"}))]})).await;
    assert_eq!(
        (out["messages"][0]["message_id"].as_str(), out["count"].clone()),
        (Some("m2"), json!(1))
    );
    decide_like_the_test(&k, keep(1));
    let (_, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/messages/m3",
        with(
            base(),
            json!({"message_id": "m3", "text": format!("sk-proj-{}", "C".repeat(40)), "labels": []}),
        ),
    )
    .await;
    assert!(
        !out["labels"].as_array().is_some_and(|l| l.contains(&json!("blocked"))),
        "a key sent to the agent is not Leaking secrets"
    );
    // The raw message: refused while a rule reads mail coming in.
    let a = run(
        &k,
        &mut req(
            AGENTMAIL_API,
            "/v0/inboxes/a%40agentmail.to/messages/m1/raw",
            "GET",
            b"",
            "",
            &[],
        ),
    )
    .await;
    assert_eq!(
        a.map(|a| (a.0, a.1["reason"].clone())),
        Some((403, json!("content_rule")))
    );
    // One message read over and over is recorded once.
    let before = k.rig.audit().len();
    for _ in 0..3 {
        respond(
            &k,
            "/v0/inboxes/a%40agentmail.to/messages/m9",
            with(base(), json!({"message_id": "m9", "subject": "salary", "labels": []})),
        )
        .await;
    }
    assert_eq!(k.rig.audit().len(), before + 1);
    // Unknown rules: a read is "try again", a write refused before it goes.
    k.rig.write_file("content-rules.json", "{");
    let (status, out) = respond(
        &k,
        "/v0/inboxes/a%40agentmail.to/messages/m1",
        with(base(), json!({"message_id": "m1", "text": "hi"})),
    )
    .await;
    assert_eq!((status, out["error"].as_str()), (503, Some("rules_loading")));
    let a = run(
        &k,
        &mut post(
            AGENTMAIL_API,
            "/v0/inboxes/a%40agentmail.to/messages/send",
            json!({"to": ["x@y.com"], "text": "hello"}),
        ),
    )
    .await;
    assert_eq!(a.map(|a| a.0), Some(503));
}

#[tokio::test]
async fn a_write_that_went_is_answered_with_its_ids() {
    let k = kit().await;
    channel_rules(&k);
    allow(&k, &"d".repeat(48));
    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"to": ["x@y.com"], "text": "hello"}),
    );
    assert!(run(&k, &mut f).await.is_none());
    assert!(f.meta.contains_key(META_RULES));
    k.rig.write_file("content-rules.json", "{");
    f.response = Some(crate::checks::raw_response(
        200,
        br#"{"message_id": "m5", "thread_id": "t5"}"#.to_vec(),
        "application/json",
    ));
    AgentMailResponse(k.email.clone()).run(Hook::Response, &mut f).await;
    let r = f.response.expect("response");
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn gmail_reads() {
    let k = kit().await;
    channel_rules(&k);
    let read = |p: &str, doc: Value| {
        let mut f = req("gmail.googleapis.com", p, "GET", b"", "", &[]);
        f.response = Some(crate::checks::raw_response(
            200,
            pyjson::dumps(&doc).into_bytes(),
            "application/json",
        ));
        f
    };
    let b = |t: &str| b64url(t.as_bytes());
    let ok = json!({"id": "g1", "snippet": "hello", "payload": {"mimeType": "text/plain", "headers": [{"name": "Subject", "value": "hi"}], "body": {"data": b("hello there")}}});
    let bad = json!({"id": "g2", "snippet": "x", "payload": {"mimeType": "multipart/alternative", "headers": [{"name": "Subject", "value": "news"}],
        "parts": [{"mimeType": "text/html", "body": {"data": b("<p>your salary</p>")}}]}});
    let gi = GmailIn(k.email.clone());
    let status = |f: &Flow| f.response.as_ref().map(|r| r.status().as_u16());
    let mut f = read("/gmail/v1/users/me/messages/g1", ok.clone());
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(200));
    let mut f = read("/gmail/v1/users/me/messages/g2", bad.clone());
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(404));
    assert_eq!(
        f.response.as_ref().map(|r| r.body().clone()),
        Some(Bytes::from(
            r#"{"error": {"code": 404, "message": "Requested entity was not found.", "status": "NOT_FOUND"}}"#
        ))
    );
    let mut f = read(
        "/gmail/v1/users/me/threads/t1",
        json!({"id": "t1", "messages": [ok, bad]}),
    );
    gi.run(Hook::Response, &mut f).await;
    let doc: Value =
        serde_json::from_slice(f.response.as_ref().map(|r| r.body().as_ref()).unwrap_or(b"null")).unwrap_or_default();
    assert_eq!(doc["messages"].as_array().map(|m| m.len()), Some(1));
    let raw = b64url(b"To: x@y.com\r\nSubject: salary review\r\n\r\nx");
    let mut f = read("/gmail/v1/users/me/messages/g3", json!({"id": "g3", "raw": raw}));
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(404), "format=raw");
    let mut f = read(
        "/gmail/v1/users/me/messages/g4",
        json!({"id": "g4", "snippet": "the salary"}),
    );
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(404), "format=metadata: the snippet");
    let mut f = read("/gmail/v1/users/me/messages", json!({"messages": [{"id": "g2"}]}));
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(200), "a list of ids carries no text");
    // The AI could not judge: Gmail's own "try again".
    let mut p = rule("pol", "block", "in", &[], &[], &["email"]);
    p["policy"] = json!("salary");
    k.rig.write_rules(json!([p]));
    k.rig
        .judge
        .answer("/content", Answer::json(200, json!({"failed": true, "why": "cap"})));
    let mut f = read(
        "/gmail/v1/users/me/messages/m1",
        json!({"id": "m1", "snippet": "hello there"}),
    );
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(503));
    // Unknown rules.
    k.rig.write_file("content-rules.json", "{");
    let mut f = read("/gmail/v1/users/me/messages/g1", json!({"id": "g1"}));
    gi.run(Hook::Response, &mut f).await;
    assert_eq!(status(&f), Some(503));
}

#[tokio::test]
async fn no_destination_yet_still_checks() {
    let k = kit().await;
    let mut f = post(AGENTMAIL_API, "/v0/webhooks", json!({"url": "https://evil"}));
    // A flow the plumbing has not given a destination: the claimed name is used.
    let mut bare = crate::flow::Flow::new(f.client_ip, f.connect.clone());
    bare.request = f.request.take();
    bare.vm_id = Some("vm-a".into());
    bare.meta.insert(crate::checks::META_BODY_DECODED, json!(true));
    assert_eq!(
        run(&k, &mut bare).await.map(|a| a.1["reason"].clone()),
        Some(json!("unknown_write"))
    );
}

#[tokio::test]
async fn a_body_not_decoded_is_not_read() {
    let k = kit().await;
    let mut f = post(
        AGENTMAIL_API,
        "/v0/inboxes/a%40agentmail.to/messages/send",
        json!({"to": ["bob@y.com"], "text": "x"}),
    );
    f.meta.remove(crate::checks::META_BODY_DECODED);
    assert_eq!(
        run(&k, &mut f).await.map(|a| a.1["reason"].clone()),
        Some(json!("unreadable_recipients"))
    );
    assert!(reserves(&k).is_empty());
}

#[test]
fn agentmail_paths_as_the_server_routes_them() {
    for (raw, want) in [
        (
            "/v0/inboxes/a%40x.to/messages/m1/%72aw",
            "/v0/inboxes/a@x.to/messages/m1/raw",
        ),
        ("/v0/inboxes/a//messages/send/", "/v0/inboxes/a/messages/send"),
        ("/v0/inboxes/a/drafts/d1/x/../send", "/v0/inboxes/a/drafts/d1/send"),
        (
            "/v0/inboxes/a/./messages/%2e%2e/messages/send",
            "/v0/inboxes/a/messages/send",
        ),
        // An encoded slash or percent stays encoded: the segment stays one, decoded once later.
        ("/v0/inboxes/a%2Fb/messages/send", "/v0/inboxes/a%2Fb/messages/send"),
        ("/v0/inboxes/a%2540/messages/send", "/v0/inboxes/a%2540/messages/send"),
        // Not UTF-8 once decoded: the segment stays as written.
        ("/v0/inboxes/a%FF/messages/send", "/v0/inboxes/a%FF/messages/send"),
    ] {
        assert_eq!(admission::am_path(raw), want, "{raw}");
    }
}

#[tokio::test]
async fn agentmail_routes_written_another_way_are_still_checked() {
    let k = kit().await;
    allow(&k, &"a".repeat(48));
    // A send whose path is encoded or padded still goes through the email rules.
    for path in [
        "/v0/inboxes/ana%40agentmail.to/messages/%73end",
        "/v0/inboxes/ana%40agentmail.to//messages/send/",
        "/v0/inboxes/ana%40agentmail.to/messages/x/../send",
    ] {
        let before = reserves(&k).len();
        let mut f = post(AGENTMAIL_API, path, json!({"to": ["bob@y.com"], "text": "body"}));
        assert!(run(&k, &mut f).await.is_none(), "{path}");
        assert_eq!(reserves(&k).len(), before + 1, "{path}: admitted");
        assert_eq!(
            reserves(&k).last().map(|c| c["inboxId"].clone()),
            Some(json!("ana@agentmail.to"))
        );
    }
    // A raw read written another way is refused like the plain one.
    k.rig
        .write_rules(json!([rule("salary", "block", "in", &["salary"], &[], &["email"])]));
    for path in [
        "/v0/inboxes/a%40agentmail.to/messages/m1/%72aw",
        "/v0/inboxes/a%40agentmail.to/messages/m1/raw/",
        "/v0/inboxes/a%40agentmail.to/messages/m1/RAW",
    ] {
        let a = run(&k, &mut req(AGENTMAIL_API, path, "GET", b"", "", &[])).await;
        assert_eq!(
            a.map(|a| (a.0, a.1["reason"].clone())),
            Some((403, json!("content_rule"))),
            "{path}"
        );
    }
}
