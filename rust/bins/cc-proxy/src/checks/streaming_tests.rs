//! Which bodies W2's steps read (`Step::reads_body`, #625), and the refusal of a request a check
//! concerns whose body went past the checks anyway.

use serde_json::json;

use super::testkit::Rig;
use super::{META_BODY_DECODED, META_REQUEST_STREAMED};
use crate::flow::testing::request_flow;
use crate::flow::{Flow, Hook, Pipeline, Verdict};

const TG_SEND: &str = "https://api.telegram.org/bot123456:CC-TG-placeholder/sendMessage";
const TG_UPDATES: &str = "https://api.telegram.org/bot123456:CC-TG-placeholder/getUpdates";
const SLACK_POST: &str = "https://slack.com/api/chat.postMessage";
const AM_SEND: &str = "https://api.agentmail.to/v0/inboxes/a%40agentmail.to/messages/send";
const GMAIL_SEND: &str = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";
const TWILIO_CALL: &str = "https://api.twilio.com/2010-04-01/Accounts/ACa/Calls.json";

async fn kit() -> (Rig, Pipeline) {
    let rig = Rig::new().await;
    rig.write_rules(json!([]));
    let mut p = Pipeline::new();
    super::register_with(&mut p, rig.settings.clone());
    (rig, p)
}

/// A request as the plumbing has it before its body: the head only, with a length.
fn head(method: &str, url: &str, ctype: &str, len: u64) -> Flow {
    let mut f = request_flow(method, url, b"");
    if let Some(r) = f.request.as_mut() {
        if !ctype.is_empty()
            && let Ok(v) = http::HeaderValue::from_str(ctype)
        {
            r.headers_mut().insert(http::header::CONTENT_TYPE, v);
        }
        if len > 0 {
            r.headers_mut()
                .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
        }
    }
    f
}

/// What the plumbing leaves on a request no step said it reads.
fn streamed(mut f: Flow) -> Flow {
    f.meta.insert(META_BODY_DECODED, json!(false));
    f.meta.insert(META_REQUEST_STREAMED, json!(true));
    f
}

#[tokio::test]
async fn the_bodies_w2_reads() {
    let (_rig, p) = kit().await;
    let reads = |mut f: Flow, hook: Hook| p.reads_body(hook, &mut f);
    for (url, why) in [
        (TG_SEND, "Telegram"),
        (SLACK_POST, "Slack"),
        (AM_SEND, "AgentMail"),
        (GMAIL_SEND, "Gmail"),
        (TWILIO_CALL, "Twilio"),
        ("https://example.com/upload", "any site: a tool call can be in any body"),
    ] {
        assert!(reads(head("POST", url, "application/json", 20), Hook::Request), "{why}");
    }
    // A body that is not there is not read; nor one to a model provider W2 has nothing to check on.
    assert!(!reads(head("GET", "https://example.com/", "", 0), Hook::Request));
    assert!(!reads(
        head(
            "POST",
            "https://api.openai.com/v1/chat/completions",
            "application/json",
            20
        ),
        Hook::Request
    ));
    // Answers: only those a check reads.
    assert!(reads(head("POST", TG_UPDATES, "", 0), Hook::Response), "getUpdates");
    let mut mail = head("GET", "https://api.agentmail.to/v0/inboxes/a/messages/m1", "", 0);
    mail.response = Some(super::raw_response(200, b"{}".to_vec(), "application/json"));
    assert!(reads(mail, Hook::Response), "an AgentMail answer");
    let mut err = head("GET", "https://api.agentmail.to/v0/inboxes/a/messages/m1", "", 0);
    err.response = Some(super::raw_response(404, b"not found".to_vec(), "text/plain"));
    assert!(!reads(err, Hook::Response), "an error page is not filtered");
    assert!(!reads(
        head("GET", "https://example.com/big.iso", "", 0),
        Hook::Response
    ));
    let mut listed = head("POST", "https://mcp.example.com/mcp", "application/json", 20);
    listed.meta.insert(super::mcp::META_KIND, json!("list"));
    assert!(reads(listed, Hook::Response), "a tools/list answer");
}

#[tokio::test]
async fn a_body_streamed_past_a_check_that_concerns_it_is_refused() {
    let (rig, p) = kit().await;
    for (url, ctype, why) in [
        (TG_SEND, "application/json", "Telegram"),
        (SLACK_POST, "application/json", "Slack"),
        (AM_SEND, "application/json", "AgentMail"),
        (TWILIO_CALL, "application/x-www-form-urlencoded", "Twilio"),
        ("https://example.com/mcp", "application/json", "a possible tool call"),
    ] {
        let mut f = streamed(head("POST", url, ctype, 30));
        assert!(
            matches!(p.run(Hook::Request, &mut f).await, Verdict::Answer(_)),
            "{why}: refused, never passed unread"
        );
    }
    // A login added after the plumbing decided: the tripwire cannot read the body, so refused.
    rig.write_file(
        "credentials.json",
        &json!([{"login_id": "lg_1", "login_name": "ops", "vm_id": "vm_test", "placeholder": "Kq7-xT2_mN9.vRw4bZ",
                 "secret": "pw", "allowed_hosts": ["login.example.com"]}])
        .to_string(),
    );
    let mut f = streamed(head(
        "POST",
        "https://login.example.com/session",
        "application/x-www-form-urlencoded",
        30,
    ));
    assert!(
        matches!(p.run(Hook::Request, &mut f).await, Verdict::Answer(_)),
        "an agent with a login"
    );
    // A streamed request with no body is not one a check could not read.
    let mut f = streamed(head("GET", "https://example.com/", "", 0));
    assert!(matches!(p.run(Hook::Request, &mut f).await, Verdict::Continue));
}

#[tokio::test]
async fn review_of_the_declarations() {
    let (rig, p) = kit().await;
    // An HTTP/2 request with no length can still send a body: read.
    let mut h2 = head("POST", TG_SEND, "application/json", 0);
    if let Some(r) = h2.request.as_mut() {
        *r.version_mut() = http::Version::HTTP_2;
    }
    assert!(super::request_has_body(&h2));
    assert!(p.reads_body(Hook::Request, &mut h2));
    // An upload to an ordinary site streams while no web rule reads it; a PUT is no tool call.
    let mut up = head(
        "PUT",
        "https://bucket.example.com/a.iso",
        "application/octet-stream",
        1 << 30,
    );
    assert!(!p.reads_body(Hook::Request, &mut up));
    // With a web rule: a form is read, a large file still streams, and is not refused for it.
    rig.write_rules(json!([super::testkit::rule(
        "cust",
        "block",
        "out",
        &["customer list"],
        &[],
        &["web"]
    )]));
    let mut form = head(
        "POST",
        "https://forms.example.com/submit",
        "application/x-www-form-urlencoded",
        30,
    );
    assert!(p.reads_body(Hook::Request, &mut form));
    let mut file = head(
        "PUT",
        "https://bucket.example.com/a.iso",
        "application/octet-stream",
        1 << 30,
    );
    assert!(!p.reads_body(Hook::Request, &mut file));
    let mut file = streamed(file);
    assert!(matches!(p.run(Hook::Request, &mut file).await, Verdict::Continue));
    rig.write_rules(json!([]));
    // Another agent's stand-in, from an agent with no login, in a body that streamed: refused.
    rig.write_file(
        "credentials.json",
        &json!([{"login_id": "lg_1", "login_name": "ops", "vm_id": "other", "placeholder": "Kq7-xT2_mN9.vRw4bZ",
                 "secret": "pw", "allowed_hosts": ["login.example.com"]}])
        .to_string(),
    );
    let mut f = head("POST", "https://evil.example/x", "application/json", 30);
    assert!(p.reads_body(Hook::Request, &mut f), "any login: every body is read");
    let mut f = streamed(f);
    match p.run(Hook::Request, &mut f).await {
        Verdict::Answer(r) => assert!(
            !String::from_utf8_lossy(r.body()).contains("ops"),
            "no other agent's login named"
        ),
        other => panic!("not refused: {other:?}"),
    }
}

#[tokio::test]
async fn a_twilio_read_with_no_body_goes() {
    let (rig, p) = kit().await;
    rig.write_file(
        "credentials.json",
        &json!([{"placeholder": "CC-TWILIO-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "secret": "cccccccccccccccccccccccccccccccc",
                 "match_domain": "api.twilio.com", "vm_id": "vm_test", "locations": ["basic:authorization"],
                 "phone": {"account_sid": "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "from_number": "+14155550123",
                           "hook_url": "https://firewall.example/hook/hk_test"}}])
        .to_string(),
    );
    let mut f = head(
        "GET",
        "https://api.twilio.com/2010-04-01/Accounts/ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Calls/CA0123456789abcdef0123456789abcdef.json",
        "",
        0,
    );
    if let Some(r) = f.request.as_mut() {
        r.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static(
                "Basic QUNhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYTpDQy1UV0lMSU8tYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
            ),
        );
    }
    assert!(!p.reads_body(Hook::Request, &mut f));
    let mut f = streamed(f);
    assert!(
        matches!(p.run(Hook::Request, &mut f).await, Verdict::Continue),
        "a read of a call's status"
    );
}
