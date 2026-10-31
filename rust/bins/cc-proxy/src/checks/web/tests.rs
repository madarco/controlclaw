//! Ported from test_content_rules_channels.py (the web) and test_content_policies.py (a website post).

use bytes::Bytes;
use serde_json::{Value, json};

use super::*;
use crate::checks::pyjson;
use crate::checks::testkit::{Answer, Rig, rule};
use crate::flow::testing::request_flow;

const IBAN: &str = "GB82 WEST 1234 5698 7654 32";

fn web(rig: &Rig) -> Arc<Web> {
    Arc::new(Web {
        content: rig.content.clone(),
        control_plane_host: Some("controlclaw.test".into()),
        creds: Arc::new(crate::checks::creds::Creds::new(
            rig.dir.path().join("credentials.json"),
        )),
    })
}

fn post(host: &str, path: &str, method: &str, body: &[u8], ctype: &str) -> Flow {
    let mut f = request_flow(method, &format!("https://{host}{path}"), b"");
    let mut b = http::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"));
    if !ctype.is_empty() {
        b = b.header("content-type", ctype);
    }
    f.request = b.body(Bytes::from(body.to_vec())).ok();
    f.vm_id = Some("vm1".into());
    f.meta.insert(crate::checks::META_BODY_DECODED, json!(true));
    f
}

async fn run(w: &Arc<Web>, mut f: Flow) -> Option<Value> {
    match WebStep(w.clone()).run(Hook::Request, &mut f).await {
        Verdict::Continue => None,
        Verdict::Answer(r) => {
            assert_eq!(r.status(), 403);
            Some(serde_json::from_slice(r.body()).unwrap_or(Value::Null))
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn msg(d: &Option<Value>) -> String {
    d.as_ref().and_then(|d| d["message"].as_str()).unwrap_or("").to_owned()
}

#[tokio::test]
async fn the_web() {
    let rig = Rig::new().await;
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
    ]));
    std::fs::write(
        rig.dir.path().join("credentials.json"),
        r#"[{"placeholder": "P", "match_domain": "llm.example", "secret": "s", "model": "x/y"}]"#,
    )
    .expect("creds");
    let w = web(&rig);
    let j = |v: Value| pyjson::dumps(&v).into_bytes();
    let d = run(
        &w,
        post(
            "forms.example.com",
            "/submit",
            "POST",
            &j(json!({"name": "x", "notes": {"a": ["the customer list"]}})),
            "application/json",
        ),
    )
    .await;
    assert_eq!(
        d.as_ref().map(|d| (d["error"].clone(), d["host"].clone())),
        Some((json!("blocked_by_content_rule"), json!("forms.example.com")))
    );
    assert!(msg(&d).contains("cust reason"));
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                b"q=the+customer+list",
                "application/x-www-form-urlencoded"
            )
        )
        .await
        .is_some()
    );
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                b"the customer list",
                "text/plain"
            )
        )
        .await
        .is_some()
    );
    let d = run(
        &w,
        post(
            "forms.example.com",
            "/submit",
            "POST",
            format!("IBAN {IBAN}").as_bytes(),
            "text/plain",
        ),
    )
    .await;
    assert!(msg(&d).contains("cannot be held"));
    assert_eq!(rig.audit().pop().map(|a| a["held"].clone()), Some(json!(false)));
    assert!(
        run(
            &w,
            post("forms.example.com", "/submit", "POST", b"my budget", "text/plain")
        )
        .await
        .is_none()
    );
    assert_eq!(
        rig.audit().pop().map(|a| (a["rule"].clone(), a["channel"].clone())),
        Some((json!("watch"), json!("web")))
    );
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                b"\x89PNG\r\n\x1a\n customer list",
                "image/png"
            )
        )
        .await
        .is_none(),
        "a file"
    );
    let tok = json!({"id_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"});
    assert!(
        run(
            &w,
            post("forms.example.com", "/submit", "POST", &j(tok), "application/json")
        )
        .await
        .is_none(),
        "sign-ins post tokens"
    );
    for host in [
        "api.openai.com",
        "llm.example",
        "controlclaw.test",
        "api.telegram.org",
        "slack.com",
    ] {
        assert!(
            run(
                &w,
                post(
                    host,
                    "/api/x.y",
                    "POST",
                    &j(json!({"messages": [{"content": "the customer list"}]})),
                    "application/json"
                )
            )
            .await
            .is_none(),
            "{host}"
        );
    }
    assert!(
        run(&w, post("forms.example.com", "/search?q=customer+list", "GET", b"", ""))
            .await
            .is_none()
    );
    let d = run(
        &w,
        post(
            "forms.example.com",
            "/submit",
            "POST",
            &j(json!({"x": "y".repeat(TEXT_MAX_LONG + 1)})),
            "application/json",
        ),
    )
    .await;
    assert!(msg(&d).contains("too long to check"));
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                &j(json!({"x": "y".repeat(200_000)})),
                "application/json"
            )
        )
        .await
        .is_none()
    );
    // The Gmail API by its path, never its query.
    assert!(
        run(
            &w,
            post(
                "www.googleapis.com",
                "/upload/drive/v3/files?x=/gmail/",
                "POST",
                &j(json!({"name": "the customer list"})),
                "application/json"
            )
        )
        .await
        .is_some()
    );
    assert!(
        run(
            &w,
            post(
                "gmail.googleapis.com",
                "/gmail/v1/users/me/messages/send",
                "POST",
                &j(json!({"raw": "x", "note": "the customer list"})),
                "application/json"
            )
        )
        .await
        .is_none()
    );
    // Size first.
    let big = format!(r#"{{"x": "{}"}}"#, " ".repeat(WEB_BODY_READ_MAX + 1));
    assert!(
        msg(&run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                big.as_bytes(),
                "application/json"
            )
        )
        .await)
        .contains("too long to check")
    );
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                &vec![b'x'; WEB_BODY_READ_MAX + 1],
                "application/octet-stream"
            )
        )
        .await
        .is_none()
    );
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                &vec![b'x'; WEB_BODY_READ_MAX + 1],
                ""
            )
        )
        .await
        .is_some()
    );
    // A number under a text is read as written (#561): a card number as a JSON number is stopped.
    rig.write_rules(json!([rule("card", "block", "out", &[], &["card"], &["web"])]));
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                br#"{"order": 4111111111111111}"#,
                "application/json"
            )
        )
        .await
        .is_some()
    );
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                br#"{"order": "4111111111111111"}"#,
                "application/json"
            )
        )
        .await
        .is_some()
    );
    rig.write_rules(json!([rule(
        "cust",
        "block",
        "out",
        &["customer list"],
        &[],
        &["slack", "email", "web"]
    )]));
    // A repeated key: the last copy is read, as `json.loads` reads it.
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                br#"{"a": "hello", "a": "the customer list"}"#,
                "application/json"
            )
        )
        .await
        .is_some()
    );
    // No rule on the web: nothing is read. Unknown rules: refused.
    rig.write_rules(json!([rule(
        "cust",
        "block",
        "out",
        &["customer list"],
        &[],
        &["slack"]
    )]));
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                b"the customer list",
                "text/plain"
            )
        )
        .await
        .is_none()
    );
    rig.write_file("content-rules.json", "{");
    assert!(
        msg(&run(&w, post("forms.example.com", "/submit", "POST", b"hello", "text/plain")).await)
            .contains("could not run")
    );
}

#[tokio::test]
async fn a_website_post_and_the_ai() {
    let rig = Rig::new().await;
    let mut salary = rule("salary", "block", "both", &[], &[], &["*"]);
    salary["policy"] = json!("Can't ask about or share anyone's salary.");
    rig.write_rules(json!([salary]));
    let w = web(&rig);
    rig.judge
        .answer("/content", Answer::json(200, json!({"matches": ["salary"]})));
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                br#"{"q": "What is Anna's salary?"}"#,
                "application/json"
            )
        )
        .await
        .is_some()
    );
    assert_eq!(rig.audit().pop().map(|a| a["ai"].clone()), Some(json!("found")));
    rig.judge.answer("/content", Answer::json(200, json!({"failed": true})));
    let d = run(
        &w,
        post(
            "forms.example.com",
            "/submit",
            "POST",
            br#"{"q": "pizza"}"#,
            "application/json",
        ),
    )
    .await;
    assert!(msg(&d).contains("the AI check could not run"));
    assert_eq!(rig.audit().pop().map(|a| a["ai"].clone()), Some(json!("failed")));
}

// ---- host review of #539 (production's #561) ----

#[tokio::test]
async fn host_review_539_multipart_and_unreadable_json() {
    let rig = Rig::new().await;
    rig.write_rules(json!([rule("cust", "block", "out", &["customer list"], &[], &["web"])]));
    let w = web(&rig);
    let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nthe customer list\r\n--XyZ--\r\n";
    // A quoted boundary, and the parameter's name in another case, are read.
    for ctype in [
        "multipart/form-data; boundary=\"XyZ\"",
        "multipart/form-data; Boundary=XyZ",
    ] {
        assert!(
            run(&w, post("forms.example.com", "/submit", "POST", body, ctype))
                .await
                .is_some(),
            "{ctype}"
        );
    }
    // A body that does not split on its boundary is refused, never read as an empty form.
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                body,
                "multipart/form-data; boundary=Other"
            )
        )
        .await
        .is_some()
    );
    // A part in base64, or in another charset: refused.
    for head in [
        "Content-Disposition: form-data; name=\"note\"\r\nContent-Transfer-Encoding: base64",
        "Content-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain; charset=latin-1",
        "Content-Disposition: form-data; name*=utf-8''note",
    ] {
        let b = format!("--XyZ\r\n{head}\r\n\r\nhello\r\n--XyZ--\r\n");
        assert!(
            run(
                &w,
                post(
                    "forms.example.com",
                    "/submit",
                    "POST",
                    b.as_bytes(),
                    "multipart/form-data; boundary=XyZ"
                )
            )
            .await
            .is_some(),
            "{head}"
        );
    }
    // Deeper than the walk goes: every string, escapes undone.
    let deep = format!("{}\"the cust\\u006fmer list\"{}", "[".repeat(25), "]".repeat(25));
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                deep.as_bytes(),
                "application/json"
            )
        )
        .await
        .is_some()
    );
    // A repeated key in JSON inside a string: the same.
    let dup = r#"{"a": "{\"x\": 1, \"x\": \"the customer list\"}"}"#;
    assert!(
        run(
            &w,
            post(
                "forms.example.com",
                "/submit",
                "POST",
                dup.as_bytes(),
                "application/json"
            )
        )
        .await
        .is_some()
    );
}
