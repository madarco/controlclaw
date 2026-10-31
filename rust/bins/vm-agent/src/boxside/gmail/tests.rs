//! `gmail-watch.test.ts` and `gmail-wake.test.ts`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cc_proc::{RecordingRunner, exit, ok};
use serde_json::{Map, Value, json};

use super::*;

fn body(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

fn watch_body() -> Value {
    json!({"audience": "https://fw.example.com/hooks/abc", "path": "/gmail-pubsub", "port": 8701, "account": "ops@example.com", "topic": "projects/p/topics/t"})
}

#[test]
fn the_watch_config_is_checked_before_it_reaches_a_unit_file() {
    let c = GmailWatch::parse(&body(watch_body())).expect("good");
    assert_eq!((c.port, c.subject_email.clone()), (8701, None));
    let bad = |patch: Value| {
        let mut b = watch_body();
        for (k, v) in patch.as_object().expect("o") {
            b[k] = v.clone();
        }
        GmailWatch::parse(&body(b)).expect_err("bad")
    };
    assert_eq!(
        bad(json!({"audience": "http://fw.example.com"})),
        "audience must be the registration's https URL"
    );
    assert_eq!(bad(json!({"path": "gmail"})), "path must start with /");
    assert_eq!(
        bad(json!({"path": "/x\nCC_GMAIL_PORT=3100"})),
        "path may not contain a newline or an ="
    );
    assert_eq!(bad(json!({"topic": "a=b"})), "topic may not contain a newline or an =");
    assert_eq!(bad(json!({"port": 3100})), "port must be between 8700 and 8799");
    assert_eq!(bad(json!({"port": 8700.5})), "port must be between 8700 and 8799");
    assert_eq!(
        GmailWatch::parse(&body({
            let mut b = watch_body();
            b["port"] = json!("8702");
            b
        }))
        .expect("string port")
        .port,
        8702
    );
}

#[tokio::test]
async fn apply_writes_the_env_file_restarts_the_unit_and_renew_uses_it() {
    let r = RecordingRunner::new();
    r.answer(&["systemctl", "is-active"], ok("active\n"));
    r.answer(&["sudo"], ok(""));
    r.answer_with(|c| c.program.ends_with("gog").then(|| ok("gog 0.41.0\n")));
    let dir = tempfile::tempdir().expect("dir");
    let w = GmailWatch::new(
        Arc::new(r.clone()),
        dir.path().join("etc/gmail-watch.env"),
        dir.path().join("gmail-watch.json"),
    )
    .with_gog(dir.path().join("gog"));
    assert!(!w.supported());
    assert_eq!(w.status().await["configured"], false);
    let s = w
        .apply(&GmailWatch::parse(&body(watch_body())).expect("p"))
        .await
        .expect("apply");
    assert_eq!(s["configured"], true);
    assert_eq!(s["running"], true);
    assert_eq!(s["port"], 8701);
    assert_eq!(s["gogVersion"], "gog 0.41.0");
    let env = std::fs::read_to_string(dir.path().join("etc/gmail-watch.env")).expect("env");
    let keys: Vec<&str> = env
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split('=').next().unwrap_or(""))
        .collect();
    assert_eq!(
        keys,
        [
            "CC_GMAIL_AUDIENCE",
            "CC_GMAIL_PATH",
            "CC_GMAIL_PORT",
            "CC_GMAIL_ACCOUNT",
            "CC_GMAIL_TOPIC",
            "OPENCLAW_SKIP_GMAIL_WATCHER"
        ]
    );
    assert!(
        r.calls()
            .iter()
            .any(|c| c.program == "sudo" && c.args == ["systemctl", "restart", "cc-gmail-watch.service"])
    );
    assert_eq!(w.renew().await, json!({"ok": true, "message": "Watch renewed."}));
    assert!(r.calls().iter().any(|c| c.args
        == [
            "gmail",
            "watch",
            "start",
            "--account",
            "ops@example.com",
            "--label",
            "INBOX",
            "--topic",
            "projects/p/topics/t"
        ]));
    let cleared = w.clear().await;
    assert_eq!(cleared["configured"], false);
    assert!(!dir.path().join("etc/gmail-watch.env").exists());
    assert_eq!(
        w.renew().await,
        json!({"ok": false, "message": "This box is not watching a mailbox."})
    );

    let r = RecordingRunner::new();
    r.answer(&["sudo"], exit(1, "Failed to restart"));
    let w = GmailWatch::new(Arc::new(r), dir.path().join("e2"), dir.path().join("s2"));
    assert!(
        w.apply(&GmailWatch::parse(&body(watch_body())).expect("p"))
            .await
            .is_err()
    );
}

fn wake() -> Value {
    json!({"messageId": "1a1084d42bb053f0", "threadId": "1a1084d42bb053f0", "from": "ada@example.com", "subject": "Quarterly\nnumbers\u{0}  please"})
}

#[test]
fn the_wake_turn_carries_vetted_metadata_only() {
    let w = GmailWake::parse(&body(wake())).expect("wake");
    let m = wake_message(&w);
    assert!(m.starts_with("New email in the organization's Gmail from ada@example.com.\n"));
    assert!(m.contains("Subject (written by the sender): \"Quarterly numbers please\"\n"));
    assert!(m.contains("`gog gmail reply 1a1084d42bb053f0 --body '…'`"));
    for from in ["user@xn--p1ai.xn--p1ai", "a#b%c=d!e@example.com", "x@sub.example.co.uk"] {
        let mut b = wake();
        b["from"] = json!(from);
        assert!(GmailWake::parse(&body(b)).is_some(), "{from}");
    }
    let mut b = wake();
    b["subject"] = json!("s".repeat(1200));
    assert!(GmailWake::parse(&body(b)).is_some());
    let mut b = wake();
    b["from"] = json!("two@a.com, b@c.com");
    assert!(GmailWake::parse(&body(b)).is_none());
    let mut b = wake();
    b.as_object_mut().expect("o").remove("subject");
    assert_eq!(GmailWake::parse(&body(b)).expect("no subject").subject, "");
    let long = clean_subject(&"é".repeat(300));
    assert_eq!(long.chars().count(), 200);
    assert!(long.ends_with('…'));
}

#[tokio::test]
async fn a_turn_submitted_while_the_gateway_restarts_is_retried_until_it_listens() {
    let tb = crate::boxside::testing::test_box();
    let state = tb.dir.path().join("openclaw-hooks.json");
    std::fs::write(&state, json!({"token": "a".repeat(64)}).to_string()).expect("w");
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, String, String)>::new()));
    let (c, s) = (calls.clone(), seen.clone());
    let mut router = cc_http::Router::new(&["all"]);
    router.prefix("all", "/", move |req, _| {
        let (c, s) = (c.clone(), s.clone());
        async move {
            let h = |n: &str| {
                req.headers()
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string()
            };
            s.lock()
                .expect("l")
                .push((h("authorization"), h("idempotency-key"), req.uri().path().to_string()));
            if c.fetch_add(1, Ordering::SeqCst) < 2 {
                cc_http::json(502, &json!({}))
            } else {
                cc_http::json(200, &json!({"runId": "r1"}))
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    let w = GmailWake::new(&tb.app, state).for_test(port, 5, Duration::from_millis(1));
    let out = w
        .wake(&GmailWake::parse(&body(wake())).expect("w"))
        .await
        .expect("wake");
    assert_eq!(out, json!({"ok": true, "status": 200}));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let first = seen.lock().expect("l")[0].clone();
    assert_eq!(
        first,
        (
            format!("Bearer {}", "a".repeat(64)),
            "gmail-1a1084d42bb053f0".into(),
            "/hooks/agent".into()
        )
    );
    let r = w.run("m", "n", "k", Map::new(), None, Some(1)).await.expect("run");
    assert_eq!(r.body, Some(json!({"runId": "r1"})));
}

#[tokio::test]
async fn without_openclaw_the_hooks_cannot_be_turned_on() {
    let tb = crate::boxside::testing::test_box();
    let w = GmailWake::new(&tb.app, tb.dir.path().join("hooks.json"));
    assert_eq!(w.ensure_hooks().await, Err("OpenClaw is not running".into()));
    assert!(w.submit("m", "n", "k").await.is_err(), "the TS throws out of run()");
}

#[test]
fn the_port_is_read_as_javascript_number_reads_it_and_spaces_as_its_regexes_do() {
    let port = |v: Value| {
        let mut b = watch_body();
        b["port"] = v;
        GmailWatch::parse(&body(b)).map(|c| c.port)
    };
    assert_eq!(port(json!("0o21004")), Ok(8708));
    assert_eq!(port(json!("\u{feff}8710")), Ok(8710));
    assert_eq!(port(json!(["8711"])), Ok(8711));
    assert!(port(json!("Infinity")).is_err());
    // U+FEFF is space to JavaScript: not in an audience.
    let mut b = watch_body();
    b["audience"] = json!("https://fw.example.com/\u{feff}x");
    assert!(GmailWatch::parse(&body(b)).is_err());
    // U+0085 is not: kept in a subject.
    assert_eq!(clean_subject("a\u{85}b"), "a\u{85}b");
}

#[test]
fn a_subject_cut_through_an_emoji_is_quoted_as_javascript_quotes_it() {
    let w = WakeInput {
        message_id: "m".into(),
        thread_id: "t".into(),
        from: "a@b.co".into(),
        subject: format!("{}😀b", "a".repeat(198)),
    };
    assert!(wake_message(&w).contains(&format!("\"{}\\ud83d…\"", "a".repeat(198))));
}

#[tokio::test]
async fn a_value_ending_in_a_backslash_cannot_carry_on_to_the_next_line() {
    // Intentional difference: the TS writes values bare, so `\` at the end joined the next line.
    let r = RecordingRunner::new();
    r.answer_with(|_| Some(ok("")));
    let dir = tempfile::tempdir().expect("dir");
    let w = GmailWatch::new(
        Arc::new(r),
        dir.path().join("gmail-watch.env"),
        dir.path().join("gmail-watch.json"),
    );
    let mut b = watch_body();
    b["subjectEmail"] = json!("svc@x.iam.gserviceaccount.com\\");
    b["account"] = json!("o\"ps@example.com");
    w.apply(&GmailWatch::parse(&body(b)).expect("p")).await.expect("apply");
    let env = std::fs::read_to_string(dir.path().join("gmail-watch.env")).expect("env");
    assert!(env.contains("CC_GMAIL_OIDC_EMAIL=\"svc@x.iam.gserviceaccount.com\\\\\"\n"));
    assert!(env.contains("CC_GMAIL_ACCOUNT=\"o\\\"ps@example.com\"\n"));
    assert!(env.contains("\nOPENCLAW_SKIP_GMAIL_WATCHER=1\n"), "still its own line");
    assert!(env.contains("CC_GMAIL_PORT=8701\n"));
}
