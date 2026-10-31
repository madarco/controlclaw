use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use serde_json::json;

use super::*;

type Calls = Arc<Mutex<Vec<(&'static str, Option<String>)>>>;

fn fixture() -> (Arc<Options>, Calls, Arc<AtomicUsize>) {
    let calls: Calls = Arc::default();
    let updates = Arc::new(AtomicUsize::new(0));
    let (c, u) = (calls.clone(), updates.clone());
    let opts = Options {
        logs: Arc::new(|range, service| {
            Box::pin(async move {
                let mut r = json!({
                    "firewall": "fw.example", "range": range, "service": service, "update": null, "truncated": false,
                    "services": [{"id": "caddy", "label": "Caddy", "about": "", "active": "failed", "sub": "failed", "result": "exit-code", "since": null, "restarts": 3, "exitStatus": 1, "optional": false}],
                    "lines": [{"time": "2026-10-09T00:00:00Z", "service": "caddy", "level": "error", "message": "bad token sk-secret-value in Caddyfile"}],
                });
                if service == "run" {
                    r["run"] = json!(["TASK [x] failed sk-secret-value"]);
                }
                Ok(r)
            })
        }),
        repair: Arc::new(move |verb, arg| {
            c.lock().expect("lock").push((verb, arg.clone()));
            Box::pin(async move {
                if verb == "restart" && arg.as_deref() == Some("caddy") {
                    return Err(RepairError {
                        message: "cc-fw-repair: caddy did not start".into(),
                        output: None,
                    });
                }
                if verb == "check" && arg.as_deref() == Some("caddy") {
                    return Err(RepairError {
                        message: "cc-fw-repair: the Caddy configuration is not valid".into(),
                        output: Some("Error: Caddyfile:93 unrecognized directive sk-secret-value".into()),
                    });
                }
                Ok(format!("ok {verb} {} sk-secret-value", arg.unwrap_or_default()))
            })
        }),
        update: Arc::new(move || {
            u.fetch_add(1, Ordering::SeqCst);
            "started".into()
        }),
        redact: Arc::new(|t| t.replace("sk-secret-value", "[REDACTED]")),
    };
    (Arc::new(opts), calls, updates)
}

#[tokio::test]
async fn verbs_are_fixed_arguments_allow_listed_every_answer_redacted() {
    let (o, calls, updates) = fixture();
    let status = run_command(&o, "status", None, None).await;
    assert!(
        regex::Regex::new(r"caddy\s+failed/failed result=exit-code restarts=3")
            .expect("re")
            .is_match(&status.text),
        "{}",
        status.text
    );
    assert!(!status.text.contains("sk-secret-value"));
    assert!(
        run_command(&o, "logs", Some("caddy"), Some("24h"))
            .await
            .text
            .contains("[REDACTED]")
    );
    assert!(
        run_command(&o, "update-log", None, None)
            .await
            .text
            .contains("TASK [x] failed [REDACTED]")
    );
    for (verb, arg) in [
        ("restart", "mitm-agent"),
        ("restart", "../../etc"),
        ("reset-failed", "sshd"),
        ("check", "proxy"),
        ("clean", "/"),
        ("logs", "sshd"),
        ("sh", "-c"),
        ("cat", "/opt/controlclaw/state/box.key"),
    ] {
        assert!(!run_command(&o, verb, Some(arg), None).await.ok, "{verb} {arg}");
    }
    assert_eq!(
        *calls.lock().expect("lock"),
        vec![("status", None)],
        "nothing refused reached the root helper"
    );
    assert!(run_command(&o, "restart", Some("dnsmasq"), None).await.ok);
    assert_eq!(
        run_command(&o, "restart", Some("caddy"), None).await,
        ToolAnswer::new(false, "cc-fw-repair: caddy did not start")
    );
    let check = run_command(&o, "check", Some("caddy"), None).await;
    assert!(!check.ok);
    assert!(
        check.text.contains(
            "Caddyfile:93 unrecognized directive [REDACTED]\ncc-fw-repair: the Caddy configuration is not valid"
        ),
        "caddy's own error reaches the coding agent, redacted"
    );
    assert_eq!(run_command(&o, "update-retry", None, None).await.text, "started");
    assert_eq!(updates.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_listener_takes_only_its_sessions_token_from_loopback_while_the_session_is_active() {
    use crate::integrations::doctor::firewall::SessionTools;
    let (o, _, updates) = fixture();
    let active = Arc::new(AtomicBool::new(true));
    let a = active.clone();
    let tools = loopback::Listener(listener(o, Arc::new(move || a.load(Ordering::SeqCst))));
    let url = tools.start(None).await.expect("start");
    assert!(
        regex::Regex::new(r"^http://127\.0\.0\.1:\d+$")
            .expect("re")
            .is_match(&url)
    );
    let http = reqwest::Client::new();
    let run = |body: Value, token: String, origin: Option<&'static str>| {
        let mut r = http
            .post(format!("{url}/run"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(o) = origin {
            r = r.header("origin", o);
        }
        async move { r.send().await.expect("send") }
    };
    let token = tools.token();
    assert_eq!(run(json!({"verb": "status"}), "wrong".into(), None).await.status(), 403);
    assert_eq!(
        run(json!({"verb": "status"}), token.clone(), Some("https://evil.example"))
            .await
            .status(),
        403,
        "no browser can drive it"
    );
    let ok = run(json!({"verb": "restart", "arg": "dnsmasq"}), token.clone(), None).await;
    assert_eq!(ok.status(), 200);
    let body: Value = ok.json().await.expect("json");
    assert!(
        body["text"]
            .as_str()
            .unwrap_or("")
            .contains("ok restart dnsmasq [REDACTED]")
    );
    assert_eq!(
        run(json!({"verb": "restart", "arg": "sshd"}), token.clone(), None)
            .await
            .status(),
        400
    );
    assert_eq!(
        run(json!({"verb": "update-retry"}), token.clone(), None).await.status(),
        200
    );
    assert_eq!(
        run(json!({"verb": "update-retry"}), token.clone(), None).await.status(),
        400,
        "once per session"
    );
    assert_eq!(updates.load(Ordering::SeqCst), 1);
    active.store(false, Ordering::SeqCst);
    assert_eq!(
        run(json!({"verb": "status"}), token, None).await.status(),
        403,
        "an ended or idle session's token is dead"
    );
    tools.close().await;
}
