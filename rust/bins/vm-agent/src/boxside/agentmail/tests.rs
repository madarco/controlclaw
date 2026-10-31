//! `agentmail.test.ts`: the payload checks, the env file, and applies that are not coalesced.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::*;

fn body(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

const P: &str = "CC-AMAIL-0123456789abcdef0123456789abcdef";

fn good() -> Value {
    json!({"placeholder": P, "inboxId": "bot@agentmail.to", "humanEmail": "ada@example.com"})
}

#[test]
fn real_keys_and_env_injection_are_refused() {
    let p = parse_apply(&body(good())).expect("good");
    assert_eq!(p.allowed_senders, Some(vec!["ada@example.com".to_string()]));
    let forget = parse_apply(&body(json!({"placeholder": null, "inboxId": null}))).expect("forget");
    assert_eq!(forget.placeholder, None);
    let with = |k: &str, v: Value| {
        let mut b = good();
        b[k] = v;
        parse_apply(&body(b))
    };
    assert!(with("placeholder", json!("am_live_123")).is_none());
    assert!(with("placeholder", json!(format!("{P}\nX=1"))).is_none());
    assert!(with("inboxId", json!("bot@example.com")).is_none());
    assert!(with("humanEmail", json!("not an email")).is_none());
    assert!(with("allowedSenders", json!(["a@b.co\nX=1"])).is_none());
    assert!(with("allowedSenders", json!("a@b.co")).is_none());
    let many: Vec<String> = (0..51).map(|i| format!("u{i}@example.com")).collect();
    assert!(with("allowedSenders", json!(many)).is_none());
    assert_eq!(
        with("allowedSenders", json!([])).expect("deny all").allowed_senders,
        Some(vec![])
    );
    let wild = with("allowedSenders", json!(["*"])).expect("wildcard");
    assert_eq!(wild.dm_policy(), "open");
    // `*` among others is not the wildcard.
    assert!(with("allowedSenders", json!(["*", "a@b.co"])).is_none());
    assert_eq!(p.dm_policy(), "allowlist");
}

#[test]
fn the_env_file_keeps_other_settings_and_drops_stale_agentmail_lines() {
    let tb = crate::boxside::testing::test_box();
    let env = tb.dir.path().join(".openclaw/.env");
    std::fs::create_dir_all(env.parent().expect("p")).expect("mk");
    std::fs::write(
        &env,
        "OPENAI_API_KEY=x\r\nexport AGENTMAIL_WEBHOOK_SECRET=old\n\nAGENTMAIL_API_KEY=old\nOTHER=1\n",
    )
    .expect("w");
    let m = AgentMail::new(&tb.app, env.clone());
    m.write_env(Some(P)).expect("write");
    assert_eq!(
        std::fs::read_to_string(&env).expect("r"),
        format!("OPENAI_API_KEY=x\nOTHER=1\nAGENTMAIL_API_KEY={P}\n")
    );
    m.write_env(None).expect("forget");
    assert_eq!(std::fs::read_to_string(&env).expect("r"), "OPENAI_API_KEY=x\nOTHER=1\n");
}

#[tokio::test]
async fn a_sender_change_is_not_coalesced_with_an_older_pending_apply() {
    let tb = crate::boxside::testing::test_box();
    let m = Arc::new(AgentMail::new(&tb.app, tb.dir.path().join(".env")).with_pace(Duration::from_millis(1)));
    assert_eq!(m.status(), None);
    let first = m.start(parse_apply(&body(good())).expect("p"));
    assert_eq!(first["status"], "pending");
    // The same apply while pending is that apply.
    let again = m.start(parse_apply(&body(good())).expect("p"));
    assert_eq!(again, first);
    let mut b = good();
    b["allowedSenders"] = json!(["bob@example.com"]);
    let changed = m.start(parse_apply(&body(b)).expect("p"));
    assert_eq!(changed["allowedSenders"], json!(["bob@example.com"]));
    // No OpenClaw here: the apply ends failed, and only the newest record says so.
    for _ in 0..50 {
        if m.status().is_some_and(|s| s["status"] == "failed") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let s = m.status().expect("status");
    assert_eq!(
        (s["status"].clone(), s["allowedSenders"].clone()),
        (json!("failed"), json!(["bob@example.com"]))
    );
}

#[test]
fn an_env_file_that_cannot_be_read_is_not_written_over() {
    let tb = crate::boxside::testing::test_box();
    // A folder where the file should be: readable as nothing, so the apply fails.
    let env = tb.dir.path().join(".env");
    std::fs::create_dir(&env).expect("dir");
    let m = AgentMail::new(&tb.app, env.clone());
    assert!(
        m.write_env(Some(P))
            .expect_err("refused")
            .starts_with("EISDIR: illegal operation on a directory")
    );
    assert!(env.is_dir());
}
