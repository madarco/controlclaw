//! `google.test.ts`: the payload checks, the environment file, revokes and the status.

use std::sync::Arc;

use cc_proc::{RecordingRunner, exit, ok};
use serde_json::{Map, Value, json};

use super::*;

const P: &str = "CC-GOOG-0123456789abcdef";

fn body(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

fn good() -> Value {
    json!({"placeholder": P, "connected": true, "projectId": "my-project-1", "services": ["gmail", "drive", "gmail"], "accountLabel": "ops@example.com"})
}

fn service(r: &RecordingRunner) -> (tempfile::TempDir, Google) {
    let dir = tempfile::tempdir().expect("dir");
    let g = Google::new(
        Arc::new(r.clone()),
        dir.path().join("gog.env"),
        dir.path().join("google.json"),
    )
    .with_gog(dir.path().join("gog"));
    (dir, g)
}

#[test]
fn payloads_parse_as_the_firewall_sends_them() {
    let p = parse_apply(&body(good())).expect("good");
    assert_eq!(p.services, ["gmail", "drive"], "duplicates collapse");
    assert!(p.ticked);
    let bad = |patch: Value, want: &str| {
        let mut b = good();
        for (k, v) in patch.as_object().expect("o") {
            if v == "__drop" {
                b.as_object_mut().expect("o").remove(k);
            } else {
                b[k] = v.clone();
            }
        }
        assert_eq!(parse_apply(&body(b)).expect_err(want), want);
    };
    bad(
        json!({"placeholder": "sk-real"}),
        "placeholder is not the shape the firewall generates",
    );
    bad(json!({"placeholder": 5}), "placeholder must be a string or null");
    bad(json!({"services": "__drop"}), "services must be an array");
    bad(
        json!({"services": ["gmail", 7]}),
        "services[] 7 is not a Google service",
    );
    bad(
        json!({"services": ["youtube"]}),
        "services[] \"youtube\" is not a Google service",
    );
    bad(json!({"projectId": "X"}), "projectId is not a Google Cloud project id");
    bad(
        json!({"accountLabel": "a'; rm -rf /"}),
        "accountLabel is not an address",
    );
    bad(json!({"granted": "yes"}), "granted must be a boolean");
    // An empty placeholder is none; no tick sent: read from it.
    let p = parse_apply(&body(json!({"placeholder": "", "connected": true, "services": []}))).expect("ok");
    assert_eq!((p.placeholder, p.ticked), (None, false));
}

#[tokio::test]
async fn a_grant_writes_what_gog_reads_and_a_revoke_removes_it() {
    let r = RecordingRunner::new();
    let (dir, g) = service(&r);
    assert!(!g.supported());
    assert_eq!(g.apply(&parse_apply(&body(good())).expect("p")), Ok(true));
    let env = std::fs::read_to_string(dir.path().join("gog.env")).expect("env");
    assert!(env.contains(&format!("GOG_ACCESS_TOKEN='{P}'\n")));
    assert!(env.contains("GOG_HOME=/opt/controlclaw/gog\n"));
    assert!(env.contains("CC_GOOGLE_SERVICES='gmail,drive'\n"));
    assert!(env.contains("CC_GOOGLE_ACCOUNT='ops@example.com'\n"));
    assert!(env.contains("GOG_QUOTA_PROJECT='my-project-1'\n"));
    assert!(env.contains("It does not expire"));
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("gog.env"))
            .expect("m")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("google.json")).expect("s")).expect("json");
    assert_eq!(state["placeholder"], "set", "never the placeholder");
    let keys: Vec<&String> = state.as_object().expect("o").keys().collect();
    assert_eq!(
        keys,
        [
            "placeholder",
            "connected",
            "projectId",
            "services",
            "accountLabel",
            "ticked",
            "at"
        ]
    );
    assert_eq!(g.account().as_deref(), Some("ops@example.com"));
    assert!(g.connected());

    // A second apply replaces; no project means no variable.
    let mut b = good();
    b["projectId"] = Value::Null;
    g.apply(&parse_apply(&body(b)).expect("p")).expect("apply");
    let env = std::fs::read_to_string(dir.path().join("gog.env")).expect("env");
    assert!(!env.contains("GOG_QUOTA_PROJECT"));
    assert_eq!(env.matches("GOG_ACCESS_TOKEN=").count(), 1);

    // A failed connection: no file, the tick and the account kept.
    let mut b = good();
    b["connected"] = json!(false);
    b["granted"] = json!(true);
    assert_eq!(g.apply(&parse_apply(&body(b)).expect("p")), Ok(false));
    assert!(!dir.path().join("gog.env").exists());
    assert_eq!(g.account().as_deref(), Some("ops@example.com"));
    // A revoke on a box with nothing is not an error.
    assert_eq!(
        g.apply(&parse_apply(&body(json!({"placeholder": null, "services": []}))).expect("p")),
        Ok(false)
    );
}

#[tokio::test]
async fn status_never_carries_the_placeholder_and_survives_a_broken_state() {
    let r = RecordingRunner::new();
    r.answer_with(|_| Some(ok("gog version 0.41.0 (abc)\n")));
    let (dir, g) = service(&r);
    g.apply(&parse_apply(&body(good())).expect("p")).expect("apply");
    let s = g.status().await;
    assert_eq!(s["gogVersion"], "0.41.0");
    assert_eq!(s["hasPlaceholder"], true);
    assert!(!s.to_string().contains(P));
    let keys: Vec<&String> = s.as_object().expect("o").keys().collect();
    assert_eq!(
        keys,
        [
            "gogVersion",
            "hasPlaceholder",
            "connected",
            "services",
            "projectId",
            "accountLabel",
            "at"
        ]
    );
    // The file gone: says so, though the state remembers a connection.
    std::fs::remove_file(dir.path().join("gog.env")).expect("rm");
    assert_eq!(g.status().await["hasPlaceholder"], false);
    // A half-written state file.
    std::fs::write(dir.path().join("google.json"), "{\"conn").expect("w");
    let s = g.status().await;
    assert_eq!((s["connected"].clone(), s["at"].clone()), (json!(false), Value::Null));

    let r = RecordingRunner::new();
    r.answer_with(|_| Some(exit(1, "")));
    let (_d, g) = service(&r);
    assert_eq!(g.status().await["gogVersion"], Value::Null);
    let r = RecordingRunner::new();
    r.answer_with(|_| Some(ok("gog dev build\nmore")));
    let (_d, g) = service(&r);
    assert_eq!(g.status().await["gogVersion"], "gog dev build");
}

#[tokio::test]
async fn a_state_file_from_before_the_tick_reads_it_from_the_placeholder() {
    let r = RecordingRunner::new();
    let (dir, g) = service(&r);
    std::fs::write(
        dir.path().join("google.json"),
        r#"{"placeholder":"set","connected":true,"accountLabel":"a@b.co","services":["gmail","nope"]}"#,
    )
    .expect("w");
    assert_eq!(g.account().as_deref(), Some("a@b.co"));
    std::fs::write(
        dir.path().join("google.json"),
        r#"{"placeholder":null,"connected":true,"accountLabel":"a@b.co"}"#,
    )
    .expect("w");
    assert_eq!(g.account(), None);
}

#[tokio::test]
async fn listeners_run_after_the_apply() {
    let r = RecordingRunner::new();
    let (_d, g) = service(&r);
    let (tx, rx) = std::sync::mpsc::channel();
    g.on_applied(Arc::new(move || {
        let _ = tx.send(());
    }));
    g.apply(&parse_apply(&body(good())).expect("p")).expect("apply");
    tokio::task::yield_now().await;
    assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).is_ok());
}
