//! `tailscale.test.ts`.

use std::sync::Arc;
use std::time::Duration;

use cc_proc::{Output, RecordingRunner, ok};
use serde_json::json;

use super::*;

const JOINED: &str = r#"{"BackendState":"Running","Self":{"DNSName":"ada.tail1234.ts.net.","HostName":"ada","TailscaleIPs":["fd7a::1","100.101.102.103"],"sshHostKeys":["ssh-ed25519 AAAA"]}}"#;

fn fail(stderr: &str) -> Output {
    Output {
        code: Some(1),
        stderr: stderr.as_bytes().to_vec(),
        ..Output::default()
    }
}

fn ts(r: &RecordingRunner) -> Tailscale {
    Tailscale::new(Arc::new(r.clone())).with_settle_delay(Duration::from_millis(1))
}

#[test]
fn statuses() {
    assert_eq!(
        parse_status(JOINED),
        json!({"state": "joined", "name": "ada.tail1234.ts.net", "ip": "100.101.102.103", "ssh": true, "backendState": "Running", "message": null})
    );
    assert_eq!(
        parse_status(r#"{"BackendState":"Stopped"}"#),
        json!({"state": "off", "name": null, "ip": null, "ssh": false, "backendState": "Stopped", "message": "This box is not signed in to a tailnet."})
    );
    assert_eq!(parse_status(r#"{"BackendState":"Starting"}"#)["state"], "starting");
    assert_eq!(
        parse_status(r#"{"BackendState":"Running","Health":["no route"]}"#)["message"],
        "no route"
    );
    assert_eq!(parse_status("not json")["state"], "unavailable");
    assert!(valid_auth_key("tskey-auth-k123-abcDEF"));
    for bad in ["tskey-k-a", "tskey-auth-a-b-c", "tskey-auth--b", "x"] {
        assert!(!valid_auth_key(bad), "{bad}");
    }
}

#[tokio::test]
async fn apply_passes_the_key_on_stdin_never_in_argv() {
    let r = RecordingRunner::new();
    r.answer(&["sudo", "-n", "/usr/local/bin/cc-tailscale", "up"], ok(""));
    r.answer(&["sudo", "-n", "/usr/local/bin/cc-tailscale", "status"], ok(JOINED));
    let out = ts(&r)
        .apply("tskey-auth-k1-SECRET", false, "ada")
        .await
        .ok()
        .expect("apply");
    assert_eq!(
        out,
        json!({"ok": true, "ssh": false, "node": {"name": "ada.tail1234.ts.net", "ip": "100.101.102.103"}})
    );
    let up = &r.calls()[0];
    assert_eq!(up.args, ["-n", "/usr/local/bin/cc-tailscale", "up", "ada", "ssh0"]);
    assert_eq!(up.stdin.as_deref(), Some(&b"tskey-auth-k1-SECRET\n"[..]));
    assert!(r.calls().iter().all(|c| !c.args.iter().any(|a| a.contains("SECRET"))));
}

#[tokio::test]
async fn refusals_unsupported_and_waiting() {
    let r = RecordingRunner::new();
    r.answer(&["sudo"], fail("sudo: a password is required\n"));
    assert!(matches!(
        ts(&r).apply("tskey-auth-k1-s", true, "ada").await,
        Err(TsError::Unsupported)
    ));
    assert_eq!(ts(&r).status().await["message"], TAILSCALE_UNSUPPORTED_MESSAGE);
    assert!(matches!(ts(&r).logout().await, Err(TsError::Unsupported)));

    let r = RecordingRunner::new();
    r.answer(
        &["sudo", "-n", "/usr/local/bin/cc-tailscale", "up"],
        fail("backend error: invalid key: not found\n"),
    );
    match ts(&r).apply("tskey-auth-k1-s", true, "ada").await {
        Err(TsError::Failed(e)) => assert_eq!(
            e,
            "Tailscale could not join the network: backend error: invalid key: not found"
        ),
        _ => panic!("refused"),
    }
    assert!(matches!(
        ts(&r).apply("tskey-auth-k1-s", true, "-bad-").await,
        Err(TsError::Failed(_))
    ));
    assert_eq!(r.calls().len(), 1, "the bad hostname never reached the helper");

    // Up, but never an address: fails loudly after waiting.
    let r = RecordingRunner::new();
    r.answer(&["sudo", "-n", "/usr/local/bin/cc-tailscale", "up"], ok(""));
    r.answer(
        &["sudo", "-n", "/usr/local/bin/cc-tailscale", "status"],
        ok(r#"{"BackendState":"Starting"}"#),
    );
    match ts(&r).apply("tskey-auth-k1-s", true, "ada").await {
        Err(TsError::Failed(e)) => assert_eq!(e, "Tailscale is still starting on this box."),
        _ => panic!("failed"),
    }
    let statuses = r
        .calls()
        .iter()
        .filter(|c| c.args.get(2).map(String::as_str) == Some("status"))
        .count();
    assert_eq!(statuses, 10);
}
