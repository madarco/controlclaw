//! `ssh.test.ts`: the key minted here, its public half to root on stdin, the private half never on
//! this disk, the deadline, the close, an old script, and the login reports.

use std::sync::Arc;

use cc_proc::{Cmd, RecordingRunner, exit, ok};
use serde_json::json;

use super::*;

const PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl controlclaw-rescue-g1";

/// A runner whose `ssh-keygen` writes the two files where it was told to.
fn runner(open_out: &str) -> RecordingRunner {
    let r = RecordingRunner::new();
    r.answer_with(|c: &Cmd| {
        (c.program == "ssh-keygen").then(|| {
            let path = c
                .args
                .iter()
                .skip_while(|a| *a != "-f")
                .nth(1)
                .cloned()
                .unwrap_or_default();
            std::fs::write(
                &path,
                "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
            )
            .expect("w");
            std::fs::write(format!("{path}.pub"), format!("{PUB}\n")).expect("w");
            ok("")
        })
    });
    r.answer(&["sudo", "/usr/local/bin/cc-ssh-open"], ok(open_out));
    r.answer(&["sudo", "/usr/local/bin/cc-ssh-close"], ok(""));
    r
}

fn access(r: &RecordingRunner, dir: &std::path::Path) -> SshAccess {
    SshAccess::new(Arc::new(r.clone()), dir.join("state/ssh.json")).with_work_dir(dir.to_path_buf())
}

#[test]
fn a_fingerprint_is_the_sha256_form_sshd_logs() {
    assert_eq!(
        fingerprint_of(PUB),
        "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
    );
    assert_eq!(marker_for("g1"), "controlclaw-rescue-g1");
}

#[tokio::test]
async fn opening_mints_a_key_hands_the_public_half_to_root_and_keeps_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let r = runner("key=installed\n");
    let s = access(&r, dir.path());
    let out = s.open("g1", 3600.0).await.expect("open");
    assert_eq!(out["user"], "ccsupport");
    assert_eq!(out["sudo"], true);
    assert_eq!(out["publicKey"], PUB);
    assert!(
        out["privateKey"]
            .as_str()
            .is_some_and(|k| k.contains("OPENSSH PRIVATE KEY"))
    );
    let calls = r.calls();
    let keygen = &calls[0];
    assert_eq!(keygen.program, "ssh-keygen");
    assert!(keygen.args.windows(2).any(|w| w == ["-C", "controlclaw-rescue-g1"]));
    let open = calls
        .iter()
        .find(|c| c.args.first().map(String::as_str) == Some("/usr/local/bin/cc-ssh-open"))
        .expect("open");
    assert_eq!(open.args, ["/usr/local/bin/cc-ssh-open", "3600"]);
    assert_eq!(open.stdin.as_deref(), Some(format!("{PUB}\n").as_bytes()));
    // No keygen folder survives, and the state file holds no key.
    assert!(
        !std::fs::read_dir(dir.path())
            .expect("rd")
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("cc-ssh-"))
    );
    let state = std::fs::read_to_string(dir.path().join("state/ssh.json")).expect("state");
    assert!(!state.contains("PRIVATE"));
    let st = s.status();
    assert_eq!((st["open"].clone(), st["grantId"].clone()), (json!(true), json!("g1")));
}

#[tokio::test]
async fn status_is_closed_after_the_deadline_and_close_always_succeeds() {
    let dir = tempfile::tempdir().expect("dir");
    let r = runner("key=installed\n");
    let s = access(&r, dir.path());
    std::fs::create_dir_all(dir.path().join("state")).expect("d");
    std::fs::write(
        dir.path().join("state/ssh.json"),
        json!({"grantId": "g0", "fingerprint": "SHA256:x", "endsAt": "2000-01-01T00:00:00.000Z"}).to_string(),
    )
    .expect("w");
    assert_eq!(s.status()["open"], false);
    assert_eq!(
        s.close().await.expect("close"),
        json!({"user": "ccsupport", "closed": true})
    );
    assert_eq!(
        s.close().await.expect("close"),
        json!({"user": "ccsupport", "closed": false})
    );
    assert_eq!(
        s.status(),
        json!({"open": false, "user": "ccsupport", "grantId": null, "fingerprint": null, "endsAt": null})
    );
}

#[tokio::test]
async fn a_close_that_cannot_run_says_so() {
    let dir = tempfile::tempdir().expect("dir");
    let r = RecordingRunner::new();
    r.answer(&["sudo"], exit(1, ""));
    let s = access(&r, dir.path());
    assert!(s.close().await.is_err());
}

#[tokio::test]
async fn an_old_script_is_a_failure_and_the_port_goes_back_down() {
    let dir = tempfile::tempdir().expect("dir");
    let r = runner("opened\n");
    let s = access(&r, dir.path());
    let e = s.open("g1", 3600.0).await.expect_err("old");
    assert!(e.contains("predates root support access"), "{e}");
    assert!(r.calls().iter().any(|c| c.args == ["/usr/local/bin/cc-ssh-close"]));
    assert!(!dir.path().join("state/ssh.json").exists());
}

#[tokio::test]
async fn bad_windows_and_grant_ids_are_refused_before_anything_is_minted() {
    let dir = tempfile::tempdir().expect("dir");
    let r = runner("key=installed\n");
    let s = access(&r, dir.path());
    for secs in [60.0, 300_000.0, f64::NAN] {
        assert!(s.open("g1", secs).await.is_err());
    }
    for id in ["", "../x", "a b", &"x".repeat(65)] {
        assert_eq!(s.open(id, 3600.0).await.expect_err("bad"), "malformed grant id");
    }
    assert!(r.calls().is_empty());
}

#[test]
fn an_accepted_public_key_line_becomes_one_record_nothing_else_does() {
    let line = "2026-09-22T14:02:11+0000 box sshd[2211]: Accepted publickey for ccsupport from 203.0.113.9 port 54321 ssh2: ED25519 SHA256:abcdef";
    let (user, fp, ip, at) = parse_sshd_line(line).expect("parsed");
    assert_eq!(
        (user.as_str(), fp.as_str(), ip.as_str()),
        ("ccsupport", "SHA256:abcdef", "203.0.113.9")
    );
    assert_eq!(at, Some(1_790_085_731_000));
    assert!(parse_sshd_line("Failed password for root from 1.2.3.4 port 1 ssh2").is_none());
    assert_eq!(
        parse_sshd_line("Accepted publickey for x from 1.2.3.4 port 1 ssh2: RSA SHA256:q").map(|p| p.3),
        Some(None)
    );
}

#[tokio::test]
async fn the_watcher_ships_and_keeps_what_the_console_refused() {
    let r = RecordingRunner::new();
    let line = "2026-09-22T14:02:11+0000 box sshd[2211]: Accepted publickey for ccsupport from 203.0.113.9 port 54321 ssh2: ED25519 SHA256:abcdef\nnoise\n";
    // The journal hands a line out once: its cursor moves when it reads.
    let reads = std::sync::atomic::AtomicUsize::new(0);
    r.answer_with(move |c: &Cmd| {
        (c.program == "journalctl").then(|| {
            if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                ok(line)
            } else {
                ok("")
            }
        })
    });
    let w = SshLoginWatcher::new(Arc::new(r.clone()), "/tmp/cursor".into());
    let shipped = std::sync::Mutex::new(Vec::new());
    assert_eq!(
        w.tick(async |b: Value| {
            shipped.lock().expect("lock").push(b);
            Ok(503)
        })
        .await,
        Ok(0)
    );
    // Nothing new in the journal this time, but the refused record goes again.
    let n = w
        .tick(async |b: Value| {
            shipped.lock().expect("lock").push(b);
            Ok(200)
        })
        .await;
    assert_eq!(n, Ok(1));
    let shipped = shipped.lock().expect("lock");
    assert_eq!(shipped.len(), 2);
    let rec = &shipped[1]["records"][0];
    assert_eq!(rec["source"], "ssh_login");
    assert_eq!(rec["ts"], 1_790_085_731);
    assert_eq!(rec["user"], "ccsupport");
    assert_eq!(rec["from_ip"], "203.0.113.9");
    assert_eq!(rec["login_id"].as_str().map(str::len), Some(32));
    let journal = &r.calls()[0];
    assert_eq!(
        journal.args,
        [
            "-u",
            "ssh",
            "-u",
            "sshd",
            "--no-pager",
            "-q",
            "-o",
            "short-iso",
            "--cursor-file=/tmp/cursor"
        ]
    );
}
