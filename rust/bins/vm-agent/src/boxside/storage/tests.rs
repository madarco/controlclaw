//! `storage.test.ts` and `disk-reseal.test.ts`.

use std::sync::Arc;

use cc_proc::{Output, RecordingRunner, exit, ok};
use serde_json::json;

use super::*;

const SIZE_30: &str = r#"{"present":true,"mounted":true,"sizeGb":30,"maxGb":53,"reserveGb":10,"diskBytes":80279486464,"systemUsedBytes":11978649600,"imageBytes":2701271040,"fsBytes":31509659648,"usedBytes":1360420864,"freeBytes":28630728704,"pending":false}"#;
const KEY: &str = "OLIAAYYu9C/XU5mQckoX00FBWNlYg7+Ur4qx2M/tKXs=";
const TAG: &str = "sha256:0006bb1c1b76749b";

fn fail(stderr: &str) -> Output {
    Output {
        code: Some(1),
        stderr: stderr.as_bytes().to_vec(),
        ..Output::default()
    }
}

fn storage(answers: &[(&[&str], Output)]) -> (Storage, RecordingRunner) {
    let r = RecordingRunner::new();
    for (p, o) in answers {
        r.answer(p, o.clone());
    }
    (Storage::new(Arc::new(r.clone())), r)
}

fn argv(r: &RecordingRunner) -> Vec<Vec<String>> {
    r.calls()
        .into_iter()
        .map(|c| std::iter::once(c.program).chain(c.args).collect())
        .collect()
}

#[test]
fn parse_size_reads_the_line_cc_secure_prints() {
    assert_eq!(
        parse_size(&format!("{SIZE_30}\n")),
        Some(
            json!({"present": true, "mounted": true, "sizeGb": 30, "maxGb": 53, "reserveGb": 10, "diskBytes": 80279486464u64,
            "systemUsedBytes": 11978649600u64, "imageBytes": 2701271040u64, "fsBytes": 31509659648u64, "usedBytes": 1360420864u64,
            "freeBytes": 28630728704u64, "pending": false})
        )
    );
    let locked = parse_size(&SIZE_30.replace(r#""mounted":true"#, r#""mounted":false"#)).expect("info");
    assert_eq!(
        (locked["mounted"].clone(), locked["fsBytes"].clone()),
        (json!(false), Value::Null)
    );
    assert_eq!(
        parse_size(r#"{"present":false}"#).map(|v| v["present"].clone()),
        Some(json!(false))
    );
    assert_eq!(
        parse_size(&format!(
            "cc-secure: the container is 40G\n{}\n",
            SIZE_30.replace(r#""sizeGb":30"#, r#""sizeGb":40"#)
        ))
        .map(|v| v["sizeGb"].clone()),
        Some(json!(40))
    );
    for text in [
        "",
        "cc-secure: no container",
        "[]",
        "{",
        r#"{"present":true}"#,
        r#"{"present":true,"sizeGb":"30","maxGb":53,"diskBytes":1}"#,
        r#"{"present":true,"sizeGb":30.5,"maxGb":53,"diskBytes":1}"#,
        r#"{"present":true,"sizeGb":30,"maxGb":20,"diskBytes":1}"#,
        r#"{"present":true,"sizeGb":-1,"maxGb":20,"diskBytes":1}"#,
    ] {
        assert_eq!(parse_size(text), None, "{text}");
    }
}

#[test]
fn valid_target_gb_takes_whole_numbers_the_sudoers_pattern_can_carry() {
    for good in [1, 30, 9999] {
        assert_eq!(valid_target_gb(Some(&json!(good))), Some(good));
    }
    for bad in [
        json!(0),
        json!(-5),
        json!(10000),
        json!(30.5),
        json!("30"),
        Value::Null,
        json!([30]),
        json!({"targetGb": 30}),
    ] {
        assert_eq!(valid_target_gb(Some(&bad)), None, "{bad}");
    }
    assert_eq!(valid_target_gb(None), None);
}

#[test]
fn helper_reason_is_cc_secure_own_last_line_as_a_sentence() {
    let e = |s: &str| ExecErr {
        stderr: s.into(),
        ..ExecErr::default()
    };
    assert_eq!(
        helper_reason(&e("cc-secure: no room: this server's disk allows at most 53 GiB\n")).as_deref(),
        Some("No room: this server's disk allows at most 53 GiB.")
    );
    assert_eq!(
        helper_reason(&e(
            "resize2fs: Bad magic number\ncc-secure: the filesystem did not grow; run grow 40 again\n"
        ))
        .as_deref(),
        Some("The filesystem did not grow; run grow 40 again.")
    );
    assert_eq!(helper_reason(&e("sudo: a password is required\n")), None);
}

#[tokio::test]
async fn read_runs_the_read_only_helper_with_sudo_n() {
    let (s, r) = storage(&[(&["sudo"], ok(SIZE_30))]);
    assert_eq!(s.read().await.expect("read")["sizeGb"], 30);
    assert_eq!(argv(&r), [["sudo", "-n", "/usr/local/bin/cc-secure", "size"]]);
}

#[tokio::test]
async fn no_sudoers_line_no_helper_or_an_older_helper_is_unsupported() {
    for out in [
        fail("sudo: a password is required\n"),
        fail("usage: cc-secure {bind|unbind}\n"),
    ] {
        let (s, _) = storage(&[(&["sudo"], out)]);
        let e = s.read().await.expect_err("refused");
        assert_eq!((e.status, e.code), (409, "unsupported"));
    }
    // No sudo at all is ENOENT.
    let (s, _) = storage(&[]);
    assert_eq!(s.read().await.expect_err("refused").code, "unsupported");
    let (s, _) = storage(&[(&["sudo"], ok("garbage"))]);
    assert_eq!(s.read().await.expect_err("refused").status, 500);
}

#[tokio::test]
async fn grow_passes_one_number_and_refuses_bad_ones_before_anything_runs() {
    let (s, r) = storage(&[(&["sudo"], ok(&SIZE_30.replace(r#""sizeGb":30"#, r#""sizeGb":40"#)))]);
    assert_eq!(s.grow(Some(&json!(40))).await.expect("grow")["sizeGb"], 40);
    assert_eq!(argv(&r), [["sudo", "-n", "/usr/local/bin/cc-secure", "grow", "40"]]);
    let (s, r) = storage(&[]);
    for bad in [json!(0), json!("40"), json!(40.5)] {
        let e = s.grow(Some(&bad)).await.expect_err("bad");
        assert_eq!((e.status, e.code), (400, "invalid"));
    }
    assert!(r.calls().is_empty());
}

#[tokio::test]
async fn grow_refusals_come_back_in_the_box_own_words() {
    let (s, _) = storage(&[(
        &["sudo"],
        fail("cc-secure: no room: this server's disk allows at most 53 GiB\n"),
    )]);
    assert_eq!(
        s.grow(Some(&json!(60))).await.expect_err("refused"),
        Refusal {
            status: 422,
            code: "refused",
            message: "No room: this server's disk allows at most 53 GiB.".into()
        }
    );
    let (s, _) = storage(&[(&["sudo"], exit(1, ""))]);
    let e = s.grow(Some(&json!(40))).await.expect_err("failed");
    assert_eq!(
        (e.status, e.message.as_str()),
        (500, "The storage could not be made larger.")
    );
    // Free again after the failure.
    let e = s.grow(Some(&json!(40))).await.expect_err("failed again");
    assert_eq!(e.code, "failed");
}

#[tokio::test]
async fn reseal_passes_one_key_and_reads_the_answer() {
    let (s, r) = storage(&[(&["sudo"], ok(&format!("{{\"to\":\"{TAG}\",\"changed\":true}}\n")))]);
    assert_eq!(
        s.reseal(Some(&json!(KEY))).await.expect("reseal"),
        json!({"to": TAG, "changed": true})
    );
    assert_eq!(argv(&r), [["sudo", "-n", "/usr/local/bin/cc-secure", "reseal", KEY]]);
    let (s, r) = storage(&[]);
    for bad in [json!("x"), json!(format!("{KEY} ")), json!(42), Value::Null] {
        let e = s.reseal(Some(&bad)).await.expect_err("bad");
        assert_eq!((e.status, e.code), (400, "invalid"));
    }
    assert!(r.calls().is_empty());
}

#[test]
fn parse_reseal_reads_the_line_cc_secure_prints_and_nothing_else() {
    assert_eq!(
        parse_reseal(&format!("noise\n{{\"to\":\"{TAG}\",\"changed\":false}}\n")),
        Some(json!({"to": TAG, "changed": false}))
    );
    for bad in [
        String::new(),
        "ok".into(),
        r#"{"to":"sha256:xyz","changed":true}"#.into(),
        format!(r#"{{"to":"{TAG}"}}"#),
        format!(r#"{{"to":"{TAG}","changed":"yes"}}"#),
        "{not json".into(),
    ] {
        assert_eq!(parse_reseal(&bad), None, "{bad}");
    }
}

#[tokio::test]
async fn a_locked_box_is_told_apart_from_a_failed_seal() {
    let (s, _) = storage(&[(&["sudo"], fail("cc-secure: the disk is not open\n"))]);
    let e = s.reseal(Some(&json!(KEY))).await.expect_err("locked");
    assert_eq!((e.code, e.message.as_str()), ("locked", "The disk is not open."));
    let (s, _) = storage(&[(&["sudo"], exit(1, ""))]);
    let e = s.reseal(Some(&json!(KEY))).await.expect_err("failed");
    assert_eq!((e.status, e.code), (422, "failed"));
    assert!(e.message.contains("The old one still opens this disk"));
    let (s, _) = storage(&[(&["sudo"], ok("done"))]);
    assert_eq!(s.reseal(Some(&json!(KEY))).await.expect_err("no answer").code, "failed");
    let (s, _) = storage(&[(&["sudo"], fail("sudo: a password is required\n"))]);
    assert_eq!(s.reseal(Some(&json!(KEY))).await.expect_err("old").code, "unsupported");
}

#[tokio::test]
async fn one_reseal_at_a_time() {
    let r = RecordingRunner::new();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let rx = std::sync::Mutex::new(rx);
    r.answer_with(move |_| {
        let _ = rx.lock().ok()?.recv_timeout(std::time::Duration::from_secs(2));
        Some(ok(&format!("{{\"to\":\"{TAG}\",\"changed\":true}}")))
    });
    let s = Arc::new(Storage::new(Arc::new(r.clone())));
    let s2 = s.clone();
    let first = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move { s2.reseal(Some(&json!(KEY))).await })
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(s.reseal(Some(&json!(KEY))).await.expect_err("busy").code, "busy");
    tx.send(()).expect("release");
    assert!(first.await.expect("join").is_ok());
    assert_eq!(r.calls().len(), 1);
}
