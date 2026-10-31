//! `drive.test.ts`: the payload checks, the detached launch, and the status from the report and rclone.

use std::sync::Arc;

use cc_proc::{RecordingRunner, exit, ok};
use serde_json::{Map, Value, json};

use super::*;

const P: &str = "CC-DRIVE-0123456789abcdef";

fn body(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

fn good() -> Value {
    json!({"placeholder": P, "scope": "https://www.googleapis.com/auth/drive", "connected": true,
           "mounts": [{"name": "Team Docs", "folderId": "0AbCdEfGhIjKl", "mode": "rw"}, {"name": "Archive", "folderId": "1AbCdEfGhIjKl", "mode": "ro"}]})
}

fn bad(b: Value) -> String {
    match parse_apply(&body(b)) {
        Err(Refused::Bad(e)) => e,
        other => panic!("{other:?}"),
    }
}

#[test]
fn payloads_are_checked_and_normalised() {
    let v = parse_apply(&body(good())).expect("good");
    assert_eq!(
        v["defaults"],
        json!({"exportFormats": "docx,xlsx,pdf", "skipGdocs": true, "vfsCacheMaxSize": "2G", "vfsCacheMinFreeSpace": "4G"})
    );
    let keys: Vec<&String> = v.as_object().expect("o").keys().collect();
    assert_eq!(keys, ["placeholder", "scope", "connected", "defaults", "mounts"]);
    let with = |f: &dyn Fn(&mut Value)| {
        let mut b = good();
        f(&mut b);
        b
    };
    assert_eq!(
        bad(with(&|b| b["mounts"][0]["name"] = json!("../etc"))),
        "mounts[].name \"../etc\" cannot be a directory name"
    );
    assert_eq!(
        bad(with(&|b| b["mounts"][0]["name"] = json!("Docs "))),
        "mounts[].name \"Docs \" cannot be a directory name"
    );
    assert_eq!(
        bad(with(&|b| b["mounts"][0]["folderId"] = json!("x"))),
        "mounts[].folderId \"x\" is invalid"
    );
    assert_eq!(
        bad(with(&|b| b["mounts"][0]["mode"] = json!("rwx"))),
        "mounts[].mode must be ro or rw"
    );
    assert_eq!(
        bad(with(&|b| b["placeholder"] = json!("ya29.real"))),
        "placeholder is not the shape the firewall generates"
    );
    assert_eq!(
        bad(with(
            &|b| b["scope"] = json!("https://www.googleapis.com/auth/gmail.readonly")
        )),
        "scope is not a Google Drive scope"
    );
    assert_eq!(
        bad(with(
            &|b| b["defaults"] = json!({"vfsCacheMaxSize": "2G --rc-addr=0.0.0.0"})
        )),
        "defaults.vfsCacheMaxSize has characters that cannot go on a command line"
    );
    assert_eq!(
        bad(with(&|b| b["mounts"][1]["name"] = json!("team docs"))),
        "two folders are both named \"team docs\""
    );
    assert_eq!(
        bad(with(&|b| {
            b.as_object_mut().expect("o").remove("mounts");
        })),
        "mounts must be an array"
    );
    let nine: Vec<Value> = (0..9)
        .map(|i| json!({"name": format!("F{i}"), "folderId": "0AbCdEfGhIjKl", "mode": "ro"}))
        .collect();
    assert_eq!(bad(with(&|b| b["mounts"] = json!(nine))), "at most 8 Drive folders");
    // `null.name` throws in TS: the route's 500.
    assert!(matches!(
        parse_apply(&body(with(&|b| b["mounts"] = json!([null])))),
        Err(Refused::Threw(_))
    ));
}

fn drive(r: &RecordingRunner) -> (tempfile::TempDir, Drive) {
    let dir = tempfile::tempdir().expect("dir");
    let d = Drive::new(
        Arc::new(r.clone()),
        dir.path().join("drive.json"),
        dir.path().join("drive-mounts.json"),
    )
    .with_script(dir.path().join("cc-drive-apply"));
    (dir, d)
}

#[tokio::test]
async fn apply_writes_the_set_and_launches_the_reconcile_detached() {
    let r = RecordingRunner::new();
    r.answer(&["sudo"], ok(""));
    let (dir, d) = drive(&r);
    assert!(!d.supported());
    let input = parse_apply(&body(good())).expect("p");
    assert_eq!(
        d.apply(&input).await,
        Ok(json!({"ok": true, "reconciling": true, "folders": ["Team Docs", "Archive"]}))
    );
    let script = dir.path().join("cc-drive-apply").to_string_lossy().into_owned();
    assert_eq!(
        r.calls()[0].args,
        ["/usr/bin/systemd-run", "--unit=cc-drive-apply", "--collect", &script]
    );
    let desired = std::fs::read_to_string(dir.path().join("drive.json")).expect("desired");
    assert_eq!(desired, serde_json::to_string_pretty(&input).expect("json"));

    // Already running: accepted.
    let r = RecordingRunner::new();
    r.answer(
        &["sudo"],
        exit(1, "Failed to start transient service unit: Unit cc-drive-apply.service was already loaded or has a fragment file."),
    );
    let (_d, d2) = drive(&r);
    assert_eq!(d2.apply(&input).await.expect("ok")["reconciling"], false);

    // A launch that really failed puts the previous set back.
    let r = RecordingRunner::new();
    r.answer(&["sudo"], exit(1, "sudo: a password is required"));
    let (dir, d3) = drive(&r);
    std::fs::write(dir.path().join("drive.json"), "previous").expect("w");
    assert_eq!(d3.apply(&input).await, Err("sudo: a password is required".into()));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("drive.json")).expect("r"),
        "previous"
    );
}

/// A fake rclone `rc` on loopback.
async fn rclone(stats: Value, queue: Value) -> u16 {
    let mut router = cc_http::Router::new(&["all"]);
    router.prefix("all", "/", move |req, _| {
        let (stats, queue) = (stats.clone(), queue.clone());
        async move {
            let v = if req.uri().path() == "/vfs/stats" { stats } else { queue };
            cc_http::json(200, &v)
        }
    });
    let router = Arc::new(router);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(cc_http::serve(listener, router));
    port
}

#[tokio::test]
async fn status_reports_each_mount_and_says_why_one_is_down() {
    let r = RecordingRunner::new();
    let (dir, d) = drive(&r);
    assert_eq!(d.status().await["applyStatus"], "none");
    assert_eq!(d.summary(), None);
    let port = rclone(
        json!({"diskCache": {"bytesUsed": 2048, "uploadsQueued": 2, "uploadsInProgress": 0, "erroredFiles": 0, "outOfSpace": false}}),
        json!({"queue": [{"tries": 1, "uploading": false}, {"tries": 0, "uploading": true}]}),
    )
    .await;
    std::fs::write(
        dir.path().join("drive.json"),
        serde_json::to_string(&parse_apply(&body(good())).expect("p")).expect("j"),
    )
    .expect("w");
    std::fs::write(
        dir.path().join("drive-mounts.json"),
        json!({"status": "ok", "detail": "", "connected": true, "unsaved": [{"name": "Old", "files": 2}, 5], "at": "2026-10-28T00:00:00.000Z",
               "mounts": [{"name": "Team Docs", "rcPort": port, "mounted": true, "active": "active"},
                          {"name": "Archive", "rcPort": 1, "mounted": false, "active": "inactive"},
                          {"name": 3}]})
        .to_string(),
    )
    .expect("w");
    let s = d.status().await;
    assert_eq!(s["unsaved"], json!([{"name": "Old", "files": 2}]));
    let m = &s["mounts"];
    assert_eq!(m.as_array().map(Vec::len), Some(2), "a row with no port is dropped");
    assert_eq!(m[0]["mode"], "rw");
    assert_eq!(m[0]["cacheBytes"], 2048);
    assert_eq!(m[0]["queuedUploads"], 2);
    assert_eq!(m[0]["failingUploads"], 1);
    assert_eq!(m[0]["lastError"], Value::Null);
    assert_eq!(m[1]["mode"], "ro");
    assert_eq!(m[1]["cacheBytes"], Value::Null);
    assert_eq!(m[1]["failingUploads"], Value::Null);
    assert_eq!(m[1]["lastError"], "the mount is inactive");
    assert_eq!(
        d.summary(),
        Some(json!({"folders": 2, "mounted": 1, "connected": true}))
    );
    // A malformed report is no report.
    std::fs::write(dir.path().join("drive-mounts.json"), "{\"mounts\": 5}").expect("w");
    assert_eq!(d.status().await["applyStatus"], "none");
}
