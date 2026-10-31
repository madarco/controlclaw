//! `devices.test.ts`: the CLI path, banners, retries, busy against failed, the cache and writes.

use std::sync::Arc;

use cc_proc::{Output, RecordingRunner, ok};
use serde_json::json;

use super::*;

fn fail(stderr: &str) -> Output {
    Output {
        code: Some(1),
        stderr: stderr.as_bytes().to_vec(),
        ..Output::default()
    }
}

fn devices(r: &RecordingRunner) -> Arc<Devices> {
    Arc::new(Devices::new(Arc::new(r.clone()), Arc::new(|| None)).uncached())
}

const LIST: &str = r#"banner line
{"pending":[{"requestId":"req-1","deviceId":"dev-1","displayName":"Ada's Mac","scopes":["operator",5],"ts":1700},{"deviceId":"no-request"}],
 "paired":[{"deviceId":"dev-2","operatorLabel":"Studio","connected":true,"createdAtMs":1600}]}"#;

#[tokio::test]
async fn with_no_bridge_the_cli_carries_the_listing_past_its_banner() {
    let r = RecordingRunner::new();
    r.answer(&["/usr/bin/openclaw", "devices", "list", "--json"], ok(LIST));
    let d = devices(&r);
    let v = d.list().await;
    assert_eq!(v["error"], Value::Null);
    assert_eq!(
        v["pending"].as_array().map(Vec::len),
        Some(1),
        "a row with no request id is dropped"
    );
    assert_eq!(v["pending"][0]["scopes"], json!(["operator"]));
    assert_eq!(v["pending"][0]["at"], 1700);
    assert_eq!(v["paired"][0]["label"], "Studio");
    assert_eq!(v["paired"][0]["approvedAt"], 1600);
    assert_eq!(v["paired"][0]["connected"], true);
}

#[tokio::test]
async fn a_listing_nobody_could_read_is_an_error_busy_or_not() {
    let r = RecordingRunner::new();
    r.answer(&["/usr/bin/openclaw"], fail("Error: database is locked\n"));
    let v = devices(&r).list().await;
    assert_eq!(
        v["error"],
        json!({"busy": true, "message": "The agent is busy right now, so its paired devices could not be read."})
    );
    assert_eq!(r.calls().len(), 3, "retried");

    let r = RecordingRunner::new();
    r.answer(&["/usr/bin/openclaw"], fail("Error: unknown command devices\n"));
    let v = devices(&r).list().await;
    assert_eq!(
        v["error"],
        json!({"busy": false, "message": "The agent could not list its paired devices: Error: unknown command devices"})
    );
}

#[tokio::test]
async fn a_write_goes_through_the_cli_once_and_drops_the_cache() {
    let r = RecordingRunner::new();
    r.answer(&["/usr/bin/openclaw", "devices", "list"], ok(LIST));
    r.answer(
        &["/usr/bin/openclaw", "devices", "approve"],
        ok(r#"{"device":{"deviceId":"dev-1"}}"#),
    );
    r.answer(&["/usr/bin/openclaw", "devices", "remove"], fail("boom\n"));
    let d = Arc::new(Devices::new(Arc::new(r.clone()), Arc::new(|| None)));
    d.list().await;
    d.list().await;
    let lists = |r: &RecordingRunner| {
        r.calls()
            .iter()
            .filter(|c| c.args.get(1).map(String::as_str) == Some("list"))
            .count()
    };
    assert_eq!(lists(&r), 1, "cached");
    assert_eq!(d.approve("req-1").await, Ok(json!({"ok": true, "deviceId": "dev-1"})));
    d.list().await;
    assert_eq!(lists(&r), 2, "a write drops the cached listing");
    assert_eq!(d.remove("dev-2").await, Err("boom".into()));
    let removes = r
        .calls()
        .iter()
        .filter(|c| c.args.get(1).map(String::as_str) == Some("remove"))
        .count();
    assert_eq!(removes, 1, "a write is never retried");
}

#[tokio::test]
async fn two_callers_at_once_are_one_read() {
    let r = RecordingRunner::new();
    r.answer_with(|c| {
        (c.args.get(1).map(String::as_str) == Some("list")).then(|| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            ok(LIST)
        })
    });
    let d = Arc::new(Devices::new(Arc::new(r.clone()), Arc::new(|| None)));
    let (a, b) = tokio::join!(d.list(), d.list());
    assert_eq!(a, b);
    assert_eq!(r.calls().len(), 1);
}

#[test]
fn ids_are_shape_checked() {
    let b = |v: Value| v.as_object().cloned().expect("obj");
    assert_eq!(
        id_of(&b(json!({"requestId": "req-1:a.b_c"})), "requestId").as_deref(),
        Some("req-1:a.b_c")
    );
    for bad in [json!(""), json!("-x"), json!("a b"), json!(5), json!("x".repeat(129))] {
        assert_eq!(id_of(&b(json!({"requestId": bad})), "requestId"), None);
    }
}

#[tokio::test]
async fn a_read_its_caller_gave_up_on_is_still_kept_and_a_write_during_one_is_not() {
    let r = RecordingRunner::new();
    r.answer(&["/usr/bin/openclaw", "devices", "list"], ok(LIST));
    let d = Arc::new(Devices::new(Arc::new(r.clone()), Arc::new(|| None)));
    let lists = |r: &RecordingRunner| {
        r.calls()
            .iter()
            .filter(|c| c.args.get(1).map(String::as_str) == Some("list"))
            .count()
    };
    // The only caller goes away before the read ends; the read still settles.
    {
        let gone = d.list();
        tokio::pin!(gone);
        assert!(futures_util::poll!(&mut gone).is_pending());
    }
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(d.list().await["error"], Value::Null);
    assert_eq!(lists(&r), 1, "kept, and nothing left in flight");
    // A write while a read is in flight: the read's answer goes to its callers, not the cache.
    d.invalidate();
    let first = d.list();
    tokio::pin!(first);
    assert!(futures_util::poll!(&mut first).is_pending());
    d.invalidate();
    first.await;
    d.list().await;
    assert_eq!(lists(&r), 3);
}
