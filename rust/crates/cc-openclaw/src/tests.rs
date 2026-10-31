use std::time::Duration;

use serde_json::json;

use crate::fake::{FakeGateway, FakeReply};
use crate::{ConfigWritePhase, GatewayClient, GatewayError, GatewayEvent, GatewayOptions};

const SHORT: Duration = Duration::from_millis(500);

fn opts(url: String, token: &str) -> GatewayOptions {
    let mut o = GatewayOptions::new(url, token);
    o.min_backoff = Duration::from_millis(20);
    o.max_backoff = Duration::from_millis(50);
    o
}

async fn connected(gw: &FakeGateway, token: &str) -> GatewayClient {
    let c = GatewayClient::new(opts(gw.url(), token));
    c.start();
    assert!(c.when_connected(Duration::from_secs(5)).await, "did not connect");
    c
}

#[tokio::test]
async fn handshake_sends_the_ts_hello() {
    let gw = FakeGateway::start("tok").await.unwrap();
    let c = connected(&gw, "tok").await;
    let first = gw.received().remove(0);
    assert_eq!(
        first,
        json!({
            "type": "req", "id": "1", "method": "connect",
            "params": {
                "minProtocol": 4, "maxProtocol": 4,
                "client": { "id": "gateway-client", "version": "controlclaw-vm-agent", "platform": "linux", "mode": "backend" },
                "role": "operator",
                "scopes": ["operator.read", "operator.approvals", "operator.admin"],
                "caps": ["approvals", "exec-approvals"],
                "auth": { "token": "tok" },
            }
        })
    );
    // Value equality ignores key order; the client builds the frame in the TS order (preserve_order).
    assert_eq!(gw.handshakes(), 1);
    assert!(c.connected());
    c.stop();
}

#[tokio::test]
async fn call_correlates_by_id() {
    let gw = FakeGateway::start("tok").await.unwrap();
    gw.on("echo", |p| FakeReply::Ok(json!({ "got": p })));
    gw.reply("config.get", json!({ "hash": "h1" }));
    let c = connected(&gw, "tok").await;
    let (a, b) = tokio::join!(
        c.call("echo", json!({ "n": 1 }), SHORT),
        c.call("config.get", json!({}), SHORT)
    );
    assert_eq!(a.unwrap(), json!({ "got": { "n": 1 } }));
    assert_eq!(b.unwrap(), json!({ "hash": "h1" }));
    let ids: Vec<_> = gw.received().iter().map(|f| f["id"].clone()).collect();
    assert_eq!(ids, vec![json!("1"), json!("2"), json!("3")]);
    c.stop();
}

#[tokio::test]
async fn error_frames_read_like_the_ts() {
    let gw = FakeGateway::start("tok").await.unwrap();
    gw.on("m", |_| FakeReply::Err {
        code: Some("E".into()),
        message: Some("bad thing".into()),
    });
    gw.on("c", |_| FakeReply::Err {
        code: Some("ONLY_CODE".into()),
        message: None,
    });
    gw.on("n", |_| FakeReply::Err {
        code: None,
        message: None,
    });
    let c = connected(&gw, "tok").await;
    assert_eq!(
        c.call("m", json!({}), SHORT).await.unwrap_err().to_string(),
        "bad thing"
    );
    assert_eq!(
        c.call("c", json!({}), SHORT).await.unwrap_err().to_string(),
        "ONLY_CODE"
    );
    assert_eq!(
        c.call("n", json!({}), SHORT).await.unwrap_err().to_string(),
        "gateway error"
    );
    assert_eq!(
        c.call("nope", json!({}), SHORT).await.unwrap_err(),
        GatewayError::Remote {
            code: Some("unknown_method".into()),
            message: Some("unknown method: nope".into())
        }
    );
    c.stop();
}

#[tokio::test]
async fn timeout_and_not_connected() {
    let gw = FakeGateway::start("tok").await.unwrap();
    gw.on("slow", |_| FakeReply::Silent);
    let idle = GatewayClient::new(opts(gw.url(), "tok"));
    assert_eq!(
        idle.call("x", json!({}), SHORT).await.unwrap_err().to_string(),
        "gateway not connected"
    );
    let c = connected(&gw, "tok").await;
    let e = c.call("slow", json!({}), Duration::from_millis(100)).await.unwrap_err();
    assert_eq!(e.to_string(), "gateway call slow timed out");
    c.stop();
}

#[tokio::test]
async fn wrong_token_never_connects_and_keeps_trying() {
    let gw = FakeGateway::start("right").await.unwrap();
    let c = GatewayClient::new(opts(gw.url(), "wrong"));
    c.start();
    assert!(!c.when_connected(Duration::from_millis(400)).await);
    assert_eq!(gw.handshakes(), 0);
    assert!(gw.calls("connect").len() >= 2, "it should retry the handshake");
    c.stop();
}

#[tokio::test]
async fn reconnects_after_the_gateway_restarts() {
    let gw = FakeGateway::start("tok").await.unwrap();
    gw.on("slow", |_| FakeReply::Silent);
    let c = connected(&gw, "tok").await;
    let mut state = c.connection_state();
    let pending = {
        let c = c.clone();
        tokio::spawn(async move { c.call("slow", json!({}), Duration::from_secs(5)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    gw.drop_connections();
    // A call in flight fails the way the TS one does.
    assert_eq!(pending.await.unwrap().unwrap_err(), GatewayError::Disconnected);
    state.wait_for(|c| !*c).await.unwrap();
    assert!(c.when_connected(Duration::from_secs(5)).await);
    assert_eq!(gw.handshakes(), 2);
    c.stop();
}

#[tokio::test]
async fn connects_once_a_late_gateway_comes_up() {
    // A free port with nothing on it yet: the client retries until the gateway listens.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let c = GatewayClient::new(opts(format!("ws://127.0.0.1:{port}"), "tok"));
    c.start();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!c.connected());
    let gw = FakeGateway::start_on(format!("127.0.0.1:{port}").parse().unwrap(), "tok")
        .await
        .unwrap();
    assert!(c.when_connected(Duration::from_secs(5)).await);
    assert_eq!(gw.handshakes(), 1);
    c.stop();
}

#[tokio::test]
async fn events_and_config_write_phases() {
    let gw = FakeGateway::start("tok").await.unwrap();
    gw.reply("config.patch", json!({ "ok": true }));
    let c = connected(&gw, "tok").await;
    let mut events = c.events();
    let mut writes = c.config_writes();
    gw.emit("exec.approval.requested", json!({ "id": "a1" }));
    let ev = tokio::time::timeout(SHORT, events.recv()).await.unwrap().unwrap();
    assert_eq!(
        ev,
        GatewayEvent {
            event: "exec.approval.requested".into(),
            payload: json!({ "id": "a1" })
        }
    );
    c.call("config.patch", json!({ "raw": "{}" }), SHORT).await.unwrap();
    assert_eq!(writes.recv().await.unwrap(), ConfigWritePhase::Start);
    assert_eq!(writes.recv().await.unwrap(), ConfigWritePhase::End);
    // Other methods are not config writes.
    gw.reply("status", json!({}));
    c.call("status", json!({}), SHORT).await.unwrap();
    assert!(writes.try_recv().is_err());
    c.stop();
}

#[test]
fn options_from_keys_dir() {
    let dir = tempfile::tempdir().unwrap();
    assert!(GatewayOptions::from_keys_dir(dir.path(), 18789).is_none());
    std::fs::write(dir.path().join("openclaw_gateway_token"), "  \n").unwrap();
    assert!(GatewayOptions::from_keys_dir(dir.path(), 18789).is_none());
    std::fs::write(dir.path().join("openclaw_gateway_token"), "abc\n").unwrap();
    let o = GatewayOptions::from_keys_dir(dir.path(), 18789).unwrap();
    assert_eq!((o.url.as_str(), o.token.as_str()), ("ws://127.0.0.1:18789", "abc"));
    assert_eq!(o.max_backoff, Duration::from_secs(2));
}
