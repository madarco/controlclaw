use std::time::Duration;

use cc_auth::jwt::{self, VerifyKey, VerifyOptions};
use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_testkit::{BoxKeys, FakeConsole};
use serde_json::json;

#[tokio::test]
async fn console_calls_carry_a_box_token() {
    let dir = tempfile::tempdir().expect("dir");
    let keys = BoxKeys::write(dir.path(), "vm_1", "box.example").expect("keys");
    let console = FakeConsole::start().await.expect("console");
    console.answer("/api/vm-agent/ready", vec![(200, json!({"ok": true}))]);
    let client = ConsoleClient::new(KeysDir::new(dir.path()), HttpClient::new(true).expect("client"));
    let a = client
        .post_json(
            &console.url("/api/vm-agent/ready"),
            &json!({"x": 1}),
            Duration::from_secs(5),
        )
        .await
        .expect("post");
    assert_eq!((a.status, a.body), (200, json!({"ok": true})));
    let got = console.received().pop().expect("received");
    assert_eq!(got.body, json!({"x": 1}));
    let token = got
        .authorization
        .as_deref()
        .and_then(|h| h.strip_prefix("Bearer "))
        .expect("bearer");
    let claims = jwt::verify(
        token,
        &VerifyKey::ed25519_spki_pem(&keys.vm.public_pem).expect("key"),
        VerifyOptions::default(),
    )
    .expect("verify");
    assert_eq!(claims["vmId"], "vm_1");
    assert_eq!(
        claims["exp"].as_i64().unwrap_or_default() - claims["iat"].as_i64().unwrap_or_default(),
        30
    );
}

#[tokio::test]
async fn an_error_never_shows_the_url() {
    let dir = tempfile::tempdir().expect("dir");
    BoxKeys::write(dir.path(), "vm_1", "box.example").expect("keys");
    let client = ConsoleClient::new(KeysDir::new(dir.path()), HttpClient::new(true).expect("client"));
    // Nothing listens on port 9; the URL holds what a token in a query would look like.
    let e = client
        .get_json(
            "http://127.0.0.1:9/hook?token=very-secret-token",
            Duration::from_secs(2),
        )
        .await
        .expect_err("refused");
    let text = format!("{e} {e:?}");
    assert!(!text.contains("very-secret-token") && !text.contains("/hook"), "{text}");
}
