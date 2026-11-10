//! A box for the box side's tests: a key folder with fixed keys and a session secret, an `App`
//! with a recording runner, and helpers to serve a router and sign a session cookie.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use cc_auth::console::ConsoleAuth;
use cc_auth::firewall::FirewallAuth;
use cc_auth::jwt::VerifyKey;
use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_proc::RecordingRunner;
use cc_testkit::BoxKeys;

use crate::app::{App, Config};

pub struct TestBox {
    pub dir: tempfile::TempDir,
    pub app: Arc<App>,
    pub keys: BoxKeys,
    #[allow(dead_code)] // for the tests that check helper calls
    pub runner: RecordingRunner,
}

pub fn test_box() -> TestBox {
    let dir = tempfile::tempdir().expect("dir");
    let keys = BoxKeys::write(&dir.path().join("keys"), "vm_1", "box.example").expect("keys");
    std::fs::write(keys.dir.join("session_secret"), hex::encode([7u8; 32])).expect("secret");
    let config = Config {
        port: 0,
        legacy_port: None,
        bind: "127.0.0.1".into(),
        keys_dir: keys.dir.clone(),
        state_dir: dir.path().join("state"),
        service: "openclaw".into(),
        gateway_port: 18789,
        home: dir.path().to_path_buf(),
        pool_marker: dir.path().join("pool-unclaimed"),
        conformance_routes: false,
    };
    let kd = KeysDir::new(&keys.dir);
    let http = HttpClient::new(true).expect("http");
    let pin = keys.firewall.public_pem.clone();
    let runner = RecordingRunner::new();
    let app = Arc::new(App {
        console_auth: ConsoleAuth::new(
            VerifyKey::ed25519_spki_pem(&keys.saas.public_pem).expect("key"),
            Some("vm_1".into()),
            "openclaw",
        ),
        firewall_auth: FirewallAuth::new(move || Some(pin.clone()), Some("vm_1".into()), Vec::new, None),
        runner: Arc::new(runner.clone()),
        console: ConsoleClient::new(kd.clone(), http.clone()),
        http,
        keys: kd,
        pool_healthy: AtomicBool::new(false),
        bootstrap_ready: AtomicBool::new(false),
        contracts: crate::contracts::Contracts::default(),
        started: std::time::Instant::now(),
        unmanaged: None,
        config,
    });
    TestBox { dir, app, keys, runner }
}

/// Serve `router` on a loopback port; its base URL.
pub async fn serve(router: cc_http::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    url
}

/// `__Host-cc_session=<token>` for `vm_1`, signed with the test secret.
pub fn session_cookie(can_write: bool) -> String {
    let mut c = serde_json::Map::new();
    c.insert("sub".into(), serde_json::json!("vm_1"));
    if can_write {
        c.insert("canWrite".into(), serde_json::json!(true));
    }
    let t = cc_auth::jwt::sign(c, &cc_auth::jwt::SignKey::Hs256(vec![7u8; 32]), Some(3600), None).expect("sign");
    format!("__Host-cc_session={t}")
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}
