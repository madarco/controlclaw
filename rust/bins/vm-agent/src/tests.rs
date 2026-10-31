//! The foundation's routes, in process, with a recording runner standing in for systemctl.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use cc_auth::console::ConsoleAuth;
use cc_auth::firewall::FirewallAuth;
use cc_auth::jwt::VerifyKey;
use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_proc::{RecordingRunner, exit, ok};
use cc_testkit::BoxKeys;
use serde_json::{Value, json};

use crate::app::{App, Config};

struct Box_ {
    _dir: tempfile::TempDir,
    _app: Arc<App>,
    keys: BoxKeys,
    runner: RecordingRunner,
    url: String,
}

async fn start(service: &str, pool: bool) -> Box_ {
    start_with(service, pool, |_| {}).await
}

/// `start`, with `before` run on the app before its routes are registered (W8: a fake contract
/// provider goes in first, and the real one leaves a filled slot alone).
async fn start_with(service: &str, pool: bool, before: impl FnOnce(&Arc<App>)) -> Box_ {
    let dir = tempfile::tempdir().expect("dir");
    let keys = BoxKeys::write(&dir.path().join("keys"), "vm_1", "box.example").expect("keys");
    let marker = dir.path().join("pool-unclaimed");
    if pool {
        std::fs::write(&marker, "").expect("marker");
    }
    let config = Config {
        port: 0,
        bind: "127.0.0.1".into(),
        keys_dir: keys.dir.clone(),
        state_dir: dir.path().join("state"),
        service: service.into(),
        gateway_port: 18789,
        home: dir.path().to_path_buf(),
        pool_marker: marker,
        conformance_routes: false,
    };
    let runner = RecordingRunner::new();
    runner.answer(&["systemctl", "is-active", "openclaw"], ok("active\n"));
    runner.answer(&["systemctl", "is-active"], exit(3, "inactive\n"));
    runner.answer(&["systemctl", "cat", "docker"], ok("[Unit]\n"));
    runner.answer(&["systemctl", "status"], ok("● openclaw.service\n"));
    runner.answer(&["sudo", "-n", "systemctl"], ok(""));
    let kd = KeysDir::new(&keys.dir);
    let http = HttpClient::new(true).expect("http");
    let app = Arc::new(App {
        console_auth: ConsoleAuth::new(
            VerifyKey::ed25519_spki_pem(&keys.saas.public_pem).expect("key"),
            Some("vm_1".into()),
            service,
        ),
        firewall_auth: FirewallAuth::new(|| None, Some("vm_1".into()), Vec::new, None),
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
    before(&app);
    let router = Arc::new(crate::router(&app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, router));
    Box_ {
        _dir: dir,
        _app: app,
        keys,
        runner,
        url,
    }
}

async fn call(b: &Box_, method: &str, path: &str, token: Option<String>) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut r = c.request(method.parse().expect("method"), format!("{}{path}", b.url));
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    let res = r.send().await.expect("send");
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn health_needs_the_console_token_and_lists_no_processes() {
    let b = start("openclaw", false).await;
    assert_eq!(
        call(&b, "GET", "/health", None).await,
        (401, json!({"error": "Unauthorized"}))
    );
    let (status, body) = call(&b, "GET", "/health", Some(b.keys.console_token(json!({})))).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert!(body.get("ps").is_none());
    assert_eq!(
        body["services"],
        json!({"docker": "stopped", "tailscaled": "not-installed", "browser-stream": "not-installed", "openclaw": "running"})
    );
    // A browser login token carries a purpose and opens nothing here.
    assert_eq!(
        call(
            &b,
            "GET",
            "/health",
            Some(b.keys.console_token(json!({"purpose": "browser-login"})))
        )
        .await
        .0,
        401
    );
    // Another box's token neither.
    assert_eq!(
        call(
            &b,
            "GET",
            "/health",
            Some(b.keys.console_token(json!({"vmId": "vm_2"})))
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn off_list_paths_are_401_even_with_a_token() {
    let b = start("openclaw", false).await;
    let t = b.keys.console_token(json!({}));
    assert_eq!(call(&b, "GET", "/nope", Some(t.clone())).await.0, 401);
    assert_eq!(call(&b, "POST", "/health", Some(t)).await.0, 401);
}

#[tokio::test]
async fn lifecycle_runs_systemctl_through_sudo() {
    let b = start("openclaw", false).await;
    let (status, body) = call(&b, "POST", "/restart", Some(b.keys.console_token(json!({})))).await;
    assert_eq!(status, 200);
    assert_eq!(body["action"], "restart");
    assert_eq!(body["active"], true);
    let ran: Vec<String> = b
        .runner
        .calls()
        .iter()
        .map(|c| format!("{} {}", c.program, c.args.join(" ")))
        .collect();
    assert!(
        ran.contains(&"sudo -n systemctl restart openclaw".to_string()),
        "{ran:?}"
    );
    let (status, body) = call(&b, "GET", "/status", Some(b.keys.console_token(json!({})))).await;
    assert_eq!((status, body["action"].clone()), (200, json!("status")));
}

#[tokio::test]
async fn pool_mode_answers_only_health() {
    let b = start("openclaw", true).await;
    assert_eq!(
        call(&b, "GET", "/health", None).await,
        (503, json!({"unclaimed": true, "ready": false}))
    );
    assert_eq!(call(&b, "GET", "/health?x=1", None).await.0, 401);
    assert_eq!(
        call(&b, "GET", "/status", Some(b.keys.console_token(json!({}))))
            .await
            .0,
        401
    );
}

#[tokio::test]
async fn brain_box_has_its_own_list() {
    let b = start("gbrain", false).await;
    let (status, body) = call(&b, "GET", "/health", Some(b.keys.console_token(json!({})))).await;
    assert_eq!((status, body["role"].clone()), (200, json!("gbrain")));
    assert_eq!(
        call(&b, "GET", "/skills", Some(b.keys.console_token(json!({}))))
            .await
            .0,
        401
    );
    let (status, body) = call(&b, "POST", "/restart", Some(b.keys.console_token(json!({})))).await;
    assert_eq!((status, body["action"].clone()), (200, json!("restart")));
    assert!(
        b.runner
            .calls()
            .iter()
            .any(|c| c.program == "sudo" && c.args == ["-n", "systemctl", "restart", "gbrain"])
    );
}

struct FakeMeeting(std::sync::atomic::AtomicUsize);

impl crate::contracts::MeetingControl for FakeMeeting {
    fn busy(&self) -> bool {
        true
    }
    fn stop(&self) -> cc_http::BoxFuture<Result<(), String>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Err("left badly".to_string()) })
    }
}

#[tokio::test]
async fn stop_leaves_the_meeting_first_and_stops_anyway() {
    let meeting = Arc::new(FakeMeeting(Default::default()));
    let m = meeting.clone();
    let b = start_with("openclaw", false, move |app| app.contracts.meeting.set(m)).await;
    let (status, _) = call(&b, "POST", "/stop", Some(b.keys.console_token(json!({})))).await;
    assert_eq!(status, 200);
    assert_eq!(meeting.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        b.runner
            .calls()
            .iter()
            .any(|c| c.args == ["-n", "systemctl", "stop", "openclaw"])
    );
    // Start does not touch the meeting.
    call(&b, "POST", "/start", Some(b.keys.console_token(json!({})))).await;
    assert_eq!(meeting.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}
