//! `routes/phone-page.test.ts`, through the whole router, with W7's sessions.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use cc_auth::console::ConsoleAuth;
use cc_auth::firewall::FirewallAuth;
use cc_auth::jwt::VerifyKey;
use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_proc::RecordingRunner;
use cc_testkit::BoxKeys;
use serde_json::{Value, json};

use crate::app::{App, Config};
use crate::boxside::session::{SessionClaims, session_cookie};
use crate::phone::history::tests::{A, plugin_db, rec};

const ORIGIN: &str = "https://box.example";

struct Rig {
    _dir: tempfile::TempDir,
    app: Arc<App>,
    url: String,
    db: std::path::PathBuf,
}

async fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("dir");
    let keys = BoxKeys::write(&dir.path().join("keys"), "vm_1", "box.example").expect("keys");
    crate::keys::ensure_session_secret(&keys.dir).expect("secret");
    let call = rec(
        A,
        json!({"transcript": [{"timestamp": 2_000, "speaker": "user", "text": "my secret question"}]}),
    );
    let db = plugin_db(&dir.path().join(".openclaw"), &[call]);
    let config = Config {
        port: 0,
        bind: "127.0.0.1".into(),
        keys_dir: keys.dir.clone(),
        state_dir: dir.path().join("state"),
        service: "openclaw".into(),
        gateway_port: 18789,
        home: dir.path().to_path_buf(),
        pool_marker: dir.path().join("no-pool"),
        conformance_routes: false,
    };
    let kd = KeysDir::new(&keys.dir);
    let http = HttpClient::new(true).expect("http");
    let app = Arc::new(App {
        console_auth: ConsoleAuth::new(
            VerifyKey::ed25519_spki_pem(&keys.saas.public_pem).expect("key"),
            Some("vm_1".into()),
            "openclaw",
        ),
        firewall_auth: FirewallAuth::new(|| None, Some("vm_1".into()), Vec::new, None),
        runner: Arc::new(RecordingRunner::new()),
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
    let router = Arc::new(crate::router(&app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, router));
    Rig {
        _dir: dir,
        app,
        url,
        db,
    }
}

fn cookie(r: &Rig, vm_id: &str, can_write: bool, device: Option<&str>) -> String {
    let access = r.app.contracts.access.get().expect("access");
    let token = access
        .sessions
        .issue_session(
            vm_id,
            &SessionClaims {
                can_write,
                device_id: device.map(String::from),
            },
        )
        .expect("token");
    session_cookie(&token).split(';').next().unwrap_or_default().to_string()
}

async fn get(r: &Rig, path: &str, headers: &[(&str, &str)]) -> (u16, String, reqwest::header::HeaderMap) {
    let mut q = reqwest::Client::new().get(format!("{}{path}", r.url));
    for (k, v) in headers {
        q = q.header(*k, *v);
    }
    let res = q.send().await.expect("send");
    let (status, h) = (res.status().as_u16(), res.headers().clone());
    (status, res.text().await.expect("text"), h)
}

#[tokio::test]
async fn history_needs_an_enrolled_browser_on_this_origin_and_deleting_needs_write() {
    let r = rig().await;
    let reader = cookie(&r, "vm_1", false, Some("device"));
    let writer = cookie(&r, "vm_1", true, Some("device"));

    // The page: no session, a session without an enrolled browser, or another box's session.
    for c in [
        None,
        Some(cookie(&r, "vm_1", true, None)),
        Some(cookie(&r, "other", true, Some("d"))),
    ] {
        let headers: Vec<(&str, &str)> = c.as_deref().map(|c| vec![("cookie", c)]).unwrap_or_default();
        let (status, body, _) = get(&r, "/__cc/phone", &headers).await;
        assert_eq!(status, 401);
        assert!(body.contains("private"), "{body}");
    }
    let (status, html, h) = get(&r, "/__cc/phone", &[("cookie", &reader)]).await;
    assert_eq!(status, 200);
    assert_eq!(
        h.get("x-frame-options").map(|v| v.to_str().unwrap_or_default()),
        Some("DENY")
    );
    assert!(html.contains("/__cc/files-ui/phone.js"));
    assert!(html.contains(r#""canDelete":false"#));

    // Reads: same origin only, then the session.
    let same = [("origin", ORIGIN), ("sec-fetch-site", "same-origin")];
    let (status, _, _) = get(
        &r,
        "/__cc/phone/calls",
        &[
            ("cookie", &reader),
            ("origin", "https://evil.ccl.bot"),
            ("sec-fetch-site", "cross-site"),
        ],
    )
    .await;
    assert_eq!(status, 403);
    let (status, _, _) = get(&r, "/__cc/phone/calls", &same).await;
    assert_eq!(status, 401);
    let mut with_reader = same.to_vec();
    with_reader.push(("cookie", &reader));
    let (status, body, h) = get(&r, "/__cc/phone/calls", &with_reader).await;
    assert_eq!(status, 200);
    assert_eq!(
        h.get("cache-control").map(|v| v.to_str().unwrap_or_default()),
        Some("no-store")
    );
    let body: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(body["available"], true);
    assert_eq!(body["calls"][0]["from"], "…4183", "numbers leave the box masked");
    assert!(
        body["calls"][0].get("transcript").is_none(),
        "the list carries no transcript"
    );
    let (_, one, _) = get(&r, &format!("/__cc/phone/calls/{A}"), &with_reader).await;
    let one: Value = serde_json::from_str(&one).expect("json");
    assert_eq!(one["transcript"][0]["text"], "my secret question");
    let (status, _, _) = get(&r, "/__cc/phone/calls/not-a-call", &with_reader).await;
    assert_eq!(status, 404);

    // Delete: write sessions only, a well-formed target only.
    let del = |c: String, body: Value| {
        let url = format!("{}/__cc/phone/delete", r.url);
        async move {
            reqwest::Client::new()
                .post(url)
                .header("cookie", c)
                .header("origin", ORIGIN)
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .expect("send")
                .status()
                .as_u16()
        }
    };
    assert_eq!(del(reader.clone(), json!({"id": A})).await, 403);
    assert_eq!(
        crate::phone::history::PluginCallStore::new(&r.db)
            .calls()
            .expect("calls")
            .len(),
        1
    );
    assert_eq!(del(writer.clone(), json!({"id": "x"})).await, 400);
    assert_eq!(del(writer.clone(), json!({"id": A})).await, 200);
    assert!(
        crate::phone::history::PluginCallStore::new(&r.db)
            .calls()
            .expect("calls")
            .is_empty()
    );
    assert_eq!(del(writer, json!({"all": true})).await, 200);
}

/// `readPhoneUsage`: usage lines are read, and a log past 1 MiB is cut to its newest 5000 lines so
/// the adapter, which stops at 8 MiB, keeps writing.
#[test]
fn usage_is_read_and_the_log_kept_small() {
    let dir = tempfile::tempdir().expect("dir");
    let line = |i: usize| {
        format!(
            r#"{{"kind":"usage","startedAt":"2026-10-01T02:31:00.000Z","seconds":{}.4,"pad":"{}"}}"#,
            i % 9,
            "x".repeat(200)
        )
    };
    let text: String = (0..6000).map(|i| line(i) + "\n").collect();
    assert!(text.len() > 1024 * 1024);
    std::fs::write(dir.path().join("phone.jsonl"), &text).expect("file");
    let usage = crate::phone::page::read_phone_usage(dir.path());
    assert!(!usage.is_empty());
    assert_eq!(usage[0].seconds, 0.0);
    assert_eq!(usage[1].seconds, 1.0);
    let left = std::fs::read_to_string(dir.path().join("phone.jsonl")).expect("file");
    assert_eq!(left.lines().count(), 5000);
    assert!(left.ends_with('\n'));
    assert!(crate::phone::page::read_phone_usage(&dir.path().join("missing")).is_empty());
}
