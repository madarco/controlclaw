//! The foundation's firewall pieces in process: the heartbeat against a fake console, the ingress's
//! answers, and the TLS/HTTP split on 3100.

use std::sync::Arc;
use std::time::Duration;

use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_proc::{RecordingRunner, ok};
use cc_testkit::{BoxKeys, FakeConsole};
use serde_json::{Value, json};

use crate::app::{App, Config};
use crate::commands::{CommandOutcome, Commands};
use crate::core::control::{ControlOptions, FirewallControl};

fn config(dir: &std::path::Path) -> Config {
    Config {
        mode: crate::app::Mode::Saas,
        listen: "127.0.0.1".into(),
        keys_dir: dir.join("keys"),
        box_key_path: dir.join("keys/box_key"),
        port: 0,
        org_id: "org_1".into(),
        box_id: "fw_1".into(),
        proxy_config_dir: dir.join("run"),
        firewall_url: String::new(),
        ingress_port: 0,
        ingress_bind: "127.0.0.1".into(),
        firewall_poll_ms: 50,
        agent_version: "0.1.0".into(),
        recovery_routes: true,
        pool_marker: dir.join("pool-unclaimed"),
        pool_peer: dir.join("pool-peer.json"),
    }
}

fn app(dir: &std::path::Path, runner: RecordingRunner) -> Arc<App> {
    let kd = KeysDir::new(dir.join("keys"));
    let http = HttpClient::new(true).expect("http");
    Arc::new(App {
        config: config(dir),
        console: ConsoleClient::new(kd.clone(), http.clone()),
        keys: kd,
        box_key: cc_crypto::secret_store::generate_box_key(),
        runner: Arc::new(runner),
        http,
        contracts: crate::contracts::Contracts::default(),
        cp_inspect: Arc::new(crate::core::cp_inspect::CpInspect::new(&dir.join("cp-inspect.json"))),
    })
}

async fn beats(console: &FakeConsole, n: usize) -> Vec<Value> {
    for _ in 0..200 {
        let b: Vec<Value> = console
            .received()
            .into_iter()
            .filter(|r| r.path == "/api/vm-agent/firewall")
            .map(|r| r.body)
            .collect();
        if b.len() >= n {
            return b;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("fewer than {n} beats");
}

#[tokio::test]
async fn heartbeat_runs_commands_and_reports_them() {
    let dir = tempfile::tempdir().expect("dir");
    BoxKeys::write(&dir.path().join("keys"), "fw_1", "fw.example").expect("keys");
    let console = FakeConsole::start().await.expect("console");
    let runner = RecordingRunner::new();
    runner.answer(&["systemctl", "is-active"], ok("active\n"));
    runner.answer(&["sudo", "systemctl"], ok(""));
    let a = app(dir.path(), runner.clone());
    let mut commands = Commands::default();
    commands.handle("test.echo", |p| async move {
        CommandOutcome {
            ok: true,
            status: "done".into(),
            message: None,
            data: p
                .get("x")
                .map(|x| json!({"x": x}).as_object().cloned().unwrap_or_default()),
        }
    });
    commands.status(&["features"], || {
        json!({"features": ["test"], "undeclared": 1})
            .as_object()
            .cloned()
            .unwrap_or_default()
    });
    console.queue_command("c1", "test.echo", json!({"x": 7}));
    let control = FirewallControl::new(
        ControlOptions {
            firewall_url: console.url("/api/vm-agent/firewall"),
            agent_version: "0.1.0".into(),
            service: "controlclaw-mitmproxy".into(),
            action_timeout: Duration::from_secs(5),
        },
        commands,
        a.runner.clone(),
        a.console.clone(),
    );
    tokio::spawn(control.run(Duration::from_millis(50)));
    let b = beats(&console, 2).await;
    assert_eq!(b[0]["proxy"], "active");
    assert_eq!(b[0]["features"], json!(["test"]));
    assert!(
        b[0].get("undeclared").is_none(),
        "a key that was not declared stays off the beat"
    );
    assert!(b[0].get("results").is_none());
    let with_result = b
        .iter()
        .find(|x| x.get("results").is_some())
        .expect("a beat with the result");
    assert_eq!(
        with_result["results"],
        json!([{"command_id": "c1", "ok": true, "status": "done", "message": "", "data": {"x": 7}}])
    );

    console.queue_command("c2", "nope.nothing", json!({}));
    console.queue_command("c3", "restart", json!({}));
    let b = beats(&console, 8).await;
    let results: Vec<Value> = b
        .iter()
        .filter_map(|x| x.get("results"))
        .flat_map(|r| r.as_array().cloned().unwrap_or_default())
        .collect();
    assert!(
        results.contains(
            &json!({"command_id": "c2", "ok": false, "status": "failed", "message": "unknown command nope.nothing"})
        ),
        "{results:?}"
    );
    assert!(
        results.contains(&json!({"command_id": "c3", "ok": true, "status": "active", "message": ""})),
        "{results:?}"
    );
    assert!(
        runner
            .calls()
            .iter()
            .any(|c| c.program == "sudo" && c.args == ["systemctl", "restart", "controlclaw-mitmproxy"])
    );
}

async fn serve(router: cc_http::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", l.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(l, Arc::new(router)));
    url
}

#[tokio::test]
async fn ingress_answers_empty_404_and_403_for_upgrades() {
    let dir = tempfile::tempdir().expect("dir");
    let reg = crate::build(&app(dir.path(), RecordingRunner::new()));
    let url = serve(reg.ingress).await;
    let c = reqwest::Client::new();
    let r = c.get(format!("{url}/anything")).send().await.expect("get");
    assert_eq!(r.status(), 404);
    assert!(r.headers().get("content-type").is_none());
    assert_eq!(r.text().await.expect("body"), "");
    let r = c
        .get(format!("{url}/x"))
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .expect("get");
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn port_3100_splits_tls_from_plain() {
    let dir = tempfile::tempdir().expect("dir");
    let runner = RecordingRunner::new();
    let a = app(dir.path(), runner);
    let reg = crate::build(&a);
    // A real certificate, made the way the box makes it.
    let tls = crate::core::recovery_tls::load_or_create(
        &cc_proc::SystemRunner,
        &dir.path().join("keys"),
        "controlclaw-firewall-fw_1",
    )
    .await
    .expect("cert");
    assert!(tls.fingerprint.starts_with("sha256:") && tls.fingerprint.len() == 7 + 95);
    let acceptor = cc_http::tls_acceptor(&tls.cert, &tls.key).expect("acceptor");
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(cc_http::serve_mux(l, Arc::new(reg.plain), Arc::new(reg.tls), acceptor));
    let c = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");
    let plain = c.get(format!("http://{addr}/recovery/x")).send().await.expect("plain");
    assert_eq!(plain.status(), 426);
    assert_eq!(
        c.get(format!("http://{addr}/health"))
            .send()
            .await
            .expect("plain")
            .status(),
        404
    );
    let over_tls = c.get(format!("https://{addr}/recovery/x")).send().await.expect("tls");
    assert_eq!(over_tls.status(), 404);
    assert_eq!(over_tls.text().await.expect("body"), r#"{"error":"Not found"}"#);
}

#[test]
#[should_panic(expected = "beat key features registered twice")]
fn two_parts_cannot_claim_one_beat_key() {
    let mut c = Commands::default();
    c.status(&["features"], serde_json::Map::new);
    c.status(&["features"], serde_json::Map::new);
}

/// Every module's store and helper path, so each one registers its actions (the env is the
/// process's, so the build runs in a child: this test binary again, `CC_ACTIONS_CHILD` set).
fn full_env(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = [
        "AI_TRACE_DIR",
        "AGENTMAIL_STORE_PATH",
        "APPS_RULES_PATH",
        "CONTENT_RULES_STORE_PATH",
        "CONTENT_STOPPED_PATH",
        "EXIT_STORE_PATH",
        "KILL_STORE_PATH",
        "SEARCH_STORE_PATH",
        "CHANNEL_STORE_PATH",
        "CONNECTOR_ASKS_PATH",
        "CONNECTOR_STORE_PATH",
        "DOCTOR_KEY_PATH",
        "DOCTOR_RESERVE_PATH",
        "DOCTOR_TRANSCRIPTS_DIR",
        "DRIVE_STORE_PATH",
        "GOOGLE_STORE_PATH",
        "LLM_STORE_PATH",
        "LOGINS_STORE_PATH",
        "MCP_ASKS_PATH",
        "MCP_CATALOG_PATH",
        "MCP_SERVERS_STORE_PATH",
        "TEAMCHAT_STATS_PATH",
        "TEAMCHAT_STORE_PATH",
        "EMAIL_RULES_STORE_PATH",
        "PHONE_STORE_PATH",
        "TPLCHECK_STORE_PATH",
    ]
    .iter()
    .map(|k| (k.to_string(), dir.join(k).display().to_string()))
    .collect();
    let cp = "http://127.0.0.1:9/api/vm-agent";
    for (k, path) in [
        ("STORE_URL", "store"),
        ("RULES_URL", "egress-rules"),
        ("ACTIVITY_URL", "activity"),
        ("IDENTITIES_URL", "identities"),
        ("PERMISSION_URL", "permission"),
        ("WEBHOOKS_URL", "webhooks"),
        ("CA_URL", "ca"),
    ] {
        env.push((k.into(), format!("{cp}/{path}")));
    }
    // Doctor and template checks register only where their helpers exist; a file of our own stands
    // in, so the answer does not depend on what the host has installed (`/bin/true` is not on macOS).
    let helper = dir.join("helper");
    std::fs::write(&helper, "#!/bin/sh\nexit 0\n").expect("helper stub");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).expect("stub mode");
    }
    let helper = helper.display().to_string();
    for (k, v) in [
        ("STATE_DIR", dir.display().to_string()),
        ("CONNECTOR_URL", "http://127.0.0.1:9".into()),
        ("CONNECTOR_ADMIN_TOKEN", "x".into()),
        ("CONNECTOR_GATE_BIND", "127.0.0.1".into()),
        ("DOCTOR_RUN_HELPER", helper.clone()),
        ("TPLCHECK_CLIENT", helper),
    ] {
        env.push((k.into(), v));
    }
    env
}

/// The same registry in standalone mode (a child run, as above): the stop, the exit proxy and web
/// search are there, every action of each; Tailscale, devices, support SSH, the brain, backups and
/// updates are the SaaS's and are not.
fn standalone_registers_its_controls_only(name: &str) {
    let dir = tempfile::tempdir().expect("tmp");
    let out = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env("CC_ACTIONS_CHILD", dir.path())
        .env("CC_ACTIONS_MODE", "standalone")
        .envs(full_env(dir.path()))
        .output()
        .expect("child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "standalone child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let registered: std::collections::BTreeSet<&str> = stdout
        .lines()
        .filter_map(|l| l.split_once("ACTION ").map(|(_, a)| a))
        .collect();
    for family in ["kill.", "exit.", "search."] {
        let want: Vec<&str> = cc_contracts::commands::ACTIONS
            .iter()
            .map(|a| a.action)
            .filter(|a| a.starts_with(family))
            .collect();
        assert!(!want.is_empty(), "no {family} actions in the contract");
        let missing: Vec<_> = want.iter().filter(|a| !registered.contains(*a)).collect();
        assert!(missing.is_empty(), "standalone does not register {missing:?}");
    }
    let saas_only: Vec<_> = registered
        .iter()
        .filter(|a| {
            ["tailscale.", "devices.", "ssh.", "gbrain.", "backup.", "update."]
                .iter()
                .any(|f| a.starts_with(f))
        })
        .collect();
    assert!(saas_only.is_empty(), "standalone registers the SaaS's {saas_only:?}");
}

/// The registry and `cc_contracts::commands::ACTIONS` name the same actions: an action added or
/// removed here has its row in the contract (docs/standalone/control-plane-contract.md).
#[test]
fn registered_actions_match_the_contract() {
    const NAME: &str = "tests::registered_actions_match_the_contract";
    if let Ok(dir) = std::env::var("CC_ACTIONS_CHILD") {
        let dir = std::path::PathBuf::from(dir);
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let _g = rt.enter();
        let mut a = app(&dir, RecordingRunner::new());
        let cfg = &mut Arc::get_mut(&mut a).expect("one owner").config;
        if std::env::var("CC_ACTIONS_MODE").as_deref() == Ok("standalone") {
            // A standalone firewall: no console, its own control plane.
            cfg.mode = crate::app::Mode::Standalone;
            cfg.firewall_url = String::new();
        } else {
            cfg.firewall_url = "http://127.0.0.1:9/api/vm-agent/firewall".into();
        }
        std::fs::create_dir_all(dir.join("keys")).expect("keys dir");
        std::fs::write(dir.join("keys/vm_hostname"), "fw.example").expect("hostname");
        let reg = crate::build(&a);
        for x in reg.commands.actions() {
            println!("ACTION {x}");
        }
        for k in reg.commands.beat_keys() {
            println!("BEAT {k}");
        }
        return;
    }
    let dir = tempfile::tempdir().expect("tmp");
    let out = std::process::Command::new(std::env::current_exe().expect("exe"))
        .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
        .env("CC_ACTIONS_CHILD", dir.path())
        .envs(full_env(dir.path()))
        .output()
        .expect("child");
    standalone_registers_its_controls_only(NAME);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let registered: std::collections::BTreeSet<&str> =
        // The harness prints "test <name> ... " with no newline before the child's first line.
        stdout.lines().filter_map(|l| l.split_once("ACTION ").map(|(_, a)| a)).collect();
    let contract: std::collections::BTreeSet<&str> = cc_contracts::commands::ACTIONS.iter().map(|a| a.action).collect();
    let beat: std::collections::BTreeSet<&str> = stdout
        .lines()
        .filter_map(|l| l.split_once("BEAT ").map(|(_, a)| a))
        .collect();
    let fields: std::collections::BTreeSet<&str> =
        cc_contracts::control_plane::BEAT_FIELDS.iter().map(|f| f.0).collect();
    let undeclared: Vec<_> = beat.difference(&fields).collect();
    assert!(
        undeclared.is_empty(),
        "beat fields not in the contract's BEAT_FIELDS: {undeclared:?}"
    );
    let missing: Vec<_> = registered.difference(&contract).collect();
    let gone: Vec<_> = contract.difference(&registered).collect();
    assert!(
        missing.is_empty() && gone.is_empty(),
        "registered but not in the contract: {missing:?}; in the contract but not registered: {gone:?}"
    );
}
