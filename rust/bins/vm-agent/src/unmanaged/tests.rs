//! An unmanaged agent in process: the firewall's key from the config file opens its routes, the
//! SaaS routes are not there, and OpenClaw is driven through its CLI (a recording runner here).

use std::sync::Arc;
use std::time::Duration;

use cc_proc::{RecordingRunner, exit, ok};
use cc_testkit::{BoxKeys, Signer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::config::{AgentFile, Firewall};
use super::discover::{Install, Runs};
use super::*;
use crate::app::Config;

struct Agent {
    _dir: tempfile::TempDir,
    /// What the agent runs for OpenClaw: the wrapper in its state dir.
    wrapper: String,
    app: Arc<App>,
    keys: BoxKeys,
    runner: RecordingRunner,
    url: String,
}

/// A gateway that only answers its health check, on a free port.
async fn healthy_gateway() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                    .await;
            });
        }
    });
    port
}

async fn start(paired: bool, gateway_port: u16) -> Agent {
    let dir = tempfile::tempdir().expect("dir");
    let keys = BoxKeys::write(&dir.path().join("keys"), "vm_1", "box.example").expect("keys");
    let file = AgentFile {
        mode: "unmanaged".into(),
        state_dir: Some(dir.path().join("state")),
        agent_id: Some("vm_1".into()),
        firewall: Firewall {
            url: Some("https://fw.example".into()),
            public_key: paired.then(|| keys.firewall.public_pem.clone()),
            hostnames: Some(vec!["box.example".into()]),
            allow_from: None,
            gate: Some("10.77.0.1".parse().expect("ip")),
        },
        ..AgentFile::default()
    };
    let mut config = Config::unmanaged(&file);
    config.home = dir.path().to_path_buf();
    let install = Install {
        cli: Some("/x/openclaw".into()),
        version: Some("2026.10.9".into()),
        config_file: Some("/home/claw/.openclaw/openclaw.json".into()),
        state_dir: Some(dir.path().join(".openclaw").to_string_lossy().into_owned()),
        container_state_dir: None,
        runs: Runs::SystemdUser {
            unit: "openclaw-gateway.service".into(),
        },
        gateway_port,
    };
    let runner = RecordingRunner::new();
    // The unit is active until the emergency stop stops it, and again once it starts it.
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let st = stopped.clone();
    runner.answer_with(move |c| {
        let line = c.args.join(" ");
        let flip = |on| {
            st.store(on, std::sync::atomic::Ordering::SeqCst);
            Some(ok("{\"ok\":true}\n"))
        };
        match (c.program.as_str(), line.as_str()) {
            ("systemctl", "--user stop -- openclaw-gateway.service") => flip(true),
            ("systemctl", "--user start -- openclaw-gateway.service") => flip(false),
            (_, l) if l.starts_with("--user is-active") => Some(if st.load(std::sync::atomic::Ordering::SeqCst) {
                exit(3, "inactive\n")
            } else {
                ok("active\n")
            }),
            _ => None,
        }
    });
    runner.answer(&["/x/openclaw", "gateway", "restart"], ok("{\"ok\":true}\n"));
    let um = Unmanaged::new(file, dir.path().join("agent.json"), &config.home, install.clone());
    let app = crate::startup_unmanaged(config, um, Arc::new(runner.clone()));
    // Rediscovery after a restart finds the same install.
    runner.answer(
        &["/x/openclaw", "gateway", "status"],
        ok(&format!(
            r#"{{"service":{{"loaded":true,"systemdInstallation":{{"kind":"user","user":{{"unitName":"openclaw-gateway.service"}}}}}},"gateway":{{"port":{gateway_port}}}}}"#
        )),
    );
    let router = Arc::new(crate::router(&app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, router));
    super::start(&app);
    let wrapper = discover::wrapper_path(&dir.path().join("state"))
        .to_string_lossy()
        .into_owned();
    Agent {
        wrapper,
        _dir: dir,
        app,
        keys,
        runner,
        url,
    }
}

/// A console-style token (no purpose) signed by the firewall, as `cc-local` will sign them.
fn local_token(a: &Agent) -> String {
    a.keys.sign_with(Signer::Firewall, json!({"vmId": "vm_1"}), Some(30))
}

async fn call(a: &Agent, method: &str, path: &str, token: Option<String>, body: Option<&Value>) -> (u16, Value) {
    let c = reqwest::Client::new();
    let mut r = c.request(method.parse().expect("method"), format!("{}{path}", a.url));
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    if let Some(b) = body {
        r = r.header("content-type", "application/json").body(b.to_string());
    }
    let res = r.send().await.expect("send");
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn status_shows_the_install_to_the_firewalls_key_only() {
    let a = start(true, 1).await;
    assert_eq!(call(&a, "GET", "/status", None, None).await.0, 401);
    // The SaaS console's key opens nothing here.
    assert_eq!(
        call(&a, "GET", "/status", Some(a.keys.console_token(json!({}))), None)
            .await
            .0,
        401
    );
    let (status, body) = call(&a, "GET", "/status", Some(local_token(&a)), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["mode"], "unmanaged");
    // The unit is active and the gateway does not answer (port 1): starting.
    assert_eq!(body["state"], "starting");
    assert_eq!(
        body["install"]["runs"],
        json!({"kind": "systemd-user", "unit": "openclaw-gateway.service"})
    );
    assert_eq!(body["install"]["version"], "2026.10.9");
    assert_eq!(body["firewall"], json!({"url": "https://fw.example", "paired": true}));
}

#[tokio::test]
async fn unpaired_every_route_is_closed() {
    let a = start(false, 1).await;
    for path in ["/status", "/health"] {
        assert_eq!(
            call(&a, "GET", path, Some(local_token(&a)), None).await.0,
            401,
            "{path}"
        );
    }
    let body = json!({"type": "telegram", "secrets": {"botToken": "1:x"}});
    let t = a
        .keys
        .firewall_token("channels", "POST", "/channels/apply", Some(body.to_string().as_bytes()));
    assert_eq!(call(&a, "POST", "/channels/apply", Some(t), Some(&body)).await.0, 401);
}

#[tokio::test]
async fn the_saas_routes_are_not_there() {
    let a = start(true, 1).await;
    for path in [
        "/backup/plan",
        "/storage",
        "/skills",
        "/update",
        "/health/summary",
        "/meetings/status",
    ] {
        let (status, _) = call(&a, "GET", path, Some(local_token(&a)), None).await;
        assert!(status == 401 || status == 404, "{path}: {status}");
    }
    assert!(
        a.app.contracts.openclaw.get().is_none(),
        "no websocket bridge, so no audit or approvals"
    );
}

#[tokio::test]
async fn health_and_a_restart_the_way_it_runs() {
    let port = healthy_gateway().await;
    let a = start(true, port).await;
    let (status, body) = call(&a, "GET", "/health", Some(local_token(&a)), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["services"], json!({"openclaw": "running"}));
    let (status, body) = call(&a, "POST", "/restart", Some(local_token(&a)), None).await;
    // Answered once the restart settled; by then the look after it ran, which finds no CLI on this
    // machine (`/x/openclaw` is not there), so the state it reports is not asserted.
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    let restart = a
        .runner
        .calls()
        .into_iter()
        .find(|c| c.args.get(1).map(String::as_str) == Some("restart"))
        .expect("restart ran");
    assert_eq!(restart.program, "/x/openclaw");
    assert_eq!(restart.args, ["gateway", "restart"]);
}

#[tokio::test]
async fn a_telegram_channel_is_written_through_the_cli() {
    let port = healthy_gateway().await;
    let a = start(true, port).await;
    let cli = a.wrapper.as_str();
    a.runner.answer(
        &[cli, "gateway", "call", "config.get"],
        ok(r#"{"hash":"h1","configRevisionHash":"r1","appliedConfigHash":"r1","parsed":{},"config":{}}"#),
    );
    a.runner.answer(&[cli, "gateway", "call"], ok("{}"));
    a.runner.answer(
        &[cli, "config", "patch", "--stdin"],
        ok("Applied 1 config update(s).\n"),
    );
    // Let the probe see the gateway first.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let body = json!({"type": "telegram", "secrets": {"botToken": "123:abc"}});
    let t = a
        .keys
        .firewall_token("channels", "POST", "/channels/apply", Some(body.to_string().as_bytes()));
    let (status, reply) = call(&a, "POST", "/channels/apply", Some(t), Some(&body)).await;
    assert_eq!(status, 200, "{reply}");
    let patch = a
        .runner
        .calls()
        .into_iter()
        .find(|c| c.args.starts_with(&["config".to_string(), "patch".to_string()]))
        .expect("patched through the CLI");
    let sent: Value = serde_json::from_slice(patch.stdin.as_deref().unwrap_or_default()).expect("json");
    assert_eq!(
        sent,
        json!({"channels": {"telegram": {"enabled": true, "botToken": "123:abc", "dmPolicy": "pairing"}}})
    );
}

#[tokio::test]
async fn a_token_for_another_host_is_refused_once_tokens_are_bound() {
    let a = start(true, 1).await;
    // A bound token for this agent's name: taken (the read is refused only for want of a gateway).
    let t = a.keys.firewall_token("llm", "GET", "/llm/status", None);
    assert_ne!(call(&a, "GET", "/llm/status", Some(t), None).await.0, 401);
    let other = BoxKeys {
        dir: a.keys.dir.clone(),
        vm_id: a.keys.vm_id.clone(),
        hostname: "other.example".into(),
        vm: a.keys.vm.clone(),
        saas: a.keys.saas.clone(),
        firewall: a.keys.firewall.clone(),
    };
    let t = other.firewall_token("llm", "GET", "/llm/status", None);
    assert_eq!(call(&a, "GET", "/llm/status", Some(t), None).await.0, 401);
}

/// The emergency stop: only the firewall's `kill` token, and OpenClaw stopped the way it runs.
#[tokio::test]
async fn the_emergency_stop_stops_openclaw_the_way_it_runs() {
    // The gateway does not answer (port 1): once stopped, nothing says it runs.
    let a = start(true, 1).await;
    let body = json!({"locked": true});
    assert_eq!(
        call(&a, "POST", "/kill/apply", Some(local_token(&a)), Some(&body))
            .await
            .0,
        401
    );
    let t = a
        .keys
        .firewall_token("kill", "POST", "/kill/apply", Some(body.to_string().as_bytes()));
    let (status, reply) = call(&a, "POST", "/kill/apply", Some(t), Some(&body)).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        (reply["locked"].clone(), reply["active"].clone()),
        (json!(true), json!(false))
    );
    let stop = a
        .runner
        .calls()
        .into_iter()
        .find(|c| c.args.iter().any(|x| x == "stop"))
        .expect("a stop ran");
    assert_eq!(
        (stop.program.as_str(), stop.args.join(" ")),
        ("systemctl", "--user stop -- openclaw-gateway.service".to_string()),
        "the unit, not `openclaw gateway stop` (it refuses with no terminal)"
    );
    let t = a.keys.firewall_token("kill", "GET", "/kill/status", None);
    let (status, reply) = call(&a, "GET", "/kill/status", Some(t), None).await;
    assert_eq!((status, reply["active"].clone()), (200, json!(false)));
    // Released: started again, and starting counts as up (the gateway does not answer yet).
    let body = json!({"locked": false});
    let t = a
        .keys
        .firewall_token("kill", "POST", "/kill/apply", Some(body.to_string().as_bytes()));
    let (status, reply) = call(&a, "POST", "/kill/apply", Some(t), Some(&body)).await;
    assert_eq!((status, reply["active"].clone()), (200, json!(true)), "{reply}");
}

/// `firewall.allow_from`: a connection from any other address is closed before it is read.
#[tokio::test]
async fn only_the_firewalls_address_may_connect() {
    let router = Arc::new(cc_http::Router::new(&["all"]));
    for (allow, served) in [("127.0.0.1", true), ("10.9.9.9", false)] {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/status", l.local_addr().expect("addr"));
        tokio::spawn(cc_http::serve_from(l, router.clone(), vec![allow.parse().expect("ip")]));
        let r = reqwest::Client::new().get(&url).send().await;
        assert_eq!(r.is_ok(), served, "allow {allow}: {r:?}");
    }
}

/// A gateway that answers `config.get` and takes a patch through the CLI, as the Telegram test sets
/// it up.
async fn writable(a: &Agent) {
    let cli = a.wrapper.as_str();
    a.runner.answer(
        &[cli, "gateway", "call", "config.get"],
        ok(r#"{"hash":"h1","configRevisionHash":"r1","appliedConfigHash":"r1","parsed":{},"config":{}}"#),
    );
    a.runner.answer(&[cli, "gateway", "call"], ok("{}"));
    a.runner.answer(
        &[cli, "config", "patch", "--stdin"],
        ok("Applied 1 config update(s).\n"),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn patch_sent(a: &Agent) -> Value {
    let patch = a
        .runner
        .calls()
        .into_iter()
        .rfind(|c| c.args.starts_with(&["config".to_string(), "patch".to_string()]))
        .expect("patched through the CLI");
    serde_json::from_slice(patch.stdin.as_deref().unwrap_or_default()).expect("json")
}

/// An MCP server the firewall names at its own address is written at the gate this agent reaches
/// it by (`firewall.gate`: the tunnel's here), the same port and path.
#[tokio::test]
async fn an_mcp_server_is_written_at_the_agents_gate() {
    let port = healthy_gateway().await;
    let a = start(true, port).await;
    writable(&a).await;
    let body = json!({"servers": [{"name": "docs", "url": "http://172.31.249.2:3940/servers/docs/mcp"}]});
    let t = a.keys.firewall_token(
        "mcp-servers",
        "POST",
        "/mcp-servers/apply",
        Some(body.to_string().as_bytes()),
    );
    let (status, reply) = call(&a, "POST", "/mcp-servers/apply", Some(t), Some(&body)).await;
    assert_eq!(status, 200, "{reply}");
    assert_eq!(
        patch_sent(&a),
        json!({"mcp": {"servers": {"docs": {"url": "http://10.77.0.1:3940/servers/docs/mcp", "transport": "streamable-http"}}}})
    );
    // Another port of the firewall: refused, whatever the path.
    let bad = json!({"servers": [{"name": "docs", "url": "http://172.31.249.2:8800/servers/docs/mcp"}]});
    let t = a.keys.firewall_token(
        "mcp-servers",
        "POST",
        "/mcp-servers/apply",
        Some(bad.to_string().as_bytes()),
    );
    assert_eq!(call(&a, "POST", "/mcp-servers/apply", Some(t), Some(&bad)).await.0, 400);
    // Not the gate's path: refused, as on a managed box.
    let bad = json!({"servers": [{"name": "docs", "url": "http://172.31.249.2:3940/other"}]});
    let t = a.keys.firewall_token(
        "mcp-servers",
        "POST",
        "/mcp-servers/apply",
        Some(bad.to_string().as_bytes()),
    );
    assert_eq!(call(&a, "POST", "/mcp-servers/apply", Some(t), Some(&bad)).await.0, 400);
}

/// The secrets' placeholders go into OpenClaw's own `.env`, in its state folder, then OpenClaw
/// restarts the way it runs.
#[tokio::test]
async fn secrets_go_to_openclaws_own_env_file() {
    let port = healthy_gateway().await;
    let a = start(true, port).await;
    let env = a._dir.path().join(".openclaw/.env");
    std::fs::create_dir_all(env.parent().expect("dir")).expect("dir");
    std::fs::write(&env, "OTHER=keep\n").expect("env");
    let body = json!({"entries": [{"name": "STRIPE_KEY", "placeholder": "CC-SEC-0123456789abcdef0123456789abcdef0123456789abcdef"}]});
    let t = a
        .keys
        .firewall_token("secrets", "POST", "/secrets/apply", Some(body.to_string().as_bytes()));
    let (status, reply) = call(&a, "POST", "/secrets/apply", Some(t), Some(&body)).await;
    assert_eq!(status, 200, "{reply}");
    let text = std::fs::read_to_string(&env).expect("env");
    assert!(
        text.starts_with("OTHER=keep\n")
            && text.contains("STRIPE_KEY=CC-SEC-0123456789abcdef0123456789abcdef0123456789abcdef"),
        "{text}"
    );
    assert!(
        a.runner.calls().iter().any(|c| c.args.join(" ") == "gateway restart"),
        "restarted the way it runs"
    );
}

/// Search answers here now (its status reads the gateway); app connections too, outside a container.
#[tokio::test]
async fn search_and_app_connections_answer_on_an_unmanaged_agent() {
    let port = healthy_gateway().await;
    let a = start(true, port).await;
    writable(&a).await;
    for (purpose, path) in [("search", "/search/status"), ("connectors", "/connectors/status")] {
        let t = a.keys.firewall_token(purpose, "GET", path, None);
        let (status, reply) = call(&a, "GET", path, Some(t), None).await;
        assert_ne!(status, 404, "{path}: {reply}");
        assert_ne!(status, 401, "{path}: {reply}");
    }
}

/// A real container whose OpenClaw folder holds links that would climb out on this machine: an
/// inner link to `/`, and the folder itself swapped for a link to `/`. The copies (`docker cp -L`)
/// and the `.env` write (`docker exec`) resolve them in the container: nothing on this machine is
/// read or written. Skipped where Docker or the image is not at hand.
#[test]
fn links_in_a_containers_folder_resolve_in_the_container() {
    let docker = |args: &[&str]| std::process::Command::new("docker").args(args).output();
    let image = "alpine:3.20";
    if !docker(&["image", "inspect", image]).is_ok_and(|o| o.status.success())
        && !docker(&["pull", "-q", image]).is_ok_and(|o| o.status.success())
    {
        eprintln!("skipped: no docker or no {image}");
        return;
    }
    let name = format!("cc-links-{}", std::process::id());
    let run = docker(&["run", "-d", "--rm", "--name", &name, image, "sleep", "60"]).expect("docker");
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let sh = |script: &str| {
        let o = docker(&["exec", &name, "sh", "-c", script]).expect("exec");
        assert!(o.status.success(), "{script}: {}", String::from_utf8_lossy(&o.stderr));
    };
    // The container's own files, which a host path would not be.
    sh(
        "echo container-passwd > /etc/marker && mkdir -p /home/node/.openclaw/credentials && ln -s / /home/node/.openclaw/x \
        && ln -s /etc/marker /home/node/.openclaw/credentials/telegram-pairing.json",
    );
    let dir = tempfile::tempdir().expect("dir");
    let copy = copy_out(name.clone(), dir.path().join("from-container"));
    // An inner link to `/`, and a last link: the container's /etc/marker, not this machine's.
    for p in [
        "/home/node/.openclaw/x/etc/marker",
        "/home/node/.openclaw/credentials/telegram-pairing.json",
    ] {
        let got = copy(std::path::Path::new(p)).expect("copied");
        assert_eq!(
            std::fs::read_to_string(&got.path).expect("read"),
            "container-passwd\n",
            "{p}"
        );
        assert!(std::fs::symlink_metadata(&got.path).expect("m").file_type().is_file());
    }
    // A folder, or a file over its cap: not copied. A copy is 0600, in a 0700 folder.
    sh("head -c 1100000 /dev/zero > /home/node/.openclaw/credentials/slack-pairing.json");
    assert!(
        copy(std::path::Path::new("/home/node/.openclaw/credentials")).is_none(),
        "a folder"
    );
    assert!(
        copy(std::path::Path::new(
            "/home/node/.openclaw/credentials/slack-pairing.json"
        ))
        .is_none(),
        "over 1 MB"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        let got = copy(std::path::Path::new(
            "/home/node/.openclaw/credentials/telegram-pairing.json",
        ))
        .expect("copied");
        assert_eq!(
            std::fs::metadata(&got.path).expect("m").permissions().mode() & 0o7777,
            0o600
        );
        let folder = got.path.parent().expect("folder");
        assert_eq!(
            std::fs::metadata(folder).expect("m").permissions().mode() & 0o7777,
            0o700
        );
    }
    // The folder swapped for a link to `/`, then a `.env` written through it: in the container.
    sh("rm -rf /home/node/.openclaw && ln -s / /home/node/.openclaw");
    let w = std::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            &name,
            "sh",
            "-c",
            crate::platform::secrets::CONTAINER_WRITE,
            "sh",
            "/home/node/.openclaw/.env",
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().expect("stdin").write_all(b"A=1\n")?;
            c.wait()
        })
        .expect("write");
    assert!(w.success());
    let o = docker(&["exec", &name, "cat", "/.env"]).expect("cat");
    assert_eq!(String::from_utf8_lossy(&o.stdout), "A=1\n", "the container's /.env");
    assert!(
        !std::path::Path::new("/.env").exists()
            || std::fs::read_to_string("/.env").map(|t| t != "A=1\n").unwrap_or(true)
    );
    let _ = docker(&["rm", "-f", &name]);
}

/// Every command in unmanaged mode is capped on the host: an OpenClaw (a container's) prints what
/// it likes, and the agent may be root.
#[tokio::test]
async fn every_command_here_has_an_output_cap() {
    let inner = RecordingRunner::new();
    inner.answer(&["docker"], ok(""));
    let r = super::CappedRunner(inner.clone());
    use cc_proc::Runner;
    r.run(cc_proc::Cmd::new("docker").args(["exec", "c", "sh"]))
        .await
        .expect("ran");
    r.run(cc_proc::Cmd::new("docker").max_output(10)).await.expect("ran");
    r.run(cc_proc::Cmd::new("docker").max_output(usize::MAX))
        .await
        .expect("ran");
    let caps: Vec<Option<usize>> = inner.calls().iter().map(|c| c.max_output).collect();
    assert_eq!(caps, [Some(super::MAX_OUTPUT), Some(10), Some(super::MAX_OUTPUT)]);
}
