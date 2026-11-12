//! `controlplane-mcp-gate.test.ts` and the gate part of `mcp-servers.test.ts`: the 3940 listener
//! with a real socket, a fake control plane, and the server gate in front of a fake MCP server.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde_json::{Value, json};

use super::*;
use crate::integrations::mcp::calls::tests::{rule, tools};
use crate::integrations::mcp::server_gate::{ServerGateOptions, rpc_summary, server_name_of};
use crate::integrations::mcp::servers::tests as srv;
use crate::integrations::testing::{self, Answer, FakeServer, Identities, Stop};

struct Echo;

impl LocalTools for Echo {
    fn path(&self) -> &str {
        "/logins/mcp"
    }
    fn answer(&self, vm_id: String, body: Bytes) -> BoxFuture<Result<(u16, Option<Value>), String>> {
        Box::pin(async move {
            Ok((
                200,
                Some(json!({"vmId": vm_id, "echoed": String::from_utf8_lossy(&body)})),
            ))
        })
    }
}

struct G {
    _dir: tempfile::TempDir,
    base: String,
    cp: FakeServer,
    ids: Arc<Identities>,
    stop: Arc<Stop>,
    traffic: std::path::PathBuf,
}

async fn listen(gate: &Arc<ToolsGate>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(cc_http::serve(l, Arc::new(gate.router())));
    format!("http://127.0.0.1:{port}")
}

async fn gate(servers: Option<Arc<ServerGate>>, app: Option<Arc<App>>) -> G {
    let dir = tempfile::tempdir().expect("dir");
    let ids = Identities::of(&[("agent-1", "127.0.0.1", "One"), ("agent-2", "10.0.0.9", "Two")]);
    // An app of its own gets this identity map; a given one (the servers' tests) has its own.
    let app = match app {
        Some(a) => a,
        None => {
            let a = testing::app(dir.path());
            a.contracts.identities.set(ids.clone());
            a
        }
    };
    let stop = Arc::new(Stop(AtomicBool::new(false)));
    let cp =
        FakeServer::start(|_| Answer::json(200, &json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}))).await;
    let traffic = dir.path().join("traffic.jsonl");
    let s = stop.clone();
    let g = ToolsGate::new(
        &app,
        format!("{}/api/mcp/agent", cp.url()),
        Some(traffic.clone()),
        Arc::new(move |_| s.0.load(Ordering::SeqCst)),
        Some(Arc::new(Echo)),
        servers,
    );
    G {
        base: listen(&g).await,
        _dir: dir,
        cp,
        ids,
        stop,
        traffic,
    }
}

async fn post(base: &str, path: &str, body: &str, extra: &[(&str, &str)]) -> reqwest::Response {
    let mut r = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer stolen")
        .header("cookie", "a=b");
    for (k, v) in extra {
        r = r.header(*k, *v);
    }
    r.body(body.to_string()).send().await.expect("send")
}

fn claims(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .expect("b64"),
    )
    .expect("json")
}

#[tokio::test]
async fn signs_for_the_agent_at_the_callers_address_with_the_bodys_hash_and_drops_the_callers_own_credentials() {
    let g = gate(None, None).await;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
    let r = post(&g.base, "/mcp", &body, &[("mcp-protocol-version", "2025-06-18")]).await;
    assert_eq!(r.status(), 200);
    let seen = g.cp.got();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/api/mcp/agent");
    assert_eq!(seen[0].body, body.as_bytes());
    assert!(seen[0].headers.get("cookie").is_none());
    assert_eq!(seen[0].headers["mcp-protocol-version"], "2025-06-18");
    let token = seen[0].headers["authorization"]
        .to_str()
        .expect("s")
        .trim_start_matches("Bearer ")
        .to_string();
    let c = claims(&token);
    assert_eq!(c["vmId"], "fw_1");
    assert_eq!(c["purpose"], "agent-mcp");
    assert_eq!(c["agentVmId"], "agent-1");
    assert_eq!(c["bodySha256"], hex::encode(Sha256::digest(body.as_bytes())));
    assert!(c["exp"].as_i64().expect("exp") - c["iat"].as_i64().expect("iat") <= 30);
    let line: Value = serde_json::from_str(
        std::fs::read_to_string(&g.traffic)
            .expect("log")
            .lines()
            .last()
            .expect("line"),
    )
    .expect("json");
    assert_eq!(
        (line["host"].clone(), line["effect"].clone(), line["rule"].clone()),
        (json!("controlplane-mcp"), json!("allow"), json!("controlclaw tools"))
    );
}

#[tokio::test]
async fn the_logins_path_is_answered_here_and_callers_that_are_not_agents_are_refused() {
    let g = gate(None, None).await;
    let r = post(&g.base, "/logins/mcp", r#"{"x":1}"#, &[]).await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.json::<Value>().await.expect("json"),
        json!({"vmId": "agent-1", "echoed": "{\"x\":1}"})
    );
    assert!(g.cp.got().is_empty());
    g.ids.0.lock().expect("lock")[0].private_ip = "10.0.0.3".into();
    assert_eq!(post(&g.base, "/logins/mcp", "{}", &[]).await.status(), 403);
    assert_eq!(post(&g.base, "/mcp", "{}", &[]).await.status(), 403);
    assert!(g.cp.got().is_empty());
    g.ids.0.lock().expect("lock")[0].private_ip = "127.0.0.1".into();
    assert_eq!(post(&g.base, "/other", "{}", &[]).await.status(), 404);
}

#[tokio::test]
async fn an_emergency_stop_refuses_and_only_post_mcp_within_the_caps() {
    let g = gate(None, None).await;
    g.stop.0.store(true, Ordering::SeqCst);
    assert_eq!(post(&g.base, "/mcp", "{}", &[]).await.status(), 403);
    g.stop.0.store(false, Ordering::SeqCst);
    let line: Value = serde_json::from_str(
        std::fs::read_to_string(&g.traffic)
            .expect("log")
            .lines()
            .last()
            .expect("line"),
    )
    .expect("json");
    assert_eq!(
        (line["vm_id"].clone(), line["effect"].clone()),
        (json!("agent-1"), json!("drop"))
    );
    assert_eq!(
        reqwest::get(format!("{}/mcp", g.base)).await.expect("get").status(),
        405
    );
    assert_eq!(
        post(&g.base, "/mcp", &"x".repeat(GATE_MAX_BODY + 1), &[])
            .await
            .status(),
        413
    );
    // A chunked body over the cap still gets a 413.
    let chunks =
        futures_util::stream::iter((0..6).map(|_| Ok::<_, std::io::Error>(Bytes::from("x".repeat(64 * 1024)))));
    let chunked = reqwest::Client::new()
        .post(format!("{}/mcp", g.base))
        .body(reqwest::Body::wrap_stream(chunks))
        .send()
        .await
        .expect("send");
    assert_eq!(chunked.status(), 413);
    let mut last = 200;
    for _ in 0..=GATE_CALLS_PER_MINUTE {
        last = post(&g.base, "/mcp", "{}", &[]).await.status().as_u16();
    }
    assert_eq!(last, 429);
}

#[test]
fn the_control_plane_url_comes_from_the_firewalls_own() {
    assert_eq!(
        control_plane_mcp_url("https://controlclaw.com/api/vm-agent/firewall", None).as_deref(),
        Some("https://controlclaw.com/api/mcp/agent")
    );
    assert_eq!(control_plane_mcp_url("not a url", None), None);
    assert_eq!(
        control_plane_mcp_url("x", Some("https://override/api/mcp/agent")).as_deref(),
        Some("https://override/api/mcp/agent")
    );
    assert_eq!(server_name_of("/servers/linear/mcp"), Some("linear"));
    assert_eq!(server_name_of("/servers/../mcp"), None);
    assert_eq!(server_name_of("/servers/linear/mcp/x"), None);
    let s = rpc_summary(br#"[{"jsonrpc":"2.0","method":"notifications/x"},{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t"}}]"#);
    assert_eq!(
        (
            s.method.as_deref(),
            s.tool.as_deref(),
            s.tools.clone(),
            s.id.clone(),
            s.count
        ),
        (Some("tools/call"), Some("t"), vec!["t".to_string()], Some(json!(3)), 2)
    );
    assert_eq!(rpc_summary(b"not json").count, 0);
}

/// The server gate in front of the fake MCP server, with the firewall signed in to `notes`.
async fn servers_gate(
    log: &std::path::Path,
) -> (
    srv::T,
    Arc<crate::integrations::mcp::servers::McpServersFirewall>,
    G,
    Arc<AtomicBool>,
) {
    let t = srv::T::new().await;
    let fw = t.make();
    let d = t.sign_in(&fw, "notes", json!([{"vmId": "agent-1"}])).await;
    let done = srv::run(&fw, "callback", json!({"state": d["state"], "code": "the-code"})).await;
    assert_eq!(done.status, "applied", "{:?}", done.message);
    let h = crate::integrations::mcp::calls::tests::harness_logging(vec![], false, Some(log.to_path_buf()));
    let stopped = Arc::new(AtomicBool::new(false));
    let s = stopped.clone();
    let mut opts = ServerGateOptions::new(
        Some(fw.clone()),
        Some(h.calls.clone()),
        Arc::new(move |_| s.load(Ordering::SeqCst)),
    );
    opts.log_path = Some(log.to_path_buf());
    opts.recheck = std::time::Duration::from_millis(50);
    opts.stream = std::time::Duration::from_millis(600);
    let sg = ServerGate::new(opts);
    let g = gate(Some(sg), Some(t.app.clone())).await;
    std::mem::forget(h);
    (t, fw, g, stopped)
}

#[tokio::test]
async fn the_server_gate_adds_the_credential_drops_the_callers_streams_sse_and_keeps_one_metadata_line() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("mcp-calls.jsonl");
    // The identity map names agent-1 at the caller's address; the servers firewall knows it too.
    let (t, fw, g, _) = servers_gate(&log).await;
    t.server.clear();
    let call = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "read_doc", "arguments": {"id": "private-arg"}}}).to_string();
    let r = post(
        &g.base,
        "/servers/notes/mcp",
        &call,
        &[
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", "sess-1"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    assert_eq!(r.headers()["mcp-session-id"], "sess-1");
    assert!(r.text().await.expect("text").contains("secret result"));
    let up = t
        .server
        .got()
        .into_iter()
        .find(|s| s.path == "/mcp" && String::from_utf8_lossy(&s.body).contains("tools/call"))
        .expect("upstream");
    let token = t.mcp.valid_token.lock().expect("lock").clone();
    assert_eq!(up.headers["authorization"], format!("Bearer {token}").as_str());
    assert!(up.headers.get("cookie").is_none());
    assert_eq!(up.headers["mcp-session-id"], "sess-1");
    // The server's GET stream passes too.
    let stream = reqwest::Client::new()
        .get(format!("{}/servers/notes/mcp", g.base))
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("get");
    assert_eq!(stream.status(), 200);
    assert!(stream.text().await.expect("text").contains("list_changed"));
    // A 401: the firewall renews its token once and sends again; the agent sees no 401.
    t.mcp.fail_next_401.store(true, Ordering::SeqCst);
    let retried = post(
        &g.base,
        "/servers/notes/mcp",
        &call,
        &[("accept", "application/json, text/event-stream")],
    )
    .await;
    assert_eq!(retried.status(), 200);
    assert_ne!(*t.mcp.valid_token.lock().expect("lock"), token);
    // A tool list larger than the firewall reads is refused whole, never sent cut.
    t.mcp.big_list.store(true, Ordering::SeqCst);
    let big = post(
        &g.base,
        "/servers/notes/mcp",
        &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).to_string(),
        &[],
    )
    .await;
    t.mcp.big_list.store(false, Ordering::SeqCst);
    let b: Value = big.json().await.expect("json");
    assert_eq!(b["id"], 3);
    assert!(
        b["error"]["message"]
            .as_str()
            .expect("m")
            .contains("listed more tools than the firewall reads at once")
    );
    // Not given and unknown: refused in words the agent reads.
    srv::run(
        &fw,
        "propose",
        json!({"changeId": "g2", "kind": "unassign", "name": "notes", "agents": [{"vmId": "agent-1"}]}),
    )
    .await;
    let not_given = post(&g.base, "/servers/notes/mcp", &call, &[]).await;
    assert_eq!(not_given.status(), 403);
    assert!(
        not_given.json::<Value>().await.expect("json")["error"]["message"]
            .as_str()
            .expect("m")
            .contains("was not given the MCP server notes")
    );
    assert_eq!(post(&g.base, "/servers/nope/mcp", &call, &[]).await.status(), 404);
    for name in ["constructor", "__proto__", "toString", "hasOwnProperty"] {
        assert_eq!(
            post(&g.base, &format!("/servers/{name}/mcp"), "{}", &[]).await.status(),
            404,
            "{name}"
        );
    }
    let text = std::fs::read_to_string(&log).expect("log");
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).expect("line")).collect();
    let allowed = lines
        .iter()
        .find(|l| l["decision"] == "allowed" && l["action_id"] == "read_doc")
        .expect("allowed");
    assert_eq!(
        [
            &allowed["route"],
            &allowed["service"],
            &allowed["method"],
            &allowed["path"],
            &allowed["vm_id"]
        ],
        [
            &json!("mcp_server"),
            &json!("mcp:notes"),
            &json!("POST"),
            &json!("tools/call"),
            &json!("agent-1")
        ]
    );
    assert!(
        lines
            .iter()
            .any(|l| l["decision"] == "blocked" && l["error_code"] == "not_given")
    );
    assert!(
        !lines
            .iter()
            .any(|l| l["decision"] == "allowed" && l["action_id"].is_null()),
        "the session's own traffic is not a row"
    );
    assert!(
        !text.contains("private-arg") && !text.contains("secret result"),
        "no argument or result in the log"
    );
}

#[tokio::test]
async fn open_streams_end_when_the_agent_loses_the_server_or_is_stopped_and_live_at_most_a_while() {
    let dir = tempfile::tempdir().expect("dir");
    let (_t, fw, g, stopped) = servers_gate(&dir.path().join("log.jsonl")).await;
    let base = g.base.clone();
    let open = move || {
        let base = base.clone();
        async move {
            let t0 = std::time::Instant::now();
            let r = reqwest::Client::new()
                .get(format!("{base}/servers/notes/mcp"))
                .header("accept", "text/event-stream")
                .header("last-event-id", "hold")
                .send()
                .await;
            if let Ok(r) = r {
                let _ = r.text().await;
            }
            t0.elapsed()
        }
    };
    let ended = tokio::spawn(open());
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    srv::run(
        &fw,
        "propose",
        json!({"changeId": "st2", "kind": "unassign", "name": "notes", "agents": [{"vmId": "agent-1"}]}),
    )
    .await;
    assert!(ended.await.expect("joined") < std::time::Duration::from_millis(500));
    srv::run(
        &fw,
        "propose",
        json!({"changeId": "st3", "kind": "assign", "name": "notes", "agents": [{"vmId": "agent-1"}]}),
    )
    .await;
    let ended = tokio::spawn(open());
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    stopped.store(true, Ordering::SeqCst);
    assert!(ended.await.expect("joined") < std::time::Duration::from_millis(500));
    stopped.store(false, Ordering::SeqCst);
    // Its lifetime: closed after the stream time with nothing changed.
    let lived = open().await;
    assert!(
        lived >= std::time::Duration::from_millis(500) && lived < std::time::Duration::from_secs(2),
        "lived {lived:?}"
    );
}

#[tokio::test]
async fn give_needs_an_apply_grant_and_a_name_checked_first() {
    let asked: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let a = asked.clone();
    let mut opts = ServerGateOptions::new(None, None, Arc::new(|_| false));
    opts.give = Some(Arc::new(move |vm, name| {
        a.lock().expect("lock").push((vm, name.clone()));
        Box::pin(async move {
            if name == "linear" {
                (true, "given".to_string())
            } else {
                (false, "needs a code".to_string())
            }
        })
    }));
    let g = gate(Some(ServerGate::new(opts)), None).await;
    assert_eq!(
        post(&g.base, "/servers/give", r#"{"name":"linear"}"#, &[])
            .await
            .status(),
        200
    );
    let refused = post(&g.base, "/servers/give", r#"{"name":"github"}"#, &[]).await;
    assert_eq!(refused.status(), 409);
    assert_eq!(refused.json::<Value>().await.expect("json")["message"], "needs a code");
    assert_eq!(
        post(&g.base, "/servers/give", r#"{"name":"../etc"}"#, &[])
            .await
            .status(),
        400
    );
    assert_eq!(
        *asked.lock().expect("lock"),
        [
            ("agent-1".to_string(), "linear".to_string()),
            ("agent-1".to_string(), "github".to_string())
        ]
    );
    let _ = rule(|_| {});
    let _ = tools(&[]);
}

#[tokio::test]
async fn a_held_call_is_sent_on_send_with_the_agents_session_headers() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("log.jsonl");
    let t = srv::T::new().await;
    let fw = t.make();
    let d = t.sign_in(&fw, "notes", json!([{"vmId": "agent-1"}])).await;
    let done = srv::run(&fw, "callback", json!({"state": d["state"], "code": "the-code"})).await;
    assert_eq!(done.status, "applied", "{:?}", done.message);
    let h = crate::integrations::mcp::calls::tests::harness_logging(vec![], true, Some(log.clone()));
    let content = h.content.clone().expect("content rules");
    *content.out.lock().expect("lock") = Some(crate::integrations::testing::rule("c1", "hold", "needs a look"));
    let opts = ServerGateOptions::new(Some(fw.clone()), Some(h.calls.clone()), Arc::new(|_| false));
    let g = gate(Some(ServerGate::new(opts)), Some(t.app.clone())).await;
    t.server.clear();
    let call = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "read_doc", "arguments": {"id": "x"}}}).to_string();
    let held = post(
        &g.base,
        "/servers/notes/mcp",
        &call,
        &[
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", "sess-9"),
            ("mcp-protocol-version", "2025-06-18"),
        ],
    )
    .await;
    assert_eq!(held.status(), 200);
    let sent_now = |s: &[crate::integrations::testing::Got]| {
        s.iter()
            .filter(|g| String::from_utf8_lossy(&g.body).contains("tools/call"))
            .count()
    };
    assert_eq!(sent_now(&t.server.got()), 0, "held, not sent");
    let send = content.send.lock().expect("lock").take().expect("a hold to send");
    send().await.expect("sent");
    let up = t
        .server
        .got()
        .into_iter()
        .find(|s| String::from_utf8_lossy(&s.body).contains("tools/call"))
        .expect("upstream");
    let token = t.mcp.valid_token.lock().expect("lock").clone();
    assert_eq!(up.headers["authorization"], format!("Bearer {token}").as_str());
    assert_eq!(up.headers["mcp-session-id"], "sess-9");
    assert_eq!(up.headers["mcp-protocol-version"], "2025-06-18");
    assert_eq!(up.headers["content-type"], "application/json");
    assert_eq!(up.headers["accept"], "application/json, text/event-stream");
    drop(h);
}

/// `GET /ca` (main #564): the CA and its signature for an agent of the organization, also under
/// the stop; the box is recorded for inspection only when it confirms THIS CA's sha256.
#[tokio::test]
async fn the_ca_is_given_to_agents_and_a_box_that_installed_it_is_recorded() {
    use sha2::Digest;
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    app.contracts
        .identities
        .set(Identities::of(&[("agent-1", "127.0.0.1", "One")]));
    let cert_path = dir.path().join("ca-cert.pem");
    std::fs::write(
        &cert_path,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .expect("cert");
    let cert = std::fs::read_to_string(&cert_path).expect("read");
    let stopped = Arc::new(AtomicBool::new(true));
    let s = stopped.clone();
    let g = ToolsGate::new(
        &app,
        "http://127.0.0.1:9/api/mcp/agent".into(),
        None,
        Arc::new(move |_| s.load(Ordering::SeqCst)),
        None,
        None,
    );
    let _ = g.ca.set(crate::integrations::mcp::ca_answer(
        &app,
        cert_path.display().to_string(),
    ));
    let base = listen(&g).await;
    let get = |q: &str| reqwest::get(format!("{base}/ca{q}"));
    // Asked without saying it installed it: given, nothing recorded.
    let r = get("").await.expect("get");
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.expect("json");
    assert_eq!(body["caCert"], json!(cert));
    assert!(body["caSig"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(!app.cp_inspect.has("agent-1"));
    // Another CA's hash: not recorded.
    let other = hex::encode(sha2::Sha256::digest(b"another CA"));
    let _ = get(&format!("?installed={other}")).await.expect("get");
    assert!(!app.cp_inspect.has("agent-1"));
    // This one's: recorded (under the stop, too).
    let mine = hex::encode(sha2::Sha256::digest(cert.as_bytes()));
    assert_eq!(get(&format!("?installed={mine}")).await.expect("get").status(), 200);
    assert!(app.cp_inspect.has("agent-1"));
    // Only GET.
    let r = reqwest::Client::new()
        .post(format!("{base}/ca"))
        .send()
        .await
        .expect("post");
    assert_eq!(r.status(), 405);
}

/// OpenClaw's approvals as the core answers them: recorded, with the agent the gate named.
struct Perms {
    on: AtomicBool,
    seen: Mutex<Vec<(String, String, Value)>>,
}

impl crate::contracts::AgentPermissions for Perms {
    fn active(&self) -> bool {
        self.on.load(Ordering::SeqCst)
    }
    fn raise(&self, vm_id: &str, body: Value) -> BoxFuture<(u16, Value)> {
        self.seen.lock().expect("l").push(("raise".into(), vm_id.into(), body));
        Box::pin(async { (200, json!({"ok": true, "status": "approved"})) })
    }
    fn status(&self, vm_id: &str, permission_id: &str) -> BoxFuture<(u16, Value)> {
        self.seen
            .lock()
            .expect("l")
            .push(("status".into(), vm_id.into(), json!(permission_id)));
        Box::pin(async { (200, json!({"status": "pending"})) })
    }
    fn settle(&self, vm_id: &str, body: Value, token: &str) -> BoxFuture<(u16, Value)> {
        let mut body = body;
        body["token"] = json!(token);
        self.seen.lock().expect("l").push(("settle".into(), vm_id.into(), body));
        Box::pin(async { (200, json!({"ok": true, "status": "denied"})) })
    }
}

#[tokio::test]
async fn approvals_go_to_the_core_for_the_agent_at_the_callers_address_once_it_checks_them() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    app.contracts
        .identities
        .set(Identities::of(&[("agent-1", "127.0.0.1", "One")]));
    let g = gate(None, Some(app.clone())).await;
    let raise = json!({"permission_id": "oc:1", "kind": "exec", "title": "ls"}).to_string();
    // Starting (the core has not set it up yet): 503, marked as this gate's, so the agent waits.
    let r = post(&g.base, "/permission", &raise, &[]).await;
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers().get("x-cc-gate").map(|v| v.as_bytes()), Some(&b"1"[..]));
    let perms = Arc::new(Perms {
        on: AtomicBool::new(false),
        seen: Mutex::new(Vec::new()),
    });
    app.contracts.agent_permissions.set(perms.clone());
    // Not checking yet (an older control plane): 404 that says so; the agent asks the console.
    let r = post(&g.base, "/permission", &raise, &[]).await;
    assert_eq!(r.status(), 404);
    assert_eq!(
        r.headers().get("x-cc-auto-approve").map(|v| v.as_bytes()),
        Some(&b"off"[..])
    );
    assert!(r.headers().get("x-cc-gate").is_some());
    perms.on.store(true, Ordering::SeqCst);
    let r = post(&g.base, "/permission", &raise, &[]).await;
    assert_eq!(r.status(), 200);
    assert!(r.headers().get("x-cc-gate").is_some());
    assert_eq!(r.json::<Value>().await.expect("json")["status"], json!("approved"));
    // A settle needs the vm-agent's own token: anything else at the agent's address has none.
    let settle = json!({"permission_id": "oc:1", "resolution": "approved"}).to_string();
    assert_eq!(post(&g.base, "/permission", &settle, &[]).await.status(), 403);
    let settle = json!({"permission_id": "oc:1", "resolution": "denied"}).to_string();
    assert_eq!(
        post(&g.base, "/permission", &settle, &[("x-cc-agent-token", "tok")])
            .await
            .status(),
        200
    );
    let st = reqwest::get(format!("{}/permission?permission_id=oc%3A1", g.base))
        .await
        .expect("get");
    assert_eq!(st.json::<Value>().await.expect("json")["status"], json!("pending"));
    let seen = perms.seen.lock().expect("l").clone();
    let what: Vec<(String, String)> = seen.iter().map(|(k, v, _)| (k.clone(), v.clone())).collect();
    assert_eq!(
        what,
        vec![
            ("raise".into(), "agent-1".into()),
            ("settle".into(), "agent-1".into()),
            ("status".into(), "agent-1".into())
        ]
    );
    assert_eq!(seen[1].2["token"], json!("tok"));
    assert_eq!(seen[2].2, json!("oc:1"));
    // Bad input, a body too large, another method.
    assert_eq!(post(&g.base, "/permission", "not json", &[]).await.status(), 400);
    assert_eq!(
        post(&g.base, "/permission", &"x".repeat(20 * 1024), &[]).await.status(),
        413
    );
    assert_eq!(
        reqwest::get(format!("{}/permission", g.base))
            .await
            .expect("get")
            .status(),
        400
    );
    // Under an emergency stop the agent's approvals are refused, as its other calls are.
    g.stop.0.store(true, Ordering::SeqCst);
    assert_eq!(post(&g.base, "/permission", &raise, &[]).await.status(), 403);
    let _ = &g.ids;
}

/// A standalone agent in a container: its OpenClaw at one address, its vm-agent at another.
struct Split(Mutex<String>);

impl crate::contracts::IdentityMap for Split {
    fn agents(&self) -> Vec<crate::contracts::AgentIdentity> {
        vec![crate::contracts::AgentIdentity {
            vm_id: "agent-1".into(),
            private_ip: "10.0.0.9".into(),
            hostname: None,
            name: Some("One".into()),
        }]
    }
    fn agent(&self, vm_id: &str) -> Option<crate::contracts::AgentIdentity> {
        self.agents().into_iter().find(|a| a.vm_id == vm_id)
    }
    fn host_for(&self, _: &str) -> Option<String> {
        None
    }
    fn route_for(&self, vm_id: &str) -> Option<crate::contracts::AgentRoute> {
        let addr = self.0.lock().expect("l").parse().expect("addr");
        (vm_id == "agent-1").then(|| crate::contracts::AgentRoute::direct(addr))
    }
}

#[tokio::test]
async fn a_vm_agent_away_from_its_openclaw_is_answered_on_permission_only_at_its_paired_address() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    let ids = Arc::new(Split(Mutex::new("127.0.0.1:3102".into())));
    app.contracts.identities.set(ids.clone());
    let perms = Arc::new(Perms {
        on: AtomicBool::new(true),
        seen: Mutex::new(Vec::new()),
    });
    app.contracts.agent_permissions.set(perms.clone());
    let g = ToolsGate::new(&app, String::new(), None, Arc::new(|_| false), None, None);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://127.0.0.1:{}", l.local_addr().expect("addr").port());
    tokio::spawn(cc_http::serve(l, Arc::new(g.permission_router())));
    let raise = json!({"permission_id": "oc:1", "kind": "exec", "title": "ls"}).to_string();
    assert_eq!(post(&base, "/permission", &raise, &[]).await.status(), 200);
    assert_eq!(perms.seen.lock().expect("l")[0].1, "agent-1");
    // Nothing else is served there.
    assert_eq!(post(&base, "/mcp", "{}", &[]).await.status(), 404);
    // The agents' own gate does not take the vm-agent's address as the agent.
    let main = listen(&g).await;
    assert_eq!(post(&main, "/permission", &raise, &[]).await.status(), 403);
    // Another vm-agent address: refused.
    *ids.0.lock().expect("l") = "10.0.0.8:3102".into();
    assert_eq!(post(&base, "/permission", &raise, &[]).await.status(), 403);
}

/// Two agents whose vm-agents are at one host address.
struct Shared;

impl crate::contracts::IdentityMap for Shared {
    fn agents(&self) -> Vec<crate::contracts::AgentIdentity> {
        ["agent-1", "agent-2"]
            .iter()
            .map(|v| crate::contracts::AgentIdentity {
                vm_id: v.to_string(),
                private_ip: "10.0.0.9".into(),
                hostname: None,
                name: None,
            })
            .collect()
    }
    fn agent(&self, vm_id: &str) -> Option<crate::contracts::AgentIdentity> {
        self.agents().into_iter().find(|a| a.vm_id == vm_id)
    }
    fn host_for(&self, _: &str) -> Option<String> {
        None
    }
    fn route_for(&self, vm_id: &str) -> Option<crate::contracts::AgentRoute> {
        let port = if vm_id == "agent-1" { 3100 } else { 3101 };
        Some(crate::contracts::AgentRoute::direct(
            format!("127.0.0.1:{port}").parse().expect("addr"),
        ))
    }
}

#[tokio::test]
async fn two_vm_agents_at_one_address_cannot_be_told_apart_so_neither_is_answered() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    app.contracts.identities.set(Arc::new(Shared));
    let perms = Arc::new(Perms {
        on: AtomicBool::new(true),
        seen: Mutex::new(Vec::new()),
    });
    app.contracts.agent_permissions.set(perms.clone());
    let g = ToolsGate::new(&app, String::new(), None, Arc::new(|_| false), None, None);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://127.0.0.1:{}", l.local_addr().expect("addr").port());
    tokio::spawn(cc_http::serve(l, Arc::new(g.permission_router())));
    let raise = json!({"permission_id": "oc:1", "kind": "exec", "title": "ls"}).to_string();
    assert_eq!(post(&base, "/permission", &raise, &[]).await.status(), 403);
    assert!(perms.seen.lock().expect("l").is_empty());
}

#[tokio::test]
async fn permission_has_a_budget_of_its_own() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    app.contracts
        .identities
        .set(Identities::of(&[("agent-1", "127.0.0.1", "One")]));
    let perms = Arc::new(Perms {
        on: AtomicBool::new(true),
        seen: Mutex::new(Vec::new()),
    });
    app.contracts.agent_permissions.set(perms);
    let g = gate(None, Some(app)).await;
    let get = || async {
        reqwest::get(format!("{}/permission?permission_id=oc%3A1", g.base))
            .await
            .expect("get")
            .status()
    };
    // More than the gate's own budget for /mcp, all answered.
    for _ in 0..(GATE_CALLS_PER_MINUTE + 5) {
        assert_eq!(get().await, 200);
    }
}
