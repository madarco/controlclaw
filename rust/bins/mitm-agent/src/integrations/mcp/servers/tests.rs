//! `mcp-servers.test.ts`: the commands, OAuth against a fake authorization server, with a fake MCP
//! server (plain HTTP on loopback, which only a test build may dial).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::integrations::mcp::oauth::{auth_param, resource_matches};
use crate::integrations::testing::{
    self, Answer, FakeAgents, FakeCodes, FakeServer, Got, Identities, Routes, owner_route,
};

#[derive(Default)]
pub struct Mcp {
    /// `none`, `header` or `oauth`.
    pub auth: Mutex<String>,
    pub challenge: Mutex<Option<String>>,
    pub issued: Mutex<u32>,
    pub valid_token: Mutex<String>,
    pub refresh_token: Mutex<String>,
    pub fail_next_401: AtomicBool,
    pub sse_lists: AtomicBool,
    pub big_list: AtomicBool,
    pub origin: Mutex<String>,
}

fn form(body: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

fn get<'a>(f: &'a [(String, String)], k: &str) -> Option<&'a str> {
    f.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

/// The fake MCP server, which is also its own authorization server.
pub fn mcp_answer(m: &Mcp, g: &Got) -> Answer {
    let origin = m.origin.lock().expect("lock").clone();
    let path = g.path.split('?').next().unwrap_or_default();
    let h = |k: &str| g.headers.get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    if path == "/.well-known/oauth-protected-resource/mcp" {
        return Answer::json(
            200,
            &json!({"resource": format!("{origin}/mcp"), "authorization_servers": [origin], "scopes_supported": ["read", "write"]}),
        );
    }
    if path == "/.well-known/oauth-authorization-server" {
        return Answer::json(
            200,
            &json!({"issuer": origin, "authorization_endpoint": format!("{origin}/authorize"), "token_endpoint": format!("{origin}/token"),
            "registration_endpoint": format!("{origin}/register"), "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["client_secret_post"]}),
        );
    }
    if path == "/register" {
        let doc: Value = serde_json::from_slice(&g.body).unwrap_or(Value::Null);
        assert_eq!(doc["redirect_uris"], json!(["https://cp.example/oauth/callback"]));
        return Answer::json(
            201,
            &json!({"client_id": "dyn-client", "client_secret": "dyn-secret", "token_endpoint_auth_method": "client_secret_post"}),
        );
    }
    if path == "/token" {
        let f = form(&g.body);
        assert_eq!(get(&f, "client_id"), Some("dyn-client"));
        assert_eq!(get(&f, "client_secret"), Some("dyn-secret"));
        assert_eq!(get(&f, "resource"), Some(format!("{origin}/mcp").as_str()));
        match get(&f, "grant_type") {
            Some("authorization_code") => {
                if get(&f, "code") != Some("the-code") {
                    return Answer::json(400, &json!({"error": "invalid_grant"}));
                }
                let v = get(&f, "code_verifier").unwrap_or_default();
                let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
                if Some(c) != *m.challenge.lock().expect("lock") {
                    return Answer::json(400, &json!({"error": "invalid_grant", "error_description": "PKCE"}));
                }
            }
            Some("refresh_token") => {
                if get(&f, "refresh_token") != Some(m.refresh_token.lock().expect("lock").as_str()) {
                    return Answer::json(400, &json!({"error": "invalid_grant"}));
                }
            }
            _ => return Answer::json(400, &json!({"error": "unsupported_grant_type"})),
        }
        let n = {
            let mut i = m.issued.lock().expect("lock");
            *i += 1;
            *i
        };
        *m.valid_token.lock().expect("lock") = format!("tok-{n}");
        *m.refresh_token.lock().expect("lock") = format!("ref-{n}");
        return Answer::json(
            200,
            &json!({"access_token": format!("tok-{n}"), "refresh_token": format!("ref-{n}"), "expires_in": 3600, "token_type": "Bearer"}),
        );
    }
    if path == "/hang" {
        let mut a = Answer::json(200, &json!({}));
        a.delay_ms = 5_000;
        return a;
    }
    if path != "/mcp" {
        return Answer::json(404, &json!({}));
    }
    let auth = m.auth.lock().expect("lock").clone();
    let valid = format!("Bearer {}", m.valid_token.lock().expect("lock"));
    let ok = match auth.as_str() {
        "none" => true,
        "header" => h("x-api-key").as_deref() == Some("right-key"),
        _ => h("authorization").as_deref() == Some(valid.as_str()) && !m.fail_next_401.load(Ordering::SeqCst),
    };
    if !ok {
        m.fail_next_401.store(false, Ordering::SeqCst);
        return Answer {
            status: 401,
            headers: vec![(
                "www-authenticate".into(),
                format!("Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource/mcp\""),
            )],
            body: vec![],
            delay_ms: 0,
        };
    }
    let sse = |id: &Value, result: Value| Answer {
        status: 200,
        headers: vec![
            ("content-type".into(), "text/event-stream".into()),
            ("mcp-session-id".into(), "sess-1".into()),
        ],
        body: format!(
            "event: message\ndata: {}\n\n",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        )
        .into_bytes(),
        delay_ms: 0,
    };
    if g.method == "GET" && h("last-event-id").as_deref() == Some("hold") {
        let mut a = Answer::typed(200, "text/event-stream", b": open\n\n".to_vec());
        a.delay_ms = 5_000;
        return a;
    }
    if g.method == "GET" {
        return Answer::typed(
            200,
            "text/event-stream",
            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n".to_vec(),
        );
    }
    if g.method == "DELETE" {
        return Answer::typed(200, "", vec![]);
    }
    let msg: Value = serde_json::from_slice(&g.body).unwrap_or(Value::Null);
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    match msg["method"].as_str().unwrap_or_default() {
        "notifications/initialized" => Answer::typed(202, "", vec![]),
        "initialize" => {
            let mut a = Answer::json(
                200,
                &json!({"jsonrpc": "2.0", "id": id, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "Fake MCP"}}}),
            );
            a.headers.push(("mcp-session-id".into(), "sess-1".into()));
            a
        }
        "tools/list" if m.big_list.load(Ordering::SeqCst) => {
            let tools: Vec<Value> = (0..5000)
                .map(|i| json!({"name": format!("tool_{i}"), "description": "y".repeat(1000), "inputSchema": {}}))
                .collect();
            Answer::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}))
        }
        "tools/list" => {
            let second = msg["params"]["cursor"] == "p2";
            let page = if second {
                json!([{"name": "delete_doc", "description": "Delete a doc", "annotations": {"destructiveHint": true}, "inputSchema": {}}])
            } else {
                json!([{"name": "read_doc", "description": "x".repeat(900), "annotations": {"readOnlyHint": true}, "inputSchema": {}}])
            };
            let mut result = json!({"tools": page});
            if !second {
                result["nextCursor"] = json!("p2");
            }
            if m.sse_lists.load(Ordering::SeqCst) {
                return sse(&id, result);
            }
            Answer::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }
        "tools/call" => sse(&id, json!({"content": [{"type": "text", "text": "secret result"}]})),
        _ => Answer::json(
            200,
            &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no"}}),
        ),
    }
}

pub struct T {
    pub _dir: tempfile::TempDir,
    pub app: Arc<crate::app::App>,
    pub mcp: Arc<Mcp>,
    pub server: FakeServer,
    pub agents: Arc<FakeAgents>,
    pub routes: Arc<Routes>,
    pub origin: String,
}

impl T {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let app = testing::app(dir.path());
        let mcp = Arc::new(Mcp::default());
        *mcp.auth.lock().expect("lock") = "none".into();
        let m = mcp.clone();
        let server = FakeServer::start(move |g| mcp_answer(&m, g)).await;
        let origin = server.url();
        *mcp.origin.lock().expect("lock") = origin.clone();
        let agents = Arc::new(FakeAgents::default());
        let routes = Arc::new(Routes(Mutex::new(vec![])));
        app.contracts.agents.set(agents.clone());
        app.contracts.consent.set(FakeCodes::new("123456"));
        app.contracts.code_routes.set(routes.clone());
        // agent-1 at the address the gate tests call from; vm-a elsewhere.
        app.contracts.identities.set(Identities::of(&[
            ("agent-1", "127.0.0.1", "One"),
            ("vm-a", "10.0.0.7", "Sales bot"),
        ]));
        Self {
            _dir: dir,
            app,
            mcp,
            server,
            agents,
            routes,
            origin,
        }
    }

    pub fn make(&self) -> Arc<McpServersFirewall> {
        McpServersFirewall::new(
            &self.app,
            self._dir.path().join(format!("mcp-{}.enc", rand::random::<u32>())),
            "http://10.0.0.2:3940/servers/".into(),
            "https://cp.example/oauth/callback".into(),
        )
    }

    pub fn auth(&self, a: &str) {
        *self.mcp.auth.lock().expect("lock") = a.into();
    }

    /// Starts an OAuth add and signs in with the relayed code.
    pub async fn sign_in(&self, fw: &Arc<McpServersFirewall>, name: &str, agents: Value) -> Value {
        self.auth("oauth");
        let started = run(fw, "propose", json!({"changeId": "o1", "kind": "add", "name": name, "url": format!("{}/mcp", self.origin), "auth": "oauth", "agents": agents})).await;
        assert_eq!(started.status, "awaiting_authorization", "{:?}", started.message);
        let d = data(&started);
        let auth_url = url::Url::parse(d["authorizationUrl"].as_str().expect("url")).expect("url");
        *self.mcp.challenge.lock().expect("lock") = auth_url
            .query_pairs()
            .find(|(k, _)| k == "code_challenge")
            .map(|(_, v)| v.to_string());
        d
    }
}

pub async fn run(fw: &Arc<McpServersFirewall>, action: &str, p: Value) -> CommandOutcome {
    fw.handle(action, p.as_object().cloned().expect("object")).await
}

pub fn data(o: &CommandOutcome) -> Value {
    Value::Object(o.data.clone().unwrap_or_default())
}

fn agent() -> Value {
    json!({"vmId": "vm-a", "name": "Sales bot"})
}

#[test]
fn proposals_names_addresses_and_headers_are_checked() {
    let parse = |v: Value| parse_proposal(v.as_object().expect("o"));
    let url = "https://mcp.example.com/mcp";
    assert!(parse(json!({"changeId": "c", "kind": "add", "name": "Bad Name", "url": url})).is_err());
    assert!(parse(json!({"changeId": "c", "kind": "add", "name": "controlclaw-x", "url": url})).is_err());
    assert!(
        parse(json!({"changeId": "c", "kind": "add", "name": "gbrain", "url": url})).is_err(),
        "the brain's entry is not an organization's"
    );
    let r = parse(json!({"changeId": "c", "kind": "replace", "name": "docs", "auth": "header", "headerName": "X-Key", "agents": [agent()]})).expect("p");
    assert!(r.agents.is_empty(), "a replace names no agent");
    assert!(parse(json!({"changeId": "c", "kind": "add", "name": "ok", "url": "https://10.0.0.3/mcp"})).is_err());
    assert!(
        parse(json!({"changeId": "c", "kind": "add", "name": "ok", "url": "https://mcp.example.com/mcp?key=x"}))
            .is_err()
    );
    assert!(parse(json!({"changeId": "c", "kind": "add", "name": "ok", "url": url, "auth": "header", "headerName": "Mcp-Session-Id"})).is_err());
    let p = parse(json!({"changeId": "c", "kind": "add", "name": "docs", "url": url, "agents": [{"vmId": "vm-a", "name": "Somebody else"}]})).expect("p");
    assert_eq!(p.agents[0].name, "vm-a", "the proposal's name for an agent is not used");
    let mut named = p.clone();
    named.agents[0].name = "Sales bot".into();
    assert_eq!(
        summarize(&named, named.url.as_deref()),
        "Add the MCP server docs (mcp.example.com) and give it to Sales bot"
    );
    for name in ["constructor", "__proto__", "toString", "hasOwnProperty"] {
        assert!(!mcp_name_ok(name), "{name}");
    }
    assert_eq!(
        auth_param(
            Some(
                r#"Bearer realm="x", resource_metadata="https://a.b/.well-known/oauth-protected-resource", scope="r w""#
            ),
            "resource_metadata"
        )
        .as_deref(),
        Some("https://a.b/.well-known/oauth-protected-resource")
    );
    assert!(resource_matches(
        "https://mcp.example.com",
        &url::Url::parse(url).expect("u")
    ));
}

#[tokio::test]
async fn a_server_with_no_sign_in_tools_read_kept_given_and_pushed() {
    let t = T::new().await;
    let fw = t.make();
    t.mcp.sse_lists.store(true, Ordering::SeqCst);
    let out = run(&fw, "propose", json!({"changeId": "c1", "kind": "add", "name": "docs", "url": format!("{}/mcp", t.origin), "agents": [agent()]})).await;
    t.mcp.sse_lists.store(false, Ordering::SeqCst);
    assert_eq!(out.status, "applied", "{:?}", out.message);
    let d = data(&out);
    assert_eq!(d["tofu"], true);
    let s = &d["server"];
    let names: Vec<&str> = s["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|x| x["name"].as_str())
        .collect();
    assert_eq!(names, ["read_doc", "delete_doc"]);
    assert_eq!(s["tools"][0]["description"].as_str().expect("d").len(), 500);
    assert_eq!(s["tools"][1]["annotations"]["destructiveHint"], true);
    assert_eq!(s["serverName"], "Fake MCP");
    assert_eq!(s["agents"], json!(["vm-a"]));
    let pushes = t.agents.calls.lock().expect("lock").clone();
    assert_eq!(
        pushes,
        vec![(
            "vm-a".to_string(),
            "/mcp-servers/apply".to_string(),
            json!({"servers": [{"name": "docs", "url": "http://10.0.0.2:3940/servers/docs/mcp"}]})
        )]
    );
    // The session the firewall opened to read the tools is closed again.
    assert!(
        t.server
            .got()
            .iter()
            .any(|g| g.method == "DELETE" && g.headers.get("mcp-session-id").is_some_and(|v| v == "sess-1"))
    );
    assert_eq!(
        d["summary"],
        format!(
            "Add the MCP server docs ({}) and give it to Sales bot",
            t.origin.trim_start_matches("http://")
        )
    );
    let stranger = run(
        &fw,
        "propose",
        json!({"changeId": "c1b", "kind": "assign", "name": "docs", "agents": [{"vmId": "vm-unknown", "name": "x"}]}),
    )
    .await;
    assert!(stranger.message.expect("m").contains("does not know that agent"));
    let again = run(
        &fw,
        "propose",
        json!({"changeId": "c2", "kind": "add", "name": "docs", "url": format!("{}/mcp", t.origin)}),
    )
    .await;
    assert_eq!(
        again.message.as_deref(),
        Some("The organization already has an MCP server called docs.")
    );
}

#[tokio::test]
async fn a_header_server_a_wrong_key_keeps_nothing_and_the_right_one_is_kept_and_never_read_back() {
    let t = T::new().await;
    let fw = t.make();
    t.auth("header");
    let url = format!("{}/mcp", t.origin);
    let wrong = run(&fw, "propose", json!({"changeId": "h1", "kind": "add", "name": "keyed", "url": url, "auth": "header", "headerName": "X-API-Key", "secret": {"headerValue": "wrong"}})).await;
    assert_eq!(
        wrong.message.as_deref(),
        Some("The server refused the credential (401).")
    );
    assert_eq!(data(&run(&fw, "read", json!({})).await)["servers"], json!([]));
    let right = run(&fw, "propose", json!({"changeId": "h2", "kind": "add", "name": "keyed", "url": url, "auth": "header", "headerName": "X-API-Key", "secret": {"headerValue": "right-key"}})).await;
    assert_eq!(right.status, "applied", "{:?}", right.message);
    let read = data(&run(&fw, "read", json!({})).await).to_string();
    assert!(!read.contains("right-key"), "the key is not in a read");
    assert!(read.contains(r#""headerName":"X-API-Key""#));
    assert_eq!(
        fw.credential_headers("keyed").await,
        Some(vec![("X-API-Key".to_string(), "right-key".to_string())])
    );
    // A replace that also names agents gives none: its code message would not say so.
    let replaced = run(&fw, "propose", json!({"changeId": "h3", "kind": "replace", "name": "keyed", "auth": "header", "headerName": "X-API-Key", "secret": {"headerValue": "right-key"}, "agents": [agent()]})).await;
    assert_eq!(replaced.status, "applied", "{:?}", replaced.message);
    assert!(matches!(
        fw.server_for("vm-a", "keyed"),
        ServerFor::Known { allowed: false, .. }
    ));
    let reconnect = run(
        &fw,
        "propose",
        json!({"changeId": "h4", "kind": "reconnect", "name": "keyed"}),
    )
    .await;
    assert_eq!(reconnect.message.as_deref(), Some("keyed does not sign in with OAuth."));
    // A key the server stops taking: no renewal, and the card says what to do.
    assert!(!fw.refresh("keyed").await);
    let servers = data(&run(&fw, "read", json!({})).await)["servers"].clone();
    assert_eq!(
        servers[0]["lastError"],
        "The server refused the key (401). Replace the credential."
    );
}

#[tokio::test]
async fn once_someone_is_approved_every_change_waits_for_the_firewalls_code() {
    let t = T::new().await;
    let fw = t.make();
    run(
        &fw,
        "propose",
        json!({"changeId": "s1", "kind": "add", "name": "docs", "url": format!("{}/mcp", t.origin)}),
    )
    .await;
    *t.routes.0.lock().expect("lock") = vec![owner_route()];
    t.agents.calls.lock().expect("lock").clear();
    let proposed = run(
        &fw,
        "propose",
        json!({"changeId": "s2", "kind": "assign", "name": "docs", "agents": [agent()]}),
    )
    .await;
    assert_eq!(proposed.status, "awaiting_code", "{:?}", proposed.message);
    assert!(
        t.agents.calls.lock().expect("lock").is_empty(),
        "nothing applied before the code"
    );
    assert_eq!(
        run(&fw, "confirm", json!({"changeId": "s2", "code": "000000"}))
            .await
            .status,
        "invalid_code"
    );
    let ok = run(&fw, "confirm", json!({"changeId": "s2", "code": "123456"})).await;
    assert_eq!(ok.status, "applied", "{:?}", ok.message);
    assert!(matches!(
        fw.server_for("vm-a", "docs"),
        ServerFor::Known { allowed: true, .. }
    ));
    *t.routes.0.lock().expect("lock") = vec![];
    let off = run(
        &fw,
        "propose",
        json!({"changeId": "s3", "kind": "unassign", "name": "docs", "agents": [agent()]}),
    )
    .await;
    assert_eq!(off.status, "applied");
    assert_eq!(
        t.agents.calls.lock().expect("lock").last().map(|c| c.2.clone()),
        Some(json!({"servers": []}))
    );
    // forget drops a deleted agent from every server.
    run(
        &fw,
        "propose",
        json!({"changeId": "s4", "kind": "assign", "name": "docs", "agents": [agent()]}),
    )
    .await;
    run(&fw, "forget", json!({"vmId": "vm-a"})).await;
    assert!(matches!(
        fw.server_for("vm-a", "docs"),
        ServerFor::Known { allowed: false, .. }
    ));
}

#[tokio::test]
async fn oauth_discovery_from_the_401_registration_pkce_the_relayed_code_refresh() {
    let t = T::new().await;
    let fw = t.make();
    *t.mcp.valid_token.lock().expect("lock") = "none-yet".into();
    let d = t.sign_in(&fw, "notes", json!([agent()])).await;
    let auth_url = url::Url::parse(d["authorizationUrl"].as_str().expect("url")).expect("url");
    assert_eq!(
        format!("{}{}", auth_url.origin().ascii_serialization(), auth_url.path()),
        format!("{}/authorize", t.origin)
    );
    let q = |k: &str| auth_url.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.to_string());
    assert_eq!(q("client_id").as_deref(), Some("dyn-client"));
    assert_eq!(q("redirect_uri").as_deref(), Some("https://cp.example/oauth/callback"));
    assert_eq!(q("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(q("resource"), Some(format!("{}/mcp", t.origin)));
    assert_eq!(q("scope").as_deref(), Some("read write"));
    let state = d["state"].as_str().expect("state").to_string();
    assert_eq!(
        run(&fw, "callback", json!({"state": "not-ours", "code": "the-code"}))
            .await
            .status,
        "expired"
    );
    let done = run(&fw, "callback", json!({"state": state, "code": "the-code"})).await;
    assert_eq!(done.status, "applied", "{:?}", done.message);
    let read = data(&run(&fw, "read", json!({})).await).to_string();
    let token = t.mcp.valid_token.lock().expect("lock").clone();
    assert!(
        !read.contains(&token) && !read.contains("dyn-secret") && !read.contains("ref-1"),
        "no token or secret in a read"
    );
    assert!(read.contains(r#""signedIn":true"#));
    assert_eq!(
        run(&fw, "callback", json!({"state": state, "code": "the-code"}))
            .await
            .status,
        "expired",
        "a state is used once"
    );
    // A 401 on a live token: one refresh, then the new token.
    assert!(fw.refresh("notes").await);
    let token2 = t.mcp.valid_token.lock().expect("lock").clone();
    assert_ne!(token2, token);
    assert_eq!(
        fw.credential_headers("notes").await,
        Some(vec![("authorization".to_string(), format!("Bearer {token2}"))])
    );
    // A refresh the server refuses: the server needs a new sign-in.
    *t.mcp.refresh_token.lock().expect("lock") = "revoked".into();
    assert!(!fw.refresh("notes").await);
    assert!(matches!(fw.server_for("vm-a", "notes"), ServerFor::Known { ref state, .. } if state == "reauth_required"));
}

#[tokio::test]
async fn a_sign_in_still_waiting_when_its_server_is_removed_cannot_land_on_a_server_added_again() {
    let t = T::new().await;
    let fw = t.make();
    let d = t.sign_in(&fw, "notes", json!([])).await;
    assert_eq!(
        run(&fw, "callback", json!({"state": d["state"], "code": "the-code"}))
            .await
            .status,
        "applied"
    );
    let again = run(
        &fw,
        "propose",
        json!({"changeId": "r2", "kind": "reconnect", "name": "notes"}),
    )
    .await;
    assert_eq!(again.status, "awaiting_authorization");
    let a = data(&again);
    let u = url::Url::parse(a["authorizationUrl"].as_str().expect("u")).expect("u");
    *t.mcp.challenge.lock().expect("lock") = u
        .query_pairs()
        .find(|(k, _)| k == "code_challenge")
        .map(|(_, v)| v.to_string());
    assert_eq!(
        run(
            &fw,
            "propose",
            json!({"changeId": "r3", "kind": "remove", "name": "notes"})
        )
        .await
        .status,
        "applied"
    );
    t.auth("none");
    assert_eq!(
        run(
            &fw,
            "propose",
            json!({"changeId": "r4", "kind": "add", "name": "notes", "url": format!("{}/mcp", t.origin)})
        )
        .await
        .status,
        "applied"
    );
    let late = run(&fw, "callback", json!({"state": a["state"], "code": "the-code"})).await;
    assert!(!late.ok);
    let read = data(&run(&fw, "read", json!({})).await).to_string();
    assert!(
        read.contains(r#""auth":"none""#),
        "the server added again keeps its own sign-in"
    );
}

#[tokio::test]
async fn reading_tools_has_an_overall_time() {
    let url = url::Url::parse(&format!("{}/hang", T::new().await.origin)).expect("url");
    let t0 = std::time::Instant::now();
    let got = tokio::time::timeout(
        std::time::Duration::from_secs(70),
        list_tools(&url, &[], std::time::Duration::from_millis(300)),
    )
    .await
    .expect("bounded");
    assert!(got.is_err());
    assert!(t0.elapsed() < std::time::Duration::from_secs(3));
}

#[tokio::test]
async fn with_no_identity_map_on_this_build_no_agent_is_known_and_nothing_is_given() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    app.contracts.consent.set(FakeCodes::new("1"));
    app.contracts.code_routes.set(Arc::new(Routes(Mutex::new(vec![]))));
    let fw = McpServersFirewall::new(
        &app,
        dir.path().join("m.enc"),
        "http://x/servers/".into(),
        "https://cp/oauth/callback".into(),
    );
    let t = T::new().await;
    let r = run(&fw, "propose", json!({"changeId": "c", "kind": "add", "name": "docs", "url": format!("{}/mcp", t.origin), "agents": [agent()]})).await;
    assert_eq!(
        r.message.as_deref(),
        Some("This firewall does not know that agent. If it was just created, try again in a minute.")
    );
}
