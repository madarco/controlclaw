//! `connectors.test.ts`: the commands against a fake OpenConnector and a fake agent box.

use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::*;
use crate::integrations::connectors::runtime::ConnectorRuntime;
use crate::integrations::connectors::store;
use crate::integrations::testing::{self, Answer, FakeAgents, FakeCodes, FakeServer, Routes, owner_route};

#[derive(Default)]
struct Oc {
    connections: Vec<Value>,
    tokens: Vec<Value>,
    token_seq: u32,
    oauth: Map<String, Value>,
    request_status: Value,
    connect_fails: Option<String>,
}

fn envelope(data: Value) -> Answer {
    Answer::json(
        200,
        &json!({"success": true, "message": "OK", "data": data, "meta": {}}),
    )
}

fn oc_answer(oc: &Mutex<Oc>, g: &testing::Got) -> Answer {
    let mut oc = oc.lock().expect("lock");
    let body: Value = serde_json::from_slice(&g.body).unwrap_or(Value::Null);
    let path = g.path.split('?').next().unwrap_or_default().to_string();
    let seg: Vec<&str> = path.split('/').collect();
    let m = g.method.as_str();
    if path.starts_with("/v1/providers/") && path.ends_with("/setup") {
        return envelope(json!({"service": "gitea",
            "auth": [{"type": "api_key", "fields": [{"key": "apiKey", "label": "Token", "inputType": "password", "required": true, "secret": true}]}],
            "oauthClient": {"configured": false, "expectedRedirectUri": "https://controlclaw.io/oauth/callback", "missingFields": ["clientId"]}}));
    }
    if path == "/v1/connections" && m == "GET" {
        return envelope(Value::Array(oc.connections.clone()));
    }
    if path.ends_with("/connect/api-key") && m == "POST" {
        if let Some(f) = &oc.connect_fails {
            return Answer::json(
                400,
                &json!({"success": false, "message": f, "data": null, "errorCode": "credential_verification_failed", "meta": {}}),
            );
        }
        let by_id = seg[3] == "by-id";
        let id = if by_id {
            seg[4].to_string()
        } else {
            format!("rc-{}-1", seg[3])
        };
        let service = if by_id {
            oc.connections
                .iter()
                .find(|c| c["id"] == id.as_str())
                .and_then(|c| c["service"].as_str())
                .unwrap_or("gitea")
                .to_string()
        } else {
            seg[3].to_string()
        };
        let key = body["apiKey"].as_str().unwrap_or_default();
        let tail: String = key
            .chars()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let row = json!({"id": id, "service": service, "alias": format!("alias-{id}"), "status": "active",
            "authType": "api_key", "accountLabel": format!("acct({tail})"), "comment": body.get("comment").cloned().unwrap_or(Value::Null)});
        oc.connections.retain(|c| c["id"] != id.as_str());
        oc.connections.push(row.clone());
        return envelope(row);
    }
    if path.ends_with("/connect/custom-credential") && m == "POST" {
        let id = format!("rc-{}-1", seg[3]);
        let row = json!({"id": id, "service": seg[3], "alias": format!("alias-{id}"), "status": "active",
            "authType": "custom_credential", "accountLabel": "custom acct"});
        oc.connections.push(row.clone());
        return envelope(row);
    }
    if path.starts_with("/api/connections/") && m == "DELETE" {
        oc.connections.retain(|c| c["service"] != seg[3]);
        return envelope(json!({"ok": true}));
    }
    if path.starts_with("/api/oauth/configs/") && m == "PUT" {
        oc.oauth.insert(seg[4].to_string(), body);
        return envelope(json!({"configured": true}));
    }
    if path.ends_with("/connect") && m == "POST" {
        return envelope(
            json!({"authorizationUrl": "https://provider.example/authorize?state=st-1",
            "stateHandle": "st-1", "connectionRequestId": "req-1", "status": "initiated"}),
        );
    }
    if path == "/oauth/callback" {
        return Answer {
            status: 302,
            headers: vec![("location".into(), "https://provider.example/done".into())],
            body: vec![],
            delay_ms: 0,
        };
    }
    if path.starts_with("/v1/connection-requests/") {
        let mut s = json!({"connectionRequestId": "req-1", "service": "github"});
        if let Some(o) = oc.request_status.as_object() {
            for (k, v) in o {
                s[k] = v.clone();
            }
        }
        return envelope(s);
    }
    if path == "/api/runtime-tokens" && m == "POST" {
        oc.token_seq += 1;
        let id = format!("tok-{}", oc.token_seq);
        let mut rec = json!({"id": id});
        for (k, v) in body.as_object().cloned().unwrap_or_default() {
            rec[k] = v;
        }
        oc.tokens.push(rec.clone());
        return Answer::json(200, &json!({"token": format!("oct_{id}"), "record": rec}));
    }
    if path.starts_with("/api/runtime-tokens/") && m == "PUT" {
        let id = seg[3];
        let mut rec = json!({"id": id});
        for (k, v) in body.as_object().cloned().unwrap_or_default() {
            rec[k] = v;
        }
        oc.tokens.retain(|t| t["id"] != id);
        oc.tokens.push(rec.clone());
        return Answer::json(200, &rec);
    }
    if path.starts_with("/api/runtime-tokens/") && m == "DELETE" {
        oc.tokens.retain(|t| t["id"] != seg[3]);
        return Answer::json(200, &json!({"ok": true}));
    }
    Answer::json(
        404,
        &json!({"success": false, "message": "not found", "data": null, "errorCode": "not_found", "meta": {}}),
    )
}

struct T {
    _dir: tempfile::TempDir,
    app: Arc<crate::app::App>,
    path: std::path::PathBuf,
    oc: Arc<Mutex<Oc>>,
    server: FakeServer,
    agents: Arc<FakeAgents>,
    codes: Arc<FakeCodes>,
    routes: Arc<Routes>,
}

impl T {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let app = testing::app(dir.path());
        let oc: Arc<Mutex<Oc>> = Arc::default();
        let o = oc.clone();
        let server = FakeServer::start(move |g| oc_answer(&o, g)).await;
        let agents = Arc::new(FakeAgents::default());
        let codes = FakeCodes::new("654321");
        let routes = Arc::new(Routes(Mutex::new(vec![])));
        app.contracts.agents.set(agents.clone());
        app.contracts.consent.set(codes.clone());
        app.contracts.code_routes.set(routes.clone());
        let path = dir.path().join("connectors.enc");
        Self {
            _dir: dir,
            app,
            path,
            oc,
            server,
            agents,
            codes,
            routes,
        }
    }

    fn make(&self) -> Arc<ConnectorsFirewall> {
        ConnectorsFirewall::new(
            &self.app,
            self.path.clone(),
            ConnectorRuntime::new(&self.server.url(), "admin-secret"),
            "http://10.0.0.2:3900".into(),
        )
    }

    fn store(&self) -> store::ConnectorStore {
        store::load(&self.path, &self.app.box_key, "org1", "fw1")
    }

    fn calls(&self) -> Vec<(String, String, Value)> {
        self.agents.calls.lock().expect("lock").clone()
    }

    fn clear_calls(&self) {
        self.agents.calls.lock().expect("lock").clear();
    }

    fn tokens(&self) -> Vec<Value> {
        self.oc.lock().expect("lock").tokens.clone()
    }
}

async fn run(fw: &Arc<ConnectorsFirewall>, action: &str, p: Value) -> crate::commands::CommandOutcome {
    fw.handle(action, p.as_object().cloned().expect("object")).await
}

fn agent_a() -> Value {
    json!({"vmId": "vm-a", "name": "marcobot", "hostname": "a.vm.example", "privateIp": "10.0.0.5"})
}

fn agent_b() -> Value {
    json!({"vmId": "vm-b", "name": "opsbot", "hostname": "b.vm.example", "privateIp": "10.0.0.6"})
}

fn data(o: &crate::commands::CommandOutcome) -> Value {
    Value::Object(o.data.clone().unwrap_or_default())
}

#[test]
fn parses_a_proposal_and_refuses_a_malformed_one() {
    let p = parse_proposal(
        json!({"changeId": "c1", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "label": "Work",
            "extra": {"baseUrl": "https://gitea.example.com", "bad key": "x"}, "agents": [agent_a()], "secret": {"apiKey": "pat-123"}})
        .as_object()
        .expect("object"),
    )
    .expect("parsed");
    assert_eq!(p.service, "gitea");
    assert_eq!(
        Value::Object(p.extra.clone()),
        json!({"baseUrl": "https://gitea.example.com"}),
        "a key that is not a plain identifier is dropped"
    );
    assert_eq!(p.secret.and_then(|s| s.api_key).as_deref(), Some("pat-123"));
    for bad in [
        json!({"changeId": "c1", "kind": "nope", "service": "gitea"}),
        json!({"changeId": "c1", "kind": "connect", "service": "Not A Service"}),
    ] {
        assert_eq!(
            parse_proposal(bad.as_object().expect("o")),
            Err("malformed connectors.propose payload".into())
        );
    }
}

#[test]
fn summaries_name_the_app_the_label_and_the_agent() {
    let p = |kind: &str, label: Option<&str>, agents: Vec<Value>| {
        let mut v =
            json!({"changeId": "c", "kind": kind, "service": "gitea", "serviceName": "Gitea", "agents": agents});
        if let Some(l) = label {
            v["label"] = json!(l);
        }
        summarize(&parse_proposal(v.as_object().expect("o")).expect("p"))
    };
    assert_eq!(
        p("connect", Some("Work"), vec![agent_a()]),
        "Connect Gitea (Work) to marcobot"
    );
    assert_eq!(p("remove", None, vec![]), "Remove Gitea from the organization");
    assert_eq!(p("unassign", None, vec![agent_b()]), "Stop opsbot using Gitea");
    assert_eq!(
        p("connect", None, vec![agent_a(), agent_b()]),
        "Connect Gitea to 2 agents"
    );
}

#[tokio::test]
async fn trust_on_first_use_an_api_key_goes_to_the_runtime_and_the_agent_gets_a_token() {
    let t = T::new().await;
    let fw = t.make();
    let r = run(&fw, "propose", json!({"changeId": "c1", "kind": "connect", "service": "gitea", "serviceName": "Gitea",
        "label": "Work", "extra": {"baseUrl": "https://gitea.example.com"}, "agents": [agent_a()], "secret": {"apiKey": "pat-abc"}})).await;
    assert_eq!(r.status, "applied", "{r:?}");
    let d = data(&r);
    assert_eq!(d["tofu"], true);
    assert_eq!(d["connection"]["id"], "rc-gitea-1");
    assert_eq!(d["connection"]["accountLabel"], "acct(abc)");
    let connect = t
        .server
        .got()
        .into_iter()
        .find(|g| g.path.ends_with("/connect/api-key"))
        .expect("connect");
    let body: Value = serde_json::from_slice(&connect.body).expect("json");
    assert_eq!(body["apiKey"], "pat-abc");
    assert_eq!(body["extra"], json!({"baseUrl": "https://gitea.example.com"}));
    assert_eq!(connect.headers["authorization"], "Bearer admin-secret");
    // A token limited to this connection and its service, with proxies denied.
    let minted = &t.tokens()[0];
    assert_eq!(minted["allowedConnections"], json!(["rc-gitea-1"]));
    assert_eq!(minted["allowedActions"], json!(["gitea.*"]));
    assert_eq!(minted["allowedProxies"], json!([]));
    let push = t
        .calls()
        .into_iter()
        .find(|c| c.1 == "/connectors/apply")
        .expect("push");
    assert_eq!(push.0, "vm-a");
    assert_eq!(
        push.2["gateway"],
        json!({"url": "http://10.0.0.2:3900", "token": "oct_tok-1"})
    );
    assert_eq!(
        push.2["connections"],
        json!([{"id": "rc-gitea-1", "service": "gitea", "alias": "alias-rc-gitea-1", "label": "Work", "accountLabel": "acct(abc)"}])
    );
    // The store holds no credential, only the map.
    let raw = std::fs::read_to_string(&t.path).expect("store");
    assert!(!raw.contains("pat-abc"));
    let s = t.store();
    assert_eq!(s.connections.keys().cloned().collect::<Vec<_>>(), ["rc-gitea-1"]);
    assert!(!serde_json::to_string(&s).expect("json").contains("pat-abc"));
    assert_eq!(
        s.agents.get("vm-a").and_then(|a| a.token.clone()).as_deref(),
        Some("oct_tok-1")
    );
    assert_eq!(store::services_for(&s, s.agents.get("vm-a").expect("a")), ["gitea"]);
}

#[tokio::test]
async fn a_credential_the_provider_refuses_fails_the_change_and_nothing_is_pushed() {
    let t = T::new().await;
    let fw = t.make();
    t.oc.lock().expect("lock").connect_fails = Some("Bad credentials".into());
    let r = run(
        &fw,
        "propose",
        json!({"changeId": "c2", "kind": "connect", "service": "gitea", "serviceName": "Gitea",
        "agents": [agent_a()], "secret": {"apiKey": "wrong"}}),
    )
    .await;
    assert!(!r.ok);
    assert_eq!(r.status, "failed");
    assert_eq!(r.message.as_deref(), Some("Bad credentials"));
    assert!(t.calls().is_empty());
}

#[tokio::test]
async fn once_someone_is_approved_a_connect_waits_for_a_code_and_a_wrong_one_counts_down() {
    let t = T::new().await;
    let fw = t.make();
    *t.routes.0.lock().expect("lock") = vec![owner_route()];
    let proposed = run(
        &fw,
        "propose",
        json!({"changeId": "c3", "kind": "connect", "service": "gitea", "serviceName": "Gitea",
        "agents": [agent_a()], "secret": {"apiKey": "pat-xyz"}}),
    )
    .await;
    assert_eq!(proposed.status, "awaiting_code");
    assert_eq!(data(&proposed)["sentVia"], "telegram:Marco");
    assert_eq!(data(&proposed)["attemptsLeft"], 5);
    assert!(
        !t.server.got().iter().any(|g| g.path.contains("/connect/")),
        "nothing reached the runtime yet"
    );
    assert_eq!(
        t.codes.sent.lock().expect("lock").as_slice(),
        ["Connect Gitea to marcobot"]
    );
    let wrong = run(&fw, "confirm", json!({"changeId": "c3", "code": "111111"})).await;
    assert_eq!(wrong.status, "invalid_code");
    assert_eq!(data(&wrong)["attemptsLeft"], 4);
    let right = run(&fw, "confirm", json!({"changeId": "c3", "code": "654 321"})).await;
    assert_eq!(right.status, "applied");
    assert_eq!(data(&right)["tofu"], false);
    assert_eq!(data(&right)["sentVia"], "telegram:Marco");
    assert_eq!(data(&right)["connection"]["id"], "rc-gitea-1");
}

#[tokio::test]
async fn a_cancelled_change_is_dropped_and_confirming_it_afterwards_is_refused() {
    let t = T::new().await;
    let fw = t.make();
    *t.routes.0.lock().expect("lock") = vec![owner_route()];
    run(&fw, "propose", json!({"changeId": "c4", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [], "secret": {"apiKey": "k"}})).await;
    let c = run(&fw, "cancel", json!({"changeId": "c4"})).await;
    assert_eq!((c.ok, c.status.as_str()), (true, "cancelled"));
    let r = run(&fw, "confirm", json!({"changeId": "c4", "code": "654321"})).await;
    assert_eq!(r.status, "expired");
    assert_eq!(
        r.message.as_deref(),
        Some("No change is waiting for a code, or the code expired.")
    );
}

#[tokio::test]
async fn assigning_and_unassigning_narrow_the_token_and_the_last_one_revokes_it() {
    let t = T::new().await;
    let fw = t.make();
    run(&fw, "propose", json!({"changeId": "c5", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [agent_a()], "secret": {"apiKey": "pat-1"}})).await;
    let assigned = run(
        &fw,
        "propose",
        json!({"changeId": "c6", "kind": "assign", "service": "gitea", "serviceName": "Gitea",
        "connectionId": "rc-gitea-1", "agents": [agent_b()]}),
    )
    .await;
    assert_eq!(assigned.status, "applied");
    assert_eq!(t.tokens().len(), 2, "each agent has its own token");
    t.clear_calls();
    let unassigned = run(
        &fw,
        "propose",
        json!({"changeId": "c7", "kind": "unassign", "service": "gitea", "serviceName": "Gitea",
        "connectionId": "rc-gitea-1", "agents": [agent_b()]}),
    )
    .await;
    assert_eq!(unassigned.status, "applied");
    assert_eq!(t.tokens().len(), 1, "B's token is gone from the runtime");
    let b = t.calls().into_iter().find(|c| c.0 == "vm-b").expect("b");
    assert_eq!(b.2, json!({"remove": true}));
    let s = t.store();
    assert_eq!(s.agents.get("vm-a").expect("a").connections, ["rc-gitea-1"]);
    assert!(s.agents.get("vm-b").expect("b").connections.is_empty());
    let missing = run(
        &fw,
        "propose",
        json!({"changeId": "c8", "kind": "assign", "service": "gitea", "connectionId": "nope", "agents": [agent_b()]}),
    )
    .await;
    assert_eq!(
        missing.message.as_deref(),
        Some("This app is not connected on the firewall. Connect it again.")
    );
}

#[tokio::test]
async fn removing_a_connection_deletes_it_in_the_runtime_and_drops_every_grant() {
    let t = T::new().await;
    let fw = t.make();
    run(&fw, "propose", json!({"changeId": "c8", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [agent_a()], "secret": {"apiKey": "pat-1"}})).await;
    t.clear_calls();
    let r = run(&fw, "propose", json!({"changeId": "c9", "kind": "remove", "service": "gitea", "serviceName": "Gitea", "connectionId": "rc-gitea-1", "agents": []})).await;
    assert_eq!(r.status, "applied");
    assert!(t.oc.lock().expect("lock").connections.is_empty());
    assert!(
        t.tokens().is_empty(),
        "the agent held nothing else, so its token went too"
    );
    assert_eq!(t.calls()[0].2, json!({"remove": true}));
    assert_eq!(t.store().connections.len(), 0);
}

#[tokio::test]
async fn a_push_resends_the_same_state_and_forget_revokes_the_token() {
    let t = T::new().await;
    let fw = t.make();
    run(&fw, "propose", json!({"changeId": "c10", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [agent_a()], "secret": {"apiKey": "pat-1"}})).await;
    t.clear_calls();
    let pushed = run(
        &fw,
        "push",
        json!({"vmId": "vm-a", "name": "marcobot", "hostname": "a2.vm.example", "privateIp": "10.0.0.9"}),
    )
    .await;
    assert_eq!(pushed.status, "applied");
    assert_eq!(pushed.message.as_deref(), Some(""));
    assert_eq!(t.calls().len(), 1);
    let s = t.store();
    assert_eq!(
        s.agents.get("vm-a").and_then(|a| a.private_ip.clone()).as_deref(),
        Some("10.0.0.9")
    );
    assert_eq!(
        s.agents.get("vm-a").and_then(|a| a.hostname.clone()).as_deref(),
        Some("a2.vm.example")
    );
    let forgotten = run(&fw, "forget", json!({"vmId": "vm-a"})).await;
    assert_eq!(data(&forgotten)["revoked"], true);
    assert!(t.tokens().is_empty());
    assert!(t.store().agents.get("vm-a").is_none());
    // A push the agent box refuses is reported as failed, with the reason.
    run(&fw, "propose", json!({"changeId": "c11", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [agent_a()], "secret": {"apiKey": "pat-1"}})).await;
    *t.agents.fail.lock().expect("lock") = Some("agent 500: down".into());
    let r = run(&fw, "push", json!({"vmId": "vm-a"})).await;
    assert_eq!(
        (r.ok, r.status.as_str(), r.message.as_deref()),
        (false, "failed", Some("agent 500: down"))
    );
}

#[tokio::test]
async fn a_push_for_an_agent_this_firewall_holds_nothing_for_reports_empty() {
    let t = T::new().await;
    let fw = t.make();
    let r = run(
        &fw,
        "push",
        json!({"vmId": "vm-unknown", "name": "x", "hostname": "x.example"}),
    )
    .await;
    assert_eq!(r.status, "empty");
    assert_eq!(
        data(&r),
        json!({"vmId": "vm-unknown", "applied": [], "failed": [], "held": 0})
    );
    assert_eq!(
        r.message.as_deref(),
        Some("This firewall has no app connections for that agent. Connect the apps again.")
    );
    assert!(t.calls().is_empty());
}

#[tokio::test]
async fn reads_return_labels_and_states_never_a_credential() {
    let t = T::new().await;
    let fw = t.make();
    run(
        &fw,
        "propose",
        json!({"changeId": "c11", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "label": "Work",
        "agents": [agent_a()], "secret": {"apiKey": "pat-secret-value"}}),
    )
    .await;
    let list = run(&fw, "read", json!({"kind": "connections"})).await;
    assert!(list.ok);
    let text = serde_json::to_string(&data(&list)).expect("json");
    assert!(!text.contains("pat-secret-value"));
    assert!(!text.contains("oct_"), "a read never hands out a runtime token either");
    assert_eq!(
        data(&list)["agents"],
        json!([{"vmId": "vm-a", "name": "marcobot", "connections": ["rc-gitea-1"], "hasToken": true}])
    );
    let setup = run(&fw, "read", json!({"kind": "setup", "service": "gitea"})).await;
    assert!(setup.ok);
    assert_eq!(data(&setup)["oauthClient"]["configured"], false);
    let bad = run(&fw, "read", json!({"kind": "runs"})).await;
    assert_eq!(bad.message.as_deref(), Some("unknown connectors.read kind runs"));
    assert_eq!(data(&bad), json!({"kind": "runs"}));
    let none = run(&fw, "read", json!({})).await;
    assert_eq!(data(&none), json!({"kind": null}));
    let worse = run(
        &fw,
        "read",
        json!({"kind": "setup", "service": "../../api/connections"}),
    )
    .await;
    assert_eq!(worse.message.as_deref(), Some("connectors.read setup needs a service"));
}

#[tokio::test]
async fn a_connection_the_runtime_lost_disappears_on_the_next_read() {
    let t = T::new().await;
    let fw = t.make();
    run(&fw, "propose", json!({"changeId": "c12", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [agent_a()], "secret": {"apiKey": "pat-1"}})).await;
    t.oc.lock().expect("lock").connections.clear();
    let list = run(&fw, "read", json!({"kind": "connections"})).await;
    assert_eq!(data(&list)["connections"], json!([]));
    assert!(t.store().agents.get("vm-a").expect("a").connections.is_empty());
}

#[tokio::test]
async fn oauth_the_client_secret_goes_to_the_runtime_and_a_sign_in_link_comes_back() {
    let t = T::new().await;
    let fw = t.make();
    let r = run(
        &fw,
        "propose",
        json!({"changeId": "c13", "kind": "oauth_connect", "service": "github", "serviceName": "GitHub",
        "label": "Acme", "clientId": "Iv1.abc", "agents": [agent_a()], "secret": {"clientSecret": "shh"}}),
    )
    .await;
    assert_eq!(r.status, "awaiting_authorization");
    let d = data(&r);
    assert_eq!(d["state"], "st-1");
    assert_eq!(d["authorizationUrl"], "https://provider.example/authorize?state=st-1");
    assert_eq!(d["tofu"], true);
    assert_eq!(t.oc.lock().expect("lock").oauth["github"]["clientSecret"], "shh");
    assert!(t.calls().is_empty(), "nothing is pushed until the sign-in finishes");
    // A provider's extra client fields reach the runtime, secret ones included.
    run(
        &fw,
        "propose",
        json!({"changeId": "c13b", "kind": "oauth_connect", "service": "gitlab", "serviceName": "GitLab",
        "clientId": "app-1", "extra": {"instanceUrl": "https://gitlab.example.com"}, "agents": [],
        "secret": {"clientSecret": "shh", "extraSecret": {"developerToken": "dev-token"}}}),
    )
    .await;
    assert_eq!(
        t.oc.lock().expect("lock").oauth["gitlab"],
        json!({"clientId": "app-1", "clientSecret": "shh", "extra": {"instanceUrl": "https://gitlab.example.com", "developerToken": "dev-token"}})
    );
}

#[tokio::test]
async fn the_relayed_callback_is_accepted_only_for_a_state_this_firewall_minted() {
    let t = T::new().await;
    let fw = t.make();
    let bad = run(
        &fw,
        "callback",
        json!({"changeId": "c14", "state": "st-someone-elses", "code": "code-1"}),
    )
    .await;
    assert_eq!((bad.ok, bad.status.as_str()), (false, "expired"));
    assert!(!t.server.got().iter().any(|g| g.path.starts_with("/oauth/callback")));
    // A callback the provider refused fails the change.
    run(
        &fw,
        "propose",
        json!({"changeId": "c15", "kind": "oauth_connect", "service": "github", "serviceName": "GitHub",
        "clientId": "Iv1.abc", "agents": [], "secret": {"clientSecret": "shh"}}),
    )
    .await;
    t.oc.lock().expect("lock").request_status =
        json!({"status": "failed", "errorCode": "provider_error", "errorMessage": "OAuth connection failed."});
    let r = run(
        &fw,
        "callback",
        json!({"changeId": "c15", "state": "st-1", "error": "access_denied"}),
    )
    .await;
    assert!(!r.ok);
    assert_eq!(r.message.as_deref(), Some("OAuth connection failed."));
    let replayed = t
        .server
        .got()
        .into_iter()
        .find(|g| g.path.starts_with("/oauth/callback"))
        .expect("replayed");
    assert_eq!(replayed.path, "/oauth/callback?state=st-1&error=access_denied");
    assert!(
        replayed.headers.get("authorization").is_none(),
        "the callback needs no admin token"
    );
}

#[tokio::test]
async fn a_finished_callback_records_the_connection_and_pushes_the_agents() {
    let t = T::new().await;
    let fw = t.make();
    run(
        &fw,
        "propose",
        json!({"changeId": "c16", "kind": "oauth_connect", "service": "github", "serviceName": "GitHub",
        "label": "Acme", "clientId": "Iv1.abc", "agents": [agent_a()], "secret": {"clientSecret": "shh"}}),
    )
    .await;
    {
        let mut oc = t.oc.lock().expect("lock");
        oc.connections.push(
            json!({"id": "rc-github-1", "service": "github", "alias": "acme", "status": "active",
            "authType": "oauth2", "accountLabel": "acme-org"}),
        );
        oc.request_status = json!({"status": "connected", "appId": "rc-github-1"});
    }
    let r = run(&fw, "callback", json!({"state": "st-1", "code": "code-1"})).await;
    assert_eq!(r.status, "applied", "{r:?}");
    let d = data(&r);
    assert_eq!(d["summary"], "Connect GitHub (Acme) to marcobot");
    assert_eq!(d["connection"]["label"], "Acme");
    assert_eq!(d["connection"]["authType"], "oauth2");
    assert_eq!(d["applied"], json!(["vm-a"]));
    assert_eq!(t.calls()[0].2["gateway"]["token"], "oct_tok-1");
    // The state is used once.
    let again = run(&fw, "callback", json!({"state": "st-1", "code": "code-1"})).await;
    assert_eq!(again.status, "expired");
}

#[tokio::test]
async fn a_run_record_is_attributed_to_the_agent_by_its_token_id() {
    let t = T::new().await;
    let fw = t.make();
    run(&fw, "propose", json!({"changeId": "c1", "kind": "connect", "service": "gitea", "serviceName": "Gitea", "agents": [agent_a()], "secret": {"apiKey": "pat-1"}})).await;
    assert_eq!(fw.agent_for_token("tok-1").as_deref(), Some("vm-a"));
    let gate = fw.agent_for_runtime_token("oct_tok-1").expect("known");
    assert_eq!(gate.vm_id, "vm-a");
    assert_eq!(gate.private_ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(
        gate.connections[0].label.as_deref(),
        Some("acct(t-1)"),
        "the account when nobody named it"
    );
    assert!(fw.agent_for_runtime_token("oct_other").is_none());
}

#[tokio::test]
async fn with_no_confirmation_codes_on_this_build_a_change_is_refused_never_applied() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    // Code routes but no consent codes: still not known who can be asked.
    app.contracts.code_routes.set(Arc::new(Routes(Mutex::new(vec![]))));
    let oc: Arc<Mutex<Oc>> = Arc::default();
    let o = oc.clone();
    let server = FakeServer::start(move |g| oc_answer(&o, g)).await;
    let fw = ConnectorsFirewall::new(
        &app,
        dir.path().join("connectors.enc"),
        ConnectorRuntime::new(&server.url(), "admin-secret"),
        "http://10.0.0.2:3900".into(),
    );
    let r = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "kind": "connect", "service": "gitea", "serviceName": "Gitea",
        "agents": [agent_a()], "secret": {"apiKey": "pat-1"}}),
    )
    .await;
    assert_eq!((r.ok, r.status.as_str()), (false, "failed"));
    assert_eq!(r.message.as_deref(), Some(crate::integrations::codes::NOT_READY));
    assert_eq!(
        data(&r),
        json!({"changeId": "c1", "summary": "Connect Gitea to marcobot"})
    );
    assert!(server.got().is_empty(), "nothing reached the runtime");
}
