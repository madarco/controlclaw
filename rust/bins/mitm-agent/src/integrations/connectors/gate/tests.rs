//! `connector-gate.test.ts`: the gate with real sockets, a fake OpenConnector behind it, and the
//! Integrations rules, content rules and permission path as small stand-ins.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::integrations::apps_rules::schema::{AppMatch, AppRule, Fit, decide_app, decide_app_judged, seeded_app_rule};
use crate::integrations::call_asks::ASKS_PER_AGENT;
use crate::integrations::connectors::firewall::{GateAgent, GateConnection};
use crate::integrations::connectors::parse::GATE_MAX_BODY;
use crate::integrations::testing::{Answer, FakeContent, FakeServer, Got};

const CATALOG: &[(&str, &str, &str)] = &[
    ("github.get_user", "github", "read"),
    ("github.create_issue", "github", "write"),
    ("github.delete_repo", "github", "destructive"),
    ("notion.search", "notion", "read"),
    // No kind in the catalog: counts as destructive.
    ("github.mystery", "github", ""),
];

#[derive(Default)]
struct Up {
    sse: AtomicBool,
    slow_ms: AtomicU64,
    broken_list: AtomicBool,
    runs: AtomicU32,
    result: Mutex<Value>,
}

fn rpc(id: &Value, payload: Value) -> Value {
    let ok = payload["ok"] == true;
    let mut result = json!({"content": [{"type": "text", "text": crate::integrations::js::stringify_pretty(&payload)}], "structuredContent": payload});
    if !ok {
        result["isError"] = json!(true);
    }
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn catalog() -> Value {
    Value::Array(
        CATALOG
            .iter()
            .map(|(id, s, k)| json!({"id": id, "service": s, "operationType": k}))
            .collect(),
    )
}

fn upstream(up: &Up, g: &Got) -> Answer {
    let path = g.path.split('?').next().unwrap_or_default();
    let mcp_sse = up.sse.load(Ordering::SeqCst) && path == "/mcp";
    let json_ = |status: u16, doc: Value| {
        let text = serde_json::to_string(&doc).expect("json");
        if mcp_sse {
            return Answer::typed(
                status,
                "text/event-stream",
                format!("event: message\nid: 1\ndata: {text}\n\n").into_bytes(),
            );
        }
        Answer::typed(status, "application/json", text.into_bytes())
    };
    if path == "/v1/actions/search" && up.broken_list.load(Ordering::SeqCst) {
        return Answer::typed(200, "text/html", b"<html>not a list</html>".to_vec());
    }
    if path == "/v1/actions/search" {
        return json_(200, json!({"success": true, "data": catalog()}));
    }
    let result = up.result.lock().expect("lock").clone();
    if let Some(raw) = path.strip_prefix("/v1/actions/") {
        let id = crate::integrations::connectors::parse::decode_uri_component(raw).unwrap_or_default();
        if g.method == "GET" {
            if id == "github.flaky" {
                return json_(500, json!({"success": false, "errorCode": "internal_error"}));
            }
            return match CATALOG.iter().find(|(i, _, _)| *i == id) {
                Some((i, s, k)) => json_(
                    200,
                    json!({"success": true, "data": {"id": i, "service": s, "operationType": k}}),
                ),
                None => json_(404, json!({"success": false, "errorCode": "unknown_action"})),
            };
        }
        let n = up.runs.fetch_add(1, Ordering::SeqCst) + 1;
        let mut a = json_(
            200,
            json!({"success": true, "message": "OK", "data": result, "meta": {"executionId": format!("exe-{n}"), "actionId": raw}}),
        );
        a.delay_ms = up.slow_ms.load(Ordering::SeqCst);
        return a;
    }
    if path.starts_with("/v1/proxy/") {
        up.runs.fetch_add(1, Ordering::SeqCst);
        return json_(200, json!({"success": true, "data": {"status": 200, "body": result}}));
    }
    if path == "/mcp" {
        let msg: Value = serde_json::from_slice(&g.body).unwrap_or(Value::Null);
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let name = msg["params"]["name"].as_str().unwrap_or_default();
        if msg["method"] == "tools/call" && name == "execute_action" {
            let n = up.runs.fetch_add(1, Ordering::SeqCst) + 1;
            return json_(
                200,
                rpc(
                    &id,
                    json!({"ok": true, "data": result, "executionId": format!("exe-{n}"), "auditPersisted": true}),
                ),
            );
        }
        if msg["method"] == "tools/call" && name == "search_actions" {
            return json_(200, rpc(&id, json!({"ok": true, "data": catalog()})));
        }
        if msg["method"] == "tools/call" && name == "get_action_guide" {
            let aid = msg["params"]["arguments"]["actionId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let kind = CATALOG.iter().find(|(i, _, _)| *i == aid).map(|(_, _, k)| *k);
            return json_(
                200,
                rpc(
                    &id,
                    json!({"ok": true, "data": {"capability": {"operationType": kind}, "markdown": format!("# {aid}")}}),
                ),
            );
        }
        return json_(
            200,
            json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "execute_action"}]}}),
        );
    }
    json_(200, json!({"success": true, "data": []}))
}

struct TestRules {
    rules: Mutex<Vec<AppRule>>,
    fits: Mutex<Fit>,
}

impl GateRules for TestRules {
    fn decide(&self, call: &AppCall, connections: &[String]) -> Result<AppDecision, RulesUnknown> {
        Ok(decide_app(&self.rules.lock().expect("lock"), call, connections))
    }
    fn decide_judged(&self, call: AppCall, connections: Vec<String>) -> BoxFuture<Result<AppDecision, RulesUnknown>> {
        let rules = self.rules.lock().expect("lock").clone();
        let fit = *self.fits.lock().expect("lock");
        Box::pin(async move {
            let judge = move |_: &AppRule, _: &AppCall| -> BoxFuture<Fit> { Box::pin(async move { fit }) };
            Ok(decide_app_judged(&rules, &call, &connections, Some(&judge)).await)
        })
    }
}

#[derive(Default)]
struct TestAsks {
    asks: Mutex<Vec<Value>>,
    grants: Mutex<HashSet<String>>,
}

impl crate::integrations::call_asks::Asks for TestAsks {
    fn ask(&self, rec: Value) -> Result<(), String> {
        self.asks.lock().expect("lock").push(rec);
        Ok(())
    }
    fn granted(&self, id: &str) -> bool {
        self.grants.lock().expect("lock").contains(id)
    }
    fn consume(&self, id: &str) {
        self.grants.lock().expect("lock").remove(id);
    }
}

fn agent(vm: &str, ip: &str, connections: Vec<GateConnection>) -> GateAgent {
    GateAgent {
        vm_id: vm.into(),
        private_ip: Some(ip.into()),
        connections,
    }
}

fn work() -> GateConnection {
    GateConnection {
        id: "conn-gh".into(),
        service: "github".into(),
        alias: "work".into(),
        label: Some("Work GitHub".into()),
    }
}

fn personal() -> GateConnection {
    GateConnection {
        id: "conn-gh2".into(),
        service: "github".into(),
        alias: "personal".into(),
        label: None,
    }
}

struct T {
    dir: tempfile::TempDir,
    up: Arc<Up>,
    server: FakeServer,
    rules: Arc<TestRules>,
    content: Arc<FakeContent>,
    asks: Arc<TestAsks>,
    base: String,
    http: reqwest::Client,
}

fn rule_with(f: impl FnOnce(&mut AppRule)) -> AppRule {
    let mut r = seeded_app_rule();
    f(&mut r);
    r
}

struct Opts {
    resolve: Option<Resolve>,
    rules: Option<Arc<dyn Fn() -> RulesNow + Send + Sync>>,
    content: Option<Arc<dyn Fn() -> ContentNow + Send + Sync>>,
    asks: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            resolve: None,
            rules: None,
            content: None,
            asks: true,
        }
    }
}

impl T {
    async fn new() -> Self {
        let up = Arc::new(Up::default());
        *up.result.lock().expect("lock") = json!({"title": "a fine issue"});
        let u = up.clone();
        let server = FakeServer::start(move |g| upstream(&u, g)).await;
        let mut t = Self {
            dir: tempfile::tempdir().expect("dir"),
            up,
            server,
            rules: Arc::new(TestRules {
                rules: Mutex::new(vec![seeded_app_rule()]),
                fits: Mutex::new(Fit::Fits),
            }),
            content: Arc::new(FakeContent::default()),
            asks: Arc::new(TestAsks::default()),
            base: String::new(),
            http: reqwest::Client::new(),
        };
        std::fs::write(t.log_path(), "").expect("log");
        t.base = t.gate(Opts::default()).await;
        t
    }

    fn log_path(&self) -> std::path::PathBuf {
        self.dir.path().join("connector-calls.jsonl")
    }

    /// A gate on its own port, over the same upstream, call log and asks.
    async fn gate(&self, o: Opts) -> String {
        let rules = self.rules.clone();
        let content = self.content.clone();
        let resolve = o.resolve.unwrap_or_else(|| {
            Arc::new(|t: &str| match t {
                "oct_a" => Some(agent("vm-a", "127.0.0.1", vec![work()])),
                "oct_b" => Some(agent("vm-b", "10.9.9.9", vec![])),
                "oct_c" => Some(agent("vm-c", "127.0.0.1", vec![work()])),
                _ => None,
            })
        });
        let gate = Gate::new(GateOptions {
            target: ("127.0.0.1".into(), self.server.port),
            resolve,
            rules: o
                .rules
                .unwrap_or_else(|| Arc::new(move || RulesNow::On(rules.clone() as Arc<dyn GateRules>))),
            content: o
                .content
                .unwrap_or_else(|| Arc::new(move || ContentNow::On(content.clone() as Arc<dyn AppContent>))),
            asks: o
                .asks
                .then(|| self.asks.clone() as Arc<dyn crate::integrations::call_asks::Asks>),
            locked: Arc::new(|_| false),
            log_path: Some(self.log_path()),
            ask_state_path: Some(self.dir.path().join("asks.json")),
            app_name: None,
            grant_wait_ms: 0,
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        tokio::spawn(cc_http::serve(l, Arc::new(gate.router())));
        format!("http://127.0.0.1:{port}")
    }

    fn set_rules(&self, r: Vec<AppRule>) {
        *self.rules.rules.lock().expect("lock") = r;
    }

    async fn post_to(&self, base: &str, path: &str, body: &Value, token: &str, ctype: &str) -> reqwest::Response {
        let body = match body {
            Value::String(s) => s.clone(),
            v => serde_json::to_string(v).expect("json"),
        };
        self.http
            .post(format!("{base}{path}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", ctype)
            .body(body)
            .send()
            .await
            .expect("send")
    }

    async fn post(&self, path: &str, body: Value) -> reqwest::Response {
        self.post_to(&self.base, path, &body, "oct_a", "application/json").await
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.http
            .get(format!("{}{path}", self.base))
            .header("authorization", "Bearer oct_a")
            .send()
            .await
            .expect("send")
    }

    async fn mcp_call(&self, name: &str, args: Value) -> reqwest::Response {
        self.post(
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}),
        )
        .await
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log_path())
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("line"))
            .collect()
    }

    fn last(&self) -> Value {
        self.records().pop().expect("a line")
    }

    fn received(&self) -> Vec<Got> {
        self.server.got()
    }

    fn posts(&self) -> usize {
        self.received().iter().filter(|g| g.method == "POST").count()
    }

    fn asks(&self) -> Vec<Value> {
        self.asks.asks.lock().expect("lock").clone()
    }

    fn grant(&self, id: &str) {
        self.asks.grants.lock().expect("lock").insert(id.to_string());
    }
}

/// A tool result's payload, with `isError`.
async fn payload_of(res: reqwest::Response) -> Value {
    let doc: Value = res.json().await.expect("json");
    let mut p = doc["result"]["structuredContent"].clone();
    p["isError"] = json!(doc["result"]["isError"] == true);
    p
}

async fn pid_of(res: reqwest::Response) -> String {
    let doc: Value = res.json().await.expect("json");
    doc["data"]["permission_id"].as_str().expect("pid").to_string()
}

#[tokio::test]
async fn an_allowed_mcp_call_goes_through_as_it_was_sent_and_is_recorded_with_its_run_id() {
    let t = T::new().await;
    let sent = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "execute_action",
        "arguments": {"actionId": "github.create_issue", "input": {"title": "hi"}, "connectionName": "work"}}});
    let p = payload_of(t.post("/mcp", sent.clone()).await).await;
    assert_eq!(p["ok"], true);
    let call = t.received().into_iter().find(|r| r.path == "/mcp").expect("forwarded");
    assert_eq!(
        call.body,
        serde_json::to_vec(&sent).expect("json"),
        "the bytes the gate read, exactly"
    );
    assert!(call.headers.get("accept-encoding").is_none(), "asked for uncompressed");
    assert_eq!(call.headers["authorization"], "Bearer oct_a");
    let rec = t.last();
    assert_eq!(rec["source"], "connector_call");
    assert_eq!(rec["decision"], "allowed");
    assert_eq!(rec["by"], "default");
    assert_eq!(rec["action_id"], "github.create_issue");
    assert_eq!(rec["operation"], "write");
    assert_eq!(rec["connection_id"], "conn-gh", "the agent's one GitHub connection");
    assert!(rec["run_id"].as_str().expect("run").starts_with("exe-"));
    assert_eq!(rec["ok"], true);
    assert!(!rec.to_string().contains("hi\""), "never the input");
    let keys: Vec<&String> = rec.as_object().expect("o").keys().collect();
    assert_eq!(
        keys,
        [
            "source",
            "id",
            "ts",
            "duration_ms",
            "vm_id",
            "route",
            "service",
            "connection_id",
            "action_id",
            "operation",
            "method",
            "path",
            "decision",
            "by",
            "rule",
            "run_id",
            "ok",
            "http_status",
            "error_code"
        ],
        "the TS's order"
    );
}

#[tokio::test]
async fn a_blocked_action_is_not_run_and_the_agent_is_told_why_in_a_tool_result() {
    let t = T::new().await;
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-delete".into();
        r.name = "No deleting repos".into();
        r.match_ = AppMatch::Actions {
            actions: vec!["github.delete_*".into()],
        };
        r.then = AppEffect::Block;
        r.service = Some("github".into());
    })]);
    let p = payload_of(
        t.mcp_call(
            "execute_action",
            json!({"actionId": "github.delete_repo", "input": {"repo": "x"}}),
        )
        .await,
    )
    .await;
    assert_eq!(p["isError"], true);
    assert_eq!(p["error"]["code"], "action_blocked");
    assert!(p["error"]["message"].as_str().expect("m").contains("No deleting repos"));
    assert!(
        !t.received().iter().any(|r| r.path == "/mcp"),
        "OpenConnector never saw it"
    );
    let last = t.last();
    assert_eq!(
        (last["decision"].clone(), last["rule"].clone()),
        (json!("blocked"), json!("No deleting repos"))
    );
    assert_eq!(last["rule_id"], "no-delete", "the rule's id, for the console's counts");
}

#[tokio::test]
async fn a_blocked_action_is_missing_from_listings_and_its_guide_is_refused() {
    let t = T::new().await;
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-delete".into();
        r.name = "No deleting".into();
        r.then = AppEffect::Block;
    })]);
    let search = payload_of(t.mcp_call("search_actions", json!({"query": "repo"})).await).await;
    let ids: Vec<&str> = search["data"]
        .as_array()
        .expect("list")
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(!ids.contains(&"github.delete_repo"));
    assert!(ids.contains(&"github.create_issue"));
    let http: Value = t.get("/v1/actions/search?q=repo").await.json().await.expect("json");
    let mut ids: Vec<&str> = http["data"]
        .as_array()
        .expect("list")
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    ids.sort();
    assert_eq!(ids, ["github.create_issue", "github.get_user", "notion.search"]);
    let guide = payload_of(
        t.mcp_call("get_action_guide", json!({"actionId": "github.delete_repo"}))
            .await,
    )
    .await;
    assert_eq!(guide["error"]["code"], "action_blocked");
    assert_eq!(t.get("/v1/actions/github.delete_repo").await.status(), 403);
    let tools: Value = t
        .post("/mcp", json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(
        tools["result"]["tools"].as_array().expect("tools").len(),
        1,
        "tools/list is passed as it is"
    );
}

#[tokio::test]
async fn a_rule_with_a_sentence_decides_calls_by_their_input_and_never_takes_an_action_off_a_list() {
    let t = T::new().await;
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-old-deletes".into();
        r.name = "No deleting old repos".into();
        r.sentence = Some("Block deleting repositories named old.".into());
        r.then = AppEffect::Block;
    })]);
    let search = payload_of(t.mcp_call("search_actions", json!({"query": "repo"})).await).await;
    assert!(
        search["data"]
            .as_array()
            .expect("list")
            .iter()
            .any(|a| a["id"] == "github.delete_repo")
    );
    let blocked = t
        .post("/v1/actions/github.delete_repo", json!({"input": {"repo": "old"}}))
        .await;
    assert_eq!(blocked.status(), 403);
    assert_eq!(t.last()["rule"], "No deleting old repos");
    *t.rules.fits.lock().expect("lock") = Fit::No;
    let passed = t
        .post("/v1/actions/github.delete_repo", json!({"input": {"repo": "new"}}))
        .await;
    assert_eq!(
        passed.status(),
        200,
        "does not fit: the next rules decide, and none does"
    );
}

#[tokio::test]
async fn an_ask_rule_asks_once_an_approval_runs_that_one_call_and_the_next_one_asks_again() {
    let t = T::new().await;
    let first = t
        .post("/v1/actions/github.delete_repo", json!({"input": {"repo": "old"}}))
        .await;
    assert_eq!(first.status(), 451);
    let body: Value = first.json().await.expect("json");
    assert_eq!(body["errorCode"], "app_needs_approval");
    let asks = t.asks();
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0]["kind"], "app_call");
    assert_eq!(asks[0]["action"], "github.delete_repo");
    assert_eq!(asks[0]["connection"], "Work GitHub");
    let scope = asks[0]["scope"].as_str().expect("scope");
    assert!(
        regex::Regex::new(r"^APP github/work github\.delete_repo #[0-9a-f]{12}$")
            .expect("re")
            .is_match(scope),
        "{scope}"
    );
    assert_eq!(asks[0]["permission_id"], body["data"]["permission_id"]);
    assert_eq!(
        asks[0].as_object().expect("o").keys().collect::<Vec<_>>(),
        [
            "summary",
            "service",
            "action",
            "operation",
            "connection",
            "rule",
            "permission_id",
            "vm_id",
            "scope",
            "kind",
            "expires_at"
        ]
    );
    assert_eq!(t.last()["decision"], "asked");
    // The same call again before anyone answered: the same ask, not a second card.
    assert_eq!(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"repo": "old"}}))
            .await
            .status(),
        451
    );
    assert_eq!(t.asks().len(), 1);
    let pid = body["data"]["permission_id"].as_str().expect("pid").to_string();
    t.grant(&pid);
    let other = t
        .post("/v1/actions/github.delete_repo", json!({"input": {"repo": "another"}}))
        .await;
    assert_eq!(other.status(), 451, "an approval is for the input it was asked with");
    let asked_line = t
        .records()
        .into_iter()
        .find(|r| r["decision"] == "asked" && r["action_id"] == "github.delete_repo")
        .expect("asked");
    let ok = t
        .post("/v1/actions/github.delete_repo", json!({"input": {"repo": "old"}}))
        .await;
    assert_eq!(ok.status(), 200);
    assert_eq!(
        t.last()["follows"],
        asked_line["id"],
        "the run names the ask's line it replaces"
    );
    assert_eq!(asked_line["rule_id"], "ask-destructive");
    assert_eq!(t.last()["rule_id"], "ask-destructive");
    assert!(t.asks.grants.lock().expect("lock").is_empty(), "used up");
    assert_eq!(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"repo": "old"}}))
            .await
            .status(),
        451
    );
    let ids: Vec<Value> = t.asks().iter().map(|a| a["permission_id"].clone()).collect();
    assert_eq!(
        ids.iter().collect::<HashSet<_>>().len(),
        ids.len(),
        "a new id each time"
    );
}

#[tokio::test]
async fn over_mcp_an_ask_is_a_tool_result_that_names_cc_perm() {
    let t = T::new().await;
    let p = payload_of(
        t.mcp_call("execute_action", json!({"actionId": "github.delete_repo", "input": {}}))
            .await,
    )
    .await;
    assert_eq!(p["error"]["code"], "app_needs_approval");
    assert!(
        regex::Regex::new(r"cc-perm perm_[0-9a-f]{32}")
            .expect("re")
            .is_match(p["error"]["message"].as_str().expect("m"))
    );
    assert!(p["permission_id"].as_str().expect("pid").starts_with("perm_"));
}

#[tokio::test]
async fn a_content_rule_stops_an_input_before_it_leaves() {
    let t = T::new().await;
    let p = payload_of(
        t.mcp_call(
            "execute_action",
            json!({"actionId": "github.create_issue", "input": {"body": "here is SECRET-OUT"}}),
        )
        .await,
    )
    .await;
    assert_eq!(p["error"]["code"], "blocked_by_content_rule");
    assert_eq!(
        p["error"]["message"],
        "Blocked by your organization's rules: it carries a secret. The call was not made."
    );
    assert!(!t.received().iter().any(|r| r.path == "/mcp"));
    assert_eq!(
        t.content.lines.lock().expect("lock").last().cloned(),
        Some(("no-secrets".into(), "out".into(), "block".into()))
    );
    assert_eq!(t.last()["by"], "content_rule");
}

#[tokio::test]
async fn a_content_hold_queues_the_call_says_so_plainly_and_runs_it_on_send() {
    let t = T::new().await;
    let res = t
        .post(
            "/v1/actions/github.create_issue",
            json!({"input": {"body": "HOLD-ME please"}}),
        )
        .await;
    assert_eq!(res.status(), 202);
    let body: Value = res.json().await.expect("json");
    assert_eq!(body["errorCode"], "queued_for_approval");
    let m = body["message"].as_str().expect("m");
    assert!(m.contains("will not receive its result") && m.contains("Do not call it again"));
    assert_eq!(t.posts(), 0, "not run yet");
    let held = t.last();
    assert_eq!(held["decision"], "held");
    t.content.send(0).await.expect("sent");
    let last = t.last();
    assert_eq!(last["follows"], held["id"]);
    assert_eq!(
        t.received()
            .iter()
            .filter(|r| r.method == "POST" && r.path == "/v1/actions/github.create_issue")
            .count(),
        1,
        "run on Send"
    );
    assert_eq!(last["released"], true);
    assert!(last["run_id"].as_str().expect("run").starts_with("exe-"));
    // Over MCP it is a result, not an error.
    let p = payload_of(
        t.mcp_call(
            "execute_action",
            json!({"actionId": "github.create_issue", "input": {"body": "HOLD-ME"}}),
        )
        .await,
    )
    .await;
    assert_eq!(p["isError"], false);
    assert_eq!(p["status"], "queued_for_approval");
}

#[tokio::test]
async fn a_result_is_checked_before_the_agent_gets_it_and_a_stopped_one_is_replaced() {
    let t = T::new().await;
    *t.up.result.lock().expect("lock") = json!({"title": "SECRET-IN here"});
    let p = payload_of(
        t.mcp_call("execute_action", json!({"actionId": "github.get_user", "input": {}}))
            .await,
    )
    .await;
    assert_eq!(p["error"]["code"], "result_stopped_by_content_rule");
    assert!(!p.to_string().contains("SECRET-IN"));
    assert!(p["executionId"].as_str().expect("id").starts_with("exe-"));
    assert_eq!(t.last()["decision"], "blocked");
    assert!(t.last()["run_id"].as_str().expect("run").starts_with("exe-"));
    let http = t.post("/v1/actions/github.get_user", json!({"input": {}})).await;
    assert_eq!(http.status(), 403);
    assert!(!http.text().await.expect("text").contains("SECRET-IN"));
}

#[tokio::test]
async fn an_sse_answer_is_read_event_by_event() {
    let t = T::new().await;
    t.up.sse.store(true, Ordering::SeqCst);
    *t.up.result.lock().expect("lock") = json!({"title": "SECRET-IN"});
    let res = t
        .mcp_call("execute_action", json!({"actionId": "github.get_user", "input": {}}))
        .await;
    assert!(
        res.headers()["content-type"]
            .to_str()
            .expect("ct")
            .contains("event-stream")
    );
    let events = parse_sse(&res.text().await.expect("text"));
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].fields,
        [
            ("event".to_string(), "message".to_string()),
            ("id".to_string(), "1".to_string())
        ]
    );
    let doc: Value = serde_json::from_str(events[0].data.as_deref().expect("data")).expect("json");
    assert_eq!(
        doc["result"]["structuredContent"]["error"]["code"],
        "result_stopped_by_content_rule"
    );
    *t.up.result.lock().expect("lock") = json!({"title": "fine"});
    let ok = parse_sse(
        &t.mcp_call("execute_action", json!({"actionId": "github.get_user", "input": {}}))
            .await
            .text()
            .await
            .expect("text"),
    );
    assert!(ok[0].data.as_deref().expect("data").contains("fine"));
}

#[tokio::test]
async fn a_body_that_does_not_parse_is_refused_never_forwarded() {
    let t = T::new().await;
    assert_eq!(t.post("/mcp", json!("{not json")).await.status(), 400);
    assert_eq!(
        t.post("/v1/actions/github.create_issue", json!("[1,2")).await.status(),
        400
    );
    let batch = t
        .post("/mcp", json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_action", "arguments": {"actionId": "github.get_user"}}}]))
        .await;
    assert_eq!(batch.status(), 400, "one call per request");
    let body: Value = batch.json().await.expect("json");
    assert_eq!(
        body,
        json!({"success": false, "message": "The firewall could not read this request: send one tool call per request.", "errorCode": "invalid_input"})
    );
    assert!(t.received().is_empty());
    assert_eq!(
        (t.last()["by"].clone(), t.last()["rule"].clone()),
        (json!("gate"), json!("malformed"))
    );
    // Oversize, and named two different ways.
    let big = json!({"input": {"body": "x".repeat(GATE_MAX_BODY + 10)}}).to_string();
    assert_eq!(
        t.post("/v1/actions/github.create_issue", Value::String(big))
            .await
            .status(),
        413
    );
    assert_eq!(
        t.post(
            "/v1/actions/github.get_user?connectionName=personal",
            json!({"input": {}, "connectionName": "work"})
        )
        .await
        .status(),
        400
    );
    // A call sent as anything but JSON.
    let plain = t
        .post_to(
            &t.base,
            "/v1/actions/github.create_issue",
            &json!({"input": {}}),
            "oct_a",
            "text/plain",
        )
        .await;
    assert_eq!(plain.status(), 400);
    assert!(t.received().is_empty());
}

#[tokio::test]
async fn proxy_calls_are_matched_by_method_and_path_decoded_and_without_case() {
    let t = T::new().await;
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-admin".into();
        r.name = "No admin API".into();
        r.service = Some("github".into());
        r.match_ = AppMatch::Proxy {
            method: None,
            path: Some("/admin/".into()),
        };
        r.then = AppEffect::Block;
    })]);
    let blocked = t
        .post(
            "/v1/proxy/github",
            json!({"endpoint": "/admin/users?x=1", "method": "GET"}),
        )
        .await;
    assert_eq!(blocked.status(), 403);
    assert_eq!(t.last()["path"], "/admin/users", "no query");
    assert_eq!(t.last()["method"], "GET");
    assert_eq!(
        t.post("/v1/proxy/github", json!({"endpoint": "/repos/a/b", "method": "GET"}))
            .await
            .status(),
        200
    );
    assert_eq!(
        t.post(
            "/v1/proxy/github",
            json!({"endpoint": "/repos/../admin/users", "method": "GET"})
        )
        .await
        .status(),
        400
    );
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-admin".into();
        r.name = "No admin API".into();
        r.service = Some("github".into());
        r.match_ = AppMatch::Proxy {
            method: None,
            path: Some("/admin".into()),
        };
        r.then = AppEffect::Block;
    })]);
    assert_eq!(
        t.post(
            "/v1/proxy/github",
            json!({"endpoint": "/%61dmin/users", "method": "GET"})
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        t.post("/v1/proxy/github", json!({"endpoint": "/ADMIN", "method": "GET"}))
            .await
            .status(),
        403
    );
    assert_eq!(
        t.post("/v1/proxy/github", json!({"endpoint": "/admin-notes", "method": "GET"}))
            .await
            .status(),
        200
    );
    assert_eq!(
        t.post("/v1/proxy/github", json!({"endpoint": "/a%2fb", "method": "GET"}))
            .await
            .status(),
        400
    );
    // The seeded rule asks before a DELETE, as before a destructive action.
    t.set_rules(vec![seeded_app_rule()]);
    assert_eq!(
        t.post(
            "/v1/proxy/github",
            json!({"endpoint": "/repos/a/b", "method": "DELETE"})
        )
        .await
        .status(),
        451
    );
}

#[tokio::test]
async fn an_unknown_token_is_refused_and_a_token_from_another_boxs_address_too() {
    let t = T::new().await;
    let nope = t
        .post_to(&t.base, "/mcp", &json!({}), "oct_nope", "application/json")
        .await;
    assert_eq!(nope.status(), 401);
    assert_eq!(
        nope.json::<Value>().await.expect("json"),
        json!({"success": false, "message": "This firewall does not know that token.", "errorCode": "unauthorized"})
    );
    assert_eq!(
        t.post_to(&t.base, "/mcp", &json!({}), "oct_b", "application/json")
            .await
            .status(),
        403
    );
    assert!(t.received().is_empty());
    assert_eq!(
        (t.last()["vm_id"].clone(), t.last()["rule"].clone()),
        (json!("vm-b"), json!("wrong address"))
    );
    // Anything but the execution routes is not there at all; health needs no token.
    let admin = t
        .http
        .get(format!("{}/api/runtime-tokens", t.base))
        .send()
        .await
        .expect("send");
    assert_eq!(admin.status(), 404);
    assert_eq!(
        t.http
            .get(format!("{}/v1/health", t.base))
            .send()
            .await
            .expect("send")
            .status(),
        200
    );
}

#[tokio::test]
async fn rules_that_cannot_be_read_refuse_every_call() {
    let t = T::new().await;
    let base = t
        .gate(Opts {
            rules: Some(Arc::new(|| RulesNow::Unknown)),
            ..Opts::default()
        })
        .await;
    let res = t
        .post_to(
            &base,
            "/v1/actions/github.get_user",
            &json!({}),
            "oct_a",
            "application/json",
        )
        .await;
    assert_eq!(res.status(), 503);
    assert_eq!(res.json::<Value>().await.expect("json")["errorCode"], "rules_loading");
}

#[tokio::test]
async fn a_write_the_gate_does_not_read_is_refused() {
    let t = T::new().await;
    assert_eq!(
        t.post("/v1/actions/github.delete_repo/", json!({"input": {}}))
            .await
            .status(),
        400
    );
    assert_eq!(
        t.post("/v1/proxy/github/x", json!({"endpoint": "/a", "method": "GET"}))
            .await
            .status(),
        400
    );
    let put = t
        .http
        .put(format!("{}/v1/actions/github.delete_repo", t.base))
        .header("authorization", "Bearer oct_a")
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 400);
    assert_eq!(t.received().iter().filter(|r| r.method != "GET").count(), 0);
}

#[tokio::test]
async fn an_action_the_catalog_cannot_be_read_for_is_not_made_and_one_with_no_kind_is_destructive() {
    let t = T::new().await;
    let res = t.post("/v1/actions/github.flaky", json!({"input": {}})).await;
    assert_eq!(res.status(), 502);
    assert_eq!(t.posts(), 0);
    assert_eq!(t.last()["rule"], "catalog unreadable");
    assert_eq!(
        t.post("/v1/actions/github.mystery", json!({"input": {}}))
            .await
            .status(),
        451
    );
    // #488-4: an unknown action is answered here, not forwarded.
    let res = t.post("/v1/actions/github.no_such_thing", json!({"input": {}})).await;
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.expect("json")["errorCode"], "unknown_action");
    let p = payload_of(
        t.mcp_call(
            "execute_action",
            json!({"actionId": "github.no_such_thing", "input": {}}),
        )
        .await,
    )
    .await;
    assert_eq!(p["error"]["code"], "unknown_action");
    assert_eq!(
        t.mcp_call("execute_action", json!({"actionId": "not an id"}))
            .await
            .status(),
        400
    );
    assert_eq!(t.posts(), 0);
}

#[tokio::test]
async fn an_approval_is_not_used_up_by_a_call_refused_after_it_and_survives_a_restart() {
    let t = T::new().await;
    let pid = pid_of(
        t.post(
            "/v1/actions/github.delete_repo",
            json!({"input": {"body": "SECRET-OUT"}}),
        )
        .await,
    )
    .await;
    t.grant(&pid);
    assert_eq!(
        t.post(
            "/v1/actions/github.delete_repo",
            json!({"input": {"body": "SECRET-OUT"}})
        )
        .await
        .status(),
        403
    );
    assert!(t.asks.grants.lock().expect("lock").contains(&pid), "still there");
    let ask = pid_of(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"repo": "x"}}))
            .await,
    )
    .await;
    t.grant(&ask);
    // A second gate on the same state file (a restart) knows the ask.
    let base = t.gate(Opts::default()).await;
    let res = t
        .post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &json!({"input": {"repo": "x"}}),
            "oct_a",
            "application/json",
        )
        .await;
    assert_eq!(res.status(), 200);
    // Asks on disk keep their agent.
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(t.dir.path().join("asks.json")).expect("asks")).expect("json");
    assert!(saved.as_array().expect("list").iter().all(|e| e[1]["vmId"] == "vm-a"));
}

#[tokio::test]
async fn a_held_call_is_checked_again_on_send() {
    let t = T::new().await;
    t.post("/v1/actions/github.create_issue", json!({"input": {"body": "HOLD-ME"}}))
        .await;
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-writes".into();
        r.name = "No writes".into();
        r.match_ = AppMatch::Operation {
            operations: vec![AppOperation::Write],
        };
        r.then = AppEffect::Block;
    })]);
    let e = t.content.send(0).await.expect_err("stopped");
    assert_eq!(e, "an app rule now blocks it (No writes)");
    assert_eq!(t.posts(), 0);
}

#[tokio::test]
async fn one_approval_runs_one_call_even_when_the_same_call_comes_twice_at_once() {
    let t = T::new().await;
    let pid = pid_of(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"repo": "twice"}}))
            .await,
    )
    .await;
    t.grant(&pid);
    let (a, b) = tokio::join!(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"repo": "twice"}})),
        t.post("/v1/actions/github.delete_repo", json!({"input": {"repo": "twice"}}))
    );
    let mut codes = [a.status().as_u16(), b.status().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 451]);
    assert_eq!(
        t.received()
            .iter()
            .filter(|r| r.method == "POST" && r.path == "/v1/actions/github.delete_repo")
            .count(),
        1
    );
}

#[tokio::test]
async fn a_call_approved_and_then_held_runs_on_send() {
    let t = T::new().await;
    let pid = pid_of(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"body": "HOLD-ME"}}))
            .await,
    )
    .await;
    t.grant(&pid);
    assert_eq!(
        t.post("/v1/actions/github.delete_repo", json!({"input": {"body": "HOLD-ME"}}))
            .await
            .status(),
        202
    );
    assert!(
        t.asks.grants.lock().expect("lock").is_empty(),
        "the approval went with the hold"
    );
    t.content.send(0).await.expect("sent");
    assert_eq!(
        t.received()
            .iter()
            .filter(|r| r.method == "POST" && r.path == "/v1/actions/github.delete_repo")
            .count(),
        1
    );
}

#[tokio::test]
async fn over_mcp_the_connection_is_the_tools_connection_name_and_any_other_way_is_refused() {
    let t = T::new().await;
    t.set_rules(vec![rule_with(|r| {
        r.id = "no-personal".into();
        r.name = "Not the personal account".into();
        r.service = Some("github".into());
        r.connection_id = Some("conn-gh2".into());
        r.match_ = AppMatch::Any;
        r.then = AppEffect::Block;
    })]);
    let base = t
        .gate(Opts {
            resolve: Some(Arc::new(|t: &str| {
                (t == "oct_a").then(|| agent("vm-a", "127.0.0.1", vec![work(), personal()]))
            })),
            content: Some(Arc::new(|| ContentNow::Off)),
            ..Opts::default()
        })
        .await;
    let send = |args: Value, extra: Option<(&'static str, &'static str)>, q: &'static str| {
        let mut a = json!({"actionId": "github.get_user", "input": {}});
        for (k, v) in args.as_object().cloned().unwrap_or_default() {
            a[k] = v;
        }
        let mut req = t
            .http
            .post(format!("{base}/mcp{q}"))
            .header("authorization", "Bearer oct_a")
            .header("content-type", "application/json")
            .body(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_action", "arguments": a}}).to_string());
        if let Some((k, v)) = extra {
            req = req.header(k, v);
        }
        req.send()
    };
    assert_eq!(
        payload_of(send(json!({"connectionName": "work"}), None, "").await.expect("send")).await["ok"],
        true
    );
    assert_eq!(
        payload_of(
            send(json!({"connectionName": "personal"}), None, "")
                .await
                .expect("send")
        )
        .await["error"]["code"],
        "action_blocked"
    );
    assert_eq!(
        send(
            json!({"connectionName": "work"}),
            Some(("x-oo-connector-alias", "personal")),
            ""
        )
        .await
        .expect("send")
        .status(),
        400
    );
    assert_eq!(
        send(json!({"connectionName": "work"}), None, "?alias=personal")
            .await
            .expect("send")
            .status(),
        400
    );
    assert_eq!(
        send(json!({"alias": "personal"}), None, "")
            .await
            .expect("send")
            .status(),
        400
    );
    // With several grants and none named, the agent is told its names and where the name goes.
    let p = payload_of(send(json!({}), None, "").await.expect("send")).await;
    assert_eq!(p["isError"], true);
    assert_eq!(p["error"]["code"], "connection_required");
    let m = p["error"]["message"].as_str().expect("m");
    assert!(m.contains(r#""work" (Work GitHub), "personal""#), "{m}");
    assert!(m.contains("next to actionId, not inside input"));
    assert!(!m.contains("Your call had it inside input"));
    assert_eq!(
        p["connections"],
        json!([{"connectionName": "work", "label": "Work GitHub"}, {"connectionName": "personal", "label": null}])
    );
    let inside = payload_of(
        send(json!({"input": {"connectionName": "work"}}), None, "")
            .await
            .expect("send"),
    )
    .await;
    assert!(
        inside["error"]["message"]
            .as_str()
            .expect("m")
            .contains("Your call had it inside input, where it is not read")
    );
    assert_eq!(t.last()["rule"], "no connection named");
}

#[tokio::test]
async fn a_call_that_names_no_connection_runs_on_the_agents_one_grant_named_by_the_gate() {
    let t = T::new().await;
    assert_eq!(
        payload_of(
            t.mcp_call("execute_action", json!({"actionId": "github.get_user", "input": {}}))
                .await
        )
        .await["ok"],
        true
    );
    let mcp: Value =
        serde_json::from_slice(&t.received().into_iter().find(|r| r.path == "/mcp").expect("mcp").body).expect("json");
    assert_eq!(
        mcp["params"]["arguments"],
        json!({"actionId": "github.get_user", "input": {}, "connectionName": "work"})
    );
    assert_eq!(
        t.post("/v1/actions/github.get_user", json!({"input": {"q": 1}}))
            .await
            .status(),
        200
    );
    let sent = t
        .received()
        .into_iter()
        .find(|r| r.path == "/v1/actions/github.get_user" && r.method == "POST")
        .expect("sent");
    assert_eq!(
        String::from_utf8_lossy(&sent.body),
        r#"{"input":{"q":1},"connectionName":"work"}"#
    );
    assert_eq!(
        t.post("/v1/proxy/github", json!({"endpoint": "/user", "method": "GET"}))
            .await
            .status(),
        200
    );
    let proxy: Value = serde_json::from_slice(
        &t.received()
            .into_iter()
            .find(|r| r.path.starts_with("/v1/proxy/"))
            .expect("p")
            .body,
    )
    .expect("json");
    assert_eq!(proxy["connectionName"], "work");
    assert_eq!(t.last()["connection_id"], "conn-gh");
    t.server.clear();
    t.mcp_call("execute_action", json!({"actionId": "notion.search", "input": {}}))
        .await;
    let mcp: Value =
        serde_json::from_slice(&t.received().into_iter().find(|r| r.path == "/mcp").expect("mcp").body).expect("json");
    assert!(mcp["params"]["arguments"].get("connectionName").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn calls_in_flight_are_capped_per_agent_and_an_answer_too_large_to_check_is_not_passed() {
    let t = T::new().await;
    t.set_rules(vec![]);
    t.up.slow_ms.store(300, Ordering::SeqCst);
    let all =
        futures_util::future::join_all((0..10).map(|_| t.post("/v1/actions/github.get_user", json!({"input": {}}))))
            .await;
    let codes: Vec<u16> = all.iter().map(|r| r.status().as_u16()).collect();
    assert_eq!(codes.iter().filter(|c| **c == 429).count(), 2, "{codes:?}");
    t.up.slow_ms.store(0, Ordering::SeqCst);
    *t.up.result.lock().expect("lock") = json!({"blob": "x".repeat(3 * 1024 * 1024)});
    let big = t.post("/v1/actions/github.get_user", json!({"input": {}})).await;
    assert_eq!(big.status(), 502);
    assert!(big.text().await.expect("text").len() < 1000);
}

#[tokio::test]
async fn a_listing_that_cannot_be_read_is_refused_while_rules_apply() {
    let t = T::new().await;
    t.up.broken_list.store(true, Ordering::SeqCst);
    let res = t.get("/v1/actions/search?q=x").await;
    assert_eq!(res.status(), 502);
    assert_eq!(res.json::<Value>().await.expect("json")["errorCode"], "list_unreadable");
}

#[tokio::test]
async fn one_agents_asks_push_out_only_its_own() {
    let t = T::new().await;
    let other = pid_of(
        t.post_to(
            &t.base,
            "/v1/actions/github.delete_repo",
            &json!({"input": {"n": "c"}}),
            "oct_c",
            "application/json",
        )
        .await,
    )
    .await;
    for i in 0..=ASKS_PER_AGENT {
        t.post("/v1/actions/github.delete_repo", json!({"input": {"n": i}}))
            .await;
    }
    let again = pid_of(
        t.post_to(
            &t.base,
            "/v1/actions/github.delete_repo",
            &json!({"input": {"n": "c"}}),
            "oct_c",
            "application/json",
        )
        .await,
    )
    .await;
    assert_eq!(again, other, "vm-c's ask is still there");
}

#[tokio::test]
async fn the_call_log_is_rotated() {
    let t = T::new().await;
    std::fs::write(t.log_path(), "x".repeat(8 * 1024 * 1024 + 1)).expect("log");
    t.post("/v1/actions/github.get_user", json!({"input": {}})).await;
    assert!(t.dir.path().join("connector-calls.jsonl.1").exists());
    assert!(std::fs::read_to_string(t.log_path()).expect("log").len() < 10_000);
}

struct Down;

impl AppContent for Down {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _: &str) -> bool {
        true
    }
    fn body_text(&self, body: &[u8], _: &str) -> Option<String> {
        Some(String::from_utf8_lossy(body).into_owned())
    }
    fn check(&self, _: &str, _: String, _: Option<String>) -> BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        Box::pin(async { Err(ContentError::Failed("down".into())) })
    }
    fn record(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: Map<String, Value>) -> Option<String> {
        None
    }
    fn hold(&self, _: AppHold) -> BoxFuture<Option<String>> {
        Box::pin(async { None })
    }
    fn stopped_here(&self, _: &CheckedRule, _: &str, _: Option<&str>, _: &str, _: Option<&str>) {}
}

#[tokio::test]
async fn a_call_refused_after_finding_its_approval_leaves_it_to_the_retry() {
    let t = T::new().await;
    let broken = Arc::new(AtomicBool::new(true));
    let (b, good) = (broken.clone(), t.content.clone());
    let base = t
        .gate(Opts {
            content: Some(Arc::new(move || {
                if b.load(Ordering::SeqCst) {
                    ContentNow::On(Arc::new(Down))
                } else {
                    ContentNow::On(good.clone() as Arc<dyn AppContent>)
                }
            })),
            ..Opts::default()
        })
        .await;
    let body = json!({"input": {"repo": "e"}});
    let go = || {
        t.post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &body,
            "oct_a",
            "application/json",
        )
    };
    let first = go().await;
    let pid = pid_of(first).await;
    t.grant(&pid);
    let refused = go().await;
    assert_eq!(refused.status(), 403, "the check could not run");
    assert!(refused.text().await.expect("text").contains("the check could not run"));
    broken.store(false, Ordering::SeqCst);
    assert_eq!(go().await.status(), 200, "the retry still has it");
}

#[tokio::test]
async fn an_ask_retried_before_an_answer_is_one_row_and_an_approved_call_that_is_held_replaces_it() {
    let t = T::new().await;
    t.post(
        "/v1/actions/github.delete_repo",
        json!({"input": {"body": "HOLD-ME", "n": "row"}}),
    )
    .await;
    let first = t.last()["id"].clone();
    t.post(
        "/v1/actions/github.delete_repo",
        json!({"input": {"body": "HOLD-ME", "n": "row"}}),
    )
    .await;
    assert_eq!(t.last()["id"], first, "the retry reuses the ask's line");
    let pid = t.asks().last().expect("ask")["permission_id"]
        .as_str()
        .expect("pid")
        .to_string();
    t.grant(&pid);
    assert_eq!(
        t.post(
            "/v1/actions/github.delete_repo",
            json!({"input": {"body": "HOLD-ME", "n": "row"}})
        )
        .await
        .status(),
        202
    );
    assert_eq!(t.last()["decision"], "held");
    assert_eq!(t.last()["follows"], first, "the held row replaces the ask's");
}

#[tokio::test]
async fn no_permission_path_refuses_an_ask_and_an_emergency_stop_refuses_everything() {
    let t = T::new().await;
    let base = t
        .gate(Opts {
            asks: false,
            ..Opts::default()
        })
        .await;
    let res = t
        .post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &json!({"input": {}}),
            "oct_a",
            "application/json",
        )
        .await;
    assert_eq!(res.status(), 403);
    assert!(
        res.text()
            .await
            .expect("text")
            .contains("this firewall cannot ask anyone")
    );
}

#[test]
fn addresses_and_paths() {
    assert!(same_address(Some("::ffff:10.0.0.5"), Some("10.0.0.5")));
    assert!(!same_address(Some(""), Some("")));
    assert!(!same_address(Some("10.0.0.6"), Some("10.0.0.5")));
    for p in [
        "/mcp",
        "/mcp/tools",
        "/v1/health",
        "/v1/apps",
        "/v1/apps/x",
        "/v1/actions",
        "/v1/proxy/x",
    ] {
        assert!(gate_allows(p), "{p}");
    }
    for p in [
        "/",
        "/api/runtime-tokens",
        "/v1/connections",
        "/v1/providers/x/setup",
        "/mcpx",
        "/v1/proxy",
    ] {
        assert!(!gate_allows(p), "{p}");
    }
    assert_eq!(reason_words(" a reason. "), "a reason");
    // A path the runtime would read as another is refused before it is routed.
    for p in [
        "/v1/actions/x\\..\\..\\connections",
        "/v1/actions/%2E%2e/connections",
        "/v1/actions/./x",
    ] {
        assert!(dotted(p), "{p}");
    }
    assert!(!dotted("/v1/actions/run"));
}

struct Slow;

impl AppContent for Slow {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _: &str) -> bool {
        true
    }
    fn body_text(&self, body: &[u8], _: &str) -> Option<String> {
        Some(String::from_utf8_lossy(body).into_owned())
    }
    fn check(&self, _: &str, _: String, _: Option<String>) -> BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Ok(None)
        })
    }
    fn record(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: Map<String, Value>) -> Option<String> {
        None
    }
    fn hold(&self, _: AppHold) -> BoxFuture<Option<String>> {
        Box::pin(async { None })
    }
    fn stopped_here(&self, _: &CheckedRule, _: &str, _: Option<&str>, _: &str, _: Option<&str>) {}
}

#[tokio::test]
async fn an_agent_that_hangs_up_after_its_approval_was_found_leaves_it_to_the_retry() {
    let t = T::new().await;
    let slow = Arc::new(AtomicBool::new(true));
    let (s, good) = (slow.clone(), t.content.clone());
    let base = t
        .gate(Opts {
            content: Some(Arc::new(move || {
                if s.load(Ordering::SeqCst) {
                    ContentNow::On(Arc::new(Slow))
                } else {
                    ContentNow::On(good.clone() as Arc<dyn AppContent>)
                }
            })),
            ..Opts::default()
        })
        .await;
    let body = json!({"input": {"repo": "hangup"}});
    // Asked while the check is quick, approved, then retried while it is slow and dropped.
    slow.store(false, Ordering::SeqCst);
    let pid = pid_of(
        t.post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &body,
            "oct_a",
            "application/json",
        )
        .await,
    )
    .await;
    t.grant(&pid);
    slow.store(true, Ordering::SeqCst);
    let gone = t
        .http
        .post(format!("{base}/v1/actions/github.delete_repo"))
        .header("authorization", "Bearer oct_a")
        .header("content-type", "application/json")
        .body(body.to_string())
        .timeout(std::time::Duration::from_millis(300))
        .send()
        .await;
    assert!(gone.is_err(), "the agent gave up");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    slow.store(false, Ordering::SeqCst);
    let retry = t
        .post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &body,
            "oct_a",
            "application/json",
        )
        .await;
    assert_eq!(retry.status(), 200, "the approval was not left in flight");
}

#[test]
fn odd_addresses_do_not_panic() {
    assert!(!same_address(Some("::fff\u{e9}x"), Some("10.0.0.5")));
    assert!(!same_address(Some("\u{e9}\u{e9}\u{e9}\u{e9}"), Some("x")));
}

#[tokio::test]
async fn with_no_emergency_stop_on_this_build_every_agent_counts_as_stopped() {
    let dir = tempfile::tempdir().expect("dir");
    let app = crate::integrations::testing::app(dir.path());
    let rules = crate::integrations::apps_rules::firewall::AppRulesFirewall::new(&app, dir.path().join("r.enc"));
    let shared = crate::integrations::Shared::new(&app, &crate::integrations::Env, rules);
    assert!((shared.locked)("vm-a"));
}

/// One request written by hand, so nothing on the way normalises its method or path.
async fn raw(base: &str, line: &str, body: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "{line} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer oct_a\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).await.expect("read");
    out
}

#[tokio::test]
async fn a_method_in_another_case_and_an_encoded_dot_segment_are_refused_never_forwarded() {
    let t = T::new().await;
    let body = r#"{"input":{"repo":"x"}}"#;
    let lower = raw(&t.base, "post /v1/actions/github.delete_repo", body).await;
    assert!(lower.starts_with("HTTP/1.1 405"), "{lower}");
    for path in [
        "/v1/actions/%2e%2e/connections",
        "/v1/apps/%2E%2E/%2e%2e/",
        "/v1/apps/%2e/x",
        "/v1/actions/../connections",
        "/v1/apps/./x",
    ] {
        let r = raw(&t.base, &format!("GET {path}"), "").await;
        assert!(r.starts_with("HTTP/1.1 400"), "{path}: {r}");
        assert!(r.contains("the path has a dot segment"), "{path}");
    }
    assert!(t.received().is_empty(), "nothing reached the runtime");
    assert_eq!(t.posts(), 0);
}

struct NoHold;

impl AppContent for NoHold {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _: &str) -> bool {
        true
    }
    fn body_text(&self, body: &[u8], _: &str) -> Option<String> {
        Some(String::from_utf8_lossy(body).into_owned())
    }
    fn check(&self, d: &str, text: String, _: Option<String>) -> BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        let hold = d == "out" && text.contains("HOLD-ME");
        Box::pin(async move {
            Ok(hold.then(|| crate::integrations::testing::rule("hold-it", "hold", "a person checks these")))
        })
    }
    fn record(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: Map<String, Value>) -> Option<String> {
        None
    }
    /// Nobody could be asked; or, `slow`, no answer for a long while.
    fn hold(&self, _: AppHold) -> BoxFuture<Option<String>> {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            None
        })
    }
    fn stopped_here(&self, _: &CheckedRule, _: &str, _: Option<&str>, _: &str, _: Option<&str>) {}
}

#[tokio::test]
async fn an_approval_is_taken_while_the_hold_is_made_and_put_back_when_none_is() {
    let t = T::new().await;
    let use_nohold = Arc::new(AtomicBool::new(false));
    let (u, good) = (use_nohold.clone(), t.content.clone());
    let base = t
        .gate(Opts {
            content: Some(Arc::new(move || {
                if u.load(Ordering::SeqCst) {
                    ContentNow::On(Arc::new(NoHold))
                } else {
                    ContentNow::On(good.clone() as Arc<dyn AppContent>)
                }
            })),
            ..Opts::default()
        })
        .await;
    let body = json!({"input": {"body": "HOLD-ME"}});
    let go = || {
        t.post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &body,
            "oct_a",
            "application/json",
        )
    };
    let pid = pid_of(go().await).await;
    t.grant(&pid);
    // No hold could be made: refused, and the approval is the retry's again.
    use_nohold.store(true, Ordering::SeqCst);
    let (a, b) = tokio::join!(go(), async {
        // A copy that comes while the hold is being made does not find the approval.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        go().await
    });
    assert_eq!(a.status(), 403);
    assert_eq!(b.status(), 451, "the approval was taken while the hold was made");
    assert!(
        t.asks.grants.lock().expect("lock").contains(&pid),
        "the grant is not used up"
    );
    // With nothing holding it now, the retry runs on the same approval.
    use_nohold.store(false, Ordering::SeqCst);
    let fine = json!({"input": {"body": "HOLD-ME"}});
    let _ = fine;
    let held = go().await;
    assert_eq!(held.status(), 202, "held, with the approval going with the hold");
    assert!(
        !t.asks.grants.lock().expect("lock").contains(&pid),
        "used up by the hold"
    );
}

struct SlowHold;

impl AppContent for SlowHold {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _: &str) -> bool {
        true
    }
    fn body_text(&self, body: &[u8], _: &str) -> Option<String> {
        Some(String::from_utf8_lossy(body).into_owned())
    }
    fn check(&self, d: &str, _: String, _: Option<String>) -> BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        let hold = d == "out";
        Box::pin(async move {
            Ok(hold.then(|| crate::integrations::testing::rule("hold-it", "hold", "a person checks these")))
        })
    }
    fn record(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: Map<String, Value>) -> Option<String> {
        None
    }
    fn hold(&self, _: AppHold) -> BoxFuture<Option<String>> {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Some("hold-1".to_string())
        })
    }
    fn stopped_here(&self, _: &CheckedRule, _: &str, _: Option<&str>, _: &str, _: Option<&str>) {}
}

#[tokio::test]
async fn an_agent_that_hangs_up_while_its_hold_is_made_has_the_call_asked_again() {
    let t = T::new().await;
    let slow = Arc::new(AtomicBool::new(false));
    let (s, good) = (slow.clone(), t.content.clone());
    let base = t
        .gate(Opts {
            content: Some(Arc::new(move || {
                if s.load(Ordering::SeqCst) {
                    ContentNow::On(Arc::new(SlowHold))
                } else {
                    ContentNow::On(good.clone() as Arc<dyn AppContent>)
                }
            })),
            ..Opts::default()
        })
        .await;
    let body = json!({"input": {"repo": "slow"}});
    let pid = pid_of(
        t.post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &body,
            "oct_a",
            "application/json",
        )
        .await,
    )
    .await;
    t.grant(&pid);
    slow.store(true, Ordering::SeqCst);
    let gone = t
        .http
        .post(format!("{base}/v1/actions/github.delete_repo"))
        .header("authorization", "Bearer oct_a")
        .header("content-type", "application/json")
        .body(body.to_string())
        .timeout(std::time::Duration::from_millis(300))
        .send()
        .await;
    assert!(gone.is_err(), "the agent gave up");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    slow.store(false, Ordering::SeqCst);
    // The hold may have been made: the approval is not used for a second run; a new ask is filed.
    let again = t
        .post_to(
            &base,
            "/v1/actions/github.delete_repo",
            &body,
            "oct_a",
            "application/json",
        )
        .await;
    assert_eq!(again.status(), 451);
    assert_ne!(pid_of(again).await, pid, "a new ask, not the one already approved");
    assert_eq!(t.posts(), 0, "never run");
}
