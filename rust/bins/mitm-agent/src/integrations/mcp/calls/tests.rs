//! `mcp-rules.test.ts`: the checker every tool call goes through, `tools/list`, and the catalog.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::contracts::IntegrationJudge;
use crate::integrations::apps_rules::schema::{AppMatch, AppRule, decide_app, decide_app_judged, seeded_app_rule};
use crate::integrations::testing;

pub struct Rules(pub Mutex<Vec<AppRule>>);

impl GateRules for Rules {
    fn decide(&self, call: &AppCall, c: &[String]) -> Result<AppDecision, RulesUnknown> {
        Ok(decide_app(&self.0.lock().expect("lock"), call, c))
    }
    fn decide_judged(&self, call: AppCall, c: Vec<String>) -> BoxFuture<Result<AppDecision, RulesUnknown>> {
        let rules = self.0.lock().expect("lock").clone();
        Box::pin(async move { Ok(decide_app_judged(&rules, &call, &c, None).await) })
    }
}

#[derive(Default)]
pub struct AsksLog {
    pub asks: Mutex<Vec<Value>>,
    pub granted: Mutex<Vec<String>>,
}

impl Asks for AsksLog {
    fn ask(&self, rec: Value) -> Result<(), String> {
        self.asks.lock().expect("lock").push(rec);
        Ok(())
    }
    fn granted(&self, id: &str) -> bool {
        self.granted.lock().expect("lock").iter().any(|g| g == id)
    }
    fn consume(&self, id: &str) {
        self.granted.lock().expect("lock").retain(|g| g != id);
    }
}

type Send_ = Box<dyn FnOnce() -> BoxFuture<Result<(), String>> + Send>;

/// Content rules whose answers a test sets.
#[derive(Default)]
pub struct Content {
    pub out: Mutex<Option<CheckedRule>>,
    pub inn: Mutex<Option<CheckedRule>>,
    pub send: Mutex<Option<Send_>>,
}

impl AppContent for Content {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _: &str) -> bool {
        true
    }
    fn body_text(&self, body: &[u8], _: &str) -> Option<String> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let mut out = Vec::new();
        testing::json_strings(&v, &mut out);
        Some(out.join("\n"))
    }
    fn check(
        &self,
        direction: &str,
        _: String,
        _: Option<String>,
    ) -> BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        let r = if direction == "out" {
            self.out.lock()
        } else {
            self.inn.lock()
        }
        .expect("lock")
        .clone();
        Box::pin(async move { Ok(r) })
    }
    fn record(&self, _: &str, _: &str, _: &str, _: Option<&str>, _: Map<String, Value>) -> Option<String> {
        Some("line-1".into())
    }
    fn hold(&self, h: AppHold) -> BoxFuture<Option<String>> {
        *self.send.lock().expect("lock") = Some(h.send);
        Box::pin(async { Some("hold-1".to_string()) })
    }
    fn stopped_here(&self, _: &CheckedRule, _: &str, _: Option<&str>, _: &str, _: Option<&str>) {}
}

pub struct H {
    pub _dir: tempfile::TempDir,
    pub calls: Arc<McpCalls>,
    pub rules: Arc<Rules>,
    pub asks: Arc<AsksLog>,
    pub content: Option<Arc<Content>>,
    pub catalog: Arc<McpCatalog>,
    log: std::path::PathBuf,
}

pub fn rule(f: impl FnOnce(&mut AppRule)) -> AppRule {
    let mut r = seeded_app_rule();
    r.id = "r1".into();
    r.name = "Rule".into();
    r.match_ = AppMatch::Any;
    r.then = AppEffect::Block;
    f(&mut r);
    r
}

pub fn tools(tools: &[&str]) -> AppMatch {
    AppMatch::Tools {
        tools: tools.iter().map(|t| t.to_string()).collect(),
    }
}

pub fn harness(rules: Vec<AppRule>, content: bool) -> H {
    harness_logging(rules, content, None)
}

/// The same, with the call log at `log`.
pub fn harness_logging(rules: Vec<AppRule>, content: bool, log: Option<std::path::PathBuf>) -> H {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    let catalog = McpCatalog::new(&app, dir.path().join("cat.enc"));
    let r = Arc::new(Rules(Mutex::new(rules)));
    let c = content.then(|| Arc::new(Content::default()));
    let asks = Arc::new(AsksLog::default());
    let (r2, c2) = (r.clone(), c.clone());
    let shared = Shared {
        rules: Arc::new(move || RulesNow::On(r2.clone() as Arc<dyn GateRules>)),
        content: Arc::new(move || match &c2 {
            Some(c) => ContentNow::On(c.clone() as Arc<dyn AppContent>),
            None => ContentNow::Off,
        }),
        asks: None,
        locked: Arc::new(|_| false),
    };
    let log = log.unwrap_or_else(|| dir.path().join("calls.jsonl"));
    let calls = McpCalls::new(
        &shared,
        catalog.clone(),
        Some(asks.clone() as Arc<dyn Asks>),
        Some(log.clone()),
        None,
        Some(0),
    );
    H {
        _dir: dir,
        calls,
        rules: r,
        asks,
        content: c,
        catalog,
        log,
    }
}

impl H {
    pub fn read(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

pub fn tool_call(name: &str, args: Value, id: u64) -> Bytes {
    Bytes::from(
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
            .to_string(),
    )
}

pub fn req(body: Bytes) -> McpCallRequest {
    McpCallRequest {
        vm_id: "vm-a".into(),
        host: "mcp.example.com".into(),
        managed: None,
        route: McpRoute::Proxy,
        body,
        replay: None,
    }
}

fn answer(v: &Verdict) -> Value {
    match v {
        Verdict::Answer { body, .. } => serde_json::from_slice(body).expect("json"),
        _ => panic!("not an answer"),
    }
}

#[tokio::test]
async fn other_traffic_passes_and_a_block_refuses_with_the_rules_name_and_one_metadata_line() {
    let h = harness(
        vec![rule(|r| {
            r.name = "No deletes".into();
            r.service = Some("mcp:mcp.example.com".into());
            r.match_ = tools(&["delete_*"]);
        })],
        false,
    );
    let init = Bytes::from(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).to_string());
    assert!(matches!(h.calls.check(req(init)).await, Verdict::Pass));
    assert!(matches!(
        h.calls.check(req(Bytes::from("not json"))).await,
        Verdict::Pass
    ));
    let v = h
        .calls
        .check(req(tool_call("delete_doc", json!({"secret": "do-not-log"}), 7)))
        .await;
    let a = answer(&v);
    assert_eq!(a["result"]["isError"], true);
    assert_eq!(a["result"]["structuredContent"]["error"]["code"], "action_blocked");
    assert!(
        a["result"]["structuredContent"]["error"]["message"]
            .as_str()
            .expect("m")
            .contains("rule: No deletes")
    );
    let line = &h.read()[0];
    assert_eq!(
        [
            &line["route"],
            &line["service"],
            &line["action_id"],
            &line["decision"],
            &line["by"],
            &line["rule"],
            &line["rule_id"]
        ],
        [
            &json!("mcp_proxy"),
            &json!("mcp:mcp.example.com"),
            &json!("delete_doc"),
            &json!("blocked"),
            &json!("app_rule"),
            &json!("No deletes"),
            &json!("r1")
        ]
    );
    assert!(
        !json!(h.read()).to_string().contains("do-not-log"),
        "no argument in the log"
    );
    // A batch with a tool call in it is refused as a batch, whatever else it holds.
    let batch = Bytes::from(json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_doc"}}, {"jsonrpc": "2.0", "id": 2, "method": "ping"}]).to_string());
    assert_eq!(
        answer(&h.calls.check(req(batch)).await)
            .as_array()
            .expect("batch")
            .len(),
        2
    );
    let bare = Bytes::from(json!({"id": 3, "method": "tools/call", "params": {"name": "delete_doc"}}).to_string());
    assert!(
        matches!(h.calls.check(req(bare)).await, Verdict::Answer { .. }),
        "no jsonrpc field"
    );
}

#[tokio::test]
async fn an_ask_files_one_request_and_its_approval_lets_that_exact_call_through_once() {
    let h = harness(
        vec![rule(|r| {
            r.name = "Ask before writes".into();
            r.then = AppEffect::Ask;
            r.service = Some("mcp:mcp.example.com".into());
            r.match_ = tools(&["note_add"]);
        })],
        false,
    );
    let first = answer(
        &h.calls
            .check(req(tool_call("note_add", json!({"text": "hi"}), 7)))
            .await,
    );
    assert_eq!(
        first["result"]["structuredContent"]["error"]["code"],
        "app_needs_approval"
    );
    let asks = h.asks.asks.lock().expect("lock").clone();
    assert_eq!(asks.len(), 1);
    assert_eq!(
        (asks[0]["service"].clone(), asks[0]["action"].clone()),
        (json!("mcp:mcp.example.com"), json!("note_add"))
    );
    assert_eq!(
        asks[0]["summary"],
        "Run the tool note_add on the MCP server mcp.example.com"
    );
    h.calls
        .check(req(tool_call("note_add", json!({"text": "hi"}), 7)))
        .await;
    assert_eq!(
        h.asks.asks.lock().expect("lock").len(),
        1,
        "asked again before anyone answered: the same request"
    );
    let pid = first["result"]["structuredContent"]["permission_id"]
        .as_str()
        .expect("pid")
        .to_string();
    h.asks.granted.lock().expect("lock").push(pid);
    assert!(
        matches!(
            h.calls
                .check(req(tool_call("note_add", json!({"text": "other"}), 7)))
                .await,
            Verdict::Answer { .. }
        ),
        "other arguments are another call"
    );
    let Verdict::Allow(t) = h
        .calls
        .check(req(tool_call("note_add", json!({"text": "hi"}), 7)))
        .await
    else {
        panic!("allowed");
    };
    t.done(200, Some(true), None);
    assert!(
        matches!(
            h.calls
                .check(req(tool_call("note_add", json!({"text": "hi"}), 7)))
                .await,
            Verdict::Answer { .. }
        ),
        "used once"
    );
    assert!(
        h.read()
            .iter()
            .any(|r| r["decision"] == "allowed" && r.get("follows").is_some()),
        "the run takes the ask's place in Activity"
    );
}

#[tokio::test]
async fn content_rules_on_the_arguments_and_on_the_result() {
    let h = harness(vec![], true);
    let c = h.content.clone().expect("content");
    let stop = crate::contracts::CheckedRule {
        id: "c1".into(),
        name: Some("No payroll".into()),
        action: "block".into(),
        reason: "it mentions payroll".into(),
        by: None,
    };
    *c.out.lock().expect("lock") = Some(stop.clone());
    let stopped = answer(
        &h.calls
            .check(req(tool_call("note_add", json!({"text": "payroll"}), 7)))
            .await,
    );
    assert_eq!(
        stopped["result"]["structuredContent"]["error"]["code"],
        "blocked_by_content_rule"
    );

    *c.out.lock().expect("lock") = Some(CheckedRule {
        action: "hold".into(),
        reason: "a person checks these.".into(),
        ..stop.clone()
    });
    let replayed = Arc::new(AtomicUsize::new(0));
    let r = replayed.clone();
    let mut held_req = req(tool_call("note_add", json!({"text": "payroll"}), 7));
    held_req.replay = Some(Arc::new(move || {
        let r = r.clone();
        Box::pin(async move {
            r.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }));
    let held = h.calls.check(held_req).await;
    assert!(matches!(held, Verdict::Answer { held: true, .. }));
    let a = answer(&held);
    assert_eq!(a["result"]["structuredContent"]["error"]["code"], "queued_for_approval");
    assert!(
        a["result"]["structuredContent"]["error"]["message"]
            .as_str()
            .expect("m")
            .contains("(a person checks these). It has not run")
    );
    // A rule added since blocks it: Send does not run it.
    h.rules.0.lock().expect("lock").push(rule(|r| {
        r.service = Some("mcp:mcp.example.com".into());
        r.match_ = tools(&["note_add"]);
    }));
    let send = c.send.lock().expect("lock").take().expect("held");
    assert_eq!(send().await, Err("an integration rule now blocks it (Rule)".into()));
    assert_eq!(replayed.load(Ordering::SeqCst), 0);
    h.rules.0.lock().expect("lock").clear();

    *c.out.lock().expect("lock") = None;
    *c.inn.lock().expect("lock") = Some(stop);
    let Verdict::Allow(t) = h
        .calls
        .check(req(tool_call("note_add", json!({"text": "fine"}), 9)))
        .await
    else {
        panic!("allowed");
    };
    assert!(t.read_result());
    let sse = format!(
        "event: message\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "id": 9, "result": {"content": [{"type": "text", "text": "payroll numbers"}]}})
    );
    let replaced = t
        .check_result(sse.as_bytes(), "text/event-stream", 200)
        .await
        .expect("replaced");
    let text = String::from_utf8_lossy(&replaced);
    assert!(text.contains("result_stopped_by_content_rule"));
    assert!(!text.contains("payroll numbers"));
    assert!(
        text.starts_with("event: message\ndata: "),
        "an SSE answer stays an SSE answer"
    );
}

#[test]
fn tools_list_the_catalog_learns_the_tools_and_a_blocked_tool_is_not_offered() {
    let h = harness(
        vec![
            rule(|r| {
                r.id = "b".into();
                r.service = Some("mcp:mcp.example.com".into());
                r.match_ = tools(&["delete_doc"]);
            }),
            rule(|r| {
                r.id = "s".into();
                r.service = Some("mcp:mcp.example.com".into());
                r.match_ = tools(&["archive_doc"]);
                r.sentence = Some("Only last year's docs".into());
            }),
        ],
        false,
    );
    let listed = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "read_doc", "annotations": {"readOnlyHint": true}}, {"name": "delete_doc"}, {"name": "archive_doc"}]}}).to_string();
    let out = h
        .calls
        .tools_listed("vm-a", "mcp.example.com", None, listed.as_bytes(), "application/json")
        .expect("changed");
    let v: Value = serde_json::from_slice(&out).expect("json");
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .expect("t")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(
        names,
        ["read_doc", "archive_doc"],
        "a rule with a sentence never hides a tool"
    );
    assert_eq!(
        h.catalog.kind_of("mcp.example.com", "read_doc"),
        Some(AppOperation::Read)
    );
    assert!(
        h.calls
            .tools_listed("vm-a", "other.example.com", None, listed.as_bytes(), "application/json")
            .is_none()
    );
    assert_eq!(h.catalog.kind_of("constructor", "x"), None);
}

struct Labeller {
    asked: Mutex<Vec<String>>,
    epoch: Mutex<String>,
    answer: Mutex<Option<String>>,
}

impl IntegrationJudge for Labeller {
    fn integration_fits(&self, _: &str, _: &str, _: &str, _: &str, _: &Value) -> BoxFuture<String> {
        Box::pin(async { "unavailable".to_string() })
    }
    fn label_tool(&self, _: &str, name: &str, _: Option<&str>, _: &[String]) -> BoxFuture<Option<String>> {
        self.asked.lock().expect("lock").push(name.into());
        let a = if name.starts_with("wipe") {
            Some("destructive".to_string())
        } else {
            self.answer.lock().expect("lock").clone()
        };
        Box::pin(async move { a })
    }
    fn label_epoch(&self) -> String {
        self.epoch.lock().expect("lock").clone()
    }
}

#[tokio::test]
async fn the_catalog_kinds_from_hints_else_the_ais_label_once_per_tool_shape() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    let judge = Arc::new(Labeller {
        asked: Mutex::new(vec![]),
        epoch: Mutex::new("none".into()),
        answer: Mutex::new(None),
    });
    app.contracts.judge.set(judge.clone());
    let catalog = McpCatalog::new(&app, dir.path().join("catalog.enc"));
    let asked = || judge.asked.lock().expect("lock").clone();
    catalog.listed(
        "vm-a",
        "mcp.example.com",
        &[
            json!({"name": "read_doc", "description": "Read", "annotations": {"readOnlyHint": true}, "inputSchema": {}}),
            json!({"name": "wipe_all", "description": "Wipes", "inputSchema": {"properties": {"force": {}}}}),
            json!({"name": "Not a tool!"}),
        ],
        None,
    );
    catalog.label_missing().await;
    assert_eq!(catalog.kind_of("mcp.example.com", "read_doc"), Some(AppOperation::Read));
    assert_eq!(
        catalog.kind_of("mcp.example.com", "wipe_all"),
        Some(AppOperation::Destructive)
    );
    assert_eq!(asked(), ["wipe_all"], "a tool with hints is not asked about");
    catalog.listed(
        "vm-b",
        "mcp.example.com",
        &[json!({"name": "wipe_all", "description": "Wipes", "inputSchema": {"properties": {"force": {}}}})],
        None,
    );
    catalog.label_missing().await;
    assert_eq!(asked(), ["wipe_all"], "the same shape is not asked about again");
    catalog.listed("vm-b", "mcp.example.com", &[json!({"name": "wipe_all", "description": "Now it only previews", "inputSchema": {"properties": {"force": {}}}})], None);
    catalog.label_missing().await;
    assert_eq!(
        asked(),
        ["wipe_all", "wipe_all"],
        "a changed description is labelled again"
    );
    let s = &catalog.servers()[0];
    let mut agents: Vec<&String> = s["agents"].as_object().expect("a").keys().collect();
    agents.sort();
    assert_eq!(agents, ["vm-a", "vm-b"]);
    assert_eq!(s["tools"].as_array().expect("t").len(), 2);
    // A tool the AI could not label is not asked again under the same AI, and is at once under another.
    catalog.listed("vm-a", "mcp.example.com", &[json!({"name": "odd"})], None);
    catalog.label_missing().await;
    catalog.label_missing().await;
    assert_eq!(asked().iter().filter(|n| *n == "odd").count(), 1);
    *judge.epoch.lock().expect("lock") = "jev-accepted".into();
    *judge.answer.lock().expect("lock") = Some("read".into());
    catalog.label_missing().await;
    assert_eq!(catalog.kind_of("mcp.example.com", "odd"), Some(AppOperation::Read));
    // Kept across a restart.
    catalog.save_now();
    let again = McpCatalog::new(&app, dir.path().join("catalog.enc"));
    assert_eq!(again.kind_of("mcp.example.com", "odd"), Some(AppOperation::Read));
}

#[tokio::test]
async fn json_this_firewall_cannot_read_is_refused_not_passed_unchecked() {
    let h = harness(vec![], false);
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"delete_all","arguments":{{"x":{}{}}}}}}}"#,
        "[".repeat(130),
        "]".repeat(130)
    );
    let v = h.calls.check(req(Bytes::from(deep))).await;
    assert_eq!(
        answer(&v)["result"]["structuredContent"]["error"]["code"],
        "unreadable_tool_call"
    );
    let lone = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x\ud800"}}"#;
    assert!(matches!(
        h.calls.check(req(Bytes::from(lone))).await,
        Verdict::Answer { .. }
    ));
    assert!(
        matches!(h.calls.check(req(Bytes::from("not json"))).await, Verdict::Pass),
        "what is not JSON runs nothing"
    );
    assert_eq!(h.read()[0]["rule"], "unreadable tool call");
}

#[tokio::test]
async fn a_call_let_through_whose_end_never_came_still_gets_its_line() {
    let h = harness(vec![], false);
    let Verdict::Allow(t) = h.calls.check(req(tool_call("read_doc", json!({}), 7))).await else {
        panic!("allowed");
    };
    drop(t);
    let lines = h.read();
    assert_eq!(lines.len(), 1);
    assert_eq!(
        (lines[0]["decision"].clone(), lines[0]["error_code"].clone()),
        (json!("allowed"), json!("no_answer"))
    );
    assert!(!h.calls.reads_results());
}

#[tokio::test]
async fn a_result_under_another_spelling_of_its_id_or_in_an_error_is_read_too() {
    let h = harness(vec![], true);
    let c = h.content.clone().expect("content");
    *c.inn.lock().expect("lock") = Some(CheckedRule {
        id: "c1".into(),
        name: Some("No payroll".into()),
        action: "block".into(),
        reason: "it mentions payroll".into(),
        by: None,
    });
    // `9.0`, `1e1` and `"9"` are the call's id to the agent's client, and so is no id at all to the
    // firewall: every answer in the body is read.
    for answer_doc in [
        r#"{"jsonrpc":"2.0","id":9.0,"result":{"content":[{"type":"text","text":"payroll numbers"}]}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":"9","result":{"content":[{"type":"text","text":"payroll numbers"}]}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":9,"error":{"code":-1,"message":"payroll numbers","data":"payroll numbers"}}"#
            .to_string(),
    ] {
        let Verdict::Allow(t) = h.calls.check(req(tool_call("read", json!({}), 9))).await else {
            panic!("allowed");
        };
        let replaced = t
            .check_result(answer_doc.as_bytes(), "application/json", 200)
            .await
            .expect("replaced");
        let text = String::from_utf8_lossy(&replaced);
        assert!(text.contains("result_stopped_by_content_rule"), "{answer_doc}");
        assert!(!text.contains("payroll numbers"), "{answer_doc}");
    }
}

#[tokio::test]
async fn a_tool_call_with_a_byte_order_mark_or_in_utf16_is_refused_not_passed() {
    let h = harness(vec![], false);
    let call = tool_call("delete_all", json!({}), 1);
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(&call);
    let utf16be: Vec<u8> = std::iter::once([0xFE, 0xFF])
        .chain(String::from_utf8_lossy(&call).encode_utf16().map(u16::to_be_bytes))
        .flatten()
        .collect();
    let utf16be_bare: Vec<u8> = String::from_utf8_lossy(&call)
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    for body in [bom, utf16be, utf16be_bare] {
        assert!(super::unreadable_json(&body));
        assert!(matches!(
            h.calls.check(req(Bytes::from(body))).await,
            Verdict::Answer { .. }
        ));
    }
    // A request that says it is JSON and is not: refused at the gate.
    assert!(super::unreadable_json_as(
        b"tools/call please",
        Some("application/json")
    ));
    assert!(!super::unreadable_json_as(b"tools/call please", Some("text/plain")));
    assert!(!super::unreadable_json_as(b"", Some("application/json")));
}

#[tokio::test]
async fn keys_another_server_reads_otherwise_are_refused_unread() {
    let h = harness(vec![], false);
    let code = |v: &Verdict| answer(v)["result"]["structuredContent"]["error"]["code"].clone();
    // `Method` in another case: a Go server runs it.
    let v = h
        .calls
        .check(req(Bytes::from(
            r#"{"jsonrpc":"2.0","id":7,"Method":"tools/call","params":{"name":"x"}}"#,
        )))
        .await;
    assert_eq!(code(&v), "unreadable_tool_call");
    assert_eq!(answer(&v)["id"], 7);
    // A key named twice: serde keeps the last, Go may keep the first.
    let twice = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","method":null,"params":{"name":"x"}}"#;
    assert_eq!(
        code(&h.calls.check(req(Bytes::from(twice))).await),
        "unreadable_tool_call"
    );
    // `Name` in the params of a call.
    let odd = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","Name":"y"}}"#;
    assert_eq!(
        code(&h.calls.check(req(Bytes::from(odd))).await),
        "unreadable_tool_call"
    );
    // A tool name that is not a string.
    let num = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":5}}"#;
    assert_eq!(
        code(&h.calls.check(req(Bytes::from(num))).await),
        "unreadable_tool_call"
    );
    // Not a call, whatever its case: passes.
    let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    assert!(matches!(h.calls.check(req(Bytes::from(list))).await, Verdict::Pass));
    assert!(super::may_run_tool(r#"{"METHOD":"tools/call"}"#.as_bytes()));
    assert!(!super::may_run_tool(list.as_bytes()));
}

/// ControlClaw's default web search (OpenClaw's `parallel-free`): one MCP server every agent uses,
/// whose tools the plugin never lists, and which puts a new `session_id` in every search.
fn parallel(args: Value) -> McpCallRequest {
    McpCallRequest {
        host: "search.parallel.ai".into(),
        ..req(tool_call("web_search", args, 1))
    }
}

#[tokio::test]
async fn a_parallel_search_reads_so_the_seeded_destructive_rule_lets_it_through() {
    let h = harness(vec![seeded_app_rule()], false);
    let v = h
        .calls
        .check(parallel(
            json!({"objective": "news", "search_queries": ["news"], "session_id": "s-1"}),
        ))
        .await;
    let Verdict::Allow(t) = v else {
        panic!("a search is a read")
    };
    t.done(200, Some(true), None);
    assert!(h.asks.asks.lock().expect("lock").is_empty(), "nobody asked");
    assert_eq!(
        h.catalog.kind_of("search.parallel.ai", "web_search"),
        Some(AppOperation::Read)
    );
    assert_eq!(
        h.catalog.kind_of("search.parallel.ai", "send_feedback"),
        Some(AppOperation::Write)
    );
    assert_eq!(h.catalog.kind_of("search.parallel.ai", "other"), None);
    assert_eq!(
        h.catalog.kind_of("search.parallel.ai", "web_fetch"),
        None,
        "it fetches any address"
    );
    assert_eq!(
        h.catalog.kind_of("mcp.example.com", "web_search"),
        None,
        "only on Parallel's host"
    );
}

#[tokio::test]
async fn a_strict_rule_asks_once_and_the_retry_with_a_new_session_id_uses_the_approval() {
    let h = harness(
        vec![rule(|r| {
            r.name = "Ask for every search".into();
            r.then = AppEffect::Ask;
            r.service = Some("mcp:search.parallel.ai".into());
        })],
        false,
    );
    let first = answer(
        &h.calls
            .check(parallel(
                json!({"objective": "news", "search_queries": ["news"], "session_id": "s-1"}),
            ))
            .await,
    );
    assert_eq!(
        first["result"]["structuredContent"]["error"]["code"],
        "app_needs_approval"
    );
    let pid = first["result"]["structuredContent"]["permission_id"]
        .as_str()
        .expect("pid")
        .to_string();
    // Retried before anyone answered, with the new session the plugin makes: still the one request.
    h.calls
        .check(parallel(
            json!({"objective": "news", "search_queries": ["news"], "session_id": "s-2"}),
        ))
        .await;
    assert_eq!(h.asks.asks.lock().expect("lock").len(), 1);
    h.asks.granted.lock().expect("lock").push(pid);
    assert!(
        matches!(
            h.calls
                .check(parallel(
                    json!({"objective": "other", "search_queries": ["other"], "session_id": "s-3"})
                ))
                .await,
            Verdict::Answer { .. }
        ),
        "another search is another call"
    );
    let Verdict::Allow(t) = h
        .calls
        .check(parallel(
            json!({"objective": "news", "search_queries": ["news"], "session_id": "s-4"}),
        ))
        .await
    else {
        panic!("the approval is used");
    };
    t.done(200, Some(true), None);
}

#[test]
fn only_parallels_per_call_arguments_are_left_out_of_the_key() {
    use super::super::catalog::key_input;
    let args = json!({"objective": "x", "session_id": "s"});
    assert_eq!(
        key_input("search.parallel.ai", "web_search", &args),
        json!({"objective": "x"})
    );
    assert_eq!(key_input("search.parallel.ai", "send_feedback", &args), args);
    assert_eq!(key_input("mcp.example.com", "web_search", &args), args);
}
