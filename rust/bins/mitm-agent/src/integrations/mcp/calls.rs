//! Every MCP tool call the firewall sees, checked one way (`mcp-calls.ts`,
//! docs/plans/mcp-inspection.md): those an agent makes to a server it added itself (the proxy asks
//! through the 8796 admission service), and those it makes to the organization's own servers (the
//! server gate).
//!
//! For a `tools/call`, in this order: the Integrations rules (a rule's sentence judged by the AI),
//! a person's approval for an Ask (good for that one call, once), the content rules on the
//! arguments going out (stop, hold for Send, record), and, when the call ran, the content rules on
//! its result. One metadata line per call goes to the call log. `tools/list` answers teach the
//! catalog the tools and lose the tools a rule blocks for that agent. Everything else passes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use serde_json::{Map, Value, json};

use super::catalog::McpCatalog;
use crate::contracts::{AppContent, AppHold, CheckedRule, ContentError};
use crate::integrations::apps_rules::schema::{AppCall, AppDecision, AppEffect, AppOperation, Judged};
use crate::integrations::call_asks::{Approval, Asks, CallAsks, GRANT_WAIT_MS};
use crate::integrations::connectors::gate::{
    ContentNow, GateRules, RulesNow, RulesUnknown, append_call_line, reason_words,
};
use crate::integrations::connectors::parse::{call_key, parse_sse, tool_answer, with_tool_payload, write_sse};
use crate::integrations::{Shared, as_map, js};
use cc_http::BoxFuture;

/// Answers read when a content rule covers results: past this, the result is refused.
pub const MCP_RESULT_MAX: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpRoute {
    Proxy,
    Server,
}

impl McpRoute {
    fn as_str(self) -> &'static str {
        match self {
            McpRoute::Proxy => "mcp_proxy",
            McpRoute::Server => "mcp_server",
        }
    }
}

pub type Replay = Arc<dyn Fn() -> BoxFuture<Result<(), String>> + Send + Sync>;

pub struct McpCallRequest {
    pub vm_id: String,
    /// The server's host: what Integrations rules name (`mcp:<host>`).
    pub host: String,
    /// The organization's own server's name, at the gate.
    pub managed: Option<String>,
    pub route: McpRoute,
    pub body: Bytes,
    /// Sends the held request as it was; for a content rule's hold. Its answer goes nowhere.
    pub replay: Option<Replay>,
}

pub enum Verdict {
    Pass,
    /// `held`: a content rule holds the call for Send.
    Answer {
        status: u16,
        content_type: String,
        body: Bytes,
        held: bool,
    },
    Allow(Arc<Ticket>),
}

/// A request body as its messages, read the way a server would: a `tools/call` counts whether or
/// not it says `jsonrpc`, and a batch may mix requests with answers. With them, how many entries
/// the body held (a batch's length, or 1).
pub fn rpc_read(body: &[u8]) -> Option<(Vec<Map<String, Value>>, usize)> {
    let doc: Value = serde_json::from_slice(body).ok()?;
    let list = match doc {
        Value::Array(a) => a,
        v => vec![v],
    };
    let whole = list.len();
    Some((list.into_iter().filter_map(|m| m.as_object().cloned()).collect(), whole))
}

/// A body that looks like JSON but does not parse here, though another parser might read it
/// (nesting past serde_json's limit, a lone surrogate escape, a UTF-8 byte order mark, UTF-16 or
/// UTF-32, which Python's `json.loads(bytes)` reads): it is refused, never passed unchecked.
pub fn unreadable_json(body: &[u8]) -> bool {
    let first = body.iter().find(|b| !b.is_ascii_whitespace());
    matches!(first, Some(b'{' | b'[' | 0xEF | 0xFE | 0xFF | 0x00)) && serde_json::from_slice::<Value>(body).is_err()
}

/// The same, for a request that says it is JSON: anything serde_json cannot read is refused.
pub fn unreadable_json_as(body: &[u8], content_type: Option<&str>) -> bool {
    let says_json = content_type.is_some_and(|t| t.to_ascii_lowercase().contains("json"));
    unreadable_json(body)
        || (says_json
            && body.iter().any(|b| !b.is_ascii_whitespace())
            && serde_json::from_slice::<Value>(body).is_err())
}

/// The keys a server reads a call by. Go's encoding/json (mcp-go, GitHub's MCP server) takes them
/// in any case (`go_json_key`).
const RPC_KEYS: &[&str] = &["jsonrpc", "method", "params", "name", "arguments", "id"];

/// `oddKeys`: whether a tool call (its method `tools/call` under a key of any case) has one of
/// those keys, in it or in its params, written in another case: read one way here and another there.
fn odd_keys(messages: &[Map<String, Value>]) -> bool {
    use crate::integrations::go_json::go_json_key as fold;
    let odd = |o: &Map<String, Value>| {
        o.keys()
            .any(|k| !RPC_KEYS.contains(&k.as_str()) && RPC_KEYS.contains(&fold(k).as_str()))
    };
    messages.iter().any(|m| {
        let call = m
            .iter()
            .any(|(k, v)| fold(k) == "method" && v.as_str() == Some("tools/call"));
        call && (odd(m)
            || m.iter()
                .any(|(k, v)| fold(k) == "params" && v.as_object().is_some_and(odd)))
    })
}

/// A body this firewall reads one way and a server could read another: a key one object names
/// twice (`"method":null` after `"method":"tools/call"` is a tool call to Go), or a tool call's keys
/// in another case. Refused unread, whatever it spells.
fn ambiguous(body: &[u8], messages: &[Map<String, Value>]) -> bool {
    std::str::from_utf8(body).is_ok_and(|t| crate::integrations::go_json::duplicate_key(t).is_some())
        || odd_keys(messages)
}

/// `mayRunTool`: whether a request body may run a tool, so the checks have to see it: a readable
/// `tools/call`, or one this firewall reads one way and a server could read another (keys in
/// another case, a key named twice, JSON that does not parse here). False for the rest
/// (`initialize`, `tools/list`, answers), which `check` passes as they are.
pub fn may_run_tool(body: &[u8]) -> bool {
    match rpc_read(body) {
        None => unreadable_json(body),
        Some((messages, _)) => {
            ambiguous(body, &messages)
                || messages
                    .iter()
                    .any(|m| m.get("method").and_then(Value::as_str) == Some("tools/call"))
        }
    }
}

/// What a tool call refused unread is told (`UNREADABLE`).
const UNREADABLE: &str = "Your organization's firewall could not read this tool call, so it did not send it. Send it as plain UTF-8 JSON, with the tool's name as a string.";

fn json_bytes(v: &Value) -> Bytes {
    Bytes::from(js::stringify(v))
}

/// The JSON-RPC messages of an answer (JSON or SSE), and how to write them back the same way.
struct Messages {
    messages: Vec<Value>,
    sse: Option<(Vec<crate::integrations::connectors::parse::SseEvent>, Vec<usize>)>,
    batch: bool,
}

impl Messages {
    fn read(body: &[u8], content_type: &str) -> Option<Self> {
        let text = String::from_utf8_lossy(body);
        if content_type.to_lowercase().contains("text/event-stream") {
            let events = parse_sse(&text);
            let mut at = Vec::new();
            let mut messages = Vec::new();
            for (i, e) in events.iter().enumerate() {
                let Some(d) = &e.data else { continue };
                messages.push(serde_json::from_str::<Value>(d).ok()?);
                at.push(i);
            }
            return Some(Self {
                messages,
                sse: Some((events, at)),
                batch: false,
            });
        }
        match serde_json::from_str::<Value>(&text).ok()? {
            Value::Array(a) => Some(Self {
                messages: a,
                sse: None,
                batch: true,
            }),
            v => Some(Self {
                messages: vec![v],
                sse: None,
                batch: false,
            }),
        }
    }

    fn write(&self, next: &[Value]) -> Bytes {
        match &self.sse {
            Some((events, at)) => {
                let mut events = events.clone();
                for (j, &i) in at.iter().enumerate() {
                    if let Some(d) = next.get(j) {
                        events[i].data = Some(js::stringify(d));
                    }
                }
                Bytes::from(write_sse(&events))
            }
            None if self.batch => json_bytes(&Value::Array(next.to_vec())),
            None => json_bytes(next.first().unwrap_or(&Value::Null)),
        }
    }
}

#[derive(Clone)]
struct Base {
    vm_id: String,
    route: McpRoute,
    service: String,
    action_id: Option<String>,
    operation: Option<AppOperation>,
    started_at: i64,
    rule_id: Option<String>,
}

/// The outcome fields of one line.
struct End {
    decision: &'static str,
    by: &'static str,
    rule: Option<String>,
    ok: Option<bool>,
    http_status: u16,
    error_code: Option<String>,
    follows: Option<String>,
}

pub struct McpCalls {
    rules: Arc<dyn Fn() -> RulesNow + Send + Sync>,
    content: Arc<dyn Fn() -> ContentNow + Send + Sync>,
    locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    catalog: Arc<McpCatalog>,
    asks: CallAsks,
    log_path: Option<PathBuf>,
}

impl McpCalls {
    pub fn new(
        shared: &Shared,
        catalog: Arc<McpCatalog>,
        asks: Option<Arc<dyn Asks>>,
        log_path: Option<PathBuf>,
        ask_state_path: Option<PathBuf>,
        grant_wait_ms: Option<i64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            rules: shared.rules.clone(),
            content: shared.content.clone(),
            locked: shared.locked.clone(),
            catalog,
            asks: CallAsks::new(asks, ask_state_path, "mcp", grant_wait_ms.unwrap_or(GRANT_WAIT_MS)),
            log_path,
        })
    }

    fn record(&self, base: &Base, e: End, id: Option<String>) -> String {
        let id = id.unwrap_or_else(|| hex::encode(rand::random::<[u8; 12]>()));
        let now = js::now_ms();
        let mut l = Map::new();
        l.insert("source".into(), json!("connector_call"));
        l.insert("id".into(), json!(id));
        l.insert("ts".into(), json!(now as f64 / 1000.0));
        l.insert("duration_ms".into(), json!((now - base.started_at).max(0)));
        l.insert("connection_id".into(), Value::Null);
        l.insert("run_id".into(), Value::Null);
        l.insert("vm_id".into(), json!(base.vm_id));
        l.insert("route".into(), json!(base.route.as_str()));
        l.insert("service".into(), json!(base.service));
        l.insert("action_id".into(), json!(base.action_id));
        l.insert("operation".into(), json!(base.operation.map(|o| o.as_str())));
        l.insert("method".into(), json!("POST"));
        l.insert("path".into(), json!("tools/call"));
        l.insert("decision".into(), json!(e.decision));
        l.insert("by".into(), json!(e.by));
        l.insert("rule".into(), json!(e.rule));
        l.insert("ok".into(), json!(e.ok));
        l.insert("http_status".into(), json!(e.http_status));
        l.insert("error_code".into(), json!(e.error_code));
        if let Some(f) = e.follows {
            l.insert("follows".into(), json!(f));
        }
        if e.by == "app_rule"
            && let Some(r) = &base.rule_id
        {
            l.insert("rule_id".into(), json!(r));
        }
        if let Some(p) = &self.log_path {
            append_call_line(p, &Value::Object(l));
        }
        id
    }

    fn end(decision: &'static str, by: &'static str, rule: Option<String>, code: &str) -> End {
        End {
            decision,
            by,
            rule,
            ok: None,
            http_status: 200,
            error_code: Some(code.into()),
            follows: None,
        }
    }

    /// A refusal the agent reads: a tool result with `isError`, so the model sees the words.
    /// Refused unread: every request in it gets the answer, a batch as a batch.
    fn unreadable(&self, base: &Base, messages: &[Map<String, Value>], batch: bool) -> Verdict {
        self.record(
            base,
            Self::end(
                "blocked",
                "gate",
                Some("unreadable tool call".into()),
                "unreadable_tool_call",
            ),
            None,
        );
        let one = |id: Option<&Value>| {
            tool_answer(
                id,
                as_map(json!({"ok": false, "error": {"code": "unreadable_tool_call", "message": UNREADABLE}})),
                true,
            )
        };
        let ids: Vec<Option<&Value>> = messages.iter().filter_map(|m| m.get("id").map(Some)).collect();
        let body = if batch {
            let ids = if ids.is_empty() { vec![None] } else { ids };
            Value::Array(ids.into_iter().map(one).collect())
        } else {
            one(ids.first().copied().flatten())
        };
        Verdict::Answer {
            status: 200,
            content_type: "application/json".into(),
            body: json_bytes(&body),
            held: false,
        }
    }

    fn refusal(id: Option<&Value>, code: &str, message: &str, data: Map<String, Value>) -> Verdict {
        let mut p = as_map(json!({"ok": false, "error": {"code": code, "message": message}}));
        p.extend(data);
        Verdict::Answer {
            status: 200,
            content_type: "application/json".into(),
            body: json_bytes(&tool_answer(id, p, true)),
            held: false,
        }
    }

    async fn decide_judged(rules: &Arc<dyn GateRules>, call: &AppCall) -> Result<AppDecision, RulesUnknown> {
        rules.decide_judged(call.clone(), vec![]).await
    }

    /// One request an agent sends to an MCP server.
    pub async fn check(self: &Arc<Self>, req: McpCallRequest) -> Verdict {
        let started_at = js::now_ms();
        let service = format!("mcp:{}", req.host);
        let server = req.managed.clone().unwrap_or_else(|| req.host.clone());
        // Not JSON, or no tool call in it: it runs nothing, and passes as it is. JSON this
        // firewall cannot read is refused: it could hold a tool call.
        let Some((messages, whole)) = rpc_read(&req.body) else {
            if unreadable_json(&req.body) {
                let base = Base {
                    vm_id: req.vm_id.clone(),
                    route: req.route,
                    service: req
                        .managed
                        .as_ref()
                        .map(|m| format!("mcp:{m}"))
                        .unwrap_or_else(|| service.clone()),
                    action_id: None,
                    operation: None,
                    started_at,
                    rule_id: None,
                };
                return self.unreadable(&base, &[], false);
            }
            return Verdict::Pass;
        };
        let batch = matches!(serde_json::from_slice::<Value>(&req.body), Ok(Value::Array(_)));
        let calls: Vec<&Map<String, Value>> = messages
            .iter()
            .filter(|m| m.get("method").and_then(Value::as_str) == Some("tools/call"))
            .collect();
        let odd = ambiguous(&req.body, &messages);
        if calls.is_empty() && !odd {
            return Verdict::Pass;
        }
        let log_service = req
            .managed
            .as_ref()
            .map(|m| format!("mcp:{m}"))
            .unwrap_or_else(|| service.clone());
        let mut base = Base {
            vm_id: req.vm_id.clone(),
            route: req.route,
            service: log_service,
            action_id: None,
            operation: None,
            started_at,
            rule_id: None,
        };
        if odd {
            return self.unreadable(&base, &messages, batch);
        }
        if whole > 1 {
            self.record(
                &base,
                Self::end("blocked", "gate", Some("batched tool call".into()), "batch_refused"),
                None,
            );
            // A batch is answered as a batch: every request in it gets the refusal.
            let answers: Vec<Value> = messages
                .iter()
                .filter(|m| m.contains_key("id"))
                .map(|m| {
                    tool_answer(
                        m.get("id"),
                        as_map(json!({"ok": false, "error": {"code": "batch_refused", "message": "Your organization's firewall checks each tool call on its own. Send tool calls one at a time, not in a batch."}})),
                        true,
                    )
                })
                .collect();
            return Verdict::Answer {
                status: 200,
                content_type: "application/json".into(),
                body: json_bytes(&Value::Array(answers)),
                held: false,
            };
        }
        let call = calls[0];
        let id = call.get("id").cloned();
        let id = id.as_ref();
        let params = call.get("params");
        let tool = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(|t| super::client::cut(t, 128))
            .unwrap_or_default();
        let args = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        // A name that is not a string is not one the rules can read; a server may still make one of it.
        if tool.is_empty() {
            return self.unreadable(&base, std::slice::from_ref(call), false);
        }
        let operation = self.catalog.kind_of(&req.host, &tool);
        base.action_id = Some(tool.clone());
        base.operation = operation;
        if (self.locked)(&req.vm_id) {
            self.record(
                &base,
                Self::end("blocked", "gate", Some("emergency stop".into()), "emergency_stop"),
                None,
            );
            return Self::refusal(
                id,
                "emergency_stop",
                "This agent is under an emergency stop.",
                Map::new(),
            );
        }

        // 1. The Integrations rules.
        let rules = match (self.rules)() {
            RulesNow::On(r) => r,
            RulesNow::Unknown => {
                self.record(
                    &base,
                    Self::end("blocked", "gate", Some("rules loading".into()), "rules_loading"),
                    None,
                );
                return Self::refusal(
                    id,
                    "rules_loading",
                    "The firewall is loading its rules. Try again in a few seconds.",
                    Map::new(),
                );
            }
        };
        let app_call = AppCall {
            vm_id: req.vm_id.clone(),
            service: service.clone(),
            connection_id: None,
            action_id: None,
            operation,
            proxy: None,
            tool: Some(tool.clone()),
            input: args.clone(),
        };
        let decision = match Self::decide_judged(&rules, &app_call).await {
            Ok(d) => d,
            Err(RulesUnknown) => {
                self.record(
                    &base,
                    Self::end("blocked", "gate", Some("rules unreadable".into()), "rules_unreadable"),
                    None,
                );
                return Self::refusal(
                    id,
                    "rules_unreadable",
                    "The firewall could not read its integration rules, so it refuses tool calls until someone saves a change to them.",
                    Map::new(),
                );
            }
        };
        let by: &'static str = if decision.rule.is_some() { "app_rule" } else { "default" };
        let rule_name = decision.rule.as_ref().map(|r| r.name.clone());
        let rule_words = rule_name.clone().unwrap_or_else(|| "null".into());
        base.rule_id = decision.rule.as_ref().map(|r| r.id.clone());
        if decision.then == AppEffect::Block {
            self.record(
                &base,
                Self::end("blocked", by, rule_name.clone(), "action_blocked"),
                None,
            );
            return Self::refusal(
                id,
                "action_blocked",
                &format!(
                    "Blocked by your organization's integration rules (rule: {rule_words}). Do not try again. If this call is needed, ask a person to change the rule."
                ),
                Map::new(),
            );
        }

        // 2. A person's approval, for an Ask.
        let mut approval: Option<Approval> = None;
        let mut _in_flight: Option<Release> = None;
        if decision.then == AppEffect::Ask {
            let key = match call_key(&req.vm_id, Some(&service), &tool, &args) {
                Ok(k) => k,
                Err(_) => {
                    return Self::refusal(
                        id,
                        "invalid_input",
                        "The firewall could not read this call.",
                        Map::new(),
                    );
                }
            };
            approval = self.asks.approval_for(&key).await;
            if let Some(a) = &approval {
                _in_flight = Some(Release {
                    calls: self.clone(),
                    pid: a.pid.clone(),
                });
            }
            if approval.is_none() {
                let why = if decision.judged == Some(Judged::Unavailable) {
                    " The rule's sentence could not be checked, so a person decides."
                } else {
                    ""
                };
                if !self.asks.enabled() {
                    self.record(
                        &base,
                        Self::end("blocked", by, rule_name.clone(), "action_blocked"),
                        None,
                    );
                    return Self::refusal(
                        id,
                        "action_blocked",
                        &format!(
                            "Your organization's integration rules want a person to approve this call (rule: {rule_words}), and this firewall cannot ask anyone."
                        ),
                        Map::new(),
                    );
                }
                let short = super::client::cut(&tool, 120);
                let mut rec = Map::new();
                rec.insert("service".into(), json!(service));
                rec.insert("action".into(), json!(short));
                rec.insert("operation".into(), json!(operation.map(|o| o.as_str())));
                rec.insert("connection".into(), Value::Null);
                rec.insert("rule".into(), json!(rule_name.clone().unwrap_or_default()));
                let summary = format!("Run the tool {short} on the MCP server {server}");
                let Some(ask) = self
                    .asks
                    .file(&key, &req.vm_id, &format!("MCP {service} {short}"), &summary, rec)
                else {
                    self.record(
                        &base,
                        Self::end("blocked", "gate", rule_name.clone(), "approval_unavailable"),
                        None,
                    );
                    return Self::refusal(
                        id,
                        "approval_unavailable",
                        &format!(
                            "Your organization's integration rules want a person to approve this call (rule: {rule_words}), and the firewall could not ask anyone just now. Try again later."
                        ),
                        Map::new(),
                    );
                };
                let before = self.asks.line_of(&key);
                let line = self.record(
                    &base,
                    Self::end("asked", by, rule_name.clone(), "app_needs_approval"),
                    before,
                );
                self.asks.set_line(&key, &line);
                return Self::refusal(
                    id,
                    "app_needs_approval",
                    &format!(
                        "A person must approve this call first (rule: {rule_words}).{why} It is on their Permission requests page now. Tell them you are waiting, run `cc-perm {}` (it waits up to five minutes and exits 0 when approved), then make exactly the same call again. Do not retry in a loop.",
                        ask.pid
                    ),
                    as_map(
                        json!({"permission_id": ask.pid, "reason": "app_needs_approval", "summary": ask.summary, "expires_at": ask.expires_at}),
                    ),
                );
            }
        }

        // 3. The content rules on the arguments.
        let content = match (self.content)() {
            ContentNow::Unknown => {
                self.record(
                    &base,
                    Self::end("blocked", "gate", Some("content rules loading".into()), "rules_loading"),
                    None,
                );
                return Self::refusal(
                    id,
                    "rules_loading",
                    "The firewall is loading its rules. Try again in a few seconds.",
                    Map::new(),
                );
            }
            ContentNow::On(c) => Some(c),
            ContentNow::Off => None,
        };
        let mut read_result = false;
        if let Some(content) = &content {
            read_result = content.applies("in");
            let mut text = String::new();
            let mut found: Option<CheckedRule> = None;
            if content.applies("out") {
                text = content
                    .body_text(js::stringify(&args).as_bytes(), "application/json")
                    .unwrap_or_default();
                if !text.is_empty() {
                    match content.check("out", text.clone(), Some(req.vm_id.clone())).await {
                        Ok(r) => found = r,
                        Err(e) => {
                            let too_long = e == ContentError::TooLong;
                            content.record(
                                "error",
                                "out",
                                "block",
                                Some(&req.vm_id),
                                if too_long {
                                    as_map(json!({"detail": "too long"}))
                                } else {
                                    Map::new()
                                },
                            );
                            self.record(
                                &base,
                                Self::end(
                                    "blocked",
                                    "content_rule",
                                    Some("error".into()),
                                    "blocked_by_content_rule",
                                ),
                                None,
                            );
                            let why = if too_long {
                                "it is too long to check"
                            } else {
                                "the check could not run"
                            };
                            return Self::refusal(
                                id,
                                "blocked_by_content_rule",
                                &format!("Blocked by your organization's rules: {why}. The call was not made."),
                                Map::new(),
                            );
                        }
                    }
                }
            }
            if let Some(rule) = found {
                let ai = rule.by.as_ref().map(|b| as_map(json!({"ai": b}))).unwrap_or_default();
                let label = rule.name.clone().unwrap_or_else(|| rule.id.clone());
                if rule.action == "hold"
                    && let Some(replay) = req.replay.clone()
                {
                    let approved = approval.is_some();
                    let me = self.clone();
                    let (vm, call_now) = (req.vm_id.clone(), app_call.clone());
                    // On Send: run only if it may still run, under the rules and the emergency stop as they are then.
                    let send = Box::new(move || -> BoxFuture<Result<(), String>> {
                        Box::pin(async move {
                            if (me.locked)(&vm) {
                                return Err("the agent is under an emergency stop".into());
                            }
                            let RulesNow::On(r) = (me.rules)() else {
                                return Err("the firewall could not read its integration rules".into());
                            };
                            let now = Self::decide_judged(&r, &call_now)
                                .await
                                .map_err(|_| "the firewall could not read its integration rules".to_string())?;
                            if now.then == AppEffect::Block || (now.then == AppEffect::Ask && !approved) {
                                let what = if now.then == AppEffect::Block {
                                    "blocks it"
                                } else {
                                    "needs a person to approve it"
                                };
                                let name = now.rule.map(|r| r.name).unwrap_or_else(|| "a rule".into());
                                return Err(format!("an integration rule now {what} ({name})"));
                            }
                            replay().await
                        })
                    });
                    // Used before the hold is awaited, as at the connector gate: put back when no hold
                    // is made, dropped (the call asked again) when the request ends meanwhile.
                    let mut taken = approval.as_ref().map(|a| Taken {
                        calls: self.clone(),
                        taken: Some(self.asks.take(a)),
                    });
                    let hold_id = content
                        .hold(AppHold {
                            vm_id: req.vm_id.clone(),
                            what: format!("a tool call ({tool})"),
                            where_: format!("the MCP server {server}"),
                            text: text.clone(),
                            rule: rule.clone(),
                            send,
                        })
                        .await;
                    // Resolved either way here: put back with no hold, used with the hold below.
                    if let Some(t) = taken.as_mut().and_then(|g| g.taken.take())
                        && hold_id.is_none()
                    {
                        self.asks.put_back(&t);
                    }
                    if let Some(hold_id) = hold_id {
                        let mut extra = as_map(json!({"hold": hold_id}));
                        extra.extend(ai.clone());
                        content.record(&rule.id, "out", "hold", Some(&req.vm_id), extra);
                        let follows = approval.as_ref().and_then(|a| a.line.clone());
                        if let Some(a) = approval.take() {
                            self.asks.use_approval(&a);
                        }
                        let mut e = Self::end("held", "content_rule", Some(label), "queued_for_approval");
                        e.follows = follows;
                        self.record(&base, e, None);
                        let Verdict::Answer {
                            status,
                            content_type,
                            body,
                            ..
                        } = Self::refusal(
                            id,
                            "queued_for_approval",
                            &format!(
                                "Queued for a person's approval. Your organization's rules hold this call ({}). It has not run. It runs if a person presses Send, and you will not receive its result. Do not call it again; tell the person it is waiting for their approval.",
                                reason_words(&rule.reason)
                            ),
                            as_map(json!({"status": "queued_for_approval", "hold_id": hold_id})),
                        )
                        else {
                            return Verdict::Pass;
                        };
                        return Verdict::Answer {
                            status,
                            content_type,
                            body,
                            held: true,
                        };
                    }
                }
                let mut extra = if rule.action == "hold" {
                    as_map(json!({"held": false}))
                } else {
                    Map::new()
                };
                extra.extend(ai);
                let line = content.record(&rule.id, "out", "block", Some(&req.vm_id), extra);
                content.stopped_here(&rule, "out", Some(&req.vm_id), &text, line.as_deref());
                self.record(
                    &base,
                    Self::end("blocked", "content_rule", Some(label), "blocked_by_content_rule"),
                    None,
                );
                let nobody = if rule.action == "hold" {
                    " (nobody could be asked to approve it)"
                } else {
                    ""
                };
                return Self::refusal(
                    id,
                    "blocked_by_content_rule",
                    &format!(
                        "Blocked by your organization's rules: {}{nobody}. The call was not made.",
                        reason_words(&rule.reason)
                    ),
                    Map::new(),
                );
            }
        }

        // 4. Let it run. The approval is used now: a call refused above still waits for its run.
        let follows = approval.as_ref().and_then(|a| a.line.clone());
        if let Some(a) = approval.take() {
            self.asks.use_approval(&a);
        }
        let reading = if read_result { content } else { None };
        Verdict::Allow(Arc::new(Ticket {
            calls: self.clone(),
            base,
            by,
            rule_name,
            follows,
            id: id.cloned(),
            reading,
            ended: Mutex::new(false),
        }))
    }

    /// Whether the content rules read results now: an event stream could replay one.
    pub fn reads_results(&self) -> bool {
        matches!((self.content)(), ContentNow::On(c) if c.applies("in"))
    }

    /// A `tools/list` answer: its tools go to the catalog, and the tools a rule blocks for this agent
    /// are taken out. None: pass it as it is.
    pub fn tools_listed(
        &self,
        vm_id: &str,
        host: &str,
        managed: Option<&str>,
        body: &[u8],
        content_type: &str,
    ) -> Option<Bytes> {
        let parsed = Messages::read(body, content_type)?;
        let rules = (self.rules)();
        let mut changed = false;
        let out: Vec<Value> =
            parsed
                .messages
                .iter()
                .map(|m| {
                    let Some(tools) = m.get("result").and_then(|r| r.get("tools")).and_then(Value::as_array) else {
                        return m.clone();
                    };
                    self.catalog.listed(vm_id, host, tools, managed);
                    // While the rules cannot be read, every tool call is refused anyway; the list is left whole.
                    let RulesNow::On(rules) = &rules else { return m.clone() };
                    let kept: Vec<Value> = tools
                    .iter()
                    .filter(|t| {
                        let Some(name) = t.get("name").and_then(Value::as_str) else { return true };
                        let call = AppCall {
                            vm_id: vm_id.into(),
                            service: format!("mcp:{host}"),
                            connection_id: None,
                            action_id: None,
                            operation: self.catalog.kind_of(host, name),
                            proxy: None,
                            tool: Some(name.into()),
                            input: Value::Null,
                        };
                        // A rule with a sentence is not judged here: it never hides a tool.
                        !matches!(rules.decide(&call, &[]), Ok(d) if d.then == AppEffect::Block && d.judged.is_none())
                    })
                    .cloned()
                    .collect();
                    if kept.len() == tools.len() {
                        return m.clone();
                    }
                    changed = true;
                    let mut msg = m.clone();
                    msg["result"]["tools"] = Value::Array(kept);
                    msg
                })
                .collect();
        changed.then(|| parsed.write(&out))
    }
}

/// An approval taken while a hold is made; dropped unresolved, the ask goes.
struct Taken {
    calls: Arc<McpCalls>,
    taken: Option<crate::integrations::call_asks::Taken>,
}

impl Drop for Taken {
    fn drop(&mut self) {
        if let Some(t) = self.taken.take() {
            self.calls.asks.drop_taken(&t);
        }
    }
}

/// An approval marked in flight, released when the request ends however it ends.
struct Release {
    calls: Arc<McpCalls>,
    pid: String,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.calls.asks.release(&self.pid);
    }
}

/// What the caller does with the result of a call that was let through.
pub struct Ticket {
    calls: Arc<McpCalls>,
    base: Base,
    by: &'static str,
    rule_name: Option<String>,
    follows: Option<String>,
    id: Option<Value>,
    reading: Option<Arc<dyn AppContent>>,
    ended: Mutex<bool>,
}

/// A call let through whose end was never told (the request was dropped mid-answer): it ran, so it
/// still gets its line.
impl Drop for Ticket {
    fn drop(&mut self) {
        if !*self.ended.lock().unwrap_or_else(|e| e.into_inner()) {
            self.done(0, None, Some("no_answer"));
        }
    }
}

impl Ticket {
    /// Whether the answer must be read before the agent gets it (a content rule covers results).
    pub fn read_result(&self) -> bool {
        self.reading.is_some()
    }

    fn end(&self, mut e: End) {
        let mut ended = self.ended.lock().unwrap_or_else(|x| x.into_inner());
        if *ended {
            return;
        }
        *ended = true;
        e.follows = self.follows.clone();
        self.calls.record(&self.base, e, None);
    }

    fn allowed(&self, ok: Option<bool>, status: u16, code: Option<String>) -> End {
        End {
            decision: "allowed",
            by: self.by,
            rule: self.rule_name.clone(),
            ok,
            http_status: status,
            error_code: code,
            follows: None,
        }
    }

    /// The call ended without its answer being read (or could not be).
    pub fn done(&self, status: u16, ok: Option<bool>, error: Option<&str>) {
        let code = error
            .map(str::to_string)
            .or_else(|| (ok == Some(false)).then(|| format!("http_{status}")));
        self.end(self.allowed(ok, status, code));
    }

    fn stopped(&self, status: u16, why: &str, words: &str) -> Bytes {
        self.end(End {
            decision: "blocked",
            by: "content_rule",
            rule: Some(words.into()),
            ok: None,
            http_status: status,
            error_code: Some("result_stopped_by_content_rule".into()),
            follows: None,
        });
        json_bytes(&tool_answer(
            self.id.as_ref(),
            as_map(
                json!({"ok": false, "error": {"code": "result_stopped_by_content_rule", "message": format!("The tool ran, but your organization's rules kept its result from you: {why}. Do not run it again.")}}),
            ),
            true,
        ))
    }

    /// The answer, checked: None to pass it as it is, or the answer to send instead.
    pub async fn check_result(&self, body: &[u8], content_type: &str, status: u16) -> Option<Bytes> {
        let ok_end = || {
            self.allowed(
                Some(status < 400),
                status,
                (status >= 400).then(|| format!("http_{status}")),
            )
        };
        let Some(reading) = &self.reading else {
            self.end(ok_end());
            return None;
        };
        if body.len() > MCP_RESULT_MAX {
            return Some(self.stopped(status, "it is too long to check", "too long"));
        }
        let Some(parsed) = Messages::read(body, content_type) else {
            return Some(self.stopped(status, "the firewall could not read it", "unreadable"));
        };
        let mut out = Vec::new();
        let mut stopped: Option<String> = None;
        for m in &parsed.messages {
            // Every answer in it is read, whatever its id says: a client matches ids by value
            // (`9` is `9.0`, and the TS SDK's `Number(id)` makes `"9"` the same), so an answer
            // under another spelling of the call's id would reach the agent unread. An error is
            // read too: a server can put any text in its message and data.
            let answer = m.get("result").or(m.get("error"));
            let Some(answer) = answer.filter(|_| m.is_object()) else {
                out.push(m.clone());
                continue;
            };
            let text = reading
                .body_text(js::stringify(answer).as_bytes(), "application/json")
                .unwrap_or_default();
            let rule = if text.is_empty() {
                None
            } else {
                match reading.check("in", text.clone(), Some(self.base.vm_id.clone())).await {
                    Ok(r) => r,
                    Err(e) => {
                        let too_long = e == ContentError::TooLong;
                        reading.record(
                            "error",
                            "in",
                            "block",
                            Some(&self.base.vm_id),
                            if too_long {
                                as_map(json!({"detail": "too long"}))
                            } else {
                                Map::new()
                            },
                        );
                        let why = if too_long {
                            "it is too long to check"
                        } else {
                            "the firewall could not check it"
                        };
                        return Some(self.stopped(status, why, "error"));
                    }
                }
            };
            let Some(rule) = rule else {
                out.push(m.clone());
                continue;
            };
            let ai = rule.by.as_ref().map(|b| as_map(json!({"ai": b}))).unwrap_or_default();
            let line = reading.record(&rule.id, "in", "block", Some(&self.base.vm_id), ai);
            reading.stopped_here(&rule, "in", Some(&self.base.vm_id), &text, line.as_deref());
            stopped = Some(rule.name.clone().unwrap_or_else(|| rule.id.clone()));
            let payload = as_map(
                json!({"ok": false, "error": {"code": "result_stopped_by_content_rule", "message": format!("The tool ran, but your organization's rules kept its result from you: {}. Do not run it again.", rule.reason)}}),
            );
            out.push(match m.as_object() {
                Some(o) => {
                    let mut o = o.clone();
                    o.shift_remove("error");
                    with_tool_payload(&o, payload, true)
                }
                None => m.clone(),
            });
        }
        if let Some(rule) = stopped {
            self.end(End {
                decision: "blocked",
                by: "content_rule",
                rule: Some(rule),
                ok: None,
                http_status: status,
                error_code: Some("result_stopped_by_content_rule".into()),
                follows: None,
            });
            return Some(parsed.write(&out));
        }
        self.end(ok_end());
        None
    }
}

#[cfg(test)]
pub(crate) mod tests;
