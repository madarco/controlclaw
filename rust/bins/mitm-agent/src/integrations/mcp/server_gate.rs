//! The MCP server gate (`mcp-server-gate.ts`, docs/plans/mcp-servers.md §5): `/servers/<name>/mcp`
//! on the 3940 listener, which has already told who the caller is by its source address. Here:
//!
//! 1. The server exists and this agent was given it; else refused, in words the agent can read.
//! 2. `POST` (up to 1 MB), `GET` (the server's event stream) and `DELETE` (end of a session) go to
//!    the server's own URL with only the MCP headers and the firewall's credential, never the
//!    caller's own `authorization` or cookies.
//! 3. The answer is streamed back, JSON or SSE. A 401 makes the firewall renew an OAuth token once
//!    and send the request again; the agent never sees a 401.
//! 4. One line per tool call, and per refusal, goes to the call log. Never the arguments or the
//!    result.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Frame;
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::calls::{MCP_RESULT_MAX, McpCallRequest, McpCalls, McpRoute, Replay, Ticket, Verdict};
use super::public::{Request, idle_body, public_fetch, public_request};
use super::servers::{McpServersFirewall, ServerFor, mcp_name_ok};
use crate::integrations::connectors::gate::append_call_line;
use crate::integrations::js;
use cc_http::{BoxFuture, Req, Resp};

/// A `tools/list` answer is read up to this; a larger one is refused, never cut.
pub const MCP_LIST_MAX: usize = 4 * 1024 * 1024;
pub const SERVER_GATE_PREFIX: &str = "/servers/";
pub const SERVER_GATE_MAX_BODY: usize = 1024 * 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);
const FORWARD: &[&str] = &[
    "content-type",
    "accept",
    "mcp-protocol-version",
    "mcp-session-id",
    "last-event-id",
];
const ANSWER: &[&str] = &[
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
    "cache-control",
];
/// Requests one agent may have open through the gate at once (event streams included).
pub const SERVER_GATE_OPEN_PER_AGENT: usize = 8;
/// The longest a server's event stream (`GET`) stays open; the client opens a new one.
pub const SERVER_GATE_STREAM: Duration = Duration::from_secs(30 * 60);
/// How often open requests are checked against the agent's access and its emergency stop.
const RECHECK: Duration = Duration::from_secs(10);

/// `/servers/<name>/mcp` → `<name>`; None for any other path.
pub fn server_name_of(path: &str) -> Option<&str> {
    let name = path.strip_prefix("/servers/")?.strip_suffix("/mcp")?;
    (!name.contains('/') && mcp_name_ok(name)).then_some(name)
}

/// What a request body says, for the call log: the JSON-RPC method and, for `tools/call`, the
/// tool (`tools`: every one in a batch). Metadata only.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RpcSummary {
    pub method: Option<String>,
    pub tool: Option<String>,
    pub tools: Vec<String>,
    pub id: Option<Value>,
    pub count: usize,
}

pub fn rpc_summary(body: &[u8]) -> RpcSummary {
    let Ok(doc) = serde_json::from_slice::<Value>(body) else {
        return RpcSummary::default();
    };
    let list = match doc {
        Value::Array(a) => a,
        v => vec![v],
    };
    // Keys as a Go server reads them: any case, the last of two.
    fn get<'a>(o: Option<&'a Value>, name: &str) -> Option<&'a Value> {
        o?.as_object()?
            .iter()
            .rfind(|(k, _)| crate::integrations::go_json::go_json_key(k) == name)
            .map(|(_, v)| v)
    }
    let is_call = |m: &Value| get(Some(m), "method").and_then(Value::as_str) == Some("tools/call");
    fn name_of(m: Option<&Value>) -> Option<&str> {
        get(get(m, "params"), "name").and_then(Value::as_str)
    }
    let tools: Vec<String> = list
        .iter()
        .filter(|m| is_call(m))
        .filter_map(|m| name_of(Some(m)))
        .map(|n| super::client::cut(n, 128))
        .take(50)
        .collect();
    let first = list.iter().find(|m| is_call(m)).or(list.first());
    let method = get(first, "method")
        .and_then(Value::as_str)
        .map(|m| super::client::cut(m, 80));
    let tool = (method.as_deref() == Some("tools/call"))
        .then(|| name_of(first))
        .flatten()
        .map(|n| super::client::cut(n, 128));
    let id = get(first, "id").filter(|v| v.is_string() || v.is_number()).cloned();
    RpcSummary {
        method,
        tool,
        tools,
        id,
        count: list.len(),
    }
}

/// `POST /servers/give {name}`: a template's `managed: true` step asks for the organization's
/// server. Decides whether there is consent for it and gives it.
pub type Give = Arc<dyn Fn(String, String) -> BoxFuture<(bool, String)> + Send + Sync>;

pub struct ServerGateOptions {
    pub servers: Option<Arc<McpServersFirewall>>,
    /// Every tool call's checks. None: tool calls are refused (fail closed).
    pub calls: Option<Arc<McpCalls>>,
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub give: Option<Give>,
    pub log_path: Option<PathBuf>,
    pub stream: Duration,
    pub recheck: Duration,
}

impl ServerGateOptions {
    pub fn new(
        servers: Option<Arc<McpServersFirewall>>,
        calls: Option<Arc<McpCalls>>,
        locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            servers,
            calls,
            locked,
            give: None,
            log_path: None,
            stream: SERVER_GATE_STREAM,
            recheck: RECHECK,
        }
    }
}

struct Open {
    name: String,
    close: CancellationToken,
}

pub struct ServerGate {
    opts: ServerGateOptions,
    /// Every request open through the gate, by agent: checked again every few seconds and closed
    /// when the agent no longer may.
    open: Mutex<HashMap<String, Vec<(u64, Open)>>>,
    seq: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
struct Base {
    vm_id: String,
    service: Option<String>,
    action_id: Option<String>,
    method: String,
    path: Option<String>,
    started_at: i64,
}

fn json_resp(status: u16, doc: &Value) -> Resp {
    crate::integrations::json_reply(status, js::stringify(doc))
}

/// A refusal the agent reads: a JSON-RPC error for the request's id.
fn refuse(status: u16, id: Option<&Value>, message: &str) -> Resp {
    json_resp(
        status,
        &json!({"jsonrpc": "2.0", "id": id.cloned().unwrap_or(Value::Null), "error": {"code": -32001, "message": message}}),
    )
}

/// A response whose body ends the connection: what `res.destroy()` does.
fn destroyed() -> Resp {
    let s = futures_util::stream::once(async { Err::<Frame<Bytes>, _>(std::io::Error::other("closed by the gate")) });
    http::Response::new(BodyExt::boxed(http_body_util::StreamBody::new(s)))
}

/// Calls `done` once, when dropped: a streamed answer's end, however it ends.
struct OnEnd(Option<Box<dyn FnOnce() + Send + Sync>>);

impl Drop for OnEnd {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Removes its entry from the open set when the request is over.
struct Slot {
    gate: Arc<ServerGate>,
    vm_id: String,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut open = self.gate.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(list) = open.get_mut(&self.vm_id) {
            list.retain(|(i, _)| *i != self.id);
            if list.is_empty() {
                open.remove(&self.vm_id);
            }
        }
    }
}

impl ServerGate {
    pub fn new(opts: ServerGateOptions) -> Arc<Self> {
        let me = Arc::new(Self {
            opts,
            open: Mutex::new(HashMap::new()),
            seq: std::sync::atomic::AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&me);
        let every = me.opts.recheck;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                loop {
                    tokio::time::sleep(every).await;
                    let Some(g) = weak.upgrade() else { return };
                    g.recheck();
                }
            });
        }
        me
    }

    fn recheck(&self) {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        for (vm, list) in open.iter() {
            for (_, o) in list {
                let allowed = self
                    .opts
                    .servers
                    .as_ref()
                    .is_some_and(|s| matches!(s.server_for(vm, &o.name), ServerFor::Known { allowed: true, .. }));
                if !allowed || (self.opts.locked)(vm) {
                    o.close.cancel();
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        b: &Base,
        decision: &str,
        by: &str,
        rule: &str,
        ok: Option<bool>,
        status: u16,
        code: Option<&str>,
    ) {
        let Some(path) = &self.opts.log_path else { return };
        let now = js::now_ms();
        let mut l = Map::new();
        l.insert("source".into(), json!("connector_call"));
        l.insert("id".into(), json!(hex::encode(rand::random::<[u8; 12]>())));
        l.insert("ts".into(), json!(now as f64 / 1000.0));
        l.insert("duration_ms".into(), json!((now - b.started_at).max(0)));
        l.insert("route".into(), json!("mcp_server"));
        l.insert("connection_id".into(), Value::Null);
        l.insert("operation".into(), Value::Null);
        l.insert("run_id".into(), Value::Null);
        l.insert("vm_id".into(), json!(b.vm_id));
        l.insert("service".into(), json!(b.service));
        l.insert("action_id".into(), json!(b.action_id));
        l.insert("method".into(), json!(b.method));
        l.insert("path".into(), json!(b.path));
        l.insert("decision".into(), json!(decision));
        l.insert("by".into(), json!(by));
        l.insert("rule".into(), json!(rule));
        l.insert("ok".into(), json!(ok));
        l.insert("http_status".into(), json!(status));
        l.insert("error_code".into(), json!(code));
        append_call_line(path, &Value::Object(l));
    }

    fn blocked(&self, b: &Base, status: u16, code: &str, why: &str, message: &str, id: Option<&Value>) -> Resp {
        self.record(b, "blocked", "gate", why, None, status, Some(code));
        refuse(status, id, message)
    }

    async fn give_route(&self, vm_id: &str, req: Req) -> Resp {
        let started_at = js::now_ms();
        let answer = |status: u16, ok: bool, message: &str, asked: Option<&str>| {
            // Every ask is a row: a server given to an agent outside the console's own changes must show.
            if let Some(name) = asked {
                let b = Base {
                    vm_id: vm_id.into(),
                    service: Some(format!("mcp:{name}")),
                    action_id: None,
                    method: "POST".into(),
                    path: Some("servers/give".into()),
                    started_at,
                };
                let rule = if ok {
                    "given by a template".to_string()
                } else {
                    super::client::cut(message, 200)
                };
                self.record(
                    &b,
                    if ok { "allowed" } else { "blocked" },
                    "gate",
                    &rule,
                    Some(ok),
                    status,
                    (!ok).then_some("not_given"),
                );
            }
            json_resp(status, &json!({"ok": ok, "message": message}))
        };
        let Some(give) = (req.method() == http::Method::POST)
            .then_some(())
            .and(self.opts.give.clone())
        else {
            return answer(
                404,
                false,
                "This firewall does not give MCP servers to templates.",
                None,
            );
        };
        let body = http_body_util::Limited::new(req.into_body(), 4096)
            .collect()
            .await
            .map(|b| b.to_bytes());
        let name = body
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
            .filter(|n| mcp_name_ok(n));
        let Some(name) = name else {
            return answer(400, false, "Name one MCP server.", None);
        };
        let (ok, message) = give(vm_id.to_string(), name.clone()).await;
        answer(if ok { 200 } else { 409 }, ok, &message, Some(&name))
    }

    /// One request from the agent `vm_id` (told by the 3940 listener from its source address).
    pub async fn handle(self: &Arc<Self>, vm_id: &str, req: Req) -> Resp {
        let started_at = js::now_ms();
        let method = req.method().as_str().to_uppercase();
        let path = req.uri().path().to_string();
        if path == "/servers/give" {
            return self.give_route(vm_id, req).await;
        }
        let name = server_name_of(&path).map(str::to_string);
        let mut base = Base {
            vm_id: vm_id.into(),
            service: name.as_ref().map(|n| format!("mcp:{n}")),
            action_id: None,
            method: method.clone(),
            path: None,
            started_at,
        };
        let (Some(name), Some(servers)) = (name, self.opts.servers.clone()) else {
            return self.blocked(
                &base,
                404,
                "not_found",
                "no such server",
                "There is no MCP server at this address.",
                None,
            );
        };
        let ServerFor::Known { url, allowed, state } = servers.server_for(vm_id, &name) else {
            let m = format!("Your organization has no MCP server called {name}.");
            return self.blocked(&base, 404, "not_found", "no such server", &m, None);
        };
        if !allowed {
            let m = format!(
                "This agent was not given the MCP server {name}. A person can give it on the Integrations page."
            );
            return self.blocked(&base, 403, "not_given", "not given to this agent", &m, None);
        }
        if (self.opts.locked)(vm_id) {
            return self.blocked(
                &base,
                403,
                "emergency_stop",
                "emergency stop",
                "This agent is under an emergency stop.",
                None,
            );
        }
        let close = CancellationToken::new();
        let slot = {
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            let mine = open.entry(vm_id.to_string()).or_default();
            if mine.len() >= SERVER_GATE_OPEN_PER_AGENT {
                drop(open);
                return self.blocked(
                    &base,
                    429,
                    "too_many_calls",
                    "too many at once",
                    "Too many calls to MCP servers at once. Wait for one to finish, then try again.",
                    None,
                );
            }
            let id = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            mine.push((
                id,
                Open {
                    name: name.clone(),
                    close: close.clone(),
                },
            ));
            Slot {
                gate: self.clone(),
                vm_id: vm_id.to_string(),
                id,
            }
        };
        // A server's event stream is closed after a while; the client opens a new one.
        if method == "GET" {
            let (c, after) = (close.clone(), self.opts.stream);
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(after) => c.cancel(),
                    _ = c.cancelled() => {}
                }
            });
        }
        if method != "POST" && method != "GET" && method != "DELETE" {
            let mut r = cc_http::empty(405);
            r.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("POST, GET, DELETE"));
            return r;
        }
        let headers = req.headers().clone();
        let body = if method == "POST" {
            let declared = headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            if declared > SERVER_GATE_MAX_BODY as f64 {
                return self.blocked(
                    &base,
                    413,
                    "too_large",
                    "too large",
                    "That request is too large for the firewall to pass on.",
                    None,
                );
            }
            match http_body_util::Limited::new(req.into_body(), SERVER_GATE_MAX_BODY)
                .collect()
                .await
            {
                Ok(b) => Some(b.to_bytes()),
                Err(_) => {
                    return self.blocked(
                        &base,
                        413,
                        "too_large",
                        "too large",
                        "That request is too large for the firewall to pass on.",
                        None,
                    );
                }
            }
        } else {
            None
        };
        let rpc = body.as_ref().map(|b| rpc_summary(b));
        base.path = rpc.as_ref().and_then(|r| r.method.clone());
        base.action_id = rpc.as_ref().and_then(|r| r.tool.clone());
        let send = self.send(
            &servers,
            &name,
            &url,
            &state,
            &base,
            &method,
            &headers,
            body,
            rpc,
            close.clone(),
        );
        let resp = tokio::select! {
            r = send => r,
            _ = close.cancelled() => return destroyed(),
        };
        // The slot and the close token stay with the answer until it is sent.
        resp.map(move |b| {
            let stream = http_body_util::BodyStream::new(b);
            let s = futures_util::stream::unfold((stream, close, Some(slot)), |(mut st, c, slot)| async move {
                slot.as_ref()?;
                tokio::select! {
                    f = st.next() => f.map(|f| (f, (st, c, slot))),
                    _ = c.cancelled() => Some((Err(std::io::Error::other("closed by the gate")), (st, c, None))),
                }
            });
            BodyExt::boxed(http_body_util::StreamBody::new(s))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        servers: &Arc<McpServersFirewall>,
        name: &str,
        url: &str,
        state: &str,
        base: &Base,
        method: &str,
        req_headers: &HeaderMap,
        body: Option<Bytes>,
        rpc: Option<RpcSummary>,
        _close: CancellationToken,
    ) -> Resp {
        let id = rpc.as_ref().and_then(|r| r.id.clone());
        let id = id.as_ref();
        if state == "reauth_required" {
            let m = format!(
                "The firewall's sign-in to the MCP server {name} has ended. A person has to press Sign in again on the Integrations page. Do not retry until then."
            );
            return self.blocked(base, 503, "reauth_required", "sign in again", &m, id);
        }
        let Ok(parsed) = Url::parse(url) else {
            return self.blocked(
                base,
                502,
                "server_unreachable",
                "server unreachable",
                "The firewall could not forward this request.",
                id,
            );
        };
        let host = {
            let h = parsed.host_str().unwrap_or_default().to_lowercase();
            match parsed.port() {
                Some(p) => format!("{h}:{p}"),
                None => h,
            }
        };
        // A server's event stream can replay an earlier answer (`last-event-id`), which the result
        // checks would not see: while they read results, a stream is not resumed.
        let resume = !(method == "GET" && self.opts.calls.as_ref().is_some_and(|c| c.reads_results()));
        let forward: Vec<(String, String)> = FORWARD
            .iter()
            .filter(|h| resume || **h != "last-event-id")
            .filter_map(|h| {
                let all: Vec<&HeaderValue> = req_headers.get_all(*h).iter().collect();
                // Node gives a repeated header as one joined string; only a single one is a string here.
                (all.len() == 1)
                    .then(|| all[0].to_str().ok().map(|v| (h.to_string(), v.to_string())))
                    .flatten()
            })
            .collect();
        let headers_out = || async {
            let credential = servers.credential_headers(name).await?;
            Some(with_credential(forward.clone(), credential))
        };

        // The checks every MCP tool call gets: the rules, approvals, content rules. Without them,
        // a tool call is refused rather than sent unchecked.
        let checker = self.opts.calls.clone();
        let mut ticket: Option<Arc<Ticket>> = None;
        // A tool call, or a body this firewall cannot read (it could hold one), goes to the checks.
        // Whether it is one is the checker's reading (`mayRunTool`), not `rpc_summary`'s: a Go server
        // (GitHub's) also runs `{"Method":"tools/call",...}`, which the checker refuses.
        if let (Some(b), Some(_)) = (&body, &rpc)
            && (super::calls::may_run_tool(b)
                || super::calls::unreadable_json_as(
                    b,
                    req_headers
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok()),
                ))
        {
            let Some(c) = &checker else {
                return self.blocked(
                    base,
                    503,
                    "check_unavailable",
                    "checks unavailable",
                    "The firewall cannot check tool calls right now, so it did not make this one. Try again in a minute.",
                    id,
                );
            };
            let (s, n, u, b2, fw) = (
                servers.clone(),
                name.to_string(),
                parsed.clone(),
                b.clone(),
                forward.clone(),
            );
            // A held call, sent on Send with the firewall's credential as it is then and the
            // headers the agent sent (`headersOut`: its session, protocol version, content type);
            // its answer goes nowhere.
            let replay: Replay = Arc::new(move || {
                let (s, n, u, b2, fw) = (s.clone(), n.clone(), u.clone(), b2.clone(), fw.clone());
                Box::pin(async move {
                    let credential = s
                        .credential_headers(&n)
                        .await
                        .ok_or_else(|| format!("the firewall is not signed in to {n}"))?;
                    let mut h = with_credential(fw, credential);
                    h.push(("content-length".into(), b2.len().to_string()));
                    let req = Request {
                        method: "POST",
                        headers: h,
                        body: Some(b2),
                        timeout: Duration::from_secs(60),
                    };
                    let a = public_fetch(&u, req, 1024 * 1024).await?;
                    if a.status >= 400 {
                        return Err(format!("the server answered {}", a.status));
                    }
                    Ok(())
                })
            });
            match c
                .check(McpCallRequest {
                    vm_id: base.vm_id.clone(),
                    host: host.clone(),
                    managed: Some(name.to_string()),
                    route: McpRoute::Server,
                    body: b.clone(),
                    replay: Some(replay),
                })
                .await
            {
                Verdict::Answer {
                    status,
                    content_type,
                    body,
                    ..
                } => {
                    let len = body.len();
                    let mut r = cc_http::full(
                        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                        &content_type,
                        body,
                    );
                    r.headers_mut()
                        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
                    return r;
                }
                Verdict::Allow(t) => ticket = Some(t),
                Verdict::Pass => {}
            }
        }
        // Read whole when the answer is checked (a result rule) or teaches tools (`tools/list`).
        let listing = rpc.as_ref().and_then(|r| r.method.as_deref()) == Some("tools/list") && checker.is_some();
        let reading = ticket.as_ref().is_some_and(|t| t.read_result()) || listing;
        let done = |status: u16, ok: Option<bool>, err: Option<&str>| {
            if let Some(t) = &ticket {
                t.done(status, ok, err);
            }
        };
        let mut retried = false;
        loop {
            let Some(mut headers) = headers_out().await else {
                done(503, None, Some("reauth_required"));
                let m = format!(
                    "The firewall is not signed in to the MCP server {name}. A person has to press Sign in again on the Integrations page."
                );
                return self.blocked(base, 503, "reauth_required", "sign in again", &m, id);
            };
            if let Some(b) = &body {
                headers.push(("content-length".into(), b.len().to_string()));
            }
            let up = public_request(
                &parsed,
                Request {
                    method,
                    headers,
                    body: body.clone(),
                    timeout: UPSTREAM_TIMEOUT,
                },
            )
            .await;
            let up = match up {
                Ok(u) => u,
                Err(e) => {
                    tracing::info!("[mcp-servers] {name} for {}: {e}", base.vm_id);
                    done(502, None, Some("server_unreachable"));
                    let m = format!("The MCP server {name} did not answer the firewall. Try again later.");
                    return self.blocked(base, 502, "server_unreachable", "server unreachable", &m, id);
                }
            };
            let status = up.status().as_u16();
            if status == 401 && !retried {
                retried = true;
                if !servers.refresh(name).await {
                    done(401, Some(false), Some("credential_refused"));
                    let m = format!(
                        "The MCP server {name} refused the firewall's credential. A person has to fix it on the Integrations page. Do not retry until then."
                    );
                    return self.blocked(base, 503, "credential_refused", "credential refused", &m, id);
                }
                continue;
            }
            if status == 401 {
                done(401, Some(false), Some("credential_refused"));
                let m = format!(
                    "The MCP server {name} refused the firewall's credential. A person has to check it on the Integrations page. Do not retry until then."
                );
                return self.blocked(base, 503, "credential_refused", "credential refused", &m, id);
            }
            let mut answer = HeaderMap::new();
            for h in ANSWER {
                let all: Vec<&HeaderValue> = up.headers().get_all(*h).iter().collect();
                if all.len() == 1 {
                    answer.insert(*h, all[0].clone());
                }
            }
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            if !reading {
                let t = ticket.clone();
                let end = OnEnd(Some(Box::new(move || {
                    if let Some(t) = t {
                        t.done(status, Some(status < 400), None);
                    }
                })));
                let s = idle_body(up, UPSTREAM_TIMEOUT).map(move |c| {
                    let _end = &end;
                    c.map(Frame::data).map_err(std::io::Error::other)
                });
                let mut r = http::Response::new(BodyExt::boxed(http_body_util::StreamBody::new(s)));
                *r.status_mut() = code;
                *r.headers_mut() = answer;
                return r;
            }
            // A result over its cap is refused by its check; a tool list is read up to its own, larger one.
            let cap = if listing && ticket.is_none() {
                MCP_LIST_MAX
            } else {
                MCP_RESULT_MAX
            };
            let mut got = Vec::new();
            let mut size = 0usize;
            let mut stream = std::pin::pin!(idle_body(up, UPSTREAM_TIMEOUT));
            while let Some(c) = stream.next().await {
                match c {
                    Ok(c) => {
                        size += c.len();
                        if size <= cap + 1 {
                            got.extend_from_slice(&c);
                        }
                    }
                    Err(_) => {
                        done(502, None, Some("answer_broken"));
                        let m = format!("The MCP server {name} broke off its answer.");
                        return self.blocked(base, 502, "server_unreachable", "answer broken", &m, id);
                    }
                }
            }
            let content_type = answer
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if listing && ticket.is_none() && size > MCP_LIST_MAX {
                // Never a cut list: the agent would read half a JSON answer.
                let refusal = js::stringify(&json!({"jsonrpc": "2.0", "id": id.cloned().unwrap_or(Value::Null),
                    "error": {"code": -32001, "message": format!("The MCP server {name} listed more tools than the firewall reads at once.")}}));
                answer.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                answer.insert(http::header::CONTENT_LENGTH, HeaderValue::from(refusal.len()));
                let mut r = cc_http::full(code, "", refusal);
                *r.headers_mut() = answer;
                return r;
            }
            let out = match (&ticket, &checker) {
                // Over the cap: checked as what it is, too long, never as the part that was kept.
                (Some(t), _) if size > cap => {
                    t.check_result(&vec![0u8; MCP_RESULT_MAX + 1], &content_type, status)
                        .await
                }
                (Some(t), _) => t.check_result(&got, &content_type, status).await,
                (None, Some(c)) if listing => c.tools_listed(&base.vm_id, &host, Some(name), &got, &content_type),
                _ => None,
            };
            let sent = out.unwrap_or_else(|| Bytes::from(got));
            answer.insert(http::header::CONTENT_LENGTH, HeaderValue::from(sent.len()));
            let mut r = http::Response::new(BodyExt::boxed(
                http_body_util::Full::new(sent).map_err(|never| match never {}),
            ));
            *r.status_mut() = code;
            *r.headers_mut() = answer;
            return r;
        }
    }
}

/// `{ ...forwarded, ...credential }`: the firewall's credential over anything the agent sent.
fn with_credential(mut h: Vec<(String, String)>, credential: Vec<(String, String)>) -> Vec<(String, String)> {
    for (k, v) in credential {
        h.retain(|(x, _)| !x.eq_ignore_ascii_case(&k));
        h.push((k, v));
    }
    h
}

#[cfg(test)]
mod tests;
