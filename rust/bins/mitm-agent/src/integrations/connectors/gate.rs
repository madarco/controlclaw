//! The connector gate (`connector-gate.ts`): the only way an agent box reaches OpenConnector, and
//! the place every app call is read before it runs (docs/plans/connector-inspection.md).
//!
//! OpenConnector stays on loopback of this box. This listener sits on the private IP and forwards
//! only what an agent executes with: `/mcp` and the `/v1` action, app, proxy and health routes.
//! Everything else is 404 here.
//!
//! On every request it resolves the runtime token to the agent it was minted for and compares the
//! connection's source address with that agent's private IP. Then, for a call that runs something
//! (`execute_action` over MCP, `POST /v1/actions/:id`, `POST /v1/proxy/:service`), in this order:
//!
//! 1. The body is read whole (up to `GATE_MAX_BODY`) and parsed. What does not parse is refused,
//!    and exactly the bytes parsed are forwarded.
//! 2. The Integrations rules decide: allow, ask (a permission request with an approval good for
//!    this one call), or block.
//! 3. The content rules read the input (channel `apps`, going out): stop, hold, or record.
//! 4. The answer is read (up to `GATE_MAX_ANSWER`, SSE event by event) and the content rules read
//!    the result coming in. A stopped result is replaced.
//! 5. One line goes to the call log (`connector-calls.jsonl`): metadata only.
//!
//! Answers that list actions are filtered, so a blocked action is not offered.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::firewall::GateAgent;
use super::parse::{
    GATE_MAX_ANSWER, GATE_MAX_BODY, ListVia, Route, RouteHeaders, SseEvent, Via, call_key, listed_action, parse_route,
    parse_sse, result_part, run_of, tool_answer, tool_payload, with_connection_name, with_tool_payload, write_sse,
};
use crate::contracts::{AppContent, AppHold, CheckedRule, ContentError};
use crate::integrations::apps_rules::schema::{
    AppCall, AppDecision, AppEffect, AppOperation, ProxyCall, proxy_operation,
};
use crate::integrations::call_asks::{Approval, Asks, CallAsks};
use crate::integrations::{as_map, js};
use cc_http::{Body, BoxFuture, Ctx, Req, Resp};

const GATEWAY_TIMEOUT: Duration = Duration::from_secs(120);
/// Calls the gate holds in memory at once, per agent and in all: past these it answers 429.
pub const CALLS_PER_AGENT: usize = 8;
pub const CALLS_IN_ALL: usize = 64;
/// The call log is rotated to `.1` past this size, as the proxy rotates its logs.
const CALL_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Request headers never forwarded: the gate says who the caller is, and reads answers uncompressed.
const DROP: &[&str] = &[
    "host",
    "accept-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "cookie",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "proxy-authorization",
];

/// The Integrations rules (`AppRulesFirewall`), as the gate asks them. Both fail with
/// [`RulesUnknown`] while the store cannot be read.
pub trait GateRules: Send + Sync {
    /// For listings, which have no input to judge: a rule with a sentence is not judged here.
    fn decide(&self, call: &AppCall, connections: &[String]) -> Result<AppDecision, RulesUnknown>;
    /// For a call, asking the AI about a rule's sentence.
    fn decide_judged(&self, call: AppCall, connections: Vec<String>) -> BoxFuture<Result<AppDecision, RulesUnknown>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesUnknown;

/// The rules as a call finds them: loading ("unknown", calls refused), or the module.
pub enum RulesNow {
    /// The TS's `appRulesFailed`; the Rust store starts empty-and-refusing instead (`RulesUnknown`).
    #[allow(dead_code)]
    Unknown,
    On(Arc<dyn GateRules>),
}

pub enum ContentNow {
    Off,
    Unknown,
    On(Arc<dyn AppContent>),
}

/// Token → the agent it belongs to.
pub type Resolve = Arc<dyn Fn(&str) -> Option<GateAgent> + Send + Sync>;
pub type AppName = Arc<dyn Fn(&str) -> String + Send + Sync>;

pub struct GateOptions {
    /// Where OpenConnector listens on loopback.
    pub target: (String, u16),
    /// Token → the agent it belongs to. None for a token this firewall did not mint (refused).
    pub resolve: Resolve,
    pub rules: Arc<dyn Fn() -> RulesNow + Send + Sync>,
    pub content: Arc<dyn Fn() -> ContentNow + Send + Sync>,
    /// None: an Ask rule's calls are refused, since nobody can approve them.
    pub asks: Option<Arc<dyn Asks>>,
    /// True while that agent (or the whole organization) is under an emergency stop.
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// The call log Activity reads. None: nothing is recorded.
    pub log_path: Option<PathBuf>,
    /// Where the asks waiting for a person are kept across a restart.
    pub ask_state_path: Option<PathBuf>,
    /// The app's name as people know it, for a held call's message.
    pub app_name: Option<AppName>,
    /// How long a retried call waits for an approval the bridge has not written yet.
    pub grant_wait_ms: i64,
}

/// An action's app and kind, from the runtime's catalog.
#[derive(Debug, Clone, PartialEq)]
struct ActionInfo {
    service: String,
    operation: Option<AppOperation>,
}

enum Info {
    Known(ActionInfo),
    Unknown,
    Unreadable,
}

pub struct Gate {
    opts: GateOptions,
    client: Client<HttpConnector, Body>,
    action_cache: Mutex<HashMap<String, ActionInfo>>,
    asks: CallAsks,
    busy: Mutex<(HashMap<String, usize>, usize)>,
}

/// The methods the gate forwards, as written: an upper-case standard one.
const STANDARD_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// A `.` or `..` segment, `%2e` in any case, or a backslash anywhere in the path: a path the
/// runtime would read as another.
pub fn dotted(path: &str) -> bool {
    // `\` too: OpenConnector parses the URL the WHATWG way, where it is `/`.
    path.to_ascii_lowercase().contains("%2e") || path.contains('\\') || path.split('/').any(|s| s == "." || s == "..")
}

/// Whether the gate forwards a path at all.
pub fn gate_allows(path: &str) -> bool {
    static ALLOWED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            r"^/mcp$",
            r"^/mcp/tools$",
            r"^/v1/health$",
            r"^/v1/apps(/|$)",
            r"^/v1/actions(/|$)",
            r"^/v1/proxy/",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("pattern"))
        .collect()
    });
    ALLOWED.iter().any(|r| r.is_match(path))
}

/// `::ffff:10.0.0.5` and `10.0.0.5` are the same address; compare the v4 form.
pub fn same_address(a: Option<&str>, b: Option<&str>) -> bool {
    let norm = |v: Option<&str>| {
        let v = v.unwrap_or_default();
        let v = if v.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("::ffff:")) {
            &v[7..]
        } else {
            v
        };
        js::trim(v).to_string()
    };
    let left = norm(a);
    !left.is_empty() && left == norm(b)
}

/// The address as Node's `socket.remoteAddress` writes it.
pub fn remote_address(ctx: &Ctx) -> String {
    match ctx.remote {
        std::net::SocketAddr::V4(a) => a.ip().to_string(),
        std::net::SocketAddr::V6(a) => a.ip().to_string(),
    }
}

fn plain(status: u16, code: &str, message: &str) -> Resp {
    let text = js::stringify(&json!({"success": false, "message": message, "errorCode": code}));
    json_resp(status, text)
}

fn json_resp(status: u16, text: String) -> Resp {
    crate::integrations::json_reply(status, text)
}

/// Node keeps the first `Authorization` header of several.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let h = js::trim(headers.get(http::header::AUTHORIZATION)?.to_str().ok()?);
    let (scheme, rest) = h.split_at_checked(6)?;
    if !scheme.eq_ignore_ascii_case("bearer") || !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let t = js::trim(rest);
    (!t.is_empty()).then(|| t.to_string())
}

/// A header as Node gives it: several values joined with `, `.
fn header_joined(headers: &HeaderMap, name: &str) -> Option<String> {
    let v: Vec<&str> = headers.get_all(name).iter().filter_map(|v| v.to_str().ok()).collect();
    (!v.is_empty()).then(|| v.join(", "))
}

/// Why a call was not run, in the runtime's own envelope (`/v1`) or as a tool result (`/mcp`).
struct Refusal {
    status: u16,
    code: &'static str,
    message: String,
    data: Option<Map<String, Value>>,
}

impl Refusal {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            data: None,
        }
    }
}

fn send_refusal(route: &Route, r: Refusal, mcp_is_error: bool) -> Resp {
    let (is_mcp, rpc_id) = match route {
        Route::Action {
            via: Via::Mcp, rpc_id, ..
        }
        | Route::Guide {
            via: Via::Mcp, rpc_id, ..
        } => (true, rpc_id.as_ref()),
        _ => (false, None),
    };
    let doc = if is_mcp {
        let mut payload = Map::new();
        payload.insert("ok".into(), json!(false));
        payload.insert("error".into(), json!({"code": r.code, "message": r.message}));
        payload.extend(r.data.unwrap_or_default());
        tool_answer(rpc_id, payload, mcp_is_error)
    } else {
        json!({"success": false, "message": r.message, "errorCode": r.code,
            "data": r.data.map(Value::Object).unwrap_or(Value::Null)})
    };
    json_resp(if is_mcp { 200 } else { r.status }, js::stringify(&doc))
}

/// One call log line's fields after `source`, `id`, `ts` and `duration_ms`, in the TS's order.
#[derive(Clone)]
struct Line(Map<String, Value>);

impl Line {
    fn new() -> Self {
        Self(Map::new())
    }
    fn set(mut self, k: &str, v: impl Into<Value>) -> Self {
        self.0.insert(k.into(), v.into());
        self
    }
}

fn opt(v: Option<String>) -> Value {
    v.map(Value::String).unwrap_or(Value::Null)
}

fn opt_op(v: Option<AppOperation>) -> Value {
    v.map(|o| json!(o.as_str())).unwrap_or(Value::Null)
}

/// The base of a call's lines: who, where, what.
fn base_line(b: &Base) -> Line {
    Line::new()
        .set("vm_id", b.vm_id.clone())
        .set("route", b.route)
        .set("service", opt(b.service.clone()))
        .set("connection_id", opt(b.connection_id.clone()))
        .set("action_id", opt(b.action_id.clone()))
        .set("operation", opt_op(b.operation))
        .set("method", opt(b.method.clone()))
        .set("path", opt(b.path.clone()))
}

#[derive(Clone)]
struct Base {
    vm_id: String,
    route: &'static str,
    service: Option<String>,
    connection_id: Option<String>,
    action_id: Option<String>,
    operation: Option<AppOperation>,
    method: Option<String>,
    path: Option<String>,
    started_at: i64,
}

/// One line to a call log, rotated to `.1` past `CALL_LOG_MAX_BYTES`. Never fails a call.
pub fn append_call_line(path: &std::path::Path, line: &Value) {
    let _ = cc_store::rotate_if_larger(path, CALL_LOG_MAX_BYTES - 1);
    let text = format!("{}\n", js::stringify(line));
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .open(path)
    {
        let _ = f.write_all(text.as_bytes());
    }
}

/// What the gate knows about one request while it decides on it.
struct Call {
    agent: GateAgent,
    token: String,
    route: Route,
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Option<Bytes>,
    /// An approval this request marked in flight and has not used yet, released if it fails.
    approval_pid: Mutex<Option<String>>,
}

/// The documents of an answer: one JSON body, or each JSON `data` of an SSE body.
struct Answer {
    status: u16,
    sse: Option<(Vec<SseEvent>, Vec<usize>)>,
    docs: Vec<Value>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Must,
    May,
}

type Transform = Box<dyn FnOnce(Answer) -> BoxFuture<Answer> + Send>;

#[derive(Default)]
struct On {
    streamed: Option<Box<dyn FnOnce() + Send>>,
    unreadable: Option<Box<dyn FnOnce() + Send>>,
    unreadable_answer: Option<Refusal>,
}

/// A held call: what its replay needs, and nothing of the request it came in.
struct Held {
    url: String,
    headers: HeaderMap,
    body: Bytes,
    token: String,
    vm_id: String,
    via: Via,
    call: AppCall,
    connection_name: Option<String>,
    line: Mutex<Option<String>>,
    approved: bool,
}

/// An approval marked in flight, released when the request ends however it ends. Releasing one
/// already used up changes nothing: it is no longer asked for.
struct InFlight {
    gate: Arc<Gate>,
    pid: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.gate.asks.release(&self.pid);
    }
}

/// An approval taken while a hold is made. Dropped unresolved (the request ended while the hold
/// was being made, made or not): the ask goes, and the next call is asked again.
struct TakenGuard {
    gate: Arc<Gate>,
    taken: Option<crate::integrations::call_asks::Taken>,
}

impl Drop for TakenGuard {
    fn drop(&mut self) {
        if let Some(t) = self.taken.take() {
            self.gate.asks.drop_taken(&t);
        }
    }
}

struct BusyGuard {
    gate: Arc<Gate>,
    vm_id: String,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        let mut b = self.gate.busy.lock().unwrap_or_else(|e| e.into_inner());
        b.1 = b.1.saturating_sub(1);
        let left = b.0.get(&self.vm_id).copied().unwrap_or(1).saturating_sub(1);
        if left > 0 {
            b.0.insert(self.vm_id.clone(), left);
        } else {
            b.0.remove(&self.vm_id);
        }
    }
}

/// Keep `guard` until the answer's body is done or dropped, as the TS waits for `res` to close.
fn hold_until_sent(resp: Resp, guard: BusyGuard) -> Resp {
    resp.map(move |b| {
        b.map_frame(move |f| {
            let _held = &guard;
            f
        })
        .boxed()
    })
}

fn full_body(b: Bytes) -> Body {
    Full::new(b).map_err(|never| match never {}).boxed()
}

impl Gate {
    pub fn new(opts: GateOptions) -> Arc<Self> {
        let asks = CallAsks::new(
            opts.asks.clone(),
            opts.ask_state_path.clone(),
            "connectors",
            opts.grant_wait_ms,
        );
        Arc::new(Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            opts,
            action_cache: Mutex::new(HashMap::new()),
            asks,
            busy: Mutex::new((HashMap::new(), 0)),
        })
    }

    /// A router that sends every request here, for `cc_http::serve`.
    pub fn router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["gate"]);
        let me = self.clone();
        r.route(
            "gate",
            |_, _| true,
            move |req, ctx| {
                let me = me.clone();
                async move { me.serve(req, ctx).await }
            },
        );
        r
    }

    fn record(&self, line: Line, started_at: i64, id: Option<String>) -> String {
        let id = id.unwrap_or_else(|| hex::encode(rand::random::<[u8; 12]>()));
        let now = js::now_ms();
        let mut out = Map::new();
        out.insert("source".into(), json!("connector_call"));
        out.insert("id".into(), json!(id));
        out.insert("ts".into(), json!(now as f64 / 1000.0));
        out.insert("duration_ms".into(), json!((now - started_at).max(0)));
        out.extend(line.0);
        if let Some(p) = &self.opts.log_path {
            append_call_line(p, &Value::Object(out));
        }
        id
    }

    fn target_url(&self, path: &str) -> String {
        format!("http://{}:{}{path}", self.opts.target.0, self.opts.target.1)
    }

    fn forward_headers(&self, headers: &HeaderMap, token: Option<&str>, keep_length: bool) -> HeaderMap {
        let mut out = HeaderMap::new();
        for (k, v) in headers {
            let key = k.as_str();
            let keep = keep_length && (key == "content-length" || key == "transfer-encoding");
            if DROP.contains(&key) && !keep {
                continue;
            }
            out.append(k.clone(), v.clone());
        }
        if let Ok(h) = HeaderValue::from_str(&format!("{}:{}", self.opts.target.0, self.opts.target.1)) {
            out.insert(http::header::HOST, h);
        }
        if let Some(t) = token
            && let Ok(h) = HeaderValue::from_str(&format!("Bearer {t}"))
        {
            out.insert(http::header::AUTHORIZATION, h);
        }
        out
    }

    async fn upstream(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Body,
    ) -> Result<http::Response<Incoming>, String> {
        let mut req = http::Request::new(body);
        *req.method_mut() = method;
        *req.uri_mut() = self
            .target_url(url)
            .parse()
            .map_err(|e: http::uri::InvalidUri| e.to_string())?;
        *req.headers_mut() = headers;
        match tokio::time::timeout(GATEWAY_TIMEOUT, self.client.request(req)).await {
            Ok(Ok(r)) => Ok(r),
            // Fixed words, never the error's own text: nothing of the request goes in the log.
            Ok(Err(e)) => Err(if e.is_connect() {
                "connect failed"
            } else {
                "request failed"
            }
            .into()),
            Err(_) => Err("timeout".into()),
        }
    }

    pub async fn serve(self: Arc<Self>, req: Req, ctx: Ctx) -> Resp {
        let started_at = js::now_ms();
        let url = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let path = url.split('?').next().unwrap_or("/").to_string();
        let method = req.method().clone();
        // A method the runtime's parser would read another way (`post`) is not forwarded, and
        // neither is a path with a dot segment, written or encoded: the runtime normalises them, so
        // `/v1/actions/%2e%2e/connections` would reach a route the gate never allows.
        if !STANDARD_METHODS.contains(&method.as_str()) {
            return plain(405, "method_not_allowed", "The firewall does not forward this method.");
        }
        if dotted(&path) {
            return plain(
                400,
                "invalid_input",
                "The firewall could not read this request: the path has a dot segment.",
            );
        }
        if !gate_allows(&path) {
            return plain(404, "not_found", "Not found.");
        }
        if path == "/v1/health" {
            return self.forward_raw(req, None).await;
        }
        let token = bearer(req.headers());
        let agent = token.as_deref().and_then(|t| (self.opts.resolve)(t));
        let (Some(token), Some(agent)) = (token, agent) else {
            return plain(401, "unauthorized", "This firewall does not know that token.");
        };
        let route_name = if path == "/mcp" {
            "mcp"
        } else if path.starts_with("/v1/proxy/") {
            "proxy"
        } else {
            "http"
        };
        let refuse = |status: u16, code: &str, message: &str, why: &str| {
            let line = Line::new()
                .set("vm_id", agent.vm_id.clone())
                .set("route", route_name)
                .set("service", Value::Null)
                .set("connection_id", Value::Null)
                .set("action_id", Value::Null)
                .set("operation", Value::Null)
                .set("method", Value::Null)
                .set("path", Value::Null)
                .set("decision", "blocked")
                .set("by", "gate")
                .set("rule", why)
                .set("run_id", Value::Null)
                .set("ok", Value::Null)
                .set("http_status", status)
                .set("error_code", code);
            self.record(line, started_at, None);
            plain(status, code, message)
        };
        let remote = remote_address(&ctx);
        if let Some(ip) = &agent.private_ip
            && !same_address(Some(&remote), Some(ip))
        {
            tracing::info!(
                "[connectors] refused {}'s token from {remote} (expected {ip})",
                agent.vm_id
            );
            return refuse(
                403,
                "source_not_allowed",
                "This token belongs to another agent.",
                "wrong address",
            );
        }
        if agent.private_ip.is_none() {
            tracing::info!(
                "[connectors] {} has no private IP on file; allowing on the token alone",
                agent.vm_id
            );
        }
        if (self.opts.locked)(&agent.vm_id) {
            return refuse(
                403,
                "emergency_stop",
                "This agent is under an emergency stop.",
                "emergency stop",
            );
        }
        let declared = header_joined(req.headers(), "content-length")
            .and_then(|v| js::trim(&v).parse::<f64>().ok())
            .unwrap_or(0.0);
        if declared > GATE_MAX_BODY as f64 {
            return refuse(
                413,
                "too_large",
                "That request is too large for the firewall to check.",
                "too large",
            );
        }
        // Every request the gate reads is held in memory until it is answered: a cap per agent and in all.
        {
            let mut b = self.busy.lock().unwrap_or_else(|e| e.into_inner());
            let mine = b.0.get(&agent.vm_id).copied().unwrap_or(0);
            if mine >= CALLS_PER_AGENT || b.1 >= CALLS_IN_ALL {
                drop(b);
                return refuse(
                    429,
                    "too_many_calls",
                    "Too many app calls at once. Wait for one to finish, then try again.",
                    "too many at once",
                );
            }
            b.0.insert(agent.vm_id.clone(), mine + 1);
            b.1 += 1;
        }
        let guard = BusyGuard {
            gate: self.clone(),
            vm_id: agent.vm_id.clone(),
        };
        let content_type = header_joined(req.headers(), "content-type");
        let alias = header_joined(req.headers(), "x-oo-connector-alias");
        let rh = RouteHeaders {
            content_type: content_type.as_deref(),
            alias: alias.as_deref(),
        };
        if method != Method::POST {
            let route = match parse_route(method.as_str(), &url, &rh, None) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("The firewall could not read this request: {}.", e.0);
                    return hold_until_sent(refuse(400, "invalid_input", &msg, "malformed"), guard);
                }
            };
            // Something that runs comes only as a POST, read whole above; never forwarded unread.
            if matches!(route, Route::Action { .. } | Route::Proxy { .. }) {
                let msg = "The firewall could not read this request: send it as a POST.";
                return hold_until_sent(refuse(400, "invalid_input", msg, "malformed"), guard);
            }
            if matches!(route, Route::List { .. } | Route::Guide { .. }) {
                let call = Arc::new(Call {
                    agent,
                    token,
                    route,
                    method,
                    url,
                    headers: req.headers().clone(),
                    body: None,
                    approval_pid: Mutex::new(None),
                });
                let resp = self.filtered(call).await;
                return hold_until_sent(resp, guard);
            }
            let resp = self.forward_raw(req, Some(&token)).await;
            return hold_until_sent(resp, guard);
        }
        let (parts, body) = req.into_parts();
        let limited = http_body_util::Limited::new(body, GATE_MAX_BODY);
        let body = match limited.collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                    return hold_until_sent(
                        refuse(
                            413,
                            "too_large",
                            "That request is too large for the firewall to check.",
                            "too large",
                        ),
                        guard,
                    );
                }
                return hold_until_sent(
                    plain(400, "invalid_input", "The firewall could not read this request."),
                    guard,
                );
            }
        };
        let route = match parse_route(method.as_str(), &url, &rh, Some(&body)) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("The firewall could not read this request: {}.", e.0);
                return hold_until_sent(refuse(400, "invalid_input", &msg, "malformed"), guard);
            }
        };
        let call = Arc::new(Call {
            agent,
            token,
            route,
            method,
            url,
            headers: parts.headers,
            body: Some(body),
            approval_pid: Mutex::new(None),
        });
        let resp = match &call.route {
            Route::Action { .. } | Route::Proxy { .. } => match self.call(call.clone(), started_at).await {
                Ok(r) => r,
                Err(e) => self.fail(&call, &e),
            },
            Route::List { .. } | Route::Guide { .. } => self.filtered(call.clone()).await,
            Route::Pass => {
                self.forward_body(
                    call.clone(),
                    None,
                    Box::new(|a| Box::pin(async move { a })),
                    On::default(),
                )
                .await
            }
        };
        hold_until_sent(resp, guard)
    }

    fn fail(&self, call: &Call, err: &str) -> Resp {
        tracing::info!("[connectors] gate: {err}");
        // A call that failed between finding its approval and using it leaves the approval to its retry.
        if let Some(pid) = call.approval_pid.lock().unwrap_or_else(|e| e.into_inner()).take() {
            self.asks.release(&pid);
        }
        plain_502_gate_error()
    }

    fn rules_now(&self) -> RulesNow {
        (self.opts.rules)()
    }

    fn app_name(&self, service: &str) -> String {
        self.opts
            .app_name
            .as_ref()
            .map(|f| f(service))
            .unwrap_or_else(|| service.to_string())
    }

    async fn info_for(&self, action_id: &str, token: &str) -> Info {
        if let Some(hit) = self
            .action_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(action_id)
        {
            return Info::Known(hit.clone());
        }
        let info = self.action_info(action_id, token).await;
        if let Info::Known(i) = &info {
            let mut cache = self.action_cache.lock().unwrap_or_else(|e| e.into_inner());
            if cache.len() > 5000 {
                cache.clear();
            }
            cache.insert(action_id.to_string(), i.clone());
        }
        info
    }

    /// An action's app and kind, from the runtime's catalog (`GET /v1/actions/:id`).
    async fn action_info(&self, action_id: &str, token: &str) -> Info {
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
            h.insert(http::header::AUTHORIZATION, v);
        }
        if let Ok(v) = HeaderValue::from_str(&format!("{}:{}", self.opts.target.0, self.opts.target.1)) {
            h.insert(http::header::HOST, v);
        }
        let path = format!("/v1/actions/{}", super::runtime::enc(action_id));
        let got = async {
            let r = self
                .upstream(Method::GET, &path, h, full_body(Bytes::new()))
                .await
                .ok()?;
            let status = r.status().as_u16();
            let b = r.into_body().collect().await.ok()?.to_bytes();
            Some((status, b))
        };
        let Ok(Some((status, b))) = tokio::time::timeout(Duration::from_secs(10), got).await else {
            return Info::Unreadable;
        };
        let Ok(doc) = serde_json::from_slice::<Value>(&b) else {
            return Info::Unreadable;
        };
        if status == 404 && doc.get("errorCode").and_then(Value::as_str) == Some("unknown_action") {
            return Info::Unknown;
        }
        let data = doc.get("data");
        match (
            doc.get("success").is_some_and(super::firewall::truthy),
            data.and_then(|d| d.get("service")).and_then(Value::as_str),
        ) {
            (true, Some(service)) => Info::Known(ActionInfo {
                service: service.to_string(),
                operation: data
                    .and_then(|d| d.get("operationType"))
                    .and_then(Value::as_str)
                    .and_then(AppOperation::parse),
            }),
            _ => Info::Unreadable,
        }
    }

    async fn decide(rules: &RulesNow, call: &AppCall, candidates: &[String]) -> Result<AppDecision, RulesUnknown> {
        match rules {
            RulesNow::On(r) => r.decide_judged(call.clone(), candidates.to_vec()).await,
            _ => Ok(AppDecision {
                then: AppEffect::Allow,
                rule: None,
                judged: None,
            }),
        }
    }

    async fn call(self: &Arc<Self>, ctx: Arc<Call>, started_at: i64) -> Result<Resp, String> {
        let agent = &ctx.agent;
        let (via, record_route) = match &ctx.route {
            Route::Proxy { .. } => (Via::Http, "proxy"),
            Route::Action { via: Via::Mcp, .. } => (Via::Mcp, "mcp"),
            _ => (Via::Http, "http"),
        };
        let (service, operation) = match &ctx.route {
            Route::Action { action_id, .. } => {
                let blocked_line = |rule: &str, status: u16, code: &str| {
                    Line::new()
                        .set("vm_id", agent.vm_id.clone())
                        .set("route", record_route)
                        .set("service", Value::Null)
                        .set("connection_id", Value::Null)
                        .set("action_id", js_cut(action_id, 240))
                        .set("operation", Value::Null)
                        .set("method", Value::Null)
                        .set("path", Value::Null)
                        .set("decision", "blocked")
                        .set("by", "gate")
                        .set("rule", rule)
                        .set("run_id", Value::Null)
                        .set("ok", Value::Null)
                        .set("http_status", status)
                        .set("error_code", code)
                };
                match self.info_for(action_id, &ctx.token).await {
                    // Not in the catalog: answered here, as the runtime would, so nothing unchecked reaches it.
                    Info::Unknown => {
                        self.record(blocked_line("unknown action", 404, "unknown_action"), started_at, None);
                        return Ok(send_refusal(
                            &ctx.route,
                            Refusal::new(404, "unknown_action", format!("Unknown action: {action_id}")),
                            true,
                        ));
                    }
                    // The catalog could not be read: the call cannot be checked, so it is not made.
                    Info::Unreadable => {
                        self.record(
                            blocked_line("catalog unreadable", 502, "check_unavailable"),
                            started_at,
                            None,
                        );
                        return Ok(send_refusal(
                            &ctx.route,
                            Refusal::new(
                                502,
                                "check_unavailable",
                                "The firewall could not look this action up, so it did not make the call. Try again in a minute.",
                            ),
                            true,
                        ));
                    }
                    Info::Known(i) => (i.service, i.operation),
                }
            }
            Route::Proxy { service, method, .. } => (service.clone(), Some(proxy_operation(method))),
            _ => return Err("not a call".into()),
        };
        let route_connection = match &ctx.route {
            Route::Action { connection_name, .. } | Route::Proxy { connection_name, .. } => connection_name.clone(),
            _ => None,
        };
        let conn = connection_of(agent, &service, route_connection.as_deref());
        let (target, input) = match &ctx.route {
            Route::Action { action_id, input, .. } => (action_id.clone(), input.clone()),
            Route::Proxy {
                method,
                path,
                endpoint,
                query,
                body,
                ..
            } => (
                format!("{method} {path}"),
                json!({"endpoint": endpoint, "query": query, "body": body}),
            ),
            _ => unreachable!("checked above"),
        };
        let base = Base {
            vm_id: agent.vm_id.clone(),
            route: record_route,
            service: Some(service.clone()),
            connection_id: conn.id.clone(),
            action_id: match &ctx.route {
                Route::Action { action_id, .. } => Some(js_cut(action_id, 240)),
                _ => None,
            },
            operation,
            method: match &ctx.route {
                Route::Proxy { method, .. } => Some(method.clone()),
                _ => None,
            },
            path: match &ctx.route {
                Route::Proxy { path, .. } => Some(js_cut(path, 300)),
                _ => None,
            },
            started_at,
        };
        let app_call = AppCall {
            vm_id: agent.vm_id.clone(),
            service: service.clone(),
            connection_id: conn.id.clone(),
            action_id: match &ctx.route {
                Route::Action { action_id, .. } => Some(action_id.clone()),
                _ => None,
            },
            operation,
            proxy: match &ctx.route {
                Route::Proxy { method, path, .. } => Some(ProxyCall {
                    method: method.clone(),
                    path: path.clone(),
                }),
                _ => None,
            },
            tool: None,
            input: input.clone(),
        };
        // The approval this call runs under: in flight from when it is found, used up when sent or held.
        let mut approval: Option<Approval> = None;
        let mut _in_flight: Option<InFlight> = None;
        let mut rule_id: Option<String> = None;
        let me = self.clone();
        let stop = |approval: &mut Option<Approval>,
                    rule_id: &Option<String>,
                    r: Refusal,
                    decision: &str,
                    by: &str,
                    rule: Option<String>,
                    mcp_is_error: bool,
                    id: Option<String>,
                    follows: Option<String>|
         -> (Resp, String) {
            // Refused after it was found (a content rule, rules loading): the approval is still this call's.
            if let Some(a) = approval.as_ref() {
                me.asks.release(&a.pid);
                ctx.approval_pid.lock().unwrap_or_else(|e| e.into_inner()).take();
            }
            let mut line = base_line(&base);
            if let Some(f) = follows {
                line = line.set("follows", f);
            }
            line = line.set("decision", decision).set("by", by);
            if by == "app_rule"
                && let Some(id) = rule_id
            {
                line = line.set("rule_id", id.clone());
            }
            let line = line
                .set("rule", opt(rule))
                .set("run_id", Value::Null)
                .set("ok", Value::Null)
                .set("http_status", r.status)
                .set("error_code", r.code);
            let id = me.record(line, base.started_at, id);
            (send_refusal(&ctx.route, r, mcp_is_error), id)
        };

        // 2. Which connection. With one grant of the app the gate names it; with several it cannot guess.
        let mut connection_name = route_connection.clone();
        let mut body = ctx.body.clone();
        if connection_name.is_none() {
            let own: Vec<_> = agent.connections.iter().filter(|c| c.service == service).collect();
            if own.len() == 1 {
                connection_name = Some(own[0].alias.clone());
                body = Some(Bytes::from(with_connection_name(body.as_deref(), via, &own[0].alias)));
            } else if own.len() > 1 {
                let r = connection_required(&self.app_name(&service), &own, &ctx.route);
                return Ok(stop(
                    &mut approval,
                    &rule_id,
                    r,
                    "blocked",
                    "gate",
                    Some("no connection named".into()),
                    true,
                    None,
                    None,
                )
                .0);
            }
        }

        // 3. The Integrations rules.
        let rules = self.rules_now();
        if matches!(rules, RulesNow::Unknown) {
            let r = Refusal::new(
                503,
                "rules_loading",
                "The firewall is loading its rules. Try again in a few seconds.",
            );
            return Ok(stop(
                &mut approval,
                &rule_id,
                r,
                "blocked",
                "gate",
                Some("rules loading".into()),
                true,
                None,
                None,
            )
            .0);
        }
        let decision = match Self::decide(&rules, &app_call, &conn.candidates).await {
            Ok(d) => d,
            Err(RulesUnknown) => {
                let r = Refusal::new(
                    503,
                    "rules_unreadable",
                    "The firewall could not read its app rules, so it refuses app calls until someone saves a change to them.",
                );
                return Ok(stop(
                    &mut approval,
                    &rule_id,
                    r,
                    "blocked",
                    "gate",
                    Some("rules unreadable".into()),
                    true,
                    None,
                    None,
                )
                .0);
            }
        };
        let by = if decision.rule.is_some() { "app_rule" } else { "default" };
        let rule_name = decision.rule.as_ref().map(|r| r.name.clone());
        rule_id = decision.rule.as_ref().map(|r| r.id.clone());
        let rule_words = rule_name.clone().unwrap_or_else(|| "null".into());
        if decision.then == AppEffect::Block {
            let r = Refusal::new(
                403,
                "action_blocked",
                format!(
                    "Blocked by your organization's app rules (rule: {rule_words}). Do not try again. If this call is needed, ask a person to change the rule."
                ),
            );
            return Ok(stop(&mut approval, &rule_id, r, "blocked", by, rule_name, true, None, None).0);
        }
        if decision.then == AppEffect::Ask {
            // With no connection the gate can pin down, the approval is for the set it could be.
            let conn_key = match &conn.id {
                Some(id) => id.clone(),
                None => {
                    let mut c = conn.candidates.clone();
                    c.sort();
                    format!("default:{}:{}", conn.alias.clone().unwrap_or_default(), c.join(","))
                }
            };
            let key = call_key(&agent.vm_id, Some(&conn_key), &target, &input).map_err(|e| e.0)?;
            approval = self.asks.approval_for(&key).await;
            if let Some(a) = &approval {
                *ctx.approval_pid.lock().unwrap_or_else(|e| e.into_inner()) = Some(a.pid.clone());
                // The request can end anywhere from here (the agent hangs up during a check): the
                // approval is then the retry's, not stuck in flight.
                _in_flight = Some(InFlight {
                    gate: self.clone(),
                    pid: a.pid.clone(),
                });
            }
            if approval.is_none() {
                if !self.asks.enabled() {
                    let r = Refusal::new(
                        403,
                        "action_blocked",
                        format!(
                            "Your organization's app rules want a person to approve this call (rule: {rule_words}), and this firewall cannot ask anyone."
                        ),
                    );
                    return Ok(stop(&mut approval, &rule_id, r, "blocked", by, rule_name, true, None, None).0);
                }
                let app = self.app_name(&service);
                let label = conn.label.clone().or_else(|| conn.alias.clone());
                let short = js_cut(&target, 300);
                let summary = format!(
                    "Run {short} in {app}{}",
                    label.as_ref().map(|l| format!(" ({l})")).unwrap_or_default()
                );
                let scope = format!(
                    "APP {service}{} {short}",
                    conn.alias.as_ref().map(|a| format!("/{a}")).unwrap_or_default()
                );
                let mut rec = Map::new();
                rec.insert("service".into(), json!(service));
                rec.insert("action".into(), json!(short));
                rec.insert("operation".into(), opt_op(operation));
                rec.insert("connection".into(), opt(label));
                rec.insert("rule".into(), json!(rule_name.clone().unwrap_or_default()));
                let Some(ask) = self.asks.file(&key, &agent.vm_id, &scope, &summary, rec) else {
                    let r = Refusal::new(
                        503,
                        "approval_unavailable",
                        format!(
                            "Your organization's app rules want a person to approve this call (rule: {rule_words}), and the firewall could not ask anyone just now. Try again later."
                        ),
                    );
                    return Ok(stop(
                        &mut approval,
                        &rule_id,
                        r,
                        "blocked",
                        "gate",
                        rule_name,
                        true,
                        None,
                        None,
                    )
                    .0);
                };
                // The same call asked again before anyone answered is the same row in Activity.
                let before = self.asks.line_of(&key);
                let mut r = Refusal::new(
                    451,
                    "app_needs_approval",
                    format!(
                        "A person must approve this call first (rule: {rule_words}). It is on their Permission requests page now. Tell them you are waiting, run `cc-perm {}` (it waits up to five minutes and exits 0 when approved), then make exactly the same call again. Do not retry in a loop.",
                        ask.pid
                    ),
                );
                r.data = Some(as_map(json!({"permission_id": ask.pid, "reason": "app_needs_approval",
                    "summary": ask.summary, "expires_at": ask.expires_at})));
                let (resp, line) = stop(&mut approval, &rule_id, r, "asked", by, rule_name, true, before, None);
                // The first ask's line: the run, once approved, takes its place in Activity.
                self.asks.set_line(&key, &line);
                return Ok(resp);
            }
        }

        // 4. The content rules on the input.
        let content = (self.opts.content)();
        if matches!(content, ContentNow::Unknown) {
            let r = Refusal::new(
                503,
                "rules_loading",
                "The firewall is loading its rules. Try again in a few seconds.",
            );
            return Ok(stop(
                &mut approval,
                &rule_id,
                r,
                "blocked",
                "gate",
                Some("content rules loading".into()),
                true,
                None,
                None,
            )
            .0);
        }
        let mut check_in = false;
        let content = match content {
            ContentNow::On(c) => Some(c),
            _ => None,
        };
        if let Some(content) = &content {
            check_in = content.applies("in");
            let mut text = String::new();
            let mut found: Option<CheckedRule> = None;
            if content.applies("out") {
                text = content
                    .body_text(js::stringify(&input).as_bytes(), "application/json")
                    .unwrap_or_default();
                if !text.is_empty() {
                    match content.check("out", text.clone(), Some(agent.vm_id.clone())).await {
                        Ok(r) => found = r,
                        Err(e) => {
                            let too_long = e == ContentError::TooLong;
                            let extra = if too_long {
                                as_map(json!({"detail": "too long"}))
                            } else {
                                Map::new()
                            };
                            content.record("error", "out", "block", Some(&agent.vm_id), extra);
                            let why = if too_long {
                                "it is too long to check"
                            } else {
                                "the check could not run"
                            };
                            let r = Refusal::new(
                                403,
                                "blocked_by_content_rule",
                                format!("Blocked by your organization's rules: {why}. The call was not made."),
                            );
                            return Ok(stop(
                                &mut approval,
                                &rule_id,
                                r,
                                "blocked",
                                "content_rule",
                                Some("error".into()),
                                true,
                                None,
                                None,
                            )
                            .0);
                        }
                    }
                }
            }
            if let Some(rule) = found {
                let ai = rule.by.as_ref().map(|b| as_map(json!({"ai": b}))).unwrap_or_default();
                let rule_label = rule.name.clone().unwrap_or_else(|| rule.id.clone());
                if rule.action == "hold" {
                    let label = conn.label.clone().or_else(|| conn.alias.clone());
                    // Only what a replay needs, not the request: a hold can wait 24 hours.
                    let held = Arc::new(Held {
                        url: ctx.url.clone(),
                        headers: self.forward_headers(&ctx.headers, Some(&ctx.token), false),
                        body: body.clone().unwrap_or_default(),
                        token: ctx.token.clone(),
                        vm_id: agent.vm_id.clone(),
                        via,
                        call: app_call.clone(),
                        connection_name: connection_name.clone(),
                        line: Mutex::new(None),
                        approved: approval.is_some(),
                    });
                    let gate = self.clone();
                    let (held2, base2) = (held.clone(), base.clone());
                    // Used before the hold is awaited: a copy of this call that comes meanwhile, or a
                    // retry after this request ends, cannot run it a second time.
                    let mut taken = approval.as_ref().map(|a| TakenGuard {
                        gate: self.clone(),
                        taken: Some(self.asks.take(a)),
                    });
                    let hold_id = content
                        .hold(AppHold {
                            vm_id: agent.vm_id.clone(),
                            what: format!("an app action ({target})"),
                            where_: format!(
                                "{}{}",
                                self.app_name(&service),
                                label.map(|l| format!(", connection {l}")).unwrap_or_default()
                            ),
                            text: text.clone(),
                            rule: rule.clone(),
                            send: Box::new(move || Box::pin(async move { gate.replay(&held2, &base2).await })),
                        })
                        .await;
                    if hold_id.is_none()
                        && let Some(t) = taken.as_mut().and_then(|g| g.taken.take())
                    {
                        // No hold was made: the approval is still this call's retry's.
                        self.asks.put_back(&t);
                    }
                    if let Some(g) = taken.as_mut() {
                        // Made: the approval goes with the hold (used below).
                        g.taken = None;
                    }
                    if let Some(hold_id) = hold_id {
                        let mut extra = as_map(json!({"hold": hold_id}));
                        extra.extend(ai);
                        content.record(&rule.id, "out", "hold", Some(&agent.vm_id), extra);
                        // A person approved this call already: the approval goes with the hold, so
                        // Send can run it, and the held row takes the place of the ask's.
                        let asked = approval.as_ref().and_then(|a| a.line.clone());
                        if let Some(a) = approval.take() {
                            self.use_approval(&a, &ctx);
                        }
                        let mut r = Refusal::new(
                            202,
                            "queued_for_approval",
                            format!(
                                "Queued for a person's approval. Your organization's rules hold this call ({}). It has not run. It runs if a person presses Send, and you will not receive its result. Do not call it again; tell the person it is waiting for their approval.",
                                rule.reason
                            ),
                        );
                        r.data = Some(as_map(json!({"status": "queued_for_approval", "hold_id": hold_id})));
                        let (resp, line) = stop(
                            &mut approval,
                            &rule_id,
                            r,
                            "held",
                            "content_rule",
                            Some(rule_label),
                            false,
                            None,
                            asked,
                        );
                        *held.line.lock().unwrap_or_else(|e| e.into_inner()) = Some(line);
                        return Ok(resp);
                    }
                    let mut extra = as_map(json!({"held": false}));
                    extra.extend(ai);
                    content.record(&rule.id, "out", "block", Some(&agent.vm_id), extra);
                    let r = Refusal::new(
                        403,
                        "blocked_by_content_rule",
                        format!(
                            "Blocked by your organization's rules: {} (nobody could be asked to approve it). The call was not made.",
                            reason_words(&rule.reason)
                        ),
                    );
                    return Ok(stop(
                        &mut approval,
                        &rule_id,
                        r,
                        "blocked",
                        "content_rule",
                        Some(rule_label),
                        true,
                        None,
                        None,
                    )
                    .0);
                }
                let line = content.record(&rule.id, "out", "block", Some(&agent.vm_id), ai);
                content.stopped_here(&rule, "out", Some(&agent.vm_id), &text, line.as_deref());
                let r = Refusal::new(
                    403,
                    "blocked_by_content_rule",
                    format!(
                        "Blocked by your organization's rules: {}. The call was not made.",
                        reason_words(&rule.reason)
                    ),
                );
                return Ok(stop(
                    &mut approval,
                    &rule_id,
                    r,
                    "blocked",
                    "content_rule",
                    Some(rule_label),
                    true,
                    None,
                    None,
                )
                .0);
            }
        }

        // 5. Run it, and read what comes back. An approval is used up now, not before.
        let follows = approval.as_ref().and_then(|a| a.line.clone());
        if let Some(a) = approval.take() {
            self.use_approval(&a, &ctx);
        }
        let reading = if check_in { content.clone() } else { None };
        let ran = |line: Line| match &follows {
            Some(f) => line.set("follows", f.clone()),
            None => line,
        };
        let with_rule = |line: Line, by: &str, ruled: bool| {
            let line = line.set("decision", "allowed").set("by", by);
            let line = match (&rule_id, ruled && by == "app_rule") {
                (Some(id), true) => line.set("rule_id", id.clone()),
                _ => line,
            };
            line.set("rule", opt(rule_name.clone()))
        };
        let ctx2 = Arc::new(Call {
            agent: ctx.agent.clone(),
            token: ctx.token.clone(),
            route: ctx.route.clone(),
            method: ctx.method.clone(),
            url: ctx.url.clone(),
            headers: ctx.headers.clone(),
            body,
            approval_pid: Mutex::new(None),
        });
        let gate = self.clone();
        let base_t = base.clone();
        let (follows_t, rule_id_t, rule_name_t) = (follows.clone(), rule_id.clone(), rule_name.clone());
        let vm = agent.vm_id.clone();
        let transform: Transform = Box::new(move |answer: Answer| {
            Box::pin(async move {
                let runs: Vec<_> = answer.docs.iter().map(|d| run_of(d, via)).collect();
                let run = runs
                    .iter()
                    .find(|r| r.run_id.is_some())
                    .or(runs.first())
                    .cloned()
                    .unwrap_or_default();
                let ran = |line: Line| match &follows_t {
                    Some(f) => line.set("follows", f.clone()),
                    None => line,
                };
                let allowed = |line: Line, by: &str| {
                    let line = line.set("decision", "allowed").set("by", by);
                    let line = match (&rule_id_t, by == "app_rule") {
                        (Some(id), true) => line.set("rule_id", id.clone()),
                        _ => line,
                    };
                    line.set("rule", opt(rule_name_t.clone()))
                };
                let Some(reading) = reading.filter(|_| !answer.docs.is_empty()) else {
                    let line = allowed(ran(base_line(&base_t)), by)
                        .set("run_id", opt(run.run_id))
                        .set("ok", run.ok.map(Value::Bool).unwrap_or(Value::Null))
                        .set("http_status", answer.status)
                        .set("error_code", opt(run.error_code));
                    gate.record(line, base_t.started_at, None);
                    return answer;
                };
                let mut out = Vec::new();
                let mut stop_rule: Option<String> = None;
                let mut status = answer.status;
                for doc in &answer.docs {
                    let text = reading
                        .body_text(js::stringify(&result_part(doc)).as_bytes(), "application/json")
                        .unwrap_or_default();
                    if text.is_empty() {
                        out.push(doc.clone());
                        continue;
                    }
                    match reading.check("in", text.clone(), Some(vm.clone())).await {
                        Err(e) => {
                            let too_long = e == ContentError::TooLong;
                            let extra = if too_long {
                                as_map(json!({"detail": "too long"}))
                            } else {
                                Map::new()
                            };
                            reading.record("error", "in", "block", Some(&vm), extra);
                            let why = if too_long {
                                "it is too long to check"
                            } else {
                                "the firewall could not check it"
                            };
                            out.push(replaced(doc, why, via));
                            stop_rule = Some("error".into());
                            if via == Via::Http {
                                status = 403;
                            }
                        }
                        Ok(None) => out.push(doc.clone()),
                        Ok(Some(rule)) => {
                            let ai = rule.by.as_ref().map(|b| as_map(json!({"ai": b}))).unwrap_or_default();
                            let line = reading.record(&rule.id, "in", "block", Some(&vm), ai);
                            reading.stopped_here(&rule, "in", Some(&vm), &text, line.as_deref());
                            out.push(replaced(doc, &rule.reason, via));
                            stop_rule = Some(rule.name.clone().unwrap_or_else(|| rule.id.clone()));
                            if via == Via::Http {
                                status = 403;
                            }
                        }
                    }
                }
                let mut line = ran(base_line(&base_t));
                line = match &stop_rule {
                    Some(r) => line
                        .set("decision", "blocked")
                        .set("by", "content_rule")
                        .set("rule", r.clone()),
                    None => allowed(line, by),
                };
                let line = line
                    .set("run_id", opt(run.run_id))
                    .set("ok", run.ok.map(Value::Bool).unwrap_or(Value::Null))
                    .set("http_status", status)
                    .set(
                        "error_code",
                        if stop_rule.is_some() {
                            json!("result_stopped_by_content_rule")
                        } else {
                            opt(run.error_code)
                        },
                    );
                gate.record(line, base_t.started_at, None);
                Answer {
                    docs: out,
                    status,
                    ..answer
                }
            })
        });
        let (g1, g2) = (self.clone(), self.clone());
        let (b1, b2) = (base.clone(), base.clone());
        let streamed_line = with_rule(ran(base_line(&base)), by, true)
            .set("run_id", Value::Null)
            .set("ok", Value::Null)
            .set("http_status", 200)
            .set("error_code", Value::Null);
        let on = On {
            streamed: Some(Box::new(move || {
                g1.record(streamed_line, b1.started_at, None);
            })),
            unreadable: Some(Box::new(move || {
                let line = base_line(&b2)
                    .set("decision", "blocked")
                    .set("by", "gate")
                    .set("rule", "result unreadable")
                    .set("run_id", Value::Null)
                    .set("ok", Value::Null)
                    .set("http_status", 502)
                    .set("error_code", "result_unreadable");
                g2.record(line, b2.started_at, None);
            })),
            unreadable_answer: None,
        };
        let need = if check_in && content.is_some() {
            Need::Must
        } else {
            Need::May
        };
        Ok(self.forward_body(ctx2, Some(need), transform, on).await)
    }

    /// An approval used up: the call it was for is being sent, or held with it.
    fn use_approval(&self, a: &Approval, ctx: &Call) {
        ctx.approval_pid.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.asks.use_approval(a);
    }

    /// A held call, run on Send with the agent's token as it is then, if it may still run: the
    /// agent still holds the token and the connection, it is not under an emergency stop, and the
    /// Integrations rules as they are now allow it. Its result goes nowhere.
    async fn replay(&self, held: &Held, base: &Base) -> Result<(), String> {
        let who = (self.opts.resolve)(&held.token);
        let Some(who) = who.filter(|w| w.vm_id == held.vm_id) else {
            return Err("the agent no longer holds this app".into());
        };
        if (self.opts.locked)(&held.vm_id) {
            return Err("the agent is under an emergency stop".into());
        }
        let conn = connection_of(&who, &held.call.service, held.connection_name.as_deref());
        if held.call.connection_id.is_some() && conn.id != held.call.connection_id {
            return Err("the agent no longer has this connection".into());
        }
        let rules = self.rules_now();
        let decided = if matches!(rules, RulesNow::Unknown) {
            Err(RulesUnknown)
        } else {
            Self::decide(&rules, &held.call, &conn.candidates).await
        };
        let Ok(now) = decided else {
            return Err("the firewall could not read its app rules".into());
        };
        // Approved before it was held: the approval went with it, so an Ask rule lets it through.
        if now.then == AppEffect::Block || (now.then == AppEffect::Ask && !held.approved) {
            let what = if now.then == AppEffect::Block {
                "blocks it"
            } else {
                "needs a person to approve it"
            };
            let name = now
                .rule
                .as_ref()
                .map(|r| r.name.clone())
                .unwrap_or_else(|| "a rule".into());
            return Err(format!("an app rule now {what} ({name})"));
        }
        let started_at = js::now_ms();
        let mut headers = held.headers.clone();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(held.body.len()));
        let r = self
            .upstream(Method::POST, &held.url, headers, full_body(held.body.clone()))
            .await
            .map_err(|e| if e == "timeout" { "timeout".to_string() } else { e })?;
        let status = r.status().as_u16();
        let ctype = r
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        // Only what a run id needs: the result goes nowhere.
        let raw = read_capped(r.into_body(), REPLAY_READ_MAX).await;
        let docs = answer_docs(&raw, &ctype);
        let run = docs
            .iter()
            .map(|d| run_of(d, held.via))
            .find(|x| x.run_id.is_some())
            .unwrap_or_default();
        let mut line = base_line(base)
            .set("decision", "allowed")
            .set("by", "content_rule")
            .set("rule", Value::Null)
            .set("run_id", opt(run.run_id.clone()))
            .set("ok", run.ok.map(Value::Bool).unwrap_or(Value::Null))
            .set("http_status", status)
            .set("error_code", opt(run.error_code.clone()))
            .set("released", true);
        if let Some(l) = held.line.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            line = line.set("follows", l);
        }
        self.record(line, started_at, None);
        if run.ok == Some(false) || status >= 400 {
            return Err(format!(
                "the app refused it{}",
                run.error_code.map(|c| format!(" ({c})")).unwrap_or_default()
            ));
        }
        Ok(())
    }

    /// Answers that list or describe actions, with what the rules block taken out.
    async fn filtered(self: &Arc<Self>, ctx: Arc<Call>) -> Resp {
        let rules = match self.rules_now() {
            RulesNow::On(r) => r,
            // No rules to apply, or none readable: the listing is passed; every call is still decided on its own.
            _ => {
                return self
                    .forward_body(
                        ctx,
                        Some(Need::May),
                        Box::new(|a| Box::pin(async move { a })),
                        On::default(),
                    )
                    .await;
            }
        };
        let agent = ctx.agent.clone();
        let blocked = {
            let rules = rules.clone();
            move |id: &str,
                  service: Option<&str>,
                  operation: Option<AppOperation>,
                  name: Option<&str>|
                  -> Option<String> {
                let svc = service
                    .map(str::to_string)
                    .unwrap_or_else(|| id.split('.').next().unwrap_or_default().to_string());
                let conn = connection_of(&agent, &svc, name);
                let call = AppCall {
                    vm_id: agent.vm_id.clone(),
                    service: svc,
                    connection_id: conn.id,
                    action_id: Some(id.to_string()),
                    operation,
                    proxy: None,
                    tool: None,
                    input: Value::Null,
                };
                match rules.decide(&call, &conn.candidates) {
                    // A rule with a sentence decides each call by its input; it never takes an action off a list.
                    Ok(d) if d.then == AppEffect::Block && d.judged.is_none() => {
                        Some(d.rule.map(|r| r.name).unwrap_or_else(|| "a rule".into()))
                    }
                    _ => None,
                }
            }
        };
        if let Route::Guide {
            action_id,
            connection_name,
            ..
        } = &ctx.route
        {
            let rule = match self.info_for(action_id, &ctx.token).await {
                Info::Known(i) => blocked(action_id, Some(&i.service), i.operation, connection_name.as_deref()),
                _ => None,
            };
            if let Some(rule) = rule {
                return send_refusal(
                    &ctx.route,
                    Refusal::new(
                        403,
                        "action_blocked",
                        format!("{action_id} is blocked by your organization's app rules (rule: {rule})."),
                    ),
                    true,
                );
            }
            return self
                .forward_body(
                    ctx,
                    Some(Need::May),
                    Box::new(|a| Box::pin(async move { a })),
                    On::default(),
                )
                .await;
        }
        // A list too large or too odd to read is refused, not passed: it could offer a blocked action.
        let mcp_search = matches!(
            ctx.route,
            Route::List {
                via: ListVia::McpSearch
            }
        );
        let transform: Transform = Box::new(move |answer: Answer| {
            Box::pin(async move {
                let keep = |list: &Vec<Value>| -> Vec<Value> {
                    list.iter()
                        .filter(|v| match listed_action(v) {
                            None => true,
                            Some(a) => blocked(&a.id, a.service.as_deref(), a.operation, None).is_none(),
                        })
                        .cloned()
                        .collect()
                };
                let docs = answer
                    .docs
                    .iter()
                    .map(|doc| {
                        if mcp_search {
                            let Some(mut p) = tool_payload(doc) else {
                                return doc.clone();
                            };
                            let ok = p.get("ok") == Some(&Value::Bool(true));
                            let Some(list) = p.get("data").and_then(Value::as_array).filter(|_| ok).cloned() else {
                                return doc.clone();
                            };
                            p.insert("data".into(), Value::Array(keep(&list)));
                            return doc
                                .as_object()
                                .map(|m| with_tool_payload(m, p, false))
                                .unwrap_or_else(|| doc.clone());
                        }
                        match doc.get("data").and_then(Value::as_array) {
                            Some(list) => {
                                let mut d = doc.clone();
                                d["data"] = Value::Array(keep(list));
                                d
                            }
                            None => doc.clone(),
                        }
                    })
                    .collect();
                Answer { docs, ..answer }
            })
        });
        let on = On {
            unreadable_answer: Some(Refusal::new(
                502,
                "list_unreadable",
                "The firewall could not read this list of actions to take out the ones your organization blocks.",
            )),
            ..On::default()
        };
        self.forward_body(ctx, Some(Need::Must), transform, on).await
    }

    /// To the runtime with the body the gate read, and back through `transform`. `need`: `Must` when
    /// the answer has to be read (one that cannot be read is refused), `May` when the gate reads it
    /// if it can and otherwise streams it as it came, None when it is only streamed.
    async fn forward_body(&self, ctx: Arc<Call>, need: Option<Need>, transform: Transform, mut on: On) -> Resp {
        let mut headers = self.forward_headers(&ctx.headers, Some(&ctx.token), false);
        if let Some(b) = &ctx.body {
            headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(b.len()));
        }
        let body = full_body(ctx.body.clone().unwrap_or_default());
        let up = match self.upstream(ctx.method.clone(), &ctx.url, headers, body).await {
            Ok(r) => r,
            Err(e) => {
                tracing::info!("[connectors] gate upstream failed: {e}");
                return send_refusal(
                    &ctx.route,
                    Refusal::new(
                        502,
                        "runtime_unreachable",
                        "The connector runtime is not answering on this firewall.",
                    ),
                    true,
                );
            }
        };
        let status = up.status().as_u16();
        let up_headers = up.headers().clone();
        let ctype = up_headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let lower = ctype.to_lowercase();
        let encoded = up_headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|e| !e.is_empty() && e != "identity");
        let readable = (lower.contains("json") || lower.contains("event-stream")) && !encoded;
        let stream_as_is = |up: http::Response<Incoming>, on: &mut On| -> Resp {
            if let Some(f) = on.streamed.take() {
                f();
            }
            pass_through(up)
        };
        let Some(need) = need.filter(|n| readable || *n == Need::Must) else {
            return stream_as_is(up, &mut on);
        };
        let mut body = up.into_body();
        let mut chunks: Vec<Bytes> = Vec::new();
        let mut size = 0usize;
        let mut over = false;
        // Node's `setTimeout` on the socket: an answer that stops coming is given up on.
        while let Ok(Some(frame)) = tokio::time::timeout(GATEWAY_TIMEOUT, body.frame()).await {
            let Ok(frame) = frame else { break };
            let Ok(data) = frame.into_data() else { continue };
            size += data.len();
            if size <= GATE_MAX_ANSWER {
                chunks.push(data);
                continue;
            }
            if need == Need::Must {
                over = true;
                continue;
            }
            // Too large to read and nothing has to read it: from here it goes as it came.
            if let Some(f) = on.streamed.take() {
                f();
            }
            chunks.push(data);
            let head = futures_util::stream::iter(chunks.into_iter().map(|c| Ok::<_, std::io::Error>(Frame::data(c))));
            let rest = idle_stream(body);
            let stream = head.chain(rest);
            let mut resp = http::Response::new(BodyExt::boxed(http_body_util::StreamBody::new(stream)));
            *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            *resp.headers_mut() = pass_headers(&up_headers);
            return resp;
        }
        let result: Result<(String, u16), String> = async {
            if over || size > GATE_MAX_ANSWER || !readable {
                return Err(if over || size > GATE_MAX_ANSWER {
                    "too large"
                } else {
                    "not readable"
                }
                .into());
            }
            let raw: Vec<u8> = chunks.concat();
            let is_sse = lower.contains("event-stream");
            let mut docs = Vec::new();
            let mut shape = None;
            if is_sse {
                let events = parse_sse(&String::from_utf8_lossy(&raw));
                let mut json_at = Vec::new();
                for (i, e) in events.iter().enumerate() {
                    let Some(d) = &e.data else { continue };
                    match serde_json::from_str::<Value>(d) {
                        Ok(v) => {
                            docs.push(v);
                            json_at.push(i);
                        }
                        Err(_) if need == Need::Must => return Err("an SSE event that is not JSON".into()),
                        Err(_) => {}
                    }
                }
                shape = Some((events, json_at));
            } else if !raw.is_empty() {
                let text = String::from_utf8_lossy(&raw);
                docs.push(serde_json::from_str::<Value>(&text).map_err(|e| e.to_string())?);
            }
            let out = transform(Answer {
                status,
                sse: shape,
                docs,
            })
            .await;
            let text = match out.sse {
                Some((mut events, json_at)) => {
                    for (j, d) in out.docs.iter().enumerate() {
                        if let Some(&i) = json_at.get(j) {
                            events[i].data = Some(js::stringify(d));
                        }
                    }
                    write_sse(&events)
                }
                None => out.docs.first().map(js::stringify).unwrap_or_default(),
            };
            Ok((text, out.status))
        }
        .await;
        match result {
            Ok((text, status)) => {
                let mut h = HeaderMap::new();
                for (k, v) in &out_headers_kept(&up_headers) {
                    h.append(k.clone(), v.clone());
                }
                h.insert(http::header::CONTENT_LENGTH, HeaderValue::from(text.len()));
                let mut resp = http::Response::new(full_body(Bytes::from(text)));
                *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                *resp.headers_mut() = h;
                resp
            }
            Err(e) => {
                // Fail closed when the answer had to be read: an answer the check cannot read does not reach the agent.
                tracing::info!("[connectors] could not read an answer: {e}");
                if need == Need::Must {
                    if let Some(f) = on.unreadable.take() {
                        f();
                    }
                    let r = on.unreadable_answer.take().unwrap_or_else(|| {
                        Refusal::new(
                            502,
                            "result_unreadable",
                            "The action ran, but the firewall could not read its result, so it kept it from you. Do not run it again.",
                        )
                    });
                    return send_refusal(&ctx.route, r, true);
                }
                send_refusal(
                    &ctx.route,
                    Refusal::new(502, "gate_error", "The firewall could not read the runtime's answer."),
                    true,
                )
            }
        }
    }

    /// Forwarded as it is, streamed both ways: routes that run nothing and carry no action list.
    async fn forward_raw(&self, req: Req, token: Option<&str>) -> Resp {
        let headers = self.forward_headers(req.headers(), token, true);
        let method = req.method().clone();
        let url = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        // The body goes as it comes, but never past the cap.
        let mut size = 0usize;
        let capped = http_body_util::BodyStream::new(req.into_body()).map(move |f| {
            let f = f.map_err(std::io::Error::other)?;
            if let Some(d) = f.data_ref() {
                size += d.len();
                if size > GATE_MAX_BODY {
                    return Err(std::io::Error::other("body over the cap"));
                }
            }
            Ok(f)
        });
        let body = BodyExt::boxed(http_body_util::StreamBody::new(capped));
        match self.upstream(method, &url, headers, body).await {
            Ok(up) => pass_through(up),
            Err(e) => {
                tracing::info!("[connectors] gate upstream failed: {e}");
                plain(
                    502,
                    "runtime_unreachable",
                    "The connector runtime is not answering on this firewall.",
                )
            }
        }
    }
}

/// What a replayed call's answer is read up to.
const REPLAY_READ_MAX: usize = 1024 * 1024;

/// A body read up to `max` bytes, each frame within `GATEWAY_TIMEOUT`; the rest is not read.
async fn read_capped(mut body: Incoming, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while let Ok(Some(Ok(frame))) = tokio::time::timeout(GATEWAY_TIMEOUT, body.frame()).await {
        if let Ok(d) = frame.into_data() {
            out.extend_from_slice(&d);
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

fn plain_502_gate_error() -> Resp {
    plain(502, "gate_error", "The firewall could not check this call.")
}

/// Upstream headers for an answer streamed as it came: hyper frames it again.
fn pass_headers(h: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in h {
        if k == http::header::TRANSFER_ENCODING || k == http::header::CONNECTION || k.as_str() == "keep-alive" {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out
}

/// Upstream headers for an answer the gate rewrote: no length, framing or encoding of the old body.
fn out_headers_kept(h: &HeaderMap) -> HeaderMap {
    let mut out = pass_headers(h);
    out.remove(http::header::CONTENT_LENGTH);
    out.remove(http::header::CONTENT_ENCODING);
    out
}

/// An upstream body passed on as it comes, ended when it stalls for `GATEWAY_TIMEOUT`.
fn idle_stream(body: Incoming) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, std::io::Error>> + Send {
    futures_util::stream::unfold(Some(body), |body| async move {
        let mut body = body?;
        match tokio::time::timeout(GATEWAY_TIMEOUT, body.frame()).await {
            Ok(Some(f)) => Some((f.map_err(std::io::Error::other), Some(body))),
            Ok(None) => None,
            Err(_) => Some((Err(std::io::Error::other("the runtime stopped answering")), None)),
        }
    })
}

fn pass_through(up: http::Response<Incoming>) -> Resp {
    let (parts, body) = up.into_parts();
    let mut resp = http::Response::new(BodyExt::boxed(http_body_util::StreamBody::new(idle_stream(body))));
    *resp.status_mut() = parts.status;
    *resp.headers_mut() = pass_headers(&parts.headers);
    resp
}

/// The documents of an answer: one JSON body, or each JSON `data` of an SSE body.
fn answer_docs(raw: &[u8], ctype: &str) -> Vec<Value> {
    let text = String::from_utf8_lossy(raw);
    if ctype.to_lowercase().contains("event-stream") {
        let parsed: Result<Vec<Value>, _> = parse_sse(&text)
            .into_iter()
            .filter_map(|e| e.data)
            .map(|d| serde_json::from_str::<Value>(&d))
            .collect();
        return parsed.unwrap_or_default();
    }
    if raw.is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<Value>(&text)
        .map(|v| vec![v])
        .unwrap_or_default()
}

/// A stopped result, replaced: the action has run, the agent does not get what it answered.
fn replaced(doc: &Value, why: &str, via: Via) -> Value {
    let message =
        format!("The action ran, but your organization's rules kept its result from you: {why}. Do not run it again.");
    let r = run_of(doc, via);
    if via == Via::Mcp {
        let mut p =
            as_map(json!({"ok": false, "error": {"code": "result_stopped_by_content_rule", "message": message}}));
        if let Some(id) = &r.run_id {
            p.insert("executionId".into(), json!(id));
        }
        return doc
            .as_object()
            .map(|m| with_tool_payload(m, p, true))
            .unwrap_or_else(|| doc.clone());
    }
    json!({"success": false, "message": message, "errorCode": "result_stopped_by_content_rule", "data": null,
        "meta": r.run_id.map(|id| json!({"executionId": id})).unwrap_or(Value::Null)})
}

/// The agent's connection a call uses, and the ones it could be when it names none the gate can pin down.
struct ConnOf {
    id: Option<String>,
    candidates: Vec<String>,
    label: Option<String>,
    alias: Option<String>,
}

fn connection_of(agent: &GateAgent, service: &str, name: Option<&str>) -> ConnOf {
    let own: Vec<_> = agent.connections.iter().filter(|c| c.service == service).collect();
    let named = match name {
        Some(n) => own.iter().find(|c| c.alias == n).copied(),
        None if own.len() == 1 => Some(own[0]),
        None => None,
    };
    if let Some(c) = named {
        return ConnOf {
            id: Some(c.id.clone()),
            candidates: vec![],
            label: c.label.clone(),
            alias: Some(c.alias.clone()),
        };
    }
    // Named but not the agent's: the runtime refuses it. Not named, several: the runtime picks its default.
    ConnOf {
        id: None,
        candidates: own.iter().map(|c| c.id.clone()).collect(),
        label: None,
        alias: name.map(str::to_string),
    }
}

/// The answer to a call that names no connection when the agent has several of the app.
fn connection_required(app: &str, own: &[&super::firewall::GateConnection], route: &Route) -> Refusal {
    let names: Vec<String> = own
        .iter()
        .map(|c| {
            format!(
                "\"{}\"{}",
                c.alias,
                c.label.as_ref().map(|l| format!(" ({l})")).unwrap_or_default()
            )
        })
        .collect();
    let where_ = match route {
        Route::Action { via: Via::Mcp, .. } => {
            "Put connectionName in execute_action's arguments next to actionId, not inside input."
        }
        _ => "Put connectionName in the request body next to input, not inside input.",
    };
    let input = match route {
        Route::Action { input, .. } => input.clone(),
        Route::Proxy { body, .. } => body.clone(),
        _ => Value::Null,
    };
    let misplaced = match input.as_object() {
        Some(o) if o.contains_key("connectionName") || o.contains_key("alias") => {
            " Your call had it inside input, where it is not read."
        }
        _ => "",
    };
    let mut r = Refusal::new(
        400,
        "connection_required",
        format!(
            "You have {} {app} connections, so the call must name one with connectionName: {}. {where_}{misplaced} The call was not made.",
            own.len(),
            names.join(", ")
        ),
    );
    r.data = Some(as_map(
        json!({"connections": own.iter().map(|c| json!({"connectionName": c.alias, "label": c.label})).collect::<Vec<_>>()}),
    ));
    r
}

/// `reasonWords` in `content-rules.ts`.
pub fn reason_words(reason: &str) -> String {
    js::trim(reason).trim_end_matches('.').to_string()
}

/// `s.slice(0, n)`.
fn js_cut(s: &str, n: usize) -> String {
    super::firewall::js_slice(s, n)
}

#[cfg(test)]
mod tests;
