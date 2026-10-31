//! How the connector gate reads OpenConnector's execution surface (`connector-parse.ts`,
//! docs/plans/connector-inspection.md §2). Pure: no I/O. Nothing here knows any one app: it reads
//! MCP JSON-RPC and OpenConnector's own `/v1` shapes.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::integrations::apps_rules::schema::AppOperation;
use crate::integrations::js;

/// The request bodies the gate reads are held in memory; far above any action input.
pub const GATE_MAX_BODY: usize = 1024 * 1024;
/// An answer the gate reads (a result the content rules check, a list it filters).
pub const GATE_MAX_ANSWER: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct GateParseError(pub String);

fn err<T>(m: &str) -> Result<T, GateParseError> {
    Err(GateParseError(m.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Mcp,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListVia {
    McpSearch,
    HttpList,
    HttpSearch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    /// Forwarded as it is: health, the app list, the MCP tool preview, an MCP message that runs nothing.
    Pass,
    /// An action run: `execute_action` over MCP, or `POST /v1/actions/:id`.
    Action {
        via: Via,
        action_id: String,
        input: Value,
        connection_name: Option<String>,
        rpc_id: Option<Value>,
    },
    /// `POST /v1/proxy/:service`: a provider call with the stored credential.
    Proxy {
        service: String,
        method: String,
        path: String,
        endpoint: String,
        query: Value,
        body: Value,
        connection_name: Option<String>,
    },
    /// An answer that lists actions: blocked ones are taken out of it.
    List { via: ListVia },
    /// One action's guide or definition: refused when the action is blocked.
    Guide {
        via: Via,
        action_id: String,
        connection_name: Option<String>,
        rpc_id: Option<Value>,
    },
}

static ACTION_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9_]{1,61}\.[A-Za-z0-9_.-]{1,160}$").expect("pattern"));
static SERVICE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_]{0,60}$").expect("pattern"));

fn name(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !js::trim(s).is_empty() => Some(js::trim(s).to_string()),
        _ => None,
    }
}

fn name_str(v: Option<&str>) -> Option<String> {
    v.map(js::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// `URLSearchParams` over a raw query.
pub fn query_pairs(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.as_bytes()).into_owned().collect()
}

fn get<'a>(q: &'a [(String, String)], k: &str) -> Option<&'a str> {
    q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

fn count(q: &[(String, String)], k: &str) -> usize {
    q.iter().filter(|(n, _)| n == k).count()
}

/// The connection a call names, read the way the runtime reads it: body `connectionName`, body
/// `alias`, the `x-oo-connector-alias` header, query `connectionName`, query `alias`, first one
/// set wins. Naming two different ones is refused: the gate and the runtime must never pick
/// different connections.
pub fn connection_name_of(
    body: Option<&Map<String, Value>>,
    header: Option<&str>,
    query: &[(String, String)],
) -> Result<Option<String>, GateParseError> {
    let found: Vec<String> = [
        name(body.and_then(|b| b.get("connectionName"))),
        name(body.and_then(|b| b.get("alias"))),
        name_str(header),
        name_str(get(query, "connectionName")),
        name_str(get(query, "alias")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if count(query, "connectionName") > 1 || count(query, "alias") > 1 {
        return err("the connection is named twice");
    }
    if found.iter().any(|f| *f != found[0]) {
        return err("two different connections are named");
    }
    Ok(found.into_iter().next())
}

/// A Content-Type's media type alone, lowercased.
pub fn media_type(header: Option<&str>) -> String {
    header
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

fn parse_json(body: &[u8]) -> Result<Value, GateParseError> {
    // A body that is not valid UTF-8 could be read one way here and another way upstream.
    let Ok(text) = std::str::from_utf8(body) else {
        return err("the body is not UTF-8");
    };
    serde_json::from_str(text).or_else(|_| err("the body is not JSON"))
}

/// `decodeURIComponent`: refuses a stray `%` and bytes that are not UTF-8.
pub fn decode_uri_component(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let h = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `/v1/proxy/:service`'s endpoint as the rules read it: the path without its query, each segment
/// percent-decoded, with no traversal. A segment that decodes to a `/` or a `\` is refused.
pub fn proxy_path(endpoint: &str) -> Result<String, GateParseError> {
    if !endpoint.starts_with('/') || endpoint.starts_with("//") || endpoint.contains('\\') {
        return err("the endpoint is not a relative path");
    }
    let raw = endpoint
        .split(['?', '#'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    let mut out = Vec::new();
    for seg in raw.split('/') {
        let Some(decoded) = decode_uri_component(seg) else {
            return err("the endpoint is not a valid path");
        };
        if decoded == "."
            || decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.chars().any(|c| (c as u32) < 0x20)
        {
            return err("the endpoint has a traversal segment");
        }
        out.push(decoded);
    }
    Ok(out.join("/"))
}

/// The headers [`parse_route`] reads.
#[derive(Debug, Default, Clone)]
pub struct RouteHeaders<'a> {
    pub content_type: Option<&'a str>,
    /// `x-oo-connector-alias`, as Node gives it (several joined with `, `).
    pub alias: Option<&'a str>,
}

/// What one request to the gate is, from its method, target, headers and (buffered) body. A body
/// the gate cannot read on a route that runs something is refused, never forwarded unread.
pub fn parse_route(
    method: &str,
    url: &str,
    headers: &RouteHeaders,
    body: Option<&[u8]>,
) -> Result<Route, GateParseError> {
    // `url.split("?", 2)`: the path, and the query up to a second `?`.
    let mut parts = url.split('?');
    let path = parts.next().unwrap_or_default();
    let raw_query = parts.next().unwrap_or_default();
    let query = query_pairs(raw_query);
    let m = method.to_uppercase();
    // The runtime reads a body only when it says it is JSON, so a body read under another type is
    // not the one that would run.
    if m == "POST" && media_type(headers.content_type) != "application/json" {
        return err("send it as application/json");
    }
    if path == "/mcp" && m == "POST" {
        // Over MCP the runtime takes the connection from the tool's `connectionName` alone.
        if headers.alias.is_some() || get(&query, "connectionName").is_some() || get(&query, "alias").is_some() {
            return err("over MCP, name the connection with connectionName in the tool's arguments");
        }
        return parse_mcp(body.unwrap_or_default());
    }
    if m == "GET" && path == "/v1/actions" {
        let listing = get(&query, "service").is_some_and(|s| !s.is_empty());
        return Ok(if listing {
            Route::List { via: ListVia::HttpList }
        } else {
            Route::Pass
        });
    }
    if m == "GET" && path == "/v1/actions/search" {
        return Ok(Route::List {
            via: ListVia::HttpSearch,
        });
    }
    let action = path
        .strip_prefix("/v1/actions/")
        .filter(|rest| !rest.is_empty() && !rest.contains('/'));
    if let Some(raw_id) = action {
        let Some(action_id) = decode_uri_component(raw_id) else {
            return err("the action id is not valid");
        };
        if m == "GET" {
            return Ok(Route::Guide {
                via: Via::Http,
                connection_name: connection_name_of(None, headers.alias, &query)?,
                action_id,
                rpc_id: None,
            });
        }
        if m == "POST" {
            if !ACTION_ID.is_match(&action_id) {
                return err("the action id is not valid");
            }
            let doc = match body {
                Some(b) if !b.is_empty() => parse_json(b)?,
                _ => json!({}),
            };
            let Some(b) = doc.as_object() else {
                return err("the body is not an object");
            };
            return Ok(Route::Action {
                via: Via::Http,
                input: nullish_or(b.get("input"), json!({})),
                connection_name: connection_name_of(Some(b), headers.alias, &query)?,
                action_id,
                rpc_id: None,
            });
        }
    }
    let proxy = path
        .strip_prefix("/v1/proxy/")
        .filter(|rest| !rest.is_empty() && !rest.contains('/'));
    // Anything else that writes under `/v1` is refused, not passed.
    if m != "GET" && m != "HEAD" && !(proxy.is_some() && m == "POST") {
        return err("the gate does not forward this request");
    }
    if let Some(service) = proxy
        && m == "POST"
    {
        if !SERVICE.is_match(service) {
            return err("the service is not valid");
        }
        let doc = parse_json(body.unwrap_or_default())?;
        let Some(b) = doc.as_object() else {
            return err("the body is not an object");
        };
        let endpoint = b.get("endpoint").and_then(Value::as_str);
        let verb = b.get("method").and_then(Value::as_str).map(js::to_upper);
        let (Some(endpoint), Some(verb)) = (endpoint.filter(|e| !e.is_empty()), verb) else {
            return err("the proxy call needs an endpoint and a method");
        };
        if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].contains(&verb.as_str()) {
            return err("the proxy call needs an endpoint and a method");
        }
        return Ok(Route::Proxy {
            service: service.to_string(),
            path: proxy_path(endpoint)?,
            endpoint: endpoint.to_string(),
            method: verb,
            query: nullish_or(b.get("query"), Value::Null),
            body: nullish_or(b.get("body"), Value::Null),
            connection_name: connection_name_of(Some(b), headers.alias, &query)?,
        });
    }
    Ok(Route::Pass)
}

/// `v ?? fallback`.
fn nullish_or(v: Option<&Value>, fallback: Value) -> Value {
    match v {
        None | Some(Value::Null) => fallback,
        Some(v) => v.clone(),
    }
}

/// An MCP POST. One message, or a batch: a batch with a `tools/call` in it is refused (send one
/// call per request). A batch of anything else is passed.
fn parse_mcp(body: &[u8]) -> Result<Route, GateParseError> {
    let doc = parse_json(body)?;
    if let Value::Array(list) = &doc {
        if list
            .iter()
            .any(|m| m.get("method").and_then(Value::as_str) == Some("tools/call"))
        {
            return err("send one tool call per request");
        }
        return Ok(Route::Pass);
    }
    let Some(msg) = doc.as_object() else {
        return err("the body is not a JSON-RPC message");
    };
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(Route::Pass);
    }
    let params = msg.get("params").and_then(Value::as_object);
    let rpc_id = match msg.get("id") {
        Some(v @ (Value::String(_) | Value::Number(_))) => Some(v.clone()),
        _ => None,
    };
    let tool = params.and_then(|p| p.get("name")).and_then(Value::as_str);
    let raw_args = params.and_then(|p| p.get("arguments"));
    if raw_args.is_some() && !raw_args.is_some_and(Value::is_object) {
        return err("the tool arguments are not an object");
    }
    let empty = Map::new();
    let args = raw_args.and_then(Value::as_object).unwrap_or(&empty);
    if args.contains_key("alias") {
        return err("over MCP, name the connection with connectionName");
    }
    let connection_name = name(args.get("connectionName"));
    let action_id = args.get("actionId").and_then(Value::as_str);
    match tool {
        Some("execute_action") => {
            let Some(id) = action_id.filter(|a| ACTION_ID.is_match(a)) else {
                return err("execute_action needs a valid actionId");
            };
            Ok(Route::Action {
                via: Via::Mcp,
                action_id: id.to_string(),
                input: nullish_or(args.get("input"), json!({})),
                connection_name,
                rpc_id,
            })
        }
        Some("search_actions") => Ok(Route::List {
            via: ListVia::McpSearch,
        }),
        Some("get_action_guide") => {
            let Some(id) = action_id.filter(|a| ACTION_ID.is_match(a)) else {
                return err("get_action_guide needs a valid actionId");
            };
            Ok(Route::Guide {
                via: Via::Mcp,
                action_id: id.to_string(),
                connection_name,
                rpc_id,
            })
        }
        _ => Ok(Route::Pass),
    }
}

/// The same call with its connection named: `connectionName` in the tool's arguments over MCP, in
/// the body on `/v1`. The body was parsed already, so it is JSON.
pub fn with_connection_name(body: Option<&[u8]>, via: Via, connection_name: &str) -> Vec<u8> {
    let parsed = body
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice::<Value>(b).ok())
        .unwrap_or_else(|| json!({}));
    let mut doc = match parsed {
        Value::Object(o) => o,
        _ => Map::new(),
    };
    match via {
        Via::Mcp => {
            let mut params = doc
                .get("params")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut args = params
                .get("arguments")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            args.insert("connectionName".into(), json!(connection_name));
            params.insert("arguments".into(), Value::Object(args));
            doc.insert("params".into(), Value::Object(params));
        }
        Via::Http => {
            doc.insert("connectionName".into(), json!(connection_name));
        }
    }
    js::stringify(&Value::Object(doc)).into_bytes()
}

/// JSON with its keys sorted and no spaces: the same input always hashes the same. Keys sort as
/// JavaScript sorts them (UTF-16 code units), so a key made here is the one the TS made.
pub fn canonical_json(value: &Value, depth: usize) -> Result<String, GateParseError> {
    if depth > 64 {
        return err("nested too deep");
    }
    match value {
        Value::Array(a) => {
            let parts: Result<Vec<String>, _> = a.iter().map(|v| canonical_json(v, depth + 1)).collect();
            Ok(format!("[{}]", parts?.join(",")))
        }
        Value::Object(o) => {
            let mut entries: Vec<(&String, &Value)> = o.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            let parts: Result<Vec<String>, _> = entries
                .into_iter()
                .map(|(k, v)| {
                    Ok(format!(
                        "{}:{}",
                        js::stringify(&json!(k)),
                        canonical_json(v, depth + 1)?
                    ))
                })
                .collect();
            Ok(format!("{{{}}}", parts?.join(",")))
        }
        v => Ok(js::stringify(v)),
    }
}

/// The one call an approval is for: this agent, this connection, this action, this exact input.
pub fn call_key(
    vm_id: &str,
    connection_id: Option<&str>,
    target: &str,
    input: &Value,
) -> Result<String, GateParseError> {
    let doc = json!([vm_id, connection_id.unwrap_or(""), target, input]);
    Ok(hex::encode(Sha256::digest(canonical_json(&doc, 0)?.as_bytes())))
}

// ---- answers ----------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub fields: Vec<(String, String)>,
    pub data: Option<String>,
}

static BLANK_LINES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n\n+").expect("pattern"));

/// An SSE body as its events: each one's fields in order, and its `data` lines joined.
pub fn parse_sse(text: &str) -> Vec<SseEvent> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = Vec::new();
    for block in BLANK_LINES.split(&text) {
        if js::trim(block).is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        let mut data = Vec::new();
        for line in block.split('\n') {
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = match line.find(':') {
                None => (line, ""),
                Some(i) => (&line[..i], line[i + 1..].strip_prefix(' ').unwrap_or(&line[i + 1..])),
            };
            if field == "data" {
                data.push(value.to_string());
            } else {
                fields.push((field.to_string(), value.to_string()));
            }
        }
        out.push(SseEvent {
            fields,
            data: (!data.is_empty()).then(|| data.join("\n")),
        });
    }
    out
}

pub fn write_sse(events: &[SseEvent]) -> String {
    events
        .iter()
        .map(|e| {
            let mut lines: Vec<String> = e.fields.iter().map(|(f, v)| format!("{f}: {v}")).collect();
            if let Some(d) = &e.data {
                lines.extend(d.split('\n').map(|l| format!("data: {l}")));
            }
            format!("{}\n\n", lines.join("\n"))
        })
        .collect()
}

/// An MCP tool result's payload: OpenConnector puts the same object in `structuredContent` and as JSON text.
pub fn tool_payload(message: &Value) -> Option<Map<String, Value>> {
    let result = message.get("result")?.as_object()?;
    if let Some(s) = result.get("structuredContent").and_then(Value::as_object) {
        return Some(s.clone());
    }
    let first = result.get("content")?.as_array()?.first()?.as_object()?;
    if first.get("type").and_then(Value::as_str) == Some("text")
        && let Some(text) = first.get("text").and_then(Value::as_str)
    {
        return serde_json::from_str::<Value>(text).ok()?.as_object().cloned();
    }
    None
}

fn text_content(payload: &Map<String, Value>) -> Value {
    json!([{"type": "text", "text": js::stringify_pretty(&Value::Object(payload.clone()))}])
}

/// A JSON-RPC answer carrying `payload` as OpenConnector's tools do (`toolResult` in mcp.ts).
pub fn tool_answer(rpc_id: Option<&Value>, payload: Map<String, Value>, is_error: bool) -> Value {
    let mut result = Map::new();
    result.insert("content".into(), text_content(&payload));
    result.insert("structuredContent".into(), Value::Object(payload));
    if is_error {
        result.insert("isError".into(), json!(true));
    }
    json!({"jsonrpc": "2.0", "id": rpc_id.cloned().unwrap_or(Value::Null), "result": result})
}

/// The same JSON-RPC answer with its payload replaced, the rest of it kept.
pub fn with_tool_payload(message: &Map<String, Value>, payload: Map<String, Value>, is_error: bool) -> Value {
    let mut result = message
        .get("result")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    result.shift_remove("isError");
    result.insert("content".into(), text_content(&payload));
    result.insert("structuredContent".into(), Value::Object(payload));
    if is_error {
        result.insert("isError".into(), json!(true));
    }
    let mut out = message.clone();
    out.insert("result".into(), Value::Object(result));
    Value::Object(out)
}

/// What an action listing entry says about itself, for the rules.
pub struct Listed {
    pub id: String,
    pub service: Option<String>,
    pub operation: Option<AppOperation>,
}

pub fn listed_action(v: &Value) -> Option<Listed> {
    let o = v.as_object()?;
    let id = o.get("id")?.as_str()?.to_string();
    Some(Listed {
        id,
        service: o.get("service").and_then(Value::as_str).map(str::to_string),
        operation: o
            .get("operationType")
            .and_then(Value::as_str)
            .and_then(AppOperation::parse),
    })
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunOf {
    pub run_id: Option<String>,
    pub ok: Option<bool>,
    pub error_code: Option<String>,
}

/// The run id (OpenConnector's `executionId`) and whether it worked, from a call's answer.
pub fn run_of(doc: &Value, via: Via) -> RunOf {
    let s = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
    match via {
        Via::Mcp => match tool_payload(doc) {
            None => RunOf::default(),
            Some(p) => RunOf {
                run_id: s(p.get("executionId")),
                ok: p.get("ok").and_then(Value::as_bool),
                error_code: s(p.get("error").and_then(|e| e.get("code"))),
            },
        },
        Via::Http => RunOf {
            run_id: s(doc.get("meta").and_then(|m| m.get("executionId"))),
            ok: doc.get("success").and_then(Value::as_bool),
            error_code: s(doc.get("errorCode")),
        },
    }
}

/// What the content rules read of a call's answer: all of it. Over MCP, the tool result's text is
/// the same payload as `structuredContent`, so it is read once rather than twice.
pub fn result_part(doc: &Value) -> Value {
    let Some(m) = doc.as_object() else { return doc.clone() };
    let Some(result) = m.get("result").and_then(Value::as_object) else {
        return doc.clone();
    };
    if !result.get("structuredContent").is_some_and(Value::is_object) {
        return doc.clone();
    }
    let mut rest = result.clone();
    rest.shift_remove("content");
    let mut out = m.clone();
    out.insert("result".into(), Value::Object(rest));
    Value::Object(out)
}

#[cfg(test)]
mod tests;
