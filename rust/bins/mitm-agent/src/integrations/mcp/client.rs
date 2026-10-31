//! The firewall as an MCP client of a managed server (`mcp-client.ts`), for two things only:
//! checking a server answers when a person adds it, and reading its tool list for the console
//! (`tools/list`). It never calls a tool. Streamable HTTP; an answer may be JSON or an SSE stream.

use std::sync::LazyLock;
use std::time::Duration;

use bytes::Bytes;
use regex::Regex;
use serde_json::{Map, Value, json};
use url::Url;

use super::public::{PublicAnswer, Request, public_fetch};
use crate::integrations::js;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Kept of each tool for the console: metadata only, cut to size.
pub const TOOLS_MAX: usize = 500;
pub const TOOL_DESCRIPTION_MAX: usize = 500;
/// All of `list_tools` together: a slow server cannot hold a command for minutes.
pub const LIST_TOOLS_TOTAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct McpServerError {
    pub message: String,
    /// The server's 401, with what it said about signing in (`WWW-Authenticate`).
    pub unauthorized: Option<Option<String>>,
}

impl McpServerError {
    fn new(m: impl Into<String>) -> Self {
        Self {
            message: m.into(),
            unauthorized: None,
        }
    }
}

/// `s.slice(0, n)`.
pub fn cut(s: &str, n: usize) -> String {
    crate::integrations::connectors::firewall::js_slice(s, n)
}

pub static TOOL_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.:/-]{1,128}$").expect("pattern"));

/// The JSON-RPC answer with this id, from a JSON body or an SSE stream.
pub fn rpc_answer(content_type: &str, body: &[u8], id: u64) -> Option<Map<String, Value>> {
    let text = String::from_utf8_lossy(body);
    let pick = |doc: &Value| -> Option<Map<String, Value>> {
        let list = match doc {
            Value::Array(a) => a.clone(),
            v => vec![v.clone()],
        };
        list.into_iter()
            .filter_map(|m| m.as_object().cloned())
            .find(|m| m.get("id").and_then(Value::as_f64) == Some(id as f64))
    };
    if content_type.to_lowercase().contains("text/event-stream") {
        static EVENTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n\r?\n").expect("pattern"));
        static LINES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n").expect("pattern"));
        for event in EVENTS.split(&text) {
            let data: Vec<&str> = LINES
                .split(event)
                .filter(|l| l.starts_with("data:"))
                .map(|l| l[5..].strip_prefix(' ').unwrap_or(&l[5..]))
                .collect();
            let data = data.join("\n");
            if data.is_empty() {
                continue;
            }
            if let Ok(doc) = serde_json::from_str::<Value>(&data)
                && let Some(hit) = pick(&doc)
            {
                return Some(hit);
            }
        }
        return None;
    }
    serde_json::from_str::<Value>(&text).ok().and_then(|d| pick(&d))
}

/// One tool, as the console keeps it: `{name, title, description, annotations}`.
pub fn clean_tool(raw: &Value) -> Option<Value> {
    let t = raw.as_object()?;
    let name = t.get("name")?.as_str().filter(|n| TOOL_NAME.is_match(n))?;
    let a = t.get("annotations").and_then(Value::as_object);
    let mut annotations = Map::new();
    for k in ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] {
        if let Some(b) = a.and_then(|a| a.get(k)).and_then(Value::as_bool) {
            annotations.insert(k.into(), json!(b));
        }
    }
    if let Some(title) = a.and_then(|a| a.get("title")).and_then(Value::as_str) {
        annotations.insert("title".into(), json!(cut(title, 120)));
    }
    let s = |k: &str, n: usize| {
        t.get(k)
            .and_then(Value::as_str)
            .map(|v| json!(cut(v, n)))
            .unwrap_or(Value::Null)
    };
    Some(
        json!({"name": name, "title": s("title", 120), "description": s("description", TOOL_DESCRIPTION_MAX), "annotations": annotations}),
    )
}

pub struct Listed {
    pub tools: Vec<Value>,
    pub server_name: Option<String>,
}

/// Initialize a session and read every tool (`tools/list`, following `nextCursor`), then end the
/// session.
pub async fn list_tools(url: &Url, headers: &[(String, String)], timeout: Duration) -> Result<Listed, McpServerError> {
    match tokio::time::timeout(LIST_TOOLS_TOTAL, list_tools_once(url, headers, timeout)).await {
        Ok(r) => r,
        Err(_) => Err(McpServerError::new("The server took too long to list its tools.")),
    }
}

struct Session<'a> {
    url: &'a Url,
    headers: &'a [(String, String)],
    timeout: Duration,
    session: Option<String>,
    id: u64,
}

impl Session<'_> {
    async fn post(&self, body: Value) -> Result<PublicAnswer, McpServerError> {
        let mut h: Vec<(String, String)> = self.headers.to_vec();
        h.push(("content-type".into(), "application/json".into()));
        h.push(("accept".into(), "application/json, text/event-stream".into()));
        h.push(("mcp-protocol-version".into(), PROTOCOL_VERSION.into()));
        if let Some(s) = &self.session {
            h.push(("mcp-session-id".into(), s.clone()));
        }
        let req = Request {
            method: "POST",
            headers: h,
            body: Some(Bytes::from(js::stringify(&body))),
            timeout: self.timeout,
        };
        let answer = public_fetch(self.url, req, 4 * 1024 * 1024)
            .await
            .map_err(|e| McpServerError::new(format!("The server did not answer: {e}.")))?;
        match answer.status {
            401 => Err(McpServerError {
                message: "The server wants a sign-in.".into(),
                unauthorized: Some(answer.header("www-authenticate")),
            }),
            403 => Err(McpServerError::new("The server refused the credential (403).")),
            404 | 405 => Err(McpServerError::new(format!(
                "The server answered {}. It may only speak the older HTTP+SSE transport, which managed servers do not support, or the address is wrong.",
                answer.status
            ))),
            s if s >= 300 && s != 202 => Err(McpServerError::new(format!("The server answered HTTP {s}."))),
            _ => Ok(answer),
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Map<String, Value>, McpServerError> {
        self.id += 1;
        let rid = self.id;
        let answer = self
            .post(json!({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
            .await?;
        let ctype = answer.header("content-type").unwrap_or_default();
        let Some(rpc) = rpc_answer(&ctype, &answer.body, rid) else {
            return Err(McpServerError::new(format!(
                "The server's answer to {method} could not be read."
            )));
        };
        if let Some(e) = rpc.get("error") {
            let what = e
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| js::stringify(e.get("code").unwrap_or(&Value::Null)));
            return Err(McpServerError::new(format!(
                "The server refused {method}: {}.",
                cut(&what, 200)
            )));
        }
        Ok(rpc
            .get("result")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default())
    }
}

async fn list_tools_once(url: &Url, headers: &[(String, String)], timeout: Duration) -> Result<Listed, McpServerError> {
    let mut s = Session {
        url,
        headers,
        timeout,
        session: None,
        id: 1,
    };
    let init = s
        .post(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_VERSION,
            "capabilities": {}, "clientInfo": {"name": "controlclaw-firewall", "version": "1"}}}),
        )
        .await?;
    s.session = init.header("mcp-session-id").filter(|v| !v.is_empty());
    let rpc = rpc_answer(&init.header("content-type").unwrap_or_default(), &init.body, 1);
    let Some(result) = rpc
        .as_ref()
        .and_then(|r| r.get("result"))
        .and_then(Value::as_object)
        .cloned()
    else {
        let message = match rpc.as_ref().and_then(|r| r.get("error")) {
            Some(e) => format!(
                "The server refused to start a session: {}.",
                cut(
                    &e.get("message")
                        .map(|m| m.as_str().map(str::to_string).unwrap_or_else(|| js::stringify(m)))
                        .unwrap_or_else(|| "undefined".into()),
                    200
                )
            ),
            None => "The server's answer to initialize could not be read. Is this an MCP server address?".into(),
        };
        return Err(McpServerError::new(message));
    };
    let _ = s
        .post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let page = s.call("tools/list", params).await?;
        for raw in page.get("tools").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(t) = clean_tool(&raw)
                && tools.len() < TOOLS_MAX
            {
                tools.push(t);
            }
        }
        cursor = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .map(str::to_string);
        if cursor.is_none() || tools.len() >= TOOLS_MAX {
            break;
        }
    }
    if let Some(sess) = &s.session {
        let mut h: Vec<(String, String)> = headers.to_vec();
        h.push(("mcp-session-id".into(), sess.clone()));
        h.push(("mcp-protocol-version".into(), PROTOCOL_VERSION.into()));
        let req = Request {
            method: "DELETE",
            headers: h,
            body: None,
            timeout: Duration::from_secs(5),
        };
        let _ = public_fetch(url, req, 1024 * 1024).await;
    }
    let server_name = result
        .get("serverInfo")
        .and_then(|i| i.get("name"))
        .and_then(Value::as_str)
        .map(|n| cut(n, 120));
    Ok(Listed { tools, server_name })
}
