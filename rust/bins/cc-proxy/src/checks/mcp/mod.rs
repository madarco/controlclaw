//! MCP (appendix F feature 24, addon.py 6630-6820, docs/plans/mcp-inspection.md). A remote MCP
//! server an agent added itself is ordinary HTTPS to this proxy. A POST whose JSON body holds a
//! `tools/call` is a tool call, whatever its content type or the order of its fields: it goes to the
//! firewall agent's admission service (`:8796`), which runs the integration rules, approvals and
//! content rules and answers `answer` or `allow`. A `tools/list` answer goes there too, to teach the
//! catalog and lose the tools a rule blocks. The decision is the agent's; this only finds the traffic.
//!
//! Fail closed for tool calls: no answer from the admission service refuses the call. Everything
//! else (initialize, notifications, pings, event streams) passes as it did.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::{Map, Value, json};

use super::web::Web;
use super::{check_host, loopback, pyjson, raw_response};
use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};

const MCP_BODY_MAX: usize = 1024 * 1024;
const MCP_ANSWER_MAX: usize = 4 * 1024 * 1024;
/// A body larger than MCP_BODY_MAX is still parsed up to this, to tell a tool call (refused as too
/// large) from any other large JSON, such as a JSON upload to an API. JSON larger still is refused
/// as a tool call, since only a parse can tell (an escaped `tools\u002fcall` has no bytes to find).
const MCP_PARSE_MAX: usize = 32 * 1024 * 1024;
/// Headers a held call is not sent again with: the connection's own, and the proxy's.
const HEADERS_DROP: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "accept-encoding",
];

pub const META_KIND: &str = "cc_mcp";
pub const META_VM: &str = "cc_mcp_vm";
pub const META_TICKET: &str = "cc_mcp_ticket";
pub const META_READ: &str = "cc_mcp_read";
/// Whether the body was read as plain UTF-8 JSON (`cc_mcp_plain`): a tool call read any other way is refused.
pub const META_PLAIN: &str = "cc_mcp_plain";
/// The tool call's JSON-RPC id (`cc_mcp_id`), for the refusals.
pub const META_ID: &str = "cc_mcp_id";

pub struct Mcp {
    /// `MITM_MCP_ADMISSION_URL`, without a trailing `/`.
    pub url: String,
    pub creds: Arc<super::creds::Creds>,
    /// What "a channel the firewall reads its own way" is (`_own_channel_flow`).
    pub web: Arc<Web>,
    /// The website logins, swapped into a held call's headers as `apply_swaps` does.
    pub logins: Option<Arc<super::logins::Logins>>,
}

pub fn register(pipeline: &mut Pipeline, mcp: Arc<Mcp>) {
    pipeline.push(order::MCP, Arc::new(McpRequest(mcp.clone())));
    pipeline.push(order::RESPONSE_MCP, Arc::new(McpResponse(mcp.clone())));
    pipeline.push(order::ERROR_MCP, Arc::new(McpError(mcp)));
}

/// `_mcp_admission`: one call; the answer as JSON, or an error.
async fn admission(m: &Mcp, path: &str, payload: &Value, timeout: Duration) -> Result<Map<String, Value>, String> {
    let raw = loopback::post(&format!("{}{path}", m.url), pyjson::dumps(payload).as_bytes(), timeout)
        .await
        .map_err(|e| e.to_string())?;
    match super::json::loads(std::str::from_utf8(&raw).map_err(|e| e.to_string())?).map_err(|e| e.to_string())? {
        Value::Object(o) => Ok(o),
        _ => Err("not an object".into()),
    }
}

/// `_mcp_refuse_text`: the call's own id when it is known, so the client pairs the refusal with
/// the call it waits on.
fn refuse_text(message: &str, rpc_id: Option<&Value>) -> String {
    let id = rpc_id.cloned().unwrap_or(Value::Null);
    pyjson::dumps(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": message}}))
}

/// `_mcp_answer`: answered here, recorded as a block under `rule`.
fn mcp_answer(flow: &mut Flow, status: u16, content_type: &str, body: &str, rule: &str) -> Verdict {
    super::note(flow, "block", rule, status, Map::new());
    Verdict::Answer(Box::new(raw_response(status, body.as_bytes().to_vec(), content_type)))
}

/// `_MCP_CALL_NEEDLES`: `tools/call` as a body can carry it in bytes: plain, with JSON's escaped
/// slash, in UTF-16 or UTF-32, either order. One pass over the body.
#[allow(clippy::expect_used)] // built from fixed needles, checked by the tests
static CALL_NEEDLES: std::sync::LazyLock<regex::bytes::Regex> = std::sync::LazyLock::new(|| {
    let mut alts = Vec::new();
    for n in ["tools/call", "tools\\/call", "tools\\u002fcall", "tools\\u002Fcall"] {
        let encodings: [Vec<u8>; 5] = [
            n.as_bytes().to_vec(),
            n.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            n.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            n.chars().flat_map(|c| u32::from(c).to_le_bytes()).collect(),
            n.chars().flat_map(|c| u32::from(c).to_be_bytes()).collect(),
        ];
        for e in encodings {
            alts.push(e.iter().map(|b| format!("\\x{b:02x}")).collect::<String>());
        }
    }
    regex::bytes::Regex::new(&format!("(?-u){}", alts.join("|"))).expect("valid")
});

fn mentions_call(raw: &[u8]) -> bool {
    CALL_NEEDLES.is_match(raw)
}

/// `_BOMS`: UTF-8's and UTF-16's (UTF-32 LE's starts with UTF-16 LE's), and UTF-32 BE's, which
/// the addon misses (it starts with zero bytes and no `{`).
const BOMS: &[&[u8]] = &[b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff"];

/// `bytes.lstrip()`: ASCII whitespace off the start.
fn lstrip(b: &[u8]) -> &[u8] {
    let i = b
        .iter()
        .position(|c| !b" \t\n\r\x0b\x0c".contains(c))
        .unwrap_or(b.len());
    &b[i..]
}

/// `_looks_wide_json`: JSON in UTF-16 or UTF-32: zero bytes round a `{` or `[` at the start. The
/// addon looks at the first 8 bytes only, so leading spaces in UTF-16 or UTF-32 hide the `{`; here
/// zero bytes and whitespace are skipped to the first other byte.
fn looks_wide_json(raw: &[u8]) -> bool {
    let first = raw.iter().find(|b| **b != 0 && !b" \t\n\r\x0b\x0c".contains(b));
    raw.iter().take(8).any(|b| *b == 0) && matches!(first, Some(b'{' | b'['))
}

/// Whether JSON text that parsed holds `NaN`, `Infinity` or `-Infinity`: the only bare `N` or `I`
/// outside a string in JSON that Python takes.
fn has_constant(text: &str) -> bool {
    let mut in_str = false;
    let mut escaped = false;
    for b in text.bytes() {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else if b == b'"' {
            in_str = true;
        } else if b == b'N' || b == b'I' {
            return true;
        }
    }
    false
}

/// `_mcp_plain`: the body as plain UTF-8 JSON, the one reading every server shares; `None` on
/// anything else: a BOM, a bad byte, or `NaN`/`Infinity` (Python's parser takes them, JavaScript's
/// does not).
/// Also the document when only a constant kept it from being plain (`json.loads(bytes)` reads it
/// the same way, so it is not parsed again).
fn plain(raw: &[u8]) -> Result<Value, Option<Value>> {
    if raw.starts_with(b"\xef\xbb\xbf") {
        return Err(None);
    }
    let text = std::str::from_utf8(raw).map_err(|_| None)?;
    let doc = super::json::loads(text).map_err(|_| None)?;
    if has_constant(text) { Err(Some(doc)) } else { Ok(doc) }
}

/// `json.detect_encoding`, then the text; `None` when it does not decode.
fn json_text(b: &[u8]) -> Option<String> {
    let utf16 = |b: &[u8], le: bool| -> Option<String> {
        if !b.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = b
            .chunks(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units).ok()
    };
    let utf32 = |b: &[u8], le: bool| -> Option<String> {
        if !b.len().is_multiple_of(4) {
            return None;
        }
        b.chunks(4)
            .map(|c| {
                let a = [c[0], c[1], c[2], c[3]];
                char::from_u32(if le {
                    u32::from_le_bytes(a)
                } else {
                    u32::from_be_bytes(a)
                })
            })
            .collect()
    };
    if let Some(r) = b.strip_prefix(b"\xef\xbb\xbf") {
        return std::str::from_utf8(r).ok().map(str::to_owned);
    }
    if let Some(r) = b.strip_prefix(b"\xff\xfe\x00\x00") {
        return utf32(r, true);
    }
    if let Some(r) = b.strip_prefix(b"\x00\x00\xfe\xff") {
        return utf32(r, false);
    }
    if let Some(r) = b.strip_prefix(b"\xff\xfe") {
        return utf16(r, true);
    }
    if let Some(r) = b.strip_prefix(b"\xfe\xff") {
        return utf16(r, false);
    }
    if b.len() == 2 {
        if b[0] == 0 {
            return utf16(b, false);
        }
        if b[1] == 0 {
            return utf16(b, true);
        }
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] == 0 { utf32(b, false) } else { utf16(b, false) };
        }
        if b[1] == 0 {
            return if b[2] == 0 && b[3] == 0 {
                utf32(b, true)
            } else {
                utf16(b, true)
            };
        }
    }
    std::str::from_utf8(b).ok().map(str::to_owned)
}

/// How `mcp_request_kind` read a body: its kind, whether it was plain UTF-8 JSON
/// (`cc_mcp_plain`), and the tool call's id (`cc_mcp_id`).
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub kind: &'static str,
    pub plain: bool,
    pub id: Option<Value>,
}

/// The keys a server reads a call by (`_MCP_KEYS`). Go's encoding/json (mcp-go, GitHub's MCP
/// server) takes any case, and folds `ſ` to `s` and the Kelvin sign to `k`.
const MCP_KEYS: &[&str] = &["jsonrpc", "method", "params", "name", "arguments", "id"];

/// `str.casefold()` for what can fold to these keys: lower case (the Kelvin sign is `k` there),
/// and `ß`, `ſ` and the Latin ligatures folded as Python folds them.
fn casefold(k: &str) -> String {
    let mut out = String::with_capacity(k.len());
    for c in k.chars() {
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'ſ' => out.push('s'),
            'ﬀ' => out.push_str("ff"),
            'ﬁ' => out.push_str("fi"),
            'ﬂ' => out.push_str("fl"),
            'ﬃ' => out.push_str("ffi"),
            'ﬄ' => out.push_str("ffl"),
            'ﬅ' | 'ﬆ' => out.push_str("st"),
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// `_mcp_odd_keys`: whether a tool call (its method `tools/call` under a key of any case) has one
/// of those keys, in it or in its params, written in another case. Other JSON is not one.
fn odd_keys(msgs: &[Value]) -> bool {
    let odd = |d: &Value| {
        d.as_object().is_some_and(|o| {
            o.keys()
                .any(|k| !MCP_KEYS.contains(&k.as_str()) && MCP_KEYS.contains(&casefold(k).as_str()))
        })
    };
    msgs.iter().any(|m| {
        let Some(o) = m.as_object() else { return false };
        let call = o
            .iter()
            .any(|(k, v)| casefold(k) == "method" && v.as_str() == Some("tools/call"));
        call && (odd(m) || o.iter().any(|(k, v)| casefold(k) == "params" && odd(v)))
    })
}

/// A message's id when it is `isinstance(id, (str, int)) and not isinstance(id, bool)`.
fn rpc_id(m: &Value) -> Option<Value> {
    m.get("id")
        .filter(|i| i.is_string() || i.is_i64() || i.is_u64())
        .cloned()
}

/// `mcp_request_kind`: `call` when a JSON body holds a `tools/call`, `list` or `other` for other
/// JSON-RPC, `None` otherwise.
pub fn kind(flow: &Flow) -> Option<&'static str> {
    read(flow).map(|r| r.kind)
}

/// [`kind`], with how the body was read.
pub fn read(flow: &Flow) -> Option<Reading> {
    let r = flow.request.as_ref()?;
    if r.method() != http::Method::POST {
        return None;
    }
    let raw = r.body();
    // JSON, or JSON in UTF-16/32 (a zero byte next to the first character) or behind a BOM:
    // servers read all of them (Python's `json.loads(bytes)` does), so all are looked at.
    if !matches!(lstrip(raw).first(), Some(b'{' | b'['))
        && !BOMS.iter().any(|b| raw.starts_with(b))
        && !looks_wide_json(raw)
    {
        return None;
    }
    let call = |plain, id| Reading {
        kind: "call",
        plain,
        id,
    };
    if raw.len() > MCP_PARSE_MAX {
        // Too large to parse: JSON this large is a tool call, never sent unchecked (a byte search
        // misses `tools/call` and the like).
        return Some(call(false, None));
    }
    // As a server could read it: plain UTF-8, then bytes (BOM and UTF-16/32 detected), then UTF-8
    // with bad bytes replaced (the TypeScript SDK's way). Only the first is plain: a tool call
    // read any other way is refused.
    let (doc, plain) = match plain(raw) {
        Ok(d) => (d, true),
        Err(Some(d)) => (d, false),
        Err(None) => {
            // UTF-8 with no mark and no zero byte decodes to the text the plain reading already
            // tried, and valid UTF-8 is what the lossy one would read: neither is parsed again.
            let utf8 = std::str::from_utf8(raw).is_ok();
            let other = raw.starts_with(b"\xef\xbb\xbf")
                || raw.iter().take(4).any(|b| *b == 0)
                || raw.starts_with(b"\xff\xfe")
                || raw.starts_with(b"\xfe\xff");
            let wide = || {
                other
                    .then(|| json_text(raw))
                    .flatten()
                    .and_then(|t| super::json::loads(&t).ok())
            };
            let lossy = || {
                (!utf8)
                    .then(|| String::from_utf8_lossy(raw))
                    .and_then(|t| super::json::loads(t.trim_start_matches('\u{feff}')).ok())
            };
            match wide().or_else(lossy) {
                Some(d) => (d, false),
                // Not JSON to us; a server may still run it. A body that names a tool call is one.
                None => return mentions_call(raw).then(|| call(false, None)),
            }
        }
    };
    let msgs: Vec<Value> = match doc {
        Value::Array(a) => a,
        other => vec![other],
    };
    if odd_keys(&msgs) {
        // Read one way here and another by a server that matches keys in any case: a call.
        let id = msgs.iter().filter(|m| m.is_object()).find_map(rpc_id);
        return Some(call(false, id));
    }
    let methods: Vec<&str> = msgs
        .iter()
        .filter_map(|m| m.as_object()?.get("method")?.as_str())
        .collect();
    if methods.contains(&"tools/call") {
        let id = msgs
            .iter()
            .find(|m| m.get("method").and_then(Value::as_str) == Some("tools/call"))
            .and_then(rpc_id);
        return Some(call(plain, id));
    }
    if methods.is_empty()
        || !msgs
            .iter()
            .any(|m| m.as_object().is_some_and(|o| o.contains_key("jsonrpc")))
    {
        return None;
    }
    let kind = if methods.contains(&"tools/list") {
        "list"
    } else {
        "other"
    };
    Some(Reading { kind, plain, id: None })
}

/// `mcp_host`: the server as the integration rules name it (its port when not 443). The name the
/// client handshook with, the one the request claims and the checked destination must agree.
pub fn host(flow: &Flow) -> Option<String> {
    let host = check_host(flow);
    let claimed = flow.claimed_host().map(|h| h.trim_end_matches('.').to_lowercase());
    let sni = flow
        .sni
        .as_deref()
        .map(|s| s.trim_end_matches('.').to_lowercase())
        .filter(|s| !s.is_empty());
    if sni.as_deref().is_some_and(|s| s != host) || claimed.as_deref().is_some_and(|c| c != host) {
        return None;
    }
    let port = super::logins::scope::port(flow);
    Some(if port == 443 { host } else { format!("{host}:{port}") })
}

/// The header part of `apply_swaps` for a held call's headers: a legacy credential's header
/// locations (a substring swap) and a custom secret's header (the whole value, with its prefix).
fn held_swaps(creds: &super::creds::Creds, headers: &mut Map<String, Value>, host: &str, vm: Option<&str>) {
    for c in creds.for_host(host, vm) {
        let (ph, secret) = (
            super::logins::scope::str_of(&c, "placeholder"),
            super::logins::scope::str_of(&c, "secret"),
        );
        if ph.is_empty()
            || secret.is_empty()
            || super::creds::truthy(c.get("login_id"))
            || super::creds::truthy(c.get("speech"))
        {
            continue;
        }
        if super::creds::truthy(c.get("secret_name")) {
            for loc in c
                .get("secret_locations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if loc.get("kind").and_then(Value::as_str) != Some("header") {
                    continue;
                }
                let name = loc.get("name").and_then(Value::as_str).unwrap_or("").to_lowercase();
                let prefix = loc.get("prefix").and_then(Value::as_str).unwrap_or("");
                if headers.get(&name).and_then(Value::as_str) == Some(&format!("{prefix}{ph}")) {
                    headers.insert(name, json!(format!("{prefix}{secret}")));
                }
            }
            continue;
        }
        let locations: Vec<String> = match c.get("locations").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            _ => ["header:authorization", "header:x-api-key", "header:private-token"]
                .map(String::from)
                .to_vec(),
        };
        for loc in locations {
            if let Some(name) = loc.strip_prefix("header:")
                && let Some(v) = headers
                    .get(&name.to_lowercase())
                    .and_then(Value::as_str)
                    .filter(|v| v.contains(&ph))
            {
                let swapped = v.replace(&ph, &secret);
                headers.insert(name.to_lowercase(), json!(swapped));
            }
        }
    }
}

/// `{k.lower(): v for k, v in headers.items()}`: a repeated header's values joined with `, `, as
/// mitmproxy's `headers.items()` gives them.
fn sendable_headers(r: &http::Request<Bytes>) -> Map<String, Value> {
    let mut out = Map::new();
    for name in r.headers().keys() {
        let lower = name.as_str().to_lowercase();
        if HEADERS_DROP.contains(&lower.as_str()) {
            continue;
        }
        let joined: Vec<String> = r
            .headers()
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        out.insert(lower, json!(joined.join(", ")));
    }
    out
}

pub struct McpRequest(pub Arc<Mcp>);

impl Step for McpRequest {
    fn name(&self) -> &'static str {
        "mcp"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// Any POST body to a site that is not a model provider or a channel: a tool call can be in
    /// any, whatever its type (`read` takes POSTs only).
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        flow.request.as_ref().is_some_and(|r| r.method() == http::Method::POST)
            && super::request_has_body(flow)
            && !super::web::own_channel(&self.0.web, flow)
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move { request(&self.0, flow).await.unwrap_or(Verdict::Continue) })
    }
}

/// `mcp_request`: `Some` when the call was answered here.
async fn request(m: &Mcp, flow: &mut Flow) -> Option<Verdict> {
    // Model providers, the control plane and the channels read their own way are never MCP servers.
    if super::web::own_channel(&m.web, flow) {
        return None;
    }
    // A body the plumbing has not decoded, or that went past the checks unread, cannot be read
    // for a tool call: a request with one is refused, as one that could not be checked.
    if super::request_body_unread(flow) && flow.request.as_ref().is_some_and(|r| r.method() == http::Method::POST) {
        let t = refuse_text(
            "The firewall could not check this tool call, so it did not send it. Try again in a minute.",
            None,
        );
        return Some(mcp_answer(
            flow,
            503,
            "application/json",
            &t,
            "integrations: check failed",
        ));
    }
    let Reading { kind, plain, id } = read(flow)?;
    flow.meta.insert(META_KIND, json!(kind));
    flow.meta.insert(META_VM, json!(flow.vm_id));
    flow.meta.insert(META_PLAIN, json!(plain));
    if let Some(id) = &id {
        flow.meta.insert(META_ID, id.clone());
    }
    if kind != "call" {
        return None;
    }
    let (Some(vm), Some(host)) = (flow.vm_id.clone().filter(|v| !v.is_empty()), host(flow)) else {
        let t = refuse_text(
            "The firewall could not tell which agent or which server this tool call is for, so it did not send it.",
            id.as_ref(),
        );
        return Some(mcp_answer(flow, 403, "application/json", &t, "integrations: unknown"));
    };
    let r = flow.request.as_ref()?;
    if r.body().len() > MCP_BODY_MAX {
        let t = refuse_text("That tool call is too large for the firewall to check.", id.as_ref());
        return Some(mcp_answer(flow, 413, "application/json", &t, "integrations: too large"));
    }
    if !plain {
        // A BOM, UTF-16/32, a bad byte, NaN, or not JSON to us: the check would read it one way
        // and the server another.
        let t = refuse_text(
            "The firewall could not read this tool call, so it did not send it. Send it as plain UTF-8 JSON.",
            id.as_ref(),
        );
        return Some(mcp_answer(
            flow,
            400,
            "application/json",
            &t,
            "integrations: unreadable",
        ));
    }
    let scheme = if super::logins::scope::is_https(flow) {
        "https"
    } else {
        "http"
    };
    let payload = json!({"vm_id": vm, "host": host, "url": format!("{scheme}://{host}{}", super::logins::scope::target(flow)),
                         "headers": sendable_headers(r), "body": String::from_utf8_lossy(r.body())});
    let verdict = match admission(m, "/call", &payload, Duration::from_secs(30)).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("[mcp] admission failed, refusing the tool call: {e}");
            let t = refuse_text(
                "The firewall could not check this tool call, so it did not send it. Try again in a minute.",
                id.as_ref(),
            );
            return Some(mcp_answer(
                flow,
                503,
                "application/json",
                &t,
                "integrations: check failed",
            ));
        }
    };
    match verdict.get("action").and_then(Value::as_str) {
        Some("answer") => {
            if let Some(hold_ref) = verdict.get("hold_ref").filter(|h| super::creds::truthy(Some(h))) {
                // Held for Send: the call goes out later from the firewall, with the headers this
                // proxy would have sent, credentials swapped in (to the firewall agent on loopback,
                // never outward). This flow is answered here and never sent on.
                // The website logins go in on the flow itself, which is never sent on.
                if let Some(logins) = &m.logins {
                    logins.swap(flow);
                }
                let mut headers = flow.request.as_ref().map(sendable_headers).unwrap_or_default();
                held_swaps(&m.creds, &mut headers, &check_host(flow), flow.vm_id.as_deref());
                if let Err(e) = admission(
                    m,
                    "/held",
                    &json!({"hold_ref": hold_ref, "headers": headers}),
                    Duration::from_secs(5),
                )
                .await
                {
                    tracing::warn!("[mcp] could not keep a held call's headers: {e}");
                }
            }
            // `int(verdict.get("status") or 200)`: a status that is not a number is refused here
            // (the addon raised, and mitmproxy let the flow on).
            let status = match verdict.get("status") {
                None | Some(Value::Null) => Some(200),
                Some(v) if !super::creds::truthy(Some(v)) => Some(200),
                // `int(200.0)` is 200; `int(200.5)` is 200 too.
                Some(Value::Number(n)) => n
                    .as_u64()
                    .or_else(|| {
                        n.as_f64()
                            .filter(|f| f.is_finite() && *f >= 0.0)
                            .map(|f| f.trunc() as u64)
                    })
                    .and_then(|n| u16::try_from(n).ok()),
                Some(Value::String(s)) => s.trim().parse().ok(),
                _ => None,
            };
            let ct = verdict
                .get("content_type")
                .filter(|c| super::creds::truthy(Some(c)))
                .map_or_else(
                    || "application/json".to_owned(),
                    |c| super::logins::scope::str_of(&json!({"c": c}), "c"),
                );
            let body = verdict
                .get("body")
                .filter(|b| super::creds::truthy(Some(b)))
                .map(|b| super::logins::scope::str_of(&json!({"b": b}), "b"))
                .unwrap_or_default();
            Some(match status.filter(|s| (100..=999).contains(s)) {
                Some(s) => mcp_answer(flow, s, &ct, &body, "integrations"),
                None => {
                    let t = refuse_text(
                        "The firewall could not check this tool call, so it did not send it. Try again in a minute.",
                        id.as_ref(),
                    );
                    mcp_answer(flow, 503, "application/json", &t, "integrations: check failed")
                }
            })
        }
        Some("allow") => {
            flow.meta
                .insert(META_TICKET, verdict.get("ticket").cloned().unwrap_or(Value::Null));
            flow.meta
                .insert(META_READ, json!(super::creds::truthy(verdict.get("read_result"))));
            // Its arguments were read under the Integrations channel: the website check is not run again.
            flow.meta.insert(super::META_MCP_CHECKED, json!(true));
            None
        }
        _ => None,
    }
}

pub struct McpResponse(pub Arc<Mcp>);

impl Step for McpResponse {
    fn name(&self) -> &'static str {
        "mcp-response"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// A `tools/list` answer or a tool call's result, as the request step marked them.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        flow.meta.contains_key(META_KIND) || super::creds::truthy(flow.meta.get(META_TICKET))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            response(&self.0, flow).await;
            Verdict::Continue
        })
    }
}

/// `mcp_response`: a `tools/list` answer to the catalog (and rewritten), a tool call's result to its checks.
async fn response(m: &Mcp, flow: &mut Flow) {
    let kind = flow.meta.get(META_KIND).and_then(Value::as_str).map(str::to_owned);
    let ticket = flow
        .meta
        .get(META_TICKET)
        .filter(|t| super::creds::truthy(Some(t)))
        .cloned();
    let vm = flow.meta.get(META_VM).and_then(Value::as_str).map(str::to_owned);
    let read = super::creds::truthy(flow.meta.get(META_READ));
    let Some(resp) = flow.response.as_ref() else { return };
    if kind.as_deref() != Some("list") && ticket.is_none() {
        return;
    }
    let ct = super::body::content_type(resp.headers());
    let status = resp.status().as_u16();
    // A body the plumbing did not decode cannot be read: as one that could not be read.
    let body = super::body_ready(flow).then(|| resp.body().clone());
    let replace = |flow: &mut Flow, text: String| {
        if let Some(r) = flow.response.as_mut() {
            super::set_body(r, text.into_bytes());
        }
    };
    if kind.as_deref() == Some("list") {
        let Some(host) = host(flow) else { return };
        if body.is_none() {
            // Not decoded: the list cannot be read, so the tools a rule blocks cannot be taken out.
            replace(
                flow,
                refuse_text(
                    "The firewall could not check this list of tools, so it kept it from you.",
                    None,
                ),
            );
            if let Some(r) = flow.response.as_mut() {
                r.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
            }
            return;
        }
        let Some(vm) = vm else { return };
        let Some(b) = body.filter(|b| b.len() <= MCP_ANSWER_MAX) else {
            // Too large to check: it could still name blocked tools, so it is kept from the agent.
            // The addon passed it unchanged; a difference on purpose.
            replace(
                flow,
                refuse_text(
                    "The firewall could not check this list of tools, so it kept it from you.",
                    None,
                ),
            );
            if let Some(r) = flow.response.as_mut() {
                r.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
            }
            return;
        };
        let payload = json!({"vm_id": vm, "host": host, "content_type": ct, "body": String::from_utf8_lossy(&b)});
        match admission(m, "/tools", &payload, Duration::from_secs(30)).await {
            Ok(r) if r.get("action").and_then(Value::as_str) == Some("replace") => replace(
                flow,
                r.get("body")
                    .filter(|b| super::creds::truthy(Some(b)))
                    .map(|b| super::logins::scope::str_of(&json!({"b": b}), "b"))
                    .unwrap_or_default(),
            ),
            Ok(_) => {}
            Err(e) => {
                // Fail closed: a list that could not be checked could still name blocked tools.
                tracing::warn!("[mcp] answer check failed: {e}");
                replace(
                    flow,
                    refuse_text(
                        "The firewall could not check this list of tools, so it kept it from you.",
                        None,
                    ),
                );
                if let Some(r) = flow.response.as_mut() {
                    r.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/json"),
                    );
                }
            }
        }
        return;
    }
    let ticket = ticket.unwrap_or(Value::Null);
    if !read {
        if let Err(e) = admission(
            m,
            "/done",
            &json!({"ticket": ticket, "status": status, "ok": status < 400}),
            Duration::from_secs(5),
        )
        .await
        {
            tracing::warn!("[mcp] answer check failed: {e}");
        }
        return;
    }
    let payload = match body.filter(|b| b.len() <= MCP_ANSWER_MAX) {
        Some(b) => json!({"ticket": ticket, "status": status, "content_type": ct, "body": String::from_utf8_lossy(&b)}),
        // A result too large to check does not reach the agent while a rule covers results.
        None => json!({"ticket": ticket, "status": status, "content_type": ct, "body": "", "too_large": true}),
    };
    match admission(m, "/result", &payload, Duration::from_secs(30)).await {
        Ok(r) if r.get("action").and_then(Value::as_str) == Some("replace") => replace(
            flow,
            r.get("body")
                .filter(|b| super::creds::truthy(Some(b)))
                .map(|b| super::logins::scope::str_of(&json!({"b": b}), "b"))
                .unwrap_or_default(),
        ),
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("[mcp] answer check failed: {e}");
            // Fail closed: a result that was to be checked and could not be does not reach the agent.
            replace(
                flow,
                refuse_text(
                    "The firewall could not check this result, so it kept it from you.",
                    None,
                ),
            );
            if let Some(r) = flow.response.as_mut() {
                r.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
            }
        }
    }
}

/// `error`: a tool call that never got an answer closes its row.
pub struct McpError(pub Arc<Mcp>);

impl Step for McpError {
    fn name(&self) -> &'static str {
        "mcp-error"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Error]
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if let Some(ticket) = flow
                .meta
                .get(META_TICKET)
                .filter(|t| super::creds::truthy(Some(t)))
                .cloned()
            {
                let _ = admission(
                    &self.0,
                    "/done",
                    &json!({"ticket": ticket, "status": 0, "ok": false, "error": "server_unreachable"}),
                    Duration::from_secs(5),
                )
                .await;
            }
            Verdict::Continue
        })
    }
}

#[cfg(test)]
mod tests;
