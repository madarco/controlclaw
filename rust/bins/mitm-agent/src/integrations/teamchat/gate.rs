//! The chat gate (`teamchat-gate.ts`): the only way an agent box reaches ClickClack.
//!
//! ClickClack listens on loopback of this box. This listener sits on the private address and
//! forwards the chat API and its WebSocket, and nothing else, after three checks:
//!
//! 1. The bearer is a placeholder this firewall gave one agent (`cctc_…`). The gate puts the real
//!    bot token on the request here; the token never leaves this box.
//! 2. The connection comes from that agent's own private address. Another box presenting it gets a
//!    bare 404.
//! 3. That agent is not under an emergency stop (403).
//!
//! Every request is written to the traffic log as metadata, never a body. Content rules are checked
//! here, since the chat does not go through the proxy: a message the agent posts or edits (a JSON
//! write), and the messages it reads. The realtime socket carries only ids, so it is not read.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Frame, Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use regex::Regex;
use serde_json::{Map, Value, json};

use cc_http::{Body, Ctx, Req, Resp};

use crate::contracts::{ChatContent, ChatHold, CheckedRule, ContentError};
use crate::integrations::connectors::gate::{dotted, remote_address, same_address};
use crate::integrations::js;

/// ClickClack's uploads cap at 64 MiB; a little over that for the multipart framing.
pub const GATE_MAX_BODY: u64 = 70 * 1024 * 1024;
/// A JSON write the content rules read is held in memory.
pub const GATE_MAX_CHECKED_BODY: usize = 1024 * 1024;
/// A JSON answer the content rules read (a page of messages).
pub const GATE_MAX_CHECKED_ANSWER: usize = 8 * 1024 * 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(120);
/// Messages of one answer checked at once: each may be a call to the AI.
const CHECKS_AT_ONCE: usize = 4;
/// The fields of a chat write that people see (ClickClack 0.7.1): messages, channel and topic titles
/// and sidebar sections, display names and handles, home links, moderation notes, reactions, bot
/// commands and their hints, the tool name in a progress line (`toolName` too, kept as sent), and the
/// links people's browsers open or fetch. In lower case: keys are compared through `go_json_key`.
const TEXT_KEYS: &[&str] = &[
    "body",
    "text",
    "title",
    "topic",
    "description",
    "purpose",
    "name",
    "display_name",
    "display_title",
    "label",
    "handle",
    "moderation_note",
    "command",
    "emoji",
    "args_hint",
    "tool_name",
    "toolname",
    "sidebar_section",
    "external_url",
    "external_ref",
    "avatar_url",
    "icon_url",
];
/// Request headers never forwarded: the gate decides who the caller is, not the caller.
const DROP: &[&str] = &[
    "authorization",
    "cookie",
    "host",
    "x-clickclack-user",
    "cf-access-jwt-assertion",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "proxy-authorization",
];

/// Writes that post a new message, the ones a hold can keep and post later.
static MESSAGE_POST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^/api/(?:(channels|dms)/([^/]+)/messages|messages/([^/]+)/thread/replies)$").expect("pattern")
});

/// Whether ClickClack reads `k` as one of `TEXT_KEYS` (`goJsonKey`).
fn is_text_key(k: &str) -> bool {
    TEXT_KEYS.contains(&crate::integrations::go_json::go_json_key(k).as_str())
}

/// The strings under `TEXT_KEYS`, at any depth.
pub fn chat_text(value: &Value, under: bool, depth: usize, out: &mut Vec<String>) -> Result<(), String> {
    if depth > 40 {
        return Err("nested too deep".into());
    }
    match value {
        Value::String(s) if under => out.push(s.clone()),
        Value::Array(a) => {
            for v in a {
                chat_text(v, under, depth + 1, out)?;
            }
        }
        Value::Object(o) => {
            for (k, v) in o {
                chat_text(v, under || is_text_key(k), depth + 1, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A message as ClickClack answers it: an object with its words in `body` and an author.
fn as_message(v: &Value) -> Option<(&str, Option<String>)> {
    let o = v.as_object()?;
    let body = o.get("body")?.as_str()?;
    o.get("author_id")?.as_str()?;
    let id = o
        .get("id")
        .and_then(Value::as_str)
        .map(|i| crate::integrations::connectors::firewall::js_slice(i, 100));
    Some((body, id))
}

/// A ClickClack answer with the messages the content rules stop taken out: the one message asked
/// for (`gone`: the gate answers 404), or members of a list. Recurses into objects and arrays.
pub fn filter_messages(
    doc: &Value,
    stopped: &mut dyn FnMut(&str, Option<&str>) -> bool,
) -> Result<(Value, bool), String> {
    if let Some(one) = doc.as_object().and_then(|o| o.get("message"))
        && let Some((body, id)) = as_message(one)
        && stopped(body, id.as_deref())
    {
        return Ok((doc.clone(), true));
    }
    fn walk(v: &Value, depth: usize, stopped: &mut dyn FnMut(&str, Option<&str>) -> bool) -> Result<Value, String> {
        if depth > 40 {
            return Err("nested too deep".into());
        }
        Ok(match v {
            Value::Array(a) => {
                let mut out = Vec::new();
                for x in a {
                    if let Some((body, id)) = as_message(x)
                        && stopped(body, id.as_deref())
                    {
                        continue;
                    }
                    out.push(walk(x, depth + 1, stopped)?);
                }
                Value::Array(out)
            }
            Value::Object(o) => {
                let mut out = Map::new();
                for (k, x) in o {
                    out.insert(k.clone(), walk(x, depth + 1, stopped)?);
                }
                Value::Object(out)
            }
            other => other.clone(),
        })
    }
    Ok((walk(doc, 0, stopped)?, false))
}

/// What an agent may reach: the chat API and its WebSocket. Not sign-in, setup codes or push, and
/// not the webhooks (`/api/hooks/slash/...` reads its text from the query and from any form body,
/// which the gate does not read; the agents' plugin posts through the messages API).
pub fn gate_allows(path: &str) -> bool {
    static NOT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)^/api/(auth|bot-setup-codes|me/push|hooks)(/|$)").expect("pattern"));
    // One spelling of a path: no `%` escapes, `//`, `.` or `..` segments or backslashes. ClickClack's
    // router answers 404 to those today (chi routes on the raw path); the gate does not rely on it.
    static ODD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[%\\]|//|(^|/)\.{1,2}(/|$)").expect("pattern"));
    let bare = path.split('?').next().unwrap_or("");
    !ODD.is_match(bare) && bare.starts_with("/api/") && !NOT.is_match(bare)
}

/// The path as Activity shows it: ids replaced by `[id]`, no query.
pub fn template_path(path: &str) -> String {
    static A: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[a-z]{2,6}_[0-9a-z]{8,}$").expect("pattern"));
    static B: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9A-Z]{12,}$").expect("pattern"));
    static C: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").expect("pattern"));
    let out = path
        .split('?')
        .next()
        .unwrap_or("")
        .split('/')
        .map(|seg| {
            if A.is_match(seg) || B.is_match(seg) || C.is_match(seg) {
                "[id]".to_string()
            } else if seg.encode_utf16().count() > 40 {
                "[…]".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let out = crate::integrations::connectors::firewall::js_slice(&out, 200);
    if out.is_empty() { "/".into() } else { out }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^Bearer\s+(\S+)$").expect("pattern"));
    let h = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    RE.captures(js::trim(h)).map(|c| c[1].to_string())
}

/// Who the placeholder belongs to: `(vm_id, token, private_ip)`.
pub type Resolve = Arc<dyn Fn(&str) -> Option<(String, String, String)> + Send + Sync>;

/// The content rules as the gate sees them.
pub enum ChatContentNow {
    On(Arc<dyn ChatContent>),
    /// Should run and is not up: messages are refused with a 503.
    Unknown,
    Off,
}

pub struct GateOptions {
    /// Where ClickClack listens on loopback.
    pub target: (String, u16),
    pub resolve: Resolve,
    /// True while that agent (or the whole organization) is under an emergency stop.
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub content: Arc<dyn Fn() -> ChatContentNow + Send + Sync>,
    /// The proxy's traffic log, for Activity. None: nothing is recorded.
    pub log_path: Option<std::path::PathBuf>,
}

struct Who {
    vm_id: String,
    token: String,
}

pub struct TeamChatGate {
    opts: GateOptions,
    client: Client<HttpConnector, Body>,
}

fn empty(status: u16) -> Resp {
    let mut r = cc_http::empty(status);
    r.headers_mut()
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(0));
    r
}

/// `JSON.stringify(body).length`: the TS records the text's length in UTF-16 units here.
fn js_len(text: &str) -> u64 {
    text.encode_utf16().count() as u64
}

impl TeamChatGate {
    pub fn new(opts: GateOptions) -> Arc<Self> {
        Arc::new(Self {
            opts,
            client: Client::builder(TokioExecutor::new()).build_http(),
        })
    }

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
        let mut up = cc_http::Router::new(&["upgrade"]);
        let me = self.clone();
        up.route(
            "upgrade",
            |_, _| true,
            move |req, ctx| {
                let me = me.clone();
                async move { me.upgrade(req, ctx).await }
            },
        );
        r.upgrades(up);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        vm_id: Option<&str>,
        method: &str,
        path: &str,
        status: u16,
        bytes_in: u64,
        bytes_out: u64,
        started_at: i64,
        refused: Option<&str>,
    ) {
        let Some(p) = &self.opts.log_path else { return };
        let now = js::now_ms();
        let mut rec = Map::new();
        rec.insert("source".into(), json!("egress"));
        rec.insert(
            "flow_id".into(),
            json!(format!("tc-{}", hex::encode(rand::random::<[u8; 10]>()))),
        );
        rec.insert("ts".into(), json!(now as f64 / 1000.0));
        rec.insert(
            "method".into(),
            json!(crate::integrations::connectors::firewall::js_slice(method, 16)),
        );
        rec.insert("host".into(), json!("team-chat"));
        rec.insert("path".into(), json!(template_path(path)));
        if let Some(v) = vm_id {
            rec.insert("vm_id".into(), json!(v));
        }
        rec.insert("effect".into(), json!(if refused.is_some() { "drop" } else { "allow" }));
        rec.insert("status".into(), json!(status));
        rec.insert("bytes_in".into(), json!(bytes_in));
        rec.insert("bytes_out".into(), json!(bytes_out));
        rec.insert("duration_ms".into(), json!((now - started_at).max(0)));
        rec.insert(
            "rule".into(),
            json!(
                refused
                    .map(|r| format!("team chat: {r}"))
                    .unwrap_or_else(|| "team chat".into())
            ),
        );
        append_line(p, &Value::Object(rec));
    }

    /// Who is calling, or why not. Every refusal looks the same from outside except the stop.
    fn admit(&self, path: &str, headers: &HeaderMap, ctx: &Ctx) -> Result<Who, (u16, &'static str, Option<String>)> {
        let bare = path.split('?').next().unwrap_or("");
        // A path with `.`/`..` segments (or their encodings) is not looked at: ClickClack may read it
        // as another path than the one checked here (beyond the TS, as in the connector gate).
        // And as ClickClack may read it, decoded: `/api/%61uth/…` is `/api/auth/…` (beyond the TS).
        let decoded = percent_decode(bare);
        if !gate_allows(bare) || !gate_allows(&decoded) || dotted(bare) || dotted(&decoded) {
            return Err((404, "path", None));
        }
        let who = bearer(headers).and_then(|p| (self.opts.resolve)(&p));
        let Some((vm_id, token, ip)) = who else {
            return Err((404, "unknown token", None));
        };
        let remote = remote_address(ctx);
        if !same_address(Some(&remote), Some(&ip)) {
            tracing::info!("[teamchat] refused {vm_id}'s token from {remote} (expected {ip})");
            return Err((404, "wrong address", Some(vm_id)));
        }
        if (self.opts.locked)(&vm_id) {
            return Err((403, "emergency stop", Some(vm_id)));
        }
        Ok(Who { vm_id, token })
    }

    fn forward_headers(&self, headers: &HeaderMap, token: &str) -> HeaderMap {
        let mut out = HeaderMap::new();
        for (k, v) in headers {
            if DROP.contains(&k.as_str()) {
                continue;
            }
            out.append(k.clone(), v.clone());
        }
        if let Ok(h) = HeaderValue::from_str(&format!("{}:{}", self.opts.target.0, self.opts.target.1)) {
            out.insert(http::header::HOST, h);
        }
        if let Ok(h) = HeaderValue::from_str(&format!("Bearer {token}")) {
            out.insert(http::header::AUTHORIZATION, h);
        }
        out
    }

    async fn send_up(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: Body,
    ) -> Result<http::Response<Incoming>, String> {
        // Node's socket timeout is an idle one: a large upload that keeps moving is not cut at 120 s.
        // Every frame sent up counts as activity; the wait ends 120 s after the last.
        let last = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let seen = last.clone();
        let body: Body = body
            .map_frame(move |f| {
                *seen.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
                f
            })
            .boxed();
        let mut req = http::Request::new(body);
        *req.method_mut() = method;
        *req.uri_mut() = format!("http://{}:{}{path}", self.opts.target.0, self.opts.target.1)
            .parse()
            .map_err(|e: http::uri::InvalidUri| e.to_string())?;
        *req.headers_mut() = headers;
        let sent = self.client.request(req);
        tokio::pin!(sent);
        loop {
            let until = *last.lock().unwrap_or_else(|e| e.into_inner()) + UPSTREAM_TIMEOUT;
            tokio::select! {
                r = &mut sent => return match r {
                    Ok(r) => Ok(r),
                    Err(e) => Err(if e.is_connect() { "connect failed" } else { "request failed" }.into()),
                },
                _ = tokio::time::sleep_until(until) => {
                    if *last.lock().unwrap_or_else(|e| e.into_inner()) + UPSTREAM_TIMEOUT <= tokio::time::Instant::now() {
                        return Err("timeout".into());
                    }
                }
            }
        }
    }

    pub async fn serve(self: Arc<Self>, req: Req, ctx: Ctx) -> Resp {
        let started_at = js::now_ms();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let method = req.method().to_string();
        let who = match self.admit(&path, req.headers(), &ctx) {
            Ok(w) => w,
            Err((status, why, vm)) => {
                if let Some(v) = &vm {
                    self.record(Some(v), &method, &path, status, 0, 0, started_at, Some(why));
                }
                return empty(status);
            }
        };
        let declared = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if declared > GATE_MAX_BODY {
            self.record(
                Some(&who.vm_id),
                &method,
                &path,
                413,
                0,
                0,
                started_at,
                Some("too large"),
            );
            return empty(413);
        }
        let json_reply = |code: u16, body: Value, refused: Option<&str>| {
            let text = js::stringify(&body);
            self.record(
                Some(&who.vm_id),
                &method,
                &path,
                code,
                0,
                js_len(&text),
                started_at,
                refused,
            );
            let len = text.len();
            let mut r = cc_http::full(
                StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
                "application/json",
                text,
            );
            r.headers_mut()
                .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
            r
        };

        // Which way the content rules read this request: a write going out (any but a file upload),
        // or an answer coming in. Every method but GET, HEAD and OPTIONS writes (`isCheckedWrite`).
        let is_write = !matches!(req.method(), &Method::GET | &Method::HEAD | &Method::OPTIONS);
        let multipart = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| js::trim(t).to_ascii_lowercase().starts_with("multipart/"));
        // ClickClack reads a multipart body only at `POST /api/uploads`; every other handler decodes
        // the body as JSON whatever its Content-Type says, so there a multipart label is checked too.
        // Beyond the TS, which leaves every multipart write unchecked.
        let upload = req.method() == Method::POST && path.split('?').next() == Some("/api/uploads");
        let is_json_write = is_write && !(multipart && upload);
        let is_get = req.method() == Method::GET;
        let mut content: Option<Arc<dyn ChatContent>> = None;
        let (mut check_out, mut check_in) = (false, false);
        if is_json_write || is_get {
            match (self.opts.content)() {
                ChatContentNow::Off => {}
                ChatContentNow::Unknown => {
                    return json_reply(
                        503,
                        json!({"error": "rules_loading", "message": "The firewall is loading its rules. Try again in a few seconds."}),
                        Some("content rules unknown"),
                    );
                }
                ChatContentNow::On(c) => {
                    check_out = is_json_write && c.applies("out");
                    check_in = is_get && c.applies("in");
                    content = Some(c);
                }
            }
        }
        if !check_out {
            let c = if check_in { content } else { None };
            return self.forward(req, who, path, started_at, c).await;
        }
        let c = content.expect("content rules");
        // A write the content rules read: buffered, checked, then sent on (or held, or refused).
        let (parts, body) = req.into_parts();
        // The sender stopped before the body arrived: nothing is checked or sent.
        let Some((raw, over)) = read_up_to(body, GATE_MAX_CHECKED_BODY).await else {
            self.record(
                Some(&who.vm_id),
                &method,
                &path,
                400,
                0,
                0,
                started_at,
                Some("body broken off"),
            );
            return empty(400);
        };
        let reason = |why: &str| json!({"error": "blocked_by_organization_rules", "message": format!("Blocked by your organization's rules: {why}")});
        if over {
            c.record(
                "error",
                "out",
                "block",
                Some(&who.vm_id),
                crate::integrations::as_map(json!({"detail": "too long"})),
                None,
            );
            return json_reply(403, reason("it is too long to check"), Some("content: too long"));
        }
        let text_raw = String::from_utf8_lossy(&raw).into_owned();
        let looks_json = matches!(js::trim(&text_raw).chars().next(), Some('{' | '['))
            || parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|t| js::trim(t).to_ascii_lowercase().starts_with("application/json"));
        // No body (a DELETE, a reaction): no words, as `JSON.parse("")` failing leaves the TS.
        // No body (a DELETE, a reaction): no words, as `JSON.parse("")` failing leaves the TS.
        let text = match serde_json::from_str::<Value>(&text_raw) {
            Err(_) if js::trim(&text_raw).is_empty() => Ok(String::new()),
            Err(_) if js::trim(&text_raw).is_empty() => Ok(String::new()),
            // JSON this check cannot read (a lone surrogate escape, nesting past 128) that ClickClack
            // would: its escaped words are not checked as raw text. Fail closed.
            Err(_) if looks_json => Err("the check could not run".to_string()),
            // Not JSON: every word of it is read, so whatever ClickClack makes of it was checked.
            Err(_) => Ok(text_raw.clone()),
            Ok(doc) => {
                // A key one object names twice, in any case: which value ClickClack keeps is Go's
                // choice, and it can be the one the parser dropped.
                if let Some(twice) = crate::integrations::go_json::duplicate_key(&text_raw) {
                    c.record(
                        "error",
                        "out",
                        "block",
                        Some(&who.vm_id),
                        crate::integrations::as_map(json!({"detail": "ambiguous keys"})),
                        None,
                    );
                    return json_reply(
                        403,
                        reason(&format!("it names \"{twice}\" twice")),
                        Some("content: ambiguous keys"),
                    );
                }
                let mut out = Vec::new();
                chat_text(&doc, false, 0, &mut out).map(|()| out.join("\n"))
            }
        };
        let checked = match text {
            Err(e) => Err(ContentError::Failed(e)),
            Ok(t) if t.is_empty() => Ok((t, None)),
            Ok(t) => c
                .check("out", t.clone(), Some(who.vm_id.clone()), None)
                .await
                .map(|r| (t, r)),
        };
        let (text, rule) = match checked {
            Ok(x) => x,
            Err(e) => {
                // Fail closed: a write the check cannot read is not sent.
                let long = e == ContentError::TooLong;
                let extra = if long { json!({"detail": "too long"}) } else { json!({}) };
                c.record(
                    "error",
                    "out",
                    "block",
                    Some(&who.vm_id),
                    crate::integrations::as_map(extra),
                    None,
                );
                return json_reply(
                    403,
                    reason(if long {
                        "it is too long to check"
                    } else {
                        "the check could not run"
                    }),
                    Some("content: error"),
                );
            }
        };
        let Some(rule) = rule else {
            let req = http::Request::from_parts(parts, ());
            return self
                .forward_buffered(req, who, path, started_at, Bytes::from(raw))
                .await;
        };
        let ai = rule.by.as_ref().map(|b| json!({"ai": b})).unwrap_or(json!({}));
        let bare = path.split('?').next().unwrap_or("").to_string();
        let post = (parts.method == Method::POST)
            .then(|| MESSAGE_POST.captures(&bare))
            .flatten();
        if rule.action == "hold"
            && let Some(caps) = post
        {
            let where_ = match (caps.get(1), caps.get(2), caps.get(3)) {
                (Some(kind), Some(id), _) => format!(
                    "team chat {} {}",
                    if kind.as_str() == "dms" {
                        "conversation"
                    } else {
                        "channel"
                    },
                    id.as_str()
                ),
                (_, _, Some(m)) => format!("a team chat thread (message {})", m.as_str()),
                _ => String::new(),
            };
            let placeholder = bearer(&parts.headers).unwrap_or_default();
            let me = self.clone();
            let (b2, path2) = (Bytes::from(raw.clone()), bare.clone());
            let hold = c
                .hold(ChatHold {
                    vm_id: who.vm_id.clone(),
                    where_,
                    text: text.clone(),
                    rule: rule.clone(),
                    send: Box::new(move || Box::pin(async move { me.post_later(&placeholder, &path2, b2).await })),
                })
                .await;
            if let Some(hold_id) = hold {
                let mut extra = crate::integrations::as_map(json!({"hold": hold_id}));
                extra.extend(crate::integrations::as_map(ai.clone()));
                c.record(&rule.id, "out", "hold", Some(&who.vm_id), extra, None);
                // The agent is told it went (decided 2026-10-15): the people who get codes decide.
                // The text as ClickClack would read it: `body` under any key that folds to it.
                let body = serde_json::from_str::<Value>(&text_raw)
                    .ok()
                    .and_then(|d| {
                        d.as_object()?
                            .iter()
                            .find(|(k, _)| crate::integrations::go_json::go_json_key(k) == "body")
                            .and_then(|(_, v)| v.as_str().map(String::from))
                    })
                    .unwrap_or_default();
                let clean: String = hold_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(24).collect();
                return json_reply(
                    201,
                    json!({"message": {"id": format!("msg_held_{clean}"), "body": body, "author_id": "held", "created_at": js::iso(js::now_ms())}}),
                    None,
                );
            }
            let mut extra = crate::integrations::as_map(json!({"held": false}));
            extra.extend(crate::integrations::as_map(ai));
            c.record(&rule.id, "out", "block", Some(&who.vm_id), extra, None);
            return json_reply(
                403,
                reason(&format!("{} (nobody could be asked to approve it)", rule.reason)),
                Some(&format!("content: {}", rule.id)),
            );
        }
        let mut extra = if rule.action == "hold" {
            crate::integrations::as_map(json!({"held": false}))
        } else {
            Map::new()
        };
        extra.extend(crate::integrations::as_map(ai));
        c.record(&rule.id, "out", "block", Some(&who.vm_id), extra, None);
        c.stopped_here(&rule, "out", Some(&who.vm_id), &text, None);
        let why = if rule.action == "hold" {
            format!("{} (it could not be held for approval)", rule.reason)
        } else {
            rule.reason.clone()
        };
        json_reply(403, reason(&why), Some(&format!("content: {}", rule.id)))
    }

    /// A held message, posted on Send with the agent's token as it is then.
    async fn post_later(&self, placeholder: &str, path: &str, body: Bytes) -> Result<(), String> {
        let Some((vm_id, token, _)) = (self.opts.resolve)(placeholder) else {
            return Err("the agent is no longer in the team chat".into());
        };
        if (self.opts.locked)(&vm_id) {
            return Err("the agent is under an emergency stop".into());
        }
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&format!("{}:{}", self.opts.target.0, self.opts.target.1)) {
            h.insert(http::header::HOST, v);
        }
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
            h.insert(http::header::AUTHORIZATION, v);
        }
        h.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        let full = http_body_util::Full::new(body).map_err(|never| match never {}).boxed();
        let r = self
            .send_up(Method::POST, path, h, full)
            .await
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("the team chat refused it (HTTP {status})"))
        }
    }

    async fn forward_buffered(
        self: &Arc<Self>,
        req: http::Request<()>,
        who: Who,
        path: String,
        started_at: i64,
        body: Bytes,
    ) -> Resp {
        let mut headers = self.forward_headers(req.headers(), &who.token);
        headers.remove(http::header::TRANSFER_ENCODING);
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        let n = body.len() as u64;
        let full = http_body_util::Full::new(body).map_err(|never| match never {}).boxed();
        self.clone()
            .proxy(
                req.method().clone(),
                who,
                path,
                started_at,
                headers,
                full,
                Arc::new(AtomicU64::new(n)),
                None,
            )
            .await
    }

    /// To ClickClack and back, the request streamed; `content` reads a JSON answer for messages the
    /// rules stop (else it is streamed).
    async fn forward(
        self: &Arc<Self>,
        req: Req,
        who: Who,
        path: String,
        started_at: i64,
        content: Option<Arc<dyn ChatContent>>,
    ) -> Resp {
        let (parts, body) = req.into_parts();
        let mut headers = self.forward_headers(&parts.headers, &who.token);
        // An answer the content rules read is asked for as it is: the gate does not decompress.
        if content.is_some() {
            headers.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }
        let bytes_in = Arc::new(AtomicU64::new(0));
        let counted = bytes_in.clone();
        let limited = http_body_util::Limited::new(body, GATE_MAX_BODY as usize)
            .map_frame(move |f: Frame<Bytes>| {
                if let Some(d) = f.data_ref() {
                    counted.fetch_add(d.len() as u64, Ordering::SeqCst);
                }
                f
            })
            .map_err(std::io::Error::other)
            .boxed();
        self.clone()
            .proxy(parts.method, who, path, started_at, headers, limited, bytes_in, content)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn proxy(
        self: Arc<Self>,
        method: Method,
        who: Who,
        path: String,
        started_at: i64,
        headers: HeaderMap,
        body: Body,
        bytes_in: Arc<AtomicU64>,
        content: Option<Arc<dyn ChatContent>>,
    ) -> Resp {
        let m = method.to_string();
        let up = match self.send_up(method, &path, headers, body).await {
            Ok(u) => u,
            Err(e) => {
                tracing::info!("[teamchat] gate upstream failed: {e}");
                self.record(
                    Some(&who.vm_id),
                    &m,
                    &path,
                    502,
                    bytes_in.load(Ordering::SeqCst),
                    0,
                    started_at,
                    None,
                );
                return empty(502);
            }
        };
        let status = up.status().as_u16();
        let encoded = up
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|e| !e.is_empty() && e != "identity");
        let jsonish = up
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.to_ascii_lowercase().contains("json"));
        if let Some(c) = content
            && status == 200
            && (jsonish || encoded)
        {
            return self
                .checked_answer(up, c, who, m, path, started_at, bytes_in, encoded)
                .await;
        }
        let (parts, body) = up.into_parts();
        let bytes_out = Arc::new(AtomicU64::new(0));
        let counted = bytes_out.clone();
        let me = self.clone();
        let done = Done(Some(Box::new(move || {
            me.record(
                Some(&who.vm_id),
                &m,
                &path,
                status,
                bytes_in.load(Ordering::SeqCst),
                bytes_out.load(Ordering::SeqCst),
                started_at,
                None,
            );
        })));
        let stream = futures_util::StreamExt::map(idle(body), move |f| {
            let _done = &done;
            if let Ok(fr) = &f
                && let Some(d) = fr.data_ref()
            {
                counted.fetch_add(d.len() as u64, Ordering::SeqCst);
            }
            f
        });
        let body = BodyExt::boxed(http_body_util::StreamBody::new(stream));
        let mut r = http::Response::new(body);
        *r.status_mut() = parts.status;
        for (k, v) in &parts.headers {
            if k == http::header::TRANSFER_ENCODING || k == http::header::CONNECTION {
                continue;
            }
            r.headers_mut().append(k.clone(), v.clone());
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    async fn checked_answer(
        &self,
        up: http::Response<Incoming>,
        c: Arc<dyn ChatContent>,
        who: Who,
        method: String,
        path: String,
        started_at: i64,
        bytes_in: Arc<AtomicU64>,
        encoded: bool,
    ) -> Resp {
        let read = read_up_to(up.into_body(), GATE_MAX_CHECKED_ANSWER).await;
        let broken = read.is_none();
        let (raw, over) = read.unwrap_or_default();
        let send = |code: u16, text: String| {
            let n = text.len();
            self.record(
                Some(&who.vm_id),
                &method,
                &path,
                code,
                bytes_in.load(Ordering::SeqCst),
                n as u64,
                started_at,
                None,
            );
            let mut r = cc_http::full(
                StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
                "application/json",
                text,
            );
            r.headers_mut()
                .insert(http::header::CONTENT_LENGTH, HeaderValue::from(n));
            r
        };
        let result: Result<Result<(Value, bool), CheckFailed>, String> = async {
            if broken {
                return Err("the answer broke off".into());
            }
            if over {
                return Err(format!("{} bytes is too long to check", GATE_MAX_CHECKED_ANSWER + 1));
            }
            // Asked for uncompressed; one that comes compressed anyway cannot be read.
            if encoded {
                return Err("a compressed answer".into());
            }
            let doc: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            // Every message first, a few at a time, then the answer filtered by what was found.
            // Keyed by the message, not by order.
            let mut found: Vec<(String, String, Option<String>)> = Vec::new();
            let mut keys = std::collections::HashSet::new();
            filter_messages(&doc, &mut |text, id| {
                let key = format!("{}\u{0}{text}", id.unwrap_or(""));
                if keys.insert(key.clone()) {
                    found.push((key, text.to_string(), id.map(String::from)));
                }
                false
            })?;
            let queue = Arc::new(Mutex::new(found.into_iter().collect::<std::collections::VecDeque<_>>()));
            let stopped: Arc<Mutex<HashMap<String, bool>>> = Arc::new(Mutex::new(HashMap::new()));
            let workers = queue.lock().map(|q| q.len()).unwrap_or(0).min(CHECKS_AT_ONCE);
            let mut tasks = Vec::new();
            for _ in 0..workers {
                let (q, st, c, vm) = (queue.clone(), stopped.clone(), c.clone(), who.vm_id.clone());
                tasks.push(async move {
                    loop {
                        let next = q.lock().ok().and_then(|mut q| q.pop_front());
                        let Some((key, text, id)) = next else { return Ok(()) };
                        let rule = match c.check("in", text.clone(), Some(vm.clone()), id.clone()).await {
                            Ok(r) => r,
                            Err(ContentError::TooLong) => Some(CheckedRule {
                                id: "error".into(),
                                name: None,
                                action: String::new(),
                                reason: String::new(),
                                by: None,
                            }),
                            Err(ContentError::Failed(e)) => return Err(Err::<CheckFailed, String>(e)),
                        };
                        // Not judged: the read is answered "try again", so the message is not hidden for good.
                        if let Some(r) = &rule
                            && r.by.as_deref() == Some("failed")
                        {
                            c.record(
                                &r.id,
                                "in",
                                "wait",
                                Some(&vm),
                                crate::integrations::as_map(json!({"ai": "failed"})),
                                id.as_deref(),
                            );
                            return Err(Ok(CheckFailed));
                        }
                        if let Some(r) = &rule {
                            let extra =
                                r.by.as_ref()
                                    .map(|b| crate::integrations::as_map(json!({"ai": b})))
                                    .unwrap_or_default();
                            if let Some(line) = c.record(&r.id, "in", "block", Some(&vm), extra, id.as_deref()) {
                                c.stopped_here(r, "in", Some(&vm), &text, Some(&line));
                            }
                        }
                        if let Ok(mut s) = st.lock() {
                            s.insert(key, rule.is_some());
                        }
                    }
                });
            }
            for r in futures_util::future::join_all(tasks).await {
                match r {
                    Ok(()) => {}
                    Err(Ok(f)) => return Ok(Err(f)),
                    Err(Err(e)) => return Err(e),
                }
            }
            let stopped = stopped.lock().map(|s| s.clone()).unwrap_or_default();
            let kept = filter_messages(&doc, &mut |text, id| {
                *stopped
                    .get(&format!("{}\u{0}{text}", id.unwrap_or("")))
                    .unwrap_or(&true)
            })?;
            Ok(Ok(kept))
        }
        .await;
        match result {
            Ok(Ok((_, true))) => send(404, js::stringify(&json!({"error": "not_found"}))),
            Ok(Ok((kept, false))) => send(200, js::stringify(&kept)),
            Ok(Err(CheckFailed)) => send(
                503,
                js::stringify(
                    &json!({"error": "content_check_unavailable", "message": "The firewall could not check these messages just now. Try again later."}),
                ),
            ),
            Err(e) => {
                // Fail closed: an answer the check cannot read does not reach the agent.
                tracing::info!("[teamchat] content check of an answer failed: {e}");
                c.record("error", "in", "block", Some(&who.vm_id), Map::new(), None);
                send(502, js::stringify(&json!({"error": "content_check_failed"})))
            }
        }
    }

    /// The realtime socket: the same checks, then the two sockets are spliced.
    async fn upgrade(self: Arc<Self>, mut req: Req, ctx: Ctx) -> Resp {
        let started_at = js::now_ms();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let closing = |status: u16| {
            let mut r = empty(status);
            r.headers_mut()
                .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
            r
        };
        let who = match self.admit(&path, req.headers(), &ctx) {
            Ok(w) => w,
            Err((status, why, vm)) => {
                if let Some(v) = &vm {
                    self.record(Some(v), "WS", &path, status, 0, 0, started_at, Some(why));
                }
                return closing(status);
            }
        };
        let mut headers = self.forward_headers(req.headers(), &who.token);
        // No body goes with an upgrade: a length the caller states is not passed on.
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        let client_up = hyper::upgrade::on(&mut req);
        let empty_body = http_body_util::Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        let up = match self.send_up(req.method().clone(), &path, headers, empty_body).await {
            Ok(u) => u,
            Err(e) => {
                tracing::info!("[teamchat] gate websocket upstream failed: {e}");
                self.record(Some(&who.vm_id), "WS", &path, 502, 0, 0, started_at, None);
                return closing(502);
            }
        };
        if up.status() != StatusCode::SWITCHING_PROTOCOLS {
            // Not an upgrade (a refused token, a bad request): hand the status back and close.
            let s = up.status().as_u16();
            self.record(Some(&who.vm_id), "WS", &path, s, 0, 0, started_at, None);
            return closing(s);
        }
        let mut r = http::Response::new(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        );
        *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *r.headers_mut() = up.headers().clone();
        let me = self.clone();
        tokio::spawn(async move {
            let (a, b) = (client_up.await, hyper::upgrade::on(up).await);
            let (bytes_in, bytes_out) = match (a, b) {
                (Ok(a), Ok(b)) => splice(TokioIo::new(a), TokioIo::new(b)).await,
                _ => (0, 0),
            };
            me.record(
                Some(&who.vm_id),
                "WS",
                &path,
                101,
                bytes_in,
                bytes_out,
                started_at,
                None,
            );
        });
        r
    }
}

struct CheckFailed;

/// Both ways until either side ends, counting what went each way as it went (a reset still counts).
async fn splice<A, B>(a: A, b: B) -> (u64, u64)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn pump<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
        mut r: R,
        mut w: W,
        n: &AtomicU64,
    ) {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    n.fetch_add(k as u64, Ordering::SeqCst);
                    if w.write_all(&buf[..k]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = w.shutdown().await;
    }
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let (inn, out) = (AtomicU64::new(0), AtomicU64::new(0));
    // The first side to end ends both, as the TS destroys both sockets on either's close.
    tokio::select! {
        _ = pump(ar, bw, &inn) => {}
        _ = pump(br, aw, &out) => {}
    }
    (inn.load(Ordering::SeqCst), out.load(Ordering::SeqCst))
}

/// Runs once when the answer's body is dropped: the request's metadata line.
struct Done(Option<Box<dyn FnOnce() + Send + Sync>>);

impl Drop for Done {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// A body read whole up to `cap` bytes kept; `true` when it was longer (read to its end anyway).
/// None when it broke off or went idle past `UPSTREAM_TIMEOUT` (Node's socket timeout): a part of
/// a body is never checked or sent as if it were the whole.
async fn read_up_to(mut body: Incoming, cap: usize) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut size = 0usize;
    loop {
        match tokio::time::timeout(UPSTREAM_TIMEOUT, body.frame()).await {
            Err(_) | Ok(Some(Err(_))) => return None,
            Ok(None) => return Some((out, size > cap)),
            Ok(Some(Ok(frame))) => {
                if let Ok(d) = frame.into_data() {
                    size += d.len();
                    if size <= cap {
                        out.extend_from_slice(&d);
                    }
                }
            }
        }
    }
}

/// An answer streamed on, each frame within `UPSTREAM_TIMEOUT` of the last.
fn idle(body: Incoming) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, std::io::Error>> + Send + 'static {
    futures_util::stream::unfold(Some(body), |b| async move {
        let mut b = b?;
        match tokio::time::timeout(UPSTREAM_TIMEOUT, b.frame()).await {
            Err(_) => Some((Err(std::io::Error::other("timeout")), None)),
            Ok(None) => None,
            Ok(Some(r)) => Some((r.map_err(std::io::Error::other), Some(b))),
        }
    })
}

/// A path's percent-escapes decoded, as a router that decodes before matching reads it.
fn percent_decode(path: &str) -> String {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One line appended to the proxy's traffic log, which this gate shares and never rotates.
fn append_line(path: &std::path::Path, line: &Value) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
        let _ = f.write_all(format!("{}\n", js::stringify(line)).as_bytes());
    }
}

#[cfg(test)]
mod tests;
