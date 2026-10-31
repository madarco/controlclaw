//! The loopback service the proxy asks about MCP traffic an agent sends to a server it added itself
//! (`mcp-admission.ts`, docs/plans/mcp-inspection.md §3). The decision is the same one the gate
//! makes for the organization's own servers (`calls.rs`).
//!
//! ```text
//!   POST /call    { vm_id, host, url, headers, body }    → pass | answer {status, content_type, body, hold_ref?} | allow {ticket, read_result}
//!   POST /held    { hold_ref, headers }                  → {}   (a held call's headers after the proxy's swaps)
//!   POST /result  { ticket, status, content_type, body } → pass | replace {body}
//!   POST /done    { ticket, status, ok, error? }         → {}
//!   POST /tools   { vm_id, host, content_type, body }    → pass | replace {body}
//! ```
//!
//! Bound to 127.0.0.1 only. Bodies are MCP JSON, sent as text.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use regex::Regex;
use serde_json::{Map, Value, json};
use url::Url;

use super::calls::{MCP_RESULT_MAX, McpCallRequest, McpCalls, McpRoute, Replay, Ticket, Verdict};
use super::public::{Request, public_fetch};
use crate::integrations::js;
use cc_http::{Req, Resp};

pub const MCP_ADMISSION_PORT: u16 = 8796;
const BODY_MAX: usize = 4 * 1024 * 1024;
/// A call whose answer never came back is recorded as such after this.
const TICKET_MS: i64 = 10 * 60_000;
/// A held call's headers are kept this long (a hold lasts 24 hours).
const HELD_MS: i64 = 25 * 60 * 60_000;
const HELD_MAX: usize = 500;
/// Request headers a held call is not sent again with.
const REPLAY_DROP: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "keep-alive",
    "upgrade",
    "accept-encoding",
];

struct Held {
    at: i64,
    headers: Option<Vec<(String, String)>>,
}

pub struct Admission {
    calls: Arc<McpCalls>,
    tickets: Mutex<HashMap<String, (Arc<Ticket>, i64)>>,
    /// A held call's request headers as the proxy sends them upstream, real credentials in place of
    /// the agent's stand-ins. In memory only, until Send (or the hold's end). In insertion order.
    held: Mutex<Vec<(String, Held)>>,
}

fn reply(status: u16, doc: &Value) -> Resp {
    crate::integrations::json_reply(status, js::stringify(doc))
}

fn str_of(doc: &Value, k: &str) -> Option<String> {
    doc.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

static HEADER_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]{1,64}$").expect("pattern"));

/// At most 50 string headers, names lower-cased, values cut to 8192.
fn header_map(v: Option<&Value>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let Some(o) = v.and_then(Value::as_object) else {
        return out;
    };
    for (k, val) in o {
        if let Some(s) = val.as_str()
            && HEADER_NAME.is_match(k)
            && out.len() < 50
        {
            let name = k.to_lowercase();
            let value = super::client::cut(s, 8192);
            match out.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = value,
                None => out.push((name, value)),
            }
        }
    }
    out
}

impl Admission {
    pub fn new(calls: Arc<McpCalls>) -> Arc<Self> {
        Arc::new(Self {
            calls,
            tickets: Mutex::new(HashMap::new()),
            held: Mutex::new(Vec::new()),
        })
    }

    /// Every minute: tickets whose answer never came, and holds that ended.
    pub fn sweep(&self) {
        let now = js::now_ms();
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, h)| now - h.at <= HELD_MS);
        let gone: Vec<Arc<Ticket>> = {
            let mut t = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
            let old: Vec<String> = t
                .iter()
                .filter(|(_, (_, at))| now - at > TICKET_MS)
                .map(|(k, _)| k.clone())
                .collect();
            old.iter().filter_map(|k| t.remove(k)).map(|(x, _)| x).collect()
        };
        for t in gone {
            t.done(0, None, Some("no_answer"));
        }
    }

    pub fn router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["all"]);
        let me = self.clone();
        r.route(
            "all",
            |_, _| true,
            move |req, _| {
                let me = me.clone();
                async move { me.serve(req).await }
            },
        );
        r
    }

    async fn serve(self: Arc<Self>, req: Req) -> Resp {
        if req.method() != http::Method::POST {
            return reply(405, &json!({"error": "POST only"}));
        }
        let path = req.uri().path().to_string();
        let raw = match http_body_util::Limited::new(req.into_body(), BODY_MAX).collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
                return reply(413, &json!({"error": "too large"}));
            }
            Err(_) => return reply(400, &json!({"error": "not JSON"})),
        };
        let Ok(doc) = serde_json::from_slice::<Value>(&raw) else {
            return reply(400, &json!({"error": "not JSON"}));
        };
        let calls = self.calls.clone();
        match path.as_str() {
            "/call" => self.call(&calls, &doc).await,
            "/held" => {
                let r = str_of(&doc, "hold_ref");
                let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
                // Only for a hold this service named, and once.
                if let Some(r) = r
                    && let Some((_, h)) = held.iter_mut().find(|(k, _)| *k == r)
                    && h.headers.is_none()
                {
                    h.headers = Some(header_map(doc.get("headers")));
                }
                reply(200, &json!({}))
            }
            "/result" | "/done" => {
                let t = str_of(&doc, "ticket")
                    .and_then(|id| self.tickets.lock().unwrap_or_else(|e| e.into_inner()).remove(&id));
                let Some((t, _)) = t else {
                    return reply(200, &json!({"action": "pass"}));
                };
                let status = doc.get("status").and_then(Value::as_f64).map(|s| s as u16).unwrap_or(0);
                if path == "/done" {
                    let error = str_of(&doc, "error").map(|e| super::client::cut(&e, 64));
                    t.done(status, doc.get("ok").and_then(Value::as_bool), error.as_deref());
                    return reply(200, &json!({}));
                }
                // Too large for the proxy to send: checked as what it is, too large, which the checks refuse.
                let body = if doc.get("too_large") == Some(&json!(true)) {
                    vec![0u8; MCP_RESULT_MAX + 1]
                } else {
                    doc.get("body")
                        .and_then(Value::as_str)
                        .map(|s| s.as_bytes().to_vec())
                        .unwrap_or_default()
                };
                let ctype = str_of(&doc, "content_type").unwrap_or_default();
                match t.check_result(&body, &ctype, status).await {
                    Some(b) => reply(200, &json!({"action": "replace", "body": String::from_utf8_lossy(&b)})),
                    None => reply(200, &json!({"action": "pass"})),
                }
            }
            "/tools" => {
                let (Some(vm), Some(host), Some(body)) = (
                    str_of(&doc, "vm_id"),
                    str_of(&doc, "host"),
                    doc.get("body").and_then(Value::as_str),
                ) else {
                    return reply(400, &json!({"error": "vm_id, host and body are required"}));
                };
                let ctype = str_of(&doc, "content_type").unwrap_or_default();
                match calls.tools_listed(&vm, &host.to_lowercase(), None, body.as_bytes(), &ctype) {
                    Some(b) => reply(200, &json!({"action": "replace", "body": String::from_utf8_lossy(&b)})),
                    None => reply(200, &json!({"action": "pass"})),
                }
            }
            _ => reply(404, &json!({"error": "not found"})),
        }
    }

    async fn call(self: &Arc<Self>, calls: &Arc<McpCalls>, doc: &Value) -> Resp {
        let (Some(vm), Some(host), Some(url), Some(body)) = (
            str_of(doc, "vm_id"),
            str_of(doc, "host"),
            str_of(doc, "url"),
            doc.get("body")
                .and_then(Value::as_str)
                .map(|s| Bytes::from(s.to_string())),
        ) else {
            return reply(400, &json!({"error": "vm_id, host, url and body are required"}));
        };
        let headers = header_map(doc.get("headers"));
        let hold_ref = hex::encode(rand::random::<[u8; 12]>());
        let me = self.clone();
        let (r, b) = (hold_ref.clone(), body.clone());
        // A held call, sent again on Send as the agent sent it. Its answer goes nowhere.
        let replay: Replay = Arc::new(move || {
            let (me, r, b, url, headers) = (me.clone(), r.clone(), b.clone(), url.clone(), headers.clone());
            Box::pin(async move {
                // Kept until the send worked: a Send that fails can be pressed again.
                let swapped = {
                    let held = me.held.lock().unwrap_or_else(|e| e.into_inner());
                    held.iter().find(|(k, _)| *k == r).and_then(|(_, h)| h.headers.clone())
                };
                let mut out: Vec<(String, String)> = swapped
                    .unwrap_or(headers)
                    .into_iter()
                    .filter(|(k, _)| !REPLAY_DROP.contains(&k.as_str()))
                    .collect();
                out.push(("content-length".into(), b.len().to_string()));
                let url = Url::parse(&url).map_err(|e| e.to_string())?;
                let req = Request {
                    method: "POST",
                    headers: out,
                    body: Some(b),
                    timeout: Duration::from_secs(60),
                };
                let answer = public_fetch(&url, req, 1024 * 1024).await?;
                if answer.status >= 400 {
                    return Err(format!("the server answered {}", answer.status));
                }
                me.held
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|(k, _)| *k != r);
                Ok(())
            })
        });
        let verdict = calls
            .check(McpCallRequest {
                vm_id: vm,
                host: host.to_lowercase(),
                managed: None,
                route: McpRoute::Proxy,
                body,
                replay: Some(replay),
            })
            .await;
        match verdict {
            Verdict::Pass => reply(200, &json!({"action": "pass"})),
            Verdict::Answer {
                status,
                content_type,
                body,
                held,
            } => {
                let mut out = Map::new();
                out.insert("action".into(), json!("answer"));
                out.insert("status".into(), json!(status));
                out.insert("content_type".into(), json!(content_type));
                out.insert("body".into(), json!(String::from_utf8_lossy(&body)));
                if held {
                    let mut h = self.held.lock().unwrap_or_else(|e| e.into_inner());
                    if h.len() >= HELD_MAX {
                        h.remove(0);
                    }
                    h.push((
                        hold_ref.clone(),
                        Held {
                            at: js::now_ms(),
                            headers: None,
                        },
                    ));
                    out.insert("hold_ref".into(), json!(hold_ref));
                }
                reply(200, &Value::Object(out))
            }
            Verdict::Allow(ticket) => {
                let id = hex::encode(rand::random::<[u8; 12]>());
                let read = ticket.read_result();
                self.tickets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.clone(), (ticket, js::now_ms()));
                reply(200, &json!({"action": "allow", "ticket": id, "read_result": read}))
            }
        }
    }
}

#[cfg(test)]
mod tests;
