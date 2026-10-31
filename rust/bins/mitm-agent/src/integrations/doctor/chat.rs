//! Doctor's chat (`doctor-chat.ts`): a person reads a session's transcript and writes to its
//! coding agent, from an open intent in a browser that is already enrolled. The cookie is for one
//! session and lives at most two hours (and never past the transcript).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use cc_http::{Req, Resp};

use super::firewall::DoctorFirewall;
use crate::app::App;
use crate::integrations::js;

pub const ROOT: &str = "/__cc/doctor/chat";
const COOKIE: &str = "__Secure-cc_doctor_chat";
const BODY: &str = include_str!("page/chat-body.html");
const TAIL: &str = include_str!("page/chat-tail.html");
const CHAT_JS: &str = include_str!("page/chat.js");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const OPEN_JS: &str = r#"const intent=new URLSearchParams(location.hash.slice(1)).get("i");history.replaceState(null,"",location.pathname);if(!intent){document.getElementById("status").textContent="Open Doctor chat from the console."}else{const form=document.createElement("form");form.method="POST";form.action="/__cc/doctor/chat/open";const input=document.createElement("input");input.type="hidden";input.name="intent";input.value=intent;form.append(input);document.body.append(form);form.submit()}"#;

fn hash(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))
}

#[derive(Clone)]
pub struct Grant {
    pub session_id: String,
    pub vm_id: String,
    pub user_id: String,
    pub device_id: String,
    pub can_write: bool,
    expires_at: i64,
}

pub fn send(status: u16, text: String, kind: &str) -> Resp {
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        &format!("{kind}; charset=utf-8"),
        text,
    );
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    r
}

fn plain(status: u16) -> Resp {
    send(status, String::new(), "text/plain")
}

fn reply(status: u16, v: Value) -> Resp {
    send(status, js::stringify(&v), "application/json")
}

/// The one cookie of that name, if it is in the shape this firewall hands out.
pub fn cookie_token(headers: &HeaderMap, name: &str) -> Option<String> {
    let joined = headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    let prefix = format!("{name}=");
    let found: Vec<&str> = joined
        .split(';')
        .map(str::trim)
        .filter(|s| s.starts_with(&prefix))
        .collect();
    let token = (found.len() == 1).then(|| found[0][prefix.len()..].to_string())?;
    (token.len() == 43
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then_some(token)
}

pub fn same_origin(app: &App, headers: &HeaderMap) -> bool {
    let mine = app.contracts.page_access.get().and_then(|a| a.origin());
    let theirs = headers.get(http::header::ORIGIN).and_then(|v| v.to_str().ok());
    mine.is_some() && theirs == mine.as_deref()
}

/// A body read up to `cap` (Content-Length over it first); None past it or when it broke off.
pub async fn read_body(body: hyper::body::Incoming, headers: &HeaderMap, cap: usize) -> Option<Bytes> {
    let declared = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|d| d > cap as u64) {
        return None;
    }
    http_body_util::Limited::new(body, cap)
        .collect()
        .await
        .ok()
        .map(|b| b.to_bytes())
}

pub fn form_get(raw: &[u8], k: &str) -> String {
    url::form_urlencoded::parse(raw)
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// A notice in the firewall's frame, or a bare page with the same words.
pub fn notice(app: &App, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String {
    match app.contracts.fw_shell.get() {
        Some(s) => s.notice("Agent Doctor", heading, text, id, script),
        None => format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Agent Doctor</title><p{}>{}</p>{}",
            id.map(|i| format!(" id=\"{}\"", js::escape_html(i)))
                .unwrap_or_default(),
            js::escape_html(text),
            script
                .map(|s| format!("<script src=\"{}\"></script>", js::escape_html(s)))
                .unwrap_or_default()
        ),
    }
}

/// `fwConsoleUrl(vmId)`.
pub fn fw_console_url(app: &App, vm_id: &str) -> Option<String> {
    let f = &app.config.firewall_url;
    let u = url::Url::parse(f)
        .ok()
        .filter(|u| f.starts_with("http") && u.origin().is_tuple())?;
    let origin = u.origin().ascii_serialization();
    Some(if !vm_id.is_empty() && vm_id != app.config.box_id {
        format!(
            "{origin}/dashboard/agents/{}",
            crate::integrations::connectors::runtime::enc(vm_id)
        )
    } else {
        format!("{origin}/dashboard/firewall")
    })
}

/// The intent's session and agent, from what W3's access read out of it.
pub fn intent_session(p: &crate::contracts::PagePerson) -> Option<(String, String)> {
    let sid = p
        .extra
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let vm = p.extra.get("vmId").and_then(Value::as_str)?;
    Some((sid.into(), vm.into()))
}

pub struct DoctorChat {
    app: Arc<App>,
    doctor: Arc<DoctorFirewall>,
    grants: Mutex<HashMap<String, Grant>>,
    streams: Arc<AtomicUsize>,
    now: super::Clock,
}

impl DoctorChat {
    pub fn new(app: &Arc<App>, doctor: Arc<DoctorFirewall>, now: super::Clock) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            doctor,
            grants: Mutex::new(HashMap::new()),
            streams: Arc::default(),
            now,
        })
    }

    fn refused(&self) -> Resp {
        let t = "Open this chat from the console in an enrolled browser. To enroll, open a working agent first. Transcripts expire after seven days or when deleted.";
        send(
            403,
            notice(&self.app, Some("Chat unavailable"), t, None, None),
            "text/html",
        )
    }

    fn grant(&self, headers: &HeaderMap) -> Option<Grant> {
        let token = cookie_token(headers, COOKIE)?;
        let g = self
            .grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash(&token))
            .cloned()?;
        let access = self.app.contracts.page_access.get()?;
        if g.expires_at <= (self.now)()
            || !access.device_active(headers, "doctor", &g.user_id, &g.device_id, Some(&g.vm_id))
        {
            return None;
        }
        let record = self.doctor.record(&g.session_id)?;
        (record.vm_id == g.vm_id).then_some(g)
    }

    /// A chat cookie for one session (its `Set-Cookie` value), or None when there are too many grants.
    pub fn issue(
        &self,
        session_id: &str,
        vm_id: &str,
        user_id: &str,
        device_id: &str,
        can_write: bool,
    ) -> Option<String> {
        let record = self.doctor.record(session_id).filter(|r| r.vm_id == vm_id)?;
        let now = (self.now)();
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        grants.retain(|_, g| g.expires_at > now);
        if grants.len() >= 1000 {
            return None;
        }
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        grants.insert(
            hash(&token),
            Grant {
                session_id: session_id.into(),
                vm_id: vm_id.into(),
                user_id: user_id.into(),
                device_id: device_id.into(),
                can_write,
                expires_at: record.retain_until.min(now + 2 * 60 * 60_000),
            },
        );
        Some(format!(
            "{COOKIE}={token}; Path={ROOT}; Secure; HttpOnly; SameSite=Strict; Max-Age=7200"
        ))
    }

    pub async fn handle(self: Arc<Self>, req: Req) -> Resp {
        let path = cc_http::pathname(&req.uri().to_string());
        let method = req.method().clone();
        if path == format!("{ROOT}/open.js") && method == Method::GET {
            return send(200, OPEN_JS.into(), "text/javascript");
        }
        if path == format!("{ROOT}/open") && method == Method::GET {
            let script = format!("{ROOT}/open.js");
            return send(
                200,
                notice(&self.app, None, "Opening Doctor chat...", Some("status"), Some(&script)),
                "text/html",
            );
        }
        if path == format!("{ROOT}/open") && method == Method::POST {
            if !same_origin(&self.app, req.headers()) {
                return plain(403);
            }
            if !req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"))
            {
                return plain(415);
            }
            let (parts, body) = req.into_parts();
            let Some(raw) = read_body(body, &parts.headers, 8192).await else {
                return plain(500);
            };
            let Some(access) = self.app.contracts.page_access.get() else {
                return self.refused();
            };
            let person = access
                .authorize(&parts.headers, form_get(&raw, "intent"), "doctor-chat")
                .await;
            let Some((p, (sid, vm))) = person.and_then(|p| intent_session(&p).map(|x| (p, x))) else {
                return self.refused();
            };
            if self.doctor.record(&sid).is_none_or(|r| r.vm_id != vm) {
                return self.refused();
            }
            let Some(cookie) = self.issue(&sid, &vm, &p.user_id, &p.device_id, p.can_write) else {
                return plain(429);
            };
            let mut r = plain(303);
            r.headers_mut().remove(http::header::CONTENT_TYPE);
            r.headers_mut().insert(
                http::header::LOCATION,
                HeaderValue::from_str(&format!("{ROOT}/")).unwrap_or(HeaderValue::from_static("/")),
            );
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert(http::header::SET_COOKIE, v);
            }
            return r;
        }
        let Some(grant) = self.grant(req.headers()) else {
            return self.refused();
        };
        if method == Method::GET {
            if path == ROOT || path == format!("{ROOT}/") {
                return send(200, self.page(&grant), "text/html");
            }
            if path == format!("{ROOT}/chat.js") {
                return send(200, CHAT_JS.into(), "text/javascript");
            }
            if path == format!("{ROOT}/events") {
                return self.events(req.headers().clone(), grant);
            }
            if path == format!("{ROOT}/capture") {
                return reply(200, json!({"capture": self.capture_view(&grant.session_id)}));
            }
            if path == format!("{ROOT}/repair") {
                return reply(200, json!({"repair": self.repair_view(&grant.session_id)}));
            }
            return plain(404);
        }
        if method != Method::POST {
            return plain(405);
        }
        if !grant.can_write || !same_origin(&self.app, req.headers()) {
            return plain(403);
        }
        let sub = path.strip_prefix(ROOT).unwrap_or("").to_string();
        let sid = grant.session_id.clone();
        let running = || {
            self.doctor
                .session(&sid)
                .is_some_and(|s| matches!(s["state"].as_str(), Some("running" | "proposed")))
        };
        match sub.as_str() {
            "/delete" => {
                // A failed delete (still stopping, a store error) throws in the TS: an empty 500.
                match self.doctor.delete_transcript(&sid).await {
                    Ok(()) => reply(200, json!({"ok": true})),
                    Err(_) => cc_http::empty(500),
                }
            }
            "/stop" => {
                self.doctor.stop(&sid).await;
                reply(200, json!({"ok": true}))
            }
            "/capture/read" => {
                if running() {
                    return reply(
                        409,
                        json!({"message": "Stop the session first. The draft is read when it ends."}),
                    );
                }
                self.doctor.read_capture(&sid).await;
                reply(200, json!({"ok": true}))
            }
            "/capture/send" | "/capture/replace" => {
                // `replace`: the person read that a draft is waiting and chose to put this one in its place.
                let out = self
                    .doctor
                    .send_capture(&sid, &grant.user_id, sub.ends_with("/replace"))
                    .await;
                reply(if out["ok"] == true { 200 } else { 409 }, out)
            }
            "/repair/read" => {
                if running() {
                    return reply(
                        409,
                        json!({"message": "Stop the repair first. The changes are read when it ends."}),
                    );
                }
                self.doctor.read_repair(&sid).await;
                reply(200, json!({"ok": true}))
            }
            "/repair/send" => {
                let out = self.doctor.send_repair(&sid, &grant.user_id).await;
                reply(if out["ok"] == true { 200 } else { 409 }, out)
            }
            "/message" => {
                if !req
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|t| t.starts_with("application/json"))
                {
                    return plain(415);
                }
                let (parts, body) = req.into_parts();
                let Some(raw) = read_body(body, &parts.headers, 40_000).await else {
                    return plain(400);
                };
                let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
                    return plain(400);
                };
                let Some(text) = v
                    .get("text")
                    .and_then(Value::as_str)
                    .filter(|t| !js::trim(t).is_empty() && t.encode_utf16().count() <= 8000)
                else {
                    return plain(400);
                };
                let out = self.doctor.reply(&sid, text).await;
                let ok = out.ok;
                reply(
                    if ok { 200 } else { 409 },
                    serde_json::to_value(&out).unwrap_or(Value::Null),
                )
            }
            _ => plain(404),
        }
    }

    fn page(&self, g: &Grant) -> String {
        let console = self.console_url(&g.vm_id);
        match self.app.contracts.fw_shell.get() {
            Some(s) => {
                let body = s.content(BODY);
                s.shell_page("Agent Doctor chat", "doctor", &body, console.as_deref(), TAIL)
            }
            None => format!("<!doctype html><meta charset=\"utf-8\"><title>Agent Doctor chat</title>{BODY}{TAIL}"),
        }
    }

    /// `fwConsoleUrl(vmId)`: the agent's page in the console, or the Firewall page for this firewall.
    fn console_url(&self, vm_id: &str) -> Option<String> {
        fw_console_url(&self.app, vm_id)
    }

    fn capture_view(&self, id: &str) -> Value {
        let Some(c) = self.doctor.record(id).and_then(|r| r.capture) else {
            return Value::Null;
        };
        let sent = c
            .pack
            .as_ref()
            .is_some_and(|p| c.sent_hash.as_deref() == Some(super::capture::capture_hash(p).as_str()));
        json!({
            "checkedAt": c.checked_at,
            "problems": c.problems.clone().unwrap_or_default(),
            "held": c.pack.as_ref().map(|p| serde_json::to_value(&p.held).unwrap_or(Value::Null)).unwrap_or(json!([])),
            "files": c.pack.as_ref().map(|p| serde_json::to_value(&p.files).unwrap_or(Value::Null)).unwrap_or(json!([])),
            "sent": sent,
        })
    }

    fn repair_view(&self, id: &str) -> Value {
        let Some(r) = self.doctor.record(id).and_then(|r| r.repair) else {
            return Value::Null;
        };
        let files: Vec<Value> = r
            .pack
            .as_ref()
            .map(|p| {
                p.files
                    .iter()
                    .map(|f| {
                        let before = p
                            .before
                            .iter()
                            .find(|b| b.path == f.path)
                            .map(|b| json!(b.content))
                            .unwrap_or(Value::Null);
                        json!({"path": f.path, "executable": f.executable, "after": f.content, "before": before})
                    })
                    .collect()
            })
            .unwrap_or_default();
        let sent = r
            .pack
            .as_ref()
            .is_some_and(|p| r.sent_hash.as_deref() == Some(super::repair::pack_hash(p).as_str()));
        json!({
            "template": r.template,
            "step": r.step,
            "checkedAt": r.checked_at,
            "problems": r.problems.clone().unwrap_or_default(),
            "steps": r.pack.as_ref().map(|p| json!(p.steps)).unwrap_or(json!([])),
            "files": files,
            "sent": sent,
        })
    }

    /// Server-sent events: the transcript from where the page is, every second, 50 events at a time.
    fn events(self: &Arc<Self>, headers: HeaderMap, grant: Grant) -> Resp {
        if self.streams.load(Ordering::SeqCst) >= 100 {
            return plain(429);
        }
        self.streams.fetch_add(1, Ordering::SeqCst);
        let me = self.clone();
        let guard = Streams(self.streams.clone());
        let stream = futures_util::stream::unfold((0u64, true, guard), move |(cursor, first, guard)| {
            let (me, headers, grant) = (me.clone(), headers.clone(), grant.clone());
            async move {
                if !first {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                me.grant(&headers)?;
                let record = me.doctor.transcript_after(&grant.session_id, cursor, 50)?;
                let events: Vec<Value> = record["events"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|e| e["seq"].as_u64().unwrap_or(0) > cursor)
                    .take(50)
                    .cloned()
                    .collect();
                let next = events.last().and_then(|e| e["seq"].as_u64()).unwrap_or(cursor);
                let state = record["state"].clone();
                let mark = |k: &str| {
                    record.get(k).filter(|v| v.is_object()).map(|c| {
                        json!({"mark": format!("{}:{}:{}", state.as_str().unwrap_or(""), c["checkedAt"].as_i64().unwrap_or(0), c["sentAt"].as_i64().unwrap_or(0))})
                    })
                };
                let mut data = crate::integrations::as_map(json!({
                    "events": events, "state": state, "busy": record["busy"], "canWrite": grant.can_write, "retainUntil": record["retainUntil"],
                }));
                if let Some(m) = mark("repair") {
                    data.insert("repair".into(), m);
                }
                if let Some(m) = mark("capture") {
                    data.insert("capture".into(), m);
                }
                let line = format!("data: {}\n\n", js::stringify(&Value::Object(data)));
                Some((
                    Ok::<_, std::io::Error>(hyper::body::Frame::data(Bytes::from(line))),
                    (next, false, guard),
                ))
            }
        });
        let mut r = http::Response::new(BodyExt::boxed(http_body_util::StreamBody::new(stream)));
        let h = r.headers_mut();
        h.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
        h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
        h.insert("content-security-policy", HeaderValue::from_static(CSP));
        h.insert("x-accel-buffering", HeaderValue::from_static("no"));
        r
    }
}

/// One open event stream, counted while it is open.
struct Streams(Arc<AtomicUsize>);

impl Drop for Streams {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests;
