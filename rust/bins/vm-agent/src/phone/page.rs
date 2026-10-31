//! Phone call history as a page of this box (`routes/phone-page.ts`,
//! apps/saas/docs/features/phone-calls.md).
//!
//!   GET  /__cc/phone             the page, for a browser holding this box's session
//!   GET  /__cc/phone/calls       the newest calls
//!   GET  /__cc/phone/calls/<id>  one call with its transcript
//!   POST /__cc/phone/delete      `{id}` or `{all: true}`: removes ended calls, transcripts included
//!
//! A transcript is what a caller said, so this is served like Meetings, not like the log: only a
//! session a firewall-checked Open gave to an enrolled browser (`deviceId`) reads it, and only one
//! that may write deletes. The control plane is never on the path and never sees a call.
//!
//! Sessions, the page shell and the refusal page are W7's (`app.contracts.access`). While that
//! slot is empty every request is answered as if there were no session.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use cc_http::{BodyBinding, Req, Resp, Router, full, read_json_body, send_json};
use http::{HeaderValue, StatusCode};
use regex::Regex;
use serde_json::{Value, json};

use super::Phone;
use super::history::{HISTORY_LIMIT, VoiceUsage, call_detail, now_ms, parse_iso, summarize_call};
use crate::app::App;
use crate::stages;

static CALL_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").expect("regex"));
static ONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/__cc/phone/calls/([^/]+)$").expect("regex"));
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
/// When W7's shell is not there to draw its own refusal page.
const BARE_DENIED: &str = "<!doctype html><title>These calls are private</title><h1>These calls are private</h1>";

/// `isPhonePagePath`.
pub fn is_phone_page_path(path: &str) -> bool {
    path == "/__cc/phone" || path.starts_with("/__cc/phone/")
}

fn page(status: u16, html: String) -> Resp {
    let mut r = full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        "text/html; charset=utf-8",
        html,
    );
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    r
}

/// `readPhoneUsage`: the voice sessions the adapter logged for phone calls (`phone.jsonl`, the
/// last 4 MiB).
pub fn read_phone_usage(dir: &Path) -> Vec<VoiceUsage> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_READ: u64 = 4 * 1024 * 1024;
    let Ok(mut f) = std::fs::File::open(dir.join("phone.jsonl")) else {
        return Vec::new();
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let len = size.min(MAX_READ);
    let mut buf = vec![0u8; len as usize];
    if f.seek(SeekFrom::Start(size - len)).is_err() || f.read_exact(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    // The adapter stops writing at 8 MiB; keep the newest usage so it never gets there.
    if text.encode_utf16().count() > 1024 * 1024 {
        let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
        let keep = lines[lines.len().saturating_sub(5000)..].join("\n") + "\n";
        // A folder that cannot be written is fine: the usage is still read.
        let _ = cc_store::write_atomic(
            &dir.join("phone.jsonl"),
            keep.as_bytes(),
            0o600,
            cc_store::TmpName::Suffix,
        );
    }
    text.split('\n')
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|e| {
            // `Date.parse(String(entry.startedAt))`.
            let started = e.get("startedAt").and_then(Value::as_str).and_then(parse_iso)?;
            let seconds = e.get("seconds").and_then(Value::as_f64)?;
            (e.get("kind").and_then(Value::as_str) == Some("usage") && (0.0..=86_400.0).contains(&seconds)).then(|| {
                VoiceUsage {
                    started_at: started,
                    seconds: (seconds + 0.5).floor(),
                }
            })
        })
        .collect()
}

/// What the pages need besides the phone parts.
pub struct PageContext {
    pub app: Arc<App>,
    /// The voice adapter's log folder (`~/.openclaw/cc-voice`).
    pub voice_dir: PathBuf,
}

pub fn register(router: &mut Router, ctx: Arc<PageContext>, phone: Arc<Phone>) {
    router.route(
        stages::PHONE_PAGES,
        |_, p| is_phone_page_path(p),
        move |req, _| {
            let (ctx, phone) = (ctx.clone(), phone.clone());
            async move { handle(&ctx, &phone, req).await }
        },
    );
}

async fn handle(ctx: &PageContext, phone: &Phone, req: Req) -> Resp {
    let path = cc_http::pathname(&req.uri().to_string());
    let method = req.method().clone();
    let access = ctx.app.contracts.access.get();
    let vm_id = ctx.app.keys.vm_id().unwrap_or_default();
    // Node joins a repeated `Cookie` header with "; ".
    let cookies: Vec<&str> = req
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let cookie = (!cookies.is_empty()).then(|| cookies.join("; "));
    let session = access
        .as_ref()
        .and_then(|a| a.sessions.read_session(cookie.as_deref(), &vm_id));
    let enrolled = session.as_ref().is_some_and(|s| s.device_id.is_some());

    if path == "/__cc/phone" && method == http::Method::GET {
        let Some(access) = access.as_ref().filter(|_| enrolled) else {
            return page(
                401,
                access
                    .as_ref()
                    .map_or_else(|| BARE_DENIED.to_string(), |a| a.denied_phone_page()),
            );
        };
        let shell = access.shell_context();
        let agent = crate::boxside::shell::agent_name_of(shell.hostname.as_deref());
        let can_delete = session.as_ref().is_some_and(|s| s.can_write);
        let body = format!(
            r#"<div id="root"></div><script id="cc-phone" type="application/json">{}</script><script type="module" src="/__cc/files-ui/phone.js"></script>"#,
            crate::boxside::shell::inline_json(&json!({"agentName": agent, "canDelete": can_delete}))
        );
        let html = crate::boxside::shell::shell_page(
            &shell,
            &format!("{agent} · calls"),
            Some("phone"),
            &body,
            "",
            access.nav(),
        );
        return page(200, html);
    }

    // Every box is one site with its neighbours, so SameSite decides nothing: same origin only.
    let (parts, body) = req.into_parts();
    let own = access.as_ref().and_then(|a| a.allowed_origins().0);
    let facts = cc_origin::agent_request_facts(parts.method.as_str(), &parts.headers, None);
    let policy = cc_origin::OriginPolicy {
        allowed: vec![own],
        allow_top_level_navigation: false,
        ..Default::default()
    };
    if let cc_origin::OriginVerdict::Denied { reason, origin } = cc_origin::check_origin(&facts, &policy) {
        tracing::warn!(
            "[phone] history: {}",
            cc_origin::denial_message(reason, origin.as_deref())
        );
        return send_json(403, &json!({"error": "Not from this agent's own page."}));
    }
    if !enrolled {
        return send_json(
            401,
            &json!({"error": "Your session on this agent has expired. Open Call history again from your ControlClaw console."}),
        );
    }
    let failed = || send_json(500, &json!({"error": "The call history could not be read. Try again."}));
    let now = now_ms() as f64;
    // SQLite can wait seconds on the plugin's lock, and the usage file is up to 4 MiB: both are
    // read on a blocking thread, never on the threads relaying calls.
    let store = phone.calls.clone();
    let read_calls = || {
        let store = store.clone();
        async move {
            tokio::task::spawn_blocking(move || store.calls())
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
        }
    };
    let voice_dir = ctx.voice_dir.clone();
    let read_usage = || {
        let dir = voice_dir.clone();
        async move {
            tokio::task::spawn_blocking(move || read_phone_usage(&dir))
                .await
                .unwrap_or_default()
        }
    };

    if path == "/__cc/phone/calls" && method == http::Method::GET {
        let calls = match read_calls().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("[phone] history: {e}");
                return failed();
            }
        };
        let usage = read_usage().await;
        let list: Vec<Value> = calls
            .iter()
            .take(HISTORY_LIMIT)
            .map(|c| Value::Object(summarize_call(c, &phone.log, &usage, now)))
            .collect();
        return send_json(200, &json!({"available": phone.calls.available(), "calls": list}));
    }
    if let Some(m) = ONE.captures(&path)
        && method == http::Method::GET
    {
        let id = &m[1];
        if !CALL_ID.is_match(id) {
            return send_json(404, &json!({"error": "No such call."}));
        }
        let calls = match read_calls().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("[phone] history: {e}");
                return failed();
            }
        };
        let Some(call) = calls
            .iter()
            .find(|c| c.get("callId").and_then(Value::as_str) == Some(id))
        else {
            return send_json(404, &json!({"error": "No such call."}));
        };
        let usage = read_usage().await;
        return send_json(200, &Value::Object(call_detail(call, &phone.log, &usage, now)));
    }
    if path == "/__cc/phone/delete" && method == http::Method::POST {
        if !session.as_ref().is_some_and(|s| s.can_write) {
            return send_json(403, &json!({"error": "This session can only read."}));
        }
        let body = read_json_body(body, 16384, &BodyBinding::not_firewall()).await;
        let ids: Option<Option<HashSet<String>>> = match &body {
            Some(b) if b.get("all") == Some(&json!(true)) => Some(None),
            Some(b) => b
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| CALL_ID.is_match(id))
                .map(|id| Some([id.to_string()].into())),
            None => None,
        };
        let Some(ids) = ids else {
            return send_json(400, &json!({"error": "Say which call to delete."}));
        };
        let removed = tokio::task::spawn_blocking(move || store.remove(ids.as_ref()))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        let removed = match removed {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("[phone] history: {e}");
                return failed();
            }
        };
        phone.log.forget(removed.iter().map(|r| r.1.as_deref()));
        phone.forget_seen();
        tracing::info!("[phone] history: deleted {} call(s)", removed.len());
        return send_json(200, &json!({"deleted": removed.len()}));
    }
    send_json(404, &json!({"error": "Not found"}))
}

#[cfg(test)]
mod tests;
