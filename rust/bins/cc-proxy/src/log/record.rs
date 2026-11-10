//! The records of HTTP flows (addon.py `_http_record`, `_allow_record`, `redact_path`, `_log_once`)
//! and the steps that write them once a flow has its answer or its error.
//!
//! What a step leaves in `flow.meta` for the record, by key (the addon's `flow.metadata`):
//! `effect` (`cc_effect`), `rule` (`cc_rule`), `rule_ref` (`[id, label]`, `cc_rule_ref`), `ai`
//! (`cc_ai`), `email_sent`, `granted` (`cc_granted`), `applied` (every placeholder swapped in, in
//! order: `cc_applied`), `secret_swaps` (custom secrets' names), `login_placeholders` (the logins'
//! placeholders, left off `swapped`), `logged` (`cc_logged`), `included`, `model_error`.

use std::sync::Arc;

use cc_contracts::Maybe;
use cc_contracts::traffic::TrafficRecord;
use serde_json::Value;

use crate::flow::{Flow, Hook, Step, StepFuture, Verdict, order};
use crate::net::Ctx;

/// The query-stripped path with any embedded credential replaced by a marker (addon.py
/// `redact_path`): Twilio and AgentMail keep only their fixed resource names, a Telegram bot token
/// becomes `/bot<redacted>`, and a meeting code becomes `<meeting>`.
pub fn redact_path(path: &str, host: &str) -> String {
    let bare = path.split_once('?').map_or(path, |(p, _)| p);
    let host = host.to_ascii_lowercase();
    if host == "api.twilio.com" {
        return keep_segments(bare, &["", "2010-04-01", "Accounts", "Calls", "Calls.json"]);
    }
    if host == "api.agentmail.to" || host == "ws.agentmail.to" {
        const RESOURCES: &[&str] = &[
            "v0",
            "inboxes",
            "messages",
            "threads",
            "drafts",
            "attachments",
            "send",
            "reply",
            "reply-all",
            "forward",
            "raw",
            "api-keys",
            "organizations",
            "",
        ];
        return keep_segments(bare, RESOURCES);
    }
    redact_meeting_codes(&redact_telegram_token(bare))
}

fn keep_segments(path: &str, keep: &[&str]) -> String {
    path.split('/')
        .map(|p| if keep.contains(&p) { p } else { "{id}" })
        .collect::<Vec<_>>()
        .join("/")
}

/// `/bot\d+:[A-Za-z0-9_-]{20,}(?=/|$)` → `/bot<redacted>`.
fn redact_telegram_token(path: &str) -> String {
    let b = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"/bot") {
            let mut j = i + 4;
            let digits = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > digits && j < b.len() && b[j] == b':' {
                let tok = j + 1;
                let mut k = tok;
                while k < b.len() && (b[k].is_ascii_alphanumeric() || b[k] == b'_' || b[k] == b'-') {
                    k += 1;
                }
                if k - tok >= 20 && (k == b.len() || b[k] == b'/') {
                    out.push_str("/bot<redacted>");
                    i = k;
                    continue;
                }
            }
        }
        let ch = path[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8().max(1);
    }
    out
}

/// `(?<![a-z])[a-z]{3}-[a-z]{4}-[a-z]{3}(?![a-z])` → `<meeting>`.
fn redact_meeting_codes(path: &str) -> String {
    let b = path.as_bytes();
    let lower = |i: usize| i < b.len() && b[i].is_ascii_lowercase();
    let run = |from: usize, n: usize| (from..from + n).all(lower);
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < b.len() {
        let before_ok = i == 0 || !b[i - 1].is_ascii_lowercase();
        if before_ok
            && i + 12 <= b.len()
            && run(i, 3)
            && b[i + 3] == b'-'
            && run(i + 4, 4)
            && b[i + 8] == b'-'
            && run(i + 9, 3)
            && !lower(i + 12)
        {
            out.push_str("<meeting>");
            i += 12;
            continue;
        }
        let ch = path[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8().max(1);
    }
    out
}

/// A string from `flow.meta`, if there is one.
pub fn meta_str<'a>(flow: &'a Flow, key: &str) -> Option<&'a str> {
    flow.meta.get(key).and_then(Value::as_str)
}

/// The host a record names: the checked destination, else the name the request gave.
pub fn record_host(flow: &Flow) -> String {
    flow.destination()
        .map(|d| d.name.clone())
        .or_else(|| flow.claimed_host())
        .unwrap_or_default()
}

/// The request's path and query before the swaps ran (set by `http::swaps`).
#[derive(Clone, Debug)]
pub struct PathBeforeSwap(pub String);

/// The bodies' sizes as they came (`raw_content`), before the plumbing decoded them for the checks:
/// what `bytes_out` and `bytes_in` count, as the addon's do.
#[derive(Clone, Copy, Debug)]
pub struct RawLen {
    pub request: usize,
    pub response: Option<usize>,
}

/// The bytes a streamed request body has sent so far: its record's `bytes_out`, read when the
/// record is written (the upload can still be going when the answer's head comes).
#[derive(Clone, Debug)]
pub struct UploadCount(pub Arc<std::sync::atomic::AtomicU64>);

/// One record per HTTP request (addon.py `_http_record`). The path is query-stripped and redacted.
pub fn http_record(ctx: &Ctx, flow: &Flow, effect: &str) -> TrafficRecord {
    let mut rec = ctx.record(flow, effect);
    let host = record_host(flow);
    let (method, mut path) = flow.request.as_ref().map_or((String::new(), String::new()), |r| {
        (
            r.method().to_string(),
            r.uri().path_and_query().map_or("/", |p| p.as_str()).to_owned(),
        )
    });
    // The path as the agent sent it, when a swap rewrote it: a path credential never reaches the log.
    if let Some(PathBeforeSwap(p)) = flow.extensions.get::<PathBeforeSwap>() {
        path.clone_from(p);
    }
    rec.path = Maybe::Value(redact_path(&path, &host));
    rec.host = Maybe::Value(host);
    rec.method = Maybe::Value(method);
    // The label as the flow carries it (the rule's name or domain as written, or a check's own).
    let rule = flow.meta.get("rule").cloned().unwrap_or(Value::Null);
    if let Some(Value::Array(r)) = flow.meta.get("rule_ref")
        && let Some(id) = r.first().and_then(Value::as_str)
        && r.get(1).unwrap_or(&Value::Null) == &rule
    {
        rec.rule_id = Maybe::Value(id.to_owned());
        // A rule the control plane added for a provider or a channel says so; the AI log review
        // and the Activity log read it (`cc_contracts::managed`).
        if let Some(m) = flow
            .meta
            .get("rule_view")
            .and_then(|v| v.get(cc_contracts::managed::FIELD))
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
        {
            rec.extra.insert(cc_contracts::managed::FIELD.into(), m.into());
        }
    }
    rec.rule = match rule {
        Value::String(s) => Maybe::Value(s),
        Value::Null => Maybe::Null,
        other => Maybe::Value(other.to_string()),
    };
    if flow.meta.get("email_sent") == Some(&Value::Bool(true)) {
        rec.extra.insert("email".into(), "sent".into());
    }
    if let Some(ai) = flow.meta.get("ai") {
        rec.extra.insert("ai".into(), ai.clone());
    }
    rec
}

/// The record of a request that was let through (addon.py `_allow_record`).
pub fn allow_record(ctx: &Ctx, flow: &Flow) -> TrafficRecord {
    let mut rec = http_record(ctx, flow, "allow");
    // `swapped`: the placeholders swapped in, without custom secrets' (named instead) and logins'.
    let list = |k: &str| -> Vec<Value> { flow.meta.get(k).and_then(Value::as_array).cloned().unwrap_or_default() };
    let logins = list("login_placeholders");
    let mut swapped: Vec<Value> = list("applied")
        .into_iter()
        .filter(|p| p.as_str().is_some_and(|s| !s.starts_with("CC-SEC-")) && !logins.contains(p))
        .collect();
    swapped.extend(list("secret_swaps"));
    rec.extra.insert("swapped".into(), Value::Array(swapped));
    if let Some(Value::Object(login)) = flow.meta.get("login_record") {
        for (k, v) in login {
            rec.extra.insert(k.clone(), v.clone());
        }
    }
    if let Some(pid) = flow.meta.get("granted") {
        rec.extra.insert("permission_id".into(), pid.clone());
    }
    let bytes_out = match (flow.extensions.get::<UploadCount>(), flow.extensions.get::<RawLen>()) {
        (Some(UploadCount(n)), _) => {
            usize::try_from(n.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(usize::MAX)
        }
        (None, Some(r)) => r.request,
        (None, None) => flow.request.as_ref().map_or(0, |r| r.body().len()),
    };
    rec.extra.insert("bytes_out".into(), bytes_out.into());
    rec
}

/// Write a flow's record once: an answer and an error can both come for one flow (addon.py
/// `_log_once`).
pub fn log_once(ctx: &Ctx, flow: &mut Flow, rec: &TrafficRecord) {
    if flow.meta.get("logged") == Some(&Value::Bool(true)) {
        return;
    }
    flow.meta.insert("logged", Value::Bool(true));
    ctx.log.append(rec);
}

/// Whether the record is the allow record's to write: no step set an effect other than `allow`.
fn allowed(flow: &Flow) -> bool {
    matches!(meta_str(flow, "effect"), None | Some("allow"))
}

/// Set on a flow whose answer is streamed to the agent: its record is not written at the response
/// steps but kept ([`Pending`]) and written when the stream ends, with the bytes that went.
pub const STREAMED: &str = "cc_streamed";

/// The record of a streamed answer, waiting for its end.
#[derive(Clone)]
pub struct Pending(pub TrafficRecord);

/// The allow record once the answer is in (the tail of addon.py `response`).
pub struct ResponseRecord(pub Arc<Ctx>);

impl Step for ResponseRecord {
    fn name(&self) -> &'static str {
        "traffic_log_response"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !allowed(flow) {
                // A W2 check that answered or rewrote the flow: its record, from `effect`, `rule`
                // and the fields it left in `record` (addon `_log_once(flow, {..._http_record(...),
                // "status": ...})`). W1's own refusals log at once and set no `record`.
                if let (Some(effect), Some(Value::Object(fields))) = (
                    meta_str(flow, "effect").map(str::to_owned),
                    flow.meta.get("record").cloned(),
                ) {
                    let mut rec = http_record(&self.0, flow, &effect);
                    for (k, v) in fields {
                        if k == "status" {
                            if let Some(n) = v.as_u64() {
                                rec.status = Maybe::Value(n.into());
                            }
                        } else {
                            rec.extra.insert(k, v);
                        }
                    }
                    log_once(&self.0, flow, &rec);
                }
                return Verdict::Continue;
            }
            let mut rec = allow_record(&self.0, flow);
            if let Some(v) = flow.meta.get("included") {
                rec.extra.insert("included".into(), v.clone());
            }
            if let Some(v) = flow.meta.get("model_error") {
                rec.extra.insert("model_error".into(), v.clone());
            }
            if let Some(resp) = &flow.response {
                rec.status = Maybe::Value(u64::from(resp.status().as_u16()).into());
                let bytes_in = flow
                    .extensions
                    .get::<RawLen>()
                    .and_then(|r| r.response)
                    .unwrap_or(resp.body().len());
                rec.extra.insert("bytes_in".into(), bytes_in.into());
            }
            rec.extra.insert(
                "duration_ms".into(),
                u64::try_from(flow.started.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .into(),
            );
            // A streamed answer: written when its body has gone through, with its bytes.
            if flow.meta.get(STREAMED) == Some(&Value::Bool(true)) {
                if flow.meta.get("logged") != Some(&Value::Bool(true)) {
                    flow.meta.insert("logged", Value::Bool(true));
                    flow.extensions.insert(Pending(rec));
                }
                return Verdict::Continue;
            }
            log_once(&self.0, flow, &rec);
            Verdict::Continue
        })
    }
}

/// An allowed request that never got an answer (addon.py `error`).
pub struct ErrorRecord(pub Arc<Ctx>);

/// The prefix of an error the address check gave; its record was written when it refused.
pub const NON_ROUTABLE_REFUSAL: &str = "refused by the firewall:";

impl Step for ErrorRecord {
    fn name(&self) -> &'static str {
        "traffic_log_error"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Error]
    }
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !allowed(flow) || flow.request.is_none() {
                return Verdict::Continue;
            }
            let error = flow.error.clone().unwrap_or_default();
            if error.contains(NON_ROUTABLE_REFUSAL) {
                return Verdict::Continue;
            }
            let mut rec = allow_record(&self.0, flow);
            let host = record_host(flow);
            let text = if flow.meta.contains_key("secret_swaps") {
                "Secret request failed".to_owned()
            } else if ["api.agentmail.to", "ws.agentmail.to", "api.twilio.com"].contains(&host.as_str()) {
                "Integration request failed".to_owned()
            } else if error.is_empty() {
                "upstream error".to_owned()
            } else {
                crate::net::target::truncate(&error, 200)
            };
            rec.extra.insert("error".into(), text.into());
            rec.extra.insert(
                "duration_ms".into(),
                u64::try_from(flow.started.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .into(),
            );
            log_once(&self.0, flow, &rec);
            Verdict::Continue
        })
    }
}

/// Add the record steps at the end of the response and error hooks.
pub fn register(pipeline: &mut crate::flow::Pipeline, ctx: &Arc<Ctx>) {
    pipeline.push(order::RESPONSE_LOG, Arc::new(ResponseRecord(ctx.clone())));
    pipeline.push(order::ERROR_LOG, Arc::new(ErrorRecord(ctx.clone())));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_like_the_addon() {
        assert_eq!(
            redact_path(
                "/bot123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage?chat_id=1",
                "api.telegram.org"
            ),
            "/bot<redacted>/sendMessage"
        );
        assert_eq!(
            redact_path("/bot123:short/getMe", "api.telegram.org"),
            "/bot123:short/getMe"
        );
        assert_eq!(
            redact_path("/bot123456:AAAAAAAAAAAAAAAAAAAAAAAA", "x"),
            "/bot<redacted>"
        );
        assert_eq!(redact_path("/abc-defg-hij/x", "meet.google.com"), "/<meeting>/x");
        assert_eq!(redact_path("/xabc-defg-hij", "meet.google.com"), "/xabc-defg-hij");
        assert_eq!(redact_path("/abc-defg-hijk", "meet.google.com"), "/abc-defg-hijk");
        assert_eq!(redact_path("/ABC-defg-hij", "x"), "/ABC-defg-hij");
        assert_eq!(
            redact_path("/2010-04-01/Accounts/AC123/Calls.json?x=1", "api.twilio.com"),
            "/2010-04-01/Accounts/{id}/Calls.json"
        );
        assert_eq!(
            redact_path("/v0/inboxes/me@x.to/messages/abc", "API.agentmail.to"),
            "/v0/inboxes/{id}/messages/{id}"
        );
        assert_eq!(redact_path("/a/é?q", "x"), "/a/é");
    }
}
