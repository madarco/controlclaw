//! Slack (appendix F feature 20, addon.py 5820-5990). Out: the Web API (`slack.com/api/<method>`)
//! and incoming webhooks (`hooks.slack.com`). In: the Socket Mode websocket the agent's Slack app
//! holds open (`wss-*.slack.com`), one JSON frame per event, each acknowledged by the client with
//! its `envelope_id`. A stopped event is dropped and acknowledged here, so Slack does not send it
//! again; one the AI could not judge is dropped and not acknowledged, so Slack does.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::content::engine::{self, Action, Rule};
use super::content::{CheckError, Content, HOLD_BODY_MAX, HOLD_TEXT_MAX};
use super::telegram::{TextsError, detail, out_fields, texts};
use super::{body, check_host, pyjson};
use crate::flow::{Direction, Flow, FrameKind, Hook, Pipeline, Step, StepFuture, Verdict, WsFrame, order};

#[allow(clippy::expect_used)] // a fixed expression, checked by the tests
static METHOD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/api/([A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)$").expect("valid expression"));

const API_HOSTS: &[&str] = &["slack.com", "api.slack.com"];
pub const TEXT_KEYS: &[&str] = &[
    "text",
    "initial_comment",
    "title",
    "pretext",
    "fallback",
    "footer",
    "author_name",
    "alt_text",
    "topic",
    "purpose",
    "description",
    "markdown",
    "markdown_text",
    "status_text",
    "label",
    "placeholder",
    "name",
    "value",
    "header",
    "subtitle",
    "content",
];
const HOLDABLE: &[&str] = &["chat.postMessage", "chat.update"];

pub fn register(pipeline: &mut Pipeline, content: Arc<Content>) {
    pipeline.push(order::SLACK, Arc::new(SlackOut(content.clone())));
    pipeline.push(order::WS_SLACK, Arc::new(SlackSocket(content)));
}

fn path(flow: &Flow) -> String {
    flow.request
        .as_ref()
        .map(|r| r.uri().path().to_owned())
        .unwrap_or_default()
}

/// `is_slack_out_flow`.
pub fn is_slack_out_flow(flow: &Flow) -> bool {
    let h = check_host(flow);
    (API_HOSTS.contains(&h.as_str()) && path(flow).starts_with("/api/")) || h == "hooks.slack.com"
}

/// `is_slack_socket`.
pub fn is_slack_socket(flow: &Flow) -> bool {
    let h = check_host(flow);
    h.ends_with(".slack.com") && h.starts_with("wss")
}

/// `_slack_refuse`: Slack answers its errors with HTTP 200 and `ok: false`; its clients raise on that.
fn refuse(flow: &mut Flow, rule: Option<&Rule>, extra: &str, reason: Option<&str>) -> Verdict {
    let reason = rule.map_or(reason.unwrap_or("the check could not run"), |r| r.reason.as_str());
    let body = json!({"ok": false, "error": "blocked_by_organization_rules",
                      "response_metadata": {"messages": [format!("Blocked by your organization's rules: {reason}{extra}")]}});
    let label = rule.map_or_else(|| "content: error".to_owned(), |r| format!("content: {}", r.id));
    super::answer(flow, 200, &body, "block", &label, Map::new())
}

/// `_slack_auth`: the token the call was made with (a placeholder on a secured box).
fn auth(flow: &Flow, fields: &[(String, Value)]) -> Option<String> {
    let header = flow
        .request
        .as_ref()
        .and_then(|r| r.headers().get(http::header::AUTHORIZATION))
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    if let Some(rest) = header
        .get(..7)
        .filter(|h| h.eq_ignore_ascii_case("bearer "))
        .map(|_| &header[7..])
    {
        return Some(engine::cut(rest.trim_matches(body::is_py_space), 200)).filter(|t| !t.is_empty());
    }
    fields
        .iter()
        .find(|(k, _)| k == "token")
        .and_then(|(_, v)| v.as_str())
        .filter(|t| !t.is_empty())
        .map(|t| engine::cut(t, 200))
}

fn first_str(fields: &[(String, Value)], key: &str) -> Option<String> {
    fields
        .iter()
        .find(|(k, v)| k == key && v.is_string())
        .and_then(|(_, v)| v.as_str())
        .map(str::to_owned)
}

fn slack_text(fields: &[(String, Value)]) -> Result<String, TextsError> {
    super::telegram::text_of(fields, TEXT_KEYS)
}

pub struct SlackOut(pub Arc<Content>);

impl Step for SlackOut {
    fn name(&self) -> &'static str {
        "slack-out"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// Slack's Web API and its webhooks.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        is_slack_out_flow(flow) && super::request_has_body(flow)
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !is_slack_out_flow(flow) {
                return Verdict::Continue;
            }
            match out(&self.0, flow).await {
                Ok(v) => v.unwrap_or(Verdict::Continue),
                Err(CheckError::TooLong(_)) => {
                    let v = refuse(flow, None, "", Some("it is too long to check"));
                    self.0
                        .audit(Some(flow), "error", "slack", "out", "block", None, detail("too long"));
                    v
                }
                Err(e) => {
                    tracing::warn!("[content-rules] outgoing Slack check failed, refusing: {e}");
                    let v = refuse(flow, None, "", None);
                    self.0
                        .audit(Some(flow), "error", "slack", "out", "block", None, Map::new());
                    v
                }
            }
        })
    }
}

/// `content_rules_slack_out`: `Some` when the call was answered here (blocked or held).
async fn out(content: &Content, flow: &mut Flow) -> Result<Option<Verdict>, CheckError> {
    let hook = check_host(flow) == "hooks.slack.com";
    let p = path(flow);
    let method = if hook {
        None
    } else {
        METHOD_RE.captures(&p).map(|c| c[1].to_owned())
    };
    if !hook && method.is_none() {
        // Anything else under /api/ still reaches Slack with the real token after the swap.
        let v = refuse(flow, None, "", Some("this Slack call could not be checked"));
        content.audit(
            Some(flow),
            "error",
            "slack",
            "out",
            "block",
            None,
            detail("unmatched path"),
        );
        return Ok(Some(v));
    }
    // A body the plumbing has not decoded is refused, never passed unread.
    if super::request_body_unread(flow) {
        return Err(CheckError::Failed("a body the firewall cannot read".into()));
    }
    let has_query = flow
        .request
        .as_ref()
        .is_some_and(|r| !body::query_items(r.uri()).is_empty());
    let verb = flow
        .request
        .as_ref()
        .map(|r| r.method().as_str().to_uppercase())
        .unwrap_or_default();
    if matches!(verb.as_str(), "GET" | "HEAD") && !has_query {
        return Ok(None);
    }
    let (fields, is_json) = out_fields(flow)?;
    let text = slack_text(&fields)?;
    if text.is_empty() {
        return Ok(None);
    }
    let rules = content.rules()?;
    let vm_id = flow.vm_id.clone();
    let (found, text) = content.out_evaluate(&rules, "slack", text, vm_id.as_deref()).await?;
    let Some(rule) = content.acted(Some(flow), found, "out", "slack", &text, None) else {
        return Ok(None);
    };
    let channel = first_str(&fields, "channel").filter(|c| !c.is_empty());
    let token = auth(flow, &fields);
    let verdict = if rule.action == Action::Hold {
        let mut extra = " (it could not be held for approval)";
        let raw_len = flow.request.as_ref().map_or(0, |r| r.body().len());
        let holdable = method.as_deref().is_some_and(|m| HOLDABLE.contains(&m))
            && channel.is_some()
            && !has_query
            && raw_len <= HOLD_BODY_MAX;
        if holdable {
            // `_out_body(flow)[2]`: the body as UTF-8, as the check read it.
            let text_body = flow
                .request
                .as_ref()
                .map(|r| String::from_utf8_lossy(r.body()).into_owned())
                .unwrap_or_default();
            let mut payload = Map::new();
            payload.insert("channel".into(), json!("slack"));
            payload.insert("method".into(), json!(method));
            payload.insert("body".into(), json!(text_body));
            payload.insert("contentType".into(), json!(if is_json { "json" } else { "form" }));
            payload.insert("chatId".into(), json!(channel));
            payload.insert("auth".into(), json!(token));
            payload.insert("vmId".into(), json!(vm_id));
            payload.insert("rule".into(), rule.brief());
            payload.insert("text".into(), json!(engine::cut(&text, HOLD_TEXT_MAX)));
            if let Some(super::content::Held { answer, .. }) = content.hold(flow, payload).await? {
                let first_text = first_str(&fields, "text").unwrap_or_default();
                let ts = first_str(&fields, "ts")
                    .filter(|t| !t.is_empty())
                    .unwrap_or_else(fresh_ts);
                let body = if method.as_deref() == Some("chat.postMessage") {
                    json!({"ok": true, "channel": channel, "ts": ts, "message": {"type": "message", "text": first_text, "ts": ts}})
                } else {
                    json!({"ok": true, "channel": channel, "ts": ts, "text": first_text})
                };
                let hold_id = answer.get("holdId").cloned().unwrap_or(Value::Null);
                return Ok(Some(content.held_answer(flow, &rule, "slack", hold_id, 200, &body)));
            }
            extra = " (nobody could be asked to approve it)";
        }
        let v = refuse(flow, Some(&rule), extra, None);
        let mut x = Map::new();
        x.insert("held".into(), json!(false));
        content.audit(Some(flow), &rule.id, "slack", "out", "block", None, x);
        v
    } else {
        let v = refuse(flow, Some(&rule), "", None);
        content.audit(Some(flow), &rule.id, "slack", "out", "block", None, Map::new());
        v
    };
    if let Some(ch) = channel {
        let mut n = json!({"kind": "out", "channel": "slack", "chatId": ch, "auth": token, "vmId": vm_id, "reason": rule.reason});
        if let Some(t) = first_str(&fields, "thread_ts").filter(|t| !t.is_empty()) {
            n["threadTs"] = json!(t);
        }
        content.notice(n);
    }
    Ok(Some(verdict))
}

/// `f"{int(time.time())}.{secrets.randbelow(1_000_000):06d}"`: a Slack message timestamp.
fn fresh_ts() -> String {
    let n = u32::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..4].try_into().unwrap_or([0; 4])) % 1_000_000;
    format!("{}.{n:06}", super::content::rules::now() as i64)
}

// ---- in: Socket Mode ----------------------------------------------------------------------------

pub struct SlackSocket(pub Arc<Content>);

impl Step for SlackSocket {
    fn name(&self) -> &'static str {
        "slack-socket"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::WsFrame]
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !is_slack_socket(flow) {
                return Verdict::Continue;
            }
            let Some(frame) = flow.ws_frame.as_ref().filter(|f| f.direction == Direction::In) else {
                return Verdict::Continue;
            };
            let payload = frame.payload.clone();
            match socket_check(&self.0, flow, &payload).await {
                Ok(true) => Verdict::Continue,
                Ok(false) => Verdict::Drop,
                Err(e) => {
                    // Not passed on and not acknowledged, so Slack sends it again.
                    tracing::warn!("[content-rules] incoming Slack check failed, held back: {e}");
                    self.0
                        .audit(Some(flow), "error", "slack", "in", "block", None, Map::new());
                    Verdict::Drop
                }
            }
        })
    }
}

/// `_slack_socket_check` of one frame from Slack: whether it may reach the agent.
async fn socket_check(content: &Content, flow: &mut Flow, payload: &[u8]) -> Result<bool, CheckError> {
    // Not an event (Slack's pings and the like): passed on.
    // Read as Python's `json.loads` reads it (`NaN`, lone surrogates): a frame serde refuses must
    // not pass unread.
    let Ok(frame) = std::str::from_utf8(payload)
        .map_err(|_| ())
        .and_then(|t| super::json::loads_raw_numbers(t).map_err(|_| ()))
    else {
        return Ok(true);
    };
    let kind = frame.get("type").and_then(Value::as_str).unwrap_or("");
    if !frame.is_object() || !matches!(kind, "events_api" | "slash_commands" | "interactive") {
        return Ok(true);
    }
    let p = frame
        .get("payload")
        .filter(|p| p.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    // A button press, a form sent or a shortcut (`interactive`): only what a person typed, or
    // the message a shortcut was run on; never the agent's own wording (labels, titles, button
    // values), names or places. The addon passed these unread; a difference on purpose.
    let (event, who) = match kind {
        "events_api" => (p.get("event").cloned().unwrap_or(Value::Null), None),
        "interactive" => {
            let id = |k: &str| p.get(k).and_then(|v| v.get("id")).cloned();
            (interaction_text(&p)?, Some((id("channel"), id("user"))))
        }
        _ => (p, None),
    };
    if !event.is_object() {
        return Ok(true);
    }
    let mut out = Vec::new();
    texts(&event, false, &mut out, 0, TEXT_KEYS)?;
    let text = out.join("\n");
    if text.is_empty() {
        return Ok(true);
    }
    let rules = content.rules()?;
    let rule = match super::content::evaluate_shown(&rules, "in", "slack", &text).await {
        Ok(found) => {
            content
                .acting_found(Some(flow), &rules, "in", "slack", &text, None, Some(found))
                .await
        }
        Err(e) => Err(e.into()),
    };
    let rule = match rule {
        Ok(r) => r,
        Err(CheckError::TooLong(_)) => Some(too_long()),
        Err(e) => return Err(e),
    };
    let Some(rule) = rule else { return Ok(true) };
    let failed = rule.by.as_deref() == Some("failed");
    // Not judged (the AI could not run): not acknowledged, so Slack sends it again later.
    if let Some(envelope) = frame.get("envelope_id").and_then(Value::as_str).filter(|_| !failed) {
        flow.inject.push(WsFrame {
            direction: Direction::Out,
            kind: FrameKind::Text,
            payload: Bytes::from(pyjson::dumps(&json!({"envelope_id": envelope}))),
        });
    }
    content.audit(Some(flow), &rule.id, "slack", "in", "block", None, Map::new());
    let pick = |a: &str, b: &str| {
        event
            .get(a)
            .filter(|v| crate::checks::email::admission::truthy(Some(v)))
            .or_else(|| event.get(b))
    };
    let (ch, user) = match who {
        // A form has no channel: the person is told directly.
        Some((ch, user)) => (ch.or_else(|| user.clone()), user),
        None => (pick("channel", "channel_id").cloned(), pick("user", "user_id").cloned()),
    };
    if let (Some(Value::String(ch)), Some(Value::String(user))) = (ch, user) {
        let mut n = json!({"kind": "in", "channel": "slack", "chatId": ch, "userId": user, "vmId": flow.vm_id, "reason": rule.reason});
        if failed {
            n["failed"] = json!(true);
        }
        content.notice(n);
    }
    Ok(false)
}

/// What a person wrote on an interaction, as `{"text": [...]}` for the text walk: what they
/// typed in a form or a message's inputs (`state.values`), a typed input action, and for a message
/// shortcut, the message it was run on unless a bot (the agent) wrote it.
fn interaction_text(p: &Value) -> Result<Value, TextsError> {
    let mut out: Vec<Value> = Vec::new();
    let mut typed = |el: &Value| {
        if let Some(v) = el.get("value").filter(|v| v.is_string()) {
            out.push(v.clone());
        }
        if let Some(rich) = el.get("rich_text_value") {
            out.push(json!({"text": rich}));
        }
    };
    for state in [p.pointer("/view/state/values"), p.pointer("/state/values")]
        .into_iter()
        .flatten()
    {
        for block in state.as_object().into_iter().flat_map(|m| m.values()) {
            for el in block.as_object().into_iter().flat_map(|m| m.values()) {
                typed(el);
            }
        }
    }
    for a in p.get("actions").and_then(Value::as_array).into_iter().flatten() {
        if matches!(
            a.get("type").and_then(Value::as_str),
            Some("plain_text_input" | "rich_text_input")
        ) {
            typed(a);
        }
    }
    if p.get("type").and_then(Value::as_str) == Some("message_action")
        && let Some(m) = p.get("message").filter(|m| m.get("bot_id").is_none())
    {
        let mut words = Vec::new();
        texts(m, false, &mut words, 0, TEXT_KEYS)?;
        out.extend(words.into_iter().map(Value::String));
    }
    Ok(json!({"text": out}))
}

fn too_long() -> Rule {
    Rule {
        id: "error".into(),
        name: None,
        direction: "in".into(),
        channels: vec![],
        patterns: vec![],
        detectors: vec![],
        policy: None,
        action: Action::Block,
        reason: "it is too long to check".into(),
        by: None,
    }
}

#[cfg(test)]
mod tests;
