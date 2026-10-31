//! Email rules (addon.py 1086-1660, docs/plans/email-rules.md). The proxy holds no email rule. For
//! every AgentMail or Gmail send it works out what is being sent where (recipients, ids, the RFC
//! 822 header block, never a body) and asks the firewall agent on `127.0.0.1:8792`, which allows
//! and counts, blocks, or asks the owner. For every AgentMail message or thread it is about to show
//! an agent, it asks the same service whether to keep it, blank its preview, or hide it. Anything
//! that fails, fails closed.

use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::checks::{body, loopback, mime, pyjson};
use crate::flow::Flow;

pub const AGENTMAIL_API: &str = "api.agentmail.to";
pub const AGENTMAIL_WS: &str = "ws.agentmail.to";
pub const PERMISSION_STATUS: u16 = 451;
pub const PERMISSION_TTL: i64 = 300;

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

pub static AM_SEND: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/([^/]+)/messages/send$"));
pub static AM_MSG_OP: LazyLock<Regex> =
    LazyLock::new(|| re(r"^/v0/inboxes/([^/]+)/messages/([^/]+)/(reply|reply-all|forward)$"));
static AM_DRAFT_SEND: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/([^/]+)/drafts/([^/]+)/send$"));
static AM_DRAFT_CREATE: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/[^/]+/drafts$"));
static AM_DRAFT_ONE: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/[^/]+/drafts/[^/]+$"));
static AM_DRAFT_EDIT: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/([^/]+)/drafts/([^/]+)$"));
static AM_MESSAGE_ONE: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/[^/]+/messages/[^/]+$"));
static AM_THREAD_ONE: LazyLock<Regex> = LazyLock::new(|| re(r"^/v0/inboxes/[^/]+/threads/[^/]+$"));
pub static AM_THREAD_ATTACHMENT: LazyLock<Regex> =
    LazyLock::new(|| re(r"^/v0/(?:inboxes/[^/]+/)?threads/[^/]+/attachments(?:/|$)"));
static AM_HEADER_OK: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^(?:X-[A-Za-z0-9-]{1,64}|In-Reply-To|References)$"));
pub static GM_SEND: LazyLock<Regex> = LazyLock::new(|| re(r"^/(upload/)?gmail/v1/users/[^/]+/(messages|drafts)/send$"));
static GM_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| re(r"^/(?:upload/)?gmail/v1/users/[^/]+/messages/(?:import|insert)$"));
static GM_SETTINGS: LazyLock<Regex> = LazyLock::new(|| {
    re(r"^/gmail/v1/users/[^/]+/settings/(forwardingAddresses|autoForwarding|delegates|sendAs|filters)(?:/|$)")
});
static GM_DRAFT_ONE: LazyLock<Regex> = LazyLock::new(|| re(r"^/(?:upload/)?gmail/v1/users/[^/]+/drafts/([^/]+)$"));
static SLASHES: LazyLock<Regex> = LazyLock::new(|| re(r"/+"));
const HIDDEN_FIELDS: &[&str] = &["text", "html", "extracted_text", "extracted_html", "preview", "subject"];

/// `_EMAIL_REASONS`: the words an agent is shown for each refusal.
pub fn reason_text(reason: &str) -> &'static str {
    match reason {
        "sending_off" => "Email sending is turned off for this mailbox.",
        "not_allowed" => "This recipient is not on the allowed list for this mailbox.",
        "hourly_limit" => "This mailbox has reached its hourly sending limit.",
        "daily_limit" => "This mailbox has reached its daily sending limit.",
        "too_many_recipients" => "Too many recipients in one message.",
        "no_recipients" => "The message has no recipients.",
        "unreadable_recipients" => "The firewall could not read the recipients of this message.",
        "lookup_failed" => "The firewall could not check this message. Try again.",
        "headers_refused" => "Custom headers may only be X-* headers, In-Reply-To or References.",
        "unknown_write" => "This AgentMail operation is not allowed from an agent.",
        "forwarding_refused" => "Agents may not set up forwarding, delegates or send-as addresses.",
        "unsupported_upload" => "Send the message with a plain or multipart upload.",
        "held_back" => "This message was held back by your organization's email rules.",
        "draft_busy" => "This draft is being sent. Wait for that to finish before changing it.",
        "scheduled_send" => "Scheduled sending is not allowed from an agent. Send the message when it should go.",
        "thread_attachment" => "Read attachments through the message they belong to.",
        "email_rules_unavailable" => "Email rules are unavailable on the firewall, so email is refused.",
        _ => "Email refused by the firewall.",
    }
}

/// `is_googleapis`.
pub fn is_googleapis(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "googleapis.com" || h.ends_with(".googleapis.com")
}

/// The checked destination's name, lower case ([`crate::checks::check_host`]).
pub fn host(flow: &Flow) -> String {
    crate::checks::check_host(flow)
}

pub fn method(flow: &Flow) -> String {
    flow.request
        .as_ref()
        .map(|r| r.method().as_str().to_uppercase())
        .unwrap_or_default()
}

/// The request's path; for AgentMail, as its server routes it ([`am_path`]).
pub fn path(flow: &Flow) -> String {
    let raw = raw_path(flow);
    if host(flow) == AGENTMAIL_API {
        am_path(&raw)
    } else {
        raw
    }
}

/// The path as sent: what a held request is sent again with, and what a record shows.
pub fn raw_path(flow: &Flow) -> String {
    flow.request
        .as_ref()
        .map(|r| r.uri().path().to_owned())
        .unwrap_or_default()
}

/// The path AgentMail acts on: each segment percent-decoded (but an encoded `/` or `%` kept
/// encoded, so a segment stays one and the ids are decoded once, later), empty and `.` segments
/// dropped, `..` taken back, no trailing slash. `/messages/m1/%72aw`, `/messages//send/` and
/// `/drafts/d1/x/../send` are the routes they name, not other paths the patterns miss. The addon
/// matched the path as written; a difference on purpose.
pub fn am_path(raw: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for seg in raw.split('/') {
        let mut bytes = Vec::with_capacity(seg.len());
        let b = seg.as_bytes();
        let mut i = 0;
        while i < b.len() {
            let hex = (b[i] == b'%')
                .then(|| b.get(i + 1..i + 3))
                .flatten()
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match hex {
                Some(c) if c != b'/' && c != b'%' => {
                    bytes.push(c);
                    i += 3;
                }
                _ => {
                    bytes.push(b[i]);
                    i += 1;
                }
            }
        }
        // A segment that does not decode to UTF-8 stays as written: an id is never changed.
        let d = String::from_utf8(bytes).unwrap_or_else(|_| seg.to_owned());
        match d.as_str() {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            _ => out.push(d),
        }
    }
    format!("/{}", out.join("/"))
}

/// The path Google acts on: percent-decoded, slashes collapsed, no trailing slash.
pub fn google_path(raw: &str) -> String {
    let p = SLASHES.replace_all(&body::unquote(raw), "/").into_owned();
    if p.len() > 1 {
        p.trim_end_matches('/').to_owned()
    } else {
        p
    }
}

/// `_json_body`: the request body as a JSON object; `None` when it is too big, not JSON or not an
/// object. An empty body is `{}`.
pub fn json_body(flow: &Flow) -> Option<Map<String, Value>> {
    let req = flow.request.as_ref()?;
    if req.body().len() > 40 * 1024 * 1024 {
        return None;
    }
    let raw: &[u8] = if req.body().is_empty() { b"{}" } else { req.body() };
    match crate::checks::json::loads(std::str::from_utf8(raw).ok()?).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// What a send looks like to the email rules.
#[derive(Debug, Clone, PartialEq)]
pub enum SendRequest {
    /// Not a send at all.
    None,
    /// Refused with this reason.
    Refuse(&'static str),
    /// Ask the admission service with this payload.
    Ask(Map<String, Value>),
}

fn obj(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

/// `email_send_request`.
pub fn send_request(flow: &Flow) -> SendRequest {
    let vm_id = flow.vm_id.clone().unwrap_or_default();
    let host = host(flow);
    let method = method(flow);
    let path = path(flow);
    if host == AGENTMAIL_API && matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        let (m_send, m_op, m_draft) = (
            AM_SEND.captures(&path),
            AM_MSG_OP.captures(&path),
            AM_DRAFT_SEND.captures(&path),
        );
        let drafting = (method == "POST" && AM_DRAFT_CREATE.is_match(&path))
            || (matches!(method.as_str(), "PATCH" | "PUT") && AM_DRAFT_ONE.is_match(&path));
        if m_send.is_none() && m_op.is_none() && m_draft.is_none() {
            let safe = (method == "DELETE" && AM_DRAFT_ONE.is_match(&path))
                || (method == "PATCH" && (AM_MESSAGE_ONE.is_match(&path) || AM_THREAD_ONE.is_match(&path)));
            if safe {
                return SendRequest::None;
            }
            if !drafting {
                return SendRequest::Refuse("unknown_write");
            }
        }
        let b = if method == "DELETE" {
            Some(Map::new())
        } else {
            json_body(flow)
        };
        let Some(b) = b else {
            return SendRequest::Refuse("unreadable_recipients");
        };
        if let Some(h) = b.get("headers") {
            let ok = h
                .as_object()
                .is_some_and(|m| m.keys().all(|k| AM_HEADER_OK.is_match(k)));
            if !h.is_null() && !ok {
                return SendRequest::Refuse("headers_refused");
            }
        }
        if drafting {
            // A draft that sends itself later would skip every check made at send time.
            if b.keys().any(|k| {
                let k = k.to_lowercase();
                k.contains("send_at") || k.contains("sendat") || k.contains("schedul")
            }) {
                return SendRequest::Refuse("scheduled_send");
            }
            if let Some(c) = AM_DRAFT_EDIT.captures(&path) {
                return SendRequest::Ask(obj(vec![
                    ("action", json!("email.draft_write")),
                    ("provider", json!("agentmail")),
                    ("inboxId", json!(body::unquote(&c[1]))),
                    ("draftId", json!(body::unquote(&c[2]))),
                ]));
            }
            // Recipients are checked when the draft is sent, from the draft itself.
            return SendRequest::None;
        }
        let get = |k: &str| b.get(k).cloned().unwrap_or(Value::Null);
        let mut p = obj(vec![
            ("action", json!("email.reserve")),
            ("vmId", json!(vm_id)),
            ("provider", json!("agentmail")),
            ("to", get("to")),
            ("cc", get("cc")),
            ("bcc", get("bcc")),
        ]);
        if let Some(c) = m_send {
            p.insert("inboxId".into(), json!(body::unquote(&c[1])));
            p.insert("op".into(), json!("send"));
        } else if let Some(c) = m_op {
            p.insert("inboxId".into(), json!(body::unquote(&c[1])));
            p.insert("messageId".into(), json!(body::unquote(&c[2])));
            let op = match &c[3] {
                "reply" if b.get("reply_all") == Some(&Value::Bool(true)) => "reply_all",
                "reply" => "reply",
                "reply-all" => "reply_all",
                _ => "forward",
            };
            p.insert("op".into(), json!(op));
        } else if let Some(c) = m_draft {
            p.insert("inboxId".into(), json!(body::unquote(&c[1])));
            p.insert("draftId".into(), json!(body::unquote(&c[2])));
            p.insert("op".into(), json!("draft_send"));
        }
        return SendRequest::Ask(p);
    }
    if !is_googleapis(&host) {
        return SendRequest::None;
    }
    let gpath = google_path(&path);
    let raw_body = flow.request.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    if gpath.starts_with("/batch/gmail/") || (gpath.starts_with("/batch") && contains(&raw_body, b"/gmail/v1/")) {
        return SendRequest::Refuse("unsupported_upload");
    }
    if method != "GET" && GM_IMPORT.is_match(&gpath) {
        return SendRequest::Refuse("unknown_write");
    }
    if let Some(c) = GM_SETTINGS.captures(&gpath)
        && method != "GET"
    {
        if &c[1] != "filters" {
            return SendRequest::Refuse("forwarding_refused");
        }
        let b = json_body(flow);
        if method == "POST" {
            let Some(b) = b else {
                return SendRequest::Refuse("forwarding_refused");
            };
            // `(body.get("action") or {}).get("forward")`: an action that is truthy and not an
            // object raises, which `email_outbound` answers as unreadable.
            match b.get("action").filter(|a| truthy(Some(a))) {
                Some(Value::Object(a)) if truthy(a.get("forward")) => return SendRequest::Refuse("forwarding_refused"),
                Some(Value::Object(_)) | None => {}
                Some(_) => return SendRequest::Refuse("unreadable_recipients"),
            }
        }
        return SendRequest::None;
    }
    if let Some(c) = GM_DRAFT_ONE.captures(&gpath)
        && matches!(method.as_str(), "PUT" | "PATCH" | "DELETE")
    {
        return SendRequest::Ask(obj(vec![
            ("action", json!("email.draft_write")),
            ("provider", json!("gmail")),
            ("draftId", json!(&c[1])),
        ]));
    }
    let Some(c) = GM_SEND.captures(&gpath).filter(|_| method == "POST") else {
        return SendRequest::None;
    };
    let upload = c.get(1).is_some();
    let kind = c[2].to_owned();
    let mut p = obj(vec![
        ("action", json!("email.reserve")),
        ("vmId", json!(vm_id)),
        ("provider", json!("gmail")),
        ("op", json!(if kind == "messages" { "send" } else { "draft_send" })),
    ]);
    let with_head = |mut p: Map<String, Value>, message: &[u8]| match mime::header_block(message) {
        Some(h) => {
            p.insert("head".into(), json!(h));
            SendRequest::Ask(p)
        }
        None => SendRequest::Refuse("unreadable_recipients"),
    };
    if upload {
        if kind == "drafts" {
            return SendRequest::Refuse("unsupported_upload");
        }
        let message = match upload_type(flow).as_str() {
            "media" => Some(raw_body.to_vec()),
            "multipart" => {
                let ct = flow
                    .request
                    .as_ref()
                    .map(|r| body::content_type(r.headers()))
                    .unwrap_or_default();
                mime::multipart_message(&ct, &raw_body)
            }
            _ => return SendRequest::Refuse("unsupported_upload"),
        };
        return match message.filter(|m| !m.is_empty()) {
            Some(m) => with_head(p, &m),
            None => SendRequest::Refuse("unreadable_recipients"),
        };
    }
    let Some(b) = json_body(flow) else {
        return SendRequest::Refuse("unreadable_recipients");
    };
    if kind == "messages" {
        return match b.get("raw").and_then(mime::b64url).filter(|m| !m.is_empty()) {
            Some(m) => with_head(p, &m),
            None => SendRequest::Refuse("unreadable_recipients"),
        };
    }
    let inner = b.get("message").and_then(Value::as_object).cloned().unwrap_or_default();
    if inner.get("raw").is_some_and(|r| !r.is_null()) {
        return match inner.get("raw").and_then(mime::b64url).filter(|m| !m.is_empty()) {
            Some(m) => with_head(p, &m),
            None => SendRequest::Refuse("unreadable_recipients"),
        };
    }
    if let Some(id) = b.get("id").and_then(Value::as_str) {
        p.insert("draftId".into(), json!(id));
        return SendRequest::Ask(p);
    }
    SendRequest::Refuse("unreadable_recipients")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Python truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// `request.query.get("uploadType", "")`: the first value.
pub fn upload_type(flow: &Flow) -> String {
    flow.request
        .as_ref()
        .map(|r| body::query_items(r.uri()))
        .and_then(|q| q.into_iter().find(|(k, _)| k == "uploadType").map(|(_, v)| v))
        .unwrap_or_default()
}

/// `email_admission`: one call to 8792; an error unless the answer says `ok: true`.
pub async fn admission(
    url: &str,
    payload: &Value,
    timeout: Duration,
) -> Result<Map<String, Value>, loopback::CallError> {
    match loopback::post(url, pyjson::dumps(payload).as_bytes(), timeout).await {
        Ok(raw) => match serde_json::from_slice::<Value>(&raw)? {
            Value::Object(m) if m.get("ok") == Some(&Value::Bool(true)) => Ok(m),
            _ => Err(loopback::CallError::Malformed),
        },
        Err(e) => Err(e),
    }
}

/// `email_approval_doc`: what an agent is told when a send waits for the owner.
pub fn approval_doc(pids: &[String], recipients: &[String], summary: &str) -> Value {
    let who = if recipients.is_empty() {
        "a new recipient".to_owned()
    } else {
        recipients.join(", ")
    };
    let ids = pids.join(", ");
    let wait = pids
        .iter()
        .map(|p| format!("`cc-perm {p}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    let first = pids.first().map_or("<id>", String::as_str);
    let message = format!(
        "Approval needed: nothing was sent. The owner has been asked to approve emailing {who} (request {ids}). The whole message is held, every recipient included, and it does not send itself once approved: send it again after approval. Wait for the answer with {wait}, or check it with `cc-perm status {first}`. Tell the person you are waiting for the owner. Do not retry in a loop."
    );
    json!({"permission_id": pids.first(), "permission_ids": pids, "reason": "email_recipient_needs_approval",
           "recipients": recipients, "summary": summary, "resend": "manual", "message": message,
           "expires_at": crate::checks::content::rules::now() as i64 + PERMISSION_TTL})
}

/// `_email_answer`: a refused or held send, as the agent's mail client shows it. On googleapis.com
/// Google's own `{"error": {...}}` object carries it too.
pub fn email_answer_body(flow: &Flow, status: u16, mut doc: Value) -> Value {
    if is_googleapis(&host(flow)) {
        let reason = match doc.get("error") {
            Some(Value::String(s)) => json!(s),
            _ => doc.get("reason").cloned().unwrap_or(Value::Null),
        };
        let message = doc.get("message").cloned().unwrap_or(Value::Null);
        doc["error"] = json!({"code": status, "message": message,
            "status": if status == PERMISSION_STATUS { "FAILED_PRECONDITION" } else { "PERMISSION_DENIED" },
            "errors": [{"domain": "controlclaw.firewall", "reason": reason, "message": message}]});
    }
    doc
}

/// `permission_id_for`.
pub fn permission_id_for(scope: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("perm_{}", &hex::encode(Sha256::digest(scope.as_bytes()))[..32])
}

// ---- AgentMail in -------------------------------------------------------------------------------

pub fn is_message(d: &Value) -> bool {
    d.as_object().is_some_and(|o| {
        o.get("message_id").is_some_and(Value::is_string)
            && o.get("inbox_id").is_some_and(Value::is_string)
            && o.contains_key("thread_id")
    })
}

pub fn is_thread(d: &Value) -> bool {
    d.as_object().is_some_and(|o| {
        o.get("thread_id").is_some_and(Value::is_string)
            && o.get("inbox_id").is_some_and(Value::is_string)
            && !o.contains_key("message_id")
    })
}

/// `_hide_message`: a message the agent asked for by id, marked blocked and emptied.
pub fn hide_message(m: &mut Map<String, Value>) {
    let mut labels = m.get("labels").and_then(Value::as_array).cloned().unwrap_or_default();
    if !labels.iter().any(|l| l == "blocked") {
        labels.push(json!("blocked"));
    }
    m.insert("labels".into(), Value::Array(labels));
    for f in HIDDEN_FIELDS {
        if m.contains_key(*f) {
            m.insert((*f).into(), json!(""));
        }
    }
    if m.contains_key("attachments") {
        m.insert("attachments".into(), json!([]));
    }
    for f in ["headers", "authentication_results"] {
        if m.contains_key(f) {
            m.insert(f.into(), json!({}));
        }
    }
}

/// One item the admission service is asked about, with where it sits in the document.
pub struct Target {
    pub inbox: String,
    pub item: Value,
    /// The path to the original in the document: indexes and keys.
    pub at: Vec<Step>,
}

#[derive(Clone, Debug)]
pub enum Step {
    Key(&'static str),
    Index(usize),
}

fn message_item(m: &Map<String, Value>) -> Value {
    let mut item = Map::new();
    item.insert("kind".into(), json!("message"));
    for (k, v) in m {
        if [
            "message_id",
            "from",
            "labels",
            "authentication_results",
            "headers",
            "text",
            "html",
            "extracted_text",
            "extracted_html",
        ]
        .contains(&k.as_str())
        {
            item.insert(k.clone(), v.clone());
        }
    }
    Value::Object(item)
}

fn collect(container: &[Value], at: &[Step], targets: &mut Vec<Target>) {
    for (i, item) in container.iter().enumerate() {
        let mut here = at.to_vec();
        here.push(Step::Index(i));
        if is_message(item) {
            let o = item.as_object().cloned().unwrap_or_default();
            targets.push(Target {
                inbox: str_of(&o, "inbox_id"),
                item: message_item(&o),
                at: here,
            });
        } else if is_thread(item) {
            if let Some(ms) = item.get("messages").and_then(Value::as_array) {
                let mut inner = here.clone();
                inner.push(Step::Key("messages"));
                collect(ms, &inner, targets);
            }
            targets.push(Target {
                inbox: item.get("inbox_id").and_then(Value::as_str).unwrap_or_default().to_owned(),
                item: json!({"kind": "thread", "senders": item.get("senders").cloned().unwrap_or(Value::Null), "labels": item.get("labels").cloned().unwrap_or(Value::Null)}),
                at: here,
            });
        }
    }
}

fn str_of(o: &Map<String, Value>, k: &str) -> String {
    o.get(k).and_then(Value::as_str).unwrap_or_default().to_owned()
}

/// The items of an AgentMail answer to ask about (`agentmail_filter`'s `collect`).
pub fn targets(doc: &Value) -> Vec<Target> {
    let mut t = Vec::new();
    if is_message(doc) || is_thread(doc) {
        collect(std::slice::from_ref(doc), &[], &mut t);
        // The document itself is at the root, not at index 0.
        for target in &mut t {
            target.at.remove(0);
        }
    } else if let Some(o) = doc.as_object() {
        for key in ["messages", "threads"] {
            if let Some(list) = o.get(key).and_then(Value::as_array) {
                collect(list, &[Step::Key(key)], &mut t);
            }
        }
    }
    t
}

pub fn get_at<'a>(doc: &'a Value, at: &[Step]) -> Option<&'a Value> {
    let mut v = doc;
    for s in at {
        v = match s {
            Step::Key(k) => v.get(*k)?,
            Step::Index(i) => v.get(*i)?,
        };
    }
    Some(v)
}

/// `agentmail_filter`, given each target's verdict (`keep`, `strip` or `hide`), by its place.
pub fn apply_verdicts(doc: &mut Value, verdicts: &[(Vec<Step>, String)]) {
    let by_path: std::collections::HashMap<String, &String> = verdicts.iter().map(|(p, v)| (key(p), v)).collect();
    let verdict_at = |at: &[Step]| -> String {
        by_path
            .get(&key(at))
            .map_or_else(|| "keep".to_owned(), |v| (*v).clone())
    };
    if is_message(doc) {
        let v = verdict_at(&[]);
        if let Some(o) = doc.as_object_mut() {
            if v == "hide" {
                hide_message(o);
            } else if v == "strip" && o.contains_key("preview") {
                o.insert("preview".into(), json!(""));
            }
        }
        return;
    }
    if is_thread(doc) {
        let mut single = vec![doc.clone()];
        let pruned = prune(&mut single, &[], &verdict_at, true);
        if pruned.is_empty() {
            if let Some(o) = doc.as_object_mut() {
                o.insert("messages".into(), json!([]));
                for f in ["preview", "subject"] {
                    if o.contains_key(f) {
                        o.insert(f.into(), json!(""));
                    }
                }
            }
        } else {
            *doc = pruned.into_iter().next().unwrap_or(Value::Null);
        }
        return;
    }
    let Some(o) = doc.as_object_mut() else { return };
    for key in ["messages", "threads"] {
        let Some(list) = o.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        let before = list.len();
        let kept = prune(list, &[Step::Key(key)], &verdict_at, false);
        let removed = before - kept.len();
        *list = kept;
        if let Some(count) = o
            .get("count")
            .and_then(Value::as_i64)
            .filter(|_| o.get("count").is_some_and(|c| c.is_i64() || c.is_u64()))
        {
            o.insert("count".into(), json!((count - removed as i64).max(0)));
        }
    }
}

/// A place in the document as one string: `messages/3/messages/0`.
fn key(at: &[Step]) -> String {
    at.iter()
        .map(|s| match s {
            Step::Key(k) => (*k).to_owned(),
            Step::Index(i) => i.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `prune`: hidden items out, stripped ones and threads without a preview. `root`: the list is the
/// thread document itself (its place has no index).
fn prune(container: &mut [Value], at: &[Step], verdict_at: &dyn Fn(&[Step]) -> String, root: bool) -> Vec<Value> {
    let mut kept = Vec::new();
    for (i, item) in container.iter_mut().enumerate() {
        let mut here = at.to_vec();
        if !root {
            here.push(Step::Index(i));
        }
        let act = verdict_at(&here);
        if is_thread(item)
            && let Some(ms) = item.get_mut("messages").and_then(Value::as_array_mut)
        {
            let mut inner = here.clone();
            inner.push(Step::Key("messages"));
            let pruned = prune(ms, &inner, verdict_at, false);
            let empty = pruned.is_empty();
            *ms = pruned;
            if empty
                && act != "hide"
                && let Some(o) = item.as_object_mut()
            {
                o.insert("subject".into(), json!(""));
            }
        }
        if act == "hide" {
            continue;
        }
        if (act == "strip" || is_thread(item))
            && let Some(o) = item.as_object_mut()
            && o.contains_key("preview")
        {
            o.insert("preview".into(), json!(""));
        }
        kept.push(item.clone());
    }
    kept
}

/// `_decide_via_admission`: one call per inbox (in chunks of 200); no answer hides everything.
pub async fn decide(url: &str, items: &[(String, Value)]) -> Vec<Value> {
    let mut out = vec![json!({"action": "hide"}); items.len()];
    let mut inboxes: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, (inbox, _)) in items.iter().enumerate() {
        match inboxes.iter_mut().find(|(n, _)| n == inbox) {
            Some((_, idx)) => idx.push(i),
            None => inboxes.push((inbox.clone(), vec![i])),
        }
    }
    for (inbox, idx) in inboxes {
        for chunk in idx.chunks(200) {
            let payload = json!({"action": "email.inbound", "provider": "agentmail", "inboxId": inbox,
                                 "items": chunk.iter().map(|i| items[*i].1.clone()).collect::<Vec<_>>()});
            if let Ok(result) = admission(url, &payload, Duration::from_secs(5)).await
                && let Some(acts) = result.get("actions").and_then(Value::as_array)
                && acts.len() == chunk.len()
            {
                for (i, a) in chunk.iter().zip(acts) {
                    out[*i] = if a.is_object() {
                        a.clone()
                    } else {
                        json!({"action": "hide"})
                    };
                }
            }
        }
    }
    out
}

/// The action an answer names (`a.get("action")`), `hide` for anything that is not an object.
pub fn action_of(a: &Value) -> String {
    match a {
        Value::Object(o) => match o.get("action") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => "None".into(),
            Some(other) => other.to_string(),
        },
        _ => "hide".into(),
    }
}
