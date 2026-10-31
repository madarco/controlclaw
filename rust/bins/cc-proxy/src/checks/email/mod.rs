//! Email (appendix F features 16 and 21): the email rules on AgentMail and Gmail sends
//! ([`admission`]), and the content rules on what is sent and what is read (addon.py 6180-6505).
//!
//! Out: after the email rules let a write through, the text of the message: AgentMail's JSON
//! (subject, text, HTML) and Gmail's MIME message. Drafts are read when they are written, because
//! sending one carries no text. A forward is checked with the mail it carries, read from AgentMail
//! with the agent's own key. In: AgentMail messages the email rules kept, over the API and the
//! websocket, and Gmail's `messages.get` and `threads.get`.

pub mod admission;

use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use self::admission::{
    AGENTMAIL_API, AGENTMAIL_WS, AM_MSG_OP, AM_SEND, AM_THREAD_ATTACHMENT, GM_SEND, PERMISSION_STATUS, SendRequest,
    host, is_googleapis, method, path,
};
use super::content::engine::{self, Rule, TooLong};
use super::content::{CheckError, Content, HOLD_BODY_MAX, HOLD_TEXT_MAX};
use super::telegram::{detail, py_str};
use super::{body, mime, pyjson, raw_response, set_body};
use crate::flow::{Direction, Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

// In any case: a read the server routes another way must not pass unchecked.
static AM_RAW: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^/v0/inboxes/[^/]+/messages/[^/]+/raw$"));
static AM_ATTACHMENT: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^/v0/inboxes/([^/]+)/messages/([^/]+)/(?:attachments/[^/]+|raw)$"));
static GM_DRAFT_WRITE: LazyLock<Regex> = LazyLock::new(|| re(r"^/(upload/)?gmail/v1/users/[^/]+/drafts(?:/[^/]+)?$"));
static GM_READ: LazyLock<Regex> = LazyLock::new(|| re(r"^/gmail/v1/users/[^/]+/(messages|threads)/[^/]+$"));

pub const META_RESERVATION: &str = "cc_email_reservation";
/// A send the email rules let through: the record says `email: sent` (W1 writes it).
pub const META_SENT: &str = "email_sent";
/// The rules an AgentMail write read before it went, for its answer to be checked with.
pub const META_RULES: &str = "cc_content_rules";

const RULES_LOADING: &str =
    r#"{"error":"rules_loading","message":"The firewall is loading its rules. Try again in a few seconds."}"#;
const AGENTMAIL_FORWARD_READ_MAX: usize = 4 * 1024 * 1024;

/// What the email steps share.
pub struct Email {
    pub content: Arc<Content>,
    pub admission_url: String,
    pub pending: Pending,
    /// Where the proxy reads a forwarded mail from (`https://api.agentmail.to`; a test's own server).
    pub agentmail_base: String,
    pub creds: Arc<super::creds::Creds>,
    /// The client a forward's mail is read with, kept for its connections.
    pub http: reqwest::Client,
}

pub fn register(pipeline: &mut Pipeline, email: Arc<Email>) {
    pipeline.push(order::EMAIL, Arc::new(EmailRequest(email.clone())));
    pipeline.push(order::RESPONSE_GMAIL_IN, Arc::new(GmailIn(email.clone())));
    pipeline.push(order::RESPONSE_EMAIL_SETTLE, Arc::new(EmailSettle(email.clone())));
    pipeline.push(order::RESPONSE_AGENTMAIL, Arc::new(AgentMailResponse(email.clone())));
    pipeline.push(order::WS_AGENTMAIL, Arc::new(AgentMailSocket(email)));
}

fn is_email_host(h: &str) -> bool {
    h == AGENTMAIL_API || h == AGENTMAIL_WS || is_googleapis(h)
}

// ---- pending requests ---------------------------------------------------------------------------

/// `record_pending`: a permission request for the mitm-agent, once per id and agent per process.
pub struct Pending {
    pub path: std::path::PathBuf,
    seen: Mutex<std::collections::HashSet<String>>,
}

impl Pending {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            seen: Mutex::new(Default::default()),
        }
    }

    pub fn record(&self, permission_id: &str, record: &Value) {
        let vm = record.get("vm_id").and_then(Value::as_str).unwrap_or("");
        let key = format!("{permission_id}|{vm}");
        let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !seen.insert(key) {
            return;
        }
        use std::io::Write;
        let line = format!("{}\n", pyjson::dumps_unicode(record));
        let r = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = r {
            tracing::warn!("[mitm] pending write failed: {e}");
        }
    }
}

// ---- answers ------------------------------------------------------------------------------------

/// `_email_refuse`: 403 `email_refused`, in Google's shape too on googleapis.com.
fn refuse(flow: &mut Flow, reason: &str, message: Option<&str>, rule: Option<&str>) -> Verdict {
    let doc = json!({"error": "email_refused", "reason": reason, "message": message.unwrap_or_else(|| admission::reason_text(reason))});
    let doc = admission::email_answer_body(flow, 403, doc);
    let mut rec = Map::new();
    rec.insert("email_reason".into(), json!(reason));
    super::answer(flow, 403, &doc, "block", rule.unwrap_or("email"), rec)
}

/// A JSON answer written as the addon writes a fixed one (its own bytes, not `json.dumps`).
fn literal(flow: &mut Flow, status: u16, body: &str, effect: &str, rule: &str) -> Verdict {
    super::note(flow, effect, rule, status, Map::new());
    Verdict::Answer(Box::new(raw_response(
        status,
        body.as_bytes().to_vec(),
        "application/json",
    )))
}

// ---- the request --------------------------------------------------------------------------------

pub struct EmailRequest(pub Arc<Email>);

impl Step for EmailRequest {
    fn name(&self) -> &'static str {
        "email"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// AgentMail's API and Google's: sends, drafts and the rules a write reads.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        super::request_has_body(flow) && is_email_host(&host(flow))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !is_email_host(&host(flow)) {
                return Verdict::Continue;
            }
            let e = &self.0;
            // A body the plumbing has not decoded cannot be read for its recipients or its words.
            if super::request_body_unread(flow) {
                return refuse(flow, "unreadable_recipients", None, None);
            }
            if let Some(v) = agentmail_raw(e, flow).or_else(|| agentmail_before(e, flow)) {
                return v;
            }
            if !attachment_allowed(e, flow).await {
                let why = if AM_THREAD_ATTACHMENT.is_match(&path(flow)) {
                    "thread_attachment"
                } else {
                    "held_back"
                };
                return refuse(flow, why, None, None);
            }
            if let Some(v) = outbound(e, flow).await {
                return v;
            }
            content_out(e, flow).await.unwrap_or(Verdict::Continue)
        })
    }
}

/// `content_rules_agentmail_raw`: the raw message is the whole mail, which the JSON filter never
/// sees: refused while a rule reads mail coming in.
fn agentmail_raw(e: &Email, flow: &mut Flow) -> Option<Verdict> {
    if host(flow) != AGENTMAIL_API || !AM_RAW.is_match(&path(flow)) {
        return None;
    }
    if let Ok(rules) = e.content.rules()
        && !engine::applies(&rules, "in", "email")
    {
        return None;
    }
    Some(refuse(
        flow,
        "content_rule",
        Some("Read the message instead of its raw form: your organization's content rules check messages coming in."),
        Some("content: raw read"),
    ))
}

/// `content_rules_agentmail_before`: a write reads the rules before it goes; while they are not
/// known it is refused here, before anything was sent.
fn agentmail_before(e: &Email, flow: &mut Flow) -> Option<Verdict> {
    if host(flow) != AGENTMAIL_API || matches!(method(flow).as_str(), "GET" | "HEAD" | "OPTIONS") {
        return None;
    }
    match e.content.rules() {
        Ok(rules) => {
            flow.meta
                .insert(META_RULES, serde_json::to_value(&*rules).unwrap_or(Value::Null));
            None
        }
        Err(_) => Some(literal(flow, 503, RULES_LOADING, "block", "content: rules unknown")),
    }
}

/// `agentmail_attachment_allowed`: attachment and raw reads carry no message, so the firewall
/// checks the message they belong to.
async fn attachment_allowed(e: &Email, flow: &Flow) -> bool {
    if host(flow) != AGENTMAIL_API || method(flow) != "GET" {
        return true;
    }
    let p = path(flow);
    if AM_THREAD_ATTACHMENT.is_match(&p) {
        return false;
    }
    let Some(c) = AM_ATTACHMENT.captures(&p) else {
        return true;
    };
    let payload = json!({"action": "email.inbound", "provider": "agentmail", "inboxId": body::unquote(&c[1]),
                         "items": [{"kind": "ref", "message_id": body::unquote(&c[2])}]});
    match admission::admission(&e.admission_url, &payload, Duration::from_secs(20)).await {
        Ok(r) => r
            .get("actions")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .is_some_and(|a| a.get("action") == Some(&json!("keep"))),
        Err(_) => false,
    }
}

/// `email_outbound`: `None` when the request may go on (counted if it is a send).
async fn outbound(e: &Email, flow: &mut Flow) -> Option<Verdict> {
    let payload = match admission::send_request(flow) {
        SendRequest::None => return None,
        SendRequest::Refuse(reason) => return Some(refuse(flow, reason, None, None)),
        SendRequest::Ask(p) => p,
    };
    let is_draft = payload.get("action") == Some(&json!("email.draft_write"));
    let Ok(result) = admission::admission(&e.admission_url, &Value::Object(payload), Duration::from_secs(20)).await
    else {
        return Some(refuse(flow, "email_rules_unavailable", None, None));
    };
    if is_draft {
        return if result.get("draftOk") == Some(&Value::Bool(true)) {
            None
        } else {
            Some(refuse(flow, "draft_busy", None, None))
        };
    }
    let decision = result.get("decision").and_then(Value::as_str).unwrap_or("");
    if let Some(id) = result
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| decision == "allow" && is_reservation(id))
    {
        flow.meta.insert(META_RESERVATION, json!(id));
        flow.meta.insert(META_SENT, json!(true));
        return None;
    }
    let asks: Vec<Map<String, Value>> = result
        .get("asks")
        .and_then(Value::as_array)
        .filter(|a| decision == "ask" && !a.is_empty())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_object())
                .filter(|x| {
                    x.get("scope").is_some_and(Value::is_string) && x.get("summary").is_some_and(Value::is_string)
                })
                .take(20)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if decision == "ask"
        && result
            .get("asks")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    {
        let (mut pids, mut recipients) = (Vec::new(), Vec::new());
        let (h, m) = (host(flow), method(flow));
        for ask in &asks {
            let scope = ask["scope"].as_str().unwrap_or("");
            let summary = ask["summary"].as_str().unwrap_or("");
            let pid = admission::permission_id_for(scope);
            pids.push(pid.clone());
            let recipient = ask.get("recipient").and_then(Value::as_str);
            let mailbox = ask.get("mailbox").and_then(Value::as_str);
            if let Some(r) = recipient.filter(|r| !r.is_empty()) {
                recipients.push(r.to_owned());
            }
            let mut rec = json!({"permission_id": pid, "vm_id": flow.vm_id, "scope": scope, "summary": engine::cut(summary, 300),
                                 "kind": "email_recipient", "host": h, "method": m, "path": super::record::redact_path(&path(flow), &h)});
            if let (Some(r), Some(mb)) = (recipient.filter(|r| !r.is_empty()), mailbox.filter(|m| !m.is_empty())) {
                rec["recipient"] = json!(engine::cut(r, 254));
                rec["mailbox"] = json!(engine::cut(mb, 300));
            }
            e.pending.record(&pid, &rec);
        }
        let summary = asks
            .iter()
            .filter_map(|a| a["summary"].as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let doc = admission::email_answer_body(
            flow,
            PERMISSION_STATUS,
            admission::approval_doc(&pids, &recipients, &summary),
        );
        let mut rec = Map::new();
        rec.insert("permission_id".into(), json!(pids.first()));
        return Some(super::answer(
            flow,
            PERMISSION_STATUS,
            &doc,
            "require_permission",
            "email",
            rec,
        ));
    }
    let reason = match result.get("reason") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(v) if admission::truthy(Some(v)) => py_str(v),
        _ => "not_allowed".into(),
    };
    Some(refuse(flow, &reason, None, None))
}

fn is_reservation(id: &str) -> bool {
    id.len() == 48 && id.bytes().all(|b| matches!(b, b'a'..=b'f' | b'0'..=b'9'))
}

// ---- content rules out --------------------------------------------------------------------------

/// `_agentmail_text`: what an AgentMail item says.
pub fn agentmail_text(item: &Value) -> String {
    let mut out: Vec<String> = ["subject", "preview", "text", "extracted_text"]
        .iter()
        .filter_map(|k| item.get(*k).and_then(Value::as_str).map(str::to_owned))
        .collect();
    for k in ["html", "extracted_html"] {
        if let Some(h) = item.get(k).and_then(Value::as_str) {
            out.push(mime::html_text(h));
        }
    }
    out.into_iter().filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n")
}

/// A Gmail message to read, owned, so it can be read on the blocking pool (base64 and MIME over up
/// to about 37 MB).
enum GmailOut {
    Upload {
        kind: String,
        raw: bytes::Bytes,
        content_type: String,
    },
    Raw(Value),
}

impl GmailOut {
    fn read(self) -> Result<Option<(String, bool)>, CheckError> {
        let unreadable = || CheckError::Failed("an upload the firewall cannot read".into());
        let message = match self {
            GmailOut::Upload {
                kind,
                raw,
                content_type,
            } => {
                let m = match kind.as_str() {
                    "media" => Some(raw.to_vec()),
                    "multipart" => mime::multipart_message(&content_type, &raw),
                    // A resumable upload sends the message in a later request this check cannot tie back.
                    _ => return Err(unreadable()),
                };
                Some(m.filter(|m| !m.is_empty()).ok_or_else(unreadable)?)
            }
            GmailOut::Raw(r) => mime::b64url(&r),
        };
        // A draft sent by its id: its text was read when it was written.
        match message.filter(|m| !m.is_empty()) {
            None => Ok(None),
            Some(m) => mime::mime_text(&m)
                .map(|t| Some((t, false)))
                .ok_or_else(|| CheckError::Failed("a message the firewall cannot read".into())),
        }
    }
}

/// `_email_out_text`: the text of an outgoing message and whether it can be held; `Ok(None)` when
/// the request carries no message; an error for an upload the firewall cannot read. The Gmail
/// message is read off the async workers.
async fn out_text_off(flow: &Flow) -> Result<Option<(String, bool)>, CheckError> {
    match out_source(flow)? {
        None => Ok(None),
        Some(Ok(found)) => Ok(Some(found)),
        Some(Err(job)) => engine::off_workers(move || job.read()).await,
    }
}

/// What carries the outgoing message: AgentMail's text (read here), or a Gmail message to read.
#[allow(clippy::type_complexity)]
fn out_source(flow: &Flow) -> Result<Option<Result<(String, bool), GmailOut>>, CheckError> {
    let (h, m, p) = (host(flow), method(flow), path(flow));
    if !matches!(m.as_str(), "POST" | "PUT" | "PATCH") {
        return Ok(None);
    }
    if h == AGENTMAIL_API {
        let Some(b) = admission::json_body(flow) else {
            return Ok(None);
        };
        if !["subject", "text", "html"].iter().any(|k| b.contains_key(*k)) {
            return Ok(None);
        }
        return Ok(Some(Ok((
            agentmail_text(&Value::Object(b)),
            AM_SEND.is_match(&p) || AM_MSG_OP.is_match(&p),
        ))));
    }
    if !is_googleapis(&h) {
        return Ok(None);
    }
    let gp = admission::google_path(&p);
    if !(GM_SEND.is_match(&gp) || GM_DRAFT_WRITE.is_match(&gp)) {
        return Ok(None);
    }
    if gp.starts_with("/upload/") {
        let raw = flow.request.as_ref().map(|r| r.body().clone()).unwrap_or_default();
        let content_type = flow
            .request
            .as_ref()
            .map(|r| body::content_type(r.headers()))
            .unwrap_or_default();
        return Ok(Some(Err(GmailOut::Upload {
            kind: admission::upload_type(flow),
            raw,
            content_type,
        })));
    }
    let b = admission::json_body(flow).unwrap_or_default();
    let inner = b.get("message").and_then(Value::as_object).cloned().unwrap_or(b);
    match inner.get("raw").filter(|r| !r.is_null()) {
        Some(r) => Ok(Some(Err(GmailOut::Raw(r.clone())))),
        None => Ok(None),
    }
}

/// `_agentmail_forward`: the inbox and message of an AgentMail forward.
fn forward_of(flow: &Flow) -> Option<(String, String)> {
    if host(flow) != AGENTMAIL_API || method(flow) != "POST" {
        return None;
    }
    let p = path(flow);
    let c = AM_MSG_OP.captures(&p)?;
    (&c[3] == "forward").then(|| (body::unquote(&c[1]), body::unquote(&c[2])))
}

async fn content_out(e: &Email, flow: &mut Flow) -> Option<Verdict> {
    let refuse_with = |flow: &mut Flow, rule: Option<&Rule>, extra: &str, reason: Option<&str>| {
        let why = rule.map_or(reason.unwrap_or("the check could not run"), |r| r.reason.as_str());
        let label = rule.map_or_else(|| "content: error".to_owned(), |r| format!("content: {}", r.id));
        refuse(
            flow,
            "content_rule",
            Some(&format!("Blocked by your organization's rules: {why}{extra}")),
            Some(&label),
        )
    };
    match content_out_checked(e, flow, &refuse_with).await {
        Ok(v) => v,
        Err(CheckError::TooLong(_)) => {
            let v = refuse_with(flow, None, "", Some("it is too long to check"));
            e.content
                .audit(Some(flow), "error", "email", "out", "block", None, detail("too long"));
            Some(v)
        }
        Err(err) => {
            tracing::warn!("[content-rules] outgoing email check failed, refusing: {err}");
            let v = refuse_with(flow, None, "", None);
            e.content
                .audit(Some(flow), "error", "email", "out", "block", None, Map::new());
            Some(v)
        }
    }
}

type RefuseWith<'r> = dyn Fn(&mut Flow, Option<&Rule>, &str, Option<&str>) -> Verdict + Sync + 'r;

async fn content_out_checked(
    e: &Email,
    flow: &mut Flow,
    refuse_with: &RefuseWith<'_>,
) -> Result<Option<Verdict>, CheckError> {
    let found = out_text_off(flow).await?;
    let forward = forward_of(flow);
    if forward.is_none() && found.as_ref().is_none_or(|(t, _)| t.is_empty()) {
        return Ok(None);
    }
    let rules = e.content.rules()?;
    if !engine::applies(&rules, "out", "email") {
        return Ok(None);
    }
    let (mut text, holdable) = found.unwrap_or_else(|| (String::new(), true));
    if let Some((inbox, message_id)) = forward {
        // A forward sends a received mail on, which its body does not carry: read with the agent's
        // own key, as the agent could read it, and checked with the forward's own words.
        let original = forwarded_text(e, flow, &inbox, &message_id).await?;
        text = [text, original]
            .into_iter()
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if text.is_empty() {
            return Ok(None);
        }
    }
    let Some(rule) = e
        .content
        .acting(Some(flow), &rules, "out", "email", &text, None)
        .await?
    else {
        return Ok(None);
    };
    if rule.action == engine::Action::Hold {
        let mut extra = " (it could not be held for approval)";
        let p = path(flow);
        let m = AM_SEND.captures(&p).or_else(|| AM_MSG_OP.captures(&p));
        let raw_len = flow.request.as_ref().map_or(0, |r| r.body().len());
        if let Some(c) = m.filter(|_| holdable && raw_len <= HOLD_BODY_MAX) {
            let text_body = flow
                .request
                .as_ref()
                .map(|r| body::get_text(&body::content_type(r.headers()), r.body()))
                .unwrap_or_default();
            let mut payload = Map::new();
            payload.insert("channel".into(), json!("email"));
            payload.insert("method".into(), json!(method(flow)));
            payload.insert("path".into(), json!(admission::raw_path(flow)));
            payload.insert("body".into(), json!(text_body));
            payload.insert("chatId".into(), json!(body::unquote(&c[1])));
            payload.insert("vmId".into(), json!(flow.vm_id));
            payload.insert("rule".into(), rule.brief());
            payload.insert("text".into(), json!(engine::cut(&text, HOLD_TEXT_MAX)));
            if let Some(super::content::Held { answer, .. }) = e.content.hold(flow, payload).await? {
                let hold_id = answer.get("holdId").cloned().unwrap_or(Value::Null);
                let held = format!("held-{}", hold_id.as_str().unwrap_or_default());
                let body = json!({"message_id": held, "thread_id": held});
                return Ok(Some(e.content.held_answer(flow, &rule, "email", hold_id, 200, &body)));
            }
            extra = " (nobody could be asked to approve it)";
        }
        let v = refuse_with(flow, Some(&rule), extra, None);
        let mut x = Map::new();
        x.insert("held".into(), json!(false));
        e.content.audit(Some(flow), &rule.id, "email", "out", "block", None, x);
        return Ok(Some(v));
    }
    let v = refuse_with(flow, Some(&rule), "", None);
    e.content
        .audit(Some(flow), &rule.id, "email", "out", "block", None, Map::new());
    Ok(Some(v))
}

/// `_agentmail_message_text`: the mail a forward sends on, read with the key the proxy would swap
/// in for the agent's placeholder. Its own words on failure: an error about the request could
/// carry the key.
async fn forwarded_text(e: &Email, flow: &Flow, inbox: &str, message_id: &str) -> Result<String, CheckError> {
    let auth = flow
        .request
        .as_ref()
        .and_then(|r| r.headers().get(http::header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let token = if auth.len() >= 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
        auth[7..].trim().to_owned()
    } else {
        String::new()
    };
    let key = super::record::agentmail_key(&e.creds, flow.vm_id.as_deref(), &token).unwrap_or(token);
    if key.is_empty() {
        return Err(CheckError::Failed("a forward with no key".into()));
    }
    let url = format!(
        "{}/v0/inboxes/{}/messages/{}",
        e.agentmail_base,
        quote(inbox, "@"),
        quote(message_id, "")
    );
    let failed = |what: &str| CheckError::Failed(format!("the forwarded mail could not be read ({what})"));
    let mut resp = e
        .http
        .get(url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| failed("unreachable"))?;
    if !resp.status().is_success() {
        return Err(failed("HTTPError"));
    }
    // `res.read(MAX + 1)`: no more than a chunk past the limit is read.
    let mut raw = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| failed("read"))? {
        raw.extend_from_slice(&chunk);
        if raw.len() > AGENTMAIL_FORWARD_READ_MAX {
            return Err(TooLong(raw.len()).into());
        }
    }
    match std::str::from_utf8(&raw)
        .map_err(|_| ())
        .and_then(|t| super::json::loads(t).map_err(|_| ()))
    {
        Ok(doc @ Value::Object(_)) => Ok(agentmail_text(&doc)),
        _ => Err(failed("ValueError")),
    }
}

/// `urllib.parse.quote(s, safe=...)`: everything but letters, digits, `_.-~` and `safe` escaped.
fn quote(s: &str, safe: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "_.-~".contains(c) || safe.contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---- content rules in: AgentMail ----------------------------------------------------------------

/// The content rules could not judge an item: answered "try again", never hidden for good.
#[derive(Debug)]
struct Unavailable;

/// `_agentmail_blocked`'s `blocked(item)`.
async fn agentmail_blocked(
    e: &Email,
    flow: Option<&mut Flow>,
    rules: &[Rule],
    item: &Value,
) -> Result<bool, Unavailable> {
    if !engine::applies(rules, "in", "email") {
        return Ok(false);
    }
    let id = item
        .get("message_id")
        .filter(|v| admission::truthy(Some(v)))
        .or_else(|| item.get("thread_id").filter(|v| admission::truthy(Some(v))));
    let once = id.map(py_str).map(|s| engine::cut(&s, 200)).filter(|s| !s.is_empty());
    let text = agentmail_text(item);
    let mut flow = flow;
    let rule = if text.is_empty() {
        None
    } else {
        match e
            .content
            .acting(flow.as_deref_mut(), rules, "in", "email", &text, once.as_deref())
            .await
        {
            Ok(r) => r,
            Err(CheckError::TooLong(_)) => Some(error_rule()),
            Err(_) => return Err(Unavailable),
        }
    };
    let Some(rule) = rule else { return Ok(false) };
    if rule.by.as_deref() == Some("failed") {
        e.content
            .audit(flow, &rule.id, "email", "in", "wait", once.as_deref(), Map::new());
        return Err(Unavailable);
    }
    e.content
        .audit(flow, &rule.id, "email", "in", "block", once.as_deref(), Map::new());
    Ok(true)
}

fn error_rule() -> Rule {
    Rule {
        id: "error".into(),
        name: None,
        direction: "in".into(),
        channels: vec![],
        patterns: vec![],
        detectors: vec![],
        policy: None,
        action: engine::Action::Block,
        reason: String::new(),
        by: None,
    }
}

/// `agentmail_filter` with the admission service and the content rules: the document as the agent
/// may see it.
async fn agentmail_filter(
    e: &Email,
    mut flow: Option<&mut Flow>,
    rules: &[Rule],
    mut doc: Value,
) -> Result<Value, Unavailable> {
    let targets = admission::targets(&doc);
    if targets.is_empty() {
        return Ok(doc);
    }
    let items: Vec<(String, Value)> = targets.iter().map(|t| (t.inbox.clone(), t.item.clone())).collect();
    let actions = admission::decide(&e.admission_url, &items).await;
    let mut verdicts = Vec::new();
    for (t, a) in targets.iter().zip(&actions) {
        let mut v = admission::action_of(a);
        if v != "hide" {
            let original = admission::get_at(&doc, &t.at).cloned().unwrap_or(Value::Null);
            if agentmail_blocked(e, flow.as_deref_mut(), rules, &original).await? {
                v = "hide".into();
            }
        }
        verdicts.push((t.at.clone(), v));
    }
    admission::apply_verdicts(&mut doc, &verdicts);
    Ok(doc)
}

/// The rules a write read before it went, if it did.
fn rules_read_before(flow: &Flow) -> Option<Vec<Rule>> {
    let v = flow.meta.get(META_RULES)?;
    serde_json::from_value(v.clone()).ok()
}

pub struct AgentMailResponse(pub Arc<Email>);

impl Step for AgentMailResponse {
    fn name(&self) -> &'static str {
        "agentmail-response"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// A JSON answer of AgentMail's API that went through: what it shows the agent is filtered.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        host(flow) == AGENTMAIL_API
            && flow.response.as_ref().is_some_and(|r| {
                r.status().is_success() && body::content_type(r.headers()).to_lowercase().contains("json")
            })
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            agentmail_response(&self.0, flow).await;
            Verdict::Continue
        })
    }
}

fn replace_response(flow: &mut Flow, status: u16, body: &str) {
    flow.response = Some(raw_response(status, body.as_bytes().to_vec(), "application/json"));
}

/// `agentmail_response`: what an AgentMail API answer shows the agent.
async fn agentmail_response(e: &Email, flow: &mut Flow) {
    let Some(resp) = flow.response.as_ref() else { return };
    if host(flow) != AGENTMAIL_API
        || !resp.status().is_success()
        || !body::content_type(resp.headers()).to_lowercase().contains("json")
    {
        return;
    }
    let raw = if resp.body().is_empty() {
        bytes::Bytes::from_static(b"null")
    } else {
        resp.body().clone()
    };
    let ready = super::body_ready(flow);
    let Some(doc) = std::str::from_utf8(&raw)
        .ok()
        .filter(|_| ready)
        .and_then(|t| super::json::loads(t).ok())
    else {
        replace_response(flow, 502, r#"{"error":"unreadable_response"}"#);
        return;
    };
    let wrote = rules_read_before(flow);
    let rules = match &wrote {
        Some(r) => Arc::new(r.clone()),
        None => match e.content.rules() {
            Ok(r) => r,
            // Asked again in a moment, once the rules are known: hiding would be for good.
            Err(_) => return replace_response(flow, 503, RULES_LOADING),
        },
    };
    match agentmail_filter(e, Some(flow), &rules, doc.clone()).await {
        Ok(filtered) => {
            if let Some(r) = flow.response.as_mut() {
                set_body(r, pyjson::dumps(&filtered).into_bytes());
            }
        }
        Err(Unavailable) if wrote.is_some() => {
            // A write that already went: its ids, and nothing it carried back, rather than "try again".
            e.content
                .audit(Some(flow), "error", "email", "in", "block", None, Map::new());
            let kept: Map<String, Value> = ["message_id", "thread_id", "draft_id", "inbox_id"]
                .iter()
                .filter_map(|k| {
                    doc.get(*k)
                        .filter(|v| v.is_string())
                        .map(|v| ((*k).to_owned(), v.clone()))
                })
                .collect();
            if let Some(r) = flow.response.as_mut() {
                set_body(r, pyjson::dumps(&kept).into_bytes());
            }
        }
        Err(Unavailable) => {
            e.content
                .audit(Some(flow), "error", "email", "in", "wait", None, Map::new());
            replace_response(
                flow,
                503,
                r#"{"error":"check_failed","message":"The firewall could not check this mail. Try again."}"#,
            );
        }
    }
}

/// `agentmail_ws_message`: a received-mail event over AgentMail's websocket reaches the agent only
/// if the rules keep it.
pub struct AgentMailSocket(pub Arc<Email>);

impl Step for AgentMailSocket {
    fn name(&self) -> &'static str {
        "agentmail-socket"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::WsFrame]
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if host(flow) != AGENTMAIL_WS {
                return Verdict::Continue;
            }
            let Some(frame) = flow.ws_frame.as_ref() else {
                return Verdict::Continue;
            };
            if frame.direction == Direction::Out {
                return Verdict::Continue;
            }
            let payload = frame.payload.clone();
            if ws_keep(&self.0, &payload).await {
                Verdict::Continue
            } else {
                Verdict::Drop
            }
        })
    }
}

/// `_agentmail_ws_decide` for a frame from the server.
async fn ws_keep(e: &Email, payload: &[u8]) -> bool {
    let Ok(event) = std::str::from_utf8(payload)
        .map_err(|_| ())
        .and_then(|t| super::json::loads(t).map_err(|_| ()))
    else {
        return false;
    };
    if !event.is_object() || event.get("type") != Some(&json!("event")) {
        return true;
    }
    let kind = ["event_type", "eventType"]
        .iter()
        .filter_map(|k| event.get(*k))
        .find(|v| admission::truthy(Some(v)))
        .map(py_str)
        .unwrap_or_default();
    if !kind.starts_with("message.received") {
        return true;
    }
    let msg = event.get("message").cloned().unwrap_or(Value::Null);
    if kind != "message.received" || !admission::is_message(&msg) {
        return false;
    }
    let mut item = Map::new();
    item.insert("kind".into(), json!("message"));
    if let Some(o) = msg.as_object() {
        item.extend(o.clone());
    }
    let inbox = msg
        .get("inbox_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let acts = admission::decide(&e.admission_url, &[(inbox, Value::Object(item))]).await;
    if acts.first().map(admission::action_of).as_deref() != Some("keep") {
        return false;
    }
    // While the rules are not known yet (a firewall starting), wait for them.
    let Ok(rules) = e.content.file.rules_wait(Duration::from_secs(15)).await else {
        return false;
    };
    matches!(agentmail_blocked(e, None, &rules, &msg).await, Ok(false))
}

// ---- content rules in: Gmail --------------------------------------------------------------------

fn gmail_not_found() -> String {
    pyjson::dumps(&json!({"error": {"code": 404, "message": "Requested entity was not found.", "status": "NOT_FOUND"}}))
}

/// `_gmail_message_text`.
pub fn gmail_message_text(m: &Value) -> Result<String, CheckError> {
    let mut out = vec![m.get("snippet").and_then(Value::as_str).unwrap_or("").to_owned()];
    if let Some(raw) = m
        .get("raw")
        .filter(|r| !r.is_null())
        .and_then(mime::b64url)
        .filter(|r| !r.is_empty())
    {
        // A message the reader cannot follow is not shown to the agent.
        out.push(mime::mime_text(&raw).ok_or_else(|| CheckError::Failed("a message the firewall cannot read".into()))?);
    }
    walk_gmail(m.get("payload"), 0, &mut out)?;
    Ok(out.into_iter().filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n"))
}

/// `part.get(k) or []` iterated: a list, nothing, or (anything else truthy) an error.
fn list_of(v: Option<&Value>) -> Result<Vec<Value>, CheckError> {
    match v {
        Some(Value::Array(a)) => Ok(a.clone()),
        // A string or an object iterates over characters or keys: none of them is a dict.
        Some(Value::String(_) | Value::Object(_)) => Ok(Vec::new()),
        v if !admission::truthy(v) => Ok(Vec::new()),
        _ => Err(CheckError::Failed("not a list".into())),
    }
}

fn walk_gmail(part: Option<&Value>, depth: usize, out: &mut Vec<String>) -> Result<(), CheckError> {
    let Some(p) = part.filter(|p| p.is_object()) else {
        return Ok(());
    };
    if depth > 30 {
        return Ok(());
    }
    for h in list_of(p.get("headers"))? {
        let name = h.get("name").map(py_str).unwrap_or_default();
        if h.is_object()
            && name.to_lowercase() == "subject"
            && let Some(v) = h.get("value").and_then(Value::as_str)
        {
            out.push(v.to_owned());
        }
    }
    let mime_type = p
        .get("mimeType")
        .filter(|v| admission::truthy(Some(v)))
        .map(py_str)
        .unwrap_or_default();
    let data = p.get("body").filter(|b| b.is_object()).and_then(|b| b.get("data"));
    if (mime_type == "text/plain" || mime_type == "text/html")
        && !admission::truthy(p.get("filename"))
        && admission::truthy(data)
    {
        let decoded = String::from_utf8_lossy(&data.and_then(mime::b64url).unwrap_or_default()).into_owned();
        out.push(if mime_type == "text/html" {
            mime::html_text(&decoded)
        } else {
            decoded
        });
    }
    for child in list_of(p.get("parts"))? {
        walk_gmail(Some(&child), depth + 1, out)?;
    }
    Ok(())
}

pub struct GmailIn(pub Arc<Email>);

impl Step for GmailIn {
    fn name(&self) -> &'static str {
        "gmail-in"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// A Gmail read that went through (`messages.get`, `threads.get`).
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        is_googleapis(&host(flow))
            && method(flow) == "GET"
            && flow.response.as_ref().is_some_and(|r| r.status() == 200)
            && GM_READ.is_match(&admission::google_path(&path(flow)))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            gmail_in(&self.0, flow).await;
            Verdict::Continue
        })
    }
}

/// `content_rules_gmail_in`: a blocked message is not found, or left out of its thread.
async fn gmail_in(e: &Email, flow: &mut Flow) {
    if !is_googleapis(&host(flow)) || method(flow) != "GET" || flow.response.as_ref().is_none_or(|r| r.status() != 200)
    {
        return;
    }
    let gp = admission::google_path(&path(flow));
    let Some(kind) = GM_READ.captures(&gp).map(|c| c[1].to_owned()) else {
        return;
    };
    let rules = match e.content.rules() {
        Ok(r) if !engine::applies(&r, "in", "email") => return,
        Ok(r) => r,
        Err(_) => {
            let b = pyjson::dumps(
                &json!({"error": {"code": 503, "message": "The firewall is loading its rules. Try again in a few seconds.", "status": "UNAVAILABLE"}}),
            );
            return replace_response(flow, 503, &b);
        }
    };
    match gmail_check(e, flow, &kind, &rules).await {
        Ok(()) => {}
        Err(GmailError::Unavailable) => {
            let b = pyjson::dumps(
                &json!({"error": {"code": 503, "message": "The firewall could not check this mail just now. Try again later.", "status": "UNAVAILABLE"}}),
            );
            replace_response(flow, 503, &b);
        }
        Err(GmailError::Failed(why)) => {
            tracing::warn!("[content-rules] incoming Gmail check failed, holding it back: {why}");
            e.content
                .audit(Some(flow), "error", "email", "in", "block", None, Map::new());
            replace_response(flow, 404, &gmail_not_found());
        }
    }
}

enum GmailError {
    Unavailable,
    Failed(String),
}

async fn gmail_blocked(e: &Email, flow: &mut Flow, rules: &[Rule], msg: &Value) -> Result<bool, GmailError> {
    if !msg.is_object() {
        return Ok(false);
    }
    let once = msg
        .get("id")
        .filter(|v| admission::truthy(Some(v)))
        .map(py_str)
        .map(|s| engine::cut(&s, 200))
        .filter(|s| !s.is_empty());
    // Base64 and MIME over up to about 37 MB: on the blocking pool.
    let owned = msg.clone();
    let text = engine::off_workers(move || gmail_message_text(&owned))
        .await
        .map_err(|e| GmailError::Failed(e.to_string()))?;
    let rule = match e
        .content
        .acting(Some(flow), rules, "in", "email", &text, once.as_deref())
        .await
    {
        Ok(r) => r,
        Err(CheckError::TooLong(_)) => Some(error_rule()),
        Err(err) => return Err(GmailError::Failed(err.to_string())),
    };
    let Some(rule) = rule else { return Ok(false) };
    if rule.by.as_deref() == Some("failed") {
        e.content
            .audit(Some(flow), &rule.id, "email", "in", "wait", once.as_deref(), Map::new());
        return Err(GmailError::Unavailable);
    }
    e.content.audit(
        Some(flow),
        &rule.id,
        "email",
        "in",
        "block",
        once.as_deref(),
        Map::new(),
    );
    Ok(true)
}

async fn gmail_check(e: &Email, flow: &mut Flow, kind: &str, rules: &[Rule]) -> Result<(), GmailError> {
    let raw = flow.response.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    let doc = match std::str::from_utf8(&raw)
        .ok()
        .filter(|_| super::body_ready(flow))
        .map(super::json::loads)
    {
        Some(Ok(d @ Value::Object(_))) => d,
        _ => return Err(GmailError::Failed("not a Gmail answer".into())),
    };
    if kind == "messages" {
        if gmail_blocked(e, flow, rules, &doc).await? {
            replace_response(flow, 404, &gmail_not_found());
        }
        return Ok(());
    }
    let messages = doc
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut kept = Vec::new();
    for m in &messages {
        if !gmail_blocked(e, flow, rules, m).await? {
            kept.push(m.clone());
        }
    }
    if kept.len() == messages.len() {
        return Ok(());
    }
    if kept.is_empty() {
        replace_response(flow, 404, &gmail_not_found());
        return Ok(());
    }
    let mut out = doc;
    out["messages"] = Value::Array(kept);
    if let Some(r) = flow.response.as_mut() {
        set_body(r, pyjson::dumps(&out).into_bytes());
    }
    Ok(())
}

// ---- settle -------------------------------------------------------------------------------------

/// `email_settle`: after the mail service answered, the reservation is settled (a refused send
/// gives its slot back). Not waited for: an unsettled one counts after ten minutes anyway.
pub struct EmailSettle(pub Arc<Email>);

impl Step for EmailSettle {
    fn name(&self) -> &'static str {
        "email-settle"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// Only the status is read.
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            let Some(id) = flow
                .meta
                .get(META_RESERVATION)
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                return Verdict::Continue;
            };
            let rejected = flow
                .response
                .as_ref()
                .is_some_and(|r| (400..500).contains(&r.status().as_u16()));
            let url = self.0.admission_url.clone();
            tokio::spawn(async move {
                let _ = admission::admission(
                    &url,
                    &json!({"action": "email.settle", "id": id, "rejected": rejected}),
                    Duration::from_secs(5),
                )
                .await;
            });
            Verdict::Continue
        })
    }
}

#[cfg(test)]
mod tests;
