//! Content rules on the web (appendix F feature 22, addon.py 6505-6605): the body of every other
//! request the host rules let through. Not the model providers (a rule there would stop the
//! agent's every later turn), the control plane, Twilio, or the channels with adapters of their
//! own. A website's answer cannot be made up, so a hold stops the request.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::content::engine::TEXT_MAX_LONG;
use super::content::engine::{self, Action, Rule};
use super::content::{CheckError, Content};
use super::telegram::{detail, is_telegram_flow, texts};
use super::{body, check_host, email, json as cjson, record, slack};
use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};

const MODEL_HOSTS: &[&str] = &[
    "ai-gateway.vercel.sh",
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "openrouter.ai",
    "api.x.ai",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.moonshot.ai",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.cerebras.ai",
    "api.perplexity.ai",
];
/// Bytes of a text body the web check parses: twice what it reads (quotes, keys and escapes take
/// room). More is stopped before it is parsed.
pub const WEB_BODY_READ_MAX: usize = 2 * TEXT_MAX_LONG;
const BLOCK_STATUS: u16 = 403;

pub struct Web {
    pub content: Arc<Content>,
    pub control_plane_host: Option<String>,
    pub creds: Arc<super::creds::Creds>,
}

pub fn register(pipeline: &mut Pipeline, web: Arc<Web>) {
    pipeline.push(order::WEB_CONTENT_RULES, Arc::new(WebStep(web)));
}

/// `_is_gmail_api_path`: the Gmail API, by its path alone (never the query).
fn is_gmail_api_path(raw: &str) -> bool {
    let p = email::admission::google_path(raw);
    p.starts_with("/gmail/") || p.starts_with("/upload/gmail/")
}

/// `_own_channel_flow`: a service the firewall reads its own way.
pub fn own_channel(w: &Web, flow: &Flow) -> bool {
    let h = check_host(flow);
    if is_telegram_flow(flow)
        || slack::is_slack_out_flow(flow)
        || [
            email::admission::AGENTMAIL_API,
            email::admission::AGENTMAIL_WS,
            "api.twilio.com",
        ]
        .contains(&h.as_str())
    {
        return true;
    }
    let p = flow
        .request
        .as_ref()
        .map(|r| r.uri().path().to_owned())
        .unwrap_or_default();
    if email::admission::is_googleapis(&h) && is_gmail_api_path(&p) {
        return true;
    }
    if w.control_plane_host
        .as_deref()
        .is_some_and(|cp| record::host_matches(cp, &h))
    {
        return true;
    }
    MODEL_HOSTS.contains(&h.as_str()) || record::model_credential(&w.creds, flow.vm_id.as_deref(), &h)
}

/// `_web_flow`.
fn is_web_flow(w: &Web, flow: &Flow) -> bool {
    let Some(r) = flow.request.as_ref() else { return false };
    // By the head: a body streamed past the checks is not in the flow (#625), and is refused below.
    if matches!(r.method().as_str().to_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
        || !super::request_has_body(flow)
    {
        return false;
    }
    !own_channel(w, flow)
}

/// A file `web_text` would not read: a type that is not text (nor a form, nor unsaid) and a length,
/// said in the head, past what a check reads. Its body need not be held for this check.
fn large_file(flow: &Flow) -> bool {
    let Some(r) = flow.request.as_ref() else { return false };
    let ct_raw = body::content_type(r.headers());
    let media = body::header_params(&ct_raw).map_or_else(
        |_| ct_raw.split(';').next().unwrap_or("").trim().to_lowercase(),
        |(m, _)| m,
    );
    let textual = media.starts_with("text/")
        || ["json", "xml", "javascript", "graphql", "x-www-form-urlencoded"]
            .iter()
            .any(|t| media.contains(t));
    let length = r
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok());
    !ct_raw.is_empty() && !textual && media != "multipart/form-data" && length.is_some_and(|n| n > WEB_BODY_READ_MAX)
}

/// `_web_text`: the words in a request body (string values of JSON, form values, text parts, plain
/// text); `None` when it is not text.
pub fn web_text(flow: &Flow) -> Result<Option<String>, CheckError> {
    let Some(r) = flow.request.as_ref() else {
        return Ok(None);
    };
    let ct_raw = body::content_type(r.headers());
    let (media, params) = body::header_params(&ct_raw).unwrap_or_else(|_| {
        let head = ct_raw.split(';').next().unwrap_or("");
        (head.trim_matches(body::is_py_space).to_lowercase(), Vec::new())
    });
    let raw = r.body();
    let textual = media.starts_with("text/")
        || ["json", "xml", "javascript", "graphql", "x-www-form-urlencoded"]
            .iter()
            .any(|t| media.contains(t));
    // The size before any parsing: more text than a check reads is stopped without reading it.
    // A body that says nothing of its type is read as text, as below.
    if (textual || ct_raw.is_empty()) && raw.len() > WEB_BODY_READ_MAX {
        return Err(engine::TooLong(raw.len()).into());
    }
    if media == "multipart/form-data" {
        // Read strictly (a body a lenient reader half reads is refused); a part that is not UTF-8
        // is a file, not read.
        let parts = body::multipart_fields(body::param(&params, "boundary"), raw)
            .map_err(|e| CheckError::Failed(e.to_string()))?;
        let out: Vec<String> = parts
            .into_iter()
            .filter_map(|(_, v)| String::from_utf8(v).ok())
            .collect();
        return Ok(Some(out.join("\n")));
    }
    if raw.len() > WEB_BODY_READ_MAX {
        return Ok(None); // a file, not read
    }
    if media == "application/x-www-form-urlencoded" {
        return Ok(Some(
            body::parse_qsl(&String::from_utf8_lossy(raw))
                .into_iter()
                .map(|(_, v)| v)
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t.to_owned(),
        Err(_) if !textual => return Ok(None),               // binary
        Err(_) => String::from_utf8_lossy(raw).into_owned(), // another charset: its ASCII words still read
    };
    let starts_json = text.trim_start_matches(body::is_py_space).starts_with(['{', '[']);
    if media.contains("json") || starts_json {
        // `json.loads` without the duplicate check (the last copy wins), numbers as written.
        if let Ok(doc) = cjson::loads_raw_numbers(&text).map_err(|_| ())
            && !doc.is_null()
        {
            let mut out = Vec::new();
            if texts(&doc, true, &mut out, 0, &[]).is_err() {
                // Deeper than the walk goes, or a repeated key in JSON in a string: every string
                // in it, escapes undone, rather than none.
                return Ok(Some(cjson::unescape_loose(&text)));
            }
            return Ok(Some(out.join("\n")));
        }
    }
    if !ct_raw.is_empty() && !textual {
        return Ok(None);
    }
    Ok(Some(text))
}

fn refuse(flow: &mut Flow, rule: Option<&Rule>, extra: &str, reason: Option<&str>) -> Verdict {
    let why = rule.map_or(reason.unwrap_or("the check could not run"), |r| r.reason.as_str());
    let host = flow.claimed_host().unwrap_or_else(|| check_host(flow));
    let body = json!({"error": "blocked_by_content_rule", "host": host, "message": format!("Blocked by your organization's rules: {why}{extra}")});
    let label = rule.map_or_else(|| "content: error".to_owned(), |r| format!("content: {}", r.id));
    super::answer(flow, BLOCK_STATUS, &body, "block", &label, Map::new())
}

pub struct WebStep(pub Arc<Web>);

impl Step for WebStep {
    fn name(&self) -> &'static str {
        "web-content"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// Any other site's request body while a web rule may read it; not a file too large to read.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        // Unknown rules read it (the check then refuses as it would); known ones only with a web rule.
        is_web_flow(&self.0, flow)
            && super::request_has_body(flow)
            && !large_file(flow)
            && match self.0.content.rules() {
                Ok(r) => engine::applies(&r, "out", "web"),
                Err(_) => true,
            }
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            // A tool call the MCP check already read under the Integrations channel is not read twice.
            if flow
                .meta
                .get(super::META_MCP_CHECKED)
                .is_some_and(|v| v == &Value::Bool(true))
                || !is_web_flow(&self.0, flow)
            {
                return Verdict::Continue;
            }
            let content = &self.0.content;
            match check(content, flow).await {
                Ok(v) => v.unwrap_or(Verdict::Continue),
                Err(CheckError::TooLong(_)) => {
                    let v = refuse(flow, None, "", Some("it is too long to check"));
                    content.audit(Some(flow), "error", "web", "out", "block", None, detail("too long"));
                    v
                }
                Err(e) => {
                    tracing::warn!("[content-rules] web check failed, refusing: {e}");
                    let v = refuse(flow, None, "", None);
                    content.audit(Some(flow), "error", "web", "out", "block", None, Map::new());
                    v
                }
            }
        })
    }
}

async fn check(content: &Content, flow: &mut Flow) -> Result<Option<Verdict>, CheckError> {
    let rules = content.rules()?;
    if !engine::applies(&rules, "out", "web") {
        return Ok(None);
    }
    // A file too large to read is not read (`web_text`), held or not.
    if large_file(flow) {
        return Ok(None);
    }
    // A body the plumbing has not decoded is refused, never passed unread.
    if super::request_body_unread(flow) {
        return Err(CheckError::Failed("a body the firewall cannot read".into()));
    }
    let Some(text) = web_text(flow)?.filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let Some(rule) = content.acting(Some(flow), &rules, "out", "web", &text, None).await? else {
        return Ok(None);
    };
    let held = rule.action == Action::Hold;
    let v = refuse(
        flow,
        Some(&rule),
        if held {
            " (a request to a website cannot be held for approval)"
        } else {
            ""
        },
        None,
    );
    let mut x = Map::new();
    if held {
        x.insert("held".into(), json!(false));
    }
    content.audit(Some(flow), &rule.id, "web", "out", "block", None, x);
    Ok(Some(v))
}

#[cfg(test)]
mod tests;
