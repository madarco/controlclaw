//! Telegram (addon.py 2247-2290, 4906-4990, 5440-5760): the content rules on what an agent sends
//! (`sendMessage` and every other call that is not a read) and on what it is sent (`getUpdates`),
//! the refusal of a poll while the rules are unknown, and the confirmation-code button taps that
//! are taken out of `getUpdates` and handed to the firewall agent.
//!
//! The flow is Telegram by its checked destination: the name (in any form IDNA folds into
//! `api.telegram.org`) or, for the Bot API's paths only, Telegram's own address ranges.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::content::engine::{self, Action, Rule};
use super::content::{CheckError, Content, HOLD_BODY_MAX, HOLD_TEXT_MAX};
use super::json::{JsonError, loads_strict_raw_numbers, number_text, unescape_loose};
use super::{body, pyjson, set_body};
use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};

pub const TAP_PREFIX: &str = "cc1:";

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

static GET_UPDATES_RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^/bot(\d+):[^/]+/getUpdates$"));
static METHOD_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^/bot(\d+):[^/]+/([A-Za-z]+)$"));
static FILE_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^/file/bot\d+:[^/]+/[A-Za-z0-9_./-]+$"));
static BOT_API_PATH: LazyLock<Regex> = LazyLock::new(|| re(r"^/(?:file/)?bot\d+:"));

/// The methods a held message can be sent with later (content-rules.ts holds the same list).
const HOLDABLE: &[&str] = &[
    "sendMessage",
    "editMessageText",
    "editMessageCaption",
    "sendPhoto",
    "sendDocument",
    "sendVideo",
    "sendAudio",
    "sendAnimation",
    "sendVoice",
    "sendMediaGroup",
];
/// Every field that carries words someone reads, wherever it sits.
const TEXT_KEYS: &[&str] = &[
    "text",
    "caption",
    "question",
    "explanation",
    "title",
    "description",
    "short_description",
    "address",
    "first_name",
    "last_name",
    "name",
    "message_text",
    "vcard",
    "quote",
    "label",
    "options",
];
/// Who sent a message and where, never its words (`_TG_IN_SKIP`): a name is not checked, or every
/// message from a person whose name holds a blocked word would be stopped.
const IN_SKIP: &[&str] = &[
    "from",
    "chat",
    "sender_chat",
    "sender_business_bot",
    "via_bot",
    "forward_from",
    "forward_from_chat",
    "forward_origin",
    "origin",
    "user",
    "new_chat_members",
    "left_chat_member",
    "users",
    "chats",
    "old_chat_member",
    "new_chat_member",
    "actor_chat",
    "entities",
    "caption_entities",
    // Not in the addon's list, which reads these names (a difference on purpose): a poll's voter,
    // giveaway winners, a proximity alert's people, a checklist's ticker, a shared chat or user.
    "voter_chat",
    "winners",
    "traveler",
    "watcher",
    "completed_by_user",
    "chat_shared",
    "users_shared",
];
/// Where the agent's own message can sit on an update (`_TG_IN_OWN_KEYS`): checked when it went
/// out, not read again coming in.
const IN_OWN_KEYS: &[&str] = &["reply_to_message", "pinned_message", "external_reply", "message"];

/// `_TG_IN_KEYS`: the outgoing fields, an inline query, a join request's bio.
fn in_key(k: &str) -> bool {
    TEXT_KEYS.contains(&k) || k == "query" || k == "bio"
}

/// Telegram's published address ranges (core.telegram.org/resources/cidr.txt, 2026-10-15).
const NETWORKS: &[&str] = &[
    "91.108.56.0/22",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.16.0/22",
    "91.108.12.0/22",
    "149.154.160.0/20",
    "91.105.192.0/23",
    "91.108.20.0/22",
    "185.76.151.0/24",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2001:67c:4e8::/48",
    "2001:b28:f23c::/48",
    "2a0a:f280::/32",
];

/// `api.telegram.org`, written any way that still reaches it: any case, the root's trailing dot,
/// or dots and letters IDNA folds into those.
pub fn is_telegram_host(host: Option<&str>) -> bool {
    let h = host.unwrap_or("").to_lowercase();
    let h = if h.is_ascii() {
        h
    } else {
        match idna_ascii(&h) {
            Some(a) => a,
            None => return false,
        }
    };
    h.trim_end_matches('.') == "api.telegram.org"
}

/// `host.encode("idna")`, near enough: UTS 46 through the `url` crate.
pub fn idna_ascii(host: &str) -> Option<String> {
    match url::Host::parse(host).ok()? {
        url::Host::Domain(d) => Some(d),
        _ => None,
    }
}

static PARSED: LazyLock<Vec<(IpAddr, u32)>> = LazyLock::new(|| {
    NETWORKS
        .iter()
        .filter_map(|n| {
            let (base, bits) = n.split_once('/')?;
            Some((base.parse().ok()?, bits.parse().ok()?))
        })
        .collect()
});

pub fn is_telegram_ip(addr: IpAddr) -> bool {
    let addr = match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    PARSED.iter().any(|(base, bits)| in_network(addr, *base, *bits))
}

fn in_network(addr: IpAddr, base: IpAddr, bits: u32) -> bool {
    match (addr, base) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Whether this request goes to Telegram: by its checked name, or by its checked address for the
/// Bot API's paths (the same addresses serve t.me and telegram.org, which are web pages).
pub fn is_telegram_flow(flow: &Flow) -> bool {
    // No checked destination (the plumbing sets one before the checks run): the name the request
    // claims is used instead, which can only add checks, never skip one.
    let Some(d) = flow.destination() else {
        return is_telegram_host(flow.claimed_host().as_deref());
    };
    if is_telegram_host(Some(&d.name)) {
        return true;
    }
    // An address not resolved yet (only the dial resolves it) could still be Telegram's, so a Bot
    // API path to it is checked: that can only add checks, never skip one.
    let by_address =
        d.name.parse::<IpAddr>().is_ok_and(is_telegram_ip) || d.addr.is_none_or(|a| is_telegram_ip(a.ip()));
    by_address && BOT_API_PATH.is_match(path(flow))
}

fn path(flow: &Flow) -> &str {
    flow.request.as_ref().map_or("", |r| r.uri().path())
}

/// Register the Telegram steps.
pub fn register(pipeline: &mut Pipeline, content: Arc<Content>, buttons_url: String) {
    pipeline.push(
        order::TELEGRAM,
        Arc::new(TelegramOut {
            content: content.clone(),
        }),
    );
    pipeline.push(
        order::RESPONSE_TELEGRAM_TAPS,
        Arc::new(TelegramTaps { url: buttons_url }),
    );
    pipeline.push(order::RESPONSE_TELEGRAM_IN, Arc::new(TelegramIn { content }));
}

// ---- out ----------------------------------------------------------------------------------------

pub struct TelegramOut {
    pub content: Arc<Content>,
}

impl Step for TelegramOut {
    fn name(&self) -> &'static str {
        "telegram-out"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// Telegram's Bot API (by name, or by address on its paths).
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        is_telegram_flow(flow) && super::request_has_body(flow)
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !is_telegram_flow(flow) {
                return Verdict::Continue;
            }
            if let Some(v) = poll(&self.content, flow) {
                return v;
            }
            out(&self.content, flow).await.unwrap_or(Verdict::Continue)
        })
    }
}

/// `content_rules_telegram_poll`: a `getUpdates` while the rules are unknown is refused before
/// Telegram is asked, with Telegram's own "retry after". Telegram keeps the messages.
fn poll(content: &Content, flow: &mut Flow) -> Option<Verdict> {
    if !GET_UPDATES_RE.is_match(path(flow)) || content.rules().is_ok() {
        return None;
    }
    let body = json!({"ok": false, "error_code": 429, "description": "Too Many Requests: retry after 5 (the firewall is loading its rules)", "parameters": {"retry_after": 5}});
    let v = super::answer(flow, 429, &body, "block", "content: rules unknown", Map::new());
    content.audit(
        Some(flow),
        "error",
        "telegram",
        "in",
        "wait",
        None,
        detail("rules unknown"),
    );
    Some(v)
}

pub fn detail(d: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("detail".into(), json!(d));
    m
}

fn refuse(flow: &mut Flow, rule: Option<&Rule>, extra: &str, reason: Option<&str>) -> Verdict {
    let reason = rule.map_or(reason.unwrap_or("the check could not run"), |r| r.reason.as_str());
    let body = json!({"ok": false, "error_code": 400, "description": format!("Bad Request: blocked by your organization's rules: {reason}{extra}")});
    let label = rule.map_or_else(|| "content: error".to_owned(), |r| format!("content: {}", r.id));
    super::answer(flow, 400, &body, "block", &label, Map::new())
}

/// `content_rules_telegram_out`: `Some` when the call was answered here (blocked or held).
async fn out(content: &Content, flow: &mut Flow) -> Option<Verdict> {
    let p = path(flow).to_owned();
    let Some(caps) = METHOD_RE.captures(&p) else {
        // A file download is a read. Anything else the pattern does not take still reaches
        // Telegram with the real token after the swap, so it is refused rather than passed.
        let method = flow.request.as_ref().map(|r| r.method().clone());
        if FILE_RE.is_match(&p) && matches!(method, Some(http::Method::GET | http::Method::HEAD)) {
            return None;
        }
        let v = refuse(flow, None, "", Some("this Telegram call could not be checked"));
        content.audit(
            Some(flow),
            "error",
            "telegram",
            "out",
            "block",
            None,
            detail("unmatched path"),
        );
        return Some(v);
    };
    let bot_id = caps[1].to_owned();
    let method = caps[2].to_owned();
    // Every method that is not a read: text can ride on a poll, a contact, a description, a GET.
    if method.to_lowercase().starts_with("get") {
        return None;
    }
    // A body the check cannot read as Telegram will (compressed, or not yet decoded by the
    // plumbing) is refused, never passed unread.
    let encoding = flow
        .request
        .as_ref()
        .and_then(|r| r.headers().get(http::header::CONTENT_ENCODING))
        .map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_lowercase())
        .unwrap_or_default();
    if !(encoding.is_empty() || encoding == "identity") || super::request_body_unread(flow) {
        let v = refuse(flow, None, "", Some("this Telegram call could not be checked"));
        content.audit(
            Some(flow),
            "error",
            "telegram",
            "out",
            "block",
            None,
            detail("encoded body"),
        );
        return Some(v);
    }
    match out_checked(content, flow, &bot_id, &method).await {
        Ok(v) => v,
        Err(CheckError::TooLong(_)) => {
            let v = refuse(flow, None, "", Some("it is too long to check"));
            content.audit(
                Some(flow),
                "error",
                "telegram",
                "out",
                "block",
                None,
                detail("too long"),
            );
            Some(v)
        }
        Err(e) => {
            tracing::warn!("[content-rules] outgoing Telegram check failed, refusing: {e}");
            let v = refuse(flow, None, "", None);
            content.audit(Some(flow), "error", "telegram", "out", "block", None, Map::new());
            Some(v)
        }
    }
}

async fn out_checked(
    content: &Content,
    flow: &mut Flow,
    bot_id: &str,
    method: &str,
) -> Result<Option<Verdict>, CheckError> {
    let (fields, is_json) = out_fields(flow)?;
    // A webhook takes the bot's messages past the firewall: no rule on what comes in, no taps.
    if method.eq_ignore_ascii_case("setWebhook")
        && fields
            .iter()
            .any(|(k, v)| k == "url" && !py_str(v).trim_matches(body::is_py_space).is_empty())
    {
        // Deleting one (an empty url) is allowed.
        let v = refuse(
            flow,
            None,
            "",
            Some("a Telegram webhook would skip the firewall's checks"),
        );
        content.audit(Some(flow), "error", "telegram", "out", "block", None, detail("webhook"));
        return Ok(Some(v));
    }
    let text = tg_text(&fields)?;
    if text.is_empty() {
        return Ok(None);
    }
    let rules = content.rules()?;
    let vm_id = flow.vm_id.clone();
    let (found, text) = content.out_evaluate(&rules, "telegram", text, vm_id.as_deref()).await?;
    let Some(rule) = content.acted(Some(flow), found, "out", "telegram", &text, None) else {
        return Ok(None);
    };
    // A number kept as written goes back to a plain number: `json.dumps` writes `_JsonInt` and
    // `_JsonFloat` as numbers in the answer the agent gets.
    let chat_id = fields
        .iter()
        .find(|(k, _)| k == "chat_id")
        .map(|(_, v)| super::json::plain_number(v));
    let chat = chat_id.as_ref().filter(|c| !c.is_null()).map(py_str);
    let verdict = if rule.action == Action::Hold {
        let raw_len = flow.request.as_ref().map_or(0, |r| r.body().len());
        let detail_text = if is_json && HOLDABLE.contains(&method) && chat.is_some() && raw_len <= HOLD_BODY_MAX {
            let mut payload = Map::new();
            payload.insert("botId".into(), json!(bot_id));
            payload.insert("method".into(), json!(method));
            payload.insert("body".into(), json!(request_text(flow)));
            payload.insert("chatId".into(), json!(chat));
            payload.insert("vmId".into(), json!(vm_id));
            payload.insert("rule".into(), rule.brief());
            payload.insert("text".into(), json!(engine::cut(&text, HOLD_TEXT_MAX)));
            if let Some(super::content::Held { answer, key }) = content.hold(flow, key_first(payload)).await? {
                // The agent is told it went (decided 2026-10-15): the people who get codes decide.
                let first_text = fields
                    .iter()
                    .find(|(k, v)| k == "text" && v.is_string())
                    .map(|(_, v)| v.clone());
                // `int(answer.get("messageId") or 0) or 1`
                let raw_id = answer.get("messageId");
                let message_id = match py_int(raw_id) {
                    _ if is_falsy(raw_id) => 1,
                    Some(0) => 1,
                    Some(n) => n,
                    None => {
                        // The agent is told it was stopped, so the hold must not stay approvable.
                        content.cancel(&key).await;
                        return Err(CheckError::Failed("messageId is not a number".into()));
                    }
                };
                let mut message = Map::new();
                message.insert("message_id".into(), json!(message_id));
                message.insert("date".into(), json!(super::content::rules::now() as i64));
                message.insert("chat".into(), json!({"id": chat_id}));
                if let Some(t) = first_text {
                    message.insert("text".into(), t);
                }
                let hold_id = answer.get("holdId").cloned().unwrap_or(Value::Null);
                let body = json!({"ok": true, "result": message});
                return Ok(Some(content.held_answer(flow, &rule, "telegram", hold_id, 200, &body)));
            }
            " (nobody could be asked to approve it)"
        } else {
            " (it could not be held for approval)"
        };
        let v = refuse(flow, Some(&rule), detail_text, None);
        let mut extra = Map::new();
        extra.insert("held".into(), json!(false));
        content.audit(Some(flow), &rule.id, "telegram", "out", "block", None, extra);
        v
    } else {
        let v = refuse(flow, Some(&rule), "", None);
        content.audit(Some(flow), &rule.id, "telegram", "out", "block", None, Map::new());
        v
    };
    if let Some(chat) = chat {
        content.notice(json!({"kind": "out", "botId": bot_id, "chatId": chat, "vmId": vm_id, "reason": rule.reason}));
    }
    Ok(Some(verdict))
}

/// The hold's payload with `key` first, as the addon builds it (`{"key": key, ...}`); the key
/// itself is filled in by [`Content::hold`].
fn key_first(payload: Map<String, Value>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("key".into(), Value::Null);
    m.extend(payload);
    m
}

/// `int(x or 0)`: `None` when Python's `int()` would raise.
fn py_int(v: Option<&Value>) -> Option<i64> {
    match v {
        None | Some(Value::Null) => Some(0),
        Some(Value::Bool(b)) => Some(i64::from(*b)),
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Some(Value::String(s)) if s.is_empty() => Some(0),
        Some(Value::String(s)) => s.trim().replace('_', "").parse().ok(),
        Some(Value::Array(a)) if a.is_empty() => Some(0),
        Some(Value::Object(o)) if o.is_empty() => Some(0),
        Some(_) => None,
    }
}

fn is_falsy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => !b,
        Some(Value::Number(n)) => n.as_f64() == Some(0.0),
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
    }
}

/// Python's `str(value)` for what a chat id can be.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::Number(n) if n.is_f64() => py_float(n.as_f64().unwrap_or(0.0)),
        other => number_text(other).unwrap_or_else(|| pyjson::dumps(other)),
    }
}

/// `repr(float)`: the shortest digits, positional from 1e-4 up to 1e16, exponent form outside.
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let a = f.abs();
    if a == 0.0 || (1e-4..1e16).contains(&a) {
        let s = format!("{f}");
        return if s.contains('.') { s } else { format!("{s}.0") };
    }
    let e = format!("{f:e}");
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    format!("{mant}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs())
}

/// The request body as text (`get_text(strict=False)`).
fn request_text(flow: &Flow) -> String {
    flow.request
        .as_ref()
        // As the check read it (`get_text_utf8`): what is approved is what was checked.
        .map(|r| body::get_text_utf8(&body::content_type(r.headers()), r.body()))
        .unwrap_or_default()
}

/// `_tg_out_fields`: every field of the call, the query string's included, every value of a
/// repeated key; and whether it is a JSON body with no fields in the query (only that can be held).
/// The body as Telegram and Slack read it (`_out_body`): a compressed body, another charset, or a
/// multipart body that does not split cleanly is an error, never read as empty.
pub fn out_fields(flow: &Flow) -> Result<(Vec<(String, Value)>, bool), CheckError> {
    let Some(req) = flow.request.as_ref() else {
        return Ok((Vec::new(), false));
    };
    let query = body::query_items(req.uri());
    let mut fields: Vec<(String, Value)> = query.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let unreadable = |e: body::Unreadable| CheckError::Failed(e.to_string());
    let (media, params, raw) = body::out_body(req.headers(), req.body()).map_err(unreadable)?;
    let mut is_json = false;
    if media == "multipart/form-data" {
        for (k, v) in body::multipart_fields(body::param(&params, "boundary"), req.body()).map_err(unreadable)? {
            fields.push((k, json!(String::from_utf8_lossy(&v))));
        }
    } else if media == "application/x-www-form-urlencoded" {
        fields.extend(body::parse_qsl(&raw).into_iter().map(|(k, v)| (k, json!(v))));
    } else if !raw.trim_matches(body::is_py_space).is_empty() {
        let doc = loads_strict_raw_numbers(&raw).map_err(|e| CheckError::Failed(e.to_string()))?;
        let Value::Object(map) = doc else {
            return Err(CheckError::Failed("not a JSON object".into()));
        };
        fields.extend(map);
        is_json = query.is_empty();
    }
    Ok((fields, is_json))
}

/// Why `texts` stopped: a repeated key (refused wherever it sits) or nesting past 20 levels
/// (`_TooDeep`, refused wherever it sits).
#[derive(Debug)]
pub enum TextsError {
    Duplicate,
    TooDeep,
}

impl From<TextsError> for CheckError {
    fn from(e: TextsError) -> Self {
        match e {
            TextsError::Duplicate => CheckError::Failed(JsonError::Duplicate.to_string()),
            TextsError::TooDeep => CheckError::Failed("nested too deep".into()),
        }
    }
}

/// `_tg_texts`: the strings under any of `keys`, at any depth (`under` takes every string), and
/// the numbers there as written. A string that is JSON is read inside too, and kept as it is when
/// it is under a text key: Telegram shows it as written. Numbers are read as written only when the
/// value came from [`loads_strict_raw_numbers`] or [`super::json::loads_raw_numbers`].
pub fn texts(value: &Value, under: bool, out: &mut Vec<String>, depth: usize, keys: &[&str]) -> Result<(), TextsError> {
    if depth > 20 {
        return Err(TextsError::TooDeep);
    }
    if let Some(n) = number_text(value) {
        if under {
            out.push(n);
        }
        return Ok(());
    }
    match value {
        Value::String(s) => {
            let stripped = s.trim_start_matches(body::is_py_space);
            if stripped.starts_with('[') || stripped.starts_with('{') {
                // Form and multipart calls carry objects as JSON in a string (media, options, results).
                match loads_strict_raw_numbers(s) {
                    // Too deep inside is refused, as at the top.
                    Ok(inner) => texts(&inner, under, out, depth + 1, keys)?,
                    Err(JsonError::Duplicate) => return Err(TextsError::Duplicate),
                    // JSON to Telegram's parser but not to this one (a control character in a
                    // string): every word in it is read, its escapes undone, whatever its keys.
                    // Pushed once when it reads the same as written (the addon pushed it twice).
                    Err(JsonError::Invalid(_)) => {
                        let loose = unescape_loose(s);
                        if !under || loose != *s {
                            out.push(loose);
                        }
                    }
                }
            }
            if under {
                out.push(s.clone());
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                texts(v, under || keys.contains(&k.as_str()), out, depth + 1, keys)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                texts(v, under, out, depth + 1, keys)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn tg_text(fields: &[(String, Value)]) -> Result<String, CheckError> {
    Ok(text_of(fields, TEXT_KEYS)?)
}

/// `_tg_text(fields, keys)`: the words of every field, by these keys.
pub fn text_of(fields: &[(String, Value)], keys: &[&str]) -> Result<String, TextsError> {
    let mut out = Vec::new();
    for (k, v) in fields {
        texts(v, keys.contains(&k.as_str()), &mut out, 0, keys)?;
    }
    Ok(out.join("\n"))
}

// ---- taps ---------------------------------------------------------------------------------------

pub struct TelegramTaps {
    pub url: String,
}

fn is_tap(u: &Value) -> bool {
    u.get("callback_query")
        .filter(|c| c.is_object())
        .and_then(|c| c.get("data"))
        .and_then(Value::as_str)
        .is_some_and(|d| d.starts_with(TAP_PREFIX))
}

fn is_int(v: &Value) -> bool {
    // `isinstance(x, int)`: a JSON integer, or a bool (Python's bool is an int).
    v.is_i64() || v.is_u64() || v.is_boolean()
}

fn int_of(v: &Value) -> Option<i128> {
    v.as_i64()
        .map(i128::from)
        .or_else(|| v.as_u64().map(i128::from))
        .or_else(|| v.as_bool().map(i128::from))
}

/// `keep_top_update`: `kept`, with the batch's highest `update_id` still in it.
pub fn keep_top_update(updates: &[Value], mut kept: Vec<Value>) -> Vec<Value> {
    let top = updates
        .iter()
        .filter_map(|u| u.get("update_id").filter(|i| is_int(i)).and_then(int_of))
        .max();
    if let Some(top) = top {
        let present = kept
            .iter()
            .any(|u| u.get("update_id").and_then(|i| py_num_eq(i, top)).unwrap_or(false));
        if !present {
            let id = updates
                .iter()
                .filter_map(|u| u.get("update_id").filter(|i| is_int(i)))
                .find(|i| int_of(i) == Some(top))
                .cloned()
                .unwrap_or(Value::Null);
            kept.push(json!({"update_id": id}));
        }
    }
    kept
}

/// `u.get("update_id") == top` with Python's numeric equality (1.0 == 1 == True).
fn py_num_eq(v: &Value, top: i128) -> Option<bool> {
    Some(match v {
        Value::Number(n) => match n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)) {
            Some(i) => i == top,
            None => n.as_f64() == Some(top as f64),
        },
        Value::Bool(b) => i128::from(*b) == top,
        _ => false,
    })
}

/// `strip_taps`: the answer for the agent and the taps taken out of it.
pub fn strip_taps(doc: &Value) -> (Value, Vec<Value>) {
    let Some(updates) = doc
        .get("result")
        .and_then(Value::as_array)
        .filter(|_| doc.get("ok") == Some(&Value::Bool(true)))
    else {
        return (doc.clone(), Vec::new());
    };
    let taps: Vec<Value> = updates
        .iter()
        .filter(|u| is_tap(u))
        .map(|u| u["callback_query"].clone())
        .collect();
    if taps.is_empty() {
        return (doc.clone(), taps);
    }
    let kept = keep_top_update(updates, updates.iter().filter(|u| !is_tap(u)).cloned().collect());
    let mut clean = doc.clone();
    clean["result"] = Value::Array(kept);
    (clean, taps)
}

impl Step for TelegramTaps {
    fn name(&self) -> &'static str {
        "telegram-taps"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// `getUpdates` answers: the taps are taken out of them.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        is_telegram_flow(flow) && GET_UPDATES_RE.is_match(path(flow))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !is_telegram_flow(flow) || flow.response.as_ref().is_none_or(|r| r.status() != 200) {
                return Verdict::Continue;
            }
            let Some(bot_id) = GET_UPDATES_RE.captures(path(flow)).map(|c| c[1].to_owned()) else {
                return Verdict::Continue;
            };
            let Some(resp) = flow.response.as_mut() else {
                return Verdict::Continue;
            };
            if !contains(resp.body(), TAP_PREFIX.as_bytes()) {
                return Verdict::Continue;
            }
            let Ok(doc) = std::str::from_utf8(resp.body())
                .map_err(|_| ())
                .and_then(|t| super::json::loads(t).map_err(|_| ()))
            else {
                return Verdict::Continue;
            };
            let (clean, taps) = strip_taps(&doc);
            if taps.is_empty() {
                return Verdict::Continue;
            }
            set_body(resp, pyjson::dumps(&clean).into_bytes());
            let url = self.url.clone();
            let payload = json!({"botId": bot_id, "queries": taps.into_iter().take(100).collect::<Vec<_>>()});
            tokio::spawn(async move {
                // The tap is gone either way: the person taps again or types the code.
                if let Err(e) =
                    super::loopback::post(&url, pyjson::dumps(&payload).as_bytes(), Duration::from_secs(5)).await
                {
                    tracing::warn!("[mitm] could not hand a button tap to the firewall: {e}");
                }
            });
            Verdict::Continue
        })
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---- in -----------------------------------------------------------------------------------------

pub struct TelegramIn {
    pub content: Arc<Content>,
}

/// What `_tg_update_text` found in one update: its text, chat and sender, or that reading it failed.
type UpdateText = Result<Option<(String, Value)>, ()>;

/// `_tg_own`: whether a message on an update is the agent's own: its sender, or the sender it is
/// quoted from, is the bot.
fn own(msg: Option<&Value>, bot_id: &str) -> bool {
    let Some(msg) = msg.and_then(Value::as_object) else {
        return false;
    };
    let origin_sender = msg
        .get("origin")
        .and_then(Value::as_object)
        .and_then(|o| o.get("sender_user"));
    [msg.get("from"), origin_sender]
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .any(|s| py_str(s.get("id").unwrap_or(&Value::Null)) == bot_id)
}

/// `_tg_in_texts`: the texts on an incoming update. Telegram's own JSON: a string is shown as
/// written and never parsed, so nothing a person types can make the walk fail.
fn in_texts(value: &Value, under: bool, out: &mut Vec<String>, bot_id: &str, depth: usize) -> Result<(), ()> {
    if depth > 40 {
        return Err(());
    }
    match value {
        Value::String(s) if under => out.push(s.clone()),
        Value::Object(m) => {
            for (k, v) in m {
                let k = k.as_str();
                if IN_SKIP.contains(&k) || (depth > 0 && IN_OWN_KEYS.contains(&k) && own(Some(v), bot_id)) {
                    continue;
                }
                if k == "quote" && own(m.get("reply_to_message"), bot_id) {
                    continue; // a quote of the agent's own message
                }
                in_texts(v, under || in_key(k), out, bot_id, depth + 1)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                in_texts(v, under, out, bot_id, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `_tg_update_text`: the text of one incoming update and its chat; `None` when it carries
/// nothing. Every text in it is read, wherever it sits, on every kind of update Telegram has or
/// adds; not the agent's own messages (`IN_OWN_KEYS`).
fn update_text(u: &Value, bot_id: &str) -> UpdateText {
    let Some(u) = u.as_object() else { return Ok(None) };
    let Some(body) = u
        .iter()
        .find(|(k, v)| *k != "update_id" && v.is_object())
        .and_then(|(_, v)| v.as_object())
    else {
        return Ok(None);
    };
    // `update_id` is a number, which this walk never reads: the update is walked as it is.
    let mut out = Vec::new();
    // As `in_texts` at the top (depth 0), without copying the update.
    for (k, v) in u {
        if IN_SKIP.contains(&k.as_str()) || (k == "quote" && own(u.get("reply_to_message"), bot_id)) {
            continue;
        }
        in_texts(v, in_key(k), &mut out, bot_id, 1)?;
    }
    // A button tap's chat is on the message it was tapped under.
    let chat = match (body.get("chat"), body.get("message")) {
        (Some(c @ Value::Object(_)), _) => Some(c),
        (_, Some(Value::Object(m))) => m.get("chat"),
        _ => None,
    };
    Ok(Some((out.join("\n"), id_of(chat)?)))
}

/// `(x or {}).get("id")`: an error when `x` is truthy and not an object.
fn id_of(v: Option<&Value>) -> Result<Value, ()> {
    match v {
        Some(Value::Object(o)) => Ok(o.get("id").cloned().unwrap_or(Value::Null)),
        v if is_falsy(v) => Ok(Value::Null),
        _ => Err(()),
    }
}

impl Step for TelegramIn {
    fn name(&self) -> &'static str {
        "telegram-in"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// `getUpdates` answers: what comes in is checked.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        is_telegram_flow(flow) && GET_UPDATES_RE.is_match(path(flow))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            incoming(&self.content, flow).await;
            Verdict::Continue
        })
    }
}

/// `content_rules_telegram_in`: messages coming in to the agent; a blocked one is taken out, the
/// offset kept moving.
async fn incoming(content: &Arc<Content>, flow: &mut Flow) {
    if !is_telegram_flow(flow) || flow.response.as_ref().is_none_or(|r| r.status() != 200) {
        return;
    }
    let Some(bot_id) = GET_UPDATES_RE.captures(path(flow)).map(|c| c[1].to_owned()) else {
        return;
    };
    let raw = flow.response.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    let ready = super::body_ready(flow);
    let doc = std::str::from_utf8(&raw)
        .ok()
        .and_then(|t| super::json::loads(t).ok())
        .filter(|_| ready)
        .filter(|d| d.get("ok") == Some(&Value::Bool(true)) && d.get("result").is_some_and(Value::is_array));
    let Some(doc) = doc else {
        // An answer that cannot be read cannot be checked: the agent gets nothing this time, and
        // Telegram sends the same batch again on the next poll.
        tracing::warn!("[content-rules] incoming Telegram answer unreadable, held back");
        content.audit(
            Some(flow),
            "error",
            "telegram",
            "in",
            "block",
            None,
            detail("unreadable answer"),
        );
        rewrite(flow, &json!({"ok": true, "result": []}));
        return;
    };
    let updates = doc["result"].as_array().cloned().unwrap_or_default();
    if updates.is_empty() {
        return;
    }
    let vm_id = flow.vm_id.clone();
    let mut kept = Vec::new();
    let mut notices = Vec::new();
    match filter(
        content,
        flow,
        &bot_id,
        &updates,
        vm_id.as_deref(),
        &mut kept,
        &mut notices,
    )
    .await
    {
        Ok(()) => {}
        Err(CheckError::Unreadable(_)) => {
            // The rules became unknown while Telegram answered: an empty answer, so the offset
            // does not move and Telegram sends the same messages again.
            content.audit(
                Some(flow),
                "error",
                "telegram",
                "in",
                "wait",
                None,
                detail("rules unknown"),
            );
            let mut empty = doc.clone();
            empty["result"] = json!([]);
            rewrite(flow, &empty);
            return;
        }
        Err(e) => {
            tracing::warn!("[content-rules] incoming Telegram check failed, holding back messages: {e}");
            content.audit(Some(flow), "error", "telegram", "in", "block", None, Map::new());
            notices.clear();
            kept = updates
                .iter()
                .map(|u| update_text(u, &bot_id).map(|t| (u, t)))
                .collect::<Result<Vec<_>, ()>>()
                .map(|all| {
                    all.into_iter()
                        .filter(|(_, t)| t.as_ref().is_none_or(|(s, _)| s.is_empty()))
                        .map(|(u, _)| u.clone())
                        .collect()
                })
                .unwrap_or_default();
        }
    }
    if kept.len() == updates.len() {
        return;
    }
    let kept = keep_top_update(&updates, kept);
    let mut out = doc.clone();
    out["result"] = Value::Array(kept);
    rewrite(flow, &out);
    for n in notices {
        content.notice(n);
    }
}

fn rewrite(flow: &mut Flow, doc: &Value) {
    if let Some(r) = flow.response.as_mut() {
        set_body(r, pyjson::dumps(doc).into_bytes());
    }
}

/// `_tg_in_filter`'s loop: which updates the agent keeps, and the notices to send.
async fn filter(
    content: &Arc<Content>,
    flow: &mut Flow,
    bot_id: &str,
    updates: &[Value],
    vm_id: Option<&str>,
    kept: &mut Vec<Value>,
    notices: &mut Vec<Value>,
) -> Result<(), CheckError> {
    let rules = content.rules()?;
    let found_texts: Vec<Option<(String, Value)>> = updates
        .iter()
        .map(|u| update_text(u, bot_id))
        .collect::<Result<_, ()>>()
        .map_err(|()| CheckError::Failed("an update is not in the expected shape".into()))?;
    let todo: Vec<usize> = (0..updates.len())
        .filter(|i| found_texts[*i].as_ref().is_some_and(|(t, _)| !t.is_empty()))
        .collect();
    let mut answers: Vec<Option<engine::Found>> = vec![None; updates.len()];
    if todo.len() > 1 && engine::policy_applies(&rules, "in", "telegram") {
        // Each is a call to the AI: a few at once, so a batch waits about as long as one.
        let gate = Arc::new(tokio::sync::Semaphore::new(8));
        let mut set = tokio::task::JoinSet::new();
        for i in todo {
            let text = found_texts[i].as_ref().map(|(t, _)| t.clone()).unwrap_or_default();
            let (content, rules, gate, vm) = (content.clone(), rules.clone(), gate.clone(), vm_id.map(str::to_owned));
            set.spawn(async move {
                let _permit = gate.acquire().await;
                (i, judged(&content, &rules, &text, vm.as_deref()).await)
            });
        }
        while let Some(r) = set.join_next().await {
            let (i, found) = r.map_err(|e| CheckError::Failed(e.to_string()))?;
            answers[i] = Some(found);
        }
    } else {
        for i in todo {
            let text = found_texts[i].as_ref().map_or("", |(t, _)| t.as_str());
            answers[i] = Some(judged(content, &rules, text, vm_id).await);
        }
    }
    for (i, update) in updates.iter().enumerate() {
        let Some((text, chat)) = found_texts[i].as_ref().filter(|(t, _)| !t.is_empty()) else {
            kept.push(update.clone());
            continue;
        };
        let Some(found) = answers[i].take() else {
            return Err(CheckError::Failed("an update was not checked".into()));
        };
        let Some(rule) = content.acted(Some(flow), found, "in", "telegram", text, None) else {
            kept.push(update.clone());
            continue;
        };
        content.audit(Some(flow), &rule.id, "telegram", "in", "block", None, Map::new());
        if !chat.is_null() {
            let mut n =
                json!({"kind": "in", "botId": bot_id, "chatId": py_str(chat), "vmId": vm_id, "reason": rule.reason});
            if rule.by.as_deref() == Some("failed") {
                n["failed"] = json!(true);
            }
            notices.push(n);
        }
    }
    Ok(())
}

/// One incoming text judged; too long to check is a block, as the addon's `judged` has it.
async fn judged(content: &Content, rules: &[Rule], text: &str, vm_id: Option<&str>) -> engine::Found {
    match engine::judge(&content.ask, rules, "in", "telegram", text, None, vm_id).await {
        Ok(f) => f,
        // `judge`'s one error: the text is longer than a check reads.
        Err(engine::TooLong(_)) => {
            let too_long = Rule {
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
            };
            engine::Found {
                winner: Some(too_long),
                hits: vec![],
            }
        }
    }
}

#[cfg(test)]
mod tests;
