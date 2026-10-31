//! Twilio (appendix F feature 25, addon.py 1037-1086, 1660-1797, 3126-3131): an agent's phone
//! number is its own and no one else's. A call goes out only from that agent, only with its own
//! account and number, only through the narrow operations the phone plugin uses (create a call,
//! read one, hang one up, update it with TwiML from a short allow-list), always with a hard
//! duration, and only after the firewall agent reserved a slot for it (`:8791`).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::creds::{Creds, truthy};
use super::logins::scope::{header_values, is_https, method, port, quote_plus, str_of, target};
use super::{body, check_host, loopback, pyjson};
use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};

pub const TWILIO: &str = "api.twilio.com";
pub const META_RESERVATION: &str = "cc_phone_reservation";
const DEFAULT_ADMISSION: &str = "http://127.0.0.1:8791/";

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

static TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-zA-Z0-9_-]{1,160}$"));
static E164: LazyLock<Regex> = LazyLock::new(|| re(r"^\+[1-9]\d{6,14}$"));
static TIMEOUT: LazyLock<Regex> = LazyLock::new(|| re(r"^(?:[1-9]|[12][0-9]|30)$"));
static DIGITS: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9*#wW]{1,100}$"));
static RESERVATION: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-f0-9]{48}$"));
static BAD_PERCENT: LazyLock<Regex> = LazyLock::new(|| re(r"%(?:[^0-9a-fA-F]|.[^0-9a-fA-F]|.?$)"));
static XML_DECL: LazyLock<Regex> = LazyLock::new(|| re(r#"^\s*<\?xml version="1\.0"(?: encoding="UTF-8")?\?>"#));

/// The pieces of a URL `urlsplit` gives.
fn split(u: &str) -> (String, String, String, String, bool) {
    let (scheme, rest) = u.split_once("://").map_or(("", u), |(s, r)| (s, r));
    let (rest, frag) = match rest.split_once('#') {
        Some((r, _)) => (r, true),
        None => (rest, false),
    };
    let (before_q, query) = rest.split_once('?').map_or((rest, ""), |(a, b)| (a, b));
    let (netloc, path) = match before_q.find('/') {
        Some(i) if u.contains("://") => (&before_q[..i], &before_q[i..]),
        None if u.contains("://") => (before_q, ""),
        _ => ("", before_q),
    };
    (
        scheme.to_lowercase(),
        netloc.to_owned(),
        path.to_owned(),
        query.to_owned(),
        frag,
    )
}

/// `parse_qsl(q, keep_blank_values=True, strict_parsing=True)`: `None` for a piece without `=`.
fn qsl_strict(q: &str) -> Option<Vec<(String, String)>> {
    if q.is_empty() {
        return Some(Vec::new());
    }
    q.split('&')
        .map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((body::unquote(&k.replace('+', " ")), body::unquote(&v.replace('+', " "))))
        })
        .collect()
}

/// `phone_hook_url`: the firewall's own phone hook, with only the parameters the plugin sets.
pub fn hook_url(value: &str, hook: &str) -> bool {
    let (us, un, up, uq, uf) = split(value);
    let (hs, hn, hp, _, _) = split(hook);
    if (us, un, up) != (hs, hn, hp) || uf || uq.chars().count() > 2048 {
        return false;
    }
    let Some(pairs) = qsl_strict(&uq) else { return false };
    let mut keys: Vec<&String> = pairs.iter().map(|(k, _)| k).collect();
    keys.sort();
    keys.dedup();
    if keys.len() != pairs.len() {
        return false;
    }
    pairs.iter().all(|(k, v)| {
        if k == "type" {
            v == "status"
        } else {
            ["callId", "turnToken", "ccCall"].contains(&k.as_str()) && TOKEN.is_match(v)
        }
    })
}

// ---- TwiML ----------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Node {
    tag: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<Node>,
}

/// The five predefined entities; anything else was refused before.
fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// A strict reader of the XML TwiML is: elements, attributes and text. Anything ElementTree would
/// refuse (unclosed tags, a repeated attribute, text outside the root, a prefixed name) is an error.
fn parse_xml(xml: &str) -> Option<Node> {
    let b = xml.as_bytes();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < b.len() && b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    };
    let name_char = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.');
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    loop {
        if root.is_some() && stack.is_empty() {
            skip_ws(&mut i);
            return (i == b.len()).then(|| root.take()).flatten();
        }
        if i >= b.len() {
            return None;
        }
        if b[i] != b'<' {
            let end = xml[i..].find('<').map_or(b.len(), |e| i + e);
            let text = &xml[i..end];
            match stack.last_mut() {
                Some(n) if n.children.is_empty() => n.text.push_str(&unescape_xml(text)),
                Some(_) => {}
                None if text.trim().is_empty() => {}
                None => return None,
            }
            i = end;
            continue;
        }
        if b.get(i + 1) == Some(&b'/') {
            let end = xml[i..].find('>').map(|e| i + e)?;
            let name = xml[i + 2..end].trim_end();
            let node = stack.pop()?;
            if node.tag != name {
                return None;
            }
            i = end + 1;
            match stack.last_mut() {
                Some(parent) => parent.children.push(node),
                None => root = Some(node),
            }
            continue;
        }
        i += 1;
        let start = i;
        while i < b.len() && name_char(b[i]) {
            i += 1;
        }
        if i == start {
            return None;
        }
        let mut node = Node {
            tag: xml[start..i].to_owned(),
            ..Node::default()
        };
        loop {
            skip_ws(&mut i);
            match b.get(i) {
                Some(b'>') => {
                    i += 1;
                    stack.push(node);
                    break;
                }
                Some(b'/') if b.get(i + 1) == Some(&b'>') => {
                    i += 2;
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => root = Some(node),
                    }
                    break;
                }
                Some(c) if name_char(*c) => {
                    let s = i;
                    while i < b.len() && name_char(b[i]) {
                        i += 1;
                    }
                    let name = xml[s..i].to_owned();
                    skip_ws(&mut i);
                    if b.get(i) != Some(&b'=') {
                        return None;
                    }
                    i += 1;
                    skip_ws(&mut i);
                    let q = *b.get(i)?;
                    if q != b'"' && q != b'\'' {
                        return None;
                    }
                    let e = xml[i + 1..].find(q as char).map(|e| i + 1 + e)?;
                    let value = &xml[i + 1..e];
                    if value.contains('<') || name == "xmlns" || node.attrs.iter().any(|(k, _)| *k == name) {
                        return None;
                    }
                    // Attribute values are normalised: a line break or a tab reads as a space.
                    node.attrs
                        .push((name, unescape_xml(value).replace(['\n', '\t', '\r'], " ")));
                    i = e + 1;
                }
                _ => return None,
            }
        }
    }
}

fn all_nodes<'a>(n: &'a Node, out: &mut Vec<&'a Node>) {
    out.push(n);
    for c in &n.children {
        all_nodes(c, out);
    }
}

/// `phone_twiml_allowed`: TwiML from the short list, every hook the firewall's own.
pub fn twiml_allowed(xml: &str, hook: &str) -> bool {
    static AMP: LazyLock<Regex> = LazyLock::new(|| re(r"&(?:amp;|lt;|gt;|quot;|apos;)"));
    if xml.len() > 65536 || xml.contains("<!") || AMP.replace_all(xml, "").contains('&') {
        return false;
    }
    let xml = XML_DECL.replace(xml, "").into_owned();
    if xml.contains("<?") {
        return false;
    }
    let allowed = |tag: &str| -> Option<&'static [&'static str]> {
        Some(match tag {
            "Response" | "Hangup" => &[],
            "Say" => &["voice", "language", "loop"],
            "Gather" => &[
                "input",
                "speechTimeout",
                "timeout",
                "language",
                "action",
                "method",
                "numDigits",
                "finishOnKey",
                "actionOnEmptyResult",
            ],
            "Pause" => &["length"],
            "Reject" => &["reason"],
            "Play" => &["digits"],
            "Redirect" => &["method"],
            _ => return None,
        })
    };
    let Some(root) = parse_xml(&xml) else { return false };
    if root.tag != "Response" {
        return false;
    }
    let mut nodes = Vec::new();
    all_nodes(&root, &mut nodes);
    if nodes.len() > 128 {
        return false;
    }
    for (i, node) in nodes.iter().enumerate() {
        let Some(names) = allowed(&node.tag) else { return false };
        if node.attrs.iter().any(|(k, _)| !names.contains(&k.as_str())) || (i > 0 && node.tag == "Response") {
            return false;
        }
        let attr = |k: &str| node.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        if attr("method").unwrap_or("POST") != "POST" {
            return false;
        }
        if node.tag == "Gather" && !hook_url(attr("action").unwrap_or(""), hook) {
            return false;
        }
        if node.tag == "Redirect" && !hook_url(node.text.trim(), hook) {
            return false;
        }
        if node.tag == "Play" && (!DIGITS.is_match(attr("digits").unwrap_or("")) || !node.text.trim().is_empty()) {
            return false;
        }
        if matches!(node.tag.as_str(), "Say" | "Play" | "Redirect") && !node.children.is_empty() {
            return false;
        }
    }
    true
}

// ---- the request ----------------------------------------------------------------------------

pub struct Phone {
    pub creds: Arc<Creds>,
    /// `127.0.0.1:8791`, fixed in the addon; a test's own service here.
    pub admission_url: String,
}

impl Phone {
    pub fn new(creds: Arc<Creds>) -> Arc<Self> {
        Arc::new(Self {
            creds,
            admission_url: DEFAULT_ADMISSION.into(),
        })
    }

    /// `phone_credential`: this agent's phone entry for Twilio.
    pub fn credential(&self, flow: &Flow) -> Option<Value> {
        let vm = flow.vm_id.as_deref().filter(|v| !v.is_empty())?;
        if check_host(flow) != TWILIO {
            return None;
        }
        self.creds
            .for_host(TWILIO, Some(vm))
            .into_iter()
            .find(|c| truthy(c.get("phone")) && c.get("vm_id").and_then(Value::as_str) == Some(vm))
    }
}

/// `phone_authorized`: the request is one of the plugin's operations on its own account. A call
/// it creates gets the hard duration (`TimeLimit`) written in.
pub fn authorized(flow: &mut Flow, cred: &Value) -> bool {
    let sni_ok = flow.sni.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(TWILIO));
    if check_host(flow) != TWILIO || !sni_ok || !is_https(flow) || port(flow) != 443 {
        return false;
    }
    // The addon pins routing to api.twilio.com before a secret can go in. Here routing is the
    // checked destination's: without one that is Twilio's on 443, nothing is put in.
    if !flow
        .destination()
        .is_some_and(|d| d.port == 443 && d.name.trim_end_matches('.').eq_ignore_ascii_case(TWILIO))
    {
        return false;
    }
    // `cred["placeholder"]` raised without one: an entry with no stand-in is refused.
    let Some(placeholder) = cred
        .get("placeholder")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
    else {
        return false;
    };
    let Some(config) = cred.get("phone") else { return false };
    let (Some(sid), Some(from), Some(hook)) = (
        config.get("account_sid").and_then(Value::as_str),
        config.get("from_number").and_then(Value::as_str),
        config.get("hook_url").and_then(Value::as_str),
    ) else {
        return false;
    };
    let auth = header_values(flow, "authorization");
    if auth.len() != 1 || !auth[0].starts_with("Basic ") {
        return false;
    }
    let Some(decoded) = base64::engine::general_purpose::STANDARD
        .decode(&auth[0][6..])
        .ok()
        .and_then(|d| String::from_utf8(d).ok())
        .filter(|d| d.is_ascii())
    else {
        return false;
    };
    if decoded != format!("{sid}:{placeholder}") {
        return false;
    }
    let prefix = format!("/2010-04-01/Accounts/{sid}/Calls");
    let path = target(flow);
    let create = path == format!("{prefix}.json");
    let item = path
        .strip_prefix(&format!("{prefix}/CA"))
        .and_then(|r| r.strip_suffix(".json"))
        .is_some_and(|id| id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()));
    let m = method(flow);
    if m == "GET" {
        return item;
    }
    if m != "POST" || !(create || item) {
        return false;
    }
    let ct = header_values(flow, "content-type").first().cloned().unwrap_or_default();
    if !ct.to_lowercase().starts_with("application/x-www-form-urlencoded") {
        return false;
    }
    // The addon read the raw bytes, so a compressed form failed its UTF-8 read: refused here too,
    // so what is checked is what is sent.
    if header_values(flow, "content-encoding")
        .iter()
        .any(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
    {
        return false;
    }
    let raw = flow.request.as_ref().map(|r| r.body().to_vec()).unwrap_or_default();
    let Ok(text) = String::from_utf8(raw) else { return false };
    if text.chars().count() > 65536 || BAD_PERCENT.is_match(&text) {
        return false;
    }
    let Some(pairs) = qsl_strict_utf8(&text) else {
        return false;
    };
    if pairs.len() > 128 {
        return false;
    }
    let mut fields: Vec<(String, String)> = Vec::new();
    for (k, v) in &pairs {
        if fields.iter().any(|(fk, _)| fk == k) && k != "StatusCallbackEvent" {
            return false;
        }
        fields.retain(|(fk, _)| fk != k);
        fields.push((k.clone(), v.clone()));
    }
    let get = |k: &str| fields.iter().find(|(fk, _)| fk == k).map(|(_, v)| v.as_str());
    if create {
        const OK: &[&str] = &[
            "To",
            "From",
            "Url",
            "Method",
            "StatusCallback",
            "StatusCallbackMethod",
            "StatusCallbackEvent",
            "Timeout",
            "TimeLimit",
        ];
        if fields.iter().any(|(k, _)| !OK.contains(&k.as_str())) {
            return false;
        }
        if get("From") != Some(from) || !E164.is_match(get("To").unwrap_or("")) {
            return false;
        }
        if !hook_url(get("Url").unwrap_or(""), hook) || !hook_url(get("StatusCallback").unwrap_or(""), hook) {
            return false;
        }
        if get("Method").unwrap_or("POST") != "POST" || get("StatusCallbackMethod").unwrap_or("POST") != "POST" {
            return false;
        }
        if pairs.iter().any(|(k, v)| {
            k == "StatusCallbackEvent" && !["initiated", "ringing", "answered", "completed"].contains(&v.as_str())
        }) {
            return false;
        }
        if get("Timeout").is_some_and(|t| !t.is_empty() && !TIMEOUT.is_match(t)) {
            return false;
        }
        // Always the provider's hard duration for outbound calls.
        let limit = match config.get("max_duration") {
            None => 300,
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().unwrap_or(i64::MAX).clamp(60, 3600),
            _ => return false,
        };
        let mut out: Vec<(String, String)> = pairs.into_iter().filter(|(k, _)| k != "TimeLimit").collect();
        out.push(("TimeLimit".into(), limit.to_string()));
        set_form(flow, &out);
        return true;
    }
    if fields.len() == 1 && get("Status") == Some("completed") {
        return true;
    }
    fields.len() == 1 && get("Twiml").is_some_and(|t| twiml_allowed(t, hook))
}

/// `parse_qsl(..., strict_parsing=True, errors="strict")`: a piece without `=` or a value that is
/// not UTF-8 once decoded is an error.
fn qsl_strict_utf8(q: &str) -> Option<Vec<(String, String)>> {
    if q.is_empty() {
        return Some(Vec::new());
    }
    q.split('&')
        .map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((
                super::logins::scope::decode_once(k)?,
                super::logins::scope::decode_once(v)?,
            ))
        })
        .collect()
}

/// `urlencode(pairs)` written as the request body.
fn set_form(flow: &mut Flow, pairs: &[(String, String)]) {
    let text = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k, ""), quote_plus(v, "")))
        .collect::<Vec<_>>()
        .join("&");
    if let Some(r) = flow.request.as_mut() {
        let len = text.len();
        *r.body_mut() = Bytes::from(text);
        r.headers_mut()
            .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
    }
}

/// `phone_admission`: one call to 8791; an error unless it says `ok: true`.
async fn admission(url: &str, payload: &Value, timeout: Duration) -> Option<Map<String, Value>> {
    let raw = loopback::post(url, pyjson::dumps(payload).as_bytes(), timeout)
        .await
        .ok()?;
    match super::json::loads(std::str::from_utf8(&raw).ok()?).ok()? {
        Value::Object(m) if m.get("ok") == Some(&Value::Bool(true)) => Some(m),
        _ => None,
    }
}

/// `phone_reserve`: a slot for a call this agent creates, and the reservation in the call's hooks.
async fn reserve(phone: &Phone, flow: &mut Flow, cred: &Value) -> bool {
    if method(flow) != "POST" || !target(flow).ends_with("/Calls.json") {
        return true;
    }
    let payload = json!({"action": "reserve", "vmId": cred.get("vm_id"), "placeholder": cred.get("placeholder")});
    let Some(result) = admission(&phone.admission_url, &payload, Duration::from_secs(2)).await else {
        return false;
    };
    let Some(id) = result
        .get("id")
        .and_then(Value::as_str)
        .filter(|i| RESERVATION.is_match(i))
        .map(str::to_owned)
    else {
        return false;
    };
    flow.meta.insert(META_RESERVATION, json!(id));
    let raw = flow.request.as_ref().map(|r| r.body().to_vec()).unwrap_or_default();
    let ct = flow
        .request
        .as_ref()
        .map(|r| body::content_type(r.headers()))
        .unwrap_or_default();
    let pairs = body::urlencoded_items(&ct, &raw);
    let updated: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(k, v)| {
            if k != "Url" && k != "StatusCallback" {
                return (k, v);
            }
            let (s, n, p, q, _) = split(&v);
            let mut query: Vec<(String, String)> = body::parse_qsl(&q)
                .into_iter()
                .filter(|(qk, _)| qk != "ccCall")
                .collect();
            query.push(("ccCall".into(), id.clone()));
            let qs = query
                .iter()
                .map(|(a, b)| format!("{}={}", quote_plus(a, ""), quote_plus(b, "")))
                .collect::<Vec<_>>()
                .join("&");
            (k, format!("{s}://{n}{p}?{qs}"))
        })
        .collect();
    set_form(flow, &updated);
    true
}

/// The record's rule for a Twilio request (`_http_record`): the last four digits of the number called.
pub fn record_rule(flow: &Flow) -> String {
    let raw = flow.request.as_ref().map(|r| r.body().to_vec()).unwrap_or_default();
    let ct = flow
        .request
        .as_ref()
        .map(|r| body::content_type(r.headers()))
        .unwrap_or_default();
    let to = body::urlencoded_items(&ct, &raw)
        .into_iter()
        .find(|(k, _)| k == "To")
        .map(|(_, v)| v)
        .unwrap_or_default();
    if E164.is_match(&to) {
        format!("phone: outbound ****{}", &to[to.len() - 4..])
    } else {
        "phone".into()
    }
}

pub struct TwilioStep(pub Arc<Phone>);

impl Step for TwilioStep {
    fn name(&self) -> &'static str {
        "twilio"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// Twilio's REST API.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        check_host(flow) == TWILIO && super::request_has_body(flow)
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if check_host(flow) != TWILIO {
                return Verdict::Continue;
            }
            let ok = match self.0.credential(flow) {
                Some(cred) if !super::request_body_unread(flow) && authorized(flow, &cred) => {
                    reserve(&self.0, flow, &cred).await
                }
                _ => false,
            };
            if ok {
                return Verdict::Continue;
            }
            let rule = record_rule(flow);
            let mut rec = Map::new();
            rec.insert("rule".into(), json!(rule));
            super::note(flow, "block", "phone", 403, rec);
            Verdict::Answer(Box::new(super::raw_response(
                403,
                br#"{"error":"phone_assignment_required_or_operation_refused"}"#.to_vec(),
                "application/json",
            )))
        })
    }
}

/// The account's secret in `Authorization: Basic` (the phone part of `apply_swaps`), only for a
/// request `authorized` takes.
pub struct TwilioSwap(pub Arc<Phone>);

impl Step for TwilioSwap {
    fn name(&self) -> &'static str {
        "twilio-swap"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// A header swap.
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            let Some(cred) = self.0.credential(flow) else {
                return Verdict::Continue;
            };
            let locations: Vec<String> = cred
                .get("locations")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default();
            let secret = str_of(&cred, "secret");
            let sid = cred
                .get("phone")
                .and_then(|p| p.get("account_sid"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if secret.is_empty() || !locations.iter().any(|l| l == "basic:authorization") || !authorized(flow, &cred) {
                return Verdict::Continue;
            }
            let value = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{sid}:{secret}"))
            );
            if let (Some(r), Ok(v)) = (flow.request.as_mut(), http::HeaderValue::from_str(&value)) {
                r.headers_mut().insert(http::header::AUTHORIZATION, v);
            }
            let e = flow.meta.entry("cc_applied").or_insert_with(|| json!([]));
            if let Some(a) = e.as_array_mut() {
                a.push(json!([secret, str_of(&cred, "placeholder")]));
            }
            Verdict::Continue
        })
    }
}

/// `phone_settle`: after Twilio answered, the reservation is settled. Not waited for.
pub struct TwilioSettle(pub Arc<Phone>);

impl Step for TwilioSettle {
    fn name(&self) -> &'static str {
        "twilio-settle"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// A call that reserved a slot: its answer says which call it is.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        flow.meta.contains_key(META_RESERVATION)
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
            let Some(r) = flow.response.as_ref() else {
                return Verdict::Continue;
            };
            let status = r.status().as_u16();
            let sid = if (200..300).contains(&status) {
                // An answer the plumbing did not decode cannot be read for its sid: the slot is
                // kept until the call's longest life, as for one that does not parse (fewer calls,
                // never more).
                if !super::body_ready(flow) {
                    return Verdict::Continue;
                }
                match std::str::from_utf8(r.body())
                    .ok()
                    .and_then(|t| super::json::loads(t).ok())
                {
                    Some(doc) => doc.get("sid").cloned().unwrap_or(Value::Null),
                    // `json.loads(...).get` failing: the slot stays until the call's longest life.
                    None => return Verdict::Continue,
                }
            } else {
                Value::Null
            };
            let url = self.0.admission_url.clone();
            let payload = json!({"action": "settle", "id": id, "sid": sid, "rejected": (400..500).contains(&status)});
            tokio::spawn(async move {
                let _ = admission(&url, &payload, Duration::from_secs(2)).await;
            });
            Verdict::Continue
        })
    }
}

pub fn register(pipeline: &mut Pipeline, phone: Arc<Phone>) {
    pipeline.push(order::TWILIO, Arc::new(TwilioStep(phone.clone())));
    pipeline.push(order::SWAPS, Arc::new(TwilioSwap(phone.clone())));
    pipeline.push(order::RESPONSE_PHONE_SETTLE, Arc::new(TwilioSettle(phone)));
}

#[cfg(test)]
mod tests;
