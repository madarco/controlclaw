//! What a phone hook may answer Twilio with (`phone-policy.ts`): a short list of verbs, every
//! callback back to this firewall's own hook, no entities and no namespaces. Not a TwiML schema.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::core::url_form::QUERY_VALUE;

const VERBS: [&str; 8] = [
    "Response", "Say", "Gather", "Pause", "Hangup", "Reject", "Play", "Redirect",
];

/// JavaScript's `\s` and `trim`: U+FEFF is whitespace there and U+0085 is not, the other way round
/// from Rust's.
pub(super) const WS: &str =
    r"[\t\n\x0B\x0C\r \u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}]";

fn is_js_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\x0B' | '\x0C' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `s.trim()` as JavaScript trims.
pub(super) fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_ws)
}

static BAD_ENTITY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&(amp|lt|gt|quot|apos);|&").expect("regex"));
static DECL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r#"^{WS}*<\?xml version="1\.0"(?: encoding="UTF-8")?\?>"#)).expect("regex"));
static FORBIDDEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<!|<\?|[\x00-\x08]").expect("regex"));
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^<>]+)>").expect("regex"));
static END: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^/([A-Za-z0-9_]+){WS}*$")).expect("regex"));
static START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"^([A-Za-z0-9_]+)((?:{WS}+[\s\S]*)?)$")).expect("regex"));
static ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r#"^{WS}+([a-zA-Z]+){WS}*={WS}*(?:"([^"<>]*)"|'([^'<>]*)')"#)).expect("regex")
});
static DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9*#wW]{1,100}$").expect("regex"));

/// The five XML entities, and nothing else (`unescapeXml`).
fn unescape_xml(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut last = 0;
    for m in BAD_ENTITY.captures_iter(text) {
        let whole = m.get(0)?;
        out.push_str(&text[last..whole.start()]);
        out.push(match m.get(1)?.as_str() {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            _ => '\'',
        });
        last = whole.end();
    }
    out.push_str(&text[last..]);
    Some(out)
}

/// `samePhoneHook`: the firewall's own hook, with only the query a hook may carry.
pub fn same_phone_hook(value: &str, hook: &str) -> bool {
    let (Ok(url), Ok(base)) = (url::Url::parse(value), url::Url::parse(hook)) else {
        return false;
    };
    if url.origin() != base.origin()
        || url.path() != base.path()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    // `url.search`: `?` and the query, or empty for none or an empty one.
    if url
        .query()
        .map_or(0, |q| if q.is_empty() { 0 } else { q.encode_utf16().count() + 1 })
        > 2048
    {
        return false;
    }
    let mut keys: Vec<String> = vec![];
    for (k, v) in url.query_pairs() {
        let ok = if k == "type" {
            v == "status"
        } else {
            ["callId", "turnToken", "ccCall"].contains(&k.as_ref()) && QUERY_VALUE.is_match(&v)
        };
        if keys.contains(&k.to_string()) || !ok {
            return false;
        }
        keys.push(k.into_owned());
    }
    true
}

struct Node {
    name: String,
    text: String,
}

/// `allowedPhoneTwiml`.
pub fn allowed_phone_twiml(xml: &str, hook: &str) -> bool {
    check(xml, hook).unwrap_or(false)
}

fn check(xml: &str, hook: &str) -> Option<bool> {
    if xml.len() > 65536 {
        return Some(false);
    }
    let text = DECL.replace(xml, "");
    let text = text.as_ref();
    if FORBIDDEN.is_match(text) {
        return Some(false);
    }
    let mut stack: Vec<Node> = vec![];
    let (mut roots, mut offset) = (0, 0);
    for m in TAG.captures_iter(text) {
        let whole = m.get(0)?;
        let content = &text[offset..whole.start()];
        if content.contains('<') || content.contains('>') {
            return Some(false);
        }
        if let Some(top) = stack.last_mut() {
            top.text.push_str(&unescape_xml(content)?);
        } else if !js_trim(content).is_empty() {
            return Some(false);
        }
        let tag = m.get(1)?.as_str();
        offset = whole.end();
        if let Some(end) = END.captures(tag) {
            let Some(node) = stack.pop() else { return Some(false) };
            if node.name != end[1] {
                return Some(false);
            }
            if node.name == "Redirect" && !same_phone_hook(js_trim(&node.text), hook) {
                return Some(false);
            }
            if node.name == "Play" && !js_trim(&node.text).is_empty() {
                return Some(false);
            }
            continue;
        }
        let Some(start) = START.captures(tag.strip_suffix('/').unwrap_or(tag)) else {
            return Some(false);
        };
        let name = start.get(1)?.as_str();
        if !VERBS.contains(&name) {
            return Some(false);
        }
        if stack.is_empty() {
            roots += 1;
            if name != "Response" || roots > 1 {
                return Some(false);
            }
        }
        if stack
            .last()
            .is_some_and(|t| ["Say", "Play", "Redirect"].contains(&t.name.as_str()))
            || (!stack.is_empty() && name == "Response")
        {
            return Some(false);
        }
        let mut attrs: HashMap<String, String> = HashMap::new();
        let mut rest = start.get(2).map_or("", |r| r.as_str());
        while !js_trim(rest).is_empty() {
            let Some(a) = ATTR.captures(rest) else {
                return Some(false);
            };
            let key = a[1].to_string();
            if attrs.contains_key(&key) {
                return Some(false);
            }
            let raw = a.get(2).or(a.get(3)).map_or("", |v| v.as_str());
            attrs.insert(key, unescape_xml(raw)?);
            rest = &rest[a.get(0)?.end()..];
        }
        let allowed: &[&str] = match name {
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
            _ => &[],
        };
        if attrs.keys().any(|k| !allowed.contains(&k.as_str())) {
            return Some(false);
        }
        if attrs.get("method").is_some_and(|m| !m.is_empty() && m != "POST") {
            return Some(false);
        }
        if name == "Gather"
            && !attrs
                .get("action")
                .is_some_and(|a| !a.is_empty() && same_phone_hook(a, hook))
        {
            return Some(false);
        }
        if name == "Play" && !DIGITS.is_match(attrs.get("digits").map_or("", |d| d.as_str())) {
            return Some(false);
        }
        if name == "Redirect" && tag.ends_with('/') {
            return Some(false);
        }
        if !tag.ends_with('/') {
            stack.push(Node {
                name: name.into(),
                text: String::new(),
            });
        }
        if stack.len() > 8 {
            return Some(false);
        }
    }
    Some(roots == 1 && stack.is_empty() && js_trim(&text[offset..]).is_empty())
}
