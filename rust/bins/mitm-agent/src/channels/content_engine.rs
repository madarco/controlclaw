//! The content rules' engine (`content-engine.ts`), the same as the proxy's (`addon.py`,
//! `content_evaluate`), for the checks that do not go through the proxy: the webhook and team-chat
//! gates, the app calls, and the console's "Try a message". No I/O. `content-vectors.json` holds this
//! file, the TS and the proxy to the same answers.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contracts::ContentError;

/// The most text the AI judges: four pieces of 16,000 characters, each overlapping the one before
/// by 500. More than this is not judged: the rules act on it.
pub const CONTENT_AI_TEXT_MAX: usize = 4 * (16_000 - 500) + 500;
pub const CONTENT_AI_CHUNK: usize = 16_000;
pub const CONTENT_AI_OVERLAP: usize = 500;

/// The channels a content rule can cover (`content-rules-schema.ts`).
pub const CONTENT_CHANNELS: [&str; 8] = [
    "telegram", "slack", "email", "web", "webhook", "teamchat", "voice", "apps",
];

/// Our own expressions, each linear: the same as the proxy's `_SECRET_RES`. `\b` is ASCII, as in
/// JavaScript.
pub static SECRET_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----",
        r"(?-u:\b)sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{32,}",
        r"(?-u:\b)AKIA[0-9A-Z]{16}(?-u:\b)",
        r"(?-u:\b)gh[pousr]_[A-Za-z0-9]{36,}",
        r"(?-u:\b)github_pat_[A-Za-z0-9_]{40,}",
        r"(?-u:\b)xox[abprs]-[A-Za-z0-9-]{10,}",
        r"(?-u:\b)AIza[0-9A-Za-z_-]{35}(?-u:\b)",
        r"(?-u:\b)[0-9]{6,12}:AA[A-Za-z0-9_-]{33}(?-u:\b)",
        r"(?-u:\b)eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"(?-u:\b)vck_[A-Za-z0-9]{24,}",
    ]
    .iter()
    .map(|r| Regex::new(r).expect("valid regex"))
    .collect()
});

/// A text as the AI is sent it: what looks like a secret replaced, then cut into overlapping
/// pieces. `None` over `CONTENT_AI_TEXT_MAX`. Lengths count UTF-16 units, as the TS does.
pub fn ai_chunks(text: &str) -> Option<Vec<String>> {
    let mut out = text.to_string();
    for re in SECRET_RES.iter() {
        out = re.replace_all(&out, "[secret]").into_owned();
    }
    let units: Vec<u16> = out.encode_utf16().collect();
    if units.len() > CONTENT_AI_TEXT_MAX {
        return None;
    }
    let mut chunks = Vec::new();
    let mut at = 0;
    loop {
        chunks.push(crate::channels::js::js_slice_range(&units, at, at + CONTENT_AI_CHUNK));
        if at + CONTENT_AI_CHUNK >= units.len() {
            break;
        }
        at += CONTENT_AI_CHUNK - CONTENT_AI_OVERLAP;
    }
    Some(chunks)
}

pub const CONTENT_TEXT_MAX: usize = 65_536;
/// Email, web and app call bodies are longer than any chat message; more than this is stopped,
/// never cut.
pub const CONTENT_TEXT_MAX_LONG: usize = 524_288;
pub const CONTENT_EMAILS_BULK: usize = 5;

/// A rule as the engine reads it: the proxy's file has this shape (no `enabled`, only enabled rules).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `in`, `out` or `both`.
    pub direction: String,
    pub channels: Vec<String>,
    pub patterns: Vec<String>,
    pub detectors: Vec<String>,
    /// `log`, `hold` or `block`.
    pub action: String,
    pub reason: String,
    /// The rule as one sentence, judged by the AI on the firewall, never here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// Leaking secrets: ships with the firewall, on for every organization, not the web.
pub static CORE_SECRETS_RULE: LazyLock<EngineRule> = LazyLock::new(|| EngineRule {
    id: "core-leaking-secrets".into(),
    name: Some("Leaking secrets".into()),
    direction: "out".into(),
    channels: ["telegram", "slack", "email", "teamchat", "voice", "apps"]
        .map(String::from)
        .to_vec(),
    patterns: vec![],
    detectors: vec!["secrets".into()],
    action: "block".into(),
    reason: "it looks like it contains a password, key or token".into(),
    policy: None,
});

/// Weakest to strongest (`CONTENT_ACTIONS`); an unknown action is weaker than all.
fn strength(action: &str) -> i32 {
    match action {
        "log" => 0,
        "hold" => 1,
        "block" => 2,
        _ => -1,
    }
}

pub fn content_text_max(channel: &str) -> usize {
    if matches!(channel, "email" | "web" | "apps") {
        CONTENT_TEXT_MAX_LONG
    } else {
        CONTENT_TEXT_MAX
    }
}

fn is_word_char(c: Option<char>) -> bool {
    static WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\p{L}\p{N}_]$").expect("regex"));
    c.is_some_and(|c| WORD.is_match(c.encode_utf8(&mut [0; 4])))
}

/// Lower case, every run of spaces and line breaks (a non-breaking space included) one space: the
/// same set as the proxy's `_CONTENT_WS`.
pub fn fold(text: &str) -> String {
    static WS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new("[\t\n\x0b\x0c\r\x1c-\x1f \u{85}\u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}]+")
            .expect("regex")
    });
    let lower = text.to_lowercase();
    let one = WS.replace_all(&lower, " ");
    // `/^ | $/g`: one space off each end.
    let t = one.strip_prefix(' ').unwrap_or(&one);
    t.strip_suffix(' ').unwrap_or(t).to_string()
}

/// Length in code points, as Python counts it.
pub fn text_length(text: &str) -> usize {
    text.chars().count()
}

/// A word or phrase in a text, case-insensitive, on word edges, by a plain search: never a regular
/// expression, so a phrase cannot be made to backtrack.
#[cfg_attr(not(test), allow(dead_code))] // the TS exports it; the vectors test it
pub fn phrase_in(phrase: &str, text: &str) -> bool {
    phrase_in_folded(&fold(phrase), &fold(text))
}

fn phrase_in_folded(needle: &str, hay: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let start = from + i;
        let end = start + needle.len();
        if !is_word_char(hay[..start].chars().next_back()) && !is_word_char(hay[end..].chars().next()) {
            return true;
        }
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

fn iban_ok(candidate: &str) -> bool {
    let s: String = candidate.chars().filter(|c| *c != ' ').collect();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    let mut rest: u32 = 0;
    for c in s[4..].chars().chain(s[..4].chars()) {
        let Some(v) = c.to_digit(36) else { return false };
        for d in v.to_string().bytes() {
            rest = (rest * 10 + u32::from(d - b'0')) % 97;
        }
    }
    rest == 1
}

fn luhn_ok(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let total: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                if d > 4 { d * 2 - 9 } else { d * 2 }
            } else {
                d
            }
        })
        .sum();
    total.is_multiple_of(10)
}

/// `CARD_RE`, `/(?<![\d-])[2-6]\d{3}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\d-])/g`, as JavaScript
/// finds its matches: left to right, each start tried in the order a backtracking engine tries it.
/// The `regex` crate has no lookaround.
fn card_matches(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let edge = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit() || *c == b'-');
    let sep = |i: usize| b.get(i).is_some_and(|c| *c == b' ' || *c == b'-');
    let four = |i: usize| (i..i + 4).all(digit);
    // From `at`, the groups left (`left`, then the tail): the end of the first way through that
    // is not followed by a digit or a dash.
    fn groups(
        at: usize,
        left: u8,
        four: &dyn Fn(usize) -> bool,
        sep: &dyn Fn(usize) -> bool,
        digit: &dyn Fn(usize) -> bool,
        edge: &dyn Fn(usize) -> bool,
    ) -> Option<usize> {
        let starts = if sep(at) { vec![at + 1, at] } else { vec![at] };
        for s in starts {
            if left > 0 {
                if four(s)
                    && let Some(e) = groups(s + 4, left - 1, four, sep, digit, edge)
                {
                    return Some(e);
                }
            } else {
                let mut n = 0;
                while n < 7 && digit(s + n) {
                    n += 1;
                }
                for k in (1..=n).rev() {
                    if !edge(s + k) {
                        return Some(s + k);
                    }
                }
            }
        }
        None
    }
    let mut out = Vec::new();
    let mut p = 0;
    while p < b.len() {
        let ok_start = (b'2'..=b'6').contains(&b[p]) && (p == 0 || !(b[p - 1].is_ascii_digit() || b[p - 1] == b'-'));
        if ok_start
            && (p + 1..p + 4).all(digit)
            && let Some(e) = groups(p + 4, 2, &four, &sep, &digit, &edge)
        {
            out.push(&text[p..e]);
            p = e;
            continue;
        }
        p += 1;
    }
    out
}

pub fn detect(name: &str, text: &str) -> Result<bool, ContentError> {
    static IBAN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?-u:\b)[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?-u:\b)").expect("regex")
    });
    static EMAIL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}").expect("regex"));
    Ok(match name {
        "secrets" => SECRET_RES.iter().any(|r| r.is_match(text)),
        "iban" => IBAN.find_iter(&text.to_uppercase()).any(|m| iban_ok(m.as_str())),
        "card" => card_matches(text).into_iter().any(luhn_ok),
        "emails" => {
            let set: std::collections::HashSet<String> =
                EMAIL.find_iter(text).map(|m| m.as_str().to_lowercase()).collect();
            set.len() >= CONTENT_EMAILS_BULK
        }
        other => return Err(ContentError::Failed(format!("unknown detector {other}"))),
    })
}

fn covers(rule: &EngineRule, direction: &str, channel: &str) -> bool {
    (rule.direction == direction || rule.direction == "both") && rule.channels.iter().any(|c| c == channel || c == "*")
}

/// Whether any rule looks at this direction and channel: when none does, nothing is read.
pub fn content_applies(rules: &[EngineRule], direction: &str, channel: &str) -> bool {
    rules.iter().any(|r| covers(r, direction, channel))
}

/// What `evaluate` found: the rule whose action wins, and every rule that matched.
#[derive(Debug, Clone, Default)]
pub struct Found {
    pub rule: Option<EngineRule>,
    pub hits: Vec<EngineRule>,
}

fn strongest(hits: &[EngineRule]) -> Option<EngineRule> {
    let mut rule: Option<&EngineRule> = None;
    for hit in hits {
        if rule.is_none_or(|r| strength(&hit.action) > strength(&r.action)) {
            rule = Some(hit);
        }
    }
    rule.cloned()
}

/// Every rule that applies to this direction and channel and matches the text, and the one whose
/// action wins (block over hold over log; the first listed among equals). `TooLong` over the
/// channel's limit: the caller stops the message, never cuts it.
pub fn evaluate(rules: &[EngineRule], direction: &str, channel: &str, text: &str) -> Result<Found, ContentError> {
    if text_length(text) > content_text_max(channel) {
        return Err(ContentError::TooLong);
    }
    let mut folded: Option<String> = None;
    let mut hits = Vec::new();
    for r in rules {
        if !covers(r, direction, channel) {
            continue;
        }
        if !r.patterns.is_empty() && folded.is_none() {
            folded = Some(fold(text));
        }
        let hay = folded.as_deref().unwrap_or("");
        let mut hit = r.patterns.iter().any(|p| phrase_in_folded(&fold(p), hay));
        if !hit {
            for d in &r.detectors {
                if detect(d, text)? {
                    hit = true;
                    break;
                }
            }
        }
        if hit {
            hits.push(r.clone());
        }
    }
    Ok(Found {
        rule: strongest(&hits),
        hits,
    })
}

/// Whether a policy rule looks at this direction and channel: when none does, the model is not called.
#[cfg_attr(not(test), allow(dead_code))] // the TS exports it; its test uses it
pub fn policy_applies(rules: &[EngineRule], direction: &str, channel: &str) -> bool {
    rules
        .iter()
        .any(|r| r.policy.is_some() && covers(r, direction, channel))
}

/// The policy rules to ask the AI about, for a text the words and detectors have read: those that
/// cover it and did not match already; none when a rule already blocks it.
pub fn policies_to_ask(
    rules: &[EngineRule],
    direction: &str,
    channel: &str,
    found: &Found,
    text: &str,
) -> Vec<EngineRule> {
    if found.rule.as_ref().is_some_and(|r| r.action == "block") || text.trim().is_empty() {
        return vec![];
    }
    rules
        .iter()
        .filter(|r| {
            r.policy.as_deref().is_some_and(|p| !p.is_empty())
                && covers(r, direction, channel)
                && !found.hits.contains(r)
        })
        .cloned()
        .collect()
}

/// `withPolicies`'s answer: `found` with the AI's, and which rules the AI found (`found`) or acted
/// for because it could not run (`failed`), in order.
#[derive(Debug, Clone, Default)]
pub struct Judged {
    pub rule: Option<EngineRule>,
    pub hits: Vec<EngineRule>,
    pub ai: Vec<(String, &'static str)>,
}

impl Judged {
    pub fn by(&self, id: &str) -> Option<&'static str> {
        self.ai.iter().find(|(i, _)| i == id).map(|(_, b)| *b)
    }
}

/// `evaluate`'s answer with the AI's: the rules it matched, or every block and hold rule it was
/// asked about when it could not answer (`None`: fail closed); a log-only rule then records nothing.
pub fn with_policies(
    found: Found,
    asked: &[EngineRule],
    matched: Option<&std::collections::HashSet<String>>,
) -> Judged {
    static END: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ .]+$").expect("regex"));
    let more: Vec<&EngineRule> = asked
        .iter()
        .filter(|r| matched.map_or(r.action != "log", |m| m.contains(&r.id)))
        .collect();
    let mut ai = Vec::new();
    let by = if matched.is_some() { "found" } else { "failed" };
    for r in &more {
        // A `Map`: a repeated id keeps its place.
        if !ai.iter().any(|(i, _): &(String, &str)| *i == r.id) {
            ai.push((r.id.clone(), by));
        }
    }
    let mut hits = found.hits;
    for r in more {
        if matched.is_some() {
            hits.push(r.clone());
        } else {
            let mut r = r.clone();
            r.reason = format!("{} (the AI check could not run)", END.replace(&r.reason, ""));
            hits.push(r);
        }
    }
    Judged {
        rule: strongest(&hits),
        hits,
        ai,
    }
}

/// The most a compressed delivery is unpacked to: more than any body a webhook takes.
pub const DECODED_MAX: u64 = 16 * 1024 * 1024;

fn read_capped(r: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    r.take(DECODED_MAX + 1).read_to_end(&mut out)?;
    if out.len() as u64 > DECODED_MAX {
        return Err(std::io::Error::other("larger than a check unpacks"));
    }
    Ok(out)
}

/// A body with its `Content-Encoding` undone (gzip, deflate, br; the last applied listed last). An
/// error on any other: bytes the check cannot read would pass as "not text".
pub fn decode_body(body: &[u8], content_encoding: &str) -> Result<Vec<u8>, ContentError> {
    let failed = |_| ContentError::Failed("a body the firewall could not unpack".into());
    let mut out = body.to_vec();
    let codings: Vec<String> = content_encoding
        .split(',')
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    for coding in codings.iter().rev() {
        out = match coding.as_str() {
            "identity" => continue,
            "gzip" | "x-gzip" => read_capped(flate2::read::MultiGzDecoder::new(&out[..])).map_err(failed)?,
            // As the standard has it (zlib-wrapped), or raw, as some senders send it.
            "deflate" => read_capped(flate2::read::ZlibDecoder::new(&out[..]))
                .or_else(|_| read_capped(flate2::read::DeflateDecoder::new(&out[..])))
                .map_err(failed)?,
            "br" => read_capped(brotli_decompressor::Decompressor::new(&out[..], 4096)).map_err(failed)?,
            _ => {
                return Err(ContentError::Failed(
                    "a body in an encoding the firewall cannot read".into(),
                ));
            }
        };
    }
    Ok(out)
}

/// The words in a body for a gate: every string and number of a JSON document, the values of a
/// form, the text parts of a multipart body, or the text itself. `Ok(None)` when it is not text (a
/// file). Another charset than UTF-8 is read with what it has in common (its ASCII words), as the
/// proxy reads it. An error for a multipart body this firewall cannot read strictly.
pub fn body_text(body: &[u8], content_type: Option<&str>) -> Result<Option<String>, ContentError> {
    static TEXTUAL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^text/|json|xml|javascript|graphql|x-www-form-urlencoded").expect("regex"));
    static OPENS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*[\[{]").expect("regex"));
    let ctype = content_type.unwrap_or("").to_lowercase();
    if ctype.starts_with("multipart/") {
        return multipart_text(body, content_type.unwrap_or("")).map(Some);
    }
    let textual = TEXTUAL.is_match(&ctype);
    let text = match std::str::from_utf8(body) {
        Ok(t) => t.to_string(),
        Err(_) if !textual => return Ok(None),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    };
    // `TextDecoder` drops a byte order mark at the start.
    let text = text.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(text);
    if ctype.contains("application/x-www-form-urlencoded") {
        let values: Vec<String> = url::form_urlencoded::parse(text.as_bytes())
            .map(|(_, v)| v.into_owned())
            .collect();
        return Ok(Some(values.join("\n")));
    }
    if ctype.contains("json") || OPENS.is_match(&text) {
        match parse_json(&text) {
            Ok(v) => {
                let mut out = Vec::new();
                // Deeper than the walk goes: every string in it, escapes undone, rather than none.
                if !strings(&v, &mut out, 0) {
                    return Ok(Some(unescape_json_loose(&text)));
                }
                return Ok(Some(out.join("\n")));
            }
            // JSON serde_json refuses and `JSON.parse` may read (nested past serde_json's limit, a lone
            // surrogate escape), or not JSON at all: its escapes undone, so whatever a service decodes
            // of it was read. Text that is not JSON has no escapes to undo, and reads as it is.
            Err(_) => return Ok(Some(unescape_json_loose(&text))),
        }
    }
    if !ctype.is_empty() && !textual {
        return Ok(None);
    }
    Ok(Some(text))
}

/// The mark a number written in a document carries through the parse, so it is read as written
/// (`4111111111111111` is digits someone reads, and a long one would be rounded).
const NUMBER_MARK: &str = "\u{E000}#";

/// JSON with its numbers kept as written: each number outside a string becomes a string with
/// `NUMBER_MARK` and its text, before serde_json parses it.
fn parse_json(text: &str) -> Result<Value, serde_json::Error> {
    let mut out = String::with_capacity(text.len() + 16);
    let mut chars = text.char_indices().peekable();
    let mut in_string = false;
    while let Some((_, c)) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => {
                    if let Some((_, n)) = chars.next() {
                        out.push(n);
                    }
                }
                '"' => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '-' || c.is_ascii_digit() {
            let mut num = String::from(c);
            while let Some(&(_, n)) = chars.peek() {
                if n.is_ascii_digit() || matches!(n, '.' | 'e' | 'E' | '+' | '-') {
                    num.push(n);
                    chars.next();
                } else {
                    break;
                }
            }
            // What is a JSON number by its syntax is marked, whatever its range (`1e400` is one to
            // `JSON.parse`); anything else stays as it was, for serde to refuse.
            static NUMBER: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$").expect("regex"));
            if NUMBER.is_match(&num) {
                out.push('"');
                out.push_str(NUMBER_MARK);
                out.push_str(&num);
                out.push('"');
            } else {
                out.push_str(&num);
            }
        } else {
            out.push(c);
        }
    }
    serde_json::from_str(&out)
}

/// JSON escapes undone in a text that is JSON too deep to walk, so its strings read as written.
fn unescape_json_loose(text: &str) -> String {
    static ESC: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))"#).expect("regex"));
    ESC.replace_all(text, |c: &regex::Captures| {
        if let Some(h) = c.get(1) {
            // `String.fromCharCode`: one UTF-16 unit; a lone surrogate reads as the replacement.
            return u32::from_str_radix(h.as_str(), 16)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or('\u{FFFD}')
                .to_string();
        }
        match c.get(2).map(|m| m.as_str()) {
            Some("b") => "\u{8}".into(),
            Some("f") => "\u{c}".into(),
            Some("n") => "\n".into(),
            Some("r") => "\r".into(),
            Some("t") => "\t".into(),
            Some(o) => o.to_string(),
            None => String::new(),
        }
    })
    .into_owned()
}

fn failed(why: &str) -> ContentError {
    ContentError::Failed(why.into())
}

/// A part's headers, names in lower case. A repeated one fails: which copy counts is not ours to guess.
fn part_headers(head: &str) -> Result<Vec<(String, String)>, ContentError> {
    static LINE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)$").expect("regex"));
    let mut out: Vec<(String, String)> = Vec::new();
    if head.is_empty() {
        return Ok(out);
    }
    for line in head.split("\r\n") {
        if line.starts_with([' ', '\t'])
            && let Some(last) = out.last_mut()
        {
            // A folded header goes on.
            last.1 = format!("{} {}", last.1, line.trim());
            continue;
        }
        let m = LINE
            .captures(line)
            .ok_or_else(|| failed("a multipart part header the firewall cannot read"))?;
        let name = m[1].to_lowercase();
        if out.iter().any(|(n, _)| *n == name) {
            return Err(failed("a multipart part with a header twice"));
        }
        out.push((name, m[2].trim().to_string()));
    }
    Ok(out)
}

/// A header's parameters (`; name="value"`), names in lower case: `filename=` inside a quoted name
/// is not one.
fn header_params(value: &str) -> Vec<(String, String)> {
    static PARAM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#";\s*([^=;\s]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)"#).expect("regex"));
    static UNQUOTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\(.)").expect("regex"));
    PARAM
        .captures_iter(value)
        .map(|m| {
            let v = m[2].trim();
            let v = match v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                Some(inner) => UNQUOTE.replace_all(inner, "$1").into_owned(),
                None => v.to_string(),
            };
            (m[1].to_lowercase(), v)
        })
        .collect()
}

fn get<'a>(list: &'a [(String, String)], name: &str) -> Option<&'a str> {
    list.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The parts of a multipart body that are not files, each read as `body_text` reads a body, the
/// body read as Latin-1, byte for byte, as the TS does. Read strictly: a body with no parts, a
/// part with no blank line after its headers, a header twice, or an encoding other than as sent
/// fails, where it used to be skipped and its words passed unread.
fn multipart_text(body: &[u8], ctype: &str) -> Result<String, ContentError> {
    static BOUNDARY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)boundary="?([^";]{1,200})"?"#).expect("regex"));
    let boundary = BOUNDARY
        .captures(ctype)
        .and_then(|c| c.get(1))
        .ok_or_else(|| failed("a multipart body without a boundary"))?
        .as_str();
    // A boundary with a character Latin-1 has not never appears in the body.
    let mark = boundary
        .chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| failed("a multipart body without its boundary"))?;
    let mark = [b"--".as_slice(), &mark].concat();
    let parts = split_bytes(body, &mark);
    if parts.len() < 2 {
        return Err(failed("a multipart body without its boundary"));
    }
    let mut out = Vec::new();
    for part in parts.into_iter().skip(1) {
        if part.starts_with(b"--") {
            break;
        }
        let end = find_bytes(part, b"\r\n\r\n")
            .ok_or_else(|| failed("a multipart part without a blank line after its headers"))?;
        let head: String = part[..end].iter().map(|&b| char::from(b)).collect();
        let head = head.strip_prefix("\r\n").unwrap_or(&head);
        let headers = part_headers(head)?;
        let disposition = header_params(get(&headers, "content-disposition").unwrap_or(""));
        if get(&disposition, "filename").is_some() || get(&disposition, "filename*").is_some() {
            continue; // a file
        }
        if let Some(enc) = get(&headers, "content-transfer-encoding").map(|e| e.trim().to_lowercase())
            && !["7bit", "8bit", "binary"].contains(&enc.as_str())
        {
            return Err(failed("a multipart part in an encoding the firewall cannot read"));
        }
        let part_type = get(&headers, "content-type").unwrap_or("text/plain").to_string();
        let charset = get(&header_params(&part_type), "charset")
            .map(str::to_lowercase)
            .unwrap_or_default();
        let rest = &part[end + 4..];
        let rest = rest.strip_suffix(b"\r\n").unwrap_or(rest);
        // UTF-16 is read as UTF-16 (as bytes it would be noise); another charset by its ASCII
        // words, as a body is.
        let wide = |rest: &[u8], be: bool| {
            let units: Vec<u16> = rest
                .chunks(2)
                .map(|c| {
                    let (a, b) = (c[0], c.get(1).copied().unwrap_or(0));
                    if be {
                        u16::from_be_bytes([a, b])
                    } else {
                        u16::from_le_bytes([a, b])
                    }
                })
                .collect();
            String::from_utf16_lossy(&units)
        };
        // A byte order mark decides, and is not a word (beyond the TS, which reads UTF-16 as LE).
        let (rest, bom_be) = match rest {
            [0xFE, 0xFF, r @ ..] if charset.starts_with("utf-16") => (r, Some(true)),
            [0xFF, 0xFE, r @ ..] if charset.starts_with("utf-16") => (r, Some(false)),
            r => (r, None),
        };
        let text = match charset.as_str() {
            "utf-16" | "utf-16le" => Some(wide(rest, bom_be.unwrap_or(false))),
            "utf-16be" => Some(wide(rest, bom_be.unwrap_or(true))),
            _ => body_text(rest, Some(&part_type))?,
        };
        if let Some(text) = text
            && !text.is_empty()
        {
            out.push(text);
        }
    }
    Ok(out.join("\n"))
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn split_bytes<'a>(hay: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = hay;
    while let Some(i) = find_bytes(rest, sep) {
        out.push(&rest[..i]);
        rest = &rest[i + sep.len()..];
    }
    out.push(rest);
    out
}

/// Every string and number of a JSON value, in `Object.values` order (array-index keys first,
/// ascending). A string that is JSON is read inside too, and kept as written: the service shows it
/// as it is, keys included. False when it is nested deeper than 40.
fn strings(value: &Value, out: &mut Vec<String>, depth: usize) -> bool {
    static OPENS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*[\[{]").expect("regex"));
    if depth > 40 {
        return false;
    }
    match value {
        Value::String(s) => {
            if let Some(raw) = s.strip_prefix(NUMBER_MARK) {
                out.push(raw.to_string());
                return true;
            }
            if OPENS.is_match(s)
                && let Ok(inner) = parse_json(s)
                && !strings(&inner, out, depth + 1)
            {
                return false;
            }
            out.push(s.clone());
        }
        Value::Number(n) => out.push(n.to_string()),
        Value::Array(a) => {
            for v in a {
                if !strings(v, out, depth + 1) {
                    return false;
                }
            }
        }
        Value::Object(m) => {
            let index = |k: &str| k.parse::<u32>().ok().filter(|n| *n != u32::MAX && n.to_string() == k);
            let mut keyed: Vec<(u32, &Value)> = m.iter().filter_map(|(k, v)| index(k).map(|n| (n, v))).collect();
            keyed.sort_by_key(|(n, _)| *n);
            let rest = m.iter().filter(|(k, _)| index(k).is_none()).map(|(_, v)| v);
            for v in keyed.into_iter().map(|(_, v)| v).chain(rest) {
                if !strings(v, out, depth + 1) {
                    return false;
                }
            }
        }
        _ => {}
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_masked_and_long_text_cut_with_overlap() {
        let c = ai_chunks("key sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 here").expect("short");
        assert_eq!(c, vec!["key [secret] here".to_string()]);
        let long = "a".repeat(CONTENT_AI_CHUNK + 10);
        let c = ai_chunks(&long).expect("fits");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].len(), CONTENT_AI_CHUNK);
        assert_eq!(c[1].len(), 10 + CONTENT_AI_OVERLAP);
        assert!(ai_chunks(&"b".repeat(CONTENT_AI_TEXT_MAX + 1)).is_none());
        assert_eq!(ai_chunks(&"b".repeat(CONTENT_AI_TEXT_MAX)).expect("max").len(), 4);
        assert_eq!(ai_chunks("").expect("empty"), vec![String::new()]);
    }

    #[derive(serde::Deserialize)]
    struct Vectors {
        phrases: Vec<Phrase>,
        detectors: Vec<Detector>,
        rules: Vec<EngineRule>,
        evaluations: Vec<Evaluation>,
        limits: Vec<Limit>,
        lengths: Vec<Length>,
    }
    #[derive(serde::Deserialize)]
    struct Phrase {
        phrase: String,
        text: String,
        found: bool,
    }
    #[derive(serde::Deserialize)]
    struct Detector {
        detector: String,
        text: String,
        found: bool,
    }
    #[derive(serde::Deserialize)]
    struct Evaluation {
        direction: String,
        channel: String,
        text: String,
        rule: Option<String>,
        hits: Vec<String>,
        #[serde(default)]
        core: bool,
    }
    #[derive(serde::Deserialize)]
    struct Limit {
        channel: String,
        max: usize,
    }
    #[derive(serde::Deserialize)]
    struct Length {
        channel: String,
        repeat: String,
        count: usize,
        #[serde(rename = "tooLong")]
        too_long: bool,
    }

    /// The same cases the proxy's engine and the TS are held to.
    fn vectors() -> Vectors {
        serde_json::from_str(include_str!(
            "../../../../../packages/mitm-agent/src/content-vectors.json"
        ))
        .expect("vectors")
    }

    fn ids(rules: &[EngineRule]) -> Vec<&str> {
        rules.iter().map(|r| r.id.as_str()).collect()
    }

    #[test]
    fn phrases_whole_words_any_case_never_a_regex() {
        for v in vectors().phrases {
            assert_eq!(phrase_in(&v.phrase, &v.text), v.found, "{} in {}", v.phrase, v.text);
        }
    }

    #[test]
    fn detectors() {
        for v in vectors().detectors {
            assert_eq!(
                detect(&v.detector, &v.text).expect("known"),
                v.found,
                "{}: {}",
                v.detector,
                v.text
            );
        }
        assert!(detect("nope", "x").is_err());
        // Lookaround as JavaScript reads it: a card number inside a longer run of digits is not one.
        assert!(!detect("card", "4111 1111 1111 1111-2").expect("card"));
        assert!(detect("card", "4111-1111-1111-1111.").expect("card"));
    }

    #[test]
    fn evaluate_direction_channel_the_strongest_action_every_hit() {
        let v = vectors();
        for e in v.evaluations {
            let mut rules = if e.core {
                vec![CORE_SECRETS_RULE.clone()]
            } else {
                vec![]
            };
            rules.extend(v.rules.iter().cloned());
            let f = evaluate(&rules, &e.direction, &e.channel, &e.text).expect("evaluates");
            assert_eq!(f.rule.map(|r| r.id), e.rule, "{}", e.text);
            assert_eq!(ids(&f.hits), e.hits, "{}", e.text);
        }
    }

    #[test]
    fn limits_more_text_is_refused_never_cut() {
        let core = [CORE_SECRETS_RULE.clone()];
        for l in vectors().limits {
            assert_eq!(content_text_max(&l.channel), l.max);
            assert_eq!(
                evaluate(&core, "out", &l.channel, &"x".repeat(l.max + 1)).err(),
                Some(ContentError::TooLong)
            );
            evaluate(&core, "out", &l.channel, &"x".repeat(l.max)).expect("at the limit");
        }
    }

    #[test]
    fn length_is_counted_in_characters_as_the_proxy_counts_it() {
        let core = [CORE_SECRETS_RULE.clone()];
        for l in vectors().lengths {
            let r = evaluate(&core, "out", &l.channel, &l.repeat.repeat(l.count));
            assert_eq!(r.is_err(), l.too_long, "{} x{}", l.channel, l.count);
        }
    }

    #[test]
    fn content_applies_by_direction_and_channel() {
        let rules = vectors().rules;
        assert!(content_applies(&rules, "in", "webhook"));
        assert!(
            content_applies(&rules, "out", "webhook"),
            "pay covers every channel both ways"
        );
        assert!(!content_applies(&rules[..1], "in", "slack"));
    }

    #[test]
    fn body_text_reads_what_main_561_closed() {
        let t = |b: &[u8], c: &str| body_text(b, Some(c));
        let read = |b: &[u8], c: &str| t(b, c).expect("reads").expect("text");
        // Numbers as written: a card number and a long one, not rounded.
        assert_eq!(
            read(
                br#"{"n":4111111111111111,"x":12345678901234567890123,"f":1.50}"#,
                "application/json"
            ),
            "4111111111111111\n12345678901234567890123\n1.50"
        );
        // A string that is JSON is read inside, and kept as written.
        assert_eq!(
            read(br#"{"d":"{\"note\":\"the customer list\"}"}"#, "application/json"),
            "the customer list\n{\"note\":\"the customer list\"}"
        );
        // Too deep to walk: the escapes undone, so `\u0070assword` reads as `password`.
        let deep = format!("{}\"\\u0070assword\"{}", "[".repeat(45), "]".repeat(45));
        assert!(read(deep.as_bytes(), "application/json").contains("\"password\""));
        let deeper = format!("{}\"\\u0070assword\"{}", "[".repeat(200), "]".repeat(200));
        assert!(read(deeper.as_bytes(), "application/json").contains("\"password\""));
        // JSON serde refuses and `JSON.parse` reads (a number out of range, a lone surrogate):
        // escapes undone, not passed as written.
        assert!(read(br#"{"a":"\u0070assword","b":1e400}"#, "application/json").contains("password"));
        assert!(read(br#"{"a":"\u0070assword","b":"\ud800"}"#, "application/json").contains("password"));
        // Multipart, strictly.
        let mp = |parts: &str| {
            t(
                parts.replace('\n', "\r\n").as_bytes(),
                "multipart/form-data; boundary=XB",
            )
        };
        assert!(mp("--XB\nContent-Disposition: form-data; name=\"a\"\nwords with no blank line\n--XB--\n").is_err());
        assert!(t(b"no parts at all", "multipart/form-data; boundary=XB").is_err());
        assert!(mp("--XB\nContent-Type: text/plain\nContent-Type: text/html\n\nx\n--XB--\n").is_err());
        assert!(mp("--XB\nContent-Transfer-Encoding: base64\n\ndGhlIGN1c3RvbWVy\n--XB--\n").is_err());
        // A file only by its filename parameter: `filename=` inside a quoted name is not one.
        assert_eq!(
            mp("--XB\nContent-Disposition: form-data; name=\"x filename=y\"\n\nthe customer list\n--XB--\n")
                .expect("reads")
                .as_deref(),
            Some("the customer list")
        );
        // UTF-16 parts read as UTF-16.
        let words: Vec<u8> = "the list".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut body = b"--XB\r\nContent-Type: text/plain; charset=utf-16le\r\n\r\n".to_vec();
        body.extend(&words);
        body.extend(b"\r\n--XB--\r\n");
        assert_eq!(
            t(&body, "multipart/form-data; boundary=XB").expect("reads").as_deref(),
            Some("the list")
        );
        // A byte order mark decides the order.
        let be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain("the list".encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        let mut body = b"--XB\r\nContent-Type: text/plain; charset=utf-16\r\n\r\n".to_vec();
        body.extend(&be);
        body.extend(b"\r\n--XB--\r\n");
        assert_eq!(
            t(&body, "multipart/form-data; boundary=XB").expect("reads").as_deref(),
            Some("the list")
        );
    }

    #[test]
    fn body_text_json_strings_forms_text_not_files() {
        let t = |b: &[u8], c: &str| body_text(b, Some(c)).expect("reads");
        assert_eq!(
            t(br#"{"a":{"b":["the customer list",3]},"c":"x"}"#, "application/json").as_deref(),
            Some("the customer list\n3\nx")
        );
        assert_eq!(
            t(b"a=customer+list&b=%C3%A9", "application/x-www-form-urlencoded").as_deref(),
            Some("customer list\n\u{e9}")
        );
        assert_eq!(t(b"plain words", "text/plain").as_deref(), Some("plain words"));
        assert_eq!(t(b"{not json", "application/json").as_deref(), Some("{not json"));
        assert_eq!(t(&[0xff, 0xfe, 0x00], "application/octet-stream"), None);
        assert_eq!(t(b"readable", "image/png"), None);
        assert!(
            t(b"caf\xe9 customer list", "text/plain; charset=iso-8859-1")
                .expect("text")
                .contains("customer list")
        );
        // `Object.values`: index keys first.
        assert_eq!(
            t(br#"{"b":"two","1":"one","a":"three"}"#, "application/json").as_deref(),
            Some("one\ntwo\nthree")
        );
        let mp = [
            "--XB",
            "Content-Disposition: form-data; name=\"text\"",
            "",
            "the customer list",
            "--XB",
            "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"",
            "Content-Type: text/plain",
            "",
            "secret file words",
            "--XB--",
            "",
        ]
        .join("\r\n");
        let got = t(mp.as_bytes(), "multipart/form-data; boundary=XB").expect("text");
        assert!(got.contains("the customer list"));
        assert!(!got.contains("secret file words"));
        assert!(body_text(mp.as_bytes(), Some("multipart/form-data")).is_err());
    }

    fn rule(id: &str, policy: Option<&str>, action: &str, channels: &[&str], patterns: &[&str]) -> EngineRule {
        EngineRule {
            id: id.into(),
            name: None,
            direction: "both".into(),
            channels: channels.iter().map(|s| s.to_string()).collect(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            detectors: vec![],
            action: action.into(),
            reason: id.into(),
            policy: policy.map(String::from),
        }
    }

    #[test]
    fn policies_asked_only_for_what_covers_and_did_not_match_folded_in_fail_closed() {
        let pay = rule("pay", Some("No salaries."), "block", &["*"], &[]);
        let rules = vec![
            pay.clone(),
            rule("hold", Some("No customer lists."), "hold", &["*"], &[]),
            rule("log", Some("Note travel plans."), "log", &["*"], &[]),
            rule("word", Some("No payroll."), "block", &["*"], &["payroll"]),
            rule("voiceonly", Some("x"), "block", &["voice"], &[]),
        ];
        assert!(policy_applies(&rules, "in", "email"));
        assert!(!policy_applies(
            &[rule("p", None, "block", &["*"], &["a"])],
            "in",
            "email"
        ));
        let plain = evaluate(&rules, "in", "email", "hello").expect("ok");
        assert_eq!(
            ids(&policies_to_ask(&rules, "in", "email", &plain, "hello")),
            ["pay", "hold", "log", "word"]
        );
        let worded = evaluate(&rules, "in", "email", "the payroll").expect("ok");
        assert!(
            policies_to_ask(&rules, "in", "email", &worded, "the payroll").is_empty(),
            "a word already blocks it"
        );
        assert!(
            policies_to_ask(&rules, "in", "email", &plain, "  ").is_empty(),
            "nothing to read"
        );
        let asked = policies_to_ask(&rules, "in", "email", &plain, "hello");
        let matched: std::collections::HashSet<String> = ["hold".to_string(), "log".to_string()].into();
        let found = with_policies(plain.clone(), &asked, Some(&matched));
        assert_eq!(found.rule.as_ref().map(|r| r.id.as_str()), Some("hold"));
        assert_eq!(
            found.ai,
            vec![("hold".to_string(), "found"), ("log".to_string(), "found")]
        );
        let failed = with_policies(plain.clone(), &asked, None);
        assert_eq!(failed.rule.as_ref().map(|r| r.id.as_str()), Some("pay"));
        assert_eq!(
            failed.rule.as_ref().map(|r| r.reason.as_str()),
            Some("pay (the AI check could not run)")
        );
        let mut stop = pay.clone();
        stop.reason = "Pay is not discussed.".into();
        assert_eq!(
            with_policies(plain, &[stop], None).rule.map(|r| r.reason),
            Some("Pay is not discussed (the AI check could not run)".into()),
            "one full stop, after the note"
        );
        assert_eq!(
            ids(&failed.hits),
            ["pay", "hold", "word"],
            "a log-only policy records nothing when the AI could not run"
        );
    }
}
