//! Whether a received message really comes from its `From:` domain, from the provider's own verdict
//! (`email-auth.ts`, docs/plans/email-rules.md §2.1). The firewall never sees the raw message for
//! AgentMail and does not fetch it for Gmail, so it cannot check a DKIM signature itself: it
//! trusts the receiving server's `Authentication-Results`, and only the one that server wrote.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use super::schema::{RequireAuth, domain_of};

/// A refusal's reason: `unauthenticated`, `spam` or `bad_from`.
pub type Verdict = (Result<(), &'static str>, Option<String>);

pub struct AuthResult {
    pub method: String,
    pub result: String,
    pub props: HashMap<String, String>,
}

pub struct ParsedAuthResults {
    pub authserv_id: String,
    pub results: Vec<AuthResult>,
}

static FOLD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n[ \t]+").expect("regex"));
static AUTHSERV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9.-]+$").expect("regex"));
static METHOD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^([a-z0-9-]+)=([a-z0-9]+)$").expect("regex"));
static PROP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^([a-z0-9-]+\.[a-z0-9-]+)=(.+)$").expect("regex"));
static SIGNER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[a-z0-9.-]+$").expect("regex"));
static ANGLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^<>]*)>\s*$").expect("regex"));
static LOCAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[^\s@"<>()\\\[\],;:]+$"#).expect("regex"));
static HEADER_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([!-9;-~]+):([^\r\n\u{2028}\u{2029}]*)$").expect("regex"));
static BLANK_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n\r?\n").expect("regex"));
static NEWLINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n").expect("regex"));

use crate::channels::js::js_len;

/// Remove RFC 5322 comments `( … )`, which may nest and may hold `;`.
fn strip_comments(value: &str) -> String {
    let mut out = String::new();
    let mut depth = 0u32;
    let mut quoted = false;
    let mut it = value.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\'
            && let Some(&n) = it.peek()
        {
            it.next();
            if depth == 0 {
                out.push(c);
                out.push(n);
            }
            continue;
        }
        if c == '"' && depth == 0 {
            quoted = !quoted;
        }
        if !quoted && c == '(' {
            depth += 1;
        } else if !quoted && c == ')' && depth > 0 {
            depth -= 1;
        } else if depth == 0 {
            out.push(c);
        }
    }
    out
}

/// Parse one `Authentication-Results` value (RFC 8601). `None` when it does not parse.
pub fn parse_auth_results(value: &str) -> Option<ParsedAuthResults> {
    if js_len(value) > 8192 {
        return None;
    }
    let cleaned = strip_comments(&FOLD.replace_all(value, " "));
    let mut parts = cleaned.split(';').map(str::trim).filter(|p| !p.is_empty());
    let head = parts.next()?;
    let authserv_id = head.split_whitespace().next().unwrap_or("").to_lowercase();
    if !AUTHSERV.is_match(&authserv_id) {
        return None;
    }
    let mut results = vec![];
    for part in parts {
        let mut tokens = part.split_whitespace();
        let Some(m) = METHOD.captures(tokens.next().unwrap_or("")) else {
            continue;
        };
        let mut props = HashMap::new();
        for t in tokens {
            if let Some(p) = PROP.captures(t) {
                let v = &p[2];
                let v = v.strip_prefix('"').unwrap_or(v);
                let v = v.strip_suffix('"').unwrap_or(v);
                props.insert(p[1].to_lowercase(), v.to_string());
            }
        }
        results.push(AuthResult {
            method: m[1].to_lowercase(),
            result: m[2].to_lowercase(),
            props,
        });
    }
    Some(ParsedAuthResults { authserv_id, results })
}

/// The single address in a `From:` value (`Name <a@b>` or `a@b`). `None` for none, several, or a
/// group: the agent must never have to guess which sender a message is from.
pub fn parse_from_address(value: &str) -> Option<String> {
    if js_len(value) > 2048 {
        return None;
    }
    let v = strip_comments(value);
    let v = v.trim();
    let mut quoted = false;
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            it.next();
            continue;
        }
        if c == '"' {
            quoted = !quoted;
        } else if !quoted && matches!(c, ',' | ';' | ':') {
            return None;
        }
    }
    if quoted {
        return None;
    }
    let angle = ANGLE.captures(v);
    if angle.is_some() && v.find('<') != v.rfind('<') {
        return None;
    }
    let addr = angle
        .as_ref()
        .map_or(v, |a| a.get(1).map_or("", |m| m.as_str()))
        .trim()
        .to_lowercase();
    if angle.is_none() && addr.chars().any(char::is_whitespace) {
        return None;
    }
    let at = addr.rfind('@').filter(|&at| at > 0)?;
    if !LOCAL.is_match(&addr[..at]) {
        return None;
    }
    domain_of(&addr).map(|_| addr)
}

/// DKIM signing domain from `header.d`, or the domain of `header.i` (`@x.com` or `u@x.com`).
fn signing_domain(r: &AuthResult) -> Option<String> {
    if let Some(d) = r.props.get("header.d").filter(|d| !d.is_empty()) {
        return SIGNER.is_match(d).then(|| d.to_lowercase());
    }
    let i = r.props.get("header.i").filter(|i| !i.is_empty())?;
    let dom = i.rfind('@').map_or(i.as_str(), |at| &i[at + 1..]).to_lowercase();
    AUTHSERV.is_match(&dom).then_some(dom)
}

/// Relaxed alignment without a public-suffix list: the signing domain equals the From domain, or one
/// is a subdomain of the other. A signing domain without a dot is never accepted.
pub fn aligned(from_domain: &str, signer: &str) -> bool {
    signer.contains('.')
        && (from_domain == signer
            || from_domain.ends_with(&format!(".{signer}"))
            || signer.ends_with(&format!(".{from_domain}")))
}

/// The pass/fail decision on one parsed header, for one From domain.
pub fn passes(ar: &ParsedAuthResults, from_domain: &str, require: RequireAuth) -> bool {
    if let Some(dmarc) = ar.results.iter().find(|r| r.method == "dmarc")
        && dmarc.result == "pass"
    {
        match dmarc.props.get("header.from").filter(|h| !h.is_empty()) {
            None => return true,
            Some(hf) if hf.to_lowercase() == from_domain => return true,
            _ => {}
        }
    }
    if require == RequireAuth::Dmarc {
        return false;
    }
    ar.results.iter().any(|r| {
        r.method == "dkim" && r.result == "pass" && signing_domain(r).is_some_and(|s| aligned(from_domain, &s))
    })
}

#[derive(Debug, Clone)]
pub struct GmailHeader {
    pub name: String,
    pub value: String,
}

/// A Gmail message, from `messages.get?format=metadata`. Gmail returns headers top to bottom and
/// writes its own block first, so its `Authentication-Results` is the FIRST header with that exact
/// name. `ARC-Authentication-Results` is not it; a header the sender wrote comes later.
pub fn gmail_verdict(headers: &[GmailHeader], labels: &[String], require: RequireAuth) -> Verdict {
    let froms: Vec<_> = headers.iter().filter(|h| h.name.eq_ignore_ascii_case("from")).collect();
    let from = if froms.len() == 1 {
        parse_from_address(&froms[0].value)
    } else {
        None
    };
    let Some(from) = from else {
        return (Err("bad_from"), None);
    };
    if labels.iter().any(|l| l == "SPAM" || l == "TRASH") {
        return (Err("spam"), Some(from));
    }
    let ar = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authentication-results"))
        .and_then(|h| parse_auth_results(&h.value));
    let ok = ar.is_some_and(|ar| {
        ar.authserv_id == "mx.google.com" && domain_of(&from).is_some_and(|d| passes(&ar, &d, require))
    });
    (if ok { Ok(()) } else { Err("unauthenticated") }, Some(from))
}

/// An AgentMail received message. The gate is AgentMail's own verdict: the labels and the
/// structured `authentication_results`. DMARC must pass, whatever `requireAuth` says: the
/// structured field does not say which domain a DKIM signature was for, so an aligned-DKIM pass
/// cannot be trusted here and this fails closed. AgentMail's own `amazonses.com` header can still
/// narrow: if it names a different From domain, the message is refused.
pub fn agentmail_verdict(msg: &Map<String, Value>) -> Verdict {
    let Some(from) = msg.get("from").and_then(Value::as_str).and_then(parse_from_address) else {
        return (Err("bad_from"), None);
    };
    let labels: Vec<&str> = msg
        .get("labels")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if labels.contains(&"spam") || labels.contains(&"blocked") {
        return (Err("spam"), Some(from));
    }
    if labels.contains(&"unauthenticated") || !labels.contains(&"received") {
        return (Err("unauthenticated"), Some(from));
    }
    let dmarc_pass = msg
        .get("authentication_results")
        .and_then(Value::as_object)
        .and_then(|a| a.get("dmarc"))
        .and_then(Value::as_str)
        == Some("pass");
    if !dmarc_pass {
        return (Err("unauthenticated"), Some(from));
    }
    let raw = msg
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("authentication-results")))
        .and_then(|(_, v)| v.as_str());
    if let Some(ar) = raw.and_then(parse_auth_results) {
        let hf = ar
            .results
            .iter()
            .find(|r| r.method == "dmarc")
            .and_then(|r| r.props.get("header.from"))
            .filter(|h| !h.is_empty())
            .map(|h| h.to_lowercase());
        if ar.authserv_id == "amazonses.com"
            && let Some(hf) = hf
            && Some(hf) != domain_of(&from)
        {
            return (Err("unauthenticated"), Some(from));
        }
    }
    (Ok(()), Some(from))
}

/// Every address in an address-list header value (`To:`, `Cc:`, `Bcc:`), group members included.
/// `None` when anything does not parse: recipients the firewall cannot read are refused.
pub fn parse_address_list(value: &str) -> Option<Vec<String>> {
    if js_len(value) > 65536 {
        return None;
    }
    let v = strip_comments(&FOLD.replace_all(value, " "));
    let mut items: Vec<String> = vec![];
    let mut cur = String::new();
    let (mut quoted, mut angle) = (false, false);
    let mut it = v.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\'
            && let Some(&n) = it.peek()
        {
            it.next();
            cur.push(c);
            cur.push(n);
            continue;
        }
        if c == '"' && !angle {
            quoted = !quoted;
        } else if !quoted && c == '<' {
            if angle {
                return None;
            }
            angle = true;
        } else if !quoted && c == '>' {
            if !angle {
                return None;
            }
            angle = false;
        }
        if !quoted && !angle && (c == ',' || c == ';') {
            items.push(std::mem::take(&mut cur));
            continue;
        }
        if !quoted && !angle && c == ':' {
            // `Group name: a@b, c@d;`: drop the display name, keep the members. A "name" holding an
            // address is not a group name: refused rather than drop a recipient.
            if cur.contains(['@', '<', '>']) {
                return None;
            }
            cur.clear();
            continue;
        }
        cur.push(c);
    }
    if quoted || angle {
        return None;
    }
    items.push(cur);
    let mut out = vec![];
    for raw in items {
        if raw.trim().is_empty() {
            continue;
        }
        out.push(parse_from_address(&raw)?);
    }
    Some(out)
}

/// AgentMail `to`/`cc`/`bcc`: a string or a list of strings, each possibly `Name <a@b>`.
pub fn parse_address_field(value: Option<&Value>) -> Option<Vec<String>> {
    let list: Vec<&Value> = match value {
        None | Some(Value::Null) => return Some(vec![]),
        Some(s @ Value::String(_)) => vec![s],
        Some(Value::Array(a)) => a.iter().collect(),
        _ => return None,
    };
    if list.len() > 100 {
        return None;
    }
    let mut out = vec![];
    for v in list {
        out.extend(parse_address_list(v.as_str()?)?);
    }
    Some(out)
}

/// The recipients of a raw RFC 822 message, from its header block only (never the body). `None`
/// when the block does not parse, or carries `Resent-*` headers (a second set of recipients).
pub fn recipients_from_header_block(head: &str) -> Option<Vec<String>> {
    if js_len(head) > 262144 {
        return None;
    }
    let block = BLANK_LINE.find(head).map_or(head, |m| &head[..m.start()]);
    let block = FOLD.replace_all(block, " ");
    let mut out = vec![];
    for line in NEWLINE.split(&block) {
        if line.is_empty() {
            continue;
        }
        let m = HEADER_LINE.captures(line)?;
        let name = m[1].to_lowercase();
        if name.starts_with("resent-") {
            return None;
        }
        if !matches!(name.as_str(), "to" | "cc" | "bcc") {
            continue;
        }
        out.extend(parse_address_list(&m[2])?);
    }
    Some(out)
}
