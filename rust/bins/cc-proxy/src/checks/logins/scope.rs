//! Where a password may be put in (docs/plans/login-swap-scope.md, addon.py 2090-2790): the body of
//! a POST or PUT, over https, to the login's sign-in page, to a form target read off that page
//! that the owner approved, or to an address the owner added; a login saved as HTTP Basic in
//! `Authorization: Basic` and nowhere else. Everything here reads a request the one way every
//! server reads it, and refuses what some server could read another way.

use base64::Engine;
use serde_json::Value;

use super::find::Finder;
use crate::checks::body;
use crate::checks::creds::{ascii_host, truthy};
use crate::checks::json as cjson;
use crate::checks::record::secret_host_matches;
use crate::flow::Flow;

pub const LOGIN_BODY_MAX: usize = 64 * 1024;
pub const LOGIN_FIELDS_MAX: usize = 200;
pub const LOGIN_JSON_DEPTH_MAX: usize = 8;
pub const NAVIGATION_HEADERS: &[&str] = &["referer", "origin", "ping-from", "ping-to"];
const METHOD_OVERRIDE_HEADERS: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];

/// This request does not have the exact shape of a sign-in; the reason on the record.
#[derive(Debug, Clone, PartialEq)]
pub struct NotASignIn(pub &'static str);

/// A sign-in address: a host, a port, one exact path (or under it, for an owner's `/*`), and its
/// query pairs, sorted.
#[derive(Debug, Clone, PartialEq)]
pub struct Address {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub prefix: bool,
    pub owner: bool,
}

// ---- the request as a server reads it -----------------------------------------------------------

pub fn is_https(flow: &Flow) -> bool {
    flow.request.as_ref().is_some_and(|r| match r.uri().scheme_str() {
        Some(s) => s == "https",
        // Origin-form inside TLS: the plumbing intercepted a TLS connection.
        None => flow.sni.is_some(),
    })
}

pub fn port(flow: &Flow) -> u16 {
    flow.destination()
        .map(|d| d.port)
        .or_else(|| flow.request.as_ref().and_then(|r| r.uri().port_u16()))
        .unwrap_or(if is_https(flow) { 443 } else { 80 })
}

/// `flow.request.path`: the path and the query as sent.
pub fn target(flow: &Flow) -> String {
    flow.request
        .as_ref()
        .map(|r| {
            r.uri()
                .path_and_query()
                .map_or_else(|| r.uri().path().to_owned(), |pq| pq.as_str().to_owned())
        })
        .unwrap_or_default()
}

pub fn method(flow: &Flow) -> String {
    flow.request
        .as_ref()
        .map(|r| r.method().as_str().to_owned())
        .unwrap_or_default()
}

/// Every value of a header, as sent.
pub fn header_values(flow: &Flow, name: &str) -> Vec<String> {
    flow.request
        .as_ref()
        .map(|r| {
            r.headers()
                .get_all(name)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

pub fn header_names(flow: &Flow) -> Vec<String> {
    let mut names: Vec<String> = flow
        .request
        .as_ref()
        .map(|r| r.headers().keys().map(|k| k.as_str().to_lowercase()).collect())
        .unwrap_or_default();
    names.sort();
    names.dedup();
    names
}

/// `_plain_path`: the path without its query, or `None` when a server could read it as another
/// path (dot segments, doubled or encoded slashes, backslashes, `;`, an encoded percent, a fragment).
pub fn plain_path(path: &str) -> Option<String> {
    if path.contains('#') {
        return None;
    }
    let only = path.split('?').next().unwrap_or("");
    let low = only.to_lowercase();
    if !only.starts_with('/') || only.contains("//") || only.contains('\\') || only.contains(';') {
        return None;
    }
    if ["%2f", "%5c", "%2e", "%00", "%25", "%3b", "%23", "%3f"]
        .iter()
        .any(|t| low.contains(t))
    {
        return None;
    }
    if only.split('/').any(|s| s == "." || s == "..") {
        return None;
    }
    Some(only.to_owned())
}

/// `_decode_once`: percent-decoded once, `+` as a space; `None` unless it is well-formed UTF-8.
pub fn decode_once(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = |c: u8| (c as char).to_digit(16);
                let (Some(x), Some(y)) = (b.get(i + 1).and_then(|c| h(*c)), b.get(i + 2).and_then(|c| h(*c))) else {
                    return None;
                };
                out.push((x * 16 + y) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn field_name(k: &str) -> bool {
    (1..=64).contains(&k.len())
        && k.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// A field name as servers that fold names read it.
pub fn fold(name: &str) -> String {
    name.to_lowercase().replace('.', "_")
}

/// `_strict_pairs`: the `key=value` pairs read the one way every server reads them, or `None`.
pub fn strict_pairs(raw: &str) -> Option<Vec<(String, String)>> {
    if raw.is_empty() {
        return Some(Vec::new());
    }
    if raw.bytes().any(|c| !(0x21..=0x7e).contains(&c) || c == b';') {
        return None;
    }
    let pieces: Vec<&str> = raw.split('&').collect();
    if pieces.len() > LOGIN_FIELDS_MAX {
        return None;
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for piece in pieces {
        let (k, v) = piece.split_once('=')?;
        let (k, v) = (decode_once(k)?, decode_once(v)?);
        if !field_name(&k) || !seen.insert(fold(&k)) {
            return None;
        }
        out.push((k, v));
    }
    Some(out)
}

/// `urllib.parse.quote_plus(s, safe=...)`.
pub fn quote_plus(s: &str, safe: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "_.-~".contains(c) || (c.is_ascii() && safe.contains(c)) {
            out.push(c);
        } else if c == ' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote(s, safe="")`.
pub fn quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "_.-~".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `unquote_plus`.
pub fn unquote_plus(s: &str) -> String {
    body::unquote(&s.replace('+', " "))
}

// ---- sign-in addresses --------------------------------------------------------------------------

struct Split {
    scheme: String,
    userinfo: bool,
    hostname: Option<String>,
    port: Option<Result<u16, ()>>,
    path: String,
    query: String,
    fragment: bool,
}

/// `urllib.parse.urlsplit`, the parts a sign-in address needs.
fn urlsplit(spec: &str) -> Option<Split> {
    let (scheme, rest) = spec.split_once("://")?;
    let scheme = scheme.to_lowercase();
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (netloc, tail) = rest.split_at(end);
    let (tail, fragment) = match tail.split_once('#') {
        Some((t, _)) => (t, true),
        None => (tail, false),
    };
    let (path, query) = tail.split_once('?').map_or((tail, ""), |(p, q)| (p, q));
    let (userinfo, hostport) = match netloc.rsplit_once('@') {
        Some((_, hp)) => (true, hp),
        None => (false, netloc),
    };
    let (hostname, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        (h.to_owned(), after.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (hostport.to_owned(), None),
        }
    };
    let port = port.filter(|p| !p.is_empty()).map(|p| {
        if p.bytes().all(|c| c.is_ascii_digit()) {
            p.parse::<u16>().map_err(|_| ())
        } else {
            Err(())
        }
    });
    Some(Split {
        scheme,
        userinfo,
        hostname: Some(hostname.to_lowercase()).filter(|h| !h.is_empty()),
        port,
        path: path.to_owned(),
        query: query.to_owned(),
        fragment,
    })
}

/// `_sign_in_address`: a full https address, or (with `default`) an owner's `/path` or `host/path`.
pub fn sign_in_address(spec: &str, default: Option<(&str, u16)>) -> Option<Address> {
    if spec.is_empty() || spec.chars().count() > 2048 || spec.chars().any(|c| body::is_py_space(c) || (c as u32) < 32) {
        return None;
    }
    let mut owner = false;
    let (host, port, mut path, query) = if spec.contains("://") {
        let u = urlsplit(spec)?;
        let port = match u.port {
            Some(Err(())) => return None,
            Some(Ok(p)) => Some(p),
            None => None,
        };
        if u.scheme != "https" || u.userinfo || u.fragment {
            return None;
        }
        let hostname = u.hostname?;
        let path = if u.path.is_empty() { "/".to_owned() } else { u.path };
        (
            ascii_host(&hostname),
            port.filter(|p| *p != 0).unwrap_or(443),
            path,
            u.query,
        )
    } else if let Some((h, p)) = default.filter(|_| spec.starts_with('/')) {
        owner = true;
        let (path, query) = spec.split_once('?').map_or((spec, ""), |(a, b)| (a, b));
        (Some(h.to_owned()), p, path.to_owned(), query.to_owned())
    } else if default.is_some() {
        owner = true;
        let (name, rest) = spec.split_once('/')?;
        let tail = format!("/{rest}");
        let (path, query) = tail.split_once('?').map_or((tail.as_str(), ""), |(a, b)| (a, b));
        (ascii_host(name), 443, path.to_owned(), query.to_owned())
    } else {
        return None;
    };
    let host = host?;
    let prefix = owner && path.ends_with("/*") && query.is_empty();
    if prefix {
        path.pop();
    }
    if owner && path == "/" {
        return None;
    }
    if path.contains('#')
        || query.contains('#')
        || path.contains('*')
        || plain_path(&path).as_deref() != Some(path.as_str())
    {
        return None;
    }
    let mut pairs = strict_pairs(&query)?;
    if spec.contains('?') && pairs.is_empty() {
        return None;
    }
    pairs.sort();
    Some(Address {
        host,
        port,
        path,
        query: pairs,
        prefix,
        owner,
    })
}

/// `_address_text`.
pub fn address_text(a: &Address) -> String {
    let port = if a.port == 443 {
        String::new()
    } else {
        format!(":{}", a.port)
    };
    let q = if a.query.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            a.query
                .iter()
                .map(|(k, v)| format!("{}={}", quote_plus(k, ""), quote_plus(v, "")))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    format!("https://{}{port}{}{q}", a.host, a.path)
}

/// `_goes_to`: https, the address's host and port, its exact path (or under it for `/*`) and
/// exactly its query.
pub fn goes_to(flow: &Flow, host: &str, a: &Address) -> bool {
    if !is_https(flow) || ascii_host(host).as_deref() != Some(a.host.as_str()) || port(flow) != a.port {
        return false;
    }
    let t = target(flow);
    let Some(path) = plain_path(&t) else { return false };
    if !(if a.prefix {
        path.starts_with(&a.path)
    } else {
        path == a.path
    }) {
        return false;
    }
    let Some((_, query)) = t.split_once('?') else {
        return a.query.is_empty();
    };
    if a.query.is_empty() {
        return false;
    }
    strict_pairs(query).is_some_and(|mut p| {
        p.sort();
        p == a.query
    })
}

/// `_login_page`: the sign-in page as an address, never the top of a site.
pub fn login_page(cred: &Value) -> Option<Address> {
    sign_in_address(&str_of(cred, "login_url"), None).filter(|p| p.path != "/")
}

pub fn str_of(v: &Value, k: &str) -> String {
    match v.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => crate::checks::telegram::py_str(other),
    }
}

/// A list of strings on a credential (`cred.get(key) or []`), each as Python's `str()` gives it.
pub fn cred_list(cred: &Value, key: &str) -> Vec<String> {
    cred.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| {
                    v.as_str()
                        .map_or_else(|| crate::checks::telegram::py_str(v), str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `_login_host`.
pub fn login_host(cred: &Value, host: &str) -> bool {
    cred.get("allowed_hosts").and_then(Value::as_array).is_some_and(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .any(|p| secret_host_matches(p, host) || secret_host_matches(&ascii_pattern(p), host))
    })
}

fn ascii_pattern(p: &str) -> String {
    let star = if p.starts_with("*.") { "*." } else { "" };
    let rest = &p[star.len()..];
    format!("{star}{}", ascii_host(rest).unwrap_or_else(|| rest.to_owned()))
}

// ---- where the stand-in is ----------------------------------------------------------------------

/// `_spellings`: as it is, percent-decoded (twice), and with `\uXXXX` escapes read.
pub fn spellings(text: &str) -> Vec<String> {
    let mut out = vec![text.to_owned()];
    if text.contains('%') || text.contains('+') {
        let once = unquote_plus(text);
        if once.contains('%') {
            out.push(unquote_plus(&once));
        }
        out.push(once);
    }
    if text.contains("\\u") {
        out.push(u_escapes(text));
    }
    out
}

fn u_escapes(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("\\u") {
        out.push_str(&rest[..i]);
        let hex = rest
            .get(i + 2..i + 6)
            .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()));
        match hex.and_then(|h| u32::from_str_radix(h, 16).ok()) {
            Some(n) => {
                out.push(char::from_u32(n).unwrap_or('\u{fffd}'));
                rest = &rest[i + 6..];
            }
            None => {
                out.push_str("\\u");
                rest = &rest[i + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn carries(found: &Finder, text: &str) -> bool {
    spellings(text).iter().any(|t| found.search(t))
}

/// `wire` in `_login_destination_ok`: the ASCII name, or the name lower-cased when it is not a
/// host name, so two different names never compare equal.
pub fn wire_host(name: &str) -> String {
    ascii_host(name).unwrap_or_else(|| name.to_lowercase().trim_end_matches('.').to_owned())
}

/// `_basic_credentials`: the `user:password` of a Basic `Authorization` value.
pub fn basic_credentials(value: &str) -> Option<String> {
    // `get`: a value whose sixth byte is inside a character is not Basic (no panic).
    if !value.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("basic ")) {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value[6..].trim_matches(body::is_py_space))
        .ok()?;
    String::from_utf8(raw).ok()
}

/// `_login_places`.
#[derive(Debug, Default)]
pub struct Places {
    pub in_path: bool,
    pub in_query: bool,
    pub in_body: bool,
    pub headers: Vec<String>,
}

impl Places {
    pub fn any(&self) -> bool {
        self.in_path || self.in_query || self.in_body || !self.headers.is_empty()
    }
}

/// The request body with its `content-encoding` undone (mitmproxy's `get_content`): the plumbing
/// passes bodies de-chunked but still encoded. `None` when the encoding is unknown or the bytes do
/// not decode; an empty body for no request.
pub fn content(flow: &Flow) -> Option<bytes::Bytes> {
    flow.request.as_ref().map_or(Some(bytes::Bytes::new()), |r| {
        crate::http::body::decoded(r.headers(), r.body())
    })
}

/// `get_text(strict=False)` on the request, `""` when its encoding cannot be undone (the addon's
/// `except ValueError: body = ""`).
pub fn request_text(flow: &Flow) -> String {
    text_of(flow, content(flow).as_ref())
}

fn text_of(flow: &Flow, content: Option<&bytes::Bytes>) -> String {
    let ct = flow
        .request
        .as_ref()
        .map(|r| body::content_type(r.headers()))
        .unwrap_or_default();
    content.map(|c| body::get_text(&ct, c)).unwrap_or_default()
}

pub fn places(flow: &Flow, placeholder: &str) -> Places {
    let found = Finder::new(placeholder);
    let seen = |t: &str| carries(&found, t);
    // The bytes as sent (`raw_content`, still encoded) and as decoded, and the text: the addon
    // reads the bytes as sent only; the decoded ones are read too, so an encoded body hides nothing.
    let raw = flow.request.as_ref().map(|r| r.body().clone()).unwrap_or_default();
    let decoded = content(flow);
    let text = text_of(flow, decoded.as_ref());
    let mut bytes = vec![&raw];
    if let Some(d) = decoded.as_ref().filter(|d| **d != raw) {
        bytes.push(d);
    }
    let small = bytes.iter().all(|b| b.len() <= 4 * LOGIN_BODY_MAX);
    let mut in_body = false;
    for b in &bytes {
        let plain: String = b.iter().map(|c| char::from(*c)).collect();
        in_body |= if small {
            seen(&text) || seen(&plain)
        } else {
            found.search(&text) || found.search(&plain)
        };
        if !in_body && small && !b.is_empty() && b.contains(&0) {
            // A form sent as UTF-16 reads as the stand-in to a server that honours the charset.
            in_body = [true, false].iter().any(|le| found.search(&utf16_ignore(b, *le)));
        }
    }
    let t = target(flow);
    let (path_only, query) = t.split_once('?').unwrap_or((&t, ""));
    let mut headers = Vec::new();
    for name in header_names(flow) {
        if NAVIGATION_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let values = header_values(flow, &name);
        let decoded: Vec<String> = if name == "authorization" || name == "proxy-authorization" {
            values.iter().filter_map(|v| basic_credentials(v)).collect()
        } else {
            Vec::new()
        };
        if values.iter().chain(&decoded).any(|v| seen(v)) {
            headers.push(name);
        }
    }
    Places {
        in_path: seen(path_only),
        in_query: seen(query),
        in_body,
        headers,
    }
}

fn utf16_ignore(raw: &[u8], le: bool) -> String {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if le {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    char::decode_utf16(units).filter_map(Result::ok).collect()
}

/// `_only_basic_header`.
pub fn only_basic_header(flow: &Flow, p: &Places, placeholder: Option<&str>) -> bool {
    if p.in_path || p.in_query || p.in_body || p.headers != ["authorization"] {
        return false;
    }
    let decoded: Vec<Option<String>> = header_values(flow, "authorization")
        .iter()
        .map(|v| basic_credentials(v))
        .collect();
    if decoded.len() != 1 {
        return false;
    }
    let Some(d) = &decoded[0] else { return false };
    placeholder.is_none_or(|ph| d.split_once(':').map_or("", |(_, pw)| pw) == ph)
}

/// `_content_type`: `form` or `json`, said the way a browser says it, or `None`.
pub fn sign_in_content_type(flow: &Flow) -> Option<&'static str> {
    let lines = header_values(flow, "content-type");
    if lines.len() != 1 {
        return None;
    }
    let l = lines[0].as_str();
    let (kind, rest) = if let Some(r) = l.strip_prefix("application/x-www-form-urlencoded") {
        ("form", r)
    } else {
        ("json", l.strip_prefix("application/json")?)
    };
    matches!(
        rest,
        "" | ";charset=utf-8" | "; charset=utf-8" | ";charset=UTF-8" | "; charset=UTF-8"
    )
    .then_some(kind)
}

/// `_body_text`: the body as UTF-8, refused when long, compressed, not UTF-8 or marked.
pub fn body_text(flow: &Flow) -> Result<String, NotASignIn> {
    let raw = flow.request.as_ref().map(|r| r.body().to_vec()).unwrap_or_default();
    let encoded = header_values(flow, "content-encoding")
        .first()
        .is_some_and(|v| !v.is_empty());
    let te = header_values(flow, "transfer-encoding")
        .first()
        .map(|v| v.to_lowercase())
        .unwrap_or_default();
    if raw.len() > LOGIN_BODY_MAX || encoded || !(te.is_empty() || te == "chunked") {
        return Err(NotASignIn("body"));
    }
    let text = String::from_utf8(raw).map_err(|_| NotASignIn("body"))?;
    if text.starts_with('\u{feff}') || text.contains('\0') {
        return Err(NotASignIn("body"));
    }
    Ok(text)
}

/// `_strict_json`: nesting at most 8 deep, no member twice, no `NaN` or its kin.
pub fn strict_json(text: &str) -> Result<Value, NotASignIn> {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for ch in text.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == '[' || ch == '{' {
            depth += 1;
            if depth > LOGIN_JSON_DEPTH_MAX {
                return Err(NotASignIn("body"));
            }
        } else if ch == ']' || ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    cjson::loads_no_constants(text).map_err(|_| NotASignIn("body"))
}

/// `_strings`: every string in a JSON value; a member name marked as one.
pub fn strings(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::String(s) => out.push(s.clone()),
        // A whole number as written: `{"note": 48213907}` carries an all-digit stand-in too. Not a
        // float: its text here is not the literal (`1e7` reads `10000000.0`); a float written with
        // the stand-in is in the raw text, which `quoted_whole` and the raw count read.
        Value::Number(n) if n.is_i64() || n.is_u64() => out.push(n.to_string()),
        Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
        Value::Object(o) => {
            for (k, v) in o {
                out.push(format!("\0key:{k}"));
                strings(v, out);
            }
        }
        _ => {}
    }
}

fn no_method_override<'a>(mut names: impl Iterator<Item = &'a str>) -> Result<(), NotASignIn> {
    if names.any(|n| n.eq_ignore_ascii_case("_method")) {
        Err(NotASignIn("method"))
    } else {
        Ok(())
    }
}

/// `_sign_in_field`: the one field holding the stand-in as its whole value, and the form's fields.
pub fn sign_in_field(flow: &Flow, placeholder: &str) -> Result<(String, Vec<(String, String)>), NotASignIn> {
    let found = Finder::new(placeholder);
    let kind = sign_in_content_type(flow).ok_or(NotASignIn("body"))?;
    let text = body_text(flow)?;
    if found.count(&text) != 1 {
        return Err(NotASignIn("body"));
    }
    if kind == "form" {
        let pairs = strict_pairs(&text).ok_or(NotASignIn("body"))?;
        no_method_override(pairs.iter().map(|(k, _)| k.as_str()))?;
        let holders: Vec<&String> = pairs.iter().filter(|(_, v)| v == placeholder).map(|(k, _)| k).collect();
        if holders.len() != 1
            || pairs
                .iter()
                .any(|(k, v)| carries(&found, k) || (v != placeholder && carries(&found, v)))
        {
            return Err(NotASignIn("body"));
        }
        return Ok((holders[0].clone(), pairs));
    }
    let doc = strict_json(&text)?;
    let Value::Object(o) = &doc else {
        return Err(NotASignIn("body"));
    };
    if o.len() > LOGIN_FIELDS_MAX {
        return Err(NotASignIn("body"));
    }
    no_method_override(o.keys().map(String::as_str))?;
    let holders: Vec<&String> = o
        .iter()
        .filter(|(_, v)| v.as_str() == Some(placeholder))
        .map(|(k, _)| k)
        .collect();
    let mut all = Vec::new();
    strings(&doc, &mut all);
    if holders.len() != 1 || all.iter().filter(|t| carries(&found, t)).count() != 1 || !quoted_whole(&found, &text) {
        return Err(NotASignIn("body"));
    }
    Ok((holders[0].clone(), Vec::new()))
}

/// Whether the one place the stand-in is written is a whole JSON string (`"<stand-in>"`, its quote
/// not escaped): the swap goes in there. The holder can be spelled with escapes (`"\u0034…"`) that
/// the parsed check reads and the raw text does not, so the raw match must be the holder's value
/// itself, never a number or another field written plainly.
fn quoted_whole(found: &Finder, text: &str) -> bool {
    let mut at = found.find_iter(text);
    let (Some((s, e)), None) = (at.next(), at.next()) else {
        return false;
    };
    let before = &text[..s];
    let Some(head) = before.strip_suffix('"') else {
        return false;
    };
    let slashes = head.len() - head.trim_end_matches('\\').len();
    slashes % 2 == 0 && text[e..].starts_with('"')
}

/// `_swap_google_sign_in` (main #617): Google's sign-in with the password set at
/// `payload[3][4][0]` and the `f.req` field written out again; every other byte of the form as the
/// page sent it. By the structure, never by finding the stand-in in the text: the check reads the
/// parsed payload, so the swap lands where the parsed payload has it.
pub fn swap_google_sign_in(body: &str, placeholder: &str, secret: &str) -> Result<String, NotASignIn> {
    let refused = || NotASignIn("body");
    let mut parts: Vec<String> = body.split('&').map(str::to_owned).collect();
    let mut done = 0;
    for part in &mut parts {
        let Some(("f.req", value)) = part.split_once('=') else {
            continue;
        };
        let mut envelope = sign_in_raw(&unquote_plus(value))?;
        let call = envelope
            .as_array_mut()
            .filter(|e| e.len() == 1)
            .and_then(|e| e[0].as_array_mut())
            .filter(|e| e.len() == 1)
            .and_then(|e| e[0].as_array_mut())
            .filter(|c| c.len() == 4 && c[1].is_string())
            .ok_or_else(refused)?;
        let mut payload = sign_in_raw(call[1].as_str().unwrap_or(""))?;
        let at = payload
            .get_mut(3)
            .and_then(|v| v.get_mut(4))
            .and_then(|v| v.get_mut(0))
            .ok_or_else(refused)?;
        if at.as_str() != Some(placeholder) {
            return Err(refused());
        }
        *at = Value::String(secret.to_owned());
        call[1] = Value::String(crate::checks::pyjson::dumps_compact(&payload));
        *part = format!(
            "f.req={}",
            quote_plus(&crate::checks::pyjson::dumps_compact(&envelope), "*")
        );
        done += 1;
    }
    if done == 1 { Ok(parts.join("&")) } else { Err(refused()) }
}

/// A sign-in's JSON to be written out again: read as the check reads it ([`strict_json`]: the
/// depth limit, no member twice, no `NaN` or infinity), then with its numbers kept as written. A
/// member name carrying the reader's own number marker is refused: written out, it could stand
/// for a number it is not.
fn sign_in_raw(text: &str) -> Result<Value, NotASignIn> {
    fn marked(v: &Value) -> bool {
        match v {
            Value::Array(a) => a.iter().any(marked),
            Value::Object(o) => o.iter().any(|(k, v)| k.starts_with('\0') || marked(v)),
            _ => false,
        }
    }
    if marked(&strict_json(text)?) {
        return Err(NotASignIn("body"));
    }
    cjson::loads_sign_in_raw(text).map_err(|_| NotASignIn("body"))
}

/// `_google_sign_in`: Google's `batchexecute` sign-in, that shape and no other.
pub fn google_sign_in(flow: &Flow, placeholder: &str) -> Result<(), NotASignIn> {
    let found = Finder::new(placeholder);
    if sign_in_content_type(flow) != Some("form") {
        return Err(NotASignIn("body"));
    }
    let text = body_text(flow)?;
    // The one `&` Google's page ends the form with. Any other empty piece is refused below.
    let pairs = strict_pairs(text.strip_suffix('&').unwrap_or(&text));
    let Some(pairs) = pairs.filter(|_| found.count(&text) == 1) else {
        return Err(NotASignIn("body"));
    };
    no_method_override(pairs.iter().map(|(k, _)| k.as_str()))?;
    let mut exact = 0;
    for (key, value) in &pairs {
        if carries(&found, key) {
            return Err(NotASignIn("body"));
        }
        if !carries(&found, value) {
            continue;
        }
        if key != "f.req" {
            return Err(NotASignIn("body"));
        }
        let envelope = strict_json(value)?;
        let call = envelope
            .as_array()
            .filter(|e| e.len() == 1)
            .and_then(|e| e[0].as_array())
            .filter(|e| e.len() == 1)
            .and_then(|e| e[0].as_array())
            .filter(|c| c.len() == 4 && c[0].is_string() && c[1].is_string() && c[2].is_null() && c[3].is_string())
            .ok_or(NotASignIn("body"))?;
        if carries(&found, call[0].as_str().unwrap_or("")) || carries(&found, call[3].as_str().unwrap_or("")) {
            return Err(NotASignIn("body"));
        }
        let payload = strict_json(call[1].as_str().unwrap_or(""))?;
        let at = payload
            .get(3)
            .filter(|v| v.is_array())
            .and_then(|v| v.get(4))
            .filter(|v| v.is_array());
        let mut all = Vec::new();
        strings(&payload, &mut all);
        // ...and written once in the payload's text, as that whole string (main #617): the
        // swap goes by the structure, so the text must not spell it anywhere else.
        if !at
            .and_then(|a| a.get(0))
            .is_some_and(|v| v.as_str() == Some(placeholder))
            || all.iter().filter(|t| carries(&found, t)).count() != 1
            || !quoted_whole(&found, call[1].as_str().unwrap_or(""))
        {
            return Err(NotASignIn("body"));
        }
        exact += 1;
    }
    if exact == 1 { Ok(()) } else { Err(NotASignIn("body")) }
}

/// `_password_name`.
pub fn password_name(name: &str) -> bool {
    let low = name.to_lowercase();
    let parts: Vec<&str> = low.split(['_', '.', '-']).collect();
    // `(?:.*[_.-])?(?:pass|passwd|password|pwd|passphrase|secret)(?:[_.-].*)?`: one of the words as a
    // whole piece between separators.
    let word = parts
        .iter()
        .any(|p| matches!(*p, "pass" | "passwd" | "password" | "pwd" | "passphrase" | "secret"));
    word || camel(name)
}

/// `[A-Za-z0-9]*[a-z0-9](?:Password|Passwd|Pwd)`, the whole name.
fn camel(name: &str) -> bool {
    for suffix in ["Password", "Passwd", "Pwd"] {
        if let Some(head) = name.strip_suffix(suffix)
            && !head.is_empty()
            && head.bytes().all(|c| c.is_ascii_alphanumeric())
            && head
                .bytes()
                .last()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// Whether the request asks to be run as another verb.
pub fn method_override(flow: &Flow) -> bool {
    if header_names(flow)
        .iter()
        .any(|n| METHOD_OVERRIDE_HEADERS.contains(&n.as_str()))
    {
        return true;
    }
    let t = target(flow);
    let q = t.split_once('?').map_or("", |(_, q)| q).to_lowercase();
    q.starts_with("_method=") || q.contains("&_method=") || q.contains("?_method=")
}

pub fn truthy_field(v: &Value, k: &str) -> bool {
    truthy(v.get(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_and_wire_names() {
        // Five ASCII bytes and a replacement character: byte 6 is inside it.
        assert_eq!(basic_credentials("Token\u{fffd}"), None);
        assert_eq!(basic_credentials("Basic dTpw").as_deref(), Some("u:p"));
        assert_ne!(wire_host("a_b"), wire_host("c_d"), "two names that are not host names");
        assert_eq!(wire_host("Login.Example.COM."), "login.example.com");
        assert_eq!(wire_host("single"), "single");
    }

    #[test]
    fn password_names() {
        for n in [
            "password",
            "pwd",
            "user_password",
            "j_password",
            "wpPassword",
            "pass",
            "login.pass",
            "secret-key",
        ] {
            assert!(password_name(n), "{n}");
        }
        for n in ["user_login", "comment", "wpTextbox1", "c", "passport", "mypassword"] {
            assert!(!password_name(n), "{n}");
        }
    }

    #[test]
    fn addresses() {
        let a = sign_in_address("https://Login.Example.com/session", None).expect("an address");
        assert_eq!(
            (a.host.as_str(), a.port, a.path.as_str()),
            ("login.example.com", 443, "/session")
        );
        assert!(sign_in_address("http://login.example.com/session", None).is_none());
        assert!(sign_in_address("https://u:p@login.example.com/s", None).is_none());
        assert!(sign_in_address("https://login.example.com/a/../s", None).is_none());
        assert!(
            sign_in_address("https://login.example.com/s?", None).is_none(),
            "a `?` with nothing after"
        );
        let w = sign_in_address("https://w.example/w/index.php?title=Special:UserLogin&returnto=x", None)
            .expect("with a query");
        assert_eq!(
            address_text(&w),
            "https://w.example/w/index.php?returnto=x&title=Special%3AUserLogin"
        );
        let o = sign_in_address("/api/*", Some(("login.example.com", 8443))).expect("owner prefix");
        assert!(o.prefix && o.owner && o.path == "/api/" && o.port == 8443);
        assert!(
            sign_in_address("/", Some(("login.example.com", 443))).is_none(),
            "the top of a site"
        );
        assert!(
            sign_in_address("x.accounts.example.com/session", Some(("a.b", 443)))
                .is_some_and(|a| a.host == "x.accounts.example.com")
        );
        assert_eq!(strict_pairs("a=1&A=2"), None, "a key twice under another case");
        assert_eq!(strict_pairs("a.b=1&a_b=2"), None, "`.` as `_`");
        assert_eq!(strict_pairs("a=%zz"), None);
        assert_eq!(strict_pairs("a"), None);
        assert_eq!(strict_pairs("a=b c"), None);
        assert_eq!(plain_path("/a%2fb"), None);
        assert_eq!(plain_path("/a;b"), None);
        assert_eq!(plain_path("/a/b?x"), Some("/a/b".into()));
    }
}
