//! Reading mail the way the addon reads it with Python's `email` package: the subject and the
//! text and HTML parts of a message (`_mime_text`, `policy.default`), the header block of a message
//! (`_header_block`), the one `message/rfc822` part of a Gmail multipart upload
//! (`_multipart_message`), Gmail's base64url (`_b64url`) and HTML to text (`_html_text`).
//!
//! What this covers: headers unfolded, RFC 2047 words (B and Q) in the subject, `multipart/*`
//! split on its boundary (the line break before a boundary belongs to it), `message/rfc822`
//! walked into, base64 and quoted-printable bodies, and the charsets `body::get_text` decodes. A
//! text part with no charset is ASCII, so its other bytes read as U+FFFD, as `get_content` gives
//! them. Other charsets: Python's own names, UTF-7, then the WHATWG labels (`encoding_rs`). A text
//! part in a charset none of these knows, or a message nested past 50 levels, is not read
//! (`mime_text` gives `None`) and the caller refuses it.
//!
//! Lines end at `\r\n`, `\r` or `\n`; a boundary line is the boundary and only whitespace after
//! it; the headers end at the first line that is not a header. Parts are slices of the message,
//! never copies.

use std::sync::LazyLock;

use base64::Engine;
use regex::Regex;

use super::body;

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| re(r"<[^<>]{0,4000}>"));
static HEAD_END: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    regex::bytes::Regex::new(r"\r?\n\r?\n").expect("valid expression")
});
static ENCODED_WORD: LazyLock<Regex> = LazyLock::new(|| re(r"=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?="));

pub const HEADER_LIMIT: usize = 262_144;

/// `_header_block`: the header block of an RFC 822 message, never the body; `None` when the
/// headers do not end within the limit (a recipient past it would go unchecked).
pub fn header_block(message: &[u8]) -> Option<String> {
    let window = &message[..message.len().min(HEADER_LIMIT)];
    let head = match HEAD_END.find(window) {
        Some(m) => &message[..m.start()],
        None if message.len() <= HEADER_LIMIT => message,
        None => return None,
    };
    Some(String::from_utf8_lossy(head).into_owned())
}

/// `_b64url`: Gmail's base64url, padded; characters outside the alphabet are skipped, as
/// `base64.b64decode` does without `validate`.
pub fn b64url(value: &serde_json::Value) -> Option<Vec<u8>> {
    let s = value.as_str()?;
    if s.len() > 50 * 1024 * 1024 {
        return None;
    }
    b64_lenient(&s.replace('-', "+").replace('_', "/"))
}

/// `base64.b64decode(s)` without `validate`: other characters dropped, padding optional.
pub fn b64_lenient(s: &str) -> Option<Vec<u8>> {
    let clean: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .collect();
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    );
    engine.decode(clean).ok()
}

#[allow(clippy::expect_used)] // a fixed expression, checked by the tests
static INLINE_TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^<(?:!--|/?(?:a|abbr|b|bdi|bdo|code|em|font|i|kbd|mark|q|s|samp|small|span|strike|strong|sub|sup|u|var|wbr)\b)")
        .expect("valid")
});

/// `_html_text`: the words of an HTML body: tags as spaces (`<p>customer</p><p>list</p>`), and
/// again, when it has inline tags, with those taken out, as a mail client shows them
/// (`pass<b></b>word`).
pub fn html_text(html: &str) -> String {
    let spaced = unescape(&TAG_RE.replace_all(html, " "));
    // `_INLINE_TAG_RE.search(html)`: an inline tag or a comment anywhere.
    let any_inline = html.match_indices('<').any(|(i, _)| INLINE_TAG_RE.is_match(&html[i..]));
    if !any_inline {
        return spaced;
    }
    let joined = TAG_RE.replace_all(
        html,
        |c: &regex::Captures<'_>| {
            if INLINE_TAG_RE.is_match(&c[0]) { "" } else { " " }
        },
    );
    format!("{spaced}\n{}", unescape(&joined))
}

/// The end of the line starting at `from` and where the next starts: a line ends at `\r\n`, `\r`
/// or `\n`, as Python's `email` parser splits it.
fn line_at(b: &[u8], from: usize) -> (usize, usize) {
    match b[from..].iter().position(|c| *c == b'\r' || *c == b'\n') {
        None => (b.len(), b.len()),
        Some(i) => {
            let end = from + i;
            if b[end] == b'\r' && b.get(end + 1) == Some(&b'\n') {
                (end, end + 2)
            } else {
                (end, end + 1)
            }
        }
    }
}

/// `headerRE`: a field name of printable characters but the colon, then the colon.
fn header_line(line: &[u8]) -> Option<(String, String)> {
    let colon = line.iter().position(|c| *c == b':')?;
    let name = &line[..colon];
    if !name.iter().all(|c| (0x21..=0x7e).contains(c)) {
        return None;
    }
    Some((
        String::from_utf8_lossy(name).trim().to_owned(),
        String::from_utf8_lossy(&line[colon + 1..]).trim_start().to_owned(),
    ))
}

/// One part: its headers (name, unfolded value) and its body, a slice of the message.
#[derive(Debug, Clone, Default)]
pub struct Part<'a> {
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
}

impl<'a> Part<'a> {
    /// The headers end at a blank line, or at the first line that is not a header (Python reads
    /// that line as the start of the body).
    pub fn parse(raw: &'a [u8]) -> Self {
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut pos = 0;
        let mut body_start = raw.len();
        while pos < raw.len() {
            let (end, next) = line_at(raw, pos);
            let line = &raw[pos..end];
            if line.is_empty() {
                body_start = next;
                break;
            }
            if line[0] == b' ' || line[0] == b'\t' {
                // A continuation; one with no header before it is skipped, as Python does.
                if let Some(last) = headers.last_mut() {
                    last.1.push_str(&String::from_utf8_lossy(line));
                }
                pos = next;
                continue;
            }
            if pos == 0 && line.starts_with(b"From ") {
                pos = next;
                continue;
            }
            match header_line(line) {
                Some(h) => headers.push(h),
                None => {
                    body_start = pos;
                    break;
                }
            }
            pos = next;
        }
        Self {
            headers,
            body: &raw[body_start.min(raw.len())..],
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `get_content_type()`: `text/plain` when missing or not `type/subtype`.
    pub fn content_type(&self) -> String {
        let raw = self.header("content-type").unwrap_or("");
        match body::parse_content_type(raw) {
            Some((t, s, _)) if !t.trim().is_empty() && !s.trim().is_empty() => format!("{}/{}", t.trim(), s.trim()),
            _ => "text/plain".into(),
        }
    }

    /// `get_param(name, header=...)`, RFC 2231 included (`name*`, `name*0`, `name*1*`, ...): a
    /// plain parameter first, as Python lists them.
    pub fn param(&self, header: &str, name: &str) -> Option<String> {
        let raw = self.header(header)?;
        let params = raw.split_once(';')?.1;
        let name = name.to_ascii_lowercase();
        let mut extended: Option<String> = None;
        let mut pieces: Vec<(u32, bool, String)> = Vec::new();
        for clause in split_params(params) {
            let Some((k, v)) = clause.split_once('=') else { continue };
            let k = k.trim().to_ascii_lowercase();
            let v = unquote_param(v.trim());
            if k == name {
                return Some(v);
            }
            let Some(rest) = k.strip_prefix(&name).and_then(|r| r.strip_prefix('*')) else {
                continue;
            };
            if rest.is_empty() {
                extended.get_or_insert(v);
            } else {
                let (n, encoded) = match rest.strip_suffix('*') {
                    Some(n) => (n, true),
                    None => (rest, false),
                };
                if let Ok(n) = n.parse::<u32>() {
                    pieces.push((n, encoded, v));
                }
            }
        }
        if let Some(v) = extended {
            return Some(rfc2231(&v, true));
        }
        if pieces.is_empty() {
            return None;
        }
        pieces.sort_by_key(|p| p.0);
        let mut charset = String::new();
        let mut bytes = Vec::new();
        for (i, (_, encoded, v)) in pieces.iter().enumerate() {
            if *encoded {
                let mut v = v.as_str();
                if i == 0 {
                    let mut it = v.splitn(3, '\'');
                    if let (Some(cs), Some(_), Some(rest)) = (it.next(), it.next(), it.next()) {
                        charset = cs.to_owned();
                        v = rest;
                    }
                }
                bytes.extend(percent_decode(v));
            } else {
                bytes.extend_from_slice(v.as_bytes());
            }
        }
        Some(decode_charset(
            if charset.is_empty() { "us-ascii" } else { &charset },
            &bytes,
        ))
    }

    /// `get_filename()`: the disposition's `filename`, else the type's `name`.
    pub fn filename(&self) -> Option<String> {
        self.param("content-disposition", "filename")
            .or_else(|| self.param("content-type", "name"))
    }

    pub fn is_multipart(&self) -> bool {
        self.content_type().starts_with("multipart/") || self.content_type() == "message/rfc822"
    }

    /// The parts of a `multipart/*` (`message/rfc822`: the one message inside).
    pub fn children(&self) -> Vec<Part<'a>> {
        let ct = self.content_type();
        if ct == "message/rfc822" {
            return vec![Part::parse(self.body)];
        }
        // `get_boundary()` strips trailing whitespace.
        let Some(boundary) = self.param("content-type", "boundary").map(|b| b.trim_end().to_owned()) else {
            return Vec::new();
        };
        split_multipart(self.body, boundary.as_bytes())
            .into_iter()
            .map(Part::parse)
            .collect()
    }

    /// The body with its transfer encoding undone.
    pub fn decoded(&self) -> Vec<u8> {
        match self
            .header("content-transfer-encoding")
            .map(|e| e.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("base64") => b64_lenient(&String::from_utf8_lossy(self.body)).unwrap_or_default(),
            Some("quoted-printable") => quoted_printable(self.body, false),
            _ => self.body.to_vec(),
        }
    }

    /// `get_content()` of a text part: decoded, in its charset (ASCII when it names none).
    /// `None` for a charset this reader does not know.
    pub fn text(&self) -> Option<String> {
        let bytes = self.decoded();
        let charset = self
            .param("content-type", "charset")
            .unwrap_or_else(|| "us-ascii".into());
        decode_charset_known(&charset, &bytes)
    }
}

/// An RFC 2231 value `charset'language'percent-encoded` (or just percent-encoded).
fn rfc2231(v: &str, encoded: bool) -> String {
    if !encoded {
        return v.to_owned();
    }
    let mut it = v.splitn(3, '\'');
    match (it.next(), it.next(), it.next()) {
        (Some(cs), Some(_), Some(rest)) => {
            let cs = if cs.is_empty() { "us-ascii" } else { cs };
            decode_charset(cs, &percent_decode(rest))
        }
        _ => String::from_utf8_lossy(&percent_decode(v)).into_owned(),
    }
}

fn percent_decode(v: &str) -> Vec<u8> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|c| (*c as char).to_digit(16)),
                b.get(i + 2).and_then(|c| (*c as char).to_digit(16)),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ';' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn unquote_param(v: &str) -> String {
    match v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) => inner.replace("\\\"", "\"").replace("\\\\", "\\"),
        None => v.to_owned(),
    }
}

/// `boundaryre`: the line is `--boundary`, then `--` for the closing one, then only spaces or tabs.
fn boundary_line(line: &[u8], delim: &[u8]) -> Option<bool> {
    let rest = line.strip_prefix(delim)?;
    let (closing, rest) = match rest.strip_prefix(b"--") {
        Some(r) => (true, r),
        None => (false, rest),
    };
    rest.iter().all(|c| *c == b' ' || *c == b'\t').then_some(closing)
}

/// A body split on its boundary lines: the line break before a boundary belongs to it; the
/// preamble and the epilogue are not parts.
fn split_multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let delim = [b"--".as_slice(), boundary].concat();
    // (where the part before it ends, where the part after it starts, closing)
    let mut marks: Vec<(usize, usize, bool)> = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let (end, next) = line_at(body, pos);
        if let Some(closing) = boundary_line(&body[pos..end], &delim) {
            // The break before the boundary is the boundary's.
            let mut before = pos;
            if before > 0 && body[before - 1] == b'\n' {
                before -= 1;
                if before > 0 && body[before - 1] == b'\r' {
                    before -= 1;
                }
            } else if before > 0 && body[before - 1] == b'\r' {
                before -= 1;
            }
            marks.push((before, next, closing));
            if closing {
                break;
            }
        }
        pos = next;
    }
    let mut parts = Vec::new();
    for w in marks.windows(2) {
        let (_, from, closing) = w[0];
        let (to, _, _) = w[1];
        if !closing && from <= to {
            parts.push(&body[from..to]);
        }
    }
    // No closing boundary: the last part runs to the end, its last line break dropped (Python's
    // `email` keeps it, as a defect).
    if let Some(&(_, from, false)) = marks.last()
        && from <= body.len()
    {
        let last = &body[from..];
        let last = last
            .strip_suffix(b"\r\n")
            .or_else(|| last.strip_suffix(b"\n"))
            .or_else(|| last.strip_suffix(b"\r"))
            .unwrap_or(last);
        parts.push(last);
    }
    parts
}

/// `quopri` decoding (`header`: `_` is a space, as in a Q word).
pub fn quoted_printable(b: &[u8], header: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16);
    while i < b.len() {
        let c = b[i];
        if c == b'=' {
            // A soft break: `=` at the end of a line, spaces allowed before it ends.
            let mut j = i + 1;
            while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                j += 1;
            }
            if j < b.len() && (b[j] == b'\n' || b[j] == b'\r') {
                i = j + if b[j] == b'\r' && b.get(j + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                continue;
            }
            if j == b.len() {
                i = j;
                continue;
            }
            if let (Some(h), Some(l)) = (b.get(i + 1).and_then(|x| hex(*x)), b.get(i + 2).and_then(|x| hex(*x))) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if header && c == b'_' { b' ' } else { c });
        i += 1;
    }
    out
}

/// Bytes in a charset, for a header: a charset this reader does not know reads as UTF-8.
pub fn decode_charset(charset: &str, bytes: &[u8]) -> String {
    decode_charset_known(charset, bytes).unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned())
}

/// Bytes in a charset, `None` for one this reader does not know: a text part in it cannot be
/// checked. A text part with no charset is ASCII with replacement.
pub fn decode_charset_known(charset: &str, bytes: &[u8]) -> Option<String> {
    let c = charset.trim().to_ascii_lowercase().replace('_', "-");
    if matches!(c.as_str(), "us-ascii" | "ascii" | "ansi-x3.4-1968") {
        return Some(
            bytes
                .iter()
                .map(|b| if b.is_ascii() { char::from(*b) } else { '\u{fffd}' })
                .collect(),
        );
    }
    if c.starts_with("utf-8") || c == "utf8" {
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }
    if matches!(c.as_str(), "utf-7" | "utf7" | "unicode-1-1-utf-7") {
        return Some(utf7(bytes));
    }
    // Python's own names first (Latin-1 is Latin-1 there, not Windows-1252), then the WHATWG
    // labels for the rest (Shift JIS, KOI8-R, GB 2312, ...).
    if matches!(
        c.replace('-', "").as_str(),
        "latin1" | "latin" | "l1" | "iso88591" | "iso885911987" | "8859" | "cp819"
    ) {
        return Some(bytes.iter().map(|b| char::from(*b)).collect());
    }
    if c.starts_with("utf-16") || c.starts_with("utf-32") || c.starts_with("utf16") || c.starts_with("utf32") {
        return Some(body::get_text(&format!("text/plain; charset={charset}"), bytes));
    }
    let enc = encoding_rs::Encoding::for_label(c.as_bytes())?;
    Some(enc.decode_without_bom_handling(bytes).0.into_owned())
}

/// UTF-7 (RFC 2152), with replacement for what does not decode, as Python's `utf-7` codec reads it.
pub fn utf7(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c != b'+' {
            out.push(if c.is_ascii() { char::from(c) } else { '\u{fffd}' });
            i += 1;
            continue;
        }
        i += 1;
        if bytes.get(i) == Some(&b'-') {
            out.push('+');
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'+' || bytes[i] == b'/') {
            i += 1;
        }
        let run = &bytes[start..i];
        if bytes.get(i) == Some(&b'-') {
            i += 1;
        }
        let decoded = b64_lenient(&String::from_utf8_lossy(run)).unwrap_or_default();
        let units: Vec<u16> = decoded
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        out.extend(char::decode_utf16(units).map(|r| r.unwrap_or('\u{fffd}')));
    }
    out
}

/// The subject (or any header) with its RFC 2047 words decoded: whitespace between two encoded
/// words is dropped, other text kept.
pub fn decode_header(v: &str) -> String {
    let mut out = String::new();
    let mut last = 0;
    let mut prev_was_word = false;
    for m in ENCODED_WORD.captures_iter(v) {
        let whole = m.get(0).map_or(0..0, |g| g.range());
        let between = &v[last..whole.start];
        if !(prev_was_word && between.chars().all(char::is_whitespace)) {
            out.push_str(between);
        }
        let (charset, enc, text) = (&m[1], &m[2], &m[3]);
        let charset = charset.split('*').next().unwrap_or(charset);
        let bytes = if enc.eq_ignore_ascii_case("b") {
            b64_lenient(text).unwrap_or_default()
        } else {
            quoted_printable(text.as_bytes(), true)
        };
        out.push_str(&decode_charset(charset, &bytes));
        last = whole.end;
        prev_was_word = true;
    }
    out.push_str(&v[last..]);
    out
}

/// How deep parts may nest, and how many there may be: past either the message is not read.
pub const MIME_MAX_DEPTH: usize = 50;
pub const MIME_MAX_PARTS: usize = 10_000;

/// `_mime_text`: the subject and the text and HTML parts of a message, decoded. `None` for a
/// message this reader cannot follow (nested too deep, too many parts, a text part in a charset it
/// does not know): the caller refuses it rather than let it pass unread.
pub fn mime_text(message: &[u8]) -> Option<String> {
    let top = Part::parse(message);
    let mut out = vec![top.header("subject").map(decode_header).unwrap_or_default()];
    let mut parts = 0;
    walk(&top, &mut out, 0, &mut parts)?;
    Some(out.into_iter().filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n"))
}

fn walk(p: &Part<'_>, out: &mut Vec<String>, depth: usize, parts: &mut usize) -> Option<()> {
    *parts += 1;
    if depth > MIME_MAX_DEPTH || *parts > MIME_MAX_PARTS {
        return None;
    }
    if p.is_multipart() {
        for c in p.children() {
            walk(&c, out, depth + 1, parts)?;
        }
        return Some(());
    }
    let ct = p.content_type();
    if (ct != "text/plain" && ct != "text/html") || p.filename().is_some() {
        return Some(());
    }
    let body = p.text()?;
    out.push(if ct == "text/html" { html_text(&body) } else { body });
    Some(())
}

/// `_multipart_message`: the one `message/rfc822` part of a Gmail multipart upload, as bytes.
/// Python re-serialises the inner message, which can fold long headers again; here the part's
/// own bytes are returned. Only its header block is read from it, so the recipients are the same.
pub fn multipart_message(content_type: &str, content: &[u8]) -> Option<Vec<u8>> {
    if !content_type.to_lowercase().starts_with("multipart/") {
        return None;
    }
    let mut raw = format!("Content-Type: {content_type}\r\n\r\n").into_bytes();
    raw.extend_from_slice(content);
    let top = Part::parse(&raw);
    if !top.content_type().starts_with("multipart/") {
        return None;
    }
    let parts: Vec<Part<'_>> = top
        .children()
        .into_iter()
        .filter(|p| p.content_type() == "message/rfc822")
        .collect();
    if parts.len() != 1 {
        return None;
    }
    Some(parts[0].body.to_vec())
}

#[allow(clippy::expect_used)] // a fixed expression, checked by the tests
static CHARREF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\x0c <&#;]{1,32};?)").expect("valid"));

/// `html.unescape`, as CPython writes it: every HTML5 named reference (with the old names that
/// may go without a semicolon), numeric references with HTML5's replacements, and the code points
/// HTML forbids taken out (`cust&#1;omer` reads `customer`).
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    CHARREF
        .replace_all(s, |c: &regex::Captures<'_>| replace_charref(&c[1]))
        .into_owned()
}

/// `html._replace_charref`.
fn replace_charref(s: &str) -> String {
    use super::html_entities::{HTML5, INVALID_CHARREFS, INVALID_CODEPOINTS};
    let lookup = |name: &str| HTML5.binary_search_by(|(k, _)| (*k).cmp(name)).ok().map(|i| HTML5[i].1);
    if let Some(num) = s.strip_prefix('#') {
        let num = num.trim_end_matches(';');
        let n = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => num.parse::<u32>(),
        }
        // Past u32 is past 0x10FFFF.
        .unwrap_or(u32::MAX);
        if let Ok(i) = INVALID_CHARREFS.binary_search_by(|(k, _)| k.cmp(&n)) {
            return INVALID_CHARREFS[i].1.to_owned();
        }
        if (0xD800..=0xDFFF).contains(&n) || n > 0x10FFFF {
            return "\u{fffd}".into();
        }
        if INVALID_CODEPOINTS.binary_search(&n).is_ok() {
            return String::new();
        }
        return char::from_u32(n).map_or_else(|| "\u{fffd}".into(), String::from);
    }
    if let Some(v) = lookup(s) {
        return v.to_owned();
    }
    // The longest name, of two characters or more, that is a prefix (the old names without `;`).
    let ends: Vec<usize> = s.char_indices().map(|(i, _)| i).skip(2).collect();
    for &end in ends.iter().rev() {
        if let Some(v) = lookup(&s[..end]) {
            return format!("{v}{}", &s[end..]);
        }
    }
    format!("&{s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mt(m: &[u8]) -> String {
        mime_text(m).expect("read")
    }

    /// Each answer was taken from Python 3.12's `email` package on the same input.
    #[test]
    fn mime_text_like_python() {
        assert_eq!(
            mt(b"Subject: =?utf-8?B?Y2Fmw6k=?= x\r\n =?utf-8?Q?a_b?=\r\n\r\nhello\r\nworld\r\n"),
            "caf\u{e9} x a b\nhello\r\nworld\r\n"
        );
        assert_eq!(mt(b"Subject: hi\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9 =\r\nsoft\r\n"),
            "hi\ncaf\u{fffd}\u{fffd} soft\r\n"
        );
        assert_eq!(mt(b"Subject: hi\r\n\r\ncaf\xc3\xa9"), "hi\ncaf\u{fffd}\u{fffd}");
        assert_eq!(
            mt(b"Subject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ncaf\xc3\xa9"),
            "hi\ncaf\u{e9}"
        );
        let multi = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\npre\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=\"a.txt\"\r\n\r\natt\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nSubject: inner\r\n\r\ninner body\r\n--b--\r\n";
        assert_eq!(mt(multi), " x \ninner body");
        assert_eq!(mt(b"Subject: x\r\nContent-Transfer-Encoding: base64\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nY2Fmw6k=\r\n"), "x\ncaf\u{e9}");
    }

    #[test]
    fn a_last_part_with_no_closing_boundary() {
        let m = b"Subject: s\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>last</p>\r\n";
        assert_eq!(mt(m), "s\nfirst\n last ");
    }

    #[test]
    fn header_blocks() {
        assert_eq!(
            header_block(b"To: a\r\nBcc: b\r\n\r\nSECRET").as_deref(),
            Some("To: a\r\nBcc: b")
        );
        assert_eq!(header_block(b"To: a").as_deref(), Some("To: a"));
        let mut big = b"To: a\r\nX-Pad: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', 300_000));
        big.extend_from_slice(b"\r\nBcc: evil\r\n\r\nbody");
        assert_eq!(header_block(&big), None);
    }

    #[test]
    fn gmail_base64url_and_uploads() {
        let v = serde_json::json!("VG86IGJvYkB5LmNvbQ0KDQpoaQ");
        assert_eq!(b64url(&v).as_deref(), Some(b"To: bob@y.com\r\n\r\nhi".as_slice()));
        assert_eq!(b64url(&serde_json::json!(5)), None);
        let raw = b"From: me@x.com\r\nTo: Bob <bob@y.com>\r\nBcc: hidden@w.com\r\n\r\nSECRET\r\n";
        let mut body = b"--BND\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{\"threadId\":\"t1\"}\r\n--BND\r\nContent-Type: message/rfc822\r\n\r\n".to_vec();
        body.extend_from_slice(raw);
        body.extend_from_slice(b"\r\n--BND--\r\n");
        let m = multipart_message("multipart/related; boundary=\"BND\"", &body).expect("one part");
        assert!(header_block(&m).is_some_and(|h| h.contains("hidden@w.com") && !h.contains("SECRET")));
        assert_eq!(multipart_message("application/json", &body), None);
    }

    #[test]
    fn unescape_as_python() {
        let cases = [
            ("cust&#1;omer", "customer"),
            ("&ccedil;a", "\u{e7}a"),
            ("&notit;", "\u{ac}it;"),
            ("&amp &ampx &amp;", "& &x &"),
            ("&#x110000; &#99999999999;", "\u{fffd} \u{fffd}"),
            ("&#150;&#0;&#13;", "\u{2013}\u{fffd}\r"),
            ("&#xd800;", "\u{fffd}"),
            ("&nosuch; & &;", "&nosuch; & &;"),
            ("&NotNestedGreaterGreater;", "\u{2aa2}\u{338}"),
        ];
        for (input, want) in cases {
            assert_eq!(unescape(input), want, "{input}");
        }
    }

    #[test]
    fn html_inline_tags_read_both_ways() {
        // Block tags break words; inline tags and comments do not, as a mail client shows them.
        assert_eq!(html_text("<p>customer</p><p>list</p>"), " customer  list ");
        assert_eq!(html_text("pass<b></b>word"), "pass  word\npassword");
        assert_eq!(html_text("pass<!-- x -->word"), "pass word\npassword");
        assert!(html_text("<P>cust<SPAN>om</SPAN>er</P>").ends_with("\n customer "));
        assert_eq!(html_text("<br>x"), " x", "br is not inline");
    }

    #[test]
    fn html_like_python() {
        assert_eq!(
            html_text("<p>caf&eacute; &amp; &#233;&#x41;</p>"),
            " caf\u{e9} & \u{e9}A "
        );
        assert_eq!(
            unescape("&eacutex &notit; &unknown; &#128;"),
            "\u{e9}x \u{ac}it; &unknown; \u{20ac}"
        );
    }

    /// The host review's probes (#528). Each answer is the addon's own `_mime_text` on the same bytes.
    #[test]
    fn probes_read_like_python() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"Subject: s\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nhello\r\n--aX\r\nContent-Type: image/png\r\n\r\nSECRET\r\n--a--\r\n",
                "s\nhello\r\n--aX\r\nContent-Type: image/png\r\n\r\nSECRET",
            ),
            (
                b"Subject: s\r\nContent-Type: multipart/mixed; boundary*=''zz\r\n\r\n--zz\r\nContent-Type: text/plain\r\n\r\nSECRET 2231\r\n--zz--\r\n",
                "s\nSECRET 2231",
            ),
            (
                b"Subject: s\r\nContent-Type: multipart/mixed; boundary*0=\"z\"; boundary*1=\"q\"\r\n\r\n--zq\r\nContent-Type: text/plain\r\n\r\nSECRET cont\r\n--zq--\r\n",
                "s\nSECRET cont",
            ),
            (
                b"Subject: s\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: text/plain\r\nnot a header\r\nContent-Type : image/png\r\n\r\nSECRET body\r\n--a--\r\n",
                "s\nnot a header\r\nContent-Type : image/png\r\n\r\nSECRET body",
            ),
            (
                b"Subject: s\r\nContent-Type : image/png\r\n\r\nSECRET top\r\n",
                "s\nContent-Type : image/png\r\n\r\nSECRET top\r\n",
            ),
            (
                b"Subject: s\rContent-Type: multipart/mixed; boundary=a\r\r--a\rContent-Type: text/plain\r\rSECRET cr\r--a--\r",
                "s\nSECRET cr",
            ),
            (
                b"Subject: s\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n+AFMARQBDAFIARQBU-\r\n",
                "s\nSECRET\r\n",
            ),
            (
                b"Subject: s\r\nContent-Type: text/plain; charset=shift_jis\r\n\r\n\x94\xe9\x96\xa7",
                "s\n\u{79d8}\u{5bc6}",
            ),
            (
                b"Subject: s\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a \t\r\nContent-Type: text/plain\r\n\r\nSECRET ws\r\n--a-- \r\n",
                "s\nSECRET ws",
            ),
        ];
        for (m, want) in cases {
            assert_eq!(mt(m), *want, "{}", String::from_utf8_lossy(m));
        }
    }

    fn nested(n: usize) -> Vec<u8> {
        let mut m = b"Content-Type: text/plain\r\n\r\nSECRET deep\r\n".to_vec();
        for i in 0..n {
            let b = format!("b{i}");
            let mut outer = format!("Content-Type: multipart/mixed; boundary={b}\r\n\r\n--{b}\r\n").into_bytes();
            outer.extend(m);
            outer.extend(format!("\r\n--{b}--\r\n").into_bytes());
            m = outer;
        }
        [b"Subject: s\r\n".as_slice(), &m].concat()
    }

    #[test]
    fn too_deep_or_unknown_is_not_read() {
        assert_eq!(mt(&nested(10)), "s\nSECRET deep\r\n");
        // Python reads 60 levels; here past 50 the message is refused, never passed unread.
        assert_eq!(mime_text(&nested(60)), None);
        assert_eq!(
            mime_text(b"Subject: s\r\nContent-Type: text/plain; charset=x-no-such\r\n\r\nSECRET"),
            None
        );
        // A charset in a header only is read as UTF-8, as before.
        assert_eq!(decode_header("=?x-no-such?Q?a?="), "a");
        assert_eq!(utf7(b"a+-b+AGEAYgBj-"), "a+babc");
    }
}
