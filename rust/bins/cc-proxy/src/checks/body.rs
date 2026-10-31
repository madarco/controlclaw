//! Reading a message's fields the way mitmproxy 12.2.2 hands them to the addon, quirks included:
//!
//! - `get_text(strict=False)`: the charset from a byte-order mark, then the `Content-Type`'s
//!   `charset`, then UTF-8 for JSON, HTML, XML, JavaScript and CSS, and Latin-1 for anything else.
//!   A charset this port cannot decode is read as UTF-8, as mitmproxy does when decoding fails;
//!   only UTF-8, Latin-1 (and its aliases), ASCII and UTF-16/32 with a mark are decoded here.
//! - `query` and `urlencoded_form`: `urllib.parse.parse_qsl(keep_blank_values=True)`.
//! - `_multipart_fields`: a `multipart/form-data` body read strictly (production since #561);
//!   anything that does not split cleanly is an error, never an empty form.

use http::HeaderMap;

/// The request's or response's `Content-Type`, or "".
pub fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

/// A content type: type, subtype, and its parameters in order.
pub type ContentType = (String, String, Vec<(String, String)>);

/// `parse_content_type`: (type, subtype, params) or `None`.
pub fn parse_content_type(c: &str) -> Option<ContentType> {
    let (main, params) = match c.split_once(';') {
        Some((m, p)) => (m, Some(p)),
        None => (c, None),
    };
    let (t, s) = main.split_once('/')?;
    let mut d = Vec::new();
    if let Some(p) = params {
        for clause in p.split(';') {
            if let Some((k, v)) = clause.split_once('=') {
                let k = k.trim().to_owned();
                // An OrderedDict: a repeated key keeps its first place and its last value.
                match d.iter_mut().find(|(dk, _): &&mut (String, String)| *dk == k) {
                    Some(e) => e.1 = v.trim().to_owned(),
                    None => d.push((k, v.trim().to_owned())),
                }
            }
        }
    }
    Some((t.to_lowercase(), s.to_lowercase(), d))
}

/// `Message.get_text(strict=False)`.
pub fn get_text(content_type: &str, content: &[u8]) -> String {
    let enc = infer_encoding(content_type, content);
    decode(&enc, content).unwrap_or_else(|| String::from_utf8_lossy(content).into_owned())
}

fn infer_encoding(content_type: &str, content: &[u8]) -> String {
    let mut enc: Option<String> = None;
    if content.starts_with(b"\x00\x00\xfe\xff") {
        enc = Some("utf-32be".into());
    } else if content.starts_with(b"\xff\xfe\x00\x00") {
        enc = Some("utf-32le".into());
    } else if content.starts_with(b"\xfe\xff") {
        enc = Some("utf-16be".into());
    } else if content.starts_with(b"\xff\xfe") {
        enc = Some("utf-16le".into());
    } else if content.starts_with(b"\xef\xbb\xbf") {
        enc = Some("utf-8-sig".into());
    } else if let Some((_, _, params)) = parse_content_type(content_type) {
        enc = params.into_iter().find(|(k, _)| k == "charset").map(|(_, v)| v);
    }
    let enc = enc.filter(|e| !e.is_empty());
    if let Some(e) = enc {
        return e;
    }
    // On the header as it was sent, not lower-cased: mitmproxy's `infer_content_encoding` does the
    // same, so `APPLICATION/JSON` with no charset is Latin-1 there too (a quirk, ported).
    for needle in ["json", "html", "xml", "javascript", "ecmascript", "text/css"] {
        if content_type.contains(needle) {
            // A `<meta charset>` or `<?xml encoding>` names another charset; they are rare on
            // the bodies the checks read, and are read as UTF-8 here.
            return "utf8".into();
        }
    }
    "latin-1".into()
}

/// Decode with a Python codec name; `None` when this port does not know it or it fails.
fn decode(enc: &str, content: &[u8]) -> Option<String> {
    let e = enc.to_ascii_lowercase().replace(['-', '_', ' '], "");
    match e.as_str() {
        "utf8" | "u8" | "utf" | "cp65001" => std::str::from_utf8(content).ok().map(str::to_owned),
        "utf8sig" => {
            let c = content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content);
            std::str::from_utf8(c).ok().map(str::to_owned)
        }
        "latin1" | "latin" | "l1" | "iso88591" | "iso885911987" | "8859" | "cp819" => {
            Some(content.iter().map(|b| char::from(*b)).collect())
        }
        "ascii" | "usascii" | "646" => content
            .is_ascii()
            .then(|| String::from_utf8_lossy(content).into_owned()),
        "utf16le" | "utf16be" | "utf16" => {
            let (body, le) = match e.as_str() {
                "utf16le" => (content, true),
                "utf16be" => (content, false),
                _ if content.starts_with(b"\xff\xfe") => (&content[2..], true),
                _ if content.starts_with(b"\xfe\xff") => (&content[2..], false),
                _ => (content, true),
            };
            // A mark is kept by the explicit codecs, as Python does.
            if !body.len().is_multiple_of(2) {
                return None;
            }
            let units: Vec<u16> = body
                .chunks(2)
                .map(|c| {
                    if le {
                        u16::from_le_bytes([c[0], c[1]])
                    } else {
                        u16::from_be_bytes([c[0], c[1]])
                    }
                })
                .collect();
            String::from_utf16(&units).ok()
        }
        "utf32le" | "utf32be" => {
            if !content.len().is_multiple_of(4) {
                return None;
            }
            content
                .chunks(4)
                .map(|c| {
                    let v = if e == "utf32le" {
                        u32::from_le_bytes([c[0], c[1], c[2], c[3]])
                    } else {
                        u32::from_be_bytes([c[0], c[1], c[2], c[3]])
                    };
                    char::from_u32(v)
                })
                .collect()
        }
        _ => None,
    }
}

/// `urllib.parse.unquote(s, errors="surrogateescape")`: each run of ASCII is percent-decoded to
/// bytes and read as UTF-8 (a byte that is not valid UTF-8 becomes U+FFFD here, a lone surrogate
/// in Python); other characters stay as they are. A `%` without two hex digits stays.
pub fn unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut ascii = Vec::new();
    let flush = |ascii: &mut Vec<u8>, out: &mut String| {
        out.push_str(&String::from_utf8_lossy(&percent_decode(ascii)));
        ascii.clear();
    };
    for c in s.chars() {
        if c.is_ascii() {
            ascii.push(c as u8);
        } else {
            flush(&mut ascii, &mut out);
            out.push(c);
        }
    }
    flush(&mut ascii, &mut out);
    out
}

fn percent_decode(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `urllib.parse.parse_qsl(s, keep_blank_values=True)`: pairs split on `&`, `+` as a space.
pub fn parse_qsl(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for piece in s.split('&') {
        if piece.is_empty() {
            continue;
        }
        let (k, v) = piece.split_once('=').unwrap_or((piece, ""));
        out.push((unquote(&k.replace('+', " ")), unquote(&v.replace('+', " "))));
    }
    out
}

/// The query string's pairs (`request.query.items(multi=True)`).
pub fn query_items(uri: &http::Uri) -> Vec<(String, String)> {
    uri.query().map(parse_qsl).unwrap_or_default()
}

/// The form's pairs (`urlencoded_form.items(multi=True)`), only for a form content type.
pub fn urlencoded_items(content_type: &str, body: &[u8]) -> Vec<(String, String)> {
    if !content_type
        .to_lowercase()
        .contains("application/x-www-form-urlencoded")
    {
        return Vec::new();
    }
    parse_qsl(&get_text(content_type, body))
}

/// The text of a body as Telegram and Slack read it: UTF-8 unless the type names a charset, the
/// type matched in any case. (`get_text` is mitmproxy's reading, Latin-1 for a form; a server
/// reads UTF-8, so a check that reads Latin-1 sees other words than the server.)
pub fn get_text_utf8(content_type: &str, content: &[u8]) -> String {
    let named = parse_content_type(content_type).and_then(|(_, _, p)| {
        p.into_iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("charset"))
            .map(|(_, v)| v)
    });
    match named {
        Some(cs) => get_text(&format!("text/plain; charset={cs}"), content),
        None => String::from_utf8_lossy(content.strip_prefix(b"\xef\xbb\xbf").unwrap_or(content)).into_owned(),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn split_bytes<'a>(hay: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = hay;
    while let Some(i) = find(rest, sep) {
        out.push(&rest[..i]);
        rest = &rest[i + sep.len()..];
    }
    out.push(rest);
    out
}

/// `bytes.splitlines()`: on `\n`, `\r\n` and `\r`, without the breaks.
pub fn splitlines(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\n' => {
                out.push(&b[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&b[start..i]);
                i += if b.get(i + 1) == Some(&b'\n') { 2 } else { 1 };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < b.len() {
        out.push(&b[start..]);
    }
    out
}

/// `str.lstrip()`/`strip()`: Python's whitespace.
pub use super::content::engine::py_space as is_py_space;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_follows_the_charset_rules() {
        assert_eq!(get_text("application/json", "caf\u{e9}".as_bytes()), "caf\u{e9}");
        // A form with no charset is Latin-1, so UTF-8 bytes read as two characters each.
        assert_eq!(
            get_text("application/x-www-form-urlencoded", "\u{e9}".as_bytes()),
            "\u{c3}\u{a9}"
        );
        assert_eq!(get_text("text/plain; charset=utf-8", "\u{e9}".as_bytes()), "\u{e9}");
        assert_eq!(get_text("", b"\xef\xbb\xbfhi"), "hi");
        // Not valid UTF-8 under a UTF-8 charset: read with replacement.
        assert_eq!(get_text("application/json", b"a\xffb"), "a\u{fffd}b");
        assert_eq!(get_text("text/plain; charset=nope", b"ok"), "ok");
        // As mitmproxy 12.2.2 reads it: the type's fallback is case-sensitive.
        assert_eq!(get_text("APPLICATION/JSON", "caf\u{e9}".as_bytes()), "caf\u{c3}\u{a9}");
    }

    #[test]
    fn qsl_like_urllib() {
        assert_eq!(
            parse_qsl("a=1&b=&c&&d=x+y%20z&e=%zz&f=caf%C3%A9&g=%FF"),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "".into()),
                ("c".into(), "".into()),
                ("d".into(), "x y z".into()),
                ("e".into(), "%zz".into()),
                ("f".into(), "caf\u{e9}".into()),
                ("g".into(), "\u{fffd}".into()),
            ]
        );
        assert_eq!(
            parse_qsl("a=1;b=2"),
            vec![("a".into(), "1;b=2".into())],
            "only & separates"
        );
        assert_eq!(unquote("%"), "%");
        assert_eq!(unquote("%4"), "%4");
    }

    #[test]
    fn multipart_read_strictly() {
        let body = b"--B\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n42\r\n--B\r\ncontent-type: text/plain\r\nCONTENT-DISPOSITION: form-data; name=caption\r\n\r\nline one\r\nline two\r\n--B--\r\n";
        let got = multipart_fields(Some("B"), body).expect("clean");
        assert_eq!(
            got,
            vec![
                ("chat_id".to_owned(), b"42".to_vec()),
                ("caption".to_owned(), b"line one\r\nline two".to_vec())
            ]
        );
        let (_, params) = header_params("Multipart/Form-Data; Boundary=\"B\"").expect("header");
        assert_eq!(param(&params, "boundary"), Some("B"));
        assert!(
            header_params("multipart/form-data; boundary=B; boundary=C").is_err(),
            "repeated"
        );
        assert!(header_params("application/json;").is_ok(), "an empty parameter");
        let bad: [&[u8]; 6] = [
            b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\nx\r\n--B--",
            b"--B\r\nContent-Disposition: form-data\r\n\r\nx\r\n--B--",
            b"--B\r\nContent-Disposition: form-data; name=a\r\n\r\nx",
            b"pre\r\n--B\r\nContent-Disposition: form-data; name=a\r\n\r\nx\r\n--B--",
            b"--B\r\nContent-Disposition: form-data; name=a\r\nContent-Disposition: form-data; name=b\r\n\r\nx\r\n--B--",
            b"--B\r\nContent-Disposition: form-data; filename=a b.jpg; name=x\r\n\r\nx\r\n--B--",
        ];
        for b in bad {
            assert!(
                multipart_fields(Some("B"), b).is_err(),
                "{}",
                String::from_utf8_lossy(b)
            );
        }
        assert!(multipart_fields(Some("C"), body).is_err(), "the boundary is not there");
        assert!(multipart_fields(None, body).is_err());
        // grammY's unquoted file name, spaces and all.
        let grammy =
            b"--B\r\nContent-Disposition: form-data; name=\"photo\"; filename=my photo.jpg\r\n\r\nJPEG\r\n--B--\r\n";
        assert_eq!(multipart_fields(Some("B"), grammy).map(|v| v.len()), Ok(1));
        assert_eq!(
            get_text_utf8("application/x-www-form-urlencoded", "\u{e9}".as_bytes()),
            "\u{e9}"
        );
    }

    #[test]
    fn lines_like_python() {
        assert_eq!(
            splitlines(b"a\r\nb\rc\n\nd"),
            vec![b"a".as_slice(), b"b", b"c", b"", b"d"]
        );
        assert_eq!(splitlines(b"a\n"), vec![b"a".as_slice()]);
        assert!(is_py_space('\x1c') && is_py_space('\u{a0}') && !is_py_space('x'));
    }
}

const TOKEN: &str = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+";

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
static HEADER_PARAM: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(&format!(
        r#"^;[ \t]*({TOKEN})[ \t]*=[ \t]*("(?:[^"\\\r\n]|\\.)*"|{TOKEN})[ \t]*"#
    ))
    .expect("valid")
});
#[allow(clippy::expect_used)]
static HEADER_EMPTY_PARAM: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^;[ \t]*").expect("valid"));
#[allow(clippy::expect_used)]
static QUOTED_PAIR: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\\(.)").expect("valid"));
#[allow(clippy::expect_used)]
static MP_HEADER: std::sync::LazyLock<regex::bytes::Regex> =
    std::sync::LazyLock::new(|| regex::bytes::Regex::new(&format!(r"^({TOKEN}):[ \t]*(.*?)[ \t]*$")).expect("valid"));
#[allow(clippy::expect_used)]
static MP_LOOSE_FILENAME: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?i);[ \t]*filename=").expect("valid"));
#[allow(clippy::expect_used)]
static MP_SECOND_NAME: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)[;\s]name\*?[ \t]*=").expect("valid"));

/// A header the firewall cannot read the one way the service reads it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unreadable(pub &'static str);

/// `_header_params`: a header's first word, lower case, and its parameters (names lower case,
/// quotes taken off). Anything else is an error, a repeated parameter included.
pub fn header_params(value: &str) -> Result<(String, Vec<(String, String)>), Unreadable> {
    let (head, rest) = match value.split_once(';') {
        Some((h, r)) => (h, format!(";{r}")),
        None => (value, String::new()),
    };
    let end = rest.trim_end_matches([' ', '\t']).len();
    let mut params: Vec<(String, String)> = Vec::new();
    let mut pos = 0;
    while pos < end {
        let m = HEADER_PARAM.captures(&rest[pos..]);
        if m.is_none()
            && let Some(empty) = HEADER_EMPTY_PARAM.find(&rest[pos..])
        {
            let after = pos + empty.end();
            if after >= end || rest.as_bytes()[after] == b';' {
                pos = after; // an empty parameter (`application/json;`)
                continue;
            }
        }
        let Some(m) = m else {
            return Err(Unreadable("a header the firewall cannot read"));
        };
        let name = m[1].to_lowercase();
        if params.iter().any(|(k, _)| *k == name) {
            return Err(Unreadable("a header the firewall cannot read"));
        }
        let v = &m[2];
        let v = match v.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
            Some(inner) => QUOTED_PAIR.replace_all(inner, "$1").into_owned(),
            None => v.to_owned(),
        };
        params.push((name, v));
        pos += m.get(0).map_or(0, |x| x.end());
    }
    Ok((head.trim_matches([' ', '\t']).to_lowercase(), params))
}

/// A parameter of [`header_params`]'s result.
pub fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// `_charset_ok`: Telegram and Slack read UTF-8 whatever the header says; a body that says
/// otherwise is not checked.
pub fn charset_ok(params: &[(String, String)]) -> bool {
    matches!(
        param(params, "charset").unwrap_or("utf-8").to_lowercase().as_str(),
        "utf-8" | "utf8"
    )
}

/// `_multipart_fields`: the named parts of a `multipart/form-data` body, read strictly: every
/// delimiter on its own CRLF line, nothing before the first or after the last, each part a block
/// of headers, a blank line and its value, with one `Content-Disposition: form-data` naming it.
/// Anything else is an error: an empty form would pass unchecked. The values as sent.
pub fn multipart_fields(boundary: Option<&str>, body: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Unreadable> {
    let boundary = boundary.unwrap_or("");
    if boundary.is_empty() || boundary.chars().count() > 70 || !boundary.is_ascii() {
        return Err(Unreadable("a multipart body with no usable boundary"));
    }
    let delimiter = [b"\r\n--".as_slice(), boundary.as_bytes()].concat();
    // `(b"\r\n" + body).split(delimiter)` without copying the body: its first piece is empty only
    // when the body starts on the boundary.
    let first = &delimiter[2..];
    let Some(after) = body.strip_prefix(first) else {
        return Err(Unreadable(
            "a multipart body that does not start and end on its boundary",
        ));
    };
    let mut pieces = vec![b"".as_slice()];
    pieces.extend(split_bytes(after, &delimiter));
    let last = pieces.last().copied().unwrap_or_default();
    if pieces.len() < 2 || !(last == b"--" || last == b"--\r\n") {
        return Err(Unreadable(
            "a multipart body that does not start and end on its boundary",
        ));
    }
    let mut fields = Vec::new();
    for piece in &pieces[1..pieces.len() - 1] {
        let Some(piece) = piece.strip_prefix(b"\r\n") else {
            return Err(Unreadable("a multipart delimiter not on a line of its own"));
        };
        let Some(at) = find(piece, b"\r\n\r\n") else {
            return Err(Unreadable("a multipart part without headers"));
        };
        let (head, value) = (&piece[..at], &piece[at + 4..]);
        if head.is_empty() {
            return Err(Unreadable("a multipart part without headers"));
        }
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in split_bytes(head, b"\r\n") {
            let m = MP_HEADER
                .captures(line)
                .ok_or(Unreadable("a multipart part header the firewall cannot read"))?;
            let name = String::from_utf8_lossy(&m[1]).to_lowercase();
            let value = std::str::from_utf8(&m[2])
                .map_err(|_| Unreadable("a multipart part header the firewall cannot read"))?;
            if headers.iter().any(|(k, _)| *k == name) {
                return Err(Unreadable("a multipart part header the firewall cannot read"));
            }
            headers.push((name, value.to_owned()));
        }
        let mut disposition = param(&headers, "content-disposition").unwrap_or("").to_owned();
        // grammY writes a file's name unquoted, spaces and all (`filename=my photo.jpg`): it runs
        // to the end of the line, and must not hold a second name.
        let loose = MP_LOOSE_FILENAME
            .find_iter(&disposition)
            .find(|m| disposition.as_bytes().get(m.end()) != Some(&b'"'))
            .map(|m| (m.start(), m.end()));
        if let Some((start, end)) = loose {
            if MP_SECOND_NAME.is_match(&disposition[end..]) {
                return Err(Unreadable("a multipart part named twice"));
            }
            disposition = format!("{};filename=\"\"", &disposition[..start]);
        }
        let (kind, params) = header_params(&disposition)?;
        let name = param(&params, "name").unwrap_or("");
        if kind != "form-data" || name.is_empty() || param(&params, "name*").is_some() {
            return Err(Unreadable("a multipart part without a name"));
        }
        let cte = param(&headers, "content-transfer-encoding")
            .unwrap_or("binary")
            .to_lowercase();
        if !matches!(cte.as_str(), "binary" | "8bit" | "7bit") {
            return Err(Unreadable("a multipart part in an encoding the firewall cannot read"));
        }
        if param(&params, "filename").is_none()
            && let Some(ct) = param(&headers, "content-type")
            && !charset_ok(&header_params(ct)?.1)
        {
            return Err(Unreadable("a multipart part in a charset the firewall cannot read"));
        }
        fields.push((name.to_owned(), value.to_vec()));
    }
    Ok(fields)
}

/// Header parameters, names lower case, in order.
pub type Params = Vec<(String, String)>;

/// `_out_body`: an outgoing chat call's body as Telegram and Slack read it: its media type, the
/// type's parameters, and the body as UTF-8 text. A compressed body, or one in another charset, is
/// an error: what the check would read is not what the service reads.
pub fn out_body(headers: &HeaderMap, raw: &[u8]) -> Result<(String, Params, String), Unreadable> {
    let codings = |name: http::header::HeaderName| -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .flat_map(|v| {
                String::from_utf8_lossy(v.as_bytes())
                    .split(',')
                    .map(|e| e.trim().to_lowercase())
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    if codings(http::header::CONTENT_ENCODING)
        .iter()
        .any(|e| !e.is_empty() && e != "identity")
        || codings(http::header::TRANSFER_ENCODING)
            .iter()
            .any(|e| !e.is_empty() && e != "chunked")
    {
        return Err(Unreadable("a compressed body"));
    }
    let (media, params) = header_params(&content_type(headers))?;
    if !charset_ok(&params) {
        return Err(Unreadable("a body in a charset the firewall cannot read"));
    }
    Ok((media, params, String::from_utf8_lossy(raw).into_owned()))
}
