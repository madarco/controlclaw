//! What the box side's routes share beyond `cc_http`: headers added the way the TS's `writeHead`
//! objects add them, streamed bodies, and the few JavaScript conversions whose output reaches the
//! console (ISO dates, `toUTCString`, `parseInt`, `Date.parse`).

use std::convert::Infallible;

use bytes::Bytes;
use cc_http::{Body, Resp};
use http::HeaderValue;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

/// Add `headers`, a `Set-Cookie` as one more line, anything else in place. A header the HTTP
/// stack refuses (Node would throw `ERR_INVALID_CHAR`) makes the answer a 500 rather than one that
/// is quietly missing its Location or cookie.
pub fn with_headers(mut r: Resp, headers: &[(&str, String)]) -> Resp {
    for (k, v) in headers {
        match (http::HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            (Ok(name), Ok(value)) if name == http::header::SET_COOKIE => {
                r.headers_mut().append(name, value);
            }
            (Ok(name), Ok(value)) => {
                r.headers_mut().insert(name, value);
            }
            _ => {
                tracing::error!("refused to send a {k} header with characters HTTP does not allow");
                return cc_http::send_json(500, &json!({"error": "Internal error"}));
            }
        }
    }
    r
}

/// `sendJson(res, status, body, extra)`: JSON, `Cache-Control: no-store`, then `extra`.
pub fn send_json(status: u16, body: &Value, extra: &[(&str, String)]) -> Resp {
    with_headers(cc_http::send_json(status, body), extra)
}

/// A response whose body comes in pieces from `rx`; the stream ends when every sender is gone.
/// When the client hangs up hyper drops the body, and the senders' next `send` fails.
pub fn streamed(status: u16, rx: tokio::sync::mpsc::Receiver<Bytes>, headers: &[(&str, String)]) -> Resp {
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|b| (Ok::<_, std::io::Error>(Frame::data(b)), rx))
    });
    let body: Body = BodyExt::boxed(StreamBody::new(stream));
    let mut r = http::Response::new(body);
    *r.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
    with_headers(r, headers)
}

/// A file, streamed. A read error midway ends the body short of its `Content-Length`, which hyper
/// turns into a closed connection: the client sees a cut download, as Node's pipeline gave it.
pub fn file_body(mut file: tokio::fs::File, status: u16, headers: &[(&str, String)]) -> Resp {
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    tokio::spawn(async move {
        loop {
            let mut buf = vec![0u8; 64 * 1024];
            match file.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    buf.truncate(n);
                    if tx.send(Bytes::from(buf)).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    streamed(status, rx, headers)
}

/// An empty body of type [`Body`] (for a 204).
pub fn empty_body(status: u16, headers: &[(&str, String)]) -> Resp {
    let body: Body = http_body_util::Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed();
    let mut r = http::Response::new(body);
    *r.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
    with_headers(r, headers)
}

/// Milliseconds since the epoch of a file time; `Date`'s precision.
pub fn time_ms(t: std::time::SystemTime) -> i64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// `Date.prototype.toISOString` (`2026-10-28T10:45:01.123Z`).
pub fn iso(ms: i64) -> String {
    cc_auth::firewall::chrono_like_iso(ms)
}

/// Days since the epoch to (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since the epoch of a civil date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `Date.prototype.toUTCString` (`Wed, 28 Oct 2026 10:45:01 GMT`), the HTTP date.
pub fn utc_string(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `parseInt(s, 10)`: optional whitespace and sign, then the leading digits; `None` for NaN.
pub fn parse_int(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let n: i64 = digits.parse().unwrap_or(i64::MAX);
    Some(if neg { -n } else { n })
}

/// `Date.parse` for the forms that reach it here: ISO 8601 (`2026-10-28T10:45:01.123Z`, with an
/// offset, or a date alone, which is UTC) and systemd's `Wed 2026-10-28 10:45:01 UTC`. `None` is
/// NaN. A time without a zone is read as UTC: the boxes run in UTC.
pub fn date_parse(s: &str) -> Option<i64> {
    let s = s.trim();
    // systemd: an optional weekday, then `YYYY-MM-DD HH:MM:SS[.ffffff] [ZONE]`.
    let s = match s.split_once(' ') {
        Some((day, rest)) if day.len() == 3 && day.chars().all(|c| c.is_ascii_alphabetic()) => rest,
        _ => s,
    };
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        part.bytes().all(|c| c.is_ascii_digit()).then(|| part.parse().ok())?
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let day_ms = days_from_civil(y, mo, d) * 86_400_000;
    if b.len() == 10 {
        return Some(day_ms);
    }
    if !matches!(b.get(10), Some(b'T') | Some(b' ')) {
        return None;
    }
    let (h, mi) = (num(11, 2)?, num(14, 2)?);
    let mut i = 16;
    let mut sec = 0;
    if b.get(i) == Some(&b':') {
        sec = num(17, 2)?;
        i = 19;
    }
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        let frac: String = s[i + 1..].chars().take_while(char::is_ascii_digit).collect();
        if frac.is_empty() {
            return None;
        }
        let mut f = frac.clone();
        f.truncate(3);
        while f.len() < 3 {
            f.push('0');
        }
        ms = f.parse().ok()?;
        i += 1 + frac.len();
    }
    if h > 24 || mi > 59 || sec > 59 {
        return None;
    }
    let zone = s[i..].trim();
    let offset_min = match zone {
        "" | "Z" | "UTC" | "GMT" => 0,
        z if (z.starts_with('+') || z.starts_with('-')) && z.len() >= 5 => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits: String = z[1..].chars().filter(char::is_ascii_digit).collect();
            if digits.len() != 4 {
                return None;
            }
            let hh: i64 = digits[..2].parse().ok()?;
            let mm: i64 = digits[2..].parse().ok()?;
            sign * (hh * 60 + mm)
        }
        _ => return None,
    };
    Some(day_ms + ((h * 60 + mi - offset_min) * 60 + sec) * 1000 + ms)
}

/// The split the firewall-or-console routes share: a POST only with the firewall's token for
/// `purpose` (its JSON body read), a GET with that or the console's. `Err` is the 401, worded
/// `write_refused` for a write.
pub async fn firewall_or_console(
    app: &crate::app::App,
    req: cc_http::Req,
    purpose: &str,
    write_refused: &str,
) -> Result<(http::request::Parts, cc_http::FirewallBody), Box<cc_http::Resp>> {
    use cc_http::{FirewallBody, FirewallRequest, ReadBody};
    let write = req.method() == http::Method::POST;
    let read = if write {
        ReadBody::Json { limit: 16384 }
    } else {
        ReadBody::No
    };
    match cc_http::firewall_request(&app.firewall_auth, req, purpose, 0, read).await {
        FirewallRequest::Accepted { parts, body, .. } => Ok((parts, body)),
        FirewallRequest::Refused { parts, .. } => {
            let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let console_ok = !write
                && app
                    .console_auth
                    .verify(parts.method.as_str(), target, cc_http::header(&parts, "authorization"))
                    .is_some();
            if !console_ok {
                let msg = if write { write_refused } else { "Unauthorized" };
                return Err(Box::new(send_json(401, &serde_json::json!({"error": msg}), &[])));
            }
            Ok((parts, FirewallBody::NotRead))
        }
    }
}

/// `url.searchParams.get(name)` of the request.
pub fn query(parts: &http::request::Parts, name: &str) -> Option<String> {
    let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    url::Url::parse("http://box")
        .and_then(|b| b.join(target))
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// `String(value)` for what a JSON record can hold.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{}", f as i64),
            _ => n.to_string(),
        },
        Value::Array(a) => a
            .iter()
            .map(|x| if x.is_null() { String::new() } else { js_string(x) })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `JSON.stringify(v)` for a value read from a request: numbers as JavaScript prints them.
pub fn json_stringify(v: &Value) -> String {
    match v {
        Value::Number(_) => js_string(v),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// JavaScript's `\s` (and what `trim()` removes): not quite Unicode `White_Space`, which has
/// U+0085 and lacks U+FEFF.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// The same set as a regex class body, for patterns that use `\s`.
pub const JS_SPACE_CLASS: &str =
    r"\t\n\x0B\x0C\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

/// `String.prototype.trim`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// An `fs` error as Node words it (`EACCES: permission denied, open '<path>'`), so a 500 carries
/// the same text as the TS build's.
pub fn node_io(e: &std::io::Error, syscall: &str, path: &str, dest: Option<&str>) -> String {
    let (code, text) = match e.raw_os_error() {
        Some(1) => ("EPERM", "operation not permitted"),
        Some(2) => ("ENOENT", "no such file or directory"),
        Some(13) => ("EACCES", "permission denied"),
        Some(17) => ("EEXIST", "file already exists"),
        Some(20) => ("ENOTDIR", "not a directory"),
        Some(21) => ("EISDIR", "illegal operation on a directory"),
        Some(28) => ("ENOSPC", "no space left on device"),
        Some(30) => ("EROFS", "read-only file system"),
        Some(122) => ("EDQUOT", "disk quota exceeded"),
        _ => return e.to_string(),
    };
    match dest {
        Some(d) => format!("{code}: {text}, {syscall} '{path}' -> '{d}'"),
        None => format!("{code}: {text}, {syscall} '{path}'"),
    }
}

/// `writeAtomic`: the parent made, `<path>.tmp` written with `mode`, then renamed over. The error
/// is Node's text for the step that failed. A leftover tmp is given `mode` too (Node would keep
/// the leftover's own), so a wider one never passes its mode on.
pub fn write_atomic(path: &std::path::Path, body: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let shown = |p: &std::path::Path| p.display().to_string();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| node_io(&e, "mkdir", &shown(dir), None))?;
    }
    let tmp = std::path::PathBuf::from(format!("{}.tmp", path.display()));
    let open = |e: std::io::Error| node_io(&e, "open", &shown(&tmp), None);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(open)?;
    let _ = f.set_permissions(std::fs::Permissions::from_mode(mode));
    f.write_all(body)
        .map_err(|e| node_io(&e, "write", &shown(&tmp), None))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| node_io(&e, "rename", &shown(&tmp), Some(&shown(path))))
}

/// `JSON.stringify` of a string held as UTF-16, where a slice may have split a surrogate pair:
/// the lone half is written `\udXXX`, as JavaScript writes it (a Rust `String` cannot hold it).
pub fn json_quote_utf16(units: &[u16]) -> String {
    let mut out = String::from("\"");
    for c in char::decode_utf16(units.iter().copied()) {
        match c {
            Ok(c) => {
                let q = serde_json::to_string(&c.to_string()).unwrap_or_default();
                out.push_str(&q[1..q.len() - 1]);
            }
            Err(e) => out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate())),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(utc_string(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(utc_string(1_793_179_840_000), "Wed, 28 Oct 2026 09:30:40 GMT");
        assert_eq!(date_parse("1970-01-01T00:00:01.5Z"), Some(1500));
        assert_eq!(date_parse("2026-10-28T09:30:40.000Z"), Some(1_793_179_840_000));
        assert_eq!(date_parse("Wed 2026-10-28 09:30:40 UTC"), Some(1_793_179_840_000));
        assert_eq!(date_parse("2026-10-28T11:30:40+02:00"), Some(1_793_179_840_000));
        assert_eq!(date_parse("2026-10-28"), Some(1_793_145_600_000));
        assert_eq!(date_parse(""), None);
        assert_eq!(date_parse("n/a"), None);
        assert_eq!(iso(1_793_179_840_123), "2026-10-28T09:30:40.123Z");
    }

    #[test]
    fn parse_ints() {
        assert_eq!(parse_int("12abc"), Some(12));
        assert_eq!(parse_int(" -5"), Some(-5));
        assert_eq!(parse_int("x"), None);
        assert_eq!(parse_int(""), None);
    }

    #[test]
    fn strings() {
        assert_eq!(js_string(&json!(5)), "5");
        assert_eq!(js_string(&json!(1.5)), "1.5");
        assert_eq!(js_string(&json!(true)), "true");
        assert_eq!(js_string(&json!({"a": 1})), "[object Object]");
    }
}
