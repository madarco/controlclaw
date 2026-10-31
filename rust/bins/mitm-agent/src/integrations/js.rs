//! What the TS gets from JavaScript itself and Rust does not give the same way: `JSON.stringify`
//! (numbers as `Number#toString` writes them: `1` for `1.0`, `1e+21`), `String#trim`, and the
//! timestamps `Date#toISOString` writes. Bytes the integrations write and hash (a rewritten request
//! body, an approval's key, a tool result's text) come out as the Node build wrote them.

use serde_json::Value;

/// `String.prototype.trim`: ECMAScript white space and line terminators.
pub fn trim(s: &str) -> &str {
    // Unicode White_Space without U+0085, which ECMAScript does not count, and with U+FEFF, which it does.
    s.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}')
}

pub fn to_upper(s: &str) -> String {
    s.to_uppercase()
}

/// `Number.prototype.toString()` for a finite number; `null` for the rest, as `JSON.stringify` writes them.
pub fn number(f: f64) -> String {
    if !f.is_finite() {
        return "null".into();
    }
    if f == 0.0 {
        return "0".into();
    }
    let sign = if f < 0.0 { "-" } else { "" };
    // Rust's `{:e}` is the shortest form that reads back the same, as JavaScript picks.
    let e = format!("{:e}", f.abs());
    let (mantissa, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exp: i32 = exp.parse().unwrap_or(0);
    let k = digits.len() as i32;
    let n = exp + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let tail = if k > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let sign = if n > 0 { "+" } else { "-" };
        format!("{}{tail}e{sign}{}", &digits[..1], (n - 1).abs())
    };
    format!("{sign}{body}")
}

fn number_of(n: &serde_json::Number) -> String {
    // Integers past 2^53 are rounded as a JavaScript number holds them.
    if let Some(i) = n.as_i64()
        && i.unsigned_abs() <= (1u64 << 53)
    {
        return i.to_string();
    }
    if let Some(u) = n.as_u64()
        && u <= (1u64 << 53)
    {
        return u.to_string();
    }
    number(n.as_f64().unwrap_or(f64::NAN))
}

fn string(s: &str, out: &mut String) {
    // serde_json escapes the same set JSON.stringify does: `"`, `\`, and below U+0020.
    out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()));
}

fn write(v: &Value, out: &mut String, indent: Option<&str>, level: usize) {
    let nl = |out: &mut String, level: usize| {
        if let Some(ind) = indent {
            out.push('\n');
            for _ in 0..level {
                out.push_str(ind);
            }
        }
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_of(n)),
        Value::String(s) => string(s, out),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, level + 1);
                write(x, out, indent, level + 1);
            }
            nl(out, level);
            out.push(']');
        }
        Value::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, level + 1);
                string(k, out);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write(x, out, indent, level + 1);
            }
            nl(out, level);
            out.push('}');
        }
    }
}

/// `JSON.stringify(v)`.
pub fn stringify(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out, None, 0);
    out
}

/// `JSON.stringify(v, null, 2)`.
pub fn stringify_pretty(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out, Some("  "), 0);
    out
}

/// `new Date(ms).toISOString()`.
pub fn iso(ms: i64) -> String {
    cc_crypto::store_health::iso_from_millis(ms)
}

/// `Date.now()`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `Date.parse` of an ISO timestamp, the forms the runtime and the TS write; None otherwise.
pub fn parse_iso(s: &str) -> Option<i64> {
    // YYYY-MM-DDTHH:MM:SS(.sss)?(Z|±HH:MM)?
    let b = s.as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    if !s.is_char_boundary(19) {
        return None;
    }
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut rest = &s[19..];
    let mut ms = 0i64;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let padded = format!("{digits:0<3}");
        ms = padded[..3].parse().ok()?;
        rest = &frac[digits.len()..];
    }
    let offset_min = match rest {
        "" | "Z" | "z" => 0,
        o if o.len() == 6 && o.is_ascii() && (o.starts_with('+') || o.starts_with('-')) && &o[3..4] == ":" => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o[1..3].parse::<i64>().ok()? * 60 + o[4..6].parse::<i64>().ok()?)
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 24 || mi > 59 || se > 59 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se) - offset_min * 60) * 1000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_as_javascript_writes_them() {
        for (f, s) in [
            (1.0, "1"),
            (0.1, "0.1"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1.5e-7, "1.5e-7"),
            (0.000001, "0.000001"),
            (-2.5, "-2.5"),
            (123456.789, "123456.789"),
        ] {
            assert_eq!(number(f), s, "{f}");
        }
        assert_eq!(stringify(&json!(12345678901234567890u64)), "12345678901234567000");
    }

    #[test]
    fn stringify_compact_and_pretty() {
        let v = json!({"b": [1, 2.0, {}], "a": "x\ny", "c": []});
        assert_eq!(stringify(&v), r#"{"b":[1,2,{}],"a":"x\ny","c":[]}"#);
        assert_eq!(
            stringify_pretty(&v),
            "{\n  \"b\": [\n    1,\n    2,\n    {}\n  ],\n  \"a\": \"x\\ny\",\n  \"c\": []\n}"
        );
    }

    #[test]
    fn iso_round_trips() {
        let ms = 1_761_600_000_123;
        assert_eq!(parse_iso(&iso(ms)), Some(ms));
        assert_eq!(
            parse_iso("2026-10-28T00:00:00+01:00"),
            parse_iso("2026-10-27T23:00:00Z")
        );
        assert_eq!(parse_iso("not a date"), None);
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    #[test]
    fn trim_as_javascript_and_odd_timestamps() {
        assert_eq!(trim("\u{85}work"), "\u{85}work", "NEL is not JavaScript white space");
        assert_eq!(trim("\u{feff} work\u{a0}"), "work");
        assert_eq!(parse_iso("2026-10-28T10:00:00+0\u{e9}00"), None);
        assert_eq!(parse_iso("2026-10-28T10:00:0\u{e9}Z"), None);
    }
}

/// `a.localeCompare(b)` for the names people type, close to ICU's root order: letters compare
/// without case first, and of two names that differ only in case the lower-case one comes first.
pub fn locale_compare(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| b.cmp(a))
}

/// Text for an HTML page: `&`, `<`, `>` and `"` written as entities.
pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
