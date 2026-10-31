//! JSON text as Python's `json.dumps` writes it by default: `", "` and `": "` between items and
//! every character outside ASCII as `\uXXXX`. The addon builds every answer and every rewritten
//! body with `json.dumps`, so writing the same bytes keeps lengths and bodies identical to it.

use std::io;

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, Serializer};

struct Py;

impl Formatter for Py {
    fn begin_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }
    fn write_string_fragment<W: ?Sized + io::Write>(&mut self, w: &mut W, fragment: &str) -> io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            if c.is_ascii() {
                continue;
            }
            w.write_all(&fragment.as_bytes()[start..i])?;
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                write!(w, "\\u{u:04x}")?;
            }
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, w: &mut W, e: CharEscape) -> io::Result<()> {
        // Python writes the control characters it has no short form for as `\u00XX`, as serde does,
        // and `/` as itself.
        let s: &[u8] = match e {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(b) => return write!(w, "\\u{:04x}", b),
        };
        w.write_all(s)
    }
}

/// `json.dumps(value, ensure_ascii=False)`: the same separators, other characters as they are.
pub fn dumps_unicode(v: &impl Serialize) -> String {
    let mut out = Vec::new();
    let mut ser = Serializer::with_formatter(&mut out, PyUnicode);
    if v.serialize(&mut ser).is_err() {
        return "null".into();
    }
    String::from_utf8(out).unwrap_or_default()
}

struct PyUnicode;

impl Formatter for PyUnicode {
    fn begin_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, w: &mut W, e: CharEscape) -> io::Result<()> {
        Py.write_char_escape(w, e)
    }
}

/// `json.dumps(value)`.
pub fn dumps(v: &impl Serialize) -> String {
    let mut out = Vec::new();
    let mut ser = Serializer::with_formatter(&mut out, Py);
    if v.serialize(&mut ser).is_err() {
        return "null".into();
    }
    String::from_utf8(out).unwrap_or_default()
}

/// `json.dumps(value, separators=(",", ":"))`: no spaces, every character outside ASCII as `\uXXXX`.
/// A number kept as written (`checks::json::RAW_NUMBER`) is written as Python writes what it read:
/// an integer as its digits, a float as its `repr`.
pub fn dumps_compact(v: &serde_json::Value) -> String {
    let mut out = String::new();
    compact(v, &mut out);
    out
}

fn compact(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match v {
        Value::Object(m)
            if m.len() == 1
                && m.get(super::json::RAW_NUMBER)
                    .and_then(Value::as_str)
                    .is_some_and(number_literal) =>
        {
            let t = m.get(super::json::RAW_NUMBER).and_then(Value::as_str).unwrap_or("0");
            if t.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                out.push_str(&float_repr(t.parse().unwrap_or(0.0)));
            } else if t.trim_start_matches('-').bytes().all(|b| b == b'0') {
                // `int("-0")` is 0.
                out.push('0');
            } else {
                out.push_str(t);
            }
        }
        Value::Number(n) => match (n.is_f64(), n.as_f64()) {
            (true, Some(f)) => out.push_str(&float_repr(f)),
            _ => out.push_str(&n.to_string()),
        },
        Value::String(_) | Value::Null | Value::Bool(_) => out.push_str(&dumps(v)),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                compact(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&dumps(k));
                out.push(':');
                compact(x, out);
            }
            out.push('}');
        }
    }
}

/// A JSON number as written: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`. Only such a literal
/// is written as a number; anything else stays the object it is.
fn number_literal(t: &str) -> bool {
    let b = t.strip_prefix('-').unwrap_or(t).as_bytes();
    let digits = |at: usize| b[at.min(b.len())..].iter().take_while(|c| c.is_ascii_digit()).count();
    let int = digits(0);
    if int == 0 || (int > 1 && b[0] == b'0') {
        return false;
    }
    let mut i = int;
    if b.get(i) == Some(&b'.') {
        let f = digits(i + 1);
        if f == 0 {
            return false;
        }
        i += 1 + f;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let e = digits(i);
        if e == 0 {
            return false;
        }
        i += e;
    }
    i == b.len()
}

/// Python's `repr(float)`: the shortest form that reads back, in exponent form below 1e-4 and from
/// 1e16 (`1e-05`, `1e+16`).
fn float_repr(f: f64) -> String {
    let s = format!("{f:?}");
    let Some((mantissa, exp)) = s.split_once('e') else {
        return s;
    };
    let (sign, digits) = exp.strip_prefix('-').map_or(("+", exp), |d| ("-", d));
    format!("{mantissa}e{sign}{digits:0>2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_json_dumps() {
        let v = serde_json::json!({"ok": false, "a": [1, 2, {"b": "caf\u{e9} \u{1F600}\n"}], "c": null});
        assert_eq!(
            dumps(&v),
            r#"{"ok": false, "a": [1, 2, {"b": "caf\u00e9 \ud83d\ude00\n"}], "c": null}"#
        );
        assert_eq!(dumps(&serde_json::json!({})), "{}");
        assert_eq!(dumps(&serde_json::json!([])), "[]");
    }

    #[test]
    fn like_compact_json_dumps() {
        let v = super::super::json::loads_sign_in_raw(
            r#"{"a":[1,1.5,1e3,12345678901234567890123,null,true],"b":"caf\u00e9","c":{"d":-0.0001,"e":1e16}}"#,
        )
        .expect("json");
        assert_eq!(
            dumps_compact(&v),
            r#"{"a":[1,1.5,1000.0,12345678901234567890123,null,true],"b":"caf\u00e9","c":{"d":-0.0001,"e":1e+16}}"#
        );
        assert_eq!(float_repr(1e-5), "1e-05");
        assert_eq!(
            dumps_compact(
                &super::super::json::loads_sign_in_raw("[-0,-0.0,100000000000000000000000000000000000000000]")
                    .expect("json")
            ),
            "[0,-0.0,100000000000000000000000000000000000000000]"
        );
        // An object a page wrote with the marker key is written as the object it is.
        let forged = serde_json::json!({super::super::json::RAW_NUMBER: "[[[["});
        assert!(dumps_compact(&forged).starts_with("{\"\\u0000cc-number\":"));
        assert!(number_literal("1.5e+3") && !number_literal("01") && !number_literal("1.") && !number_literal("[1]"));
    }
}
