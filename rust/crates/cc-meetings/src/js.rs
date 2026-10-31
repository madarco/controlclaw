//! How JavaScript reads strings and numbers, where the meetings code must match the TS: lengths
//! and slices in UTF-16 units, safe integers.

use serde_json::Value;

/// JavaScript truthiness of an optional JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// `s.length`.
pub fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `s.slice(0, n)`, never splitting a character.
pub fn head16(s: &str, n: usize) -> String {
    let mut units = 0;
    s.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= n
        })
        .collect()
}

/// `s.slice(-n)`, never splitting a character.
pub fn tail16(s: &str, n: usize) -> String {
    let mut units = 0;
    let mut out: Vec<char> = s
        .chars()
        .rev()
        .take_while(|c| {
            units += c.len_utf16();
            units <= n
        })
        .collect();
    out.reverse();
    out.into_iter().collect()
}

/// A character JavaScript's `\s` and `trim()` take as white space.
pub fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// `s.trim()`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(js_space)
}

/// `s.trim().replace(/\s+/g, " ")`.
pub fn js_tidy(s: &str) -> String {
    js_trim(s)
        .split(js_space)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `Number.isSafeInteger(v)`, and the value.
pub fn safe_int(v: Option<&Value>) -> Option<i64> {
    let f = v?.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

/// `String(v)` for a JSON value (`undefined` when absent).
/// A setting that must be one of a few words, where settings are parsed: the text, or nothing.
/// Rust only: the TS read these with `String(x)`, so a one-element array (`["bidi"]`) passed.
pub fn js_word(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or_default()
}

pub fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
            _ => n.to_string(),
        },
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| if x.is_null() { String::new() } else { js_string(Some(x)) })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// `Number(v)` for a JSON value, for the forms the agent meets (decimal text, numbers, booleans).
pub fn js_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else if t
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
            {
                t.parse().unwrap_or(f64::NAN)
            } else {
                f64::NAN
            }
        }
        Some(Value::Array(a)) if a.is_empty() => 0.0,
        Some(Value::Array(a)) if a.len() == 1 => js_number(Some(&Value::String(js_string(a.first())))),
        Some(_) => f64::NAN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn utf16_slices_and_numbers() {
        assert_eq!(head16("a😀b", 2), "a");
        assert_eq!(head16("a😀b", 3), "a😀");
        assert_eq!(tail16("a😀b", 3), "😀b");
        assert_eq!(len16("😀"), 2);
        assert_eq!(safe_int(Some(&json!(3))), Some(3));
        assert_eq!(safe_int(Some(&json!(1.5))), None);
        assert_eq!(js_string(Some(&json!(5))), "5");
        assert_eq!(js_number(Some(&json!("175"))), 175.0);
        assert!(js_number(Some(&json!("x"))).is_nan());
        // NEL is not JS white space; the BOM is.
        assert_eq!(js_tidy("\u{FEFF} a \t\u{3000}b\u{85} "), "a b\u{85}");
    }
}
