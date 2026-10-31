//! JSON read as Python's `json.loads(text, object_pairs_hook=_no_duplicates)` reads it:
//!
//! - an object that repeats a key is an error, at any depth (which copy a service reads is not
//!   ours to guess, so such a body is refused rather than checked on the other copy);
//! - `NaN`, `Infinity` and `-Infinity` are numbers (kept here as `null`: no check reads a number);
//! - a lone surrogate escape (`"\ud800"`) is a string (it becomes U+FFFD here);
//! - whitespace is space, tab, line feed and carriage return; nothing may follow the value.
//!
//! serde_json refuses the second and third, so a body Python reads, and checks, would be read as
//! a plain string or refused here. Nesting is not limited by recursion: an explicit stack.

use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum JsonError {
    #[error("a JSON object repeats a key")]
    Duplicate,
    #[error("not JSON at {0}")]
    Invalid(usize),
}

enum Frame {
    Array(Vec<Value>),
    /// The object so far and the key whose value is being read.
    Object(Map<String, Value>, String),
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
    /// Whether `NaN`, `Infinity` and `-Infinity` are numbers.
    constants: bool,
    /// Numbers kept as written ([`loads_raw_numbers`]).
    raw: bool,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn err<T>(&self) -> Result<T, JsonError> {
        Err(JsonError::Invalid(self.i))
    }
    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        // At the opening quote.
        self.i += 1;
        let mut out = String::new();
        let mut units: Vec<u16> = Vec::new();
        let flush = |units: &mut Vec<u16>, out: &mut String| {
            out.extend(char::decode_utf16(units.drain(..)).map(|r| r.unwrap_or('\u{fffd}')));
        };
        loop {
            let Some(&c) = self.s.get(self.i) else {
                return self.err();
            };
            match c {
                b'"' => {
                    self.i += 1;
                    flush(&mut units, &mut out);
                    return Ok(out);
                }
                b'\\' => {
                    let Some(&e) = self.s.get(self.i + 1) else {
                        return self.err();
                    };
                    self.i += 2;
                    if e == b'u' {
                        let hex = self.s.get(self.i..self.i + 4).and_then(|h| std::str::from_utf8(h).ok());
                        let Some(u) = hex.and_then(|h| u16::from_str_radix(h, 16).ok()) else {
                            return self.err();
                        };
                        self.i += 4;
                        units.push(u);
                        continue;
                    }
                    flush(&mut units, &mut out);
                    out.push(match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => return self.err(),
                    });
                }
                // Python's strict mode refuses control characters inside a string.
                0..=0x1f => return self.err(),
                _ => {
                    flush(&mut units, &mut out);
                    let start = self.i;
                    while self.i < self.s.len() && !matches!(self.s[self.i], b'"' | b'\\' | 0..=0x1f) {
                        self.i += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|_| JsonError::Invalid(start))?);
                }
            }
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.i;
        if self.constants && self.eat(b"-Infinity") {
            return Ok(self.constant("-inf"));
        }
        self.eat(b"-");
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
            }
            _ => return self.err(),
        }
        let mut float = false;
        if self.s.get(self.i) == Some(&b'.') && self.s.get(self.i + 1).is_some_and(u8::is_ascii_digit) {
            float = true;
            self.i += 1;
            while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                self.i += 1;
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                float = true;
                while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
            } else {
                self.i = save;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| JsonError::Invalid(start))?;
        // A sign-in's JSON (no constants): a float `1e400` is infinity to Python, refused like
        // `Infinity` (main #617). An integer that long is exact to Python, and taken.
        if !self.constants && float && text.parse::<f64>().is_ok_and(|f| !f.is_finite()) {
            return Err(JsonError::Invalid(start));
        }
        if self.raw {
            // Kept as a number when it reads back as written; otherwise as its literal.
            let n = if float {
                text.parse::<f64>().ok().and_then(serde_json::Number::from_f64)
            } else {
                text.parse::<i64>()
                    .ok()
                    .map(Into::into)
                    .or_else(|| text.parse::<u64>().ok().map(Into::into))
            };
            return Ok(match n {
                Some(n) if n.to_string() == text => Value::Number(n),
                _ => raw_number(text),
            });
        }
        if !float {
            if let Ok(n) = text.parse::<i64>() {
                return Ok(n.into());
            }
            if let Ok(n) = text.parse::<u64>() {
                return Ok(n.into());
            }
        }
        // A float, or an integer too big for 64 bits (Python keeps it exact; no check reads it).
        Ok(text
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number))
    }

    /// A scalar, or the start of a container (pushed on `stack`; `None` returned).
    fn value(&mut self, stack: &mut Vec<Frame>) -> Result<Option<Value>, JsonError> {
        self.ws();
        let Some(&c) = self.s.get(self.i) else {
            return self.err();
        };
        Ok(Some(match c {
            b'{' => {
                self.i += 1;
                self.ws();
                if self.eat(b"}") {
                    return Ok(Some(Value::Object(Map::new())));
                }
                let key = self.key()?;
                stack.push(Frame::Object(Map::new(), key));
                return Ok(None);
            }
            b'[' => {
                self.i += 1;
                self.ws();
                if self.eat(b"]") {
                    return Ok(Some(Value::Array(Vec::new())));
                }
                stack.push(Frame::Array(Vec::new()));
                return Ok(None);
            }
            b'"' => Value::String(self.string()?),
            b't' if self.eat(b"true") => Value::Bool(true),
            b'f' if self.eat(b"false") => Value::Bool(false),
            b'n' if self.eat(b"null") => Value::Null,
            b'N' if self.constants && self.eat(b"NaN") => self.constant("nan"),
            b'I' if self.constants && self.eat(b"Infinity") => self.constant("inf"),
            b'-' | b'0'..=b'9' => self.number()?,
            _ => return self.err(),
        }))
    }

    /// `NaN`, `Infinity`, `-Infinity`: `null`, or with numbers kept, Python's `str()` of the float.
    fn constant(&self, shown: &str) -> Value {
        if self.raw { raw_number(shown) } else { Value::Null }
    }

    /// `"key" :`, at a quote after optional whitespace.
    fn key(&mut self) -> Result<String, JsonError> {
        self.ws();
        if self.s.get(self.i) != Some(&b'"') {
            return self.err();
        }
        let k = self.string()?;
        self.ws();
        if !self.eat(b":") {
            return self.err();
        }
        Ok(k)
    }
}

#[allow(clippy::expect_used)] // a fixed expression, checked by the tests
static JSON_ESCAPE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r#"\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))"#).expect("valid"));

/// `_json_unescape_loose`: JSON escapes undone in a string that may not parse.
pub fn unescape_loose(text: &str) -> String {
    JSON_ESCAPE
        .replace_all(text, |c: &regex::Captures<'_>| {
            if let Some(hex) = c.get(1) {
                // A lone surrogate cannot be a Rust character; it matches no rule either way.
                return u32::from_str_radix(hex.as_str(), 16)
                    .ok()
                    .and_then(char::from_u32)
                    .unwrap_or('\u{fffd}')
                    .to_string();
            }
            match c.get(2).map_or("", |m| m.as_str()) {
                "b" => "\u{8}".into(),
                "f" => "\u{c}".into(),
                "n" => "\n".into(),
                "r" => "\r".into(),
                "t" => "\t".into(),
                other => other.to_owned(),
            }
        })
        .into_owned()
}

/// `json.loads(text, object_pairs_hook=_no_duplicates)`.
pub fn loads_strict(text: &str) -> Result<Value, JsonError> {
    read(text, true, true, false)
}

/// `json.loads(text)`: a repeated key is taken, the last copy winning.
pub fn loads(text: &str) -> Result<Value, JsonError> {
    read(text, false, true, false)
}

/// A sign-in's JSON (`_strict_json`): a repeated key, `NaN`, `Infinity` and `-Infinity` refused.
pub fn loads_no_constants(text: &str) -> Result<Value, JsonError> {
    read(text, true, false, false)
}

/// A sign-in's JSON with numbers kept as written ([`loads_no_constants`] and [`loads_raw_numbers`]):
/// what a sign-in is written out again from, so its numbers keep their digits.
pub fn loads_sign_in_raw(text: &str) -> Result<Value, JsonError> {
    read(text, true, false, true)
}

/// The key of the one-key object a number stands as when it does not read back as written
/// (`1e3`, `1.50`, `-0`, digits past 64 bits, `NaN`): `{RAW_NUMBER: "1e3"}`. A JSON key cannot
/// start with a NUL unless escaped, and one that does only adds a text to check.
pub const RAW_NUMBER: &str = "\u{0}cc-number";

fn raw_number(text: &str) -> Value {
    let mut m = Map::new();
    m.insert(RAW_NUMBER.into(), Value::String(text.to_owned()));
    Value::Object(m)
}

/// The literal of a number read with [`loads_raw_numbers`] / [`loads_strict_raw_numbers`]:
/// `_JsonInt.raw` / `_JsonFloat.raw`, or `str()` of a plain number.
pub fn number_text(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::Object(m) if m.len() == 1 => m.get(RAW_NUMBER).and_then(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

/// A number kept as written ([`RAW_NUMBER`]) as a plain JSON number, as `json.dumps` writes a
/// `_JsonInt` or `_JsonFloat`; anything else as it is.
pub fn plain_number(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.len() == 1 && m.contains_key(RAW_NUMBER) => {
            let t = m.get(RAW_NUMBER).and_then(Value::as_str).unwrap_or("");
            t.parse::<i64>()
                .ok()
                .map(Value::from)
                .or_else(|| {
                    t.parse::<f64>()
                        .ok()
                        .and_then(serde_json::Number::from_f64)
                        .map(Value::Number)
                })
                .unwrap_or(Value::Null)
        }
        other => other.clone(),
    }
}

/// `_json_loads`: no repeated key, numbers kept as written (`parse_int=_JsonInt`,
/// `parse_float=_JsonFloat`).
pub fn loads_strict_raw_numbers(text: &str) -> Result<Value, JsonError> {
    read(text, true, true, true)
}

/// `json.loads(text, parse_int=_JsonInt, parse_float=_JsonFloat)`.
pub fn loads_raw_numbers(text: &str) -> Result<Value, JsonError> {
    read(text, false, true, true)
}

fn read(text: &str, strict: bool, constants: bool, raw: bool) -> Result<Value, JsonError> {
    let mut r = Reader {
        s: text.as_bytes(),
        i: 0,
        constants,
        raw,
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut done = r.value(&mut stack)?;
    loop {
        let Some(v) = done.take() else {
            // A container was opened: read its first or next value.
            done = r.value(&mut stack)?;
            continue;
        };
        let Some(top) = stack.last_mut() else {
            r.ws();
            if r.i != r.s.len() {
                return r.err();
            }
            return Ok(v);
        };
        // A value finished inside the container on top: add it, then a comma or the close.
        match top {
            Frame::Array(items) => items.push(v),
            Frame::Object(map, key) => {
                if strict && map.contains_key(key.as_str()) {
                    return Err(JsonError::Duplicate);
                }
                map.insert(std::mem::take(key), v);
            }
        }
        r.ws();
        let is_object = matches!(top, Frame::Object(..));
        if r.eat(b",") {
            if is_object {
                let k = r.key()?;
                if let Some(Frame::Object(_, key)) = stack.last_mut() {
                    *key = k;
                }
            }
            done = r.value(&mut stack)?;
            continue;
        }
        let close: &[u8] = if is_object { b"}" } else { b"]" };
        if !r.eat(close) {
            return r.err();
        }
        done = Some(match stack.pop() {
            Some(Frame::Array(items)) => Value::Array(items),
            Some(Frame::Object(map, _)) => Value::Object(map),
            None => return r.err(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repeated_keys_are_refused_at_any_depth() {
        assert_eq!(loads_strict(r#"{"a": 1, "a": 2}"#), Err(JsonError::Duplicate));
        assert_eq!(loads_strict(r#"[{"x": {"a": 1, "a": 2}}]"#), Err(JsonError::Duplicate));
        assert_eq!(
            loads_strict(r#" {"a": [1, "b", null, true, -2.5e3, {}]} "#),
            Ok(json!({"a": [1, "b", null, true, -2500.0, {}]}))
        );
        assert!(loads_strict("{} x").is_err());
        assert!(loads_strict("").is_err());
        assert!(loads_strict("[1,]").is_err());
        assert!(loads_strict("{\"a\":1,}").is_err());
        assert!(loads_strict("\"a\nb\"").is_err(), "a raw line break in a string");
        // Key order is kept.
        assert_eq!(
            loads_strict(r#"{"b": 1, "a": 2}"#).map(|v| v.to_string()),
            Ok(r#"{"b":1,"a":2}"#.to_owned())
        );
    }

    #[test]
    fn what_python_reads_and_serde_does_not() {
        assert_eq!(
            loads_strict(r#"[NaN, Infinity, -Infinity, {"caption": "x"}]"#),
            Ok(json!([null, null, null, {"caption": "x"}]))
        );
        assert_eq!(
            loads_strict(r#""\ud800 \ud83d\ude00""#),
            Ok(json!("\u{fffd} \u{1f600}"))
        );
        assert_eq!(
            loads_strict("123456789012345678901234567890").map(|v| v.is_number()),
            Ok(true)
        );
        let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
        assert!(loads_strict(&deep).is_ok(), "no recursion limit");
        assert_eq!(loads(r#"{"a": 1, "a": 2}"#), Ok(json!({"a": 2})), "the last copy wins");
        assert!(loads_no_constants("[NaN]").is_err() && loads_no_constants("[-Infinity]").is_err());
        // main #617: a float that reads as infinity is refused like `Infinity`, on both readers;
        // an integer that long is exact to Python, and taken.
        let long_int = format!("[{}]", "9".repeat(400));
        for read in [loads_no_constants, loads_sign_in_raw] {
            assert!(read("[1e400]").is_err() && read("[-1e400]").is_err());
            assert!(read(&long_int).is_ok() && read("[1e300]").is_ok());
        }
    }
}
