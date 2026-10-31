//! Answers the proxy gives itself: the addon's JSON refusals and mitmproxy's own error page.

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Response, StatusCode, Version};

/// The `Server` header on mitmproxy's own answers.
const SERVER: &str = "mitmproxy 12.2.2";

/// A JSON answer, as `http.Response.make(status, json.dumps(...), {"Content-Type": ...})` makes it.
pub fn json(status: StatusCode, body: &serde_json::Value) -> Response<Bytes> {
    let text = py_json(body);
    let mut r = Response::new(Bytes::from(text));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

/// `json.dumps` with its default separators (`", "` and `": "`) and ASCII escapes, so a body is
/// byte for byte what the addon sent.
pub fn py_json(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_py(v, &mut out, true);
    out
}

/// `json.dumps(v, ensure_ascii=False)`: the default separators, text left as UTF-8. What the addon
/// writes to `traffic.jsonl` and `pending.jsonl`.
pub fn py_json_utf8(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_py(v, &mut out, false);
    out
}

fn write_py(v: &serde_json::Value, out: &mut String, ascii: bool) {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_str(k, out, ascii);
                out.push_str(": ");
                write_py(v, out, ascii);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py(v, out, ascii);
            }
            out.push(']');
        }
        Value::String(s) => write_str(s, out, ascii),
        other => out.push_str(&other.to_string()),
    }
}

/// A JSON string with `ensure_ascii=True`: everything past ASCII as `\uXXXX` (surrogate pairs above
/// the BMP), as Python writes it.
fn write_str(s: &str, out: &mut String, ascii: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (ascii && (c as u32) > 0x7e) => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// mitmproxy's error page (`make_error_response` / `format_error`), for an answer it never got.
pub fn mitmproxy_error(status: StatusCode, message: &str, version: Version) -> Response<Bytes> {
    let reason = status.canonical_reason().unwrap_or("Unknown");
    let code = status.as_u16();
    let body = format!(
        "<html>\n<head>\n    <title>{code} {reason}</title>\n</head>\n<body>\n    <h1>{code} {reason}</h1>\n    <p>{}</p>\n</body>\n</html>",
        html_escape(message)
    );
    let mut r = Response::new(Bytes::from(body));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(header::SERVER, HeaderValue::from_static(SERVER));
    if version != Version::HTTP_2 {
        h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    r.extensions_mut().insert(ProxyMade);
    r
}

/// Marks an answer the proxy made itself and that ends the agent's connection (mitmproxy's error
/// page): its `Connection: close` is meant for the agent, not a site's header passed along.
#[derive(Debug, Clone, Copy)]
pub struct ProxyMade;

/// Python's `html.escape` (quotes included).
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_as_python_does() {
        let v = serde_json::json!({"error": "blocked_by_policy", "host": "é.example", "n": 3, "l": [1, "a"]});
        assert_eq!(
            py_json(&v),
            "{\"error\": \"blocked_by_policy\", \"host\": \"\\u00e9.example\", \"n\": 3, \"l\": [1, \"a\"]}"
        );
        assert_eq!(
            py_json_utf8(&serde_json::json!({"host": "é.example", "c": "a\u{7f}\n"})),
            "{\"host\": \"é.example\", \"c\": \"a\u{7f}\\n\"}"
        );
        assert_eq!(py_json(&serde_json::json!("\u{1F600}")), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn error_page_is_mitmproxys() {
        let r = mitmproxy_error(StatusCode::BAD_GATEWAY, "a <b>", Version::HTTP_11);
        assert!(String::from_utf8_lossy(r.body()).contains("<p>a &lt;b&gt;</p>"));
        assert_eq!(r.headers()[header::CONNECTION], "close");
        assert!(
            mitmproxy_error(StatusCode::BAD_GATEWAY, "x", Version::HTTP_2)
                .headers()
                .get(header::CONNECTION)
                .is_none()
        );
    }
}
