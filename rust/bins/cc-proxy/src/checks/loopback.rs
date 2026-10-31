//! Calls to the firewall agent's loopback services (`127.0.0.1:3101`, `8791`-`8796`): one JSON
//! POST, never through a proxy, as `urllib` with an empty `ProxyHandler` makes it in `addon.py`.
//!
//! Plain HTTP/1.1 on a fresh connection with `Connection: close`, read to the end of the body. Any
//! status outside 2xx is an error, as `urllib` raises `HTTPError` for one; so is a body that is not
//! JSON. The callers decide what an error means, which is always a refusal or "no answer".

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("bad url {0}")]
    Url(String),
    #[error("timed out")]
    Timeout,
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP {0}")]
    Status(u16),
    #[error("malformed answer")]
    Malformed,
    #[error("answer too large")]
    TooLarge,
    #[error("not JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// The most a loopback answer may be. The addon reads 64 KiB of the judge's answer and everything
/// of the others; their answers are small.
const MAX_ANSWER: usize = 4 * 1024 * 1024;

/// `POST url` with `body` as JSON, the answer parsed. An empty body reads as `{}` (the addon's
/// `answer.read() or b"{}"`).
pub async fn post_json(url: &str, body: &impl Serialize, timeout: Duration) -> Result<Value, CallError> {
    let raw = post(url, &serde_json::to_vec(body)?, timeout).await?;
    if raw.is_empty() {
        return Ok(Value::Object(Default::default()));
    }
    Ok(serde_json::from_slice(&raw)?)
}

/// `POST url` with a JSON body; the answer's body.
pub async fn post(url: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>, CallError> {
    tokio::time::timeout(timeout, post_inner(url, body))
        .await
        .map_err(|_| CallError::Timeout)?
}

async fn post_inner(url: &str, body: &[u8]) -> Result<Vec<u8>, CallError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| CallError::Url(url.to_owned()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(CallError::Url(url.to_owned()));
    }
    let addr = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let mut stream = TcpStream::connect(addr).await?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    read_answer(&mut stream).await
}

async fn read_answer(stream: &mut TcpStream) -> Result<Vec<u8>, CallError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 8192];
    // The head.
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return Err(CallError::Malformed);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CallError::Malformed);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| CallError::Malformed)?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(CallError::Malformed)?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            length = Some(v.parse::<usize>().map_err(|_| CallError::Malformed)?);
        } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let mut rest = buf.split_off(head_end + 4);
    // The rest of the body: to its length, to its last chunk, or to the end of the connection.
    let body = loop {
        if rest.len() > MAX_ANSWER {
            return Err(CallError::TooLarge);
        }
        // A chunked body ends with an empty line: only then is it worth reading the chunks. A
        // chunked answer's `Content-Length`, if it has one, is not its length.
        if chunked {
            if rest.ends_with(b"\r\n")
                && let Some(b) = dechunk(&rest)?
            {
                break b;
            }
        } else if let Some(l) = length
            && rest.len() >= l
        {
            rest.truncate(l);
            break rest;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            if chunked || length.is_some() {
                return Err(CallError::Malformed);
            }
            break rest;
        }
        rest.extend_from_slice(&chunk[..n]);
    };
    if !(200..300).contains(&status) {
        return Err(CallError::Status(status));
    }
    Ok(body)
}

/// A chunked body: `Ok(None)` while it is not complete (its last chunk and trailers not read yet).
fn dechunk(mut raw: &[u8]) -> Result<Option<Vec<u8>>, CallError> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find(raw, b"\r\n") else {
            return Ok(None);
        };
        let size_text = std::str::from_utf8(&raw[..line_end]).map_err(|_| CallError::Malformed)?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| CallError::Malformed)?;
        if size > MAX_ANSWER {
            return Err(CallError::TooLarge);
        }
        raw = &raw[line_end + 2..];
        if size == 0 {
            // Trailers, each a line, up to an empty line.
            loop {
                let Some(end) = find(raw, b"\r\n") else { return Ok(None) };
                if end == 0 {
                    return Ok(Some(out));
                }
                raw = &raw[end + 2..];
            }
        }
        if raw.len() < size.checked_add(2).ok_or(CallError::TooLarge)? {
            return Ok(None);
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::{Answer, FakeService};

    #[tokio::test]
    async fn posts_json_and_reads_the_answer() -> anyhow::Result<()> {
        let svc = FakeService::start().await?;
        svc.answer("/x", Answer::json(200, serde_json::json!({"ok": true})));
        let got = post_json(&svc.url("/x"), &serde_json::json!({"a": 1}), Duration::from_secs(2)).await?;
        assert_eq!(got, serde_json::json!({"ok": true}));
        assert_eq!(svc.calls("/x"), vec![serde_json::json!({"a": 1})]);
        Ok(())
    }

    #[tokio::test]
    async fn refusals_are_errors() -> anyhow::Result<()> {
        let svc = FakeService::start().await?;
        svc.answer("/bad", Answer::json(400, serde_json::json!({"error": "no"})));
        svc.answer("/text", Answer::raw(200, "nope"));
        svc.answer("/empty", Answer::raw(200, ""));
        svc.answer("/chunked", Answer::chunked(200, "{\"rest\":\"a\"}"));
        // Chunked with a Content-Length that is not its length: the chunks decide.
        svc.answer(
            "/both",
            Answer::raw(200, "")
                .chunked_raw("5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n")
                .with_length(3),
        );
        assert_eq!(
            dechunk(b"3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n").ok().flatten().as_deref(),
            Some(b"abc".as_slice())
        );
        assert_eq!(dechunk(b"3\r\nabc\r\n0\r\n").ok().flatten(), None, "not complete yet");
        assert!(
            matches!(dechunk(b"ffffffffffffffff\r\nx\r\n"), Err(CallError::TooLarge)),
            "a size that overflows"
        );
        svc.answer(
            "/huge",
            Answer::raw(200, "").chunked_raw("ffffffffffffffff\r\nx\r\n0\r\n\r\n"),
        );
        svc.answer(
            "/slow",
            Answer::json(200, serde_json::json!({})).delayed(Duration::from_secs(5)),
        );
        let t = Duration::from_millis(500);
        let body = serde_json::json!({});
        assert!(
            post_json(&svc.url("/huge"), &body, t).await.is_err(),
            "a chunk size that overflows"
        );
        assert!(matches!(
            post_json(&svc.url("/bad"), &body, t).await,
            Err(CallError::Status(400))
        ));
        assert!(matches!(
            post_json(&svc.url("/text"), &body, t).await,
            Err(CallError::Json(_))
        ));
        assert_eq!(post_json(&svc.url("/empty"), &body, t).await?, serde_json::json!({}));
        assert_eq!(
            post_json(&svc.url("/chunked"), &body, t).await?,
            serde_json::json!({"rest": "a"})
        );
        assert_eq!(
            post_json(&svc.url("/both"), &body, t).await?,
            serde_json::json!({"a": 1}),
            "the chunks decide, not Content-Length"
        );
        assert!(matches!(
            post_json(&svc.url("/slow"), &body, t).await,
            Err(CallError::Timeout)
        ));
        // Nobody listening.
        let closed = svc.url("/x").replace(&svc.port().to_string(), "1");
        assert!(post_json(&closed, &body, t).await.is_err());
        Ok(())
    }
}
