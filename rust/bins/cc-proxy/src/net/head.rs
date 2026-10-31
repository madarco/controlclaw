//! The first thing a client sends the proxy: a `CONNECT` (what redsocks sends for every connection
//! an agent box makes), or an absolute-form request for plain HTTP (`GET http://host/path`, what a
//! client configured with an explicit proxy sends, and what the smoke rigs use). Then, inside a
//! CONNECT tunnel, the protocol peek: TLS, HTTP or other TCP, decided the way mitmproxy 12.2.2's
//! `next_layer` decides it (`mitmproxy/addons/next_layer.py`).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::flow::Authority;

/// The request head may not be longer than this.
pub const MAX_HEAD: usize = 8 * 1024;
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a tunnel may stay silent before its first bytes. mitmproxy waits with no limit; a
/// limit keeps descriptors from piling up behind tunnels that never speak (Chrome's idle
/// preconnects among them): closed with no record. redsocks connects as soon as the client does,
/// so a client that waits for the server reaches us silent; a tunnel rule for its address and port
/// lets the server speak ([`SERVER_FIRST_WAIT`]).
pub const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a silent client is waited for before a tunnel rule for its address and port is applied
/// with no bytes (the server speaks first). TLS and HTTP clients speak at once.
pub const SERVER_FIRST_WAIT: Duration = Duration::from_secs(3);

/// How long fewer than 3 first bytes wait for more before they are judged as they are.
pub const SHORT_FIRST_WAIT: Duration = Duration::from_secs(1);

/// What the client asked the proxy for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// `CONNECT host:port`. Bytes after the head stay in the buffer.
    Connect(Authority),
    /// An absolute-form request (`GET http://host/path HTTP/1.1`). The head is left in the buffer,
    /// so the HTTP layer reads the request as it came.
    Absolute,
    /// Anything else: an origin-form request or a method the proxy does not take.
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum HeadError {
    #[error("closed before the request head")]
    Closed,
    #[error("request head too long")]
    TooLong,
    #[error("no request head in time")]
    Timeout,
    #[error("bad CONNECT target {0:?}")]
    BadTarget(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Read the request head into `buf`. A CONNECT's head is taken out of `buf` (a client may send its
/// ClientHello without waiting for the 200, so what follows stays); any other head is left in.
pub async fn read_head<S: AsyncRead + Unpin>(client: &mut S, buf: &mut Vec<u8>) -> Result<Head, HeadError> {
    let end = tokio::time::timeout(HEAD_TIMEOUT, async {
        let mut searched: usize = 0;
        loop {
            // Only the new bytes (and the three before them) can complete the terminator.
            let from = searched.saturating_sub(3);
            if let Some(i) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
                let end = from + i + 4;
                return if end > MAX_HEAD {
                    Err(HeadError::TooLong)
                } else {
                    Ok(end)
                };
            }
            if buf.len() > MAX_HEAD {
                return Err(HeadError::TooLong);
            }
            searched = buf.len();
            let mut chunk = [0u8; 2048];
            let n = client.read(&mut chunk).await?;
            if n == 0 {
                return Err(HeadError::Closed);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| HeadError::Timeout)??;
    let head = parse_head(&buf[..end])?;
    if matches!(head, Head::Connect(_)) {
        buf.drain(..end);
    }
    Ok(head)
}

fn parse_head(head: &[u8]) -> Result<Head, HeadError> {
    let text = String::from_utf8_lossy(head);
    let line = text.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method.eq_ignore_ascii_case("CONNECT") {
        return parse_authority(target).map(Head::Connect);
    }
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok(Head::Absolute);
    }
    Ok(Head::Other(method.to_owned()))
}

/// `host:port`, `[v6]:port`. The port is required, as in a CONNECT it always is.
pub fn parse_authority(target: &str) -> Result<Authority, HeadError> {
    let bad = || HeadError::BadTarget(target.chars().take(100).collect());
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        rest.split_once("]:").ok_or_else(bad)?
    } else {
        target.rsplit_once(':').ok_or_else(bad)?
    };
    if host.is_empty() {
        return Err(bad());
    }
    Ok(Authority {
        host: host.to_owned(),
        port: port.parse().map_err(|_| bad())?,
    })
}

/// What a tunnel carries, from its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tls,
    Http,
    /// Not TLS and not HTTP: dropped unless a tunnel or residential rule names its IP and port.
    Tcp,
}

/// mitmproxy's `starts_like_tls_record`: a handshake record with a TLS 1.x version.
pub fn starts_like_tls(data: &[u8]) -> bool {
    data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03
}

/// mitmproxy's `probably_no_http` (next_layer.py, step 5d), for the first bytes a client sent.
/// There are no server bytes to consider: nothing is dialled before the decision.
pub fn probably_not_http(data: &[u8]) -> bool {
    let space = data.iter().position(|b| *b == b' ');
    // Python's `find` gives -1 for "not there", which is below any space position.
    let newline = data.iter().position(|b| *b == b'\n');
    data.len() < 3
        || space.is_none()
        || space.is_some_and(|s| newline.is_none_or(|n| s > n))
        || !data[..3].iter().all(u8::is_ascii_alphabetic)
        || data.starts_with(b"SSH")
}

/// Classify a tunnel by its first bytes, or `None` while more are needed to tell.
///
/// mitmproxy decides on the first bytes it has, with two waits, both taken here: with
/// `--ignore-hosts` set (the unit sets it for the control plane), a request line that has
/// `HTTP/` but no line end yet waits for the rest, and so does a ClientHello that is not complete
/// (`tls::read_client_hello` waits for that). Fewer than 3 bytes also wait here, for at most
/// [`SHORT_FIRST_WAIT`] ([`sniff`]): mitmproxy takes them as "not TLS" at once, which drops a
/// ClientHello whose first segment is that short.
pub fn classify(data: &[u8]) -> Option<Protocol> {
    if data.len() < 3 {
        return None;
    }
    if starts_like_tls(data) {
        return Some(Protocol::Tls);
    }
    if awaits_host_header(data) {
        return None;
    }
    Some(if probably_not_http(data) {
        Protocol::Tcp
    } else {
        Protocol::Http
    })
}

/// mitmproxy's `_get_host_header` raising `NeedsMoreData`: `[A-Z]{3,}.+HTTP/` (any case) on the
/// first line, and no `\r\n` yet.
fn awaits_host_header(data: &[u8]) -> bool {
    let letters = data.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if letters < 3 {
        return false;
    }
    // `.` does not match a newline, so `HTTP/` must be on the first line, after at least one byte.
    let first_line = data[letters..].split(|b| *b == b'\n').next().unwrap_or(&[]);
    let has_http = first_line.len() > 1 && first_line[1..].windows(5).any(|w| w.eq_ignore_ascii_case(b"HTTP/"));
    has_http && !data.windows(2).any(|w| w == b"\r\n")
}

/// Read the client's first bytes inside a tunnel until [`classify`] can decide. `Ok(None)` when it
/// closed first, or stayed quiet past [`FIRST_BYTES_TIMEOUT`]. Nothing is dialled
/// before this returns, as with mitmproxy's `connection_strategy=lazy`.
pub async fn sniff<S: AsyncRead + Unpin>(client: &mut S, buf: &mut Vec<u8>) -> std::io::Result<Option<Protocol>> {
    sniff_within(client, buf, FIRST_BYTES_TIMEOUT).await
}

async fn sniff_within<S: AsyncRead + Unpin>(
    client: &mut S,
    buf: &mut Vec<u8>,
    wait: Duration,
) -> std::io::Result<Option<Protocol>> {
    let read = async {
        loop {
            if let Some(p) = classify(buf) {
                return Ok(Some(p));
            }
            if buf.len() >= MAX_HEAD {
                // Past this, decide on what there is, as mitmproxy would have from the start.
                return Ok(Some(if probably_not_http(buf) {
                    Protocol::Tcp
                } else {
                    Protocol::Http
                }));
            }
            let mut chunk = [0u8; 2048];
            let n = if buf.is_empty() {
                client.read(&mut chunk).await?
            } else if buf.len() < 3 {
                match tokio::time::timeout(SHORT_FIRST_WAIT, client.read(&mut chunk)).await {
                    Ok(n) => n?,
                    // What mitmproxy decides on these bytes: not TLS, too short for HTTP.
                    Err(_) => return Ok(Some(Protocol::Tcp)),
                }
            } else {
                client.read(&mut chunk).await?
            };
            if n == 0 {
                return Ok(None);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };
    tokio::time::timeout(wait, read).await.unwrap_or(Ok(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that never speaks is let go once the wait is over, never held open; one that
    /// closes is let go at once. Neither is judged.
    #[tokio::test]
    async fn a_silent_client_is_raw_tcp_after_the_wait() -> std::io::Result<()> {
        let wait = Duration::from_millis(50);
        let (mut ours, _theirs) = tokio::io::duplex(64);
        let mut buf = Vec::new();
        assert_eq!(sniff_within(&mut ours, &mut buf, wait).await?, None);
        assert!(buf.is_empty());
        let (mut ours, theirs) = tokio::io::duplex(64);
        drop(theirs);
        assert_eq!(sniff_within(&mut ours, &mut buf, wait).await?, None);
        Ok(())
    }

    async fn head(bytes: &[u8]) -> (Result<Head, HeadError>, Vec<u8>) {
        let mut buf = Vec::new();
        let mut src = bytes;
        let h = read_head(&mut src, &mut buf).await;
        (h, buf)
    }

    #[tokio::test]
    async fn reads_connect_and_keeps_what_follows() {
        let (h, buf) = head(b"CONNECT 203.0.113.5:443 HTTP/1.1\r\nHost: x\r\n\r\n\x16\x03\x01").await;
        assert_eq!(
            h.ok(),
            Some(Head::Connect(Authority {
                host: "203.0.113.5".into(),
                port: 443
            }))
        );
        assert_eq!(buf, b"\x16\x03\x01");
        let (h, _) = head(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            h.ok(),
            Some(Head::Connect(Authority {
                host: "2001:db8::1".into(),
                port: 8443
            }))
        );
        assert!(matches!(
            head(b"CONNECT example.com HTTP/1.1\r\n\r\n").await.0,
            Err(HeadError::BadTarget(_))
        ));
    }

    #[tokio::test]
    async fn leaves_an_absolute_form_request_in_the_buffer() {
        let req = b"GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n";
        let (h, buf) = head(req).await;
        assert_eq!(h.ok(), Some(Head::Absolute));
        assert_eq!(buf, req);
        assert!(matches!(
            head(b"GET / HTTP/1.1\r\n\r\n").await.0,
            Ok(Head::Other(m)) if m == "GET"
        ));
        assert!(matches!(head(b"GET / HTTP/1.1\r\n").await.0, Err(HeadError::Closed)));
    }

    #[tokio::test]
    async fn refuses_a_head_past_the_limit() {
        let mut long = b"CONNECT a:1 HTTP/1.1\r\nX: ".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        long.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(head(&long).await.0, Err(HeadError::TooLong)));
    }

    #[test]
    fn classifies_like_next_layer() {
        let c = classify;
        assert_eq!(c(&[0x16, 0x03, 0x01, 0x02, 0x00]), Some(Protocol::Tls));
        assert_eq!(c(b"GET / HTTP/1.1\r\n"), Some(Protocol::Http));
        assert_eq!(c(b"post /x HTTP/1.1\r\nHost: a\r\n"), Some(Protocol::Http));
        // STUN-like binary, SSH banners, no space, the space after the first newline, digits.
        assert_eq!(c(b"\x00\x01\x00\x00!\x12\xa4B"), Some(Protocol::Tcp));
        assert_eq!(c(b"SSH-2.0-OpenSSH_9.6\r\n"), Some(Protocol::Tcp));
        assert_eq!(c(b"hello"), Some(Protocol::Tcp));
        assert_eq!(c(b"HELO\nx y"), Some(Protocol::Tcp));
        assert_eq!(c(b"123 abc"), Some(Protocol::Tcp));
        // A TLS record with a version mitmproxy does not take is neither TLS nor HTTP.
        assert_eq!(c(&[0x16, 0x03, 0x09]), Some(Protocol::Tcp));
    }

    #[test]
    fn waits_where_mitmproxy_waits() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(&[0x16, 0x03]), None);
        // A request line cut before its line end.
        assert_eq!(classify(b"POST /x HTTP/1.1"), None);
        assert_eq!(classify(b"GET /x HT"), Some(Protocol::Tcp));
    }

    #[tokio::test]
    async fn sniffs_across_reads() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for part in [&b"\x16"[..], b"\x03", b"\x01\x00"] {
                if tx.write_all(part).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let mut buf = Vec::new();
        assert_eq!(sniff(&mut rx, &mut buf).await.ok().flatten(), Some(Protocol::Tls));
        let mut closed: &[u8] = b"GE";
        let mut buf = Vec::new();
        assert_eq!(sniff(&mut closed, &mut buf).await.ok().flatten(), None);
        // Two bytes and then quiet: judged as they are once the short wait is over.
        let (mut tx, mut rx) = tokio::io::duplex(64);
        {
            use tokio::io::AsyncWriteExt;
            tx.write_all(b"\x16\x03").await.ok();
        }
        let mut buf = Vec::new();
        assert_eq!(sniff(&mut rx, &mut buf).await.ok().flatten(), Some(Protocol::Tcp));
        drop(tx);
    }
}
