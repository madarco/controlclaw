//! TLS. Owner: W1.
//!
//! Here now: reading a whole ClientHello before anything is decided, so a connection can be passed
//! through untouched (the bytes read are written upstream as they came) or, later, intercepted.
//!
//! W1: leaf minting from the CA in `Config::ca_dir` (rcgen, LRU cache), the rustls server with
//! ALPN h2/http1.1 fed with the buffered bytes, and the upstream rustls client.

pub mod anchors;
pub mod ca;
pub mod chrome;
pub mod config;
pub mod hello;
mod intercept;
pub mod mirror;

pub use intercept::intercept;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// A ClientHello bigger than this is refused. Post-quantum key shares make Chrome's about 1.8 KB;
/// 64 KiB leaves room for anything legitimate and bounds what a client can make us hold.
pub const MAX_HELLO_BYTES: usize = 64 * 1024;

/// How long a client may take to send its ClientHello.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

const RECORD_HEADER: usize = 5;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Lower-cased server name, if the client sent one.
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    #[error("the connection closed before a full ClientHello")]
    Closed,
    #[error("no ClientHello within the time allowed")]
    Timeout,
    #[error("the ClientHello is larger than allowed")]
    TooLarge,
    #[error("not a TLS ClientHello")]
    NotHello,
    /// The server name is not a host name or an address (`[a.example].b.example`, spaces, ...):
    /// nothing may be matched or dialled on it.
    #[error("the ClientHello names {0:?}, which is not a host name")]
    BadSni(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Read from `stream` into `buf` (which may already hold bytes) until it holds a whole ClientHello,
/// reassembled across records and TCP segments, and parse it. `buf` keeps every byte read, so the
/// caller can forward them unchanged.
pub async fn read_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> Result<ClientHello, HelloError> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(handshake) = complete_handshake(buf)? {
                return parse_hello(&handshake);
            }
            if buf.len() >= MAX_HELLO_BYTES {
                return Err(HelloError::TooLarge);
            }
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(HelloError::Closed);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| HelloError::Timeout)?
}

/// The handshake message, once `buf` holds all of it: the payloads of consecutive handshake
/// records joined, cut at the message's own length. `None` while more is needed.
fn complete_handshake(buf: &[u8]) -> Result<Option<Vec<u8>>, HelloError> {
    let mut msg = Vec::new();
    let mut at = 0;
    while buf.len() >= at + RECORD_HEADER {
        if buf[at] != CONTENT_HANDSHAKE {
            return Err(HelloError::NotHello);
        }
        let len = usize::from(u16::from_be_bytes([buf[at + 3], buf[at + 4]]));
        if buf.len() < at + RECORD_HEADER + len {
            break;
        }
        msg.extend_from_slice(&buf[at + RECORD_HEADER..at + RECORD_HEADER + len]);
        at += RECORD_HEADER + len;
        if msg.len() >= 4 {
            if msg[0] != HANDSHAKE_CLIENT_HELLO {
                return Err(HelloError::NotHello);
            }
            let want = 4 + (usize::from(msg[1]) << 16 | usize::from(msg[2]) << 8 | usize::from(msg[3]));
            if want > MAX_HELLO_BYTES {
                return Err(HelloError::TooLarge);
            }
            if msg.len() >= want {
                msg.truncate(want);
                return Ok(Some(msg));
            }
        }
    }
    // The first byte alone says whether this can be TLS at all.
    if buf.first().is_some_and(|b| *b != CONTENT_HANDSHAKE) {
        return Err(HelloError::NotHello);
    }
    Ok(None)
}

fn parse_hello(handshake: &[u8]) -> Result<ClientHello, HelloError> {
    use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake};
    let (_, msg) = tls_parser::parse_tls_message_handshake(handshake).map_err(|_| HelloError::NotHello)?;
    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg else {
        return Err(HelloError::NotHello);
    };
    let mut hello = ClientHello {
        sni: None,
        alpn: Vec::new(),
    };
    let Some(ext) = ch.ext else { return Ok(hello) };
    let (_, exts) = tls_parser::parse_tls_client_hello_extensions(ext).map_err(|_| HelloError::NotHello)?;
    for e in exts {
        match e {
            TlsExtension::SNI(names) => {
                // Type 0 is host_name, the only one defined.
                let Some((_, raw)) = names.iter().find(|(t, _)| t.0 == 0) else {
                    continue;
                };
                let raw = String::from_utf8_lossy(raw);
                // The one form every later decision reads: matched and dialled as the same string.
                hello.sni = Some(
                    crate::net::destination::wire_name(&raw)
                        .ok_or_else(|| HelloError::BadSni(raw.chars().take(100).collect()))?,
                );
            }
            TlsExtension::ALPN(protos) => hello.alpn = protos.iter().map(|p| p.to_vec()).collect(),
            _ => {}
        }
    }
    Ok(hello)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ClientHello with an SNI, split into records of at most `record_max` bytes.
    pub(crate) fn hello_records(sni: &str, record_max: usize) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let list_len = 3 + name.len();
        sni_ext.extend_from_slice(&[0x00, 0x00]); // type: server_name
        sni_ext.extend_from_slice(&u16::try_from(list_len + 2).unwrap_or(0).to_be_bytes());
        sni_ext.extend_from_slice(&u16::try_from(list_len).unwrap_or(0).to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        body.extend_from_slice(&u16::try_from(sni_ext.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&sni_ext);
        let mut hs = vec![HANDSHAKE_CLIENT_HELLO];
        hs.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut out = Vec::new();
        for part in hs.chunks(record_max) {
            out.extend_from_slice(&[CONTENT_HANDSHAKE, 0x03, 0x01]);
            out.extend_from_slice(&u16::try_from(part.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[tokio::test]
    async fn reads_a_hello_split_over_records_and_reads() -> Result<(), HelloError> {
        let bytes = hello_records("Example.COM", 20);
        // Delivered a few bytes at a time, as a slow client or two TCP segments would.
        let (mut tx, mut rx) = tokio::io::duplex(8);
        let sent = bytes.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for b in sent.chunks(3) {
                if tx.write_all(b).await.is_err() {
                    return;
                }
            }
        });
        let mut buf = Vec::new();
        let hello = read_client_hello(&mut rx, &mut buf, Duration::from_secs(5)).await?;
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        assert_eq!(buf, bytes, "every byte read is kept for the upstream");
        Ok(())
    }

    #[tokio::test]
    async fn refuses_a_server_name_that_is_not_a_host_name() {
        // The host review's probe: it matched `*.tailscale.com` and was dialled as `attacker.example`.
        for bad in ["[attacker.example].tailscale.com", "a b.example", "x\0.example"] {
            let bytes = hello_records(bad, 512);
            let mut buf = Vec::new();
            let mut src = &bytes[..];
            let r = read_client_hello(&mut src, &mut buf, Duration::from_secs(1)).await;
            assert!(matches!(r, Err(HelloError::BadSni(_))), "{bad}: {r:?}");
        }
        let bytes = hello_records("Bücher.Example.", 512);
        let mut buf = Vec::new();
        let mut src = &bytes[..];
        let hello = read_client_hello(&mut src, &mut buf, Duration::from_secs(1)).await;
        assert_eq!(hello.ok().and_then(|h| h.sni).as_deref(), Some("xn--bcher-kva.example"));
    }

    #[tokio::test]
    async fn refuses_what_is_not_tls() {
        let mut buf = b"GET / HTTP/1.1\r\n".to_vec();
        let mut empty: &[u8] = &[];
        assert!(matches!(
            read_client_hello(&mut empty, &mut buf, Duration::from_secs(1)).await,
            Err(HelloError::NotHello)
        ));
        let mut short: &[u8] = &[0x16, 0x03];
        let mut buf = Vec::new();
        assert!(matches!(
            read_client_hello(&mut short, &mut buf, Duration::from_secs(1)).await,
            Err(HelloError::Closed)
        ));
    }
}
