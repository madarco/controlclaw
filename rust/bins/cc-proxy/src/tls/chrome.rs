//! The built-in browser profile: what the upstream handshake and the upstream HTTP/2 connection
//! send when the agent's own cannot be copied (no ClientHello to read, a request that did not
//! come over TLS, a field BoringSSL cannot send). Normally the agent's own is mirrored
//! (`tls::mirror`, `http::h2print`).
//!
//! The profile IS a capture of a real Chrome, parsed by the same code that reads the agent's: its
//! ClientHello and the start of its HTTP/2 connection. To update it when Chrome changes, capture
//! both again (a local listener that saves the first bytes, Chrome pointed at it with
//! `--host-resolver-rules`; for HTTP/2 a TLS listener offering `h2` and Chrome with
//! `--ignore-certificate-errors`), replace the two files and the version below, and run the tests.

use std::sync::OnceLock;

use super::hello::{self, Hello};
use crate::http::h2print::{self, H2Print};

/// The Chrome the captures came from.
pub const VERSION: &str = "Chrome 153.0.8010.52";

const HELLO: &[u8] = include_bytes!("testdata/chrome-153-hello.bin");
const H2_PREFACE: &[u8] = include_bytes!("testdata/chrome-153-h2-preface.bin");

/// Chrome's ClientHello.
pub fn hello() -> &'static Hello {
    static P: OnceLock<Hello> = OnceLock::new();
    P.get_or_init(|| {
        hello::handshake_of(HELLO)
            .and_then(|h| hello::parse(&h))
            .unwrap_or_default()
    })
}

/// Chrome's HTTP/2 connection start.
pub fn h2() -> &'static H2Print {
    static P: OnceLock<H2Print> = OnceLock::new();
    P.get_or_init(|| h2print::from_bytes(H2_PREFACE).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::hello::ext;

    #[test]
    fn the_captures_parse() {
        let h = hello();
        assert!(h.grease());
        assert_eq!(h.alpn, [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(h.groups.contains(&0x11ec), "X25519MLKEM768 first: {:x?}", h.groups);
        assert_eq!(h.key_shares.iter().filter(|g| !hello::is_grease(**g)).count(), 2);
        assert!(h.has(ext::ECH) && h.has(ext::ALPS) && h.has(ext::COMPRESS_CERTIFICATE));
        assert_eq!(h.cert_compression, [2]);
        assert_eq!(h.alps, [b"h2".to_vec()]);
        assert!(h.versions.contains(&0x0304));
        assert_eq!(h2().settings.len(), 4);
        assert!(h2().saw_headers);
    }
}
