//! The trust_anchors extension (draft-ietf-tls-trust-anchor-ids), which the agent's Chrome sends
//! and the upstream handshake copies. `btls` has no safe wrapper for it, so this is the one place
//! in cc-proxy that calls C directly (owner, 2026-10-28): one function, the list checked in Rust
//! before it crosses.

use btls::ssl::SslRef;
use foreign_types::ForeignTypeRef;

/// Whether `ids` is a trust anchor ID list in wire form, as BoringSSL requires: a series of
/// non-empty, 8-bit length-prefixed IDs, nothing left over. Empty is allowed (the extension is
/// then sent with no IDs, to signal the retry flow).
pub fn well_formed(ids: &[u8]) -> bool {
    let mut rest = ids;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len);
        if len == 0 || tail.len() < len {
            return false;
        }
        rest = &tail[len..];
    }
    true
}

/// Ask the site for a certificate from one of `ids` (wire form, see [`well_formed`]); BoringSSL
/// then sends the trust_anchors extension in this connection's ClientHello. `false` when the list
/// is malformed (nothing is passed to C) or BoringSSL refuses it.
#[allow(unsafe_code)]
pub fn set_requested(ssl: &mut SslRef, ids: &[u8]) -> bool {
    if !well_formed(ids) {
        return false;
    }
    // SAFETY: `ssl.as_ptr()` is the live `SSL*` behind `&mut SslRef`: the exclusive borrow keeps
    // it alive and unshared for the call. `ids.as_ptr()` and `ids.len()` describe one readable
    // slice that outlives the call (it is borrowed for it), and BoringSSL only reads that many
    // bytes: `SSL_set1_requested_trust_anchors` copies them into the `SSL` ("set1") before it
    // returns, so nothing keeps the pointer. An empty slice is valid (a dangling but non-null
    // pointer with a length of zero, which it does not read). The list was checked above to be
    // the wire form it parses, so it is not asked to reject a malformed one. When it refuses
    // anyway, the error it queued on this thread is cleared, so a later call on the thread does
    // not report it; `ERR_clear_error` takes no arguments.
    unsafe {
        let rc = btls_sys::SSL_set1_requested_trust_anchors(ssl.as_ptr(), ids.as_ptr(), ids.len());
        if rc != 1 {
            btls_sys::ERR_clear_error();
        }
        rc == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::ssl::{SslConnector, SslMethod};

    fn ssl() -> Option<btls::ssl::Ssl> {
        let c = SslConnector::builder(SslMethod::tls()).ok()?.build();
        c.configure().ok()?.into_ssl("example.com").ok()
    }

    #[test]
    fn checks_the_wire_form() {
        assert!(well_formed(&[]));
        assert!(well_formed(&[1, 7]));
        assert!(well_formed(&[2, 1, 2, 3, 9, 9, 9]));
        assert!(!well_formed(&[0]));
        assert!(!well_formed(&[3, 1, 2]));
        assert!(!well_formed(&[1, 7, 0]));
    }

    #[test]
    fn sets_a_list_and_refuses_a_malformed_one() {
        let Some(mut s) = ssl() else { panic!("no SSL") };
        assert!(set_requested(&mut s, &[]));
        assert!(set_requested(&mut s, &[3, 0x2b, 0x06, 0x01, 2, 0xaa, 0xbb]));
        assert!(!set_requested(&mut s, &[0]));
        assert!(!set_requested(&mut s, &[5, 1]));
    }

    /// A small fixed-seed generator, so a failure is reproducible.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let n = usize::try_from(self.next() % (max as u64 + 1)).unwrap_or(0);
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Many random lists, well formed or not, and many random ClientHellos parsed for their
    /// trust_anchors: the call agrees with the Rust check every time and never fails a good one.
    #[test]
    fn random_lists_and_hellos() {
        let Some(mut s) = ssl() else { panic!("no SSL") };
        let mut r = XorShift(0x9e37_79b9_7f4a_7c15);
        for _ in 0..20_000 {
            let ids = r.bytes(300);
            assert_eq!(set_requested(&mut s, &ids), well_formed(&ids), "{ids:?}");
        }
        // Well-formed lists of random IDs: always taken.
        for _ in 0..5_000 {
            let mut ids = Vec::new();
            for _ in 0..(r.next() % 8) {
                let id = r.bytes(40);
                if id.is_empty() {
                    continue;
                }
                ids.push(u8::try_from(id.len()).unwrap_or(1));
                ids.extend_from_slice(&id);
            }
            assert!(set_requested(&mut s, &ids), "{ids:?}");
        }
        // Random ClientHellos: Chrome's with its trust_anchors data replaced by random bytes, and
        // random bytes outright. Whatever parses goes through the same call.
        let chrome =
            crate::tls::hello::handshake_of(include_bytes!("testdata/chrome-153-hello.bin")).unwrap_or_default();
        for i in 0..20_000 {
            let mut msg = chrome.clone();
            if i % 2 == 0 {
                for _ in 0..(r.next() % 16) {
                    let at = usize::try_from(r.next() % msg.len() as u64).unwrap_or(0);
                    msg[at] = r.next() as u8;
                }
            } else {
                msg = r.bytes(2048);
            }
            if let Some(h) = crate::tls::hello::parse(&msg)
                && let Some(ids) = h.trust_anchors
            {
                assert_eq!(set_requested(&mut s, &ids), well_formed(&ids));
            }
        }
    }

    /// No other function in cc-proxy may use unsafe code: across every Rust file of the crate
    /// (src, tests, build.rs, benches), the lint's name appears once and every unsafe block,
    /// function, impl, extern block or attribute is in this file, and only one. Whitespace is
    /// removed first, so spacing does not hide one. The patterns are built with `concat!` so this
    /// test does not count itself.
    #[test]
    fn this_is_the_only_unsafe() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "tests", "benches", "examples"] {
            walk(&root.join(dir), &mut files);
        }
        files.push(root.join("build.rs"));
        let lint = concat!("unsafe", "_code");
        let uses = [
            concat!("unsafe", "{"),
            concat!("unsafe", "fn"),
            concat!("unsafe", "impl"),
            concat!("unsafe", "extern"),
            concat!("unsafe", "trait"),
            concat!("#[unsafe", "("),
        ];
        let (mut lints, mut found) = (Vec::new(), Vec::new());
        for p in &files {
            let Ok(text) = std::fs::read_to_string(p) else { continue };
            let flat: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            let name = p.display().to_string();
            let n = flat.matches(lint).count();
            if n > 0 {
                lints.push((name.clone(), n));
            }
            let n: usize = uses.iter().map(|u| flat.matches(u).count()).sum();
            if n > 0 {
                found.push((name, n));
            }
        }
        let here = |v: &[(String, usize)]| v.len() == 1 && v[0].0.ends_with("tls/anchors.rs") && v[0].1 == 1;
        assert!(here(&lints), "{lints:?}");
        assert!(here(&found), "{found:?}");
    }
}
