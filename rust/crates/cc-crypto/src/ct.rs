//! Comparisons that take the same time whatever the input, for codes, tokens and hashes. The TS
//! uses `crypto.timingSafeEqual` in nine files; these are what a port uses instead of `==`.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Equal bytes, in time that depends only on the lengths. Unequal lengths are unequal at once,
/// as `timingSafeEqual` throws on them (every TS caller checks the length first).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Equal after SHA-256, so neither the content nor the length leaks: the TS pattern
/// `timingSafeEqual(sha256(a), sha256(b))` (consent codes, page doors, webhook secrets).
pub fn sha256_ct_eq(a: &[u8], b: &[u8]) -> bool {
    ct_eq(&Sha256::digest(a), &Sha256::digest(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(sha256_ct_eq(b"123456", b"123456"));
        assert!(!sha256_ct_eq(b"123456", b"123457"));
        assert!(!sha256_ct_eq(b"", b"x"));
    }
}
