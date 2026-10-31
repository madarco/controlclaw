//! The session secret the agent makes for itself on first start (`session.ts`). The box keypair is
//! `cc_auth::keys::ensure_vm_keypair`.

use std::path::Path;

/// The secret's length: 32 random bytes.
pub const SESSION_SECRET_BYTES: usize = 32;

/// `ensureSessionSecret`: 32 random bytes as hex in `session_secret`, made once (0600). The HS256
/// key for the browser sessions (W7) is the hex-decoded value. A file that does not hold exactly
/// 32 bytes of hex (empty after a crash during the first write, say) is made again: a short key
/// would let anyone sign a session, and jose refuses a zero-length one.
pub fn ensure_session_secret(dir: &Path) -> std::io::Result<Vec<u8>> {
    let path = dir.join("session_secret");
    let current = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
        .filter(|k| k.len() == SESSION_SECRET_BYTES);
    if let Some(k) = current {
        return Ok(k);
    }
    let mut b = [0u8; SESSION_SECRET_BYTES];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    cc_store::write_atomic(&path, hex::encode(b).as_bytes(), 0o600, cc_store::TmpName::Suffix)?;
    tracing::info!("[session] generated session secret");
    Ok(b.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn made_once_and_made_again_when_short() {
        let dir = tempfile::tempdir().expect("dir");
        let first = ensure_session_secret(dir.path()).expect("make");
        assert_eq!(first.len(), 32);
        assert_eq!(ensure_session_secret(dir.path()).expect("again"), first);
        for bad in ["", "\n", "abcd", "zz", &"0".repeat(62)] {
            std::fs::write(dir.path().join("session_secret"), bad).expect("write");
            let k = ensure_session_secret(dir.path()).expect("remake");
            assert_eq!(k.len(), 32, "{bad:?}");
            assert_ne!(k, first);
            let on_disk = std::fs::read_to_string(dir.path().join("session_secret")).expect("read");
            assert_eq!(hex::decode(on_disk.trim()).expect("hex"), k);
        }
    }
}
