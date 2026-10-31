//! The key folder (`KEYS_DIR`, `/opt/controlclaw/keys`): the same files the Node builds read.

use std::path::{Path, PathBuf};

/// `readKeyFile`: the file's text, trimmed, or `None` when it is missing or unreadable.
pub fn read_key_file(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

#[derive(Debug, Clone)]
pub struct KeysDir(pub PathBuf);

impl KeysDir {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self(dir.into())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn read(&self, name: &str) -> Option<String> {
        read_key_file(&self.0, name)
    }

    pub fn vm_id(&self) -> Option<String> {
        self.read("vm_id").filter(|s| !s.is_empty())
    }

    /// The names this box answers on, for the firewall token's `h` check.
    pub fn hostnames(&self) -> Vec<String> {
        ["vm_hostname", "access_hostname"]
            .iter()
            .filter_map(|n| self.read(n))
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// `ensureVmKeypair` (both agents' `keys.ts`): the box's public key as SPKI PEM, making the pair
/// on first boot (`vm_private_key.pem` 0600, `vm_public_key.pem` 0644).
pub fn ensure_vm_keypair(dir: &Path) -> Option<String> {
    ensure_keypair(dir, "vm_private_key.pem", "vm_public_key.pem", "on-box vm keypair")
}

/// An Ed25519 pair in `dir` (PKCS#8 private 0600, SPKI public 0644), made once: the public PEM, or
/// `None` when it cannot be read or written. `what` names it in the log.
pub fn ensure_keypair(dir: &Path, private_file: &str, public_file: &str, what: &str) -> Option<String> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
    let private = dir.join(private_file);
    let public = dir.join(public_file);
    if private.exists() {
        if let Ok(p) = std::fs::read_to_string(&public) {
            return Some(p);
        }
        let sk = SigningKey::from_pkcs8_pem(std::fs::read_to_string(&private).ok()?.trim()).ok()?;
        return sk.verifying_key().to_public_key_pem(LineEnding::LF).ok();
    }
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).ok()?;
    let pub_pem = sk.verifying_key().to_public_key_pem(LineEnding::LF).ok()?;
    std::fs::create_dir_all(dir).ok()?;
    cc_store::write_file(&private, priv_pem.as_bytes(), 0o600).ok()?;
    cc_store::write_file(&public, pub_pem.as_bytes(), 0o644).ok()?;
    tracing::info!("[keys] generated {what}");
    Some(pub_pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_made_once() {
        let d = tempfile::tempdir().expect("dir");
        let first = ensure_vm_keypair(d.path()).expect("made");
        assert_eq!(ensure_vm_keypair(d.path()).as_deref(), Some(first.as_str()));
        std::fs::remove_file(d.path().join("vm_public_key.pem")).expect("rm");
        assert_eq!(ensure_vm_keypair(d.path()).as_deref(), Some(first.as_str()));
    }
}
