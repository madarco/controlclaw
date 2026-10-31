//! The firewall's own key pair beyond making it (`keys.ts`): registering the public half with the
//! control plane on first boot, and detached signatures over what it publishes (the CA, the Doctor
//! SSH key). The private key never leaves the box.

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::Signer;
use ed25519_dalek::pkcs8::DecodePrivateKey;

fn read_trimmed(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

/// `signDetached`: Ed25519 over the UTF-8 bytes, base64.
pub fn sign_detached(keys_dir: &Path, message: &str) -> Result<String, String> {
    let pem = std::fs::read_to_string(keys_dir.join("vm_private_key.pem")).map_err(|e| e.to_string())?;
    let key = ed25519_dalek::SigningKey::from_pkcs8_pem(pem.trim()).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.sign(message.as_bytes()).to_bytes()))
}

/// `registerPublicKey`: with the one-time bootstrap token, before any call signed with the key.
/// Nothing to do on a box with no token (its key is already on the control plane).
pub async fn register_public_key(keys_dir: &Path, http: &cc_client::HttpClient) {
    let vm_id = read_trimmed(keys_dir, "vm_id");
    let token = read_trimmed(keys_dir, "bootstrap_token").filter(|s| !s.is_empty());
    let url = read_trimmed(keys_dir, "register_api_url").filter(|s| !s.is_empty());
    let public_key = read_trimmed(keys_dir, "vm_public_key.pem");
    let (Some(token), Some(url)) = (token, url) else { return };
    let (Some(vm_id), Some(public_key)) = (vm_id, public_key) else {
        tracing::warn!("[keys] missing vm_id / vm_public_key.pem — cannot register");
        return;
    };
    const MAX_ATTEMPTS: u64 = 10;
    let body = serde_json::json!({"vm_id": vm_id, "public_key": public_key});
    for attempt in 1..=MAX_ATTEMPTS {
        let res = http
            .get()
            .post(&url)
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap_or_default())
            .timeout(Duration::from_secs(300))
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {
                tracing::info!("[keys] registered public key (attempt {attempt})");
                return;
            }
            Ok(r) if r.status().as_u16() == 409 => {
                tracing::error!("[keys] registration refused (409): identity already registered to another key");
                return;
            }
            Ok(r) => tracing::warn!(
                "[keys] register attempt {attempt}/{MAX_ATTEMPTS}: HTTP {}",
                r.status().as_u16()
            ),
            Err(e) => tracing::warn!(
                "[keys] register attempt {attempt}/{MAX_ATTEMPTS} failed: fetch failed ({})",
                e.without_url()
            ),
        }
        tokio::time::sleep(Duration::from_millis((2000 * attempt).min(15_000))).await;
    }
    tracing::error!("[keys] gave up registering after {MAX_ATTEMPTS} attempts");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn signature_verifies() {
        let d = tempfile::tempdir().expect("dir");
        cc_auth::keys::ensure_vm_keypair(d.path()).expect("keys");
        let sig = sign_detached(d.path(), "cert").expect("sig");
        let pem = std::fs::read_to_string(d.path().join("vm_private_key.pem")).expect("pem");
        let key = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).expect("key");
        let raw = base64::engine::general_purpose::STANDARD.decode(sig).expect("b64");
        let sig = ed25519_dalek::Signature::from_slice(&raw).expect("sig");
        key.verifying_key().verify(b"cert", &sig).expect("verifies");
    }
}
