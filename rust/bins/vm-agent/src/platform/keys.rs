//! On-box identity keys (`keys.ts`): register the box's own public key with the console once,
//! with the one-time bootstrap token, and the detached-signature check the CA install uses.

use std::time::Duration;

use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::app::App;

/// `registerPublicKey`. A no-op on a legacy box (no token or no register URL). Up to 10 attempts,
/// 2 s × attempt apart (15 s at most); a 409 is final.
pub async fn register_public_key(app: &App) {
    // An empty file counts as missing, as the TS's falsy checks have it.
    let read = |name: &str| app.keys.read(name).filter(|v| !v.is_empty());
    let (Some(token), Some(url)) = (read("bootstrap_token"), read("register_api_url")) else {
        return;
    };
    let (Some(vm_id), Some(public_key)) = (read("vm_id"), read("vm_public_key.pem")) else {
        tracing::warn!("[keys] missing vm_id / vm_public_key.pem — cannot register");
        return;
    };
    let body = json!({ "vm_id": vm_id, "public_key": public_key });
    const MAX: u64 = 10;
    for attempt in 1..=MAX {
        let res = app
            .http
            .get()
            .post(&url)
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body(body.to_string())
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
            Ok(r) => tracing::warn!("[keys] register attempt {attempt}/{MAX}: HTTP {}", r.status().as_u16()),
            // Without the URL: a request's error text names it, and these URLs come from the box's keys.
            Err(e) => tracing::warn!("[keys] register attempt {attempt}/{MAX} failed: {}", e.without_url()),
        }
        tokio::time::sleep(Duration::from_millis((2000 * attempt).min(15_000))).await;
    }
    tracing::error!("[keys] gave up registering after {MAX} attempts");
}

/// `verifyDetached`: an Ed25519 signature (base64) over `message`, against an SPKI PEM read from
/// its base64 body, so a pin written back on one line (T-88) still reads.
pub fn verify_detached(message: &str, signature_b64: &str, public_key_pem: &str) -> bool {
    let body: String = public_key_pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD;
    let Ok(der) = b64.decode(body) else { return false };
    let Ok(key) = VerifyingKey::from_public_key_der(&der) else {
        return false;
    };
    let Ok(sig) = b64.decode(signature_b64) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig) else {
        return false;
    };
    key.verify(message.as_bytes(), &sig).is_ok()
}

/// `sha256Hex`.
pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBfakeCA\n-----END CERTIFICATE-----\n";

    fn pair() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pem = sk.verifying_key().to_public_key_pem(LineEnding::LF).expect("pem");
        (sk, pem)
    }

    fn sign(msg: &str, sk: &SigningKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(sk.sign(msg.as_bytes()).to_bytes())
    }

    #[test]
    fn detached_signatures() {
        let (sk, pem) = pair();
        assert!(verify_detached(CA, &sign(CA, &sk), &pem));
        let flat = pem.replace('\n', "");
        assert!(verify_detached(CA, &sign(CA, &sk), &flat));
        let (attacker, _) = pair();
        assert!(!verify_detached(CA, &sign(CA, &attacker), &flat));
        assert!(!verify_detached(&format!("{CA}x"), &sign(CA, &sk), &pem));
        assert!(!verify_detached(CA, &sign(CA, &attacker), &pem));
        assert!(!verify_detached(CA, "not-base64!!", &pem));
        assert!(!verify_detached(CA, &sign(CA, &sk), "not-a-key"));
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(sha256_hex(CA), sha256_hex(CA));
        assert_ne!(sha256_hex(CA), sha256_hex(&format!("{CA}x")));
    }
}
