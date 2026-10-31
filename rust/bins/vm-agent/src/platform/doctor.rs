//! Doctor on this box (`doctor.ts`, `routes/doctor.ts`): whether it can be repaired from the
//! firewall, and the key the firewall's Doctor signs in with (`/doctor/status`, `/doctor/key`).

use std::path::Path;

use std::sync::LazyLock;

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use sha2::{Digest, Sha256};

pub const DOCTOR_KEY_FILE: &str = "/home/ccdoctor/.ssh/authorized_keys";

/// `doctorHostKey`: this box's SSH host key, for the firewall to pin.
pub fn host_key() -> Option<String> {
    std::fs::read_to_string("/etc/ssh/ssh_host_ed25519_key.pub")
        .ok()
        .map(|s| s.trim().to_string())
}

static KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"ssh-ed25519 ([A-Za-z0-9+/=]+)").expect("regex"));

/// Decodes as Node's `Buffer.from(s, "base64")` does for these blobs: padding optional, stops at
/// the first `=`, loose trailing bits.
fn lenient_b64(s: &str) -> Option<Vec<u8>> {
    let cfg = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    let body = s.split('=').next().unwrap_or_default();
    // A single leftover character carries no whole byte; Node drops it.
    let body = if body.len() % 4 == 1 {
        &body[..body.len() - 1]
    } else {
        body
    };
    GeneralPurpose::new(&alphabet::STANDARD, cfg).decode(body).ok()
}

/// `SHA256:<unpadded base64>` of an ssh-ed25519 key's blob.
pub fn fingerprint(blob_b64: &str) -> Option<String> {
    let raw = lenient_b64(blob_b64)?;
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(raw));
    Some(format!("SHA256:{}", digest.trim_end_matches('=')))
}

/// `doctorStatus`: the fingerprint of the first ssh-ed25519 key in the file, or null.
pub fn status(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    fingerprint(KEY.captures(&text)?.get(1)?.as_str())
}

/// `doctorAvailable`: the root helper, the firewall's Doctor pin and an installed key.
/// `fingerprint` is `doctorStatus().fingerprint`, read once by the caller.
pub fn available(fingerprint: Option<&str>) -> bool {
    Path::new("/usr/local/bin/cc-doctor-key-install").exists()
        && Path::new("/etc/controlclaw/doctor-mitm-pin.pem").exists()
        && fingerprint.is_some()
}

pub const DOCTOR_KEY_DOMAIN: &str = "controlclaw:doctor-key:v1\n";
static PUB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^ssh-ed25519 [A-Za-z0-9+/=]{68}(?: [A-Za-z0-9_-]{1,64})?$").expect("regex"));
static SIG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/=]{88}$").expect("regex"));

/// `installDoctorKey`: the firewall's signature over the key, checked here against its pinned key,
/// then the root helper (which checks it again; this process cannot write `authorized_keys`).
pub async fn install_key(
    runner: &dyn cc_proc::Runner,
    pin_path: &Path,
    public: Option<&serde_json::Value>,
    sig: Option<&serde_json::Value>,
) -> Result<String, String> {
    let (Some(public), Some(sig)) = (
        public.and_then(|v| v.as_str()).filter(|p| PUB.is_match(p)),
        sig.and_then(|v| v.as_str()).filter(|s| SIG.is_match(s)),
    ) else {
        return Err("Invalid doctor key".into());
    };
    let pin = std::fs::read_to_string(pin_path).map_err(|_| "no pinned key")?;
    use ed25519_dalek::pkcs8::DecodePublicKey;
    let key = ed25519_dalek::VerifyingKey::from_public_key_pem(&pin).map_err(|_| "no pinned key")?;
    let raw: [u8; 64] = lenient_b64(sig)
        .and_then(|b| b.try_into().ok())
        .ok_or("Invalid doctor key signature")?;
    let message = format!("{DOCTOR_KEY_DOMAIN}{public}");
    // Strict: a signature OpenSSL would refuse is refused here too.
    key.verify_strict(message.as_bytes(), &ed25519_dalek::Signature::from_bytes(&raw))
        .map_err(|_| "Invalid doctor key signature")?;
    let stdin = serde_json::json!({ "pub": public, "sig": sig }).to_string();
    let cmd = cc_proc::Cmd::new("sudo")
        .args(["-n", "/usr/local/bin/cc-doctor-key-install"])
        .timeout(std::time::Duration::from_secs(15))
        .stdin(stdin.into_bytes());
    match runner.run(cmd).await {
        Ok(o) if o.success() => {}
        _ => return Err("the helper refused the key".into()),
    }
    fingerprint(public.split(' ').nth(1).unwrap_or_default()).ok_or_else(|| "Invalid doctor key".into())
}

/// `/doctor/status` and `/doctor/key`: the firewall's token with purpose `doctor` only.
pub fn register(router: &mut cc_http::Router, app: &std::sync::Arc<crate::app::App>) {
    use cc_http::{FirewallBody, FirewallRequest, ReadBody, send_json};
    use hyper::Method;
    use serde_json::json;
    let a = app.clone();
    router.prefix(crate::stages::PREFIXED, "/doctor/", move |req, _| {
        let app = a.clone();
        async move {
            let read = if req.method() == Method::POST {
                ReadBody::Json { limit: 2048 }
            } else {
                ReadBody::No
            };
            let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "doctor", 0, read).await {
                FirewallRequest::Accepted { parts, body, .. } => (parts, body),
                FirewallRequest::Refused { .. } => {
                    return send_json(401, &json!({ "error": "Doctor keys require the org firewall" }));
                }
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            if path == "/doctor/status" && parts.method == Method::GET {
                return send_json(
                    200,
                    &json!({ "fingerprint": status(Path::new(DOCTOR_KEY_FILE)), "sshHostKey": host_key() }),
                );
            }
            if path != "/doctor/key" || parts.method != Method::POST {
                return send_json(404, &json!({ "error": "Not found" }));
            }
            let b = match body {
                FirewallBody::Json(b) => b,
                _ => serde_json::Map::new(),
            };
            let pin = app.config.keys_dir.join("mitm_pinned_pubkey.pem");
            match install_key(app.runner.as_ref(), &pin, b.get("pub"), b.get("sig")).await {
                Ok(fp) => {
                    // The first ready report can come before the key: tell the console it is there.
                    // Only once the bootstrap has reported ready itself. The firewall sends the key
                    // to every box it knows, a new one too, and a ready from here while OpenClaw is
                    // still starting made the console push the model and channels to a gateway that
                    // was not up (the TS reports here at once; fixed in Rust). The bootstrap's own
                    // report carries the key, its software report is built per attempt.
                    let a = app.clone();
                    let ready = app.bootstrap_ready.load(std::sync::atomic::Ordering::SeqCst);
                    tokio::spawn(async move {
                        if !ready {
                            return;
                        }
                        let b = a.clone();
                        super::ready::report_ready(&a, serde_json::Map::new(), move || super::box_software(&b, None))
                            .await;
                    });
                    send_json(200, &json!({ "ok": true, "fingerprint": fp }))
                }
                Err(e) => {
                    tracing::warn!("[doctor] key refused: {e}");
                    send_json(400, &json!({ "error": "Doctor key installation refused" }))
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_of_the_installed_key() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("authorized_keys");
        assert_eq!(status(&p), None);
        let blob = base64::engine::general_purpose::STANDARD.encode([7u8; 51]);
        std::fs::write(&p, format!("restrict ssh-ed25519 {blob} ccdoctor\n")).expect("write");
        let want = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest([7u8; 51]))
                .trim_end_matches('=')
        );
        assert_eq!(status(&p), Some(want));
        std::fs::write(&p, "ssh-rsa AAAA\n").expect("write");
        assert_eq!(status(&p), None);
    }

    #[tokio::test]
    async fn a_key_installs_only_with_the_firewalls_signature() {
        use ed25519_dalek::Signer;
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let d = tempfile::tempdir().expect("dir");
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pin = d.path().join("pin.pem");
        let pem = signer
            .verifying_key()
            .to_public_key_pem(Default::default())
            .expect("pem");
        std::fs::write(&pin, pem).expect("w");
        let b64 = base64::engine::general_purpose::STANDARD;
        let public = format!("ssh-ed25519 {} doctor", b64.encode([1u8; 51]));
        let sig = b64.encode(
            signer
                .sign(format!("{DOCTOR_KEY_DOMAIN}{public}").as_bytes())
                .to_bytes(),
        );
        let runner = cc_proc::RecordingRunner::new();
        runner.answer(&["sudo", "-n", "/usr/local/bin/cc-doctor-key-install"], cc_proc::ok(""));
        let v = |s: &str| serde_json::json!(s);
        let fp = install_key(&runner, &pin, Some(&v(&public)), Some(&v(&sig)))
            .await
            .expect("installed");
        assert!(fp.starts_with("SHA256:"));
        let stdin = String::from_utf8(runner.calls()[0].stdin.clone().unwrap_or_default()).expect("utf8");
        assert!(stdin.contains("\"pub\"") && stdin.contains(&sig));
        let other = format!("ssh-ed25519 {} doctor", b64.encode([2u8; 51]));
        assert!(
            install_key(&runner, &pin, Some(&v(&other)), Some(&v(&sig)))
                .await
                .is_err(),
            "signed for another key"
        );
        assert!(
            install_key(&runner, &pin, Some(&v("ssh-rsa AAAA")), Some(&v(&sig)))
                .await
                .is_err()
        );
        assert_eq!(runner.calls().len(), 1, "the helper ran once");
    }
}
