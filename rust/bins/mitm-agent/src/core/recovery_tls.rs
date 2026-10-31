//! The recovery certificate (`loadOrCreateRecoveryTls` in `recovery-tls.ts`): made once with
//! openssl, kept as `recovery_key.pem` (0600) and `recovery_cert.pem` (0644) in the key folder. Its
//! fingerprint is what `npx @controlclaw/recover --fingerprint` pins.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use sha2::{Digest, Sha256};

pub struct RecoveryTls {
    pub key: String,
    pub cert: String,
    /// `sha256:AB:CD:…`, as `openssl x509 -fingerprint` prints it.
    pub fingerprint: String,
}

const CERT_DAYS: u32 = 3650;

pub async fn load_or_create(runner: &dyn Runner, dir: &Path, subject: &str) -> Option<RecoveryTls> {
    let key_path = dir.join("recovery_key.pem");
    let cert_path = dir.join("recovery_cert.pem");
    let made = async {
        if !key_path.exists() || !cert_path.exists() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let cmd = Cmd::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
                .arg(key_path.display().to_string())
                .arg("-out")
                .arg(cert_path.display().to_string())
                .args([
                    "-days".to_string(),
                    CERT_DAYS.to_string(),
                    "-subj".to_string(),
                    format!("/CN={subject}"),
                ])
                .timeout(Duration::from_secs(60));
            let out = runner.run(cmd).await.map_err(|e| e.to_string())?;
            if !out.success() {
                return Err(format!("Command failed: openssl req\n{}", out.stderr_str()));
            }
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
            std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
            tracing::info!(
                "[recovery] generated this box's recovery certificate ({})",
                cert_path.display()
            );
        }
        let cert = std::fs::read_to_string(&cert_path).map_err(|e| e.to_string())?;
        let key = std::fs::read_to_string(&key_path).map_err(|e| e.to_string())?;
        Ok::<_, String>(RecoveryTls {
            fingerprint: cert_fingerprint(&cert),
            key,
            cert,
        })
    };
    match made.await {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::info!("[recovery] no recovery certificate on this box, so the recovery routes are off: {e}");
            None
        }
    }
}

/// `certFingerprint`: SHA-256 of the DER, upper-case hex pairs joined with `:`.
pub fn cert_fingerprint(pem: &str) -> String {
    let body: String = pem
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = cc_crypto::b64::decode(&body).unwrap_or_default();
    let hex = hex::encode_upper(Sha256::digest(der));
    let pairs: Vec<&str> = hex
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    format!("sha256:{}", pairs.join(":"))
}
