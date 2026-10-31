//! The firewall's own backup (`self-backup.ts`): the handful of small files in
//! `FIREWALL_BACKUP_FILES`, as one JSON document sealed with the backup envelope and PUT to a
//! presigned URL. Wrapped to the recovery key only: this box's own backup key is one of the files.

use std::os::unix::fs::PermissionsExt;

use cc_crypto::envelope::{ArchiveKind, CHUNK_BYTES, Encryptor, EnvelopeBinding, wrap_data_key};
use serde_json::json;

use super::backup_manifest::{FIREWALL_BACKUP_FILES, manifest_hash};
use super::consent::iso;
use super::now_ms;

/// A firewall backup over this is not the small bundle this is meant to carry.
const MAX_SELF_BACKUP_BYTES: u64 = 8 * 1024 * 1024;

pub struct SelfBackupInput {
    pub backup_id: String,
    pub upload_url: String,
    pub data_key: String,
    pub recovery_public_key: String,
    pub recovery_fingerprint: String,
}

#[derive(Debug)]
pub struct SelfBackupResult {
    pub header: String,
    pub manifest_hash: String,
    pub plain_bytes: u64,
    pub cipher_bytes: usize,
    pub entries: usize,
    /// The data key sealed to the recovery key: the only copy there is.
    pub wrapped: String,
    pub recovery_fingerprint: String,
    pub taken_at: String,
}

#[derive(Clone)]
pub struct SelfBackup {
    org_id: String,
    box_id: String,
    files: Vec<String>,
    http: reqwest::Client,
}

impl SelfBackup {
    pub fn new(org_id: &str, box_id: &str, http: reqwest::Client) -> Self {
        Self::with_files(
            org_id,
            box_id,
            http,
            FIREWALL_BACKUP_FILES.iter().map(|s| s.to_string()).collect(),
        )
    }

    pub fn with_files(org_id: &str, box_id: &str, http: reqwest::Client, files: Vec<String>) -> Self {
        Self {
            org_id: org_id.into(),
            box_id: box_id.into(),
            files,
            http,
        }
    }

    /// Seal and upload; also the archive bytes, for the tests.
    pub async fn seal(&self, input: &SelfBackupInput) -> Result<(SelfBackupResult, Vec<u8>), String> {
        let mut files = Vec::new();
        let mut entries = Vec::new();
        let mut plain_bytes: u64 = 0;
        for path in &self.files {
            // A firewall without WhatsApp has no channel store; that is not a failure.
            let Ok(st) = std::fs::metadata(path) else { continue };
            if !st.is_file() {
                continue;
            }
            if plain_bytes + st.len() > MAX_SELF_BACKUP_BYTES {
                return Err("This firewall's state is larger than a firewall backup is meant to carry.".into());
            }
            let body = std::fs::read(path).map_err(|e| e.to_string())?;
            let mode = st.permissions().mode() & 0o7777;
            files.push(json!({"path": path, "mode": mode, "base64": cc_crypto::b64::encode(&body)}));
            entries.push(json!({"path": path, "bytes": body.len(), "mode": mode, "kind": "file"}));
            plain_bytes += body.len() as u64;
        }
        if entries.is_empty() {
            return Err("There is nothing on this firewall to back up yet.".into());
        }
        let taken_at = iso(now_ms());
        let count = entries.len();
        let manifest = json!({
            "version": 1, "kind": "firewall", "takenAt": taken_at, "root": "/",
            "entries": entries, "totalBytes": plain_bytes, "excluded": [],
        });
        let hash = manifest_hash(manifest.as_object().expect("an object"));
        // Bound to this box: a blob from one firewall cannot be served to another.
        let binding = EnvelopeBinding {
            org_id: self.org_id.clone(),
            vm_id: self.box_id.clone(),
            backup_id: input.backup_id.clone(),
            kind: ArchiveKind::Firewall,
        };
        let mut enc = Encryptor::new(&input.data_key, &binding).map_err(|e| e.0)?;
        let plain = serde_json::to_vec(&json!({"manifest": manifest, "files": files})).map_err(|e| e.to_string())?;
        let mut blob = Vec::new();
        for chunk in plain.chunks(CHUNK_BYTES) {
            blob.extend(enc.push(chunk).map_err(|e| e.0)?);
        }
        blob.extend(enc.finish().map_err(|e| e.0)?);
        let header = enc.header().to_string();
        let wrapped = wrap_data_key(&input.data_key, &input.recovery_public_key).map_err(|e| e.0)?;
        Ok((
            SelfBackupResult {
                header,
                manifest_hash: hash,
                plain_bytes,
                cipher_bytes: blob.len(),
                entries: count,
                wrapped,
                recovery_fingerprint: input.recovery_fingerprint.clone(),
                taken_at,
            },
            blob,
        ))
    }

    pub async fn run(&self, input: SelfBackupInput) -> Result<SelfBackupResult, String> {
        let (r, blob) = self.seal(&input).await?;
        let res = self
            .http
            .put(&input.upload_url)
            .header("content-length", blob.len().to_string())
            .header("content-type", "application/octet-stream")
            .body(blob)
            .send()
            .await
            // The presigned URL carries a signature: never in the message.
            .map_err(|e| e.without_url().to_string())?;
        if !res.status().is_success() {
            return Err(format!(
                "The backup store refused the upload (HTTP {}).",
                res.status().as_u16()
            ));
        }
        tracing::info!(
            "[backup] firewall state sealed: {} file(s), {} bytes",
            r.entries,
            r.cipher_bytes
        );
        Ok(r)
    }
}
