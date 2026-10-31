//! Putting this firewall back from its own backup (`self-restore.ts`). Nothing on the box changes
//! until the archive is downloaded, opened, hash-checked against its manifest and written to a
//! staging folder; then one swap runs, and a failure during it puts the old files back.
//!
//! Only paths on `FIREWALL_BACKUP_FILES` can be written, and that list holds no identity (the vm
//! keypair, `vm_id`, the pinned console key), so the new box stays the new box. The encrypted
//! stores in the archive are bound to the old box id, so each is opened with the restored box key
//! and sealed again under this box's id.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use cc_crypto::envelope::{ArchiveKind, Decryptor, EnvelopeBinding, fingerprint};
use cc_proc::{Cmd, Runner};
use regex::Regex;
use serde_json::Value;

use super::backup_manifest::{FIREWALL_BACKUP_FILES, manifest_hash, parse_manifest};

/// An archive over this is not the small bundle `self_backup` produces.
const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;

/// The associated-data purpose of each encrypted store, by file name (`<org>:<box>:<purpose>`).
const ENC_PURPOSES: &[(&str, &str)] = &[
    ("channels.enc", "channels"),
    ("llm.enc", "llm"),
    ("backup.enc", "backup"),
    ("connectors.enc", "connectors"),
    ("drive.enc", "drive"),
    ("google.enc", "google"),
    ("agentmail.enc", "agentmail"),
    ("twilio-voice.enc", "twilio-voice"),
    ("secrets.enc", "secrets"),
    ("logins.enc", "logins"),
    ("access.enc", "access"),
    ("meetings.enc", "meetings"),
    ("content-rules.enc", "content-rules"),
];

pub struct SelfRestoreInput {
    pub backup_id: String,
    /// The box the archive was taken on; it goes into the envelope binding, so a wrong one fails.
    pub source_box_id: String,
    pub download_url: Option<String>,
    /// The archive itself, when the owner streamed it (the recovery routes).
    pub archive: Option<Vec<u8>>,
    pub header: String,
    pub manifest_hash: String,
    /// Already unsealed with this box's backup key.
    pub data_key: String,
    /// The date the person was shown in the code message: the archive must be from then.
    pub taken_at: Option<String>,
}

#[derive(Debug)]
pub struct SelfRestoreResult {
    pub entries: usize,
    pub taken_at: Value,
    pub fingerprint: Option<String>,
    pub quarantined: Vec<String>,
}

#[derive(Debug, Clone)]
struct Staged {
    path: String,
    mode: u32,
    staged: PathBuf,
}

pub type Restart = Arc<dyn Fn() + Send + Sync>;
/// `Err(reason)` when this firewall may not be put back now (an emergency stop is on).
pub type Guard = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
/// `true` before the proxy is stopped for the swap: the backup commands freeze, so nothing saves
/// the old box's store over a restored one. `false` when the swap was undone in full.
pub type Freeze = Arc<dyn Fn(bool) + Send + Sync>;

pub struct SelfRestore {
    org_id: String,
    box_id: String,
    files: Vec<String>,
    work_dir: PathBuf,
    http: reqwest::Client,
    /// Stops and starts the proxy around the swap; `None` in the tests.
    runner: Option<Arc<dyn Runner>>,
    /// After a swap: production exits a little later so systemd starts it on the restored state.
    restart: Option<Restart>,
    /// One restore at a time: the console's and the recovery route's share this instance.
    busy: tokio::sync::Mutex<()>,
    guard: OnceLock<Guard>,
    freeze: OnceLock<Freeze>,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => ".",
    }
}

/// Write next to the target and rename, so a target is never seen half written.
fn write_atomic(path: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(dirname(path))?;
    let tmp = format!("{path}.cc-restoring");
    // Created with its mode (`writeFileSync(tmp, bytes, {mode})`): a box key is never readable
    // to others, not even for a moment.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
}

impl SelfRestore {
    pub fn new(
        org_id: &str,
        box_id: &str,
        work_dir: PathBuf,
        http: reqwest::Client,
        runner: Option<Arc<dyn Runner>>,
        restart: Option<Restart>,
    ) -> Self {
        Self {
            org_id: org_id.into(),
            box_id: box_id.into(),
            files: FIREWALL_BACKUP_FILES.iter().map(|s| s.to_string()).collect(),
            work_dir,
            http,
            runner,
            restart,
            busy: tokio::sync::Mutex::new(()),
            guard: OnceLock::new(),
            freeze: OnceLock::new(),
        }
    }

    /// Set once, by the wiring.
    pub fn set_hooks(&self, guard: Guard, freeze: Freeze) {
        let _ = self.guard.set(guard);
        let _ = self.freeze.set(freeze);
    }

    fn check_guard(&self) -> Result<(), String> {
        self.guard.get().map_or(Ok(()), |g| g())
    }

    fn set_frozen(&self, on: bool) {
        if let Some(f) = self.freeze.get() {
            f(on);
        }
    }

    #[allow(dead_code)] // the tests
    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.files = files;
        self
    }

    pub async fn run(&self, input: SelfRestoreInput) -> Result<SelfRestoreResult, String> {
        let Ok(_one) = self.busy.try_lock() else {
            return Err("A restore of this firewall is already running.".into());
        };
        let staging = self.work_dir.join(format!("cc-restore-{}", super::now_ms()));
        let r = async {
            self.check_guard()?;
            let (taken_at, staged) = self.stage(&input, &staging).await?;
            // The code message named a date; an archive from another one is not what was approved.
            // (Changed from the TS, which does not compare them.)
            if let Some(want) = &input.taken_at
                && taken_at.as_str() != Some(want.as_str())
            {
                return Err("That archive is not from the date the code was sent for. Nothing was changed.".into());
            }
            // Again: a stop may have been engaged while the archive came in.
            self.check_guard()?;
            let quarantined = self.swap(&staged, &input.source_box_id).await?;
            let fp = self.fingerprint_after(&staged);
            tracing::info!(
                "[backup] firewall state restored: {} file(s) from {}, backup key {}",
                staged.len(),
                taken_at
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| taken_at.to_string()),
                fp.as_deref().unwrap_or("unknown")
            );
            if let Some(r) = &self.restart {
                r();
            }
            Ok(SelfRestoreResult {
                entries: staged.len(),
                taken_at,
                fingerprint: fp,
                quarantined,
            })
        }
        .await;
        let _ = std::fs::remove_dir_all(&staging);
        r
    }

    // ---- before the swap: nothing on this box changes ----

    async fn download(&self, url: Option<&str>) -> Result<Vec<u8>, String> {
        let Some(url) = url else {
            return Err("There is no archive to put back: neither the bytes nor an address for them.".into());
        };
        let res = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !res.status().is_success() {
            return Err(format!(
                "The backup store did not serve the archive (HTTP {}).",
                res.status().as_u16()
            ));
        }
        Ok(res.bytes().await.map_err(|e| e.without_url().to_string())?.to_vec())
    }

    async fn stage(&self, input: &SelfRestoreInput, staging: &Path) -> Result<(Value, Vec<Staged>), String> {
        let blob = match &input.archive {
            Some(a) => a.clone(),
            None => self.download(input.download_url.as_deref()).await?,
        };
        if blob.len() > MAX_ARCHIVE_BYTES {
            return Err("That archive is far larger than a firewall backup, so it is not one.".into());
        }
        // The binding names the box that TOOK the backup.
        let binding = EnvelopeBinding {
            org_id: self.org_id.clone(),
            vm_id: input.source_box_id.clone(),
            backup_id: input.backup_id.clone(),
            kind: ArchiveKind::Firewall,
        };
        let mut dec = Decryptor::new(&input.data_key, &input.header, &binding).map_err(|e| e.0)?;
        let parts = dec.push(&blob).map_err(|e| e.0)?;
        dec.end().map_err(|e| e.0)?;
        let plain: Vec<u8> = parts.concat();
        let doc: Value = serde_json::from_slice(&plain)
            .map_err(|_| "That archive opened but is not a firewall backup.".to_string())?;
        let manifest = parse_manifest(doc.get("manifest").unwrap_or(&Value::Null))?;
        let kind = manifest.get("kind").cloned().unwrap_or(Value::Null);
        if kind.as_str() != Some("firewall") {
            let k = kind.as_str().map(str::to_string).unwrap_or_else(|| "undefined".into());
            return Err(format!("That archive is a {k} backup, not a firewall backup."));
        }
        if manifest_hash(&manifest) != input.manifest_hash {
            return Err("That archive is not the one recorded for this backup. Nothing was changed.".into());
        }
        let empty = Vec::new();
        let files = doc.get("files").and_then(Value::as_array).unwrap_or(&empty);
        let entries = manifest
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        std::fs::create_dir_all(staging).map_err(|e| e.to_string())?;
        std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let mut staged = Vec::new();
        for (i, f) in files.iter().enumerate() {
            let path = f.get("path").and_then(Value::as_str).unwrap_or_default().to_string();
            let b64 = f.get("base64").and_then(Value::as_str);
            // The allow-list is the identity guard.
            if !self.files.contains(&path) {
                return Err(format!(
                    "That archive carries a file this firewall will not restore ({}).",
                    if path.is_empty() { "unnamed" } else { &path }
                ));
            }
            let Some(b64) = b64 else {
                return Err(format!("The {path} entry in that archive has no content."));
            };
            let Some(entry) = entries
                .iter()
                .find(|e| e.get("path").and_then(Value::as_str) == Some(path.as_str()))
            else {
                return Err(format!("The {path} entry is in that archive but not in its manifest."));
            };
            // `Buffer.from(b64, "base64")` is lenient; so is this, on what this box wrote.
            let bytes = cc_crypto::b64::decode(b64).unwrap_or_default();
            let want = entry.get("bytes").and_then(Value::as_f64).unwrap_or(f64::NAN);
            if bytes.len() as f64 != want {
                return Err(format!(
                    "The {path} entry is {} bytes, and its manifest says {}.",
                    bytes.len(),
                    entry
                        .get("bytes")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "undefined".into())
                ));
            }
            let staged_path = staging.join(i.to_string());
            write_private(&staged_path, &bytes)?;
            let mode = entry.get("mode").and_then(Value::as_u64).unwrap_or(0) as u32 & 0o7777;
            staged.push(Staged {
                path,
                mode,
                staged: staged_path,
            });
        }
        if staged.is_empty() {
            return Err("That archive holds no files, so there is nothing to put back.".into());
        }
        self.derive_ca_pair(&mut staged, staging)?;
        // The box key first, so it is in place before the stores it opens.
        let order = |p: &str| self.files.iter().position(|f| f == p).map_or(-1, |i| i as i64);
        staged.sort_by_key(|s| order(&s.path));
        Ok((manifest.get("takenAt").cloned().unwrap_or(Value::Null), staged))
    }

    /// Backups from before 2026-09-22 carry only the combined `mitmproxy-ca.pem`; split the pair
    /// out of it so the published CA matches the one the proxy signs with.
    fn derive_ca_pair(&self, staged: &mut Vec<Staged>, staging: &Path) -> Result<(), String> {
        static KEY: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----\n?").expect("re")
        });
        static CERT: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n?").expect("re")
        });
        let Some(combined) = staged.iter().find(|f| basename(&f.path) == "mitmproxy-ca.pem").cloned() else {
            return Ok(());
        };
        let dir = dirname(&combined.path);
        let cert_path = format!("{dir}/ca-cert.pem");
        let key_path = format!("{dir}/ca-key.pem");
        if !self.files.contains(&cert_path) || !self.files.contains(&key_path) {
            return Ok(());
        }
        if staged.iter().any(|f| f.path == cert_path) && staged.iter().any(|f| f.path == key_path) {
            return Ok(());
        }
        let pem = String::from_utf8_lossy(&std::fs::read(&combined.staged).map_err(|e| e.to_string())?).into_owned();
        let (Some(key), Some(cert)) = (KEY.find(&pem), CERT.find(&pem)) else {
            tracing::info!(
                "[backup] the archive's mitmproxy-ca.pem holds no key+certificate pair; the published CA is left as it is"
            );
            return Ok(());
        };
        for (path, body, mode) in [(cert_path, cert.as_str(), 0o644), (key_path, key.as_str(), 0o600)] {
            if staged.iter().any(|f| f.path == path) {
                continue;
            }
            let staged_path = staging.join(format!("derived-{}", basename(&path)));
            write_private(&staged_path, body.as_bytes())?;
            staged.push(Staged {
                path,
                mode,
                staged: staged_path,
            });
        }
        tracing::info!(
            "[backup] the archive carried only the proxy's combined CA file; ca-cert.pem and ca-key.pem were split out of it so the published CA matches the one the proxy signs with"
        );
        Ok(())
    }

    // ---- the swap ----

    async fn systemctl(&self, verb: &str) -> Result<(), String> {
        let Some(r) = &self.runner else { return Ok(()) };
        let cmd = Cmd::new("sudo")
            .args(["systemctl", verb, "controlclaw-mitmproxy"])
            .timeout(Duration::from_secs(30));
        let out = r.run(cmd).await.map_err(|e| e.to_string())?;
        if !out.success() {
            return Err(format!(
                "Command failed: sudo systemctl {verb} controlclaw-mitmproxy\n{}",
                out.stderr_str()
            ));
        }
        Ok(())
    }

    async fn start_proxy(&self) {
        if let Err(e) = self.systemctl("start").await {
            tracing::info!("[backup] the proxy did not start again: {e}. Start it from the Firewall page.");
        }
    }

    async fn swap(&self, staged: &[Staged], source_box_id: &str) -> Result<Vec<String>, String> {
        // Only a regular file can be copied back; anything else at a target is removed on undo. A
        // file that is there but cannot be read stops the restore here, before anything changed
        // (`readFileSync` throws): an undo would otherwise delete what it could not copy.
        let mut rollback: Vec<(String, Option<Vec<u8>>, u32)> = Vec::new();
        for f in staged {
            let st = std::fs::metadata(&f.path).ok().filter(|m| m.is_file());
            let before = match &st {
                Some(_) => Some(
                    std::fs::read(&f.path)
                        .map_err(|e| format!("{} could not be read, so nothing was replaced: {e}", f.path))?,
                ),
                None => None,
            };
            let mode = st.map_or(f.mode, |m| m.permissions().mode() & 0o7777);
            rollback.push((f.path.clone(), before, mode));
        }
        // The box key before: when the archive brings the same one, every store on disk still opens.
        let key_before = self.restored_box_key().ok();
        self.set_frozen(true);
        if self.systemctl("stop").await.is_err() {
            self.set_frozen(false);
            return Err("The proxy could not be stopped, so nothing was replaced.".into());
        }
        let mut failed = None;
        for f in staged {
            let r = self
                .rebind(f, source_box_id)
                .and_then(|b| write_atomic(&f.path, &b, f.mode).map_err(|e| e.to_string()));
            if let Err(e) = r {
                failed = Some(e);
                break;
            }
        }
        if let Some(e) = failed {
            let mut undone = true;
            for (path, before, mode) in &rollback {
                let r = match before {
                    Some(b) => write_atomic(path, b, *mode),
                    None => match std::fs::remove_file(path) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                        _ => Ok(()),
                    },
                };
                if let Err(u) = r {
                    undone = false;
                    tracing::info!("[backup] could not undo {path}: {u}");
                }
            }
            // Only a full undo puts back the store the running process holds.
            if undone {
                self.set_frozen(false);
            }
            self.start_proxy().await;
            return Err(format!("The swap failed and this firewall was put back as it was: {e}"));
        }
        self.start_proxy().await;
        // The same box key: the other stores still open, so they stay. (Changed from the TS, which
        // moves them aside on every restore, an emergency stop's store with them.)
        if key_before.is_some() && self.restored_box_key().ok() == key_before {
            return Ok(Vec::new());
        }
        match self.quarantine_strangers(staged) {
            Ok(m) => Ok(m),
            Err(e) => {
                tracing::info!("[backup] could not move the replaced box's other stores aside: {e}");
                Ok(Vec::new())
            }
        }
    }

    /// An encrypted store, sealed again under this box's id with the restored box key.
    fn rebind(&self, f: &Staged, source_box_id: &str) -> Result<Vec<u8>, String> {
        let bytes = std::fs::read(&f.staged).map_err(|e| e.to_string())?;
        let name = basename(&f.path);
        let Some((_, purpose)) = ENC_PURPOSES.iter().find(|(n, _)| *n == name) else {
            return Ok(bytes);
        };
        if source_box_id == self.box_id {
            return Ok(bytes);
        }
        let key = self.restored_box_key()?;
        let value = cc_crypto::enc_file::decrypt_json(
            &String::from_utf8_lossy(&bytes),
            &key,
            &format!("{}:{source_box_id}:{purpose}", self.org_id),
        )
        .map_err(|_| format!("The {name} in that archive cannot be opened with the box key that came with it."))?;
        let sealed =
            cc_crypto::enc_file::encrypt_json(&value, &key, &format!("{}:{}:{purpose}", self.org_id, self.box_id))
                .map_err(|e| e.0)?;
        Ok(sealed.into_bytes())
    }

    fn restored_box_key(&self) -> Result<String, String> {
        let missing = || "The restored box key is not in place, so the stores cannot be re-sealed.".to_string();
        let path = self
            .files
            .iter()
            .find(|p| basename(p) == "box_key")
            .ok_or_else(missing)?;
        Ok(std::fs::read_to_string(path).map_err(|_| missing())?.trim().to_string())
    }

    /// The backup-key fingerprint now on disk: the old one, back again.
    fn fingerprint_after(&self, staged: &[Staged]) -> Option<String> {
        let store = staged.iter().find(|f| basename(&f.path) == "backup.enc")?;
        let r = (|| {
            let raw = std::fs::read_to_string(&store.path).map_err(|e| e.to_string())?;
            let v = cc_crypto::enc_file::decrypt_json(
                &raw,
                &self.restored_box_key()?,
                &format!("{}:{}:backup", self.org_id, self.box_id),
            )
            .map_err(|e| e.0)?;
            Ok::<_, String>(
                v.get("keypair")
                    .and_then(|k| k.get("publicKey"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            )
        })();
        match r {
            Ok(Some(pk)) => fingerprint(&pk).ok(),
            Ok(None) => None,
            Err(e) => {
                tracing::info!("[backup] restored, but this box's own backup key could not be read back: {e}");
                None
            }
        }
    }

    /// Any `*.enc` in the state folder the archive did not bring is sealed under the replaced box
    /// key and can never be opened again: moved aside.
    fn quarantine_strangers(&self, staged: &[Staged]) -> Result<Vec<String>, String> {
        let Some(dir) = staged.iter().map(|f| dirname(&f.path)).find(|d| d.ends_with("/state")) else {
            return Ok(Vec::new());
        };
        if !Path::new(dir).exists() {
            return Ok(Vec::new());
        }
        let mut moved = Vec::new();
        for e in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let name = e.map_err(|e| e.to_string())?.file_name().to_string_lossy().into_owned();
            let path = format!("{dir}/{name}");
            if !name.ends_with(".enc") || staged.iter().any(|f| f.path == path) {
                continue;
            }
            let aside = format!("{path}.cc-previous-{}", super::now_ms());
            std::fs::rename(&path, &aside).map_err(|e| e.to_string())?;
            tracing::info!("[backup] {name} was sealed under the replaced box key; moved to {aside}");
            moved.push(name);
        }
        Ok(moved)
    }
}

#[cfg(test)]
mod tests {
    use super::super::self_backup::{SelfBackup, SelfBackupInput};
    use super::*;
    use cc_crypto::envelope::{generate_recipient_keypair, random_data_key};

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[tokio::test]
    async fn a_target_it_cannot_read_stops_the_restore_before_anything_changes() {
        let dir = tempfile::tempdir().expect("dir");
        let (target, staged) = (dir.path().join("ca-key.pem"), dir.path().join("staged"));
        std::fs::write(&target, "old").expect("w");
        std::fs::write(&staged, "new").expect("w");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::read(&target).is_ok() {
            return; // root reads it anyway
        }
        let restore = SelfRestore::new("o", "b", dir.path().to_path_buf(), reqwest::Client::new(), None, None)
            .with_files(vec![target.display().to_string()]);
        let f = Staged {
            path: target.display().to_string(),
            mode: 0o600,
            staged,
        };
        let e = restore.swap(&[f], "b").await.expect_err("refused");
        assert!(e.contains("could not be read, so nothing was replaced"), "{e}");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(std::fs::read_to_string(&target).expect("r"), "old");
    }

    #[tokio::test]
    async fn round_trip_rebinds_stores_and_quarantines() {
        let dir = tempfile::tempdir().expect("dir");
        let root = dir.path().display().to_string();
        let state = format!("{root}/state");
        std::fs::create_dir_all(&state).expect("mkdir");
        let files = vec![
            format!("{root}/keys/box_key"),
            format!("{state}/backup.enc"),
            format!("{state}/llm.enc"),
        ];
        std::fs::create_dir_all(format!("{root}/keys")).expect("mkdir");
        std::fs::write(&files[0], format!("{KEY}\n")).expect("key");
        let kp = generate_recipient_keypair();
        let store = serde_json::json!({"version": 1, "keypair": {"publicKey": kp.public_key, "secretKey": kp.secret_key, "fingerprint": kp.fingerprint}, "recovery": null});
        std::fs::write(
            &files[1],
            cc_crypto::enc_file::encrypt_json(&store, KEY, "org_1:old_box:backup").expect("seal"),
        )
        .expect("w");
        std::fs::write(
            &files[2],
            cc_crypto::enc_file::encrypt_json(&serde_json::json!({"a": 1}), KEY, "org_1:old_box:llm").expect("seal"),
        )
        .expect("w");

        let http = reqwest::Client::new();
        let backup = SelfBackup::with_files("org_1", "old_box", http.clone(), files.clone());
        let recovery = generate_recipient_keypair();
        let data_key = random_data_key();
        let (r, blob) = backup
            .seal(&SelfBackupInput {
                backup_id: "b1".into(),
                upload_url: "https://x".into(),
                data_key: data_key.clone(),
                recovery_public_key: recovery.public_key.clone(),
                recovery_fingerprint: recovery.fingerprint.clone(),
            })
            .await
            .expect("seal");
        assert_eq!(r.entries, 3);

        // The new box: its own box key, a different store that must be moved aside, and a
        // different llm.enc.
        std::fs::write(&files[0], "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n").expect("key");
        std::fs::write(&files[2], "junk").expect("w");
        std::fs::write(format!("{state}/connectors.enc"), "old").expect("w");
        let restore =
            SelfRestore::new("org_1", "new_box", dir.path().to_path_buf(), http, None, None).with_files(files.clone());
        let wrong = restore
            .run(SelfRestoreInput {
                backup_id: "b1".into(),
                source_box_id: "new_box".into(),
                download_url: None,
                archive: Some(blob.clone()),
                header: r.header.clone(),
                manifest_hash: r.manifest_hash.clone(),
                data_key: data_key.clone(),
                taken_at: None,
            })
            .await
            .expect_err("wrong source box");
        assert_eq!(wrong, cc_crypto::envelope::WRONG_KEY);
        let input = |taken_at: Option<String>| SelfRestoreInput {
            backup_id: "b1".into(),
            source_box_id: "old_box".into(),
            download_url: None,
            archive: Some(blob.clone()),
            header: r.header.clone(),
            manifest_hash: r.manifest_hash.clone(),
            data_key: data_key.clone(),
            taken_at,
        };
        let other_day = restore
            .run(input(Some("2020-01-01T00:00:00.000Z".into())))
            .await
            .expect_err("another date");
        assert!(other_day.contains("not from the date"), "{other_day}");
        let frozen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (f2, stop) = (frozen.clone(), Arc::new(std::sync::atomic::AtomicBool::new(true)));
        let s2 = stop.clone();
        restore.set_hooks(
            Arc::new(move || {
                if s2.load(std::sync::atomic::Ordering::SeqCst) {
                    Err("stop on".into())
                } else {
                    Ok(())
                }
            }),
            Arc::new(move |on| f2.lock().expect("l").push(on)),
        );
        assert_eq!(restore.run(input(None)).await.expect_err("stop"), "stop on");
        stop.store(false, std::sync::atomic::Ordering::SeqCst);
        let done = restore.run(input(None)).await.expect("restore");
        assert_eq!(
            *frozen.lock().expect("l"),
            vec![true],
            "frozen before the swap, kept after"
        );
        assert_eq!(done.entries, 3);
        assert_eq!(done.fingerprint.as_deref(), Some(kp.fingerprint.as_str()));
        assert_eq!(done.quarantined, vec!["connectors.enc".to_string()]);
        let llm = std::fs::read_to_string(&files[2]).expect("llm");
        assert_eq!(
            cc_crypto::enc_file::decrypt_json(&llm, KEY, "org_1:new_box:llm").expect("rebound"),
            serde_json::json!({"a": 1})
        );

        // Again, now with the same box key on disk: the other stores still open, so they stay.
        std::fs::write(format!("{state}/kill.enc"), "stop").expect("w");
        let again = restore.run(input(None)).await.expect("restore");
        assert!(again.quarantined.is_empty());
        assert!(std::path::Path::new(&format!("{state}/kill.enc")).exists());
    }
}
