//! Backing an agent's content up, and putting it back (`backup.ts`, `routes/backup.ts`). The org
//! firewall (never the console) posts `/backup/run` with a data key it minted, the archive's
//! identity and a presigned URL; the box seals the archive under that key and PUTs the ciphertext
//! straight to the object store. A restore downloads, opens, verifies everything into a staging
//! directory next to the target, and only then stops OpenClaw and swaps the directories.
//!
//! The ciphertext is spooled once to a temp file before the PUT (a presigned PUT needs a length).
//! A failed restore leaves the old content in place.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_crypto::envelope::{ArchiveKind, CHUNK_BYTES, Decryptor, Encryptor, EnvelopeBinding};
use cc_http::{BoxFuture, FirewallBody, Req, Resp};
use cc_proc::{Cmd, Runner};
use serde_json::{Map, Value, json};

use super::archive::{
    MANIFEST_PATH, Manifest, ManifestEntry, TarEntry, TarReader, TarType, archive_root, assert_archivable_root,
    keep_on_restore, safe_entry_path, should_exclude, tar_end, tar_header, tar_padding,
};
use super::web::{self, send_json};

/// v1: one presigned PUT per archive.
pub const MAX_ARCHIVE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const ACTION_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the object store may say nothing (undici's headers and body timeouts in the TS).
const STALL: Duration = Duration::from_secs(300);

/// An agent's archives (`AGENT_KINDS`); a brain passes its own.
pub const AGENT_KINDS: &[&str] = &["workspace", "state"];

/// A kind whose content is a copy made for the backup (the brain's, `StagedKind`): W8 provides it.
pub trait StagedKind: Send + Sync {
    fn kind(&self) -> &'static str;
    /// Where `prepare` leaves the copy.
    fn root(&self) -> PathBuf;
    /// Where a restore is extracted before `apply`.
    fn restore_dir(&self) -> PathBuf;
    fn prepare(&self) -> BoxFuture<Result<(), String>>;
    fn release(&self) -> BoxFuture<Result<(), String>>;
    fn apply(&self, dir: PathBuf) -> BoxFuture<Result<(), String>>;
}

/// `bytesLine`: binary units.
pub fn bytes_line(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let num = if i > 0 && v < 10.0 && v.fract() != 0.0 {
        let n = (v * 10.0 + 0.5).floor();
        format!("{}.{}", (n / 10.0).trunc() as i64, (n % 10.0) as i64)
    } else {
        format!("{}", (v + 0.5).floor() as u64)
    };
    format!("{num} {}", UNITS[i])
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub kind: String,
    pub root: PathBuf,
    pub manifest: Manifest,
    pub plain_bytes: u64,
    pub largest: Vec<(String, u64)>,
    /// Each file's device and inode as the walk saw it: the tar archives that file or nothing.
    pub inodes: std::collections::HashMap<String, (u64, u64)>,
}

/// No `Debug`: the data key and the presigned URL must never reach a log line.
#[derive(Clone)]
pub struct RunInput {
    pub org_id: String,
    pub vm_id: String,
    pub backup_id: String,
    pub kind: String,
    pub data_key: String,
    pub upload_url: String,
}

/// No `Debug`, as [`RunInput`].
#[derive(Clone)]
pub struct RestoreInput {
    pub org_id: String,
    pub vm_id: String,
    pub backup_id: String,
    pub kind: String,
    pub data_key: String,
    pub header: String,
    pub manifest_hash: String,
    pub download_url: String,
    pub source_vm_id: Option<String>,
}

fn binding(org: &str, vm: &str, backup: &str, kind: &str) -> Result<EnvelopeBinding, String> {
    Ok(EnvelopeBinding {
        org_id: org.into(),
        vm_id: vm.into(),
        backup_id: backup.into(),
        kind: ArchiveKind::parse(kind).ok_or("unknown archive kind")?,
    })
}

/// The TS's `fetch` failing without an answer. reqwest's own text carries the URL, and a
/// presigned URL carries a signature, so it is never shown.
const FETCH_FAILED: &str = "fetch failed";

/// Where the restore hooks come from: the `backup_hooks` slot, read when a restore runs.
pub type HooksSource = Arc<dyn Fn() -> Option<Arc<dyn crate::contracts::BackupHooks>> + Send + Sync>;

pub struct BackupService {
    home: PathBuf,
    spool_dir: PathBuf,
    runner: Arc<dyn Runner>,
    http: cc_client::HttpClient,
    /// `CC_SERVICE`: the unit a restore stops and starts.
    service: String,
    staged: Option<Arc<dyn StagedKind>>,
    hooks: Option<HooksSource>,
    /// One backup or restore at a time.
    busy: Mutex<Option<String>>,
}

/// Clears the busy label however a run ends.
struct BusyGuard<'a>(&'a Mutex<Option<String>>);
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut b) = self.0.lock() {
            *b = None;
        }
    }
}

impl BackupService {
    pub fn new(
        home: PathBuf,
        spool_dir: PathBuf,
        runner: Arc<dyn Runner>,
        http: cc_client::HttpClient,
        service: String,
    ) -> Self {
        Self {
            home,
            spool_dir,
            runner,
            http,
            service,
            staged: None,
            hooks: None,
            busy: Mutex::new(None),
        }
    }

    /// The brain's staged kind (W8's `gbrain` entry).
    pub fn with_staged(mut self, staged: Arc<dyn StagedKind>) -> Self {
        self.staged = Some(staged);
        self
    }

    /// Where the meetings hooks come from (a contract slot read when a restore runs).
    pub fn with_hooks(
        mut self,
        f: Arc<dyn Fn() -> Option<Arc<dyn crate::contracts::BackupHooks>> + Send + Sync>,
    ) -> Self {
        self.hooks = Some(f);
        self
    }

    fn staged_for(&self, kind: &str) -> Option<Arc<dyn StagedKind>> {
        self.staged.clone().filter(|s| s.kind() == kind)
    }

    fn root_for(&self, kind: &str) -> Result<PathBuf, String> {
        if kind == "firewall" {
            return Err("an agent box does not hold the firewall's own backup".into());
        }
        if let Some(s) = self.staged_for(kind) {
            let root = s.root();
            assert_archivable_root(&root.to_string_lossy())?;
            return Ok(root);
        }
        if kind == "gbrain" {
            return Err("an agent box does not hold a brain".into());
        }
        let root = match archive_root(kind).ok_or("unknown archive kind")? {
            "." => self.home.clone(),
            sub => self.home.join(sub),
        };
        assert_archivable_root(&root.to_string_lossy())?;
        Ok(root)
    }

    fn take_busy(&self, label: String) -> Result<BusyGuard<'_>, String> {
        let mut b = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = b.as_ref() {
            return Err(format!(
                "This agent is already backing up or restoring ({current}). Wait for that to finish."
            ));
        }
        *b = Some(label);
        Ok(BusyGuard(&self.busy))
    }

    /// What a backup of this kind would contain and cost, without producing it.
    pub async fn plan(&self, kind: &str) -> Result<Plan, String> {
        let root = self.root_for(kind)?;
        let kind = kind.to_string();
        tokio::task::spawn_blocking(move || plan_blocking(&root, &kind))
            .await
            .map_err(|e| e.to_string())?
    }

    fn over_limit(plan: &Plan) -> String {
        let worst: Vec<String> = plan
            .largest
            .iter()
            .filter(|(_, b)| *b > 0)
            .map(|(p, b)| format!("{p} ({})", bytes_line(*b)))
            .collect();
        format!(
            "This agent's {} is {}, over the {} limit for one backup. {}Move or delete what you do not need, or ask us to enable large backups.",
            plan.kind,
            bytes_line(plan.plain_bytes),
            bytes_line(MAX_ARCHIVE_BYTES),
            if worst.is_empty() {
                String::new()
            } else {
                format!("The biggest directories are {}. ", worst.join(", "))
            }
        )
    }

    pub async fn run(&self, input: &RunInput) -> Result<Value, String> {
        let _busy = self.take_busy(format!("{} of {}", input.kind, input.vm_id))?;
        let staged = self.staged_for(&input.kind);
        let mut spool_dir: Option<PathBuf> = None;
        let result = async {
            if let Some(s) = &staged {
                s.prepare().await?;
            }
            let plan = self.plan(&input.kind).await?;
            if plan.plain_bytes > MAX_ARCHIVE_BYTES {
                return Err(Self::over_limit(&plan));
            }
            let hash = plan.manifest.hash();
            let enc = Encryptor::new(
                &input.data_key,
                &binding(&input.org_id, &input.vm_id, &input.backup_id, &input.kind)?,
            )
            .map_err(|e| e.to_string())?;
            let header = enc.header().to_string();
            let dir = make_spool_dir(&self.spool_dir)?;
            spool_dir = Some(dir.clone());
            let spool = dir.join("archive.bin");
            let (root, manifest, path, inodes) = (
                plan.root.clone(),
                plan.manifest.clone(),
                spool.clone(),
                plan.inodes.clone(),
            );
            let cipher_bytes = tokio::task::spawn_blocking(move || seal_archive(&root, &manifest, &inodes, enc, &path))
                .await
                .map_err(|e| e.to_string())??;
            tracing::info!(
                "[backup] {} of {}: {} of content → {} sealed",
                input.kind,
                input.vm_id,
                bytes_line(plan.plain_bytes),
                bytes_line(cipher_bytes)
            );
            self.put(&input.upload_url, &spool, cipher_bytes).await?;
            let mut out = Map::new();
            out.insert("kind".into(), json!(input.kind));
            out.insert("header".into(), json!(header));
            out.insert("manifestHash".into(), json!(hash));
            out.insert("plainBytes".into(), json!(plan.plain_bytes));
            out.insert("cipherBytes".into(), json!(cipher_bytes));
            out.insert("entries".into(), json!(plan.manifest.entries.len()));
            out.insert(
                "excludedBytes".into(),
                json!(plan.manifest.excluded.iter().map(|e| e.1).sum::<u64>()),
            );
            out.insert("takenAt".into(), json!(plan.manifest.taken_at));
            Ok(Value::Object(out))
        }
        .await;
        if let Some(d) = spool_dir {
            let _ = tokio::fs::remove_dir_all(d).await;
        }
        if let Some(s) = &staged
            && let Err(e) = s.release().await
        {
            tracing::info!("[backup] could not drop the staged copy: {e}");
        }
        result
    }

    async fn put(&self, url: &str, path: &Path, size: u64) -> Result<(), String> {
        let file = tokio::fs::File::open(path).await.map_err(|e| e.to_string())?;
        let stream = futures_util::stream::unfold(file, |mut f| async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 256 * 1024];
            match f.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some((Ok::<_, std::io::Error>(buf), f))
                }
                Err(e) => Some((Err(e), f)),
            }
        });
        let send = self
            .http
            .get()
            .put(url)
            .header("content-length", size.to_string())
            .header("content-type", "application/octet-stream")
            .body(reqwest::Body::wrap_stream(stream))
            .send();
        // The whole upload at no less than 100 kB/s, plus undici's 300 s for the answer.
        let budget = STALL + Duration::from_secs(size / 100_000);
        let res = tokio::time::timeout(budget, send)
            .await
            .map_err(|_| FETCH_FAILED.to_string())?
            .map_err(|_| FETCH_FAILED.to_string())?;
        if !res.status().is_success() {
            // Never the URL (it carries a signature), never the body (it echoes the key).
            return Err(format!(
                "The backup store refused the upload (HTTP {}).",
                res.status().as_u16()
            ));
        }
        Ok(())
    }

    /// Download, open, verify, then swap. Nothing under the target is touched until the archive
    /// was extracted whole and its manifest matched.
    pub async fn restore(&self, input: &RestoreInput) -> Result<Value, String> {
        let _busy = self.take_busy(format!("restore of {} onto {}", input.kind, input.vm_id))?;
        let target = self.root_for(&input.kind)?;
        let staged = self.staged_for(&input.kind);
        let staging = match &staged {
            Some(s) => s.restore_dir(),
            None => PathBuf::from(format!("{}.cc-restoring", target.display())),
        };
        let aside = PathBuf::from(format!(
            "{}.cc-previous-{}",
            target.display(),
            web::time_ms(std::time::SystemTime::now())
        ));
        let hooks = self.hooks.as_ref().and_then(|f| f());
        let result = self
            .restore_into(input, &target, staged, &staging, &aside, hooks.clone())
            .await;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        if let Some(h) = &hooks {
            h.restore_finished();
        }
        result
    }

    async fn restore_into(
        &self,
        input: &RestoreInput,
        target: &Path,
        staged: Option<Arc<dyn StagedKind>>,
        staging: &Path,
        aside: &Path,
        hooks: Option<Arc<dyn crate::contracts::BackupHooks>>,
    ) -> Result<Value, String> {
        // The meetings scrub (W8): without it a restore could bring back meetings the owner deleted,
        // so no restore runs until it is there. Checked before anything is downloaded.
        if staged.is_none() && hooks.is_none() {
            return Err("This agent cannot restore a backup yet: its meetings service is not ready.".into());
        }
        let _ = tokio::fs::remove_dir_all(staging).await;
        mkdir_all_mode(staging, 0o700).map_err(|e| e.to_string())?;
        let (hash, entries, plain_bytes) = self.extract(input, staging).await?;
        if hash != input.manifest_hash {
            return Err("This backup does not match what was recorded for it. Nothing was restored.".into());
        }
        tracing::info!(
            "[backup] restore of {} onto {}: {entries} entries verified, swapping",
            input.kind,
            input.vm_id
        );
        let result = |restarted: bool| json!({"kind": input.kind, "entries": entries, "plainBytes": plain_bytes, "restarted": restarted});
        if let Some(s) = staged {
            s.apply(staging.to_path_buf()).await?;
            return Ok(result(true));
        }
        let Some(hooks) = hooks else {
            return Err("This agent cannot restore a backup yet: its meetings service is not ready.".into());
        };
        hooks.before_restore().await?;
        if let Err(e) = self.unit("stop").await {
            // The scrub needs the writer stopped, so the restore ends here (the TS's
            // `sanitizeRestore && !stopped.ok`).
            tracing::info!("[backup] could not stop OpenClaw cleanly: {e}");
            return Err("Could not stop the archive writer before restore".into());
        }
        let (kind, target_p, staging_p, aside_p) = (
            input.kind.clone(),
            target.to_path_buf(),
            staging.to_path_buf(),
            aside.to_path_buf(),
        );
        // Renames and tree walks: a thread of their own, not the runtime's.
        let swapped = tokio::task::spawn_blocking(move || {
            hooks.sanitize_restore(&kind, &staging_p)?;
            swap_directory(&target_p, &staging_p, &aside_p, &keep_on_restore(&kind)).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        if let Err(e) = swapped {
            if let Err(s) = self.unit("start").await {
                tracing::error!("[backup] the restore stopped ({e}) and OpenClaw did not start again: {s}");
            }
            return Err(e);
        }
        let started = self.unit("start").await;
        if let Err(e) = &started {
            tracing::info!("[backup] OpenClaw did not start after the restore: {e}");
        }
        let _ = tokio::fs::remove_dir_all(aside).await;
        Ok(result(started.is_ok()))
    }

    /// `runAction`: `sudo systemctl <action> <service>` (no `-n`, as the TS runs it). Noted as
    /// this agent's own short stop (`OWN_STOP_MS`), which the watchdog leaves alone.
    async fn unit(&self, action: &str) -> Result<(), String> {
        let own = crate::platform::stop_mark::OWN_STOP_MS;
        crate::platform::stop_mark::STOP_MARK.note(action, Some(own));
        let cmd = Cmd::new("sudo")
            .args(["systemctl", action, &self.service])
            .timeout(ACTION_TIMEOUT);
        match self.runner.run(cmd).await {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => {
                let e = out.stderr_str().trim().to_string();
                Err(if e.is_empty() {
                    format!("Command failed: sudo systemctl {action} {}", self.service)
                } else {
                    e
                })
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The blob into `into`, entry by entry: download → unseal → gunzip → untar. The envelope is
    /// the outer layer, so nothing is decompressed, let alone written, before its MAC passed.
    async fn extract(&self, input: &RestoreInput, into: &Path) -> Result<(String, u64, u64), String> {
        let res = tokio::time::timeout(STALL, self.http.get().get(&input.download_url).send())
            .await
            .map_err(|_| FETCH_FAILED.to_string())?
            .map_err(|_| FETCH_FAILED.to_string())?;
        if !res.status().is_success() {
            return Err(format!(
                "The backup store would not serve this archive (HTTP {}).",
                res.status().as_u16()
            ));
        }
        // The box it was sealed on: still bound to the org, the backup and the kind.
        let dec = Decryptor::new(
            &input.data_key,
            &input.header,
            &binding(
                &input.org_id,
                input.source_vm_id.as_deref().unwrap_or(&input.vm_id),
                &input.backup_id,
                &input.kind,
            )?,
        )
        .map_err(|e| e.to_string())?;
        let (tx, rx) = tokio::sync::mpsc::channel::<Option<Vec<u8>>>(8);
        let dir = into.to_path_buf();
        let worker = tokio::task::spawn_blocking(move || unpack(dec, rx, &dir));
        let mut res = res;
        let mut fed = Ok(());
        loop {
            // A store that stops sending is a failed restore, not one that holds the box busy.
            match tokio::time::timeout(STALL, res.chunk()).await {
                Ok(Ok(Some(c))) => {
                    if tx.send(Some(c.to_vec())).await.is_err() {
                        break;
                    }
                }
                Ok(Ok(None)) => {
                    let _ = tx.send(None).await;
                    break;
                }
                _ => {
                    fed = Err(FETCH_FAILED.to_string());
                    break;
                }
            }
        }
        drop(tx);
        let unpacked = worker.await.map_err(|e| e.to_string())?;
        // The unpacker's reason first: a broken stream is better explained by what it saw.
        let r = unpacked?;
        fed?;
        Ok(r)
    }
}

fn make_spool_dir(base: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(base).map_err(|e| e.to_string())?;
    for _ in 0..10 {
        let suffix: String = uuid::Uuid::new_v4().simple().to_string()[..6].to_string();
        let d = base.join(format!("cc-backup-{suffix}"));
        match std::fs::create_dir(&d) {
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
                return Ok(d);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("could not make a spool directory".into())
}

fn mkdir_all_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(mode).create(p)
}

/// The walk behind `plan`.
fn plan_blocking(root: &Path, kind: &str) -> Result<Plan, String> {
    use std::os::unix::fs::MetadataExt;
    let mut entries = Vec::new();
    let mut excluded: Vec<(String, u64)> = Vec::new();
    let mut dir_bytes: Vec<(String, u64)> = Vec::new();
    let mut plain = 0u64;
    let mut inodes = std::collections::HashMap::new();
    #[allow(clippy::too_many_arguments)]
    fn walk(
        root: &Path,
        rel: &str,
        kind: &str,
        entries: &mut Vec<ManifestEntry>,
        excluded: &mut Vec<(String, u64)>,
        dir_bytes: &mut Vec<(String, u64)>,
        plain: &mut u64,
        inodes: &mut std::collections::HashMap<String, (u64, u64)>,
    ) {
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        // A directory that vanished mid-walk is not a failed backup.
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            let child = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let abs = root.join(&child);
            if should_exclude(&child, kind) {
                let is_dir = item.file_type().is_ok_and(|t| t.is_dir());
                let bytes = if is_dir { dir_size(&abs) } else { file_size(&abs) };
                excluded.push((child, bytes));
                continue;
            }
            let Ok(st) = std::fs::symlink_metadata(&abs) else {
                continue;
            };
            if st.file_type().is_symlink() {
                let target = std::fs::read_link(&abs)
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_default();
                entries.push(ManifestEntry {
                    path: child,
                    bytes: 0,
                    mode: 0o777,
                    kind: "link",
                    target: Some(target),
                });
                continue;
            }
            if st.is_dir() {
                entries.push(ManifestEntry {
                    path: child.clone(),
                    bytes: 0,
                    mode: st.mode() & 0o7777,
                    kind: "dir",
                    target: None,
                });
                walk(root, &child, kind, entries, excluded, dir_bytes, plain, inodes);
                continue;
            }
            if !st.is_file() {
                continue;
            }
            inodes.insert(child.clone(), (st.dev(), st.ino()));
            entries.push(ManifestEntry {
                path: child.clone(),
                bytes: st.len(),
                mode: st.mode() & 0o7777,
                kind: "file",
                target: None,
            });
            *plain += st.len();
            let top = child.split('/').next().unwrap_or_default().to_string();
            match dir_bytes.iter_mut().find(|(p, _)| *p == top) {
                Some(e) => e.1 += st.len(),
                None => dir_bytes.push((top, st.len())),
            }
        }
    }
    walk(
        root,
        "",
        kind,
        &mut entries,
        &mut excluded,
        &mut dir_bytes,
        &mut plain,
        &mut inodes,
    );
    // Biggest first; a stable sort keeps the walk's order on ties, as the TS's does.
    excluded.sort_by_key(|e| std::cmp::Reverse(e.1));
    excluded.truncate(20);
    dir_bytes.sort_by_key(|e| std::cmp::Reverse(e.1));
    dir_bytes.truncate(5);
    let manifest = Manifest {
        kind: kind.to_string(),
        taken_at: web::iso(web::time_ms(std::time::SystemTime::now())),
        root: root.to_string_lossy().into_owned(),
        entries,
        total_bytes: plain,
        excluded,
        extra: Map::new(),
    };
    Ok(Plan {
        kind: kind.to_string(),
        root: root.to_path_buf(),
        manifest,
        plain_bytes: plain,
        largest: dir_bytes,
        inodes,
    })
}

fn file_size(p: &Path) -> u64 {
    std::fs::metadata(p)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .unwrap_or(0)
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    let mut total = 0;
    for item in rd.flatten() {
        let child = item.path();
        match item.file_type() {
            Ok(t) if t.is_dir() => total += dir_size(&child),
            Ok(t) if t.is_file() => total += file_size(&child),
            _ => {}
        }
    }
    total
}

/// Writes whole envelope chunks of what gzip produces, to the spool file.
struct Sealer {
    enc: Encryptor,
    pending: Vec<u8>,
    out: std::io::BufWriter<std::fs::File>,
    written: u64,
}

impl Write for Sealer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while self.pending.len() >= CHUNK_BYTES {
            let chunk: Vec<u8> = self.pending.drain(..CHUNK_BYTES).collect();
            let sealed = self.enc.push(&chunk).map_err(std::io::Error::other)?;
            self.out.write_all(&sealed)?;
            self.written += sealed.len() as u64;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sealer {
    fn finish(mut self) -> std::io::Result<u64> {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            let sealed = self.enc.push(&rest).map_err(std::io::Error::other)?;
            self.out.write_all(&sealed)?;
            self.written += sealed.len() as u64;
        }
        let last = self.enc.finish().map_err(std::io::Error::other)?;
        self.out.write_all(&last)?;
        self.written += last.len() as u64;
        self.out.flush()?;
        Ok(self.written)
    }
}

/// tar → gzip (level 6) → seal, into `spool` (0600). Returns the ciphertext's size.
fn seal_archive(
    root: &Path,
    manifest: &Manifest,
    inodes: &std::collections::HashMap<String, (u64, u64)>,
    enc: Encryptor,
    spool: &Path,
) -> Result<u64, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(spool)
        .map_err(|e| e.to_string())?;
    let sealer = Sealer {
        enc,
        pending: Vec::with_capacity(CHUNK_BYTES),
        out: std::io::BufWriter::new(file),
        written: 0,
    };
    let mut gz = flate2::write::GzEncoder::new(sealer, flate2::Compression::new(6));
    write_tar(root, manifest, inodes, &mut gz).map_err(|e| e.to_string())?;
    let sealer = gz.finish().map_err(|e| e.to_string())?;
    sealer.finish().map_err(|e| e.to_string())
}

/// The archive as tar: the manifest first, then everything it lists. A file that changed since
/// the walk is padded or cut to the size the manifest promised.
/// `O_NOFOLLOW` on Linux.
pub(super) const O_NOFOLLOW: i32 = 0o400_000;

/// The file the walk saw, opened again: not through a link, and the same device and inode. A file
/// swapped for a link to somewhere else since the walk (a parent folder included) reads as gone.
fn open_walked(
    root: &Path,
    rel: &str,
    inodes: &std::collections::HashMap<String, (u64, u64)>,
) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(root.join(rel))
        .ok()?;
    let m = f.metadata().ok()?;
    (m.is_file() && inodes.get(rel) == Some(&(m.dev(), m.ino()))).then_some(f)
}

fn write_tar(
    root: &Path,
    manifest: &Manifest,
    inodes: &std::collections::HashMap<String, (u64, u64)>,
    out: &mut impl Write,
) -> std::io::Result<()> {
    use std::io::Read;
    let io = std::io::Error::other;
    let body = manifest.to_json().into_bytes();
    let mtime = super::web::date_parse(&manifest.taken_at)
        .map(|ms| (ms / 1000).max(0) as u64)
        .unwrap_or(0);
    let header = |path: &str, kind: TarType, size: u64, mode: u32, target: Option<&str>| {
        tar_header(&TarEntry {
            path: path.into(),
            kind,
            size,
            mode,
            mtime,
            target: target.map(str::to_string),
        })
    };
    out.write_all(&header(MANIFEST_PATH, TarType::File, body.len() as u64, 0o600, None).map_err(io)?)?;
    out.write_all(&body)?;
    out.write_all(&tar_padding(body.len() as u64))?;
    for e in &manifest.entries {
        match e.kind {
            "dir" => out.write_all(&header(&format!("{}/", e.path), TarType::Dir, 0, e.mode, None).map_err(io)?)?,
            "link" => out.write_all(
                &header(
                    &e.path,
                    TarType::Link,
                    0,
                    e.mode,
                    Some(e.target.as_deref().unwrap_or("")),
                )
                .map_err(io)?,
            )?,
            _ => {
                out.write_all(&header(&e.path, TarType::File, e.bytes, e.mode, None).map_err(io)?)?;
                let mut sent = 0u64;
                if let Some(f) = open_walked(root, &e.path, inodes) {
                    let mut f = f.take(e.bytes);
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        out.write_all(&buf[..n])?;
                        sent += n as u64;
                    }
                }
                let mut left = e.bytes - sent;
                let zeros = [0u8; 8192];
                while left > 0 {
                    let n = left.min(zeros.len() as u64) as usize;
                    out.write_all(&zeros[..n])?;
                    left -= n as u64;
                }
                out.write_all(&tar_padding(e.bytes))?;
            }
        }
    }
    out.write_all(&tar_end())
}

/// Writes what gunzip produces into the tar reader, and each entry to disk.
struct Untar<'a> {
    reader: TarReader,
    into: &'a Path,
    manifest: Option<Manifest>,
    entries: u64,
    plain: u64,
    dirs: Vec<(PathBuf, u32)>,
    error: Option<String>,
}

impl Write for Untar<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let found = self.reader.push(buf).map_err(|e| self.fail(e))?;
        for e in found {
            self.place(e).map_err(|e| self.fail(e))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Untar<'_> {
    fn fail(&mut self, e: String) -> std::io::Error {
        self.error.get_or_insert(e.clone());
        std::io::Error::other(e)
    }

    fn place(&mut self, e: super::archive::ReadEntry) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        let rel = safe_entry_path(&e.entry.path)?;
        if rel == MANIFEST_PATH {
            self.manifest = Some(Manifest::parse(&String::from_utf8_lossy(&e.body))?);
            return Ok(());
        }
        // Never through a link this restore made: a name like `a\\x` (read as `a/x`) after a link
        // `a` would otherwise write wherever `a` points. The TS has no such check.
        let mut at = self.into.to_path_buf();
        let parts: Vec<&str> = rel.split('/').collect();
        for p in &parts[..parts.len().saturating_sub(1)] {
            at.push(p);
            if std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(format!("this archive contains a path through a link ({rel})"));
            }
        }
        let abs = self.into.join(&rel);
        if std::fs::symlink_metadata(&abs).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!("this archive contains a path through a link ({rel})"));
        }
        if e.entry.kind == TarType::Dir {
            mkdir_all_mode(&abs, 0o700).map_err(|x| x.to_string())?;
            self.dirs.push((abs, e.entry.mode));
            return Ok(());
        }
        if let Some(parent) = abs.parent() {
            mkdir_all_mode(parent, 0o700).map_err(|x| x.to_string())?;
        }
        if e.entry.kind == TarType::Link {
            let _ = std::os::unix::fs::symlink(e.entry.target.as_deref().unwrap_or(""), &abs);
            return Ok(());
        }
        // `writeFile(abs, body, {mode})`: the mode applies when the file is made.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(e.entry.mode & 0o7777)
            .open(&abs)
            .map_err(|x| x.to_string())?;
        f.write_all(&e.body).map_err(|x| x.to_string())?;
        drop(f);
        if e.entry.mtime > 0 {
            let t = std::time::UNIX_EPOCH + Duration::from_secs(e.entry.mtime);
            // `futimens` needs ownership, not write access, so a read-only file gets its time too.
            if let Ok(f) = std::fs::File::open(&abs) {
                let _ = f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t));
            }
        }
        self.entries += 1;
        self.plain += e.body.len() as u64;
        Ok(())
    }
}

/// The blocking half of a restore: plaintext chunks into gunzip, gunzip into the tar reader.
fn unpack(
    mut dec: Decryptor,
    mut rx: tokio::sync::mpsc::Receiver<Option<Vec<u8>>>,
    into: &Path,
) -> Result<(String, u64, u64), String> {
    let untar = Untar {
        reader: TarReader::default(),
        into,
        manifest: None,
        entries: 0,
        plain: 0,
        dirs: Vec::new(),
        error: None,
    };
    let mut gz = flate2::write::GzDecoder::new(untar);
    let mut ended = false;
    while let Some(msg) = rx.blocking_recv() {
        let Some(cipher) = msg else {
            ended = true;
            break;
        };
        for plain in dec.push(&cipher).map_err(|e| e.to_string())? {
            if let Err(e) = gz.write_all(&plain) {
                return Err(gz.get_ref().error.clone().unwrap_or_else(|| e.to_string()));
            }
        }
    }
    if !ended {
        // The download broke off; the caller says so.
        return Err(FETCH_FAILED.into());
    }
    // Before gunzip is closed: "this archive is incomplete" is the truthful answer.
    dec.end().map_err(|e| e.to_string())?;
    let untar = match gz.finish() {
        Ok(u) => u,
        Err(e) => return Err(e.to_string()),
    };
    if !untar.reader.complete() {
        return Err("This archive ended early — it is incomplete. Nothing was restored.".into());
    }
    let Some(manifest) = untar.manifest else {
        return Err("This archive has no manifest, so it cannot be checked. Nothing was restored.".into());
    };
    // Directory modes last: content never sits in a world-readable directory.
    use std::os::unix::fs::PermissionsExt;
    for (abs, mode) in &untar.dirs {
        let _ = std::fs::set_permissions(abs, std::fs::Permissions::from_mode(mode & 0o7777));
    }
    Ok((manifest.hash(), untar.entries, untar.plain))
}

/// `swapDirectory`: replace `target` with `staged` by rename, carrying `keep` over from the old one
/// first; every step undone on failure.
pub fn swap_directory(target: &Path, staged: &Path, aside: &Path, keep: &[String]) -> std::io::Result<()> {
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    let undo = |moved: &mut Vec<(PathBuf, PathBuf)>| {
        for (from, to) in moved.drain(..).rev() {
            let _ = std::fs::rename(&to, &from);
        }
    };
    for rel in keep {
        let from = target.join(rel);
        let to = staged.join(rel);
        if std::fs::symlink_metadata(&from).is_err() {
            continue;
        }
        let step = (|| {
            match std::fs::symlink_metadata(&to) {
                Ok(m) if m.is_dir() => std::fs::remove_dir_all(&to)?,
                Ok(_) => std::fs::remove_file(&to)?,
                Err(_) => {}
            }
            if let Some(p) = to.parent() {
                mkdir_all_mode(p, 0o700)?;
            }
            std::fs::rename(&from, &to)
        })();
        if let Err(e) = step {
            undo(&mut moved);
            return Err(e);
        }
        moved.push((from, to));
    }
    let existed = std::fs::symlink_metadata(target).is_ok();
    if existed && let Err(e) = std::fs::rename(target, aside) {
        undo(&mut moved);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(staged, target) {
        if existed {
            let _ = std::fs::rename(aside, target);
        }
        undo(&mut moved);
        return Err(e);
    }
    Ok(())
}

// ---- the routes ----

fn s<'a>(b: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    b.get(k).and_then(Value::as_str).filter(|v| !v.is_empty())
}

fn is_id(v: &str) -> bool {
    (1..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `/^[A-Za-z0-9+/]+={0,2}$/`.
fn is_b64(v: &str) -> bool {
    let body = v.trim_end_matches('=');
    v.len() - body.len() <= 2
        && !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn https_url(b: &Map<String, Value>, k: &str) -> Option<String> {
    let v = s(b, k)?;
    if v.encode_utf16().count() > 4096 {
        return None;
    }
    (url::Url::parse(v).ok()?.scheme() == "https").then(|| v.to_string())
}

fn kinds_text(kinds: &[&str]) -> String {
    format!("kind must be {}", kinds.join(" or "))
}

#[allow(clippy::type_complexity)]
fn common(b: &Map<String, Value>, kinds: &[&str]) -> Result<(String, String, String, String, String), String> {
    let org = s(b, "orgId")
        .filter(|o| o.encode_utf16().count() <= 64)
        .ok_or("orgId is required")?;
    let vm = s(b, "vmId").filter(|v| is_id(v)).ok_or("vmId is required")?;
    let backup = s(b, "backupId").filter(|v| is_id(v)).ok_or("backupId is required")?;
    let kind = s(b, "kind")
        .filter(|k| kinds.contains(k))
        .ok_or_else(|| kinds_text(kinds))?;
    let key = s(b, "dataKey")
        .filter(|k| k.len() == 44 && is_b64(k))
        .ok_or("dataKey is required")?;
    Ok((org.into(), vm.into(), backup.into(), kind.into(), key.into()))
}

pub fn parse_run(b: &Map<String, Value>, kinds: &[&str]) -> Result<RunInput, String> {
    let (org_id, vm_id, backup_id, kind, data_key) = common(b, kinds)?;
    let upload_url = https_url(b, "uploadUrl").ok_or("uploadUrl must be an https URL")?;
    Ok(RunInput {
        org_id,
        vm_id,
        backup_id,
        kind,
        data_key,
        upload_url,
    })
}

pub fn parse_restore(b: &Map<String, Value>, kinds: &[&str]) -> Result<RestoreInput, String> {
    let (org_id, vm_id, backup_id, kind, data_key) = common(b, kinds)?;
    let download_url = https_url(b, "downloadUrl").ok_or("downloadUrl must be an https URL")?;
    let header = s(b, "header")
        .filter(|h| h.len() == 32 && is_b64(h))
        .ok_or("header is required")?;
    let manifest_hash = s(b, "manifestHash")
        .filter(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
        .ok_or("manifestHash is required")?;
    let source_vm_id = match s(b, "sourceVmId") {
        Some(v) if is_id(v) => Some(v.to_string()),
        Some(_) => return Err("sourceVmId must be a vm id".into()),
        None => None,
    };
    Ok(RestoreInput {
        org_id,
        vm_id,
        backup_id,
        kind,
        data_key,
        header: header.into(),
        manifest_hash: manifest_hash.into(),
        download_url,
        source_vm_id,
    })
}

fn failed(message: String) -> Resp {
    let lower = message.to_lowercase();
    let status = if lower.contains("already backing up") || lower.contains("already restoring") {
        409
    } else {
        500
    };
    send_json(status, &json!({"ok": false, "error": message}), &[])
}

fn ok_with(v: Value) -> Resp {
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    if let Value::Object(m) = v {
        out.extend(m);
    }
    send_json(200, &Value::Object(out), &[])
}

/// `handleBackup`: writes from the firewall only (`backup`), the plan with either token.
pub async fn handle(app: &crate::app::App, service: &BackupService, req: Req, kinds: &[&str]) -> Resp {
    let write = req.method() == http::Method::POST;
    let (parts, body) =
        match web::firewall_or_console(app, req, "backup", "backups must come from the org firewall").await {
            Ok(r) => r,
            Err(r) => return *r,
        };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    if pathname == "/backup/plan" && parts.method == http::Method::GET {
        let kind = web::query(&parts, "kind").unwrap_or_default();
        if !kinds.contains(&kind.as_str()) {
            return send_json(400, &json!({"ok": false, "error": kinds_text(kinds)}), &[]);
        }
        return match service.plan(&kind).await {
            // The manifest itself (every file the customer has) never leaves the box; its shape does.
            Ok(p) => send_json(
                200,
                &json!({
                    "ok": true,
                    "kind": p.kind,
                    "plainBytes": p.plain_bytes,
                    "entries": p.manifest.entries.len(),
                    "largest": p.largest.iter().map(|(path, bytes)| json!({"path": path, "bytes": bytes})).collect::<Vec<_>>(),
                    "excluded": p.manifest.excluded.iter().map(|(path, bytes)| json!({"path": path, "bytes": bytes})).collect::<Vec<_>>(),
                }),
                &[],
            ),
            Err(e) => failed(e),
        };
    }
    if !write {
        return send_json(404, &json!({"error": "Not found"}), &[]);
    }
    let FirewallBody::Json(body) = body else {
        return send_json(400, &json!({"ok": false, "error": "Invalid JSON body"}), &[]);
    };
    match pathname.as_str() {
        "/backup/run" => match parse_run(&body, kinds) {
            Err(e) => send_json(400, &json!({"ok": false, "error": e}), &[]),
            Ok(input) => match service.run(&input).await {
                Ok(v) => ok_with(v),
                Err(e) => failed(e),
            },
        },
        "/backup/restore" => match parse_restore(&body, kinds) {
            Err(e) => send_json(400, &json!({"ok": false, "error": e}), &[]),
            Ok(input) => match service.restore(&input).await {
                Ok(v) => ok_with(v),
                Err(e) => failed(e),
            },
        },
        _ => send_json(404, &json!({"error": "Not found"}), &[]),
    }
}

#[cfg(test)]
mod tests;
