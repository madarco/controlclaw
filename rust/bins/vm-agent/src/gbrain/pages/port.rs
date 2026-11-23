//! Export and Import on the brain's pages: the whole brain out as a zip of Markdown, a zip of
//! Markdown in (an Obsidian vault, a Notion export).
//!
//! GBrain's own `export` and `import` do the work. They need GBrain's env file, so a root helper
//! runs them with fixed verbs and fixed paths (`cc-gbrain-pages export|import`, the Ansible role's
//! `gbrain-pages.yml`). The hand-over directory is the vm-agent's, in the state directory, inside the
//! encrypted container:
//!
//! - `export/`: GBrain's export, given to the vm-agent, zipped to the browser, then removed.
//! - `import/upload.zip`: the upload, which the helper takes; `import/progress`: what it has done
//!   (`read {...}` once the zip is read, then `<done> <total>` as GBrain imports).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use cc_proc::Runner;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use super::super::{now_ms, run_helper};
use super::client::PagesError;
use crate::boxside::export::Sink;
use crate::boxside::zip::ZipWriter;

use super::HELPER;
/// The largest zip Import takes. The page says so.
pub const IMPORT_MAX_BYTES: u64 = 100 * 1024 * 1024;
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const IMPORT_TIMEOUT: Duration = Duration::from_secs(3 * 60 * 60);

/// Where an import is: `idle`, `running` (reading the zip, then importing), `done` or `failed`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportStatus {
    pub state: &'static str,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

pub struct Port {
    runner: Arc<dyn Runner>,
    dir: PathBuf,
    exporting: Arc<AtomicBool>,
    import: Arc<Mutex<ImportStatus>>,
}

/// Removes a directory when it goes out of scope.
struct RemoveOnDrop(Option<PathBuf>);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

/// An import that never got going (the upload failed, or the browser left during it) goes back to
/// idle with its upload removed, unless `started` says the helper took it over.
struct ImportClaim {
    status: Arc<Mutex<ImportStatus>>,
    dir: PathBuf,
    started: bool,
}
impl Drop for ImportClaim {
    fn drop(&mut self) {
        if !self.started {
            let _ = std::fs::remove_dir_all(&self.dir);
            *self.status.lock().unwrap_or_else(|e| e.into_inner()) = ImportStatus {
                state: "idle",
                ..Default::default()
            };
        }
    }
}

/// Clears the export's busy flag however it ends.
struct Claim(Arc<AtomicBool>);
impl Drop for Claim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Port {
    pub fn new(runner: Arc<dyn Runner>, dir: PathBuf) -> Self {
        Self {
            runner,
            dir,
            exporting: Arc::new(AtomicBool::new(false)),
            import: Arc::new(Mutex::new(ImportStatus {
                state: "idle",
                ..Default::default()
            })),
        }
    }

    fn status(&self) -> std::sync::MutexGuard<'_, ImportStatus> {
        self.import.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// GBrain's export, then the zip down `tx`. `done(completed)` when the zip has ended. One at a time.
    pub async fn export(
        &self,
        tx: tokio::sync::mpsc::Sender<Bytes>,
        base: String,
        done: Box<dyn FnOnce(bool) + Send>,
    ) -> Result<(), PagesError> {
        if self.exporting.swap(true, Ordering::SeqCst) {
            return Err(PagesError::new(
                409,
                "busy",
                "An export is already running. Try again when it has finished.",
            ));
        }
        let claim = Claim(self.exporting.clone());
        let root = self.dir.join("export");
        // What GBrain exported is the whole brain: it does not stay on the disk, however this ends
        // (a failed helper, a browser that left while it ran). The zip task takes the guard over.
        let leftover = RemoveOnDrop(Some(root.clone()));
        let cmd = crate::gbrain::helper(HELPER).arg("export").timeout(EXPORT_TIMEOUT);
        if let Err(e) = run_helper(self.runner.as_ref(), cmd).await {
            tracing::error!("[brain-pages] export: {e}");
            return Err(PagesError::new(
                502,
                "export_failed",
                "GBrain could not export the brain. Try again in a minute.",
            ));
        }
        tokio::task::spawn_blocking(move || {
            let mut sink = Sink::new(tx);
            let completed = match write_zip(&root, &base, &mut sink) {
                Ok(()) => std::io::Write::flush(&mut sink).is_ok(),
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        tracing::error!("[brain-pages] export zip: {e}");
                    }
                    false
                }
            };
            drop(leftover);
            drop(claim);
            done(completed);
        });
        Ok(())
    }

    pub fn import_status(&self) -> Value {
        let s = self.status().clone();
        let mut out = json!({
            "state": s.state,
            "maxBytes": IMPORT_MAX_BYTES,
            "startedAt": s.started_ms,
            "finishedAt": s.finished_ms,
            "result": s.result,
            "error": s.error,
        });
        if s.state == "running" {
            let progress = std::fs::read_to_string(self.dir.join("import/progress")).unwrap_or_default();
            out["progress"] = parse_progress(&progress);
        }
        out
    }

    /// Take the upload and start the import; it runs on after the request. `done(ok, imported)`
    /// when it has ended.
    pub async fn import(
        &self,
        body: hyper::body::Incoming,
        declared: Option<&str>,
        done: Box<dyn FnOnce(bool, Option<u64>) + Send>,
    ) -> Result<Value, PagesError> {
        {
            let mut s = self.status();
            if s.state == "running" {
                return Err(PagesError::new(
                    409,
                    "busy",
                    "An import is already running. Wait for it to finish.",
                ));
            }
            *s = ImportStatus {
                state: "running",
                started_ms: Some(now_ms()),
                ..Default::default()
            };
        }
        let dir = self.dir.join("import");
        let mut claim = ImportClaim {
            status: self.import.clone(),
            dir: dir.clone(),
            started: false,
        };
        spool(body, declared, &dir).await?;
        claim.started = true;
        drop(claim);
        let (runner, status) = (self.runner.clone(), self.import.clone());
        tokio::spawn(async move {
            let cmd = crate::gbrain::helper(HELPER).arg("import").timeout(IMPORT_TIMEOUT);
            let outcome = run_helper(runner.as_ref(), cmd).await;
            let _ = tokio::fs::remove_dir_all(&dir).await;
            let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
            s.finished_ms = Some(now_ms());
            match outcome {
                Ok(out) => {
                    let summary = last_json(&out).unwrap_or(Value::Null);
                    let imported = summary.get("imported").and_then(Value::as_u64);
                    s.state = "done";
                    s.result = Some(json!({
                        "imported": imported,
                        "skipped": summary.get("skipped").and_then(Value::as_u64),
                        "errors": summary.get("errors").and_then(Value::as_u64),
                    }));
                    drop(s);
                    done(true, imported);
                }
                Err(e) => {
                    tracing::error!("[brain-pages] import: {e}");
                    // The reader's refusals are sentences for a person; anything else is not.
                    let message = last_json(&e)
                        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                        .unwrap_or_else(|| {
                            "The import did not finish. Nothing after the last imported page was added.".into()
                        });
                    s.state = "failed";
                    s.error = Some(message);
                    drop(s);
                    done(false, None);
                }
            }
        });
        Ok(self.import_status())
    }
}

/// The progress file: `read {"files":N,"skipped":M}` once the zip is read, then `<done> <total>`.
pub fn parse_progress(raw: &str) -> Value {
    let line = raw.lines().next_back().unwrap_or_default().trim();
    if let Some(read) = line.strip_prefix("read ") {
        let v: Value = serde_json::from_str(read).unwrap_or(Value::Null);
        return json!({
            "step": "importing",
            "done": 0,
            "total": v.get("files").and_then(Value::as_u64),
            "skippedFiles": v.get("skipped").and_then(Value::as_u64),
        });
    }
    let mut parts = line.split(' ').map(|p| p.parse::<u64>().ok());
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(done), Some(total)) => json!({"step": "importing", "done": done, "total": total}),
        _ => json!({"step": "reading"}),
    }
}

/// The last line of `out` that is a JSON object.
fn last_json(out: &str) -> Option<Value> {
    out.lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok().filter(Value::is_object))
}

/// The upload into `dir/upload.zip`, at most `IMPORT_MAX_BYTES`.
async fn spool(mut body: hyper::body::Incoming, declared: Option<&str>, dir: &Path) -> Result<(), PagesError> {
    let too_large = || {
        PagesError::new(
            413,
            "too_large",
            "The zip is over 100 MB. Split it and import the parts one at a time.",
        )
    };
    if declared
        .and_then(|d| d.trim().parse::<u64>().ok())
        .is_some_and(|n| n > IMPORT_MAX_BYTES)
    {
        return Err(too_large());
    }
    let failed = || PagesError::new(400, "upload_failed", "The upload did not finish.");
    let _ = tokio::fs::remove_dir_all(dir).await;
    std::fs::DirBuilder::new()
        .mode(0o750)
        .recursive(true)
        .create(dir)
        .map_err(|e| {
            tracing::error!("[brain-pages] import dir: {e}");
            failed()
        })?;
    let path = dir.join("upload.zip");
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&path)
        .await
        .map_err(|_| failed())?;
    let mut written: u64 = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| failed())?;
        if let Ok(chunk) = frame.into_data() {
            written += chunk.len() as u64;
            if written > IMPORT_MAX_BYTES {
                drop(f);
                let _ = tokio::fs::remove_dir_all(dir).await;
                return Err(too_large());
            }
            f.write_all(&chunk).await.map_err(|_| failed())?;
        }
    }
    f.sync_all().await.map_err(|_| failed())?;
    if written == 0 {
        let _ = tokio::fs::remove_dir_all(dir).await;
        return Err(PagesError::new(400, "empty", "Choose a zip file to import."));
    }
    Ok(())
}

use std::os::unix::fs::DirBuilderExt;

/// Every file under `root` into the zip, under `base/`: GBrain's export is one `<slug>.md` per page.
/// Links are not followed.
pub fn write_zip(root: &Path, base: &str, out: &mut impl std::io::Write) -> std::io::Result<()> {
    use std::io::Read;
    let mut zip = ZipWriter::new(out);
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    let now = now_ms().div_euclid(1000);
    for path in files {
        let Ok(rel) = path.strip_prefix(root) else { continue };
        let Some(rel) = rel.to_str() else { continue };
        let mut e = zip.start(&format!("{base}/{rel}"), now, true)?;
        let mut src = std::fs::File::open(&path)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            e.write(&buf[..n])?;
        }
        e.finish()?;
    }
    zip.finish()?;
    Ok(())
}
