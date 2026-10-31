//! The workspace file explorer's API (`routes/files.ts`), under `/files/*`, behind Caddy's
//! `/__cc/agent/files/...`. The caller is a browser with this box's session cookie, not the
//! console: the bytes of a customer's files never pass through ControlClaw. Reading is for every
//! session, changing the tree only for one that may write (`read_only`).
//!
//! Every path is attacker-controlled twice over (by the session and by the agent, which writes the
//! tree). So a path is resolved with `realpath`, following every symlink the agent may have planted,
//! and refused unless the result is inside the workspace root; names on the deny list are refused
//! too, whatever a symlink says.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use cc_http::{BodyBinding, Req, Resp};
use cc_origin::OriginPolicy;
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tokio::io::AsyncWriteExt;

use super::access::{Access, same_site};
use super::session::SessionClaims;
use super::web::{self, send_json};

/// A text preview stops here; the console says so and offers Download.
pub const TEXT_PREVIEW_BYTES: u64 = 1024 * 1024;
/// An image larger than this is not previewed inline, only downloaded.
pub const IMAGE_PREVIEW_BYTES: u64 = 20 * 1024 * 1024;
/// Hard cap on one upload.
pub const UPLOAD_MAX_BYTES: u64 = 100 * 1024 * 1024;
/// A recursive delete above this many entries is refused rather than run.
pub const RECURSIVE_DELETE_MAX_ENTRIES: usize = 10_000;
/// One listing never returns more than this.
pub const LIST_MAX_ENTRIES: usize = 5_000;

#[derive(Debug, Clone, Copy)]
pub struct FilesLimits {
    pub text_preview_bytes: u64,
    pub image_preview_bytes: u64,
    pub upload_max_bytes: u64,
    pub recursive_delete_max_entries: usize,
    pub list_max_entries: usize,
}

impl Default for FilesLimits {
    fn default() -> Self {
        Self {
            text_preview_bytes: TEXT_PREVIEW_BYTES,
            image_preview_bytes: IMAGE_PREVIEW_BYTES,
            upload_max_bytes: UPLOAD_MAX_BYTES,
            recursive_delete_max_entries: RECURSIVE_DELETE_MAX_ENTRIES,
            list_max_entries: LIST_MAX_ENTRIES,
        }
    }
}

/// One change made through the explorer (`FilesWrite`); `export` is Download workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesWrite {
    pub op: &'static str,
    pub path: String,
    pub size: Option<u64>,
}

/// Refused by name (`DEFAULT_DENIED`): the box's keys, state and agent bundle, and the account's
/// own credentials (`~/.ssh` is what rescue access writes).
fn default_denied() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into());
    [
        "/opt/controlclaw".to_string(),
        "/opt/controlclaw/keys".into(),
        "/opt/controlclaw/keys/openclaw_gateway_token".into(),
        "/opt/controlclaw/state".into(),
        "/opt/controlclaw/agent".into(),
        format!("{home}/.ssh"),
        format!("{home}/.openclaw/credentials"),
    ]
    .into_iter()
    .map(|p| resolve(Path::new(&p)))
    .collect()
}

const EXT_MIME: &[(&str, &str)] = &[
    (".txt", "text/plain"),
    (".md", "text/markdown"),
    (".markdown", "text/markdown"),
    (".json", "application/json"),
    (".jsonl", "application/json"),
    (".ndjson", "application/json"),
    (".yaml", "text/yaml"),
    (".yml", "text/yaml"),
    (".toml", "text/plain"),
    (".ini", "text/plain"),
    (".conf", "text/plain"),
    (".log", "text/plain"),
    (".csv", "text/csv"),
    (".tsv", "text/tab-separated-values"),
    (".xml", "text/xml"),
    (".html", "text/html"),
    (".htm", "text/html"),
    (".css", "text/css"),
    (".js", "text/javascript"),
    (".mjs", "text/javascript"),
    (".cjs", "text/javascript"),
    (".jsx", "text/javascript"),
    (".ts", "text/typescript"),
    (".tsx", "text/typescript"),
    (".py", "text/x-python"),
    (".rb", "text/x-ruby"),
    (".go", "text/x-go"),
    (".rs", "text/x-rust"),
    (".java", "text/x-java"),
    (".c", "text/x-c"),
    (".h", "text/x-c"),
    (".cpp", "text/x-c++"),
    (".sh", "text/x-shellscript"),
    (".bash", "text/x-shellscript"),
    (".zsh", "text/x-shellscript"),
    (".sql", "text/x-sql"),
    (".php", "text/x-php"),
    (".svg", "image/svg+xml"),
    (".png", "image/png"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".gif", "image/gif"),
    (".webp", "image/webp"),
    (".avif", "image/avif"),
    (".bmp", "image/bmp"),
    (".ico", "image/x-icon"),
    (".pdf", "application/pdf"),
    (".zip", "application/zip"),
    (".gz", "application/gzip"),
    (".tgz", "application/gzip"),
    (".tar", "application/x-tar"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".webm", "video/webm"),
    (".wav", "audio/wav"),
];

/// Extensionless files that are plain text in practice.
const TEXT_BASENAMES: &[&str] = &[
    "dockerfile",
    "makefile",
    "procfile",
    "license",
    "readme",
    "changelog",
    "authors",
    "notice",
    ".gitignore",
    ".dockerignore",
    ".npmrc",
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".editorconfig",
];

/// `mimeFor`.
pub fn mime_for(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    // A dotfile with no second dot (".bashrc") has no extension; its whole name is the key.
    let ext = match lower.rfind('.') {
        Some(dot) if dot > 0 => &lower[dot..],
        _ => "",
    };
    if lower == ".env" || lower.starts_with(".env.") {
        return "text/plain";
    }
    if let Some((_, m)) = EXT_MIME.iter().find(|(e, _)| !ext.is_empty() && *e == ext) {
        return m;
    }
    if TEXT_BASENAMES.contains(&lower.as_str()) {
        return "text/plain";
    }
    "application/octet-stream"
}

/// Whether the console can show this as text. SVG is an image but reads better as source.
pub fn is_textual(mime: &str) -> bool {
    mime.starts_with("text/") || mime == "application/json" || mime == "image/svg+xml"
}

pub fn is_previewable_image(mime: &str) -> bool {
    mime.starts_with("image/") && mime != "image/svg+xml"
}

/// `toFixed(1)`: the nearer of the two, the larger on a tie.
fn to_fixed_1(v: f64) -> String {
    let n = (v * 10.0 + 0.5).floor();
    format!("{}.{}", (n / 10.0).trunc() as i64, (n % 10.0) as i64)
}

/// `humanBytes`: decimal units, as the console shows them.
pub fn human_bytes(n: u64) -> String {
    if n < 1000 {
        return format!("{n} B");
    }
    const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];
    let mut v = n as f64 / 1000.0;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    let num = if v < 10.0 {
        to_fixed_1(v)
    } else {
        format!("{}", (v + 0.5).floor() as u64)
    };
    format!("{num} {}", UNITS[i])
}

/// `toLocaleString("en-US")` for a whole number.
fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

fn err(status: u16, code: &'static str, message: impl Into<String>) -> FilesError {
    FilesError {
        status,
        code,
        message: message.into(),
    }
}

/// Anything that is not a `FilesError` (`The file explorer could not read that.`).
fn internal(e: std::io::Error) -> FilesError {
    tracing::error!("[files] {e}");
    err(500, "internal", "The file explorer could not read that.")
}

/// `normalizeRelative`: a root-relative POSIX path with `.`, `..`, empty segments and NUL dropped.
/// The realpath check, not this, is what enforces the boundary.
pub fn normalize_relative(input: Option<&str>) -> String {
    let raw: String = input.unwrap_or_default().chars().filter(|c| *c != '\0').collect();
    let mut parts: Vec<&str> = Vec::new();
    for seg in raw.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// `path.resolve` for an absolute path: `.` and `..` resolved as text.
fn resolve(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    let p = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(n) => out.push(n),
            _ => {}
        }
    }
    out
}

/// True when `candidate` is `root` or sits inside it. Both must already be real paths.
pub fn is_inside(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

/// `realpath` for a path that may not exist yet: the nearest existing ancestor is resolved and the
/// rest joined back on.
pub async fn realpath_lenient(path: &Path) -> PathBuf {
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = resolve(path);
    loop {
        if let Ok(real) = tokio::fs::canonicalize(&cursor).await {
            let mut out = real;
            for m in missing.iter().rev() {
                out.push(m);
            }
            return out;
        }
        let Some(parent) = cursor.parent().map(Path::to_path_buf) else {
            return resolve(path);
        };
        if let Some(name) = cursor.file_name() {
            missing.push(name.to_owned());
        }
        cursor = parent;
    }
}

fn name_of(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

async fn exists(p: &Path) -> bool {
    tokio::fs::symlink_metadata(p).await.is_ok()
}

fn mode_of(mode: u32) -> String {
    format!("{:04o}", mode & 0o777)
}

fn mtime_ms(m: &std::fs::Metadata) -> i64 {
    m.modified().map(web::time_ms).unwrap_or(0)
}

/// What a path was resolved to.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub rel: String,
    pub abs: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub rel: String,
    pub abs: PathBuf,
    pub parent: PathBuf,
}

type OnWrite = Arc<dyn Fn(FilesWrite) + Send + Sync>;
type TemplateReview = Arc<dyn Fn() -> Option<Value> + Send + Sync>;

pub struct FilesService {
    root: PathBuf,
    /// The root's realpath, resolved once: /home may itself be a symlink.
    root_real: tokio::sync::OnceCell<PathBuf>,
    vm_id: Option<String>,
    denied: Vec<PathBuf>,
    denied_real: tokio::sync::OnceCell<Vec<PathBuf>>,
    pub limits: FilesLimits,
    on_write: Option<OnWrite>,
    template_review: Option<TemplateReview>,
    /// Download workspace (B3); without it the export routes answer 503.
    pub exporter: Mutex<Option<Arc<dyn super::Exporter>>>,
}

impl FilesService {
    pub fn new(root: PathBuf, vm_id: Option<String>) -> Self {
        Self {
            root,
            root_real: tokio::sync::OnceCell::new(),
            vm_id,
            denied: default_denied(),
            denied_real: tokio::sync::OnceCell::new(),
            limits: FilesLimits::default(),
            on_write: None,
            template_review: None,
            exporter: Mutex::new(None),
        }
    }

    /// Another deny list (tests point it inside the root).
    #[cfg(test)]
    pub fn with_denied(mut self, denied: Vec<PathBuf>) -> Self {
        self.denied = denied.iter().map(|p| resolve(p)).collect();
        self
    }

    #[cfg(test)]
    pub fn with_limits(mut self, limits: FilesLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn on_write(mut self, f: OnWrite) -> Self {
        self.on_write = Some(f);
        self
    }

    pub fn template_review(mut self, f: TemplateReview) -> Self {
        self.template_review = Some(f);
        self
    }

    pub fn vm_id(&self) -> Option<&str> {
        self.vm_id.as_deref()
    }

    async fn root(&self) -> Result<&PathBuf, FilesError> {
        self.root_real
            .get_or_try_init(|| async { tokio::fs::canonicalize(&self.root).await })
            .await
            .map_err(internal)
    }

    async fn denied_list(&self) -> &Vec<PathBuf> {
        self.denied_real
            .get_or_init(|| async {
                let mut out = Vec::new();
                for d in &self.denied {
                    out.push(realpath_lenient(d).await);
                }
                out
            })
            .await
    }

    async fn assert_allowed(&self, real: &Path) -> Result<(), FilesError> {
        for d in self.denied_list().await {
            if is_inside(d, real) {
                return Err(err(
                    403,
                    "denied",
                    "That path is part of the box's own credentials and is not browsable.",
                ));
            }
        }
        Ok(())
    }

    /// `resolveExisting`: a path that must already exist, every symlink followed.
    pub async fn resolve_existing(&self, rel: &str) -> Result<Resolved, FilesError> {
        let root = self.root().await?.clone();
        let normalized = normalize_relative(Some(rel));
        let target = if normalized.is_empty() {
            root.clone()
        } else {
            root.join(&normalized)
        };
        let real = tokio::fs::canonicalize(&target)
            .await
            .map_err(|_| err(404, "not_found", "No such file or folder."))?;
        if !is_inside(&root, &real) {
            return Err(err(403, "outside_root", "That path leaves the agent's workspace."));
        }
        self.assert_allowed(&real).await?;
        Ok(Resolved {
            rel: normalized,
            abs: real,
        })
    }

    /// `resolveEntry`: the parent resolved strictly, the name appended, so the entry itself (a
    /// symlink, say) stays the entry.
    pub async fn resolve_entry(&self, rel: &str) -> Result<Entry, FilesError> {
        let normalized = normalize_relative(Some(rel));
        if normalized.is_empty() {
            let root = self.root().await?.clone();
            return Ok(Entry {
                rel: String::new(),
                abs: root.clone(),
                parent: root,
            });
        }
        let (parent_rel, name) = match normalized.rsplit_once('/') {
            Some((p, n)) => (p.to_string(), n.to_string()),
            None => (String::new(), normalized.clone()),
        };
        if name.is_empty() || name == "." || name == ".." {
            return Err(err(400, "bad_path", "That name is not allowed."));
        }
        let parent = self.resolve_existing(&parent_rel).await?;
        let is_dir = tokio::fs::metadata(&parent.abs).await.is_ok_and(|m| m.is_dir());
        if !is_dir {
            return Err(err(400, "not_a_directory", "The destination is not a folder."));
        }
        let abs = parent.abs.join(&name);
        self.assert_allowed(&abs).await?;
        Ok(Entry {
            rel: normalized,
            abs,
            parent: parent.abs,
        })
    }

    async fn resolve_for_create(&self, rel: &str) -> Result<Entry, FilesError> {
        let entry = self.resolve_entry(rel).await?;
        if entry.rel.is_empty() {
            return Err(err(400, "bad_path", "A name is required."));
        }
        Ok(entry)
    }

    pub async fn list(&self, rel: &str) -> Result<Value, FilesError> {
        let root = self.root().await?.clone();
        let Resolved { rel: rel_path, abs } = self.resolve_existing(rel).await?;
        let st = tokio::fs::metadata(&abs).await.map_err(internal)?;
        if !st.is_dir() {
            return Err(err(400, "not_a_directory", "That is a file, not a folder."));
        }
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(&abs).await.map_err(internal)?;
        while let Some(e) = rd.next_entry().await.map_err(internal)? {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        // Node's `readdir` (libuv's scandir) is in byte order: the truncation and the sort's ties
        // follow it.
        names.sort();
        let truncated = names.len() > self.limits.list_max_entries;
        let mut entries: Vec<(bool, String, Value)> = Vec::new();
        for name in names.into_iter().take(self.limits.list_max_entries) {
            if let Some(e) = describe(&root, &abs.join(&name), &name).await {
                let is_dir = e["kind"] == "dir";
                entries.push((is_dir, name, e));
            }
        }
        // Folders first, then `localeCompare("en", {numeric, sensitivity: "base"})`; stable.
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| locale_compare(&a.1, &b.1)));
        Ok(json!({
            "path": rel_path,
            "entries": entries.into_iter().map(|e| e.2).collect::<Vec<_>>(),
            "truncated": truncated,
        }))
    }

    /// The file a read or download is about.
    pub async fn file_for(&self, rel: &str) -> Result<(Resolved, u64, i64, &'static str), FilesError> {
        let r = self.resolve_existing(rel).await?;
        let st = tokio::fs::metadata(&r.abs).await.map_err(internal)?;
        if st.is_dir() {
            return Err(err(400, "is_a_directory", "That is a folder, not a file."));
        }
        if !st.is_file() {
            return Err(err(400, "not_a_file", "That is not a regular file."));
        }
        let mime = mime_for(&name_of(&r.abs));
        Ok((r, st.len(), mtime_ms(&st), mime))
    }

    pub async fn mkdir(&self, rel: &str) -> Result<Value, FilesError> {
        let target = self.resolve_for_create(rel).await?;
        if let Err(e) = tokio::fs::create_dir(&target.abs).await {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(err(409, "exists", "Something with that name is already there."));
            }
            return Err(err(500, "mkdir_failed", "Could not create the folder."));
        }
        self.announce(FilesWrite {
            op: "mkdir",
            path: target.rel.clone(),
            size: None,
        });
        Ok(json!({"path": target.rel}))
    }

    pub async fn rename(&self, from_rel: &str, to_rel: &str) -> Result<Value, FilesError> {
        let from = self.resolve_entry(from_rel).await?;
        if from.rel.is_empty() {
            return Err(err(400, "bad_path", "The workspace root cannot be renamed."));
        }
        if !exists(&from.abs).await {
            return Err(err(404, "not_found", "No such file or folder."));
        }
        let to = self.resolve_for_create(to_rel).await?;
        if exists(&to.abs).await {
            return Err(err(409, "exists", "Something with that name is already there."));
        }
        if is_inside(&from.abs, &to.abs) {
            return Err(err(400, "bad_path", "A folder cannot be moved into itself."));
        }
        if tokio::fs::rename(&from.abs, &to.abs).await.is_err() {
            return Err(err(500, "rename_failed", "Could not rename that."));
        }
        self.announce(FilesWrite {
            op: "rename",
            path: format!("{} → {}", from.rel, to.rel),
            size: None,
        });
        Ok(json!({"from": from.rel, "to": to.rel}))
    }

    pub async fn delete(&self, rel: &str, recursive: bool) -> Result<Value, FilesError> {
        let Entry { rel: rel_path, abs, .. } = self.resolve_entry(rel).await?;
        if rel_path.is_empty() {
            return Err(err(400, "bad_path", "The workspace root cannot be deleted."));
        }
        let st = tokio::fs::symlink_metadata(&abs)
            .await
            .map_err(|_| err(404, "not_found", "No such file or folder."))?;
        // A symlink is unlinked, never followed.
        if st.file_type().is_symlink() || !st.is_dir() {
            if tokio::fs::remove_file(&abs).await.is_err() {
                return Err(err(500, "delete_failed", "Could not delete that."));
            }
            let size = (!st.file_type().is_symlink()).then_some(st.len());
            self.announce(FilesWrite {
                op: "delete",
                path: rel_path.clone(),
                size,
            });
            return Ok(json!({"path": rel_path, "entries": 1}));
        }
        let mut rd = tokio::fs::read_dir(&abs).await.map_err(internal)?;
        let any = rd.next_entry().await.map_err(internal)?.is_some();
        if any && !recursive {
            return Err(err(
                409,
                "not_empty",
                "That folder is not empty. Delete it with its contents to remove it.",
            ));
        }
        let max = self.limits.recursive_delete_max_entries;
        let Some(entries) = count_entries(&abs, max).await else {
            return Err(err(
                413,
                "too_many_entries",
                format!(
                    "That folder holds more than {} items. Delete it from the agent's terminal instead.",
                    thousands(max)
                ),
            ));
        };
        // `rm(abs, {recursive: true, force: true})`: what is already gone is no error.
        if let Err(e) = tokio::fs::remove_dir_all(&abs).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(internal(e));
        }
        self.announce(FilesWrite {
            op: "delete",
            path: rel_path.clone(),
            size: None,
        });
        Ok(json!({"path": rel_path, "entries": entries}))
    }

    /// The request body into a temp file next to the target, then renamed into place: a connection
    /// that dies halfway leaves the old file untouched.
    pub async fn upload(
        &self,
        body: hyper::body::Incoming,
        declared: Option<&str>,
        rel: &str,
        overwrite: bool,
    ) -> Result<Value, FilesError> {
        let target = self.resolve_for_create(rel).await?;
        if !overwrite && exists(&target.abs).await {
            return Err(err(409, "exists", "A file with that name is already there."));
        }
        let (tmp, written) = spool(body, declared, &target.parent, self.limits.upload_max_bytes, "upload").await?;
        // Re-checked after the body arrived: the file may have appeared while it was streaming.
        if !overwrite && exists(&target.abs).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err(409, "exists", "A file with that name is already there."));
        }
        commit(&tmp, &target.abs, "upload_failed").await?;
        self.announce(FilesWrite {
            op: "upload",
            path: target.rel.clone(),
            size: Some(written),
        });
        Ok(json!({"path": target.rel, "size": written}))
    }

    /// An edit made in the console, written back: capped at the preview's size, optimistic on the
    /// file's mtime (`expect_mtime` none is Overwrite), `create` is New file.
    pub async fn write(
        &self,
        body: hyper::body::Incoming,
        declared: Option<&str>,
        rel: &str,
        expect_mtime: Option<&str>,
        create: bool,
    ) -> Result<Value, FilesError> {
        let target = self.resolve_for_create(rel).await?;
        if create && exists(&target.abs).await {
            return Err(err(409, "exists", "Something with that name is already there."));
        }
        if !create {
            assert_writable_file(&target.abs, expect_mtime).await?;
        }
        let (tmp, written) = spool(body, declared, &target.parent, self.limits.text_preview_bytes, "write").await?;
        let recheck = async {
            if create && exists(&target.abs).await {
                return Err(err(409, "exists", "Something with that name is already there."));
            }
            if !create {
                assert_writable_file(&target.abs, expect_mtime).await?;
            }
            Ok(())
        };
        if let Err(e) = recheck.await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        // Keep the mode the file had; a new one gets the usual 0644.
        use std::os::unix::fs::PermissionsExt;
        let mode = match tokio::fs::metadata(&target.abs).await {
            Ok(m) => m.permissions().mode() & 0o777,
            Err(_) => 0o644,
        };
        let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).await;
        commit(&tmp, &target.abs, "write_failed").await?;
        let mtime = match tokio::fs::metadata(&target.abs).await {
            Ok(m) => mtime_ms(&m),
            Err(_) => web::time_ms(std::time::SystemTime::now()),
        };
        self.announce(FilesWrite {
            op: "write",
            path: target.rel.clone(),
            size: Some(written),
        });
        Ok(json!({"path": target.rel, "size": written, "mtime": web::iso(mtime)}))
    }

    pub fn announce(&self, write: FilesWrite) {
        if let Some(f) = &self.on_write {
            f(write);
        }
    }

    pub fn review(&self) -> Option<Value> {
        self.template_review.as_ref().and_then(|f| f())
    }
}

async fn assert_writable_file(abs: &Path, expect: Option<&str>) -> Result<(), FilesError> {
    let st = tokio::fs::symlink_metadata(abs).await.ok();
    if let Some(st) = &st
        && !st.is_file()
    {
        return Err(err(400, "not_a_file", "Only a plain file can be edited here."));
    }
    let Some(expect) = expect else { return Ok(()) };
    let Some(st) = st else {
        return Err(err(404, "not_found", "That file is no longer on the box."));
    };
    if web::iso(mtime_ms(&st)) != expect {
        return Err(err(
            409,
            "changed",
            "The agent changed this file while you were editing it.",
        ));
    }
    Ok(())
}

fn too_large(op: &str, max: u64) -> FilesError {
    if op == "write" {
        err(
            413,
            "too_large",
            format!(
                "The editor saves files up to {}. Download this one, change it, and upload it back.",
                human_bytes(max)
            ),
        )
    } else {
        err(413, "too_large", format!("Files are limited to {}.", human_bytes(max)))
    }
}

/// `Number(header ?? "")`: an empty header is 0, anything not a number is NaN (`None`).
fn js_number(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    t.parse::<f64>().ok().filter(|f| f.is_finite())
}

async fn spool(
    mut body: hyper::body::Incoming,
    declared: Option<&str>,
    parent: &Path,
    max: u64,
    op: &'static str,
) -> Result<(PathBuf, u64), FilesError> {
    if let Some(n) = js_number(declared.unwrap_or_default())
        && n > max as f64
    {
        return Err(too_large(op, max));
    }
    let tmp = parent.join(format!(".cc-{op}-{}.part", uuid::Uuid::new_v4()));
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .await
        .map_err(internal)?;
    let mut written: u64 = 0;
    let failed = |too_big: bool| {
        if too_big {
            too_large(op, max)
        } else if op == "write" {
            err(400, "write_failed", "The edit did not reach the box.")
        } else {
            err(400, "upload_failed", "The upload did not finish.")
        }
    };
    let outcome: Result<(), bool> = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| {
                tracing::error!("[files] {op} failed: {e}");
                false
            })?;
            if let Ok(chunk) = frame.into_data() {
                written += chunk.len() as u64;
                if written > max {
                    return Err(true);
                }
                f.write_all(&chunk).await.map_err(|e| {
                    tracing::error!("[files] {op} failed: {e}");
                    false
                })?;
            }
        }
        f.sync_all().await.map_err(|_| false)
    }
    .await;
    drop(f);
    if let Err(too_big) = outcome {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(failed(too_big));
    }
    Ok((tmp, written))
}

async fn commit(tmp: &Path, abs: &Path, code: &'static str) -> Result<(), FilesError> {
    if tokio::fs::rename(tmp, abs).await.is_err() {
        let _ = tokio::fs::remove_file(tmp).await;
        return Err(err(500, code, "Could not save the file."));
    }
    Ok(())
}

/// Everything under a folder, giving up at `max` (`None`). Symlinks are counted, never followed.
async fn count_entries(dir: &Path, max: usize) -> Option<usize> {
    let mut count = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(mut rd) = tokio::fs::read_dir(&current).await else {
            continue;
        };
        while let Ok(Some(e)) = rd.next_entry().await {
            count += 1;
            if count > max {
                return None;
            }
            let child = e.path();
            if tokio::fs::symlink_metadata(&child).await.is_ok_and(|m| m.is_dir()) {
                stack.push(child);
            }
        }
    }
    Some(count)
}

/// One directory entry. A symlink is described by its target, and flagged when it leaves the root.
async fn describe(root: &Path, abs: &Path, name: &str) -> Option<Value> {
    use std::os::unix::fs::PermissionsExt;
    let link = tokio::fs::symlink_metadata(abs).await.ok()?;
    let kind = |m: &std::fs::Metadata| {
        if m.is_dir() {
            "dir"
        } else if m.is_file() {
            "file"
        } else {
            "other"
        }
    };
    if !link.file_type().is_symlink() {
        return Some(json!({
            "name": name,
            "kind": kind(&link),
            "size": link.len(),
            "mtime": web::iso(mtime_ms(&link)),
            "mode": mode_of(link.permissions().mode()),
        }));
    }
    let inside = tokio::fs::canonicalize(abs)
        .await
        .ok()
        .is_some_and(|real| is_inside(root, &real));
    let target = if inside {
        tokio::fs::metadata(abs).await.ok()
    } else {
        None
    };
    let mut m = Map::new();
    m.insert("name".into(), json!(name));
    m.insert("kind".into(), json!(target.as_ref().map(kind).unwrap_or("other")));
    m.insert("size".into(), json!(target.as_ref().map(|t| t.len()).unwrap_or(0)));
    m.insert(
        "mtime".into(),
        json!(web::iso(mtime_ms(target.as_ref().unwrap_or(&link)))),
    );
    m.insert("mode".into(), json!(mode_of(link.permissions().mode())));
    m.insert("symlink".into(), json!(true));
    if !inside {
        m.insert("blocked".into(), json!(true));
    }
    Some(Value::Object(m))
}

/// ICU's root order for ASCII punctuation and symbols, which all sort before digits and letters.
const PUNCT_ORDER: &str = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";

/// A primary weight for one character, case and (common Latin) accents ignored.
fn weight(c: char) -> (u8, u32) {
    if c.is_whitespace() {
        return (0, c as u32);
    }
    if let Some(i) = PUNCT_ORDER.find(c) {
        return (1, i as u32);
    }
    if c.is_ascii_digit() {
        return (2, c as u32);
    }
    let folded = fold(c);
    if folded.is_alphabetic() {
        return (3, folded as u32);
    }
    (4, c as u32)
}

fn fold(c: char) -> char {
    let l = c.to_lowercase().next().unwrap_or(c);
    match l {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
        'ç' => 'c',
        'è' | 'é' | 'ê' | 'ë' => 'e',
        'ì' | 'í' | 'î' | 'ï' => 'i',
        'ñ' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
        'ù' | 'ú' | 'û' | 'ü' => 'u',
        'ý' | 'ÿ' => 'y',
        other => other,
    }
}

/// `a.localeCompare(b, "en", {numeric: true, sensitivity: "base"})`, closely enough for file names:
/// runs of digits compare by value, case and accents do not count, punctuation sorts first.
pub fn locale_compare(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let si = i;
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            let sj = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let x: String = a[si..i].iter().collect::<String>().trim_start_matches('0').to_string();
            let y: String = b[sj..j].iter().collect::<String>().trim_start_matches('0').to_string();
            let o = x.len().cmp(&y.len()).then_with(|| x.cmp(&y));
            if o != Ordering::Equal {
                return o;
            }
            continue;
        }
        let o = weight(a[i]).cmp(&weight(b[j]));
        if o != Ordering::Equal {
            return o;
        }
        i += 1;
        j += 1;
    }
    (a.len() - i.min(a.len())).cmp(&(b.len() - j.min(b.len())))
}

/// `contentDisposition`: an ASCII name (each other UTF-16 unit, `"` and `\` an underscore) and
/// the real one in `filename*`.
pub fn content_disposition(name: &str) -> String {
    let mut ascii = String::new();
    for c in name.chars() {
        if (' '..='~').contains(&c) {
            ascii.push(if c == '"' || c == '\\' { '_' } else { c });
        } else {
            for _ in 0..c.len_utf16() {
                ascii.push('_');
            }
        }
    }
    format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        super::shell::encode_uri_component(name)
    )
}

const WRITE_OPS: &[&str] = &[
    "/files/upload",
    "/files/write",
    "/files/mkdir",
    "/files/rename",
    "/files/delete",
];
const JSON_OPS: &[&str] = &["/files/mkdir", "/files/rename", "/files/delete"];

/// The origins that may call with this box's cookie: the box, and the console only while it is
/// the same site as the box (`FilesService.origins`).
fn origins(access: &Access) -> Vec<String> {
    let (box_origin, console) = access.allowed_origins();
    let console_if_same = same_site(box_origin.as_deref(), console.as_deref())
        .then_some(console)
        .flatten();
    [box_origin, console_if_same]
        .into_iter()
        .flatten()
        .filter(|o| !o.is_empty())
        .collect()
}

/// `corsHeaders`: always `Vary: Origin`; the Origin echoed with credentials when it is allowed.
fn cors(parts: &http::request::Parts, origins: &[String]) -> Vec<(&'static str, String)> {
    let origin = cc_origin::node_header(&parts.headers, "origin");
    match origin {
        Some(o) if !o.is_empty() && origins.contains(&o) => vec![
            ("vary", "Origin".into()),
            ("access-control-allow-origin", o),
            ("access-control-allow-credentials", "true".into()),
        ],
        _ => vec![("vary", "Origin".into())],
    }
}

fn error_resp(e: &FilesError, cors: &[(&str, String)]) -> Resp {
    send_json(e.status, &json!({"error": e.message, "code": e.code}), cors)
}

/// `handleFiles`.
pub async fn handle(service: &FilesService, access: &Access, req: Req) -> Resp {
    let (parts, body) = req.into_parts();
    let origins = origins(access);
    let cors = cors(&parts, &origins);
    if parts.method == http::Method::OPTIONS {
        let mut h = cors.clone();
        h.push(("access-control-allow-methods", "GET, POST, OPTIONS".into()));
        h.push(("access-control-allow-headers", "Content-Type".into()));
        h.push(("access-control-max-age", "600".into()));
        return web::empty_body(204, &h);
    }
    let policy = OriginPolicy {
        allowed: origins.iter().cloned().map(Some).collect(),
        allow_top_level_navigation: true,
        uncredentialed: cc_origin::Uncredentialed::Allow,
    };
    let facts = cc_origin::agent_request_facts(parts.method.as_str(), &parts.headers, None);
    if let cc_origin::OriginVerdict::Denied { reason, origin } = cc_origin::check_origin(&facts, &policy) {
        tracing::warn!("[files] {}", cc_origin::denial_message(reason, origin.as_deref()));
        return send_json(
            403,
            &json!({"error": "This request did not come from your console.", "code": "bad_origin"}),
            &cors,
        );
    }
    let cookie = cc_origin::node_header(&parts.headers, "cookie");
    let session = service
        .vm_id()
        .and_then(|vm| access.sessions.read_session(cookie.as_deref(), vm));
    let Some(session) = session else {
        return send_json(
            401,
            &json!({"error": "This browser is not signed in to the agent.", "code": "unpaired"}),
            &cors,
        );
    };
    match dispatch(service, &parts, body, &session, &cors).await {
        Ok(r) => r,
        Err(e) => error_resp(&e, &cors),
    }
}

use super::web::query;

async fn dispatch(
    service: &FilesService,
    parts: &http::request::Parts,
    body: hyper::body::Incoming,
    session: &SessionClaims,
    cors: &[(&str, String)],
) -> Result<Resp, FilesError> {
    let path = cc_http::pathname(&parts.uri.to_string());
    let q = query(parts, "path").unwrap_or_default();
    let get = parts.method == http::Method::GET;
    let post = parts.method == http::Method::POST;
    if WRITE_OPS.contains(&path.as_str()) && !session.can_write {
        return Ok(send_json(
            403,
            &json!({"error": "Your pass for this agent can read its files but not change them.", "code": "read_only"}),
            cors,
        ));
    }
    match path.as_str() {
        "/files/template-review" if get => Ok(send_json(
            200,
            &service
                .review()
                .unwrap_or_else(|| json!({"template": null, "files": []})),
            cors,
        )),
        "/files/list" if get => Ok(send_json(200, &service.list(&q).await?, cors)),
        "/files/read" if get => read(service, &q, cors).await,
        "/files/download" if get => {
            let (file, size, _, _) = service.file_for(&q).await?;
            let f = tokio::fs::File::open(&file.abs).await.map_err(internal)?;
            let mut h = cors.to_vec();
            h.push(("content-type", "application/octet-stream".into()));
            h.push(("content-length", size.to_string()));
            h.push(("content-disposition", content_disposition(&name_of(&file.abs))));
            h.push(("cache-control", "no-store".into()));
            h.push(("x-content-type-options", "nosniff".into()));
            Ok(web::file_body(f, 200, &h))
        }
        "/files/export" | "/files/export/plan" if get => export(service, &path, cors).await,
        "/files/upload" if post => {
            let overwrite = query(parts, "overwrite").as_deref() == Some("1");
            let declared = cc_http::header(parts, "content-length");
            Ok(send_json(
                200,
                &service.upload(body, declared, &q, overwrite).await?,
                cors,
            ))
        }
        "/files/write" if post => {
            let expect = query(parts, "mtime");
            let create = query(parts, "create").as_deref() == Some("1");
            let declared = cc_http::header(parts, "content-length");
            Ok(send_json(
                200,
                &service.write(body, declared, &q, expect.as_deref(), create).await?,
                cors,
            ))
        }
        p if JSON_OPS.contains(&p) && post => {
            let Some(b) = cc_http::read_json_body(body, 8192, &BodyBinding::not_firewall()).await else {
                return Err(err(400, "bad_body", "That request was not understood."));
            };
            let s = |k: &str| b.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
            let out = match p {
                "/files/mkdir" => service.mkdir(&s("path")).await?,
                "/files/rename" => service.rename(&s("from"), &s("to")).await?,
                _ => {
                    let recursive = matches!(b.get("recursive"), Some(Value::Bool(true)))
                        || b.get("recursive").and_then(Value::as_f64) == Some(1.0);
                    service.delete(&s("path"), recursive).await?
                }
            };
            Ok(send_json(200, &out, cors))
        }
        _ => Ok(send_json(
            404,
            &json!({"error": "Not found", "code": "not_found"}),
            cors,
        )),
    }
}

async fn read(service: &FilesService, q: &str, cors: &[(&str, String)]) -> Result<Resp, FilesError> {
    let (file, size, mtime, mime) = service.file_for(q).await?;
    let mut meta = Map::new();
    meta.insert("path".into(), json!(file.rel));
    meta.insert("name".into(), json!(name_of(&file.abs)));
    meta.insert("mime".into(), json!(mime));
    meta.insert("size".into(), json!(size));
    meta.insert("mtime".into(), json!(web::iso(mtime)));
    if is_previewable_image(mime) {
        if size > service.limits.image_preview_bytes {
            meta.insert("kind".into(), json!("binary"));
            meta.insert("reason".into(), json!("too_large"));
            return Ok(send_json(200, &Value::Object(meta), cors));
        }
        let f = tokio::fs::File::open(&file.abs).await.map_err(internal)?;
        let mut h = cors.to_vec();
        h.push(("content-type", mime.into()));
        h.push(("content-length", size.to_string()));
        h.push(("last-modified", web::utc_string(mtime)));
        h.push(("access-control-expose-headers", "Last-Modified".into()));
        h.push(("cache-control", "no-store".into()));
        h.push(("x-content-type-options", "nosniff".into()));
        h.push(("content-security-policy", "default-src 'none'; sandbox".into()));
        return Ok(web::file_body(f, 200, &h));
    }
    if !is_textual(mime) {
        meta.insert("kind".into(), json!("binary"));
        return Ok(send_json(200, &Value::Object(meta), cors));
    }
    let max = size.min(service.limits.text_preview_bytes);
    let content = read_head(&file.abs, max).await.map_err(internal)?;
    meta.insert("kind".into(), json!("text"));
    meta.insert("truncated".into(), json!(size > service.limits.text_preview_bytes));
    meta.insert("content".into(), json!(content));
    Ok(send_json(200, &Value::Object(meta), cors))
}

/// First `max` bytes as UTF-8; a character cut in half becomes U+FFFD.
async fn read_head(path: &Path, max: u64) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt;
    if max == 0 {
        return Ok(String::new());
    }
    let f = tokio::fs::File::open(path).await?;
    let mut buf = Vec::with_capacity(max as usize);
    f.take(max).read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Download workspace (`exportWorkspace`): the plan, or the zip streamed.
async fn export(service: &FilesService, path: &str, cors: &[(&str, String)]) -> Result<Resp, FilesError> {
    let exporter = service.exporter.lock().ok().and_then(|e| e.clone());
    let Some(exporter) = exporter else {
        return Err(err(
            503,
            "unavailable",
            "This agent cannot make a workspace download yet.",
        ));
    };
    if path == "/files/export/plan" {
        let mut plan = exporter.plan().await;
        if let Value::Object(m) = &mut plan {
            m.insert("busy".into(), json!(exporter.busy()));
        }
        return Ok(send_json(200, &plan, cors));
    }
    if exporter.busy() {
        return Err(err(
            409,
            "busy",
            "A workspace download is already running on this agent. Try again when it has finished.",
        ));
    }
    let name = format!("{}.zip", exporter.base_name());
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let mut h = cors.to_vec();
    h.push(("content-type", "application/zip".into()));
    h.push(("content-disposition", content_disposition(&name)));
    h.push(("cache-control", "no-store".into()));
    h.push(("x-content-type-options", "nosniff".into()));
    let announce = service.on_write.clone();
    let started = std::time::Instant::now();
    let claimed = exporter.stream(
        tx,
        Box::new(move |completed, bytes| {
            if completed {
                if let Some(f) = &announce {
                    f(FilesWrite {
                        op: "export",
                        path: name.clone(),
                        size: Some(bytes),
                    });
                }
            } else {
                tracing::info!(
                    "[files] workspace download stopped by the browser after {} s",
                    started.elapsed().as_secs_f64().round()
                );
            }
        }),
    );
    if !claimed {
        // Another download took the slot after the check above.
        return Err(err(
            409,
            "busy",
            "A workspace download is already running on this agent. Try again when it has finished.",
        ));
    }
    Ok(web::streamed(200, rx, &h))
}

#[cfg(test)]
mod tests;
