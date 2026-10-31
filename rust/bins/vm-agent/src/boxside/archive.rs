//! The backup format around the envelope (`packages/backup-envelope`: `tar.ts`, `manifest.ts`,
//! `paths.ts`): a minimal ustar/GNU tar writer and reader with the path checks a restore needs, the
//! manifest and its hash, and what an archive holds and leaves out. The envelope itself is
//! `cc_crypto::envelope`. Kept here until W0 moves it next to the envelope (the firewall reads the
//! same format).

use serde_json::{Map, Value, json};

const BLOCK: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarType {
    File,
    Dir,
    Link,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    pub path: String,
    pub kind: TarType,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub target: Option<String>,
}

fn octal(value: u64, width: usize) -> String {
    format!("{value:0w$o}\0", w = width - 1)
}

fn write_str(h: &mut [u8], at: usize, s: &str, width: usize) -> Result<(), String> {
    let b = s.as_bytes();
    if b.len() > width {
        return Err(format!("tar field does not fit: {s}"));
    }
    h[at..at + b.len()].copy_from_slice(b);
    Ok(())
}

fn typeflag(t: TarType) -> &'static str {
    match t {
        TarType::File => "0",
        TarType::Dir => "5",
        TarType::Link => "2",
    }
}

fn header_block(e: &TarEntry, flag: &str, name: &str) -> Result<Vec<u8>, String> {
    let mut h = vec![0u8; BLOCK];
    write_str(&mut h, 0, name, 100)?;
    write_str(&mut h, 100, &octal(u64::from(e.mode & 0o7777), 8), 8)?;
    write_str(&mut h, 108, &octal(0, 8), 8)?;
    write_str(&mut h, 116, &octal(0, 8), 8)?;
    write_str(
        &mut h,
        124,
        &octal(if e.kind == TarType::File { e.size } else { 0 }, 12),
        12,
    )?;
    write_str(&mut h, 136, &octal(e.mtime, 12), 12)?;
    h[148..156].fill(0x20);
    write_str(&mut h, 156, flag, 1)?;
    if let Some(t) = e.target.as_deref().filter(|t| !t.is_empty()) {
        write_str(&mut h, 157, t, 100)?;
    }
    write_str(&mut h, 257, "ustar", 6)?;
    write_str(&mut h, 263, "00", 2)?;
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    write_str(&mut h, 148, &format!("{sum:06o}\0 "), 8)?;
    Ok(h)
}

fn padding_len(size: u64) -> usize {
    let rest = (size % BLOCK as u64) as usize;
    if rest == 0 { 0 } else { BLOCK - rest }
}

fn long_link(value: &str, flag: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    let e = TarEntry {
        path: "././@LongLink".into(),
        kind: TarType::File,
        size: bytes.len() as u64 + 1,
        mode: 0o644,
        mtime: 0,
        target: None,
    };
    let mut out = header_block(&e, flag, "././@LongLink")?;
    out.extend_from_slice(bytes);
    out.push(0);
    out.extend(std::iter::repeat_n(0u8, padding_len(bytes.len() as u64 + 1)));
    Ok(out)
}

/// `tarHeader`: the header blocks for one entry, with a GNU long-link pair in front for a name or
/// a link target over 100 bytes.
pub fn tar_header(e: &TarEntry) -> Result<Vec<u8>, String> {
    let name_long = e.path.len() > 100;
    let target = e.target.clone().unwrap_or_default();
    let target_long = target.len() > 100;
    let mut out = Vec::new();
    if target_long {
        out.extend(long_link(&target, "K")?);
    }
    if name_long {
        out.extend(long_link(&e.path, "L")?);
    }
    let name = if name_long {
        "././@LongLink".to_string()
    } else {
        e.path.clone()
    };
    let real = TarEntry {
        path: name.clone(),
        target: if target_long { None } else { e.target.clone() },
        ..e.clone()
    };
    out.extend(header_block(&real, typeflag(e.kind), &name)?);
    Ok(out)
}

pub fn tar_padding(size: u64) -> Vec<u8> {
    vec![0u8; padding_len(size)]
}

pub fn tar_end() -> Vec<u8> {
    vec![0u8; 2 * BLOCK]
}

fn read_str(buf: &[u8], at: usize, width: usize) -> String {
    let slice = &buf[at..at + width];
    let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn read_octal(buf: &[u8], at: usize, width: usize) -> Result<u64, String> {
    let s = read_str(buf, at, width);
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    // `parseInt(s, 8)`: the leading octal digits.
    let digits: String = s.chars().take_while(|c| ('0'..='7').contains(c)).collect();
    u64::from_str_radix(&digits, 8).map_err(|_| "this archive has a malformed tar header".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadEntry {
    pub entry: TarEntry,
    pub body: Vec<u8>,
}

/// `TarReader`: feed chunks in, get whole entries out; anything a backup never holds is refused.
#[derive(Default)]
pub struct TarReader {
    buffer: Vec<u8>,
    long_name: Option<String>,
    long_target: Option<String>,
    zero_blocks: u32,
    ended: bool,
}

impl TarReader {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<ReadEntry>, String> {
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.ended || self.buffer.len() < BLOCK {
                return Ok(out);
            }
            if self.buffer[..BLOCK].iter().all(|b| *b == 0) {
                self.buffer.drain(..BLOCK);
                self.zero_blocks += 1;
                if self.zero_blocks >= 2 {
                    self.ended = true;
                }
                continue;
            }
            self.zero_blocks = 0;
            let head = self.buffer[..BLOCK].to_vec();
            if read_str(&head, 257, 6) != "ustar" {
                return Err("this archive is not a tar file we wrote".into());
            }
            let size = read_octal(&head, 124, 12)?;
            let body_blocks = size.div_ceil(BLOCK as u64) as usize * BLOCK;
            if self.buffer.len() < BLOCK + body_blocks {
                return Ok(out);
            }
            let body = self.buffer[BLOCK..BLOCK + size as usize].to_vec();
            let flag = read_str(&head, 156, 1);
            let path = self.long_name.clone().unwrap_or_else(|| read_str(&head, 0, 100));
            self.buffer.drain(..BLOCK + body_blocks);
            if flag == "L" || flag == "K" {
                let value = String::from_utf8_lossy(&body).trim_end_matches('\0').to_string();
                if flag == "L" {
                    self.long_name = Some(value);
                } else {
                    self.long_target = Some(value);
                }
                continue;
            }
            let long_target = self.long_target.take();
            self.long_name = None;
            let kind = match flag.as_str() {
                "0" | "" => TarType::File,
                "5" => TarType::Dir,
                "2" => TarType::Link,
                other => {
                    return Err(format!(
                        "this archive contains an entry type we do not restore ({other})"
                    ));
                }
            };
            out.push(ReadEntry {
                entry: TarEntry {
                    path,
                    kind,
                    size: if kind == TarType::File { size } else { 0 },
                    mode: (read_octal(&head, 100, 8)? & 0o7777) as u32,
                    mtime: read_octal(&head, 136, 12)?,
                    target: (kind == TarType::Link).then(|| long_target.unwrap_or_else(|| read_str(&head, 157, 100))),
                },
                body: if kind == TarType::File { body } else { Vec::new() },
            });
        }
    }

    /// Both end-of-archive blocks arrived.
    pub fn complete(&self) -> bool {
        self.ended
    }
}

/// `safeEntryPath`: the only safe reading of an entry's name.
pub fn safe_entry_path(path: &str) -> Result<String, String> {
    let replaced = path.replace('\\', "/");
    let clean = replaced.strip_prefix("./").unwrap_or(&replaced);
    if clean.is_empty() || clean == "." {
        return Err("this archive contains an entry with no name".into());
    }
    if clean.starts_with('/') {
        return Err(format!("this archive contains an absolute path ({clean})"));
    }
    let parts: Vec<&str> = clean.split('/').collect();
    if parts.contains(&"..") {
        return Err(format!("this archive contains a path that climbs out of it ({clean})"));
    }
    if clean.contains('\0') {
        return Err("this archive contains an entry name with a null byte".into());
    }
    Ok(parts
        .into_iter()
        .filter(|p| !p.is_empty() && *p != ".")
        .collect::<Vec<_>>()
        .join("/"))
}

// ---- manifest ----

pub const MANIFEST_PATH: &str = ".controlclaw-backup-manifest.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub bytes: u64,
    pub mode: u32,
    /// `file`, `dir` or `link`.
    pub kind: &'static str,
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub kind: String,
    pub taken_at: String,
    pub root: String,
    pub entries: Vec<ManifestEntry>,
    pub total_bytes: u64,
    pub excluded: Vec<(String, u64)>,
    /// What a manifest read back carried beyond these (written by a newer build).
    pub extra: Map<String, Value>,
}

/// JavaScript's `<` on strings: UTF-16 code units, which is not UTF-8 byte order once a name
/// mixes characters above U+FFFF with ones from U+E000 to U+FFFF.
pub fn js_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

impl Manifest {
    /// `JSON.stringify(manifest)` in the TS key order: what goes into the archive.
    pub fn to_json(&self) -> String {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                let mut m = Map::new();
                m.insert("path".into(), json!(e.path));
                m.insert("bytes".into(), json!(e.bytes));
                m.insert("mode".into(), json!(e.mode));
                m.insert("kind".into(), json!(e.kind));
                if let Some(t) = &e.target {
                    m.insert("target".into(), json!(t));
                }
                Value::Object(m)
            })
            .collect();
        let excluded: Vec<Value> = self
            .excluded
            .iter()
            .map(|(p, b)| json!({"path": p, "bytes": b}))
            .collect();
        json!({
            "version": 1,
            "kind": self.kind,
            "takenAt": self.taken_at,
            "root": self.root,
            "entries": entries,
            "totalBytes": self.total_bytes,
            "excluded": excluded,
        })
        .to_string()
    }

    /// `canonicalManifest`: keys in a fixed order, entries and exclusions sorted by path.
    pub fn canonical(&self) -> String {
        let mut entries = self.entries.clone();
        entries.sort_by(|a, b| js_cmp(&a.path, &b.path));
        let entries: Vec<Value> = entries
            .iter()
            .map(|e| {
                if e.kind == "link" {
                    json!({"bytes": e.bytes, "kind": e.kind, "mode": e.mode, "path": e.path, "target": e.target.clone().unwrap_or_default()})
                } else {
                    json!({"bytes": e.bytes, "kind": e.kind, "mode": e.mode, "path": e.path})
                }
            })
            .collect();
        let mut excluded = self.excluded.clone();
        excluded.sort_by(|a, b| js_cmp(&a.0, &b.0));
        let excluded: Vec<Value> = excluded.iter().map(|(p, b)| json!({"bytes": b, "path": p})).collect();
        json!({
            "entries": entries,
            "excluded": excluded,
            "kind": self.kind,
            "root": self.root,
            "takenAt": self.taken_at,
            "totalBytes": self.total_bytes,
            "version": 1,
        })
        .to_string()
    }

    /// `manifestHash`: BLAKE2b-256 of the canonical form, hex.
    pub fn hash(&self) -> String {
        let mut h = [0u8; 32];
        let canonical = self.canonical();
        // 32 bytes is a valid generichash length, and the key is none.
        let _ = dryoc::classic::crypto_generichash::crypto_generichash(&mut h, canonical.as_bytes(), None);
        hex::encode(h)
    }

    /// `parseManifest`.
    pub fn parse(json: &str) -> Result<Self, String> {
        let bad = || "the archive's manifest is not readable".to_string();
        let mut m = match serde_json::from_str::<Value>(json) {
            Ok(Value::Object(m)) => m,
            _ => return Err(bad()),
        };
        if m.get("version").and_then(Value::as_f64) != Some(1.0) {
            return Err(bad());
        }
        let Some(Value::Array(raw_entries)) = m.remove("entries") else {
            return Err(bad());
        };
        let str_of = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or_default().to_string();
        let num_of = |v: Option<&Value>| v.and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as u64;
        let entries = raw_entries
            .iter()
            .map(|e| ManifestEntry {
                path: str_of(e.get("path")),
                bytes: num_of(e.get("bytes")),
                mode: num_of(e.get("mode")) as u32,
                kind: match e.get("kind").and_then(Value::as_str) {
                    Some("dir") => "dir",
                    Some("link") => "link",
                    _ => "file",
                },
                target: e.get("target").and_then(Value::as_str).map(str::to_string),
            })
            .collect();
        let excluded = match m.remove("excluded") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| (str_of(x.get("path")), num_of(x.get("bytes"))))
                .collect(),
            _ => Vec::new(),
        };
        m.remove("version");
        Ok(Self {
            kind: m.remove("kind").map(|v| str_of(Some(&v))).unwrap_or_default(),
            taken_at: m.remove("takenAt").map(|v| str_of(Some(&v))).unwrap_or_default(),
            root: m.remove("root").map(|v| str_of(Some(&v))).unwrap_or_default(),
            total_bytes: m.remove("totalBytes").map(|v| num_of(Some(&v))).unwrap_or(0),
            entries,
            excluded,
            extra: m,
        })
    }
}

// ---- paths ----

/// Where each archive's root sits, relative to OpenClaw's home.
pub fn archive_root(kind: &str) -> Option<&'static str> {
    match kind {
        "workspace" => Some("workspace"),
        "state" => Some("."),
        _ => None,
    }
}

const EXCLUDED_SEGMENTS: &[&str] = &[
    "node_modules",
    ".cache",
    "cache",
    "caches",
    "cachestorage",
    "code cache",
    "gpucache",
    "shadercache",
    "dawncache",
    "crashpad",
    "_cacache",
    ".pnpm-store",
    ".turbo",
    ".venv",
    "__pycache__",
    "logs",
    "tmp",
    ".tmp",
];

/// This box's identity, never archived and never removed by a restore.
pub const IDENTITY_NAMES: &[&str] = &[
    "openclaw_gateway_token",
    "saas_public_key.pem",
    "vm_private_key.pem",
    "vm_public_key.pem",
    "mitm_pinned_pubkey.pem",
    "session_secret",
];

const EXCLUDED_SUFFIXES: &[&str] = &[".log", ".log.gz", ".sock", ".pid", ".swp", ".core"];

/// What a restore carries across from the old directory rather than replacing (`keepOnRestore`).
pub fn keep_on_restore(kind: &str) -> Vec<String> {
    if kind != "state" {
        return Vec::new();
    }
    ["workspace", "extensions/google-meet"]
        .iter()
        .chain(IDENTITY_NAMES)
        .map(|s| s.to_string())
        .collect()
}

/// `RESTORE_SCRATCH`: `.cc-restoring` and `.cc-previous-<digits>` at the end of a segment.
fn is_restore_scratch(seg: &str) -> bool {
    if seg.ends_with(".cc-restoring") {
        return true;
    }
    match seg.rfind(".cc-previous-") {
        Some(i) => {
            let digits = &seg[i + ".cc-previous-".len()..];
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// `shouldExclude`.
pub fn should_exclude(rel_path: &str, kind: &str) -> bool {
    let parts: Vec<&str> = rel_path.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.is_empty() {
        return false;
    }
    if kind == "state" && parts[0] == "workspace" {
        return true;
    }
    if parts.iter().any(|p| is_restore_scratch(p)) {
        return true;
    }
    let name = parts[parts.len() - 1].to_lowercase();
    if IDENTITY_NAMES.contains(&name.as_str()) || name == ".ds_store" {
        return true;
    }
    if kind == "gbrain" {
        return false;
    }
    if EXCLUDED_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return true;
    }
    parts
        .iter()
        .any(|p| EXCLUDED_SEGMENTS.contains(&p.to_lowercase().as_str()))
}

const FORBIDDEN_ROOTS: &[&str] = &["/opt/controlclaw/keys", "/opt/controlclaw/mitm", "/etc/ssh", "/root"];

/// `assertArchivableRoot`.
pub fn assert_archivable_root(path: &str) -> Result<(), String> {
    let p = path.trim_end_matches('/');
    let p = if p.is_empty() { "/" } else { p };
    if p == "/" {
        return Err("refusing to archive the whole filesystem".into());
    }
    for bad in FORBIDDEN_ROOTS {
        if p == *bad || p.starts_with(&format!("{bad}/")) {
            return Err(format!(
                "refusing to archive {bad}: it is this box's identity, not its content"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_sort_as_javascript_sorts_them() {
        // Node: ["a", "😀", "｡"].
        let mut v = vec!["\u{FF61}", "\u{1F600}", "a"];
        v.sort_by(|a, b| js_cmp(a, b));
        assert_eq!(v, ["a", "\u{1F600}", "\u{FF61}"]);
    }

    fn entry(path: &str, kind: TarType, size: u64, target: Option<&str>) -> TarEntry {
        TarEntry {
            path: path.into(),
            kind,
            size,
            mode: 0o644,
            mtime: 1_700_000_000,
            target: target.map(str::to_string),
        }
    }

    #[test]
    fn tar_round_trip_with_long_names_and_targets() {
        let long = format!("{}/file.txt", "d".repeat(120));
        let target = "t".repeat(150);
        let mut tar = Vec::new();
        tar.extend(tar_header(&entry("a/", TarType::Dir, 0, None)).expect("h"));
        tar.extend(tar_header(&entry(&long, TarType::File, 5, None)).expect("h"));
        tar.extend(b"hello");
        tar.extend(tar_padding(5));
        tar.extend(tar_header(&entry("link", TarType::Link, 0, Some(&target))).expect("h"));
        tar.extend(tar_end());
        let mut r = TarReader::default();
        let mut got = Vec::new();
        // Fed a few bytes at a time, as a download arrives.
        for chunk in tar.chunks(97) {
            got.extend(r.push(chunk).expect("push"));
        }
        assert!(r.complete());
        assert_eq!(got.len(), 3);
        assert_eq!(got[1].entry.path, long);
        assert_eq!(got[1].body, b"hello");
        assert_eq!(got[2].entry.target.as_deref(), Some(target.as_str()));
        assert_eq!(got[0].entry.kind, TarType::Dir);
    }

    #[test]
    fn the_reader_refuses_what_a_backup_never_holds() {
        let mut h = tar_header(&entry("x", TarType::File, 0, None)).expect("h");
        h[156] = b'3';
        // A character device; the checksum is not read.
        assert!(TarReader::default().push(&h).is_err());
        let mut not_ours = vec![1u8; 512];
        not_ours[257..263].copy_from_slice(b"other\0");
        assert!(TarReader::default().push(&not_ours).is_err());
    }

    #[test]
    fn safe_entry_paths() {
        assert_eq!(safe_entry_path("./a//b/./c").as_deref(), Ok("a/b/c"));
        assert_eq!(safe_entry_path("a\\b").as_deref(), Ok("a/b"));
        for bad in ["", ".", "/etc/shadow", "../x", "a/../../x", "a\0b"] {
            assert!(safe_entry_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn exclusions() {
        assert!(should_exclude("workspace/x", "state"));
        assert!(!should_exclude("workspace/x", "workspace"));
        assert!(should_exclude("a/node_modules/b", "workspace"));
        assert!(should_exclude("a/Code Cache", "workspace"));
        assert!(should_exclude("x.log", "workspace"));
        assert!(should_exclude("deep/session_secret", "gbrain"));
        assert!(!should_exclude("pages/logs/note.md", "gbrain"));
        assert!(should_exclude("workspace.cc-previous-1700", "state"));
        assert!(!should_exclude("workspace.cc-previous-", "workspace"));
        assert!(!should_exclude("", "state"));
        assert_eq!(keep_on_restore("workspace"), Vec::<String>::new());
        assert_eq!(
            keep_on_restore("state")[..2],
            ["workspace".to_string(), "extensions/google-meet".into()]
        );
    }

    #[test]
    fn archivable_roots() {
        assert!(assert_archivable_root("/home/controlclaw/.openclaw").is_ok());
        for bad in [
            "/",
            "//",
            "/opt/controlclaw/keys",
            "/opt/controlclaw/keys/",
            "/root/x",
            "/etc/ssh",
        ] {
            assert!(assert_archivable_root(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_manifest_hash_ignores_order_and_survives_a_round_trip() {
        let m = Manifest {
            kind: "workspace".into(),
            taken_at: "2026-10-28T09:30:40.000Z".into(),
            root: "/home/controlclaw/.openclaw/workspace".into(),
            entries: vec![
                ManifestEntry {
                    path: "b".into(),
                    bytes: 1,
                    mode: 0o644,
                    kind: "file",
                    target: None,
                },
                ManifestEntry {
                    path: "a".into(),
                    bytes: 0,
                    mode: 0o777,
                    kind: "link",
                    target: Some("b".into()),
                },
            ],
            total_bytes: 1,
            excluded: vec![("node_modules".into(), 5)],
            extra: Map::new(),
        };
        let mut swapped = m.clone();
        swapped.entries.reverse();
        assert_eq!(m.hash(), swapped.hash());
        let back = Manifest::parse(&m.to_json()).expect("parse");
        assert_eq!(back.hash(), m.hash());
        assert!(Manifest::parse(r#"{"version":2,"entries":[]}"#).is_err());
    }
}
