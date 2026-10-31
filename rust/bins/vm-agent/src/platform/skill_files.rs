//! Skill folders and shared notes as files (`@controlclaw/templates`: `skill-files.ts`,
//! `skill-folder.ts`, `skill-names.ts`, `notes-directory.ts`, `notes-folder.ts`). The hashes here
//! must equal the TS ones byte for byte: the console compares them with the ones it computed.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A skill's name: its folder under `~/.openclaw/skills` and its key in `skills.entries`.
pub static SKILL_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,63}$").expect("regex"));
/// The skills every agent gets from ControlClaw: switched off, never removed.
pub const BUILTIN_SKILL_NAMES: [&str; 4] = ["agentmail", "apify-scraping", "controlclaw", "google-account"];
/// The install record beside `SKILL.md`.
pub const SKILL_RECORD: &str = ".controlclaw.json";
/// What is in an installed folder and is not the skill.
pub const SKILL_NOT_CONTENT: [&str; 2] = [SKILL_RECORD, ".openclaw"];
pub const SKILL_LIMITS: (usize, u64, u64) = (100, 256 * 1024, 1_000_000);
pub const NOTES_LIMITS: (usize, u64, u64) = (200, 256 * 1024, 2_000_000);
/// The most sets an agent holds (`cc-notes` keeps the same cap).
pub const NOTES_ON_AGENT: usize = 60;
/// `CONFIG_CHANGED_MEANWHILE`: OpenClaw's config file moved while the CLI worked; run it again.
pub static CONFIG_CHANGED_MEANWHILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)config (file )?changed (while|since)").expect("regex"));

/// Names every plain JavaScript object has (`name in {}`): never a key we write.
pub const OBJECT_KEYS: [&str; 12] = [
    "constructor",
    "__proto__",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

pub fn object_key(name: &str) -> bool {
    OBJECT_KEYS.contains(&name)
}

/// One file of a skill or a set; `path` relative, with `/`.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillFile {
    pub path: String,
    pub content: Vec<u8>,
    pub executable: bool,
}

/// JavaScript's `a < b` on strings: UTF-16 code units.
fn js_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `hashSkillFiles`: changes when a file's path, content or executable bit does.
pub fn hash_skill_files(files: &[SkillFile]) -> String {
    let mut sorted: Vec<&SkillFile> = files.iter().collect();
    sorted.sort_by(|a, b| js_cmp(&a.path, &b.path));
    let mut h = Sha256::new();
    for f in sorted {
        h.update(
            format!(
                "{}\0{}\0{}\0",
                f.path,
                if f.executable { "x" } else { "-" },
                f.content.len()
            )
            .as_bytes(),
        );
        h.update(&f.content);
    }
    hex::encode(h.finalize())
}

/// `notesHash`: the files (never executable) and which one is always loaded.
pub fn notes_hash(files: &[SkillFile], always: Option<&str>) -> String {
    let plain: Vec<SkillFile> = files
        .iter()
        .map(|f| SkillFile {
            executable: false,
            ..f.clone()
        })
        .collect();
    let inner = hash_skill_files(&plain);
    hex::encode(Sha256::digest(
        format!("{inner}\0always\0{}", always.unwrap_or_default()).as_bytes(),
    ))
}

/// `notesNameProblem`: a set's name is a skill's shape, not an object key, not `_…`.
pub fn notes_name_ok(name: &str) -> bool {
    SKILL_NAME.is_match(name) && !object_key(name) && !name.starts_with('_')
}

/// The install record (`parseSkillRecord`).
#[derive(Debug, Clone, PartialEq)]
pub struct SkillRecord {
    pub source: String,
    pub id: String,
    pub version: Option<String>,
    pub installed_hash: String,
    pub installed_at: String,
}

static HASH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("regex"));

pub fn is_hash(s: &str) -> bool {
    HASH_RE.is_match(s)
}

pub fn parse_skill_record(raw: &Value) -> Option<SkillRecord> {
    let r = raw.as_object()?;
    let source = r
        .get("source")?
        .as_str()
        .filter(|s| ["controlclaw", "organization", "template"].contains(s))?;
    let id = r.get("id")?.as_str()?;
    let hash = r.get("installedHash")?.as_str().filter(|h| is_hash(h))?;
    let version = match r.get("version") {
        Some(Value::Null) => None,
        Some(Value::String(v)) => Some(v.clone()),
        _ => return None,
    };
    Some(SkillRecord {
        source: source.into(),
        id: id.into(),
        version,
        installed_hash: hash.into(),
        installed_at: r.get("installedAt").and_then(Value::as_str).unwrap_or_default().into(),
    })
}

/// `readSkillRecord`.
pub fn read_skill_record(dir: &Path) -> Option<SkillRecord> {
    let text = std::fs::read_to_string(dir.join(SKILL_RECORD)).ok()?;
    parse_skill_record(&serde_json::from_str(&text).ok()?)
}

#[derive(Debug, Clone)]
struct Stat {
    path: String,
    size: u64,
    mtime_ns: i128,
    executable: bool,
}

/// `statSkillFolder`: every file of a skill folder by its stats, or None for a folder a skill
/// cannot be (a link, too many files, too big, no `SKILL.md`).
fn stat_skill_folder(dir: &Path) -> Option<Vec<Stat>> {
    fn walk(folder: &Path, prefix: &str, found: &mut Vec<Stat>) -> Option<()> {
        let mut names: Vec<String> = std::fs::read_dir(folder)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort_by(|a, b| js_cmp(a, b));
        for name in names {
            if prefix.is_empty() && SKILL_NOT_CONTENT.contains(&name.as_str()) {
                continue;
            }
            let path = folder.join(&name);
            let st = std::fs::symlink_metadata(&path).ok()?;
            if st.is_dir() {
                walk(&path, &format!("{prefix}{name}/"), found)?;
            } else if !st.is_file() {
                return None;
            } else {
                found.push(Stat {
                    path: format!("{prefix}{name}"),
                    size: st.len(),
                    mtime_ns: i128::from(st.mtime()) * 1_000_000_000 + i128::from(st.mtime_nsec()),
                    executable: st.mode() & 0o111 != 0,
                });
                let total: u64 = found.iter().map(|f| f.size).sum();
                if found.len() > SKILL_LIMITS.0 || st.len() > SKILL_LIMITS.1 || total > SKILL_LIMITS.2 {
                    return None;
                }
            }
        }
        Some(())
    }
    let mut found = Vec::new();
    walk(dir, "", &mut found)?;
    found.iter().any(|f| f.path == "SKILL.md").then_some(found)
}

/// The hash of each managed skill folder, read again only when a file's size, time or mode changed.
#[derive(Default)]
pub struct SkillHashes {
    known: Mutex<HashMap<PathBuf, (String, Option<String>)>>,
}

impl SkillHashes {
    pub fn of(&self, dir: &Path) -> Option<String> {
        let stats = stat_skill_folder(dir);
        let signature = stats
            .as_ref()
            .map(|s| {
                s.iter()
                    .map(|f| {
                        format!(
                            "{}:{}:{}:{}",
                            f.path,
                            f.size,
                            f.mtime_ns,
                            if f.executable { "x" } else { "-" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .unwrap_or_default();
        if let Some((sig, hash)) = super::common::lock(&self.known).get(dir)
            && *sig == signature
        {
            return hash.clone();
        }
        let hash = stats.and_then(|stats| {
            let mut files = Vec::new();
            for f in stats {
                files.push(SkillFile {
                    content: std::fs::read(dir.join(&f.path)).ok()?,
                    path: f.path,
                    executable: f.executable,
                });
            }
            Some(hash_skill_files(&files))
        });
        super::common::lock(&self.known).insert(dir.to_path_buf(), (signature, hash.clone()));
        hash
    }

    /// Forget the folders that are gone.
    pub fn keep(&self, dirs: &[PathBuf]) {
        super::common::lock(&self.known).retain(|d, _| dirs.contains(d));
    }
}

/// `NotesPlace`: the folder the sets are in, and the helper that writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct NotesPlace {
    pub root: PathBuf,
    pub helper: Vec<String>,
}

/// `notesPlace()` from the environment.
pub fn notes_place() -> NotesPlace {
    NotesPlace {
        root: std::env::var("CC_NOTES_DIR")
            .unwrap_or_else(|_| "/var/lib/controlclaw-notes/sets".into())
            .into(),
        helper: match std::env::var("CC_NOTES_HELPER") {
            Ok(h) => vec![h],
            Err(_) => vec!["sudo".into(), "-n".into(), "/usr/local/sbin/cc-notes".into()],
        },
    }
}

/// `notesLocked`: on an encrypted disk that is locked, the notes are in the locked part.
pub fn notes_locked(place: &NotesPlace) -> bool {
    let marker =
        std::env::var("CC_NOTES_IN_CONTAINER").unwrap_or_else(|_| "/etc/controlclaw/notes-in-container".into());
    if std::fs::symlink_metadata(&marker).is_err() {
        return false;
    }
    let Some(base) = place.root.parent() else { return true };
    let Some(above) = base.parent() else { return true };
    match (std::fs::metadata(base), std::fs::metadata(above)) {
        // A mount is on another device than the folder it is in.
        (Ok(b), Ok(a)) => b.dev() == a.dev(),
        _ => true,
    }
}

/// What this agent recorded when a set was put (`~/.controlclaw/notes/<set>.json`).
#[derive(Debug, Clone, PartialEq)]
pub struct NotesRecord {
    pub source: String,
    pub id: String,
    pub version: Option<String>,
    pub payload: Option<String>,
    pub hash: String,
    pub always: Option<String>,
    pub installed_at: String,
}

fn record_path(home: &Path, set: &str) -> PathBuf {
    home.join(".controlclaw").join("notes").join(format!("{set}.json"))
}

pub fn read_notes_record(home: &Path, set: &str) -> Option<NotesRecord> {
    if !notes_name_ok(set) {
        return None;
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(record_path(home, set)).ok()?).ok()?;
    let source = v
        .get("source")?
        .as_str()
        .filter(|s| *s == "organization" || *s == "template")?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let hash = s("hash").filter(|h| is_hash(h))?;
    Some(NotesRecord {
        source: source.into(),
        id: v.get("id")?.as_str()?.into(),
        version: s("version"),
        payload: s("payload"),
        hash,
        always: s("always"),
        installed_at: s("installedAt").unwrap_or_default(),
    })
}

pub fn remove_notes_record(home: &Path, set: &str) {
    if notes_name_ok(set) {
        let _ = std::fs::remove_file(record_path(home, set));
    }
}

/// `installedNotes`: a set's files, or None when it is not there or not a readable set.
pub fn installed_notes(root: &Path, set: &str) -> Option<Vec<SkillFile>> {
    if !notes_name_ok(set) {
        return None;
    }
    fn walk(folder: &Path, prefix: &str, files: &mut Vec<SkillFile>, bytes: &mut u64) -> Option<()> {
        let mut names: Vec<String> = std::fs::read_dir(folder)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort_by(|a, b| js_cmp(a, b));
        for name in names {
            let path = folder.join(&name);
            let st = std::fs::symlink_metadata(&path).ok()?;
            if st.is_dir() {
                walk(&path, &format!("{prefix}{name}/"), files, bytes)?;
            } else if !st.is_file() {
                return None;
            } else {
                *bytes += st.len();
                if files.len() >= NOTES_LIMITS.0 || st.len() > NOTES_LIMITS.1 || *bytes > NOTES_LIMITS.2 {
                    return None;
                }
                files.push(SkillFile {
                    path: format!("{prefix}{name}"),
                    content: std::fs::read(&path).ok()?,
                    executable: false,
                });
            }
        }
        Some(())
    }
    let dir = root.join(set);
    if !std::fs::symlink_metadata(&dir).ok()?.is_dir() {
        return None;
    }
    let mut files = Vec::new();
    let mut bytes = 0;
    walk(&dir, "", &mut files, &mut bytes)?;
    Some(files)
}

/// `notesSets`: the sets' names, sorted, at most 60.
pub fn notes_sets(root: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| notes_name_ok(n))
        .collect();
    names.sort_by(|a, b| js_cmp(a, b));
    names.truncate(NOTES_ON_AGENT);
    names
}

/// A set's folder without reading a file: every entry's path, inode, size and change times.
fn signature(root: &Path, set: &str) -> Option<String> {
    fn walk(folder: &Path, prefix: &str, parts: &mut Vec<String>, count: &mut usize) -> Option<()> {
        let mut names: Vec<String> = std::fs::read_dir(folder)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort_by(|a, b| js_cmp(a, b));
        for name in names {
            let path = folder.join(&name);
            let st = std::fs::symlink_metadata(&path).ok()?;
            if st.is_dir() {
                walk(&path, &format!("{prefix}{name}/"), parts, count)?;
            } else {
                *count += 1;
                if !st.is_file() || *count > NOTES_LIMITS.0 {
                    return None;
                }
                let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
                parts.push(format!(
                    "{prefix}{name}\0{}\0{}\0{}\0{}",
                    st.ino(),
                    st.len(),
                    ns(st.ctime(), st.ctime_nsec()),
                    ns(st.mtime(), st.mtime_nsec())
                ));
            }
        }
        Some(())
    }
    let dir = root.join(set);
    if !std::fs::symlink_metadata(&dir).ok()?.is_dir() {
        return None;
    }
    let mut parts = Vec::new();
    let mut count = 0;
    walk(&dir, "", &mut parts, &mut count)?;
    Some(parts.join("\n"))
}

/// The last hash worked out for each set, with its folder's signature then.
/// A set's signature and the hash it had then.
type Hashed = HashMap<String, (String, Option<String>)>;
static HASHED: LazyLock<Mutex<Hashed>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// `notesSetHash`: worked out again only when the folder's signature changed.
pub fn notes_set_hash(root: &Path, set: &str, always: Option<&str>) -> Option<String> {
    let key = format!("{}\0{set}", root.display());
    let Some(now) = signature(root, set) else {
        super::common::lock(&HASHED).remove(&key);
        return None;
    };
    let sig = format!("{}\n{now}", always.unwrap_or_default());
    if let Some((s, h)) = super::common::lock(&HASHED).get(&key)
        && *s == sig
    {
        return h.clone();
    }
    let hash = installed_notes(root, set).map(|f| notes_hash(&f, always));
    super::common::lock(&HASHED).insert(key, (sig, hash.clone()));
    hash
}

/// `reportNotes`: every set with its hash and what was recorded when it was put.
pub fn report_notes(home: &Path, place: &NotesPlace) -> Vec<Value> {
    let names = notes_sets(&place.root);
    let prefix = format!("{}\0", place.root.display());
    super::common::lock(&HASHED)
        .retain(|k, _| !k.starts_with(&prefix) || names.iter().any(|n| k[prefix.len()..] == **n));
    names
        .iter()
        .map(|name| {
            let r = read_notes_record(home, name);
            serde_json::json!({
                "name": name,
                "hash": notes_set_hash(&place.root, name, r.as_ref().and_then(|r| r.always.as_deref())),
                "source": r.as_ref().map(|r| r.source.clone()),
                "id": r.as_ref().map(|r| r.id.clone()),
                "version": r.as_ref().and_then(|r| r.version.clone()),
                "installedHash": r.as_ref().map(|r| r.hash.clone()),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, content: &str, executable: bool) -> SkillFile {
        SkillFile {
            path: path.into(),
            content: content.as_bytes().to_vec(),
            executable,
        }
    }

    /// The same files hashed by the TS (`hashSkillFiles`, `notesHash` run with tsx).
    #[test]
    fn hashes_match_the_ts() {
        let files = vec![
            f("scripts/run.sh", "#!/bin/sh\necho hi\n", true),
            f("SKILL.md", "---\nname: x\n---\n", false),
            f("ref/é.md", "ü", false),
        ];
        assert_eq!(
            hash_skill_files(&files),
            "4b13f52621dee083bdcc4389a3188ffbfba81e3d87a46160f9cc723a249c2452"
        );
        assert_eq!(
            notes_hash(&files, Some("SKILL.md")),
            "220a29b8140d458ee5c75dfef49ac3664b7df89e475907cf7b36c02f4c93bae3"
        );
    }

    #[test]
    fn names_and_records() {
        assert!(notes_name_ok("house-style"));
        assert!(!notes_name_ok("_hidden"));
        assert!(!notes_name_ok("constructor"));
        assert!(!notes_name_ok("Caps"));
        let r = serde_json::json!({ "source": "organization", "id": "sk-1", "version": null, "installedHash": "a".repeat(64) });
        assert_eq!(parse_skill_record(&r).expect("r").source, "organization");
        assert!(
            parse_skill_record(
                &serde_json::json!({ "source": "me", "id": "x", "version": null, "installedHash": "a".repeat(64) })
            )
            .is_none()
        );
        assert!(
            parse_skill_record(
                &serde_json::json!({ "source": "template", "id": "x", "version": 3, "installedHash": "a".repeat(64) })
            )
            .is_none()
        );
    }

    #[test]
    fn a_skill_folder_hash_ignores_our_record_and_refuses_a_link() {
        let d = tempfile::tempdir().expect("dir");
        let dir = d.path().join("s");
        std::fs::create_dir_all(dir.join("ref")).expect("d");
        std::fs::write(dir.join("SKILL.md"), "x").expect("w");
        std::fs::write(dir.join("ref/a.md"), "y").expect("w");
        let hashes = SkillHashes::default();
        let want = hash_skill_files(&[f("SKILL.md", "x", false), f("ref/a.md", "y", false)]);
        assert_eq!(hashes.of(&dir), Some(want.clone()));
        std::fs::write(dir.join(SKILL_RECORD), "{}").expect("w");
        assert_eq!(hashes.of(&dir), Some(want));
        std::os::unix::fs::symlink("/etc/passwd", dir.join("ref/link")).expect("l");
        assert_eq!(hashes.of(&dir), None);
    }

    #[test]
    fn the_notes_report() {
        let d = tempfile::tempdir().expect("dir");
        let place = NotesPlace {
            root: d.path().join("sets"),
            helper: vec!["true".into()],
        };
        std::fs::create_dir_all(place.root.join("handbook")).expect("d");
        std::fs::create_dir_all(place.root.join("_skip")).expect("d");
        std::fs::write(place.root.join("handbook/a.md"), "A").expect("w");
        let home = d.path().join("home");
        std::fs::create_dir_all(home.join(".controlclaw/notes")).expect("d");
        std::fs::write(
            home.join(".controlclaw/notes/handbook.json"),
            serde_json::json!({ "source": "organization", "id": "n1", "version": "2", "payload": "snt-abcdefgh", "hash": "b".repeat(64), "always": "a.md", "installedAt": "t" }).to_string(),
        )
        .expect("w");
        let report = report_notes(&home, &place);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0]["name"], "handbook");
        assert_eq!(
            report[0]["hash"],
            serde_json::json!(notes_hash(&[f("a.md", "A", false)], Some("a.md")))
        );
        assert_eq!(report[0]["installedHash"], serde_json::json!("b".repeat(64)));
        assert_eq!(report[0]["version"], "2");
    }
}
