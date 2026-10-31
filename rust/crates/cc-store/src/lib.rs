//! Files on the box: written whole or not at all, appended a line at a time, and read back without
//! losing fields this build does not know (so the Node build can read what Rust wrote after a
//! rollback). Encrypted stores are in `cc-crypto::enc_file`; the proxy's config files and their
//! reload cache are in `cc-contracts`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// `O_NOFOLLOW` (Linux): open fails with ELOOP when the last component is a symlink.
const O_NOFOLLOW: i32 = 0o400_000;

/// Where the temporary file of an atomic write goes. The two agents differ, and the proxy keys its
/// reloads on the final file's mtime, so each caller keeps the naming the TS used for that file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmpName {
    /// `<path>.tmp` (encrypted stores, most vm-agent state files).
    Suffix,
    /// `.<name>.tmp` in the same folder (the proxy config files in `/run/mitm/config`).
    HiddenPrefix,
}

pub fn tmp_path(path: &Path, naming: TmpName) -> PathBuf {
    match naming {
        TmpName::Suffix => PathBuf::from(format!("{}.tmp", path.display())),
        TmpName::HiddenPrefix => {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            path.with_file_name(format!(".{name}.tmp"))
        }
    }
}

/// Write `data` to a temporary file with `mode`, then rename it over `path`. Creates the folder.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32, naming: TmpName) -> io::Result<()> {
    write_atomic_owned(path, data, mode, naming, None)
}

/// As [`write_atomic`], with the file's owner and group (uid, gid) set on the temporary file before
/// the rename: the file never exists under `path` with another owner, so a crash cannot leave one
/// that its own service is locked out of. Changing the owner needs root.
pub fn write_atomic_owned(
    path: &Path,
    data: &[u8],
    mode: u32,
    naming: TmpName,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let tmp = tmp_path(path, naming);
    // The folder may belong to the service whose store this is, and this may run as root: never
    // write through whatever is at the temp name. A leftover (or a planted symlink) is unlinked,
    // then the file is created fresh: create_new (O_EXCL) and O_NOFOLLOW refuse anything that is
    // there by then, symlinks included, so nothing outside the folder is ever opened.
    match fs::symlink_metadata(&tmp) {
        Ok(_) => fs::remove_file(&tmp)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(O_NOFOLLOW)
            .open(&tmp)?;
        // The mode is applied when the file is created, less the umask; set it exactly.
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(data)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        f.sync_all()
    })();
    if let Err(e) = written {
        // Never leave a half-made file, or one with the wrong owner, at the temp name.
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, path)?;
    sync_dir(path)
}

/// Make a rename or a removal in `path`'s folder durable: until the folder is synced, a power loss
/// can undo it while later writes survive.
pub fn sync_dir(path: &Path) -> io::Result<()> {
    match path.parent().filter(|d| !d.as_os_str().is_empty()) {
        Some(dir) => fs::File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

/// Write a whole file in place (not atomic) with `mode`, also when it already existed with
/// another one. For the small key files the agents make once.
pub fn write_file(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    // Never through a symlink: the path is written as itself or not at all.
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.write_all(data)
}

/// `JSON.stringify(value)` and an atomic write.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T, mode: u32, naming: TmpName) -> io::Result<()> {
    let data = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_atomic(path, &data, mode, naming)
}

/// A JSON file, or `None` when it is missing or does not parse (the TS treats both as "not yet").
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let raw = fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// One JSON line, appended with `O_APPEND` in a single write, so two writers (the proxy and the
/// firewall agent share `traffic.jsonl`) never interleave inside a line.
pub fn append_jsonl<T: Serialize>(path: &Path, value: &T, mode: u32) -> io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().append(true).create(true).mode(mode).open(path)?;
    f.write_all(&line)
}

/// Move `path` to `<path>.1` once it is larger than `max_bytes` (the addon's traffic log rotation).
/// Returns whether it rotated.
pub fn rotate_if_larger(path: &Path, max_bytes: u64) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(m) if m.len() > max_bytes => {
            fs::rename(path, PathBuf::from(format!("{}.1", path.display())))?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Where the Ansible role's cc-runtime-fallback leaves a marker for a unit whose Rust build was
/// put back on Node (`<unit>.fallback`), as the Node builds read it (`software.ts`).
pub const RUNTIME_MARKERS_DIR: &str = "/etc/controlclaw/runtime";

/// The features a Rust build reports about itself, in its software report: `rust_runtime`, and
/// `runtime_fallback` when one of `units` (other units of its box, never its own: its own marker is
/// stale while it runs) was put back on Node.
pub fn runtime_features(units: &[&str], dir: &Path) -> Vec<String> {
    let mut f = vec!["rust_runtime".to_string()];
    if units.iter().any(|u| dir.join(format!("{u}.fallback")).exists()) {
        f.push("runtime_fallback".to_string());
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::{Map, Value, json};

    #[derive(Serialize, Deserialize)]
    struct Known {
        a: u32,
        #[serde(flatten)]
        extra: Map<String, Value>,
    }

    #[test]
    fn atomic_write_names_and_modes() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("sub/rules.json");
        assert_eq!(
            tmp_path(&p, TmpName::HiddenPrefix),
            d.path().join("sub/.rules.json.tmp")
        );
        write_atomic(&p, b"{}", 0o600, TmpName::HiddenPrefix).expect("write");
        assert_eq!(fs::metadata(&p).expect("meta").permissions().mode() & 0o777, 0o600);
        assert!(!tmp_path(&p, TmpName::HiddenPrefix).exists());
    }

    #[test]
    fn the_owner_is_there_before_the_rename() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("s.enc");
        let me = fs::metadata(d.path()).expect("meta");
        // Our own uid and gid (no root here): fchown to them is allowed, and the file has them.
        write_atomic_owned(&p, b"x", 0o600, TmpName::Suffix, Some((me.uid(), me.gid()))).expect("write");
        let m = fs::metadata(&p).expect("meta");
        assert_eq!((m.uid(), m.gid(), m.mode() & 0o777), (me.uid(), me.gid(), 0o600));
        // Another owner without root is refused, and nothing appears under the name.
        let q = d.path().join("t.enc");
        assert!(write_atomic_owned(&q, b"x", 0o600, TmpName::Suffix, Some((0, 0))).is_err() || me.uid() == 0);
        assert!(!q.exists() || me.uid() == 0);
    }

    #[test]
    fn a_planted_symlink_at_the_temp_name_is_never_written_through() {
        let d = tempfile::tempdir().expect("dir");
        let target = d.path().join("shadow");
        fs::write(&target, "root:secret").expect("target");
        let p = d.path().join("x.enc");
        // What a compromised service user could leave in its own folder.
        std::os::unix::fs::symlink(&target, tmp_path(&p, TmpName::Suffix)).expect("symlink");
        write_atomic(&p, b"new", 0o600, TmpName::Suffix).expect("write");
        assert_eq!(
            fs::read_to_string(&target).expect("target"),
            "root:secret",
            "the target is untouched"
        );
        assert_eq!(fs::read(&p).expect("store"), b"new");
        assert!(!fs::symlink_metadata(&p).expect("meta").file_type().is_symlink());
    }

    #[test]
    fn write_file_refuses_a_symlink() {
        let d = tempfile::tempdir().expect("dir");
        let target = d.path().join("shadow");
        fs::write(&target, "root:secret").expect("target");
        let p = d.path().join("session_secret");
        std::os::unix::fs::symlink(&target, &p).expect("symlink");
        assert!(write_file(&p, b"x", 0o600).is_err());
        assert_eq!(fs::read_to_string(&target).expect("target"), "root:secret");
    }

    #[test]
    fn a_failed_owner_change_leaves_no_temp_file() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().expect("dir");
        if fs::metadata(d.path()).expect("meta").uid() == 0 {
            return; // root may give the file away; the case is for a user who may not
        }
        let p = d.path().join("t.enc");
        assert!(write_atomic_owned(&p, b"x", 0o600, TmpName::Suffix, Some((0, 0))).is_err());
        assert!(!p.exists() && !tmp_path(&p, TmpName::Suffix).exists());
    }

    #[test]
    fn runtime_features_name_the_build_and_a_fallback() {
        let d = tempfile::tempdir().expect("dir");
        assert_eq!(runtime_features(&["controlclaw-mitmproxy"], d.path()), ["rust_runtime"]);
        fs::write(d.path().join("controlclaw-mitmproxy.fallback"), "{}").expect("marker");
        assert_eq!(
            runtime_features(&["controlclaw-mitmproxy"], d.path()),
            ["rust_runtime", "runtime_fallback"]
        );
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("s.json");
        fs::write(&p, r#"{"a":1,"later":{"x":[1,2]},"b":"keep"}"#).expect("seed");
        let k: Known = read_json(&p).expect("read");
        write_json_atomic(&p, &k, 0o600, TmpName::Suffix).expect("write");
        assert_eq!(
            fs::read_to_string(&p).expect("read"),
            r#"{"a":1,"later":{"x":[1,2]},"b":"keep"}"#
        );
        assert!(read_json::<Known>(&d.path().join("missing")).is_none());
    }

    #[test]
    fn jsonl_append_and_rotate() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("traffic.jsonl");
        append_jsonl(&p, &json!({"n": 1}), 0o640).expect("append");
        append_jsonl(&p, &json!({"n": 2}), 0o640).expect("append");
        assert_eq!(fs::read_to_string(&p).expect("read"), "{\"n\":1}\n{\"n\":2}\n");
        assert!(!rotate_if_larger(&p, 100).expect("rotate"));
        assert!(rotate_if_larger(&p, 4).expect("rotate"));
        assert!(d.path().join("traffic.jsonl.1").exists() && !p.exists());
    }
}
