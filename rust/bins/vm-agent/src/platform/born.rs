//! The born stamp (`born.ts`): when this box was given to its organization, and so the one
//! definition of a new agent. `/etc/controlclaw/born` holds one ISO time, root's, in root's folder.
//!
//! - A missing stamp means not new.
//! - Only root's stamp, in root's folder, counts: a file that is not root's, is a link, or that
//!   others can write, or a folder that is not root's or that others can write, reads as missing.
//!   The file is opened once and checked through that handle.
//! - Asked every time: nothing is kept between calls.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::time::{now_ms, parse_iso_z};

pub const BORN_PATH: &str = "/etc/controlclaw/born";

/// How long after its born stamp a box is a new agent (templates, start skills and notes).
pub const NEW_AGENT_HOURS: f64 = 1.0;

/// A stamp further in the future than this is not believed.
const FUTURE_SLACK_MS: i64 = 5 * 60_000;

/// `O_NOFOLLOW` on Linux.
const O_NOFOLLOW: i32 = 0o400_000;

/// When this box was born (ms since the epoch), or None. `owner` is who must own the file and its
/// folder: root (0); tests pass their own uid.
pub fn born_at(path: &Path, owner: u32) -> Option<i64> {
    let folder = std::fs::metadata(path.parent()?).ok()?;
    if !folder.is_dir() || folder.uid() != owner || folder.mode() & 0o022 != 0 {
        return None;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .ok()?;
    let stat = file.metadata().ok()?;
    if !stat.is_file() || stat.uid() != owner || stat.mode() & 0o022 != 0 || stat.len() > 64 {
        return None;
    }
    let mut buf = [0u8; 64];
    let n = file.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    parse_iso_z(text.trim())
}

/// Whether this box was born less than `hours` ago. False without a stamp, and for a stamp from
/// the future.
pub fn is_new_at(hours: f64, path: &Path, owner: u32, now: i64) -> bool {
    let Some(born) = born_at(path, owner) else {
        return false;
    };
    let age = now - born;
    age >= -FUTURE_SLACK_MS && (age as f64) < hours * 3_600_000.0
}

pub fn is_new(hours: f64) -> bool {
    is_new_at(hours, Path::new(BORN_PATH), 0, now_ms())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn me(dir: &Path) -> u32 {
        std::fs::metadata(dir).expect("meta").uid()
    }

    fn stamp(dir: &Path, name: &str, content: &str, mode: u32) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).expect("write");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
        p
    }

    fn now() -> i64 {
        parse_iso_z("2026-10-12T10:00:00.000Z").expect("now")
    }

    fn private_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("dir");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod");
        d
    }

    #[test]
    fn a_missing_stamp_is_not_new() {
        let d = private_dir();
        let me = me(d.path());
        let p = d.path().join("none");
        assert_eq!(born_at(&p, me), None);
        assert!(!is_new_at(1.0, &p, me, now()));
        assert!(!is_new_at(1000.0, &p, me, now()));
        assert_eq!(BORN_PATH, "/etc/controlclaw/born");
    }

    #[test]
    fn new_for_the_hours_asked_and_read_again_on_every_call() {
        let d = private_dir();
        let me = me(d.path());
        let p = stamp(d.path(), "born", "2026-10-12T09:30:00Z\n", 0o644);
        assert_eq!(born_at(&p, me), parse_iso_z("2026-10-12T09:30:00.000Z"));
        assert!(is_new_at(1.0, &p, me, now()));
        let later = parse_iso_z("2026-10-12T10:30:00.000Z").expect("t");
        assert!(!is_new_at(1.0, &p, me, later));
        assert!(is_new_at(2.0, &p, me, later));
        std::fs::write(&p, "2026-10-10T09:30:00Z\n").expect("write");
        assert!(!is_new_at(1.0, &p, me, now()));
    }

    #[test]
    fn only_the_owners_stamp_counts() {
        let d = private_dir();
        let me = me(d.path());
        let p = stamp(d.path(), "mine", "2026-10-12T09:59:00Z\n", 0o644);
        if me != 0 {
            assert_eq!(born_at(&p, 0), None);
        }
        assert!(is_new_at(1.0, &p, me, now()));
    }

    #[test]
    fn writable_links_long_and_non_times_are_not_stamps() {
        let d = private_dir();
        let me = me(d.path());
        assert_eq!(
            born_at(&stamp(d.path(), "group", "2026-10-12T09:59:00Z\n", 0o664), me),
            None
        );
        assert_eq!(
            born_at(&stamp(d.path(), "world", "2026-10-12T09:59:00Z\n", 0o646), me),
            None
        );
        let real = stamp(d.path(), "real", "2026-10-12T09:59:00Z\n", 0o644);
        std::os::unix::fs::symlink(&real, d.path().join("link")).expect("link");
        assert_eq!(born_at(&d.path().join("link"), me), None);
        let long = format!("2026-10-12T09:59:00Z{}", " ".repeat(80));
        for (name, text) in [
            ("empty", ""),
            ("words", "yesterday"),
            ("date", "2026-10-12"),
            ("local", "2026-10-12T09:59:00+02:00"),
            ("long", long.as_str()),
            ("two", "2026-10-12T09:59:00Z\n2026-10-12T09:59:00Z"),
        ] {
            assert_eq!(born_at(&stamp(d.path(), name, text, 0o644), me), None, "{name}");
        }
    }

    #[test]
    fn a_folder_others_can_write_is_not_trusted() {
        let d = private_dir();
        let me = me(d.path());
        let p = stamp(d.path(), "born", "2026-10-12T09:59:00Z\n", 0o644);
        assert!(is_new_at(1.0, &p, me, now()));
        for mode in [0o777, 0o775] {
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(born_at(&p, me), None);
        }
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(is_new_at(1.0, &p, me, now()));
        if me != 0 {
            assert_eq!(born_at(&p, 0), None);
        }
    }

    #[test]
    fn a_stamp_from_the_future_is_not_new() {
        let d = private_dir();
        let me = me(d.path());
        assert!(!is_new_at(
            1.0,
            &stamp(d.path(), "future", "2026-10-13T10:00:00Z\n", 0o644),
            me,
            now()
        ));
        assert!(is_new_at(
            1.0,
            &stamp(d.path(), "soon", "2026-10-12T10:00:20Z\n", 0o644),
            me,
            now()
        ));
    }
}
