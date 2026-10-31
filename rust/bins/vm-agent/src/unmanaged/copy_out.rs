//! OpenClaw's files in a container, read through a copy. `docker cp -L <container>:<path> -` resolves
//! the path and a last link inside the container's own root and writes a tar to stdout. Only one
//! entry is taken from it: a single regular file (PAX headers before it are allowed, and their
//! `size` is the file's), at most `cap` bytes. It is written 0600 into a folder of its own (0700)
//! under one of the agent's (0700), so no mode, owner, link or device node from the container's tar
//! lands on this machine, no path the container names is walked here, and two reads at once never
//! share a copy. The copy goes when it has been read.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::platform::channels::Readable;

/// A SQLite database or its write-ahead log.
pub const DB_CAP: u64 = 64 * 1024 * 1024;
/// A small file (a channel's pending pairings).
pub const FILE_CAP: u64 = 1024 * 1024;
/// A PAX header's own size: names and times, never the file.
const PAX_CAP: u64 = 64 * 1024;
const BLOCK: usize = 512;
/// How long one `docker cp` may take before it is killed.
const COPY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// The archive docker sends for a path that is not there (or went away during the copy).
const EMPTY: &str = "an empty archive";

/// The cap for one of OpenClaw's files: a database's or its log's, else a small file's.
pub fn cap_for(path: &Path) -> u64 {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.ends_with(".sqlite") || name.ends_with(".sqlite-wal") {
        DB_CAP
    } else {
        FILE_CAP
    }
}

/// Copy `inside` out of `container` into a folder of its own under `into`, and a database's
/// write-ahead log beside it: the copy, or None when it is not there, not one regular file, or
/// larger than its cap (said in the log).
pub fn copy(container: &str, inside: &Path, into: &Path) -> Option<Readable> {
    let name = inside.file_name()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(into)
        .ok()?;
    std::fs::set_permissions(into, std::fs::Permissions::from_mode(0o700)).ok()?;
    let dir = tempfile::Builder::new().prefix("copy-").tempdir_in(into).ok()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
    let dest = dir.path().join(name);
    if let Err(e) = copy_one(container, inside, &dest) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("[channels] {} not read from the container: {e}", inside.display());
        }
        return None;
    }
    if name.to_string_lossy().ends_with(".sqlite") {
        // Its log, if there is one: a log that cannot be taken would leave the copy out of date.
        let mut wal = inside.as_os_str().to_owned();
        wal.push("-wal");
        let wal = PathBuf::from(wal);
        let mut wal_dest = dest.as_os_str().to_owned();
        wal_dest.push("-wal");
        match copy_one(container, &wal, Path::new(&wal_dest)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!("[channels] {} not read from the container: {e}", wal.display());
                return None;
            }
        }
    }
    Some(Readable::copied(dest, dir))
}

/// One file through `docker cp -L … -`, killed after [`COPY_TIMEOUT`]. NotFound: docker says the
/// path is not there; any other failure (the daemon or the container down, a bad archive) is an
/// error, so a database is never read without a log that is there but could not be taken.
fn copy_one(container: &str, inside: &Path, dest: &Path) -> std::io::Result<()> {
    use std::sync::{Arc, Mutex};
    let src = format!("{container}:{}", inside.to_string_lossy());
    let mut child = Command::new("docker")
        .args(["cp", "-L", "--", src.as_str(), "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut out = child.stdout.take().ok_or_else(|| std::io::Error::other("no output"))?;
    let mut err = child.stderr.take().ok_or_else(|| std::io::Error::other("no output"))?;
    // The child, and whether it was reaped, under one lock: the watchdog kills it only before it is
    // reaped, so it never signals a process id the system has given to another.
    let shared = Arc::new(Mutex::new((child, false)));
    let (done, wait) = std::sync::mpsc::channel::<()>();
    let w = shared.clone();
    let watchdog = std::thread::spawn(move || {
        if wait.recv_timeout(COPY_TIMEOUT).is_err()
            && let Ok(mut g) = w.lock()
            && !g.1
        {
            let _ = g.0.kill();
        }
    });
    let got = one_file(&mut out, cap_for(inside), dest);
    if got.is_ok() {
        // The rest of the end of the archive (zeros), so docker finishes its write.
        let _ = std::io::copy(&mut (&mut out).take(16 * BLOCK as u64), &mut std::io::sink());
    } else if let Ok(mut g) = shared.lock() {
        let _ = g.0.kill();
    }
    drop(out);
    let mut said = Vec::new();
    let _ = (&mut err).take(4096).read_to_end(&mut said);
    // Reaped under the lock, polled so the watchdog can still stop a child that hangs.
    let status = loop {
        let Ok(mut g) = shared.lock() else {
            break None;
        };
        match g.0.try_wait() {
            Ok(Some(s)) => {
                g.1 = true;
                break Some(s);
            }
            Ok(None) => {}
            Err(_) => {
                g.1 = true;
                break None;
            }
        }
        drop(g);
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let _ = done.send(());
    let _ = watchdog.join();
    let said = String::from_utf8_lossy(&said);
    let not_there = said.contains("Could not find the file") || said.contains("no such file or directory");
    match (got, status) {
        (Ok(()), Some(s)) if s.success() => Ok(()),
        (_, _) if not_there => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not there")),
        (Ok(()), _) => Err(std::io::Error::other(format!("docker cp failed: {}", said.trim()))),
        (Err(e), _) if said.trim().is_empty() => Err(e),
        (Err(e), _) => Err(std::io::Error::other(format!("{e} ({})", said.trim()))),
    }
}

/// Reads a tar from `r`: optional PAX headers, then one regular file of at most `cap` bytes, written
/// to `dest` (made new, 0600), then the end of the archive. Anything else is an error.
pub fn one_file(mut r: impl Read, cap: u64, dest: &Path) -> std::io::Result<()> {
    let bad = |m: &str| std::io::Error::other(m.to_string());
    let mut header = [0u8; BLOCK];
    let mut pax_size: Option<u64> = None;
    loop {
        r.read_exact(&mut header)?;
        if header.iter().all(|b| *b == 0) {
            return Err(bad(EMPTY));
        }
        if &header[257..262] != b"ustar" {
            return Err(bad("not a tar"));
        }
        let size = octal(&header[124..136]).ok_or_else(|| bad("a tar header with no size"))?;
        match header[156] {
            // A PAX header, this entry's or the archive's: an entry's `size` record is the file's.
            b'x' | b'g' => {
                if size > PAX_CAP {
                    return Err(bad("a tar header too large"));
                }
                let mut data = vec![0u8; size as usize];
                r.read_exact(&mut data)?;
                skip(&mut r, padding(size))?;
                if header[156] == b'x'
                    && let Some(v) = pax_record(&data, "size")
                {
                    pax_size = Some(v.parse().map_err(|_| bad("a PAX size that is not a number"))?);
                }
            }
            // A regular file: the one taken.
            b'0' | 0 => {
                let size = pax_size.unwrap_or(size);
                if size > cap {
                    return Err(bad(&format!("larger than its cap ({} MB)", cap / (1024 * 1024))));
                }
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(dest)?;
                let mut left = size;
                let mut buf = [0u8; 64 * 1024];
                while left > 0 {
                    let want = left.min(buf.len() as u64) as usize;
                    let n = r.read(&mut buf[..want])?;
                    if n == 0 {
                        return Err(bad("the tar ends inside the file"));
                    }
                    f.write_all(&buf[..n])?;
                    left -= n as u64;
                }
                skip(&mut r, padding(size))?;
                // Then only the end of the archive: a block of zeros, not another entry.
                r.read_exact(&mut header)?;
                if header.iter().any(|b| *b != 0) {
                    return Err(bad("more than one entry"));
                }
                return Ok(());
            }
            // A folder, a link, a device node, anything else: not taken.
            _ => return Err(bad("not a regular file")),
        }
    }
}

/// Read past `n` bytes.
fn skip(r: &mut impl Read, n: u64) -> std::io::Result<()> {
    let copied = std::io::copy(&mut r.take(n), &mut std::io::sink())?;
    if copied != n {
        return Err(std::io::Error::other("the tar ends early"));
    }
    Ok(())
}

fn padding(n: u64) -> u64 {
    (BLOCK as u64 - n % BLOCK as u64) % BLOCK as u64
}

/// A tar number field: octal, padded with spaces or NULs either side.
fn octal(field: &[u8]) -> Option<u64> {
    let s: String = field
        .iter()
        .skip_while(|b| **b == 0 || **b == b' ')
        .take_while(|b| **b != 0 && **b != b' ')
        .map(|b| *b as char)
        .collect();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(&s, 8).ok()
}

/// A PAX record's value, read by each record's length (`<len> <key>=<value>\n`, where `<len>`
/// counts the whole record and a value may hold newlines). None when there is none or the records
/// do not add up.
fn pax_record(data: &[u8], key: &str) -> Option<String> {
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest.iter().position(|b| *b == b' ')?;
        let len: usize = std::str::from_utf8(&rest[..sp]).ok()?.parse().ok()?;
        if len <= sp + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return None;
        }
        let record = &rest[sp + 1..len - 1];
        let eq = record.iter().position(|b| *b == b'=')?;
        if &record[..eq] == key.as_bytes() {
            return std::str::from_utf8(&record[eq + 1..]).ok().map(str::to_string);
        }
        rest = &rest[len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One tar entry: a ustar header with this type, data and size field.
    fn entry_sized(kind: u8, name: &str, data: &[u8], size: &[u8]) -> Vec<u8> {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0004755"); // setuid in the container's tar: never kept
        h[124..124 + size.len()].copy_from_slice(size);
        h[156] = kind;
        h[257..262].copy_from_slice(b"ustar");
        let mut v = h.to_vec();
        v.extend_from_slice(data);
        v.resize(v.len() + padding(data.len() as u64) as usize, 0);
        v
    }

    fn entry(kind: u8, name: &str, data: &[u8]) -> Vec<u8> {
        entry_sized(kind, name, data, format!("{:011o}", data.len()).as_bytes())
    }

    fn end() -> Vec<u8> {
        vec![0u8; BLOCK * 2]
    }

    #[test]
    fn one_regular_file_within_its_cap_is_taken_0600() {
        let d = tempfile::tempdir().expect("dir");
        let cases = [
            ("plain", [entry(b'0', "a.json", b"{}"), end()].concat()),
            (
                "after a PAX header",
                [
                    entry(b'x', "PaxHeaders/a", b"15 path=a.json\n"),
                    entry(b'0', "a.json", b"{}"),
                    end(),
                ]
                .concat(),
            ),
            (
                "a size padded with spaces",
                [entry_sized(b'0', "a.json", b"{}", b"          2"), end()].concat(),
            ),
            (
                "the size a PAX record gives",
                [
                    entry(b'x', "PaxHeaders/a", b"9 size=2\n"),
                    entry_sized(b'0', "a.json", b"{}", b"00000000000"),
                    end(),
                ]
                .concat(),
            ),
        ];
        for (what, tar) in cases {
            let dest = d.path().join("a.json");
            let _ = std::fs::remove_file(&dest);
            one_file(&tar[..], FILE_CAP, &dest).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(std::fs::read(&dest).expect("read"), b"{}", "{what}");
            assert_eq!(
                std::fs::metadata(&dest).expect("m").permissions().mode() & 0o7777,
                0o600,
                "{what}"
            );
        }
    }

    #[test]
    fn a_folder_a_link_a_device_two_files_too_much_or_nothing_is_refused() {
        let d = tempfile::tempdir().expect("dir");
        let cases: Vec<(&str, Vec<u8>, u64)> = vec![
            ("a folder", [entry(b'5', "credentials/", b""), end()].concat(), FILE_CAP),
            ("a link", [entry(b'2', "x", b""), end()].concat(), FILE_CAP),
            ("a device", [entry(b'3', "x", b""), end()].concat(), FILE_CAP),
            (
                "two files",
                [entry(b'0', "a", b"1"), entry(b'0', "b", b"2"), end()].concat(),
                FILE_CAP,
            ),
            ("over the cap", [entry(b'0', "a", &[7u8; 2048]), end()].concat(), 1024),
            ("cut short", entry(b'0', "a", b"12345")[..BLOCK + 2].to_vec(), FILE_CAP),
            ("an empty archive", end(), FILE_CAP),
            ("not a tar", vec![b'x'; BLOCK * 3], FILE_CAP),
        ];
        for (what, tar, cap) in cases {
            let dest = d.path().join("f");
            let _ = std::fs::remove_file(&dest);
            assert!(one_file(&tar[..], cap, &dest).is_err(), "{what}");
        }
        assert_eq!(
            one_file(&end()[..], FILE_CAP, &d.path().join("g")).map_err(|e| e.to_string()),
            Err(EMPTY.to_string()),
            "an empty archive is told apart: nothing there"
        );
    }

    /// Records are read by their length: a value with a newline in it does not hide the next one.
    #[test]
    fn pax_records_are_read_by_their_length() {
        let data = b"27 path=a\nsize=999999999\nb\n9 size=2\n";
        assert_eq!(pax_record(data, "size").as_deref(), Some("2"));
        assert_eq!(pax_record(data, "path").as_deref(), Some("a\nsize=999999999\nb"));
        assert_eq!(pax_record(b"99 size=2\n", "size"), None, "a length past the data");
    }

    #[test]
    fn databases_get_the_larger_cap() {
        assert_eq!(cap_for(Path::new("/x/state/openclaw.sqlite")), DB_CAP);
        assert_eq!(cap_for(Path::new("/x/state/openclaw.sqlite-wal")), DB_CAP);
        assert_eq!(cap_for(Path::new("/x/credentials/telegram-pairing.json")), FILE_CAP);
    }
}
