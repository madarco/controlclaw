//! Writing and re-reading the shared files, the way each side does it today.
//!
//! Writes are whole-file and atomic (temp file + rename), so a reader never sees half a file. The
//! temp name, the formatting and the mode differ by file because the TS writers differ; each file's
//! [`FileSpec`] records which, so a Rust writer produces the same bytes as the TS one.
//!
//! Reads follow `addon.py`: [`MtimeCache`] is `_Cache` / `_DictCache` (reload when the mtime
//! changes), [`StatCache`] is the content rules' `(mtime_ns, size)` key, and [`read_fresh`] is the
//! lease files, which are read on every call so a missing or broken file revokes at once.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Where the temp file of an atomic write goes: `.<name>.tmp` (sync.ts `writeProxyConfig`,
/// grants.ts) or `<path>.tmp` (meetings.ts, phone-stream.ts, content-rules.ts, own-messages.ts,
/// addon.py).
pub use cc_store::TmpName;

/// How one shared file is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSpec {
    pub name: &'static str,
    pub tmp: TmpName,
    /// `JSON.stringify(v, null, 2)` when true, `JSON.stringify(v)` when false.
    pub pretty: bool,
    pub mode: u32,
}

impl FileSpec {
    pub const RULES: FileSpec = FileSpec {
        name: "rules.json",
        tmp: TmpName::HiddenPrefix,
        pretty: true,
        mode: 0o600,
    };
    pub const CREDENTIALS: FileSpec = FileSpec {
        name: "credentials.json",
        tmp: TmpName::HiddenPrefix,
        pretty: true,
        mode: 0o600,
    };
    pub const IDENTITIES: FileSpec = FileSpec {
        name: "identities.json",
        tmp: TmpName::HiddenPrefix,
        pretty: true,
        mode: 0o600,
    };
    pub const EXIT: FileSpec = FileSpec {
        name: "exit.json",
        tmp: TmpName::HiddenPrefix,
        pretty: true,
        mode: 0o600,
    };
    pub const GRANTS: FileSpec = FileSpec {
        name: "grants.json",
        tmp: TmpName::HiddenPrefix,
        pretty: true,
        mode: 0o600,
    };
    pub const MEETING_MEDIA: FileSpec = FileSpec {
        name: "meeting-media.json",
        tmp: TmpName::Suffix,
        pretty: false,
        mode: 0o600,
    };
    pub const PHONE_MEDIA: FileSpec = FileSpec {
        name: "phone-media.json",
        tmp: TmpName::Suffix,
        pretty: false,
        mode: 0o600,
    };
    pub const CONTENT_RULES: FileSpec = FileSpec {
        name: "content-rules.json",
        tmp: TmpName::Suffix,
        pretty: false,
        mode: 0o600,
    };
    /// 0644 on purpose (own-messages.ts): it holds a time, no text.
    pub const CONTENT_OWN: FileSpec = FileSpec {
        name: "content-own.json",
        tmp: TmpName::Suffix,
        pretty: false,
        mode: 0o644,
    };
    /// Written by the proxy (addon.py `_save_login_targets`), read by the agent.
    pub const LOGIN_TARGETS: FileSpec = FileSpec {
        name: "login-targets.json",
        tmp: TmpName::Suffix,
        pretty: false,
        mode: 0o600,
    };

    pub fn path_in(&self, dir: &Path) -> PathBuf {
        dir.join(self.name)
    }
}

/// Write `value` to `dir/<spec.name>` atomically: folder made first (the tmpfs is empty after a
/// reboot), temp file with the spec's mode, then rename. The rename gives the file a new mtime,
/// which is what tells the reader to reload.
pub fn write_atomic<T: Serialize + ?Sized>(dir: &Path, spec: &FileSpec, value: &T) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let bytes = if spec.pretty {
        serde_json::to_vec_pretty(value)?
    } else {
        serde_json::to_vec(value)?
    };
    cc_store::write_atomic(&spec.path_in(dir), &bytes, spec.mode, spec.tmp)
}

/// What a file that is not there means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingPolicy {
    /// Keep what was loaded last (`_Cache`, and grants: a vanished file is more likely a read error
    /// than a revocation).
    Keep,
    /// Forget it (`_DictCache(missing_is_empty=True)`: the exit file IS the credential, and
    /// deleting it is how one is revoked).
    Empty,
}

/// What a file that will not parse means. Either way the mtime is not taken, so the next read
/// tries again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// Keep the last good value (`_Cache`).
    KeepLast,
    /// Use the empty value (`_DictCache`).
    Empty,
}

struct CacheState<T> {
    mtime: Option<SystemTime>,
    data: Arc<T>,
}

/// A JSON file re-read when its mtime changes.
pub struct MtimeCache<T> {
    path: PathBuf,
    missing: MissingPolicy,
    on_error: OnError,
    state: Mutex<CacheState<T>>,
}

impl<T: DeserializeOwned + Default> MtimeCache<T> {
    pub fn new(path: impl Into<PathBuf>, missing: MissingPolicy, on_error: OnError) -> Self {
        Self {
            path: path.into(),
            missing,
            on_error,
            state: Mutex::new(CacheState {
                mtime: None,
                data: Arc::new(T::default()),
            }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self) -> Arc<T> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mtime = match fs::metadata(&self.path).and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(_) => {
                if self.missing == MissingPolicy::Empty {
                    st.mtime = None;
                    st.data = Arc::new(T::default());
                }
                return st.data.clone();
            }
        };
        if st.mtime != Some(mtime) {
            match fs::read(&self.path).map_err(ReadError::Io).and_then(|b| parse(&b)) {
                Ok(v) => {
                    st.data = Arc::new(v);
                    st.mtime = Some(mtime);
                }
                Err(_) if self.on_error == OnError::Empty => st.data = Arc::new(T::default()),
                Err(_) => {}
            }
        }
        st.data.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ReadError> {
    Ok(serde_json::from_slice(bytes)?)
}

/// A file keyed by `(mtime_ns, size)` that must exist: no file is an error, not "nothing"
/// (addon.py `content_rules`: after a reboot the proxy can start before the agent has written it).
pub struct StatCache<T> {
    path: PathBuf,
    state: Mutex<Option<(StatKey, Arc<T>)>>,
}

/// `(mtime_ns, size)`.
type StatKey = (i128, u64);

impl<T: DeserializeOwned> StatCache<T> {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            state: Mutex::new(None),
        }
    }

    pub fn get(&self) -> Result<Arc<T>, ReadError> {
        let meta = fs::metadata(&self.path)?;
        let key = (mtime_ns(&meta), meta.len());
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((k, v)) = st.as_ref()
            && *k == key
        {
            return Ok(v.clone());
        }
        let v = Arc::new(parse::<T>(&fs::read(&self.path)?)?);
        *st = Some((key, v.clone()));
        Ok(v)
    }
}

fn mtime_ns(meta: &fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec())
}

/// Read a file on every call. `None` when it is missing or broken: for the lease files that
/// revokes every lease, which is the point.
pub fn read_fresh<T: DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    type Res = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn writes_like_the_ts_side() -> Res {
        let dir = tempfile::tempdir()?;
        write_atomic(dir.path(), &FileSpec::RULES, &serde_json::json!([{"a": 1}]))?;
        assert_eq!(
            fs::read_to_string(dir.path().join("rules.json"))?,
            "[\n  {\n    \"a\": 1\n  }\n]"
        );
        assert_eq!(fs::metadata(dir.path().join("rules.json"))?.mode() & 0o777, 0o600);
        assert!(!dir.path().join(".rules.json.tmp").exists());
        write_atomic(dir.path(), &FileSpec::CONTENT_OWN, &serde_json::json!({"until": 1.5}))?;
        assert_eq!(
            fs::read_to_string(dir.path().join("content-own.json"))?,
            r#"{"until":1.5}"#
        );
        assert_eq!(fs::metadata(dir.path().join("content-own.json"))?.mode() & 0o777, 0o644);
        Ok(())
    }

    #[test]
    fn mtime_cache_follows_the_addon() -> Res {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("x.json");
        let keep: MtimeCache<Vec<u32>> = MtimeCache::new(&path, MissingPolicy::Keep, OnError::KeepLast);
        let empty: MtimeCache<Vec<u32>> = MtimeCache::new(&path, MissingPolicy::Empty, OnError::Empty);
        assert!(keep.get().is_empty());
        fs::write(&path, "[1,2]")?;
        assert_eq!(*keep.get(), vec![1, 2]);
        assert_eq!(*empty.get(), vec![1, 2]);
        // A broken file: the list cache keeps its last value, the dict-style cache empties.
        fs::write(&path, "[1,")?;
        set_mtime_later(&path)?;
        assert_eq!(*keep.get(), vec![1, 2]);
        assert!(empty.get().is_empty());
        fs::remove_file(&path)?;
        assert_eq!(*keep.get(), vec![1, 2]);
        assert!(empty.get().is_empty());
        Ok(())
    }

    #[test]
    fn stat_cache_refuses_a_missing_file() -> Res {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("content-rules.json");
        let c: StatCache<serde_json::Value> = StatCache::new(&path);
        assert!(c.get().is_err());
        fs::write(&path, r#"{"version":1,"rules":[]}"#)?;
        assert_eq!(c.get()?["version"], 1);
        assert!(read_fresh::<serde_json::Value>(&dir.path().join("nope")).is_none());
        Ok(())
    }

    // Same-second writes can share an mtime on some filesystems; move it on so the test is exact.
    fn set_mtime_later(path: &Path) -> io::Result<()> {
        let f = fs::File::options().write(true).open(path)?;
        f.set_modified(SystemTime::now() + std::time::Duration::from_secs(5))
    }
}
