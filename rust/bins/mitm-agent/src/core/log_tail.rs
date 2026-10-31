//! Following a JSONL log with a cursor `{inode, offset}` kept in a file (`log-tail.ts`). Each
//! consumer (the activity shippers, the AI review) has its own cursor, so they read one log
//! independently. The cursor moves only after the consumer took a batch: at-least-once.
//!
//! The proxy rotates the live file to `<path>.1` past a size cap. When the live inode changed, the
//! rest of `.1` is read first (only when `.1` is still the cursor's file), then the new live file
//! from 0. A live file that shrank under the same inode (truncated by hand) restarts at 0.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

const MAX_CHUNK: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Cursor {
    inode: u64,
    offset: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TailResult {
    pub read: usize,
    pub skipped: usize,
}

pub struct LogTail {
    log_path: PathBuf,
    cursor_path: PathBuf,
    pub batch_size: usize,
    cursor: Cursor,
}

struct Batch {
    records: Vec<Value>,
    consumed: u64,
    skipped: usize,
}

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

// `skip_to_end`, `has_cursor` and `read_all_records` are the AI review's (W4).
#[allow(dead_code)]
impl LogTail {
    pub fn new(log_path: impl Into<PathBuf>, cursor_path: impl Into<PathBuf>, batch_size: Option<usize>) -> Self {
        let cursor_path = cursor_path.into();
        let cursor = std::fs::read_to_string(&cursor_path)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|c| {
                Some(Cursor {
                    inode: c.get("inode")?.as_f64()? as u64,
                    offset: c.get("offset")?.as_f64()? as u64,
                })
            })
            .unwrap_or_default();
        Self {
            log_path: log_path.into(),
            cursor_path,
            batch_size: batch_size.unwrap_or(200),
            cursor,
        }
    }

    fn save_cursor(&self) {
        let body = format!(r#"{{"inode":{},"offset":{}}}"#, self.cursor.inode, self.cursor.offset);
        if let Err(e) = cc_store::write_atomic(
            &self.cursor_path,
            body.as_bytes(),
            0o600,
            cc_store::TmpName::HiddenPrefix,
        ) {
            tracing::error!("[log-tail] could not save {}: {e}", self.cursor_path.display());
        }
    }

    /// Start at the end of the live file  (a consumer that only wants new records).
    pub fn skip_to_end(&mut self) {
        let Ok(live) = std::fs::metadata(&self.log_path) else {
            return;
        };
        self.cursor = Cursor {
            inode: live.ino(),
            offset: live.len(),
        };
        self.save_cursor();
    }

    pub fn has_cursor(&self) -> bool {
        self.cursor.inode != 0
    }

    /// One pass: every unread batch to `on_batch` until caught up or a batch is refused (false).
    pub async fn drain<F, Fut>(&mut self, mut on_batch: F) -> TailResult
    where
        F: FnMut(Vec<Value>) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let mut total = TailResult::default();
        let Ok(live) = std::fs::metadata(&self.log_path) else {
            return total;
        };
        let live_inode = live.ino();
        if self.cursor.inode != 0 && self.cursor.inode != live_inode {
            // The proxy rotated. Finish the previous file first, if it is the one we were reading.
            let rotated = with_suffix(&self.log_path, ".1");
            if std::fs::metadata(&rotated).is_ok_and(|m| m.ino() == self.cursor.inode) {
                let done = self.drain_from(&rotated, &mut on_batch, &mut total).await;
                if !done {
                    return total;
                }
            }
            self.cursor = Cursor {
                inode: live_inode,
                offset: 0,
            };
            self.save_cursor();
        } else if self.cursor.inode == 0 {
            self.cursor = Cursor {
                inode: live_inode,
                offset: 0,
            };
        } else if live.len() < self.cursor.offset {
            self.cursor.offset = 0;
        }
        let path = self.log_path.clone();
        self.drain_from(&path, &mut on_batch, &mut total).await;
        total
    }

    async fn drain_from<F, Fut>(&mut self, path: &Path, on_batch: &mut F, total: &mut TailResult) -> bool
    where
        F: FnMut(Vec<Value>) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        loop {
            // A read that fails ends the pass where it is, as the TS throw does: the cursor stays
            // on this file, so a rotated `.1` is finished on the next pass before the live one.
            let batch = match self.read_batch(path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("[log-tail] could not read {}: {e}", path.display());
                    return false;
                }
            };
            total.skipped += batch.skipped;
            if batch.records.is_empty() {
                if batch.consumed > 0 {
                    self.cursor.offset += batch.consumed;
                    self.save_cursor();
                    continue;
                }
                return true;
            }
            let n = batch.records.len();
            if !on_batch(batch.records).await {
                return false;
            }
            total.read += n;
            self.cursor.offset += batch.consumed;
            self.save_cursor();
            if n < self.batch_size {
                return true;
            }
        }
    }

    fn read_batch(&self, path: &Path) -> std::io::Result<Batch> {
        let mut f = File::open(path)?;
        let size = f.metadata()?.len();
        let want = MAX_CHUNK.min(size.saturating_sub(self.cursor.offset));
        let mut out = Batch {
            records: Vec::new(),
            consumed: 0,
            skipped: 0,
        };
        if want == 0 {
            return Ok(out);
        }
        f.seek(SeekFrom::Start(self.cursor.offset))?;
        let mut buf = Vec::with_capacity(want as usize);
        f.take(want).read_to_end(&mut buf)?;
        let mut from = 0usize;
        while out.records.len() < self.batch_size {
            let Some(nl) = buf[from..].iter().position(|b| *b == b'\n') else {
                break; // a trailing partial line waits for the next pass
            };
            let line = String::from_utf8_lossy(&buf[from..from + nl]).into_owned();
            from += nl + 1;
            out.consumed = from as u64;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&line) {
                Ok(v) => out.records.push(v),
                Err(_) => out.skipped += 1,
            }
        }
        Ok(out)
    }
}

#[allow(dead_code)]
/// `readAllRecords`: every complete record on disk, `<path>.1` then the live file.
pub fn read_all_records(log_path: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    for path in [with_suffix(log_path, ".1"), log_path.to_path_buf()] {
        let Ok(text) = std::fs::read(&path) else { continue };
        for line in String::from_utf8_lossy(&text).split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str(line) {
                out.push(v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(p: &Path, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(p)
            .expect("open");
        f.write_all(text.as_bytes()).expect("write");
    }

    async fn collect(t: &mut LogTail) -> (Vec<Value>, TailResult) {
        let mut got = Vec::new();
        let r = t
            .drain(|b| {
                got.extend(b);
                async { true }
            })
            .await;
        (got, r)
    }

    #[tokio::test]
    async fn follows_rotation_and_partial_lines() {
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("traffic.jsonl");
        let cur = d.path().join("traffic.jsonl.cursor");
        append(&log, "{\"a\":1}\nnot json\n\n{\"a\":2}\n{\"a\":");
        let mut t = LogTail::new(&log, &cur, None);
        let (got, r) = collect(&mut t).await;
        assert_eq!(got, vec![serde_json::json!({"a":1}), serde_json::json!({"a":2})]);
        assert_eq!(r, TailResult { read: 2, skipped: 1 });
        append(&log, "3}\n");
        std::fs::rename(&log, d.path().join("traffic.jsonl.1")).expect("rotate");
        append(&log, "{\"a\":4}\n");
        let mut t = LogTail::new(&log, &cur, None);
        let (got, _) = collect(&mut t).await;
        assert_eq!(got, vec![serde_json::json!({"a":3}), serde_json::json!({"a":4})]);
        let (got, _) = collect(&mut t).await;
        assert!(got.is_empty());
        // Truncated in place: start again at 0.
        std::fs::write(&log, "{}\n").expect("truncate");
        let (got, _) = collect(&mut t).await;
        assert_eq!(got, vec![serde_json::json!({})]);
        let saved = std::fs::read_to_string(&cur).expect("cursor");
        assert!(saved.starts_with("{\"inode\":") && saved.ends_with(",\"offset\":3}"));
    }

    #[tokio::test]
    async fn a_rotated_file_that_cannot_be_read_is_finished_later() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("traffic.jsonl");
        let old = d.path().join("traffic.jsonl.1");
        append(&log, "{\"a\":1}\n");
        let mut t = LogTail::new(&log, d.path().join("c"), None);
        assert_eq!(collect(&mut t).await.0.len(), 1);
        append(&log, "{\"a\":2}\n");
        std::fs::rename(&log, &old).expect("rotate");
        append(&log, "{\"a\":3}\n");
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::File::open(&old).is_ok() {
            return; // root reads it anyway: nothing to test here
        }
        let (got, _) = collect(&mut t).await;
        assert!(got.is_empty(), "the live file waits for the rotated one");
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let (got, _) = collect(&mut t).await;
        assert_eq!(got, vec![serde_json::json!({"a":2}), serde_json::json!({"a":3})]);
    }

    #[tokio::test]
    async fn a_refused_batch_stays() {
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("l.jsonl");
        append(&log, "{\"a\":1}\n");
        let mut t = LogTail::new(&log, d.path().join("c"), None);
        let r = t.drain(|_| async { false }).await;
        assert_eq!(r.read, 0);
        let (got, _) = collect(&mut t).await;
        assert_eq!(got.len(), 1);
    }
}
