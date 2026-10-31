//! Disk headroom for a Firewall Doctor repair (`doctor-reserve.ts`, doctor-rescue.md, "Disk
//! full"). A file of real zeros next to the transcripts, deleted when a firewall repair is proposed
//! and written again when it ends or is dropped, and at start-up. Best effort both ways, in 1 MiB
//! steps, one rewrite at a time.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// Firewall Doctor (I7) makes and uses the reserve.
#[allow(dead_code)]
pub const DOCTOR_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

pub struct Reserve {
    path: PathBuf,
    bytes: u64,
    released: Arc<AtomicBool>,
    writing: Arc<AtomicBool>,
}

impl Reserve {
    pub fn new(path: PathBuf, bytes: u64) -> Self {
        Self {
            path,
            bytes,
            released: Arc::default(),
            writing: Arc::default(),
        }
    }

    pub fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_file(&self.path);
    }

    pub fn restore(&self) {
        self.released.store(false, Ordering::SeqCst);
        if self.writing.swap(true, Ordering::SeqCst) {
            return;
        }
        let (path, bytes, released, writing) = (
            self.path.clone(),
            self.bytes,
            self.released.clone(),
            self.writing.clone(),
        );
        tokio::spawn(async move {
            let _ = write(&path, bytes, &released).await;
            // A repair proposed while this was writing wants the space now.
            if released.load(Ordering::SeqCst) {
                let _ = std::fs::remove_file(&path);
            }
            writing.store(false, Ordering::SeqCst);
        });
    }
}

async fn write(path: &PathBuf, bytes: u64, released: &AtomicBool) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if tokio::fs::metadata(path).await.is_ok_and(|m| m.len() == bytes) {
        return Ok(());
    }
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    let chunk = vec![0u8; 1024 * 1024];
    let mut written = 0u64;
    while written < bytes && !released.load(Ordering::SeqCst) {
        let n = (bytes - written).min(chunk.len() as u64) as usize;
        f.write_all(&chunk[..n]).await?;
        written += n as u64;
    }
    f.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_reserve_is_real_bytes_freed_at_once_and_written_back_without_blocking() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("reserve");
        let r = Reserve::new(path.clone(), 3 * 1024 * 1024);
        r.restore();
        for _ in 0..100 {
            if std::fs::metadata(&path).is_ok_and(|m| m.len() == 3 * 1024 * 1024) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(std::fs::metadata(&path).expect("meta").len(), 3 * 1024 * 1024);
        assert!(std::fs::read(&path).expect("read").iter().all(|b| *b == 0));
        r.release();
        assert!(!path.exists(), "freed at once");
        r.restore();
        r.release();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!path.exists(), "a release while writing wins");
    }
}
