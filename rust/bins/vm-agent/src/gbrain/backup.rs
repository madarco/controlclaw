//! The brain's backup, box side (`gbrain-backup.ts`, docs/plans/gbrain.md §10).
//!
//! What a brain's archive holds is a copy made for it, not a live directory: a `pg_dump` of
//! GBrain's database, its pages and its settings (`config.json`), never its env file, which holds
//! the database password, the owner credential and the model key's placeholder. A root helper with
//! fixed verbs and fixed paths (`cc-gbrain-backup`, Ansible) does the privileged half: `stage` dumps
//! and copies into the stage folder, `clean` removes it, `restore` loads the restored folder back
//! with GBrain stopped. The sealing, upload and download are W7's backup service, so the brain's
//! archive gets the same envelope and keys as an agent's.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cc_http::BoxFuture;

use super::gate::BrainGate;
use crate::boxside::backup::StagedKind;
use crate::platform::common::Deps;

/// The kinds a brain backs up (`BRAIN_KINDS`): its own, and only that.
pub const BRAIN_KINDS: &[&str] = &["gbrain"];

pub const GBRAIN_BACKUP_DIR: &str = "/opt/controlclaw/state/gbrain-backup";
const HELPER: &str = "/usr/local/bin/cc-gbrain-backup";
/// A dump of a large brain takes minutes; a restore more (the load, then the index builds).
const STAGE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const RESTORE_TIMEOUT: Duration = Duration::from_secs(50 * 60);
const CLEAN_TIMEOUT: Duration = Duration::from_secs(60);

/// `gbrainStagedKind`, with the TS's `apply` wrapper from gbrain.ts: a restored database has the
/// backup's token table, so the connected agents get new tokens.
#[derive(Clone)]
pub struct BrainStaged {
    pub deps: Deps,
    pub gate: Arc<BrainGate>,
    pub dir: PathBuf,
}

impl BrainStaged {
    pub fn new(deps: Deps, gate: Arc<BrainGate>) -> Self {
        Self {
            deps,
            gate,
            dir: PathBuf::from(GBRAIN_BACKUP_DIR),
        }
    }

    /// `sudo <helper> <verb>`; the error names what could not be done and the helper's line.
    async fn run(&self, verb: &str, timeout: Duration, what: &str) -> Result<(), String> {
        self.deps
            .exec("sudo", &[HELPER, verb], timeout, None, &[])
            .await
            .map(|_| ())
            .map_err(|e| format!("could not {what}: {e}"))
    }
}

impl StagedKind for BrainStaged {
    fn kind(&self) -> &'static str {
        "gbrain"
    }
    fn root(&self) -> PathBuf {
        self.dir.join("stage")
    }
    fn restore_dir(&self) -> PathBuf {
        self.dir.join("restoring")
    }
    fn prepare(&self) -> BoxFuture<Result<(), String>> {
        let me = self.clone();
        Box::pin(async move { me.run("stage", STAGE_TIMEOUT, "copy the brain for its backup").await })
    }
    fn release(&self) -> BoxFuture<Result<(), String>> {
        let me = self.clone();
        Box::pin(async move { me.run("clean", CLEAN_TIMEOUT, "remove the brain's staged copy").await })
    }
    fn apply(&self, _dir: PathBuf) -> BoxFuture<Result<(), String>> {
        let me = self.clone();
        Box::pin(async move {
            me.run("restore", RESTORE_TIMEOUT, "load the backup into the brain")
                .await?;
            let (reissued, failed) = me.gate.reissue_all().await;
            tracing::info!(
                "[backup] restored the brain; {reissued} agent token(s) reissued{}",
                if failed.is_empty() {
                    String::new()
                } else {
                    format!(", {} failed: reconnect those agents from the Brain page", failed.len())
                }
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
