//! The crypto formats the boxes keep on disk and send to the console, byte-compatible with the TS
//! code: what one side seals, the other opens.
//!
//! - [`enc_file`]: the firewall's small encrypted JSON stores (`packages/mitm-agent/src/enc-file.ts`).
//! - [`secret_store`]: the two-payload record the console holds (`packages/secret-store`).
//! - [`envelope`]: the backup envelope (`packages/backup-envelope/src/envelope.ts`).
//! - [`store_health`]: which stores this box could not read (`store-health.ts`).
//!
//! Recovery identity, the LUKS recovery seal, the recovery-confirm challenge and the archive file
//! container are ported by workstream W3 (`docs/plans/rust-workstreams/`).

pub mod b64;
pub mod ct;
pub use ct::{ct_eq, sha256_ct_eq};
pub mod enc_file;
pub mod envelope;
pub mod recovery;
pub mod secret_store;
pub mod store_health;

/// Every error here carries the text the TS code would show, so a message that reaches the console
/// or a log reads the same from either build.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String);

impl CryptoError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type Result<T, E = CryptoError> = std::result::Result<T, E>;
