//! `health.*` payloads (`rust/bins/mitm-agent/src/core/health.rs`).

use serde::{Deserialize, Serialize};

use crate::Extra;

/// `health.probe`: read one agent's health now. An unknown or missing `vmId` fails the command.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    #[serde(default)]
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}
