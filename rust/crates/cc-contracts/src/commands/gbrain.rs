//! `gbrain.*` payloads: which agents may use the brain (`rust/bins/mitm-agent/src/core/gbrain.rs`).
//! The SaaS console sends `propose`, `confirm`, `cancel` and `disconnect`; a standalone firewall's
//! panel sends them too, through the admin's scope (no code shown), and `read`, `lock`, `status` and
//! `model`, which serve its Brain page. `gbrain.client.*` (outside AI apps) stay the SaaS's.

use serde::{Deserialize, Serialize};

use crate::Extra;

/// Read only, or read and write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Read,
    ReadWrite,
}

/// `gbrain.propose`: connect an agent, or change its scope. Widening needs a code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub agent_vm_id: String,
    pub brain_vm_id: String,
    pub scope: Scope,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `gbrain.confirm`: the code for a waiting connection, with the agent it was for.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confirm {
    pub change_id: String,
    pub agent_vm_id: String,
    #[serde(default)]
    pub code: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `gbrain.cancel`: drop a connection waiting for its code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_vm_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `gbrain.disconnect`: take an agent off the brain, with no code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disconnect {
    pub agent_vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `gbrain.lock`: every agent off the brain (or back on), connections kept, with no code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Lock {
    pub locked: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `gbrain.model`: the brain's model, as the brain names it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Model {
    pub model: String,
    #[serde(flatten)]
    pub extra: Extra,
}
