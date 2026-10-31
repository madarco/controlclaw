//! `kill.*` payloads: the emergency stop (`rust/bins/mitm-agent/src/core/kill.rs`).

use serde::{Deserialize, Serialize};

use super::channels::AgentRef;
use crate::Extra;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Org,
    Agent,
}

/// `kill.engage`: stop the whole organization or one agent, at once and with no code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Engage {
    pub change_id: String,
    pub scope: Scope,
    /// Required when `scope` is `agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    /// The agents the stop reaches, so the firewall can stop their OpenClaw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<AgentRef>>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `kill.release`: lift a stop; the same fields as [`Engage`], and it needs a code.
pub type Release = Engage;

/// `kill.confirm`: the code for a release, with the scope it was for.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confirm {
    pub change_id: String,
    #[serde(default)]
    pub code: String,
    /// Anything but `agent` means the organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `kill.cancel`: drop a release waiting for its code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
