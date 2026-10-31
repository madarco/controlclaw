//! `search.*`: the organization's web search provider and its key (`core/search.rs`).

use serde::{Deserialize, Serialize};

use super::google::AgentRef;
use crate::Extra;

/// Add, replace or remove the web search provider; it waits for a code unless nobody can be asked
/// yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    /// `add`, `replace` or `remove`.
    pub kind: String,
    pub credential_id: String,
    pub provider: String,
    /// `provider` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// The stand-in the agents see instead of the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// `{id, package}`: the OpenClaw plugin that serves the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// String values only; others are dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Map<String, serde_json::Value>>,
    /// `{matchDomain, locations}`: where the proxy puts the key in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_provider: Option<String>,
    /// The credential id a `replace` takes the place of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    /// `[{id}]`: credentials to drop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<AgentRef>>,
    /// `{apiKey}`, from the command's encrypted half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Apply the stored provider on one agent again.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// An agent is gone: drop it. No code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forget {
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}
