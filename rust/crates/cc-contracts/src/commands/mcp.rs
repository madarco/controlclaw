//! `mcpservers.*` payloads: the organization's MCP servers (`integrations/mcp/servers.rs`).
//! `mcpcatalog.read` takes none.

use serde::{Deserialize, Serialize};

use crate::Extra;

/// What a change does to a server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Add,
    Replace,
    Reconnect,
    Remove,
    Assign,
    Unassign,
}

/// An agent `add`, `assign` and `unassign` name. Other kinds ignore the list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `mcpservers.propose`: add, change or remove a server, or who may use it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub kind: Kind,
    pub name: String,
    /// `add` only: a public https address with no query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `none`, `header` or `oauth`; anything else is `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<Agent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The part the SaaS stores encrypted until hand-out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `mcpservers.callback`: the OAuth redirect's query, relayed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callback {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `mcpservers.tools`: read the server `name`'s tool list again.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tools {
    pub name: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `mcpservers.push`: an agent came up; send it its servers again.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `mcpservers.forget`: an agent was deleted; take it off every server, with no code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forget {
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}
