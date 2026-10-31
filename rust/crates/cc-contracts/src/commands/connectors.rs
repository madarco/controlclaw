//! `connectors.*` payloads: app connections through OpenConnector (`integrations/connectors/firewall.rs`).

use serde::{Deserialize, Serialize};

use crate::Extra;

/// An agent a change names. Only `vmId` is needed; the name defaults to it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `connectors.read`: `kind` is `setup` (with `service`) or `connections`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Read {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// What a change does to a connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Connect,
    Replace,
    Remove,
    Assign,
    Unassign,
    OauthConnect,
    OauthReconnect,
}

/// `connectors.propose`: connect, change or remove an app connection, or who may use it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub kind: Kind,
    /// The catalog id of the app.
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Non-secret settings of the connection, string values only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<crate::Extra>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_option_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<Agent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    #[serde(flatten)]
    pub rest: Extra,
}

/// The part the SaaS stores encrypted until hand-out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<crate::Extra>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_secret: Option<crate::Extra>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `connectors.callback`: the OAuth redirect's query, relayed. `state` must be one the firewall minted.
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

/// `connectors.push`: an agent came up; send it its connections again, with its address if it moved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `connectors.forget`: an agent was deleted; revoke its token and drop its grants, with no code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forget {
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}
