//! `google.*`: the organization's Google account (Gmail, Calendar, Drive, Contacts, Sheets, Docs)
//! and which agents get it (`channels/google/mod.rs`).

use serde::{Deserialize, Serialize};

use crate::Extra;

/// An agent a change names; `name` is what the code message calls it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRef {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Propose a change to the account; it waits for a code unless nobody can be asked yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    /// `connect_account`, `replace_account`, `forget_account`, `grant_agent`, `revoke_agent` or
    /// `set_services`.
    pub kind: String,
    /// The organization's own OAuth client, for a connect or replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<OAuthClient>,
    /// The client's secret, at the top level: it rides the command's encrypted half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// `gmail`, `calendar`, `drive`, `contacts`, `sheets`, `docs`; unknown names are dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    /// `read-send` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gmail_scope: Option<String>,
    /// `readonly` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive_scope: Option<String>,
    /// `external_testing` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<AgentRef>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClient {
    pub client_id: String,
    pub redirect_uri: String,
    /// Google's when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The OAuth redirect's query, relayed by the callback page: the firewall exchanges the code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callback {
    /// Must match the pending consent's state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Google's error, when the person refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Send the account to an agent again, with its current hostname and name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// An agent was deleted: drop it. No code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forget {
    pub vm_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}
