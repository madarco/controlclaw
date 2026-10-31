//! `drive.*`: Google Drive folders the agents may use, and the accounts that reach them
//! (`channels/drive/mod.rs`).

use serde::{Deserialize, Serialize};

use super::google::AgentRef;
use crate::Extra;

/// Propose a change to the Drive accounts or folders; it waits for a code unless nobody can be
/// asked yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    /// `connect_account`, `replace_account`, `forget_account`, `add_folder`, `edit_folder`,
    /// `remove_folder`, `assign` or `unassign`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    /// The account's credential, from the command's encrypted half: `{refresh}` for OAuth, or a
    /// service account's `{clientEmail, privateKey, tokenUri, subject?}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<Folder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<AgentRef>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// `oauth`, `service_account` or `google_account` (borrowed from the Google account).
    pub kind: String,
    /// The Drive read or write scope; any other scope is refused.
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    /// `{tokenEndpoint, clientId, clientSecret}` for an OAuth account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: String,
    pub folder_id: String,
    pub name: String,
    /// `ro` or `rw`.
    pub mode: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Send an agent its folders again, with its current hostname and name.
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
