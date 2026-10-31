//! `logins.*` payloads: website logins kept on the firewall (`integrations/logins/firewall.rs`).
//! Codes are per login, so confirm and cancel also name the login's `id`.

use serde::{Deserialize, Serialize};

use crate::Extra;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Update,
    Delete,
}

/// `logins.propose`: change a login's name, sites, agents or mode, or delete it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub id: String,
    pub action: Action,
    /// `update` only, as are the fields below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sites: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_ids: Option<Vec<String>>,
    /// `swap` or `type`; absent keeps the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `logins.confirm`: the code for a change to the login `id`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confirm {
    pub id: String,
    pub change_id: String,
    #[serde(default)]
    pub code: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `logins.cancel`: drop the change waiting on the login `id`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
