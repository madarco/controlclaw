//! `secrets.*`: named secrets the proxy puts into the agents' requests on chosen hosts, so the
//! agents never hold them (`channels/secrets.rs`).

use serde::{Deserialize, Serialize};

use crate::Extra;

/// Create, update, replace or delete a secret; every change waits for a code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    /// Up to 100 characters.
    pub change_id: String,
    /// `create`, `update`, `replace` or `delete`.
    pub action: String,
    pub name: String,
    /// Where the value goes; for `create` and `update`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
    /// The agents that get it (at most 100); for `create` and `update`, each one also in `agents`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<Target>>,
    /// `{value}`, from the command's encrypted half; for `create` and `replace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rules {
    /// 1 to 30 hosts; `*.example.com` covers the subdomains.
    pub hosts: Vec<String>,
    /// 1 to 20 places in the request.
    pub locations: Vec<Location>,
}

/// `{kind: header, name, prefix?}` or `{kind: query, name}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Location {
    Header {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    Query {
        name: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub vm_id: String,
    pub hostname: String,
}

/// Tell the agents about the secrets again, after a push that failed. No fields.
pub type Retry = super::Empty;

/// `{changeId, code, name}`: the code is asked per secret, so the confirm names it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confirm {
    pub change_id: String,
    #[serde(default)]
    pub code: String,
    pub name: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `{changeId, name}`: drop the change waiting for this secret's code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    pub change_id: String,
    pub name: String,
    #[serde(flatten)]
    pub extra: Extra,
}
