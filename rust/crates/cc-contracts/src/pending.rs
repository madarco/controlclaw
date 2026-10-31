//! `pending.jsonl`: the proxy appends one line per permission it asked for; the agent drains it into
//! permission requests on the console (permissions.ts `drainPending`). Fields from both sides.

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PendingRecord {
    pub permission_id: String,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub ts: Maybe<Num>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub tenant: Maybe<String>,
    /// One id may be asked by several agents: it is per scope.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub host: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub method: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub path: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub ai_category: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub summary: Maybe<String>,
    /// `email_recipient` or `app_call`.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub kind: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub recipient: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub mailbox: Maybe<String>,
    /// service, action, operation, connection, rule, expires_at (app calls), and anything newer.
    #[serde(flatten)]
    pub extra: Extra,
}

/// The permission id for a scope (addon.py `permission_id_for`): `perm_` + 32 hex of its sha256.
/// The hashing itself lives with the proxy; this is the scope key it hashes.
pub fn permission_scope(method: &str, host: &str, path: &str) -> String {
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    format!("{method} {host}{path}")
}
