//! `apps.*` payloads: the organization's integration rules (`integrations/apps_rules/firewall.rs`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Extra;

/// `apps.propose`: one change to the rules, applied at once when it only narrows, else after a code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub change: Change,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The change, by `op`. The firewall refuses keys it does not name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Change {
    /// A new rule at `at` (else last), or a rule replaced in place. The rule is checked by the firewall.
    Put {
        rule: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at: Option<u64>,
    },
    Delete {
        id: String,
    },
    Move {
        id: String,
        to: u64,
    },
}

impl Default for Change {
    fn default() -> Self {
        Change::Delete { id: String::new() }
    }
}
