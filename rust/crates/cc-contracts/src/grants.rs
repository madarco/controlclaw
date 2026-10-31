//! `grants.json`: permission ids that may pass an Ask rule until `expires_at` (epoch seconds).
//! One writer, the agent's `GrantStore`; the proxy only reads.

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Grant {
    pub expires_at: Num,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub scope: Maybe<String>,
    /// `ai` when the inline AI review approved it under the rule's policy.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub by: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Keyed by permission id, in the order the agent wrote them.
pub type GrantsFile = indexmap::IndexMap<String, Grant>;
