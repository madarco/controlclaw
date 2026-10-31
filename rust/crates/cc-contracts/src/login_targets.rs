//! `login-targets.json`: what the proxy read off sign-in pages (addon.py `_save_login_targets`).
//! The proxy writes it; the agent takes it into the sealed logins store and shows it to the owner
//! (logins.ts `ingestLearnedTargets`). A target counts only once the owner approved it.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct LoginTargets {
    /// The login's sign-in page these were read from; the agent ignores them if it changed.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub page: Maybe<String>,
    #[serde(default)]
    pub targets: IndexMap<String, SeenTarget>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SeenTarget {
    /// Epoch seconds.
    pub seen: Num,
    /// The password field's name in that form.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub field: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// login_id → what was learned for it.
pub type LoginTargetsFile = IndexMap<String, LoginTargets>;
