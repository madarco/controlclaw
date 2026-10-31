//! `credentials.json`: what the proxy swaps a placeholder for, and where. One list, written by the
//! agent from the control plane's sealed store plus each firewall module's own entries (channels,
//! llm, meetings, drive, phone, secrets, logins, agentmail, google, search: index.ts `runSync`).
//!
//! Three kinds share the shape, told apart by which key is set:
//! - **legacy** (`match_domain` + `locations`): most modules;
//! - **custom secret** (`secret_name` + `allowed_hosts` + `secret_locations`): secrets.ts;
//! - **website login** (`login_id` + `allowed_hosts` + the sign-in fields): logins.ts.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Credential {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub placeholder: Maybe<String>,
    /// The real value. Never logged.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub secret: Maybe<String>,
    /// Org-wide when absent; a vm-scoped entry beats an org one for the same placeholder.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,

    // Legacy swap.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub match_domain: Maybe<String>,
    /// `header:<name>`, `basic:<name>`, `query`, `path`, `body`. Default: authorization,
    /// x-api-key, private-token headers (addon.py `DEFAULT_LOCATIONS`).
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub locations: Maybe<Vec<String>>,

    // Model keys (llm.ts).
    /// Leaves model calls out of the content rules' "web" channel.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub model: Maybe<bool>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub allowed_models: Maybe<Vec<String>>,
    /// The included AI: only `allowed_models` may be called.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub included: Maybe<bool>,

    // Voice (meetings.ts, phone.ts).
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub speech: Maybe<Speech>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub speech_account_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub phone_speech: Maybe<bool>,
    /// The Twilio entry: one agent per account, narrow operations.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub phone: Maybe<Phone>,

    // Custom secrets (secrets.ts) and website logins (logins.ts).
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub secret_name: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub allowed_hosts: Maybe<Vec<String>>,
    /// Exact `header:<name>` / `query:<name>` places a custom secret may go.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub secret_locations: Maybe<Vec<String>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub login_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub login_name: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub login_url: Maybe<String>,
    /// `form` or `basic`.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub login_auth: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub sign_in_paths: Maybe<Vec<String>>,
    /// Form targets the owner approved: the only ones that get the password.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub sign_in_targets: Maybe<Vec<String>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub pending_targets: Maybe<Vec<String>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub expired_targets: Maybe<Vec<String>>,
    /// Target URL → the password field of the form read there.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub sign_in_fields: Maybe<IndexMap<String, String>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub refused_targets: Maybe<Vec<String>>,

    #[serde(flatten)]
    pub extra: Extra,
}

impl Credential {
    pub fn is_custom_secret(&self) -> bool {
        self.secret_name.get().is_some_and(|s| !s.is_empty())
    }

    pub fn is_login(&self) -> bool {
        self.login_id.get().is_some_and(|s| !s.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Speech {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub provider: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub model: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Phone {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub account_sid: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub from_number: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub hook_url: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub max_duration: Maybe<Num>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub max_concurrent_calls: Maybe<Num>,
    #[serde(flatten)]
    pub extra: Extra,
}

pub type CredentialsFile = Vec<Credential>;
