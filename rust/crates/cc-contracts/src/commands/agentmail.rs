//! `agentmail.*`: the organization's AgentMail account and its inboxes
//! (`channels/email/agentmail/mod.rs`). Every payload may carry the console's `changeId`: a change
//! the firewall already completed is answered `applied` again without running.

use serde::{Deserialize, Serialize};

use crate::Extra;

/// Sign the organization up to AgentMail and give the agent its first inbox.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signup {
    pub vm_id: String,
    /// The agent's hostname, where the inbox key is delivered.
    pub hostname: String,
    pub human_email: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// At most 50; the owner's address when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Verify the account with the code AgentMail emailed the owner.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    /// 4 to 10 digits.
    pub otp_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Read the account's state again, and deliver inbox keys once it is claimed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Create one more inbox for an agent; needs a claimed account and a `changeId`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    pub vm_id: String,
    pub hostname: String,
    pub username: String,
    /// The inbox's display name; the username when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Connect an existing AgentMail account by its API key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Import {
    /// Starts with `am_`.
    pub api_key: String,
    pub human_email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Give an existing inbox to an agent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attach {
    pub vm_id: String,
    pub hostname: String,
    pub inbox_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Set who may write to an inbox. Refused once the email rules own the inbox's senders.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Senders {
    pub inbox_id: String,
    pub allowed_senders: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Take every inbox away from an agent (the inboxes stay in the account).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Delete an inbox at AgentMail; `confirmAddress` must repeat the inbox's address.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delete {
    pub inbox_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Deliver an agent's inbox key to its box again.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
