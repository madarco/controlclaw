//! `channels.*` payloads: Telegram, Slack and WhatsApp connections
//! (`rust/bins/mitm-agent/src/channels/chan/mod.rs`).

use serde::{Deserialize, Serialize};

use crate::Extra;

/// An agent a change or a push is for. Shared with `kill.*`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRef {
    pub vm_id: String,
    /// The vm id when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Add,
    Replace,
    Remove,
    Assign,
    Unassign,
    ApprovePairing,
    WhatsappLogin,
    AddSender,
    RemoveSender,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelType {
    #[default]
    Telegram,
    Slack,
    Whatsapp,
}

/// `channels.propose`: a change to one connection, applied at once on first use, else after a code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub kind: Kind,
    pub connection_id: String,
    #[serde(rename = "type")]
    pub channel_type: ChannelType,
    /// What the code message shows of the token, such as `…abcd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The agent it is assigned to (`add`, `assign`, `replace`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentRef>,
    /// The agent it moves away from (`assign`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<FromAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<Pairing>,
    /// The sender added or removed (`add_sender`, `remove_sender`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<Sender>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Settings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FromAgent {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A pairing request the agent's OpenClaw holds, approved with its code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    pub code: String,
    pub sender_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sender {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// A Telegram bot that answers only its paired people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal: Option<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The tokens, merged into the payload when the firewall takes the command.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<String>,
    /// Slack's app-level token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_token: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `channels.push`: write an agent's connections to its OpenClaw again.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
