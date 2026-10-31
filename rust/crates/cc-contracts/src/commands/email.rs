//! `email.*`: the organization's email rules, who may write to the agents and whom they may email
//! (`channels/email/rules.rs`, the change's shape in `channels/email/schema.rs`).

use serde::{Deserialize, Serialize};

use crate::Extra;

/// Propose one change to the email rules; a loosening one waits for a code (`email.confirm`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    /// Up to 100 characters.
    pub change_id: String,
    pub change: Change,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One change, as `emailChange` in `packages/mitm-agent/src/email-rules-schema.ts` defines it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Change {
    AddSender {
        entry: Entry,
    },
    RemoveSender {
        entry: Entry,
    },
    AddRecipient {
        entry: Entry,
    },
    RemoveRecipient {
        entry: Entry,
    },
    SetInboundAuth {
        #[serde(rename = "requireAuth")]
        require_auth: RequireAuth,
    },
    SetOutbound {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<Mode>,
        #[serde(rename = "repliesToSenders", default, skip_serializing_if = "Option::is_none")]
        replies_to_senders: Option<bool>,
        /// 1 to 200.
        #[serde(rename = "perHour", default, skip_serializing_if = "Option::is_none")]
        per_hour: Option<i64>,
        /// 1 to 2000.
        #[serde(rename = "perDay", default, skip_serializing_if = "Option::is_none")]
        per_day: Option<i64>,
    },
    SetMailboxMode {
        mailbox: String,
        /// `null` drops the mailbox's own mode.
        mode: Option<Mode>,
    },
}

/// `bob@x.com` or `@x.com`, for one mailbox (`agentmail:<inbox>` or `gmail:<address>`) or all.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub value: String,
    #[serde(default)]
    pub mailbox: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequireAuth {
    Aligned,
    Dmarc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Listed,
    Ask,
    Block,
    Anyone,
}
