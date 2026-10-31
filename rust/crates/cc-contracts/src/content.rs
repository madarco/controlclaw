//! The content rules' files: `content-rules.json` (the organization's rules, written by
//! content-rules.ts), `content-own.json` (a marker for texts the firewall itself had an agent send,
//! own-messages.ts) and `content-rules.jsonl` (the firewall's record of a rule that fired, written
//! by the proxy and the agent, metadata only).

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

/// The rule file. `unreadable: true` means the agent could not open its store, so the rules are
/// unknown and the proxy refuses on every content channel. A missing file means the same.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContentRulesFile {
    pub version: Num,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub rules: Maybe<Vec<ContentRule>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub unreadable: Maybe<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl ContentRulesFile {
    /// The rules, or `None` when they cannot be known (addon.py `content_rules` raises then).
    pub fn known_rules(&self) -> Option<&[ContentRule]> {
        if self.unreadable.get() == Some(&true) || self.version.as_u64() != Some(1) {
            return None;
        }
        self.rules.get().map(Vec::as_slice)
    }
}

/// One rule, as content-rules-schema.ts `contentRule` (strict there; the agent writes only what
/// passed it). Validation lives with the agent; the proxy checks shape (`_content_rule_ok`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContentRule {
    pub id: String,
    pub name: String,
    /// `in`, `out` or `both`.
    pub direction: String,
    /// telegram, slack, email, web, webhook, teamchat, voice, apps.
    pub channels: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    /// secrets, iban, card, emails.
    #[serde(default)]
    pub detectors: Vec<String>,
    /// The rule as one sentence, judged by the firewall's AI.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub policy: Maybe<String>,
    /// `block`, `hold` or `log`.
    pub action: String,
    pub reason: String,
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `content-own.json`: until when (epoch seconds) the proxy should ask the agent whether a message
/// is one the firewall itself sent.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContentOwnFile {
    pub until: Num,
    #[serde(flatten)]
    pub extra: Extra,
}

/// One line of `content-rules.jsonl` (addon.py `_content_audit`). `id` is the console's dedupe key.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContentAuditRecord {
    pub ts: Num,
    pub id: String,
    pub rule: String,
    pub channel: String,
    pub direction: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub flow_id: Maybe<String>,
    /// `found` or `failed` when the AI decided or could not run.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub ai: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
