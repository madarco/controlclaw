//! `rules.*` payloads: content rules on messages (`rust/bins/mitm-agent/src/channels/content_rules/`).

use serde::{Deserialize, Serialize};

use crate::Extra;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    #[default]
    Out,
    Both,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Block,
    /// Only on a rule for messages going out.
    Hold,
    Log,
}

/// One content rule (`schema.rs` `parse_rule`). The firewall refuses a key not named here, a rule
/// with no policy, word or detector, and a channel listed twice.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// One line, up to 80 characters.
    pub name: String,
    pub direction: Direction,
    /// Some of `telegram`, `slack`, `email`, `web`, `webhook`, `teamchat`, `voice`, `apps`.
    pub channels: Vec<String>,
    /// Words, up to 50, each one line of up to 100 characters.
    pub patterns: Vec<String>,
    /// Some of `secrets`, `iban`, `card`, `emails`.
    pub detectors: Vec<String>,
    /// The sentence the firewall's AI judges messages by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    pub action: Action,
    /// Up to 200 characters.
    pub reason: String,
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

/// What a `rules.propose` changes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    /// Add a rule, or replace the one with its id.
    Put {
        rule: Box<Rule>,
    },
    Delete {
        id: String,
    },
    /// Judge with the model and key AI review uses now.
    #[default]
    Ai,
}

/// `rules.propose`: one change to the content rules; it needs a code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    /// Up to 100 characters.
    pub change_id: String,
    pub change: Change,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `rules.try`: what the rules, with `draft` in place of the rule of its id, would do with a
/// message. Nothing is recorded.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Try {
    /// Up to 20000 characters.
    pub text: String,
    /// `in` or `out`.
    pub direction: String,
    /// One of the rule channels.
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<Rule>,
    #[serde(flatten)]
    pub extra: Extra,
}
