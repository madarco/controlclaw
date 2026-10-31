//! `exit.*` payloads: the residential exit (`rust/bins/mitm-agent/src/core/exit.rs`). A standalone
//! firewall uses it with the user's own proxy; ControlClaw's relay is the SaaS's.

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Add,
    Replace,
    Remove,
    /// Only `country`, `capBytes` or `templates`.
    Settings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    #[default]
    Http,
    Https,
    Socks5,
}

/// `exit.propose`: set, replace or remove the upstream proxy, or change its settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub kind: Kind,
    /// `custom` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// `scheme`, `host` and `port` are required for `add` and `replace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<Scheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<serde_json::Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// `{username}` when absent; may name `{session}` and `{country}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticky: Option<bool>,
    /// Absent leaves the cap as it is; `null` removes it.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub cap_bytes: Maybe<serde_json::Number>,
    /// Absent leaves it as it is; `null` clears it.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub country: Maybe<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub templates: Option<Templates>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Templates {
    pub username_template: String,
    pub password_template: String,
    #[serde(flatten)]
    pub extra: Extra,
}
