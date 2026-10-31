//! `exit.json`: the organization's residential exit, from the firewall's own store (exit.ts
//! `exitConfig`). `{"enabled": false}` or a missing file means none, and every residential rule then
//! fails closed. It carries the upstream password: the file is the credential.

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ExitFile {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub enabled: Maybe<bool>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub upstream: Maybe<Upstream>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub sticky: Maybe<bool>,
    /// At least 32 characters when `sticky`, or the addon refuses the exit.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub sticky_salt: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub cap_bytes: Maybe<Num>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub used_bytes: Maybe<Num>,
    /// The org default; a rule's `exit_country` wins.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub country: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Upstream {
    /// `http`, `https` or `socks5`.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub scheme: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub host: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub port: Maybe<Num>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub username: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub password: Maybe<String>,
    /// Placeholders `{username}`, `{session}`, `{country}` (addon.py `render_template`).
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub username_template: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub password_template: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl ExitFile {
    pub fn is_enabled(&self) -> bool {
        self.enabled.get() == Some(&true)
    }
}
