//! One line of `traffic.jsonl`: the metadata-only record of a request or connection (addon.py
//! `_log`, `_base_record`, `_http_record`). The agent ships the file to the console's Activity page.
//! Host, method, a query-stripped and redacted path, effect, rule, status, timing; never a header
//! value, a body or a query string.

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe, Num};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct TrafficRecord {
    /// A uuid per flow: the shipper's dedupe key.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub flow_id: Maybe<String>,
    pub ts: Num,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub tenant: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub host: Maybe<String>,
    /// Raw TCP records (drop, residential).
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub port: Maybe<Num>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub method: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub path: Maybe<String>,
    /// allow, block, require_permission, drop, tunnel, ...
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub effect: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub rule: Maybe<String>,
    /// Always there (null when no website rule decided) on a record with an `effect`: it tells the
    /// console this firewall sends rule ids. Use [`TrafficRecord::with_effect`] to get that right.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub rule_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub status: Maybe<Num>,
    /// permission_id, ai, email, model_error, exit, bytes, duration_ms, ...
    #[serde(flatten)]
    pub extra: Extra,
}

impl TrafficRecord {
    /// A record with an effect, and `rule_id: null` unless one is set later.
    pub fn with_effect(ts: Num, effect: &str) -> Self {
        Self {
            ts,
            effect: Maybe::Value(effect.to_owned()),
            rule_id: Maybe::Null,
            ..Self::default()
        }
    }
}
