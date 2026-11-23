//! `ai.*` payloads (`rust/bins/mitm-agent/src/channels/ai/mod.rs`). `ai.scan`, AI Log Review run
//! now, takes no fields ([`super::Empty`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Extra;

/// `ai.relay`: one model call of an AI Log Review investigation (`channels/ai/relay.rs`), sent by the
/// control plane as the HTTP request its AI SDK provider would make, minus the key. The firewall
/// checks it, puts the organization's key in and sends it to the provider's generate endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Relay {
    /// The provider the request is written for: the AI settings' provider.
    pub provider: String,
    /// The path after the provider's base URL, e.g. `/messages` or `/language-model`.
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The request body, as the SDK wrote it.
    pub body: String,
    #[serde(flatten)]
    pub extra: Extra,
}
