//! `llm.*` payloads: model keys, sign-ins and which agent uses which model
//! (`rust/bins/mitm-agent/src/channels/llm/mod.rs`).

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Add,
    Replace,
    Remove,
    Bind,
    Unbind,
    SetModel,
}

/// `llm.propose`: add, replace or remove a credential, or set the models agents use with it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Propose {
    pub change_id: String,
    pub kind: Kind,
    pub credential_id: String,
    /// `openai`, `anthropic`, `gateway`, a custom provider's id, ...
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// `api_key`, `token` or `oauth`; any other value is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_kind: Option<String>,
    /// What the agent holds instead of the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Where the proxy puts the key in (the provider's host and the header or query).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap: Option<Swap>,
    /// How the firewall refreshes a sign-in's token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuth>,
    /// A custom provider's `models.providers` block for OpenClaw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_block: Option<ProviderBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemorySearch>,
    /// The credential this one replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<Agent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Swap {
    pub match_domain: String,
    /// Each a string; other values are read as their JSON text.
    pub locations: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth {
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderBlock {
    pub base_url: String,
    pub api: String,
    pub models: Vec<ProviderModel>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderModel {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Only `supportsPromptCacheKey` and `cacheControlFormat: "anthropic"` are kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat: Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// OpenClaw's memory search: the embeddings model and where it is served.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySearch {
    pub provider: String,
    pub model: String,
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreaming: Option<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The credential that pays for an agent's embeddings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingsRef {
    pub credential_id: String,
    pub memory: MemorySearch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    pub vm_id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// `secondary`, or the primary model otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Absent says nothing; `null` takes ours off.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub embeddings: Maybe<EmbeddingsRef>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// The key, token or sign-in, merged into the payload when the firewall takes the command. One of
/// the three.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthTokens>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthTokens {
    pub access: String,
    pub refresh: String,
    /// Epoch milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<serde_json::Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `llm.push`: write an agent's models and keys to its OpenClaw again, with what changed since.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Push {
    pub vm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub embeddings: Maybe<EmbeddingsRef>,
    /// A credential's new allowed models and memory search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Refresh>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_blocks: Option<Vec<ProviderBlockRef>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Refresh {
    pub credential_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemorySearch>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderBlockRef {
    pub credential_id: String,
    pub provider_block: ProviderBlock,
    #[serde(flatten)]
    pub extra: Extra,
}
