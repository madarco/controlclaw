//! What the proxy sends the firewall agent on loopback, and what comes back. All JSON over plain
//! HTTP POST to `127.0.0.1`, never through a proxy. The proxy treats anything it does not expect as
//! a refusal (fail closed).
//!
//! | Port | Path | Server | Proxy caller |
//! | --- | --- | --- | --- |
//! | 3101 | `/judge`, `/content` | ai/judge.ts `startJudgeServer` | `ai_judge`, `_content_policy_ask` |
//! | 8791 | `/` | phone-admission.ts | `phone_admission` |
//! | 8792 | `/` | email-rules.ts | `email_admission` |
//! | 8793 | `/` | code-buttons.ts | `_post_taps` |
//! | 8794 | `/hold /cancel /own /stopped /notice` | content-rules.ts | `_content_post` |
//! | 8796 | `/call /held /tools /result /done` | mcp-admission.ts | `_mcp_admission` |

use serde::{Deserialize, Serialize};

use crate::{Extra, Maybe};

pub const JUDGE_PORT: u16 = 3101;
pub const PHONE_PORT: u16 = 8791;
pub const EMAIL_PORT: u16 = 8792;
pub const CODE_BUTTONS_PORT: u16 = 8793;
pub const CONTENT_RULES_PORT: u16 = 8794;
pub const MCP_PORT: u16 = 8796;

// ---- 3101 /judge ----

/// The inline AI review of one request (ai/judge.ts `JudgeRequest`). Limits on the agent side:
/// path 200, body_start 300, recent 20.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct JudgeRequest {
    /// `review` (Allow rule) or `approve` (Ask rule with a policy).
    pub mode: String,
    pub rule: String,
    pub policy: Maybe<String>,
    /// Approve mode only.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub permission_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub scope: Maybe<String>,
    pub vm_id: Maybe<String>,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub content_type: Maybe<String>,
    pub body_start: Maybe<String>,
    /// The agent's last traffic records, as written to traffic.jsonl.
    pub recent: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `{decision, category?, cached?, by?}`. `fallback` (or anything else) leaves the rule's effect.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct JudgeAnswer {
    /// `allow`, `ask`, `block` or `fallback`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub category: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub cached: Maybe<bool>,
    /// `ai`: approved, and the grant is already in grants.json.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub by: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- 3101 /content ----

/// The content rules' AI check (ai/judge.ts `ContentAsk`). The proxy masks secrets first.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContentAsk {
    pub direction: String,
    pub channel: String,
    pub text: String,
    pub rules: Vec<PolicyRef>,
    pub vm_id: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyRef {
    pub id: String,
    pub policy: String,
}

/// `{matches, probabilities, cached?}` or `{failed: true, why}`. The proxy reads `matches` only;
/// no list of strings means the check could not run.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContentAnswer {
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub matches: Maybe<Vec<String>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub failed: Maybe<bool>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub why: Maybe<String>,
    /// probabilities, cached.
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- 8791 phone ----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum PhoneAdmission {
    /// Before a `POST .../Calls.json`: a slot for this agent's number.
    Reserve {
        #[serde(rename = "vmId")]
        vm_id: String,
        placeholder: String,
    },
    /// After Twilio answered: the call's sid on 2xx, `rejected` on 4xx.
    Settle {
        id: String,
        sid: Option<String>,
        rejected: bool,
    },
}

/// `{ok: true, id}` (id: 48 hex) on reserve. Anything but `ok: true` refuses.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AdmissionAnswer {
    #[serde(default)]
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub id: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- 8792 email ----

/// One email admission call. `action` is `email.reserve`, `email.settle`, `email.inbound` or
/// `email.draft_write`; the other fields depend on it and on the provider (addon.py
/// `email_send_request`, `email_settle`, `agentmail_filter`).
// unverified: the full field list per action is long and moves with email-rules.ts; kept open here
// rather than guessed. The proxy port (W2) types what it sends.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct EmailAdmission {
    pub action: String,
    #[serde(flatten)]
    pub fields: Extra,
}

/// `{ok: true, decision, id?, asks?, reason?, actions?}`. Anything but `ok: true` refuses.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct EmailAnswer {
    #[serde(default)]
    pub ok: bool,
    /// Reserve: `allow` (with `id`, 48 hex), `ask` (with `asks`) or a refusal with `reason`.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub decision: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub asks: Maybe<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub reason: Maybe<String>,
    /// Inbound: one `{action: keep|hide|...}` per item.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub actions: Maybe<Vec<serde_json::Value>>,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- 8793 code buttons ----

/// Button taps stripped out of the agent's Telegram `getUpdates` (at most 100). Fire and forget.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CodeButtonTaps {
    #[serde(rename = "botId")]
    pub bot_id: String,
    /// Telegram `callback_query` updates, as Telegram sent them.
    pub queries: Vec<serde_json::Value>,
}

// ---- 8794 content rules ----

/// A rule as a hold or a stopped record names it (addon.py `_rule_brief`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RuleBrief {
    pub id: String,
    pub name: String,
    pub reason: String,
    /// `found` or `failed`.
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub ai: Maybe<String>,
}

/// `POST /hold`: a message to keep and ask a person about. The proxy waits up to its hold limit
/// (25 s); on giving up it sends `/cancel` with the same `key`.
// unverified: the per-channel fields (Telegram, Slack, email) are taken as they come; W2 types them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HoldRequest {
    pub channel: String,
    pub key: String,
    pub rule: RuleBrief,
    #[serde(rename = "vmId", default, skip_serializing_if = "Maybe::is_absent")]
    pub vm_id: Maybe<String>,
    #[serde(default, skip_serializing_if = "Maybe::is_absent")]
    pub text: Maybe<String>,
    /// method, body, contentType, chatId, auth, ...
    #[serde(flatten)]
    pub extra: Extra,
}

/// `{ok: true, holdId}` when someone could be asked; anything else means nobody could.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HoldAnswer {
    #[serde(default)]
    pub ok: bool,
    #[serde(rename = "holdId", default, skip_serializing_if = "Maybe::is_absent")]
    pub hold_id: Maybe<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CancelRequest {
    pub key: String,
}

/// `POST /own {text}` → `{rest}`: whether a text going out is one the firewall itself had sent.
// unverified: `rest`'s exact type (the text left once the firewall's own part is taken out).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct OwnRequest {
    pub text: String,
}

/// `POST /stopped`: a stopped text for the agent's encrypted record (empty for secrets rules).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StoppedRequest {
    #[serde(rename = "vmId")]
    pub vm_id: Option<String>,
    pub rule: RuleBrief,
    pub channel: String,
    pub direction: String,
    /// The audit line's id.
    pub id: String,
    pub text: String,
}

// unverified: `/notice` payload (the firewall's own notice to the person in the chat).
pub type NoticeRequest = Extra;

// ---- 8796 MCP ----

/// `POST /call`: a `tools/call` the proxy holds until the agent says what to do.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct McpCall {
    pub vm_id: String,
    pub host: String,
    pub url: String,
    /// Lower-cased, without the connection's and the proxy's own headers.
    pub headers: indexmap::IndexMap<String, String>,
    pub body: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// unverified: the `/call` verdict and the `/held`, `/tools`, `/result`, `/done` payloads
// (addon.py 6713-6817, mcp-admission.ts). Taken as JSON until W2 types them.
pub type McpVerdict = Extra;
