use std::sync::LazyLock;

use regex::Regex;

/// Why a model call gave no answer.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LlmError {
    /// The key was refused (401, a Gateway `authentication_error`, or a 403 that says so).
    #[error("authentication failed: {0}")]
    Auth(String),
    /// No credit or quota left (402, or the providers' own words for it).
    #[error("no credit: {0}")]
    Credit(String),
    #[error("rate limited: {0}")]
    RateLimit(String),
    /// The call did not finish in its time.
    #[error("The model did not answer in time.")]
    Timeout,
    /// The questions or state were not ones the SDK would send.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The model answered, but not with a valid answer for every question.
    #[error("invalid answer: {0}")]
    InvalidAnswer(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{message}")]
    Other { status: Option<u16>, message: String },
}

/// Same words as the addon's `_MODEL_CREDIT_MARKERS`, so the firewall and the proxy agree.
const CREDIT_MARKERS: [&str; 9] = [
    "insufficient_quota",
    "billing_hard_limit",
    "billing_not_active",
    "credit balance",
    "insufficient credits",
    "insufficient_credits",
    "exceeded your current quota",
    "payment required",
    "out of credits",
];
/// Error bodies are small; only their start is read, as in the addon.
const ERROR_READ_MAX: usize = 4096;

impl LlmError {
    /// A refused call: the Gateway's `{error: {message, type}}` when it sent one, else the status.
    pub(crate) fn from_response(status: u16, body: &str) -> Self {
        let head: String = body.chars().take(ERROR_READ_MAX).collect();
        let lower = head.to_lowercase();
        let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
        let kind = parsed
            .as_ref()
            .and_then(|v| v["error"]["type"].as_str())
            .unwrap_or_default()
            .to_string();
        let message = parsed
            .as_ref()
            .and_then(|v| v["error"]["message"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {status}"));
        if status == 402 || CREDIT_MARKERS.iter().any(|m| lower.contains(m)) {
            return Self::Credit(message);
        }
        let auth_403 = status == 403
            && ["authentication", "permission", "api key", "api_key"]
                .iter()
                .any(|m| lower.contains(m));
        if status == 401 || kind == "authentication_error" || auth_403 {
            return Self::Auth(message);
        }
        if status == 429 || kind == "rate_limit_exceeded" {
            return Self::RateLimit(message);
        }
        Self::Other {
            status: Some(status),
            message,
        }
    }

    /// Worth one more try under `maxRetries`, as AI SDK's `APICallError.isRetryable` says.
    pub fn retryable(&self) -> bool {
        match self {
            Self::RateLimit(_) => true,
            Self::Other { status: None, .. } => true,
            Self::Other { status: Some(s), .. } => *s == 408 || *s == 409 || *s >= 500,
            _ => false,
        }
    }
}

static KEY_LIKE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"\b(sk|vck|vcp|vca|AIza)[-_A-Za-z0-9]{8,}").unwrap()
});

/// `failureMessage` in ai/model.ts: short, and nothing that looks like a key.
pub fn failure_message(err: &LlmError) -> String {
    if *err == LlmError::Timeout {
        return "The model did not answer in time.".into();
    }
    let text = err.to_string();
    let text = KEY_LIKE.replace_all(&text, "[REDACTED]");
    text.chars().take(200).collect()
}
