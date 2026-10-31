//! The AI settings the console sends with the egress rules (`ai/settings.ts`), and the per-call
//! provider options (`providerOptionsFor` in `ai/model.ts`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    OpenAi,
    Anthropic,
    Google,
    VercelGateway,
    /// The plan's included AI tokens: an AI Gateway key.
    ControlclawIncluded,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "openai" => Self::OpenAi,
            "anthropic" => Self::Anthropic,
            "google" => Self::Google,
            "vercel_gateway" => Self::VercelGateway,
            "controlclaw_included" => Self::ControlclawIncluded,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::VercelGateway => "vercel_gateway",
            Self::ControlclawIncluded => "controlclaw_included",
        }
    }
}

/// Decision models answer typed questions only; they cannot write a sentence.
pub fn is_decision_model(model: &str) -> bool {
    model.starts_with("typesafe-ai/")
}

static GPT5: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"^gpt-5(-mini|-nano)?(-\d{4}-\d{2}-\d{2})?$").unwrap()
});
static O_SERIES: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"^o\d").unwrap()
});

/// Zero data retention on every Gateway call. AI SDK asks OpenAI for reasoning effort `none`, which
/// the first GPT-5 models and the o-series refuse, so those get the lowest they accept.
pub fn provider_options_for(provider: Provider, model: &str) -> Value {
    let mut opts = Map::new();
    opts.insert("gateway".into(), json!({ "zeroDataRetention": true }));
    if provider == Provider::OpenAi {
        if GPT5.is_match(model) {
            opts.insert("openai".into(), json!({ "reasoningEffort": "minimal" }));
        } else if O_SERIES.is_match(model) {
            opts.insert("openai".into(), json!({ "reasoningEffort": "low" }));
        }
    }
    Value::Object(opts)
}

/// The first 16 hex of the key's SHA-256: says whether the key changed, never what it is.
pub fn key_fingerprint(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))[..16].to_string()
}

/// Mirrored in apps/saas `AI_INSTRUCTIONS_MAX`.
pub const INSTRUCTIONS_MAX: usize = 2000;

static CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"[\x00-\x08\x0b-\x1f\x7f]").unwrap()
});
static TRIPLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r#""{3,}"#).unwrap()
});

/// Owner text made safe to quote: control characters out, `"""` collapsed so it cannot close its
/// own quote, trimmed and capped. None when empty. The cap counts chars; the TS counts UTF-16 units,
/// which differs only for text outside the BMP.
pub fn clean_instructions(v: &Value, max: usize) -> Option<String> {
    let s = v.as_str()?;
    let s = CONTROL.replace_all(s, " ");
    let s = TRIPLE_QUOTE.replace_all(&s, "\"");
    let s = s.trim();
    (!s.is_empty()).then(|| s.chars().take(max).collect())
}

/// `parseAiSettings`: the `ai` block of `GET /api/vm-agent/egress-rules`.
#[derive(Debug, Clone, PartialEq)]
pub struct AiSettings {
    pub credential_id: String,
    pub provider: Provider,
    pub model: String,
    pub checks: bool,
    pub log_review: bool,
    pub daily_call_cap: u64,
    pub scan_interval_hours: u64,
    pub auto_approve_per_hour: u64,
    pub request_instructions: Option<String>,
    pub review_instructions: Option<String>,
}

impl AiSettings {
    pub fn parse(raw: &Value) -> Option<Self> {
        let r = raw.as_object()?;
        let credential_id = r.get("credential_id")?.as_str().filter(|s| !s.is_empty())?.to_string();
        let provider = Provider::parse(r.get("provider")?.as_str()?)?;
        let model = r.get("model")?.as_str().filter(|s| !s.is_empty())?.to_string();
        Some(Self {
            credential_id,
            provider,
            model,
            checks: r.get("checks") != Some(&Value::Bool(false)),
            log_review: r.get("log_review") != Some(&Value::Bool(false)),
            daily_call_cap: positive_int(r.get("daily_call_cap"), 5000),
            scan_interval_hours: positive_int(r.get("scan_interval_hours"), 6),
            // 0 is meaningful: the AI never approves.
            auto_approve_per_hour: int_at_least(r.get("auto_approve_per_hour"), 0, 30),
            request_instructions: r
                .get("request_instructions")
                .and_then(|v| clean_instructions(v, INSTRUCTIONS_MAX)),
            review_instructions: r
                .get("review_instructions")
                .and_then(|v| clean_instructions(v, INSTRUCTIONS_MAX)),
        })
    }
}

fn positive_int(v: Option<&Value>, fallback: u64) -> u64 {
    int_at_least(v, 1, fallback)
}

/// A JS `Number.isInteger` check: 3.0 counts, 3.5 does not.
fn int_at_least(v: Option<&Value>, min: u64, fallback: u64) -> u64 {
    match v.and_then(Value::as_f64) {
        Some(f) if f.fract() == 0.0 && f >= min as f64 && f <= u64::MAX as f64 => f as u64,
        _ => fallback,
    }
}
