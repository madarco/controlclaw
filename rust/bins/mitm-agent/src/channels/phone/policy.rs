//! What the phone needs from `@controlclaw/meetings` (speech and wake policies) and
//! `@controlclaw/phone` (setup error codes), plus `phone-limits.ts`.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Shared with the agent box (`@controlclaw/meetings`).
pub use cc_meetings::policy::speech_family;

fn re(s: &str) -> Regex {
    Regex::new(s).expect("regex")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeechPolicy {
    pub provider: String,
    pub credential_id: String,
    pub model: String,
    pub max_minutes: i64,
}

static CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-zA-Z0-9_-]{1,100}$"));

fn int(v: Option<&Value>) -> Option<i64> {
    let f = v?.as_f64()?;
    (f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

/// `parseSpeechPolicy`: `null` is "classic speech"; anything else is checked field for field.
pub fn parse_speech_policy(v: &Value) -> Result<Option<SpeechPolicy>, &'static str> {
    if v.is_null() {
        return Ok(None);
    }
    let Some(p) = v.as_object() else {
        return Err("Invalid speech settings");
    };
    let bad = "Choose a supported speech model and a call limit from 5 to 60 minutes";
    if p.keys()
        .any(|k| !["provider", "credentialId", "model", "maxMinutes"].contains(&k.as_str()))
    {
        return Err(bad);
    }
    let provider = p.get("provider").and_then(Value::as_str).unwrap_or("");
    let model = p.get("model").and_then(Value::as_str).ok_or(bad)?;
    let credential = p.get("credentialId").and_then(Value::as_str).ok_or(bad)?;
    let minutes = int(p.get("maxMinutes")).ok_or(bad)?;
    if speech_family(provider, model).is_none()
        || !CREDENTIAL.is_match(credential)
        || (credential == "included" && provider != "gateway")
        || !(5..=60).contains(&minutes)
    {
        return Err(bad);
    }
    Ok(Some(SpeechPolicy {
        provider: provider.into(),
        credential_id: credential.into(),
        model: model.into(),
        max_minutes: minutes,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakePolicy {
    pub enabled: bool,
    pub words: Vec<String>,
}

/// `parseWakePolicy`.
pub fn parse_wake_policy(v: &Value) -> Result<WakePolicy, String> {
    // The agent box's own rules (`cc_meetings`), JavaScript's whitespace included.
    let parsed = cc_meetings::policy::parse_wake_policy(Some(v))?;
    Ok(WakePolicy {
        enabled: parsed["enabled"].as_bool().unwrap_or(false),
        words: parsed["words"]
            .as_array()
            .map(|a| a.iter().filter_map(|w| w.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
    })
}

pub const PHONE_SETUP_ERRORS: [&str; 13] = [
    "openclaw_version",
    "voice_adapter_missing",
    "runtime_unsupported",
    "plugin_busy",
    "plugin_install_failed",
    "plugin_integrity",
    "gateway_unavailable",
    "model_missing",
    "activation_timeout",
    "listener_unavailable",
    "agent_unavailable",
    "routing_not_active",
    "phone_setup_failed",
];

/// `phoneSetupErrorCode`: a known code, or `None`.
pub fn phone_setup_error_code(v: Option<&Value>) -> Option<&'static str> {
    let s = v?.as_str()?;
    PHONE_SETUP_ERRORS.iter().copied().find(|c| *c == s)
}

/// `phoneLimits`: normalised at the trust boundary, persisted legacy settings included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_duration_seconds: i64,
    pub max_concurrent_calls: i64,
}

pub fn phone_limits(input: &Map<String, Value>) -> Result<Limits, &'static str> {
    let clamp = |k: &str, fallback: i64, min: f64, max: f64| -> Result<i64, &'static str> {
        match input.get(k) {
            None => Ok(fallback),
            Some(v) => {
                let f = v.as_f64().filter(|f| f.is_finite()).ok_or("invalid phone limit")?;
                Ok(f.floor().clamp(min, max) as i64)
            }
        }
    };
    Ok(Limits {
        max_duration_seconds: clamp("maxDurationSeconds", 300, 60.0, 3600.0)?,
        max_concurrent_calls: clamp("maxConcurrentCalls", 1, 1.0, 5.0)?,
    })
}

/// `maskTwilioAccountSids`: `AC…` and the last four.
pub fn mask_twilio_account_sids(text: &str) -> String {
    static SID: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)AC[0-9a-f]{28}([0-9a-f]{4})"));
    SID.replace_all(text, |c: &regex::Captures| format!("AC…{}", c[1].to_lowercase()))
        .into_owned()
}
