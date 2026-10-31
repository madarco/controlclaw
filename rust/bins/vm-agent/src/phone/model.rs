//! The classic phone reply model (`phone-model.ts`): a fast model on the same Included AI
//! credential when one is there, and the entry `/llm/apply` patches into the voice-call plugin so
//! its replies follow the owner's model.

use serde_json::{Value, json};

const FAST: &str = "anthropic/claude-haiku-4.5";
/// The start of the Twilio auth token placeholder ControlClaw writes into the plugin's config.
pub const TWILIO_PLACEHOLDER_PREFIX: &str = "CC-TWILIO-";
/// What OpenClaw's `config.get` shows instead of a secret.
pub const OPENCLAW_REDACTED: &str = "__OPENCLAW_REDACTED__";

/// JS truthiness of a JSON value (`x ? a : b`); a missing value is `None`.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// A low-latency phone model on the same Included AI credential (`phoneResponseModel`). The error
/// is the TS's throw on a malformed `models` list (`models?.some(...)` on a non-array, or a null
/// entry before the fast one), which fails the caller's apply.
pub fn phone_response_model(config: &Value, primary: &str) -> Result<String, String> {
    if !(primary.starts_with("controlclaw/") && primary.ends_with("@controlclaw:included")) {
        return Ok(primary.to_string());
    }
    let has_fast = match config.pointer("/models/providers/controlclaw/models") {
        None | Some(Value::Null) => false,
        Some(Value::Array(models)) => {
            let mut found = false;
            for m in models {
                if m.is_null() {
                    return Err("Cannot read properties of null (reading 'id')".into());
                }
                if m.get("id").and_then(Value::as_str) == Some(FAST) {
                    found = true;
                    break;
                }
            }
            found
        }
        Some(_) => return Err("models?.some is not a function".into()),
    };
    Ok(if has_fast {
        format!("controlclaw/{FAST}@controlclaw:included")
    } else {
        primary.to_string()
    })
}

/// Keep managed voice replies on the model and profile the owner chose (`phoneModelEntry`):
/// `{config: {responseModel}}`, `{enabled: false}` without a model, or `None` when the voice-call
/// plugin is not one ControlClaw set up. The error is the TS's throw (see `phone_response_model`).
pub fn phone_model_entry(config: &Value, primary: Option<&str>) -> Result<Option<Value>, String> {
    let entry = config.pointer("/plugins/entries/voice-call/config");
    let Some(token) = entry
        .and_then(|c| c.pointer("/twilio/authToken"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    if !(token.starts_with(TWILIO_PLACEHOLDER_PREFIX) || token == OPENCLAW_REDACTED) {
        return Ok(None);
    }
    // `primary ? … : …`: an empty string counts as none.
    let Some(primary) = primary.filter(|p| !p.is_empty()) else {
        return Ok(Some(json!({"enabled": false})));
    };
    let model = if truthy(entry.and_then(|c| c.pointer("/realtime/enabled"))) {
        primary.to_string()
    } else {
        phone_response_model(config, primary)?
    };
    Ok(Some(json!({"config": {"responseModel": model}})))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parts of `phoneConfig(input, "old/model")` these read: a managed placeholder, no speech.
    fn managed() -> Value {
        json!({"plugins": {"entries": {"voice-call": {"enabled": true, "config": {
            "provider": "twilio",
            "twilio": {"accountSid": format!("AC{}", "c".repeat(32)), "authToken": format!("CC-TWILIO-{}", "b".repeat(32))},
            "realtime": {"enabled": false},
            "responseModel": "old/model",
        }}}}})
    }

    fn entry(model: &str) -> Result<Option<Value>, String> {
        Ok(Some(json!({"config": {"responseModel": model}})))
    }

    #[test]
    fn voice_response_model_follows_owner_model_changes() {
        let config = managed();
        assert_eq!(
            phone_model_entry(&config, Some("openai/model@openai:chosen")),
            entry("openai/model@openai:chosen")
        );
        assert_eq!(phone_model_entry(&config, None), Ok(Some(json!({"enabled": false}))));
        assert_eq!(phone_model_entry(&json!({}), Some("provider/model")), Ok(None));
        let unmanaged =
            json!({"plugins": {"entries": {"voice-call": {"config": {"twilio": {"authToken": "unmanaged"}}}}}});
        assert_eq!(phone_model_entry(&unmanaged, Some("provider/model")), Ok(None));
        let redacted = json!({"plugins": {"entries": {"voice-call": {"config": {"twilio": {"authToken": OPENCLAW_REDACTED}, "realtime": {"enabled": true}}}}}});
        assert_eq!(
            phone_model_entry(&redacted, Some("controlclaw/x@controlclaw:included")),
            entry("controlclaw/x@controlclaw:included")
        );
    }

    #[test]
    fn phone_uses_a_fast_included_model_when_there_is_one() {
        let config = json!({"models": {"providers": {"controlclaw": {"models": [{"id": FAST}]}}}});
        let kimi = "controlclaw/moonshotai/kimi-k2.6@controlclaw:included";
        let fast = "controlclaw/anthropic/claude-haiku-4.5@controlclaw:included";
        assert_eq!(phone_response_model(&config, kimi).as_deref(), Ok(fast));
        assert_eq!(phone_response_model(&json!({}), kimi).as_deref(), Ok(kimi));
        assert_eq!(
            phone_response_model(&config, "openai/model@openai:chosen").as_deref(),
            Ok("openai/model@openai:chosen")
        );
        // A malformed list throws in the TS, but only when the primary is the included one.
        let broken = json!({"models": {"providers": {"controlclaw": {"models": [null]}}}});
        assert!(phone_response_model(&broken, kimi).is_err());
        let object = json!({"models": {"providers": {"controlclaw": {"models": {}}}}});
        assert!(phone_response_model(&object, kimi).is_err());
        assert_eq!(phone_response_model(&broken, "openai/x").as_deref(), Ok("openai/x"));
        // Through the entry, for a classic (not realtime) managed plugin, and a float `enabled`.
        let mut managed = managed();
        managed["models"] = config["models"].clone();
        assert_eq!(phone_model_entry(&managed, Some(kimi)), entry(fast));
        managed["plugins"]["entries"]["voice-call"]["config"]["realtime"]["enabled"] = json!(0.0);
        assert_eq!(phone_model_entry(&managed, Some(kimi)), entry(fast));
        assert!(truthy(Some(&json!(1.5))));
        assert!(!truthy(Some(&json!(""))));
    }
}
