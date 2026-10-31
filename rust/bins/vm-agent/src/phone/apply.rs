//! What `/phone/apply` takes (`parsePhoneApply` in `phone.ts`, with the speech and wake rules of
//! `@controlclaw/meetings`), the voice-call plugin entry built from it (`phoneConfig`), how a live
//! entry is compared with it, and the install provenance the plugin must have.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::model::truthy;
use super::stream::StreamBinding;
use crate::meetings::policy;
#[cfg(test)]
use crate::meetings::policy::speech_family;

pub const PHONE_PACKAGE: &str = "@openclaw/voice-call@2026.9.7";
/// The pinned plugin version (`PHONE_VERSION` in `patch-check.ts`).
pub const PHONE_VERSION: &str = "2026.9.7";
pub const PHONE_INTEGRITY: &str =
    "sha512-3UGgi96z4Q1MBu29MffT6NVRg7mYPVIUVN8wuCmEtdw7UeeLVQ4bNpvHEvysVtAqUNvPEWGbniJfjfu595cEOw==";

fn re(p: &str) -> Regex {
    Regex::new(p).expect("regex")
}

static GENERATION: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9a-f]{32}$"));
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| re(r"^CC-TWILIO-[0-9a-f]{32}$"));
static ACCOUNT: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^AC[0-9a-f]{32}$"));
static NUMBER: LazyLock<Regex> = LazyLock::new(|| re(r"^\+[1-9][0-9]{6,14}$"));
static HOOK_PATH: LazyLock<Regex> = LazyLock::new(|| re(r"^/hook/hk_[0-9a-f]{32}$"));
static SPEECH_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| re(r"^cc-speech-[0-9a-f]{48}$"));

/// `s.length` in JS: UTF-16 units.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn string_in(v: Option<&Value>, re: &Regex) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| re.is_match(s)).map(String::from)
}

/// `z.number().int().min(a).max(b)`.
fn int_in(v: &Value, min: i64, max: i64) -> Option<i64> {
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f >= min as f64 && f <= max as f64).then_some(f as i64)
}

/// Only these keys (`.strict()`).
fn strict(m: &Map<String, Value>, allowed: &[&str]) -> bool {
    m.keys().all(|k| allowed.contains(&k.as_str()))
}

// ---- Speech and wake policies (`@controlclaw/meetings`, in `meetings::policy`) ---------------

/// `parseSpeechPolicy` on `{provider, credentialId, model, maxMinutes}`: whether it is accepted.
fn speech_policy_ok(provider: &str, credential: &str, model: &str, max_minutes: i64) -> bool {
    let speech = json!({"provider": provider, "credentialId": credential, "model": model, "maxMinutes": max_minutes});
    policy::parse_speech_policy(Some(&speech)).is_ok()
}

/// `parseWakePolicy`, once the shape is right: `None` where it throws.
fn wake_policy(v: &Map<String, Value>) -> Option<()> {
    policy::parse_wake_policy(Some(&Value::Object(v.clone())))
        .ok()
        .map(|_| ())
}

// ---- The apply ----------------------------------------------------------------------------

/// `parsePhoneApply`: the settings as zod outputs them (keys in schema order), or `None`.
pub fn parse_phone_apply(raw: Option<&Value>) -> Option<Value> {
    let m = raw?.as_object()?;
    let generation = string_in(m.get("generation"), &GENERATION)?;
    if m.get("placeholder").is_some_and(Value::is_null) {
        return strict(m, &["generation", "placeholder"])
            .then(|| json!({"generation": generation, "placeholder": null}));
    }
    let allowed = [
        "generation",
        "placeholder",
        "accountSid",
        "fromNumber",
        "publicUrl",
        "allowFrom",
        "allowAll",
        "speech",
        "maxDurationSeconds",
        "maxConcurrentCalls",
        "wake",
    ];
    if !strict(m, &allowed) {
        return None;
    }
    let mut out = Map::new();
    out.insert("generation".into(), json!(generation));
    out.insert(
        "placeholder".into(),
        json!(string_in(m.get("placeholder"), &PLACEHOLDER)?),
    );
    out.insert("accountSid".into(), json!(string_in(m.get("accountSid"), &ACCOUNT)?));
    out.insert("fromNumber".into(), json!(string_in(m.get("fromNumber"), &NUMBER)?));
    let public = m.get("publicUrl")?.as_str()?;
    let u = url::Url::parse(public).ok()?;
    let url_ok = u.scheme() == "https"
        && HOOK_PATH.is_match(u.path())
        && u.query().is_none_or(str::is_empty)
        && u.fragment().is_none_or(str::is_empty)
        && u.username().is_empty()
        && u.password().is_none_or(str::is_empty);
    if !url_ok {
        return None;
    }
    out.insert("publicUrl".into(), json!(public));
    let allow = m.get("allowFrom")?.as_array()?;
    if allow.len() > 50 || !allow.iter().all(|n| n.as_str().is_some_and(|s| NUMBER.is_match(s))) {
        return None;
    }
    out.insert("allowFrom".into(), Value::Array(allow.clone()));
    out.insert("allowAll".into(), json!(m.get("allowAll")?.as_bool()?));
    match m.get("speech") {
        None => {}
        Some(Value::Null) => {
            out.insert("speech".into(), Value::Null);
        }
        Some(Value::Object(s)) => {
            if !strict(s, &["provider", "credentialId", "model", "maxMinutes", "placeholder"]) {
                return None;
            }
            let provider = s
                .get("provider")?
                .as_str()
                .filter(|p| ["gateway", "openai", "codex"].contains(p))?;
            let credential = s
                .get("credentialId")?
                .as_str()
                .filter(|c| (1..=100).contains(&js_len(c)))?;
            let model = s.get("model")?.as_str().filter(|c| (1..=100).contains(&js_len(c)))?;
            int_in(s.get("maxMinutes")?, 5, 5)?;
            let placeholder = string_in(s.get("placeholder"), &SPEECH_PLACEHOLDER)?;
            if !speech_policy_ok(provider, credential, model, 5) {
                return None;
            }
            out.insert(
                "speech".into(),
                json!({"provider": provider, "credentialId": credential, "model": model, "maxMinutes": 5, "placeholder": placeholder}),
            );
        }
        Some(_) => return None,
    }
    if let Some(v) = m.get("maxDurationSeconds") {
        out.insert("maxDurationSeconds".into(), json!(int_in(v, 60, 3600)?));
    }
    if let Some(v) = m.get("maxConcurrentCalls") {
        out.insert("maxConcurrentCalls".into(), json!(int_in(v, 1, 5)?));
    }
    if let Some(w) = m.get("wake") {
        let w = w.as_object()?;
        let words = w.get("words")?.as_array()?;
        if !strict(w, &["enabled", "words"])
            || !w.get("enabled")?.is_boolean()
            || words.is_empty()
            || words.len() > 5
            || !words.iter().all(Value::is_string)
        {
            return None;
        }
        // The meetings package's own checks, once the shape is right.
        wake_policy(w)?;
        out.insert("wake".into(), json!({"enabled": w["enabled"], "words": words}));
    }
    Some(Value::Object(out))
}

/// What the stream relay checks against, from parsed settings.
pub fn stream_binding(input: &Value) -> StreamBinding {
    StreamBinding {
        generation: input["generation"].as_str().unwrap_or_default().to_string(),
        placeholder: input["placeholder"].as_str().map(String::from),
        speech: input.get("speech").is_some_and(|s| !s.is_null()),
        public_url: input["publicUrl"].as_str().unwrap_or_default().to_string(),
        max_concurrent_calls: input["maxConcurrentCalls"].as_u64(),
        max_duration_seconds: input["maxDurationSeconds"].as_u64(),
    }
}

/// `phoneConfig`: the voice-call plugin entry for settings with a placeholder.
pub fn phone_config(input: &Value, response_model: &str) -> Value {
    let speech = input.get("speech").filter(|s| !s.is_null());
    let wake = input.get("wake");
    let max_duration = input["maxDurationSeconds"].as_i64().unwrap_or(300);
    let realtime = match speech {
        Some(speech) => {
            let wake_on = wake.is_some_and(|w| truthy(w.get("enabled")));
            let how = if wake_on {
                let words: Vec<&str> = wake
                    .and_then(|w| w["words"].as_array())
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                format!("answer only caller turns that start with {}", words.join(" or "))
            } else {
                "answer caller turns without a wake name".to_string()
            };
            let mut provider = speech.as_object().cloned().unwrap_or_default();
            // Shared voice adapter accepts 5–60 minutes; the call deadline enforces shorter limits.
            provider.insert("maxMinutes".into(), json!(5.max((max_duration + 59) / 60)));
            provider.insert("surface".into(), json!("phone"));
            provider.insert("interruptResponseOnInputAudio".into(), json!(false));
            if let Some(w) = wake {
                provider.insert("wake".into(), w.clone());
            }
            json!({
                "enabled": true,
                "provider": "cc-phone-voice",
                "streamPath": "/voice/stream/realtime",
                "toolPolicy": "safe-read-only",
                "consultPolicy": "auto",
                "fastContext": {"enabled": false},
                "agentContext": {"enabled": false},
                "instructions": format!("You are on a phone call. Greet once, then {how}. The caller is not an owner. Use ask_agent for read-only memory and research. Keep replies brief."),
                "providers": {"cc-phone-voice": provider},
            })
        }
        None => json!({"enabled": false}),
    };
    json!({
        "enabled": true,
        "config": {
            "provider": "twilio",
            "twilio": {"accountSid": input["accountSid"], "authToken": input["placeholder"]},
            "fromNumber": input["fromNumber"],
            "publicUrl": input["publicUrl"],
            "serve": {"bind": "127.0.0.1", "port": 8789, "path": "/voice/webhook"},
            "tunnel": {"provider": "none"},
            "tailscale": {"mode": "off"},
            "streaming": {"enabled": false},
            "realtime": realtime,
            "skipSignatureVerification": false,
            "webhookSecurity": {"trustForwardingHeaders": false},
            "inboundPolicy": if input["allowAll"].as_bool() == Some(true) { "open" } else { "allowlist" },
            "allowFrom": input["allowFrom"],
            "outbound": {"defaultMode": "conversation"},
            "agentId": "main",
            "responseModel": response_model,
            "inboundGreeting": "Hello! How can I help you today?",
            // Below the reply deadline in phone-reply-compat.ts, which is below the 30 s wait pause.
            "responseTimeoutMs": 24000,
            "responseSystemPrompt": "You are a helpful phone assistant. Answer in one short plain sentence unless more detail is requested. Do not use markdown, formatting marks, or punctuation-only utterances. Phone callers are not authorized owners.",
            "sessionScope": "per-call",
            "maxConcurrentCalls": input["maxConcurrentCalls"].as_i64().unwrap_or(1),
            "maxDurationSeconds": max_duration,
        },
    })
}

/// `phoneConfigMatches`: every expected value is in the live entry (arrays exactly), with
/// OpenClaw's redacted auth token standing for any.
pub fn phone_config_matches(actual: Option<&Value>, expected: &Value) -> bool {
    match expected {
        Value::Object(e) => {
            let Some(Value::Object(a)) = actual else { return false };
            e.iter().all(|(k, v)| {
                (k == "authToken" && a.get(k).and_then(Value::as_str) == Some(super::model::OPENCLAW_REDACTED))
                    || phone_config_matches(a.get(k), v)
            })
        }
        Value::Array(_) => {
            // `JSON.stringify(actual) === JSON.stringify(expected)`; only an object is compared so.
            matches!(actual, Some(a) if a.is_object() || a.is_array()) && actual == Some(expected)
        }
        // `===`: one number, however JSON wrote it.
        Value::Number(n) => actual.and_then(Value::as_f64).is_some_and(|a| Some(a) == n.as_f64()),
        other => actual == Some(other),
    }
}

/// `trustedPhoneInstall`: OpenClaw trusts state storage only for plugins with official npm
/// provenance, so the install receipt must be exactly the pinned package.
pub fn trusted_phone_install(info: &Value) -> bool {
    let Some(i) = info.get("install") else { return false };
    let s = |k: &str| i.get(k).and_then(Value::as_str);
    s("source") == Some("npm")
        && s("spec") == Some(PHONE_PACKAGE)
        && s("resolvedName") == Some("@openclaw/voice-call")
        && s("resolvedVersion") == Some("2026.9.7")
        && s("integrity") == Some(PHONE_INTEGRITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        json!({
            "generation": "a".repeat(32),
            "placeholder": format!("CC-TWILIO-{}", "b".repeat(32)),
            "accountSid": format!("AC{}", "c".repeat(32)),
            "fromNumber": "+14155550123",
            "publicUrl": format!("https://firewall.example/hook/hk_{}", "d".repeat(32)),
            "allowFrom": ["+14155550999"],
            "allowAll": false,
        })
    }

    fn with(mut v: Value, k: &str, x: Value) -> Value {
        v[k] = x;
        v
    }

    /// `phone.test.ts`: "phone config uses loopback, classic speech, placeholder and exact caller
    /// policy".
    #[test]
    fn phone_config_loopback_classic_placeholder_policy() {
        let parsed = parse_phone_apply(Some(&input())).expect("valid");
        let config = phone_config(&parsed, "controlclaw/test-model@controlclaw:included");
        let c = &config["config"];
        assert_eq!(
            c["serve"],
            json!({"bind": "127.0.0.1", "port": 8789, "path": "/voice/webhook"})
        );
        assert_eq!(c["twilio"]["authToken"], input()["placeholder"]);
        assert_eq!(c["responseModel"], "controlclaw/test-model@controlclaw:included");
        assert_eq!(c["streaming"]["enabled"], false);
        assert_eq!(c["realtime"]["enabled"], false);
        assert_eq!(c["skipSignatureVerification"], false);
        assert_eq!(c["inboundPolicy"], "allowlist");
        assert!(phone_config_matches(Some(&config), &config));
        let mut streaming = config.clone();
        streaming["config"]["streaming"]["enabled"] = json!(true);
        assert!(!phone_config_matches(Some(&streaming), &config));
        let mut more = config.clone();
        more["config"]["allowFrom"] = json!(["+14155550999", "+14155550888"]);
        assert!(!phone_config_matches(Some(&more), &config));
        let mut redacted = config.clone();
        redacted["config"]["twilio"]["authToken"] = json!(super::super::model::OPENCLAW_REDACTED);
        assert!(phone_config_matches(Some(&redacted), &config));
        assert!(parse_phone_apply(Some(&with(input(), "authToken", json!("real")))).is_none());
        assert!(
            parse_phone_apply(Some(&with(
                input(),
                "publicUrl",
                json!("http://evil.test/hook/hk_test")
            )))
            .is_none()
        );
        assert!(parse_phone_apply(Some(&with(input(), "placeholder", json!("real-token")))).is_none());
        assert!(parse_phone_apply(Some(&json!({"generation": "a".repeat(32), "placeholder": null}))).is_some());
        assert!(
            parse_phone_apply(Some(
                &json!({"generation": "a".repeat(32), "placeholder": null, "x": 1})
            ))
            .is_none()
        );
    }

    /// "voice plugin must have the pinned official npm provenance and integrity".
    #[test]
    fn pinned_provenance() {
        let install = json!({
            "source": "npm", "spec": PHONE_PACKAGE, "resolvedName": "@openclaw/voice-call",
            "resolvedVersion": "2026.9.7", "integrity": PHONE_INTEGRITY,
        });
        assert!(trusted_phone_install(&json!({"install": install})));
        for (k, v) in [
            ("source", "path"),
            ("spec", "@openclaw/voice-call@latest"),
            ("resolvedName", "voice-call"),
            ("resolvedVersion", "2026.9.8"),
            ("integrity", "sha512-wrong"),
        ] {
            let mut i = install.clone();
            i[k] = json!(v);
            assert!(!trusted_phone_install(&json!({"install": i})), "{k}");
        }
        assert!(!trusted_phone_install(&Value::Null));
    }

    fn speech() -> Value {
        json!({
            "provider": "gateway", "credentialId": "included", "model": "openai/gpt-realtime-1.5",
            "maxMinutes": 5, "placeholder": format!("cc-speech-{}", "f".repeat(48)),
        })
    }

    /// "realtime phone uses fixed transport, non-owner per-call consultation and a separate speech
    /// placeholder" and "classic and realtime plugins receive assignment limits".
    #[test]
    fn realtime_config_and_limits() {
        let raw = with(with(input(), "speech", speech()), "maxDurationSeconds", json!(120));
        let parsed = parse_phone_apply(Some(&raw)).expect("valid");
        let c = phone_config(&parsed, "owner/model@profile")["config"].clone();
        assert_eq!(c["realtime"]["provider"], "cc-phone-voice");
        assert_eq!(c["realtime"]["streamPath"], "/voice/stream/realtime");
        assert_eq!(c["realtime"]["toolPolicy"], "safe-read-only");
        assert_eq!(c["realtime"]["consultPolicy"], "auto");
        let p = &c["realtime"]["providers"]["cc-phone-voice"];
        assert_eq!(p["placeholder"], speech()["placeholder"]);
        assert_eq!(p["maxMinutes"], 5);
        assert_eq!(p["surface"], "phone");
        assert_eq!(c["twilio"]["authToken"], input()["placeholder"]);
        assert_eq!(c["maxDurationSeconds"], 120);
        assert_eq!(c["maxConcurrentCalls"], 1);
        let long = with(with(input(), "speech", speech()), "maxDurationSeconds", json!(1800));
        let long = phone_config(&parse_phone_apply(Some(&long)).expect("valid"), "m");
        assert_eq!(
            long["config"]["realtime"]["providers"]["cc-phone-voice"]["maxMinutes"],
            30
        );
        for bad in [
            with(speech(), "model", json!("openai/gpt-realtime-transcribe")),
            with(speech(), "provider", json!("openai")),
            with(speech(), "maxMinutes", json!(6)),
            with(speech(), "placeholder", json!("cc-speech-short")),
            with(speech(), "extra", json!(1)),
        ] {
            assert!(
                parse_phone_apply(Some(&with(input(), "speech", bad.clone()))).is_none(),
                "{bad}"
            );
        }
        for (k, v) in [
            ("maxDurationSeconds", 59),
            ("maxDurationSeconds", 3601),
            ("maxConcurrentCalls", 6),
        ] {
            assert!(
                parse_phone_apply(Some(&with(input(), k, json!(v)))).is_none(),
                "{k}={v}"
            );
        }
        let three = parse_phone_apply(Some(&with(input(), "maxConcurrentCalls", json!(3)))).expect("valid");
        assert_eq!(phone_config(&three, "m")["config"]["maxConcurrentCalls"], 3);
        assert_eq!(stream_binding(&three).max_concurrent_calls, Some(3));
    }

    /// "the phone voice gets the wake setting, and the instructions follow it".
    #[test]
    fn wake_setting_and_instructions() {
        let raw = with(
            with(input(), "speech", speech()),
            "wake",
            json!({"enabled": true, "words": ["Ada", "Pip Boy"]}),
        );
        let c = phone_config(&parse_phone_apply(Some(&raw)).expect("valid"), "m")["config"].clone();
        assert_eq!(
            c["realtime"]["providers"]["cc-phone-voice"]["wake"],
            json!({"enabled": true, "words": ["Ada", "Pip Boy"]})
        );
        assert!(
            c["realtime"]["instructions"]
                .as_str()
                .unwrap_or_default()
                .contains("start with Ada or Pip Boy")
        );
        let off = with(
            with(input(), "speech", speech()),
            "wake",
            json!({"enabled": false, "words": ["Ada"]}),
        );
        let c = phone_config(&parse_phone_apply(Some(&off)).expect("valid"), "m")["config"].clone();
        assert!(
            c["realtime"]["instructions"]
                .as_str()
                .unwrap_or_default()
                .contains("without a wake name")
        );
        for words in [
            json!([]),
            json!(["ok"]),
            json!(["Ada", "ada"]),
            json!(["hey team"]),
            json!([1]),
        ] {
            let bad = with(
                with(input(), "speech", speech()),
                "wake",
                json!({"enabled": true, "words": words}),
            );
            assert!(parse_phone_apply(Some(&bad)).is_none(), "{words}");
        }
    }

    #[test]
    fn speech_families() {
        assert_eq!(speech_family("gateway", "openai/gpt-realtime"), Some("realtime"));
        assert_eq!(speech_family("gateway", "openai/gpt-realtime-2.1"), Some("realtime"));
        assert_eq!(speech_family("gateway", "openai/gpt-live-1"), Some("live"));
        assert_eq!(speech_family("gateway", "openai/gpt-realtime-mini-transcribe"), None);
        assert_eq!(speech_family("openai", "gpt-realtime-whisper"), None);
        assert_eq!(speech_family("codex", "gpt-realtime"), Some("realtime"));
        assert_eq!(speech_family("codex", "gpt-realtime-2"), None);
        assert_eq!(speech_family("other", "gpt-realtime"), None);
    }
}
