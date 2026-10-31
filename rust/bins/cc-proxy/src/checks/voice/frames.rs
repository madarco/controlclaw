//! What a voice socket may carry from the agent (addon.py `live_client_event`,
//! `voice_client_event`) and which speech models the firewall knows how to police
//! (`speech_family`, `_SPEECH_FAMILIES`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

pub const LIVE_VOICES: [&str; 10] = [
    "marin", "cedar", "alloy", "ash", "ballad", "coral", "echo", "sage", "shimmer", "verse",
];
pub const LIVE_MAX_APPENDS: u64 = 400;

#[allow(clippy::expect_used)] // a fixed expression, checked by the tests
static LIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?$").expect("valid"));

/// `gpt-realtime` and `_REALTIME_SUFFIX`: a suffix of a dash, then up to 24 of `[a-z0-9.-]`
/// starting with a letter or digit, naming no transcription or translation model.
fn realtime(model: &str) -> bool {
    let Some(rest) = model.strip_prefix("gpt-realtime") else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some(suffix) = rest.strip_prefix('-') else {
        return false;
    };
    let b = suffix.as_bytes();
    (1..=24).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-'))
        && !["whisper", "translate", "transcribe"]
            .iter()
            .any(|w| suffix.contains(w))
}

/// `speech_family`: `realtime` or `live` for a model of a family the firewall polices; `None` else.
pub fn speech_family(provider: &str, model: &str) -> Option<&'static str> {
    match provider {
        "gateway" => {
            let m = model.strip_prefix("openai/")?;
            if realtime(m) {
                Some("realtime")
            } else if LIVE.is_match(m) {
                Some("live")
            } else {
                None
            }
        }
        "openai" => {
            if realtime(model) {
                Some("realtime")
            } else if LIVE.is_match(model) {
                Some("live")
            } else {
                None
            }
        }
        "codex" => (model == "gpt-realtime").then_some("realtime"),
        _ => None,
    }
}

/// Python `==` between JSON values: numbers by value (`512.0 == 512`, `True == 1`), objects by
/// their keys whatever the order.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(v, w)| py_eq(v, w)),
        _ => match (number(a), number(b)) {
            (Some(x), Some(y)) => x == y,
            _ => a == b,
        },
    }
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        _ => None,
    }
}

/// `set(obj) - allowed` is empty.
fn only(obj: &Map<String, Value>, allowed: &[&str]) -> bool {
    obj.keys().all(|k| allowed.contains(&k.as_str()))
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// `live_client_event`: gpt-live frames from the agent. `state` is this socket's: whether
/// `session.start` was seen, and how many appends.
pub fn live_client_event(event: &Map<String, Value>, model: &str, state: &mut Map<String, Value>) -> bool {
    let kind = event.get("type").and_then(Value::as_str);
    if state.get("started") != Some(&Value::Bool(true)) {
        // The first frame starts the session, once, with settings the firewall can vouch for: the
        // bound model, nothing stored, client delegation only, 24 kHz PCM and a known voice.
        let Some(session) = event.get("session").and_then(Value::as_object) else {
            return false;
        };
        if kind != Some("session.start") || !only(event, &["type", "session", "event_id"]) {
            return false;
        }
        if !only(session, &["model", "store", "delegation", "audio", "instructions"])
            || session.get("model").and_then(Value::as_str) != Some(model)
        {
            return false;
        }
        if session.get("store") != Some(&Value::Bool(false))
            || !session
                .get("delegation")
                .is_some_and(|d| py_eq(d, &serde_json::json!({"type": "client"})))
        {
            return false;
        }
        match session.get("instructions") {
            None => {}
            Some(Value::String(s)) if chars(s) <= 32000 => {}
            Some(_) => return false,
        }
        let empty = Map::new();
        let audio = match session.get("audio") {
            None => &empty,
            Some(Value::Object(a)) => a,
            Some(_) => return false,
        };
        if !only(audio, &["format", "output"])
            || audio
                .get("format")
                .is_some_and(|f| !py_eq(f, &serde_json::json!({"type": "audio/pcm", "rate": 24000})))
        {
            return false;
        }
        let output = match audio.get("output") {
            None => &empty,
            Some(Value::Object(o)) => o,
            Some(_) => return false,
        };
        let voice_ok = match output.get("voice") {
            None => true,
            Some(Value::String(v)) => LIVE_VOICES.contains(&v.as_str()),
            Some(_) => false,
        };
        if !only(output, &["voice"]) || !voice_ok {
            return false;
        }
        state.insert("started".into(), Value::Bool(true));
        return true;
    }
    match kind {
        Some("session.input_audio.append") => {
            only(event, &["type", "audio", "event_id"]) && event.get("audio").is_some_and(Value::is_string)
        }
        Some("session.input_audio.mute" | "session.input_audio.unmute" | "session.close") => {
            only(event, &["type", "event_id"])
        }
        Some("session.thinking.append" | "session.commentary.append") => {
            let appends = state.get("appends").and_then(Value::as_u64).unwrap_or(0) + 1;
            state.insert("appends".into(), Value::from(appends));
            let delegation_ok = match event.get("delegation_id") {
                None | Some(Value::Null) => true,
                Some(Value::String(d)) => chars(d) <= 200,
                Some(_) => false,
            };
            only(event, &["type", "content", "delegation_id", "event_id"])
                && event
                    .get("content")
                    .and_then(Value::as_str)
                    .is_some_and(|c| chars(c) <= 4000)
                && delegation_ok
                && appends <= LIVE_MAX_APPENDS
        }
        // session.update, session.instructions.append, response.* and anything new are refused.
        _ => false,
    }
}

const GATEWAY_KINDS: [&str; 8] = [
    "session-update",
    "input-audio-append",
    "input-audio-commit",
    "input-audio-clear",
    "conversation-item-create",
    "conversation-item-truncate",
    "response-create",
    "response-cancel",
];
const OPENAI_KINDS: [&str; 8] = [
    "session.update",
    "input_audio_buffer.append",
    "input_audio_buffer.commit",
    "input_audio_buffer.clear",
    "conversation.item.create",
    "conversation.item.truncate",
    "response.create",
    "response.cancel",
];

/// `voice_client_event`: a frame from the agent on a voice socket.
pub fn voice_client_event(
    event: &Value,
    provider: &str,
    model: &str,
    family: &str,
    state: &mut Map<String, Value>,
) -> bool {
    let Some(event) = event.as_object() else {
        return false;
    };
    if family == "live" {
        return live_client_event(event, model, state);
    }
    let Some(kind) = event.get("type").and_then(Value::as_str) else {
        return false;
    };
    let openai = matches!(provider, "openai" | "codex");
    let allowed: &[&str] = if openai { &OPENAI_KINDS } else { &GATEWAY_KINDS };
    if !allowed.contains(&kind) {
        return false;
    }
    // Session policy cannot be overridden on an individual response.
    if matches!(kind, "response.create" | "response-create") && !(event.len() == 1 && event.contains_key("type")) {
        return false;
    }
    if !matches!(kind, "session-update" | "session.update") {
        return true;
    }
    let gateway = provider == "gateway";
    let empty = Value::Object(Map::new());
    let config = event.get(if gateway { "config" } else { "session" }).unwrap_or(&empty);
    let Some(config) = config.as_object() else {
        return false;
    };
    if config.get("model").is_some_and(|m| m.as_str() != Some(model)) {
        return false;
    }
    if gateway && config.contains_key("model") {
        return false;
    }
    let cap = Value::from(512);
    if openai && !config.get("max_output_tokens").is_some_and(|m| py_eq(m, &cap)) {
        return false;
    }
    let options = match config.get("providerOptions") {
        None => Map::new(),
        Some(Value::Object(o)) => o.clone(),
        Some(_) => return false,
    };
    if !only(&options, &["audio", "max_output_tokens"]) {
        return false;
    }
    if gateway && (!model.starts_with("openai/") || !options.get("max_output_tokens").is_some_and(|m| py_eq(m, &cap))) {
        return false;
    }
    match config.get("tools") {
        None => true,
        Some(Value::Array(tools)) => {
            tools.len() <= 1
                && tools.iter().all(|t| {
                    t.as_object().is_some_and(|t| {
                        t.get("type").and_then(Value::as_str) == Some("function")
                            && t.get("name").and_then(Value::as_str) == Some("ask_agent")
                    })
                })
        }
        Some(_) => false,
    }
}
