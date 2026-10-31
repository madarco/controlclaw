//! What the shipper strips from AgentMail and phone records before they leave the box
//! (`agentmail-activity.ts`, `phone-activity.ts`): mail and call content, signatures and provider
//! credentials never belong in Activity. Ported here because the shipper applies them to every
//! batch; the files are W4's, and W4 uses these.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use super::identities::js_number_string;

/// `String(v)` for a JSON value (`undefined` for a missing one).
pub fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => js_number_string(n),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

fn truthy(v: Option<&Value>) -> bool {
    v.is_some_and(super::sync::js_truthy)
}

fn pick(r: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|k| r.get(*k).map(|v| ((*k).to_string(), v.clone())))
        .collect()
}

/// `sanitizeAgentMailActivity`.
pub fn agentmail(raw: Value) -> Value {
    let Some(r) = raw.as_object() else { return raw };
    let host = r.get("host").and_then(Value::as_str);
    if host != Some("api.agentmail.to") && host != Some("ws.agentmail.to") {
        return raw;
    }
    const RESOURCES: &[&str] = &[
        "v0",
        "inboxes",
        "messages",
        "threads",
        "drafts",
        "attachments",
        "send",
        "reply",
        "reply-all",
        "forward",
        "raw",
        "api-keys",
        "organizations",
    ];
    let path = r.get("path").and_then(Value::as_str).map(|p| {
        p.split('?')
            .next()
            .unwrap_or_default()
            .split('/')
            .map(|s| {
                if s.is_empty() || RESOURCES.contains(&s) {
                    s
                } else {
                    "{id}"
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    });
    let mut out = pick(
        r,
        &[
            "source",
            "flow_id",
            "ts",
            "vm_id",
            "host",
            "port",
            "effect",
            "status",
            "duration_ms",
            "bytes_in",
            "bytes_out",
            "email",
            "email_reason",
            "rule_id",
        ],
    );
    let method = js_string(r.get("method"));
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    out.insert(
        "method".into(),
        if methods.contains(&method.as_str()) {
            r.get("method").cloned().unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    if let Some(p) = path {
        out.insert("path".into(), Value::String(p));
    }
    let rule = if r.get("rule") == Some(&Value::String("email".into())) {
        "email"
    } else {
        "agentmail"
    };
    out.insert("rule".into(), Value::String(rule.into()));
    if truthy(r.get("error")) {
        out.insert("error".into(), Value::String("AgentMail request failed".into()));
    }
    Value::Object(out)
}

// Transcription and translation models share the gpt-realtime prefix and are not voice models.
static REALTIME_REST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9.-]{0,23}$").expect("regex"));
static GATEWAY_LIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^openai/gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?$").expect("regex"));
static OPENAI_LIVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?$").expect("regex"));

/// `^<prefix>(?:-(?!…(whisper|translate|transcribe))[a-z0-9][a-z0-9.-]{0,23})?$` without lookahead.
fn realtime(model: &str, prefix: &str) -> bool {
    let Some(rest) = model.strip_prefix(prefix) else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some(rest) = rest.strip_prefix('-') else {
        return false;
    };
    REALTIME_REST.is_match(rest) && !["whisper", "translate", "transcribe"].iter().any(|w| rest.contains(w))
}

/// `speechFamily` in `@controlclaw/meetings`.
pub fn speech_family(provider: &str, model: &str) -> Option<&'static str> {
    let (rt, live) = match provider {
        "gateway" => (realtime(model, "openai/gpt-realtime"), GATEWAY_LIVE.is_match(model)),
        "openai" => (realtime(model, "gpt-realtime"), OPENAI_LIVE.is_match(model)),
        "codex" => (model == "gpt-realtime", false),
        _ => return None,
    };
    if rt {
        Some("realtime")
    } else if live {
        Some("live")
    } else {
        None
    }
}

static STREAM_RULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^phone stream: (open|close|refusal) (admission|verified|transport|completed|invalid_frame|invalid_agent_frame|backpressure|start_timeout|revoked|admission_expired|shutdown|lease_error) (inbound|outbound|unknown) (gateway|openai|codex|classic) (\S{1,100})$").expect("regex")
});
static PHONE_RULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^phone: (outbound|call) \*{4}[0-9]{4}$").expect("regex"));
static PHONE_HOOK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^Phone \(Twilio\) \*{4}[0-9]{4}$").expect("regex"));

fn phone_stream_rule(rule: &str) -> bool {
    let Some(m) = STREAM_RULE.captures(rule) else {
        return false;
    };
    let (provider, model) = (&m[4], &m[5]);
    if provider == "classic" {
        model == "none"
    } else {
        speech_family(provider, model).is_some()
    }
}

/// `sanitizePhoneActivity`.
pub fn phone(raw: Value) -> Value {
    let Some(r) = raw.as_object() else { return raw };
    let hook_name = match r.get("hook_name") {
        None | Some(Value::Null) => String::new(),
        v => js_string(v),
    };
    if r.get("host").and_then(Value::as_str) != Some("api.twilio.com")
        && r.get("rule").and_then(Value::as_str) != Some("phone")
        && !hook_name.starts_with("Phone (Twilio)")
    {
        return raw;
    }
    if r.get("source").and_then(Value::as_str) == Some("webhook") {
        let mut out = pick(
            r,
            &[
                "source",
                "delivery_id",
                "ts",
                "hook_id",
                "verdict",
                "target_vm_id",
                "forward_status",
                "bytes",
                "duration_ms",
                "arrived",
            ],
        );
        let named = PHONE_HOOK.is_match(&js_string(r.get("hook_name")));
        out.insert(
            "hook_name".into(),
            if named {
                r.get("hook_name").cloned().unwrap_or(Value::Null)
            } else {
                Value::String("Phone (Twilio)".into())
            },
        );
        if truthy(r.get("reason")) {
            out.insert("reason".into(), Value::String("Phone delivery refused".into()));
        }
        return Value::Object(out);
    }
    let mut out = pick(
        r,
        &[
            "source",
            "flow_id",
            "ts",
            "vm_id",
            "host",
            "port",
            "effect",
            "status",
            "duration_ms",
            "bytes_in",
            "bytes_out",
        ],
    );
    let rule = js_string(r.get("rule"));
    out.insert(
        "rule".into(),
        if phone_stream_rule(&rule) || PHONE_RULE.is_match(&rule) {
            r.get("rule").cloned().unwrap_or(Value::Null)
        } else {
            Value::String("phone".into())
        },
    );
    let method = js_string(r.get("method"));
    out.insert(
        "method".into(),
        if ["GET", "POST", "WS"].contains(&method.as_str()) {
            r.get("method").cloned().unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    const RESOURCES: &[&str] = &["", "2010-04-01", "Accounts", "Calls", "Calls.json"];
    let path = if r.get("method").and_then(Value::as_str) == Some("WS")
        && r.get("path").and_then(Value::as_str) == Some("/phone-stream/[stream]")
    {
        "/phone-stream/[stream]".to_string()
    } else if let (Some("api.twilio.com"), Some(p)) = (
        r.get("host").and_then(Value::as_str),
        r.get("path").and_then(Value::as_str),
    ) {
        p.split('?')
            .next()
            .unwrap_or_default()
            .split('/')
            .map(|s| if RESOURCES.contains(&s) { s } else { "{id}" })
            .collect::<Vec<_>>()
            .join("/")
    } else {
        "/hook/{id}".to_string()
    };
    out.insert("path".into(), Value::String(path));
    if truthy(r.get("error")) {
        out.insert("error".into(), Value::String("Phone request failed".into()));
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn agentmail_records_lose_content() {
        let r = agentmail(
            json!({"host": "api.agentmail.to", "path": "/v0/inboxes/abc@x/messages/m1?x=1", "method": "POST", "flow_id": "f", "subject": "secret", "error": "boom"}),
        );
        assert_eq!(
            r,
            json!({"flow_id": "f", "host": "api.agentmail.to", "method": "POST", "path": "/v0/inboxes/{id}/messages/{id}", "rule": "agentmail", "error": "AgentMail request failed"})
        );
        let other = json!({"host": "example.com", "subject": "kept"});
        assert_eq!(agentmail(other.clone()), other);
    }

    #[test]
    fn phone_records_lose_content() {
        let r = phone(
            json!({"host": "api.twilio.com", "path": "/2010-04-01/Accounts/AC1/Calls.json", "method": "PUT", "rule": "x", "body": "y"}),
        );
        assert_eq!(
            r,
            json!({"host": "api.twilio.com", "rule": "phone", "method": null, "path": "/2010-04-01/Accounts/{id}/Calls.json"})
        );
        let r = phone(json!({"source": "webhook", "hook_name": "Phone (Twilio) ****1234", "reason": "x", "secret": 1}));
        assert_eq!(
            r,
            json!({"source": "webhook", "hook_name": "Phone (Twilio) ****1234", "reason": "Phone delivery refused"})
        );
        let rule = "phone stream: open verified inbound gateway openai/gpt-realtime-2";
        assert_eq!(phone(json!({"rule": "phone", "x": 1}))["rule"], json!("phone"));
        assert!(phone_stream_rule(rule));
        assert!(!phone_stream_rule(
            "phone stream: open verified inbound gateway openai/gpt-realtime-transcribe"
        ));
        assert!(phone_stream_rule("phone stream: close completed outbound classic none"));
    }

    #[test]
    fn speech_families() {
        assert_eq!(speech_family("gateway", "openai/gpt-realtime"), Some("realtime"));
        assert_eq!(speech_family("gateway", "openai/gpt-realtime-mini"), Some("realtime"));
        assert_eq!(speech_family("openai", "gpt-realtime-whisper-1"), None);
        assert_eq!(speech_family("openai", "gpt-live-1.5"), Some("live"));
        assert_eq!(speech_family("codex", "gpt-realtime"), Some("realtime"));
        assert_eq!(speech_family("codex", "gpt-live-1"), None);
        assert_eq!(speech_family("toString", "x"), None);
    }
}
