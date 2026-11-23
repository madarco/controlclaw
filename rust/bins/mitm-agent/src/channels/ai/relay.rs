//! `ai.relay`: one model call of an AI Log Review investigation (docs/plans/ai-log-review-agent.md).
//!
//! The investigation runs in the control plane, which never holds a model key. Its AI SDK provider
//! hands each HTTP request to this command instead of sending it; the firewall checks the request,
//! puts the organization's key in and sends it to the provider's one generate endpoint, then hands
//! back the answer. What it refuses: another provider than the review's, another endpoint or model,
//! streaming, a body over 256 KB, Log Review off, and calls past the daily caps. Every header but the
//! provider's own is dropped, so the caller cannot add anything the provider would act on. The tokens
//! are counted as `log_review_agent` in the firewall's AI usage.

use std::collections::BTreeMap;
use std::time::Duration;

use cc_contracts::commands::ai::Relay;
use cc_llm::structured::{ANTHROPIC_BASE_URL, GOOGLE_BASE_URL, OPENAI_BASE_URL};
use cc_llm::{AiSettings, GATEWAY_BASE_URL, Provider, is_decision_model, provider_options_for};
use serde_json::{Map, Value, json};

use super::model::AiClient;
use crate::commands::CommandOutcome;

/// The usage purpose: "Log Review investigations" on the AI usage page.
pub const PURPOSE: &str = "log_review_agent";
/// Model calls a day for investigations, on top of the review's own daily cap they also count in.
pub const RELAY_DAILY_CAP: u64 = 300;
/// The model an investigation uses on the AI Gateway when the review's model is a decision model
/// (Jev answers questions only). The included tokens cover it (apps/saas `INCLUDED_MODELS`).
pub const GATEWAY_AGENT_MODEL: &str = "openai/gpt-5.4-mini";
const BODY_MAX: usize = 256 * 1024;
const ANSWER_MAX: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(60);

/// Where each provider is reached; the tests point them at a stand-in.
#[derive(Clone)]
pub struct Targets {
    pub gateway: String,
    pub openai: String,
    pub anthropic: String,
    pub google: String,
}

impl Default for Targets {
    fn default() -> Self {
        Self {
            gateway: GATEWAY_BASE_URL.into(),
            openai: OPENAI_BASE_URL.into(),
            anthropic: ANTHROPIC_BASE_URL.into(),
            google: GOOGLE_BASE_URL.into(),
        }
    }
}

/// The model an investigation may use with these settings.
pub fn agent_model(s: &AiSettings) -> String {
    match s.provider {
        Provider::VercelGateway | Provider::ControlclawIncluded if is_decision_model(&s.model) => {
            GATEWAY_AGENT_MODEL.into()
        }
        _ => s.model.clone(),
    }
}

/// A request ready to send.
#[derive(Debug, PartialEq)]
pub struct Outgoing {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub model: String,
}

fn refuse(message: &str) -> Result<Outgoing, String> {
    Err(message.to_string())
}

fn header<'a>(h: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Check a relay request against the settings and build what goes out. Pure, for the tests.
pub fn prepare(s: &AiSettings, key: &str, req: &Relay, t: &Targets) -> Result<Outgoing, String> {
    if Provider::parse(&req.provider) != Some(s.provider) {
        return refuse("The request is not for the provider AI Log Review uses.");
    }
    if req.body.len() > BODY_MAX {
        return refuse("The request is too large.");
    }
    let mut body: Value = match serde_json::from_str(&req.body) {
        Ok(v @ Value::Object(_)) => v,
        _ => return refuse("The request body is not a JSON object."),
    };
    if body.get("stream").is_some_and(|v| v != &Value::Bool(false)) {
        return refuse("Streaming is not relayed.");
    }
    let model = agent_model(s);
    let mut headers: Vec<(String, String)> = vec![("content-type".into(), "application/json".into())];
    let url = match s.provider {
        Provider::VercelGateway | Provider::ControlclawIncluded => {
            if req.path != "/language-model" {
                return refuse("Only the Gateway's language model endpoint is relayed.");
            }
            if header(&req.headers, "ai-language-model-streaming") != Some("false") {
                return refuse("Streaming is not relayed.");
            }
            if header(&req.headers, "ai-language-model-id") != Some(model.as_str()) {
                return refuse("The request is for another model.");
            }
            let version = match header(&req.headers, "ai-language-model-specification-version") {
                None => "4",
                Some(v @ ("2" | "3" | "4")) => v,
                Some(_) => return refuse("The request names an unknown specification version."),
            };
            headers.extend([
                ("authorization".into(), format!("Bearer {key}")),
                ("ai-gateway-auth-method".into(), "api-key".into()),
                ("ai-gateway-protocol-version".into(), "0.0.1".into()),
                ("ai-language-model-specification-version".into(), version.to_string()),
                ("ai-language-model-id".into(), model.clone()),
                ("ai-language-model-streaming".into(), "false".into()),
            ]);
            // Zero data retention, whatever the caller asked for.
            let opts = provider_options_for(s.provider, &model);
            if let Some(o) = body.as_object_mut() {
                let po = o.entry("providerOptions").or_insert_with(|| json!({}));
                if !po.is_object() {
                    *po = json!({});
                }
                if let (Some(po), Some(add)) = (po.as_object_mut(), opts.as_object()) {
                    for (k, v) in add {
                        po.insert(k.clone(), v.clone());
                    }
                }
            }
            format!("{}/language-model", t.gateway.trim_end_matches('/'))
        }
        Provider::OpenAi => {
            if req.path != "/responses" {
                return refuse("Only OpenAI's responses endpoint is relayed.");
            }
            if body.get("model").and_then(Value::as_str) != Some(model.as_str()) {
                return refuse("The request is for another model.");
            }
            headers.push(("authorization".into(), format!("Bearer {key}")));
            format!("{}/responses", t.openai.trim_end_matches('/'))
        }
        Provider::Anthropic => {
            if req.path != "/messages" {
                return refuse("Only Anthropic's messages endpoint is relayed.");
            }
            if body.get("model").and_then(Value::as_str) != Some(model.as_str()) {
                return refuse("The request is for another model.");
            }
            headers.extend([
                ("x-api-key".into(), key.to_string()),
                ("anthropic-version".into(), "2023-06-01".into()),
            ]);
            format!("{}/messages", t.anthropic.trim_end_matches('/'))
        }
        Provider::Google => {
            let name = model.strip_prefix("models/").unwrap_or(&model);
            if req.path != format!("/models/{name}:generateContent") {
                return refuse("Only the review model's generateContent endpoint is relayed.");
            }
            headers.push(("x-goog-api-key".into(), key.to_string()));
            format!("{}/models/{name}:generateContent", t.google.trim_end_matches('/'))
        }
    };
    Ok(Outgoing {
        url,
        headers,
        body: body.to_string(),
        model,
    })
}

/// The tokens a provider's answer reports: (input, output).
pub fn usage_of(provider: Provider, body: &Value) -> (Option<u64>, Option<u64>) {
    // A LanguageModelV4 total is `{total, ...}`; older ones a number.
    let total = |v: &Value| v.get("total").and_then(Value::as_u64).or_else(|| v.as_u64());
    match provider {
        Provider::VercelGateway | Provider::ControlclawIncluded => (
            total(&body["usage"]["inputTokens"]),
            total(&body["usage"]["outputTokens"]),
        ),
        p => {
            let (_, _, u) = cc_llm::structured::read_response(p, body);
            (u.input_tokens, u.output_tokens)
        }
    }
}

/// Run one relay: check it, send it, count it.
pub async fn run(client: &AiClient, http: &reqwest::Client, targets: &Targets, req: Relay) -> CommandOutcome {
    let Some((s, key)) = client.ready() else {
        return CommandOutcome::failed("off", "AI Log Review has no model key on this firewall.");
    };
    if !s.log_review {
        return CommandOutcome::failed("off", "AI Log Review is off.");
    }
    let out = match prepare(&s, &key, &req, targets) {
        Ok(o) => o,
        Err(m) => return CommandOutcome::failed("refused", m),
    };
    if !client.take_caps(&[("review".into(), s.daily_call_cap), ("relay".into(), RELAY_DAILY_CAP)]) {
        return CommandOutcome::failed("capped", "Today's model calls for AI Log Review are used up.");
    }
    let mut rb = http.post(&out.url).timeout(TIMEOUT).body(out.body);
    for (k, v) in &out.headers {
        rb = rb.header(k, v);
    }
    let res = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            let why = if e.is_timeout() { "timed out" } else { "failed" };
            tracing::info!("[ai] relay: the request {why}");
            return CommandOutcome::failed("unreachable", format!("The provider request {why}."));
        }
    };
    let status = res.status().as_u16();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let text = match res.bytes().await {
        Ok(b) if b.len() <= ANSWER_MAX => String::from_utf8_lossy(&b).into_owned(),
        Ok(_) => return CommandOutcome::failed("too_large", "The provider's answer is too large."),
        Err(_) => return CommandOutcome::failed("unreachable", "The provider's answer was cut off."),
    };
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let (input, output) = if (200..300).contains(&status) {
        usage_of(s.provider, &parsed)
    } else {
        (None, None)
    };
    client.count(s.provider.as_str(), &out.model, PURPOSE, input, output);
    let mut data = Map::new();
    data.insert("status".into(), json!(status));
    data.insert("contentType".into(), json!(content_type));
    data.insert("body".into(), json!(text));
    CommandOutcome {
        ok: true,
        status: "done".into(),
        message: None,
        data: Some(data),
    }
}
