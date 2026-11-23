//! `ai.relay`: what it lets through for each provider, what it refuses, the key it puts in, and the
//! usage it counts. The provider is a local stand-in.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use cc_contracts::commands::ai::Relay;
use cc_http::BoxFuture;
use cc_llm::{AiSettings, Evaluation, LlmError, Provider, Questions};
use cc_testkit::FakeConsole;
use serde_json::{Value, json};

use super::model::{AiClient, ModelCalls};
use super::relay::*;
use super::usage::UsageCounter;

struct NoModels;

impl ModelCalls for NoModels {
    fn evaluate(
        &self,
        _: Provider,
        _: &str,
        _: &str,
        _: Value,
        _: Questions,
        _: Value,
        _: u32,
        _: Duration,
    ) -> BoxFuture<Result<Evaluation, LlmError>> {
        Box::pin(async { Err(LlmError::Timeout) })
    }
    fn explain(
        &self,
        _: Provider,
        _: &str,
        _: &str,
        _: String,
        _: Value,
        _: Duration,
    ) -> BoxFuture<Result<String, LlmError>> {
        Box::pin(async { Err(LlmError::Timeout) })
    }
}

fn settings(provider: Provider, model: &str) -> AiSettings {
    AiSettings {
        credential_id: "cred1".into(),
        provider,
        model: model.into(),
        checks: true,
        log_review: true,
        daily_call_cap: 100,
        scan_interval_hours: 6,
        auto_approve_per_hour: 30,
        request_instructions: None,
        review_instructions: None,
        false_alarms: vec![],
        recent_dismissals: vec![],
        agents: vec![],
    }
}

fn req(provider: &str, path: &str, headers: &[(&str, &str)], body: Value) -> Relay {
    Relay {
        provider: provider.into(),
        path: path.into(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        body: body.to_string(),
        extra: Default::default(),
    }
}

fn gateway_headers(model: &str) -> Vec<(&str, &str)> {
    vec![
        ("ai-language-model-specification-version", "4"),
        ("ai-language-model-id", model),
        ("ai-language-model-streaming", "false"),
    ]
}

#[test]
fn a_decision_model_is_replaced_on_the_gateway_only() {
    assert_eq!(
        agent_model(&settings(Provider::ControlclawIncluded, "typesafe-ai/jev")),
        GATEWAY_AGENT_MODEL
    );
    assert_eq!(
        agent_model(&settings(Provider::VercelGateway, "typesafe-ai/jev")),
        GATEWAY_AGENT_MODEL
    );
    assert_eq!(
        agent_model(&settings(Provider::VercelGateway, "anthropic/claude-haiku-4.5")),
        "anthropic/claude-haiku-4.5"
    );
    assert_eq!(
        agent_model(&settings(Provider::Anthropic, "claude-haiku-4-5")),
        "claude-haiku-4-5"
    );
}

#[test]
fn the_gateway_request_gets_the_key_and_zero_retention() {
    let s = settings(Provider::ControlclawIncluded, "typesafe-ai/jev");
    let t = Targets::default();
    let body = json!({"prompt": [], "providerOptions": {"gateway": {"zeroDataRetention": false}, "openai": {"x": 1}}});
    let mut h = gateway_headers(GATEWAY_AGENT_MODEL);
    h.push(("authorization", "Bearer placeholder"));
    h.push(("x-forwarded-for", "1.2.3.4"));
    let out = prepare(
        &s,
        "vck_secret",
        &req("controlclaw_included", "/language-model", &h, body),
        &t,
    )
    .unwrap();
    assert_eq!(out.url, "https://ai-gateway.vercel.sh/v4/ai/language-model");
    let hv = |k: &str| out.headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(hv("authorization").as_deref(), Some("Bearer vck_secret"));
    assert_eq!(hv("ai-language-model-id").as_deref(), Some(GATEWAY_AGENT_MODEL));
    // Only the provider's own headers go out: the caller's are dropped.
    assert!(hv("x-forwarded-for").is_none());
    assert_eq!(out.headers.iter().filter(|(n, _)| n == "authorization").count(), 1);
    let sent: Value = serde_json::from_str(&out.body).unwrap();
    assert_eq!(sent["providerOptions"]["gateway"]["zeroDataRetention"], true);
    assert_eq!(sent["providerOptions"]["openai"]["x"], 1);
}

#[test]
fn what_is_refused() {
    let t = Targets::default();
    let g = settings(Provider::ControlclawIncluded, "typesafe-ai/jev");
    let ok = gateway_headers(GATEWAY_AGENT_MODEL);
    let refused = |s: &AiSettings, r: Relay| prepare(s, "k", &r, &t).unwrap_err();

    assert!(refused(&g, req("anthropic", "/language-model", &ok, json!({}))).contains("provider"));
    assert!(refused(&g, req("controlclaw_included", "/embedding-model", &ok, json!({}))).contains("endpoint"));
    let other = gateway_headers("anthropic/claude-sonnet-5");
    assert!(refused(&g, req("controlclaw_included", "/language-model", &other, json!({}))).contains("model"));
    let streaming = vec![
        ("ai-language-model-id", GATEWAY_AGENT_MODEL),
        ("ai-language-model-streaming", "true"),
    ];
    assert!(
        refused(
            &g,
            req("controlclaw_included", "/language-model", &streaming, json!({}))
        )
        .contains("Streaming")
    );
    let big = json!({"x": "a".repeat(300 * 1024)});
    assert!(refused(&g, req("controlclaw_included", "/language-model", &ok, big)).contains("large"));
    let mut odd_version = gateway_headers(GATEWAY_AGENT_MODEL);
    odd_version.push(("ai-language-model-specification-version", "4\r\nx-evil: 1"));
    odd_version.remove(0);
    assert!(
        refused(
            &g,
            req("controlclaw_included", "/language-model", &odd_version, json!({}))
        )
        .contains("version")
    );
    let mut not_json = req("controlclaw_included", "/language-model", &ok, json!({}));
    not_json.body = "[1]".into();
    assert!(refused(&g, not_json).contains("JSON object"));

    let a = settings(Provider::Anthropic, "claude-haiku-4-5");
    assert!(
        refused(
            &a,
            req("anthropic", "/messages", &[], json!({"model": "claude-opus-5"}))
        )
        .contains("model")
    );
    assert!(
        refused(
            &a,
            req(
                "anthropic",
                "/messages",
                &[],
                json!({"model": "claude-haiku-4-5", "stream": true})
            )
        )
        .contains("Streaming")
    );
    assert!(
        refused(
            &a,
            req(
                "anthropic",
                "/messages/batches",
                &[],
                json!({"model": "claude-haiku-4-5"})
            )
        )
        .contains("endpoint")
    );

    let o = settings(Provider::OpenAi, "gpt-5.4-mini");
    assert!(refused(&o, req("openai", "/files", &[], json!({"model": "gpt-5.4-mini"}))).contains("endpoint"));
    let gm = settings(Provider::Google, "gemini-3-flash-preview");
    assert!(
        refused(
            &gm,
            req("google", "/models/gemini-3-pro:generateContent", &[], json!({}))
        )
        .contains("endpoint")
    );
    assert!(
        refused(
            &gm,
            req(
                "google",
                "/models/gemini-3-flash-preview:streamGenerateContent",
                &[],
                json!({})
            )
        )
        .contains("endpoint")
    );
}

#[test]
fn each_provider_gets_its_own_key_header() {
    let t = Targets::default();
    let a = prepare(
        &settings(Provider::Anthropic, "claude-haiku-4-5"),
        "sk-ant",
        &req(
            "anthropic",
            "/messages",
            &[("x-api-key", "placeholder")],
            json!({"model": "claude-haiku-4-5"}),
        ),
        &t,
    )
    .unwrap();
    assert_eq!(a.url, "https://api.anthropic.com/v1/messages");
    assert!(a.headers.contains(&("x-api-key".into(), "sk-ant".into())));
    assert_eq!(a.headers.iter().filter(|(n, _)| n == "x-api-key").count(), 1);

    let o = prepare(
        &settings(Provider::OpenAi, "gpt-5.4-mini"),
        "sk-oai",
        &req("openai", "/responses", &[], json!({"model": "gpt-5.4-mini"})),
        &t,
    )
    .unwrap();
    assert_eq!(o.url, "https://api.openai.com/v1/responses");
    assert!(o.headers.contains(&("authorization".into(), "Bearer sk-oai".into())));

    let g = prepare(
        &settings(Provider::Google, "gemini-3-flash-preview"),
        "goog",
        &req(
            "google",
            "/models/gemini-3-flash-preview:generateContent",
            &[],
            json!({}),
        ),
        &t,
    )
    .unwrap();
    assert_eq!(
        g.url,
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent"
    );
    assert!(g.headers.contains(&("x-goog-api-key".into(), "goog".into())));
}

#[test]
fn usage_is_read_from_each_answer() {
    let gw = json!({"usage": {"inputTokens": {"total": 120, "noCache": 120}, "outputTokens": {"total": 30}}});
    assert_eq!(usage_of(Provider::VercelGateway, &gw), (Some(120), Some(30)));
    let a = json!({"content": [], "usage": {"input_tokens": 50, "output_tokens": 7}});
    assert_eq!(usage_of(Provider::Anthropic, &a), (Some(50), Some(7)));
    let o = json!({"output": [], "usage": {"input_tokens": 9, "output_tokens": 2}});
    assert_eq!(usage_of(Provider::OpenAi, &o), (Some(9), Some(2)));
    let g = json!({"candidates": [], "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3}});
    assert_eq!(usage_of(Provider::Google, &g), (Some(11), Some(3)));
}

fn client(s: Option<AiSettings>, usage: Arc<UsageCounter>) -> AiClient {
    AiClient::new(
        Arc::new(move || s.clone()),
        Arc::new(|id: &str| (id == "cred1").then(|| "sk-ant-real".to_string())),
        Arc::new(NoModels),
        Arc::new(|| 1_800_000_000_000),
    )
    .with_usage(usage)
}

#[tokio::test]
async fn a_relay_goes_out_with_the_key_and_is_counted() {
    let provider = FakeConsole::start().await.unwrap();
    let answer =
        json!({"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 40, "output_tokens": 5}});
    provider.answer("/v1/messages", vec![(200, answer.clone())]);
    let targets = Targets {
        anthropic: provider.url("/v1"),
        ..Targets::default()
    };
    let usage = Arc::new(UsageCounter::new(None));
    let c = client(Some(settings(Provider::Anthropic, "claude-haiku-4-5")), usage.clone());
    let http = reqwest::Client::new();
    let out = run(
        &c,
        &http,
        &targets,
        req(
            "anthropic",
            "/messages",
            &[],
            json!({"model": "claude-haiku-4-5", "messages": []}),
        ),
    )
    .await;
    assert!(out.ok, "{:?}", out.message);
    let data = out.data.unwrap();
    assert_eq!(data["status"], 200);
    assert_eq!(
        serde_json::from_str::<Value>(data["body"].as_str().unwrap()).unwrap(),
        answer
    );
    let got = provider.received();
    assert_eq!(got.len(), 1);
    assert!(got[0].headers.contains(&("x-api-key".into(), "sk-ant-real".into())));
    let rows = usage.pending();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["activity"], PURPOSE);
    assert_eq!(rows[0]["input"], 40);
    assert_eq!(rows[0]["output"], 5);

    // Log Review off: nothing goes out.
    let off = client(
        Some(AiSettings {
            log_review: false,
            ..settings(Provider::Anthropic, "claude-haiku-4-5")
        }),
        usage.clone(),
    );
    let out = run(
        &off,
        &http,
        &targets,
        req("anthropic", "/messages", &[], json!({"model": "claude-haiku-4-5"})),
    )
    .await;
    assert!(!out.ok);
    assert_eq!(out.status, "off");
    assert_eq!(provider.received().len(), 1);
}

#[tokio::test]
async fn the_daily_cap_stops_the_relay() {
    let provider = FakeConsole::start().await.unwrap();
    let targets = Targets {
        anthropic: provider.url("/v1"),
        ..Targets::default()
    };
    let c = client(
        Some(AiSettings {
            daily_call_cap: 2,
            ..settings(Provider::Anthropic, "claude-haiku-4-5")
        }),
        Arc::new(UsageCounter::new(None)),
    );
    let http = reqwest::Client::new();
    let r = || req("anthropic", "/messages", &[], json!({"model": "claude-haiku-4-5"}));
    assert!(run(&c, &http, &targets, r()).await.ok);
    assert!(run(&c, &http, &targets, r()).await.ok);
    let third = run(&c, &http, &targets, r()).await;
    assert_eq!(third.status, "capped");
    assert_eq!(provider.received().len(), 2);
}
