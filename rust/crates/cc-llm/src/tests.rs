use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use serde_json::{Value, json};

use crate::*;

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    headers: HeaderMap,
    body: String,
}

#[derive(Clone, Default)]
struct Fake {
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<VecDeque<(u16, String, Duration)>>>,
}

impl Fake {
    async fn start(replies: Vec<(u16, Value)>) -> (Self, String) {
        Self::start_slow(replies.into_iter().map(|(s, b)| (s, b, Duration::ZERO)).collect()).await
    }

    async fn start_slow(replies: Vec<(u16, Value, Duration)>) -> (Self, String) {
        let fake = Fake::default();
        *fake.replies.lock().unwrap() = replies.into_iter().map(|(s, b, d)| (s, b.to_string(), d)).collect();
        let f = fake.clone();
        let app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
            let f = f.clone();
            async move {
                f.seen.lock().unwrap().push(Seen {
                    path: uri.path().to_string(),
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
                let (status, body, delay) =
                    f.replies
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((500, "{}".into(), Duration::ZERO));
                tokio::time::sleep(delay).await;
                (StatusCode::from_u16(status).unwrap(), body)
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (fake, format!("http://{addr}/v4/ai"))
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn judge_questions() -> Questions {
    let mut choice = serde_json::Map::new();
    choice.insert("allow".into(), json!("Let it through."));
    choice.insert("block".into(), json!("Stop it."));
    Questions::new()
        .with(
            "risk",
            Question::Score {
                instructions: json!("How risky is this?"),
                criteria: vec![json!("None."), json!("Low."), json!("High.")],
            },
        )
        .with(
            "decision",
            Question::Choice {
                instructions: json!("Decide."),
                criteria: choice,
            },
        )
        .with(
            "secret",
            Question::Boolean {
                instructions: json!("Is a secret in it?"),
                criteria: None,
            },
        )
}

fn h<'a>(s: &'a Seen, name: &str) -> &'a str {
    s.headers.get(name).map(|v| v.to_str().unwrap()).unwrap_or("")
}

#[tokio::test]
async fn evaluate_sends_the_sdk_request() {
    let answer = json!({
        "answers": {
            "risk": { "type": "score", "score": 0.2, "probabilities": { "0": 0.8, "1": 0.2, "2": 0.0 } },
            "decision": { "type": "choice", "choice": "allow", "probabilities": { "allow": 0.9, "block": 0.1 } },
            "secret": { "type": "boolean", "probability": 0.01 },
        },
        "model": "typesafe-ai/jev",
        "usage": { "inputTokens": 120, "outputTokens": 3 },
    });
    let (fake, base) = Fake::start(vec![(200, answer)]).await;
    let g = GatewayClient::new("vck_testkey").base_url(&base);
    let state = json!({ "request": { "host": "example.com", "method": "POST" }, "recent": [] });
    let opts = provider_options_for(Provider::VercelGateway, "typesafe-ai/jev");
    let ev = g
        .evaluate(
            "typesafe-ai/jev",
            &state,
            &judge_questions(),
            &opts,
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    let s = &fake.seen()[0];
    assert_eq!(s.path, "/v4/ai/evaluation-model");
    assert_eq!(h(s, "authorization"), "Bearer vck_testkey");
    assert_eq!(h(s, "content-type"), "application/json");
    assert_eq!(h(s, "ai-gateway-protocol-version"), "0.0.1");
    assert_eq!(h(s, "ai-gateway-auth-method"), "api-key");
    assert_eq!(h(s, "ai-evaluation-model-specification-version"), "4");
    assert_eq!(h(s, "ai-model-id"), "typesafe-ai/jev");
    assert_eq!(h(s, "user-agent"), USER_AGENT);
    // Byte for byte what JSON.stringify({state, questions, providerOptions}) gives.
    assert_eq!(
        s.body,
        r#"{"state":{"request":{"host":"example.com","method":"POST"},"recent":[]},"questions":{"risk":{"type":"score","instructions":"How risky is this?","criteria":["None.","Low.","High."]},"decision":{"type":"choice","instructions":"Decide.","criteria":{"allow":"Let it through.","block":"Stop it."}},"secret":{"type":"boolean","instructions":"Is a secret in it?"}},"providerOptions":{"gateway":{"zeroDataRetention":true}}}"#
    );
    assert_eq!(
        ev.answer("decision"),
        Some(&Answer::Choice {
            choice: "allow".into(),
            probabilities: Some(json!({ "allow": 0.9, "block": 0.1 }).as_object().unwrap().clone()),
        })
    );
    assert_eq!(ev.answer("secret"), Some(&Answer::Boolean { probability: 0.01 }));
    assert_eq!(ev.model.as_deref(), Some("typesafe-ai/jev"));
    assert_eq!(ev.usage.unwrap().input_tokens, Some(120));
}

#[tokio::test]
async fn evaluate_refuses_answers_the_sdk_refuses() {
    let q = judge_questions();
    let ok_rest = json!({
        "decision": { "type": "choice", "choice": "allow" },
        "secret": { "type": "boolean", "probability": 0.5 },
    });
    let with = |risk: Value| {
        let mut a = ok_rest.clone();
        a["risk"] = risk;
        json!({ "answers": a })
    };
    let cases = vec![
        (
            json!({ "answers": ok_rest.clone() }),
            "exactly one answer for every question",
        ),
        (with(json!({ "type": "boolean", "probability": 0.5 })), "wrong type"),
        (with(json!({ "type": "score", "score": 3 })), "score must be in [0, 2]"),
        (
            with(json!({ "type": "score", "score": 1, "probabilities": { "0": 0.5, "1": 0.2, "2": 0.1 } })),
            "must sum to 1",
        ),
        (
            with(json!({ "type": "score", "score": 0, "probabilities": { "0": 0.0, "1": 0.0, "2": 1.0 } })),
            "probability-weighted mean",
        ),
    ];
    for (body, want) in cases {
        let (_fake, base) = Fake::start(vec![(200, body)]).await;
        let g = GatewayClient::new("k").base_url(&base);
        let e = g
            .evaluate("m", &json!({}), &q, &Value::Null, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, LlmError::InvalidAnswer(m) if m.contains(want)),
            "{e:?} should say {want}"
        );
    }
    // An unknown option, and a choice that is not the most likely one.
    for (decision, want) in [
        (json!({ "type": "choice", "choice": "maybe" }), "unknown option"),
        (
            json!({ "type": "choice", "choice": "block", "probabilities": { "allow": 0.9, "block": 0.1 } }),
            "highest-probability",
        ),
    ] {
        let mut a = ok_rest.clone();
        a["decision"] = decision;
        a["risk"] = json!({ "type": "score", "score": 0 });
        let (_fake, base) = Fake::start(vec![(200, json!({ "answers": a }))]).await;
        let g = GatewayClient::new("k").base_url(&base);
        let e = g
            .evaluate("m", &json!({}), &q, &Value::Null, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, LlmError::InvalidAnswer(m) if m.contains(want)),
            "{e:?} should say {want}"
        );
    }
}

#[tokio::test]
async fn refusals_are_typed() {
    let cases = vec![
        (
            401,
            json!({ "error": { "message": "Invalid API key", "type": "authentication_error" } }),
        ),
        (
            402,
            json!({ "error": { "message": "Payment required", "type": "payment_required" } }),
        ),
        (
            400,
            json!({ "error": { "message": "You exceeded your current quota", "type": "invalid_request_error" } }),
        ),
        (
            429,
            json!({ "error": { "message": "Slow down", "type": "rate_limit_exceeded" } }),
        ),
        (
            500,
            json!({ "error": { "message": "boom", "type": "internal_server_error" } }),
        ),
    ];
    let mut got = vec![];
    for (status, body) in cases {
        let (_fake, base) = Fake::start(vec![(status, body)]).await;
        let g = GatewayClient::new("k").base_url(&base);
        got.push(
            g.evaluate(
                "m",
                &json!({}),
                &judge_questions(),
                &Value::Null,
                Duration::from_secs(2),
            )
            .await
            .unwrap_err(),
        );
    }
    assert_eq!(
        got,
        vec![
            LlmError::Auth("Invalid API key".into()),
            LlmError::Credit("Payment required".into()),
            LlmError::Credit("You exceeded your current quota".into()),
            LlmError::RateLimit("Slow down".into()),
            LlmError::Other {
                status: Some(500),
                message: "boom".into()
            },
        ]
    );
}

#[tokio::test]
async fn timeout_is_its_own_failure() {
    let (_fake, base) = Fake::start_slow(vec![(200, json!({}), Duration::from_secs(2))]).await;
    let g = GatewayClient::new("k").base_url(&base);
    let e = g
        .evaluate(
            "m",
            &json!({}),
            &judge_questions(),
            &Value::Null,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
    assert_eq!(e, LlmError::Timeout);
    assert_eq!(failure_message(&e), "The model did not answer in time.");
}

#[tokio::test]
async fn invalid_input_is_refused_before_any_call() {
    let (fake, base) = Fake::start(vec![]).await;
    let g = GatewayClient::new("k").base_url(&base);
    let one_level = Questions::new().with(
        "r",
        Question::Score {
            instructions: json!("x"),
            criteria: vec![json!("a")],
        },
    );
    for (state, q) in [
        (json!(1), judge_questions()),
        (json!({}), Questions::new()),
        (json!({}), one_level),
    ] {
        let e = g
            .evaluate("m", &state, &q, &Value::Null, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(e, LlmError::InvalidInput(_)), "{e:?}");
    }
    assert!(fake.seen().is_empty());
}

#[tokio::test]
async fn generate_text_sends_the_sdk_body_and_retries_once() {
    let reply = json!({
        "content": [
            { "type": "reasoning", "text": "thinking" },
            { "type": "text", "text": "The agent posted " },
            { "type": "text", "text": "a file to a paste site." },
        ],
        "finishReason": "stop",
    });
    let (fake, base) = Fake::start(vec![(503, json!({ "error": { "message": "busy" } })), (200, reply)]).await;
    let g = GatewayClient::new("k").base_url(&base);
    let opts = provider_options_for(Provider::ControlclawIncluded, "openai/gpt-5-mini");
    let text = g
        .generate_text("openai/gpt-5-mini", "Say why.", 1024, &opts, 1, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(text, "The agent posted a file to a paste site.");
    let seen = fake.seen();
    assert_eq!(seen.len(), 2, "one retry after the 503");
    let s = &seen[1];
    assert_eq!(s.path, "/v4/ai/language-model");
    assert_eq!(h(s, "ai-language-model-specification-version"), "4");
    assert_eq!(h(s, "ai-language-model-id"), "openai/gpt-5-mini");
    assert_eq!(h(s, "ai-language-model-streaming"), "false");
    assert_eq!(
        s.body,
        r#"{"maxOutputTokens":1024,"toolChoice":{"type":"auto"},"prompt":[{"role":"user","content":[{"type":"text","text":"Say why."}]}],"providerOptions":{"gateway":{"zeroDataRetention":true}},"headers":{"user-agent":"ai/7.0.118"}}"#
    );
}

#[tokio::test]
async fn generate_text_does_not_retry_an_auth_refusal() {
    let (fake, base) = Fake::start(vec![(
        401,
        json!({ "error": { "message": "no", "type": "authentication_error" } }),
    )])
    .await;
    let g = GatewayClient::new("k").base_url(&base);
    let e = g
        .generate_text("m", "p", 1024, &Value::Null, 1, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(e, LlmError::Auth("no".into()));
    assert_eq!(fake.seen().len(), 1);
}

#[tokio::test]
async fn language_models_answer_in_their_own_json_mode() {
    let (fake, base) = Fake::start(vec![(
        200,
        json!({"content": [{"type": "text", "text": "{\"q0\":1.2,\"q1\":\"c1\",\"q2\":0.9}"}], "stop_reason": "end_turn", "usage": {"input_tokens": 5, "output_tokens": 2}}),
    )])
    .await;
    let q = judge_questions();
    let e = structured::evaluate(
        &reqwest::Client::new(),
        Provider::Anthropic,
        "sk-ant-x",
        "claude-sonnet-5",
        Some(&base),
        &json!({}),
        &q,
        &Value::Null,
        Duration::from_secs(5),
    )
    .await;
    let seen = fake.seen();
    assert_eq!(seen[0].path, "/v4/ai/messages");
    assert_eq!(h(&seen[0], "x-api-key"), "sk-ant-x");
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    let e = e.unwrap();
    assert_eq!(e.answers.len(), q.0.len());
    assert!(matches!(
        Backend::for_provider(Provider::ControlclawIncluded, "k", "m"),
        Backend::Gateway(_)
    ));
}

#[test]
fn provider_options_match_the_ts() {
    assert_eq!(
        provider_options_for(Provider::OpenAi, "gpt-5"),
        json!({ "gateway": { "zeroDataRetention": true }, "openai": { "reasoningEffort": "minimal" } })
    );
    assert_eq!(
        provider_options_for(Provider::OpenAi, "gpt-5-nano-2025-08-07")["openai"]["reasoningEffort"],
        "minimal"
    );
    assert_eq!(
        provider_options_for(Provider::OpenAi, "o3-mini")["openai"]["reasoningEffort"],
        "low"
    );
    assert!(
        provider_options_for(Provider::OpenAi, "gpt-5.1")
            .get("openai")
            .is_none()
    );
    assert!(
        provider_options_for(Provider::VercelGateway, "gpt-5")
            .get("openai")
            .is_none()
    );
    assert!(is_decision_model("typesafe-ai/jev"));
    assert!(!is_decision_model("openai/gpt-5"));
    assert_eq!(key_fingerprint("abc"), "ba7816bf8f01cfea");
}

#[test]
fn settings_parse_like_the_ts() {
    let s = AiSettings::parse(&json!({
        "credential_id": "c1", "provider": "anthropic", "model": "claude-x",
        "checks": false, "daily_call_cap": 0, "auto_approve_per_hour": 0, "scan_interval_hours": 2.0,
        "request_instructions": "  be \u{0007}strict \"\"\"really\"\"\"  ",
    }))
    .unwrap();
    assert!(!s.checks && s.log_review);
    assert_eq!(
        (s.daily_call_cap, s.auto_approve_per_hour, s.scan_interval_hours),
        (5000, 0, 2)
    );
    assert_eq!(s.request_instructions.as_deref(), Some("be  strict \"really\""));
    assert_eq!(s.review_instructions, None);
    assert!(AiSettings::parse(&json!({ "credential_id": "c", "provider": "other", "model": "m" })).is_none());
    assert!(AiSettings::parse(&json!({ "credential_id": "", "provider": "openai", "model": "m" })).is_none());
}

#[test]
fn failure_messages_hide_keys() {
    let e = LlmError::Other {
        status: Some(400),
        message: "bad key sk-proj-abcdefghij123 in request".into(),
    };
    assert_eq!(failure_message(&e), "bad key [REDACTED] in request");
}
