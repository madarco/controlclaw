//! The Vercel AI Gateway, called as `@ai-sdk/gateway` 4.0.96 calls it.
//!
//! Requests carry the same headers as the SDK's: the bearer key, `ai-gateway-protocol-version:
//! 0.0.1`, `ai-gateway-auth-method: api-key`, the model headers, and a user agent. The SDK builds
//! the user agent from its versions and the Node version; ours names the same SDK versions and this
//! runtime. Bodies are the SDK's, key for key and in the same order.

use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, USER_AGENT as UA};
use serde_json::{Value, json};

use crate::{Evaluation, LlmError, Questions, validate_answers, validate_input};

/// `createGateway`'s default `baseURL`.
pub const GATEWAY_BASE_URL: &str = "https://ai-gateway.vercel.sh/v4/ai";
/// `ai/7.0.118` is what `experimental_evaluate`/`generateText` add; `provider-utils` adds its own
/// and the runtime.
pub const USER_AGENT: &str = "ai/7.0.118 ai-sdk/provider-utils/5.0.49 runtime/controlclaw-rust";
/// What `generateText` puts in the request's own `headers` field (the SDK sends its call options).
const SDK_UA: &str = "ai/7.0.118";
/// AI SDK's first retry waits 2 s, then doubles.
const RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct GatewayClient {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl GatewayClient {
    /// A client of its own. On a box, use [`Self::with_client`] with the one that trusts the
    /// right roots (cc-client).
    pub fn new(api_key: &str) -> Self {
        Self::with_client(reqwest::Client::new(), api_key)
    }

    pub fn with_client(http: reqwest::Client, api_key: &str) -> Self {
        Self {
            http,
            base_url: GATEWAY_BASE_URL.to_string(),
            api_key: api_key.to_string(),
        }
    }

    /// Tests and dev: another base URL (no trailing slash needed).
    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    fn headers(&self, model_headers: &[(&'static str, String)]) -> Result<HeaderMap, LlmError> {
        let mut h = HeaderMap::new();
        let bad = |_| LlmError::Other {
            status: None,
            message: "a header value was not valid".into(),
        };
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.api_key)).map_err(bad)?,
        );
        h.insert("ai-gateway-protocol-version", HeaderValue::from_static("0.0.1"));
        h.insert("ai-gateway-auth-method", HeaderValue::from_static("api-key"));
        h.insert(UA, HeaderValue::from_static(USER_AGENT));
        for (k, v) in model_headers {
            h.insert(HeaderName::from_static(k), HeaderValue::from_str(v).map_err(bad)?);
        }
        Ok(h)
    }

    async fn post(&self, path: &str, headers: HeaderMap, body: &Value) -> Result<Value, LlmError> {
        let url = format!("{}/{path}", self.base_url);
        let res = self
            .http
            .post(url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| LlmError::Other {
                status: None,
                message: format!("Gateway request failed: {}", e.without_url()),
            })?;
        let status = res.status().as_u16();
        let text = res.text().await.map_err(|e| LlmError::Other {
            status: Some(status),
            message: format!("Gateway request failed: {}", e.without_url()),
        })?;
        if !(200..300).contains(&status) {
            return Err(LlmError::from_response(status, &text));
        }
        serde_json::from_str(&text).map_err(|_| LlmError::InvalidAnswer("Failed to process successful response".into()))
    }

    /// `experimental_evaluate` with a Gateway evaluation model. `provider_options` is sent as is
    /// (`providerOptionsFor`); `Value::Null` leaves it out. The SDK's `maxRetries` is 0 here, as
    /// every TS caller sets it.
    pub async fn evaluate(
        &self,
        model: &str,
        state: &Value,
        questions: &Questions,
        provider_options: &Value,
        timeout: Duration,
    ) -> Result<Evaluation, LlmError> {
        validate_input(state, questions)?;
        let mut body = json!({ "state": state, "questions": questions });
        if !provider_options.is_null()
            && let Some(o) = body.as_object_mut()
        {
            o.insert("providerOptions".into(), provider_options.clone());
        }
        let headers = self.headers(&[
            ("ai-evaluation-model-specification-version", "4".into()),
            ("ai-model-id", model.to_string()),
        ])?;
        let raw = tokio::time::timeout(timeout, self.post("evaluation-model", headers, &body))
            .await
            .map_err(|_| LlmError::Timeout)??;
        let evaluation: Evaluation = serde_json::from_value(raw)
            .map_err(|e| LlmError::InvalidAnswer(format!("Failed to process successful response: {e}")))?;
        validate_answers(questions, &evaluation.answers, evaluation.rounding)?;
        Ok(evaluation)
    }

    /// `generateText({model, prompt, maxOutputTokens, maxRetries, providerOptions})` through the
    /// Gateway's language model endpoint: the text parts of the answer, joined. `timeout` covers
    /// every try, like the TS abort signal.
    pub async fn generate_text(
        &self,
        model: &str,
        prompt: &str,
        max_output_tokens: u32,
        provider_options: &Value,
        max_retries: u32,
        timeout: Duration,
    ) -> Result<String, LlmError> {
        // The SDK posts its call options minus the abort signal; undefined ones drop out of the JSON.
        // Checked against ai 7.0.118 + @ai-sdk/gateway 4.0.96 with a stubbed fetch.
        let mut body = json!({
            "maxOutputTokens": max_output_tokens,
            "toolChoice": { "type": "auto" },
            "prompt": [{ "role": "user", "content": [{ "type": "text", "text": prompt }] }],
            "providerOptions": provider_options,
            "headers": { "user-agent": SDK_UA },
        });
        // `undefined` drops out of the SDK's JSON; a null here would be sent.
        if provider_options.is_null()
            && let Some(o) = body.as_object_mut()
        {
            o.remove("providerOptions");
        }
        let headers = self.headers(&[
            ("ai-language-model-specification-version", "4".into()),
            ("ai-language-model-id", model.to_string()),
            ("ai-language-model-streaming", "false".into()),
        ])?;
        let attempt = async {
            let mut delay = RETRY_DELAY;
            let mut tries = 0;
            loop {
                match self.post("language-model", headers.clone(), &body).await {
                    Ok(v) => return Ok(text_of(&v)),
                    Err(e) if e.retryable() && tries < max_retries => {
                        tries += 1;
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        tokio::time::timeout(timeout, attempt)
            .await
            .map_err(|_| LlmError::Timeout)?
    }
}

/// The text parts of a LanguageModelV4 result, joined.
fn text_of(v: &Value) -> String {
    v["content"]
        .as_array()
        .map(|parts| {
            parts
                .iter()
                .filter(|p| p["type"] == "text")
                .filter_map(|p| p["text"].as_str())
                .collect::<String>()
        })
        .unwrap_or_default()
}
