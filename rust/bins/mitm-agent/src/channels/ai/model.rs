//! The AI review's only way to a model (`ai/model.ts`). The model is the org's own: provider and
//! model from the settings, the key from this box's LLM store. Calls go straight out from the
//! firewall. Every call counts against the org's daily allowances, has a hard timeout, and turns any
//! failure into a `CallFailure`, so a caller never has to tell an outage from a malformed answer.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use cc_http::BoxFuture;
use cc_llm::{
    AiSettings, DailyAllowance, Evaluation, GatewayClient, LlmError, Provider, Questions, is_decision_model,
    key_fingerprint, provider_options_for, structured,
};
use serde_json::Value;

/// Why a call came back empty.
#[derive(Debug, Clone, PartialEq)]
pub enum CallFailure {
    /// No settings or no key.
    Off,
    /// Today's calls are used up.
    Cap,
    /// The model answers questions only and cannot write a sentence.
    DecisionModel,
    /// A timeout or the provider refused, with a short message.
    Error(Option<String>),
}

impl CallFailure {
    pub fn kind(&self) -> &'static str {
        match self {
            CallFailure::Off => "off",
            CallFailure::Cap => "cap",
            CallFailure::DecisionModel => "decision_model",
            CallFailure::Error(_) => "error",
        }
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            CallFailure::Error(m) => m.as_deref(),
            _ => None,
        }
    }
}

/// Which model and key a call would use: what the content rules pin.
#[derive(Debug, Clone, PartialEq)]
pub struct AiIdentity {
    pub provider: Provider,
    pub model: String,
    /// The first 16 hex of the key's SHA-256.
    pub key_fingerprint: String,
}

/// The model calls themselves, so tests can answer for the providers.
pub trait ModelCalls: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn evaluate(
        &self,
        provider: Provider,
        key: &str,
        model: &str,
        state: Value,
        questions: Questions,
        provider_options: Value,
        max_retries: u32,
        timeout: Duration,
    ) -> BoxFuture<Result<Evaluation, LlmError>>;
    fn explain(
        &self,
        provider: Provider,
        key: &str,
        model: &str,
        prompt: String,
        provider_options: Value,
        timeout: Duration,
    ) -> BoxFuture<Result<String, LlmError>>;
}

/// The real providers: the Gateway for Jev and the Gateway providers, each provider's own API
/// otherwise.
pub struct LiveModels;

impl ModelCalls for LiveModels {
    fn evaluate(
        &self,
        provider: Provider,
        key: &str,
        model: &str,
        state: Value,
        questions: Questions,
        provider_options: Value,
        max_retries: u32,
        timeout: Duration,
    ) -> BoxFuture<Result<Evaluation, LlmError>> {
        let (key, model) = (key.to_string(), model.to_string());
        Box::pin(async move {
            let http = structured::shared_client();
            let once = || async {
                match provider {
                    Provider::VercelGateway | Provider::ControlclawIncluded => {
                        GatewayClient::with_client(http.clone(), &key)
                            .evaluate(&model, &state, &questions, &provider_options, timeout)
                            .await
                    }
                    p => {
                        structured::evaluate(
                            http,
                            p,
                            &key,
                            &model,
                            None,
                            &state,
                            &questions,
                            &provider_options,
                            timeout,
                        )
                        .await
                    }
                }
            };
            // AI SDK's retries: 2 s, then doubling, inside the same deadline.
            let attempt = async {
                let mut delay = Duration::from_secs(2);
                let mut tries = 0;
                loop {
                    match once().await {
                        Err(e) if e.retryable() && tries < max_retries => {
                            tries += 1;
                            tokio::time::sleep(delay).await;
                            delay *= 2;
                        }
                        other => return other,
                    }
                }
            };
            tokio::time::timeout(timeout, attempt)
                .await
                .map_err(|_| LlmError::Timeout)?
        })
    }

    fn explain(
        &self,
        provider: Provider,
        key: &str,
        model: &str,
        prompt: String,
        provider_options: Value,
        timeout: Duration,
    ) -> BoxFuture<Result<String, LlmError>> {
        let (key, model) = (key.to_string(), model.to_string());
        Box::pin(async move {
            let http = structured::shared_client();
            match provider {
                Provider::VercelGateway | Provider::ControlclawIncluded => {
                    GatewayClient::with_client(http.clone(), &key)
                        .generate_text(&model, &prompt, 1024, &provider_options, 1, timeout)
                        .await
                }
                p => {
                    structured::generate_text(
                        http,
                        p,
                        &key,
                        &model,
                        None,
                        &prompt,
                        1024,
                        &provider_options,
                        1,
                        timeout,
                    )
                    .await
                }
            }
        })
    }
}

pub type SettingsFn = Arc<dyn Fn() -> Option<AiSettings> + Send + Sync>;
pub type KeyFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Options of one evaluation.
pub struct EvaluateOptions {
    pub timeout: Duration,
    pub max_retries: u32,
    /// Daily allowances this call counts against, instead of the review's `dailyCallCap`.
    pub caps: Option<Vec<(String, u64)>>,
}

pub struct AiClient {
    settings: SettingsFn,
    key_for: KeyFn,
    models: Arc<dyn ModelCalls>,
    allowance: DailyAllowance,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl AiClient {
    pub fn new(
        settings: SettingsFn,
        key_for: KeyFn,
        models: Arc<dyn ModelCalls>,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            settings,
            key_for,
            models,
            allowance: DailyAllowance::new(),
            now,
        }
    }

    /// Settings and a key, or `None` when the review is off or cannot run. A caller that needs
    /// them more than once in one request reads them once here and passes them on.
    pub fn ready(&self) -> Option<(AiSettings, String)> {
        let settings = (self.settings)()?;
        let key = (self.key_for)(&settings.credential_id)?;
        Some((settings, key))
    }

    #[allow(dead_code)] // `enabled()` in the TS; read by nothing on this firewall yet
    pub fn enabled(&self) -> bool {
        self.ready().is_some()
    }

    /// The AI Firewall can run: the per-request check, AI approval and the content rules' AI.
    pub fn checks_on(&self) -> bool {
        self.ready().is_some_and(|(s, _)| s.checks)
    }

    /// AI Log Review can run: the review every minute and the scan.
    pub fn review_on(&self) -> bool {
        self.ready().is_some_and(|(s, _)| s.log_review)
    }

    pub fn settings(&self) -> Option<AiSettings> {
        (self.settings)()
    }

    pub fn identity(&self) -> Option<AiIdentity> {
        let (s, key) = self.ready()?;
        Some(AiIdentity {
            provider: s.provider,
            model: s.model,
            key_fingerprint: key_fingerprint(&key),
        })
    }

    fn take(&self, caps: &[(String, u64)]) -> bool {
        let at = UNIX_EPOCH + Duration::from_millis((self.now)().max(0) as u64);
        let caps: Vec<(&str, u64)> = caps.iter().map(|(k, c)| (k.as_str(), *c)).collect();
        self.allowance.take_at(&caps, at)
    }

    #[allow(dead_code)] // the TS's `usage()`, for its tests and a later status line
    pub fn usage(&self, key: &str) -> (String, u64) {
        self.allowance.usage(key)
    }

    /// `evaluate`, saying why there is no answer.
    pub async fn evaluate_with_reason(
        &self,
        state: Value,
        questions: Questions,
        o: EvaluateOptions,
    ) -> Result<Evaluation, CallFailure> {
        self.evaluate_ready(self.ready(), state, questions, o).await
    }

    /// `evaluate_with_reason` with the settings and key already read (`ready`).
    pub async fn evaluate_ready(
        &self,
        ready: Option<(AiSettings, String)>,
        state: Value,
        questions: Questions,
        o: EvaluateOptions,
    ) -> Result<Evaluation, CallFailure> {
        let Some((s, key)) = ready else {
            return Err(CallFailure::Off);
        };
        let caps = o.caps.unwrap_or_else(|| vec![("review".to_string(), s.daily_call_cap)]);
        if !self.take(&caps) {
            let names: Vec<String> = caps
                .iter()
                .map(|(k, c)| format!("{} {c}", k.split(':').next().unwrap_or(k)))
                .collect();
            tracing::info!("[ai] daily cap reached ({}); skipping", names.join(", "));
            return Err(CallFailure::Cap);
        }
        let opts = provider_options_for(s.provider, &s.model);
        match self
            .models
            .evaluate(
                s.provider,
                &key,
                &s.model,
                state,
                questions,
                opts,
                o.max_retries,
                o.timeout,
            )
            .await
        {
            Ok(e) => Ok(e),
            Err(err) => {
                // The kind of failure only: a provider can echo the request in its error.
                tracing::info!(
                    "[ai] evaluate failed ({}/{}): {}",
                    s.provider.as_str(),
                    s.model,
                    error_name(&err)
                );
                Err(CallFailure::Error(Some(cc_llm::failure_message(&err))))
            }
        }
    }

    /// `explain`, saying why there is no sentence.
    pub async fn explain_with_reason(&self, prompt: String, timeout: Duration) -> Result<String, CallFailure> {
        let Some((s, key)) = self.ready() else {
            return Err(CallFailure::Off);
        };
        if is_decision_model(&s.model) {
            return Err(CallFailure::DecisionModel);
        }
        if !self.take(&[("review".to_string(), s.daily_call_cap)]) {
            return Err(CallFailure::Cap);
        }
        let opts = provider_options_for(s.provider, &s.model);
        match self
            .models
            .explain(s.provider, &key, &s.model, prompt, opts, timeout)
            .await
        {
            Ok(text) => {
                let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                if text.is_empty() {
                    Err(CallFailure::Error(Some("The model returned no text.".into())))
                } else {
                    Ok(crate::channels::js::js_slice(&text, 300))
                }
            }
            Err(err) => {
                tracing::info!("[ai] explain failed: {}", error_name(&err));
                Err(CallFailure::Error(Some(cc_llm::failure_message(&err))))
            }
        }
    }
}

/// A short name for the kind of failure, as the TS logs `err.name`.
fn error_name(e: &LlmError) -> &'static str {
    match e {
        LlmError::Timeout => "TimeoutError",
        LlmError::InvalidAnswer(_) | LlmError::InvalidInput(_) => "AI_InvalidResponseDataError",
        _ => "AI_APICallError",
    }
}
