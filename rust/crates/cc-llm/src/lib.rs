//! Model calls over plain HTTP, for the firewall's AI checks (the judge, content-rule policies, the
//! log review). A port of what `packages/mitm-agent/src/ai/model.ts` asks of AI SDK v7:
//!
//! - `experimental_evaluate` against the Vercel AI Gateway's evaluation endpoint, which Jev
//!   (`typesafe-ai/*`) answers natively ([`GatewayClient::evaluate`]);
//! - `generateText` for the one sentence the review writes ([`GatewayClient::generate_text`]);
//! - the provider options, the input and answer checks, the daily allowances and the failure text.
//!
//! OpenAI, Anthropic and Google models answer the same questions in each provider's own JSON mode
//! ([`Backend::LanguageModel`], `structured.rs`).

mod caps;
mod error;
mod evaluation;
mod gateway;
mod settings;
pub mod structured;

pub use caps::DailyAllowance;
pub use error::{LlmError, failure_message};
pub use evaluation::{Answer, Evaluation, Question, Questions, Rounding, Usage, validate_answers, validate_input};
pub use gateway::{GATEWAY_BASE_URL, GatewayClient, USER_AGENT};
pub use settings::{
    AiSettings, Provider, clean_instructions, is_decision_model, key_fingerprint, provider_options_for,
};

/// Which way an organization's model answers typed questions.
#[derive(Debug, Clone)]
pub enum Backend {
    /// The AI Gateway's evaluation endpoint (`vercel_gateway`, `controlclaw_included`, and any
    /// `typesafe-ai/*` decision model).
    Gateway(GatewayClient),
    /// OpenAI, Anthropic or Google answering through their own structured-output mode
    /// ([`structured::evaluate`]).
    LanguageModel {
        provider: Provider,
        api_key: String,
        model: String,
    },
}

impl Backend {
    /// As `evaluationModelFor`: the Gateway for the Gateway providers, the provider itself otherwise.
    pub fn for_provider(provider: Provider, api_key: &str, model: &str) -> Self {
        match provider {
            Provider::VercelGateway | Provider::ControlclawIncluded => Backend::Gateway(GatewayClient::new(api_key)),
            p => Backend::LanguageModel {
                provider: p,
                api_key: api_key.to_string(),
                model: model.to_string(),
            },
        }
    }

    pub async fn evaluate(
        &self,
        model: &str,
        state: &serde_json::Value,
        questions: &Questions,
        provider_options: &serde_json::Value,
        timeout: std::time::Duration,
    ) -> Result<Evaluation, LlmError> {
        match self {
            Backend::Gateway(g) => g.evaluate(model, state, questions, provider_options, timeout).await,
            // The call's model, as for the Gateway; the stored one is what `for_provider` was given.
            Backend::LanguageModel { provider, api_key, .. } => {
                structured::evaluate(
                    structured::shared_client(),
                    *provider,
                    api_key,
                    model,
                    None,
                    state,
                    questions,
                    provider_options,
                    timeout,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
