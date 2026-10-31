//! Which key a Doctor session's coding agent is given, and how (`doctor-credentials.ts`). Read from
//! the model credential W4 keeps (`StoredCredential`, as JSON): never the refresh token of a
//! subscription, and an included plan's key only through the firewall's own bridge.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::stream::Cli;

#[derive(Debug, Clone, PartialEq)]
pub struct DoctorCredentials {
    pub env: BTreeMap<String, String>,
    /// `anthropic`, `openai`, `gateway` or `openai_codex`.
    pub provider: &'static str,
    pub label: &'static str,
    /// Included credentials must use the daemon bridge enforcing this list on every request.
    pub included_models: Option<Vec<String>>,
    /// The runner must exit before an access-only subscription token expires.
    pub expires_at: Option<i64>,
}

static MODEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$").expect("pattern"));

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// `resolveDoctorCredentials`. The error is a sentence a person reads.
pub fn resolve(cli: Cli, credential: Option<&Value>, model: &str, now: i64) -> Result<DoctorCredentials, String> {
    let Some(c) = credential.filter(|c| {
        !c.get("failed")
            .is_some_and(|f| !f.is_null() && f != &Value::Bool(false) && f != "")
    }) else {
        return Err("The selected credential is unavailable on the firewall.".into());
    };
    if !MODEL.is_match(model) {
        return Err("Choose a valid model.".into());
    }
    let provider = s(c, "provider").unwrap_or("");
    let kind = s(c, "kind").unwrap_or("");
    let secret = c.get("secret").cloned().unwrap_or(Value::Null);
    // The console's catalog calls this openai_codex; existing firewall stores use OpenClaw's openai
    // provider with its dedicated ChatGPT profile and destination.
    let subscription = provider == "openai_codex"
        || (provider == "openai"
            && s(c, "profileId") == Some("openai:controlclaw-chatgpt")
            && c.get("swap").and_then(|w| w.get("matchDomain")).and_then(Value::as_str) == Some("chatgpt.com"));
    if subscription && kind == "oauth" && secret.get("access").is_some() {
        if cli == Cli::Claude {
            return Err("Claude Code cannot use a ChatGPT subscription.".into());
        }
        let access = s(&secret, "access").unwrap_or("");
        let account = s(&secret, "accountId").unwrap_or("");
        let expires = secret.get("expires").and_then(Value::as_f64).unwrap_or(0.0);
        if access.is_empty() || account.is_empty() || expires <= (now + 60_000) as f64 {
            return Err("The firewall must refresh this ChatGPT sign-in before Doctor can use it.".into());
        }
        // Never hand the refresh token to a CLI. The firewall remains its only refresh owner.
        return Ok(DoctorCredentials {
            env: env(&[("OPENAI_API_KEY", access), ("CC_DOCTOR_OPENAI_ACCOUNT_ID", account)]),
            provider: "openai_codex",
            label: "your ChatGPT subscription",
            included_models: None,
            expires_at: Some(expires as i64),
        });
    }
    if kind != "api_key" || secret.get("apiKey").is_none() {
        return Err("Choose an API key or a supported ChatGPT sign-in.".into());
    }
    let key = s(&secret, "apiKey").unwrap_or("");
    if key.is_empty() {
        return Err("The selected credential has no API key.".into());
    }
    let allowed: Option<Vec<String>> = c
        .get("allowedModels")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect());
    let included = provider == "controlclaw" || provider == "controlclaw_included";
    if included && allowed.as_ref().is_none_or(|a| a.is_empty()) {
        return Err("The firewall has no included-model allow-list for this credential.".into());
    }
    if let Some(a) = &allowed
        && !a.iter().any(|m| m == model)
    {
        return Err("This model is not included with the selected credential.".into());
    }
    if provider == "anthropic" && cli != Cli::Codex {
        return Ok(DoctorCredentials {
            env: env(&[("ANTHROPIC_API_KEY", key)]),
            provider: "anthropic",
            label: "your Anthropic key",
            included_models: None,
            expires_at: None,
        });
    }
    if provider == "openai" && cli != Cli::Claude {
        return Ok(DoctorCredentials {
            env: env(&[("OPENAI_API_KEY", key)]),
            provider: "openai",
            label: "your OpenAI key",
            included_models: None,
            expires_at: None,
        });
    }
    if provider == "vercel_gateway" || included {
        if (cli == Cli::Claude && !model.starts_with("anthropic/"))
            || (cli == Cli::Codex && !model.starts_with("openai/"))
        {
            return Err("Choose a gateway model supported by this CLI.".into());
        }
        let label = if included {
            "your included AI tokens"
        } else {
            "your AI Gateway key"
        };
        let included_models = if included { allowed.clone() } else { None };
        let env = if cli == Cli::Claude {
            env(&[
                ("ANTHROPIC_BASE_URL", "https://ai-gateway.vercel.sh"),
                ("ANTHROPIC_AUTH_TOKEN", key),
            ])
        } else {
            env(&[
                ("OPENAI_API_KEY", key),
                ("OPENAI_BASE_URL", "https://ai-gateway.vercel.sh/v1"),
            ])
        };
        return Ok(DoctorCredentials {
            env,
            provider: "gateway",
            label,
            included_models,
            expires_at: None,
        });
    }
    Err("The selected CLI cannot use this credential. Choose a compatible key or sign-in.".into())
}
