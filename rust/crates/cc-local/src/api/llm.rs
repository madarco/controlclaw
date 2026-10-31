//! The user's own model keys (Settings → AI model keys): the SaaS's `llm.addCredential` and
//! `llm.removeCredential` for the providers a standalone firewall can use. The key goes to the
//! firewall in an `llm.propose` and is kept only there; this table keeps a hint and the
//! placeholder. No included AI, no ChatGPT sign-in, and no per-agent models yet.

use http::Method;
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, new_id};
use crate::db::{Db, now_s};
use crate::plane::iso;

const TAG: &str = "llm";

/// One provider, as the SaaS's `LLM_CATALOG` has it.
pub struct Provider {
    pub id: &'static str,
    pub name: &'static str,
    openclaw_provider: &'static str,
    auth_profile_id: &'static str,
    match_domain: &'static str,
    locations: &'static [&'static str],
    /// The key starts with this and goes on with at least `min_tail` of `[A-Za-z0-9_-]`.
    key_prefix: &'static str,
    min_tail: usize,
    placeholder_prefix: &'static str,
    /// The AI review's suggested model, for a provider the review can use.
    pub review_model: Option<&'static str>,
    /// For a provider stock OpenClaw does not know: the endpoint (base URL, API) its agents are
    /// given as a custom provider, and the model the key starts with. The block goes with the key's
    /// add or replace; a bind only adds its model to it (the firewall refuses a new endpoint there).
    agent_endpoint: Option<(&'static str, &'static str, &'static str)>,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "openai",
        name: "OpenAI",
        openclaw_provider: "openai",
        auth_profile_id: "openai:controlclaw",
        match_domain: "api.openai.com",
        locations: &["header:authorization"],
        key_prefix: "sk-",
        min_tail: 8,
        placeholder_prefix: "sk-cc-openai-",
        review_model: Some("gpt-5.4-mini"),
        agent_endpoint: None,
    },
    Provider {
        id: "anthropic",
        name: "Anthropic",
        openclaw_provider: "anthropic",
        auth_profile_id: "anthropic:controlclaw",
        match_domain: "api.anthropic.com",
        locations: &["header:x-api-key", "header:authorization"],
        key_prefix: "sk-ant-",
        min_tail: 8,
        placeholder_prefix: "sk-ant-cc-",
        review_model: Some("claude-haiku-4-5"),
        agent_endpoint: None,
    },
    Provider {
        id: "google",
        name: "Google Gemini",
        openclaw_provider: "google",
        auth_profile_id: "google:controlclaw",
        match_domain: "generativelanguage.googleapis.com",
        locations: &["header:x-goog-api-key", "query"],
        key_prefix: "",
        min_tail: 20,
        placeholder_prefix: "cc-google-",
        review_model: Some("gemini-3-flash-preview"),
        agent_endpoint: None,
    },
    Provider {
        id: "openrouter",
        name: "OpenRouter",
        openclaw_provider: "openrouter",
        auth_profile_id: "openrouter:controlclaw",
        match_domain: "openrouter.ai",
        locations: &["header:authorization"],
        key_prefix: "sk-or-",
        min_tail: 8,
        placeholder_prefix: "sk-or-cc-",
        review_model: None,
        agent_endpoint: None,
    },
    Provider {
        id: "vercel_gateway",
        name: "Vercel AI Gateway",
        openclaw_provider: "vercel-ai-gateway",
        auth_profile_id: "vercel-ai-gateway:controlclaw",
        match_domain: "ai-gateway.vercel.sh",
        // OpenClaw's gateway plugin speaks Anthropic's API there, which sends the key as `x-api-key`.
        locations: &["header:authorization", "header:x-api-key"],
        key_prefix: "",
        min_tail: 16,
        placeholder_prefix: "vck-cc-",
        review_model: Some("typesafe-ai/jev"),
        // Stock OpenClaw 2026.10 has no `vercel-ai-gateway` provider (matrix 2): its agents get the
        // gateway's OpenAI-compatible endpoint, as the SaaS's included AI does.
        agent_endpoint: Some((
            "https://ai-gateway.vercel.sh/v1",
            "openai-completions",
            "anthropic/claude-haiku-5.5",
        )),
    },
];

/// The hosts where the firewall puts a held key in: a residential exit there would send the
/// placeholder upstream (the SaaS's `assertNoSwapOverlap`).
pub fn swap_hosts(db: &Db) -> rusqlite::Result<Vec<&'static str>> {
    Ok(list(db)?
        .keys
        .iter()
        .filter_map(|k| provider(&k.provider))
        .map(|p| p.match_domain)
        .collect())
}

pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.id == id)
}

impl Provider {
    fn key_ok(&self, key: &str) -> bool {
        key.strip_prefix(self.key_prefix).is_some_and(|tail| {
            tail.len() >= self.min_tail
                && tail
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
    }
}

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), ModelKeys, _, _>(
            "/api/llm/keys",
            TAG,
            "The model keys and the providers a key can be added for",
            |c| async move { Ok(Reply::ok(&list(&c.db)?)) },
        ),
        Route::write::<NewModelKey, ModelKeyChange, _, _>(
            Method::POST,
            "/api/llm/keys",
            TAG,
            "Add a provider's key, or replace it",
            |c, b| async move { add(&c, b).await },
        ),
        Route::write::<AgentModel, ModelKeyChange, _, _>(
            Method::POST,
            "/api/llm/agents/:vmId",
            TAG,
            "Give an agent a model on a provider whose key the firewall holds (its main model)",
            |c, b| async move { give_model(&c, b).await },
        ),
        Route::write::<super::NoBody, ModelKeyChange, _, _>(
            Method::DELETE,
            "/api/llm/keys/:provider",
            TAG,
            "Remove a provider's key",
            |c, _| async move { remove(&c).await },
        ),
    ]
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelKeys {
    pub keys: Vec<ModelKey>,
    pub providers: Vec<ProviderOption>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelKey {
    /// The firewall's credential id; the AI review settings name it.
    pub id: String,
    pub provider: String,
    pub name: String,
    pub label: Option<String>,
    /// The key's last four characters.
    pub hint: String,
    /// `active`, or `failed` when the firewall did not take it.
    pub state: String,
    pub last_error: Option<String>,
    pub updated_at: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderOption {
    pub id: String,
    pub name: String,
    /// The AI review can use this provider; its suggested model.
    pub review_model: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewModelKey {
    /// `openai`, `anthropic`, `google`, `openrouter` or `vercel_gateway`.
    pub provider: String,
    pub key: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Replace the provider's key; without it, a provider that has one is refused (409).
    #[serde(default)]
    pub replace: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentModel {
    /// A provider with a key here (`GET /api/llm/keys`).
    pub provider: String,
    /// OpenClaw's id for the model, with its provider: `openrouter/moonshotai/kimi-k2`.
    pub model: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelKeyChange {
    /// What the firewall said.
    pub result: CommandAnswer,
    pub keys: Vec<ModelKey>,
}

pub fn list(db: &Db) -> rusqlite::Result<ModelKeys> {
    let c = db.lock();
    let mut q = c.prepare(
        "SELECT id, provider, label, hint, state, last_error, updated_at FROM llm_keys ORDER BY created_at, id",
    )?;
    let keys = q
        .query_map([], |r| {
            let provider: String = r.get(1)?;
            Ok(ModelKey {
                id: r.get(0)?,
                name: self::provider(&provider).map_or_else(|| provider.clone(), |p| p.name.to_string()),
                provider,
                label: r.get(2)?,
                hint: r.get(3)?,
                state: r.get(4)?,
                last_error: r.get(5)?,
                updated_at: iso(r.get(6)?),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ModelKeys {
        keys,
        providers: PROVIDERS
            .iter()
            .map(|p| ProviderOption {
                id: p.id.into(),
                name: p.name.into(),
                review_model: p.review_model.map(str::to_string),
            })
            .collect(),
    })
}

/// The key a provider has here: (credential id, placeholder).
fn existing(db: &Db, provider: &str) -> rusqlite::Result<Option<(String, String)>> {
    db.lock()
        .query_row(
            "SELECT id, placeholder FROM llm_keys WHERE provider = ?1",
            [provider],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
}

/// The `llm.propose` payload, as the SaaS's `proposalPayload` makes it, with no agents: the key is
/// the firewall's to use (the AI review); [`give_model`] adds the agent that gets a model.
fn payload(
    p: &Provider,
    kind: &str,
    id: &str,
    placeholder: &str,
    hint: &str,
    label: Option<&str>,
) -> Map<String, Value> {
    let v = json!({
        "kind": kind,
        "credentialId": id,
        "provider": p.openclaw_provider,
        "providerName": p.name,
        "credKind": "api_key",
        "placeholder": placeholder,
        "hint": hint,
        "label": label,
        "profileId": p.auth_profile_id,
        "swap": {"matchDomain": p.match_domain, "locations": p.locations},
        "agents": [],
    });
    v.as_object().cloned().unwrap_or_default()
}

/// A stand-in for a key, shaped like one: the prefix, then 24 hex characters.
pub fn mint_placeholder(prefix: &str) -> String {
    let mut b = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    format!("{prefix}{}", hex::encode(b))
}

/// One key change at a time: two at once for one provider would both see "none yet" and leave two
/// credentials on the firewall.
static CHANGES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn add(c: &Ctx, b: NewModelKey) -> Result {
    let _one = CHANGES.lock().await;
    let Some(p) = provider(&b.provider) else {
        return Err(Reply::bad(format!(
            "provider: one of {}",
            PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
        )));
    };
    let key = b.key.trim();
    if !p.key_ok(key) {
        return Err(Reply::bad(format!("That does not look like a {} API key.", p.name)));
    }
    let label = b.label.as_deref().map(str::trim).filter(|l| !l.is_empty());
    if label.is_some_and(|l| l.chars().count() > 80) {
        return Err(Reply::bad("label: at most 80 characters"));
    }
    let had = existing(&c.db, p.id)?;
    match (&had, b.replace) {
        (Some(_), false) => {
            return Err(Reply::error(
                409,
                format!("{} is already set up. Replace its key instead.", p.name),
            ));
        }
        (None, true) => return Err(Reply::bad(format!("{} is not set up yet.", p.name))),
        _ => {}
    }
    let (id, kind) = match &had {
        Some((id, _)) => (id.clone(), "replace"),
        None => (new_id("cred"), "add"),
    };
    let placeholder = mint_placeholder(p.placeholder_prefix);
    let hint = format!(
        "…{}",
        key.chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
    );
    let mut payload = payload(p, kind, &id, &placeholder, &hint, label);
    payload.insert("secret".into(), json!({"apiKey": key}));
    // The endpoint agents get comes with the key: a bind may only add its model to it.
    if let Some((_, _, first)) = p.agent_endpoint
        && let Some(block) = provider_block(p, first)
    {
        payload.insert("providerBlock".into(), block);
    }
    let result = c.apply("llm", payload).await?;
    let now = now_s();
    if result.ok {
        c.db.lock().execute(
            "INSERT INTO llm_keys (id, provider, label, hint, placeholder, state, last_error, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', NULL, ?6, ?6)
             ON CONFLICT (provider) DO UPDATE SET label = excluded.label, hint = excluded.hint,
                 placeholder = excluded.placeholder, state = 'active', last_error = NULL, updated_at = excluded.updated_at",
            params![id, p.id, label, hint, placeholder, now],
        )?;
        super::egress::sync_ai(&c.db)?;
        (c.hooks.rules_changed)();
    } else if had.is_some() {
        // A replacement the firewall refused: the old key is still the one in use.
        c.db.lock().execute(
            "UPDATE llm_keys SET last_error = ?1, updated_at = ?2 WHERE provider = ?3",
            params![result.message, now, p.id],
        )?;
    }
    let status = if result.ok { 200 } else { 409 };
    Ok(Reply {
        status,
        body: serde_json::to_value(ModelKeyChange {
            result,
            keys: list(&c.db)?.keys,
        })
        .unwrap_or(Value::Null),
    })
}

/// `llm.propose` with kind `bind`: the firewall records the agent's model on that key and pushes
/// it to the agent's vm-agent (the key itself stays on the firewall; the agent gets a stand-in).
async fn give_model(c: &Ctx, b: AgentModel) -> Result {
    let _one = CHANGES.lock().await;
    let Some(p) = provider(&b.provider) else {
        return Err(Reply::bad("provider: one with a key here"));
    };
    let model = b.model.trim();
    if model.is_empty() || model.len() > 200 || model.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(Reply::bad(
            "model: OpenClaw's model id, such as openrouter/moonshotai/kimi-k2",
        ));
    }
    let Some((id, placeholder)) = existing(&c.db, p.id)? else {
        return Err(Reply::bad(format!("{} has no key here yet: add one first.", p.name)));
    };
    let (model, block) = agent_model(p, model)?;
    let agent = super::agent_ref(&c.db, c.param("vmId"))?;
    let mut payload = payload(p, "bind", &id, &placeholder, "", None);
    if let Some(block) = block {
        payload.insert("providerBlock".into(), block);
    }
    payload.insert(
        "agents".into(),
        json!([{"vmId": agent["vmId"], "name": agent["name"], "hostname": agent["hostname"], "model": model, "role": "primary"}]),
    );
    let result = c.apply("llm", payload).await?;
    let status = if result.ok { 200 } else { 409 };
    Ok(Reply {
        status,
        body: serde_json::to_value(ModelKeyChange {
            result,
            keys: list(&c.db)?.keys,
        })
        .unwrap_or(Value::Null),
    })
}

/// For a provider stock OpenClaw does not know: the model under the provider, and the custom provider
/// block that names it. The gateway's own id is taken too (`anthropic/claude-haiku-5.5` on the AI
/// Gateway): a model left outside the provider would run with no key. Other providers: unchanged.
fn agent_model(p: &Provider, model: &str) -> std::result::Result<(String, Option<Value>), Reply> {
    if p.agent_endpoint.is_none() {
        return Ok((model.to_string(), None));
    }
    let prefix = format!("{}/", p.openclaw_provider);
    let id = model.strip_prefix(&prefix).unwrap_or(model);
    if id.is_empty() {
        return Err(Reply::bad(format!("model: a {} model after {prefix}", p.name)));
    }
    Ok((format!("{prefix}{id}"), provider_block(p, id)))
}

/// The custom provider block with one model, for a provider stock OpenClaw does not know.
fn provider_block(p: &Provider, model: &str) -> Option<Value> {
    let (base_url, api, _) = p.agent_endpoint?;
    Some(json!({"baseUrl": base_url, "api": api, "models": [{"id": model, "name": model}]}))
}

async fn remove(c: &Ctx) -> Result {
    let _one = CHANGES.lock().await;
    let Some(p) = provider(c.param("provider")) else {
        return Err(Reply::not_found("Provider"));
    };
    let Some((id, placeholder)) = existing(&c.db, p.id)? else {
        return Err(Reply::not_found("Key"));
    };
    let result = c
        .apply("llm", payload(p, "remove", &id, &placeholder, "", None))
        .await?;
    if result.ok {
        c.db.lock().execute("DELETE FROM llm_keys WHERE id = ?1", [&id])?;
        super::egress::sync_ai(&c.db)?;
        (c.hooks.rules_changed)();
    }
    let status = if result.ok { 200 } else { 409 };
    Ok(Reply {
        status,
        body: serde_json::to_value(ModelKeyChange {
            result,
            keys: list(&c.db)?.keys,
        })
        .unwrap_or(Value::Null),
    })
}
