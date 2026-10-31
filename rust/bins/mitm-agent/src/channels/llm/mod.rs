//! LLM provider commands on the firewall (`llm.ts`, docs/features/llm-providers.md). Like
//! channels: hold the secrets, ask for a code when someone can be asked, push the config to agent
//! boxes with our signature. The one thing this module does on its own is refresh OAuth access
//! tokens, because the provider rotates the refresh token and the agent box never sees either.
//!
//!   llm.propose  { changeId, kind, credentialId, provider, providerName, credKind?, placeholder?,
//!                  hint?, label?, profileId?, swap?, oauth?, providerBlock?, allowedModels?,
//!                  replaces?, agents: [{vmId, name, hostname, model, role, embeddings?}], secret? }
//!   llm.confirm  { changeId, code }
//!   llm.cancel   { changeId }
//!   llm.push     { vmId, name, hostname, refresh?, embeddings?, providerBlocks? }
//!
//! What reaches an agent box is one `POST /llm/apply` with the whole desired state for that box.
//! An agent has two slots, `primary` and `secondary`; a proposal names one credential and the slot
//! it should hold, and `set_binding` moves whoever held it.
//!
//! No lock is held across an await: each step reads or changes the store under a short lock and
//! saves, so two commands interleave between their awaits as they do in the TS, and an agent that
//! is slow to answer holds up no other command and no token refresh.

pub mod store;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use self::store::{
    Embeddings, LlmStore, MemorySearch, OAuth, ProviderBlock, ProviderModel, StoredBinding, StoredCredential,
    StoredLlmAgent, StoredSecret, Swap, account_id, secret_value,
};
use super::agent::{AgentCalls, AgentError, LLM_PUSH_MS, Target};
use crate::commands::{CommandOutcome, CommandResult};
use crate::contracts::{CodeRequest, ConsentCodes, Verify};

pub const REFRESH_AHEAD_MS: i64 = 15 * 60_000;
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);
/// One pending change per organization (`SCOPE = "org"` in its own `ConsentCodes`). The shared
/// codes instance keys by scope, so this module's is its own.
pub const SCOPE: &str = "llm:org";
/// Who the code message names.
pub const CODE_SUBJECT: &str = "your organization's model providers";

/// The OAuth refresh call: a form POST, the status and the JSON body (`{}` when not JSON). An
/// error is a network failure or a timeout, with its message.
pub trait TokenFetch: Send + Sync {
    fn post_form(
        &self,
        url: &str,
        form: Vec<(String, String)>,
        timeout: Duration,
    ) -> BoxFuture<Result<(u16, Value), String>>;
}

pub struct ReqwestFetch(pub reqwest::Client);

impl TokenFetch for ReqwestFetch {
    fn post_form(
        &self,
        url: &str,
        form: Vec<(String, String)>,
        timeout: Duration,
    ) -> BoxFuture<Result<(u16, Value), String>> {
        let req = self
            .0
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(form_encode(&form))
            .timeout(timeout);
        Box::pin(async move {
            let res = req.send().await.map_err(|e| {
                if e.is_timeout() {
                    "This operation was aborted".to_string()
                } else {
                    "fetch failed".to_string()
                }
            })?;
            let status = res.status().as_u16();
            let body = res.json::<Value>().await.unwrap_or_else(|_| json!({}));
            Ok((status, body))
        })
    }
}

/// `URLSearchParams.toString()`: `application/x-www-form-urlencoded`, spaces as `+`.
pub fn form_encode(form: &[(String, String)]) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => out.push(b as char),
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
    form.iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub type Hook = Arc<dyn Fn() -> BoxFuture<()> + Send + Sync>;
pub type VmPredicate = Arc<dyn Fn(&str) -> bool + Send + Sync>;

pub struct LlmOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    /// The shared consent codes; `None` while nothing provides them.
    pub codes: Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>,
    /// Where codes can go (every agent with an approved sender): `CodeRoute & {agentName}` as JSON.
    /// `None` while nothing on this firewall can say (no channels module): a proposal is then
    /// refused, never applied on first use, since "nobody to ask" cannot be told apart from "not
    /// known".
    pub code_routes: Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>,
    /// `AgentFirstSeen.isNew`; absent means never.
    pub is_new_agent: Option<VmPredicate>,
    /// `AgentFirstSeen.isLive`; absent means no.
    pub is_live_agent: Option<VmPredicate>,
    /// Whether any channel connection is on this agent; absent means yes.
    pub agent_has_channels: Option<VmPredicate>,
    /// Push the real keys to the boxes instead of placeholders (OAuth tokens are placeholders regardless).
    pub plain_keys: bool,
    pub on_credentials_changed: Hook,
    pub fetch: Arc<dyn TokenFetch>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

fn s(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(x)) if !x.is_empty() => Some(x.clone()),
        _ => None,
    }
}

fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// How a slot is named in the code message. Mirrored in apps/saas `roleLabel`.
fn role_label(role: &str) -> &'static str {
    if role == "primary" { "main model" } else { "fallback" }
}

/// `lastIndexOf("@")` with the TS's `at > 0` and "the rest has a colon".
fn pinned_split(model: &str) -> Option<(&str, &str)> {
    let at = model.rfind('@')?;
    (at > 0 && model[at + 1..].contains(':')).then(|| (&model[..at], &model[at + 1..]))
}

/// `openai/gpt-5.6-sol@openai:controlclaw-chatgpt` → `gpt-5.6-sol`, for the code message.
pub fn model_short(model: &str) -> String {
    let bare = pinned_split(model).map(|(b, _)| b).unwrap_or(model);
    match bare.find('/') {
        Some(i) => bare[i + 1..].to_string(),
        None => bare.to_string(),
    }
}

/// `openai/gpt-5.6-sol@openai:controlclaw-chatgpt` → `openai@openai:controlclaw-chatgpt`.
pub fn model_family(model: &str) -> String {
    let (bare, pin) = pinned_split(model).unwrap_or((model, ""));
    let provider = bare.find('/').map(|i| &bare[..i]).unwrap_or("");
    format!("{provider}@{pin}")
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingsRef {
    pub credential_id: String,
    pub memory: MemorySearch,
    pub allowed_models: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRef {
    pub vm_id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub model: String,
    pub role: String,
    /// `None`: the payload said nothing (leave the box alone). `Some(None)`: take ours off.
    pub embeddings: Option<Option<EmbeddingsRef>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LlmProposal {
    pub change_id: String,
    pub kind: String,
    pub credential_id: String,
    pub provider: String,
    pub provider_name: String,
    pub cred_kind: Option<String>,
    pub placeholder: Option<String>,
    pub hint: Option<String>,
    pub label: Option<String>,
    pub profile_id: Option<String>,
    pub swap: Option<Swap>,
    pub oauth: Option<OAuth>,
    pub provider_block: Option<ProviderBlock>,
    pub allowed_models: Option<Vec<String>>,
    pub memory: Option<MemorySearch>,
    pub replaces: Option<String>,
    pub agents: Vec<AgentRef>,
    pub secret: Option<StoredSecret>,
}

/// `parseMemorySearch`.
pub fn parse_memory_search(raw: Option<&Value>) -> Option<MemorySearch> {
    let m = obj(raw)?;
    let provider = s(m.get("provider"))?;
    let model = s(m.get("model"))?;
    let base_url = s(m.get("baseUrl"))?;
    Some(MemorySearch::new(
        &provider,
        &model,
        &base_url,
        m.get("dreaming") == Some(&Value::Bool(true)),
    ))
}

fn parse_model_list(raw: Option<&Value>) -> Option<Vec<String>> {
    let list: Vec<String> = raw?
        .as_array()?
        .iter()
        .filter_map(|m| m.as_str().filter(|m| !m.is_empty()).map(str::to_string))
        .collect();
    (!list.is_empty()).then_some(list)
}

/// `parseEmbeddingsRef`: `None` when the field is absent, `Some(None)` to take ours off.
pub fn parse_embeddings_ref(raw: Option<&Value>) -> Option<Option<EmbeddingsRef>> {
    let raw = raw?;
    let Some(r) = raw.as_object() else {
        return Some(None);
    };
    let (Some(credential_id), Some(memory)) = (s(r.get("credentialId")), parse_memory_search(r.get("memory"))) else {
        return Some(None);
    };
    Some(Some(EmbeddingsRef {
        credential_id,
        memory,
        allowed_models: parse_model_list(r.get("allowedModels")),
    }))
}

/// Only the switches we know, with the values OpenClaw accepts.
fn parse_model_compat(raw: Option<&Value>) -> Option<Map<String, Value>> {
    let c = obj(raw)?;
    let mut out = Map::new();
    if let Some(Value::Bool(b)) = c.get("supportsPromptCacheKey") {
        out.insert("supportsPromptCacheKey".into(), Value::Bool(*b));
    }
    if c.get("cacheControlFormat").and_then(Value::as_str) == Some("anthropic") {
        out.insert("cacheControlFormat".into(), json!("anthropic"));
    }
    (!out.is_empty()).then_some(out)
}

fn parse_provider_block(raw: Option<&Value>) -> Option<ProviderBlock> {
    let b = obj(raw)?;
    let base_url = s(b.get("baseUrl"))?;
    let api = s(b.get("api"))?;
    let models: Vec<ProviderModel> = b
        .get("models")?
        .as_array()?
        .iter()
        .filter_map(|m| {
            let id = s(m.get("id"))?;
            Some(ProviderModel {
                name: s(m.get("name")).unwrap_or_else(|| id.clone()),
                id,
                compat: parse_model_compat(m.get("compat")),
                extra: Map::new(),
            })
        })
        .collect();
    (!models.is_empty()).then_some(ProviderBlock {
        base_url,
        api,
        models,
        extra: Map::new(),
    })
}

fn parse_secret(raw: Option<&Value>) -> Option<StoredSecret> {
    let secret = obj(raw)?;
    let mut out = Map::new();
    if let Some(k) = s(secret.get("apiKey")) {
        out.insert("apiKey".into(), json!(k));
        return Some(out);
    }
    if let Some(t) = s(secret.get("token")) {
        out.insert("token".into(), json!(t));
        return Some(out);
    }
    let o = obj(secret.get("oauth"))?;
    let (access, refresh) = (s(o.get("access"))?, s(o.get("refresh"))?);
    out.insert("access".into(), json!(access));
    out.insert("refresh".into(), json!(refresh));
    out.insert(
        "expires".into(),
        o.get("expires").filter(|e| e.is_number()).cloned().unwrap_or(json!(0)),
    );
    out.insert(
        "accountId".into(),
        s(o.get("accountId")).map_or(Value::Null, Value::String),
    );
    out.insert("email".into(), s(o.get("email")).map_or(Value::Null, Value::String));
    Some(out)
}

pub fn parse_proposal(payload: &Map<String, Value>) -> Result<LlmProposal, String> {
    let kind = payload.get("kind").and_then(Value::as_str).unwrap_or_default();
    let valid_kind = matches!(kind, "add" | "replace" | "remove" | "bind" | "unbind" | "set_model");
    let (Some(change_id), Some(credential_id), Some(provider), true) = (
        s(payload.get("changeId")),
        s(payload.get("credentialId")),
        s(payload.get("provider")),
        valid_kind,
    ) else {
        return Err("malformed llm.propose payload".into());
    };
    let swap = obj(payload.get("swap")).and_then(|w| {
        let m = s(w.get("matchDomain"))?;
        let locations = w.get("locations")?.as_array()?;
        Some(Swap {
            match_domain: m,
            locations: locations.iter().map(js_string).collect(),
            extra: Map::new(),
        })
    });
    let oauth = obj(payload.get("oauth")).and_then(|o| {
        Some(OAuth {
            token_endpoint: s(o.get("tokenEndpoint"))?,
            client_id: s(o.get("clientId"))?,
            client_secret: s(o.get("clientSecret")),
            extra: Map::new(),
        })
    });
    let cred_kind = payload
        .get("credKind")
        .and_then(Value::as_str)
        .filter(|k| matches!(*k, "api_key" | "token" | "oauth"))
        .map(str::to_string);
    let agents = payload
        .get("agents")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|a| {
                    let vm_id = s(a.get("vmId"))?;
                    let model = s(a.get("model"))?;
                    Some(AgentRef {
                        name: s(a.get("name")).unwrap_or_else(|| vm_id.clone()),
                        hostname: s(a.get("hostname")),
                        model,
                        role: if a.get("role").and_then(Value::as_str) == Some("secondary") {
                            "secondary".into()
                        } else {
                            "primary".into()
                        },
                        embeddings: parse_embeddings_ref(a.get("embeddings")),
                        vm_id,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(LlmProposal {
        change_id,
        kind: kind.to_string(),
        credential_id,
        provider_name: s(payload.get("providerName")).unwrap_or_else(|| provider.clone()),
        provider,
        cred_kind,
        placeholder: s(payload.get("placeholder")),
        hint: s(payload.get("hint")),
        label: s(payload.get("label")),
        profile_id: s(payload.get("profileId")),
        swap,
        oauth,
        provider_block: parse_provider_block(payload.get("providerBlock")),
        allowed_models: parse_model_list(payload.get("allowedModels")),
        memory: parse_memory_search(payload.get("memory")),
        replaces: s(payload.get("replaces")),
        agents,
        secret: parse_secret(payload.get("secret")),
    })
}

/// `String(x)` for what a payload's string list may hold.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// The one-line summary the code message carries.
pub fn summarize(p: &LlmProposal) -> String {
    let a = p.agents.first();
    let replaced = p
        .replaces
        .as_ref()
        .map(|r| format!(", replacing {r}"))
        .unwrap_or_default();
    let name = a.map(|a| a.name.as_str()).unwrap_or("the agent");
    let role = role_label(a.map(|a| a.role.as_str()).unwrap_or("primary"));
    let short = a.map(|a| model_short(&a.model)).unwrap_or_default();
    let label_or = |fallback: &str| {
        p.label
            .clone()
            .or_else(|| p.hint.clone())
            .unwrap_or_else(|| fallback.to_string())
    };
    let oauth = p.cred_kind.as_deref() == Some("oauth");
    match p.kind.as_str() {
        "add" if oauth => format!("Connect {} ({})", p.provider_name, label_or("account")),
        "add" => format!("Add {} key ({})", p.provider_name, p.hint.as_deref().unwrap_or("key")),
        "replace" if oauth => format!("Reconnect {} ({})", p.provider_name, label_or("account")),
        "replace" => format!(
            "Replace the {} key ({})",
            p.provider_name,
            p.hint.as_deref().unwrap_or("new key")
        ),
        "remove" => format!("Remove {} from the organization", p.provider_name),
        "bind" => squeeze(&format!(
            "Use {} {short} on {name} as the {role}{replaced}",
            p.provider_name
        )),
        "set_model" => {
            let raw = format!("Switch {name}'s {role} to {} {short}{replaced}", p.provider_name);
            space_before_punct().replace_all(&raw, "$1").trim().to_string()
        }
        _ => format!("Stop using {} on {name}", p.provider_name),
    }
}

fn squeeze(s: &str) -> String {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\s+").expect("regex"))
        .replace_all(s, " ")
        .into_owned()
}

fn space_before_punct() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\s+([,.])").expect("regex"))
}

/// What an agent box drops when a credential goes: its profile, and its provider block if it came with one.
fn remove_entry(c: &StoredCredential) -> Value {
    let mut m = Map::new();
    m.insert("provider".into(), json!(c.provider));
    m.insert("profileId".into(), json!(c.profile_id));
    m.insert("kind".into(), json!(c.kind));
    if c.provider_block.is_some() {
        m.insert("providerBlock".into(), json!(true));
    }
    Value::Object(m)
}

/// `timedOut`: no answer, outcome unknown. `refused`: the box answered no.
#[derive(Debug, Clone, PartialEq)]
pub struct PushFailure {
    pub vm_id: String,
    pub error: String,
    pub timed_out: bool,
    pub refused: bool,
}

impl PushFailure {
    fn from_error(vm_id: &str, e: &AgentError) -> Self {
        Self {
            vm_id: vm_id.into(),
            error: e.message.clone(),
            timed_out: e.timed_out,
            refused: e.refused(),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("vmId".into(), json!(self.vm_id));
        m.insert("error".into(), json!(self.error));
        if self.timed_out {
            m.insert("timedOut".into(), json!(true));
        }
        if self.refused {
            m.insert("refused".into(), json!(true));
        }
        Value::Object(m)
    }
}

fn failures_json(f: &[PushFailure]) -> Value {
    Value::Array(f.iter().map(PushFailure::to_json).collect())
}

/// The credential pieces `plainOnBox` looks at.
fn plain_on_box(plain_keys: bool, kind: &str, allowed_models: bool) -> bool {
    plain_keys && kind != "oauth" && !allowed_models
}

/// A credential entry the proxy swaps, for one agent.
fn credential_entry(vm_id: &str, c: &StoredCredential) -> Map<String, Value> {
    let mut e = Map::new();
    e.insert("placeholder".into(), json!(c.placeholder));
    e.insert("match_domain".into(), json!(c.swap.match_domain));
    e.insert("secret".into(), json!(secret_value(&c.secret)));
    e.insert("locations".into(), json!(c.swap.locations));
    e.insert("vm_id".into(), json!(vm_id));
    // The proxy leaves model calls out of the content rules' "web" channel.
    e.insert("model".into(), json!(true));
    if let Some(a) = &c.allowed_models {
        e.insert("allowed_models".into(), json!(a));
        e.insert("included".into(), json!(true));
    }
    e
}

/// The speech credential the voice modules ask for.
#[allow(dead_code)] // read by the phone and meetings modules (H7)
#[derive(Debug, Clone, PartialEq)]
pub struct SpeechCredential {
    pub secret: String,
    pub host: String,
    pub account_id: Option<String>,
}

/// What the console may see: no secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialSummary {
    pub id: String,
    pub provider: String,
    pub kind: String,
    pub hint: Option<String>,
    pub failed: Option<String>,
}

pub struct Llm {
    opts: LlmOptions,
    /// The store, held for a whole command.
    state: Mutex<LlmStore>,
    /// The last saved store, for the synchronous readers (the proxy sync, the heartbeat).
    published: RwLock<LlmStore>,
    reports: Mutex<Vec<CommandResult>>,
    /// The change the pending code is for and where it went (`VerifyResult.sentVia` in the TS).
    sent_via: Mutex<Option<(String, String)>>,
    /// A refresh is running.
    refreshing: std::sync::atomic::AtomicBool,
    /// False when the store on disk would not parse: it is never written over.
    writable: bool,
}

impl Llm {
    pub fn new(opts: LlmOptions) -> Arc<Self> {
        let (store, writable) = store::load_checked(&opts.store_path, &opts.box_key, &opts.org_id, &opts.box_id);
        Arc::new(Self {
            published: RwLock::new(store.clone()),
            state: Mutex::new(store),
            opts,
            reports: Mutex::new(Vec::new()),
            sent_via: Mutex::new(None),
            refreshing: std::sync::atomic::AtomicBool::new(false),
            writable,
        })
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    /// The store, for one step that does not wait on anything. Never held across an await: two
    /// commands interleave between their awaits, as in the TS, and a slow agent holds up no other.
    fn st(&self) -> std::sync::MutexGuard<'_, LlmStore> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn snapshot(&self) -> std::sync::RwLockReadGuard<'_, LlmStore> {
        self.published.read().unwrap_or_else(|e| e.into_inner())
    }

    fn plain(&self, c: &StoredCredential) -> bool {
        plain_on_box(self.opts.plain_keys, &c.kind, c.allowed_models.is_some())
    }

    /// Write the store; an error fails the command, as `saveLlmStore` throwing does in the TS.
    fn save(&self, store: &LlmStore) -> Result<(), String> {
        if !self.writable {
            return Err("This firewall could not read its model provider store, so it does not write over it.".into());
        }
        store::save(
            &self.opts.store_path,
            store,
            &self.opts.box_key,
            &self.opts.org_id,
            &self.opts.box_id,
        )
        .map_err(|e| {
            tracing::error!("[llm] could not save the store: {e}");
            "The firewall could not save its model provider store.".to_string()
        })?;
        *self.published.write().unwrap_or_else(|e| e.into_inner()) = store.clone();
        Ok(())
    }

    async fn credentials_changed(&self) {
        (self.opts.on_credentials_changed)().await;
    }

    /// Proxy credential entries: one per agent binding, swapped only on that agent's traffic, and
    /// one for the credential that pays an agent's embeddings when it is not one of its models.
    pub fn credentials(&self) -> Vec<Value> {
        let st = self.snapshot();
        let mut out = Vec::new();
        for (vm_id, agent) in &st.agents {
            let mut seen = HashSet::new();
            for b in &agent.bindings {
                let Some(c) = st.credentials.get(&b.credential_id) else {
                    continue;
                };
                if self.plain(c) {
                    continue; // the box holds the real key
                }
                seen.insert(b.credential_id.clone());
                out.push(Value::Object(credential_entry(vm_id, c)));
            }
            let Some(paid) = &agent.embeddings else { continue };
            if seen.contains(&paid.credential_id) {
                continue;
            }
            let Some(payer) = st.credentials.get(&paid.credential_id) else {
                continue;
            };
            if self.plain(payer) {
                continue;
            }
            // Its own allow-list: the embedding model and nothing else.
            let mut e = credential_entry(vm_id, payer);
            e.insert("allowed_models".into(), json!(paid.allowed_models));
            e.insert("included".into(), json!(true));
            out.push(Value::Object(e));
        }
        out
    }

    /// The current secret of one credential, for the firewall's own model calls. `None` when
    /// unknown or its last refresh failed.
    #[allow(dead_code)] // read by the AI judge and review (H2)
    pub fn token_for(&self, credential_id: &str) -> Option<String> {
        let st = self.snapshot();
        let c = st.credentials.get(credential_id)?;
        if c.failed.is_some() {
            return None;
        }
        Some(secret_value(&c.secret))
    }

    /// Speech is an explicit owner-approved binding, independent of text model selection.
    #[allow(dead_code)] // read by the phone and meetings modules (H7)
    /// `provider`: `gateway`, `openai` or `codex`.
    pub fn speech_credential(&self, provider: &str, credential_id: &str) -> Option<SpeechCredential> {
        let id = if credential_id == "included" {
            self.included_credential_id()?
        } else {
            credential_id.to_string()
        };
        let st = self.snapshot();
        let c = st.credentials.get(&id)?;
        let host = if provider == "gateway" {
            "ai-gateway.vercel.sh"
        } else {
            "api.openai.com"
        };
        if c.failed.is_some() {
            return None;
        }
        if provider == "codex" {
            if c.kind != "oauth"
                || c.swap.match_domain != "chatgpt.com"
                || !matches!(c.provider.as_str(), "openai" | "openai_codex")
            {
                return None;
            }
        } else if c.kind != "api_key" || c.swap.match_domain != host {
            return None;
        }
        if provider == "openai" && c.provider != "openai" {
            return None;
        }
        Some(SpeechCredential {
            secret: secret_value(&c.secret),
            host: host.into(),
            account_id: if provider == "codex" {
                account_id(&c.secret)
            } else {
                None
            },
        })
    }

    /// The included-AI credential this firewall holds, if any (reported on the heartbeat).
    pub fn included_credential_id(&self) -> Option<String> {
        self.snapshot()
            .credentials
            .iter()
            .find(|(_, c)| c.is_included())
            .map(|(id, _)| id.clone())
    }

    /// The model store was read (an unreadable one is kept and never written over).
    pub fn ready(&self) -> bool {
        self.writable
    }

    /// Firewall-local Doctor only. Never in a heartbeat or command result.
    pub async fn doctor_credential(&self, id: &str) -> Option<StoredCredential> {
        self.refresh_due().await;
        self.snapshot().credentials.get(id).cloned()
    }

    pub fn summary(&self) -> (Vec<CredentialSummary>, usize) {
        let st = self.snapshot();
        let creds = st
            .credentials
            .iter()
            .map(|(id, c)| CredentialSummary {
                id: id.clone(),
                provider: c.provider.clone(),
                kind: c.kind.clone(),
                hint: c.hint.clone(),
                failed: c.failed.clone(),
            })
            .collect();
        (creds, st.agents.len())
    }

    /// The agents that use one of the owner's own model credentials through this firewall now: what
    /// a recovery restore must find empty. The rule is [`store::agents_using_models`].
    pub fn agents_using_models(&self) -> usize {
        store::agents_using_models(&self.snapshot())
    }

    /// Reports made outside a command (refresh failures), drained by the heartbeat.
    pub fn drain_reports(&self) -> Vec<CommandResult> {
        std::mem::take(&mut *self.reports.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn codes(&self) -> Option<Arc<dyn ConsentCodes>> {
        (self.opts.codes)()
    }

    // ---- commands ----

    pub async fn propose(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let p = parse_proposal(&payload)?;
        let summary = summarize(&p);
        let mut data = Map::new();
        data.insert("changeId".into(), json!(p.change_id));
        data.insert("summary".into(), json!(summary));
        let Some(routes) = (self.opts.code_routes)() else {
            return Ok(outcome(false, "failed", Some(NO_ROUTES.into()), data));
        };
        if routes.is_empty() {
            if let Some(codes) = self.codes() {
                codes.forget(SCOPE);
            }
            let applied = self.apply(&p).await?;
            data.extend(applied);
            data.insert("tofu".into(), json!(true));
            return Ok(outcome(true, "applied", None, data));
        }

        // Not `forget`: a code already out for another change is still that change's.
        let why = self.new_agent_bind(&self.st(), &p);
        match why {
            None => {
                tracing::info!(
                    "[llm] {} on new agent {}: applied with the agent's creation, no code",
                    p.provider,
                    p.agents[0].name
                );
                let applied = self.apply(&p).await?;
                data.extend(applied);
                data.insert("tofu".into(), json!(false));
                data.insert("newAgent".into(), json!(true));
                return Ok(outcome(true, "applied", None, data));
            }
            Some(why) if p.kind == "bind" => tracing::info!(
                "[llm] bind of {} on {} needs a code: {why}",
                p.provider,
                p.agents.first().map(|a| a.name.as_str()).unwrap_or("?")
            ),
            Some(_) => {}
        }

        let Some(codes) = self.codes() else {
            return Ok(outcome(false, "failed", Some(NO_CODES.into()), data));
        };
        let sent = codes
            .send(CodeRequest {
                scope: SCOPE.into(),
                change_id: p.change_id.clone(),
                proposal: Value::Object(payload),
                agent_name: CODE_SUBJECT.into(),
                summary,
                routes,
            })
            .await;
        let Some(sent_via) = sent.sent_via.clone() else {
            let message = sent.error.unwrap_or_default();
            return Ok(outcome(false, "failed", Some(message), data));
        };
        tracing::info!("[llm] code sent for {} {} via {sent_via}", p.kind, p.provider);
        *self.sent_via.lock().unwrap_or_else(|e| e.into_inner()) = Some((p.change_id.clone(), sent_via.clone()));
        data.insert("sentVia".into(), json!(sent_via));
        data.insert(
            "expiresAt".into(),
            json!(cc_crypto::store_health::iso_from_millis(sent.expires_at_ms)),
        );
        data.insert("attemptsLeft".into(), json!(CODE_ATTEMPTS));
        Ok(outcome(true, "awaiting_code", None, data))
    }

    /// `None` when this change is a new agent's first model on a credential the organisation
    /// already approved and uses, which applies without a code; otherwise the reason it is not.
    /// Everything is checked against what THIS firewall holds and has seen, never what the
    /// proposal says about itself.
    fn new_agent_bind(&self, st: &LlmStore, p: &LlmProposal) -> Option<&'static str> {
        if p.kind != "bind" {
            return Some("not a bind");
        }
        let a = match (p.agents.first(), p.agents.len()) {
            (Some(a), 1) => a,
            _ => return Some("not exactly one agent"),
        };
        if a.role != "primary" {
            return Some("not the main model");
        }
        if p.replaces.is_some() {
            return Some("pushes another provider out");
        }
        let Some(cred) = st.credentials.get(&p.credential_id) else {
            return Some("credential not on this firewall");
        };
        if cred.failed.is_some() {
            return Some("credential failed");
        }
        if cred.provider != p.provider {
            return Some("provider does not match the stored credential");
        }
        let live = |vm: &str| self.opts.is_live_agent.as_ref().is_some_and(|f| f(vm));
        let others: Vec<&StoredBinding> = st
            .agents
            .iter()
            .filter(|(vm_id, _)| *vm_id != &a.vm_id && live(vm_id))
            .flat_map(|(_, agent)| agent.bindings.iter().filter(|b| b.credential_id == p.credential_id))
            .collect();
        if others.is_empty() {
            return Some("no other live agent uses this credential");
        }
        let family = model_family(&a.model);
        if !others.iter().any(|b| model_family(&b.model) == family) {
            return Some("model is not on the provider and profile already in use");
        }
        if st.agents.get(&a.vm_id).is_some_and(|x| !x.bindings.is_empty()) {
            return Some("agent already has a model");
        }
        if self.opts.agent_has_channels.as_ref().is_none_or(|f| f(&a.vm_id)) {
            return Some("agent has a channel");
        }
        if !self.opts.is_new_agent.as_ref().is_some_and(|f| f(&a.vm_id)) {
            return Some("agent is not new to this firewall");
        }
        None
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let Some(change_id) = s(payload.get("changeId")) else {
            return Err("malformed llm.confirm payload".into());
        };
        let code = s(payload.get("code")).unwrap_or_default();
        let mut data = Map::new();
        data.insert("changeId".into(), json!(change_id));
        let verdict = match self.codes() {
            Some(codes) => codes.verify(SCOPE, &change_id, &code),
            None => Verify::Unknown,
        };
        let proposal = match verdict {
            Verify::Ok(p) => p,
            Verify::Wrong { tries_left } => {
                data.insert("attemptsLeft".into(), json!(tries_left));
                return Ok(outcome(false, "invalid_code", Some("Wrong code.".into()), data));
            }
            Verify::Expired | Verify::Unknown => {
                return Ok(outcome(
                    false,
                    "expired",
                    Some("No change is waiting for a code, or the code expired.".into()),
                    data,
                ));
            }
        };
        let p = parse_proposal(proposal.as_object().unwrap_or(&Map::new()))?;
        let sent_via = {
            let mut g = self.sent_via.lock().unwrap_or_else(|e| e.into_inner());
            match g.take() {
                Some((id, via)) if id == change_id => Some(via),
                other => {
                    *g = other;
                    None
                }
            }
        };
        let applied = self.apply(&p).await?;
        data.extend(applied);
        data.insert("summary".into(), json!(summarize(&p)));
        data.insert("sentVia".into(), sent_via.map_or(Value::Null, Value::String));
        data.insert("tofu".into(), json!(false));
        Ok(outcome(true, "applied", None, data))
    }

    pub async fn cancel(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let change_id = s(payload.get("changeId"));
        if let Some(codes) = self.codes() {
            codes.cancel(SCOPE, change_id.as_deref());
        }
        let mut data = Map::new();
        data.insert("changeId".into(), change_id.map_or(Value::Null, Value::String));
        Ok(outcome(true, "cancelled", None, data))
    }

    pub async fn push(&self, payload: Map<String, Value>) -> Result<CommandOutcome, String> {
        let Some(vm_id) = s(payload.get("vmId")) else {
            return Err("malformed llm.push payload".into());
        };
        let name = s(payload.get("name"));
        let hostname = s(payload.get("hostname"));
        let embeddings = parse_embeddings_ref(payload.get("embeddings"));
        let empty = |vm: &str| {
            let mut d = Map::new();
            d.insert("vmId".into(), json!(vm));
            d.insert("applied".into(), json!([]));
            d.insert("failed".into(), json!([]));
            Ok(outcome(true, "applied", None, d))
        };
        let step = {
            let mut st = self.st();
            let known = st.agents.contains_key(&vm_id);
            // A push naming a payer this firewall can swap may be the first it hears of an agent.
            let fresh = !known && matches!(&embeddings, Some(Some(e)) if st.credentials.contains_key(&e.credential_id));
            if fresh {
                agent_of(&mut st, &vm_id, name.as_deref().unwrap_or(&vm_id), hostname.as_deref());
            }
            if !known && !fresh {
                return empty(&vm_id);
            }
            if let Some(agent) = st.agents.get_mut(&vm_id) {
                if let Some(h) = &hostname {
                    agent.hostname = Some(h.clone());
                }
                if let Some(n) = &name {
                    agent.name = n.clone();
                }
            }
            let refreshed = refresh_credential(&mut st, payload.get("refresh"));
            let reblocked = refresh_provider_blocks(&mut st, payload.get("providerBlocks"));
            let moved = apply_embeddings(&mut st, &vm_id, embeddings.as_ref());
            let agent = st.agents.get(&vm_id).cloned();
            let Some(agent) = agent else { return empty(&vm_id) };
            // Nothing to say: no model, nobody paying for embeddings, and no block of ours to take off.
            if agent.bindings.is_empty() && agent.embeddings.is_none() && agent.memory.is_none() {
                if fresh {
                    st.agents.shift_remove(&vm_id);
                }
                if known || reblocked {
                    self.save(&st)?;
                }
                return empty(&vm_id);
            }
            self.save(&st)?;
            (agent, refreshed || moved)
        };
        let (agent, changed) = step;
        if changed {
            self.credentials_changed().await;
        }
        let failed = self
            .push_agents(
                std::slice::from_ref(&vm_id),
                &[],
                Some(Duration::from_millis(LLM_PUSH_MS)),
            )
            .await?;
        let agent = self.st().agents.get(&vm_id).cloned().unwrap_or(agent);
        tracing::info!(
            "[llm] re-applied {} provider(s){} on {}{}",
            agent.bindings.len(),
            if agent.embeddings.is_some() {
                " + embeddings"
            } else {
                ""
            },
            agent.name,
            failed
                .first()
                .map(|f| format!(" (failed: {})", f.error))
                .unwrap_or_default()
        );
        let mut d = Map::new();
        d.insert("vmId".into(), json!(vm_id));
        d.insert(
            "applied".into(),
            if failed.is_empty() {
                json!(
                    agent
                        .bindings
                        .iter()
                        .map(|b| b.credential_id.clone())
                        .collect::<Vec<_>>()
                )
            } else {
                json!([])
            },
        );
        d.insert("failed".into(), failures_json(&failed));
        let message = failed.iter().map(|f| f.error.clone()).collect::<Vec<_>>().join("; ");
        Ok(outcome(
            failed.is_empty(),
            if failed.is_empty() { "applied" } else { "failed" },
            Some(message),
            d,
        ))
    }

    // ---- applying ----

    /// Memory search for one agent box: `Some(Some(v))` writes it, `Some(None)` takes ours off,
    /// `None` leaves the key out.
    fn memory_for(st: &LlmStore, vm_id: &str, bindings: &[StoredBinding]) -> Option<Value> {
        for b in bindings {
            if let Some(c) = st.credentials.get(&b.credential_id)
                && let Some(m) = &c.memory
            {
                return Some(memory_with_key(m, &c.placeholder));
            }
        }
        let agent = st.agents.get(vm_id);
        if let Some(paid) = agent.and_then(|a| a.embeddings.as_ref())
            && let Some(payer) = st.credentials.get(&paid.credential_id)
        {
            return Some(memory_with_key(&paid.memory, &payer.placeholder));
        }
        agent.and_then(|a| a.memory.as_ref()).map(|_| Value::Null)
    }

    /// The whole desired state of one agent box.
    pub fn apply_body_of(st: &LlmStore, plain_keys: bool, vm_id: &str, remove: &[Value]) -> Value {
        let bindings: Vec<StoredBinding> = st.agents.get(vm_id).map(|a| a.bindings.clone()).unwrap_or_default();
        let credentials: Vec<Value> = bindings
            .iter()
            .filter_map(|b| st.credentials.get(&b.credential_id).map(|c| (b, c)))
            .map(|(b, c)| {
                let mut m = Map::new();
                m.insert("provider".into(), json!(c.provider));
                m.insert("kind".into(), json!(c.kind));
                m.insert("profileId".into(), json!(c.profile_id));
                let value = if plain_on_box(plain_keys, &c.kind, c.allowed_models.is_some()) {
                    secret_value(&c.secret)
                } else {
                    c.placeholder.clone()
                };
                m.insert("value".into(), json!(value));
                m.insert("model".into(), json!(b.model));
                if let Some(acc) = account_id(&c.secret) {
                    m.insert("codex".into(), json!({"accountId": acc}));
                }
                if let Some(block) = &c.provider_block {
                    m.insert("providerBlock".into(), serde_json::to_value(block).unwrap_or_default());
                }
                Value::Object(m)
            })
            .collect();
        let primary = bindings
            .iter()
            .find(|b| b.role() == "primary")
            .or_else(|| bindings.first());
        let fallback = bindings.iter().find(|b| Some(*b) != primary && b.role() == "secondary");
        let mut body = Map::new();
        body.insert(
            "model".into(),
            json!({
                "primary": primary.map(|b| b.model.clone()),
                "fallbacks": fallback.map(|b| vec![b.model.clone()]).unwrap_or_default(),
            }),
        );
        body.insert("credentials".into(), Value::Array(credentials));
        body.insert("remove".into(), Value::Array(remove.to_vec()));
        if let Some(m) = Self::memory_for(st, vm_id, &bindings) {
            body.insert("memory".into(), m);
        }
        Value::Object(body)
    }

    async fn push_agents(
        &self,
        vm_ids: &[String],
        remove: &[Value],
        timeout: Option<Duration>,
    ) -> Result<Vec<PushFailure>, String> {
        let mut failed = Vec::new();
        for vm_id in vm_ids {
            let (body, host) = {
                let st = self.st();
                (
                    Self::apply_body_of(&st, self.opts.plain_keys, vm_id, remove),
                    st.agents.get(vm_id).and_then(|a| a.hostname.clone()),
                )
            };
            let result = match host {
                None => Err(AgentError::new("This agent has no hostname yet.")),
                Some(h) => {
                    self.opts
                        .agent
                        .post(&Target::new(vm_id, &h), "/llm/apply", body.clone(), timeout)
                        .await
                }
            };
            match result {
                Ok(_) => remember_pushed(&mut self.st(), vm_id, &body),
                // A box that never answered may still have applied it.
                Err(e) => failed.push(PushFailure::from_error(vm_id, &e)),
            }
        }
        let st = self.st();
        self.save(&st)?;
        Ok(failed)
    }

    /// The box refused a one-agent change, so this firewall goes back to what the box still runs,
    /// and sends that once more. A timeout is never rolled back.
    async fn roll_back(&self, vm_id: &str, before: Option<StoredLlmAgent>) -> Result<(), String> {
        {
            let mut st = self.st();
            match &before {
                Some(b) => {
                    st.agents.insert(vm_id.to_string(), b.clone());
                }
                None => {
                    st.agents.shift_remove(vm_id);
                }
            }
            self.save(&st)?;
        }
        self.credentials_changed().await;
        tracing::info!(
            "[llm] {} refused the change; the firewall keeps what the agent runs",
            before.as_ref().map(|b| b.name.as_str()).unwrap_or(vm_id)
        );
        if let Some(b) = before.filter(|b| !b.bindings.is_empty()) {
            let again = self.push_agents(&[vm_id.to_string()], &[], None).await?;
            if let Some(f) = again.first() {
                tracing::info!("[llm] re-sending the previous model to {} failed: {}", b.name, f.error);
            }
        }
        Ok(())
    }

    async fn apply(&self, p: &LlmProposal) -> Result<Map<String, Value>, String> {
        let mode = if self.opts.plain_keys && p.cred_kind.as_deref() != Some("oauth") && p.allowed_models.is_none() {
            "plain"
        } else {
            "placeholder"
        };
        let existing = self.st().credentials.get(&p.credential_id).cloned();
        let mut out = Map::new();
        let applied_of = |targets: &[String], failed: &[PushFailure]| -> Value {
            json!(
                targets
                    .iter()
                    .filter(|v| !failed.iter().any(|f| &f.vm_id == *v))
                    .cloned()
                    .collect::<Vec<_>>()
            )
        };
        match p.kind.as_str() {
            "add" | "replace" => {
                let Some(secret) = &p.secret else {
                    return Err("no secret in the proposal".into());
                };
                let (Some(placeholder), Some(profile_id), Some(swap), Some(cred_kind)) =
                    (&p.placeholder, &p.profile_id, &p.swap, &p.cred_kind)
                else {
                    return Err("the proposal is missing the placeholder, profile id or swap location".into());
                };
                if cred_kind == "oauth" && p.oauth.is_none() {
                    return Err("an OAuth credential needs its token endpoint".into());
                }
                let cred = StoredCredential {
                    provider: p.provider.clone(),
                    kind: cred_kind.clone(),
                    placeholder: placeholder.clone(),
                    hint: p.hint.clone(),
                    label: p.label.clone(),
                    profile_id: profile_id.clone(),
                    swap: swap.clone(),
                    oauth: p.oauth.clone(),
                    provider_block: p.provider_block.clone(),
                    allowed_models: p.allowed_models.clone(),
                    memory: p.memory.clone(),
                    secret: secret.clone(),
                    failed: None,
                    updated_at: cc_crypto::store_health::iso_from_millis(self.now()),
                    extra: Map::new(),
                };
                let targets = {
                    let mut st = self.st();
                    st.credentials.insert(p.credential_id.clone(), cred);
                    for a in &p.agents {
                        set_binding(&mut st, a, &p.credential_id);
                    }
                    let mut targets = bound_agents(&st, &p.credential_id);
                    for a in &p.agents {
                        if !targets.contains(&a.vm_id) {
                            targets.push(a.vm_id.clone());
                        }
                    }
                    // Only the agents the proposal named.
                    for a in &p.agents {
                        apply_embeddings(&mut st, &a.vm_id, a.embeddings.as_ref());
                    }
                    self.save(&st)?;
                    targets
                };
                self.credentials_changed().await;
                let failed = self.push_agents(&targets, &[], None).await?;
                out.insert("mode".into(), json!(mode));
                out.insert("applied".into(), applied_of(&targets, &failed));
                out.insert("failed".into(), failures_json(&failed));
            }
            "remove" => {
                let (bound, payees, remove) = {
                    let mut st = self.st();
                    let bound = bound_agents(&st, &p.credential_id);
                    let payees: Vec<String> = st
                        .agents
                        .iter()
                        .filter(|(_, a)| {
                            a.embeddings
                                .as_ref()
                                .is_some_and(|e| e.credential_id == p.credential_id)
                        })
                        .map(|(v, _)| v.clone())
                        .collect();
                    let remove: Vec<Value> = existing.iter().map(remove_entry).collect();
                    for vm_id in &bound {
                        drop_binding(&mut st, vm_id, &p.credential_id);
                    }
                    for vm_id in &payees {
                        if let Some(a) = st.agents.get_mut(vm_id) {
                            a.embeddings = None;
                        }
                    }
                    st.credentials.shift_remove(&p.credential_id);
                    self.save(&st)?;
                    (bound, payees, remove)
                };
                self.credentials_changed().await;
                let mut targets = bound.clone();
                for v in payees {
                    if !targets.contains(&v) {
                        targets.push(v);
                    }
                }
                let failed = self.push_agents(&targets, &remove, None).await?;
                out.insert("applied".into(), applied_of(&targets, &failed));
                out.insert("failed".into(), failures_json(&failed));
            }
            "bind" | "set_model" => {
                if existing.is_none() {
                    return Err("This provider is not set up on the firewall. Add it again.".into());
                }
                let Some(a) = p.agents.first() else {
                    return Err("no agent in the proposal".into());
                };
                let (before, added) = {
                    let mut st = self.st();
                    let before = st.agents.get(&a.vm_id).cloned();
                    let added = match &p.provider_block {
                        Some(block) => merge_provider_block(&mut st, &p.credential_id, block)?,
                        None => Vec::new(),
                    };
                    set_binding(&mut st, a, &p.credential_id);
                    apply_embeddings(&mut st, &a.vm_id, a.embeddings.as_ref());
                    self.save(&st)?;
                    (before, added)
                };
                self.credentials_changed().await;
                // One agent: the push budget, not the 25 s of a call. An unmanaged agent runs
                // `config patch` and `models auth paste-api-key` through the OpenClaw CLI, about
                // 13 s each, and the panel answered "did not answer in time" (matrix 2).
                let failed = self
                    .push_agents(
                        std::slice::from_ref(&a.vm_id),
                        &[],
                        Some(Duration::from_millis(LLM_PUSH_MS)),
                    )
                    .await?;
                if failed.first().is_some_and(|f| f.refused) {
                    self.roll_back(&a.vm_id, before).await?;
                    if !added.is_empty() {
                        let mut st = self.st();
                        unmerge_provider_block(&mut st, &p.credential_id, &added);
                        self.save(&st)?;
                    }
                }
                out.insert("mode".into(), json!(mode));
                out.insert(
                    "applied".into(),
                    if failed.is_empty() { json!([a.vm_id]) } else { json!([]) },
                );
                out.insert("failed".into(), failures_json(&failed));
            }
            _ => {
                let Some(a) = p.agents.first() else {
                    return Err("no agent in the proposal".into());
                };
                let before = {
                    let mut st = self.st();
                    let before = st.agents.get(&a.vm_id).cloned();
                    drop_binding(&mut st, &a.vm_id, &p.credential_id);
                    self.save(&st)?;
                    before
                };
                self.credentials_changed().await;
                let remove: Vec<Value> = existing.iter().map(remove_entry).collect();
                let failed = self.push_agents(std::slice::from_ref(&a.vm_id), &remove, None).await?;
                if failed.first().is_some_and(|f| f.refused) {
                    self.roll_back(&a.vm_id, before).await?;
                }
                out.insert(
                    "applied".into(),
                    if failed.is_empty() { json!([a.vm_id]) } else { json!([]) },
                );
                out.insert("failed".into(), failures_json(&failed));
            }
        }
        Ok(out)
    }

    // ---- OAuth refresh ----

    /// Refresh every OAuth credential that expires within `REFRESH_AHEAD_MS`. Called on a timer.
    /// A refresh already running is not waited for (`refreshing` in the TS). The token calls run
    /// without the state lock, so a slow token endpoint holds up no command; each answer is put on
    /// its credential only if that credential still holds the refresh token the call used.
    pub async fn refresh_due(&self) {
        if self.refreshing.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // `finally`: the flag is cleared however this ends, a dropped future or a panic included,
        // or the timer would skip every refresh after it.
        struct Clear<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let _clear = Clear(&self.refreshing);
        // From the last saved store: a command that is pushing holds up no refresh.
        let due: Vec<(String, String, String, OAuth)> = {
            let st = self.snapshot();
            let now = self.now() as f64;
            st.credentials
                .iter()
                .filter_map(|(id, c)| {
                    let oauth = c.oauth.clone()?;
                    let refresh = c.secret.get("refresh")?.as_str()?.to_string();
                    if c.kind != "oauth" || c.failed.is_some() {
                        return None;
                    }
                    let expires = c.secret.get("expires").and_then(Value::as_f64).unwrap_or(0.0);
                    (expires - now <= REFRESH_AHEAD_MS as f64).then(|| (id.clone(), c.provider.clone(), refresh, oauth))
                })
                .collect()
        };
        let mut answers = Vec::new();
        for (id, provider, refresh, oauth) in due {
            let mut form = vec![
                ("grant_type".to_string(), "refresh_token".to_string()),
                ("refresh_token".to_string(), refresh.clone()),
                ("client_id".to_string(), oauth.client_id.clone()),
            ];
            // `client_secret` only when the provider needs one.
            if let Some(secret) = oauth.client_secret.as_ref().filter(|s| !s.is_empty()) {
                form.push(("client_secret".to_string(), secret.clone()));
            }
            match self
                .opts
                .fetch
                .post_form(&oauth.token_endpoint, form, REFRESH_TIMEOUT)
                .await
            {
                Ok(answer) => answers.push((id, provider, refresh, answer)),
                Err(e) => tracing::info!("[llm] refresh of {provider} errored ({e}); will retry"),
            }
        }
        if !answers.is_empty() {
            let changed = {
                let mut st = self.st();
                let mut changed = false;
                for (id, provider, refresh, (status, body)) in answers {
                    let current = st
                        .credentials
                        .get(&id)
                        .and_then(|c| c.secret.get("refresh"))
                        .and_then(Value::as_str);
                    if current != Some(refresh.as_str()) {
                        continue; // replaced or removed while the call ran
                    }
                    changed |= self.take_refresh(&mut st, &id, &provider, &refresh, status, &body);
                }
                if changed && let Err(e) = self.save(&st) {
                    tracing::error!("[llm] refreshed tokens not saved: {e}");
                }
                changed
            };
            if changed {
                self.credentials_changed().await;
            }
        }
    }

    /// One token endpoint answer onto its credential. True when the credential changed.
    fn take_refresh(
        &self,
        st: &mut LlmStore,
        id: &str,
        provider: &str,
        refresh: &str,
        status: u16,
        body: &Value,
    ) -> bool {
        let access = body.get("access_token").and_then(Value::as_str);
        let ok = (200..300).contains(&status);
        let Some(access) = access.filter(|_| ok) else {
            let reason = s(body.get("error_description"))
                .or_else(|| s(body.get("error")))
                .unwrap_or_else(|| format!("HTTP {status}"));
            if (400..500).contains(&status) {
                // The refresh token is gone (revoked, reused, expired): only a new login helps.
                let failed = format!("Token refresh refused: {reason}. Connect the account again.");
                if let Some(c) = st.credentials.get_mut(id) {
                    c.failed = Some(failed.clone());
                }
                let mut data = Map::new();
                data.insert("credentialId".into(), json!(id));
                self.reports
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(CommandResult {
                        command_id: format!("llm.refresh:{id}"),
                        ok: false,
                        status: "failed".into(),
                        message: failed,
                        data: Some(data),
                    });
                tracing::info!("[llm] refresh of {provider} refused: {reason}");
                return true;
            }
            tracing::info!("[llm] refresh of {provider} failed ({reason}); will retry");
            return false;
        };
        let expires_in = body.get("expires_in").and_then(Value::as_f64).unwrap_or(3600.0);
        let rotated = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty())
            .unwrap_or(refresh)
            .to_string();
        let now = self.now();
        if let Some(c) = st.credentials.get_mut(id) {
            c.secret.insert("access".into(), json!(access));
            c.secret.insert("refresh".into(), json!(rotated));
            c.secret
                .insert("expires".into(), js_number(now as f64 + expires_in * 1000.0));
            c.updated_at = cc_crypto::store_health::iso_from_millis(now);
        }
        tracing::info!(
            "[llm] refreshed {provider} token (expires in {} min)",
            (expires_in / 60.0).round()
        );
        true
    }
}

/// How many tries a code gets (`CODE_ATTEMPTS`); what `send` answers on a fresh code.
pub const CODE_ATTEMPTS: u32 = 5;

/// Said when this firewall cannot tell who could confirm a change (its channels are not running),
/// so it neither asks nor applies.
pub const NO_ROUTES: &str =
    "This firewall cannot check who may confirm model provider changes yet. Update the firewall, then try again.";

/// Said when a change needs a code and nothing on this firewall can send one.
pub const NO_CODES: &str = "Confirmation codes are not available on this firewall yet.";

/// A number as JSON writes it: an integer stays an integer.
pub fn js_number(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 {
        json!(n as i64)
    } else {
        json!(n)
    }
}

fn memory_with_key(m: &MemorySearch, key: &str) -> Value {
    let mut v = serde_json::to_value(m).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("apiKey".into(), json!(key));
    }
    v
}

fn outcome(ok: bool, status: &str, message: Option<String>, data: Map<String, Value>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.into(),
        message,
        data: Some(data),
    }
}

fn agent_of<'a>(st: &'a mut LlmStore, vm_id: &str, name: &str, hostname: Option<&str>) -> &'a mut StoredLlmAgent {
    let a = st.agents.entry(vm_id.to_string()).or_insert_with(|| StoredLlmAgent {
        name: name.into(),
        hostname: hostname.map(str::to_string),
        bindings: vec![],
        memory: None,
        embeddings: None,
        extra: Map::new(),
    });
    if !name.is_empty() {
        a.name = name.into();
    }
    if let Some(h) = hostname.filter(|h| !h.is_empty()) {
        a.hostname = Some(h.into());
    }
    a
}

/// Put a credential in a slot, moving whoever held it: to the slot this credential vacates (a
/// swap) or to the free one, and dropping it when there is none.
fn set_binding(st: &mut LlmStore, r: &AgentRef, credential_id: &str) {
    let agent = agent_of(st, &r.vm_id, &r.name, r.hostname.as_deref());
    let other = if r.role == "primary" { "secondary" } else { "primary" };
    let rest: Vec<StoredBinding> = agent
        .bindings
        .iter()
        .filter(|b| b.credential_id != credential_id)
        .cloned()
        .collect();
    let holder = rest.iter().position(|b| b.role() == r.role);
    let kept: Vec<StoredBinding> = rest
        .iter()
        .enumerate()
        .filter(|(i, b)| Some(*i) != holder && b.role() == other)
        .map(|(_, b)| b.clone())
        .collect();
    let moved: Vec<StoredBinding> = match holder {
        Some(i) if kept.is_empty() => {
            let mut m = rest[i].clone();
            m.role = Some(other.into());
            vec![m]
        }
        _ => vec![],
    };
    let mut bindings = vec![StoredBinding::new(credential_id, &r.model, &r.role)];
    bindings.extend(kept);
    bindings.extend(moved);
    agent.bindings = bindings;
}

/// Take a credential off an agent. A fallback left alone moves up.
fn drop_binding(st: &mut LlmStore, vm_id: &str, credential_id: &str) {
    let Some(agent) = st.agents.get_mut(vm_id) else { return };
    agent.bindings.retain(|b| b.credential_id != credential_id);
    if !agent.bindings.is_empty() && !agent.bindings.iter().any(|b| b.role() == "primary") {
        agent.bindings[0].role = Some("primary".into());
    }
}

fn bound_agents(st: &LlmStore, credential_id: &str) -> Vec<String> {
    st.agents
        .iter()
        .filter(|(_, a)| a.bindings.iter().any(|b| b.credential_id == credential_id))
        .map(|(v, _)| v.clone())
        .collect()
}

/// Record what a box took, once the POST has come back.
fn remember_pushed(st: &mut LlmStore, vm_id: &str, body: &Value) {
    let Some(agent) = st.agents.get_mut(vm_id) else { return };
    let Some(m) = body.get("memory") else { return };
    agent.memory = parse_memory_search(Some(m));
}

/// A bind that names its model in a provider block (the standalone panel, the SaaS's included AI):
/// its models are added to the block the credential already holds, at the same endpoint. Never a
/// new block or another endpoint on a bind: a bind for a new agent needs no code, and the block goes
/// to every agent on the key, so it would redirect all of their model traffic (review of #709). A
/// credential with no block keeps none, as before blocks came with binds; the block a key needs
/// comes with its add or replace. The ids added, for a rollback that takes back only those.
fn merge_provider_block(st: &mut LlmStore, credential_id: &str, block: &ProviderBlock) -> Result<Vec<String>, String> {
    let Some(cred) = st.credentials.get_mut(credential_id) else {
        return Ok(Vec::new());
    };
    match &mut cred.provider_block {
        None => {
            tracing::info!(
                "[llm] ignoring a bind's provider block for {}: the key has none, and a bind cannot add one",
                cred.provider
            );
            Ok(Vec::new())
        }
        Some(current) if current.base_url == block.base_url && current.api == block.api => {
            let mut added = Vec::new();
            for m in &block.models {
                if !current.models.iter().any(|c| c.id == m.id) {
                    current.models.push(m.clone());
                    added.push(m.id.clone());
                }
            }
            Ok(added)
        }
        Some(_) => Err(format!(
            "This change names another endpoint for {}'s models than its key has. Replace the key instead.",
            cred.provider
        )),
    }
}

/// Take back the models a refused bind added to its credential's block, when no agent on the key
/// uses them now: a bind that ran meanwhile keeps what it added.
fn unmerge_provider_block(st: &mut LlmStore, credential_id: &str, added: &[String]) {
    let prefix = st
        .credentials
        .get(credential_id)
        .map(|c| format!("{}/", c.provider))
        .unwrap_or_default();
    let used: HashSet<String> = st
        .agents
        .values()
        .flat_map(|a| &a.bindings)
        .filter(|b| b.credential_id == credential_id)
        .filter_map(|b| b.model.strip_prefix(&prefix).map(str::to_string))
        .collect();
    if let Some(block) = st
        .credentials
        .get_mut(credential_id)
        .and_then(|c| c.provider_block.as_mut())
    {
        block.models.retain(|m| !added.contains(&m.id) || used.contains(&m.id));
    }
}

/// Replace the provider block of credentials this firewall holds with the one the push carries,
/// only when the credential came with one and the endpoint is the same.
fn refresh_provider_blocks(st: &mut LlmStore, raw: Option<&Value>) -> bool {
    let Some(list) = raw.and_then(Value::as_array) else {
        return false;
    };
    let mut changed = false;
    for r in list {
        let (Some(id), Some(block)) = (s(r.get("credentialId")), parse_provider_block(r.get("providerBlock"))) else {
            continue;
        };
        let Some(cred) = st.credentials.get_mut(&id) else {
            continue;
        };
        let Some(current) = &cred.provider_block else { continue };
        if current.base_url != block.base_url || current.api != block.api {
            tracing::info!(
                "[llm] ignoring a provider block for {}: its endpoint differs from the one proposed",
                cred.provider
            );
            continue;
        }
        if serde_json::to_string(current).ok() == serde_json::to_string(&block).ok() {
            continue;
        }
        cred.provider_block = Some(block);
        changed = true;
    }
    changed
}

/// Put the catalog data a push carries onto the credential it names.
fn refresh_credential(st: &mut LlmStore, raw: Option<&Value>) -> bool {
    let Some(r) = obj(raw) else { return false };
    let Some(id) = s(r.get("credentialId")) else {
        return false;
    };
    let Some(cred) = st.credentials.get_mut(&id) else {
        return false;
    };
    let snap = |c: &StoredCredential| serde_json::to_string(&(&c.memory, &c.allowed_models)).unwrap_or_default();
    let before = snap(cred);
    // Only ever set: taking an allow-list away would hand the box's placeholder the gateway.
    if let (Some(allowed), true) = (parse_model_list(r.get("allowedModels")), cred.allowed_models.is_some()) {
        cred.allowed_models = Some(allowed);
    }
    match parse_memory_search(r.get("memory")) {
        Some(m) if cred.allowed_models.as_ref().is_some_and(|a| !a.contains(&m.model)) => {
            tracing::info!(
                "[llm] ignoring a memory descriptor for {}: {} is not on this key's allow-list",
                cred.provider,
                m.model
            );
            cred.memory = None;
        }
        Some(m) => cred.memory = Some(m),
        None => cred.memory = None,
    }
    before != snap(cred)
}

/// Record who pays for this agent's embeddings. `None`: the payload said nothing.
fn apply_embeddings(st: &mut LlmStore, vm_id: &str, r: Option<&Option<EmbeddingsRef>>) -> bool {
    let Some(r) = r else { return false };
    let cred_known = r
        .as_ref()
        .map(|e| st.credentials.contains_key(&e.credential_id))
        .unwrap_or(false);
    let Some(agent) = st.agents.get_mut(vm_id) else {
        return false;
    };
    let before = agent.embeddings.clone();
    match r {
        None => agent.embeddings = None,
        Some(e) => {
            let covered = e.allowed_models.as_ref().is_some_and(|a| a.contains(&e.memory.model));
            if !cred_known || !covered {
                if cred_known {
                    tracing::info!(
                        "[llm] ignoring an embeddings payer for {}: {} is not on the allow-list it came with",
                        agent.name,
                        e.memory.model
                    );
                }
                agent.embeddings = None;
            } else {
                agent.embeddings = Some(Embeddings {
                    credential_id: e.credential_id.clone(),
                    memory: e.memory.clone(),
                    allowed_models: e.allowed_models.clone().unwrap_or_default(),
                    extra: Map::new(),
                });
            }
        }
    }
    let ser = |e: &Option<Embeddings>| serde_json::to_string(e).unwrap_or_default();
    ser(&before) != ser(&agent.embeddings)
}

/// `DoctorCredential` (W5's Doctor and Final check): a stored credential by id, as the store keeps
/// it, refreshed first when due. Without the refresh token and the OAuth client secret: Doctor never
/// refreshes a sign-in, the firewall does (the TS build handed over the whole record).
pub struct LlmDoctor(pub Arc<Llm>);

impl crate::contracts::DoctorCredential for LlmDoctor {
    fn credential(&self, id: &str) -> cc_http::BoxFuture<Option<Value>> {
        let (l, id) = (self.0.clone(), id.to_string());
        Box::pin(async move {
            let mut v = match serde_json::to_value(l.doctor_credential(&id).await?) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("[llm] a stored credential could not be read for Doctor: {e}");
                    return None;
                }
            };
            if let Some(s) = v.get_mut("secret").and_then(Value::as_object_mut) {
                s.remove("refresh");
            }
            if let Some(o) = v.get_mut("oauth").and_then(Value::as_object_mut) {
                o.remove("clientSecret");
            }
            Some(v)
        })
    }
}
