//! The firewall's LLM store (`llm-store.ts`): the organization's model provider credentials and
//! which agent uses which. Enc-file under the box key, AAD `<org>:<box>:llm`. Every struct keeps
//! the fields it does not know, so the Node build reads back what this one wrote.

use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Swap {
    #[serde(rename = "matchDomain")]
    pub match_domain: String,
    pub locations: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuth {
    #[serde(rename = "tokenEndpoint")]
    pub token_endpoint: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret", default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderModel {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderBlock {
    #[serde(rename = "baseUrl")]
    pub base_url: String,
    pub api: String,
    pub models: Vec<ProviderModel>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemorySearch {
    pub provider: String,
    pub model: String,
    #[serde(rename = "baseUrl")]
    pub base_url: String,
    #[serde(default)]
    pub dreaming: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl MemorySearch {
    pub fn new(provider: &str, model: &str, base_url: &str, dreaming: bool) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            base_url: base_url.into(),
            dreaming,
            extra: Map::new(),
        }
    }
}

/// `{apiKey}`, `{token}` or `{access, refresh, expires, accountId, email}`, kept as the JSON it is.
pub type StoredSecret = Map<String, Value>;

/// `secretValue`: the API key, the token, or the OAuth access token.
pub fn secret_value(s: &StoredSecret) -> String {
    for k in ["apiKey", "token", "access"] {
        if s.contains_key(k) {
            return s.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        }
    }
    String::new()
}

/// `"accountId" in c.secret && c.secret.accountId`.
pub fn account_id(s: &StoredSecret) -> Option<String> {
    s.get("accountId")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredCredential {
    pub provider: String,
    pub kind: String,
    pub placeholder: String,
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(rename = "profileId")]
    pub profile_id: String,
    pub swap: Swap,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuth>,
    #[serde(rename = "providerBlock", default, skip_serializing_if = "Option::is_none")]
    pub provider_block: Option<ProviderBlock>,
    #[serde(rename = "allowedModels", default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemorySearch>,
    pub secret: StoredSecret,
    #[serde(default)]
    pub failed: Option<String>,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredBinding {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    pub model: String,
    /// `primary` or `secondary`; older stores had `isPrimary` instead (see [`with_roles`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl StoredBinding {
    pub fn new(credential_id: &str, model: &str, role: &str) -> Self {
        Self {
            credential_id: credential_id.into(),
            model: model.into(),
            role: Some(role.into()),
            extra: Map::new(),
        }
    }

    pub fn role(&self) -> &str {
        self.role.as_deref().unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Embeddings {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    pub memory: MemorySearch,
    #[serde(rename = "allowedModels")]
    pub allowed_models: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredLlmAgent {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub bindings: Vec<StoredBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemorySearch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<Embeddings>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmStore {
    pub version: u32,
    pub credentials: IndexMap<String, StoredCredential>,
    pub agents: IndexMap<String, StoredLlmAgent>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for LlmStore {
    fn default() -> Self {
        Self {
            version: 1,
            credentials: IndexMap::new(),
            agents: IndexMap::new(),
            extra: Map::new(),
        }
    }
}

impl StoredCredential {
    /// The plan's included key: the console's `controlclaw_included`, here `controlclaw` with an
    /// allow-list of models.
    pub fn is_included(&self) -> bool {
        self.provider == "controlclaw" && self.allowed_models.is_some()
    }
}

/// See [`super::Llm::agents_using_models`]. Only the owner's own credentials count: the plan's
/// included key is one the console issues again after a restore, so a binding, embeddings or a
/// memory block on it break nothing. A credential this store no longer holds counts (it may be the
/// owner's). A memory block counts unless it is the included key's own (the included credential's
/// descriptor, or the included embeddings'): until the box takes it away it may run on any key
/// held here. (Changed from the TS, which counts every entry of `store.agents`.)
pub fn agents_using_models(st: &LlmStore) -> usize {
    let owners = |id: &str| !st.credentials.get(id).is_some_and(StoredCredential::is_included);
    let included_memory: Vec<&MemorySearch> = st
        .credentials
        .values()
        .filter(|c| c.is_included())
        .filter_map(|c| c.memory.as_ref())
        .collect();
    st.agents
        .values()
        .filter(|a| {
            let embeddings_included = a.embeddings.as_ref().filter(|e| !owners(&e.credential_id));
            let memory_included =
                |m: &MemorySearch| included_memory.contains(&m) || embeddings_included.is_some_and(|e| &e.memory == m);
            a.bindings.iter().any(|b| owners(&b.credential_id))
                || a.embeddings.as_ref().is_some_and(|e| owners(&e.credential_id))
                || a.memory.as_ref().is_some_and(|m| !memory_included(m))
        })
        .count()
}

fn aad(org_id: &str, box_id: &str) -> String {
    format!("{org_id}:{box_id}:llm")
}

/// Stores written before an agent had two slots hold `isPrimary` and any number of bindings: the
/// primary keeps the main slot, the first other becomes the fallback, the rest are dropped.
fn with_roles(mut store: LlmStore) -> LlmStore {
    for agent in store.agents.values_mut() {
        if agent
            .bindings
            .iter()
            .all(|b| matches!(b.role(), "primary" | "secondary"))
        {
            continue;
        }
        let mut ordered = agent.bindings.clone();
        // A stable sort, primaries first, as `Array.prototype.sort` with that comparator.
        ordered.sort_by_key(|b| !b.extra.get("isPrimary").and_then(Value::as_bool).unwrap_or(false));
        agent.bindings = ordered
            .into_iter()
            .take(2)
            .enumerate()
            .map(|(i, b)| StoredBinding::new(&b.credential_id, &b.model, if i == 0 { "primary" } else { "secondary" }))
            .collect();
    }
    store
}

#[cfg(test)]
pub fn load(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> LlmStore {
    load_checked(path, box_key, org_id, box_id).0
}

/// The store, and whether it may be written. One this build cannot read field for field is marked
/// unreadable (the heartbeat says so) and starts empty, and is never written over: it is not "no
/// providers".
pub fn load_checked(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> (LlmStore, bool) {
    let log = |l: &str| tracing::info!("{l}");
    let Some(raw) = cc_crypto::enc_file::load_store_or_empty("llm", path, box_key, &aad(org_id, box_id), &log) else {
        return (LlmStore::default(), true);
    };
    let good = raw.get("version") == Some(&Value::from(1))
        && raw.get("credentials").is_some_and(|v| !v.is_null())
        && raw.get("agents").is_some_and(|v| !v.is_null());
    if !good {
        return (LlmStore::default(), true);
    }
    match serde_json::from_value::<LlmStore>(raw) {
        Ok(s) => (with_roles(s), true),
        Err(e) => {
            // The kind and place only: serde quotes the value it refused, which can be a key.
            let why = format!("{:?} error at line {} column {}", e.classify(), e.line(), e.column());
            cc_crypto::store_health::note_store_unreadable("llm", &format!("the store did not parse: {why}"));
            keep_unreadable(path);
            tracing::error!(
                "[llm] the store did not parse ({why}); it is left as it is and nothing is written over it"
            );
            (LlmStore::default(), false)
        }
    }
}

/// A copy of a store this build cannot read, made once, as `enc-file` keeps one it cannot decrypt:
/// whatever a later build or a person does, the original is still there.
pub fn keep_unreadable(path: &Path) {
    let mut kept = path.as_os_str().to_owned();
    kept.push(".unreadable");
    let kept = std::path::PathBuf::from(kept);
    if !path.exists() || kept.exists() {
        return;
    }
    match std::fs::copy(path, &kept) {
        Ok(_) => tracing::info!("[llm] kept the unreadable file as {}", kept.display()),
        Err(e) => tracing::error!("[llm] could not keep a copy of {}: {e}", path.display()),
    }
}

pub fn save(path: &Path, store: &LlmStore, box_key: &str, org_id: &str, box_id: &str) -> Result<(), String> {
    let value = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store("llm", path, &value, box_key, &aad(org_id, box_id)).map_err(|e| e.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn legacy_is_primary_bindings_become_two_slots_and_unknown_fields_survive() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("llm.enc");
        let raw = json!({
            "version": 1,
            "future": {"x": 1},
            "credentials": {},
            "agents": {"vm1": {"name": "a", "hostname": null, "bindings": [
                {"credentialId": "c1", "model": "m1", "isPrimary": false},
                {"credentialId": "c2", "model": "m2", "isPrimary": true},
                {"credentialId": "c3", "model": "m3"}
            ], "later": true}}
        });
        cc_crypto::enc_file::save_encrypted_json(&path, &raw, KEY, "o:b:llm").expect("seal");
        let s = load(&path, KEY, "o", "b");
        let b = &s.agents["vm1"].bindings;
        assert_eq!(b.len(), 2);
        assert_eq!((b[0].credential_id.as_str(), b[0].role()), ("c2", "primary"));
        assert_eq!((b[1].credential_id.as_str(), b[1].role()), ("c1", "secondary"));
        save(&path, &s, KEY, "o", "b").expect("save");
        let back = cc_crypto::enc_file::load_encrypted_json(&path, KEY, "o:b:llm")
            .expect("open")
            .expect("there");
        assert_eq!(back["future"], json!({"x": 1}));
        assert_eq!(back["agents"]["vm1"]["later"], json!(true));
    }

    #[test]
    fn a_wrong_shape_or_key_starts_empty() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("llm.enc");
        cc_crypto::enc_file::save_encrypted_json(&path, &json!({"version": 2}), KEY, "o:b:llm").expect("seal");
        assert_eq!(load(&path, KEY, "o", "b"), LlmStore::default());
        assert_eq!(load(&path, KEY, "o", "other"), LlmStore::default());
    }

    #[test]
    fn a_store_that_does_not_parse_is_kept_and_not_writable() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("llm.enc");
        let raw = json!({"version": 1, "credentials": {"c": {"provider": 5}}, "agents": {}});
        cc_crypto::enc_file::save_encrypted_json(&path, &raw, KEY, "o:b:llm").expect("seal");
        let (s, writable) = load_checked(&path, KEY, "o", "b");
        assert!(!writable);
        assert_eq!(s, LlmStore::default());
        assert!(dir.path().join("llm.enc.unreadable").exists(), "a copy is kept");
    }
}
