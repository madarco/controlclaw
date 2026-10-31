//! The AgentMail store (`agentmail-store.ts`): the account, its key, and each inbox with the agent
//! it is on. Enc-file under the box key, AAD `<org>:<box>:agentmail`.

use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailInbox {
    pub inbox_id: String,
    #[serde(default)]
    pub vm_id: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub imported: bool,
    /// Kept as stored: checked when used, as the TS does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_senders: Option<Value>,
    /// The sender list last pushed to the agent; a re-push is only needed when this changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_pending: Option<bool>,
    pub status: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Create {
    pub username: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMailStore {
    pub version: u32,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub org_key: Option<String>,
    #[serde(default)]
    pub human_email: Option<String>,
    #[serde(default)]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub limits: IndexMap<String, Value>,
    #[serde(default)]
    pub signup_started: bool,
    #[serde(default)]
    pub inboxes: IndexMap<String, MailInbox>,
    #[serde(default)]
    pub completed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creates: Option<IndexMap<String, Create>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for AgentMailStore {
    fn default() -> Self {
        Self {
            version: 1,
            org_id: None,
            org_key: None,
            human_email: None,
            auth_type: None,
            limits: IndexMap::new(),
            signup_started: false,
            inboxes: IndexMap::new(),
            completed: vec![],
            creates: None,
            extra: Map::new(),
        }
    }
}

fn aad(org_id: &str, box_id: &str) -> String {
    format!("{org_id}:{box_id}:agentmail")
}

/// `Err` for a store of another version, or one this build cannot read field for field.
pub fn load(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> Result<AgentMailStore, String> {
    let log = |l: &str| tracing::info!("{l}");
    let Some(v) = cc_crypto::enc_file::load_store_or_empty("agentmail", path, box_key, &aad(org_id, box_id), &log)
    else {
        return Ok(AgentMailStore::default());
    };
    // The kind and place only: serde quotes the value it refused, which can be a key.
    let store: AgentMailStore = serde_json::from_value(v)
        .map_err(|e| format!("{:?} error at line {} column {}", e.classify(), e.line(), e.column()))?;
    if store.version != 1 {
        return Err("Unsupported AgentMail store".into());
    }
    for i in store.inboxes.values() {
        if let Some(k) = &i.key {
            cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(k.clone()), true);
        }
    }
    Ok(store)
}

pub fn save(path: &Path, store: &AgentMailStore, box_key: &str, org_id: &str, box_id: &str) -> Result<(), String> {
    let v = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store("agentmail", path, &v, box_key, &aad(org_id, box_id)).map_err(|e| e.0)
}
