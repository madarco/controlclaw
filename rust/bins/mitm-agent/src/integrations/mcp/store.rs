//! The firewall's MCP servers store (`mcp-servers-store.ts`, docs/plans/mcp-servers.md): the
//! organization's remote MCP servers, how the firewall signs in to each, and which agents may use
//! which. `mcp-servers.enc`, AAD `<org>:<box>:mcp-servers`.
//!
//! Unlike the connector store this one holds the credentials themselves (a header's value, an
//! OAuth client secret, the tokens): the firewall is where they are used.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::oauth::{OauthClient, OauthDiscovery, OauthTokens};
use crate::integrations::ordmap::OrdMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Oauth {
    pub discovery: OauthDiscovery,
    pub client: OauthClient,
    pub tokens: Option<OauthTokens>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMcpServer {
    pub name: String,
    pub url: String,
    /// `none`, `header` or `oauth`.
    pub auth: String,
    pub header: Option<Header>,
    pub oauth: Option<Oauth>,
    /// `active`, `reauth_required` or `failed`.
    pub state: String,
    pub last_error: Option<String>,
    /// What the server calls itself in `initialize`.
    pub server_name: Option<String>,
    #[serde(default)]
    pub tools: Vec<Value>,
    pub tools_at: Option<String>,
    /// The agents (vm ids) that may use it.
    #[serde(default)]
    pub agents: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServersStore {
    pub version: u32,
    pub servers: OrdMap<StoredMcpServer>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for McpServersStore {
    fn default() -> Self {
        Self {
            version: 1,
            servers: OrdMap::new(),
            extra: Map::new(),
        }
    }
}

pub const STORE: &str = "mcp-servers";

fn aad(org: &str, boxid: &str) -> String {
    format!("{org}:{boxid}:mcp-servers")
}

pub fn load(path: &Path, key: &str, org: &str, boxid: &str) -> McpServersStore {
    let log = |l: &str| tracing::info!("{l}");
    let Some(v) = cc_crypto::enc_file::load_store_or_empty(STORE, path, key, &aad(org, boxid), &log) else {
        return McpServersStore::default();
    };
    if v.get("version") != Some(&Value::from(1)) {
        return McpServersStore::default();
    }
    // A server that does not read is left out, the rest kept (the TS keeps every object).
    let mut store = McpServersStore::default();
    if let Some(o) = v.as_object() {
        store.extra = o
            .iter()
            .filter(|(k, _)| k.as_str() != "version" && k.as_str() != "servers")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
    }
    if let Some(servers) = v.get("servers").and_then(Value::as_object) {
        for (k, s) in servers {
            match serde_json::from_value::<StoredMcpServer>(s.clone()) {
                Ok(s) => store.servers.insert(k.clone(), s),
                Err(e) => tracing::error!("[mcp-servers] {k} in the store does not read: {e}"),
            }
        }
    }
    store
}

pub fn save(path: &Path, store: &McpServersStore, key: &str, org: &str, boxid: &str) -> Result<(), String> {
    let v = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store(STORE, path, &v, key, &aad(org, boxid)).map_err(|e| e.0)
}
