//! The firewall's connector store (`connector-store.ts`): which app connections the organization
//! has, which agent may use which, and the runtime token each agent holds. `connectors.enc`, AAD
//! `<org>:<box>:connectors`.
//!
//! The app credential itself is not here: OpenConnector keeps every credential in its own
//! encrypted SQLite and is the only process that decrypts one. This store holds the map: the
//! runtime's connection id, the label a person reads, and the per-agent runtime tokens (which are
//! secrets, minted here).

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::integrations::ordmap::OrdMap;

/// What the console may see about one connection. Set from the runtime's own reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StoredConnection {
    /// The runtime's stable, opaque connection id: what `allowedConnections` grants.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub service: String,
    /// The runtime's alias: what a caller names to select this connection.
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub account_label: Option<String>,
    /// What the person called it.
    #[serde(default)]
    pub label: Option<String>,
    /// The runtime's own state word (`active`, `reauth_required`, …).
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One agent's grant. `token` is the `oct_…` runtime token the agent box holds; `token_id` is the
/// runtime's record id, needed to update or revoke it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StoredConnectorAgent {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub private_ip: Option<String>,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub connections: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectorStore {
    pub version: u32,
    pub connections: OrdMap<StoredConnection>,
    pub agents: OrdMap<StoredConnectorAgent>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The agents that hold a connection now: what a recovery restore must find empty. Removing a
/// connection keeps the agent's entry, so `agents.len()` would count an agent that once had one
/// forever. (Changed from the TS, which counts `summary().agents`.)
pub fn agents_with_connections(s: &ConnectorStore) -> usize {
    s.agents.values().filter(|a| !a.connections.is_empty()).count()
}

impl Default for ConnectorStore {
    fn default() -> Self {
        Self {
            version: 1,
            connections: OrdMap::new(),
            agents: OrdMap::new(),
            extra: Map::new(),
        }
    }
}

pub const STORE: &str = "connectors";

pub fn aad(org_id: &str, box_id: &str) -> String {
    format!("{org_id}:{box_id}:connectors")
}

pub fn load(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> ConnectorStore {
    let log = |l: &str| tracing::info!("{l}");
    cc_crypto::enc_file::load_store_or_empty(STORE, path, box_key, &aad(org_id, box_id), &log)
        .and_then(|v| serde_json::from_value::<ConnectorStore>(v).ok())
        .filter(|s| s.version == 1)
        .unwrap_or_default()
}

pub fn save(path: &Path, store: &ConnectorStore, box_key: &str, org_id: &str, box_id: &str) -> Result<(), String> {
    let value = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store(STORE, path, &value, box_key, &aad(org_id, box_id)).map_err(|e| e.0)
}

/// The services an agent's token may run actions for: exactly the ones it has a connection to.
pub fn services_for(store: &ConnectorStore, agent: &StoredConnectorAgent) -> Vec<String> {
    let mut services: Vec<String> = agent
        .connections
        .iter()
        .filter_map(|id| store.connections.get(id))
        .map(|c| c.service.clone())
        .collect();
    services.sort();
    services.dedup();
    services
}
