//! The firewall's channel store (`channel-store.ts`): the organization's channel connections (bot
//! tokens, WhatsApp settings), who is an approved sender on each, and which agent each is on.
//! Enc-file under the box key, AAD `<org>:<box>:channels`. A v1 store (a channel per agent) is
//! converted on load, with the ids the console's migration mints (`legacy:<vmId>:<type>`).

use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovedSender {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An approval this firewall asked for but never heard the answer to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    #[serde(default)]
    pub sender_id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredConnection {
    #[serde(rename = "type")]
    pub kind: String,
    /// `botToken`, `appToken`: strings; anything else is kept as it was and never used.
    #[serde(default)]
    pub secrets: Map<String, Value>,
    #[serde(default)]
    pub settings: Map<String, Value>,
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub approved_senders: Vec<ApprovedSender>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_approvals: Option<Vec<PendingApproval>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declined_senders: Option<Vec<String>>,
    #[serde(default)]
    pub assigned_vm_id: Option<String>,
    #[serde(default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl StoredConnection {
    /// A token by name (`botToken`, `appToken`), when it is a non-empty string.
    pub fn secret(&self, key: &str) -> Option<&str> {
        self.secrets.get(key).and_then(Value::as_str).filter(|t| !t.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredAgent {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelStore {
    pub version: u32,
    pub connections: IndexMap<String, StoredConnection>,
    pub agents: IndexMap<String, StoredAgent>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for ChannelStore {
    fn default() -> Self {
        Self {
            version: 2,
            connections: IndexMap::new(),
            agents: IndexMap::new(),
            extra: Map::new(),
        }
    }
}

/// The id both sides mint for a channel that existed before connections.
pub fn legacy_connection_id(vm_id: &str, kind: &str) -> String {
    format!("legacy:{vm_id}:{kind}")
}

fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

fn from_v1(v1: &Value) -> ChannelStore {
    let mut store = ChannelStore::default();
    let Some(agents) = v1.get("agents").and_then(Value::as_object) else {
        return store;
    };
    for (vm_id, agent) in agents {
        store.agents.insert(
            vm_id.clone(),
            StoredAgent {
                name: s(agent.get("name")).unwrap_or_default(),
                hostname: s(agent.get("hostname")),
                extra: Map::new(),
            },
        );
        // One by one: a sender that does not fit is dropped alone, not with the others.
        let senders: Vec<ApprovedSender> = agent
            .get("approvedSenders")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| serde_json::from_value(x.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let Some(channels) = agent.get("channels").and_then(Value::as_object) else {
            continue;
        };
        for (kind, ch) in channels {
            if ch.is_null() {
                continue;
            }
            store.connections.insert(
                legacy_connection_id(vm_id, kind),
                StoredConnection {
                    kind: kind.clone(),
                    secrets: ch
                        .get("secrets")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default(),
                    settings: ch
                        .get("settings")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default(),
                    hint: s(ch.get("hint")),
                    label: s(ch.get("label")),
                    approved_senders: senders.iter().filter(|x| &x.kind == kind).cloned().collect(),
                    pending_approvals: None,
                    declined_senders: None,
                    assigned_vm_id: Some(vm_id.clone()),
                    updated_at: s(ch.get("updatedAt")).unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into()),
                    extra: Map::new(),
                },
            );
        }
    }
    store
}

fn aad(org_id: &str, box_id: &str) -> String {
    format!("{org_id}:{box_id}:channels")
}

/// `coerce`: v1 converted, v2 as it is, anything else empty. `Err` for a v2 store this build
/// cannot read field for field: it is not "no channels", and must not be written over.
pub fn coerce(parsed: Option<Value>) -> Result<ChannelStore, String> {
    let Some(v) = parsed else {
        return Ok(ChannelStore::default());
    };
    match v.get("version").and_then(Value::as_u64) {
        Some(1) => Ok(from_v1(&v)),
        Some(2)
            if v.get("connections").is_some_and(|c| !c.is_null()) && v.get("agents").is_some_and(|a| !a.is_null()) =>
        {
            // The kind and place only: serde quotes the value it refused, which can be a token.
            serde_json::from_value(v)
                .map_err(|e| format!("{:?} error at line {} column {}", e.classify(), e.line(), e.column()))
        }
        _ => Ok(ChannelStore::default()),
    }
}

/// What a load found: whether the store may be written, and whether it was read at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    /// False when the store would not parse: it is never written over.
    pub writable: bool,
    /// False when it would not decrypt or would not parse: its list of people is not known.
    pub readable: bool,
}

/// The store, and what the load found. One that would not decrypt or parse is marked unreadable
/// (the heartbeat says so) and starts empty; one that would not parse is never written over.
pub fn load(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> (ChannelStore, Loaded) {
    let log = |l: &str| tracing::info!("{l}");
    // Read once more to know, for this store, whether it decrypted (the health flag is process-wide).
    let decrypted = cc_crypto::enc_file::load_encrypted_json(path, box_key, &aad(org_id, box_id)).is_ok();
    let raw = cc_crypto::enc_file::load_store_or_empty("channels", path, box_key, &aad(org_id, box_id), &log);
    match coerce(raw) {
        Ok(s) => (
            s,
            Loaded {
                writable: true,
                readable: decrypted,
            },
        ),
        Err(e) => {
            cc_crypto::store_health::note_store_unreadable("channels", &format!("the store did not parse: {e}"));
            tracing::error!(
                "[channels] {} did not parse ({e}); it is left as it is and nothing is written over it",
                path.display()
            );
            (
                ChannelStore::default(),
                Loaded {
                    writable: false,
                    readable: false,
                },
            )
        }
    }
}

pub fn save(path: &Path, store: &ChannelStore, box_key: &str, org_id: &str, box_id: &str) -> Result<(), String> {
    let v = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store("channels", path, &v, box_key, &aad(org_id, box_id)).map_err(|e| e.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn v1_becomes_connections_with_the_consoles_ids() {
        let v1 = json!({"version": 1, "agents": {"vm1": {"name": "bot", "hostname": "bot.example", "channels": {
            "telegram": {"secrets": {"botToken": "123:abc"}, "settings": {}, "hint": "…abc", "label": "@bot", "updatedAt": "2026-09-01T00:00:00.000Z"}
        }, "approvedSenders": [{"type": "telegram", "id": "8734", "label": "Marco", "at": "x"}, {"type": "slack", "id": "U1", "label": null, "at": "y"}]}}});
        let s = coerce(Some(v1)).expect("v1");
        let c = &s.connections["legacy:vm1:telegram"];
        assert_eq!(c.assigned_vm_id.as_deref(), Some("vm1"));
        assert_eq!(c.secrets["botToken"], json!("123:abc"));
        assert_eq!(c.approved_senders.len(), 1);
        assert_eq!(s.agents["vm1"].hostname.as_deref(), Some("bot.example"));
        assert_eq!(
            coerce(Some(json!({"version": 3}))).expect("other"),
            ChannelStore::default()
        );
        assert!(
            coerce(Some(
                json!({"version": 2, "connections": {"c": {"type": 5}}, "agents": {}})
            ))
            .is_err()
        );
    }
}
