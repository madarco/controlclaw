//! The firewall's browser store (`access-store.ts`): which browsers may open the organization's
//! agents, and the hostname each agent was first seen at. Encrypted under the box key (`access.enc`,
//! AAD `<org>:<box>:access`). A device is kept by the SHA-256 of its cookie, never the cookie. A pin
//! is written once and never moved. Fields this build does not know are kept.

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredDevice {
    /// sha256(cookie value), hex.
    pub hash: String,
    #[serde(rename = "userId", default, deserialize_with = "text")]
    pub user_id: String,
    pub email: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub label: String,
    /// `code` or `tofu`.
    #[serde(default, deserialize_with = "text")]
    pub via: String,
    #[serde(rename = "createdAt", default, deserialize_with = "text")]
    pub created_at: String,
    #[serde(rename = "lastUsedAt", default, deserialize_with = "text")]
    pub last_used_at: String,
    /// Absent, `null`, or when the device was listed to the owner. A `null` is kept as one (the TS
    /// writes it for every new device), so a store the Rust build saved reads back the same.
    #[serde(
        rename = "listedAt",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub listed_at: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A string, or empty for `null`: what the TS reads such a field as.
fn text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Option::<String>::deserialize(d).map(Option::unwrap_or_default)
}

/// Any value that is there, `null` included, as `Some`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentPin {
    pub hostname: String,
    #[serde(rename = "accessHostname", default, skip_serializing_if = "Option::is_none")]
    pub access_hostname: Option<String>,
    #[serde(default, deserialize_with = "text")]
    pub at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessStore {
    pub version: u32,
    /// Keyed by device id, in the order they came.
    pub devices: IndexMap<String, StoredDevice>,
    /// Keyed by vm id.
    pub pins: IndexMap<String, AgentPin>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for AccessStore {
    fn default() -> Self {
        Self {
            version: 1,
            devices: IndexMap::new(),
            pins: IndexMap::new(),
            extra: Map::new(),
        }
    }
}

pub struct AccessStoreFile {
    pub path: PathBuf,
    pub box_key: String,
    pub aad: String,
}

impl AccessStoreFile {
    pub fn new(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> Self {
        Self {
            path: path.to_path_buf(),
            box_key: box_key.to_string(),
            aad: format!("{org_id}:{box_id}:access"),
        }
    }

    /// `loadAccessStore`: empty for a missing or unreadable file, or another version.
    pub fn load(&self) -> AccessStore {
        let log = |l: &str| tracing::error!("{l}");
        let Some(mut raw) =
            cc_crypto::enc_file::load_store_or_empty("access", &self.path, &self.box_key, &self.aad, &log)
        else {
            return AccessStore::default();
        };
        let Some(o) = raw.as_object_mut() else {
            return AccessStore::default();
        };
        if o.get("version") != Some(&Value::from(1)) {
            return AccessStore::default();
        }
        for k in ["devices", "pins"] {
            if o.get(k).is_none_or(Value::is_null) {
                o.insert(k.into(), Value::Object(Map::new()));
            }
        }
        // Entry by entry: one device or pin this build cannot read is left out (and said), never
        // the whole store, which would sign every browser out and lose the write-once pins.
        let mut store = AccessStore::default();
        for (k, v) in std::mem::take(o) {
            match k.as_str() {
                "version" => {}
                "devices" | "pins" => {
                    for (id, entry) in v.as_object().cloned().unwrap_or_default() {
                        let ok = if k == "devices" {
                            serde_json::from_value(entry)
                                .map(|d| store.devices.insert(id.clone(), d))
                                .is_ok()
                        } else {
                            serde_json::from_value(entry)
                                .map(|p| store.pins.insert(id.clone(), p))
                                .is_ok()
                        };
                        if !ok {
                            tracing::error!("[access] {k} entry {id} could not be read; it is left out");
                        }
                    }
                }
                _ => {
                    store.extra.insert(k, v);
                }
            }
        }
        // A firewall on PR 5 enrolled browsers during its migration window as `migration`.
        for d in store.devices.values_mut() {
            if d.via == "migration" {
                d.via = "tofu".into();
            }
        }
        store
    }

    pub fn save(&self, store: &AccessStore) -> Result<(), String> {
        let value = serde_json::to_value(store).map_err(|e| e.to_string())?;
        cc_crypto::enc_file::save_store("access", &self.path, &value, &self.box_key, &self.aad).map_err(|e| e.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn a_migration_device_loads_as_tofu_and_unknown_fields_stay() {
        let d = tempfile::tempdir().expect("dir");
        let f = AccessStoreFile::new(&d.path().join("access.enc"), KEY, "org_1", "fw_1");
        assert_eq!(f.load(), AccessStore::default());
        let raw = json!({"version": 1, "devices": {"dev_1": {"hash": "h", "userId": "u", "email": null, "label": "Chrome on Mac", "via": "migration", "createdAt": "2026-01-01T00:00:00.000Z", "lastUsedAt": "2026-01-01T00:00:00.000Z", "future": 1}}, "pins": {"vm_1": {"hostname": "a.example", "at": "x"}}, "later": true});
        cc_crypto::enc_file::save_encrypted_json(&f.path, &raw, KEY, "org_1:fw_1:access").expect("seal");
        let s = f.load();
        assert_eq!(s.devices["dev_1"].via, "tofu");
        assert_eq!(s.devices["dev_1"].extra.get("future"), Some(&json!(1)));
        assert_eq!(s.extra.get("later"), Some(&json!(true)));
        f.save(&s).expect("save");
        let back = cc_crypto::enc_file::load_encrypted_json(&f.path, KEY, "org_1:fw_1:access")
            .expect("open")
            .expect("some");
        assert_eq!(back["devices"]["dev_1"]["future"], json!(1));
        assert_eq!(back["pins"]["vm_1"], json!({"hostname": "a.example", "at": "x"}));
        let wrong = json!({"version": 2, "devices": {}, "pins": {}});
        cc_crypto::enc_file::save_encrypted_json(&f.path, &wrong, KEY, "org_1:fw_1:access").expect("seal");
        assert_eq!(f.load(), AccessStore::default());
    }

    #[test]
    fn one_entry_this_build_cannot_read_leaves_the_rest() {
        let d = tempfile::tempdir().expect("dir");
        let f = AccessStoreFile::new(&d.path().join("access.enc"), KEY, "org_1", "fw_1");
        // dev_1 has no hash (unusable); dev_2 lacks lastUsedAt and has a null label, as a TS store may.
        let raw = json!({"version": 1, "devices": {"dev_1": {"userId": "u"}, "dev_2": {"hash": "h2", "userId": "u", "email": null, "label": null, "via": "code", "createdAt": "x"}}, "pins": {"vm_1": {"hostname": "a.example"}, "vm_2": {"at": "x"}}});
        cc_crypto::enc_file::save_encrypted_json(&f.path, &raw, KEY, "org_1:fw_1:access").expect("seal");
        let s = f.load();
        assert_eq!(s.devices.keys().collect::<Vec<_>>(), vec!["dev_2"]);
        assert_eq!(s.pins.keys().collect::<Vec<_>>(), vec!["vm_1"]);
    }
}
