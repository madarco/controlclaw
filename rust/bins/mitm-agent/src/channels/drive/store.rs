//! The firewall's Drive store (`drive-store.ts`, docs/plans/drive-folders.md): the organization's
//! Google identity, the folders it chose, and which agent mounts which. Enc-file under the box key,
//! AAD `<org>:<box>:drive`. A `google_account` connection holds no secret: it borrows the org
//! Google account's token.

use std::path::Path;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The writable Drive scope.
pub const DRIVE_WRITE_SCOPE: &str = "https://www.googleapis.com/auth/drive";
/// The read-only one, which is all a `readonly` Google grant can back.
pub const DRIVE_READ_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";

/// `{refresh}` for an OAuth app, or a service-account key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DriveSecret {
    ServiceAccount {
        #[serde(rename = "clientEmail")]
        client_email: String,
        /// PKCS#8 PEM, as it appears in the key JSON.
        #[serde(rename = "privateKey")]
        private_key: String,
        #[serde(rename = "tokenUri")]
        token_uri: String,
        subject: Option<String>,
    },
    OAuth {
        refresh: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveOAuth {
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub expires: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveAccount {
    /// `oauth`, `service_account` or `google_account`.
    pub kind: String,
    pub account_label: Option<String>,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<DriveOAuth>,
    pub secret: Option<DriveSecret>,
    pub access: Option<AccessToken>,
    pub failed: Option<String>,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveFolder {
    pub account_id: String,
    pub folder_id: String,
    pub name: String,
    /// `ro` or `rw`.
    pub mode: String,
    pub agents: Vec<String>,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriveAgent {
    pub name: String,
    pub hostname: Option<String>,
    pub placeholder: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveStore {
    pub version: u32,
    pub accounts: IndexMap<String, DriveAccount>,
    pub folders: IndexMap<String, DriveFolder>,
    pub agents: IndexMap<String, DriveAgent>,
    /// The borrowed Google account as it was when the mount sets were last pushed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrowed_stamp: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for DriveStore {
    fn default() -> Self {
        Self {
            version: 1,
            accounts: IndexMap::new(),
            folders: IndexMap::new(),
            agents: IndexMap::new(),
            borrowed_stamp: None,
            extra: Map::new(),
        }
    }
}

static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$").expect("regex"));
static FOLDER_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{10,200}$").expect("regex"));

/// A folder name becomes a directory name on the agent box.
pub fn is_valid_folder_name(name: &str) -> bool {
    NAME.is_match(name) && !name.ends_with(' ')
}

pub fn is_valid_folder_id(id: &str) -> bool {
    FOLDER_ID.is_match(id)
}

fn aad(org_id: &str, box_id: &str) -> String {
    format!("{org_id}:{box_id}:drive")
}

/// Another version, or one missing a map, starts empty as in the TS. Rows that do not read field
/// for field are `Err`, and the store is not written over.
pub fn load(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> Result<DriveStore, String> {
    let log = |l: &str| tracing::info!("{l}");
    let Some(v) = cc_crypto::enc_file::load_store_or_empty("drive", path, box_key, &aad(org_id, box_id), &log) else {
        return Ok(DriveStore::default());
    };
    let usable = v.get("version").and_then(Value::as_u64) == Some(1)
        && ["accounts", "folders", "agents"]
            .iter()
            .all(|k| v.get(*k).is_some_and(Value::is_object));
    if !usable {
        return Ok(DriveStore::default());
    }
    let store: DriveStore = serde_json::from_value(v)
        .map_err(|e| format!("{:?} error at line {} column {}", e.classify(), e.line(), e.column()))?;
    for a in store.accounts.values() {
        match &a.secret {
            Some(DriveSecret::OAuth { refresh }) => {
                cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(refresh.clone()), true)
            }
            Some(DriveSecret::ServiceAccount { private_key, .. }) => {
                cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(private_key.clone()), true)
            }
            None => {}
        }
        if let Some(o) = &a.oauth {
            cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(o.client_secret.clone()), true);
        }
        if let Some(t) = &a.access {
            cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(t.token.clone()), true);
        }
    }
    Ok(store)
}

pub fn save(path: &Path, store: &DriveStore, box_key: &str, org_id: &str, box_id: &str) -> Result<(), String> {
    let v = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store("drive", path, &v, box_key, &aad(org_id, box_id)).map_err(|e| e.0)
}
