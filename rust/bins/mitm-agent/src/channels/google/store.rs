//! The firewall's Google account store (`google-store.ts`, docs/plans/google-account.md §7, §8):
//! the organization's own Google identity, and which agents were given it. Enc-file under the box
//! key, AAD `<org>:<box>:google`. The refresh token, the client secret and the access token never
//! leave this box; agents hold a placeholder the proxy swaps on `*.googleapis.com`.

use std::path::Path;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The one host pattern the placeholder is swapped on.
pub const GOOGLE_MATCH_DOMAIN: &str = "*.googleapis.com";
/// How long an unfinished authorization stays spendable.
pub const PENDING_AUTH_TTL_MS: i64 = 15 * 60_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub token_endpoint: String,
    pub redirect_uri: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessToken {
    pub token: String,
    pub expires: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account_label: Option<String>,
    pub services: Vec<String>,
    pub scopes: Vec<String>,
    pub gmail_scope: String,
    pub drive_scope: String,
    pub audience: String,
    #[serde(default)]
    pub project_id: Option<String>,
    pub oauth: OAuthClient,
    pub refresh: String,
    pub access: Option<AccessToken>,
    pub failed: Option<String>,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Agent {
    pub name: String,
    pub hostname: Option<String>,
    pub placeholder: String,
    pub granted: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An authorization this firewall started and is waiting for a callback on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub change_id: String,
    pub state: String,
    pub verifier: String,
    pub services: Vec<String>,
    pub gmail_scope: String,
    pub drive_scope: String,
    pub audience: String,
    pub project_id: Option<String>,
    pub oauth: OAuthClient,
    pub expires: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleStore {
    pub version: u32,
    pub accounts: IndexMap<String, Account>,
    pub agents: IndexMap<String, Agent>,
    #[serde(default)]
    pub pending: Option<Pending>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for GoogleStore {
    fn default() -> Self {
        Self {
            version: 1,
            accounts: IndexMap::new(),
            agents: IndexMap::new(),
            pending: None,
            extra: Map::new(),
        }
    }
}

pub fn is_google_audience(v: &str) -> bool {
    matches!(v, "internal" | "external_production" | "external_testing")
}

static PROJECT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$").expect("regex"));
static CLIENT_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+(-[A-Za-z0-9_]+)?\.apps\.googleusercontent\.com$").expect("regex"));

pub fn is_valid_project_id(id: &str) -> bool {
    PROJECT_ID.is_match(id)
}
pub fn is_valid_client_id(id: &str) -> bool {
    CLIENT_ID.is_match(id)
}

fn aad(org_id: &str, box_id: &str) -> String {
    format!("{org_id}:{box_id}:google")
}

/// A store of another version, or without `accounts` or `agents`, starts empty, as the TS does. One
/// whose rows do not read field for field is `Err` and is not written over.
pub fn load(path: &Path, box_key: &str, org_id: &str, box_id: &str) -> Result<GoogleStore, String> {
    let log = |l: &str| tracing::info!("{l}");
    let Some(v) = cc_crypto::enc_file::load_store_or_empty("google", path, box_key, &aad(org_id, box_id), &log) else {
        return Ok(GoogleStore::default());
    };
    let usable = v.get("version").and_then(Value::as_u64) == Some(1)
        && v.get("accounts").is_some_and(Value::is_object)
        && v.get("agents").is_some_and(Value::is_object);
    if !usable {
        return Ok(GoogleStore::default());
    }
    let store: GoogleStore = serde_json::from_value(v)
        .map_err(|e| format!("{:?} error at line {} column {}", e.classify(), e.line(), e.column()))?;
    for a in store.accounts.values() {
        for secret in [&a.refresh, &a.oauth.client_secret] {
            cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(secret.clone()), true);
        }
        if let Some(t) = &a.access {
            cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(t.token.clone()), true);
        }
    }
    if let Some(p) = &store.pending {
        cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(p.oauth.client_secret.clone()), true);
    }
    Ok(store)
}

pub fn save(path: &Path, store: &GoogleStore, box_key: &str, org_id: &str, box_id: &str) -> Result<(), String> {
    let v = serde_json::to_value(store).map_err(|e| e.to_string())?;
    cc_crypto::enc_file::save_store("google", path, &v, box_key, &aad(org_id, box_id)).map_err(|e| e.0)
}
