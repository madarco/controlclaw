//! The stores `check` opens, and how.

use std::path::Path;

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Agent,
    Firewall,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // EncFile and Json until W3-W8 list their stores
pub enum Format {
    /// An enc-file store under the box key, AAD `<org>:<box>:<purpose>`.
    EncFile { purpose: &'static str },
    /// Plain JSON.
    Json,
    /// A whole number, as text (the firewall-token floor).
    Integer,
    /// This many bytes, as hex text (the session secret).
    Hex(usize),
    /// This many bytes, as base64 text (the box key).
    Base64(usize),
}

pub struct Store {
    pub role: Role,
    /// The store's name, as the TS calls it in `store-health.ts`.
    pub name: &'static str,
    /// Absolute on the box; the command line's `--root` is put in front (a test's folder).
    pub path: &'static str,
    /// The environment variable the agent's unit names this store with (`EXIT_STORE_PATH`), when
    /// it has one: set, it wins over `path`, so the check opens what the agent will read. Ansible
    /// passes the unit's values.
    pub env: Option<&'static str>,
    pub format: Format,
}

/// Whether the store opened: `Ok(true)` read, `Ok(false)` not on this box, `Err` why not.
/// `env` reads an environment variable (`std::env::var` on a box; a map in a test).
pub fn check_one(
    s: &Store,
    root: &Path,
    key: Option<&str>,
    ids: (&str, &str),
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<bool, String> {
    let box_path = s
        .env
        .and_then(env)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| s.path.to_string());
    let path = root.join(box_path.trim_start_matches('/'));
    if !path.exists() {
        return Ok(false);
    }
    match s.format {
        Format::Json => {
            let raw = std::fs::read(&path).map_err(|e| e.to_string())?;
            serde_json::from_slice::<Value>(&raw).map_err(|e| e.to_string())?;
        }
        Format::Integer => {
            let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            raw.trim()
                .parse::<i64>()
                .map_err(|e| format!("not a whole number: {e}"))?;
        }
        Format::Hex(n) => {
            let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let b = hex::decode(raw.trim()).map_err(|e| format!("not hex: {e}"))?;
            if b.len() != n {
                return Err(format!("{} bytes, not {n}", b.len()));
            }
        }
        Format::Base64(n) => {
            let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let b = cc_crypto::b64::decode(raw.trim()).map_err(|e| e.to_string())?;
            if b.len() != n {
                return Err(format!("{} bytes, not {n}", b.len()));
            }
        }
        Format::EncFile { purpose } => {
            let key = key.ok_or("no box key")?;
            let aad = format!("{}:{}:{purpose}", ids.0, ids.1);
            cc_crypto::enc_file::load_encrypted_json(&path, key, &aad).map_err(|e| e.to_string())?;
        }
    }
    Ok(true)
}
