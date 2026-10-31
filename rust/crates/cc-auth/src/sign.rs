//! Tokens a box signs: to the console (`{vmId}`, 30 s) and, on the firewall, to its agents
//! (`{...binding, vmId, purpose, iss}`, 30 s, one request each). Key files are read on every call,
//! as the TS does, so a keypair made after start is picked up.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jwt::{self, JwtError, SignKey};
use crate::keys::KeysDir;

/// Every box token lives 30 s.
pub const BOX_TOKEN_LIFETIME_S: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("missing vm_id / vm_private_key.pem in KEYS_DIR")]
    MissingKeys,
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

fn key(keys: &KeysDir) -> Result<SignKey, SignError> {
    let pem = keys.read("vm_private_key.pem").ok_or(SignError::MissingKeys)?;
    Ok(SignKey::ed25519_pkcs8_pem(&pem)?)
}

/// `makeBoxTokenSigner`: `{vmId}` signed with `vm_private_key.pem`.
pub fn box_token(keys: &KeysDir) -> Result<String, SignError> {
    let vm_id = keys.vm_id().ok_or(SignError::MissingKeys)?;
    let mut c = Map::new();
    c.insert("vmId".into(), Value::String(vm_id));
    Ok(jwt::sign(c, &key(keys)?, Some(BOX_TOKEN_LIFETIME_S), None)?)
}

/// `makeGateTokenSigner`: the caller's claims, then this box's `vmId`.
pub fn gate_token(keys: &KeysDir, mut claims: Map<String, Value>) -> Result<String, SignError> {
    let vm_id = keys.vm_id().ok_or(SignError::MissingKeys)?;
    claims.insert("vmId".into(), Value::String(vm_id));
    Ok(jwt::sign(claims, &key(keys)?, Some(BOX_TOKEN_LIFETIME_S), None)?)
}

/// `bindingClaims` in `packages/mitm-agent/src/agent-client.ts`: method, path without query,
/// lower-cased host when known, SHA-256 of the body as sent, and a fresh id.
pub fn binding_claims(method: &str, path: &str, hostname: Option<&str>, body: Option<&[u8]>) -> Map<String, Value> {
    let mut c = Map::new();
    c.insert("m".into(), Value::String(method.to_string()));
    c.insert(
        "p".into(),
        Value::String(path.split('?').next().unwrap_or_default().to_string()),
    );
    if let Some(h) = hostname.filter(|h| !h.is_empty()) {
        c.insert("h".into(), Value::String(h.to_lowercase()));
    }
    if let Some(b) = body {
        c.insert("b".into(), Value::String(hex::encode(Sha256::digest(b))));
    }
    c.insert("jti".into(), Value::String(uuid::Uuid::new_v4().to_string()));
    c
}

/// `makeAgentTokenSigner`: `{...claims, vmId: agent, purpose, iss: boxId}` with this firewall's key.
pub fn agent_token(
    keys: &KeysDir,
    box_id: &str,
    agent_vm_id: &str,
    purpose: &str,
    mut claims: Map<String, Value>,
) -> Result<String, SignError> {
    claims.insert("vmId".into(), Value::String(agent_vm_id.to_string()));
    claims.insert("purpose".into(), Value::String(purpose.to_string()));
    claims.insert("iss".into(), Value::String(box_id.to_string()));
    Ok(jwt::sign(claims, &key(keys)?, Some(BOX_TOKEN_LIFETIME_S), None)?)
}
