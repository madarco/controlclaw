//! The two-payload record the console holds for a firewall, port of `packages/secret-store`.
//!
//! The same plaintext is sealed twice: under the random box key, and under a key derived from the
//! user's master password with Argon2id. AAD `"<org_id>:<box_id>:<version>"` binds each ciphertext
//! to its box and version, so the console cannot move a blob between boxes or roll it back unseen.

use crate::{CryptoError, Result, b64};
use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const ALG: &str = "AES-256-GCM";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const SALT_BYTES: usize = 16;
const TAG_BYTES: usize = 16;

/// Argon2id parameters, the same as `hash-wasm` is given: 64 MiB, 3 passes, 1 lane, version 0x13.
const ARGON2_M_KIB: u32 = 65_536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ids {
    pub org_id: String,
    pub box_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// base64
    pub nonce: String,
    /// base64 of ciphertext || GCM tag
    pub ct: String,
}

/// One stored record: exactly what ControlClaw holds, ciphertext only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreRecord {
    pub alg: String,
    pub version: u64,
    /// base64 Argon2id salt for `payload_user`
    pub salt: String,
    pub payload_box: Payload,
    pub payload_user: Payload,
    /// Fields a newer build may add, kept so a record round-trips unchanged.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// A random 32-byte box key, base64. Made on the box; never sent to ControlClaw.
pub fn generate_box_key() -> String {
    b64::encode(random::<KEY_BYTES>())
}

pub fn generate_salt() -> String {
    b64::encode(random::<SALT_BYTES>())
}

/// The 32-byte key from the master password and the record's salt.
pub fn derive_user_key(master_password: &str, salt_b64: &str) -> Result<[u8; KEY_BYTES]> {
    let salt = b64::decode(salt_b64)?;
    let params =
        Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_BYTES)).map_err(|e| CryptoError::new(e.to_string()))?;
    let mut out = [0u8; KEY_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(master_password.as_bytes(), &salt, &mut out)
        .map_err(|e| CryptoError::new(e.to_string()))?;
    Ok(out)
}

fn aad(ids: &Ids, version: u64) -> String {
    format!("{}:{}:{}", ids.org_id, ids.box_id, version)
}

fn encrypt(plaintext: &[u8], key: &[u8], ad: &str) -> Result<Payload> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::new("Invalid key length"))?;
    let nonce = random::<NONCE_BYTES>();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            AeadPayload {
                msg: plaintext,
                aad: ad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::new(crate::enc_file::AUTH_FAILED))?;
    Ok(Payload {
        nonce: b64::encode(nonce),
        ct: b64::encode(ct),
    })
}

fn decrypt(payload: &Payload, key: &[u8], ad: &str) -> Result<String> {
    let failed = || CryptoError::new(crate::enc_file::AUTH_FAILED);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::new("Invalid key length"))?;
    let nonce = b64::decode(&payload.nonce)?;
    let ct = b64::decode(&payload.ct)?;
    if nonce.len() != NONCE_BYTES || ct.len() < TAG_BYTES {
        return Err(failed());
    }
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            AeadPayload {
                msg: &ct,
                aad: ad.as_bytes(),
            },
        )
        .map_err(|_| failed())?;
    String::from_utf8(pt).map_err(|_| failed())
}

pub struct SealOpts<'a> {
    /// base64
    pub box_key: &'a str,
    pub master_password: &'a str,
    pub ids: &'a Ids,
    pub version: u64,
    /// Reuse an existing salt (migration keeps the same password salt).
    pub salt: Option<&'a str>,
}

/// Seal a plaintext into a record (both payloads).
pub fn seal(plaintext: &str, opts: &SealOpts) -> Result<StoreRecord> {
    let salt = opts.salt.map(str::to_string).unwrap_or_else(generate_salt);
    let ad = aad(opts.ids, opts.version);
    let user_key = derive_user_key(opts.master_password, &salt)?;
    Ok(StoreRecord {
        alg: ALG.into(),
        version: opts.version,
        payload_box: encrypt(plaintext.as_bytes(), &b64::decode(opts.box_key)?, &ad)?,
        payload_user: encrypt(plaintext.as_bytes(), &user_key, &ad)?,
        salt,
        extra: serde_json::Map::new(),
    })
}

pub fn open_with_box_key(record: &StoreRecord, box_key: &str, ids: &Ids) -> Result<String> {
    decrypt(&record.payload_box, &b64::decode(box_key)?, &aad(ids, record.version))
}

pub fn open_with_user_key(record: &StoreRecord, master_password: &str, ids: &Ids) -> Result<String> {
    let key = derive_user_key(master_password, &record.salt)?;
    decrypt(&record.payload_user, &key, &aad(ids, record.version))
}

pub struct MigrateResult {
    pub record: StoreRecord,
    /// The NEW box key: keep it on the new box's encrypted disk, never send it.
    pub box_key: String,
}

/// Copy a set to a new box: open `payload_user` with the master password, make a fresh box key,
/// seal again for the new box id with the next version and the same salt.
pub fn migrate_to_new_box(
    source: &StoreRecord,
    master_password: &str,
    source_ids: &Ids,
    new_box_id: &str,
) -> Result<MigrateResult> {
    let plaintext = open_with_user_key(source, master_password, source_ids)?;
    let box_key = generate_box_key();
    let ids = Ids {
        org_id: source_ids.org_id.clone(),
        box_id: new_box_id.into(),
    };
    let record = seal(
        &plaintext,
        &SealOpts {
            box_key: &box_key,
            master_password,
            ids: &ids,
            version: source.version + 1,
            salt: Some(&source.salt),
        },
    )?;
    Ok(MigrateResult { record, box_key })
}

/// Load the box key, or make and keep one on first boot (`box-key.ts`). On a real box the path is
/// on the encrypted disk.
pub fn load_or_create_box_key(path: &Path, log: &dyn Fn(&str)) -> std::io::Result<String> {
    if path.exists() {
        return Ok(fs::read_to_string(path)?.trim().to_string());
    }
    let key = generate_box_key();
    cc_store::write_file(path, key.as_bytes(), 0o600)?;
    log(&format!("[box-key] generated new box key at {}", path.display()));
    Ok(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ids() -> Ids {
        Ids {
            org_id: "org_1".into(),
            box_id: "box_1".into(),
        }
    }

    // Port of packages/secret-store/src/crypto.test.ts.
    #[test]
    fn both_payloads_open_and_bind_ids_and_version() {
        let box_key = generate_box_key();
        let rec = seal(
            r#"{"A":"1"}"#,
            &SealOpts {
                box_key: &box_key,
                master_password: "pw",
                ids: &ids(),
                version: 1,
                salt: None,
            },
        )
        .expect("seal");
        assert_eq!(open_with_box_key(&rec, &box_key, &ids()).expect("box"), r#"{"A":"1"}"#);
        assert_eq!(open_with_user_key(&rec, "pw", &ids()).expect("user"), r#"{"A":"1"}"#);
        assert!(open_with_user_key(&rec, "wrong", &ids()).is_err());
        assert!(open_with_box_key(&rec, &generate_box_key(), &ids()).is_err());
        let moved = Ids {
            org_id: "org_1".into(),
            box_id: "box_2".into(),
        };
        assert!(open_with_box_key(&rec, &box_key, &moved).is_err());
        let mut rolled = rec.clone();
        rolled.version = 2;
        assert!(open_with_box_key(&rolled, &box_key, &ids()).is_err());
        assert_ne!(rec.payload_box.ct, rec.payload_user.ct);
    }

    #[test]
    fn migration_keeps_the_salt_and_bumps_the_version() {
        let box_key = generate_box_key();
        let rec = seal(
            "plain",
            &SealOpts {
                box_key: &box_key,
                master_password: "pw",
                ids: &ids(),
                version: 4,
                salt: None,
            },
        )
        .expect("seal");
        let m = migrate_to_new_box(&rec, "pw", &ids(), "box_9").expect("migrate");
        let new_ids = Ids {
            org_id: "org_1".into(),
            box_id: "box_9".into(),
        };
        assert_eq!(m.record.version, 5);
        assert_eq!(m.record.salt, rec.salt);
        assert_eq!(
            open_with_box_key(&m.record, &m.box_key, &new_ids).expect("box"),
            "plain"
        );
        assert_ne!(m.box_key, box_key);
        assert!(migrate_to_new_box(&rec, "nope", &ids(), "box_9").is_err());
    }

    #[test]
    fn record_round_trips_unknown_fields() {
        let raw = r#"{"alg":"AES-256-GCM","version":1,"salt":"c2FsdHNhbHRzYWx0c2FsdA==","payload_box":{"nonce":"a","ct":"b"},"payload_user":{"nonce":"c","ct":"d"},"future":7}"#;
        let rec: StoreRecord = serde_json::from_str(raw).expect("parse");
        assert_eq!(serde_json::to_string(&rec).expect("ser"), raw);
    }

    #[test]
    fn box_key_is_made_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("keys/box_key");
        let a = load_or_create_box_key(&p, &|_| {}).expect("create");
        assert_eq!(b64::decode(&a).expect("b64").len(), 32);
        assert_eq!(load_or_create_box_key(&p, &|_| {}).expect("load"), a);
    }

    #[test]
    fn tamper_is_detected() {
        let box_key = generate_box_key();
        let mut rec = seal(
            "plain",
            &SealOpts {
                box_key: &box_key,
                master_password: "pw",
                ids: &ids(),
                version: 1,
                salt: None,
            },
        )
        .expect("seal");
        let mut ct = b64::decode(&rec.payload_box.ct).expect("b64");
        ct[0] ^= 0xff;
        rec.payload_box.ct = b64::encode(ct);
        assert!(open_with_box_key(&rec, &box_key, &ids()).is_err());
    }

    #[test]
    fn the_record_leaks_no_plaintext_or_keys() {
        let box_key = generate_box_key();
        let plain = r#"{"credentials":[{"match_domain":"github.com","secret":"ghp_REALSECRET_xyz"}]}"#;
        let pw = "correct horse battery staple";
        let rec = seal(
            plain,
            &SealOpts {
                box_key: &box_key,
                master_password: pw,
                ids: &ids(),
                version: 1,
                salt: None,
            },
        )
        .expect("seal");
        let s = serde_json::to_string(&rec).expect("ser");
        for leak in ["ghp_REALSECRET_xyz", "github.com", box_key.as_str(), pw] {
            assert!(!s.contains(leak), "{leak}");
        }
    }
}
