//! The firewall's small encrypted JSON stores, port of `packages/mitm-agent/src/enc-file.ts`.
//!
//! AES-256-GCM under the box key, AAD-bound to a caller-chosen string (`"<org>:<box>:<purpose>"`),
//! stored as `{"alg":"AES-256-GCM","nonce":<b64>,"ct":<b64 ciphertext || tag>}`, 0600, written
//! atomically. The plaintext is the value as `JSON.stringify` writes it.

use crate::{CryptoError, Result, b64, store_health};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Node's text for a GCM failure. The heartbeat carries it to the console, so it is kept as is.
pub const AUTH_FAILED: &str = "Unsupported state or unable to authenticate data";

// ---- the secrets Doctor output is redacted against ----

/// Values seen inside encrypted stores, kept before and after rotation: a CLI can print an earlier
/// token from its conversation. Insertion order, like the TS `Set`.
struct Known {
    order: Vec<String>,
    seen: HashSet<String>,
}

static KNOWN: LazyLock<Mutex<Known>> = LazyLock::new(|| {
    Mutex::new(Known {
        order: Vec::new(),
        seen: HashSet::new(),
    })
});

// JavaScript's `.` stops at line terminators; `$` is end of input in both.
static SECRET_LEAF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:secret|password|token|private[^\n\r\u{2028}\u{2029}]?key|api[^\n\r\u{2028}\u{2029}]?key|cookie|verifier|salt)$|^(?:refresh|access|key)$")
        .expect("valid regex")
});
static LINE_SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n").expect("valid regex"));

fn add_known(known: &mut Known, s: &str) {
    if known.seen.insert(s.to_string()) {
        known.order.push(s.to_string());
    }
}

/// Collect every secret-looking leaf of `value`. Strings count only when `sensitive` (a field whose
/// name says secret, or anything under a `secrets` map); each line of a multi-line value counts too.
pub fn remember_encrypted_secrets(value: &Value, sensitive: bool) {
    let mut known = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
    remember(&mut known, value, sensitive);
}

fn remember(known: &mut Known, value: &Value, sensitive: bool) {
    match value {
        Value::String(s) => {
            if sensitive && !s.is_empty() {
                add_known(known, s);
                for line in LINE_SPLIT.split(s) {
                    if !line.is_empty() {
                        add_known(known, line);
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                remember(known, item, sensitive);
            }
        }
        Value::Object(map) => {
            for (name, item) in map {
                // Containers such as credentials/secret/oauth also hold labels and model ids. Only
                // explicit secret maps pass sensitivity on to arbitrary field names.
                let secret_map = name == "secrets";
                let secret_leaf = item.is_string() && SECRET_LEAF.is_match(name);
                remember(known, item, sensitive || secret_map || secret_leaf);
            }
        }
        _ => {}
    }
}

pub fn encrypted_secret_values() -> Vec<String> {
    KNOWN.lock().unwrap_or_else(|e| e.into_inner()).order.clone()
}

// ---- seal and open ----

fn cipher(box_key_b64: &str) -> Result<Aes256Gcm> {
    let key = b64::decode(box_key_b64)?;
    Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::new("Invalid key length"))
}

/// Seal `value` under the box key. Same layout and key order as the TS `encryptJson`.
pub fn encrypt_json(value: &Value, box_key_b64: &str, aad: &str) -> Result<String> {
    remember_encrypted_secrets(value, false);
    let cipher = cipher(box_key_b64)?;
    let mut nonce = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let plaintext = serde_json::to_vec(value).map_err(|e| CryptoError::new(e.to_string()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::new(AUTH_FAILED))?;
    // Built by hand so the key order is fixed whatever serde_json's map features are.
    Ok(format!(
        r#"{{"alg":"AES-256-GCM","nonce":"{}","ct":"{}"}}"#,
        b64::encode(nonce),
        b64::encode(ct)
    ))
}

/// Open what `encrypt_json` (or the TS) sealed. Errors on a wrong key, a wrong AAD or a tampered file.
pub fn decrypt_json(raw: &str, box_key_b64: &str, aad: &str) -> Result<Value> {
    let outer: Value = serde_json::from_str(raw).map_err(|e| CryptoError::new(e.to_string()))?;
    let field = |name: &str| outer.get(name).and_then(Value::as_str).map(str::to_string);
    let (Some(nonce), Some(ct)) = (field("nonce"), field("ct")) else {
        return Err(CryptoError::new("The encrypted file has no nonce or ciphertext"));
    };
    let nonce = b64::decode(&nonce)?;
    let ct = b64::decode(&ct)?;
    if nonce.len() != NONCE_BYTES || ct.len() < TAG_BYTES {
        return Err(CryptoError::new(AUTH_FAILED));
    }
    let cipher = cipher(box_key_b64)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::new(AUTH_FAILED))?;
    let value: Value = serde_json::from_slice(&plaintext).map_err(|e| CryptoError::new(e.to_string()))?;
    remember_encrypted_secrets(&value, false);
    Ok(value)
}

/// `None` when the file does not exist. Errors on a wrong key or a tampered file.
pub fn load_encrypted_json(path: &Path, box_key_b64: &str, aad: &str) -> Result<Option<Value>> {
    match fs::read_to_string(path) {
        Ok(raw) => decrypt_json(&raw, box_key_b64, aad).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CryptoError::new(e.to_string())),
    }
}

/// Seal and write `<path>.tmp` (mode 0600), then rename it over `path`.
pub fn save_encrypted_json(path: &Path, value: &Value, box_key_b64: &str, aad: &str) -> Result<()> {
    let sealed = encrypt_json(value, box_key_b64, aad)?;
    cc_store::write_atomic(path, sealed.as_bytes(), 0o600, cc_store::TmpName::Suffix)
        .map_err(|e| CryptoError::new(e.to_string()))
}

/// Load a store, or start empty when this box cannot read it (T-53).
///
/// The ciphertext is copied to `<path>.unreadable` once before anything can overwrite it, and the
/// failure is noted in [`store_health`] so the heartbeat says so. `None` for a missing or unreadable
/// file; every caller turns that into its own empty value.
pub fn load_store_or_empty(
    store: &str,
    path: &Path,
    box_key_b64: &str,
    aad: &str,
    log: &dyn Fn(&str),
) -> Option<Value> {
    match load_encrypted_json(path, box_key_b64, aad) {
        Ok(parsed) => {
            store_health::note_store_readable(store);
            parsed
        }
        Err(error) => {
            store_health::note_store_unreadable(store, &error.0);
            log(&format!(
                "[{store}] this firewall cannot read {} ({}); starting empty. The console says so, and the next change reseals it.",
                path.display(),
                error.0
            ));
            keep_unreadable(path, store, log);
            None
        }
    }
}

/// Copied rather than moved, and written once: a box whose key was wrong for a moment reads the
/// original again on the next start.
fn keep_unreadable(path: &Path, store: &str, log: &dyn Fn(&str)) {
    let kept = suffixed(path, ".unreadable");
    if !path.exists() || kept.exists() {
        return;
    }
    match fs::copy(path, &kept) {
        Ok(_) => log(&format!("[{store}] kept the unreadable file as {}", kept.display())),
        Err(e) => log(&format!("[{store}] could not keep a copy of {}: {e}", path.display())),
    }
}

/// Save a store and record that this box can read it again: what was just sealed will open.
pub fn save_store(store: &str, path: &Path, value: &Value, box_key_b64: &str, aad: &str) -> Result<()> {
    save_encrypted_json(path, value, box_key_b64, aad)?;
    store_health::note_store_readable(store);
    Ok(())
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn round_trips_and_binds_the_aad() {
        let v = json!({"b": 1, "a": ["x", {"z": null}], "é": "ü"});
        let sealed = encrypt_json(&v, KEY, "org:box:llm").expect("seal");
        assert!(sealed.starts_with(r#"{"alg":"AES-256-GCM","nonce":""#));
        assert_eq!(decrypt_json(&sealed, KEY, "org:box:llm").expect("open"), v);
        assert_eq!(decrypt_json(&sealed, KEY, "org:box:other").unwrap_err().0, AUTH_FAILED);
    }

    #[test]
    fn unreadable_store_starts_empty_and_keeps_the_bytes_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("llm.enc");
        save_store("t-llm", &path, &json!({"k": 1}), KEY, "a").expect("save");
        let other = "HwECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let lines = std::cell::RefCell::new(Vec::new());
        let log = |l: &str| lines.borrow_mut().push(l.to_string());
        assert_eq!(load_store_or_empty("t-llm", &path, other, "a", &log), None);
        assert!(store_health::is_store_unreadable("t-llm"));
        let kept = dir.path().join("llm.enc.unreadable");
        assert_eq!(fs::read(&kept).expect("kept"), fs::read(&path).expect("orig"));
        fs::write(&kept, "first copy").expect("write");
        load_store_or_empty("t-llm", &path, other, "a", &log);
        assert_eq!(fs::read_to_string(&kept).expect("kept"), "first copy");
        assert_eq!(
            load_store_or_empty("t-llm", &path, KEY, "a", &log),
            Some(json!({"k": 1}))
        );
        assert!(!store_health::is_store_unreadable("t-llm"));
        assert!(lines.borrow()[0].contains(AUTH_FAILED));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).expect("meta").permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn missing_store_is_none_and_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            load_store_or_empty("t-missing", &dir.path().join("x.enc"), KEY, "a", &|_| {}),
            None
        );
        assert!(!store_health::is_store_unreadable("t-missing"));
    }

    #[test]
    fn remembers_secret_leaves_like_the_ts() {
        let v = json!({
            "label": "not-a-secret-label",
            "apiKey": "sk-remember-me",
            "nested": {"refresh": "rt-one\nrt-two", "count": 3, "model": "gpt-x"},
            "secrets": {"ANYTHING": "anything-under-secrets"},
            "list": [{"password": "pw-in-list"}]
        });
        remember_encrypted_secrets(&v, false);
        let known = encrypted_secret_values();
        for s in [
            "sk-remember-me",
            "rt-one\nrt-two",
            "rt-one",
            "rt-two",
            "anything-under-secrets",
            "pw-in-list",
        ] {
            assert!(known.contains(&s.to_string()), "{s}");
        }
        assert!(!known.contains(&"not-a-secret-label".to_string()));
        assert!(!known.contains(&"gpt-x".to_string()));
    }
}
