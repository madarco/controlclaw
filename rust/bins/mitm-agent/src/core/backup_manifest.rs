//! The manifest of a backup (`packages/backup-envelope/src/manifest.ts`) and the files a firewall
//! backup carries (`paths.ts`). The hash is over a canonical form, so two builds that archived the
//! same files agree on it.

use serde_json::{Map, Value, json};

/// `FIREWALL_BACKUP_FILES`: what a firewall backup carries, in this order (the box key first, so
/// a restore has it in place before the stores it opens).
pub const FIREWALL_BACKUP_FILES: &[&str] = &[
    "/opt/controlclaw/keys/box_key",
    "/opt/controlclaw/state/channels.enc",
    "/opt/controlclaw/state/llm.enc",
    "/opt/controlclaw/state/backup.enc",
    "/opt/controlclaw/state/drive.enc",
    "/opt/controlclaw/state/google.enc",
    "/opt/controlclaw/state/agentmail.enc",
    "/opt/controlclaw/state/twilio-voice.enc",
    "/opt/controlclaw/state/secrets.enc",
    "/opt/controlclaw/state/logins.enc",
    "/opt/controlclaw/state/access.enc",
    "/opt/controlclaw/state/meetings.enc",
    "/opt/controlclaw/state/content-rules.enc",
    "/opt/controlclaw/mitm/ca/ca-cert.pem",
    "/opt/controlclaw/mitm/ca/ca-key.pem",
    "/opt/controlclaw/mitm/ca/mitmproxy-ca.pem",
    "/run/mitm/config/rules.json",
    "/run/mitm/config/grants.json",
    "/run/mitm/config/identities.json",
];

/// JS `<` on strings: by UTF-16 code units.
fn js_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

/// `canonicalManifest`: fixed key order, entries and exclusions sorted by path. Values are copied as
/// they are (a missing one is left out, as `JSON.stringify` drops `undefined`).
pub fn canonical_manifest(m: &Map<String, Value>) -> String {
    let field = |o: &Map<String, Value>, out: &mut Map<String, Value>, k: &str| {
        if let Some(v) = o.get(k) {
            out.insert(k.into(), v.clone());
        }
    };
    let list = |k: &str| -> Vec<Value> {
        let mut l: Vec<Value> = m.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
        l.sort_by(|a, b| js_cmp(str_of(a, "path"), str_of(b, "path")));
        l
    };
    let entries: Vec<Value> = list("entries")
        .iter()
        .map(|e| {
            let e = e.as_object().cloned().unwrap_or_default();
            let mut out = Map::new();
            for k in ["bytes", "kind", "mode", "path"] {
                field(&e, &mut out, k);
            }
            if e.get("kind").and_then(Value::as_str) == Some("link") {
                out.insert("target".into(), e.get("target").cloned().unwrap_or(json!("")));
            }
            Value::Object(out)
        })
        .collect();
    let excluded: Vec<Value> = list("excluded")
        .iter()
        .map(|e| {
            let e = e.as_object().cloned().unwrap_or_default();
            let mut out = Map::new();
            for k in ["bytes", "path"] {
                field(&e, &mut out, k);
            }
            Value::Object(out)
        })
        .collect();
    let mut out = Map::new();
    out.insert("entries".into(), Value::Array(entries));
    out.insert("excluded".into(), Value::Array(excluded));
    for k in ["kind", "root", "takenAt", "totalBytes", "version"] {
        field(m, &mut out, k);
    }
    Value::Object(out).to_string()
}

/// `manifestHash`: BLAKE2b-256 of the canonical form, hex.
pub fn manifest_hash(m: &Map<String, Value>) -> String {
    cc_crypto::recovery::recovery_body_digest(canonical_manifest(m).as_bytes())
}

/// `parseManifest`.
pub fn parse_manifest(v: &Value) -> Result<Map<String, Value>, String> {
    let bad = || "the archive's manifest is not readable".to_string();
    let mut m = v.as_object().cloned().ok_or_else(bad)?;
    if m.get("version").and_then(Value::as_f64) != Some(1.0) || !m.get("entries").is_some_and(Value::is_array) {
        return Err(bad());
    }
    if !m.get("excluded").is_some_and(Value::is_array) {
        m.insert("excluded".into(), json!([]));
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_the_ts() {
        // From packages/backup-envelope's manifestHash.
        let m = json!({
            "version": 1, "kind": "firewall", "takenAt": "2026-10-01T00:00:00.000Z", "root": "/",
            "entries": [{"path": "/b", "bytes": 2, "mode": 0o600, "kind": "file"}, {"path": "/a", "bytes": 1, "mode": 0o644, "kind": "file"}],
            "totalBytes": 3, "excluded": [],
        });
        let m = parse_manifest(&m).expect("manifest");
        assert_eq!(
            manifest_hash(&m),
            "2baa00279df10b1fe1a49383df1bed461ca8c45a6ba48beff185793d17b430fd"
        );
        assert!(parse_manifest(&json!({"version": 2, "entries": []})).is_err());
    }
}
