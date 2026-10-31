//! A standalone firewall's own Open links. In the SaaS the console signs an intent (`open-intent`,
//! 60 s) with the organization's key and the firewall checks it against `saas_public_key.pem`. With
//! no console, the firewall signs the same intent with a key of its own, made at the first start,
//! and checks it against that key's public half. Everything after the check (the browser's
//! enrollment, the session cookie, the page) is the access module's, unchanged.
//!
//! `mitm-agent open <page>` prints a link to `/__cc/local/open` (`local_open`), which enrolls the
//! browser (docs/standalone/standalone-mode.md). The local panel
//! (plan step 13) will sign the same intents after its admin login.

use std::path::Path;

use serde_json::{Map, Value, json};

/// The private half (PKCS#8, 0600) and the public half, in `KEYS_DIR`.
pub const KEY_FILE: &str = "local_intent_key.pem";
pub const PUBLIC_FILE: &str = "local_intent_public.pem";
/// As the console's (`OPEN_INTENT_SECONDS`); the firewall refuses one over 120 s.
pub const INTENT_LIFETIME_S: i64 = 60;
/// The person a local link opens for: there is one admin until the panel has accounts.
pub const LOCAL_USER: &str = "local-admin";

/// Who signs: this firewall's organization and id, written at start so `mitm-agent open` signs for
/// the running agent whatever the shell's environment.
pub const IDENTITY_FILE: &str = "local_intent_identity.json";

/// The firewall's own pages that run with no control plane, and the path each one's Open starts
/// at (as `open-link.server.ts` builds them). Content rules and AI review are not here yet: the
/// first starts only with a control channel, the second is an agent's page.
pub const PAGES: &[(&str, &str)] = &[
    ("firewall-logs", "/__cc/doctor/logs/open"),
    ("logins", "/__cc/logins/open"),
];

/// Make the key pair if there is none, write the public half if it went missing (the page check
/// reads that file), and record whom the links are for. The public PEM.
pub fn ensure(keys_dir: &Path, org_id: &str, box_id: &str) -> Option<String> {
    let public = cc_auth::keys::ensure_keypair(
        keys_dir,
        KEY_FILE,
        PUBLIC_FILE,
        "the key that signs this firewall's Open links",
    )?;
    if !keys_dir.join(PUBLIC_FILE).exists() {
        cc_store::write_file(&keys_dir.join(PUBLIC_FILE), public.as_bytes(), 0o644).ok()?;
    }
    let who = json!({"orgId": org_id, "boxId": box_id}).to_string();
    cc_store::write_file(&keys_dir.join(IDENTITY_FILE), who.as_bytes(), 0o600).ok()?;
    Some(public)
}

/// The organization and id the running agent recorded (`ensure`).
pub fn identity(keys_dir: &Path) -> Result<(String, String), String> {
    let raw = std::fs::read_to_string(keys_dir.join(IDENTITY_FILE))
        .map_err(|_| format!("no {IDENTITY_FILE}: start the firewall agent with MITM_MODE=standalone first"))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("{IDENTITY_FILE}: {e}"))?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    s("orgId")
        .zip(s("boxId"))
        .ok_or_else(|| format!("{IDENTITY_FILE} names no orgId/boxId"))
}

/// An `open-intent` for `next` on this firewall, signed with the local key.
pub fn mint(keys_dir: &Path, org_id: &str, box_id: &str, next: &str) -> Result<String, String> {
    let pem = std::fs::read_to_string(keys_dir.join(KEY_FILE)).map_err(|e| format!("{KEY_FILE}: {e}"))?;
    let key = cc_auth::jwt::SignKey::ed25519_pkcs8_pem(&pem).map_err(|e| e.to_string())?;
    let claims: Map<String, Value> = match json!({
        "purpose": "open-intent",
        "orgId": org_id,
        "vmId": box_id,
        "userId": LOCAL_USER,
        "canWrite": true,
        "next": next,
        "jti": uuid::Uuid::new_v4().to_string(),
    }) {
        Value::Object(m) => m,
        _ => unreachable!("an object literal"),
    };
    cc_auth::jwt::sign(claims, &key, Some(INTENT_LIFETIME_S), None).map_err(|e| e.to_string())
}

/// The link a browser opens: `https://<hostname>/__cc/local/open#i=<intent>`, which enrolls the
/// browser and goes on to the page (`local_open`).
pub fn link(hostname: &str, next: &str, intent: &str) -> Option<String> {
    PAGES.iter().find(|(n, _)| *n == next)?;
    Some(format!(
        "https://{}{}#i={intent}",
        hostname.to_lowercase(),
        super::local_open::LOCAL_OPEN_PATH
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_intent_verifies_with_the_public_half() {
        let d = tempfile::tempdir().expect("dir");
        let public = ensure(d.path(), "local", "firewall").expect("made");
        assert_eq!(
            ensure(d.path(), "local", "firewall").as_deref(),
            Some(public.as_str()),
            "made once"
        );
        std::fs::remove_file(d.path().join(PUBLIC_FILE)).expect("rm");
        ensure(d.path(), "local", "firewall").expect("again");
        assert!(d.path().join(PUBLIC_FILE).exists(), "the public half is written back");
        assert_eq!(
            identity(d.path()).expect("identity"),
            ("local".into(), "firewall".into())
        );
        let jwt = mint(d.path(), "local", "firewall", "firewall-logs").expect("minted");
        let key = cc_auth::jwt::VerifyKey::ed25519_spki_pem(&public).expect("key");
        let c = cc_auth::jwt::verify(&jwt, &key, cc_auth::jwt::VerifyOptions::default()).expect("verifies");
        assert_eq!(c["purpose"], "open-intent");
        assert_eq!(c["vmId"], "firewall");
        assert_eq!(c["next"], "firewall-logs");
        assert_eq!(
            link("FW.example.com", "firewall-logs", "x").as_deref(),
            Some("https://fw.example.com/__cc/local/open#i=x")
        );
        assert_eq!(link("fw.example.com", "chat", "x"), None);
        assert_eq!(link("fw.example.com", "content-rules", "x"), None);
    }
}
