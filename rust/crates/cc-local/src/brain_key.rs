//! The brain's model key on a standalone firewall (docs/plans/standalone-brain.md, part A).
//!
//! The SaaS pays a brain's model calls from the organization's included AI (`queueBrainPush` in
//! `apps/saas/app/(brain)/lib/brain-llm.server.ts`). A standalone firewall has none: the brain is paid
//! by the user's own key, the one the panel holds for the Vercel AI Gateway, else OpenAI's. It rides
//! the same `llm.push`: the key named as the brain's embeddings payer, with the brain's allow-list.
//! The firewall then puts one proxy entry on the brain's `vm_id` that swaps the placeholder for the
//! key on that provider's host, for those models only, and POSTs `/llm/apply` to the brain with the
//! placeholder and the provider's base URL. The brain's vm-agent writes both into GBrain's env file
//! (`key::parse_standalone`). The real key never leaves the firewall.
//!
//! `embeddings: null` when there is no such key: the firewall takes the entry away and the brain's
//! key goes back to one nothing swaps, so its calls are refused where they are made.

use rusqlite::OptionalExtension;
use serde_json::{Map, Value, json};

use crate::db::Db;

/// What GBrain sends as `model`, which the proxy's allow-list compares: the twin of
/// `BRAIN_ALLOWED_MODELS` in `apps/saas/app/(brain)/lib/brain-models.ts`.
pub const BRAIN_EMBEDDING_MODEL: &str = "text-embedding-3-small";
pub const BRAIN_ALLOWED_MODELS: &[&str] = &[BRAIN_EMBEDDING_MODEL, "gpt-5.6-luna", "gpt-5.6-terra"];

/// The providers that can pay for the brain, first found first, with the base URL GBrain sends their
/// placeholder to (the brain's `key.rs` checks the same pair).
pub const BRAIN_PAYERS: &[(&str, &str)] = &[
    ("vercel_gateway", "https://ai-gateway.vercel.sh/v1"),
    ("openai", "https://api.openai.com/v1"),
];

/// Where the brains the firewall gave a key to are kept (a JSON list of `vm_id`s), so a brain that
/// is unpaired or replaced has its entry taken off the firewall, also after a restart.
const KEYED: &str = "brain_key_vms";

/// The brains that have had a key pushed, the current one included.
pub fn keyed(db: &Db) -> Vec<String> {
    db.setting(KEYED)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Remember that `vm_id` has a key (`add`), or that its entry is off the firewall.
pub fn set_keyed(db: &Db, vm_id: &str, add: bool) -> rusqlite::Result<()> {
    let mut list = keyed(db);
    list.retain(|v| v != vm_id);
    if add {
        list.push(vm_id.to_string());
    }
    db.set_setting(KEYED, &serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()))
}

/// The paired brain: `(vm_id, name, hostname)`, the hostname being what the firewall signs its
/// tokens for (where its vm-agent listens).
pub fn paired_brain(db: &Db) -> rusqlite::Result<Option<(String, String, String)>> {
    db.lock()
        .query_row(
            "SELECT vm_id, name, hostname, agent_addr, private_ip FROM agents WHERE role = 'gbrain' ORDER BY paired_at DESC, created_at DESC LIMIT 1",
            [],
            |r| {
                let hostname = r.get::<_, Option<String>>(2)?.filter(|h| !h.is_empty());
                let addr = r
                    .get::<_, Option<String>>(3)?
                    .and_then(|a| a.parse::<std::net::SocketAddrV4>().ok())
                    .map(|a| a.ip().to_string());
                let ip = r.get::<_, Option<String>>(4)?;
                // The address the firewall calls it at, and signs its tokens for, before the
                // hostname, which on a standalone firewall is the pages' name (`PUT /api/brain/pages`).
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    addr.or(hostname).or(ip).unwrap_or_default(),
                ))
            },
        )
        .optional()
}

/// The `llm.push` for the brain, and a fingerprint of what it depends on (the payer's placeholder
/// too: a replaced key is a new placeholder the brain must have). `None` without a brain.
pub fn brain_push(db: &Db) -> rusqlite::Result<Option<(Map<String, Value>, String)>> {
    let Some((vm_id, name, hostname)) = paired_brain(db)? else {
        return Ok(None);
    };
    let mut payer = None;
    for (provider, base_url) in BRAIN_PAYERS {
        let row: Option<(String, String)> = db
            .lock()
            .query_row(
                "SELECT id, placeholder FROM llm_keys WHERE provider = ?1 AND state = 'active'",
                [provider],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, placeholder)) = row {
            payer = Some((id, placeholder, *base_url));
            break;
        }
    }
    let embeddings = match &payer {
        Some((id, _, base_url)) => json!({
            "credentialId": id,
            // Nothing on the brain reads `dreaming` (OpenClaw's), but the firewall's parser wants it.
            "memory": {"provider": "openai", "model": BRAIN_EMBEDDING_MODEL, "baseUrl": base_url, "dreaming": false},
            "allowedModels": BRAIN_ALLOWED_MODELS,
        }),
        None => Value::Null,
    };
    let fingerprint = format!(
        "{vm_id}|{hostname}|{}",
        payer
            .as_ref()
            .map(|(id, p, u)| format!("{id}|{p}|{u}"))
            .unwrap_or_default()
    );
    let payload = json!({"vmId": vm_id, "name": name, "hostname": hostname, "embeddings": embeddings});
    Ok(payload.as_object().cloned().map(|p| (p, fingerprint)))
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;

    fn key(db: &Db, provider: &str, placeholder: &str) {
        db.lock()
            .execute(
                "INSERT INTO llm_keys (id, provider, label, hint, placeholder, state, last_error, created_at, updated_at)
                 VALUES (?1, ?2, NULL, '…abcd', ?3, 'active', NULL, 1, 1)",
                params![format!("cred_{provider}"), provider, placeholder],
            )
            .expect("key");
    }

    #[test]
    fn the_brains_that_had_a_key_are_remembered() {
        let db = Db::memory().expect("db");
        assert!(keyed(&db).is_empty());
        set_keyed(&db, "agent_a", true).expect("a");
        set_keyed(&db, "agent_b", true).expect("b");
        set_keyed(&db, "agent_a", true).expect("a again");
        assert_eq!(keyed(&db), vec!["agent_b".to_string(), "agent_a".to_string()]);
        set_keyed(&db, "agent_b", false).expect("b off");
        assert_eq!(keyed(&db), vec!["agent_a".to_string()]);
    }

    #[test]
    fn no_brain_no_push() {
        let db = Db::memory().expect("db");
        key(&db, "openai", "sk-cc-openai-0123456789abcdef01234567");
        assert!(brain_push(&db).expect("push").is_none());
    }

    #[test]
    fn the_gateway_pays_first_then_openai_then_nobody() {
        let db = Db::memory().expect("db");
        db.lock()
            .execute(
                "INSERT INTO agents (vm_id, role, name, private_ip, created_at, paired_at, agent_addr) VALUES ('agent_b', 'gbrain', 'brain', '172.31.251.20', 1, 1, '172.31.252.1:3103')",
                [],
            )
            .expect("brain");
        let (p, none) = brain_push(&db).expect("push").expect("brain");
        assert_eq!(p["vmId"], "agent_b");
        assert_eq!(p["hostname"], "172.31.252.1", "the address the firewall signs for");
        assert!(p["embeddings"].is_null(), "no key: the brain's is taken away");

        key(&db, "openai", "sk-cc-openai-0123456789abcdef01234567");
        let (p, openai) = brain_push(&db).expect("push").expect("brain");
        assert_eq!(p["embeddings"]["credentialId"], "cred_openai");
        assert_eq!(p["embeddings"]["memory"]["baseUrl"], "https://api.openai.com/v1");
        assert_eq!(
            p["embeddings"]["allowedModels"],
            json!(["text-embedding-3-small", "gpt-5.6-luna", "gpt-5.6-terra"])
        );
        assert_ne!(openai, none);

        key(&db, "vercel_gateway", "vck-cc-0123456789abcdef01234567");
        let (p, gateway) = brain_push(&db).expect("push").expect("brain");
        assert_eq!(p["embeddings"]["credentialId"], "cred_vercel_gateway");
        assert_eq!(p["embeddings"]["memory"]["baseUrl"], "https://ai-gateway.vercel.sh/v1");
        assert_ne!(gateway, openai);

        // A replaced key is a new placeholder: a new fingerprint, so it is pushed again.
        db.lock()
            .execute(
                "UPDATE llm_keys SET placeholder = 'vck-cc-ffffffffffffffffffffffff' WHERE provider = 'vercel_gateway'",
                [],
            )
            .expect("replace");
        assert_ne!(brain_push(&db).expect("push").expect("brain").1, gateway);
    }
}
