//! The fields the core puts on every beat (`status()` in `index.ts`): what this firewall can do
//! (`features`), what it holds (`inventory`), which stores it could not read, how its agents
//! answer, and what it runs. Other parts add their features and inventory sections here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

/// Every feature word in the order the TS beat lists them. A word not here goes last.
const ORDER: &[&str] = &[
    "included_ai",
    "web_search",
    "meetings_transcript",
    "meetings_autojoin",
    "tailscale",
    "devices",
    "gbrain",
    "drive_folders",
    "google_account",
    "agentmail",
    "email_rules",
    "phone",
    "secrets",
    "logins",
    "connectors",
    "mcp_servers",
    "mcp_rules",
    "self_update",
    "templates_code",
    "skills_apply",
    "notes_apply",
    "apply_overwrite",
    "template_check_v1",
    "bound_tokens",
    "update_all",
    "auto_update",
    "backups",
    "residential_exit",
    "kill_switch",
    "open_v1",
    "doctor_v1",
    "template_repair",
    "template_capture",
    "doctor_chat",
    "doctor_start",
    "doctor_firewall_v1",
    "ai_review_history",
    "ai_log_review",
    "open_fw_logs",
    "open_fw_content_rules",
    "doctor_terminal",
    "speech_families",
    "speech_wake",
    "speech_wake_sessions",
    "meeting_followup",
    "meeting_instructions",
    "speech_always",
    "meeting_full_agent",
    "meeting_present",
    "content_rules",
    "meeting_consult_model",
    "phone_voice_edit",
    "controlplane_mcp",
    "team_chat",
    "open_logs",
    "open_whatsapp",
    "open_phone",
];

type Check = Arc<dyn Fn() -> bool + Send + Sync>;
type Section = Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>;

#[derive(Default)]
pub struct Beat {
    features: Mutex<Vec<(&'static str, Check)>>,
    inventory: Mutex<HashMap<&'static str, Section>>,
}

impl Beat {
    /// A feature word, sent while `on()` holds. One owner per word.
    pub fn feature(&self, word: &'static str, on: impl Fn() -> bool + Send + Sync + 'static) {
        if let Ok(mut f) = self.features.lock() {
            assert!(!f.iter().any(|(w, _)| *w == word), "feature {word} registered twice");
            f.push((word, Arc::new(on)));
        }
    }

    /// An inventory section (`channels` W4, `credentials` W4, `webhooks` C3): the list, or `None`
    /// when the module is off.
    pub fn inventory_section(&self, key: &'static str, f: impl Fn() -> Option<Vec<Value>> + Send + Sync + 'static) {
        if let Ok(mut s) = self.inventory.lock() {
            assert!(
                s.insert(key, Arc::new(f)).is_none(),
                "inventory section {key} registered twice"
            );
        }
    }

    pub fn features(&self) -> Vec<String> {
        let f = self.features.lock().map(|f| f.clone()).unwrap_or_default();
        let on: Vec<&str> = f.iter().filter(|(_, c)| c()).map(|(w, _)| *w).collect();
        let mut out: Vec<String> = ORDER.iter().filter(|w| on.contains(w)).map(|w| w.to_string()).collect();
        out.extend(on.iter().filter(|w| !ORDER.contains(w)).map(|w| w.to_string()));
        out
    }

    /// `firewallInventory`: a section only when this box can vouch for all of it. A store that
    /// would not open, or a list over the console's cap, leaves its section out (absent is "do not
    /// reconcile", empty is "I hold none").
    pub fn inventory(&self) -> Option<Value> {
        let sections = self.inventory.lock().map(|s| s.clone()).unwrap_or_default();
        let mut out = Map::new();
        for (key, store, cap) in [
            ("channels", "channels", 50),
            ("credentials", "llm", 50),
            ("webhooks", "webhooks", 100),
        ] {
            if cc_crypto::store_health::is_store_unreadable(store) {
                continue;
            }
            if let Some(list) = sections.get(key).and_then(|f| f())
                && list.len() <= cap
            {
                out.insert(key.into(), Value::Array(list));
            }
        }
        (!out.is_empty()).then_some(Value::Object(out))
    }
}

/// `stores`: always sent, `[]` included, so the console's warning can clear.
pub fn stores() -> Value {
    json!(
        cc_crypto::store_health::unreadable_stores()
            .into_iter()
            .map(|u| json!({"store": u.store, "error": u.error, "at": u.at}))
            .collect::<Vec<_>>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_in_the_ts_order_and_inventory_sections() {
        let b = Beat::default();
        b.feature("kill_switch", || true);
        b.feature("bound_tokens", || true);
        b.feature("tailscale", || false);
        b.feature("zzz_new", || true);
        assert_eq!(b.features(), vec!["bound_tokens", "kill_switch", "zzz_new"]);
        assert_eq!(b.inventory(), None);
        b.inventory_section("webhooks", || Some(vec![]));
        b.inventory_section("channels", || Some(vec![json!(1); 51]));
        assert_eq!(b.inventory(), Some(json!({"webhooks": []})));
    }
}
