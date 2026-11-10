//! Nightly automatic updates (`auto-update.ts`): a standing grant, written after a code this
//! firewall sent was verified, or on first use while nobody is set to get codes, and taken away
//! with `auto-update.disable`. A grant written on first use stays when somebody is added later,
//! like every other first-use change.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::code_message::CodeParts;
use super::consent::iso;
use super::kit::{Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE: &str = "auto-update:org";
const SUMMARY: &str = "Enable nightly automatic software updates and required reboots for your firewall and all agents during your organization's update window";

/// `AutoUpdateStoreFile`.
pub struct AutoUpdateStore {
    path: PathBuf,
    box_key: String,
    aad: String,
    confirmed_at: Mutex<Option<String>>,
}

impl AutoUpdateStore {
    pub fn new(path: PathBuf, box_key: &str, org: &str, box_id: &str) -> Self {
        let aad = format!("{org}:{box_id}:auto-update");
        let log = |l: &str| tracing::error!("{l}");
        let confirmed_at = cc_crypto::enc_file::load_store_or_empty("auto-update", &path, box_key, &aad, &log)
            .filter(|v| v.get("version").and_then(Value::as_f64) == Some(1.0))
            .and_then(|v| v.get("confirmedAt").and_then(Value::as_str).map(str::to_string))
            .filter(|t| super::ssh::parse_iso_ms(t).is_some());
        Self {
            path,
            box_key: box_key.into(),
            aad,
            confirmed_at: Mutex::new(confirmed_at),
        }
    }

    pub fn confirmed_at(&self) -> Option<String> {
        self.confirmed_at.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Saved first, then kept: a write that fails leaves the old state.
    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        self.put(self.confirmed_at()).expect("save");
    }

    fn put(&self, confirmed_at: Option<String>) -> Result<(), String> {
        let mut c = self.confirmed_at.lock().unwrap_or_else(|e| e.into_inner());
        cc_crypto::enc_file::save_store(
            "auto-update",
            &self.path,
            &json!({"version": 1, "confirmedAt": confirmed_at}),
            &self.box_key,
            &self.aad,
        )
        .map_err(|e| e.0)?;
        *c = confirmed_at;
        Ok(())
    }
}

pub type OnDisable = Arc<dyn Fn() + Send + Sync>;

pub struct AutoUpdate {
    kit: Kit,
    pub store: Arc<AutoUpdateStore>,
    on_disable: OnDisable,
}

impl AutoUpdate {
    pub fn new(kit: Kit, store: Arc<AutoUpdateStore>, on_disable: OnDisable) -> Self {
        Self { kit, store, on_disable }
    }

    pub fn confirmed_at(&self) -> Option<String> {
        self.store.confirmed_at()
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "Missing change id");
        };
        let data = obj(&[("changeId", json!(change_id)), ("summary", json!(SUMMARY))]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", "Your firewall cannot read its channel list right now.", data);
        };
        if routes.is_empty() {
            self.kit.consent.forget(SCOPE);
            let confirmed_at = iso(now_ms());
            if let Err(e) = self.store.put(Some(confirmed_at.clone())) {
                return CommandOutcome::failed("failed", e);
            }
            tracing::info!("[auto-update] no code recipient: turned on on first use");
            let mut d = data;
            d.insert("confirmedAt".into(), json!(confirmed_at));
            d.insert("tofu".into(), json!(true));
            return ok("applied", d);
        }
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: SCOPE.into(),
                change_id: change_id.clone(),
                proposal: json!({"changeId": change_id}),
                agent_name: "your organization".into(),
                summary: SUMMARY.into(),
                routes,
                // A fixed sentence of ours.
                parts: Some(CodeParts {
                    ask: SUMMARY.into(),
                    ..Default::default()
                }),
                recovery: true,
                ..Default::default()
            })
            .await;
        awaiting(sent, data)
    }

    pub fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        // `typeof p.changeId !== "string"`: an empty one passes, as in the TS.
        let Some(change_id) = payload.get("changeId").and_then(Value::as_str).map(str::to_string) else {
            return CommandOutcome::failed("failed", "Missing change id");
        };
        let data = obj(&[("changeId", json!(change_id))]);
        let code = text(&payload, "code").unwrap_or_default();
        match self.kit.consent.verify(SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail("expired", "The code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { sent_via, .. } => {
                let confirmed_at = iso(now_ms());
                if let Err(e) = self.store.put(Some(confirmed_at.clone())) {
                    return CommandOutcome::failed("failed", e);
                }
                let mut d = data;
                d.insert("confirmedAt".into(), json!(confirmed_at));
                d.insert("summary".into(), json!(SUMMARY));
                d.insert("sentVia".into(), json!(sent_via));
                ok("applied", d)
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = payload.get("changeId").and_then(Value::as_str).map(str::to_string);
        self.kit.consent.cancel(SCOPE, change_id.as_deref());
        // `{changeId: p.changeId}`: left out when absent, as `JSON.stringify` drops undefined.
        let mut d = Map::new();
        if let Some(v) = payload.get("changeId") {
            d.insert("changeId".into(), v.clone());
        }
        ok("cancelled", d)
    }

    pub fn disable(&self) -> CommandOutcome {
        self.kit.consent.forget(SCOPE);
        if let Err(e) = self.store.put(None) {
            return CommandOutcome::failed("failed", e);
        }
        (self.on_disable)();
        ok("applied", obj(&[("confirmedAt", Value::Null)]))
    }
}
