//! Integrations rules on the firewall (`apps-rules.ts`, docs/plans/connector-inspection.md §3):
//! allow, ask or block what an agent does through the organization's app connections and MCP
//! servers. Kept in `apps-rules.enc` and read by the gates on every call.
//!
//! ```text
//!   apps.read     {}                       the rules
//!   apps.propose  { changeId, change }     applied at once when it only narrows, else held for a code
//!   apps.confirm  { changeId, code }
//!   apps.cancel   { changeId }
//! ```
//!
//! The store starts with "Ask before destructive integration actions" and never puts it back after
//! someone deletes it (`seeded`).

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::schema::{
    AppCall, AppDecision, AppRule, AppRulesChange, Fit, SEEDED_APP_RULE_OLD_NAME, apply_app_change, decide_app,
    decide_app_judged, describe_app_change, parse_change, parse_rule, seeded_app_rule, widens,
};
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::integrations::codes::{Codes, Verified};
use crate::integrations::connectors::gate::{GateRules, RulesUnknown};
use crate::integrations::{as_map, js, outcome};
use cc_http::BoxFuture;

const STORE: &str = "apps-rules";
const SCOPE: &str = "apps-rules";

struct State {
    rules: Vec<AppRule>,
    seeded: bool,
    /// A store that is there and will not open is not "no rules": every call is refused until a
    /// confirmed change reseals it.
    unreadable: bool,
    extra: Map<String, Value>,
}

pub struct AppRulesFirewall {
    app: Arc<App>,
    path: PathBuf,
    aad: String,
    state: RwLock<State>,
    codes: Codes,
    serial: tokio::sync::Mutex<()>,
}

/// The rules as one string, to tell whether they changed while a code was on its way.
fn basis_of(rules: &[AppRule], unreadable: bool) -> String {
    let text = if unreadable {
        "unreadable".to_string()
    } else {
        js::stringify(&serde_json::to_value(rules).unwrap_or(Value::Null))
    };
    hex::encode(Sha256::digest(text.as_bytes()))
}

impl AppRulesFirewall {
    pub fn new(app: &Arc<App>, path: PathBuf) -> Arc<Self> {
        let aad = format!("{}:{}:apps-rules", app.config.org_id, app.config.box_id);
        let existed = path.exists();
        let log = |l: &str| tracing::info!("{l}");
        let stored = cc_crypto::enc_file::load_store_or_empty(STORE, &path, &app.box_key, &aad, &log);
        let parsed: Option<Vec<AppRule>> = stored.as_ref().and_then(|s| {
            if s.get("version") != Some(&json!(1)) {
                return None;
            }
            s.get("rules")?.as_array()?.iter().map(|r| parse_rule(r).ok()).collect()
        });
        let me = |state| {
            Arc::new(Self {
                app: app.clone(),
                path: path.clone(),
                aad: aad.clone(),
                state: RwLock::new(state),
                codes: Codes::new(app, SCOPE),
                serial: tokio::sync::Mutex::new(()),
            })
        };
        if (existed && stored.is_none()) || (stored.is_some() && parsed.is_none()) {
            tracing::info!("[apps-rules] the store would not open: app calls are refused until a change is confirmed");
            return me(State {
                rules: vec![],
                seeded: true,
                unreadable: true,
                extra: Map::new(),
            });
        }
        let extra = stored
            .as_ref()
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .filter(|(k, _)| !["version", "rules", "seeded"].contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let seeded = stored.as_ref().and_then(|s| s.get("seeded")) == Some(&json!(true));
        let fw = me(State {
            rules: parsed.unwrap_or_default(),
            seeded,
            unreadable: false,
            extra,
        });
        let seed = seeded_app_rule();
        let mut changed = false;
        {
            let mut st = fw.write();
            if !st.seeded {
                let mut rules = vec![seed.clone()];
                rules.extend(st.rules.iter().filter(|r| r.id != seed.id).cloned());
                st.rules = rules;
                st.seeded = true;
                changed = true;
                tracing::info!("[apps-rules] added \"{}\"", seed.name);
            }
            // T-179: the rule covers MCP servers too, and its name says so. Only a seeded rule nobody changed.
            if let Some(r) = st
                .rules
                .iter_mut()
                .find(|r| r.id == seed.id && r.name == SEEDED_APP_RULE_OLD_NAME)
            {
                r.name = seed.name.clone();
                changed = true;
                tracing::info!("[apps-rules] renamed the seeded rule to \"{}\"", seed.name);
            }
        }
        if changed {
            fw.save();
        }
        fw
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn rules(&self) -> Vec<AppRule> {
        self.read().rules.clone()
    }

    fn save(&self) {
        let st = self.read();
        let mut v = Map::new();
        v.insert("version".into(), json!(1));
        v.insert("rules".into(), serde_json::to_value(&st.rules).unwrap_or(json!([])));
        v.insert("seeded".into(), json!(st.seeded));
        v.extend(st.extra.clone());
        if let Err(e) =
            cc_crypto::enc_file::save_store(STORE, &self.path, &Value::Object(v), &self.app.box_key, &self.aad)
        {
            tracing::error!("[apps-rules] could not save: {}", e.0);
        }
    }

    fn summary(&self) -> Map<String, Value> {
        let st = self.read();
        let mut m = Map::new();
        m.insert("rules".into(), serde_json::to_value(&st.rules).unwrap_or(json!([])));
        if st.unreadable {
            m.insert("unreadable".into(), json!(true));
        }
        m
    }

    pub async fn handle(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _one = self.serial.lock().await;
        self.command(action, &payload).await.unwrap_or_else(|()| {
            outcome(
                false,
                "failed",
                Some("The integration rules change could not be applied. Check the input, then retry.".into()),
                None,
            )
        })
    }

    async fn command(&self, action: &str, payload: &Map<String, Value>) -> Result<CommandOutcome, ()> {
        if action == "read" {
            return Ok(outcome(true, "read", None, Some(self.summary())));
        }
        let change_id = payload
            .get("changeId")
            .and_then(Value::as_str)
            .filter(|s| (1..=100).contains(&s.encode_utf16().count()))
            .ok_or(())?
            .to_string();
        if action == "cancel" {
            self.codes.cancel(Some(&change_id));
            return Ok(outcome(
                true,
                "cancelled",
                None,
                Some(as_map(json!({"changeId": change_id}))),
            ));
        }
        if action == "confirm" {
            let code = payload
                .get("code")
                .and_then(Value::as_str)
                .filter(|c| c.encode_utf16().count() <= 20)
                .ok_or(())?;
            let proposal = match self.codes.verify(&change_id, code) {
                Verified::Ok { proposal, .. } => proposal,
                Verified::Invalid { attempts_left } => {
                    return Ok(outcome(
                        false,
                        "invalid",
                        None,
                        Some(as_map(json!({"attemptsLeft": attempts_left}))),
                    ));
                }
                Verified::Expired => return Ok(outcome(false, "expired", None, Some(Map::new()))),
            };
            let change = proposal.get("change").ok_or(())?;
            let change = parse_change(change).map_err(|_| ())?;
            // The person confirmed this change against the rules in the message. Rules that changed
            // since make it another change.
            let basis = {
                let st = self.read();
                basis_of(&st.rules, st.unreadable)
            };
            if proposal.get("basis").and_then(Value::as_str) != Some(basis.as_str()) {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("Your integration rules changed while the code was on its way, so this change was not made. Save it again to get a new code.".into()),
                    None,
                ));
            }
            return self.apply(&change, true, false);
        }
        let raw = payload.get("change").ok_or(())?;
        let change = parse_change(raw).map_err(|_| ())?;
        let (unreadable, rules) = {
            let st = self.read();
            (st.unreadable, st.rules.clone())
        };
        // Refuse now what could not be applied later.
        apply_app_change(&rules, &change).map_err(|_| ())?;
        // An unreadable store is resealed only by a change someone confirmed, when anyone can be asked.
        // A change that only narrows leaves a change waiting for its code alone.
        if !unreadable && !widens(&rules, &change) {
            return self.apply(&change, false, false);
        }
        let routes = match self.codes.routes() {
            Ok(r) => r,
            Err(m) => return Ok(outcome(false, "failed", Some(m), None)),
        };
        self.codes.forget();
        if routes.is_empty() {
            return self.apply(&change, false, true);
        }
        let seed = seeded_app_rule();
        let summary = if unreadable {
            format!(
                "Your firewall could not read its integration rules. Confirming starts them again from \"{}\" and this change: {}",
                seed.name,
                describe_app_change(&change, std::slice::from_ref(&seed))
            )
        } else {
            describe_app_change(&change, &rules)
        };
        let proposal = json!({"changeId": change_id, "change": raw, "basis": basis_of(&rules, unreadable)});
        Ok(
            match self
                .codes
                .send(
                    &change_id,
                    proposal,
                    "your organization's integration rules",
                    &summary,
                    routes,
                )
                .await
            {
                Ok(sent) => outcome(
                    true,
                    "awaiting_code",
                    None,
                    Some(as_map(
                        json!({"changeId": change_id, "sentVia": sent.sent_via, "expiresAt": sent.expires_at,
                        "attemptsLeft": sent.attempts_left}),
                    )),
                ),
                Err(m) => outcome(
                    false,
                    "failed",
                    Some(if m.is_empty() {
                        "No confirmation code could be delivered. Add a recipient on the Firewall page.".into()
                    } else {
                        m
                    }),
                    None,
                ),
            },
        )
    }

    fn apply(&self, change: &AppRulesChange, confirmed: bool, tofu: bool) -> Result<CommandOutcome, ()> {
        {
            let mut st = self.write();
            // Re-applied to the rules as they are now: another change may have landed in between.
            let base = if st.unreadable {
                vec![seeded_app_rule()]
            } else {
                st.rules.clone()
            };
            st.rules = apply_app_change(&base, change).map_err(|_| ())?;
            st.seeded = true;
            st.unreadable = false;
        }
        self.save();
        let op = match change {
            AppRulesChange::Put { .. } => "put",
            AppRulesChange::Delete { .. } => "delete",
            AppRulesChange::Move { .. } => "move",
        };
        let how = if confirmed {
            " with a code"
        } else if tofu {
            " (nobody can be asked yet)"
        } else {
            " (it only narrows)"
        };
        tracing::info!("[apps-rules] {op} applied{how}");
        let mut data = self.summary();
        if tofu {
            data.insert("tofu".into(), json!(true));
        }
        Ok(outcome(true, "applied", None, Some(data)))
    }

    /// What one call gets. `RulesUnknown` while the store is unreadable: the gate refuses.
    pub fn decide(&self, call: &AppCall, connections: &[String]) -> Result<AppDecision, RulesUnknown> {
        let st = self.read();
        if st.unreadable {
            return Err(RulesUnknown);
        }
        Ok(decide_app(&st.rules, call, connections))
    }

    /// `decide`, with each matching rule's sentence judged by the AI.
    pub async fn decide_judged(&self, call: &AppCall, connections: &[String]) -> Result<AppDecision, RulesUnknown> {
        let rules = {
            let st = self.read();
            if st.unreadable {
                return Err(RulesUnknown);
            }
            st.rules.clone()
        };
        let app = self.app.clone();
        let judge = move |rule: &AppRule, call: &AppCall| -> BoxFuture<Fit> {
            let Some(j) = app.contracts.judge.get() else {
                return Box::pin(async { Fit::Unavailable });
            };
            let Some(sentence) = rule.sentence.clone() else {
                return Box::pin(async { Fit::Unavailable });
            };
            let tool = call
                .tool
                .clone()
                .or_else(|| call.action_id.clone())
                .or_else(|| call.proxy.as_ref().map(|p| format!("{} {}", p.method, p.path)))
                .unwrap_or_else(|| "call".into());
            let f = j.integration_fits(&call.vm_id, &sentence, &call.service, &tool, &call.input);
            Box::pin(async move {
                match f.await.as_str() {
                    "fits" => Fit::Fits,
                    "no" => Fit::No,
                    _ => Fit::Unavailable,
                }
            })
        };
        Ok(decide_app_judged(&rules, call, connections, Some(&judge)).await)
    }
}

/// The rules as the gates ask them.
pub struct Rules(pub Arc<AppRulesFirewall>);

impl GateRules for Rules {
    fn decide(&self, call: &AppCall, connections: &[String]) -> Result<AppDecision, RulesUnknown> {
        self.0.decide(call, connections)
    }

    fn decide_judged(&self, call: AppCall, connections: Vec<String>) -> BoxFuture<Result<AppDecision, RulesUnknown>> {
        let fw = self.0.clone();
        Box::pin(async move { fw.decide_judged(&call, &connections).await })
    }
}

#[cfg(test)]
mod tests;
