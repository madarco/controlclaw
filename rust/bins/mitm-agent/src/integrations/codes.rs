//! What each W5 module's `*.propose` / `*.confirm` does with confirmation codes, on top of W3's
//! `ConsentCodes` (`app.contracts.consent`). In the TS every module has its own `ConsentCodes`
//! instance with scope `org`; here there is one instance, so each module's scope is its own name.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::app::App;
use crate::contracts::{CodeRequest, Verify};
use crate::integrations::js;

/// What a change that needs a code gets while confirmation codes are not set up on this build.
pub const NOT_READY: &str = "This firewall cannot send confirmation codes yet, so it did not make this change. Try again after the next firewall update.";

/// `CODE_ATTEMPTS`: the tries a code has when it is sent.
pub const CODE_ATTEMPTS: u32 = 5;

pub struct Codes {
    app: Arc<App>,
    scope: String,
    /// A module of W3's `CodeService`, for a caller whose message is in two parts (`CodeParts`):
    /// its own facts apart from text that came from elsewhere. None: the shared `ConsentCodes`.
    module: Option<&'static str>,
    /// `sentVia` by change id: the TS hands it back from `verify`, the contract does not.
    sent: Mutex<HashMap<String, String>>,
}

pub struct Sent {
    pub sent_via: String,
    pub expires_at: String,
    pub attempts_left: u32,
}

pub enum Verified {
    Ok { proposal: Value, sent_via: String },
    Invalid { attempts_left: u32 },
    Expired,
}

impl Codes {
    pub fn new(app: &Arc<App>, scope: &str) -> Self {
        Self {
            app: app.clone(),
            scope: scope.to_string(),
            module: None,
            sent: Mutex::new(HashMap::new()),
        }
    }

    /// Codes of `module` in W3's `CodeService`, which takes the message's parts.
    pub fn for_module(app: &Arc<App>, module: &'static str, scope: &str) -> Self {
        Self {
            module: Some(module),
            ..Self::new(app, scope)
        }
    }

    fn module_codes(&self) -> Option<Arc<dyn crate::contracts::ModuleCodes>> {
        let m = self.module?;
        self.app.contracts.code_service.get().map(|s| s.module(m))
    }

    /// Whether the codes this caller uses are on this build.
    fn available(&self) -> bool {
        match self.module {
            Some(_) => self.module_codes().is_some(),
            None => self.app.contracts.consent.require().is_ok(),
        }
    }

    /// `codeRoutes()`: where a code can go now. An error while this firewall cannot tell (no
    /// code routes or no consent codes on it yet): a change that would need a code, or would apply
    /// with none because nobody can be asked, is refused rather than applied. Fail closed.
    pub fn routes(&self) -> Result<Vec<Value>, String> {
        let Some(routes) = self.app.contracts.code_routes.get().filter(|_| self.available()) else {
            return Err(NOT_READY.into());
        };
        Ok(routes.routes())
    }

    /// `channelsReady()`: the channel store opened, so no route means nobody, not "unknown".
    pub fn ready(&self) -> bool {
        self.app.contracts.code_routes.get().is_some_and(|r| r.ready())
    }

    /// `codes.drop(scope)`.
    pub fn forget(&self) {
        if let Some(m) = self.module_codes() {
            m.forget(&self.scope);
        } else if let Ok(c) = self.app.contracts.consent.require() {
            c.forget(&self.scope);
        }
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub async fn send(
        &self,
        change_id: &str,
        proposal: Value,
        agent_name: &str,
        summary: &str,
        routes: Vec<Value>,
    ) -> Result<Sent, String> {
        self.send_parts(change_id, proposal, agent_name, summary, routes, None)
            .await
    }

    /// `send` with the message in two parts. Only for a caller made with [`Codes::for_module`].
    pub async fn send_parts(
        &self,
        change_id: &str,
        proposal: Value,
        agent_name: &str,
        summary: &str,
        routes: Vec<Value>,
        parts: Option<crate::core::code_message::CodeParts>,
    ) -> Result<Sent, String> {
        if self.module.is_some() {
            let Some(m) = self.module_codes() else {
                return Err("Confirmation codes are not available on this firewall.".into());
            };
            let ask = crate::contracts::CodeAsk {
                scope: self.scope.clone(),
                change_id: change_id.to_string(),
                proposal,
                agent_name: agent_name.to_string(),
                summary: summary.to_string(),
                routes: crate::core::consent::routes_from_values(&routes),
                parts,
                ..Default::default()
            };
            return match m.send(ask).await {
                crate::contracts::CodeSent::Sent {
                    sent_via,
                    expires_at,
                    attempts_left,
                    ..
                } => {
                    let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
                    sent.insert(change_id.to_string(), sent_via.clone());
                    Ok(Sent {
                        sent_via,
                        expires_at,
                        attempts_left,
                    })
                }
                crate::contracts::CodeSent::Failed { message } => Err(message),
            };
        }
        let Some(c) = self.app.contracts.consent.require().ok() else {
            return Err("Confirmation codes are not available on this firewall.".into());
        };
        let r = c
            .send(CodeRequest {
                scope: self.scope.clone(),
                change_id: change_id.to_string(),
                proposal,
                agent_name: agent_name.to_string(),
                summary: summary.to_string(),
                routes,
            })
            .await;
        match (r.sent_via, r.error) {
            (Some(via), None) => {
                let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
                sent.insert(change_id.to_string(), via.clone());
                Ok(Sent {
                    sent_via: via,
                    expires_at: js::iso(r.expires_at_ms),
                    attempts_left: CODE_ATTEMPTS,
                })
            }
            (_, Some(e)) => Err(e),
            (None, None) => Err("The code could not be sent.".into()),
        }
    }

    pub fn verify(&self, change_id: &str, code: &str) -> Verified {
        if self.module.is_some() {
            let Some(m) = self.module_codes() else {
                return Verified::Expired;
            };
            return match m.verify(&self.scope, change_id, code) {
                crate::contracts::CodeCheck::Ok { proposal, sent_via } => {
                    self.sent.lock().unwrap_or_else(|e| e.into_inner()).remove(change_id);
                    Verified::Ok { proposal, sent_via }
                }
                crate::contracts::CodeCheck::Wrong { tries_left } => Verified::Invalid {
                    attempts_left: tries_left,
                },
                crate::contracts::CodeCheck::Expired => Verified::Expired,
            };
        }
        let Some(c) = self.app.contracts.consent.require().ok() else {
            return Verified::Expired;
        };
        match c.verify(&self.scope, change_id, code) {
            Verify::Ok(proposal) => {
                let sent_via = self
                    .sent
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(change_id)
                    .unwrap_or_default();
                Verified::Ok { proposal, sent_via }
            }
            Verify::Wrong { tries_left } => Verified::Invalid {
                attempts_left: tries_left,
            },
            Verify::Expired | Verify::Unknown => Verified::Expired,
        }
    }

    pub fn cancel(&self, change_id: Option<&str>) {
        if let Some(m) = self.module_codes() {
            m.cancel(&self.scope, change_id);
        } else if let Ok(c) = self.app.contracts.consent.require() {
            c.cancel(&self.scope, change_id);
        }
    }
}

/// `recordName`: an agent's name as this firewall has it on record when it is a plain name;
/// otherwise its id; otherwise "an agent". What a code message names an agent by.
pub fn record_name(name: Option<&str>, vm_id: &str) -> String {
    static NAME: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-z0-9][a-z0-9-]{0,62}$").expect("pattern"));
    static ID: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("pattern"));
    match name {
        Some(n) if NAME.is_match(n) => n.to_string(),
        _ if ID.is_match(vm_id) => vm_id.to_string(),
        _ => "an agent".into(),
    }
}
