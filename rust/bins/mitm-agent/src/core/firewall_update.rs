//! Updating this firewall in place (`firewall-update.ts`). Like an agent update, but it applies to
//! itself (a local spawn). Like an agent update it applies on first use: with nobody to ask, the
//! console chooses when, not what, because the run pulls this box's own pinned repo
//! (`/etc/controlclaw/update.conf`).

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::code_message::CodeParts;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::self_update::{SelfUpdate, Status};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

/// One box, so one scope.
const SCOPE: &str = "firewall-update:self";
const NOT_PINNED: &str = "This firewall was created before in-place updates; it has to be rebuilt instead.";

pub fn summarize() -> String {
    "Update the software on your firewall".into()
}

pub struct FirewallUpdate {
    service: Arc<SelfUpdate>,
    kit: Kit,
    box_name: String,
}

impl FirewallUpdate {
    pub fn new(service: Arc<SelfUpdate>, kit: Kit) -> Self {
        Self {
            service,
            kit,
            box_name: "your firewall".into(),
        }
    }

    /// Whether this box has a pin; false means rebuild only.
    pub fn supported(&self) -> bool {
        self.service.pinned()
    }

    /// Rides the beat while a run is going.
    pub fn status(&self) -> Status {
        self.service.status()
    }

    fn apply(&self, auto: bool, deadline: Option<f64>) -> Result<Map<String, Value>, String> {
        let status = self.service.start(auto, deadline)?;
        tracing::info!("[firewall-update] started on this box");
        Ok(obj(&[("phase", json!(status.phase))]))
    }

    /// `applyForBatch`: this box's run for a batch whose code was confirmed. No consent check here.
    pub fn apply_for_batch(&self, auto: bool, deadline: Option<f64>) -> Result<Map<String, Value>, String> {
        self.apply(auto, deadline)
    }

    /// `applyForDoctor`: Firewall Doctor's `update-retry`; the session's own code covers it.
    pub fn apply_for_doctor(&self) -> Result<Map<String, Value>, String> {
        self.apply(false, None)
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed firewall-update.propose payload");
        };
        let summary = summarize();
        let data = obj(&[("changeId", json!(change_id)), ("summary", json!(summary))]);
        if !self.service.pinned() {
            return fail("failed", NOT_PINNED, data);
        }
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            self.kit.consent.forget(SCOPE);
            return match self.apply(false, None) {
                Ok(applied) => {
                    tracing::info!("[firewall-update] no code recipient: applied on first use");
                    let mut d = data;
                    d.extend(applied);
                    d.insert("tofu".into(), json!(true));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        // Nothing in this message came from anywhere else.
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: SCOPE.into(),
                change_id: change_id.clone(),
                proposal: json!({"changeId": change_id}),
                agent_name: self.box_name.clone(),
                summary: summary.clone(),
                routes,
                parts: Some(CodeParts {
                    ask: summary,
                    ..Default::default()
                }),
                recovery: true,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[firewall-update] code sent via {sent_via}");
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed firewall-update.confirm payload");
        };
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self.kit.consent.verify(SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail("expired", "No update is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { sent_via, .. } => match self.apply(false, None) {
                Ok(applied) => {
                    let mut d = data;
                    d.extend(applied);
                    d.insert("summary".into(), json!(summarize()));
                    d.insert("sentVia".into(), json!(sent_via));
                    d.insert("tofu".into(), json!(false));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            },
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        self.kit.consent.cancel(SCOPE, change_id.as_deref());
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }
}

/// The `SelfUpdate` slot Firewall Doctor reads.
pub struct DoctorUpdate(pub Arc<FirewallUpdate>);

impl crate::contracts::SelfUpdate for DoctorUpdate {
    fn supported(&self) -> bool {
        self.0.supported()
    }

    fn phase(&self) -> String {
        self.0.status().phase
    }

    fn apply_for_doctor(&self) {
        if let Err(e) = self.0.apply_for_doctor() {
            tracing::info!("[firewall-update] Doctor's update did not start: {e}");
        }
    }
}
