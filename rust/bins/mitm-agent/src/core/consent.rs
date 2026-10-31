//! Confirmation codes, the firewall's consent primitive (`consent-codes.ts`). A change the control
//! plane proposes is held here with a 6-digit code; an agent delivers the code over one of its own
//! channels (`POST /channels/send`), with a summary written here, so a compromised control plane
//! can propose a change but neither confirm nor disguise it.
//!
//! One pending change per scope, 5 tries, 10 minutes, nothing persisted. When real people were
//! tried and none could be reached, a module that opts in gets the answer sealed to the
//! organization's recovery key instead (T-99).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::now_ms;
use cc_http::BoxFuture;
use rand::Rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::agent_client::{AgentClient, AgentTarget};
use super::code_message::{BUTTONS_OUTRO, code_message};
use super::own_messages::remember_own;
use crate::contracts::{
    ButtonOffer, CodeAsk, CodeButtons, CodeCheck, CodeRoute, CodeSender, CodeSent, CodeService, ConsentCodes,
    ModuleCodes, RecoveryChallenge, Tap, TapOwner,
};

pub const CODE_TTL_MS: u64 = 10 * 60_000;
pub const CODE_ATTEMPTS: u32 = 5;
pub const DEV_SENDER_TYPE: &str = "dev";
/// `sentVia` for a change whose code was sealed to the recovery key.
pub const RECOVERY_SENT_VIA: &str = "recovery-key";
/// `sentVia` for a change a standalone firewall's signed-in admin asked for. The code is not in it:
/// it goes back in process to the local API (`requested_via::hand_code_to_admin`), which confirms
/// at once and never shows it.
pub const LOCAL_ADMIN_SENT_VIA: &str = "local-admin";

/// Confirming with the recovery key (`RecoveryConfirm`), provided by the backups (C5).
pub trait RecoveryConfirm: Send + Sync {
    /// The org's recovery wrap key (X25519, base64), or `None` when this firewall holds none.
    fn public_key(&self) -> Option<String>;
    /// A change went through on the recovery key; the owner is told once a channel works again.
    fn used(&self, subject: &str, summary: &str, at_ms: u64);
}

/// `noRecipients` (T-83): the refusal when there is nobody to send a code to.
pub fn no_recipients(agent_allowed: Option<u32>) -> (String, serde_json::Map<String, Value>) {
    let lead = "Nobody is set to get confirmation codes.";
    let some = match agent_allowed {
        None => "Add somebody on the Firewall page.".to_string(),
        Some(0) => "Connect a channel, then add somebody on the Firewall page.".to_string(),
        Some(n) => format!(
            "{n} {} the agent approved can be added on the Firewall page.",
            if n == 1 { "person" } else { "people" }
        ),
    };
    let mut data = serde_json::Map::new();
    data.insert("noRecipients".into(), json!(true));
    if let Some(n) = agent_allowed {
        data.insert("agentAllowed".into(), json!(n));
    }
    (format!("{lead} {some}"), data)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// `new Date(ms).toISOString()`.
pub fn iso(ms: u64) -> String {
    cc_crypto::store_health::iso_from_millis(ms as i64)
}

/// Where a module's pending change is kept: the module and its scope. Module names are fixed in
/// code and hold no NUL, so one key cannot be read as another module's.
fn slot(module: &str, scope: &str) -> String {
    debug_assert!(!module.contains('\0'));
    format!("{module}\0{scope}")
}

struct Pending {
    proposal: Value,
    change_id: String,
    code_hash: String,
    attempts_left: u32,
    expires_at: u64,
    sent_via: String,
    subject: String,
    summary: String,
    nonce: Option<String>,
}

pub struct Consent {
    agent: AgentClient,
    buttons: Arc<dyn Fn() -> Option<Arc<dyn CodeButtons>> + Send + Sync>,
    pub recovery: OnceLock<Arc<dyn RecoveryConfirm>>,
    pending: Mutex<HashMap<String, Pending>>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    make_code: Arc<dyn Fn() -> String + Send + Sync>,
}

/// A tap on a button of one change's message.
struct Owner {
    consent: Arc<Consent>,
    /// `module\0scope`.
    slot: String,
    change_id: String,
    nonce: Arc<Mutex<Option<String>>>,
}

impl TapOwner for Owner {
    fn tap(&self, correct: bool) -> Tap {
        let nonce = self.nonce.lock().ok().and_then(|n| n.clone());
        self.consent
            .tapped(&self.slot, &self.change_id, nonce.as_deref(), correct)
    }

    fn cancel(&self) {
        self.consent.cancel_slot(&self.slot, Some(&self.change_id));
    }
}

impl Consent {
    pub fn new(agent: AgentClient, buttons: Arc<dyn Fn() -> Option<Arc<dyn CodeButtons>> + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            agent,
            buttons,
            recovery: OnceLock::new(),
            pending: Mutex::new(HashMap::new()),
            now: Arc::new(now_ms),
            make_code: Arc::new(|| format!("{:06}", rand::thread_rng().gen_range(0..1_000_000))),
        })
    }

    #[cfg(test)]
    pub fn for_tests(
        agent: AgentClient,
        buttons: Arc<dyn Fn() -> Option<Arc<dyn CodeButtons>> + Send + Sync>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
        code: &str,
    ) -> Arc<Self> {
        let code = code.to_string();
        Arc::new(Self {
            agent,
            buttons,
            recovery: OnceLock::new(),
            pending: Mutex::new(HashMap::new()),
            now,
            make_code: Arc::new(move || code.clone()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn buttons(&self) -> Option<Arc<dyn CodeButtons>> {
        (self.buttons)().filter(|b| b.available())
    }

    pub async fn send(self: Arc<Self>, module: &str, req: CodeAsk) -> CodeSent {
        let slot = slot(module, &req.scope);
        let code = (self.make_code)();
        let via = super::requested_via::current();
        let expires_at = (self.now)() + CODE_TTL_MS;
        // The signed-in admin of a standalone firewall: the control plane is this process, so the
        // code goes back to it (plan §3). Held and checked like any other code.
        if super::requested_via::hand_code_to_admin(&code) {
            self.replace(
                &slot,
                Pending {
                    proposal: req.proposal,
                    change_id: req.change_id,
                    code_hash: sha256_hex(&code),
                    attempts_left: CODE_ATTEMPTS,
                    expires_at,
                    sent_via: LOCAL_ADMIN_SENT_VIA.into(),
                    subject: req.agent_name,
                    summary: req.summary,
                    nonce: None,
                },
            );
            return CodeSent::Sent {
                sent_via: LOCAL_ADMIN_SENT_VIA.into(),
                expires_at: iso(expires_at),
                attempts_left: CODE_ATTEMPTS,
                recovery: None,
            };
        }
        let mut sent_via: Option<String> = None;
        let mut last_error = String::new();
        let mut delivery_failed = false;
        let scope = req.scope.clone();
        // A message that cannot be written is not sent, in any shorter form: a code with no account
        // of what it confirms would be a blind one. It counts as a delivery that failed.
        let text = match &req.message {
            Some(m) => m(&code).map_err(|e| e.to_string()),
            None => code_message(
                &req.agent_name,
                &req.summary,
                &code,
                via.as_deref(),
                req.parts.as_ref(),
                None,
            )
            .map_err(|e| e.0),
        };
        let text = match text {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::info!("[codes] the code message for {scope} could not be written, so no code was sent: {e}");
                last_error = "the message could not be written".into();
                delivery_failed = true;
                None
            }
        };
        let render: crate::contracts::CodeText = {
            let (subject, summary, code, via, parts) = (
                req.agent_name.clone(),
                req.summary.clone(),
                code.clone(),
                via.clone(),
                req.parts.clone(),
            );
            Arc::new(move |outro: &str| {
                code_message(&subject, &summary, &code, via.as_deref(), parts.as_ref(), Some(outro)).map_err(|e| e.0)
            })
        };
        // Buttons only where the person is at the console's code dialog, the one place that shows
        // the number: not a custom message, not a module that opted out, not a change asked over MCP.
        let mut button_text = None;
        if text.is_some() && req.message.is_none() && via.is_none() && !req.no_buttons && self.buttons().is_some() {
            match render(BUTTONS_OUTRO) {
                Ok(t) => button_text = Some(t),
                Err(e) => tracing::info!(
                    "[codes] the message with buttons for {scope} could not be written; the plain code goes instead: {e}"
                ),
            }
        }
        let buttons = button_text.as_ref().and_then(|_| self.buttons());
        let nonce_cell: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let recovery_key = if req.recovery {
            self.recovery.get().and_then(|r| r.public_key())
        } else {
            None
        };
        let routes = if text.is_none() { Vec::new() } else { req.routes.clone() };
        'routes: for route in &routes {
            for sender in &route.senders {
                let (kind, id, label) = match sender {
                    CodeSender::Dev if delivery_failed && recovery_key.is_some() => continue,
                    CodeSender::Dev => {
                        tracing::info!(
                            "[codes] dev build: {} — the code goes to the control plane, not to a person",
                            req.summary
                        );
                        sent_via = Some(format!("{DEV_SENDER_TYPE}:{code}"));
                        break 'routes;
                    }
                    CodeSender::Person { kind, .. } if kind == DEV_SENDER_TYPE => {
                        tracing::info!("[codes] ignoring a sender that claims the dev type but is not the dev route");
                        continue;
                    }
                    CodeSender::Person { kind, id, label } => (kind, id, label),
                };
                let named = format!("{kind}:{}", label.as_deref().unwrap_or(id));
                if let (Some(b), Some(tg), Some(bt)) = (&buttons, &route.telegram, &button_text)
                    && kind == "telegram"
                {
                    let owner = Arc::new(Owner {
                        consent: self.clone(),
                        slot: slot.clone(),
                        change_id: req.change_id.clone(),
                        nonce: nonce_cell.clone(),
                    });
                    let offered = b
                        .offer(ButtonOffer {
                            change_id: req.change_id.clone(),
                            route: tg.clone(),
                            sender_id: id.clone(),
                            text: bt.clone(),
                            render: render.clone(),
                            code: code.clone(),
                            expires_at_ms: expires_at,
                            owner,
                        })
                        .await;
                    if let Some(n) = offered {
                        if let Ok(mut c) = nonce_cell.lock() {
                            *c = Some(n);
                        }
                        sent_via = Some(named);
                        break 'routes;
                    }
                }
                let text = text.clone().unwrap_or_default();
                // The proxy lets the firewall's own text through the content rules.
                remember_own(&text);
                let target = AgentTarget::new(&route.vm_id, &route.hostname);
                match self
                    .agent
                    .post(
                        &target,
                        "/channels/send",
                        &json!({"type": kind, "to": id, "text": text}),
                    )
                    .await
                {
                    Ok(_) => {
                        sent_via = Some(named);
                        break 'routes;
                    }
                    Err(e) => {
                        last_error = e.to_string();
                        delivery_failed = true;
                        tracing::info!(
                            "[codes] could not send the code via {kind} on {}: {last_error}",
                            route.hostname
                        );
                    }
                }
            }
        }
        let failure = if text.is_none() {
            "Your firewall could not write the message for this code, so none was sent. Try again; if it happens again, the reason is in the firewall's Logs page.".to_string()
        } else {
            format!(
                "Could not reach you on any connected channel ({}). Make sure the agent is running, then try again.",
                if last_error.is_empty() {
                    "no sender answered"
                } else {
                    &last_error
                }
            )
        };
        let nobody = !routes.iter().any(|r| !r.senders.is_empty());
        if sent_via.is_none()
            && let Some(key) = &recovery_key
            && (delivery_failed || (req.recover_without_recipients && nobody))
        {
            return self.seal_to_recovery(&slot, &req, key, failure);
        }
        let Some(sent_via) = sent_via else {
            return CodeSent::Failed { message: failure };
        };
        let nonce = nonce_cell.lock().ok().and_then(|n| n.clone());
        self.replace(
            &slot,
            Pending {
                proposal: req.proposal,
                change_id: req.change_id,
                code_hash: sha256_hex(&code),
                attempts_left: CODE_ATTEMPTS,
                expires_at,
                sent_via: sent_via.clone(),
                subject: req.agent_name,
                summary: req.summary,
                nonce,
            },
        );
        CodeSent::Sent {
            sent_via,
            expires_at: iso(expires_at),
            attempts_left: CODE_ATTEMPTS,
            recovery: None,
        }
    }

    /// No channel took the code: an answer sealed to the recovery key, held exactly like a code.
    fn seal_to_recovery(&self, slot: &str, req: &CodeAsk, key: &str, failure: String) -> CodeSent {
        let expires_at = (self.now)() + CODE_TTL_MS;
        let answer = cc_crypto::recovery::make_recovery_answer();
        let body = cc_crypto::recovery::RecoveryChallengeBody {
            change_id: req.change_id.clone(),
            subject: req.agent_name.clone(),
            summary: req.summary.clone(),
            expires_at: iso(expires_at),
            answer: answer.clone(),
        };
        let challenge = match cc_crypto::recovery::seal_recovery_challenge(&body, key) {
            Ok(c) => c,
            Err(e) => {
                tracing::info!("[codes] could not seal the answer to the recovery key: {e}");
                return CodeSent::Failed { message: failure };
            }
        };
        self.replace(
            slot,
            Pending {
                proposal: req.proposal.clone(),
                change_id: req.change_id.clone(),
                code_hash: sha256_hex(&answer),
                attempts_left: CODE_ATTEMPTS,
                expires_at,
                sent_via: RECOVERY_SENT_VIA.into(),
                subject: req.agent_name.clone(),
                summary: req.summary.clone(),
                nonce: None,
            },
        );
        tracing::info!(
            "[codes] no channel could take the code for \"{}\"; sealed an answer to the recovery key instead",
            req.summary
        );
        CodeSent::Sent {
            sent_via: RECOVERY_SENT_VIA.into(),
            expires_at: iso(expires_at),
            attempts_left: CODE_ATTEMPTS,
            recovery: Some(RecoveryChallenge {
                challenge,
                delivery_error: failure,
            }),
        }
    }

    /// Constant-time check; a wrong code counts down, the last wrong one drops the change.
    /// Only `module`'s change: a code sent for one module never confirms another's.
    pub fn verify_code(&self, module: &str, scope: &str, change_id: &str, code: &str) -> CodeCheck {
        let key = slot(module, scope);
        let scope = key.as_str();
        let mut map = self.lock();
        let Some(p) = map.get_mut(scope).filter(|p| p.change_id == change_id) else {
            return CodeCheck::Expired;
        };
        if (self.now)() > p.expires_at {
            let nonce = p.nonce.clone();
            map.remove(scope);
            drop(map);
            self.settle(nonce.as_deref(), "expired");
            return CodeCheck::Expired;
        }
        let given: String = code
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_lowercase();
        if !cc_crypto::ct_eq(sha256_hex(&given).as_bytes(), p.code_hash.as_bytes()) {
            p.attempts_left = p.attempts_left.saturating_sub(1);
            let left = p.attempts_left;
            if left == 0 {
                let nonce = map.remove(scope).and_then(|p| p.nonce);
                drop(map);
                self.settle(nonce.as_deref(), "closed");
            }
            return CodeCheck::Wrong { tries_left: left };
        }
        let Some(p) = map.remove(scope) else {
            return CodeCheck::Expired;
        };
        drop(map);
        self.settle(p.nonce.as_deref(), "confirmed");
        if p.sent_via == RECOVERY_SENT_VIA
            && let Some(r) = self.recovery.get()
        {
            r.used(&p.subject, &p.summary, (self.now)());
        }
        CodeCheck::Ok {
            proposal: p.proposal,
            sent_via: p.sent_via,
        }
    }

    /// True when that change was the pending one (and is now dropped).
    pub fn cancel_change(&self, module: &str, scope: &str, change_id: Option<&str>) -> bool {
        self.cancel_slot(&slot(module, scope), change_id)
    }

    fn cancel_slot(&self, scope: &str, change_id: Option<&str>) -> bool {
        let mut map = self.lock();
        if map.get(scope).is_none_or(|p| Some(p.change_id.as_str()) != change_id) {
            return false;
        }
        let nonce = map.remove(scope).and_then(|p| p.nonce);
        drop(map);
        self.settle(nonce.as_deref(), "closed");
        true
    }

    pub fn drop_scope(&self, module: &str, scope: &str) {
        let nonce = self.lock().remove(&slot(module, scope)).and_then(|p| p.nonce);
        self.settle(nonce.as_deref(), "closed");
    }

    /// A button on this change's message was tapped. The right number changes nothing here (the
    /// console types the code); a wrong one costs a try.
    fn tapped(&self, scope: &str, change_id: &str, nonce: Option<&str>, correct: bool) -> Tap {
        let mut map = self.lock();
        let Some(p) = map.get_mut(scope) else { return Tap::Gone };
        if nonce.is_none() || p.change_id != change_id || p.nonce.as_deref() != nonce {
            return Tap::Gone;
        }
        if (self.now)() > p.expires_at {
            map.remove(scope);
            return Tap::Gone;
        }
        if correct {
            return Tap::Ok;
        }
        p.attempts_left = p.attempts_left.saturating_sub(1);
        if p.attempts_left > 0 {
            return Tap::Wrong;
        }
        map.remove(scope);
        Tap::Spent
    }

    /// A new change for a scope ends the one it replaces, buttons included.
    fn replace(&self, scope: &str, next: Pending) {
        let next_nonce = next.nonce.clone();
        let before = self.lock().insert(scope.to_string(), next).and_then(|p| p.nonce);
        if before.is_some() && before != next_nonce {
            self.settle(before.as_deref(), "closed");
        }
    }

    fn settle(&self, nonce: Option<&str>, how: &str) {
        if let Some(b) = (self.buttons)() {
            b.settle(nonce, how);
        }
    }
}

/// The shared instance as the other workstreams see it.
pub struct ConsentView(pub Arc<Consent>);

impl CodeService for ConsentView {
    fn module(&self, name: &'static str) -> Arc<dyn ModuleCodes> {
        Arc::new(ModuleView {
            consent: self.0.clone(),
            module: name,
        })
    }
}

/// One module's codes: it sends, verifies and cancels only its own.
pub struct ModuleView {
    consent: Arc<Consent>,
    module: &'static str,
}

impl ModuleCodes for ModuleView {
    fn send(&self, req: CodeAsk) -> BoxFuture<CodeSent> {
        let (c, m) = (self.consent.clone(), self.module);
        Box::pin(async move { c.send(m, req).await })
    }

    fn verify(&self, scope: &str, change_id: &str, code: &str) -> CodeCheck {
        self.consent.verify_code(self.module, scope, change_id, code)
    }

    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        self.consent.cancel_change(self.module, scope, change_id)
    }

    fn forget(&self, scope: &str) {
        self.consent.drop_scope(self.module, scope)
    }
}

/// The module every caller of W0's first `ConsentCodes` shares: they cannot be told apart.
pub const SHARED_MODULE: &str = "shared";

/// Milliseconds of a time `iso` wrote (`YYYY-MM-DDTHH:MM:SS.mmmZ`); 0 for anything else.
fn iso_ms(s: &str) -> i64 {
    let n = |r: std::ops::Range<usize>| s.get(r).and_then(|x| x.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se), Some(ms)) =
        (n(0..4), n(5..7), n(8..10), n(11..13), n(14..16), n(17..19), n(20..23))
    else {
        return 0;
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * m2 + 2) / 5 + d - 1;
    let days = era * 146_097 + doe - 719_468;
    ((days * 86_400 + h * 3600 + mi * 60 + se) * 1000) + ms
}

/// The routes as the TS shapes them (`{target: {vmId, hostname}, senders: [{type, id, label}]}`).
pub fn routes_from_values(routes: &[Value]) -> Vec<CodeRoute> {
    routes
        .iter()
        .filter_map(|r| {
            let t = r.get("target")?;
            let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            let senders = r
                .get("senders")
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .filter_map(|x| {
                            Some(CodeSender::Person {
                                kind: s(x, "type")?,
                                id: s(x, "id")?,
                                label: s(x, "label"),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(CodeRoute {
                vm_id: s(t, "vmId")?,
                hostname: s(t, "hostname")?,
                senders,
                telegram: None,
            })
        })
        .collect()
}

/// The same instance in W0's first shapes, for the modules that started from them.
impl ConsentCodes for ConsentView {
    fn send(&self, req: crate::contracts::CodeRequest) -> BoxFuture<crate::contracts::SendResult> {
        let me = self.0.clone();
        Box::pin(async move {
            // No buttons: a caller of this shape cannot say whether its code is typed in the
            // console's dialog (content rules, email rules are not).
            let ask = CodeAsk {
                no_buttons: true,
                scope: req.scope,
                change_id: req.change_id,
                proposal: req.proposal,
                agent_name: req.agent_name,
                summary: req.summary,
                routes: routes_from_values(&req.routes),
                ..Default::default()
            };
            match me.send(SHARED_MODULE, ask).await {
                CodeSent::Sent {
                    sent_via, expires_at, ..
                } => crate::contracts::SendResult {
                    sent_via: Some(sent_via),
                    error: None,
                    delivery_failed: false,
                    expires_at_ms: iso_ms(&expires_at),
                },
                CodeSent::Failed { message } => crate::contracts::SendResult {
                    sent_via: None,
                    error: Some(message),
                    delivery_failed: true,
                    expires_at_ms: 0,
                },
            }
        })
    }

    fn verify(&self, scope: &str, change_id: &str, code: &str) -> crate::contracts::Verify {
        match self.0.verify_code(SHARED_MODULE, scope, change_id, code) {
            CodeCheck::Ok { proposal, .. } => crate::contracts::Verify::Ok(proposal),
            CodeCheck::Wrong { tries_left } => crate::contracts::Verify::Wrong { tries_left },
            CodeCheck::Expired => crate::contracts::Verify::Expired,
        }
    }

    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        self.0.cancel_change(SHARED_MODULE, scope, change_id)
    }

    fn forget(&self, scope: &str) {
        self.0.drop_scope(SHARED_MODULE, scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CodeRoute;
    use std::sync::atomic::{AtomicU64, Ordering};

    async fn fixture(status: u16) -> (tempfile::TempDir, Arc<Consent>, Arc<Mutex<Vec<Value>>>, Arc<AtomicU64>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut router = cc_http::Router::new(&["all"]);
        router.route(
            "all",
            |_, _| true,
            move |req, _| {
                let s = s.clone();
                async move {
                    use http_body_util::BodyExt;
                    let raw = req
                        .into_body()
                        .collect()
                        .await
                        .map(|b| b.to_bytes())
                        .unwrap_or_default();
                    s.lock()
                        .expect("lock")
                        .push(serde_json::from_slice(&raw).unwrap_or(Value::Null));
                    cc_http::json(status, &json!({"error": "telegram said no"}))
                }
            },
        );
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        let d = tempfile::tempdir().expect("dir");
        cc_testkit::BoxKeys::write(&d.path().join("keys"), "fw_1", "fw.example").expect("keys");
        let agents = Arc::new(super::super::identities::Agents::default());
        agents.set(&[json!({"vm_id": "vm-1", "hostname": "atlas.example"})]);
        let base = format!("http://{addr}");
        let client = AgentClient::for_tests(
            cc_auth::keys::KeysDir::new(d.path().join("keys")),
            agents,
            Arc::new(move |_| Some(base.clone())),
        );
        let now = Arc::new(AtomicU64::new(1_000_000));
        let n = now.clone();
        let c = Consent::for_tests(
            client,
            Arc::new(|| None),
            Arc::new(move || n.load(Ordering::SeqCst)),
            "424242",
        );
        (d, c, seen, now)
    }

    fn route(senders: Vec<CodeSender>) -> CodeRoute {
        CodeRoute {
            vm_id: "vm-1".into(),
            hostname: "atlas.example".into(),
            senders,
            telegram: None,
        }
    }

    fn person(id: &str) -> CodeSender {
        CodeSender::Person {
            kind: "telegram".into(),
            id: id.into(),
            label: Some("@anna".into()),
        }
    }

    fn req(routes: Vec<CodeRoute>) -> CodeAsk {
        CodeAsk {
            scope: "test:org".into(),
            change_id: "chg-1".into(),
            proposal: json!({"x": 1}),
            agent_name: "atlas".into(),
            summary: "Update atlas".into(),
            routes,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_code_confirms_only_its_own_module() {
        let (_d, c, _, _) = fixture(200).await;
        // One module's change under a scope another module also uses (a vm id named after a module).
        let mut ask = req(vec![route(vec![person("1")])]);
        ask.scope = "connectors".into();
        c.clone().send("channels", ask).await;
        let view = ConsentView(c.clone());
        let connectors = view.module("connectors");
        assert_eq!(connectors.verify("connectors", "chg-1", "424242"), CodeCheck::Expired);
        assert!(!connectors.cancel("connectors", Some("chg-1")));
        connectors.forget("connectors");
        // The old shape is a namespace of its own too.
        assert_eq!(
            ConsentCodes::verify(&view, "connectors", "chg-1", "424242"),
            crate::contracts::Verify::Expired
        );
        let channels = view.module("channels");
        assert!(matches!(
            channels.verify("connectors", "chg-1", "424242"),
            CodeCheck::Ok { .. }
        ));
    }

    #[tokio::test]
    async fn the_old_shape_sends_and_verifies_in_its_own_namespace() {
        let (_d, c, _, _) = fixture(200).await;
        let view = ConsentView(c.clone());
        let r = ConsentCodes::send(
            &view,
            crate::contracts::CodeRequest {
                scope: "email:org".into(),
                change_id: "chg-1".into(),
                proposal: json!({}),
                agent_name: "atlas".into(),
                summary: "x".into(),
                routes: vec![json!({"target": {"vmId": "vm-1", "hostname": "atlas.example"}, "senders": [{"type": "telegram", "id": "1", "label": "@anna"}]})],
            },
        )
        .await;
        assert_eq!(r.sent_via.as_deref(), Some("telegram:@anna"));
        assert!(matches!(
            ConsentCodes::verify(&view, "email:org", "chg-1", "424242"),
            crate::contracts::Verify::Ok(_)
        ));
    }

    #[tokio::test]
    async fn the_local_admin_gets_the_code_and_nobody_is_messaged() {
        let (_d, c, seen, _) = fixture(200).await;
        // No routes at all, as on a standalone firewall with no channel: still a code.
        let (r, code) = super::super::requested_via::as_local_admin(c.clone().send("test", req(vec![]))).await;
        let CodeSent::Sent { sent_via, .. } = r else {
            panic!("not sent: {r:?}");
        };
        assert_eq!(
            (sent_via.as_str(), code.as_deref()),
            (LOCAL_ADMIN_SENT_VIA, Some("424242"))
        );
        assert!(seen.lock().expect("seen").is_empty(), "no message went to an agent");
        assert!(matches!(
            c.verify_code("test", "test:org", "chg-1", "424242"),
            CodeCheck::Ok { .. }
        ));
        // Outside the admin's scope, nobody to send to is still a failure.
        assert!(matches!(
            c.clone().send("test", req(vec![])).await,
            CodeSent::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn a_code_goes_out_and_is_checked_once() {
        let (_d, c, seen, _) = fixture(200).await;
        let r = c.clone().send("test", req(vec![route(vec![person("1")])])).await;
        assert_eq!(
            r,
            CodeSent::Sent {
                sent_via: "telegram:@anna".into(),
                expires_at: iso(1_000_000 + CODE_TTL_MS),
                attempts_left: 5,
                recovery: None
            }
        );
        let sent = seen.lock().expect("lock")[0].clone();
        assert_eq!(sent["type"], "telegram");
        assert_eq!(sent["to"], "1");
        assert!(sent["text"].as_str().expect("text").contains("Code: 424 242"));
        assert_eq!(c.verify_code("test", "test:org", "chg-2", "424242"), CodeCheck::Expired);
        assert_eq!(
            c.verify_code("test", "test:org", "chg-1", "000000"),
            CodeCheck::Wrong { tries_left: 4 }
        );
        assert_eq!(
            c.verify_code("test", "test:org", "chg-1", " 424 242 "),
            CodeCheck::Ok {
                proposal: json!({"x": 1}),
                sent_via: "telegram:@anna".into()
            }
        );
        assert_eq!(c.verify_code("test", "test:org", "chg-1", "424242"), CodeCheck::Expired);
    }

    #[tokio::test]
    async fn five_wrong_tries_and_the_clock_end_a_change() {
        let (_d, c, _, now) = fixture(200).await;
        c.clone().send("test", req(vec![route(vec![person("1")])])).await;
        for left in (0..5).rev() {
            assert_eq!(
                c.verify_code("test", "test:org", "chg-1", "111111"),
                CodeCheck::Wrong { tries_left: left }
            );
        }
        assert_eq!(c.verify_code("test", "test:org", "chg-1", "424242"), CodeCheck::Expired);
        c.clone().send("test", req(vec![route(vec![person("1")])])).await;
        now.fetch_add(CODE_TTL_MS + 1, Ordering::SeqCst);
        assert_eq!(c.verify_code("test", "test:org", "chg-1", "424242"), CodeCheck::Expired);
        c.clone().send("test", req(vec![route(vec![person("1")])])).await;
        assert!(!c.cancel_change("test", "test:org", None));
        assert!(!c.cancel_change("test", "test:org", Some("chg-9")));
        assert!(c.cancel_change("test", "test:org", Some("chg-1")));
    }

    #[tokio::test]
    async fn the_dev_route_and_a_failed_delivery() {
        let (_d, c, seen, _) = fixture(500).await;
        let fake_dev = CodeSender::Person {
            kind: "dev".into(),
            id: "dev".into(),
            label: None,
        };
        let r = c
            .clone()
            .send("test", req(vec![route(vec![fake_dev, person("1"), CodeSender::Dev])]))
            .await;
        assert_eq!(
            r,
            CodeSent::Sent {
                sent_via: "dev:424242".into(),
                expires_at: iso(1_000_000 + CODE_TTL_MS),
                attempts_left: 5,
                recovery: None
            }
        );
        assert_eq!(seen.lock().expect("lock").len(), 1);
        let r = c.clone().send("test", req(vec![route(vec![person("1")])])).await;
        assert_eq!(
            r,
            CodeSent::Failed {
                message: "Could not reach you on any connected channel (agent 500: telegram said no). Make sure the agent is running, then try again.".into()
            }
        );
        let r = c.clone().send("test", req(vec![])).await;
        assert_eq!(
            r,
            CodeSent::Failed {
                message: "Could not reach you on any connected channel (no sender answered). Make sure the agent is running, then try again.".into()
            }
        );
    }

    struct Key(String);
    impl RecoveryConfirm for Key {
        fn public_key(&self) -> Option<String> {
            Some(self.0.clone())
        }
        fn used(&self, _: &str, _: &str, _: u64) {}
    }

    #[tokio::test]
    async fn the_recovery_key_takes_a_code_nobody_could_get() {
        let (_d, c, _, _) = fixture(500).await;
        let k = cc_crypto::envelope::generate_recipient_keypair();
        assert!(c.recovery.set(Arc::new(Key(k.public_key.clone()))).is_ok());
        let mut r = req(vec![route(vec![person("1")])]);
        r.recovery = true;
        let CodeSent::Sent {
            sent_via,
            recovery: Some(ch),
            ..
        } = c.clone().send("test", r).await
        else {
            panic!("not sealed");
        };
        assert_eq!(sent_via, RECOVERY_SENT_VIA);
        let body =
            cc_crypto::recovery::open_recovery_challenge(&ch.challenge, &k.secret_key, Some("chg-1")).expect("open");
        assert!(matches!(
            c.verify_code("test", "test:org", "chg-1", &body.answer.to_uppercase()),
            CodeCheck::Ok { .. }
        ));
        assert_eq!(
            no_recipients(Some(2)).0,
            "Nobody is set to get confirmation codes. 2 people the agent approved can be added on the Firewall page."
        );
    }
}
