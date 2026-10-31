//! AgentMail on the firewall (`agentmail.ts`, docs/features/agentmail.md): the account and its key,
//! one inbox per agent with an inbox-scoped key the proxy swaps for a placeholder, and the push of
//! that placeholder to the agent.
//!
//!   agentmail.signup|claim|check|create|import|attach|forget|delete|push|read|senders

pub mod api;
pub mod store;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::channels::agent::{AgentCalls, Target};
use crate::commands::CommandOutcome;
use api::{AgentMailCalls, AgentMailError};
use store::{AgentMailStore, Create, MailInbox};

static INBOX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._+-]+@agentmail\.to$").expect("regex"));
static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[a-z0-9.-]+$").expect("regex"));
static HUMAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("regex"));
static USERNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{1,62}$").expect("regex"));
static OTP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]{4,10}$").expect("regex"));
/// zod 4's `z.email()`.
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_'+\-.]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$").expect("regex")
});

type E = AgentMailError;
pub type AllowFrom = Arc<dyn Fn(&str) -> Option<Vec<String>> + Send + Sync>;
pub type SeedSenders = Arc<dyn Fn(&str, Option<&str>) + Send + Sync>;
type Res<T> = Result<T, E>;

fn err(code: &'static str) -> E {
    AgentMailError::new(code)
}

fn supported_inbox(id: Option<&str>) -> bool {
    id.is_some_and(|i| INBOX.is_match(i))
}

/// A non-empty string, as the TS's `str`.
fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// `senders`: a list of up to 50 addresses, deduplicated; absent means the owner's address.
fn senders(value: Option<&Value>, fallback: Option<&str>) -> Res<Vec<String>> {
    let Some(v) = value else {
        return Ok(fallback.map(|f| vec![f.to_string()]).unwrap_or_default());
    };
    let list = v.as_array().filter(|a| a.len() <= 50).ok_or(err("invalid_input"))?;
    let mut out: Vec<String> = vec![];
    for x in list {
        let a = x
            .as_str()
            .filter(|a| {
                crate::channels::js::js_len(a) <= 254 && EMAIL.is_match(a) && !a.starts_with('.') && !a.contains("..")
            })
            .ok_or(err("invalid_input"))?;
        if !out.iter().any(|o| o == a) {
            out.push(a.to_string());
        }
    }
    Ok(out)
}

pub struct AgentMailOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    pub on_credentials_changed: Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>,
    pub api: Arc<dyn AgentMailCalls>,
    /// The senders the agent's channel accepts, from the firewall's email rules. Without it (the
    /// rules did not start), the inbox's own legacy list is used.
    pub allow_from: AllowFrom,
    /// Called before an inbox is pushed: the email rules give a new inbox its default sender.
    pub seed_senders: SeedSenders,
}

pub struct AgentMailFirewall {
    opts: AgentMailOptions,
    /// Commands, the reconcile and the sender refresh, one at a time (the TS `serial`).
    serial: tokio::sync::Mutex<()>,
    reconciling: AtomicBool,
    st: Mutex<AgentMailStore>,
}

impl AgentMailFirewall {
    pub fn new(opts: AgentMailOptions) -> Result<Arc<Self>, String> {
        let store = store::load(&opts.store_path, &opts.box_key, &opts.org_id, &opts.box_id)?;
        Ok(Arc::new(Self {
            opts,
            serial: tokio::sync::Mutex::new(()),
            reconciling: AtomicBool::new(false),
            st: Mutex::new(store),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, AgentMailStore> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save_store(&self, st: &AgentMailStore) -> Res<()> {
        store::save(
            &self.opts.store_path,
            st,
            &self.opts.box_key,
            &self.opts.org_id,
            &self.opts.box_id,
        )
        .map_err(|e| {
            tracing::error!("[agentmail] could not save the store: {e}");
            err("internal_error")
        })
    }

    /// Change the store and save it, in one step.
    fn edit<R>(&self, f: impl FnOnce(&mut AgentMailStore) -> Res<R>) -> Res<R> {
        let mut st = self.lock();
        let r = f(&mut st)?;
        self.save_store(&st)?;
        Ok(r)
    }

    fn edit_inbox<R>(&self, id: &str, f: impl FnOnce(&mut MailInbox) -> R) -> Res<R> {
        self.edit(|st| Ok(f(st.inboxes.get_mut(id).ok_or(err("inbox_not_found"))?)))
    }

    fn inbox(&self, id: &str) -> Res<MailInbox> {
        self.lock().inboxes.get(id).cloned().ok_or(err("inbox_not_found"))
    }

    fn claimed_in(st: &AgentMailStore) -> bool {
        matches!(st.auth_type.as_deref(), Some("agent_verified" | "clerk"))
    }

    fn claimed(&self) -> bool {
        Self::claimed_in(&self.lock())
    }

    fn allowed_for(&self, inbox_id: &str) -> Res<Vec<String>> {
        let (human, legacy) = {
            let st = self.lock();
            let i = st.inboxes.get(inbox_id);
            (st.human_email.clone(), i.and_then(|i| i.allowed_senders.clone()))
        };
        (self.opts.seed_senders)(inbox_id, human.as_deref());
        match (self.opts.allow_from)(inbox_id) {
            Some(a) => Ok(a),
            None => senders(legacy.as_ref(), human.as_deref()),
        }
    }

    /// Retry the inboxes still pending on their agent (a timer). One at a time; a call while one
    /// runs returns at once.
    pub async fn reconcile(&self) {
        if self.reconciling.swap(true, Ordering::SeqCst) {
            return;
        }
        // Cleared however this ends: a pass that panics or is dropped must not stop the next ones.
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _done = Done(&self.reconciling);
        let _serial = self.serial.lock().await;
        let pending: Vec<MailInbox> = self
            .lock()
            .inboxes
            .values()
            .filter(|i| i.status == "pending" && i.vm_id.is_some() && i.hostname.is_some())
            .cloned()
            .collect();
        for i in pending {
            let (Some(vm), Some(host)) = (&i.vm_id, &i.hostname) else {
                continue;
            };
            // Offline agents remain pending and can be retried from the console.
            let Ok(result) = self
                .opts
                .agent
                .get(&Target::new(vm, host), "/agentmail/status", None)
                .await
            else {
                continue;
            };
            let Some(apply) = result.get("apply").and_then(Value::as_object) else {
                continue;
            };
            let human = self.lock().human_email.clone();
            let reported = apply
                .get("allowedSenders")
                .filter(|v| !v.is_null())
                .cloned()
                .unwrap_or_else(|| json!(human.iter().collect::<Vec<_>>()));
            let Ok(expected) = self.allowed_for(&i.inbox_id) else {
                continue;
            };
            let status = apply.get("status").and_then(Value::as_str);
            if apply.get("inboxId").and_then(Value::as_str) == Some(i.inbox_id.as_str())
                && apply.get("placeholder").and_then(Value::as_str) == i.placeholder.as_deref()
                && i.placeholder.is_some()
                && reported == json!(expected)
                && matches!(status, Some("active" | "failed"))
            {
                let next = if status == Some("active") {
                    "active"
                } else {
                    "setup_failed"
                };
                let _ = self.edit_inbox(&i.inbox_id, |x| x.status = next.into());
            }
        }
    }

    fn summary_of(&self, st: &AgentMailStore) -> Value {
        let claimed = Self::claimed_in(st);
        let status = if st.org_id.is_some() {
            if claimed { "active" } else { "awaiting_claim" }
        } else if st.signup_started {
            "signup_uncertain"
        } else {
            "disconnected"
        };
        json!({
            "orgId": st.org_id,
            "humanEmail": st.human_email,
            "authType": st.auth_type,
            "status": status,
            "limits": st.limits,
            "canCreate": st.org_key.is_some() && claimed,
            "inboxes": st.inboxes.values().map(|i| json!({
                "inboxId": i.inbox_id,
                "vmId": i.vm_id,
                "status": i.status,
                "allowedSenders": (self.opts.allow_from)(&i.inbox_id)
                    .or_else(|| senders(i.allowed_senders.as_ref(), st.human_email.as_deref()).ok())
                    .unwrap_or_default(),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn summary(&self) -> Value {
        // Seeded first, outside the store's lock: the rules lock their own state.
        let (ids, human): (Vec<String>, Option<String>) = {
            let st = self.lock();
            (st.inboxes.keys().cloned().collect(), st.human_email.clone())
        };
        for id in &ids {
            (self.opts.seed_senders)(id, human.as_deref());
        }
        let st = self.lock().clone();
        self.summary_of(&st)
    }

    /// The proxy's entries: each assigned inbox's key, swapped for its placeholder toward AgentMail.
    pub fn credentials(&self) -> Vec<Value> {
        let st = self.lock();
        if !Self::claimed_in(&st) {
            return vec![];
        }
        st.inboxes
            .values()
            .filter(|i| {
                [&i.vm_id, &i.key, &i.placeholder]
                    .iter()
                    .all(|v| v.as_deref().is_some_and(|x| !x.is_empty()))
                    && (i.status == "active" || i.status == "pending")
            })
            .flat_map(|i| {
                ["api.agentmail.to", "ws.agentmail.to"].map(|domain| {
                    json!({
                        "vm_id": i.vm_id,
                        "placeholder": i.placeholder,
                        "secret": i.key,
                        "match_domain": domain,
                        "locations": ["header:authorization", "query"],
                    })
                })
            })
            .collect()
    }

    /// Each inbox's legacy sender list, for the one-time move into the email rules.
    /// `Err` when one of them does not parse: nothing is moved then, rather than an empty list.
    pub fn legacy_senders(&self) -> Result<Vec<(String, Vec<String>)>, ()> {
        let st = self.lock();
        st.inboxes
            .values()
            .map(|i| {
                senders(i.allowed_senders.as_ref(), st.human_email.as_deref())
                    .map(|l| (i.inbox_id.clone(), l))
                    .map_err(|_| ())
            })
            .collect()
    }

    /// The inboxes that belong to one agent.
    #[allow(dead_code)] // the meetings' organizer check (H7)
    pub fn inboxes_of(&self, vm_id: &str) -> Vec<String> {
        self.lock()
            .inboxes
            .values()
            .filter(|i| i.vm_id.as_deref() == Some(vm_id))
            .map(|i| i.inbox_id.clone())
            .collect()
    }

    /// The inbox-scoped key, for the email rules' own metadata reads. Never leaves this process.
    pub fn inbox_key(&self, inbox_id: &str) -> Option<String> {
        let st = self.lock();
        if !Self::claimed_in(&st) {
            return None;
        }
        st.inboxes.get(inbox_id).and_then(|i| i.key.clone())
    }

    /// Push an assigned inbox again when the email rules changed who may write to it. Only then: a
    /// push restarts the agent's gateway, so a change to limits or the outgoing mode must not.
    pub async fn refresh_senders(&self) {
        let _serial = self.serial.lock().await;
        if !self.claimed() {
            return;
        }
        let inboxes: Vec<MailInbox> = self.lock().inboxes.values().cloned().collect();
        for i in inboxes {
            if i.vm_id.is_none() || (i.status != "active" && i.status != "pending") {
                continue;
            }
            if let (Some(d), Ok(a)) = (&i.delivered_senders, self.allowed_for(&i.inbox_id))
                && d == &a
            {
                continue;
            }
            // Retried by reconcile; nothing remote is echoed.
            let _ = self.deliver(&i.inbox_id).await;
        }
    }

    fn update_org(&self, info: &Value) -> Res<()> {
        let org = s(info.get("organization_id"));
        self.edit(|st| {
            let Some(org) = org else {
                return Err(err("organization_mismatch"));
            };
            if st.org_id.as_ref().is_some_and(|o| o != &org) {
                return Err(err("organization_mismatch"));
            }
            st.org_id = Some(org);
            // The live API uses authentication_type=agent plus agent_verified; the skill reference
            // still documents the combined auth_type value. Fail closed on either form.
            st.auth_type = match info.get("auth_type") {
                Some(Value::Null) | None => match info.get("authentication_type") {
                    Some(Value::String(t)) if t == "agent" => Some(
                        if info.get("agent_verified") == Some(&Value::Bool(true)) {
                            "agent_verified"
                        } else {
                            "agent_unverified"
                        }
                        .into(),
                    ),
                    Some(Value::String(t)) => Some(t.clone()),
                    _ => None,
                },
                Some(Value::String(t)) => Some(t.clone()),
                // Anything else is not a claim this firewall recognises.
                Some(_) => None,
            };
            st.limits = [
                "inbox_limit",
                "inbox_count",
                "daily_send_limit",
                "monthly_send_limit",
                "send_limit",
            ]
            .iter()
            .filter_map(|k| {
                info.get(*k)
                    .filter(|v| v.is_number())
                    .map(|v| ((*k).to_string(), v.clone()))
            })
            .collect();
            Ok(())
        })
    }

    fn org_key(&self) -> Res<String> {
        self.lock().org_key.clone().ok_or(err("org_key_required"))
    }

    fn target(&self, p: &Map<String, Value>) -> Res<(String, String)> {
        let (Some(vm), Some(host)) = (s(p.get("vmId")), s(p.get("hostname"))) else {
            return Err(err("invalid_agent"));
        };
        if !HOSTNAME.is_match(&host) {
            return Err(err("invalid_agent"));
        }
        let asked = p.get("inboxId");
        if self.lock().inboxes.values().any(|i| {
            i.vm_id.as_deref() == Some(vm.as_str()) && asked.and_then(Value::as_str) != Some(i.inbox_id.as_str())
        }) {
            return Err(err("agent_has_inbox"));
        }
        Ok((vm, host))
    }

    async fn deliver(&self, inbox_id: &str) -> Res<()> {
        let i = self.inbox(inbox_id)?;
        let (Some(vm), Some(host)) = (i.vm_id.clone(), i.hostname.clone()) else {
            return Ok(());
        };
        if !self.claimed() {
            return Err(err("claim_required"));
        }
        self.edit_inbox(inbox_id, |x| x.status = "pending".into())?;
        if i.key.is_none() {
            let org_key = self.org_key()?;
            let minted = match api::mint(&*self.opts.api, &org_key, inbox_id).await {
                Ok(m) => m,
                Err(e) if e.http_status == 403 && self.lock().auth_type.as_deref() == Some("agent_verified") => {
                    return Err(err("claim_permissions_pending"));
                }
                Err(e) => return Err(e),
            };
            let (Some(key), Some(key_id)) = (s(minted.get("api_key")), s(minted.get("api_key_id"))) else {
                return Err(err("invalid_response"));
            };
            cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(key.clone()), true);
            self.edit_inbox(inbox_id, |x| {
                x.key = Some(key);
                x.key_id = Some(key_id);
            })?;
        }
        let placeholder = self.edit_inbox(inbox_id, |x| {
            let p = x
                .placeholder
                .get_or_insert_with(|| format!("CC-AMAIL-{}", hex::encode(rand::random::<[u8; 16]>())))
                .clone();
            x.status = "pending".into();
            p
        })?;
        (self.opts.on_credentials_changed)().await;
        let pushed = self.allowed_for(inbox_id)?;
        let human = self.lock().human_email.clone();
        let result = self
            .opts
            .agent
            .post(
                &Target::new(&vm, &host),
                "/agentmail/apply",
                json!({"placeholder": placeholder, "inboxId": inbox_id, "humanEmail": human, "allowedSenders": pushed}),
                None,
            )
            .await
            .map_err(|_| err("apply_failed"))?;
        // A failed save after the push is the TS's `apply_failed` too: it ran inside that try.
        self.edit_inbox(inbox_id, |x| x.delivered_senders = Some(pushed))
            .map_err(|_| err("apply_failed"))?;
        if result.get("status").and_then(Value::as_str) == Some("pending") {
            return Ok(());
        }
        self.edit_inbox(inbox_id, |x| x.status = "active".into())?;
        Ok(())
    }

    async fn unassign(&self, inbox_id: &str) -> Res<()> {
        let i = self.inbox(inbox_id)?;
        let previous = (i.vm_id.clone(), i.hostname.clone());
        // Remove swaps before contacting either remote. Persist revocation debt until it succeeds.
        self.edit_inbox(inbox_id, |x| {
            x.status = "unassigned".into();
            x.placeholder = None;
            x.vm_id = None;
            x.hostname = None;
            x.revoke_pending = Some(x.key.is_some());
        })?;
        (self.opts.on_credentials_changed)().await;
        if let (Some(key), Some(key_id)) = (&i.key, &i.key_id) {
            let with = self.lock().org_key.clone().unwrap_or_else(|| key.clone());
            api::revoke(&*self.opts.api, &with, inbox_id, key_id).await?;
            self.edit_inbox(inbox_id, |x| {
                x.key = None;
                x.key_id = None;
            })?;
        }
        let has_org_key = self.lock().org_key.is_some();
        self.edit_inbox(inbox_id, |x| {
            x.revoke_pending = Some(false);
            x.status = if x.imported && !has_org_key {
                "needs_key"
            } else {
                "unassigned"
            }
            .into();
        })?;
        if let (Some(vm), Some(host)) = previous {
            // Revoked upstream and in the proxy. The deleted or offline box cannot spend it.
            let _ = self
                .opts
                .agent
                .post(
                    &Target::new(&vm, &host),
                    "/agentmail/apply",
                    json!({"placeholder": null, "inboxId": null, "humanEmail": null}),
                    None,
                )
                .await;
        }
        Ok(())
    }

    pub async fn command(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _serial = self.serial.lock().await;
        match self.run(action, &payload).await {
            Ok(replayed) => {
                let data = self.summary();
                // A change already done is answered `applied`, whatever the account's state.
                let status = if !replayed && data["status"] == "awaiting_claim" {
                    "awaiting_claim"
                } else {
                    "applied"
                };
                CommandOutcome {
                    ok: true,
                    status: status.into(),
                    message: None,
                    data: data.as_object().cloned(),
                }
            }
            Err(e) => {
                let mut data = self.summary().as_object().cloned().unwrap_or_default();
                data.insert("errorCode".into(), json!(e.code));
                CommandOutcome {
                    ok: false,
                    status: "failed".into(),
                    message: Some(e.code.into()),
                    data: Some(data),
                }
            }
        }
    }

    /// `Ok(true)` for a change this firewall already completed.
    async fn run(&self, action: &str, p: &Map<String, Value>) -> Res<bool> {
        let change_id = s(p.get("changeId"));
        if let Some(c) = &change_id
            && self.lock().completed.contains(c)
        {
            return Ok(true);
        }
        if matches!(action, "signup" | "create" | "import") && p.contains_key("allowedSenders") {
            senders(p.get("allowedSenders"), None)?;
        }
        match action {
            "read" => {
                let key = {
                    let st = self.lock();
                    st.org_key
                        .clone()
                        .or_else(|| st.inboxes.values().find_map(|i| i.key.clone()))
                };
                if let Some(k) = key {
                    let info = api::organization(&*self.opts.api, &k).await?;
                    self.update_org(&info)?;
                }
            }
            "signup" => self.signup(p).await?,
            "claim" | "check" => {
                if action == "claim" {
                    let otp = p.get("otpCode");
                    let ok = s(otp).is_some_and(|o| OTP.is_match(&o));
                    if !ok {
                        return Err(err("invalid_code"));
                    }
                    let key = self.org_key()?;
                    self.opts
                        .api
                        .request("POST", "/agent/verify", Some(&key), Some(json!({"otp_code": otp})))
                        .await?;
                }
                let info = api::organization(&*self.opts.api, &self.org_key()?).await?;
                self.update_org(&info)?;
                if self.claimed() {
                    let ids: Vec<String> = self
                        .lock()
                        .inboxes
                        .values()
                        .filter(|i| i.vm_id.is_some())
                        .map(|i| i.inbox_id.clone())
                        .collect();
                    for id in ids {
                        self.deliver(&id).await?;
                    }
                }
            }
            "create" => self.create(p, change_id.as_deref()).await?,
            "import" => self.import(p).await?,
            "attach" => {
                let id = p.get("inboxId").map(js_string).unwrap_or_default();
                let i = self.inbox(&id)?;
                let (vm, host) = self.target(p)?;
                if let Some(cur) = &i.vm_id {
                    if cur != &vm {
                        return Err(err("inbox_assigned"));
                    }
                    self.deliver(&id).await?;
                    return self.complete(change_id).map(|()| false);
                }
                if i.status == "needs_key" && self.lock().org_key.is_none() {
                    return Err(err("org_key_required"));
                }
                if i.revoke_pending == Some(true) {
                    self.unassign(&id).await?;
                }
                self.edit_inbox(&id, |x| {
                    x.vm_id = Some(vm);
                    x.hostname = Some(host);
                })?;
                self.deliver(&id).await?;
            }
            "senders" => {
                // Senders moved to the email rules, where adding one needs a confirmation code.
                // Editing them here would skip that.
                let id = p.get("inboxId").map(js_string).unwrap_or_default();
                let i = self.inbox(&id)?;
                if (self.opts.allow_from)(&i.inbox_id).is_some() {
                    return Err(err("senders_moved"));
                }
                let Some(list) = p.get("allowedSenders") else {
                    return Err(err("invalid_input"));
                };
                let human = self.lock().human_email.clone();
                let list = senders(Some(list), human.as_deref())?;
                self.edit_inbox(&id, |x| x.allowed_senders = Some(json!(list)))?;
                if i.vm_id.is_some() && self.claimed() {
                    self.deliver(&id).await?;
                }
            }
            "forget" => {
                let ids: Vec<String> = self
                    .lock()
                    .inboxes
                    .values()
                    .filter(|i| i.vm_id.is_some() && p.get("vmId").and_then(Value::as_str) == i.vm_id.as_deref())
                    .map(|i| i.inbox_id.clone())
                    .collect();
                for id in ids {
                    self.unassign(&id).await?;
                }
            }
            "delete" => {
                let id = p.get("inboxId").map(js_string).unwrap_or_default();
                let i = self.inbox(&id)?;
                if p.get("confirmAddress").and_then(Value::as_str) != Some(i.inbox_id.as_str()) {
                    return Err(err("confirm_required"));
                }
                if i.vm_id.is_some() || i.key.is_some() {
                    self.unassign(&id).await?;
                }
                let key = self.org_key()?;
                self.opts
                    .api
                    .request("DELETE", &format!("/inboxes/{}", api::enc(&id)), Some(&key), None)
                    .await?;
                self.edit(|st| {
                    st.inboxes.shift_remove(&id);
                    Ok(())
                })?;
            }
            "push" => {
                let id = self
                    .lock()
                    .inboxes
                    .values()
                    .find(|i| i.vm_id.is_some() && p.get("vmId").and_then(Value::as_str) == i.vm_id.as_deref())
                    .map(|i| i.inbox_id.clone());
                if let Some(id) = id {
                    self.deliver(&id).await?;
                }
            }
            _ => {}
        }
        self.complete(change_id).map(|()| false)
    }

    fn complete(&self, change_id: Option<String>) -> Res<()> {
        let Some(c) = change_id else { return Ok(()) };
        self.edit(|st| {
            let keep = st.completed.len().saturating_sub(99);
            st.completed.drain(..keep);
            st.completed.push(c);
            Ok(())
        })
    }

    async fn signup(&self, p: &Map<String, Value>) -> Res<()> {
        let (vm, host) = self.target(p)?;
        let (human, username) = (s(p.get("humanEmail")), s(p.get("username")));
        let (Some(human), Some(username)) = (human, username) else {
            return Err(err("invalid_input"));
        };
        if !HUMAN.is_match(&human) || !USERNAME.is_match(&username) {
            return Err(err("invalid_input"));
        }
        {
            let st = self.lock();
            if st.org_id.is_some() {
                return Err(err("already_connected"));
            }
            if st.signup_started {
                return Err(err("signup_uncertain"));
            }
        }
        self.edit(|st| {
            st.signup_started = true;
            st.human_email = Some(human.clone());
            Ok(())
        })?;
        let body =
            json!({"human_email": human, "username": username, "source": "controlclaw", "referrer": "controlclaw"});
        let result = match self.opts.api.request("POST", "/agent/sign-up", None, Some(body)).await {
            Ok(r) => r,
            Err(e) => {
                if matches!(e.code, "user_exists" | "username_taken" | "rate_limited") {
                    self.edit(|st| {
                        st.signup_started = false;
                        Ok(())
                    })?;
                }
                return Err(e);
            }
        };
        let (org, inbox, key) = (
            s(result.get("organization_id")),
            result.get("inbox_id").and_then(Value::as_str).map(str::to_string),
            s(result.get("api_key")),
        );
        let (Some(org), Some(key)) = (org, key) else {
            return Err(err("signup_uncertain"));
        };
        let Some(inbox) = inbox.filter(|i| supported_inbox(Some(i))) else {
            return Err(err("signup_uncertain"));
        };
        cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(key.clone()), true);
        let allowed = senders(p.get("allowedSenders"), Some(&human))?;
        self.edit(|st| {
            st.org_id = Some(org);
            st.org_key = Some(key);
            st.auth_type = Some("agent_unverified".into());
            st.inboxes.insert(
                inbox.clone(),
                MailInbox {
                    inbox_id: inbox.clone(),
                    vm_id: Some(vm),
                    hostname: Some(host),
                    key: None,
                    key_id: None,
                    placeholder: None,
                    imported: false,
                    allowed_senders: Some(json!(allowed)),
                    delivered_senders: None,
                    revoke_pending: None,
                    status: "awaiting_claim".into(),
                    extra: Map::new(),
                },
            );
            Ok(())
        })
    }

    async fn create(&self, p: &Map<String, Value>, change_id: Option<&str>) -> Res<()> {
        if !self.claimed() {
            return Err(err("claim_required"));
        }
        let (vm, host) = self.target(p)?;
        let username = s(p.get("username")).filter(|u| USERNAME.is_match(u));
        let (Some(username), Some(change_id)) = (username, change_id) else {
            return Err(err("invalid_input"));
        };
        let client_id = self.edit(|st| {
            let creates = st.creates.get_or_insert_with(Default::default);
            let pending = creates.get(&vm);
            if pending.is_some_and(|c| c.username != username) {
                return Err(err("request_uncertain"));
            }
            let client_id = pending.map_or(change_id.to_string(), |c| c.client_id.clone());
            creates.insert(
                vm.clone(),
                Create {
                    username: username.clone(),
                    client_id: client_id.clone(),
                    extra: Map::new(),
                },
            );
            Ok(client_id)
        })?;
        let key = self.org_key()?;
        let body = json!({"username": username, "display_name": s(p.get("name")).unwrap_or_else(|| username.clone()), "client_id": client_id});
        let result = match self.opts.api.request("POST", "/inboxes", Some(&key), Some(body)).await {
            Ok(r) => r,
            Err(e) => {
                if matches!(e.code, "username_taken" | "permission_denied" | "rate_limited") {
                    self.edit(|st| {
                        if let Some(c) = st.creates.as_mut() {
                            c.shift_remove(&vm);
                        }
                        Ok(())
                    })?;
                }
                return Err(e);
            }
        };
        let Some(inbox) = result
            .get("inbox_id")
            .and_then(Value::as_str)
            .filter(|i| supported_inbox(Some(i)))
        else {
            return Err(err("invalid_response"));
        };
        let human = self.lock().human_email.clone();
        let allowed = senders(p.get("allowedSenders"), human.as_deref())?;
        self.edit(|st| {
            st.inboxes.insert(
                inbox.to_string(),
                MailInbox {
                    inbox_id: inbox.to_string(),
                    vm_id: Some(vm.clone()),
                    hostname: Some(host),
                    key: None,
                    key_id: None,
                    placeholder: None,
                    imported: false,
                    allowed_senders: Some(json!(allowed)),
                    delivered_senders: None,
                    revoke_pending: None,
                    status: "pending".into(),
                    extra: Map::new(),
                },
            );
            if let Some(c) = st.creates.as_mut() {
                c.shift_remove(&vm);
            }
            Ok(())
        })?;
        self.deliver(inbox).await
    }

    async fn import(&self, p: &Map<String, Value>) -> Res<()> {
        let (key, email) = (s(p.get("apiKey")), s(p.get("humanEmail")));
        let (Some(key), Some(email)) = (key, email) else {
            return Err(err("invalid_input"));
        };
        if !key.starts_with("am_") || !HUMAN.is_match(&email) {
            return Err(err("invalid_input"));
        }
        cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(key.clone()), true);
        let org = api::organization(&*self.opts.api, &key).await?;
        {
            let st = self.lock();
            if st.org_id.is_some() && st.org_id.as_deref() != org.get("organization_id").and_then(Value::as_str) {
                return Err(err("organization_mismatch"));
            }
        }
        let scope = api::scope(&*self.opts.api, &key).await?;
        let inboxes = api::inboxes(&*self.opts.api, &key).await?;
        let scoped = scope
            .get("inbox_id")
            .and_then(Value::as_str)
            .filter(|i| !i.is_empty())
            .map(str::to_string);
        let key_id = scope.get("api_key_id").and_then(Value::as_str).map(str::to_string);
        if scoped.is_some() && !supported_inbox(scoped.as_deref()) {
            return Err(err("unsupported_inbox"));
        }
        self.update_org(&org)?;
        self.edit(|st| {
            // Never change an existing channel's allowed sender as a side effect of importing a key.
            st.human_email.get_or_insert(email);
            if scoped.is_none() {
                st.org_key = Some(key.clone());
            }
            Ok(())
        })?;
        for b in inboxes {
            let Some(id) = b
                .get("inbox_id")
                .and_then(Value::as_str)
                .filter(|i| supported_inbox(Some(i)))
            else {
                continue;
            };
            if scoped.as_deref().is_some_and(|s| s != id) {
                return Err(err("scope_unverified"));
            }
            let existing = self.lock().inboxes.get(id).cloned();
            if let Some(e) = existing.as_ref().filter(|e| e.vm_id.is_some()) {
                if scoped.is_some() {
                    self.edit_inbox(&e.inbox_id, |x| {
                        x.key = Some(key.clone());
                        x.key_id = key_id.clone();
                        x.imported = true;
                        x.placeholder = None;
                        x.revoke_pending = Some(false);
                    })?;
                    self.deliver(id).await?;
                }
                continue;
            }
            if existing.as_ref().is_some_and(|e| e.revoke_pending == Some(true)) {
                self.unassign(id).await?;
            }
            let human = self.lock().human_email.clone();
            let allowed = match &existing {
                Some(e) => senders(e.allowed_senders.as_ref(), human.as_deref())?,
                None => senders(p.get("allowedSenders"), human.as_deref())?,
            };
            self.edit(|st| {
                st.inboxes.insert(
                    id.to_string(),
                    MailInbox {
                        inbox_id: id.to_string(),
                        vm_id: None,
                        hostname: None,
                        key: scoped.as_ref().map(|_| key.clone()),
                        key_id: scoped.as_ref().and(key_id.clone()),
                        placeholder: None,
                        imported: scoped.is_some(),
                        allowed_senders: Some(json!(allowed)),
                        delivered_senders: None,
                        revoke_pending: None,
                        status: "unassigned".into(),
                        extra: Map::new(),
                    },
                );
                Ok(())
            })?;
        }
        Ok(())
    }
}

/// `String(v)` for an id the console sent, as the TS indexes the store with it.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests;
