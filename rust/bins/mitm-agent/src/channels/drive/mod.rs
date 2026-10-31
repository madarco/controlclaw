//! Google Drive folders on the firewall (`drive.ts`, docs/plans/drive-folders.md).
//!
//!   drive.propose  { changeId, kind, accountId?, account?, secret?, folder?, agents: [...] }
//!   drive.confirm  { changeId, code }
//!   drive.cancel   { changeId }
//!   drive.push     { vmId, name, hostname }   re-apply the whole mount set for one agent
//!   drive.read     {}                         what the console may see: no secrets
//!
//! What reaches an agent box is one `POST /drive/apply` with its whole mount set and a placeholder
//! the proxy swaps for the real token on `www.googleapis.com`. A `google_account` connection
//! borrows the org Google account's live token and keeps no copy (T-78).

pub mod store;
pub mod tokens;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::channels::agent::{AgentCalls, Target};
use crate::channels::google::http::GoogleHttp;
use crate::channels::google::tokens::{Mint, s};
use crate::channels::google::{
    AgentRef, Changed, Routes, agent_list, change_data, failed_json, iso, outcome, parse_agents,
};
use crate::commands::{CommandOutcome, CommandResult};
use crate::contracts::{CodeRequest, ConsentCodes, Verify};
use store::{
    AccessToken, DRIVE_READ_SCOPE, DRIVE_WRITE_SCOPE, DriveAccount, DriveAgent, DriveFolder, DriveOAuth, DriveSecret,
    DriveStore,
};
use tokens::{Borrowed, DriveErrorKind, WriteCheck, WriteCheckOptions};

/// Mint a new access token this long before the current one expires.
pub const DRIVE_REFRESH_AHEAD_MS: i64 = 15 * 60_000;
const SCOPE: &str = "drive:org";
const CODE_SUBJECT: &str = "your organization's Google Drive folders";
const CODE_ATTEMPTS: u32 = 5;
pub const DRIVE_SKIP_GDOCS: bool = true;
pub const DRIVE_EXPORT_FORMATS: &str = "docx,xlsx,pdf";
pub const DRIVE_VFS_CACHE_MAX_SIZE: &str = "2G";
pub const DRIVE_VFS_CACHE_MIN_FREE_SPACE: &str = "4G";
pub const MAX_FOLDERS_PER_ORG: usize = 8;
pub const MAX_FOLDERS_PER_AGENT: usize = 4;

const KINDS: [&str; 8] = [
    "connect_account",
    "replace_account",
    "forget_account",
    "add_folder",
    "edit_folder",
    "remove_folder",
    "assign",
    "unassign",
];

#[derive(Debug, Clone, PartialEq)]
pub struct ProposedAccount {
    pub kind: String,
    pub scope: String,
    pub account_label: Option<String>,
    pub oauth: Option<DriveOAuth>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposedFolder {
    pub id: String,
    pub folder_id: String,
    pub name: String,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub change_id: String,
    pub kind: String,
    pub account_id: Option<String>,
    pub account: Option<ProposedAccount>,
    pub secret: Option<DriveSecret>,
    pub folder: Option<ProposedFolder>,
    pub agents: Vec<AgentRef>,
}

fn mode_label(mode: &str) -> &'static str {
    if mode == "rw" { "read and write" } else { "read-only" }
}

/// Why Google refused a write, in the sentence that helps for this credential (T-78).
pub fn why_writes_fail(kind: &str, refusal: DriveErrorKind, account_label: Option<&str>) -> String {
    if matches!(refusal, DriveErrorKind::RateLimited | DriveErrorKind::Other) {
        return String::new();
    }
    let who = account_label.unwrap_or(if kind == "service_account" {
        "the service account"
    } else {
        "your Google account"
    });
    if kind == "service_account" {
        let storage = "A service account has no storage of its own, so it can only write to a folder on a shared drive, or with domain-wide delegation.";
        return if refusal == DriveErrorKind::StorageQuota {
            format!("{storage} Mount it read-only instead.")
        } else {
            format!("Share the folder with {who} as Editor. {storage} Otherwise mount it read-only.")
        };
    }
    if refusal == DriveErrorKind::StorageQuota {
        return "That is Google's storage-quota rule, which means the token is not acting as an account that owns storage. Mount it read-only instead.".into();
    }
    format!(
        "{who} owns storage, so a folder in its own My Drive can be written. A folder somebody else owns can be written only if it is shared with {who} as Editor: shared as Viewer or Commenter it cannot, and neither can one under Computers in Drive for desktop, where Google refuses new files through the API whoever asks. Check the sharing in Drive, or mount it read-only."
    )
}

/// Google said "slow down": the message says to try again rather than what to change.
pub fn rate_limited_message(account_label: Option<&str>, hint: Option<&str>) -> String {
    let who = account_label.unwrap_or("your Google connection");
    format!(
        "Google is limiting requests from {who} right now. Try again in a few minutes{}.",
        hint.map_or(String::new(), |h| format!(", or {h}"))
    )
}

fn label_of(a: &DriveAccount) -> Option<String> {
    a.account_label.clone().or_else(|| match &a.secret {
        Some(DriveSecret::ServiceAccount { client_email, .. }) => Some(client_email.clone()),
        _ => None,
    })
}

fn source_label(a: Option<&ProposedAccount>) -> String {
    let label = a.and_then(|a| a.account_label.as_deref());
    let paren = label.map_or(String::new(), |l| format!(" ({l})"));
    if a.is_some_and(|a| a.kind == "google_account") {
        format!("using the Google account you connected{paren}")
    } else {
        format!("using a service account key{paren}")
    }
}

fn collapse(s: String) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A service account that acts for a person (domain-wide delegation) says whom, so the person
/// confirming sees whose Drive it reaches.
fn acting_as(p: &Proposal) -> String {
    match &p.secret {
        Some(DriveSecret::ServiceAccount { subject: Some(sub), .. }) if !sub.is_empty() => {
            format!(", acting as {sub}")
        }
        _ => String::new(),
    }
}

/// The one-line summary the code message carries. Mirrored in apps/saas.
pub fn summarize(p: &Proposal) -> String {
    let name = p.folder.as_ref().map_or("", |f| f.name.as_str());
    let mode = mode_label(p.folder.as_ref().map_or("ro", |f| f.mode.as_str()));
    let names: Vec<&str> = p.agents.iter().map(|a| a.name.as_str()).collect();
    match p.kind.as_str() {
        "connect_account" => format!(
            "Connect Google Drive folders {}{}",
            source_label(p.account.as_ref()),
            acting_as(p)
        ),
        "replace_account" => format!(
            "Reconnect Google Drive folders {}{}",
            source_label(p.account.as_ref()),
            acting_as(p)
        ),
        "forget_account" => "Disconnect Google Drive and unmount every folder".into(),
        "add_folder" if !p.agents.is_empty() => collapse(format!(
            "Mount the Drive folder {name} ({mode}) on {}",
            agent_list(&names)
        )),
        "add_folder" => collapse(format!("Add the Drive folder {name} ({mode})")),
        "edit_folder" => collapse(format!("Change the Drive folder {name} to {mode}")),
        "remove_folder" => collapse(format!("Stop mounting the Drive folder {name} everywhere")),
        "assign" => collapse(format!(
            "Mount the Drive folder {name} ({mode}) on {}",
            agent_list(&names)
        )),
        _ => collapse(format!(
            "Stop mounting the Drive folder {name} on {}",
            agent_list(&names)
        )),
    }
}

fn parse_secret(raw: Option<&Value>) -> Option<DriveSecret> {
    let r = raw?.as_object()?;
    if let Some(refresh) = s(r.get("refresh")) {
        return Some(DriveSecret::OAuth { refresh });
    }
    Some(DriveSecret::ServiceAccount {
        client_email: s(r.get("clientEmail"))?,
        private_key: s(r.get("privateKey"))?,
        token_uri: s(r.get("tokenUri"))?,
        subject: s(r.get("subject")),
    })
}

pub fn parse_proposal(p: &Map<String, Value>) -> Result<Proposal, String> {
    let change_id = s(p.get("changeId"));
    let kind = p.get("kind").and_then(Value::as_str).filter(|k| KINDS.contains(k));
    let (Some(change_id), Some(kind)) = (change_id, kind) else {
        return Err("malformed drive.propose payload".into());
    };
    let acc = p.get("account").and_then(Value::as_object);
    let account = acc.and_then(|a| {
        let kind = a
            .get("kind")
            .and_then(Value::as_str)
            .filter(|k| matches!(*k, "oauth" | "service_account" | "google_account"))?;
        let o = a.get("oauth").and_then(Value::as_object);
        Some(ProposedAccount {
            kind: kind.into(),
            // Drive and nothing else: a key that could ask Google for more is refused.
            scope: s(a.get("scope")).filter(|x| x == DRIVE_WRITE_SCOPE || x == DRIVE_READ_SCOPE)?,
            account_label: s(a.get("accountLabel")),
            oauth: o.and_then(|o| {
                Some(DriveOAuth {
                    token_endpoint: s(o.get("tokenEndpoint"))?,
                    client_id: s(o.get("clientId"))?,
                    client_secret: s(o.get("clientSecret"))?,
                })
            }),
        })
    });
    let folder = p.get("folder").and_then(Value::as_object).and_then(|f| {
        Some(ProposedFolder {
            mode: f
                .get("mode")
                .and_then(Value::as_str)
                .filter(|m| *m == "ro" || *m == "rw")?
                .into(),
            folder_id: s(f.get("folderId"))?,
            id: s(f.get("id"))?,
            name: s(f.get("name"))?,
        })
    });
    Ok(Proposal {
        change_id,
        kind: kind.into(),
        account_id: s(p.get("accountId")),
        account,
        secret: parse_secret(p.get("secret")),
        folder,
        agents: parse_agents(p.get("agents")),
    })
}

type Codes = Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>;

pub struct DriveOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    pub codes: Codes,
    /// `None` when the channel list cannot be read: then nothing applies on first use.
    pub code_routes: Routes,
    /// The org Google account, for a `google_account` connection. `None` when there is none.
    pub google_account: Arc<dyn Fn() -> Option<Borrowed> + Send + Sync>,
    pub on_credentials_changed: Option<Changed>,
    pub http: Arc<dyn GoogleHttp>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub write_check: WriteCheckOptions,
}

/// An error a person reads; `transient` means nothing is stored and trying again is the fix.
struct Failure {
    message: String,
    transient: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            transient: false,
        }
    }
}
impl From<&str> for Failure {
    fn from(m: &str) -> Self {
        m.to_string().into()
    }
}

fn transient(message: String) -> Failure {
    Failure {
        message,
        transient: true,
    }
}

struct State {
    store: DriveStore,
    generation: u64,
    sent_via: Option<(String, String)>,
    /// A connect's secret and client secret, waiting for its code. Held here, in memory only, and
    /// never handed to the consent module.
    held: Option<(String, Option<Value>, Option<Value>)>,
}

fn folders_for<'a>(st: &'a DriveStore, vm: &str) -> Vec<&'a DriveFolder> {
    st.folders
        .values()
        .filter(|f| f.agents.iter().any(|a| a == vm))
        .collect()
}

pub struct DriveFirewall {
    opts: DriveOptions,
    serial: tokio::sync::Mutex<()>,
    st: Mutex<State>,
    reports: Mutex<Vec<CommandResult>>,
    minting: AtomicBool,
}

impl DriveFirewall {
    pub fn new(opts: DriveOptions) -> Result<Arc<Self>, String> {
        let store = store::load(&opts.store_path, &opts.box_key, &opts.org_id, &opts.box_id)?;
        Ok(Arc::new(Self {
            opts,
            serial: tokio::sync::Mutex::new(()),
            st: Mutex::new(State {
                store,
                generation: 0,
                sent_via: None,
                held: None,
            }),
            reports: Mutex::new(vec![]),
            minting: AtomicBool::new(false),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    fn save(&self, st: &DriveStore) -> Result<(), String> {
        store::save(
            &self.opts.store_path,
            st,
            &self.opts.box_key,
            &self.opts.org_id,
            &self.opts.box_id,
        )
        .map_err(|e| {
            tracing::error!("[drive] could not save the store: {e}");
            "Your firewall could not save the Drive folders.".to_string()
        })
    }

    async fn changed(&self) {
        if let Some(f) = &self.opts.on_credentials_changed {
            f().await;
        }
    }

    fn borrowed(&self) -> Option<Borrowed> {
        (self.opts.google_account)()
    }

    fn token_of(&self, a: &DriveAccount, g: Option<&Borrowed>) -> Option<String> {
        if a.failed.is_some() {
            return None;
        }
        if a.kind != "google_account" {
            return a.access.as_ref().map(|t| t.token.clone());
        }
        g.and_then(|g| g.token.clone())
    }

    /// Why a borrowed connection cannot be used, in the words the console shows.
    fn borrowed_problem(g: Option<&Borrowed>) -> Option<String> {
        let Some(g) = g else {
            return Some("This organisation has no Google account connected, so there is no Drive access to use. Connect one on the Google page, with Drive ticked.".into());
        };
        if let Some(f) = &g.failed {
            return Some(f.clone());
        }
        if g.token.is_none() {
            return Some("Your Google account has no working token right now. The Google page says why.".into());
        }
        match g.drive_scope {
            None => Some("Your Google account was connected without Drive access. Reconnect it on the Google page with Drive ticked.".into()),
            Some("file") => Some("Your Google account grants Drive as \"Only its own files\", which means the agents can only see files they created — an existing folder would mount empty. Reconnect it with Drive on \"Read only\" or \"Full\".".into()),
            _ => None,
        }
    }

    /// What this connection can actually do right now: a borrowed one follows the Google account.
    fn effective_scope(a: &DriveAccount, g: Option<&Borrowed>) -> String {
        if a.kind != "google_account" {
            return a.scope.clone();
        }
        match tokens::scope_for_borrowed(g) {
            Some(DRIVE_READ_SCOPE) => DRIVE_READ_SCOPE.into(),
            _ => a.scope.clone(),
        }
    }

    fn narrowed_to_read_only(a: &DriveAccount, g: Option<&Borrowed>) -> bool {
        a.scope == DRIVE_WRITE_SCOPE && Self::effective_scope(a, g) == DRIVE_READ_SCOPE
    }

    /// Proxy entries: one per agent that mounts at least one folder, on `www.googleapis.com`.
    pub fn credentials(&self) -> Vec<Value> {
        let g = self.borrowed();
        let st = self.lock();
        let mut out = vec![];
        for (vm, agent) in &st.store.agents {
            let folders = folders_for(&st.store, vm);
            let Some(first) = folders.first() else { continue };
            let Some(account) = st.store.accounts.get(&first.account_id) else {
                continue;
            };
            let Some(token) = self.token_of(account, g.as_ref()) else {
                continue;
            };
            out.push(json!({
                "placeholder": agent.placeholder,
                "match_domain": "www.googleapis.com",
                "secret": token,
                "locations": ["header:authorization"],
                "vm_id": vm,
            }));
        }
        out
    }

    /// What the console may see: no secret, no access token. A borrowed connection's state is
    /// derived from the Google account on every read.
    pub fn summary(&self) -> Value {
        let g = self.borrowed();
        let st = self.lock();
        json!({
            "accounts": st.store.accounts.iter().map(|(id, a)| {
                let problem = if a.kind == "google_account" { Self::borrowed_problem(g.as_ref()) } else { None };
                let failed = a.failed.clone().or(problem).or_else(|| Self::narrowed_to_read_only(a, g.as_ref()).then(||
                    "Your Google account now grants Drive as \"Read only\", so the folders you mounted read-write are mounted read-only. Reconnect it on the Google page with Drive on \"Full\" to get writes back.".to_string()));
                json!({
                    "id": id,
                    "kind": a.kind,
                    "accountLabel": if a.kind == "google_account" {
                        g.as_ref().and_then(|g| g.account_label.clone()).or_else(|| a.account_label.clone())
                    } else { a.account_label.clone() },
                    "scope": Self::effective_scope(a, g.as_ref()),
                    "connected": self.token_of(a, g.as_ref()).is_some(),
                    "failed": failed,
                })
            }).collect::<Vec<_>>(),
            "folders": st.store.folders.iter().map(|(id, f)| json!({
                "id": id, "folderId": f.folder_id, "name": f.name, "mode": f.mode, "agents": f.agents,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn drain_reports(&self) -> Vec<CommandResult> {
        std::mem::take(&mut *self.reports.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub async fn command(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _serial = self.serial.lock().await;
        let r = match action {
            "propose" => self.propose(&payload).await,
            "confirm" => self.confirm(&payload).await,
            "cancel" => Ok(self.cancel(&payload)),
            "push" => self.push(&payload).await,
            "read" => Ok(outcome(
                true,
                "read",
                None,
                self.summary().as_object().cloned().unwrap_or_default(),
            )),
            _ => Err(format!("unknown command drive.{action}")),
        };
        r.unwrap_or_else(|message| CommandOutcome {
            ok: false,
            status: "failed".into(),
            message: Some(message),
            data: None,
        })
    }

    async fn propose(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let p = parse_proposal(payload)?;
        let Some(routes) = (self.opts.code_routes)() else {
            return Ok(outcome(
                false,
                "failed",
                Some(crate::channels::google::NO_CHANNELS.into()),
                change_data(&p.change_id),
            ));
        };
        self.validate(&p)?;
        let summary = summarize(&p);
        let mut data = change_data(&p.change_id);
        data.insert("summary".into(), json!(summary));
        if routes.is_empty() {
            if let Some(c) = (self.opts.codes)() {
                c.forget(SCOPE);
            }
            return self.apply_or_transient(&p, data, true, None).await;
        }
        let Some(codes) = (self.opts.codes)() else {
            return Ok(outcome(
                false,
                "failed",
                Some(crate::channels::google::NO_CODES.into()),
                data,
            ));
        };
        let sent = codes
            .send(CodeRequest {
                scope: SCOPE.into(),
                change_id: p.change_id.clone(),
                proposal: self.hold_secrets(&p.change_id, payload),
                agent_name: CODE_SUBJECT.into(),
                summary,
                routes,
            })
            .await;
        let Some(via) = sent.sent_via.clone() else {
            // No code went out: the secrets held for it go.
            {
                let mut st = self.lock();
                if st.held.as_ref().is_some_and(|(id, _, _)| *id == p.change_id) {
                    st.held = None;
                }
            }
            return Ok(outcome(false, "failed", Some(sent.error.unwrap_or_default()), data));
        };
        tracing::info!("[drive] code sent for {} via {via}", p.kind);
        self.lock().sent_via = Some((p.change_id.clone(), via.clone()));
        data.insert("sentVia".into(), json!(via));
        data.insert("expiresAt".into(), json!(iso(sent.expires_at_ms)));
        data.insert("attemptsLeft".into(), json!(CODE_ATTEMPTS));
        Ok(outcome(true, "awaiting_code", None, data))
    }

    async fn confirm(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let change_id = s(payload.get("changeId")).ok_or("malformed drive.confirm payload")?;
        let code = s(payload.get("code")).unwrap_or_default();
        let mut data = change_data(&change_id);
        let verdict = (self.opts.codes)().map_or(Verify::Unknown, |c| c.verify(SCOPE, &change_id, &code));
        let proposal = match verdict {
            Verify::Ok(p) => p,
            Verify::Wrong { tries_left } => {
                data.insert("attemptsLeft".into(), json!(tries_left));
                return Ok(outcome(false, "invalid_code", Some("Wrong code.".into()), data));
            }
            Verify::Expired | Verify::Unknown => {
                return Ok(outcome(
                    false,
                    "expired",
                    Some("No change is waiting for a code, or the code expired.".into()),
                    data,
                ));
            }
        };
        let mut proposal = proposal.as_object().cloned().ok_or("malformed drive.confirm payload")?;
        let held = {
            let mut st = self.lock();
            match st.held.take() {
                Some((id, secret, client_secret)) if id == change_id => Some((secret, client_secret)),
                other => {
                    st.held = other;
                    None
                }
            }
        };
        match held {
            Some((secret, client_secret)) => {
                if let Some(v) = secret {
                    proposal.insert("secret".into(), v);
                }
                if let (Some(v), Some(o)) = (
                    client_secret,
                    proposal
                        .get_mut("account")
                        .and_then(|a| a.get_mut("oauth"))
                        .and_then(Value::as_object_mut),
                ) {
                    o.insert("clientSecret".into(), v);
                }
            }
            None if proposal.get("secret").is_none()
                && matches!(
                    proposal.get("kind").and_then(Value::as_str),
                    Some("connect_account" | "replace_account")
                )
                && proposal
                    .get("account")
                    .and_then(|a| a.get("kind"))
                    .and_then(Value::as_str)
                    != Some("google_account") =>
            {
                return Ok(outcome(
                    false,
                    "failed",
                    Some(
                        "Your firewall restarted before this connection was confirmed. Start the connection again."
                            .into(),
                    ),
                    data,
                ));
            }
            None => {}
        }
        let p = parse_proposal(&proposal)?;
        let via = {
            let mut st = self.lock();
            match st.sent_via.take() {
                Some((id, via)) if id == change_id => Some(via),
                other => {
                    st.sent_via = other;
                    None
                }
            }
        };
        self.apply_or_transient(&p, data, false, Some(via)).await
    }

    /// `apply`, with a throttle or a timeout reported as a failed change marked `transient`.
    async fn apply_or_transient(
        &self,
        p: &Proposal,
        mut data: Map<String, Value>,
        tofu: bool,
        sent_via: Option<Option<String>>,
    ) -> Result<CommandOutcome, String> {
        match self.apply(p).await {
            Ok(applied) => {
                data.extend(applied);
                if let Some(via) = sent_via {
                    data.insert("summary".into(), json!(summarize(p)));
                    data.insert("sentVia".into(), json!(via));
                }
                data.insert("tofu".into(), json!(tofu));
                Ok(outcome(true, "applied", None, data))
            }
            Err(f) if f.transient => {
                tracing::info!("[drive] {} not applied, try again later: {}", p.kind, f.message);
                data.insert("transient".into(), json!(true));
                Ok(outcome(false, "failed", Some(f.message), data))
            }
            Err(f) => Err(f.message),
        }
    }

    /// The proposal the consent module keeps: without the secret or the client secret, which stay
    /// here until the code comes back.
    fn hold_secrets(&self, change_id: &str, payload: &Map<String, Value>) -> Value {
        let mut out = payload.clone();
        let secret = out.remove("secret");
        let client_secret = out
            .get_mut("account")
            .and_then(|a| a.get_mut("oauth"))
            .and_then(Value::as_object_mut)
            .and_then(|o| o.remove("clientSecret"));
        self.lock().held =
            (secret.is_some() || client_secret.is_some()).then(|| (change_id.to_string(), secret, client_secret));
        Value::Object(out)
    }

    fn cancel(&self, payload: &Map<String, Value>) -> CommandOutcome {
        let change_id = s(payload.get("changeId"));
        {
            let mut st = self.lock();
            if st
                .held
                .as_ref()
                .is_some_and(|h| change_id.as_ref().is_none_or(|c| c == &h.0))
            {
                st.held = None;
            }
        }
        if let Some(c) = (self.opts.codes)() {
            c.cancel(SCOPE, change_id.as_deref());
        }
        let mut data = Map::new();
        data.insert("changeId".into(), json!(change_id));
        outcome(true, "cancelled", None, data)
    }

    async fn push(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm = s(payload.get("vmId")).ok_or("malformed drive.push payload")?;
        let mut data = Map::new();
        data.insert("vmId".into(), json!(vm));
        let name = {
            let mut st = self.lock();
            if !st.store.agents.contains_key(&vm) {
                data.insert("mounts".into(), json!([]));
                data.insert("failed".into(), json!([]));
                return Ok(outcome(true, "applied", None, data));
            }
            let mut next = st.store.clone();
            let a = next.agents.get_mut(&vm).ok_or("unknown agent")?;
            if let Some(h) = s(payload.get("hostname")) {
                a.hostname = Some(h);
            }
            if let Some(n) = s(payload.get("name")) {
                a.name = n;
            }
            let name = a.name.clone();
            self.save(&next)?;
            st.store = next;
            name
        };
        let failed = self.push_agents(std::slice::from_ref(&vm)).await;
        let mounts: Vec<String> = folders_for(&self.lock().store, &vm)
            .iter()
            .map(|f| f.name.clone())
            .collect();
        tracing::info!(
            "[drive] re-applied {} folder(s) on {name}{}",
            mounts.len(),
            failed.first().map_or(String::new(), |f| format!(" (failed: {})", f.1))
        );
        data.insert("mounts".into(), json!(if failed.is_empty() { mounts } else { vec![] }));
        data.insert("failed".into(), failed_json(&failed));
        Ok(CommandOutcome {
            ok: failed.is_empty(),
            status: if failed.is_empty() { "applied" } else { "failed" }.into(),
            message: Some(failed.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join("; ")),
            data: Some(data),
        })
    }

    /// Refuse a proposal the control plane should not have sent.
    fn validate(&self, p: &Proposal) -> Result<(), String> {
        if let Some(f) = &p.folder {
            if !store::is_valid_folder_name(&f.name) {
                return Err("That folder name cannot be used as a directory name on the box.".into());
            }
            if !store::is_valid_folder_id(&f.folder_id) {
                return Err("That does not look like a Google Drive folder id.".into());
            }
        }
        let g = self.borrowed();
        let st = self.lock();
        let st = &st.store;
        if p.kind == "connect_account" || p.kind == "replace_account" {
            let a = p.account.as_ref().ok_or("the proposal is missing the account")?;
            if a.kind == "google_account" {
                if p.secret.is_some() {
                    return Err("a Google-account connection must not carry a secret".into());
                }
                if let Some(problem) = Self::borrowed_problem(g.as_ref()) {
                    return Err(problem);
                }
                let allowed = tokens::scope_for_borrowed(g.as_ref());
                if Some(a.scope.as_str()) != allowed
                    && !(allowed == Some(DRIVE_WRITE_SCOPE) && a.scope == DRIVE_READ_SCOPE)
                {
                    return Err("Your Google account does not grant that much of Drive. Reconnect it with more access, or connect Drive folders read-only.".into());
                }
            } else if p.secret.is_none() {
                return Err("no secret in the proposal".into());
            }
            if a.kind == "oauth" && a.oauth.is_none() {
                return Err("an OAuth connection needs its token endpoint, client id and client secret".into());
            }
            if a.scope != DRIVE_WRITE_SCOPE {
                let writable: Vec<&str> = st
                    .folders
                    .values()
                    .filter(|f| f.mode == "rw")
                    .map(|f| f.name.as_str())
                    .collect();
                if !writable.is_empty() {
                    let one = writable.len() == 1;
                    return Err(format!(
                        "This connection has no write access, but {} {} mounted read-write. Make {} read-only first, or reconnect with write access.",
                        writable.join(", "),
                        if one { "is" } else { "are" },
                        if one { "it" } else { "them" }
                    ));
                }
            }
            return Ok(());
        }
        if matches!(p.kind.as_str(), "add_folder" | "assign" | "edit_folder") {
            let (_, existing) = st
                .accounts
                .first()
                .ok_or("Connect a Google account before adding folders.")?;
            if p.folder.as_ref().is_some_and(|f| f.mode == "rw") && existing.scope != DRIVE_WRITE_SCOPE {
                return Err(
                    "This Google connection is read-only. Reconnect it with write access to make a folder writable."
                        .into(),
                );
            }
            if existing.kind == "google_account"
                && let Some(problem) = Self::borrowed_problem(g.as_ref())
            {
                return Err(problem);
            }
        }
        let folder_id = p.folder.as_ref().map(|f| f.id.as_str());
        if matches!(p.kind.as_str(), "add_folder" | "edit_folder") {
            let name = p.folder.as_ref().map(|f| f.name.as_str());
            if st
                .folders
                .iter()
                .any(|(id, f)| Some(id.as_str()) != folder_id && Some(f.name.as_str()) == name)
            {
                return Err(format!(
                    "Another Drive folder is already mounted as {}. Pick a different name.",
                    name.unwrap_or("")
                ));
            }
        }
        if p.kind == "add_folder" {
            let row = folder_id.and_then(|id| st.folders.get(id));
            if row.is_some_and(|r| Some(r.folder_id.as_str()) != p.folder.as_ref().map(|f| f.folder_id.as_str())) {
                return Err(
                    "That Drive folder row already points at a different folder. Remove it, or edit it instead.".into(),
                );
            }
            if row.is_none() && st.folders.len() >= MAX_FOLDERS_PER_ORG {
                return Err(format!(
                    "An organization can mount at most {MAX_FOLDERS_PER_ORG} Drive folders."
                ));
            }
        }
        if matches!(p.kind.as_str(), "add_folder" | "assign") {
            for a in &p.agents {
                // Counted by row id: two rows on one Drive folder are two mounts.
                let already = st
                    .folders
                    .iter()
                    .filter(|(id, f)| f.agents.contains(&a.vm_id) && Some(id.as_str()) != folder_id)
                    .count();
                if already >= MAX_FOLDERS_PER_AGENT {
                    return Err(format!(
                        "An agent can mount at most {MAX_FOLDERS_PER_AGENT} Drive folders."
                    ));
                }
            }
        }
        Ok(())
    }

    /// The whole desired state of one agent box.
    #[cfg(test)]
    pub fn apply_body(&self, vm_id: &str) -> Value {
        let g = self.borrowed();
        self.apply_body_in(&self.lock().store, vm_id, g.as_ref())
    }

    fn apply_body_in(&self, st: &DriveStore, vm_id: &str, g: Option<&Borrowed>) -> Value {
        let agent = st.agents.get(vm_id);
        let folders = folders_for(st, vm_id);
        let account = folders.first().and_then(|f| st.accounts.get(&f.account_id));
        let narrowed = account.is_some_and(|a| Self::narrowed_to_read_only(a, g));
        json!({
            "placeholder": agent.map(|a| a.placeholder.clone()),
            "scope": account.map_or(DRIVE_WRITE_SCOPE.to_string(), |a| Self::effective_scope(a, g)),
            "connected": account.is_some_and(|a| self.token_of(a, g).is_some()),
            "defaults": {
                "exportFormats": DRIVE_EXPORT_FORMATS,
                "skipGdocs": DRIVE_SKIP_GDOCS,
                "vfsCacheMaxSize": DRIVE_VFS_CACHE_MAX_SIZE,
                "vfsCacheMinFreeSpace": DRIVE_VFS_CACHE_MIN_FREE_SPACE,
            },
            "mounts": folders.iter().map(|f| json!({
                "name": f.name,
                "folderId": f.folder_id,
                "mode": if narrowed { "ro" } else { f.mode.as_str() },
            })).collect::<Vec<_>>(),
        })
    }

    async fn push_agents(&self, vm_ids: &[String]) -> Vec<(String, String)> {
        let g = self.borrowed();
        let mut failed = vec![];
        for vm in vm_ids {
            let (target, body) = {
                let st = self.lock();
                let host = st.store.agents.get(vm).and_then(|a| a.hostname.clone());
                (
                    host.map(|h| Target::new(vm, &h)),
                    self.apply_body_in(&st.store, vm, g.as_ref()),
                )
            };
            let Some(target) = target else {
                failed.push((vm.clone(), "This agent has no hostname yet.".to_string()));
                continue;
            };
            if let Err(e) = self.opts.agent.post(&target, "/drive/apply", body, None).await {
                failed.push((vm.clone(), e.message));
            }
        }
        failed
    }

    fn mounting(st: &DriveStore) -> Vec<String> {
        st.agents
            .keys()
            .filter(|vm| !folders_for(st, vm).is_empty())
            .cloned()
            .collect()
    }

    fn agent_of(st: &mut DriveStore, r: &AgentRef) {
        let a = st.agents.entry(r.vm_id.clone()).or_insert_with(|| DriveAgent {
            name: r.name.clone(),
            hostname: r.hostname.clone(),
            placeholder: format!("CC-DRIVE-{}", hex::encode(rand::random::<[u8; 12]>())),
            extra: Map::new(),
        });
        if !r.name.is_empty() {
            a.name = r.name.clone();
        }
        if r.hostname.is_some() {
            a.hostname = r.hostname.clone();
        }
    }

    /// Make a change to the store as it is now, under one lock, and save it; then re-sync the proxy
    /// and push to everyone it touched, gone or arrived. A token a refresh recorded meanwhile is
    /// kept. `replaced`: the account itself went, so a refresh answer in flight is for the old one.
    async fn commit(
        &self,
        replaced: bool,
        change: impl FnOnce(&mut DriveStore) -> Result<Vec<String>, Failure>,
    ) -> Result<Map<String, Value>, Failure> {
        let targets = {
            let mut st = self.lock();
            let mut next = st.store.clone();
            let targets = change(&mut next)?;
            self.save(&next)?;
            if replaced {
                st.generation += 1;
            }
            st.store = next;
            targets
        };
        self.changed().await;
        let failed = self.push_agents(&targets).await;
        let mut m = Map::new();
        m.insert(
            "applied".into(),
            json!(
                targets
                    .iter()
                    .filter(|v| !failed.iter().any(|f| &f.0 == *v))
                    .collect::<Vec<_>>()
            ),
        );
        m.insert("failed".into(), failed_json(&failed));
        Ok(m)
    }

    fn affected(p: &Proposal, before: Vec<String>) -> Vec<String> {
        let mut out = before;
        for a in &p.agents {
            if !out.contains(&a.vm_id) {
                out.push(a.vm_id.clone());
            }
        }
        out
    }

    async fn apply(&self, p: &Proposal) -> Result<Map<String, Value>, Failure> {
        let now = iso(self.now());
        match p.kind.as_str() {
            "connect_account" | "replace_account" => self.connect(p).await,
            "forget_account" => {
                let out = self
                    .commit(true, |next| {
                        let before = Self::mounting(next);
                        next.accounts.clear();
                        next.folders.clear();
                        Ok(before)
                    })
                    .await?;
                tracing::info!("[drive] disconnected the Google account and dropped every folder");
                Ok(out)
            }
            "add_folder" => {
                let f = p.folder.as_ref().ok_or("the proposal is missing the folder")?;
                let (id, account) = {
                    let st = self.lock();
                    let (id, a) = st
                        .store
                        .accounts
                        .first()
                        .ok_or("Connect a Google account before adding folders.")?;
                    (id.clone(), a.clone())
                };
                self.assert_writable(f, &id, &account, true).await?;
                self.commit(false, |next| {
                    let before: Vec<String> = next.folders.get(&f.id).map(|r| r.agents.clone()).unwrap_or_default();
                    for a in &p.agents {
                        Self::agent_of(next, a);
                    }
                    let mut agents = before.clone();
                    for a in &p.agents {
                        if !agents.contains(&a.vm_id) {
                            agents.push(a.vm_id.clone());
                        }
                    }
                    next.folders.insert(
                        f.id.clone(),
                        DriveFolder {
                            account_id: id,
                            folder_id: f.folder_id.clone(),
                            name: f.name.clone(),
                            mode: f.mode.clone(),
                            agents,
                            updated_at: now,
                            extra: Map::new(),
                        },
                    );
                    Ok(Self::affected(p, before))
                })
                .await
            }
            "edit_folder" => {
                let f = p.folder.as_ref().ok_or("the proposal is missing the folder")?;
                let (row, account) = {
                    let st = self.lock();
                    let row = st
                        .store
                        .folders
                        .get(&f.id)
                        .cloned()
                        .ok_or("That folder is not set up on the firewall. Add it again.")?;
                    (row, st.store.accounts.first().map(|(i, a)| (i.clone(), a.clone())))
                };
                // Only when it is becoming writable: re-probing on every rename would put a file in
                // somebody's Drive for no reason.
                if f.mode == "rw"
                    && row.mode != "rw"
                    && let Some((id, a)) = &account
                {
                    self.assert_writable(f, id, a, false).await?;
                }
                self.commit(false, |next| {
                    let r = next
                        .folders
                        .get_mut(&f.id)
                        .ok_or("That folder is not set up on the firewall. Add it again.")?;
                    let before = r.agents.clone();
                    r.name = f.name.clone();
                    r.mode = f.mode.clone();
                    r.updated_at = now;
                    Ok(Self::affected(p, before))
                })
                .await
            }
            "remove_folder" => {
                let f = p.folder.as_ref().ok_or("the proposal is missing the folder")?;
                self.commit(false, |next| {
                    let before = next.folders.shift_remove(&f.id).map(|r| r.agents).unwrap_or_default();
                    Ok(Self::affected(p, before))
                })
                .await
            }
            _ => {
                // assign / unassign
                let f = p.folder.as_ref().ok_or("the proposal is missing the folder")?;
                self.commit(false, |next| {
                    let before = next
                        .folders
                        .get(&f.id)
                        .map(|r| r.agents.clone())
                        .ok_or("That folder is not set up on the firewall. Add it again.")?;
                    if p.kind == "assign" {
                        for a in &p.agents {
                            Self::agent_of(next, a);
                        }
                    }
                    let r = next
                        .folders
                        .get_mut(&f.id)
                        .ok_or("That folder is not set up on the firewall. Add it again.")?;
                    if p.kind == "assign" {
                        for a in &p.agents {
                            if !r.agents.contains(&a.vm_id) {
                                r.agents.push(a.vm_id.clone());
                            }
                        }
                    } else {
                        r.agents.retain(|v| !p.agents.iter().any(|a| &a.vm_id == v));
                    }
                    r.updated_at = now;
                    Ok(Self::affected(p, before))
                })
                .await
            }
        }
    }

    /// Check the credential against Google before anything is stored, then replace the account.
    async fn connect(&self, p: &Proposal) -> Result<Map<String, Value>, Failure> {
        let a = p.account.as_ref().ok_or("the proposal is missing the account")?;
        let id = p.account_id.clone().unwrap_or_else(|| "account".into());
        let borrowing = a.kind == "google_account";
        if !borrowing && p.secret.is_none() {
            return Err("the proposal is missing the account or its secret".into());
        }
        let g = self.borrowed();
        let mut account = DriveAccount {
            kind: a.kind.clone(),
            account_label: if borrowing {
                g.as_ref()
                    .and_then(|g| g.account_label.clone())
                    .or_else(|| a.account_label.clone())
            } else {
                a.account_label.clone()
            },
            scope: a.scope.clone(),
            oauth: a.oauth.clone(),
            secret: if borrowing { None } else { p.secret.clone() },
            access: None,
            failed: None,
            updated_at: iso(self.now()),
            extra: Map::new(),
        };
        let token = if borrowing {
            g.as_ref().and_then(|g| g.token.clone()).ok_or_else(|| {
                Failure::from(
                    Self::borrowed_problem(g.as_ref())
                        .unwrap_or_else(|| "Your Google account has no working token right now.".into()),
                )
            })?
        } else {
            let minted = tokens::mint(&*self.opts.http, &account, self.now()).await;
            match minted.mint {
                Mint::Err { rate_limited: true, .. } => {
                    return Err(transient(rate_limited_message(label_of(&account).as_deref(), None)));
                }
                Mint::Err { reason, .. } => return Err(format!("Google refused this connection: {reason}").into()),
                Mint::Ok { token, expires, .. } => {
                    cc_crypto::enc_file::remember_encrypted_secrets(&json!(token), true);
                    account.access = Some(AccessToken {
                        token: token.clone(),
                        expires,
                    });
                    if let Some(sec) = minted.secret {
                        account.secret = Some(sec);
                    }
                    if let Some(l) = minted.account_label {
                        account.account_label = Some(l);
                    }
                    token
                }
            }
        };
        match tokens::probe_drive(&*self.opts.http, &token).await {
            Err((true, reason)) => {
                return Err(if borrowing {
                    format!("Drive does not answer for your Google account: {reason}")
                } else {
                    format!("The key works, but Drive does not answer for it: {reason}")
                }
                .into());
            }
            Err((false, reason)) => {
                tracing::info!("[drive] Drive did not answer the check ({reason}); storing the connection anyway")
            }
            Ok(()) => {}
        }
        let existed = !self.lock().store.accounts.is_empty();
        let stored = account.clone();
        let mut out = self
            .commit(true, |next| {
                next.accounts = IndexMap::from([(id.clone(), stored)]);
                for f in next.folders.values_mut() {
                    f.account_id = id.clone();
                }
                Ok(Self::mounting(next))
            })
            .await?;
        tracing::info!(
            "[drive] connected {} {} ({})",
            account.kind,
            account.account_label.as_deref().unwrap_or(""),
            if existed { "replaced" } else { "new" }
        );
        out.insert("accountId".into(), json!(id));
        out.insert("kind".into(), json!(account.kind));
        out.insert("accountLabel".into(), json!(account.account_label));
        Ok(out)
    }

    /// Refuse a read-write folder the identity cannot actually write to, with Google's reason.
    async fn assert_writable(
        &self,
        f: &ProposedFolder,
        id: &str,
        account: &DriveAccount,
        adding: bool,
    ) -> Result<(), Failure> {
        if f.mode != "rw" {
            return Ok(());
        }
        let hint = if adding {
            "add the folder read-only"
        } else {
            "keep the folder read-only"
        };
        if account.failed.is_some() {
            return Err(
                "This Google connection is not working. Connect the account again, then add the folder.".into(),
            );
        }
        let g = self.borrowed();
        let token = if account.kind == "google_account" {
            if let Some(problem) = Self::borrowed_problem(g.as_ref()) {
                return Err(problem.into());
            }
            g.as_ref().and_then(|g| g.token.clone()).unwrap_or_default()
        } else {
            match account.access.as_ref().filter(|t| t.expires - self.now() > 60_000) {
                Some(t) => t.token.clone(),
                None => {
                    let minted = tokens::mint(&*self.opts.http, account, self.now()).await;
                    let token = match &minted.mint {
                        Mint::Err { rate_limited: true, .. } => {
                            return Err(transient(rate_limited_message(
                                label_of(account).as_deref(),
                                Some(hint),
                            )));
                        }
                        Mint::Err { reason, .. } => {
                            return Err(format!("Google would not give this connection a token: {reason}").into());
                        }
                        Mint::Ok { token, .. } => token.clone(),
                    };
                    // Through `record`: an OAuth provider can rotate the refresh token on use.
                    let mut st = self.lock();
                    let mut next = st.store.clone();
                    if let Some(a) = next.accounts.get_mut(id)
                        && self.record(id, a, minted)
                        && self.save(&next).is_ok()
                    {
                        st.store = next;
                    }
                    token
                }
            }
        };
        let can =
            tokens::probe_folder_write(self.opts.http.clone(), &token, &f.folder_id, &self.opts.write_check).await;
        let WriteCheck::Refused {
            kind,
            transient: tr,
            reason,
        } = can
        else {
            return Ok(());
        };
        let label = if account.kind == "google_account" {
            g.as_ref()
                .and_then(|g| g.account_label.clone())
                .or_else(|| account.account_label.clone())
        } else {
            label_of(account)
        };
        if kind == DriveErrorKind::RateLimited {
            return Err(transient(rate_limited_message(label.as_deref(), Some(hint))));
        }
        if tr {
            return Err(transient(format!(
                "{} could not be checked for writing. {reason} Try again in a few minutes, or {hint}.",
                f.name
            )));
        }
        let why = why_writes_fail(&account.kind, kind, label.as_deref());
        Err(format!(
            "{} cannot be mounted read-write. {reason}{}",
            f.name,
            if why.is_empty() {
                String::new()
            } else {
                format!(" {why}")
            }
        )
        .into())
    }

    /// The org Google account moved (T-78): re-push to every borrower, compared on a fingerprint
    /// persisted at the last push, so the hourly token refresh does not re-push anything.
    pub async fn on_google_account_changed(&self) {
        let g = self.borrowed();
        let targets = {
            let mut st = self.lock();
            if !st.store.accounts.values().any(|a| a.kind == "google_account") {
                return;
            }
            let stamp = format!(
                "{}|{}|{}",
                if g.as_ref().is_some_and(|g| g.token.is_some()) {
                    "live"
                } else {
                    "dead"
                },
                g.as_ref().and_then(|g| g.drive_scope).unwrap_or("none"),
                g.as_ref().and_then(|g| g.account_label.clone()).unwrap_or_default()
            );
            if st.store.borrowed_stamp.as_deref() == Some(stamp.as_str()) {
                return;
            }
            let mut next = st.store.clone();
            next.borrowed_stamp = Some(stamp.clone());
            if self.save(&next).is_err() {
                return;
            }
            st.store = next;
            let targets = Self::mounting(&st.store);
            if !targets.is_empty() {
                tracing::info!(
                    "[drive] the Google account changed ({stamp}); re-applying {} agent(s)",
                    targets.len()
                );
            }
            targets
        };
        if targets.is_empty() {
            return;
        }
        let failed = self.push_agents(&targets).await;
        if let Some(f) = failed.first() {
            tracing::info!(
                "[drive] could not re-apply on {}: {}",
                failed.iter().map(|f| f.0.as_str()).collect::<Vec<_>>().join(", "),
                f.1
            );
        }
    }

    /// Keep every account's own access token live. Borrowed ones are the Google module's.
    pub async fn refresh_due(&self) {
        if self.minting.swap(true, Ordering::SeqCst) {
            return;
        }
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _done = Done(&self.minting);
        let due: Vec<(String, DriveAccount, u64)> = {
            let st = self.lock();
            let now = self.now();
            st.store
                .accounts
                .iter()
                .filter(|(_, a)| a.failed.is_none() && a.kind != "google_account")
                .filter(|(_, a)| {
                    a.access
                        .as_ref()
                        .is_none_or(|t| t.expires - now <= DRIVE_REFRESH_AHEAD_MS)
                })
                .map(|(id, a)| (id.clone(), a.clone(), st.generation))
                .collect()
        };
        let mut changed = false;
        for (id, account, generation) in due {
            let minted = tokens::mint(&*self.opts.http, &account, self.now()).await;
            let mut st = self.lock();
            if st.generation != generation || !st.store.accounts.contains_key(&id) {
                tracing::info!("[drive] token answer for {id} arrived after the account was replaced; dropped");
                continue;
            }
            let mut next = st.store.clone();
            let Some(a) = next.accounts.get_mut(&id) else { continue };
            if self.record(&id, a, minted) && self.save(&next).is_ok() {
                st.store = next;
                changed = true;
            }
        }
        if changed {
            self.changed().await;
        }
    }

    fn record(&self, id: &str, a: &mut DriveAccount, minted: tokens::Minted) -> bool {
        match minted.mint {
            Mint::Err {
                permanent: false,
                reason,
                ..
            } => {
                tracing::info!(
                    "[drive] token for {} failed ({reason}); will retry",
                    a.account_label.as_deref().unwrap_or(id)
                );
                false
            }
            Mint::Err { reason, .. } => {
                let failed = format!("Google refused the connection: {reason}. Connect the account again.");
                a.failed = Some(failed.clone());
                a.access = None;
                let mut data = Map::new();
                data.insert("accountId".into(), json!(id));
                self.reports
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(CommandResult {
                        command_id: format!("drive.token:{id}"),
                        ok: false,
                        status: "failed".into(),
                        message: failed,
                        data: Some(data),
                    });
                tracing::info!(
                    "[drive] token for {} refused: {reason}",
                    a.account_label.as_deref().unwrap_or(id)
                );
                true
            }
            Mint::Ok { token, expires, .. } => {
                cc_crypto::enc_file::remember_encrypted_secrets(&json!(token), true);
                a.access = Some(AccessToken { token, expires });
                if let Some(sec) = minted.secret {
                    a.secret = Some(sec);
                }
                a.updated_at = iso(self.now());
                tracing::info!(
                    "[drive] minted a token for {} (expires in {} min)",
                    a.account_label.as_deref().unwrap_or(id),
                    ((expires - self.now()) as f64 / 60_000.0).round()
                );
                true
            }
        }
    }
}

#[cfg(test)]
mod tests;
