//! Website logins, held on the firewall (`logins.ts`, docs/plans/website-credentials.md). A login
//! is a username and password for some sites, and the agents allowed to use it. The agent never
//! gets the password: it gets a placeholder of the same shape, types that into the sign-in form,
//! and the proxy swaps the real password in on the way out, only on the login's own sites.
//!
//! Who can do what:
//!   - create, replace a password, delete: an owner or admin on the firewall's own page, in an
//!     enrolled browser (`web.rs`). The control plane never carries a password.
//!   - change the name, sites or agents from the console (`logins.propose`): free when it
//!     narrows, a confirmation code when it reaches a new site or a new agent.
//!   - delete from the console: free, like every change that only takes access away.
//!   - use: an agent named on the login, through the tools on the private network (`mcp.rs`).
//!   - ask: an agent may ask for a login it does not have (`login_request`): a request that lives
//!     30 minutes, in memory only, and a console link for the agent to send.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::onepassword::{OnePassword, OpVault};
use super::placeholder::{make_placeholder, placeholder_fits};
use super::schema::{
    self, Change, Entry, Issue, LEARNED_TARGET_KEEP_MS, LEARNED_TARGET_TTL_MS, LEARNED_TARGETS_MAX, LOGIN_LIMIT,
    login_widens, sign_in_page_ok, site_matches,
};
use super::totp::{Totp, parse_totp, totp_code};
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::contracts::{CredentialContributor, CredentialOrder};
use crate::integrations::codes::{Codes, Verified};
use crate::integrations::ordmap::OrdMap;
use crate::integrations::{as_map, js, outcome};

/// How long a chat request can be answered.
pub const REQUEST_TTL_MS: i64 = 30 * 60_000;
/// Open requests per agent: enough for a real task, too few to flood anyone with links.
pub const REQUESTS_PER_AGENT: usize = 5;
const REFUSED_TARGETS_MAX: usize = 20;
const STORE: &str = "logins";
/// What a change says when the store could not be written (never the disk's own error text).
pub const SAVE_FAILED: &str =
    "This firewall could not save its logins, so the change was not kept. Try again in a minute.";
/// The TS's scope (`login:<id>`), under this module's name on the one `ConsentCodes`.
const SCOPE_PREFIX: &str = "logins:login:";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub kind: String,
    pub vault_id: String,
    pub item_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One login as the store keeps it, in the order the TS writes its fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Stored {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub name: String,
    pub sites: Vec<String>,
    #[serde(default)]
    pub login_url: Option<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in_paths: Option<Vec<String>>,
    /// Sign-in targets the proxy read off the sign-in page: address → when last seen (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned: Option<OrdMap<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned_fields: Option<OrdMap<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_targets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url_pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_targets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Option<Source>>,
    #[serde(default)]
    pub vm_ids: Vec<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
    /// Empty for a session login.
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp: Option<Totp>,
    /// vmId → the placeholder that agent types.
    #[serde(default)]
    pub placeholders: OrdMap<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Stored {
    fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or("password")
    }
    fn auth(&self) -> &str {
        self.auth.as_deref().unwrap_or("form")
    }
    fn op_source(&self) -> Option<&Source> {
        self.source
            .as_ref()
            .and_then(|s| s.as_ref())
            .filter(|s| s.kind == "1password")
    }
    fn approved(&self, url: &str) -> bool {
        self.approved_targets
            .as_ref()
            .is_some_and(|a| a.iter().any(|u| u == url))
    }
}

/// One connection, not a later one made in its place: the same token, vaults and time it was made.
fn same_connection(a: &OnePasswordSource, b: &OnePasswordSource) -> bool {
    use sha2::{Digest, Sha256};
    let h = |t: &str| -> [u8; 32] { Sha256::digest(t.as_bytes()).into() };
    cc_crypto::ct_eq(&h(&a.token), &h(&b.token)) && a.vaults == b.vaults && a.added_at == b.added_at
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnePasswordSource {
    pub vaults: Vec<Value>,
    pub vm_ids: Vec<String>,
    pub added_by: Option<String>,
    pub added_at: String,
    pub last_sync_at: Option<String>,
    pub last_error: Option<String>,
    pub items: u64,
    pub token: String,
    /// Items read and not used, by `vault/item` → when they last changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unused: Option<OrdMap<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Store {
    pub version: u32,
    pub logins: OrdMap<Stored>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_password: Option<Option<OnePasswordSource>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            logins: OrdMap::new(),
            one_password: None,
            extra: Map::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginRequest {
    pub id: String,
    pub vm_id: String,
    pub site: String,
    pub kind: String,
    pub reason: String,
    pub url: Option<String>,
    pub task: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    /// Set once answered: the login that was saved, or the session that was recorded.
    pub login_id: Option<String>,
}

/// `Date.now`, or the tests' clock.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A learned target counts only as an https address on one of the login's sites that the owner
/// did not remove.
fn target_fits(login: &Stored, url: &str) -> bool {
    if login
        .refused_targets
        .as_ref()
        .is_some_and(|r| r.iter().any(|u| u == url))
    {
        return false;
    }
    sign_in_page_ok(Some(url))
        && url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| site_matches(&login.sites, h)))
            .unwrap_or(false)
}

/// A login the proxy puts in with no sign-in page it can read: its password goes nowhere until the
/// owner adds one. Google's own sign-in is known to the proxy without one.
fn needs_sign_in_page(login: &Stored) -> bool {
    if login.kind() == "session" || login.mode == "type" || login.auth() == "basic" {
        return false;
    }
    if sign_in_page_ok(login.login_url.as_deref()) {
        return false;
    }
    !(login.sites.len() == 1 && login.sites[0] == "accounts.google.com")
}

fn new_id(prefix: &str) -> String {
    use base64::Engine;
    format!(
        "{prefix}_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>())
    )
}

fn remember(secret: &str) {
    cc_crypto::enc_file::remember_encrypted_secrets(&Value::String(secret.into()), true);
}

/// What the page and the agents' tools get back from a use of a login.
#[derive(Debug, Clone, PartialEq)]
pub struct Use {
    pub id: String,
    pub name: String,
    pub username: String,
    pub placeholder: Option<String>,
    pub sites: Vec<String>,
    pub login_url: Option<String>,
    pub totp: bool,
    pub auth: String,
    pub needs_sign_in_page: bool,
}

pub struct LoginsFirewall {
    app: Arc<App>,
    path: PathBuf,
    aad: String,
    store: RwLock<Store>,
    serial: tokio::sync::Mutex<()>,
    saving: Mutex<()>,
    requests: Mutex<Vec<LoginRequest>>,
    op_syncing: tokio::sync::Mutex<()>,
    log_path: Option<PathBuf>,
    targets_path: Option<PathBuf>,
    op: OnePassword,
    now: Clock,
}

/// An error a person reads, or a check that failed (the page says which field).
#[derive(Debug, Clone, PartialEq)]
pub enum Refused {
    Message(String),
    Invalid(Issue),
}

impl From<Issue> for Refused {
    fn from(i: Issue) -> Self {
        Refused::Invalid(i)
    }
}

fn say<T>(m: &str) -> Result<T, Refused> {
    Err(Refused::Message(m.into()))
}

impl LoginsFirewall {
    pub fn new(
        app: &Arc<App>,
        path: PathBuf,
        log_path: Option<PathBuf>,
        targets_path: Option<PathBuf>,
    ) -> Result<Arc<Self>, String> {
        Self::with_clock(app, path, log_path, targets_path, Arc::new(js::now_ms))
    }

    pub fn with_clock(
        app: &Arc<App>,
        path: PathBuf,
        log_path: Option<PathBuf>,
        targets_path: Option<PathBuf>,
        now: Clock,
    ) -> Result<Arc<Self>, String> {
        let aad = format!("{}:{}:logins", app.config.org_id, app.config.box_id);
        let log = |l: &str| tracing::info!("{l}");
        let store = match cc_crypto::enc_file::load_store_or_empty(STORE, &path, &app.box_key, &aad, &log) {
            None => Store::default(),
            Some(v) => {
                if v.get("version") != Some(&json!(1)) {
                    return Err("Unsupported logins store".into());
                }
                serde_json::from_value::<Store>(v).map_err(|_| "the logins store does not read".to_string())?
            }
        };
        if let Some(Some(op)) = &store.one_password {
            remember(&op.token);
        }
        for l in store.logins.values() {
            if !l.password.is_empty() {
                remember(&l.password);
            }
            if let Some(t) = &l.totp {
                remember(&t.secret);
            }
        }
        Ok(Arc::new(Self {
            op: OnePassword::new(app.runner.clone()),
            app: app.clone(),
            path,
            aad,
            store: RwLock::new(store),
            serial: tokio::sync::Mutex::new(()),
            saving: Mutex::new(()),
            requests: Mutex::new(Vec::new()),
            op_syncing: tokio::sync::Mutex::new(()),
            log_path,
            targets_path,
            now,
        }))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Store> {
        self.store.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Store> {
        self.store.write().unwrap_or_else(|e| e.into_inner())
    }

    /// The copy and the write under one lock: two saves never land out of order, so the file is
    /// never an older store than the one in memory.
    /// A store the disk did not take is an error for the change that made it (`saveStore` throws).
    fn save(&self) -> Result<(), Refused> {
        let _one = self.saving.lock().unwrap_or_else(|e| e.into_inner());
        let v = serde_json::to_value(&*self.read()).unwrap_or(Value::Null);
        cc_crypto::enc_file::save_store(STORE, &self.path, &v, &self.app.box_key, &self.aad).map_err(|e| {
            tracing::error!("[logins] could not save: {}", e.0);
            Refused::Message(SAVE_FAILED.into())
        })
    }

    fn iso(&self) -> String {
        js::iso((self.now)())
    }

    fn agents(&self) -> Vec<crate::contracts::AgentIdentity> {
        self.app
            .contracts
            .identities
            .require()
            .ok()
            .map(|i| i.agents())
            .unwrap_or_default()
    }

    fn agent_name(&self, vm_id: &str) -> String {
        self.agents()
            .into_iter()
            .find(|a| a.vm_id == vm_id)
            // `name || hostname || vmId`: an empty one counts as none.
            .and_then(|a| {
                a.name
                    .filter(|n| !n.is_empty())
                    .or(a.hostname.filter(|h| !h.is_empty()))
            })
            .unwrap_or_else(|| vm_id.to_string())
    }

    fn live_agent(&self, vm_id: &str) -> bool {
        self.agents().iter().any(|a| a.vm_id == vm_id)
    }

    fn has_target(&self, vm_id: &str) -> bool {
        self.agents()
            .into_iter()
            .any(|a| a.vm_id == vm_id && a.hostname.is_some_and(|h| !h.is_empty()))
    }

    async fn post_agent(&self, vm_id: &str, path: &str, body: Value) -> Result<Map<String, Value>, String> {
        let Some(c) = self.app.contracts.agents.get() else {
            return Err("This firewall cannot reach its agents yet.".into());
        };
        c.post(vm_id, path, body).await.map_err(|e| e.message)
    }

    async fn credentials_changed(&self) {
        match self.app.contracts.credentials_sync.get() {
            Some(s) => s.changed().await,
            // Nothing on this build writes the proxy's credentials now: a login taken away stays in
            // the proxy until the next full sync. Said, never silent.
            None => tracing::error!(
                "[logins] the proxy's credentials could not be written again: no credentials sync on this build"
            ),
        }
    }

    // ---- what others read ----

    /// Targets the owner allowed that have not been on the sign-in page for 30 days.
    fn expired_of(&self, login: &Stored) -> Vec<(String, f64)> {
        let now = (self.now)() as f64;
        login
            .learned
            .iter()
            .flat_map(|l| l.iter())
            .filter(|(url, at)| {
                **at + LEARNED_TARGET_TTL_MS as f64 <= now
                    && **at + LEARNED_TARGET_KEEP_MS as f64 > now
                    && login.approved(url)
                    && target_fits(login, url)
            })
            .map(|(u, a)| (u.clone(), *a))
            .collect()
    }

    /// A login's learned sign-in targets that still count: seen in the last 30 days, on its sites,
    /// newest first.
    fn learned_of(&self, login: &Stored) -> Vec<(String, f64)> {
        let now = (self.now)() as f64;
        let mut v: Vec<(String, f64)> = login
            .learned
            .iter()
            .flat_map(|l| l.iter())
            .filter(|(url, at)| **at + LEARNED_TARGET_TTL_MS as f64 > now && target_fits(login, url))
            .map(|(u, a)| (u.clone(), *a))
            .collect();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        v.truncate(LEARNED_TARGETS_MAX);
        v
    }

    pub fn metadata(&self, l: &Stored) -> Value {
        let field = |url: &str| {
            l.learned_fields
                .as_ref()
                .and_then(|f| f.get(url).cloned())
                .map(Value::String)
                .unwrap_or(Value::Null)
        };
        let mut targets: Vec<Value> = self
            .learned_of(l)
            .into_iter()
            .map(|(url, at)| json!({"url": url, "seenAt": js::iso(at as i64), "approved": l.approved(&url), "expired": false, "field": field(&url)}))
            .collect();
        targets.extend(
            self.expired_of(l)
                .into_iter()
                .map(|(url, at)| json!({"url": url, "seenAt": js::iso(at as i64), "approved": true, "expired": true, "field": field(&url)})),
        );
        // `{...rest}`: what the store has (unknown fields too), less what is secret or internal.
        let mut m = as_map(serde_json::to_value(l).unwrap_or(Value::Null));
        for k in [
            "password",
            "placeholders",
            "totp",
            "source",
            "learned",
            "learnedFields",
            "refusedTargets",
            "approvedTargets",
            "loginUrlPinned",
        ] {
            m.shift_remove(k);
        }
        m.insert("kind".into(), json!(l.kind()));
        m.insert("auth".into(), json!(l.auth()));
        m.insert("signInPaths".into(), json!(l.sign_in_paths.clone().unwrap_or_default()));
        m.insert("learnedTargets".into(), Value::Array(targets));
        m.insert("needsSignInPage".into(), json!(needs_sign_in_page(l)));
        m.insert("totp".into(), json!(l.totp.is_some()));
        m.insert(
            "source".into(),
            json!(if l.op_source().is_some() { "1password" } else { "vault" }),
        );
        Value::Object(m)
    }

    pub fn summary(&self) -> Map<String, Value> {
        let st = self.read();
        let mut logins: Vec<&Stored> = st.logins.values().collect();
        logins.sort_by(|a, b| js::locale_compare(&a.name, &b.name));
        let list: Vec<Value> = logins.iter().map(|l| self.metadata(l)).collect();
        drop(st);
        as_map(json!({"logins": list, "onePassword": self.one_password_status()}))
    }

    pub fn one_password_status(&self) -> Value {
        match &self.read().one_password {
            Some(Some(op)) => {
                let mut v = as_map(serde_json::to_value(op).unwrap_or(Value::Null));
                v.shift_remove("token");
                v.shift_remove("unused");
                Value::Object(v)
            }
            _ => Value::Null,
        }
    }

    pub fn get(&self, id: &str) -> Option<Value> {
        self.read().logins.get(id).map(|l| self.metadata(l))
    }

    /// One proxy entry per login and agent: the placeholder that agent types and where it may go.
    pub fn credentials(&self) -> Vec<Value> {
        let st = self.read();
        let mut out = Vec::new();
        for l in st.logins.values() {
            for vm in &l.vm_ids {
                let Some(ph) = l.placeholders.get(vm) else { continue };
                if l.kind() == "session" || l.mode == "type" || l.password.is_empty() {
                    continue;
                }
                let learned = self.learned_of(l);
                let fields: Map<String, Value> = learned
                    .iter()
                    .filter_map(|(u, _)| l.learned_fields.as_ref()?.get(u).map(|f| (u.clone(), json!(f))))
                    .collect();
                out.push(json!({
                    "login_id": l.id,
                    "login_name": l.name,
                    "vm_id": vm,
                    "placeholder": ph,
                    "secret": l.password,
                    "allowed_hosts": l.sites,
                    "login_url": l.login_url,
                    "login_auth": l.auth(),
                    "sign_in_paths": l.sign_in_paths.clone().unwrap_or_default(),
                    "sign_in_targets": learned.iter().filter(|(u, _)| l.approved(u)).map(|(u, _)| u.clone()).collect::<Vec<_>>(),
                    "pending_targets": learned.iter().filter(|(u, _)| !l.approved(u)).map(|(u, _)| u.clone()).collect::<Vec<_>>(),
                    "expired_targets": self.expired_of(l).into_iter().map(|(u, _)| u).collect::<Vec<_>>(),
                    "sign_in_fields": fields,
                    "refused_targets": l.refused_targets.clone().unwrap_or_default(),
                }));
            }
        }
        out
    }

    /// Take in what the proxy read off sign-in pages since the last look. Returns whether anything
    /// changed.
    pub async fn ingest_learned_targets(&self) -> bool {
        let _one = self.serial.lock().await;
        let Some(path) = &self.targets_path else { return false };
        let Some(seen) = cc_store::read_json::<Value>(path) else {
            return false;
        };
        let Some(seen) = seen.as_object() else { return false };
        let now = (self.now)();
        let mut changed = false;
        let mut added = false;
        {
            let mut st = self.write();
            for (id, entry) in seen {
                let Some(login) = st.logins.get(id).cloned() else {
                    continue;
                };
                // `entry.page !== login.loginUrl`: a missing page never matches, null matches null.
                let page_matches = entry.get("page") == Some(&json!(login.login_url));
                let Some(targets) = entry.get("targets").and_then(Value::as_object).filter(|_| page_matches) else {
                    continue;
                };
                let mut learned = login.learned.clone().unwrap_or_default();
                let mut fields = login.learned_fields.clone().unwrap_or_default();
                let before: Vec<String> = self.learned_of(&login).into_iter().map(|(u, _)| u).collect();
                for (url, sighting) in targets {
                    let ms = sighting
                        .get("seen")
                        .and_then(Value::as_f64)
                        .map(|s| (s * 1000.0 + 0.5).floor())
                        .unwrap_or(0.0);
                    let top = url::Url::parse(url).map(|u| u.path() == "/").unwrap_or(true);
                    // The top of a site is not a sign-in address a page can teach.
                    if ms == 0.0 || ms > (now + 60_000) as f64 || !target_fits(&login, url) || top {
                        continue;
                    }
                    let field = sighting
                        .get("field")
                        .and_then(Value::as_str)
                        .filter(|f| f.encode_utf16().count() <= 200)
                        .unwrap_or("");
                    let had = learned.get(url).copied().unwrap_or(0.0);
                    if had < ms || (!field.is_empty() && fields.get(url).map(String::as_str) != Some(field)) {
                        learned.insert(url.clone(), had.max(ms));
                        if !field.is_empty() {
                            fields.insert(url.clone(), field.into());
                        }
                        changed = true;
                    }
                }
                let mut next = login.clone();
                next.learned = Some(learned.clone());
                next.learned_fields = Some(fields.clone());
                // Back on the page (or new): the proxy is told.
                if self.learned_of(&next).iter().any(|(u, _)| !before.contains(u)) {
                    added = true;
                }
                let keep: Vec<String> = self
                    .learned_of(&next)
                    .into_iter()
                    .chain(self.expired_of(&next))
                    .map(|(u, _)| u)
                    .collect();
                let mut learned2 = OrdMap::new();
                let mut fields2 = OrdMap::new();
                for (u, at) in learned.iter() {
                    if keep.contains(u) {
                        learned2.insert(u.clone(), *at);
                        if let Some(f) = fields.get(u) {
                            fields2.insert(u.clone(), f.clone());
                        }
                    }
                }
                if let Some(l) = st.logins.get_mut(id) {
                    l.learned = Some(learned2);
                    l.learned_fields = Some(fields2);
                }
            }
        }
        if changed && self.save().is_err() {
            return false;
        }
        if added {
            self.credentials_changed().await;
        }
        changed
    }

    /// The firewall page: set a login's extra sign-in paths and remove learned targets.
    pub async fn set_scope(&self, raw: &Value) -> Result<Value, Refused> {
        let _one = self.serial.lock().await;
        let edit = schema::parse_scope_edit(raw)?;
        let name;
        {
            let mut st = self.write();
            let Some(login) = st.logins.get_mut(&edit.id) else {
                return say("That login is gone.");
            };
            if login.kind() == "session" {
                return say("A login the agent was signed in to by a person has no password to put in.");
            }
            if let Some(url) = &edit.login_url
                && *url != login.login_url
            {
                // Targets were read off the old sign-in page: a new page starts again.
                login.login_url = url.clone();
                login.learned = Some(OrdMap::new());
                login.learned_fields = Some(OrdMap::new());
                login.approved_targets = Some(vec![]);
                login.refused_targets = Some(vec![]);
                if login.op_source().is_some() {
                    login.login_url_pinned = Some(url.is_some());
                }
            }
            if let Some(a) = &edit.auth {
                login.auth = Some(a.clone());
            }
            let mut paths: Vec<String> = Vec::new();
            for p in &edit.sign_in_paths {
                if !paths.contains(p) {
                    paths.push(p.clone());
                }
            }
            login.sign_in_paths = Some(paths);
            for url in &edit.forget {
                if !login.learned.as_ref().is_some_and(|l| l.contains_key(url)) {
                    continue;
                }
                if let Some(l) = login.learned.as_mut() {
                    l.remove(url);
                }
                login.approved_targets = Some(
                    login
                        .approved_targets
                        .clone()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|u| u != url)
                        .collect(),
                );
                let mut refused = login.refused_targets.clone().unwrap_or_default();
                if !refused.contains(url) {
                    refused.push(url.clone());
                }
                let skip = refused.len().saturating_sub(REFUSED_TARGETS_MAX);
                login.refused_targets = Some(refused.into_iter().skip(skip).collect());
            }
            for url in &edit.approve {
                let known = login.learned.as_ref().is_some_and(|l| l.contains_key(url));
                if known && target_fits(login, url) {
                    let mut a = login.approved_targets.clone().unwrap_or_default();
                    if !a.contains(url) {
                        a.push(url.clone());
                    }
                    login.approved_targets = Some(a);
                }
            }
            let learned = login.learned.clone().unwrap_or_default();
            login.approved_targets = Some(
                login
                    .approved_targets
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|u| learned.contains_key(u))
                    .collect(),
            );
            login.updated_at = js::iso((self.now)());
            name = login.name.clone();
        }
        self.save()?;
        self.credentials_changed().await;
        self.record(
            None,
            "/scope",
            &format!("login {name}: sign-in paths changed on the firewall page"),
            &name,
            None,
        );
        Ok(self.get(&edit.id).unwrap_or(Value::Null))
    }

    /// The logins an agent may use, without anything secret, by name (`localeCompare`).
    pub fn list_for(&self, vm_id: &str) -> Vec<Value> {
        let st = self.read();
        let mut mine: Vec<&Stored> = st
            .logins
            .values()
            .filter(|l| l.vm_ids.iter().any(|v| v == vm_id))
            .collect();
        mine.sort_by(|a, b| js::locale_compare(&a.name, &b.name));
        mine.iter()
            .map(|l| json!({"id": l.id, "name": l.name, "sites": l.sites, "loginUrl": l.login_url, "username": l.username, "kind": l.kind(), "totp": l.totp.is_some()}))
            .collect()
    }

    fn find_id(&self, vm_id: &str, which: &str) -> Option<String> {
        let st = self.read();
        let mine: Vec<&Stored> = st
            .logins
            .values()
            .filter(|l| l.vm_ids.iter().any(|v| v == vm_id))
            .collect();
        if let Some(l) = mine.iter().find(|l| l.id == which) {
            return Some(l.id.clone());
        }
        let want = js::trim(which).to_lowercase();
        let by_name: Vec<&&Stored> = mine.iter().filter(|l| l.name.to_lowercase() == want).collect();
        (by_name.len() == 1).then(|| by_name[0].id.clone())
    }

    /// What an agent needs to sign in: the username and its placeholder. None when the agent may
    /// not use such a login.
    pub async fn use_login(&self, vm_id: &str, which: &str) -> Option<Use> {
        // One at a time with the page's saves: a placeholder made here is never lost to a replace.
        let _one = self.serial.lock().await;
        let id = self.find_id(vm_id, which)?;
        let login = self.read().logins.get(&id).cloned()?;
        if login.kind() == "session" {
            return None;
        }
        let mut u = Use {
            id: login.id.clone(),
            name: login.name.clone(),
            username: login.username.clone(),
            placeholder: None,
            sites: login.sites.clone(),
            login_url: login.login_url.clone(),
            totp: login.totp.is_some(),
            auth: login.auth().to_string(),
            needs_sign_in_page: false,
        };
        if needs_sign_in_page(&login) {
            // Nothing is handed over: the proxy would refuse the sign-in anyway.
            self.record(
                Some(vm_id),
                "/use",
                &format!("login {}: not handed to the agent, it has no sign-in page", login.name),
                &login.name,
                Some("block"),
            );
            u.auth = "form".into();
            u.needs_sign_in_page = true;
            return Some(u);
        }
        let iso = self.iso();
        if login.mode == "type" {
            if let Some(l) = self.write().logins.get_mut(&id) {
                l.last_used_at = Some(iso);
            }
            // Only when it was last used: a sign-in is not refused over that.
            let _ = self.save();
            self.record(
                Some(vm_id),
                "/use",
                &format!("login {}: handed to the agent (type mode)", login.name),
                &login.name,
                None,
            );
            return Some(u);
        }
        let mut made = false;
        let placeholder = {
            let mut st = self.write();
            let l = st.logins.get_mut(&id)?;
            l.last_used_at = Some(iso);
            match l.placeholders.get(vm_id) {
                Some(p) => p.clone(),
                None => {
                    // A store written by an older build: the proxy must know it before the agent types it.
                    let p = make_placeholder(&l.password);
                    l.placeholders.insert(vm_id.into(), p.clone());
                    made = true;
                    p
                }
            }
        };
        // The placeholder is in memory and reaches the proxy below; a store that did not take it
        // makes a new one after a restart.
        let _ = self.save();
        if made {
            self.credentials_changed().await;
        }
        self.record(
            Some(vm_id),
            "/use",
            &format!("login {}: handed to the agent", login.name),
            &login.name,
            None,
        );
        u.placeholder = Some(placeholder);
        Some(u)
    }

    /// `type` mode: have the agent box type the password into the field that has focus in its
    /// browser, after checking the page is one of the login's sites.
    pub async fn type_in(&self, vm_id: &str, which: &str) -> Result<String, String> {
        let login = self
            .find_id(vm_id, which)
            .and_then(|id| self.read().logins.get(&id).cloned());
        let Some(login) = login.filter(|l| l.kind() != "session") else {
            return Err(
                "There is no such login with a password for you. Call logins_list to see the ones you may use.".into(),
            );
        };
        if login.mode != "type" {
            return Err(format!(
                "{} is not typed in by the firewall: use login_use and type the placeholder it gives you. If that sign-in was blocked, do not retry: tell the person what the block said. They can see it in Activity, and save the login again as \"Typed into the page\" (ControlClaw, Secrets, Website logins) or sign you in themselves.",
                login.name
            ));
        }
        if !self.has_target(vm_id) {
            return Err("This firewall cannot reach your agent box right now. Try again in a minute.".into());
        }
        let name = login.name.clone();
        let out = match self
            .post_agent(
                vm_id,
                "/logins/type",
                json!({"password": login.password, "sites": login.sites}),
            )
            .await
        {
            Ok(o) => o,
            Err(m) => {
                // An agent box built before type mode has no such route.
                if m.starts_with("agent 404")
                    && m[9..]
                        .chars()
                        .next()
                        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
                {
                    self.record(
                        Some(vm_id),
                        "/type",
                        &format!("login {name}: not typed (the agent box needs an update)"),
                        &name,
                        Some("block"),
                    );
                    return Err("Your agent box is too old to type passwords in. Ask a person to update this agent (its settings page has the Update button), then try again.".into());
                }
                self.record(
                    Some(vm_id),
                    "/type",
                    &format!("login {name}: not typed (the browser did not answer)"),
                    &name,
                    Some("block"),
                );
                return Err("Your browser did not answer. Make sure the sign-in page is open, click into the password field, then try again.".into());
            }
        };
        if out.get("ok") != Some(&Value::Bool(true)) {
            let reason = out.get("reason").and_then(Value::as_str);
            let (why, label) = match reason {
                Some("site") => (
                    format!("The page with the focused field is not one of this login's sites ({}).", login.sites.join(", ")),
                    "another site",
                ),
                Some("changed") => (
                    "The page changed while the password was about to be typed (the focus moved or another page loaded), so nothing was typed. Click into the password field on the sign-in page, then call login_type again.".to_string(),
                    "the page changed",
                ),
                _ => (
                    "Click into the password field on the sign-in page first, then call login_type again.".to_string(),
                    "no password field",
                ),
            };
            self.record(
                Some(vm_id),
                "/type",
                &format!("login {name}: not typed ({label})"),
                &name,
                Some("block"),
            );
            return Err(why);
        }
        let iso = self.iso();
        if let Some(l) = self.write().logins.get_mut(&login.id) {
            l.last_used_at = Some(iso);
        }
        let _ = self.save();
        self.record(
            Some(vm_id),
            "/type",
            &format!("login {name}: typed into the page (type mode)"),
            &name,
            None,
        );
        Ok(name)
    }

    /// The current two-step code for a login the agent may use.
    pub fn code(&self, vm_id: &str, which: &str) -> Result<(String, String, u64), String> {
        let login = self
            .find_id(vm_id, which)
            .and_then(|id| self.read().logins.get(&id).cloned());
        let Some(login) = login else {
            return Err("There is no such login for you. Call logins_list to see the ones you may use.".into());
        };
        let Some(t) = &login.totp else {
            return Err(format!(
                "{} has no two-step key. Ask a person to add it on the login (Secrets, Logins, Replace password).",
                login.name
            ));
        };
        let (code, left) = totp_code(t, (self.now)());
        self.record(
            Some(vm_id),
            "/code",
            &format!("login {}: two-step code read by the agent", login.name),
            &login.name,
            None,
        );
        Ok((login.name, code, left))
    }

    // ---- chat requests ----

    fn sweep_requests(&self) {
        let now = (self.now)();
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|r| r.expires_at > now);
    }

    fn console_origin(&self) -> Option<String> {
        url::Url::parse(&self.app.config.firewall_url)
            .ok()
            .filter(|u| u.origin().is_tuple())
            .map(|u| u.origin().ascii_serialization())
    }

    /// The agent asks for a login. The link it should send, or why it cannot.
    pub fn request(&self, vm_id: &str, raw: &Value) -> Result<(String, String, i64), String> {
        let Some(origin) = self.console_origin() else {
            return Err("This firewall does not know where the ControlClaw console is, so it cannot make a link. Ask a person to add the login in ControlClaw (Secrets, Logins).".into());
        };
        let Some(input) = schema::parse_request_input(raw) else {
            return Err("Give the site as a host name, for example github.com.".into());
        };
        self.sweep_requests();
        let mut reqs = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let open = reqs.iter().filter(|r| r.vm_id == vm_id && r.login_id.is_none()).count();
        if open >= REQUESTS_PER_AGENT {
            return Err("You already have several login requests open. Wait for a person to answer them, or for them to expire (30 minutes).".into());
        }
        let id = new_id("lr");
        let url = input.url.filter(|u| {
            url::Url::parse(u)
                .ok()
                .and_then(|x| x.host_str().map(str::to_lowercase))
                .as_deref()
                == Some(input.site.as_str())
        });
        let now = (self.now)();
        let r = LoginRequest {
            id: id.clone(),
            vm_id: vm_id.into(),
            site: input.site.clone(),
            kind: input.kind.clone(),
            reason: input.reason,
            url,
            task: input.task.filter(|t| !t.is_empty()),
            created_at: now,
            expires_at: now + REQUEST_TTL_MS,
            login_id: None,
        };
        reqs.push(r.clone());
        drop(reqs);
        let session = if r.kind == "session" {
            " (sign in in its browser)"
        } else {
            ""
        };
        self.record(
            Some(vm_id),
            "/request",
            &format!("login for {}: requested by the agent{session}", r.site),
            &r.site,
            None,
        );
        let link = format!(
            "{origin}/logins/r/{}/{id}",
            crate::integrations::connectors::runtime::enc(&self.app.config.box_id)
        );
        Ok((id, link, REQUEST_TTL_MS / 60_000))
    }

    /// A request as the page shows it, while it is open.
    pub fn get_request(&self, id: &str) -> Option<LoginRequest> {
        self.sweep_requests();
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    pub fn request_status(&self, vm_id: &str, id: &str) -> Value {
        let Some(r) = self.get_request(id).filter(|r| r.vm_id == vm_id) else {
            return json!({"status": "expired"});
        };
        let Some(login_id) = &r.login_id else {
            return json!({"status": "waiting", "kind": r.kind});
        };
        match self.read().logins.get(login_id) {
            Some(l) => json!({"status": "ready", "login": l.name, "kind": l.kind()}),
            None => json!({"status": "expired"}),
        }
    }

    fn answer_request(&self, id: &str, login_id: &str) {
        if let Some(r) = self
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
            .find(|r| r.id == id)
        {
            r.login_id = Some(login_id.into());
        }
    }

    /// A person signed the agent in themselves (a `session` request). Nothing secret is kept.
    pub async fn record_session(self: &Arc<Self>, by: &str, request_id: &str) -> Result<Value, Refused> {
        let _one = self.serial.lock().await;
        let Some(r) = self.get_request(request_id) else {
            return say("That request has expired. Ask the agent to send a new link.");
        };
        if r.kind != "session" {
            return say("This request is for a username and password, not for signing the agent in yourself.");
        }
        if r.login_id.is_some() {
            return say("This request was already answered.");
        }
        if !self.live_agent(&r.vm_id) {
            return say("That agent is not part of this organization.");
        }
        if self.read().logins.len() >= LOGIN_LIMIT {
            return say(&format!("An organization can hold {LOGIN_LIMIT} logins."));
        }
        let at = self.iso();
        let id = new_id("lg");
        let login = Stored {
            id: id.clone(),
            kind: Some("session".into()),
            name: crate::integrations::connectors::firewall::js_slice(
                &format!("{} (signed in by a person)", r.site),
                64,
            ),
            sites: vec![r.site.clone()],
            login_url: None,
            username: String::new(),
            mode: "swap".into(),
            vm_ids: vec![r.vm_id.clone()],
            created_by: Some(crate::integrations::connectors::firewall::js_slice(by, 200)).filter(|b| !b.is_empty()),
            created_at: at.clone(),
            updated_at: at,
            ..Default::default()
        };
        self.write().logins.insert(id.clone(), login.clone());
        self.answer_request(&r.id, &id);
        self.save()?;
        self.record(
            Some(&r.vm_id),
            "/session",
            &format!("login {}: a person signed the agent in", login.name),
            &login.name,
            None,
        );
        self.notify_answered(&r, &login);
        Ok(self.metadata(&login))
    }

    /// Wake the agent that asked. Best effort: `login_status` still says `ready` if it fails.
    fn notify_answered(self: &Arc<Self>, r: &LoginRequest, login: &Stored) {
        if !self.has_target(&r.vm_id) {
            return;
        }
        let mut body = as_map(json!({"requestId": r.id, "site": r.site, "login": login.name, "kind": login.kind()}));
        if let Some(u) = &r.url {
            body.insert("url".into(), json!(u));
        }
        if let Some(t) = &r.task {
            body.insert("task".into(), json!(t));
        }
        let (me, vm) = (self.clone(), r.vm_id.clone());
        tokio::spawn(async move {
            if me
                .post_agent(&vm, "/logins/answered", Value::Object(body))
                .await
                .is_err()
            {
                tracing::info!("[logins] could not tell {vm} that its login request was answered");
            }
        });
    }

    /// Open the request's site in a new tab of the agent's browser, ready for the person.
    pub async fn open_tab(&self, request_id: &str) -> bool {
        let Some(r) = self.get_request(request_id) else {
            return false;
        };
        if !self.has_target(&r.vm_id) {
            return false;
        }
        let url = r.url.clone().unwrap_or_else(|| format!("https://{}/", r.site));
        self.post_agent(&r.vm_id, "/logins/open-tab", json!({"url": url}))
            .await
            .is_ok()
    }

    /// The console link that opens the requesting agent's browser (Screen) for this request.
    pub fn screen_link(&self, request_id: &str) -> Option<String> {
        let origin = self.console_origin()?;
        let r = self.get_request(request_id)?;
        let enc = crate::integrations::connectors::runtime::enc;
        Some(format!(
            "{origin}/logins/r/{}/{request_id}/screen?vm={}",
            enc(&self.app.config.box_id),
            enc(&r.vm_id)
        ))
    }

    // ---- the firewall page: an owner or admin in an enrolled browser ----

    /// Create a login, or replace one (`id`). Returns its metadata.
    pub async fn put(self: &Arc<Self>, by: &str, raw: &Value, id: Option<&str>) -> Result<Value, Refused> {
        let _one = self.serial.lock().await;
        let entry: Entry = schema::parse_entry(raw)?;
        for vm in &entry.vm_ids {
            if !self.live_agent(vm) {
                return say("That agent is not part of this organization.");
            }
        }
        if entry.mode != "type" && entry.auth != "basic" && entry.login_url.is_none() {
            return say(
                "Fill in the sign-in page: the address of the page with the password field, such as https://github.com/login. The password is only put into the sign-in request of that page.",
            );
        }
        let totp = match &entry.totp {
            Some(t) => Some(parse_totp(t).map_err(Refused::Message)?),
            None => None,
        };
        let request = match &entry.request_id {
            Some(rid) => match self.get_request(rid) {
                None => return say("That request has expired. Ask the agent to send a new link."),
                Some(r) => Some(r),
            },
            None => None,
        };
        if request.as_ref().is_some_and(|r| r.login_id.is_some()) {
            return say("This request was already answered.");
        }
        if let Some(r) = &request
            && !entry.vm_ids.contains(&r.vm_id)
        {
            return say("Tick the agent that asked for this login, or it cannot use it.");
        }
        let at = self.iso();
        let login = match id {
            Some(id) => {
                let Some(old) = self.read().logins.get(id).cloned() else {
                    return say("That login is gone.");
                };
                if old.kind() == "session" {
                    return say("A login the agent was signed in to by a person has no password to replace.");
                }
                if old.op_source().is_some() {
                    return say(
                        "This login comes from 1Password. Change it there; the firewall picks it up on the next sync.",
                    );
                }
                let mut placeholders = OrdMap::new();
                for vm in &entry.vm_ids {
                    let kept = old
                        .placeholders
                        .get(vm)
                        .filter(|k| placeholder_fits(k, &entry.password))
                        .cloned();
                    placeholders.insert(vm.clone(), kept.unwrap_or_else(|| make_placeholder(&entry.password)));
                }
                let mut next = old.clone();
                if entry.login_url != old.login_url {
                    // Targets were read off the old sign-in page: a new page starts again.
                    next.learned = Some(OrdMap::new());
                    next.learned_fields = Some(OrdMap::new());
                    next.approved_targets = Some(vec![]);
                    next.refused_targets = Some(vec![]);
                }
                next.auth = Some(entry.auth.clone());
                next.sign_in_paths = Some(entry.sign_in_paths.clone());
                next.name = entry.name.clone();
                next.sites = entry.sites.clone();
                next.login_url = entry.login_url.clone();
                next.username = entry.username.clone();
                next.password = entry.password.clone();
                next.mode = entry.mode.clone();
                next.totp = if entry.remove_totp {
                    None
                } else {
                    totp.clone().or(old.totp.clone())
                };
                next.vm_ids = entry.vm_ids.clone();
                next.placeholders = placeholders;
                next.updated_at = at;
                next
            }
            None => {
                if self.read().logins.len() >= LOGIN_LIMIT {
                    return say(&format!("An organization can hold {LOGIN_LIMIT} logins."));
                }
                let mut placeholders = OrdMap::new();
                for vm in &entry.vm_ids {
                    placeholders.insert(vm.clone(), make_placeholder(&entry.password));
                }
                Stored {
                    id: new_id("lg"),
                    kind: Some("password".into()),
                    name: entry.name.clone(),
                    sites: entry.sites.clone(),
                    login_url: entry.login_url.clone(),
                    username: entry.username.clone(),
                    mode: entry.mode.clone(),
                    auth: Some(entry.auth.clone()),
                    sign_in_paths: Some(entry.sign_in_paths.clone()),
                    vm_ids: entry.vm_ids.clone(),
                    created_by: Some(crate::integrations::connectors::firewall::js_slice(by, 200))
                        .filter(|b| !b.is_empty()),
                    created_at: at.clone(),
                    updated_at: at,
                    last_used_at: None,
                    password: entry.password.clone(),
                    totp: totp.clone(),
                    placeholders,
                    ..Default::default()
                }
            }
        };
        if let Some(t) = &totp {
            remember(&t.secret);
        }
        if let Some(r) = &request {
            self.answer_request(&r.id, &login.id);
            self.notify_answered(r, &login);
        }
        remember(&entry.password);
        self.write().logins.insert(login.id.clone(), login.clone());
        Codes::new(&self.app, &format!("{SCOPE_PREFIX}{}", login.id)).forget();
        self.save()?;
        self.credentials_changed().await;
        let what = if id.is_some() { "replaced" } else { "added" };
        self.record(
            None,
            if id.is_some() { "/replace" } else { "/create" },
            &format!("login {}: {what} on the firewall page", login.name),
            &login.name,
            None,
        );
        tracing::info!(
            "[logins] {what} {} ({}) for {} agent(s)",
            login.id,
            login.sites.join(", "),
            login.vm_ids.len()
        );
        Ok(self.metadata(&login))
    }

    /// Many logins at once, from a password manager's CSV export the page read. A row that does not
    /// fit is skipped and counted; a two-step key that cannot be read is dropped and the login kept.
    pub async fn import_rows(&self, by: &str, raw: &Value) -> Result<(usize, usize, bool), Refused> {
        let _one = self.serial.lock().await;
        let (candidates, vm_ids) = schema::parse_import(raw)?;
        for vm in &vm_ids {
            if !self.live_agent(vm) {
                return say("That agent is not part of this organization.");
            }
        }
        let room = LOGIN_LIMIT.saturating_sub(self.read().logins.len());
        let valid: Vec<schema::ImportRow> = candidates
            .iter()
            .filter_map(|c| schema::parse_import_row(c).ok())
            .collect();
        let rows: Vec<&schema::ImportRow> = valid.iter().take(room).collect();
        let at = self.iso();
        {
            let mut st = self.write();
            for r in &rows {
                let id = new_id("lg");
                remember(&r.password);
                // A seed is a secret too: masked out of the logs as the password is.
                let totp = r.totp.as_deref().and_then(|t| parse_totp(t).ok());
                if let Some(t) = &totp {
                    remember(&t.secret);
                }
                let mut placeholders = OrdMap::new();
                for vm in &vm_ids {
                    placeholders.insert(vm.clone(), make_placeholder(&r.password));
                }
                st.logins.insert(
                    id.clone(),
                    Stored {
                        id,
                        kind: Some("password".into()),
                        name: r.name.clone(),
                        sites: r.sites.clone(),
                        login_url: r.login_url.clone(),
                        username: r.username.clone(),
                        mode: "swap".into(),
                        vm_ids: vm_ids.clone(),
                        created_by: Some(crate::integrations::connectors::firewall::js_slice(by, 200))
                            .filter(|b| !b.is_empty()),
                        created_at: at.clone(),
                        updated_at: at.clone(),
                        password: r.password.clone(),
                        totp,
                        placeholders,
                        ..Default::default()
                    },
                );
            }
        }
        self.save()?;
        self.credentials_changed().await;
        let n = rows.len();
        self.record(
            None,
            "/import",
            &format!("{n} login(s) imported on the firewall page"),
            &format!("{n} imported"),
            None,
        );
        Ok((n, candidates.len() - valid.len(), valid.len() > n))
    }

    // ---- 1Password ----

    /// The vaults a token can open, to choose from before connecting. The token is not kept.
    pub async fn one_password_vaults(&self, token: &str) -> Result<Vec<OpVault>, Refused> {
        let t = schema::op_token(token)
            .map_err(|_| Refused::Message("Paste a service account token: it starts with ops_.".into()))?;
        self.op.vaults(&t).await.map_err(Refused::Message)
    }

    /// Connect a service account: keep its token here, and read its vaults' logins now.
    pub async fn one_password_connect(self: &Arc<Self>, by: &str, raw: &Value) -> Result<Value, Refused> {
        let input = schema::parse_op_connect(raw)?;
        for vm in &input.vm_ids {
            if !self.live_agent(vm) {
                return say("That agent is not part of this organization.");
            }
        }
        let all = self.op.vaults(&input.token).await.map_err(Refused::Message)?;
        let vaults: Vec<OpVault> = all.into_iter().filter(|v| input.vault_ids.contains(&v.id)).collect();
        if vaults.len() != input.vault_ids.len() {
            return say("The token cannot open one of those vaults.");
        }
        remember(&input.token);
        {
            let _one = self.serial.lock().await;
            self.write().one_password = Some(Some(OnePasswordSource {
                vaults: vaults.iter().map(|v| json!({"id": v.id, "name": v.name})).collect(),
                vm_ids: input.vm_ids.clone(),
                added_by: Some(crate::integrations::connectors::firewall::js_slice(by, 200)).filter(|b| !b.is_empty()),
                added_at: self.iso(),
                last_sync_at: None,
                last_error: None,
                items: 0,
                token: input.token.clone(),
                unused: None,
                extra: Map::new(),
            }));
            self.save()?;
        }
        let names: Vec<&str> = vaults.iter().map(|v| v.name.as_str()).collect();
        self.record(
            None,
            "/1password/connect",
            &format!("1Password connected ({})", names.join(", ")),
            "1Password",
            None,
        );
        self.one_password_sync().await;
        Ok(self.one_password_status())
    }

    /// Whether a read of 1Password is running now.
    #[cfg(test)]
    pub fn one_password_busy(&self) -> bool {
        self.op_syncing.try_lock().is_err()
    }

    /// Mirror the connected vaults. One at a time: a call while one runs waits for that one and
    /// does not read again (each read costs calls against the customer's 1Password rate limit). A
    /// failed read changes nothing, so an outage never takes logins away from the agents.
    pub async fn one_password_sync(&self) {
        match self.op_syncing.try_lock() {
            Ok(_one) => self.one_password_sync_now().await,
            Err(_) => drop(self.op_syncing.lock().await),
        }
    }

    async fn one_password_sync_now(&self) {
        let Some(op) = self.read().one_password.clone().flatten() else {
            return;
        };
        let (others, existing): (usize, Vec<Stored>) = {
            let st = self.read();
            (
                st.logins.values().filter(|l| l.op_source().is_none()).count(),
                st.logins
                    .values()
                    .filter(|l| l.op_source().is_some())
                    .cloned()
                    .collect(),
            )
        };
        let room = LOGIN_LIMIT.saturating_sub(others);
        let mut fetched: Vec<(super::onepassword::OpLogin, String)> = Vec::new();
        let mut kept: Vec<String> = Vec::new();
        let mut listed = 0usize;
        let mut overflow = 0usize;
        let unused = op.unused.clone().unwrap_or_default();
        let read: Result<(), String> = async {
            for v in &op.vaults {
                let vid = v.get("id").and_then(Value::as_str).unwrap_or("");
                for it in self.op.list(&op.token, vid).await? {
                    listed += 1;
                    if fetched.len() + kept.len() >= room {
                        overflow += 1;
                        continue;
                    }
                    // An item that has not changed since the last read is not read again.
                    let ex = existing.iter().find(|l| {
                        l.op_source()
                            .is_some_and(|s| s.item_id == it.item_id && s.vault_id == it.vault_id)
                    });
                    let same = |l: &Stored| {
                        l.op_source().and_then(|s| s.updated_at.clone()).as_deref() == Some(it.updated_at.as_str())
                    };
                    match ex {
                        Some(l) if !it.updated_at.is_empty() && same(l) => kept.push(l.id.clone()),
                        None if !it.updated_at.is_empty()
                            && unused.get(&format!("{}/{}", it.vault_id, it.item_id)) == Some(&it.updated_at) => {}
                        _ => fetched.push((
                            self.op.get(&op.token, &it.vault_id, &it.item_id).await?,
                            it.updated_at.clone(),
                        )),
                    }
                }
            }
            Ok(())
        }
        .await;
        let _one = self.serial.lock().await;
        if let Err(e) = read {
            if let Some(Some(src)) = self.write().one_password.as_mut() {
                src.last_error = Some(crate::integrations::connectors::firewall::js_slice(&e, 300));
            }
            let _ = self.save();
            return;
        }
        let at = self.iso();
        {
            let mut st = self.write();
            let Some(Some(src)) = st.one_password.clone() else {
                return;
            };
            // The connection this sync read with must still be the one there: a reconnect while it
            // read (fewer vaults, another token) would otherwise bring back what it deselected.
            // Beyond the TS, which merges into whatever is connected by then.
            if !same_connection(&src, &op) {
                return;
            }
            let mut seen: Vec<String> = kept.iter().filter(|id| st.logins.contains_key(id)).cloned().collect();
            for id in &seen {
                if let Some(l) = st.logins.get_mut(id) {
                    l.vm_ids = src.vm_ids.clone();
                }
            }
            let mut unused = src.unused.clone().unwrap_or_default();
            for (it, updated_at) in &fetched {
                let key = format!("{}/{}", it.vault_id, it.item_id);
                let mut sites: Vec<String> = Vec::new();
                for u in &it.urls {
                    static SCHEME: std::sync::LazyLock<regex::Regex> =
                        std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)^[a-z][a-z0-9+.-]*://").expect("pattern"));
                    let full = if SCHEME.is_match(u) {
                        u.clone()
                    } else {
                        format!("https://{u}")
                    };
                    let host = url::Url::parse(&full)
                        .ok()
                        .and_then(|x| x.host_str().map(str::to_lowercase))
                        .unwrap_or_default();
                    if schema::login_site(&host).is_ok() && !sites.contains(&host) {
                        sites.push(host);
                    }
                }
                sites.truncate(20);
                if sites.is_empty() || it.password.is_empty() {
                    if !updated_at.is_empty() {
                        unused.insert(key, updated_at.clone());
                    }
                    continue;
                }
                unused.remove(&key);
                let totp = it.totp.as_deref().and_then(|t| parse_totp(t).ok());
                let existing = st
                    .logins
                    .values()
                    .find(|l| {
                        l.op_source()
                            .is_some_and(|s| s.item_id == it.item_id && s.vault_id == it.vault_id)
                    })
                    .cloned();
                let id = existing.as_ref().map(|e| e.id.clone()).unwrap_or_else(|| new_id("lg"));
                seen.push(id.clone());
                remember(&it.password);
                if let Some(t) = &totp {
                    remember(&t.secret);
                }
                let mut placeholders = OrdMap::new();
                for vm in &src.vm_ids {
                    let keep = existing
                        .as_ref()
                        .and_then(|e| e.placeholders.get(vm))
                        .filter(|k| placeholder_fits(k, &it.password))
                        .cloned();
                    placeholders.insert(vm.clone(), keep.unwrap_or_else(|| make_placeholder(&it.password)));
                }
                let op_url = it
                    .urls
                    .iter()
                    .find(|u| {
                        let l = u.to_ascii_lowercase();
                        l.starts_with("http://") || l.starts_with("https://")
                    })
                    .filter(|u| u.encode_utf16().count() <= 2048)
                    .cloned();
                let pinned = existing.as_ref().and_then(|e| e.login_url_pinned).unwrap_or(false);
                let keep_learned = existing.as_ref().is_some_and(|e| pinned || e.login_url == op_url);
                let e = existing.clone().unwrap_or_default();
                st.logins.insert(
                    id.clone(),
                    Stored {
                        id: id.clone(),
                        kind: Some("password".into()),
                        name: it.title.clone(),
                        sites,
                        // The owner's own sign-in page, set on the firewall page, is kept over 1Password's.
                        login_url: if pinned { e.login_url.clone() } else { op_url },
                        username: crate::integrations::connectors::firewall::js_slice(&it.username, 256),
                        mode: existing
                            .as_ref()
                            .map(|e| e.mode.clone())
                            .unwrap_or_else(|| "swap".into()),
                        auth: e.auth.clone(),
                        sign_in_paths: e.sign_in_paths.clone(),
                        learned: if keep_learned { e.learned.clone() } else { None },
                        learned_fields: if keep_learned { e.learned_fields.clone() } else { None },
                        approved_targets: if keep_learned { e.approved_targets.clone() } else { None },
                        refused_targets: if keep_learned { e.refused_targets.clone() } else { None },
                        login_url_pinned: e.login_url_pinned,
                        vm_ids: src.vm_ids.clone(),
                        created_by: existing
                            .as_ref()
                            .map(|e| e.created_by.clone())
                            .unwrap_or(Some("1Password".into())),
                        created_at: existing
                            .as_ref()
                            .map(|e| e.created_at.clone())
                            .unwrap_or_else(|| at.clone()),
                        updated_at: at.clone(),
                        last_used_at: e.last_used_at.clone(),
                        password: it.password.clone(),
                        totp,
                        placeholders,
                        source: Some(Some(Source {
                            kind: "1password".into(),
                            vault_id: it.vault_id.clone(),
                            item_id: it.item_id.clone(),
                            updated_at: Some(updated_at.clone()),
                            extra: Map::new(),
                        })),
                        extra: e.extra.clone(),
                    },
                );
            }
            st.logins.retain(|id, l| l.op_source().is_none() || seen.contains(id));
            if let Some(Some(s)) = st.one_password.as_mut() {
                s.unused = Some(unused);
                s.last_sync_at = Some(at);
                s.last_error = (overflow > 0)
                    .then(|| format!("{overflow} of {listed} 1Password items were not read: this firewall holds {LOGIN_LIMIT} logins at most."));
                s.items = seen.len() as u64;
            }
        }
        if self.save().is_err() {
            return;
        }
        self.credentials_changed().await;
    }

    /// Forget the token and every login read with it.
    pub async fn one_password_disconnect(&self, how: &str) -> Result<bool, Refused> {
        let _one = self.serial.lock().await;
        {
            let mut st = self.write();
            if !matches!(st.one_password, Some(Some(_))) {
                return Ok(false);
            }
            st.one_password = Some(None);
            st.logins.retain(|_, l| l.op_source().is_none());
        }
        // Taken away in memory: the proxy forgets it whether or not the disk took the change.
        let saved = self.save();
        self.credentials_changed().await;
        self.record(
            None,
            "/1password/disconnect",
            &format!("1Password disconnected {how}"),
            "1Password",
            None,
        );
        saved.map(|()| true)
    }

    pub async fn remove(&self, id: &str, how: &str) -> Result<bool, Refused> {
        let _one = self.serial.lock().await;
        self.remove_now(id, how).await
    }

    async fn remove_now(&self, id: &str, how: &str) -> Result<bool, Refused> {
        let Some(login) = self.read().logins.get(id).cloned() else {
            return Ok(false);
        };
        if login.op_source().is_some() {
            return say("This login comes from 1Password. Remove it there, or disconnect 1Password.");
        }
        // A session login is the cookies in the agent's browser: sign the agent out first, and keep
        // the record if that fails.
        if login.kind() == "session" {
            // No identity map on this build: whether the agent can be reached is not known, so the
            // record stays rather than the agent staying signed in unseen.
            if self.app.contracts.identities.require().ok().is_none() {
                return say(
                    "The agent's browser could not be reached, so it is still signed in. Start the agent and delete this again.",
                );
            }
            for vm in &login.vm_ids {
                if !self.has_target(vm) {
                    continue;
                }
                if self
                    .post_agent(vm, "/logins/clear-cookies", json!({"sites": login.sites}))
                    .await
                    .is_err()
                {
                    return say(
                        "The agent's browser could not be reached, so it is still signed in. Start the agent and delete this again.",
                    );
                }
            }
        }
        self.write().logins.remove(id);
        Codes::new(&self.app, &format!("{SCOPE_PREFIX}{id}")).forget();
        let saved = self.save();
        // The proxy forgets the swap first. The placeholder is then plain text to it.
        self.credentials_changed().await;
        self.record(
            None,
            "/delete",
            &format!("login {}: deleted {how}", login.name),
            &login.name,
            None,
        );
        tracing::info!("[logins] deleted {id} {how}");
        saved.map(|()| true)
    }

    // ---- the console, through the heartbeat ----

    pub async fn handle(self: &Arc<Self>, action: &str, p: Map<String, Value>) -> CommandOutcome {
        match action {
            "read" => outcome(true, "read", None, Some(self.summary())),
            // Taking a source away only narrows: no code, like a delete.
            "1password_disconnect" => match self.one_password_disconnect("from the console").await {
                Err(Refused::Message(m) | Refused::Invalid(Issue { message: m, .. })) => {
                    outcome(false, "failed", Some(m), None)
                }
                Ok(_) => outcome(true, "applied", None, Some(self.summary())),
            },
            // Started, not awaited: a large vault takes longer than the console waits for a command.
            "1password_sync" => {
                let me = self.clone();
                tokio::spawn(async move { me.one_password_sync().await });
                outcome(
                    true,
                    "applied",
                    Some("Reading 1Password now. Refresh in a minute.".into()),
                    Some(self.summary()),
                )
            }
            "propose" => {
                let _one = self.serial.lock().await;
                self.propose(&p).await
            }
            "confirm" => {
                let _one = self.serial.lock().await;
                self.confirm(&p).await
            }
            "cancel" => {
                let id = p.get("id").and_then(Value::as_str).unwrap_or("");
                Codes::new(&self.app, &format!("{SCOPE_PREFIX}{id}")).cancel(p.get("changeId").and_then(Value::as_str));
                outcome(true, "cancelled", None, None)
            }
            _ => crate::integrations::failed(&format!("unknown command logins.{action}")),
        }
    }

    async fn propose(&self, p: &Map<String, Value>) -> CommandOutcome {
        let invalid = || outcome(false, "failed", Some("That change is not valid.".into()), None);
        let Ok(change) = schema::parse_change(p) else {
            return invalid();
        };
        let Some(change_id) = p
            .get("changeId")
            .and_then(Value::as_str)
            .filter(|c| (1..=100).contains(&c.encode_utf16().count()))
        else {
            return invalid();
        };
        let id = match &change {
            Change::Update { id, .. } | Change::Delete { id } => id.clone(),
        };
        let Some(login) = self.read().logins.get(&id).cloned() else {
            return outcome(
                false,
                "failed",
                Some("That login is gone. Refresh the page.".into()),
                None,
            );
        };
        if login.op_source().is_some() {
            return outcome(
                false,
                "failed",
                Some("This login comes from 1Password. Change or remove it there, or disconnect 1Password.".into()),
                None,
            );
        }
        let Change::Update {
            name,
            sites,
            vm_ids,
            mode,
            ..
        } = &change
        else {
            return match self.remove_now(&id, "from the console").await {
                Ok(_) => outcome(true, "applied", None, Some(self.summary())),
                Err(Refused::Message(m)) => outcome(false, "failed", Some(m), None),
                Err(Refused::Invalid(i)) => outcome(false, "failed", Some(i.message), None),
            };
        };
        if login.kind() == "session" {
            return outcome(
                false,
                "failed",
                Some("A login a person signed the agent in to cannot be changed, only deleted.".into()),
                None,
            );
        }
        for vm in vm_ids {
            if !self.live_agent(vm) {
                return outcome(
                    false,
                    "failed",
                    Some("That agent is not part of this organization.".into()),
                    None,
                );
            }
        }
        let mode = mode.clone().unwrap_or_else(|| login.mode.clone());
        let codes = Codes::new(&self.app, &format!("{SCOPE_PREFIX}{id}"));
        codes.forget();
        if !login_widens(&login.sites, &login.vm_ids, &login.mode, sites, vm_ids, &mode) {
            return self.apply(&change).await;
        }
        // No code routes or consent codes on this build: refused, never applied.
        let routes = match codes.routes() {
            Ok(r) => r,
            Err(m) => return outcome(false, "failed", Some(m), None),
        };
        if !self.app.contracts.code_routes.get().is_some_and(|r| r.ready()) {
            return outcome(
                false,
                "failed",
                Some("This firewall cannot read its channel list, so it cannot send a code. Try again shortly.".into()),
                None,
            );
        }
        let added: Vec<String> = vm_ids
            .iter()
            .filter(|v| !login.vm_ids.contains(v))
            .map(|v| self.agent_name(v))
            .collect();
        let typed = mode == "type" && login.mode != "type";
        let summary = format!(
            "Let login \"{name}\" ({}) be used on {}{}.{}",
            if login.username.is_empty() {
                "no username"
            } else {
                &login.username
            },
            sites.join(", "),
            if added.is_empty() {
                String::new()
            } else {
                format!(", by {} as well", added.join(", "))
            },
            if typed {
                " The firewall will type the password into the page itself, where the agent could read it."
            } else {
                ""
            }
        );
        let proposal = json!({"changeId": change_id, "change": change_value(&change)});
        match codes.send(change_id, proposal, "your logins", &summary, routes).await {
            Ok(sent) => outcome(
                true,
                "awaiting_code",
                None,
                Some(as_map(
                    json!({"sentVia": sent.sent_via, "expiresAt": sent.expires_at, "attemptsLeft": sent.attempts_left, "id": id}),
                )),
            ),
            Err(_) => outcome(
                false,
                "failed",
                Some("No confirmation code could be delivered. Add a recipient on the Firewall page.".into()),
                None,
            ),
        }
    }

    async fn confirm(&self, p: &Map<String, Value>) -> CommandOutcome {
        let id = p.get("id").and_then(Value::as_str).unwrap_or("");
        let change_id = p.get("changeId").and_then(Value::as_str).unwrap_or("");
        let code: String = p
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let code = crate::integrations::connectors::firewall::js_slice(&code, 20);
        match Codes::new(&self.app, &format!("{SCOPE_PREFIX}{id}")).verify(change_id, &code) {
            Verified::Expired => outcome(false, "expired", None, Some(Map::new())),
            Verified::Invalid { attempts_left } => outcome(
                false,
                "invalid",
                None,
                Some(as_map(json!({"attemptsLeft": attempts_left}))),
            ),
            Verified::Ok { proposal, .. } => {
                let change = proposal
                    .get("change")
                    .and_then(Value::as_object)
                    .and_then(|c| schema::parse_change(c).ok());
                match change {
                    Some(c) => self.apply(&c).await,
                    None => outcome(false, "failed", Some("That change is not valid.".into()), None),
                }
            }
        }
    }

    async fn apply(&self, change: &Change) -> CommandOutcome {
        let Change::Update {
            id,
            name,
            sites,
            vm_ids,
            mode,
        } = change
        else {
            return outcome(false, "failed", Some("That change is not valid.".into()), None);
        };
        let iso = self.iso();
        let login_name = {
            let mut st = self.write();
            let Some(login) = st.logins.get_mut(id) else {
                return outcome(
                    false,
                    "failed",
                    Some("That login is gone. Refresh the page.".into()),
                    None,
                );
            };
            let mut placeholders = OrdMap::new();
            for vm in vm_ids {
                let p = login
                    .placeholders
                    .get(vm)
                    .cloned()
                    .unwrap_or_else(|| make_placeholder(&login.password));
                placeholders.insert(vm.clone(), p);
            }
            login.name = name.clone();
            login.sites = sites.clone();
            login.vm_ids = vm_ids.clone();
            if let Some(m) = mode {
                login.mode = m.clone();
            }
            login.placeholders = placeholders;
            login.updated_at = iso;
            login.name.clone()
        };
        if let Err(Refused::Message(m) | Refused::Invalid(Issue { message: m, .. })) = self.save() {
            return outcome(false, "failed", Some(m), None);
        }
        self.credentials_changed().await;
        self.record(
            None,
            "/change",
            &format!("login {login_name}: sites or agents changed from the console"),
            &login_name,
            None,
        );
        outcome(true, "applied", None, Some(self.summary()))
    }

    // ---- Activity ----

    /// One metadata line in the traffic log, so Activity shows what happened to a login.
    pub fn record(&self, vm_id: Option<&str>, path: &str, rule: &str, login: &str, effect: Option<&str>) {
        let Some(p) = &self.log_path else { return };
        let mut rec = Map::new();
        rec.insert("source".into(), json!("egress"));
        rec.insert(
            "flow_id".into(),
            json!(format!("lgn-{}", hex::encode(rand::random::<[u8; 10]>()))),
        );
        rec.insert("ts".into(), json!((self.now)() as f64 / 1000.0));
        rec.insert("method".into(), json!("POST"));
        rec.insert("host".into(), json!("controlclaw-logins"));
        rec.insert("path".into(), json!(path));
        if let Some(v) = vm_id {
            rec.insert("vm_id".into(), json!(v));
        }
        rec.insert("effect".into(), json!(effect.unwrap_or("allow")));
        rec.insert("status".into(), json!(200));
        rec.insert(
            "rule".into(),
            json!(crate::integrations::connectors::firewall::js_slice(rule, 200)),
        );
        rec.insert(
            "login".into(),
            json!(crate::integrations::connectors::firewall::js_slice(login, 64)),
        );
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(p) {
            let _ = f.write_all(format!("{}\n", js::stringify(&Value::Object(rec))).as_bytes());
        }
    }
}

fn change_value(c: &Change) -> Value {
    match c {
        Change::Delete { id } => json!({"action": "delete", "id": id}),
        Change::Update {
            id,
            name,
            sites,
            vm_ids,
            mode,
        } => {
            let mut v = as_map(json!({"action": "update", "id": id, "name": name, "sites": sites, "vmIds": vm_ids}));
            if let Some(m) = mode {
                v.insert("mode".into(), json!(m));
            }
            Value::Object(v)
        }
    }
}

/// The logins' entries in the proxy's `credentials.json`, in the TS's place among the modules.
pub struct LoginCredentials(pub Arc<LoginsFirewall>);

impl CredentialContributor for LoginCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Logins
    }
    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

#[cfg(test)]
mod tests;
