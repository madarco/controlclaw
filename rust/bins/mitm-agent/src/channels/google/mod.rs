//! The organization's own Google account on the firewall (`google.ts`, docs/plans/google-account.md).
//!
//!   google.propose  { changeId, kind, client?, clientSecret?, services?, agents: [...] }
//!   google.callback { state, code?, error? }   the relayed consent result
//!   google.confirm  { changeId, code }
//!   google.cancel   { changeId }
//!   google.push     { vmId, name, hostname }   re-apply this box's whole state
//!   google.forget   { vmId }                   an agent was deleted
//!   google.read     {}                         what the console may see: no secrets
//!
//! Connecting takes two round trips: `propose` stores the client and a PKCE verifier and answers
//! with an authorization URL; the console relays the `code` back as `google.callback`, where the
//! exchange happens, and only then is a confirmation code sent. The per-agent grant is enforced
//! here: `credentials()` emits one proxy entry per granted agent, vm-scoped.

pub mod http;
pub mod store;
pub mod tokens;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::channels::agent::{AgentCalls, Target};
use crate::commands::{CommandOutcome, CommandResult};
use crate::contracts::{CodeRequest, ConsentCodes, Verify};
use http::GoogleHttp;
use store::{AccessToken, Account, Agent, GoogleStore, OAuthClient, Pending};
use tokens::{Exchange, ExchangeInput, Mint, s};

/// Mint a new access token this long before the current one expires.
pub const GOOGLE_REFRESH_AHEAD_MS: i64 = 15 * 60_000;
const SCOPE: &str = "google:org";
const CODE_SUBJECT: &str = "your organization's Google account";
const CODE_ATTEMPTS: u32 = 5;
/// v1 holds one account, and this is its key.
const ACCOUNT_ID: &str = "account";
pub const NO_CHANNELS: &str =
    "Your firewall cannot read its channel list right now, so it cannot ask you to confirm. Try again shortly.";
pub const NO_CODES: &str = "Confirmation codes are not available on this firewall yet.";

const KINDS: [&str; 6] = [
    "connect_account",
    "replace_account",
    "forget_account",
    "grant_agent",
    "revoke_agent",
    "set_services",
];

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRef {
    pub vm_id: String,
    pub name: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub change_id: String,
    pub kind: String,
    pub client: Option<OAuthClient>,
    pub services: Vec<String>,
    pub gmail_scope: String,
    pub drive_scope: String,
    pub audience: String,
    pub project_id: Option<String>,
    pub agents: Vec<AgentRef>,
}

impl Proposal {
    /// What the consent module keeps: never the client secret (a connect's account is held here).
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id,
            "kind": self.kind,
            "services": self.services,
            "gmailScope": self.gmail_scope,
            "driveScope": self.drive_scope,
            "audience": self.audience,
            "projectId": self.project_id,
            "agents": self.agents.iter().map(|a| json!({"vmId": a.vm_id, "name": a.name, "hostname": a.hostname})).collect::<Vec<_>>(),
        })
    }
}

fn service_list(services: &[String]) -> String {
    services
        .iter()
        .map(|s| match s.as_str() {
            "gmail" => "Gmail",
            "calendar" => "Calendar",
            "drive" => "Drive",
            "contacts" => "Contacts",
            "sheets" => "Sheets",
            "docs" => "Docs",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// How the agents in a proposal are named in the code message.
pub fn agent_list(names: &[&str]) -> String {
    let names: Vec<&str> = names.iter().copied().filter(|n| !n.is_empty()).collect();
    match names.len() {
        0 => "no agent yet".into(),
        1 => names[0].into(),
        n => format!("{} and {}", names[..n - 1].join(", "), names[n - 1]),
    }
}

fn collapse(s: String) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The one-line summary the code message carries. Mirrored in apps/saas.
pub fn summarize(p: &Proposal, account_label: Option<&str>) -> String {
    let names: Vec<&str> = p.agents.iter().map(|a| a.name.as_str()).collect();
    match p.kind.as_str() {
        "connect_account" => collapse(format!(
            "Connect the Google account {} ({})",
            account_label.unwrap_or(""),
            service_list(&p.services)
        )),
        "replace_account" => collapse(format!(
            "Reconnect the Google account {} ({})",
            account_label.unwrap_or(""),
            service_list(&p.services)
        )),
        "forget_account" => "Disconnect the Google account and take it off every agent".into(),
        "grant_agent" => format!("Give {} the Google account", agent_list(&names)),
        "revoke_agent" => format!("Take the Google account away from {}", agent_list(&names)),
        _ => format!("Change what the Google account covers to {}", service_list(&p.services)),
    }
}

pub fn parse_agents(raw: Option<&Value>) -> Vec<AgentRef> {
    raw.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some(AgentRef {
                        vm_id: s(x.get("vmId"))?,
                        name: s(x.get("name")).unwrap_or_default(),
                        hostname: s(x.get("hostname")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `clientSecret` is read from the top level, where the encrypted half of a command lands (a
/// shallow merge), not from inside `client`.
pub fn parse_proposal(p: &Map<String, Value>) -> Result<Proposal, String> {
    let change_id = s(p.get("changeId"));
    let kind = p.get("kind").and_then(Value::as_str).filter(|k| KINDS.contains(k));
    let (Some(change_id), Some(kind)) = (change_id, kind) else {
        return Err("malformed google.propose payload".into());
    };
    let client = p.get("client").and_then(Value::as_object).and_then(|c| {
        Some(OAuthClient {
            client_id: s(c.get("clientId"))?,
            client_secret: s(p.get("clientSecret"))?,
            redirect_uri: s(c.get("redirectUri"))?,
            token_endpoint: s(c.get("tokenEndpoint")).unwrap_or_else(|| tokens::GOOGLE_TOKEN_ENDPOINT.into()),
            extra: Map::new(),
        })
    });
    let pick = |k: &str, ok: fn(&str) -> bool, d: &str| {
        p.get(k)
            .and_then(Value::as_str)
            .filter(|v| ok(v))
            .unwrap_or(d)
            .to_string()
    };
    Ok(Proposal {
        change_id,
        kind: kind.into(),
        client,
        services: p
            .get("services")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|v| tokens::is_google_service(v))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        gmail_scope: pick("gmailScope", tokens::is_gmail_scope, "read-send"),
        drive_scope: pick("driveScope", tokens::is_drive_scope_choice, "readonly"),
        audience: pick("audience", store::is_google_audience, "external_testing"),
        project_id: s(p.get("projectId")),
        agents: parse_agents(p.get("agents")),
    })
}

/// What Drive needs to borrow this account's Drive access (T-78): a read, never copied.
#[derive(Debug, Clone, PartialEq)]
pub struct DriveAccess {
    pub account_label: Option<String>,
    pub token: Option<String>,
    pub drive_scope: Option<&'static str>,
    pub failed: Option<String>,
}

type Codes = Arc<dyn Fn() -> Option<Arc<dyn ConsentCodes>> + Send + Sync>;
pub type Routes = Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>;
pub type Changed = Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>;

pub struct GoogleOptions {
    pub store_path: PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    pub codes: Codes,
    /// `None` when the channel list cannot be read: then nothing applies on first use.
    pub code_routes: Routes,
    pub on_credentials_changed: Option<Changed>,
    pub http: Arc<dyn GoogleHttp>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

struct State {
    store: GoogleStore,
    /// Which agents a pending connect should grant. In memory: a restart drops the authorization.
    pending_agents: Vec<AgentRef>,
    /// An exchanged account waiting for its confirmation code. In memory only.
    awaiting: Option<(Account, Proposal)>,
    /// Bumped whenever the account map is replaced, so a refresh answer for a replaced account is
    /// dropped rather than written onto the new one.
    generation: u64,
    sent_via: Option<(String, String)>,
}

pub(crate) fn outcome(ok: bool, status: &str, message: Option<String>, data: Map<String, Value>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.into(),
        message,
        data: Some(data),
    }
}

pub(crate) fn change_data(change_id: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("changeId".into(), json!(change_id));
    m
}

pub(crate) fn iso(ms: i64) -> String {
    cc_crypto::store_health::iso_from_millis(ms)
}

pub struct GoogleFirewall {
    opts: GoogleOptions,
    /// Commands one at a time; the state lock is never held across an await.
    serial: tokio::sync::Mutex<()>,
    st: Mutex<State>,
    reports: Mutex<Vec<CommandResult>>,
    minting: AtomicBool,
}

impl GoogleFirewall {
    pub fn new(opts: GoogleOptions) -> Result<Arc<Self>, String> {
        let store = store::load(&opts.store_path, &opts.box_key, &opts.org_id, &opts.box_id)?;
        Ok(Arc::new(Self {
            opts,
            serial: tokio::sync::Mutex::new(()),
            st: Mutex::new(State {
                store,
                pending_agents: vec![],
                awaiting: None,
                generation: 0,
                sent_via: None,
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

    fn save(&self, st: &GoogleStore) -> Result<(), String> {
        store::save(
            &self.opts.store_path,
            st,
            &self.opts.box_key,
            &self.opts.org_id,
            &self.opts.box_id,
        )
        .map_err(|e| {
            tracing::error!("[google] could not save the store: {e}");
            "Your firewall could not save the Google account.".to_string()
        })
    }

    async fn changed(&self) {
        if let Some(f) = &self.opts.on_credentials_changed {
            f().await;
        }
    }

    fn the_account(st: &GoogleStore) -> Option<&Account> {
        st.accounts.values().next()
    }

    fn live(st: &GoogleStore) -> Option<&Account> {
        Self::the_account(st).filter(|a| a.access.is_some() && a.failed.is_none())
    }

    /// Proxy entries: one per granted agent, scoped to that agent's own traffic.
    pub fn credentials(&self) -> Vec<Value> {
        let st = self.lock();
        let Some(account) = Self::live(&st.store) else {
            return vec![];
        };
        let token = account.access.as_ref().map(|a| a.token.clone()).unwrap_or_default();
        st.store
            .agents
            .iter()
            .filter(|(_, a)| a.granted)
            .map(|(vm, a)| {
                json!({
                    "placeholder": a.placeholder,
                    "match_domain": store::GOOGLE_MATCH_DOMAIN,
                    "secret": token,
                    "locations": ["header:authorization"],
                    "vm_id": vm,
                })
            })
            .collect()
    }

    /// What Drive folders borrow (T-78). `drive_scope` is read from what consent granted.
    pub fn drive_access(&self) -> Option<DriveAccess> {
        let st = self.lock();
        let a = Self::the_account(&st.store)?;
        let has = |x: &str| {
            a.scopes
                .iter()
                .any(|s| s == &format!("https://www.googleapis.com/auth/{x}"))
        };
        let drive_scope = if has("drive") {
            Some("full")
        } else if has("drive.readonly") {
            Some("readonly")
        } else if has("drive.file") {
            Some("file")
        } else {
            None
        };
        Some(DriveAccess {
            account_label: a.account_label.clone(),
            token: a
                .access
                .as_ref()
                .filter(|_| a.failed.is_none())
                .map(|t| t.token.clone()),
            drive_scope,
            failed: a.failed.clone(),
        })
    }

    /// The live account's address and token, for the email rules' and Gmail push's own reads.
    pub fn gmail_access(&self) -> Option<(String, String)> {
        let st = self.lock();
        let a = Self::live(&st.store)?;
        Some((
            a.account_label.clone()?.to_lowercase(),
            a.access.as_ref()?.token.clone(),
        ))
    }

    /// The account's address as the summary shows it (`summary().account?.accountLabel`).
    pub fn account_label(&self) -> Option<String> {
        Self::the_account(&self.lock().store).and_then(|a| a.account_label.clone())
    }

    /// What the console may see: no secret, no access token, no client secret.
    pub fn summary(&self) -> Value {
        let st = self.lock();
        let account = Self::the_account(&st.store).map(|a| {
            json!({
                "accountLabel": a.account_label,
                "services": a.services,
                "scopes": a.scopes,
                "gmailScope": a.gmail_scope,
                "driveScope": a.drive_scope,
                "audience": a.audience,
                "projectId": a.project_id,
                "clientId": a.oauth.client_id,
                "connected": a.access.is_some() && a.failed.is_none(),
                "failed": a.failed,
                "updatedAt": a.updated_at,
            })
        });
        json!({
            "account": account,
            "agents": st.store.agents.iter().map(|(vm, a)| json!({"vmId": vm, "name": a.name, "granted": a.granted})).collect::<Vec<_>>(),
        })
    }

    /// Reports made outside a command (mint failures), drained by the heartbeat.
    pub fn drain_reports(&self) -> Vec<CommandResult> {
        std::mem::take(&mut *self.reports.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub async fn command(&self, action: &str, payload: Map<String, Value>) -> CommandOutcome {
        let _serial = self.serial.lock().await;
        let r = match action {
            "propose" => self.propose(&payload).await,
            "callback" => self.callback(&payload).await,
            "confirm" => self.confirm(&payload).await,
            "cancel" => Ok(self.cancel(&payload)),
            "push" => self.push(&payload).await,
            "forget" => self.forget(&payload).await,
            "read" => {
                let data = self.summary().as_object().cloned().unwrap_or_default();
                Ok(outcome(true, "read", None, data))
            }
            _ => Err(format!("unknown command google.{action}")),
        };
        r.unwrap_or_else(|message| CommandOutcome {
            ok: false,
            status: "failed".into(),
            message: Some(message),
            data: None,
        })
    }

    fn change_data(change_id: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("changeId".into(), json!(change_id));
        m
    }

    /// A new change replaces the one waiting for a code: an account exchanged for it is dropped,
    /// and a first connection's grant is given back (nothing on this box uses it).
    async fn drop_awaiting(&self) {
        let dropped = {
            let mut st = self.lock();
            let first = Self::the_account(&st.store).is_none();
            st.awaiting.take().filter(|_| first)
        };
        if let Some((account, _)) = dropped {
            tokens::revoke_google_token(&*self.opts.http, &account.refresh).await;
        }
    }

    async fn propose(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let p = parse_proposal(payload)?;
        self.drop_awaiting().await;
        // Before validating: a change this box cannot ask anyone to confirm is going nowhere.
        let Some(routes) = (self.opts.code_routes)() else {
            return Ok(outcome(
                false,
                "failed",
                Some(NO_CHANNELS.into()),
                Self::change_data(&p.change_id),
            ));
        };
        self.validate(&p)?;
        if p.kind == "connect_account" || p.kind == "replace_account" {
            return self.start_authorization(&p);
        }
        let label = self.account_label();
        let summary = summarize(&p, label.as_deref());
        let mut data = Self::change_data(&p.change_id);
        data.insert("summary".into(), json!(summary));
        if routes.is_empty() {
            if let Some(c) = (self.opts.codes)() {
                c.forget(SCOPE);
            }
            data.extend(self.apply(&p).await?);
            data.insert("tofu".into(), json!(true));
            return Ok(outcome(true, "applied", None, data));
        }
        self.send_code(&p, summary, routes, data).await
    }

    async fn send_code(
        &self,
        p: &Proposal,
        summary: String,
        routes: Vec<Value>,
        mut data: Map<String, Value>,
    ) -> Result<CommandOutcome, String> {
        // Nobody to hand the code to on this firewall: refused (fail closed).
        let Some(codes) = (self.opts.codes)() else {
            return Ok(outcome(false, "failed", Some(NO_CODES.into()), data));
        };
        let sent = codes
            .send(CodeRequest {
                scope: SCOPE.into(),
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: CODE_SUBJECT.into(),
                summary,
                routes,
            })
            .await;
        let Some(via) = sent.sent_via.clone() else {
            return Ok(outcome(false, "failed", Some(sent.error.unwrap_or_default()), data));
        };
        tracing::info!("[google] code sent for {} via {via}", p.kind);
        self.lock().sent_via = Some((p.change_id.clone(), via.clone()));
        data.insert("sentVia".into(), json!(via));
        data.insert("expiresAt".into(), json!(iso(sent.expires_at_ms)));
        data.insert("attemptsLeft".into(), json!(CODE_ATTEMPTS));
        Ok(outcome(true, "awaiting_code", None, data))
    }

    /// Store the customer's client and a fresh PKCE pair, and answer with the URL to send them to.
    fn start_authorization(&self, p: &Proposal) -> Result<CommandOutcome, String> {
        let client = p
            .client
            .clone()
            .ok_or("a Google connection needs its client id, client secret and redirect URI")?;
        let (verifier, challenge) = tokens::make_pkce();
        let state = tokens::make_state();
        let scopes = tokens::scopes_for(&p.services, &p.gmail_scope, &p.drive_scope);
        let expires = self.now() + store::PENDING_AUTH_TTL_MS;
        let hint = {
            let mut st = self.lock();
            let mut next = st.store.clone();
            next.pending = Some(Pending {
                change_id: p.change_id.clone(),
                state: state.clone(),
                verifier,
                services: p.services.clone(),
                gmail_scope: p.gmail_scope.clone(),
                drive_scope: p.drive_scope.clone(),
                audience: p.audience.clone(),
                project_id: p.project_id.clone(),
                oauth: client.clone(),
                expires,
                extra: Map::new(),
            });
            self.save(&next)?;
            st.store = next;
            st.pending_agents = p.agents.clone();
            Self::the_account(&st.store).and_then(|a| a.account_label.clone())
        };
        let url = tokens::authorize_url(
            &client.client_id,
            &client.redirect_uri,
            &scopes,
            &state,
            &challenge,
            hint.as_deref(),
        );
        tracing::info!(
            "[google] authorization started for {} ({} scope(s))",
            p.kind,
            scopes.len()
        );
        let mut data = Self::change_data(&p.change_id);
        data.insert("summary".into(), json!(summarize(p, None)));
        data.insert("authorizeUrl".into(), json!(url));
        data.insert("scopes".into(), json!(scopes));
        data.insert("expiresAt".into(), json!(iso(expires)));
        Ok(outcome(true, "awaiting_authorization", None, data))
    }

    /// Drop the pending authorization and save.
    fn clear_pending(&self) -> Result<(), String> {
        let mut st = self.lock();
        let mut next = st.store.clone();
        next.pending = None;
        self.save(&next)?;
        st.store = next;
        Ok(())
    }

    /// The relayed consent result: where the code becomes a refresh token. The account is stored
    /// only once a person confirmed the code.
    async fn callback(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let state = s(payload.get("state"));
        let code = s(payload.get("code"));
        let error = s(payload.get("error"));
        let pending = self.lock().store.pending.clone();
        let Some(pending) = pending.filter(|p| {
            state
                .as_deref()
                .is_some_and(|s| cc_crypto::ct_eq(s.as_bytes(), p.state.as_bytes()))
        }) else {
            // The same answer for no authorization, the wrong state and one already completed.
            return Ok(CommandOutcome {
                ok: false,
                status: "failed".into(),
                message: Some(
                    "This sign-in does not match an authorization your firewall started. Start the connection again."
                        .into(),
                ),
                data: None,
            });
        };
        let mut data = Self::change_data(&pending.change_id);
        if pending.expires < self.now() {
            self.clear_pending()?;
            return Ok(outcome(
                false,
                "expired",
                Some("That sign-in link had expired. Start the connection again.".into()),
                data,
            ));
        }
        let Some(code) = code.filter(|_| error.is_none()) else {
            self.clear_pending()?;
            let message = if error.as_deref() == Some("access_denied") {
                "The Google sign-in was cancelled.".to_string()
            } else {
                format!(
                    "Google refused the sign-in: {}.",
                    error.as_deref().unwrap_or("no code was returned")
                )
            };
            return Ok(outcome(false, "failed", Some(message), data));
        };
        let exchanged = tokens::exchange_code(
            &*self.opts.http,
            ExchangeInput {
                code: &code,
                verifier: &pending.verifier,
                client_id: &pending.oauth.client_id,
                client_secret: &pending.oauth.client_secret,
                redirect_uri: &pending.oauth.redirect_uri,
                token_endpoint: &pending.oauth.token_endpoint,
            },
            self.now(),
        )
        .await;
        // Either way the code is spent and the verifier is of no further use.
        self.clear_pending()?;
        let (refresh, access, expires, label, granted) = match exchanged {
            Exchange::Err { reason, .. } => {
                return Ok(outcome(
                    false,
                    "failed",
                    Some(format!("Google refused this connection: {reason}")),
                    data,
                ));
            }
            Exchange::Ok {
                refresh,
                access,
                expires,
                account_label,
                granted_scopes,
            } => (refresh, access, expires, account_label, granted_scopes),
        };
        cc_crypto::enc_file::remember_encrypted_secrets(&json!([refresh, access]), true);
        let requested = tokens::scopes_for(&pending.services, &pending.gmail_scope, &pending.drive_scope);
        let missing = tokens::missing_scopes(&requested, &granted);
        if !missing.is_empty() {
            // Revoking cancels the whole grant for this account and client: only a first connection
            // gives its token back.
            let first = Self::the_account(&self.lock().store).is_none();
            if first {
                tokens::revoke_google_token(&*self.opts.http, &refresh).await;
            }
            let shown: Vec<String> = granted
                .iter()
                .filter(|s| s.starts_with("https://www.googleapis.com/auth/") && !s.ends_with("/userinfo.email"))
                .map(|s| tokens::scope_name(s))
                .collect();
            let message = format!(
                "Google granted only {}. Missing: {}. Connect again and leave every permission ticked on Google's screen.",
                if shown.is_empty() {
                    "your sign-in".to_string()
                } else {
                    shown.join(", ")
                },
                missing
                    .iter()
                    .map(|s| tokens::scope_name(s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            data.insert("grantedScopes".into(), json!(granted));
            data.insert("missingScopes".into(), json!(missing));
            return Ok(outcome(false, "failed", Some(message), data));
        }
        let refusals = tokens::probe_services(&*self.opts.http, &access, &pending.services, &pending.gmail_scope).await;
        let fatal: Vec<_> = refusals.iter().filter(|r| r.permanent).collect();
        if !fatal.is_empty() {
            let named = fatal
                .iter()
                .map(|r| format!("{}: {}", service_list(std::slice::from_ref(&r.service)), r.reason))
                .collect::<Vec<_>>()
                .join(" ");
            return Ok(outcome(
                false,
                "failed",
                Some(format!(
                    "This Google account cannot use everything you asked for. {named}"
                )),
                data,
            ));
        }
        if !refusals.is_empty() {
            tracing::info!(
                "[google] {} service probe(s) inconclusive: {}",
                refusals.len(),
                refusals
                    .iter()
                    .map(|r| r.reason.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        let account = Account {
            account_label: label.clone(),
            services: pending.services.clone(),
            scopes: granted.clone(),
            gmail_scope: pending.gmail_scope.clone(),
            drive_scope: pending.drive_scope.clone(),
            audience: pending.audience.clone(),
            project_id: pending.project_id.clone(),
            oauth: pending.oauth.clone(),
            refresh,
            access: Some(AccessToken {
                token: access,
                expires,
                extra: Map::new(),
            }),
            failed: None,
            updated_at: iso(self.now()),
            extra: Map::new(),
        };
        let (kind, agents) = {
            let st = self.lock();
            let kind = if Self::the_account(&st.store).is_some() {
                "replace_account"
            } else {
                "connect_account"
            };
            (kind, st.pending_agents.clone())
        };
        let proposal = Proposal {
            change_id: pending.change_id.clone(),
            kind: kind.into(),
            client: Some(pending.oauth.clone()),
            services: pending.services.clone(),
            gmail_scope: pending.gmail_scope.clone(),
            drive_scope: pending.drive_scope.clone(),
            audience: pending.audience.clone(),
            project_id: pending.project_id.clone(),
            agents,
        };
        let summary = summarize(&proposal, label.as_deref());
        data.insert("summary".into(), json!(summary));
        data.insert("accountLabel".into(), json!(label));
        data.insert("scopes".into(), json!(granted));
        let Some(routes) = (self.opts.code_routes)() else {
            // Nothing will be stored, so a first connection gives its grant back.
            if Self::the_account(&self.lock().store).is_none() {
                tokens::revoke_google_token(&*self.opts.http, &account.refresh).await;
            }
            return Ok(outcome(false, "failed", Some(NO_CHANNELS.into()), data));
        };
        if routes.is_empty() {
            // Trust on first use: nobody is approved to be asked yet.
            if let Some(c) = (self.opts.codes)() {
                c.forget(SCOPE);
            }
            data.extend(self.apply_account(account, &proposal).await?);
            data.insert("tofu".into(), json!(true));
            return Ok(outcome(true, "applied", None, data));
        }
        // Held in memory until the code comes back: an account written now would be a credential
        // nobody confirmed, sitting on the box.
        let first = Self::the_account(&self.lock().store).is_none();
        let refresh = account.refresh.clone();
        self.lock().awaiting = Some((account, proposal.clone()));
        let out = self.send_code(&proposal, summary, routes, data).await?;
        if !out.ok {
            self.lock().awaiting = None;
            // Nothing is stored: a first connection gives its grant back.
            if first {
                tokens::revoke_google_token(&*self.opts.http, &refresh).await;
            }
        } else {
            tracing::info!(
                "[google] exchanged a code for {}; confirmation sent",
                label.as_deref().unwrap_or("an account")
            );
        }
        Ok(out)
    }

    async fn confirm(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let change_id = s(payload.get("changeId")).ok_or("malformed google.confirm payload")?;
        let code = s(payload.get("code")).unwrap_or_default();
        let mut data = Self::change_data(&change_id);
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
        let sent_via = {
            let mut st = self.lock();
            match st.sent_via.take() {
                Some((id, via)) if id == change_id => Some(via),
                other => {
                    st.sent_via = other;
                    None
                }
            }
        };
        let verified = parse_proposal(proposal.as_object().ok_or("malformed google.confirm payload")?)?;
        // The held account only for the connection the code was verified for: a code for another
        // change with the same id never installs it.
        let held = {
            let mut st = self.lock();
            match st.awaiting.take() {
                Some((a, p))
                    if p.change_id == change_id
                        && (verified.kind == "connect_account" || verified.kind == "replace_account")
                        && p.kind == verified.kind =>
                {
                    Some((a, p))
                }
                other => {
                    st.awaiting = other;
                    None
                }
            }
        };
        if let Some((account, p)) = held {
            let label = account.account_label.clone();
            data.extend(self.apply_account(account, &p).await?);
            data.insert("summary".into(), json!(summarize(&p, label.as_deref())));
            data.insert("sentVia".into(), json!(sent_via));
            data.insert("tofu".into(), json!(false));
            return Ok(outcome(true, "applied", None, data));
        }
        let p = verified;
        if p.kind == "connect_account" || p.kind == "replace_account" {
            return Ok(outcome(
                false,
                "failed",
                Some(
                    "Your firewall restarted before this connection was confirmed. Start the connection again.".into(),
                ),
                data,
            ));
        }
        data.extend(self.apply(&p).await?);
        let label = self.account_label();
        data.insert("summary".into(), json!(summarize(&p, label.as_deref())));
        data.insert("sentVia".into(), json!(sent_via));
        data.insert("tofu".into(), json!(false));
        Ok(outcome(true, "applied", None, data))
    }

    fn cancel(&self, payload: &Map<String, Value>) -> CommandOutcome {
        let change_id = s(payload.get("changeId"));
        if let Some(c) = (self.opts.codes)() {
            c.cancel(SCOPE, change_id.as_deref());
        }
        let mut st = self.lock();
        if st
            .awaiting
            .as_ref()
            .is_some_and(|(_, p)| Some(&p.change_id) == change_id.as_ref())
        {
            st.awaiting = None;
        }
        if st
            .store
            .pending
            .as_ref()
            .is_some_and(|p| change_id.as_ref().is_none_or(|c| c == &p.change_id))
        {
            let mut next = st.store.clone();
            next.pending = None;
            if self.save(&next).is_ok() {
                st.store = next;
            }
        }
        let mut data = Map::new();
        data.insert("changeId".into(), json!(change_id));
        outcome(true, "cancelled", None, data)
    }

    async fn push(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm = s(payload.get("vmId")).ok_or("malformed google.push payload")?;
        let (granted, name) = {
            let mut st = self.lock();
            if !st.store.agents.contains_key(&vm) {
                drop(st);
                let mut data = Map::new();
                data.insert("vmId".into(), json!(vm));
                data.insert("granted".into(), json!(false));
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
            let out = (a.granted, a.name.clone());
            self.save(&next)?;
            st.store = next;
            out
        };
        let failed = self.push_agents(std::slice::from_ref(&vm)).await;
        tracing::info!(
            "[google] re-applied on {name}{}",
            failed.first().map_or(String::new(), |f| format!(" (failed: {})", f.1))
        );
        let mut data = Map::new();
        data.insert("vmId".into(), json!(vm));
        data.insert("granted".into(), json!(granted));
        data.insert("failed".into(), failed_json(&failed));
        let message = failed.iter().map(|f| f.1.clone()).collect::<Vec<_>>().join("; ");
        Ok(CommandOutcome {
            ok: failed.is_empty(),
            status: if failed.is_empty() { "applied" } else { "failed" }.into(),
            message: Some(message),
            data: Some(data),
        })
    }

    /// An agent was deleted: drop it, so the proxy stops carrying a credential for it. No code.
    async fn forget(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm = s(payload.get("vmId")).ok_or("malformed google.forget payload")?;
        let mut data = Map::new();
        data.insert("vmId".into(), json!(vm));
        let removed = {
            let mut st = self.lock();
            if !st.store.agents.contains_key(&vm) {
                false
            } else {
                let mut next = st.store.clone();
                next.agents.shift_remove(&vm);
                self.save(&next)?;
                st.store = next;
                true
            }
        };
        if removed {
            self.changed().await;
            tracing::info!("[google] forgot agent {vm}");
        }
        Ok(outcome(true, "applied", None, data))
    }

    /// Refuse a proposal the control plane should not have sent.
    fn validate(&self, p: &Proposal) -> Result<(), String> {
        let pick_one = "Pick at least one Google service for the agents to use.";
        match p.kind.as_str() {
            "connect_account" | "replace_account" => {
                let c = p
                    .client
                    .as_ref()
                    .ok_or("a Google connection needs its client id, client secret and redirect URI")?;
                if !store::is_valid_client_id(&c.client_id) {
                    return Err(
                        "That does not look like a Google OAuth client id. It ends in .apps.googleusercontent.com."
                            .into(),
                    );
                }
                if p.services.is_empty() {
                    return Err(pick_one.into());
                }
                if p.project_id
                    .as_deref()
                    .is_some_and(|id| !store::is_valid_project_id(id))
                {
                    return Err(
                        "That does not look like a Google Cloud project id (lowercase letters, digits and hyphens)."
                            .into(),
                    );
                }
                let url = url::Url::parse(&c.redirect_uri).map_err(|_| "The redirect URI is not a URL.")?;
                let host = url.host_str().unwrap_or("");
                if url.scheme() != "https" && host != "localhost" && host != "127.0.0.1" {
                    return Err("The redirect URI has to be https (or localhost for a local dev run).".into());
                }
            }
            "set_services" => {
                if p.services.is_empty() {
                    return Err(pick_one.into());
                }
                let st = self.lock();
                let a = Self::the_account(&st.store).ok_or("Connect a Google account first.")?;
                let added: Vec<String> = p.services.iter().filter(|s| !a.services.contains(s)).cloned().collect();
                if !added.is_empty() {
                    return Err(format!(
                        "Google has to be asked again before the agents can use {}. Reconnect the account with those services ticked.",
                        service_list(&added)
                    ));
                }
            }
            "grant_agent" | "revoke_agent" => {
                if p.agents.is_empty() {
                    return Err("the proposal names no agent".into());
                }
                if p.kind == "grant_agent" && Self::the_account(&self.lock().store).is_none() {
                    return Err("Connect a Google account before giving it to an agent.".into());
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The whole desired state of one agent box. A revoked grant travels as `placeholder: null`.
    fn apply_body_in(st: &GoogleStore, vm_id: &str) -> Value {
        let agent = st.agents.get(vm_id);
        let account = Self::the_account(st);
        let live = account.is_some_and(|a| a.access.is_some() && a.failed.is_none());
        let granted = agent.is_some_and(|a| a.granted) && live;
        json!({
            "placeholder": if granted { agent.map(|a| a.placeholder.clone()) } else { None },
            "connected": live,
            "projectId": account.and_then(|a| a.project_id.clone()),
            "services": if granted { account.map(|a| a.services.clone()).unwrap_or_default() } else { vec![] },
            "accountLabel": account.and_then(|a| a.account_label.clone()),
            "granted": agent.is_some_and(|a| a.granted) && account.is_some(),
        })
    }

    async fn push_agents(&self, vm_ids: &[String]) -> Vec<(String, String)> {
        let mut failed = vec![];
        for vm in vm_ids {
            let (target, body) = {
                let st = self.lock();
                let host = st.store.agents.get(vm).and_then(|a| a.hostname.clone());
                (host.map(|h| Target::new(vm, &h)), Self::apply_body_in(&st.store, vm))
            };
            let Some(target) = target else {
                failed.push((vm.clone(), "This agent has no hostname yet.".to_string()));
                continue;
            };
            if let Err(e) = self.opts.agent.post(&target, "/google/apply", body, None).await {
                failed.push((vm.clone(), e.message));
            }
        }
        failed
    }

    /// Make a change to the store as it is now, under one lock, and save it; then re-sync the proxy
    /// and push to everyone it touched. A token a refresh recorded meanwhile is kept. `replaced`:
    /// the account itself went, so a refresh answer still in flight is for the old one.
    /// `applied` is the boxes reached; `granted` is read off the store, the only authority on it.
    async fn finish(
        &self,
        replaced: bool,
        change: impl FnOnce(&mut GoogleStore) -> Result<Vec<String>, String>,
    ) -> Result<Map<String, Value>, String> {
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
        let granted: Vec<String> = self
            .lock()
            .store
            .agents
            .iter()
            .filter(|(_, a)| a.granted)
            .map(|(v, _)| v.clone())
            .collect();
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
        m.insert("granted".into(), json!(granted));
        Ok(m)
    }

    fn agent_of<'a>(st: &'a mut GoogleStore, r: &AgentRef) -> &'a mut Agent {
        let a = st.agents.entry(r.vm_id.clone()).or_insert_with(|| Agent {
            name: r.name.clone(),
            hostname: r.hostname.clone(),
            placeholder: format!("CC-GOOG-{}", hex::encode(rand::random::<[u8; 12]>())),
            granted: false,
            extra: Map::new(),
        });
        if !r.name.is_empty() {
            a.name = r.name.clone();
        }
        if r.hostname.is_some() {
            a.hostname = r.hostname.clone();
        }
        a
    }

    /// Store an exchanged account and make it spendable. Agents keep their grants across a
    /// reconnect, and any agent named in the proposal is granted as well.
    async fn apply_account(&self, account: Account, p: &Proposal) -> Result<Map<String, Value>, String> {
        tracing::info!(
            "[google] connected {} ({})",
            account.account_label.as_deref().unwrap_or("an account"),
            account.services.join(", ")
        );
        let mut m = Map::new();
        m.insert("accountId".into(), json!(ACCOUNT_ID));
        m.insert("accountLabel".into(), json!(account.account_label));
        m.insert("services".into(), json!(account.services));
        m.insert("scopes".into(), json!(account.scopes));
        let done = self
            .finish(true, |next| {
                let mut targets: Vec<String> = next.agents.keys().cloned().collect();
                next.accounts = IndexMap::from([(ACCOUNT_ID.to_string(), account)]);
                for r in &p.agents {
                    Self::agent_of(next, r).granted = true;
                    if !targets.contains(&r.vm_id) {
                        targets.push(r.vm_id.clone());
                    }
                }
                Ok(targets)
            })
            .await?;
        m.extend(done);
        Ok(m)
    }

    async fn apply(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let names: Vec<&str> = p.agents.iter().map(|a| a.name.as_str()).collect();
        let vms = || p.agents.iter().map(|a| a.vm_id.clone()).collect::<Vec<_>>();
        match p.kind.as_str() {
            "forget_account" => {
                tracing::info!("[google] disconnected the Google account and cleared every grant");
                self.finish(true, |next| {
                    let before: Vec<String> = next.agents.keys().cloned().collect();
                    next.accounts.clear();
                    // The rows stay, with their grants cleared: nothing granted, nothing emitted.
                    for a in next.agents.values_mut() {
                        a.granted = false;
                    }
                    Ok(before)
                })
                .await
            }
            "grant_agent" => {
                tracing::info!("[google] granted the Google account to {}", agent_list(&names));
                self.finish(false, |next| {
                    for r in &p.agents {
                        Self::agent_of(next, r).granted = true;
                    }
                    Ok(vms())
                })
                .await
            }
            "revoke_agent" => {
                tracing::info!("[google] revoked the Google account from {}", agent_list(&names));
                self.finish(false, |next| {
                    for r in &p.agents {
                        if let Some(a) = next.agents.get_mut(&r.vm_id) {
                            a.granted = false;
                        }
                    }
                    Ok(vms())
                })
                .await
            }
            "set_services" => {
                let now = iso(self.now());
                tracing::info!("[google] the account now covers {}", service_list(&p.services));
                self.finish(false, |next| {
                    let a = next
                        .accounts
                        .values_mut()
                        .next()
                        .ok_or("Connect a Google account first.")?;
                    a.services = p.services.clone();
                    a.updated_at = now;
                    Ok(next.agents.keys().cloned().collect())
                })
                .await
            }
            _ => Err("a Google connection is applied by its callback, not by this path".into()),
        }
    }

    // ---- token minting ----

    /// Keep the account's access token live. A permanent refusal marks it failed; anything else is
    /// retried on the next tick with the old token still in place.
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
        let due: Vec<(String, Account, u64)> = {
            let st = self.lock();
            let now = self.now();
            st.store
                .accounts
                .iter()
                .filter(|(_, a)| a.failed.is_none())
                .filter(|(_, a)| {
                    a.access
                        .as_ref()
                        .is_none_or(|t| t.expires - now <= GOOGLE_REFRESH_AHEAD_MS)
                })
                .map(|(id, a)| (id.clone(), a.clone(), st.generation))
                .collect()
        };
        let mut changed = false;
        for (id, account, generation) in due {
            let minted = tokens::refresh_token(
                &*self.opts.http,
                &account.oauth.token_endpoint,
                &account.refresh,
                &account.oauth.client_id,
                &account.oauth.client_secret,
                self.now(),
            )
            .await;
            let mut st = self.lock();
            // A confirm that landed while Google was answering gave this organization a different
            // connection: the answer is for the old one.
            if st.generation != generation || !st.store.accounts.contains_key(&id) {
                tracing::info!("[google] token answer for {id} arrived after the account was replaced; dropped");
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

    fn record(&self, id: &str, a: &mut Account, minted: Mint) -> bool {
        match minted {
            Mint::Err {
                permanent: false,
                reason,
                ..
            } => {
                tracing::info!(
                    "[google] token for {} failed ({reason}); will retry",
                    a.account_label.as_deref().unwrap_or(id)
                );
                false
            }
            Mint::Err { reason, .. } => {
                let because = if a.audience == "external_testing" {
                    " An app still in Testing expires its refresh token after seven days; publishing the app removes that."
                } else {
                    ""
                };
                let failed = format!("Google refused the connection: {reason}.{because} Connect the account again.");
                a.failed = Some(failed.clone());
                a.access = None;
                let mut data = Map::new();
                data.insert("accountId".into(), json!(id));
                self.reports
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(CommandResult {
                        command_id: format!("google.token:{id}"),
                        ok: false,
                        status: "failed".into(),
                        message: failed,
                        data: Some(data),
                    });
                tracing::info!(
                    "[google] token for {} refused: {reason}",
                    a.account_label.as_deref().unwrap_or(id)
                );
                true
            }
            Mint::Ok {
                token,
                expires,
                refresh,
            } => {
                cc_crypto::enc_file::remember_encrypted_secrets(&json!([token, refresh]), true);
                a.access = Some(AccessToken {
                    token,
                    expires,
                    extra: Map::new(),
                });
                if let Some(r) = refresh {
                    a.refresh = r;
                }
                a.updated_at = iso(self.now());
                tracing::info!(
                    "[google] minted a token for {} (expires in {} min)",
                    a.account_label.as_deref().unwrap_or(id),
                    ((expires - self.now()) as f64 / 60_000.0).round()
                );
                true
            }
        }
    }
}

pub(crate) fn failed_json(failed: &[(String, String)]) -> Value {
    json!(
        failed
            .iter()
            .map(|(v, e)| json!({"vmId": v, "error": e}))
            .collect::<Vec<_>>()
    )
}

#[cfg(test)]
mod tests;
