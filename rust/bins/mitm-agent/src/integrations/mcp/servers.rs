//! MCP servers the organization defines once and gives to agents (`mcp-servers.ts`,
//! docs/plans/mcp-servers.md). The credentials live here, in `mcp-servers.enc`; an agent's OpenClaw
//! holds only the address of this firewall's gate (`/servers/<name>/mcp` on the 3940 listener),
//! which adds them.
//!
//! ```text
//!   mcpservers.read     {}                                  the servers, their tools and agents; never a secret
//!   mcpservers.propose  { changeId, kind, name, ..., secret? }
//!   mcpservers.confirm  { changeId, code }
//!   mcpservers.cancel   { changeId }
//!   mcpservers.callback { state, code? | error? }           the relayed OAuth callback
//!   mcpservers.tools    { name }                            read the tool list again
//!   mcpservers.push     { vmId }                            re-push after a box comes up
//!   mcpservers.forget   { vmId }                            an agent was deleted
//! ```

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use super::client::{McpServerError, cut, list_tools};
use super::oauth::{self, OauthClient, OauthDiscovery};
use super::public::public_https_url;
use super::store::{self, Header, McpServersStore, Oauth, StoredMcpServer};
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::integrations::codes::{Codes, Verified};
use crate::integrations::connectors::firewall::str_of;
use crate::integrations::{as_map, failed, js, outcome};

const SCOPE: &str = "mcp-servers";
pub static MCP_NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,39}$").expect("pattern"));
static HEADER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$").expect("pattern"));
/// Headers the gate sets itself: a credential header may not be one of them.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-type",
    "content-length",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
    "connection",
    "transfer-encoding",
    "cookie",
];
pub const OAUTH_PENDING_MS: i64 = 15 * 60_000;
/// A token this close to its end is refreshed before it is used.
const REFRESH_EARLY_MS: f64 = 60_000.0;
const LIST_TIMEOUT: Duration = Duration::from_secs(20);
/// The names a plain JavaScript object already has (`name in {}`): the TS refuses them.
const OBJECT_NAMES: &[&str] = &[
    "constructor",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
    "__proto__",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

/// Names the agent's own software writes in `mcp.servers`: an organization's server by one of them
/// would fight that writer for the entry.
pub fn reserved_mcp_name(name: &str) -> bool {
    name.starts_with("controlclaw") || name == "gbrain" || OBJECT_NAMES.contains(&name)
}

/// A server name the gate and the store accept: the pattern, and not reserved.
pub fn mcp_name_ok(name: &str) -> bool {
    MCP_NAME_RE.is_match(name) && !reserved_mcp_name(name)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRef {
    pub vm_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proposal {
    pub change_id: String,
    /// `add`, `replace`, `reconnect`, `remove`, `assign`, `unassign`.
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub auth: String,
    pub header_name: Option<String>,
    pub client_id: Option<String>,
    pub agents: Vec<AgentRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
}

const KINDS: &[&str] = &["add", "replace", "reconnect", "remove", "assign", "unassign"];

pub fn parse_proposal(p: &Map<String, Value>) -> Result<Proposal, String> {
    let change_id = str_of(p.get("changeId"));
    let name = str_of(p.get("name"));
    let kind = p.get("kind").and_then(Value::as_str).filter(|k| KINDS.contains(k));
    let (Some(change_id), Some(name), Some(kind)) = (change_id, name, kind) else {
        return Err("malformed mcpservers.propose payload".into());
    };
    if !MCP_NAME_RE.is_match(&name) || reserved_mcp_name(&name) {
        return Err("malformed mcpservers.propose payload".into());
    }
    let auth = match p.get("auth").and_then(Value::as_str) {
        Some(a @ ("header" | "oauth")) => a.to_string(),
        _ => "none".into(),
    };
    let url = str_of(p.get("url"));
    // No query or fragment: a key put there would be stored and shown as part of the address.
    if kind == "add"
        && !url.as_deref().is_some_and(|u| {
            public_https_url(u).is_some() && u.encode_utf16().count() <= 500 && !u.contains('?') && !u.contains('#')
        })
    {
        return Err("The address must be https, on the internet, with no user name, password or query in it.".into());
    }
    let header_name = str_of(p.get("headerName"));
    if auth == "header"
        && (kind == "add" || kind == "replace")
        && !header_name
            .as_deref()
            .is_some_and(|h| HEADER_RE.is_match(h) && !RESERVED_HEADERS.contains(&h.to_lowercase().as_str()))
    {
        return Err("The header's name is not one the firewall can send.".into());
    }
    // Only these kinds name agents. Any other ignores them, so its code message cannot hide a grant.
    let agents = if ["add", "assign", "unassign"].contains(&kind) {
        p.get("agents")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| str_of(x.get("vmId")))
                    .take(200)
                    .map(|vm| AgentRef {
                        name: vm.clone(),
                        vm_id: vm,
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };
    let secret = p.get("secret").filter(|s| !s.is_null()).map(|s| Secret {
        header_value: str_of(s.get("headerValue")).map(|v| cut(&v, 4096)),
        client_secret: str_of(s.get("clientSecret")).map(|v| cut(&v, 4096)),
    });
    Ok(Proposal {
        change_id,
        kind: kind.to_string(),
        name,
        url: if kind == "add" { url } else { None },
        header_name: if auth == "header" { header_name } else { None },
        auth,
        client_id: str_of(p.get("clientId")).map(|c| cut(&c, 500)),
        agents,
        secret,
    })
}

/// `new URL(u).host`.
fn host_of(u: &str) -> Option<String> {
    let url = Url::parse(u).ok()?;
    let h = url.host_str()?.to_string();
    Some(match url.port() {
        Some(p) => format!("{h}:{p}"),
        None => h,
    })
}

/// The one-line summary the code message carries. Written here, from the firewall's own record.
pub fn summarize(p: &Proposal, url: Option<&str>) -> String {
    let host = url.and_then(host_of).map(|h| format!(" ({h})")).unwrap_or_default();
    let named = format!("the MCP server {}{host}", p.name);
    let who = p.agents.first().map(|a| a.name.as_str()).unwrap_or("the agent");
    let to = match p.agents.len() {
        0 => String::new(),
        1 => format!(" and give it to {}", p.agents[0].name),
        n => format!(" and give it to {n} agents"),
    };
    match p.kind.as_str() {
        "add" => format!("Add {named}{to}"),
        "replace" => format!("Replace the credential of {named}"),
        "reconnect" => format!("Sign in to {named} again"),
        "remove" => format!("Remove {named} from the organization"),
        "assign" => format!("Let {who} use {named}"),
        _ => format!("Stop {who} using {named}"),
    }
}

/// What the gate needs of a server an agent calls.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerFor {
    Unknown,
    Known { url: String, allowed: bool, state: String },
}

/// A sign-in this firewall started and waits for the callback of. `server_created_at`: the server it
/// is for (None for an add), so a late callback cannot land on one removed and added again.
struct PendingOauth {
    verifier: String,
    discovery: OauthDiscovery,
    client: OauthClient,
    proposal: Proposal,
    url: String,
    server_created_at: Option<String>,
    started_at: i64,
}

struct Applied {
    status: String,
    data: Map<String, Value>,
}

fn message_of(e: &str) -> String {
    cut(e, 500)
}

pub struct McpServersFirewall {
    app: Arc<App>,
    path: PathBuf,
    store: RwLock<McpServersStore>,
    codes: Codes,
    /// `http://<private ip>:3940/servers/` : where an agent box reaches a server through this firewall.
    gate_base: String,
    /// ControlClaw's `/oauth/callback`, which relays a sign-in here.
    redirect_uri: String,
    pending: Mutex<Vec<(String, PendingOauth)>>,
    /// One command at a time, as the TS ran them between awaits.
    op: tokio::sync::Mutex<()>,
    /// One refresh at a time: a second caller waits and uses the first one's tokens.
    refreshing: tokio::sync::Mutex<()>,
    push_concurrency: usize,
}

fn now_ms() -> i64 {
    js::now_ms()
}

impl McpServersFirewall {
    pub fn new(app: &Arc<App>, path: PathBuf, gate_base: String, redirect_uri: String) -> Arc<Self> {
        let store = store::load(&path, &app.box_key, &app.config.org_id, &app.config.box_id);
        Arc::new(Self {
            app: app.clone(),
            path,
            store: RwLock::new(store),
            codes: Codes::new(app, SCOPE),
            gate_base,
            redirect_uri,
            pending: Mutex::new(Vec::new()),
            op: tokio::sync::Mutex::new(()),
            refreshing: tokio::sync::Mutex::new(()),
            push_concurrency: 4,
        })
    }

    fn read_store(&self) -> std::sync::RwLockReadGuard<'_, McpServersStore> {
        self.store.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_store(&self) -> std::sync::RwLockWriteGuard<'_, McpServersStore> {
        self.store.write().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self) {
        let s = self.read_store().clone();
        if let Err(e) = store::save(
            &self.path,
            &s,
            &self.app.box_key,
            &self.app.config.org_id,
            &self.app.config.box_id,
        ) {
            tracing::error!("[mcp-servers] could not save the store: {e}");
        }
    }

    fn server(&self, name: &str) -> Option<StoredMcpServer> {
        self.read_store().servers.get(name).cloned()
    }

    pub fn summary(&self) -> (usize, usize) {
        let s = self.read_store();
        let mut agents: Vec<&String> = s.servers.values().flat_map(|x| x.agents.iter()).collect();
        agents.sort();
        agents.dedup();
        (s.servers.len(), agents.len())
    }

    /// This firewall's own record of an agent; None for one it does not know. The code message
    /// names agents from here, never from the proposal.
    fn agent_of(&self, vm_id: &str) -> Option<Option<String>> {
        let ids = self.app.contracts.identities.require().ok()?;
        ids.agent(vm_id).map(|a| a.name)
    }

    pub fn gate_url(&self, name: &str) -> String {
        format!("{}{name}/mcp", self.gate_base)
    }

    // ---- what the gate asks ----

    /// The server an agent calls, when that agent may use it.
    pub fn server_for(&self, vm_id: &str, name: &str) -> ServerFor {
        match self.read_store().servers.get(name) {
            None => ServerFor::Unknown,
            Some(s) => ServerFor::Known {
                url: s.url.clone(),
                allowed: s.agents.iter().any(|a| a == vm_id),
                state: s.state.clone(),
            },
        }
    }

    /// The headers that sign this firewall in to the server; refreshes an OAuth token near its
    /// end. None when it cannot sign in.
    pub async fn credential_headers(&self, name: &str) -> Option<Vec<(String, String)>> {
        let s = self.server(name)?;
        match s.auth.as_str() {
            "none" => return Some(vec![]),
            "header" => return s.header.map(|h| vec![(h.name, h.value)]),
            _ => {}
        }
        let tokens = s.oauth?.tokens?;
        if let Some(exp) = tokens.expires_at
            && exp - REFRESH_EARLY_MS <= now_ms() as f64
            && !self.refresh(name).await
        {
            return None;
        }
        let fresh = self.server(name)?.oauth?.tokens?;
        Some(vec![("authorization".into(), format!("Bearer {}", fresh.access_token))])
    }

    /// The server said 401 to a token: refresh once (one refresh at a time). False when it cannot.
    pub async fn refresh(&self, name: &str) -> bool {
        let before = self.server(name).and_then(|s| s.oauth?.tokens).map(|t| t.access_token);
        let _one = self.refreshing.lock().await;
        // Another caller refreshed while this one waited: its tokens are the new ones.
        let now = self.server(name).and_then(|s| s.oauth?.tokens).map(|t| t.access_token);
        if before.is_some() && now != before {
            return self.server(name).is_some_and(|s| s.state == "active");
        }
        self.refresh_once(name).await
    }

    fn update(&self, name: &str, f: impl FnOnce(&mut StoredMcpServer)) {
        if let Some(s) = self.write_store().servers.get_mut(name) {
            f(s);
        }
        self.save();
    }

    async fn refresh_once(&self, name: &str) -> bool {
        let Some(s) = self.server(name) else { return false };
        let iso = js::iso(now_ms());
        if s.auth != "oauth" {
            // A header the server no longer takes, or a server that now wants a sign-in: nothing to
            // renew. The fix is a person's.
            let why = if s.auth == "header" {
                "The server refused the key (401). Replace the credential."
            } else {
                "The server now wants a sign-in (401)."
            };
            self.update(name, |s| {
                s.last_error = Some(why.into());
                s.updated_at = iso;
            });
            return false;
        }
        let Some(oauth) = s.oauth.clone() else {
            self.mark_reauth(
                name,
                "The sign-in ended and the server gave no way to renew it. Sign in again.",
            );
            return false;
        };
        let Some(refresh) = oauth.tokens.as_ref().and_then(|t| t.refresh_token.clone()) else {
            self.mark_reauth(
                name,
                "The sign-in ended and the server gave no way to renew it. Sign in again.",
            );
            return false;
        };
        match oauth::refresh_tokens(&oauth.discovery, &oauth.client, &refresh, now_ms() as f64).await {
            Ok(mut tokens) => {
                // A refresh rarely says who is signed in again: the account read at sign-in is kept.
                if tokens.account.is_none() {
                    tokens.account = oauth.tokens.as_ref().and_then(|t| t.account.clone());
                }
                self.update(name, |s| {
                    if let Some(o) = s.oauth.as_mut() {
                        o.tokens = Some(tokens);
                    }
                    s.state = "active".into();
                    s.last_error = None;
                    s.updated_at = iso;
                });
                true
            }
            Err(e) => {
                self.mark_reauth(name, &message_of(&e.0));
                false
            }
        }
    }

    fn mark_reauth(&self, name: &str, why: &str) {
        let iso = js::iso(now_ms());
        self.update(name, |s| {
            s.state = "reauth_required".into();
            s.last_error = Some(cut(why, 300));
            s.updated_at = iso;
        });
        tracing::info!("[mcp-servers] {name} needs a new sign-in: {why}");
    }

    // ---- reads ----

    /// What the console may see of a server: never the header's value, the client secret or a token.
    pub fn public_server(s: &StoredMcpServer) -> Value {
        let mut v = as_map(serde_json::to_value(s).unwrap_or(Value::Null));
        v.shift_remove("header");
        v.shift_remove("oauth");
        v.insert("headerName".into(), json!(s.header.as_ref().map(|h| h.name.clone())));
        let oauth = s.oauth.as_ref().map(|o| {
            let issuer = if o.discovery.meta.issuer.is_empty() {
                Url::parse(&o.discovery.meta.authorization_endpoint)
                    .map(|u| oauth::origin(&u))
                    .unwrap_or_default()
            } else {
                o.discovery.meta.issuer.clone()
            };
            json!({"issuer": issuer, "registered": o.client.registered, "signedIn": o.tokens.is_some(),
                "account": o.tokens.as_ref().and_then(|t| t.account.clone())})
        });
        v.insert("oauth".into(), oauth.unwrap_or(Value::Null));
        Value::Object(v)
    }

    pub async fn handle(&self, action: &str, p: Map<String, Value>) -> CommandOutcome {
        let _one = self.op.lock().await;
        let r = match action {
            "read" => Ok(self.read()),
            "propose" => Ok(self.propose(&p).await),
            "confirm" => self.confirm(&p).await,
            "cancel" => Ok(self.cancel(&p)),
            "callback" => self.callback(&p).await,
            "tools" => Ok(self.refresh_tools(&p).await),
            "push" => self.push(&p).await,
            "forget" => self.forget(&p),
            _ => Err(format!("unknown command mcpservers.{action}")),
        };
        r.unwrap_or_else(|e| failed(&message_of(&e)))
    }

    fn read(&self) -> CommandOutcome {
        let servers: Vec<Value> = self.read_store().servers.values().map(Self::public_server).collect();
        outcome(true, "done", None, Some(as_map(json!({"servers": servers}))))
    }

    async fn refresh_tools(&self, p: &Map<String, Value>) -> CommandOutcome {
        let name = str_of(p.get("name"));
        let Some(s) = name.as_deref().and_then(|n| self.server(n)) else {
            return outcome(
                false,
                "failed",
                Some("This firewall has no MCP server by that name.".into()),
                Some(as_map(json!({"name": name}))),
            );
        };
        let r = self.read_tools(&s.name).await;
        let server = self
            .server(&s.name)
            .map(|x| Self::public_server(&x))
            .unwrap_or(Value::Null);
        match r {
            Ok(()) => outcome(true, "done", None, Some(as_map(json!({"server": server})))),
            Err(e) => outcome(
                false,
                "failed",
                Some(message_of(&e.message)),
                Some(as_map(json!({"server": server}))),
            ),
        }
    }

    async fn list_with_credential(&self, name: &str) -> Result<super::client::Listed, McpServerError> {
        let Some(headers) = self.credential_headers(name).await else {
            return Err(McpServerError {
                message: "The firewall is not signed in to this server. Sign in again.".into(),
                unauthorized: None,
            });
        };
        let url = self.server(name).map(|s| s.url).unwrap_or_default();
        let url = Url::parse(&url).map_err(|e| McpServerError {
            message: e.to_string(),
            unauthorized: None,
        })?;
        list_tools(&url, &headers, LIST_TIMEOUT).await
    }

    /// Read the tool list with the server's credential, refreshing an OAuth token once on a 401.
    /// The server in the store is updated and saved either way.
    async fn read_tools(&self, name: &str) -> Result<(), McpServerError> {
        let got = match self.list_with_credential(name).await {
            Ok(g) => g,
            Err(e) => {
                let oauth = self.server(name).is_some_and(|s| s.auth == "oauth");
                if !(e.unauthorized.is_some() && oauth && self.refresh(name).await) {
                    self.update(name, |s| {
                        s.last_error = Some(message_of(&e.message));
                        if e.unauthorized.is_some() && s.auth == "oauth" {
                            s.state = "reauth_required".into();
                        }
                    });
                    return Err(e);
                }
                match self.list_with_credential(name).await {
                    Ok(g) => g,
                    Err(e) => {
                        self.update(name, |s| s.last_error = Some(message_of(&e.message)));
                        return Err(e);
                    }
                }
            }
        };
        let iso = js::iso(now_ms());
        self.update(name, |s| {
            s.tools = got.tools;
            s.server_name = got.server_name;
            s.tools_at = Some(iso);
            s.state = "active".into();
            s.last_error = None;
        });
        Ok(())
    }

    // ---- proposing ----

    async fn propose(&self, payload: &Map<String, Value>) -> CommandOutcome {
        let refuse =
            |m: String, id: Option<String>| outcome(false, "failed", Some(m), Some(as_map(json!({"changeId": id}))));
        let mut p = match parse_proposal(payload) {
            Ok(p) => p,
            Err(e) => return refuse(message_of(&e), str_of(payload.get("changeId"))),
        };
        let id = Some(p.change_id.clone());
        let existing = self.server(&p.name);
        if p.kind == "add" && existing.is_some() {
            return refuse(
                format!("The organization already has an MCP server called {}.", p.name),
                id,
            );
        }
        if p.kind != "add" && existing.is_none() {
            return refuse(format!("This firewall has no MCP server called {}.", p.name), id);
        }
        if (p.kind == "assign" || p.kind == "unassign") && p.agents.len() != 1 {
            return refuse("Name one agent.".into(), id);
        }
        if let Some(e) = &existing
            && (p.kind == "replace" || p.kind == "reconnect")
            && e.auth
                != if p.kind == "reconnect" {
                    "oauth"
                } else {
                    p.auth.as_str()
                }
        {
            let m = if p.kind == "reconnect" {
                format!("{} does not sign in with OAuth.", p.name)
            } else {
                format!("{} does not sign in that way.", p.name)
            };
            return refuse(m, id);
        }
        for a in &mut p.agents {
            match self.agent_of(&a.vm_id) {
                None => {
                    return refuse(
                        "This firewall does not know that agent. If it was just created, try again in a minute.".into(),
                        id,
                    );
                }
                Some(name) => a.name = name.unwrap_or_else(|| a.vm_id.clone()),
            }
        }
        let summary = summarize(&p, existing.as_ref().map(|e| e.url.as_str()).or(p.url.as_deref()));
        let mut data = as_map(json!({"changeId": p.change_id, "summary": summary}));
        let routes = match self.codes.routes() {
            Ok(r) => r,
            Err(m) => return outcome(false, "failed", Some(m), Some(data)),
        };
        if routes.is_empty() {
            self.codes.forget();
            return match self.apply(&p).await {
                Ok(a) => {
                    data.extend(a.data);
                    data.insert("tofu".into(), json!(true));
                    outcome(true, &a.status, Some(String::new()), Some(data))
                }
                Err(e) => outcome(false, "failed", Some(message_of(&e)), Some(data)),
            };
        }
        let proposal = serde_json::to_value(&p).unwrap_or(Value::Null);
        match self
            .codes
            .send(
                &p.change_id,
                proposal,
                "your organization's MCP servers",
                &summary,
                routes,
            )
            .await
        {
            Err(m) => outcome(false, "failed", Some(m), Some(data)),
            Ok(sent) => {
                tracing::info!(
                    "[mcp-servers] code sent for {} {} via {}",
                    p.kind,
                    p.name,
                    sent.sent_via
                );
                data.insert("sentVia".into(), json!(sent.sent_via));
                data.insert("expiresAt".into(), json!(sent.expires_at));
                data.insert("attemptsLeft".into(), json!(sent.attempts_left));
                outcome(true, "awaiting_code", None, Some(data))
            }
        }
    }

    async fn confirm(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let change_id = str_of(payload.get("changeId")).ok_or("malformed mcpservers.confirm payload")?;
        let code = str_of(payload.get("code")).unwrap_or_default();
        let mut data = as_map(json!({"changeId": change_id}));
        let (proposal, sent_via) = match self.codes.verify(&change_id, &code) {
            Verified::Expired => {
                return Ok(outcome(
                    false,
                    "expired",
                    Some("No change is waiting for a code, or the code expired.".into()),
                    Some(data),
                ));
            }
            Verified::Invalid { attempts_left } => {
                data.insert("attemptsLeft".into(), json!(attempts_left));
                return Ok(outcome(false, "invalid_code", Some("Wrong code.".into()), Some(data)));
            }
            Verified::Ok { proposal, sent_via } => (proposal, sent_via),
        };
        let p: Proposal = serde_json::from_value(proposal).map_err(|e| e.to_string())?;
        let url = self.server(&p.name).map(|s| s.url).or(p.url.clone());
        let summary = summarize(&p, url.as_deref());
        Ok(match self.apply(&p).await {
            Ok(a) => {
                data.extend(a.data);
                data.insert("summary".into(), json!(summary));
                data.insert("sentVia".into(), json!(sent_via));
                data.insert("tofu".into(), json!(false));
                outcome(true, &a.status, Some(String::new()), Some(data))
            }
            Err(e) => {
                data.insert("summary".into(), json!(summary));
                outcome(false, "failed", Some(message_of(&e)), Some(data))
            }
        })
    }

    fn cancel(&self, payload: &Map<String, Value>) -> CommandOutcome {
        let change_id = str_of(payload.get("changeId"));
        self.codes.cancel(change_id.as_deref());
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, p)| Some(&p.proposal.change_id) != change_id.as_ref());
        outcome(true, "cancelled", None, Some(as_map(json!({"changeId": change_id}))))
    }

    // ---- applying ----

    async fn apply(&self, p: &Proposal) -> Result<Applied, String> {
        match p.kind.as_str() {
            "add" | "replace" => {
                let oauth =
                    p.auth == "oauth" && (p.kind == "add" || self.server(&p.name).is_some_and(|s| s.auth == "oauth"));
                if oauth {
                    self.start_oauth(p).await
                } else {
                    self.apply_credential(p).await
                }
            }
            "reconnect" => self.start_oauth(p).await,
            "remove" => Ok(self.apply_remove(p).await),
            _ => self.apply_assignment(p).await,
        }
    }

    /// A server with no sign-in or a header: check it answers with the credential, read its tools,
    /// keep it. A typo fails here, with the server's own words, and nothing is stored.
    async fn apply_credential(&self, p: &Proposal) -> Result<Applied, String> {
        let iso = js::iso(now_ms());
        let existing = self.server(&p.name);
        let auth = if p.kind == "add" {
            p.auth.clone()
        } else {
            existing.as_ref().map(|e| e.auth.clone()).unwrap_or_default()
        };
        let mut header = None;
        if auth == "header" {
            let value = p.secret.as_ref().and_then(|s| s.header_value.clone());
            let name = p.header_name.clone().or_else(|| {
                existing
                    .as_ref()
                    .and_then(|e| e.header.as_ref().map(|h| h.name.clone()))
            });
            let (Some(value), Some(name)) = (value, name) else {
                return Err("No header value in the proposal.".into());
            };
            header = Some(Header {
                name,
                value,
                extra: Map::new(),
            });
        }
        if p.kind == "replace" && auth == "none" {
            return Err("This server has no credential to replace.".into());
        }
        let mut candidate = match existing {
            Some(e) => StoredMcpServer {
                header: header.clone(),
                updated_at: iso.clone(),
                ..e
            },
            None => StoredMcpServer {
                name: p.name.clone(),
                url: p.url.clone().unwrap_or_default(),
                auth: auth.clone(),
                header: header.clone(),
                oauth: None,
                state: "active".into(),
                last_error: None,
                server_name: None,
                tools: vec![],
                tools_at: None,
                agents: vec![],
                created_at: iso.clone(),
                updated_at: iso.clone(),
                extra: Map::new(),
            },
        };
        let url = Url::parse(&candidate.url).map_err(|e| e.to_string())?;
        let headers: Vec<(String, String)> = header.map(|h| vec![(h.name, h.value)]).unwrap_or_default();
        let got = match list_tools(&url, &headers, LIST_TIMEOUT).await {
            Ok(g) => g,
            Err(e) if e.unauthorized.is_some() && auth == "none" => {
                return Err("The server wants a sign-in. Choose a header with a key, or OAuth.".into());
            }
            Err(e) if e.unauthorized.is_some() => return Err("The server refused the credential (401).".into()),
            Err(e) => return Err(e.message),
        };
        candidate.tools = got.tools;
        candidate.server_name = got.server_name;
        candidate.tools_at = Some(iso);
        candidate.state = "active".into();
        candidate.last_error = None;
        Ok(self.keep(p, candidate).await)
    }

    /// Keep a server that works, give it to the proposal's agents, and push.
    async fn keep(&self, p: &Proposal, mut s: StoredMcpServer) -> Applied {
        if p.kind == "add" {
            for a in &p.agents {
                if !s.agents.contains(&a.vm_id) {
                    s.agents.push(a.vm_id.clone());
                }
            }
        }
        let holders = s.agents.clone();
        self.write_store().servers.insert(s.name.clone(), s.clone());
        self.save();
        let (applied, failed) = self.push_agents(&holders).await;
        let server = self
            .server(&s.name)
            .map(|x| Self::public_server(&x))
            .unwrap_or(Value::Null);
        Applied {
            status: "applied".into(),
            data: as_map(json!({"server": server, "applied": applied, "failed": failed})),
        }
    }

    async fn start_oauth(&self, p: &Proposal) -> Result<Applied, String> {
        let existing = self.server(&p.name);
        let url = existing
            .as_ref()
            .map(|e| e.url.clone())
            .or(p.url.clone())
            .unwrap_or_default();
        let parsed = Url::parse(&url).map_err(|e| e.to_string())?;
        // Discovery starts from the server's own 401, which may name where its sign-in settings are.
        let mut challenge = None;
        if let Err(e) = list_tools(&parsed, &[], Duration::from_secs(10)).await {
            challenge = e.unauthorized;
        }
        let discovery = oauth::discover(&parsed, challenge.as_ref().and_then(|c| c.as_deref()))
            .await
            .map_err(|e| e.0)?;
        let client = match (
            &p.client_id,
            p.kind.as_str(),
            existing.as_ref().and_then(|e| e.oauth.clone()),
        ) {
            (Some(id), _, _) => {
                let secret = p.secret.as_ref().and_then(|s| s.client_secret.clone());
                OauthClient {
                    client_id: id.clone(),
                    auth_method: if secret.is_some() { "client_secret_post" } else { "none" }.into(),
                    client_secret: secret,
                    registered: false,
                    extra: Map::new(),
                }
            }
            (None, "reconnect", Some(o)) => o.client,
            _ => oauth::register(&discovery.meta, &self.redirect_uri, "ControlClaw firewall")
                .await
                .map_err(|e| e.0)?,
        };
        let auth = oauth::authorization_url(&discovery, &client, &self.redirect_uri).map_err(|e| e.0)?;
        self.forget_stale_oauth();
        let started = now_ms();
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).push((
            auth.state.clone(),
            PendingOauth {
                verifier: auth.verifier,
                discovery,
                client,
                proposal: p.clone(),
                url,
                server_created_at: existing.map(|e| e.created_at),
                started_at: started,
            },
        ));
        tracing::info!(
            "[mcp-servers] {} sign-in started (state {}…)",
            p.name,
            cut(&auth.state, 8)
        );
        Ok(Applied {
            status: "awaiting_authorization".into(),
            data: as_map(json!({"authorizationUrl": auth.url, "state": auth.state,
                "expiresAt": js::iso(started + OAUTH_PENDING_MS)})),
        })
    }

    /// The relayed callback: a state we minted, the code exchanged here with the verifier that never left.
    async fn callback(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let state = str_of(payload.get("state")).ok_or("malformed mcpservers.callback payload")?;
        let code = str_of(payload.get("code"));
        let error = str_of(payload.get("error"));
        self.forget_stale_oauth();
        let pending = {
            let mut list = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            list.iter()
                .position(|(s, _)| cc_crypto::ct_eq(s.as_bytes(), state.as_bytes()))
                .map(|i| list.remove(i).1)
        };
        let Some(pending) = pending else {
            return Ok(outcome(
                false,
                "expired",
                Some("This sign-in is no longer waiting on your firewall. Start it again.".into()),
                Some(as_map(json!({"state": state}))),
            ));
        };
        let p = pending.proposal.clone();
        let mut data =
            as_map(json!({"changeId": p.change_id, "state": state, "summary": summarize(&p, Some(&pending.url))}));
        let Some(code) = code else {
            let why = error.map(|e| format!(" ({})", cut(&e, 100))).unwrap_or_default();
            return Ok(outcome(
                false,
                "failed",
                Some(format!("The server refused the sign-in{why}.")),
                Some(data),
            ));
        };
        // The server the sign-in was started for, still the same one (checked before the code is spent).
        let before = self.server(&p.name);
        let changed = if p.kind == "add" {
            before.is_some()
        } else {
            before
                .as_ref()
                .is_none_or(|b| b.url != pending.url || Some(&b.created_at) != pending.server_created_at.as_ref())
        };
        if changed {
            let m = if p.kind == "add" {
                format!("The organization already has an MCP server called {}.", p.name)
            } else {
                format!(
                    "The MCP server {} changed since this sign-in started. Start it again.",
                    p.name
                )
            };
            return Ok(outcome(false, "failed", Some(m), Some(data)));
        }
        let r: Result<Applied, String> = async {
            let tokens = oauth::exchange_code(
                &pending.discovery,
                &pending.client,
                &code,
                &pending.verifier,
                &self.redirect_uri,
                now_ms() as f64,
            )
            .await
            .map_err(|e| e.0)?;
            let iso = js::iso(now_ms());
            let existing = self.server(&p.name);
            if p.kind == "add" && existing.is_some() {
                return Err(format!("The organization already has an MCP server called {}.", p.name));
            }
            if p.kind != "add" && existing.as_ref().map(|e| &e.created_at) != pending.server_created_at.as_ref() {
                return Err(format!(
                    "This firewall no longer has the MCP server {} this sign-in was for.",
                    p.name
                ));
            }
            let o = Oauth {
                discovery: pending.discovery.clone(),
                client: pending.client.clone(),
                tokens: Some(tokens),
                extra: Map::new(),
            };
            let s = match existing.clone() {
                Some(e) => StoredMcpServer {
                    oauth: Some(o),
                    updated_at: iso.clone(),
                    ..e
                },
                None => StoredMcpServer {
                    name: p.name.clone(),
                    url: pending.url.clone(),
                    auth: "oauth".into(),
                    header: None,
                    oauth: Some(o),
                    state: "active".into(),
                    last_error: None,
                    server_name: None,
                    tools: vec![],
                    tools_at: None,
                    agents: vec![],
                    created_at: iso.clone(),
                    updated_at: iso,
                    extra: Map::new(),
                },
            };
            self.write_store().servers.insert(s.name.clone(), s);
            if let Err(e) = self.read_tools(&p.name).await {
                // The store goes back as it was.
                {
                    let mut st = self.write_store();
                    match existing {
                        None => {
                            st.servers.remove(&p.name);
                        }
                        Some(e) => st.servers.insert(p.name.clone(), e),
                    }
                }
                self.save();
                return Err(e.message);
            }
            let s = self.server(&p.name).ok_or("the server is gone")?;
            Ok(self.keep(&p, s).await)
        }
        .await;
        Ok(match r {
            Ok(a) => {
                data.extend(a.data);
                data.insert("tofu".into(), json!(false));
                outcome(true, "applied", Some(String::new()), Some(data))
            }
            Err(e) => outcome(false, "failed", Some(message_of(&e)), Some(data)),
        })
    }

    fn forget_stale_oauth(&self) {
        let now = now_ms();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, p)| now - p.started_at <= OAUTH_PENDING_MS);
    }

    async fn apply_remove(&self, p: &Proposal) -> Applied {
        // A sign-in still waiting for this server ends with it.
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, x)| x.proposal.name != p.name);
        let holders = self.server(&p.name).map(|s| s.agents).unwrap_or_default();
        self.write_store().servers.remove(&p.name);
        self.save();
        let (applied, failed) = self.push_agents(&holders).await;
        Applied {
            status: "applied".into(),
            data: as_map(json!({"name": p.name, "applied": applied, "failed": failed})),
        }
    }

    async fn apply_assignment(&self, p: &Proposal) -> Result<Applied, String> {
        if self.server(&p.name).is_none() {
            return Err(format!("This firewall has no MCP server called {}.", p.name));
        }
        let a = p.agents.first().ok_or("Name one agent.")?;
        let assign = p.kind == "assign";
        let iso = js::iso(now_ms());
        self.update(&p.name, |s| {
            if assign {
                if !s.agents.contains(&a.vm_id) {
                    s.agents.push(a.vm_id.clone());
                }
            } else {
                s.agents.retain(|v| *v != a.vm_id);
            }
            s.updated_at = iso;
        });
        let (applied, failed) = self.push_agents(std::slice::from_ref(&a.vm_id)).await;
        Ok(Applied {
            status: "applied".into(),
            data: as_map(
                json!({"name": p.name, "vmId": a.vm_id, "assigned": assign, "applied": applied, "failed": failed}),
            ),
        })
    }

    /// Give one agent one server with no code of its own. Only for a caller that holds consent for
    /// it: a template apply whose code message named the server.
    pub async fn give_under_consent(&self, vm_id: &str, name: &str) -> (bool, String) {
        if self.server(name).is_none() {
            return (
                false,
                format!("Your organization has no MCP server called {name}. Add it on the Integrations page first."),
            );
        }
        if self.agent_of(vm_id).is_none() {
            return (
                false,
                "This firewall does not know this agent yet. Try again in a minute.".into(),
            );
        }
        if self.server(name).is_some_and(|s| !s.agents.iter().any(|a| a == vm_id)) {
            let iso = js::iso(now_ms());
            self.update(name, |s| {
                s.agents.push(vm_id.to_string());
                s.updated_at = iso;
            });
            tracing::info!("[mcp-servers] {name} given to {vm_id} under a confirmed apply");
        }
        let (_, failed) = self.push_agents(&[vm_id.to_string()]).await;
        match failed.first() {
            Some(f) => (false, f["error"].as_str().unwrap_or_default().to_string()),
            None => (true, format!("The MCP server {name} is given to this agent.")),
        }
    }

    // ---- agents ----

    /// The servers an agent has, as its OpenClaw should list them, by name (`localeCompare`).
    pub fn servers_of(&self, vm_id: &str) -> Vec<Value> {
        let mut names: Vec<String> = self
            .read_store()
            .servers
            .values()
            .filter(|s| s.agents.iter().any(|a| a == vm_id))
            .map(|s| s.name.clone())
            .collect();
        // Names are `[a-z0-9-]`, which `localeCompare` orders as their bytes do.
        names.sort();
        names
            .into_iter()
            .map(|n| json!({"name": n, "url": self.gate_url(&n)}))
            .collect()
    }

    /// A few at a time: each write restarts that agent's gateway and can take a while.
    async fn push_agents(&self, vm_ids: &[String]) -> (Vec<String>, Vec<Value>) {
        let mut queue: Vec<String> = Vec::new();
        for v in vm_ids {
            if !queue.contains(v) {
                queue.push(v.clone());
            }
        }
        let client = self.app.contracts.agents.get();
        let jobs: Vec<_> = queue
            .into_iter()
            .map(|vm: String| {
                let client = client.clone();
                let body = json!({"servers": self.servers_of(&vm)});
                (vm, client, body)
            })
            .collect();
        // Boxed, so the futures are one named type the stream can hold across awaits.
        let jobs: Vec<cc_http::BoxFuture<Result<String, Value>>> = jobs
            .into_iter()
            .map(|(vm, client, body)| -> cc_http::BoxFuture<Result<String, Value>> {
                Box::pin(async move {
                    match client {
                        None => Err("This firewall cannot reach its agents yet.".to_string()),
                        Some(c) => c
                            .post(&vm, "/mcp-servers/apply", body)
                            .await
                            .map(|_| ())
                            .map_err(|e| e.message),
                    }
                    .map(|()| vm.clone())
                    .map_err(|e| json!({"vmId": vm, "error": message_of(&e)}))
                })
            })
            .collect();
        use futures_util::StreamExt;
        let results: Vec<Result<String, Value>> = futures_util::stream::iter(jobs)
            .buffer_unordered(self.push_concurrency.max(1))
            .collect()
            .await;
        let mut applied = Vec::new();
        let mut failed = Vec::new();
        for r in results {
            match r {
                Ok(v) => applied.push(v),
                Err(f) => failed.push(f),
            }
        }
        (applied, failed)
    }

    /// A box came up: re-push what it should have.
    async fn push(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm_id = str_of(payload.get("vmId")).ok_or("malformed mcpservers.push payload")?;
        let (applied, failed) = self.push_agents(std::slice::from_ref(&vm_id)).await;
        let names: Vec<Value> = self.servers_of(&vm_id).into_iter().map(|s| s["name"].clone()).collect();
        let message = failed
            .iter()
            .filter_map(|f| f["error"].as_str())
            .collect::<Vec<_>>()
            .join("; ");
        Ok(outcome(
            failed.is_empty(),
            if failed.is_empty() { "applied" } else { "failed" },
            Some(message),
            Some(as_map(
                json!({"vmId": vm_id, "servers": names, "applied": applied, "failed": failed}),
            )),
        ))
    }

    /// An agent was deleted: off every list, with no code (it only takes access away).
    fn forget(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm_id = str_of(payload.get("vmId")).ok_or("malformed mcpservers.forget payload")?;
        let mut changed = false;
        for s in self.write_store().servers.values_mut() {
            if s.agents.contains(&vm_id) {
                s.agents.retain(|v| *v != vm_id);
                changed = true;
            }
        }
        if changed {
            self.save();
        }
        Ok(outcome(true, "applied", None, Some(as_map(json!({"vmId": vm_id})))))
    }
}

#[cfg(test)]
pub(crate) mod tests;
