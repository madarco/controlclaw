//! App integrations on the firewall (`connectors.ts`, apps/saas/docs/features/integrations.md).
//! OpenConnector runs next to us on this box, on loopback; this is the small, fixed set of
//! management calls the control plane may cause:
//!
//! ```text
//!   connectors.read     { kind: "setup" | "connections", service? }            read-only
//!   connectors.propose  { changeId, kind, ..., secret? }
//!   connectors.confirm  { changeId, code }
//!   connectors.cancel   { changeId }
//!   connectors.callback { state, code? | error? }        the relayed OAuth callback
//!   connectors.push     { vmId, name, hostname, privateIp }   re-push after a box comes up
//!   connectors.forget   { vmId }                          an agent was deleted: revoke its token
//! ```
//!
//! The credential a person types rides the encrypted part of the proposal and goes straight into
//! OpenConnector. Nothing here stores it, and no route reads one back.
//!
//! Every agent gets its own runtime token, limited to the connections its owner assigned
//! (`allowedConnections`), to those connections' services (`allowedActions`) and with proxies
//! denied. Unassigning narrows the token; deleting the agent revokes it.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::runtime::{ConnectorRuntime, RuntimeConnection, RuntimeError, obj, search_params};
use super::store::{self, ConnectorStore, StoredConnection, StoredConnectorAgent};
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::integrations::codes::{Codes, Verified};
use crate::integrations::{as_map, failed, js, outcome};

const SCOPE: &str = "connectors";
/// How long a started OAuth authorization is remembered here (the runtime's own window is 10 min).
pub const OAUTH_PENDING_MS: i64 = 15 * 60_000;

static SERVICE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_]{0,60}$").expect("pattern"));
static KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{1,64}$").expect("pattern"));

/// What the connector gate knows about the agent behind a runtime token.
#[derive(Debug, Clone, PartialEq)]
pub struct GateAgent {
    pub vm_id: String,
    pub private_ip: Option<String>,
    pub connections: Vec<GateConnection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GateConnection {
    pub id: String,
    pub service: String,
    pub alias: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRef {
    pub vm_id: String,
    pub name: String,
    pub hostname: Option<String>,
    pub private_ip: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalSecret {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_secret: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proposal {
    pub change_id: String,
    /// `connect`, `replace`, `remove`, `assign`, `unassign`, `oauth_connect`, `oauth_reconnect`.
    pub kind: String,
    pub service: String,
    /// What the console calls the provider, for the code message.
    pub service_name: String,
    /// Set on everything but a first `connect` / `oauth_connect`: the runtime's connection id.
    pub connection_id: Option<String>,
    pub label: Option<String>,
    /// `api_key` and `custom_credential` only: the non-secret fields of the credential form.
    pub extra: Map<String, Value>,
    /// OAuth only: the customer's own client id, and which optional scopes they picked.
    pub client_id: Option<String>,
    pub authorization_option_ids: Vec<String>,
    /// The agents this change assigns the connection to (or takes it off).
    pub agents: Vec<AgentRef>,
    /// The encrypted part: the API key, the custom-credential values, or the OAuth client secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<ProposalSecret>,
}

const KINDS: &[&str] = &[
    "connect",
    "replace",
    "remove",
    "assign",
    "unassign",
    "oauth_connect",
    "oauth_reconnect",
];

/// A non-empty string.
pub fn str_of(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// At most `max` string fields with plain keys, each cut to 4096 characters.
fn str_map(v: Option<&Value>, max: usize) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(o) = v.and_then(Value::as_object) else {
        return out;
    };
    for (k, value) in o {
        if out.len() >= max {
            break;
        }
        if let Some(s) = value.as_str().filter(|s| !s.is_empty())
            && KEY_RE.is_match(k)
        {
            out.insert(k.clone(), json!(js_slice(s, 4096)));
        }
    }
    out
}

/// `s.slice(0, n)`: the first `n` UTF-16 units.
pub fn js_slice(s: &str, n: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

pub fn parse_proposal(p: &Map<String, Value>) -> Result<Proposal, String> {
    let change_id = str_of(p.get("changeId"));
    let service = str_of(p.get("service"));
    let kind = p.get("kind").and_then(Value::as_str).filter(|k| KINDS.contains(k));
    let (Some(change_id), Some(service), Some(kind)) = (change_id, service, kind) else {
        return Err("malformed connectors.propose payload".into());
    };
    if !SERVICE_RE.is_match(&service) {
        return Err("malformed connectors.propose payload".into());
    }
    let agents = p
        .get("agents")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|x| str_of(x.get("vmId")).is_some())
                .map(|x| {
                    let vm = str_of(x.get("vmId")).unwrap_or_default();
                    AgentRef {
                        name: str_of(x.get("name")).unwrap_or_else(|| vm.clone()),
                        hostname: str_of(x.get("hostname")),
                        private_ip: str_of(x.get("privateIp")),
                        vm_id: vm,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let secret = p.get("secret").filter(|s| !s.is_null()).map(|s| ProposalSecret {
        api_key: str_of(s.get("apiKey")),
        values: s.get("values").filter(|v| truthy(v)).map(|v| str_map(Some(v), 30)),
        client_secret: str_of(s.get("clientSecret")),
        extra_secret: s.get("extraSecret").filter(|v| truthy(v)).map(|v| str_map(Some(v), 20)),
    });
    Ok(Proposal {
        change_id,
        kind: kind.to_string(),
        service_name: str_of(p.get("serviceName")).unwrap_or_else(|| service.clone()),
        service,
        connection_id: str_of(p.get("connectionId")),
        label: str_of(p.get("label")),
        extra: str_map(p.get("extra"), 20),
        client_id: str_of(p.get("clientId")),
        authorization_option_ids: p
            .get("authorizationOptionIds")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().filter(|s| !s.is_empty()).map(str::to_string))
                    .take(40)
                    .collect()
            })
            .unwrap_or_default(),
        agents,
        secret,
    })
}

/// JavaScript truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// The one-line summary the code message carries. Written here, never by the control plane.
pub fn summarize(p: &Proposal) -> String {
    let named = match &p.label {
        Some(l) => format!("{} ({l})", p.service_name),
        None => p.service_name.clone(),
    };
    let one = p.agents.first();
    let on = match p.agents.len() {
        0 => String::new(),
        1 => format!(" to {}", p.agents[0].name),
        n => format!(" to {n} agents"),
    };
    let who = one.map(|a| a.name.as_str()).unwrap_or("the agent");
    match p.kind.as_str() {
        "connect" | "oauth_connect" => format!("Connect {named}{on}"),
        "replace" => format!("Replace the credentials of {named}"),
        "oauth_reconnect" => format!("Sign in to {named} again"),
        "remove" => format!("Remove {named} from the organization"),
        "assign" => format!("Let {who} use {named}"),
        _ => format!("Stop {who} using {named}"),
    }
}

/// An OAuth authorization this firewall started and is waiting for a callback on.
struct PendingOauth {
    service: String,
    request_id: String,
    proposal: Proposal,
    started_at: i64,
}

struct Applied {
    status: String,
    message: Option<String>,
    data: Map<String, Value>,
}

fn messages(e: &str) -> String {
    js_slice(e, 500)
}

pub struct ConnectorsFirewall {
    app: Arc<App>,
    path: PathBuf,
    runtime: ConnectorRuntime,
    /// The URL the agent boxes reach this firewall's connector gate on (private IP).
    gateway_url: String,
    store: RwLock<ConnectorStore>,
    codes: Codes,
    pending_oauth: Mutex<Vec<(String, PendingOauth)>>,
    /// One command at a time, as the TS ran them between awaits: a read of the store and the
    /// write it leads to are never split by another command.
    op: tokio::sync::Mutex<()>,
    now: fn() -> i64,
}

impl ConnectorsFirewall {
    pub fn new(app: &Arc<App>, path: PathBuf, runtime: ConnectorRuntime, gateway_url: String) -> Arc<Self> {
        let store = store::load(&path, &app.box_key, &app.config.org_id, &app.config.box_id);
        Arc::new(Self {
            app: app.clone(),
            path,
            runtime,
            gateway_url,
            store: RwLock::new(store),
            codes: Codes::new(app, SCOPE),
            pending_oauth: Mutex::new(Vec::new()),
            op: tokio::sync::Mutex::new(()),
            now: js::now_ms,
        })
    }

    fn read_store(&self) -> std::sync::RwLockReadGuard<'_, ConnectorStore> {
        self.store.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_store(&self) -> std::sync::RwLockWriteGuard<'_, ConnectorStore> {
        self.store.write().unwrap_or_else(|e| e.into_inner())
    }

    /// What the console may see about this firewall's connectors: counts, never a credential.
    pub fn summary(&self) -> (usize, usize) {
        let s = self.read_store();
        (s.connections.len(), s.agents.len())
    }

    /// See [`store::agents_with_connections`].
    pub fn agents_with_connections(&self) -> usize {
        store::agents_with_connections(&self.read_store())
    }

    /// Token id → vm id, so a run record can be attributed to the agent that made the call.
    pub fn agent_for_token(&self, token_id: &str) -> Option<String> {
        self.read_store()
            .agents
            .iter()
            .find(|(_, a)| a.token_id.as_deref() == Some(token_id))
            .map(|(k, _)| k.clone())
    }

    /// Runtime token → vm id, its private IP and the connections it holds, for the connector gate.
    pub fn agent_for_runtime_token(&self, token: &str) -> Option<GateAgent> {
        let s = self.read_store();
        let (vm_id, a) = s.agents.iter().find(|(_, a)| {
            a.token
                .as_deref()
                .is_some_and(|t| cc_crypto::ct_eq(t.as_bytes(), token.as_bytes()))
        })?;
        let connections = a
            .connections
            .iter()
            .filter_map(|id| s.connections.get(id))
            .map(|c| GateConnection {
                id: c.id.clone(),
                service: c.service.clone(),
                alias: c.alias.clone(),
                label: c.label.clone().or_else(|| c.account_label.clone()),
            })
            .collect();
        Some(GateAgent {
            vm_id: vm_id.clone(),
            private_ip: a.private_ip.clone(),
            connections,
        })
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
            tracing::error!("[connectors] could not save the store: {e}");
        }
    }

    pub async fn handle(self: &Arc<Self>, action: &str, p: Map<String, Value>) -> CommandOutcome {
        let _one = self.op.lock().await;
        let r = match action {
            "read" => Ok(self.read(&p).await),
            "propose" => self.propose(&p).await,
            "confirm" => self.confirm(&p).await,
            "cancel" => Ok(self.cancel(&p)),
            "callback" => self.callback(&p).await,
            "push" => self.push(&p).await,
            "forget" => self.forget(&p).await,
            _ => Err(format!("unknown command connectors.{action}")),
        };
        r.unwrap_or_else(|e| failed(&messages(&e)))
    }

    // ---- reads ----

    async fn read(&self, p: &Map<String, Value>) -> CommandOutcome {
        let kind = str_of(p.get("kind"));
        let r: Result<Map<String, Value>, String> = async {
            match kind.as_deref() {
                Some("setup") => {
                    let service = str_of(p.get("service")).filter(|s| SERVICE_RE.is_match(s));
                    let Some(service) = service else {
                        return Err("connectors.read setup needs a service".to_string());
                    };
                    let setup = self.runtime.setup(&service).await.map_err(|e| e.message)?;
                    // The descriptor holds no saved value by construction; pass on only what a form needs.
                    let auth = setup.get("auth").filter(|a| !a.is_null()).cloned().unwrap_or(json!([]));
                    let oauth = setup
                        .get("oauthClient")
                        .filter(|a| !a.is_null())
                        .cloned()
                        .unwrap_or(Value::Null);
                    Ok(as_map(
                        json!({"kind": "setup", "service": service, "auth": auth, "oauthClient": oauth}),
                    ))
                }
                Some("connections") => {
                    self.reconcile_connections().await.map_err(|e| e.message)?;
                    let s = self.read_store();
                    let connections: Vec<Value> = s.connections.values().map(|c| json!(c)).collect();
                    Ok(as_map(
                        json!({"kind": "connections", "connections": connections, "agents": agent_view(&s)}),
                    ))
                }
                other => Err(format!("unknown connectors.read kind {}", other.unwrap_or("(none)"))),
            }
        }
        .await;
        match r {
            Ok(data) => outcome(true, "done", None, Some(data)),
            Err(e) => outcome(false, "failed", Some(messages(&e)), Some(as_map(json!({"kind": kind})))),
        }
    }

    /// Bring the store's view of the connections in line with the runtime's. The runtime is the
    /// owner: it can change a connection's state on its own, and a connection it no longer has must
    /// stop being offered here.
    async fn reconcile_connections(&self) -> Result<(), RuntimeError> {
        let live = self.runtime.connections().await?;
        let mut changed = false;
        {
            let mut s = self.write_store();
            let ids: Vec<String> = s.connections.keys().cloned().collect();
            for id in ids {
                let Some(l) = live.iter().find(|c| c.id == id) else {
                    s.connections.remove(&id);
                    for a in s.agents.values_mut() {
                        a.connections.retain(|c| *c != id);
                    }
                    changed = true;
                    continue;
                };
                let Some(stored) = s.connections.get(&id).cloned() else {
                    continue;
                };
                let next = merge_connection(&stored, l);
                if next != stored {
                    s.connections.insert(id, next);
                    changed = true;
                }
            }
        }
        if changed {
            self.save();
        }
        Ok(())
    }

    // ---- proposing ----

    async fn propose(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let p = parse_proposal(payload)?;
        let summary = summarize(&p);
        let mut data = as_map(json!({"changeId": p.change_id, "summary": summary}));
        let routes = match self.codes.routes() {
            Ok(r) => r,
            Err(m) => return Ok(outcome(false, "failed", Some(m), Some(data))),
        };
        if routes.is_empty() {
            self.codes.forget();
            return Ok(match self.apply(&p).await {
                Ok(applied) => {
                    data.extend(applied.data);
                    data.insert("tofu".into(), json!(true));
                    outcome(
                        true,
                        &applied.status,
                        Some(applied.message.unwrap_or_default()),
                        Some(data),
                    )
                }
                Err(e) => outcome(false, "failed", Some(messages(&e)), Some(data)),
            });
        }
        let proposal = serde_json::to_value(&p).map_err(|e| e.to_string())?;
        match self
            .codes
            .send(
                &p.change_id,
                proposal,
                "your organization's app connections",
                &summary,
                routes,
            )
            .await
        {
            Err(message) => Ok(outcome(false, "failed", Some(message), Some(data))),
            Ok(sent) => {
                tracing::info!(
                    "[connectors] code sent for {} {} via {}",
                    p.kind,
                    p.service,
                    sent.sent_via
                );
                data.insert("sentVia".into(), json!(sent.sent_via));
                data.insert("expiresAt".into(), json!(sent.expires_at));
                data.insert("attemptsLeft".into(), json!(sent.attempts_left));
                Ok(outcome(true, "awaiting_code", None, Some(data)))
            }
        }
    }

    async fn confirm(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let change_id = str_of(payload.get("changeId")).ok_or("malformed connectors.confirm payload")?;
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
        Ok(match self.apply(&p).await {
            Ok(applied) => {
                data.extend(applied.data);
                data.insert("summary".into(), json!(summarize(&p)));
                data.insert("sentVia".into(), json!(sent_via));
                data.insert("tofu".into(), json!(false));
                outcome(
                    true,
                    &applied.status,
                    Some(applied.message.unwrap_or_default()),
                    Some(data),
                )
            }
            Err(e) => {
                data.insert("summary".into(), json!(summarize(&p)));
                outcome(false, "failed", Some(messages(&e)), Some(data))
            }
        })
    }

    fn cancel(&self, payload: &Map<String, Value>) -> CommandOutcome {
        let change_id = str_of(payload.get("changeId"));
        self.codes.cancel(change_id.as_deref());
        self.pending_oauth
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, p)| Some(&p.proposal.change_id) != change_id.as_ref());
        outcome(true, "cancelled", None, Some(as_map(json!({"changeId": change_id}))))
    }

    // ---- applying ----

    async fn apply(&self, p: &Proposal) -> Result<Applied, String> {
        match p.kind.as_str() {
            "connect" | "replace" => self.apply_credential(p).await,
            "remove" => self.apply_remove(p).await,
            "assign" | "unassign" => self.apply_assignment(p).await,
            _ => self.apply_oauth_start(p).await,
        }
    }

    /// An API key or a set of custom-credential fields: straight into the runtime, which validates it.
    async fn apply_credential(&self, p: &Proposal) -> Result<Applied, String> {
        let secret = p.secret.as_ref().filter(|s| s.api_key.is_some() || s.values.is_some());
        let Some(secret) = secret else {
            return Err("no credential in the proposal".into());
        };
        let comment = p.label.clone().map(Value::String);
        let values = || {
            let mut v = p.extra.clone();
            v.extend(secret.values.clone().unwrap_or_default());
            Value::Object(v)
        };
        let api_body = |key: &str| {
            obj(vec![
                ("apiKey", Some(json!(key))),
                ("extra", Some(Value::Object(p.extra.clone()))),
                ("comment", comment.clone()),
            ])
        };
        let custom_body = || obj(vec![("values", Some(values())), ("comment", comment.clone())]);
        let conn = if p.kind == "replace" {
            let Some(id) = &p.connection_id else {
                return Err("a replacement needs the connection it replaces".into());
            };
            match &secret.api_key {
                Some(k) => self.runtime.replace_api_key(id, api_body(k)).await,
                None => self.runtime.replace_custom(id, custom_body()).await,
            }
        } else {
            match &secret.api_key {
                Some(k) => self.runtime.connect_api_key(&p.service, api_body(k)).await,
                None => self.runtime.connect_custom(&p.service, custom_body()).await,
            }
        }
        .map_err(|e| e.message)?;
        Ok(self.record_and_assign(p, &conn).await)
    }

    /// The connection exists in the runtime: remember it, put it on the named agents, push.
    async fn record_and_assign(&self, p: &Proposal, conn: &RuntimeConnection) -> Applied {
        let iso = js::iso((self.now)());
        {
            let mut s = self.write_store();
            let existing = s.connections.get(&conn.id).cloned();
            s.connections.insert(
                conn.id.clone(),
                StoredConnection {
                    id: conn.id.clone(),
                    service: conn.service.clone(),
                    alias: conn.alias.clone().unwrap_or_else(|| "default".into()),
                    auth_type: conn.auth_type.clone().unwrap_or_else(|| "api_key".into()),
                    account_label: conn.account_label.clone().or_else(|| conn.display_name.clone()),
                    label: p
                        .label
                        .clone()
                        .or_else(|| existing.as_ref().and_then(|e| e.label.clone())),
                    state: conn.status.clone().unwrap_or_else(|| "active".into()),
                    last_error: None,
                    created_at: existing
                        .as_ref()
                        .map(|e| e.created_at.clone())
                        .unwrap_or_else(|| iso.clone()),
                    updated_at: iso,
                    extra: Map::new(),
                },
            );
            for a in &p.agents {
                grant(&mut s, a, &conn.id, true);
            }
        }
        self.save();
        let holders = self.agents_holding(&conn.id);
        let pushed = self.push_agents(&holders).await;
        let connection = self
            .read_store()
            .connections
            .get(&conn.id)
            .map(|c| json!(c))
            .unwrap_or(Value::Null);
        Applied {
            status: "applied".into(),
            message: None,
            data: as_map(json!({
                "connection": connection,
                "assigned": p.agents.iter().map(|a| a.vm_id.clone()).collect::<Vec<_>>(),
                "applied": pushed.0,
                "failed": pushed.1,
            })),
        }
    }

    async fn apply_remove(&self, p: &Proposal) -> Result<Applied, String> {
        let Some(id) = &p.connection_id else {
            return Err("a removal needs a connection id".into());
        };
        let stored = self.read_store().connections.get(id).cloned();
        let holders = self.agents_holding(id);
        if let Some(stored) = stored {
            match self
                .runtime
                .delete_connection(&stored.service, Some(&stored.alias))
                .await
            {
                Ok(_) => {}
                // Already gone in the runtime is fine: the goal is that it is not there.
                Err(e) if e.status == 404 => {}
                Err(e) => return Err(e.message),
            }
        }
        {
            let mut s = self.write_store();
            s.connections.remove(id);
            for a in s.agents.values_mut() {
                a.connections.retain(|c| c != id);
            }
        }
        self.save();
        let pushed = self.push_agents(&holders).await;
        Ok(Applied {
            status: "applied".into(),
            message: None,
            data: as_map(json!({"connectionId": id, "applied": pushed.0, "failed": pushed.1})),
        })
    }

    async fn apply_assignment(&self, p: &Proposal) -> Result<Applied, String> {
        let Some(id) = &p.connection_id else {
            return Err("an assignment needs a connection id".into());
        };
        if !self.read_store().connections.contains_key(id) {
            return Err("This app is not connected on the firewall. Connect it again.".into());
        }
        let Some(a) = p.agents.first() else {
            return Err("no agent in the proposal".into());
        };
        grant(&mut self.write_store(), a, id, p.kind == "assign");
        self.save();
        let pushed = self.push_agents(std::slice::from_ref(&a.vm_id)).await;
        Ok(Applied {
            status: "applied".into(),
            message: None,
            data: as_map(
                json!({"connectionId": id, "vmId": a.vm_id, "assigned": p.kind == "assign",
                "applied": pushed.0, "failed": pushed.1}),
            ),
        })
    }

    /// Store the customer's own OAuth client and start an authorization. The `code` the provider
    /// hands back later cannot be spent without the verifier and the client secret, and both stay
    /// in the runtime on this box: that is what makes the control-plane relay safe.
    async fn apply_oauth_start(&self, p: &Proposal) -> Result<Applied, String> {
        if p.kind == "oauth_connect" {
            let client_secret = p.secret.as_ref().and_then(|s| s.client_secret.clone());
            let (Some(client_id), Some(client_secret)) = (&p.client_id, client_secret) else {
                return Err("an OAuth app needs its client id and secret".into());
            };
            // A provider's own extra client fields go in `extra`, whichever half of the command they
            // travelled in.
            let mut extra = p.extra.clone();
            extra.extend(
                p.secret
                    .as_ref()
                    .and_then(|s| s.extra_secret.clone())
                    .unwrap_or_default(),
            );
            let body = obj(vec![
                ("clientId", Some(json!(client_id))),
                ("clientSecret", Some(json!(client_secret))),
                ("extra", (!extra.is_empty()).then_some(Value::Object(extra))),
            ]);
            self.runtime
                .put_oauth_config(&p.service, body)
                .await
                .map_err(|e| e.message)?;
        }
        let auth = match (&p.kind[..], &p.connection_id) {
            ("oauth_reconnect", Some(id)) => self.runtime.reauthorize(id, json!({})).await,
            _ => {
                let ids = (!p.authorization_option_ids.is_empty()).then(|| json!(p.authorization_option_ids));
                self.runtime
                    .start_authorization(&p.service, obj(vec![("authorizationOptionIds", ids)]))
                    .await
            }
        }
        .map_err(|e| e.message)?;
        self.forget_stale_oauth();
        {
            let mut pending = self.pending_oauth.lock().unwrap_or_else(|e| e.into_inner());
            pending.retain(|(s, _)| *s != auth.state_handle);
            pending.push((
                auth.state_handle.clone(),
                PendingOauth {
                    service: p.service.clone(),
                    request_id: auth.connection_request_id.clone(),
                    proposal: p.clone(),
                    started_at: (self.now)(),
                },
            ));
        }
        tracing::info!(
            "[connectors] {} authorization started (state {}…)",
            p.service,
            js_slice(&auth.state_handle, 8)
        );
        Ok(Applied {
            status: "awaiting_authorization".into(),
            message: None,
            data: as_map(
                json!({"authorizationUrl": auth.authorization_url, "state": auth.state_handle,
                "requestId": auth.connection_request_id, "expiresAt": auth.expires_at.unwrap_or(Value::Null)}),
            ),
        })
    }

    /// The relayed callback. The control plane only carries `state` and `code`; this checks the
    /// state is one we minted, replays it on loopback, and reads the outcome from the runtime's own
    /// request record.
    async fn callback(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let state = str_of(payload.get("state")).ok_or("malformed connectors.callback payload")?;
        let code = str_of(payload.get("code"));
        let error = str_of(payload.get("error"));
        self.forget_stale_oauth();
        let pending = {
            let mut list = self.pending_oauth.lock().unwrap_or_else(|e| e.into_inner());
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
        let data = as_map(json!({"changeId": pending.proposal.change_id, "state": state}));
        let mut pairs = vec![("state", state.as_str())];
        if let Some(c) = &code {
            pairs.push(("code", c));
        }
        if let Some(e) = &error {
            pairs.push(("error", e));
        }
        if let Err(e) = self.runtime.complete_callback(&search_params(&pairs)).await {
            // A provider error or a refused exchange is the runtime's answer, not a crash.
            tracing::info!(
                "[connectors] callback for {} refused: {}",
                pending.service,
                messages(&e.message)
            );
        }
        let status = match self.runtime.request_status(&pending.request_id).await {
            Ok(s) => s,
            Err(e) => return Ok(outcome(false, "failed", Some(messages(&e.message)), Some(data))),
        };
        let app_id = str_of(status.get("appId"));
        let connected = status.get("status").and_then(Value::as_str) == Some("connected");
        let Some(app_id) = app_id.filter(|_| connected) else {
            let message = str_of(status.get("errorMessage")).unwrap_or_else(|| match &error {
                Some(e) => format!("The provider refused the sign-in ({e})."),
                None => "The sign-in did not complete.".into(),
            });
            return Ok(outcome(false, "failed", Some(message), Some(data)));
        };
        let live = self.runtime.connections().await.map_err(|e| e.message)?;
        let Some(live) = live.into_iter().find(|c| c.id == app_id) else {
            return Ok(outcome(
                false,
                "failed",
                Some("The sign-in completed but the connection is gone.".into()),
                Some(data),
            ));
        };
        let applied = self.record_and_assign(&pending.proposal, &live).await;
        let mut data = data;
        data.extend(applied.data);
        data.insert("summary".into(), json!(summarize(&pending.proposal)));
        data.insert("tofu".into(), json!(false));
        Ok(outcome(true, "applied", Some(String::new()), Some(data)))
    }

    fn forget_stale_oauth(&self) {
        let now = (self.now)();
        self.pending_oauth
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, p)| now - p.started_at <= OAUTH_PENDING_MS);
    }

    // ---- agents ----

    fn agents_holding(&self, connection_id: &str) -> Vec<String> {
        self.read_store()
            .agents
            .iter()
            .filter(|(_, a)| a.connections.iter().any(|c| c == connection_id))
            .map(|(k, _)| k.clone())
            .collect()
    }

    async fn post_agent(&self, vm_id: &str, body: Value) -> Result<(), String> {
        let host = self.read_store().agents.get(vm_id).and_then(|a| a.hostname.clone());
        if host.is_none() {
            return Err("This agent has no hostname yet.".into());
        }
        let Some(client) = self.app.contracts.agents.get() else {
            return Err("This firewall cannot reach its agents yet.".into());
        };
        client
            .post(vm_id, "/connectors/apply", body)
            .await
            .map(|_| ())
            .map_err(|e| e.message)
    }

    /// Bring an agent's runtime token in line with its grants and push the MCP entry to its box. A
    /// connection taken away stops working the moment the firewall applies it: the agent box never
    /// has to be reachable for a revocation to bite.
    async fn sync_agent(&self, vm_id: &str) -> Result<(), String> {
        let Some(a) = self.read_store().agents.get(vm_id).cloned() else {
            return Ok(());
        };
        let services = store::services_for(&self.read_store(), &a);
        let allowed: Vec<String> = services.iter().map(|s| format!("{s}.*")).collect();
        let name = format!("controlclaw-agent-{vm_id}");
        if a.connections.is_empty() {
            if let Some(id) = &a.token_id
                && let Err(e) = self.runtime.revoke_token(id).await
            {
                tracing::info!(
                    "[connectors] could not revoke {}'s token: {}",
                    a.name,
                    messages(&e.message)
                );
            }
            if let Some(x) = self.write_store().agents.get_mut(vm_id) {
                x.token_id = None;
                x.token = None;
            }
            self.save();
            return self.post_agent(vm_id, json!({"remove": true})).await;
        }
        match (&a.token_id, &a.token) {
            (Some(id), Some(_)) => {
                self.runtime
                    .update_token(id, &name, &allowed, &a.connections)
                    .await
                    .map_err(|e| e.message)?;
            }
            _ => {
                let (token, id) = self
                    .runtime
                    .create_token(&name, &allowed, &a.connections)
                    .await
                    .map_err(|e| e.message)?;
                if let Some(x) = self.write_store().agents.get_mut(vm_id) {
                    x.token_id = Some(id);
                    x.token = Some(token);
                }
            }
        }
        self.save();
        let (token, connections) = {
            let s = self.read_store();
            let Some(x) = s.agents.get(vm_id) else { return Ok(()) };
            let connections: Vec<Value> = x
                .connections
                .iter()
                .filter_map(|id| s.connections.get(id))
                .map(|c| json!({"id": c.id, "service": c.service, "alias": c.alias, "label": c.label, "accountLabel": c.account_label}))
                .collect();
            (x.token.clone(), connections)
        };
        self.post_agent(
            vm_id,
            json!({"gateway": {"url": self.gateway_url, "token": token}, "connections": connections}),
        )
        .await
    }

    async fn push_agents(&self, vm_ids: &[String]) -> (Vec<String>, Vec<Value>) {
        let mut applied = Vec::new();
        let mut failed = Vec::new();
        for vm_id in vm_ids {
            match self.sync_agent(vm_id).await {
                Ok(()) => applied.push(vm_id.clone()),
                Err(e) => failed.push(json!({"vmId": vm_id, "error": messages(&e)})),
            }
        }
        (applied, failed)
    }

    /// A box came up: re-push what it should have. "This firewall holds nothing for that agent" is
    /// reported as `empty`, never as `applied`: the control plane asks only when its own rows say
    /// the agent has apps, so the two disagreeing means something is gone.
    async fn push(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm_id = str_of(payload.get("vmId")).ok_or("malformed connectors.push payload")?;
        let has = self
            .read_store()
            .agents
            .get(&vm_id)
            .is_some_and(|a| !a.connections.is_empty());
        if !has {
            return Ok(outcome(
                true,
                "empty",
                Some("This firewall has no app connections for that agent. Connect the apps again.".into()),
                Some(as_map(json!({"vmId": vm_id, "applied": [], "failed": [], "held": 0}))),
            ));
        }
        {
            let mut s = self.write_store();
            if let Some(a) = s.agents.get_mut(&vm_id) {
                if let Some(h) = str_of(payload.get("hostname")) {
                    a.hostname = Some(h);
                }
                if let Some(n) = str_of(payload.get("name")) {
                    a.name = n;
                }
                if let Some(ip) = str_of(payload.get("privateIp")) {
                    a.private_ip = Some(ip);
                }
            }
        }
        self.save();
        let (applied, failed) = self.push_agents(std::slice::from_ref(&vm_id)).await;
        let connections = self
            .read_store()
            .agents
            .get(&vm_id)
            .map(|a| a.connections.clone())
            .unwrap_or_default();
        let message = failed
            .iter()
            .filter_map(|f| f.get("error").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("; ");
        Ok(outcome(
            failed.is_empty(),
            if failed.is_empty() { "applied" } else { "failed" },
            Some(message),
            Some(as_map(
                json!({"vmId": vm_id, "applied": applied, "failed": failed, "connections": connections}),
            )),
        ))
    }

    /// An agent was deleted. Its token is revoked and its grants dropped with no code: this only
    /// takes access away.
    async fn forget(&self, payload: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let vm_id = str_of(payload.get("vmId")).ok_or("malformed connectors.forget payload")?;
        let Some(a) = self.read_store().agents.get(&vm_id).cloned() else {
            return Ok(outcome(
                true,
                "applied",
                None,
                Some(as_map(json!({"vmId": vm_id, "revoked": false}))),
            ));
        };
        let mut revoked = false;
        if let Some(id) = &a.token_id {
            match self.runtime.revoke_token(id).await {
                Ok(_) => revoked = true,
                Err(e) => tracing::info!(
                    "[connectors] could not revoke the token of the deleted agent {vm_id}: {}",
                    messages(&e.message)
                ),
            }
        }
        self.write_store().agents.remove(&vm_id);
        self.save();
        Ok(outcome(
            true,
            "applied",
            None,
            Some(as_map(json!({"vmId": vm_id, "revoked": revoked}))),
        ))
    }
}

fn agent_view(s: &ConnectorStore) -> Vec<Value> {
    s.agents
        .iter()
        .map(|(vm, a)| json!({"vmId": vm, "name": a.name, "connections": a.connections, "hasToken": a.token.is_some()}))
        .collect()
}

fn merge_connection(stored: &StoredConnection, live: &RuntimeConnection) -> StoredConnection {
    let mut next = stored.clone();
    next.service = live.service.clone();
    next.alias = live.alias.clone().unwrap_or_else(|| stored.alias.clone());
    next.auth_type = live.auth_type.clone().unwrap_or_else(|| stored.auth_type.clone());
    next.account_label = live
        .account_label
        .clone()
        .or_else(|| live.display_name.clone())
        .or_else(|| stored.account_label.clone());
    next.state = live.status.clone().unwrap_or_else(|| stored.state.clone());
    next.last_error = match &live.status {
        Some(s) if s != "active" => stored.last_error.clone(),
        _ => None,
    };
    next
}

fn agent_of<'a>(s: &'a mut ConnectorStore, r: &AgentRef) -> &'a mut StoredConnectorAgent {
    if !s.agents.contains_key(&r.vm_id) {
        s.agents.insert(
            r.vm_id.clone(),
            StoredConnectorAgent {
                name: r.name.clone(),
                hostname: r.hostname.clone(),
                private_ip: r.private_ip.clone(),
                ..Default::default()
            },
        );
    }
    let a = s.agents.get_mut(&r.vm_id).expect("just put there");
    if !r.name.is_empty() {
        a.name = r.name.clone();
    }
    if r.hostname.is_some() {
        a.hostname = r.hostname.clone();
    }
    if r.private_ip.is_some() {
        a.private_ip = r.private_ip.clone();
    }
    a
}

fn grant(s: &mut ConnectorStore, r: &AgentRef, connection_id: &str, on: bool) {
    let a = agent_of(s, r);
    if on {
        if !a.connections.iter().any(|c| c == connection_id) {
            a.connections.push(connection_id.to_string());
        }
    } else {
        a.connections.retain(|c| c != connection_id);
    }
}

#[cfg(test)]
mod tests;
