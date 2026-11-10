//! Connected apps (OpenConnector) and MCP servers, as the SaaS's `integrations.*` and `mcpServers.*`
//! procedures do them, and the OAuth sign-in coming back: the panel's `/oauth/callback` page posts
//! what the provider sent (`state`, `code` or `error`) to `POST /api/oauth/callback`, which hands it
//! to the module that started that sign-in. The firewall holds the PKCE verifier and the state.
//!
//! Both modules keep their own state on the firewall (`connectors.read`, `mcpservers.read`); the
//! lists here are those reads. Changes are applied at once for the signed-in admin.

use http::Method;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, agent_ref, checked, data_of, new_id};

const TAG: &str = "integrations";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), Value, _, _>(
            "/api/connectors",
            TAG,
            "The connected apps and which agents use them (`connectors.read`, kind connections)",
            |c| async move { read_connectors(&c, json!({"kind": "connections"})).await },
        ),
        Route::get::<(), Value, _, _>(
            "/api/connectors/setup/:service",
            TAG,
            "How an app is connected: its auth kinds and fields, and an OAuth client if there is one",
            |c| async move { read_connectors(&c, json!({"kind": "setup", "service": c.param("service")})).await },
        ),
        Route::write::<NewConnection, CommandAnswer, _, _>(
            Method::POST,
            "/api/connectors",
            TAG,
            "Connect an app with a key or credential fields, for these agents",
            |c, b| async move { connect(&c, b).await },
        ),
        Route::write::<NewOauthConnection, CommandAnswer, _, _>(
            Method::POST,
            "/api/connectors/oauth",
            TAG,
            "Start connecting an app with OAuth: the answer's data has the address to send the browser to",
            |c, b| async move { oauth_connect(&c, b).await },
        ),
        Route::write::<ConnectionSecrets, CommandAnswer, _, _>(
            Method::PUT,
            "/api/connectors/:id",
            TAG,
            "Replace an app connection's key or credential fields",
            |c, b| async move {
                let mut p = connector_payload("replace", c.param("id"));
                put_secrets(&mut p, b.api_key, b.secrets, b.extra);
                connector_apply(&c, p).await
            },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/connectors/:id/reconnect",
            TAG,
            "Sign in to an OAuth app again",
            |c, _| async move { connector_apply(&c, connector_payload("oauth_reconnect", c.param("id"))).await },
        ),
        Route::write::<AssignBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/connectors/:id/assign",
            TAG,
            "Let an agent use the app, or stop it (`on: false`)",
            |c, b| async move {
                let mut p = connector_payload(if b.on { "assign" } else { "unassign" }, c.param("id"));
                p.insert("agents".into(), json!([agent_ref(&c.db, &b.vm_id)?]));
                connector_apply(&c, p).await
            },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::DELETE,
            "/api/connectors/:id",
            TAG,
            "Remove an app connection",
            |c, _| async move { connector_apply(&c, connector_payload("remove", c.param("id"))).await },
        ),
        Route::get::<(), Value, _, _>(
            "/api/mcp-servers",
            TAG,
            "The MCP servers and which agents use them (`mcpservers.read`)",
            |c| async move { Ok(Reply::ok(&data_of(c.command("mcpservers.read", json!({})).await?)?)) },
        ),
        Route::write::<NewMcpServer, CommandAnswer, _, _>(
            Method::POST,
            "/api/mcp-servers",
            TAG,
            "Add an MCP server (no auth, a header, or OAuth) for these agents",
            |c, b| async move { add_mcp(&c, b).await },
        ),
        Route::write::<McpHeader, CommandAnswer, _, _>(
            Method::PUT,
            "/api/mcp-servers/:name",
            TAG,
            "Replace a header server's credential",
            |c, b| async move {
                let mut p = mcp_payload("replace", c.param("name"));
                p.insert("auth".into(), json!("header"));
                p.insert("headerName".into(), json!(b.header_name));
                p.insert("secret".into(), json!({"headerValue": b.header_value}));
                mcp_apply(&c, p).await
            },
        ),
        Route::write::<McpReconnect, CommandAnswer, _, _>(
            Method::POST,
            "/api/mcp-servers/:name/reconnect",
            TAG,
            "Sign in to an OAuth server again: the answer's data has the address to send the browser to",
            |c, b| async move {
                let mut p = mcp_payload("reconnect", c.param("name"));
                if let Some(id) = b.client_id {
                    p.insert("clientId".into(), json!(id));
                }
                if let Some(s) = b.client_secret {
                    p.insert("secret".into(), json!({"clientSecret": s}));
                }
                mcp_apply(&c, p).await
            },
        ),
        Route::write::<AssignBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/mcp-servers/:name/assign",
            TAG,
            "Let an agent use the server, or stop it (`on: false`)",
            |c, b| async move {
                agent_ref(&c.db, &b.vm_id)?;
                let mut p = mcp_payload(if b.on { "assign" } else { "unassign" }, c.param("name"));
                p.insert("agents".into(), json!([{"vmId": b.vm_id}]));
                mcp_apply(&c, p).await
            },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::DELETE,
            "/api/mcp-servers/:name",
            TAG,
            "Remove an MCP server",
            |c, _| async move { mcp_apply(&c, mcp_payload("remove", c.param("name"))).await },
        ),
        Route::write::<super::NoBody, Value, _, _>(
            Method::POST,
            "/api/mcp-servers/:name/tools",
            TAG,
            "Read the server's tools again (`mcpservers.tools`)",
            |c, _| async move {
                let p = checked("mcpservers.tools", json!({"name": c.param("name")}))?;
                Ok(Reply::ok(&data_of(
                    c.command("mcpservers.tools", Value::Object(p)).await?,
                )?))
            },
        ),
        Route::write::<OauthCallback, CommandAnswer, _, _>(
            Method::POST,
            "/api/oauth/callback",
            TAG,
            "What an OAuth provider sent back to the panel's /oauth/callback page: the sign-in it belongs to finishes",
            |c, b| async move { callback(&c, b).await },
        ),
    ]
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewConnection {
    /// The app's id in the catalog (`github`, `linear`, ...).
    pub service: String,
    /// Its name, for the summary; the id when left out.
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// An API key app's key.
    #[serde(default)]
    pub api_key: Option<String>,
    /// A credential app's secret fields.
    #[serde(default)]
    pub secrets: Option<Map<String, Value>>,
    /// Fields that are not secret (an account's domain, a region).
    #[serde(default)]
    pub extra: Option<Map<String, Value>>,
    /// The agents that may use it.
    #[serde(default)]
    pub vm_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewOauthConnection {
    pub service: String,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// Your own OAuth app, when the app needs one: its client id and secret.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Other fields of your OAuth app (a tenant, a domain).
    #[serde(default)]
    pub extra: Option<Map<String, Value>>,
    /// The permissions asked for, by the setup's option ids.
    #[serde(default)]
    pub authorization_option_ids: Vec<String>,
    #[serde(default)]
    pub vm_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionSecrets {
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub secrets: Option<Map<String, Value>>,
    #[serde(default)]
    pub extra: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignBody {
    pub vm_id: String,
    pub on: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewMcpServer {
    /// Lower case letters, digits and dashes, at most 40: how agents name it.
    pub name: String,
    /// `https://`, not a private address.
    pub url: String,
    /// `none`, `header` or `oauth`.
    pub auth: String,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_value: Option<String>,
    /// OAuth: your own client, when the server does not register one itself.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub vm_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpHeader {
    pub header_name: String,
    pub header_value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpReconnect {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OauthCallback {
    pub state: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

async fn read_connectors(c: &Ctx, p: Value) -> Result {
    let p = checked("connectors.read", p)?;
    Ok(Reply::ok(&data_of(
        c.command("connectors.read", Value::Object(p)).await?,
    )?))
}

fn connector_payload(kind: &str, connection: &str) -> Map<String, Value> {
    let v = json!({"changeId": new_id("chg"), "kind": kind, "service": "", "connectionId": connection});
    v.as_object().cloned().unwrap_or_default()
}

fn put_secrets(
    p: &mut Map<String, Value>,
    key: Option<String>,
    secrets: Option<Map<String, Value>>,
    extra: Option<Map<String, Value>>,
) {
    match (key, secrets) {
        (Some(k), _) => p.insert("secret".into(), json!({"apiKey": k.trim()})),
        (None, Some(s)) => p.insert("secret".into(), json!({"values": s})),
        (None, None) => None,
    };
    if let Some(e) = extra {
        p.insert("extra".into(), Value::Object(e));
    }
}

fn agents(c: &Ctx, ids: &[String]) -> Result<Value> {
    let mut seen = std::collections::BTreeSet::new();
    let list: Vec<Value> = ids
        .iter()
        .filter(|v| seen.insert(v.as_str()))
        .map(|v| agent_ref(&c.db, v))
        .collect::<Result<_>>()?;
    Ok(Value::Array(list))
}

/// The firewall's own check (`SERVICE_RE`): lower case letters, digits and `_`, at most 61.
fn service(s: &str) -> Result<String> {
    let s = s.trim();
    let ok = !s.is_empty()
        && s.len() <= 61
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !ok {
        return Err(Reply::bad("service: the app's id (lower case letters, digits and _)"));
    }
    Ok(s.to_string())
}

/// The app an existing connection is for, from the firewall's own list.
async fn service_of(c: &Ctx, connection: &str) -> Result<String> {
    let p = checked("connectors.read", json!({"kind": "connections"}))?;
    let data = data_of(c.command("connectors.read", Value::Object(p)).await?)?;
    data.get("connections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|x| x.get("id").and_then(Value::as_str) == Some(connection))
        .and_then(|x| x.get("service").and_then(Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| Reply::not_found("Connection"))
}

async fn connector_apply(c: &Ctx, mut p: Map<String, Value>) -> Result {
    // A change to a connection names its app, as the firewall checks it.
    if p.get("service").and_then(Value::as_str) == Some("")
        && let Some(id) = p
            .get("connectionId")
            .and_then(Value::as_str)
            .filter(|i| !i.is_empty())
            .map(str::to_string)
    {
        let svc = service_of(c, &id).await?;
        p.insert("service".into(), json!(svc));
    }
    let p = checked("connectors.propose", Value::Object(p))?;
    Ok(c.apply("connectors", p).await?.reply())
}

async fn connect(c: &Ctx, b: NewConnection) -> Result {
    let service = service(&b.service)?;
    if b.api_key.as_deref().map(str::trim).is_none_or(str::is_empty) && b.secrets.as_ref().is_none_or(Map::is_empty) {
        return Err(Reply::bad("apiKey or secrets: the app's credential"));
    }
    let mut p = connector_payload("connect", "");
    p.remove("connectionId");
    p.insert("service".into(), json!(service));
    p.insert(
        "serviceName".into(),
        json!(b.service_name.unwrap_or_else(|| service.clone())),
    );
    p.insert("label".into(), json!(b.label));
    p.insert("agents".into(), agents(c, &b.vm_ids)?);
    put_secrets(&mut p, b.api_key, b.secrets, b.extra);
    connector_apply(c, p).await
}

async fn oauth_connect(c: &Ctx, b: NewOauthConnection) -> Result {
    let service = service(&b.service)?;
    let mut p = connector_payload("oauth_connect", "");
    p.remove("connectionId");
    p.insert("service".into(), json!(service));
    p.insert(
        "serviceName".into(),
        json!(b.service_name.unwrap_or_else(|| service.clone())),
    );
    p.insert("label".into(), json!(b.label));
    p.insert("clientId".into(), json!(b.client_id));
    p.insert("extra".into(), Value::Object(b.extra.unwrap_or_default()));
    p.insert("authorizationOptionIds".into(), json!(b.authorization_option_ids));
    p.insert("agents".into(), agents(c, &b.vm_ids)?);
    if let Some(s) = b.client_secret {
        p.insert("secret".into(), json!({"clientSecret": s}));
    }
    connector_apply(c, p).await
}

fn mcp_payload(kind: &str, name: &str) -> Map<String, Value> {
    let v = json!({"changeId": new_id("chg"), "kind": kind, "name": name});
    v.as_object().cloned().unwrap_or_default()
}

async fn mcp_apply(c: &Ctx, p: Map<String, Value>) -> Result {
    let p = checked("mcpservers.propose", Value::Object(p))?;
    Ok(c.apply("mcpservers", p).await?.reply())
}

/// `https://` and a name with a dot, or an address: the MCP module checks the rest on every address
/// it resolves (a private, loopback or link-local one, IPv4 or IPv6, is refused there). A one-word
/// name (`https://intranet/`) is only ever a name on a private network.
fn https(u: &str) -> Result<()> {
    let ok = url::Url::parse(u.trim()).is_ok_and(|url| {
        url.scheme() == "https"
            && match url.host() {
                Some(url::Host::Domain(d)) => d.contains('.'),
                Some(_) => true,
                None => false,
            }
    });
    if ok {
        Ok(())
    } else {
        Err(Reply::bad("url: an https:// address on the internet"))
    }
}

async fn add_mcp(c: &Ctx, b: NewMcpServer) -> Result {
    let name = b.name.trim();
    if name.is_empty()
        || name.len() > 40
        || !name
            .bytes()
            .all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == b'-')
    {
        return Err(Reply::bad("name: lower case letters, digits and dashes, at most 40"));
    }
    https(&b.url)?;
    let mut p = mcp_payload("add", name);
    p.insert("url".into(), json!(b.url.trim()));
    p.insert(
        "agents".into(),
        json!(
            agents(c, &b.vm_ids)?
                .as_array()
                .map(|a| a.iter().map(|x| json!({"vmId": x["vmId"]})).collect::<Vec<_>>())
        ),
    );
    match b.auth.as_str() {
        "none" => {
            p.insert("auth".into(), json!("none"));
        }
        "header" => {
            let (Some(h), Some(v)) = (
                b.header_name.filter(|h| !h.trim().is_empty()),
                b.header_value.filter(|v| !v.is_empty()),
            ) else {
                return Err(Reply::bad("headerName and headerValue are needed for a header server"));
            };
            p.insert("auth".into(), json!("header"));
            p.insert("headerName".into(), json!(h.trim()));
            p.insert("secret".into(), json!({"headerValue": v}));
        }
        "oauth" => {
            p.insert("auth".into(), json!("oauth"));
            p.insert("clientId".into(), json!(b.client_id));
            if let Some(s) = b.client_secret {
                p.insert("secret".into(), json!({"clientSecret": s}));
            }
        }
        _ => return Err(Reply::bad("auth: none, header or oauth")),
    }
    mcp_apply(c, p).await
}

/// The module answered that it never started this sign-in: the connectors and MCP servers say
/// `expired` with only the state; Google says `failed` with no data. Any other answer is its own, a
/// failure included, and is the one shown.
fn not_mine(action: &str, r: &CommandAnswer) -> bool {
    let only_state = r
        .data
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|d| d.contains_key("state") && !d.contains_key("changeId"));
    match action {
        "google.callback" => r.status == "failed" && r.data.is_none(),
        _ => r.status == "expired" && only_state,
    }
}

/// The module that started this sign-in takes it: the connectors, then the MCP servers, then
/// Google, as the SaaS's callback page tries them. A module that does not know the state answers
/// with no change in it. A sign-in held for a code after it came back is confirmed at once
/// ([`Ctx::run`]).
async fn callback(c: &Ctx, b: OauthCallback) -> Result {
    if b.state.trim().is_empty() || b.state.len() > 512 {
        return Err(Reply::bad("state: what the provider sent back"));
    }
    let body = json!({"state": b.state, "code": b.code, "error": b.error});
    let mut last = None;
    for action in ["connectors.callback", "mcpservers.callback", "google.callback"] {
        let p = checked(action, body.clone())?;
        let r = match c.run(action, Value::Object(p)).await {
            Ok(r) => r,
            // Not running on this firewall (no connector runtime, say): the next one.
            Err(e) if e.status == 404 => continue,
            Err(e) => return Err(e),
        };
        if !not_mine(action, &r) {
            if action == "google.callback"
                && let Err(e) = super::managed::refresh_accounts(c).await
            {
                tracing::warn!("[cc-local] the accounts' rules: {}", e.body);
            }
            return Ok(r.reply());
        }
        // The first refusal is the one shown: the connectors' "no longer waiting, start it again"
        // fits a sign-in that expired, which Google's "does not match" does not.
        last.get_or_insert(r);
    }
    Ok(last
        .unwrap_or_else(|| CommandAnswer::failed("No sign-in on this firewall is waiting for that answer."))
        .reply())
}
