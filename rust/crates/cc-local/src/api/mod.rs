//! The local panel's REST API (docs/standalone/panel-api.md): one route table, one file per
//! feature, each route with the types of what it takes and gives, so the OpenAPI document
//! ([`openapi`]) and the TS client in `packages/fw-api` come from the same place as the handlers.
//!
//! `admin.rs` checks the Host, the session and the CSRF token before a route here runs. A route
//! answers with [`Reply`]: a status and a JSON body, `{error}` for a refusal.
//!
//! Writes that change the firewall run its command handlers through [`Ctx::apply`]: the proposal,
//! then at once its confirmation with the code the firewall hands back to the signed-in admin.
//! There is no code to type in standalone (plan §3); the SaaS keeps its codes.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use http::Method;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use crate::admin::Hooks;
use crate::db::Db;
use crate::plane::{BoxFuture, LocalControlPlane};

pub mod accounts;
pub mod activity;
pub mod channels;
pub mod controls;
pub mod egress;
pub mod integrations;
pub mod llm;
pub mod managed;
pub mod openapi;
pub mod pairing;
pub mod panel;
pub mod requests;
pub mod rules;
pub mod security;

pub use openapi::openapi;

/// A route's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
}

impl Reply {
    pub fn ok<T: Serialize>(body: &T) -> Self {
        Self {
            status: 200,
            body: serde_json::to_value(body).unwrap_or(Value::Null),
        }
    }

    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({"error": message.into()}),
        }
    }

    pub fn bad(message: impl Into<String>) -> Self {
        Self::error(400, message)
    }

    pub fn not_found(what: &str) -> Self {
        Self::error(404, format!("{what} not found"))
    }
}

/// A database failure is a 500 with nothing of it shown; the log has it.
impl From<rusqlite::Error> for Reply {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("[cc-local] api: {e}");
        Self::error(500, "Failed")
    }
}

pub type Result<T = Reply> = std::result::Result<T, Reply>;

/// The refusal every route documents: `{error}`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ApiError {
    pub error: String,
}

/// What a route's handler gets.
#[derive(Clone)]
pub struct Ctx {
    pub db: Arc<Db>,
    pub plane: Arc<LocalControlPlane>,
    pub hooks: Hooks,
    /// The `:name` parts of the path.
    pub params: HashMap<String, String>,
    /// Without the `?`.
    pub query: String,
}

impl Ctx {
    pub fn param(&self, name: &str) -> &str {
        self.params.get(name).map_or("", String::as_str)
    }

    /// The query string as `Q`; a bad one is a 400.
    pub fn query<Q: DeserializeOwned>(&self) -> Result<Q> {
        serde_urlencoded::from_str(&self.query).map_err(|e| Reply::bad(format!("query: {e}")))
    }

    /// Run a firewall command as the signed-in admin; `None` when this firewall does not run it.
    pub async fn command(&self, action: &str, payload: Value) -> Result<CommandAnswer> {
        let Value::Object(payload) = payload else {
            return Err(Reply::bad("payload: an object"));
        };
        let Some(out) = (self.hooks.command)(action.to_string(), payload).await else {
            return Err(Reply::error(404, format!("{action} is not running on this firewall")));
        };
        Ok(serde_json::from_value(out).unwrap_or_else(|_| CommandAnswer::failed("The firewall gave no answer")))
    }

    /// A change to the firewall: `<ns>.propose`, then, when the firewall holds it for a code, at
    /// once `<ns>.confirm` with the code it handed back to the admin. The code is never answered.
    pub async fn apply(&self, ns: &str, payload: Map<String, Value>) -> Result<CommandAnswer> {
        self.apply_as(&format!("{ns}.propose"), &format!("{ns}.confirm"), payload, Map::new())
            .await
    }

    /// [`Ctx::apply`] with other action names (`kill.release`, then `kill.confirm`), and fields the
    /// confirmation carries besides the change id and the code.
    pub async fn apply_as(
        &self,
        propose: &str,
        confirm: &str,
        mut payload: Map<String, Value>,
        confirm_with: Map<String, Value>,
    ) -> Result<CommandAnswer> {
        let change_id = payload
            .get("changeId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| new_id("chg"));
        payload.insert("changeId".into(), json!(change_id));
        let proposed = self.command(propose, Value::Object(payload)).await?;
        let Some(code) = proposed
            .local_code
            .clone()
            .filter(|_| proposed.status == "awaiting_code")
        else {
            return Ok(proposed);
        };
        let mut c = confirm_with;
        c.insert("changeId".into(), json!(change_id));
        c.insert("code".into(), json!(code));
        self.command(confirm, Value::Object(c)).await
    }

    /// Any action, and when its answer is held for a code (a proposal, `kill.release`, a sign-in
    /// that came back), confirmed at once by the module's own confirm with the code the firewall
    /// handed back: what the panel's routes do. The admin never has a code.
    pub async fn run(&self, action: &str, payload: Value) -> Result<CommandAnswer> {
        let out = self.command(action, payload.clone()).await?;
        let Some(code) = out.local_code.clone().filter(|_| out.status == "awaiting_code") else {
            return Ok(out);
        };
        let ns = action.split('.').next().unwrap_or_default();
        let change_id = payload
            .get("changeId")
            .or_else(|| out.data.as_ref().and_then(|d| d.get("changeId")))
            .cloned()
            .unwrap_or(Value::Null);
        let mut confirm = json!({"changeId": change_id, "code": code});
        // What a module's confirm reads besides the change and the code: the stop's scope and
        // agent, a login's id. Per module, so no other confirm is handed a field it did not ask for.
        let extra: &[&str] = match ns {
            "kill" => &["scope", "vmId"],
            "logins" => &["id"],
            "secrets" => &["name"],
            _ => &[],
        };
        for k in extra {
            if let Some(v) = payload.get(*k) {
                confirm[*k] = v.clone();
            }
        }
        self.command(&format!("{ns}.confirm"), confirm).await
    }
}

/// A command handler's outcome, as the firewall gives it (`CommandOutcome`).
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize, Serialize, JsonSchema)]
pub struct CommandAnswer {
    pub ok: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// The code a proposal is held for, handed back to the admin's API: read by [`Ctx::apply`],
    /// never answered.
    #[serde(default, rename = "localCode", skip_serializing)]
    #[schemars(skip)]
    pub local_code: Option<String>,
}

/// Where the firewall's hook puts that code in the outcome.
pub const LOCAL_CODE: &str = "localCode";

impl CommandAnswer {
    pub fn failed(message: &str) -> Self {
        Self {
            ok: false,
            status: "failed".into(),
            message: Some(message.into()),
            data: None,
            local_code: None,
        }
    }

    /// 200 when the firewall did it, 409 when it said no (the answer still says why).
    pub fn reply(self) -> Reply {
        Reply {
            status: if self.ok { 200 } else { 409 },
            body: serde_json::to_value(&self).unwrap_or(Value::Null),
        }
    }
}

/// What a command answered on success: its `data`, or `{}`; a refusal is 409 with its message.
pub fn data_of(a: CommandAnswer) -> Result<Value> {
    if !a.ok {
        return Err(a.reply());
    }
    Ok(a.data.unwrap_or_else(|| json!({})))
}

/// A body's object, checked against the action's payload type in `cc-contracts` (400 otherwise).
pub fn checked(action: &str, v: Value) -> Result<Map<String, Value>> {
    cc_contracts::commands::check(action, &v).map_err(|e| Reply::bad(e.to_string()))?;
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(Reply::bad("an object")),
    }
}

/// The agents as a command names them: `{vmId, name, hostname}`.
pub fn agent_refs(db: &Db) -> rusqlite::Result<Vec<Value>> {
    let c = db.lock();
    let mut q = c.prepare(
        "SELECT vm_id, name, hostname, private_ip, agent_addr FROM agents WHERE role = 'openclaw' ORDER BY created_at, vm_id",
    )?;
    q.query_map([], |r| {
        let ip = r.get::<_, Option<String>>(3)?;
        // A paired agent has no hostname: the modules name it by where its vm-agent listens (the
        // address the firewall signs its tokens for), else its address. The call itself goes where
        // the identity map says.
        let addr = r.get::<_, Option<String>>(4)?;
        let hostname = r.get::<_, Option<String>>(2)?.filter(|h| !h.is_empty()).or_else(|| {
            addr.and_then(|a| a.parse::<std::net::SocketAddrV4>().ok())
                .map(|a| a.ip().to_string())
                .or_else(|| ip.clone().filter(|i| !i.is_empty()))
        });
        Ok(
            json!({"vmId": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "hostname": hostname,
                  "privateIp": ip}),
        )
    })?
    .collect()
}

/// One agent as a command names it, or 404.
pub fn agent_ref(db: &Db, vm_id: &str) -> Result<Value> {
    agent_refs(db)?
        .into_iter()
        .find(|a| a["vmId"] == vm_id)
        .ok_or_else(|| Reply::not_found("Agent"))
}

/// A fresh id with a prefix: `r_3f9a…`.
pub fn new_id(prefix: &str) -> String {
    let mut b = [0u8; 9];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    format!("{prefix}_{}", hex::encode(b))
}

pub type SchemaFn = fn(&mut SchemaGenerator) -> Schema;
type Handler = Arc<dyn Fn(Ctx, Value) -> BoxFuture<'static, Reply> + Send + Sync>;

fn schema_of<T: JsonSchema>(g: &mut SchemaGenerator) -> Schema {
    g.subschema_for::<T>()
}

/// One endpoint.
#[derive(Clone)]
pub struct Route {
    pub method: Method,
    /// `/api/...`, with `:name` parts.
    pub path: &'static str,
    /// The tag: the feature it belongs to.
    pub tag: &'static str,
    pub summary: &'static str,
    pub query: Option<SchemaFn>,
    pub body: Option<SchemaFn>,
    pub resp: SchemaFn,
    handler: Handler,
}

/// The `{}` body of a write that takes nothing.
#[derive(Debug, Default, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoBody {}

impl Route {
    /// A read: no body. `Q` is the query (`()` for none).
    pub fn get<Q, R, F, Fut>(path: &'static str, tag: &'static str, summary: &'static str, f: F) -> Self
    where
        Q: JsonSchema + 'static,
        R: JsonSchema,
        F: Fn(Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        let f = Arc::new(f);
        Self {
            method: Method::GET,
            path,
            tag,
            summary,
            query: (std::any::TypeId::of::<Q>() != std::any::TypeId::of::<()>()).then_some(schema_of::<Q>),
            body: None,
            resp: schema_of::<R>,
            handler: Arc::new(move |ctx, _| {
                let f = f.clone();
                Box::pin(async move { f(ctx).await.unwrap_or_else(|e| e) })
            }),
        }
    }

    /// A write with a JSON body `B`; a body that does not parse as `B` is a 400.
    pub fn write<B, R, F, Fut>(
        method: Method,
        path: &'static str,
        tag: &'static str,
        summary: &'static str,
        f: F,
    ) -> Self
    where
        B: DeserializeOwned + JsonSchema + Send + 'static,
        R: JsonSchema,
        F: Fn(Ctx, B) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        let f = Arc::new(f);
        Self {
            method,
            path,
            tag,
            summary,
            query: None,
            body: Some(schema_of::<B>),
            resp: schema_of::<R>,
            handler: Arc::new(move |ctx, body| {
                let f = f.clone();
                Box::pin(async move {
                    // No body is an empty object, so a write that takes nothing needs none.
                    let body = if body.is_null() { json!({}) } else { body };
                    match serde_json::from_value::<B>(body) {
                        Ok(b) => f(ctx, b).await.unwrap_or_else(|e| e),
                        Err(e) => Reply::bad(format!("body: {e}")),
                    }
                })
            }),
        }
    }

    /// Name the query a write takes too (`DELETE ...?force=true`), for the OpenAPI document.
    pub fn with_query<Q: JsonSchema + 'static>(mut self) -> Self {
        self.query = Some(schema_of::<Q>);
        self
    }

    /// The path params when `path` is this route's, else `None`.
    fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
        let (mine, theirs): (Vec<&str>, Vec<&str>) = (self.path.split('/').collect(), path.split('/').collect());
        if mine.len() != theirs.len() {
            return None;
        }
        let mut params = HashMap::new();
        for (m, t) in mine.iter().zip(&theirs) {
            if let Some(name) = m.strip_prefix(':') {
                if t.is_empty() {
                    return None;
                }
                params.insert(name.to_string(), percent_decode(t)?);
            } else if m != t {
                return None;
            }
        }
        Some(params)
    }
}

/// `%XX` decoded (a `+` stays a `+`: this is a path, not a form); `None` when it is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Every route, one feature after another.
pub fn routes() -> Vec<Route> {
    [
        panel::routes(),
        egress::routes(),
        llm::routes(),
        activity::routes(),
        pairing::routes(),
        requests::routes(),
        rules::routes(),
        security::routes(),
        controls::routes(),
        channels::routes(),
        integrations::routes(),
        accounts::routes(),
    ]
    .concat()
}

/// What `find` says about a request.
pub enum Found<'a> {
    Route(&'a Route, HashMap<String, String>),
    /// The path is known; the method is not.
    Method,
    None,
}

pub fn find<'a>(table: &'a [Route], method: &Method, path: &str) -> Found<'a> {
    let mut known = false;
    for r in table {
        if let Some(params) = r.matches(path) {
            if r.method == *method {
                return Found::Route(r, params);
            }
            known = true;
        }
    }
    if known { Found::Method } else { Found::None }
}

pub async fn call(route: &Route, ctx: Ctx, body: Value) -> Reply {
    (route.handler)(ctx, body).await
}

#[cfg(test)]
mod tests;
