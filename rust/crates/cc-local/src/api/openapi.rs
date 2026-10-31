//! The OpenAPI 3.1 document of the route table: what `packages/fw-api/openapi.json` holds and its
//! TS client is generated from (`pnpm --filter @controlclaw/fw-api generate`). A test fails when the
//! checked-in file is not this.

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, SchemaGenerator};
use serde_json::{Map, Value, json};

use super::{ApiError, Route, routes};

/// `POST /api/setup`: the first admin, with the token from the log.
#[derive(serde::Deserialize, JsonSchema)]
pub struct SetupBody {
    pub token: String,
    /// At least 12 characters.
    pub password: String,
}

/// `POST /api/login`.
#[derive(serde::Deserialize, JsonSchema)]
pub struct LoginBody {
    pub password: String,
}

/// `POST /api/setup` and `/api/login`: the session cookie is set; writes send `csrf` back.
#[derive(serde::Serialize, JsonSchema)]
pub struct SignedIn {
    pub ok: bool,
    pub csrf: String,
}

/// `GET /api/session`.
#[derive(serde::Serialize, JsonSchema)]
pub struct SessionInfo {
    /// Signed in.
    pub admin: bool,
    /// No admin yet: set one up with the token from the log.
    pub setup: bool,
    /// The session's CSRF token, when signed in.
    pub csrf: Option<String>,
}

/// `POST /api/admin/password`: the current password, and a new one of at least 12 characters.
#[derive(serde::Deserialize, JsonSchema)]
pub struct PasswordBody {
    pub current: String,
    pub new: String,
}

/// The password is changed; every other session is ended, this one stays.
#[derive(serde::Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChanged {
    pub ok: bool,
    /// How many other sessions were ended.
    pub signed_out: u64,
}

#[derive(serde::Serialize, JsonSchema)]
pub struct OkReply {
    pub ok: bool,
}

/// The routes `admin.rs` answers itself, before the table: (method, path, summary, body, response).
fn session_routes(g: &mut SchemaGenerator) -> Vec<(&'static str, &'static str, &'static str, Option<Value>, Value)> {
    vec![
        (
            "post",
            "/api/setup",
            "Set the admin's password with the setup token from the log",
            Some(g.subschema_for::<SetupBody>().to_value()),
            g.subschema_for::<SignedIn>().to_value(),
        ),
        (
            "post",
            "/api/login",
            "Sign in",
            Some(g.subschema_for::<LoginBody>().to_value()),
            g.subschema_for::<SignedIn>().to_value(),
        ),
        (
            "get",
            "/api/session",
            "Whether this browser is signed in, and its CSRF token",
            None,
            g.subschema_for::<SessionInfo>().to_value(),
        ),
        (
            "post",
            "/api/admin/password",
            "Change the admin's password; every other session is signed out",
            Some(g.subschema_for::<PasswordBody>().to_value()),
            g.subschema_for::<PasswordChanged>().to_value(),
        ),
        (
            "post",
            "/api/logout",
            "Sign out",
            None,
            g.subschema_for::<OkReply>().to_value(),
        ),
    ]
}

/// `/api/egress/rules/:id` → `/api/egress/rules/{id}`, and the names of the params.
fn path_of(path: &str) -> (String, Vec<String>) {
    let mut names = Vec::new();
    let p = path
        .split('/')
        .map(|s| match s.strip_prefix(':') {
            Some(n) => {
                names.push(n.to_string());
                format!("{{{n}}}")
            }
            None => s.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/");
    (p, names)
}

/// A query type's fields, inlined, as OpenAPI parameters.
fn query_params(r: &Route) -> Vec<Value> {
    let Some(f) = r.query else { return Vec::new() };
    let mut g = SchemaSettings::draft2020_12()
        .with(|s| s.inline_subschemas = true)
        .into_generator();
    let schema = f(&mut g).to_value();
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| {
            props
                .iter()
                .map(|(name, s)| {
                    let mut s = s.clone();
                    let description = s.as_object_mut().and_then(|o| o.remove("description"));
                    let mut p = json!({"name": name, "in": "query", "required": required.contains(&name.as_str()), "schema": s});
                    if let Some(d) = description {
                        p["description"] = d;
                    }
                    p
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `get` + each path part in PascalCase, a dash kept as `_` so `/egress-rules` and `/egress/rules`
/// differ: `getEgress_rules`, `getEgressRules`, `patchEgressRulesId`.
fn operation_id(r: &Route) -> String {
    let parts = r
        .path
        .trim_start_matches("/api/")
        .split('/')
        .filter(|w| !w.is_empty())
        .map(|w| {
            let w = w.trim_start_matches(':').replace('-', "_");
            let mut c = w.chars();
            c.next()
                .map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
        });
    std::iter::once(r.method.as_str().to_lowercase()).chain(parts).collect()
}

pub fn openapi() -> Value {
    let mut g: SchemaGenerator = SchemaSettings::draft2020_12()
        .with(|s| s.definitions_path = "/components/schemas".into())
        .into_generator();
    let error = g.subschema_for::<ApiError>().to_value();
    let mut paths = Map::new();
    for (method, path, summary, body, resp) in session_routes(&mut g) {
        let id: String = format!(
            "{method}{}",
            path.trim_start_matches("/api/")
                .chars()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c })
                .collect::<String>()
        );
        let mut op = json!({
            "operationId": id,
            "tags": ["session"],
            "summary": summary,
            "security": [],
            "responses": {
                "200": {"description": "OK", "content": {"application/json": {"schema": resp}}},
                "default": {"description": "Refused: `{error}`", "content": {"application/json": {"schema": error}}},
            },
        });
        if let Some(b) = body {
            op["requestBody"] = json!({"required": true, "content": {"application/json": {"schema": b}}});
        }
        paths.entry(path.to_string()).or_insert_with(|| json!({}))[method] = op;
    }
    for r in routes() {
        let (path, names) = path_of(r.path);
        let mut params: Vec<Value> = names
            .iter()
            .map(|n| json!({"name": n, "in": "path", "required": true, "schema": {"type": "string"}}))
            .collect();
        params.extend(query_params(&r));
        let mut op = json!({
            "operationId": operation_id(&r),
            "tags": [r.tag],
            "summary": r.summary,
            "responses": {
                "200": {"description": "OK", "content": {"application/json": {"schema": (r.resp)(&mut g).to_value()}}},
                "default": {"description": "Refused: `{error}`", "content": {"application/json": {"schema": error}}},
            },
        });
        if !params.is_empty() {
            op["parameters"] = Value::Array(params);
        }
        if let Some(b) = r.body {
            op["requestBody"] =
                json!({"required": true, "content": {"application/json": {"schema": b(&mut g).to_value()}}});
        }
        let entry = paths.entry(path).or_insert_with(|| json!({}));
        entry[r.method.as_str().to_lowercase()] = op;
    }
    let schemas: Map<String, Value> = g.take_definitions(true).into_iter().collect();
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "ControlClaw firewall panel API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The local panel's API on a standalone firewall (docs/standalone/panel-api.md). Sign in with POST /api/login; every write sends the session's CSRF token as x-csrf-token.",
        },
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "session": {"type": "apiKey", "in": "cookie", "name": crate::admin::COOKIE},
                "csrf": {"type": "apiKey", "in": "header", "name": "x-csrf-token"},
            },
        },
        "security": [{"session": []}],
    })
}
