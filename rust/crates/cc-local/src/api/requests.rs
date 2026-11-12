//! Permission requests: what an agent or the firewall asked a person, listed and answered as the
//! SaaS's `requests.listPermissionRequests` and `resolvePermissionRequest` do. The box that asked
//! learns the answer on its next poll of `/permission`. A request the firewall's Auto approve rules
//! answered is here too, with the rule (`resolvedBy: rule`). There is no "Always allow" here.

use http::Method;
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Ctx, Reply, Result, Route};
use crate::plane::iso;

const TAG: &str = "requests";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<RequestsQuery, Vec<PermissionRequest>, _, _>(
            "/api/requests",
            TAG,
            "Permission requests, newest first (at most 200)",
            |c| async move { list(&c) },
        ),
        Route::write::<Resolve, PermissionRequest, _, _>(
            Method::POST,
            "/api/requests/:id/resolve",
            TAG,
            "Approve or deny a pending request",
            |c, b| async move { resolve(&c, b) },
        ),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct RequestsQuery {
    /// Only these; all when left out.
    #[serde(default)]
    pub status: Option<Status>,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resolve {
    pub decision: Decision,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    pub id: String,
    /// `access`, `email_recipient`, `app_call`, `exec`, `plugin`, `system`, `meeting_request`.
    pub kind: String,
    pub title: String,
    /// Label and value pairs, as the box sent them.
    pub detail: Vec<(String, String)>,
    /// The box's own id for it.
    pub external_id: String,
    pub status: String,
    pub vm_id: String,
    pub vm_name: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Who settled it: `user` (the panel), `rule` (an Auto approve rule), `openclaw`, `firewall`.
    pub resolved_by: Option<String>,
    /// The Auto approve rule that decided it, or that asked about it.
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
}

/// `[[label, value]]` from what the box sent: pairs, or an object's entries.
fn pairs(detail: &str) -> Vec<(String, String)> {
    let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    match serde_json::from_str::<Value>(detail).unwrap_or(Value::Null) {
        Value::Array(a) => a
            .iter()
            .filter_map(|p| Some((text(p.get(0)?), text(p.get(1)?))))
            .collect(),
        Value::Object(o) => o.iter().map(|(k, v)| (k.clone(), text(v))).collect(),
        _ => Vec::new(),
    }
}

const SELECT: &str = "SELECT p.id, p.kind, p.title, p.detail, p.external_id, p.status, p.vm_id, a.name, p.expires_at,
                             p.created_at, p.updated_at, p.resolved_by, p.rule_id, p.rule_name
                      FROM permission_requests p LEFT JOIN agents a ON a.vm_id = p.vm_id";

fn row(r: &rusqlite::Row) -> rusqlite::Result<PermissionRequest> {
    Ok(PermissionRequest {
        id: r.get::<_, i64>(0)?.to_string(),
        kind: r.get(1)?,
        title: r.get(2)?,
        detail: pairs(&r.get::<_, String>(3)?),
        external_id: r.get(4)?,
        status: r.get(5)?,
        vm_id: r.get(6)?,
        vm_name: r.get(7)?,
        expires_at: r.get::<_, Option<i64>>(8)?.map(iso),
        created_at: iso(r.get(9)?),
        updated_at: iso(r.get(10)?),
        resolved_by: r.get(11)?,
        rule_id: r.get(12)?,
        rule_name: r.get(13)?,
    })
}

fn list(c: &Ctx) -> Result {
    let q: RequestsQuery = c.query()?;
    c.plane.expire_due()?;
    let status = q.status.map(|s| {
        serde_json::to_value(s)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
    });
    let db = c.db.lock();
    let mut stmt = db.prepare(&format!(
        "{SELECT} WHERE (?1 IS NULL OR p.status = ?1) ORDER BY p.created_at DESC, p.id DESC LIMIT 200"
    ))?;
    let rows: Vec<PermissionRequest> = stmt
        .query_map(params![status.flatten()], row)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Reply::ok(&rows))
}

fn resolve(c: &Ctx, b: Resolve) -> Result {
    let id: i64 = c.param("id").parse().map_err(|_| Reply::not_found("Request"))?;
    let decision = match b.decision {
        Decision::Approved => "approved",
        Decision::Denied => "denied",
    };
    if c.plane.resolve_permission(id, decision)?.is_none() {
        return Err(Reply::error(
            409,
            "No pending request with that id, or its time ran out",
        ));
    }
    let r = c.db.lock().query_row(&format!("{SELECT} WHERE p.id = ?1"), [id], row)?;
    Ok(Reply::ok(&r))
}
