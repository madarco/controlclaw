//! The first routes, from cc-local's first version: the rules as a whole list, the identity map,
//! permission answers, recent activity, a page link, and any "both" command by name. The panel's
//! own routes are the other files; these stay for the tests and scripts that use them.

use std::collections::HashMap;

use cc_contracts::commands::{ACTIONS, SERVICE_ACTIONS, Scope};
use http::Method;
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Ctx, Reply, Result, Route, new_id};
use crate::db::{Db, now_s};
use crate::plane::iso;

const TAG: &str = "firewall";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), Value, _, _>(
            "/api/egress-rules",
            TAG,
            "Every egress rule, in the form the firewall reads them",
            |c| async move { rules(&c) },
        ),
        Route::write::<RulesBody, Value, _, _>(
            Method::PUT,
            "/api/egress-rules",
            TAG,
            "Replace every egress rule",
            |c, b| async move {
                // The same checks as one rule at a time (`egress.rs`), so this route is no way around them.
                let rules = b
                    .rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        super::egress::settle_legacy(&c.db, r).map_err(|e| Reply::bad(format!("rule {i}: {e}")))
                    })
                    .collect::<Result<Vec<Value>>>()?;
                let n = replace_rules(&c.db, &rules)?.map_err(Reply::bad)?;
                (c.hooks.rules_changed)();
                Ok(Reply::ok(&json!({"ok": true, "rules": n})))
            },
        ),
        Route::get::<(), Value, _, _>("/api/agents", TAG, "The identity map", |c| async move { agents(&c) }),
        Route::write::<AgentsBody, Value, _, _>(
            Method::PUT,
            "/api/agents",
            TAG,
            "Replace the identity map",
            |c, b| async move { put_agents(&c, &b.agents) },
        ),
        Route::get::<(), Value, _, _>(
            "/api/permissions",
            TAG,
            "The last 100 permission requests",
            |c| async move { permissions(&c) },
        ),
        Route::write::<AnswerBody, Value, _, _>(
            Method::POST,
            "/api/permissions/answer",
            TAG,
            "Answer a permission request",
            |c, b| async move { answer(&c, b.id, &b.resolution) },
        ),
        Route::get::<ActivityQuery, Value, _, _>(
            "/api/activity/recent",
            TAG,
            "The latest activity rows",
            |c| async move { recent(&c) },
        ),
        Route::write::<OpenBody, OpenLink, _, _>(
            Method::POST,
            "/api/open",
            TAG,
            "A link that opens one of the firewall's own pages",
            |c, b| async move {
                (c.hooks.open_link)(&b.page)
                    .map(|url| Reply::ok(&OpenLink { url }))
                    .map_err(Reply::bad)
            },
        ),
        Route::write::<CommandBody, super::CommandAnswer, _, _>(
            Method::POST,
            "/api/commands",
            TAG,
            "Run a firewall command by name (actions scoped \"both\")",
            |c, b| async move { command(&c, &b.action, b.payload).await },
        ),
    ]
}

#[derive(Deserialize, JsonSchema)]
pub struct RulesBody {
    pub rules: Vec<Value>,
}

#[derive(Deserialize, JsonSchema)]
pub struct AgentsBody {
    pub agents: Vec<Value>,
}

#[derive(Deserialize, JsonSchema)]
pub struct AnswerBody {
    /// The request's own id, from `GET /api/permissions`.
    pub id: i64,
    /// `approved` or `denied`.
    pub resolution: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ActivityQuery {
    /// 1 to 1000; 100 when left out.
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct OpenBody {
    /// `firewall-logs`, `logins`, ...
    pub page: String,
}

#[derive(Serialize, JsonSchema)]
pub struct OpenLink {
    pub url: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct CommandBody {
    pub action: String,
    #[serde(default)]
    pub payload: Option<Value>,
}

fn rules(c: &Ctx) -> Result {
    let db = c.db.lock();
    let mut q = db.prepare(
        "SELECT id, name, match_domain, match_path, match_method, match_port, vm_id, effect, priority, enabled
         FROM egress_rules WHERE id <> ?1 ORDER BY priority, created_at, rowid",
    )?;
    // "Every other site" is not in the list, and the list's PUT leaves it as it is (`/api/egress/default`).
    let rows: Vec<Value> = q
        .query_map([crate::db::BLOCK_ALL_ID], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?,
                "match_domain": r.get::<_, String>(2)?, "match_path": r.get::<_, Option<String>>(3)?,
                "match_method": r.get::<_, Option<String>>(4)?, "match_port": r.get::<_, Option<i64>>(5)?,
                "vm_id": r.get::<_, Option<String>>(6)?, "effect": r.get::<_, String>(7)?,
                "priority": r.get::<_, i64>(8)?, "enabled": r.get::<_, bool>(9)?,
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Reply::ok(&json!({"rules": rows})))
}

fn agents(c: &Ctx) -> Result {
    let db = c.db.lock();
    let mut q = db.prepare(
        "SELECT vm_id, role, name, private_ip, hostname, agent_addr FROM agents WHERE role <> 'mitm' ORDER BY created_at, vm_id",
    )?;
    let rows: Vec<Value> = q
        .query_map([], |r| {
            Ok(
                json!({"vm_id": r.get::<_, String>(0)?, "role": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
                      "private_ip": r.get::<_, Option<String>>(3)?, "hostname": r.get::<_, Option<String>>(4)?,
                      "agent_addr": r.get::<_, Option<String>>(5)?}),
            )
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Reply::ok(&json!({"agents": rows})))
}

/// Replace the identity map, paired agents included (pairing adds to it one agent at a time). An
/// agent the list names by its `vm_id` keeps what pairing recorded and GET does not show: its key
/// (unless the list gives one), its pairing time, its unpair secret's hash and its WireGuard key,
/// and where its vm-agent listens (unless the list gives `agent_addr`, or moves it to another
/// `private_ip`: then the vm-agent is at the new address, port 3100).
fn put_agents(c: &Ctx, list: &[Value]) -> Result {
    let mut db = c.db.lock();
    let tx = db.transaction()?;
    type Kept = (
        Option<String>,
        Option<i64>,
        Option<String>,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let kept: HashMap<String, Kept> = {
        let mut q = tx.prepare(
            "SELECT vm_id, public_key, paired_at, unpair_sha256, created_at, wg_public_key, agent_addr, private_ip FROM agents WHERE role <> 'mitm'",
        )?;
        q.query_map([], |r| {
            Ok((
                r.get(0)?,
                (
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    tx.execute("DELETE FROM agents WHERE role <> 'mitm'", [])?;
    for a in list {
        let s = |k: &str| a.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
        let (Some(id), Some(ip)) = (s("vm_id"), s("private_ip")) else {
            return Err(Reply::bad("each agent needs vm_id and private_ip"));
        };
        let role = s("role").unwrap_or("openclaw");
        if !matches!(role, "openclaw" | "gbrain") {
            return Err(Reply::bad("role: openclaw or gbrain"));
        }
        let (key, paired_at, unpair, created_at, wg, addr, was_at) =
            kept.get(id)
                .cloned()
                .unwrap_or((None, None, None, now_s(), None, None, None));
        // Its tunnel address is its peer's: moved, its calls would go outside the tunnel.
        if wg.is_some() && was_at.as_deref() != Some(ip) {
            return Err(Reply::bad(format!(
                "{id} is a WireGuard agent: its address is its tunnel's ({}). Pair it again to move it.",
                was_at.as_deref().unwrap_or("?")
            )));
        }
        let addr = match s("agent_addr") {
            // The admin's own list: an `ip:port` where a vm-agent can be, not one of the firewall's
            // own services (loopback) or the clouds' metadata service (link-local).
            Some(a) => Some(
                a.parse::<std::net::SocketAddrV4>()
                    .ok()
                    .filter(|a| {
                        let ip = a.ip();
                        a.port() != 0
                            && !(ip.is_loopback()
                                || ip.is_link_local()
                                || ip.is_unspecified()
                                || ip.is_multicast()
                                || ip.is_broadcast())
                    })
                    .ok_or_else(|| Reply::bad("agent_addr: an IPv4 address and port where a vm-agent can be"))?
                    .to_string(),
            ),
            None if was_at.as_deref() == Some(ip) => addr,
            None => None,
        };
        tx.execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, hostname, public_key, created_at, paired_at, unpair_sha256, wg_public_key, agent_addr)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                role,
                s("name").unwrap_or(id),
                ip,
                s("hostname"),
                s("public_key").map(str::to_string).or(key),
                created_at,
                paired_at,
                unpair,
                wg,
                addr
            ],
        )?;
    }
    tx.commit()?;
    Ok(Reply::ok(&json!({"ok": true, "agents": list.len()})))
}

fn permissions(c: &Ctx) -> Result {
    let db = c.db.lock();
    let mut q = db.prepare(
        "SELECT external_id, kind, title, detail, status, agent_vm_ids, created_at, expires_at, id, vm_id FROM permission_requests
         ORDER BY created_at DESC, id DESC LIMIT 100",
    )?;
    let rows: Vec<Value> = q
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(8)?, "vm_id": r.get::<_, String>(9)?,
                "permission_id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "title": r.get::<_, String>(2)?,
                "detail": serde_json::from_str::<Value>(&r.get::<_, String>(3)?).unwrap_or(Value::Null),
                "status": r.get::<_, String>(4)?,
                "agents": serde_json::from_str::<Value>(&r.get::<_, String>(5)?).unwrap_or(Value::Null),
                "created_at": iso(r.get(6)?), "expires_at": r.get::<_, Option<i64>>(7)?.map(iso),
            }))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Reply::ok(&json!({"requests": rows})))
}

/// `id` is the request's own (from `GET /api/permissions`): a box's `permission_id` is only
/// unique to that box.
fn answer(c: &Ctx, id: i64, resolution: &str) -> Result {
    if !matches!(resolution, "approved" | "denied") {
        return Err(Reply::bad("resolution: approved or denied"));
    }
    match c.plane.resolve_permission(id, resolution)? {
        Some(s) => Ok(Reply::ok(&json!({"ok": true, "status": s}))),
        None => Err(Reply::error(
            409,
            "No pending request with that id, or its time ran out",
        )),
    }
}

fn recent(c: &Ctx) -> Result {
    let q: ActivityQuery = c.query()?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let db = c.db.lock();
    let mut q = db.prepare(
        "SELECT vm_id, source, status, occurred_at, summary FROM activity_raw ORDER BY occurred_at DESC, id DESC LIMIT ?1",
    )?;
    let rows: Vec<Value> = q
        .query_map([limit], |r| {
            Ok(
                json!({"vm_id": r.get::<_, Option<String>>(0)?, "source": r.get::<_, String>(1)?,
                      "status": r.get::<_, String>(2)?, "at": iso(r.get(3)?), "summary": r.get::<_, String>(4)?}),
            )
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Reply::ok(&json!({"activity": rows})))
}

/// A config change, straight to the firewall's handler (no queue, no beat).
async fn command(c: &Ctx, action: &str, payload: Option<Value>) -> Result {
    let mut payload = payload.unwrap_or_else(|| json!({}));
    if !payload.is_object() {
        return Err(Reply::bad("payload: an object"));
    }
    // The control channel runs these itself with systemctl; the service unit is the install's.
    if SERVICE_ACTIONS.contains(&action) {
        return Err(Reply::error(
            403,
            format!("{action} is the service's own: use systemctl on the firewall"),
        ));
    }
    if !ACTIONS.iter().any(|a| a.action == action && a.scope == Scope::Both) {
        return Err(Reply::error(
            403,
            format!("{action} is not an action of a standalone firewall"),
        ));
    }
    // The panel keeps a record of these (the key's hint and placeholder, the bot list) and runs them
    // one at a time; sent here they would apply past both, and the record would go wrong.
    let own = [
        ("llm.", "/api/llm/keys"),
        ("search.", "/api/search/key"),
        ("channels.", "/api/channels"),
    ];
    if let Some((_, route)) = own
        .iter()
        .find(|(ns, _)| action.starts_with(ns) && !action.ends_with(".read"))
    {
        return Err(Reply::error(
            403,
            format!("{action} is not run here: use {route}, which keeps the panel's record of it"),
        ));
    }
    // The stop is typed, here as on its own route.
    if action == "kill.engage" && payload.get("confirm").and_then(Value::as_str) != Some("STOP") {
        return Err(Reply::bad("kill.engage: send confirm: \"STOP\" with it"));
    }
    // An AgentMail inbox goes to the address this firewall paired the agent at, here as on its route.
    if let (Some(a), Value::Object(p)) = (action.strip_prefix("agentmail."), &mut payload) {
        super::accounts::agentmail_address(c, a, p)?;
    }
    cc_contracts::commands::check(action, &payload).map_err(|e| Reply::bad(e.to_string()))?;
    let out = c.run(action, payload).await?;
    // As before: the outcome as it is, whether the firewall did it or not.
    Ok(Reply::ok(&out))
}

/// Replace the egress rules with `list` (each as the API takes it): the count, or why not.
pub fn replace_rules(db: &Db, list: &[Value]) -> rusqlite::Result<std::result::Result<usize, String>> {
    let mut c = db.lock();
    let tx = c.transaction()?;
    // Every rule but "Every other site", which is set on its own (`/api/egress/default`).
    tx.execute("DELETE FROM egress_rules WHERE id <> ?1", [crate::db::BLOCK_ALL_ID])?;
    let now = now_s();
    for (i, r) in list.iter().enumerate() {
        let s = |k: &str| r.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
        let Some(domain) = s("match_domain") else {
            return Ok(Err(format!("rule {i}: match_domain is required")));
        };
        let effect = s("effect").unwrap_or("allow");
        if !matches!(effect, "allow" | "block" | "require_permission" | "tunnel") {
            return Ok(Err(format!(
                "rule {i}: effect is allow, block, require_permission or tunnel"
            )));
        }
        let id = s("id").map_or_else(|| new_id("r"), str::to_string);
        if id == crate::db::BLOCK_ALL_ID {
            return Ok(Err(format!(
                "rule {i}: {id} is \"Every other site\": set it with PUT /api/egress/default"
            )));
        }
        // Those are the firewall's own (`plane::managed_rules`), never a row.
        if id.starts_with(cc_contracts::managed::ID_PREFIX) {
            return Ok(Err(format!(
                "rule {i}: ids starting with {} are the firewall's own",
                cc_contracts::managed::ID_PREFIX
            )));
        }
        tx.execute(
            "INSERT INTO egress_rules (id, name, match_domain, match_path, match_method, match_port, vm_id, effect,
                                       priority, enabled, ai_review, ai_policy, created_at, updated_at, exit, exit_country)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, ?14, ?15)",
            params![
                id,
                s("name").unwrap_or(domain),
                domain,
                s("match_path"),
                s("match_method"),
                r.get("match_port").and_then(Value::as_i64),
                s("vm_id"),
                effect,
                r.get("priority").and_then(Value::as_i64).unwrap_or(1000),
                r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                r.get("ai_review").and_then(Value::as_bool).unwrap_or(false),
                s("ai_policy"),
                now + i as i64,
                (s("exit") == Some("residential")).then_some("residential"),
                s("exit_country").map(str::to_ascii_uppercase),
            ],
        )?;
    }
    tx.commit()?;
    Ok(Ok(list.len()))
}
