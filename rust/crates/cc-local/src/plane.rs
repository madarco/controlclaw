//! The contract as one call: a box (by its vm id) sends a method, an endpoint path, a query and a
//! body, and gets a status and a JSON body back, as from `/api/vm-agent/*`. [`ControlPlane`] is that
//! call. The SaaS console answers it over HTTP (the firewall agent's `StoreClient` for `http`
//! URLs); [`LocalControlPlane`] answers it in process, from SQLite, for a standalone firewall
//! (`local:` URLs), and the conformance facade (`facade.rs`) serves it over HTTP to test both
//! against the same cases.
//!
//! Only the endpoints scoped "both" are served here (`cc_contracts::control_plane::ENDPOINTS`).
//! There is no command queue: `/firewall` takes a beat and its results and never hands out a
//! command, because config changes call the firewall's handlers directly (`admin.rs`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use cc_contracts::commands::Scope;
use cc_contracts::control_plane::ENDPOINTS;
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};

use crate::db::{Db, now_s};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One request to a control plane, after the caller was told apart by its token.
#[derive(Debug, Clone, Default)]
pub struct Call {
    pub method: String,
    /// `/api/vm-agent/<endpoint>`.
    pub path: String,
    /// Without the `?`.
    pub query: String,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub status: u16,
    pub body: Value,
}

impl Answer {
    pub fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            body: json!({"error": message}),
        }
    }
}

pub trait ControlPlane: Send + Sync {
    /// `caller` is the vm id the box token named. A caller the control plane does not know gets
    /// 401, as a token that does not verify does.
    fn call<'a>(&'a self, caller: &'a str, call: Call) -> BoxFuture<'a, Answer>;
}

/// How long a permission request waits when the box names no end (the SaaS: 30 minutes).
const PERMISSION_TTL_S: i64 = 30 * 60;
const TITLE_MAX: usize = 200;
const ACTIVITY_MAX_RECORDS: usize = 500;

/// Kinds a box may raise, by its role (the SaaS route's `KINDS_BY_ROLE`).
fn kinds_for(role: &str) -> &'static [&'static str] {
    match role {
        "mitm" => &["access", "email_recipient", "app_call"],
        "openclaw" => &["exec", "plugin", "system", "meeting_request"],
        _ => &[],
    }
}

/// Activity sources a box may ship, by its role (`SOURCES_BY_ROLE`).
fn sources_for(role: &str) -> &'static [&'static str] {
    match role {
        "mitm" => &[
            "egress",
            "ai_review",
            "connector_run",
            "connector_call",
            "ssh_login",
            "webhook",
            "content_rule",
            "email_held",
            "teamchat_stats",
        ],
        "openclaw" => &["tool_action", "agent_run", "ssh_login"],
        "gbrain" => &["brain_call", "brain_cycle", "ssh_login"],
        _ => &[],
    }
}

pub use crate::db::{BLOCK_ALL_ID, BLOCK_ALL_NAME, BLOCK_ALL_PRIORITY};

const EGRESS_EFFECTS: &[&str] = &["allow", "block", "require_permission", "tunnel", "drop", "residential"];

pub struct LocalControlPlane {
    pub db: Arc<Db>,
}

impl LocalControlPlane {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// This firewall itself, as the box every in-process call comes from.
    pub fn register_self(&self, vm_id: &str) -> rusqlite::Result<()> {
        self.db.lock().execute(
            "INSERT INTO agents (vm_id, role, name, created_at) VALUES (?1, 'mitm', 'firewall', ?2)
             ON CONFLICT (vm_id) DO UPDATE SET role = 'mitm'",
            params![vm_id, now_s()],
        )?;
        Ok(())
    }

    /// The enabled rules are only the one a new database starts with: everything is blocked.
    pub fn only_block_all(&self) -> rusqlite::Result<bool> {
        let ids: Vec<String> = {
            let c = self.db.lock();
            let mut q = c.prepare("SELECT id FROM egress_rules WHERE enabled = 1 LIMIT 2")?;
            q.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        Ok(ids == [BLOCK_ALL_ID])
    }

    fn role(&self, vm_id: &str) -> Option<String> {
        self.db
            .lock()
            .query_row("SELECT role FROM agents WHERE vm_id = ?1", [vm_id], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    fn handle(&self, caller: &str, call: &Call) -> Answer {
        let Some(role) = self.role(caller) else {
            return Answer::error(401, "Unauthorized");
        };
        let endpoint = ENDPOINTS.iter().find(|e| e.path == call.path);
        match endpoint {
            Some(e) if e.scope == Scope::Both && e.methods.contains(&call.method.as_str()) => {}
            Some(e) if e.scope == Scope::Both => return Answer::error(405, "Method not allowed"),
            Some(_) => return Answer::error(404, "not served by a standalone firewall"),
            None => return Answer::error(404, "Not found"),
        }
        let r = match call.path.trim_start_matches("/api/vm-agent") {
            "/firewall" => self.firewall(&role, call),
            "/egress-rules" => self.egress_rules(),
            "/identities" => self.identities(&role),
            "/permission" => self.expire_due().and_then(|()| {
                if call.method == "GET" {
                    self.permission_get(caller, &role, call)
                } else {
                    self.permission_post(caller, &role, call)
                }
            }),
            "/activity" => self.activity(caller, &role, call),
            "/ca" if call.method == "GET" => self.ca_get(),
            "/ca" => self.ca_post(&role, call),
            _ => return Answer::error(404, "Not found"),
        };
        r.unwrap_or_else(|e| {
            tracing::error!("[cc-local] {} {}: {e}", call.method, call.path);
            Answer::error(500, "Failed")
        })
    }

    // ---- /firewall ----

    fn firewall(&self, role: &str, call: &Call) -> rusqlite::Result<Answer> {
        if role != "mitm" {
            return Ok(Answer::error(403, "only a mitm box may report firewall state"));
        }
        let proxy = call.body.as_ref().and_then(|b| b.get("proxy")).and_then(Value::as_str);
        if !matches!(proxy, Some("active" | "inactive" | "failed")) {
            return Ok(Answer::error(400, "Invalid body"));
        }
        if let Some(b) = &call.body {
            // The last beat, for the panel: what the firewall says about itself.
            self.db
                .set_setting("last_beat", &json!({"at": now_s(), "beat": b}).to_string())?;
        }
        Ok(Answer::ok(json!({"command": null})))
    }

    // ---- /egress-rules ----

    fn egress_rules(&self) -> rusqlite::Result<Answer> {
        let c = self.db.lock();
        let mut q = c.prepare(
            "SELECT id, name, match_domain, match_path, match_method, match_port, vm_id, effect, exit,
                    exit_country, priority, ai_review, ai_policy
             FROM egress_rules WHERE enabled = 1 ORDER BY priority ASC, created_at ASC, rowid ASC",
        )?;
        let rules: Vec<Value> = q
            .query_map([], |r| {
                let mut m = Map::new();
                m.insert("id".into(), json!(r.get::<_, String>(0)?));
                m.insert("name".into(), json!(r.get::<_, String>(1)?));
                m.insert("match_domain".into(), json!(r.get::<_, String>(2)?));
                let opt = |m: &mut Map<String, Value>, k: &str, v: Option<Value>| {
                    if let Some(v) = v {
                        m.insert(k.into(), v);
                    }
                };
                opt(&mut m, "match_path", r.get::<_, Option<String>>(3)?.map(Value::from));
                opt(&mut m, "match_method", r.get::<_, Option<String>>(4)?.map(Value::from));
                opt(&mut m, "match_port", r.get::<_, Option<i64>>(5)?.map(Value::from));
                opt(&mut m, "vm_id", r.get::<_, Option<String>>(6)?.map(Value::from));
                let effect: String = r.get(7)?;
                m.insert("effect".into(), json!(effect));
                let exit: Option<String> = r.get(8)?;
                if exit.as_deref() == Some("residential") {
                    m.insert("exit".into(), json!("residential"));
                    opt(&mut m, "exit_country", r.get::<_, Option<String>>(9)?.map(Value::from));
                }
                m.insert("priority".into(), json!(r.get::<_, i64>(10)?));
                // As the SaaS: AI review on an allow rule, or on an ask rule that has a policy.
                let (review, policy): (bool, Option<String>) = (r.get(11)?, r.get(12)?);
                if review && (effect == "allow" || (effect == "require_permission" && policy.is_some())) {
                    m.insert("ai_review".into(), json!(true));
                    opt(&mut m, "ai_policy", policy.map(Value::from));
                }
                Ok(Value::Object(m))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let ai: Value = c
            .query_row("SELECT settings FROM ai_settings WHERE id = 1", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null);
        Ok(Answer::ok(json!({"rules": rules, "ai": ai})))
    }

    // ---- /identities ----

    fn identities(&self, role: &str) -> rusqlite::Result<Answer> {
        if role != "mitm" {
            return Ok(Answer::error(403, "only a mitm box may read identities"));
        }
        let c = self.db.lock();
        let mut q = c.prepare(
            "SELECT vm_id, private_ip, name, hostname, access_hostname, status, role, agent_addr, wg_public_key IS NOT NULL FROM agents
             WHERE role IN ('openclaw', 'gbrain') AND private_ip IS NOT NULL AND private_ip <> ''
             ORDER BY created_at, vm_id",
        )?;
        let rows: Vec<Value> = q
            .query_map([], |r| {
                let ip = r.get::<_, String>(1)?;
                // Where the firewall calls its vm-agent: from pairing; over the tunnel, its tunnel
                // address. Else nowhere: a plain call across a network would carry the request in
                // clear (an agent paired before pairing said where connects again).
                let tunnel: bool = r.get(8)?;
                let addr = r
                    .get::<_, Option<String>>(7)?
                    .or_else(|| tunnel.then(|| format!("{ip}:{}", crate::pairing::AGENT_PORT)));
                Ok(json!({
                    "vm_id": r.get::<_, String>(0)?,
                    "private_ip": ip,
                    "name": r.get::<_, String>(2)?,
                    "hostname": r.get::<_, Option<String>>(3)?,
                    "access_hostname": r.get::<_, Option<String>>(4)?,
                    "status": r.get::<_, String>(5)?,
                    "role": r.get::<_, String>(6)?,
                    "agent_addr": addr,
                }))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Answer::ok(json!({"identities": rows})))
    }

    // ---- /permission ----

    /// Requests this box may read: its own, and for an agent the firewall's asks that name it (or
    /// name nobody).
    fn readable(&self, caller: &str, role: &str, agent_vm_ids: &str, owner: &str) -> bool {
        if owner == caller {
            return true;
        }
        if role != "openclaw" || self.role(owner).as_deref() != Some("mitm") {
            return false;
        }
        let ids: Vec<String> = serde_json::from_str(agent_vm_ids).unwrap_or_default();
        ids.is_empty() || ids.iter().any(|i| i == caller)
    }

    fn permission_get(&self, caller: &str, role: &str, call: &Call) -> rusqlite::Result<Answer> {
        let id = url::form_urlencoded::parse(call.query.as_bytes())
            .find(|(k, _)| k == "permission_id")
            .map(|(_, v)| v.into_owned());
        let c = self.db.lock();
        let Some(id) = id.filter(|i| !i.is_empty()) else {
            let mut q = c.prepare(
                "SELECT external_id, title, created_at, agent_vm_ids, vm_id FROM permission_requests
                 WHERE status = 'pending' AND (expires_at IS NULL OR expires_at > ?1)
                 ORDER BY created_at DESC, id DESC LIMIT 50",
            )?;
            let rows: Vec<(String, String, i64, String, String)> = q
                .query_map([now_s()], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            drop(q);
            drop(c);
            let pending: Vec<Value> = rows
                .into_iter()
                .filter(|(_, _, _, ids, owner)| self.readable(caller, role, ids, owner))
                .map(|(id, title, at, _, _)| json!({"permission_id": id, "summary": title, "created_at": iso(at)}))
                .collect();
            return Ok(Answer::ok(json!({"pending": pending})));
        };
        let rows: Vec<(String, Option<i64>, String, String, String)> = {
            let mut q = c.prepare(
                "SELECT status, expires_at, kind, agent_vm_ids, vm_id FROM permission_requests
                 WHERE external_id = ?1 ORDER BY id",
            )?;
            q.query_map([&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        drop(c);
        let row = rows
            .into_iter()
            .find(|(_, _, _, ids, owner)| self.readable(caller, role, ids, owner));
        Ok(Answer::ok(match row {
            Some((status, expires, kind, _, _)) => json!({
                "status": status,
                "expiresAt": expires.map(iso),
                "kind": kind,
                "alwaysAllowed": false,
                "validUntil": null,
            }),
            None => {
                json!({"status": "unknown", "expiresAt": null, "kind": null, "alwaysAllowed": false, "validUntil": null})
            }
        }))
    }

    fn permission_post(&self, caller: &str, role: &str, call: &Call) -> rusqlite::Result<Answer> {
        let Some(Value::Object(b)) = &call.body else {
            return Ok(Answer::error(400, "Invalid JSON"));
        };
        let text = |k: &str| b.get(k).and_then(Value::as_str).map(str::to_string);
        let Some(pid) = text("permission_id").filter(|p| !p.is_empty() && p.len() <= 128) else {
            return Ok(Answer::error(400, "Invalid body"));
        };
        if b.contains_key("resolution") {
            let resolution = text("resolution").unwrap_or_default();
            if !matches!(resolution.as_str(), "approved" | "denied" | "expired" | "revoked") {
                return Ok(Answer::error(400, "Invalid body"));
            }
            let c = self.db.lock();
            let row: Option<(i64, String, String)> = c
                .query_row(
                    "SELECT id, status, kind FROM permission_requests WHERE vm_id = ?1 AND external_id = ?2",
                    params![caller, pid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((id, status, kind)) = row else {
                return Ok(Answer {
                    status: 404,
                    body: json!({"status": "unknown"}),
                });
            };
            if resolution == "revoked" {
                if kind != "email_recipient" {
                    return Ok(Answer::error(403, "only email approvals are revoked"));
                }
                if status == "approved" {
                    c.execute(
                        "UPDATE permission_requests SET status = 'revoked', resolved_by = 'firewall' WHERE id = ?1",
                        [id],
                    )?;
                    return Ok(Answer::ok(json!({"ok": true, "status": "revoked"})));
                }
                return Ok(Answer::ok(json!({"ok": true, "status": status})));
            }
            if status != "pending" {
                return Ok(Answer::ok(json!({"ok": true, "status": status})));
            }
            c.execute(
                "UPDATE permission_requests SET status = ?1, resolved_by = 'openclaw', updated_at = ?2 WHERE id = ?3",
                params![resolution, now_s(), id],
            )?;
            return Ok(Answer::ok(json!({"ok": true, "status": resolution})));
        }
        let kind = text("kind").unwrap_or_else(|| "access".into());
        if !matches!(
            kind.as_str(),
            "access" | "email_recipient" | "app_call" | "exec" | "plugin" | "system" | "meeting_request"
        ) {
            return Ok(Answer::error(400, "Invalid body"));
        }
        if !kinds_for(role).contains(&kind.as_str()) {
            return Ok(Answer::error(
                403,
                &format!("a {role} box may not raise {kind} requests"),
            ));
        }
        let egress = matches!(kind.as_str(), "access" | "email_recipient" | "app_call");
        let raw = if egress {
            text("summary").unwrap_or_else(|| {
                format!(
                    "{} {}",
                    text("method").unwrap_or_else(|| "GET".into()),
                    text("host").unwrap_or_default()
                )
            })
        } else {
            text("title").unwrap_or_default()
        };
        let raw = raw.trim().to_string();
        if raw.is_empty() {
            return Ok(Answer::error(400, "title required"));
        }
        let title = if raw.chars().count() > TITLE_MAX {
            format!("{}…", raw.chars().take(TITLE_MAX - 1).collect::<String>())
        } else {
            raw
        };
        let detail = if egress {
            json!([
                ["host", text("host").unwrap_or_default()],
                ["method", text("method").unwrap_or_default()],
                ["path", text("path").unwrap_or_default()]
            ])
        } else {
            b.get("detail").cloned().unwrap_or_else(|| json!([]))
        };
        let now = now_s();
        let expires = text("expires_at")
            .and_then(|s| parse_iso(&s))
            .unwrap_or(now + PERMISSION_TTL_S);
        let c = self.db.lock();
        let existing: Option<(i64, String)> = c
            .query_row(
                "SELECT id, status FROM permission_requests WHERE vm_id = ?1 AND external_id = ?2",
                params![caller, pid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (id, status, deduped) = match existing {
            Some((id, status)) => (id, status, true),
            None => {
                c.execute(
                    "INSERT INTO permission_requests (vm_id, external_id, kind, title, detail, expires_at, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    params![caller, pid, kind, title, detail.to_string(), expires, now],
                )?;
                (c.last_insert_rowid(), "pending".to_string(), false)
            }
        };
        // The agent the ask is for, when it is one of ours: added once.
        if egress && let Some(agent) = text("agent_vm_id") {
            let is_agent: bool = c
                .query_row(
                    "SELECT 1 FROM agents WHERE vm_id = ?1 AND role = 'openclaw'",
                    [&agent],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if is_agent {
                let ids: String = c.query_row(
                    "SELECT agent_vm_ids FROM permission_requests WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )?;
                let mut list: Vec<String> = serde_json::from_str(&ids).unwrap_or_default();
                if !list.contains(&agent) {
                    list.push(agent);
                    c.execute(
                        "UPDATE permission_requests SET agent_vm_ids = ?1 WHERE id = ?2",
                        params![json!(list).to_string(), id],
                    )?;
                }
            }
        }
        let mut out = json!({"ok": true, "status": status});
        if deduped {
            out["deduped"] = json!(true);
        }
        Ok(Answer::ok(out))
    }

    /// A person's answer, from the panel, to one request (its row id). `None` for a request that
    /// is not pending, or whose time ran out: an expired ask is not approved after the fact.
    pub fn resolve_permission(&self, id: i64, resolution: &str) -> rusqlite::Result<Option<String>> {
        let c = self.db.lock();
        let n = c.execute(
            "UPDATE permission_requests SET status = ?1, resolved_by = 'user', updated_at = ?2
             WHERE id = ?3 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
            params![resolution, now_s(), id],
        )?;
        Ok((n > 0).then(|| resolution.to_string()))
    }

    /// The row of the oldest pending request a box raised with this id (the conformance hook, which
    /// names requests as the box does).
    pub fn pending_row(&self, external_id: &str) -> rusqlite::Result<Option<i64>> {
        self.db
            .lock()
            .query_row(
                "SELECT id FROM permission_requests WHERE external_id = ?1 AND status = 'pending' ORDER BY id LIMIT 1",
                [external_id],
                |r| r.get(0),
            )
            .optional()
    }

    /// Requests whose time ran out read as expired at once, not at the next retention pass.
    pub fn expire_due(&self) -> rusqlite::Result<()> {
        self.db.lock().execute(
            "UPDATE permission_requests SET status = 'expired', updated_at = ?1
             WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?1",
            [now_s()],
        )?;
        Ok(())
    }

    // ---- /activity ----

    fn activity(&self, caller: &str, role: &str, call: &Call) -> rusqlite::Result<Answer> {
        let records = match call.body.as_ref().and_then(|b| b.get("records")) {
            Some(Value::Array(a)) if !a.is_empty() && a.len() <= ACTIVITY_MAX_RECORDS => a.clone(),
            Some(Value::Array(a)) if a.len() > ACTIVITY_MAX_RECORDS => {
                return Ok(Answer::error(413, "batch too large"));
            }
            _ => return Ok(Answer::error(400, "Invalid records")),
        };
        let source_of = |r: &Value| r.get("source").and_then(Value::as_str).unwrap_or("egress").to_string();
        if let Some(foreign) = records
            .iter()
            .map(source_of)
            .find(|s| !sources_for(role).contains(&s.as_str()))
        {
            return Ok(Answer::error(
                403,
                &format!("a {role} box may not ship {foreign} activity"),
            ));
        }
        let mut c = self.db.lock();
        let tx = c.transaction()?;
        let (mut accepted, mut duplicates, mut skipped) = (0u64, 0u64, 0u64);
        for r in &records {
            let source = source_of(r);
            let Some(row) = activity_row(caller, &source, r) else {
                skipped += 1;
                continue;
            };
            // The firewall reports about its agents (traffic, reviews, app calls) and names them; any
            // other box's records are about itself, whatever they say.
            let named = r.get("vm_id").and_then(Value::as_str).map(str::to_string);
            let vm = match (role, source.as_str()) {
                ("mitm", "egress") => named,
                ("mitm", _) => named.or_else(|| Some(caller.to_string())),
                _ => Some(caller.to_string()),
            };
            let n = tx.execute(
                "INSERT INTO activity_raw (vm_id, source, status, dedupe_key, occurred_at, summary, record, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT (dedupe_key) DO NOTHING",
                params![
                    vm,
                    source,
                    row.status,
                    row.dedupe,
                    row.at,
                    row.summary,
                    r.to_string(),
                    now_s()
                ],
            )?;
            if n == 0 {
                duplicates += 1;
                continue;
            }
            accepted += 1;
            tx.execute(
                "INSERT INTO activity_hourly (hour, vm_id, source, status, count) VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT (hour, vm_id, source, status) DO UPDATE SET count = count + 1",
                params![
                    row.at - row.at.rem_euclid(3600),
                    vm.unwrap_or_default(),
                    source,
                    row.status
                ],
            )?;
        }
        tx.commit()?;
        if accepted == 0 && duplicates == 0 {
            return Ok(Answer {
                status: 400,
                body: json!({"error": "Invalid records", "skipped": skipped}),
            });
        }
        let mut out = json!({"accepted": accepted, "duplicates": duplicates});
        if skipped > 0 {
            out["skipped"] = json!(skipped);
        }
        Ok(Answer::ok(out))
    }

    // ---- /ca ----

    fn ca_post(&self, role: &str, call: &Call) -> rusqlite::Result<Answer> {
        if role != "mitm" {
            return Ok(Answer::error(403, "only a mitm box may publish a CA"));
        }
        let b = call.body.clone().unwrap_or(Value::Null);
        let cert = b.get("ca_cert").and_then(Value::as_str).unwrap_or_default();
        if !cert.contains("BEGIN CERTIFICATE") {
            return Ok(Answer::error(400, "ca_cert (PEM) required"));
        }
        let Some(sig) = b.get("ca_sig").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
            return Ok(Answer::error(400, "ca_sig (base64) required"));
        };
        self.db
            .set_setting("ca", &json!({"ca_cert": cert, "ca_sig": sig}).to_string())?;
        Ok(Answer::ok(json!({"ok": true})))
    }

    fn ca_get(&self) -> rusqlite::Result<Answer> {
        let ca: Value = self
            .db
            .setting("ca")
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null);
        let fw: Option<(Option<String>, Option<String>)> = self
            .db
            .lock()
            .query_row(
                "SELECT public_key, private_ip FROM agents WHERE role = 'mitm' ORDER BY created_at LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (pub_key, ip) = fw.unwrap_or_default();
        Ok(Answer::ok(json!({
            "caCert": ca.get("ca_cert"),
            "caSig": ca.get("ca_sig"),
            "pubKey": pub_key,
            "privateIp": ip,
            "doctor_ssh_pub": null,
            "doctor_ssh_sig": null,
        })))
    }
}

impl ControlPlane for LocalControlPlane {
    fn call<'a>(&'a self, caller: &'a str, call: Call) -> BoxFuture<'a, Answer> {
        Box::pin(async move { self.handle(caller, &call) })
    }
}

struct ActivityRow {
    dedupe: String,
    at: i64,
    status: String,
    summary: String,
}

/// Activity older than this is pruned anyway; a box's clock that is behind cannot file it earlier.
const ACTIVITY_RETENTION_S: i64 = crate::retention::RAW_DAYS * 86_400;
/// How far ahead of this clock a box's record may be.
const FUTURE_SKEW_S: i64 = 5 * 60;

/// Box clocks drift: keep a row inside the retention window and never in the future (the SaaS's
/// `clampOccurredAt`).
fn clamp_ts(ts: f64, now: i64) -> i64 {
    (ts as i64).clamp(now - ACTIVITY_RETENTION_S, now + FUTURE_SKEW_S)
}

/// The SaaS's duplicate key for a record of `source` (activity/route.ts), or `None` when the record
/// lacks the id its source needs. Kept per shipping box here: one database holds every box's.
fn saas_key(source: &str, r: &Value) -> Option<String> {
    let s = |k: &str| r.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
    Some(match source {
        "egress" => format!("egress:{}", s("flow_id").filter(|f| f.len() <= 64)?),
        "tool_action" => format!("tool:{}", s("tool_call_id")?),
        "agent_run" => format!("run:{}", s("run_id")?),
        "ai_review" => format!("ai:{}", s("finding_id")?),
        "connector_run" => format!("connector:{}", s("run_id")?),
        "connector_call" => match s("run_id") {
            Some(run) => format!("connector:{run}"),
            None => format!("connector-call:{}", s("id")?),
        },
        "brain_call" => format!("brain:{}", s("call_id")?),
        "brain_cycle" => format!("brain-cycle:{}", s("cycle_id")?),
        "ssh_login" => format!("ssh:{}", s("login_id")?),
        "webhook" => format!("webhook:{}", s("delivery_id")?),
        "content_rule" => format!("content:{}", s("id")?),
        "email_held" => format!("email-held:{}", s("id")?),
        // No key on the SaaS side (a count, not a row): the record itself.
        other => format!(
            "{other}:{}",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(r.to_string().as_bytes()))
        ),
    })
}

/// What a record is filed under, or `None` for one that is not a record of its source.
fn activity_row(caller: &str, source: &str, r: &Value) -> Option<ActivityRow> {
    let s = |k: &str| r.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
    let now = now_s();
    let key = saas_key(source, r)?;
    let dedupe = format!("{caller}:{key}");
    let ts = r.get("ts").and_then(Value::as_f64);
    if source == "egress" {
        let effect = s("effect").filter(|e| EGRESS_EFFECTS.contains(e))?;
        let host = s("host").unwrap_or_default();
        return Some(ActivityRow {
            dedupe,
            at: clamp_ts(ts?, now),
            status: effect.to_string(),
            summary: format!("{} {host}{}", s("method").unwrap_or("GET"), s("path").unwrap_or("")),
        });
    }
    // An AI review finding is counted by how serious it is, as the SaaS does.
    let status = if source == "ai_review" {
        s("severity")
    } else {
        s("status").or_else(|| s("verdict"))
    };
    Some(ActivityRow {
        dedupe,
        at: ts.map_or(now, |t| clamp_ts(t, now)),
        status: status.unwrap_or("recorded").to_string(),
        summary: s("summary").or_else(|| s("title")).unwrap_or(source).to_string(),
    })
}

pub fn iso(s: i64) -> String {
    // Days from the civil calendar (Howard Hinnant's algorithm), so no date crate is needed.
    let (days, rem) = (s.div_euclid(86_400), s.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` to epoch seconds.
pub fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests;
