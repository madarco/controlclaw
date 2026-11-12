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
const ACTIVITY_MAX_RECORDS: usize = 500;

/// Kinds a box may raise, by its role (the SaaS route's `KINDS_BY_ROLE`).
fn kinds_for(role: &str) -> &'static [&'static str] {
    match role {
        "mitm" => &["access", "email_recipient", "app_call"],
        "openclaw" => &["exec", "plugin", "system", "meeting_request"],
        _ => &[],
    }
}

/// What the firewall's Auto approve rules said about a raise it sends: `decided` (Allow or Block,
/// answered on the firewall) or `checked` (Ask: a person answers). Only a firewall sends either.
#[derive(Debug, Clone, PartialEq)]
struct Verdict {
    /// `allow`, `block` or `ask`.
    effect: String,
    rule_id: Option<String>,
    rule_name: Option<String>,
}

impl Verdict {
    /// None when the raise carries neither; Err for one that does not read, or both.
    fn of(b: &Map<String, Value>) -> Result<Option<Self>, ()> {
        let rule = |o: &Map<String, Value>, k: &str| -> Result<Option<String>, ()> {
            match o.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() && s.chars().count() <= 200 => Ok(Some(s.clone())),
                _ => Err(()),
            }
        };
        match (b.get("decided"), b.get("checked")) {
            (None, None) => Ok(None),
            (Some(Value::Object(d)), None) => {
                let effect = d
                    .get("effect")
                    .and_then(Value::as_str)
                    .filter(|e| matches!(*e, "allow" | "block"));
                // Allow and Block are a rule's: one with no rule is not a decision.
                let rule_id = rule(d, "rule_id")?.ok_or(())?;
                Ok(Some(Self {
                    effect: effect.ok_or(())?.to_string(),
                    rule_id: Some(rule_id),
                    rule_name: rule(d, "rule_name")?,
                }))
            }
            (None, Some(Value::Object(c))) => Ok(Some(Self {
                effect: "ask".into(),
                rule_id: rule(c, "rule_id")?,
                rule_name: rule(c, "rule_name")?,
            })),
            _ => Err(()),
        }
    }

    fn status(&self) -> &'static str {
        match self.effect.as_str() {
            "allow" => "approved",
            "block" => "denied",
            _ => "pending",
        }
    }

    /// The outcome it is counted under (`rule_hourly`).
    fn outcome(&self) -> &'static str {
        match self.effect.as_str() {
            "allow" => "allowed",
            "block" => "blocked",
            _ => "asked",
        }
    }
}

/// An agent paired with this firewall: the only boxes a firewall raises, reads or settles for.
fn is_agent(c: &rusqlite::Connection, vm_id: &str) -> rusqlite::Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM agents WHERE vm_id = ?1 AND role = 'openclaw'",
        [vm_id],
        |_| Ok(true),
    )
    .optional()?
    .unwrap_or(false))
}

/// One hit on a rule (or on "Every other request") for the Security rules tab's counts.
fn bump_rule(c: &rusqlite::Connection, vm_id: &str, v: &Verdict, at: i64) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO rule_hourly (hour, vm_id, rule_type, rule_key, outcome, count, last_at, name)
         VALUES (?1, ?2, 'auto', ?3, ?4, 1, ?5, ?6)
         ON CONFLICT (hour, vm_id, rule_type, rule_key, outcome)
         DO UPDATE SET count = count + 1, last_at = max(last_at, excluded.last_at),
                       name = coalesce(excluded.name, name)",
        params![
            at - at.rem_euclid(3600),
            vm_id,
            v.rule_id.as_deref().unwrap_or("default"),
            v.outcome(),
            at,
            v.rule_id.as_ref().and(v.rule_name.as_deref()),
        ],
    )?;
    Ok(())
}

/// The agent a firewall acts for (`agent_vm_id`), when it is one of ours.
fn agent_named(c: &rusqlite::Connection, role: &str, named: Option<&str>) -> rusqlite::Result<Option<String>> {
    match named {
        Some(a) if role == "mitm" && is_agent(c, a)? => Ok(Some(a.to_string())),
        _ => Ok(None),
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

/// The rules this firewall adds by itself (`cc_contracts::managed`): one per host of each model key
/// it holds, for every agent, and of each bot, inbox and Gmail grant that has an agent, for that agent. Not rows: they
/// come and go with the key or the bot, and nobody can change them.
pub fn managed_rules(c: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    use cc_contracts::managed;
    let mut out = Vec::new();
    // Every key held, until it is removed: one the firewall refused on a replace still has the old one.
    let mut q = c.prepare("SELECT provider FROM llm_keys ORDER BY created_at, id")?;
    let providers: Vec<String> = q.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    for p in providers {
        if let Some(s) = managed::source(&p) {
            out.extend(managed::rules(s, None));
        }
    }
    // The bots, inboxes and Google grants on an agent, as the firewall last listed them (`api::managed`).
    let mut q = c.prepare("SELECT value FROM settings WHERE key LIKE ?1 ORDER BY key")?;
    let parts: Vec<String> = q
        .query_map([format!("{}%", crate::api::managed::SEEN_PREFIX)], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let seen: Vec<Value> = parts
        .iter()
        .filter_map(|v| serde_json::from_str::<Vec<Value>>(v).ok())
        .flatten()
        .collect();
    for ch in &seen {
        let (Some(kind), Some(vm)) = (
            ch.get("type").and_then(Value::as_str),
            ch.get("vmId").and_then(Value::as_str),
        ) else {
            continue;
        };
        if let Some(s) = managed::source(kind) {
            out.extend(managed::rules(s, Some(vm)));
        }
    }
    Ok(out)
}

const EGRESS_EFFECTS: &[&str] = &["allow", "block", "require_permission", "tunnel", "drop", "residential"];

pub struct LocalControlPlane {
    pub db: Arc<Db>,
}

/// A request as a status read sees it: status, deadline, kind, the agents it was raised for, the box
/// that raised it, and who settled it.
type StatusRow = (String, Option<i64>, String, String, String, Option<String>);

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

    /// The enabled rules are only "Every other site: Block": nothing gets out but what the managed
    /// rules let through.
    pub fn only_block_all(&self) -> rusqlite::Result<bool> {
        let ids: Vec<String> = {
            let c = self.db.lock();
            let mut q = c.prepare("SELECT id FROM egress_rules WHERE enabled = 1 LIMIT 2")?;
            q.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        Ok(ids == [BLOCK_ALL_ID])
    }

    /// The OpenClaw agent a box token names, when it verifies with that agent's own key and has not
    /// expired: what a settle the firewall carries for an agent is checked with (the agent's own
    /// call, as before the firewall carried it).
    pub fn agent_by_token(&self, token: &str) -> Option<String> {
        use base64::Engine as _;
        let payload = token.split('.').nth(1)?;
        let claims: Value =
            serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        let vm = claims.get("vmId")?.as_str()?.to_string();
        let pem: String = self
            .db
            .lock()
            .query_row(
                "SELECT public_key FROM agents WHERE vm_id = ?1 AND role = 'openclaw'",
                [&vm],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        let key = cc_auth::jwt::VerifyKey::ed25519_spki_pem(&pem).ok()?;
        cc_auth::jwt::verify(token, &key, cc_auth::jwt::VerifyOptions::default()).ok()?;
        Some(vm)
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
        let mut rules = rules;
        rules.extend(managed_rules(&c)?);
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
        let query = |name: &str| {
            url::form_urlencoded::parse(call.query.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };
        let id = query("permission_id");
        // The firewall reading for an agent behind it (the agent's approvals come through its gate):
        // it reads what that agent may read. An agent not paired here is refused.
        let named = query("agent_vm_id");
        let acting = agent_named(&self.db.lock(), role, named.as_deref())?;
        if named.is_some() && acting.is_none() {
            return Ok(Answer::error(403, "not an agent behind this firewall"));
        }
        let (caller, role) = match &acting {
            Some(a) => (a.as_str(), "openclaw"),
            None => (caller, role),
        };
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
        let rows: Vec<StatusRow> = {
            let mut q = c.prepare(
                "SELECT status, expires_at, kind, agent_vm_ids, vm_id, resolved_by FROM permission_requests
                 WHERE external_id = ?1 ORDER BY id",
            )?;
            q.query_map([&id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        drop(c);
        let row = rows
            .into_iter()
            .find(|(_, _, _, ids, owner, _)| self.readable(caller, role, ids, owner));
        Ok(Answer::ok(match row {
            Some((status, expires, kind, _, _, by)) => json!({
                // An approval the box itself settled (answered in OpenClaw) is not handed back to
                // the box as one to carry out: whatever is on the box could have sent it.
                "status": if status == "approved" && by.as_deref() == Some("openclaw") {
                    "approved_on_box".to_string()
                } else {
                    status
                },
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
            // A box settles only what it raised, as itself. An agent's settle that the firewall carries
            // is made as the agent, with the agent's own token: the firewall never settles for it.
            if text("agent_vm_id").is_some() {
                return Ok(Answer::error(403, "a box settles only its own requests"));
            }
            let c = self.db.lock();
            let owner = caller;
            let row: Option<(i64, String, String)> = c
                .query_row(
                    "SELECT id, status, kind FROM permission_requests WHERE vm_id = ?1 AND external_id = ?2",
                    params![owner, pid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((id, status, kind)) = row else {
                return Ok(Answer {
                    status: 404,
                    body: json!({"status": "unknown"}),
                });
            };
            // Carried through the firewall's gate: OpenClaw's own approvals only, never a meeting ask.
            if b.get("via_gate") == Some(&json!(true))
                && !cc_contracts::auto_approve::AGENT_KINDS.contains(&kind.as_str())
            {
                return Ok(Answer::error(
                    403,
                    "through the gate an agent settles only its own approvals",
                ));
            }
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
        let Ok(verdict) = Verdict::of(b) else {
            return Ok(Answer::error(400, "Invalid body"));
        };
        if verdict.is_some() && role != "mitm" {
            return Ok(Answer::error(403, "only a firewall says what its rules decided"));
        }
        // Its rules speak for an agent's approvals and for its own asks, nothing else.
        if verdict.is_some()
            && !matches!(
                kind.as_str(),
                "exec" | "plugin" | "system" | "access" | "email_recipient" | "app_call"
            )
        {
            return Ok(Answer::error(403, "no rule answers this kind"));
        }
        // An agent's own approval, which the firewall answered or passed on for it: raised for that
        // agent, with what the rules said. The row is the agent's, as if it had raised it here.
        let agent_kind = cc_contracts::auto_approve::AGENT_KINDS.contains(&kind.as_str());
        let owner = if role == "mitm" && agent_kind {
            if verdict.is_none() {
                return Ok(Answer::error(
                    403,
                    "a firewall raises an agent's approval with what its rules said",
                ));
            }
            match agent_named(&self.db.lock(), role, text("agent_vm_id").as_deref())? {
                Some(a) => a,
                None => return Ok(Answer::error(403, "not an agent behind this firewall")),
            }
        } else if kinds_for(role).contains(&kind.as_str()) {
            caller.to_string()
        } else {
            return Ok(Answer::error(
                403,
                &format!("a {role} box may not raise {kind} requests"),
            ));
        };
        let egress = matches!(kind.as_str(), "access" | "email_recipient" | "app_call");
        // The title the firewall matched its rules against (`request_title`, as the console's).
        let Some(title) = cc_contracts::auto_approve::request_title(&Value::Object(b.clone()), &Default::default())
        else {
            return Ok(Answer::error(400, "title required"));
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
                params![owner, pid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (id, status, deduped) = match existing {
            Some((id, status)) => (id, status, true),
            None => {
                let status = verdict.as_ref().map_or("pending", Verdict::status);
                let decided = status != "pending";
                c.execute(
                    "INSERT INTO permission_requests (vm_id, external_id, kind, title, detail, status, expires_at,
                                                      resolved_by, rule_id, rule_name, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
                    params![
                        owner,
                        pid,
                        kind,
                        title,
                        detail.to_string(),
                        status,
                        expires,
                        decided.then_some("rule"),
                        verdict.as_ref().and_then(|v| v.rule_id.clone()),
                        verdict
                            .as_ref()
                            .and_then(|v| v.rule_id.as_ref().and(v.rule_name.clone())),
                        now
                    ],
                )?;
                let id = c.last_insert_rowid();
                // Counted once, for the agent it was for (the firewall's own website and email
                // asks: for the firewall, as the SaaS counts them).
                if let Some(v) = &verdict {
                    let for_vm = match text("agent_vm_id") {
                        Some(a) if (agent_kind || kind == "app_call") && is_agent(&c, &a)? => a,
                        _ => owner.clone(),
                    };
                    bump_rule(&c, &for_vm, v, now)?;
                }
                (id, status.to_string(), false)
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
            if CONNECTOR_SOURCES.contains(&source.as_str()) {
                if connector_write(&tx, caller, vm.as_deref(), &source, r, &row)? {
                    accepted += 1;
                } else {
                    duplicates += 1;
                }
                continue;
            }
            let routine = source == "egress" && cc_contracts::managed::is_routine(r);
            let n = tx.execute(
                "INSERT INTO activity_raw (vm_id, source, status, dedupe_key, occurred_at, summary, record, created_at, routine)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT (dedupe_key) DO NOTHING",
                params![
                    vm,
                    source,
                    row.status,
                    row.dedupe,
                    row.at,
                    row.summary,
                    r.to_string(),
                    now_s(),
                    routine
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
    let at = ts.map_or(now, |t| clamp_ts(t, now));
    if CONNECTOR_SOURCES.contains(&source) {
        return Some(ActivityRow {
            dedupe,
            at,
            status: connector_status(r).to_string(),
            summary: connector_summary(source, r),
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
        at,
        status: status.unwrap_or("recorded").to_string(),
        summary: s("summary").or_else(|| s("title")).unwrap_or(source).to_string(),
    })
}

/// An app call and its run (`connector:<run_id>`), or a call that never ran (`connector-call:<id>`).
const CONNECTOR_SOURCES: &[&str] = &["connector_run", "connector_call"];
const MAX_SUMMARY: usize = 200;

/// `connectorStatus`: the gate's decision first (a stopped result is blocked though it ran), then
/// how the run ended.
fn connector_status(r: &Value) -> &'static str {
    match r.get("decision").and_then(Value::as_str) {
        Some("blocked") => "blocked",
        Some("asked" | "held") => "asked",
        _ => match r.get("ok").and_then(Value::as_bool) {
            Some(true) => "succeeded",
            Some(false) => "failed",
            None => "unknown",
        },
    }
}

/// `connectorCallRow` / `connectorRunRow`'s line: the action or tool, else the method and path, else
/// the app.
fn connector_summary(source: &str, r: &Value) -> String {
    let s = |k: &str| r.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
    let mcp = matches!(s("route"), Some("mcp_server" | "mcp_proxy"));
    let line = if source == "connector_run" {
        s("action_id")
            .or_else(|| s("service"))
            .unwrap_or("app action")
            .to_string()
    } else if let Some(a) = s("action_id") {
        a.to_string()
    } else if let Some(p) = s("path").filter(|_| mcp) {
        p.to_string()
    } else if let (Some(m), Some(p), false) = (s("method"), s("path"), mcp) {
        format!("{m} {p}")
    } else {
        s("service")
            .unwrap_or(if mcp { "MCP call" } else { "app action" })
            .to_string()
    };
    if line.chars().count() > MAX_SUMMARY {
        format!("{}…", line.chars().take(MAX_SUMMARY - 1).collect::<String>())
    } else {
        line
    }
}

/// `writeConnectorRows`: a call and its run share a key, and either may come first, more than once:
/// the records are merged (the newer one's fields win, a null never wipes one), the row keeps the
/// earlier time and its status is worked out again. A call that waited for a person and then went
/// on (`follows`) replaces the waiting row; a waiting row whose follow-up is already here is not
/// written. Only a new row is counted in the hourly rollup, and a replaced one is taken out of it.
/// True when the record changed or added a row.
fn connector_write(
    tx: &rusqlite::Transaction<'_>,
    caller: &str,
    vm: Option<&str>,
    source: &str,
    r: &Value,
    row: &ActivityRow,
) -> rusqlite::Result<bool> {
    let prefix = format!("{caller}:connector-call:");
    if let Some(waiting) = row.dedupe.strip_prefix(&prefix) {
        let followed: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM activity_raw WHERE source IN ('connector_run', 'connector_call')
             AND substr(dedupe_key, 1, length(?1)) = ?1 AND json_extract(record, '$.follows') = ?2)",
            params![format!("{caller}:connector"), waiting],
            |q| q.get(0),
        )?;
        if followed {
            return Ok(false);
        }
    }
    let old: Option<(String, i64, String, String, Option<String>, String)> = tx
        .query_row(
            "SELECT record, occurred_at, status, source, vm_id, summary FROM activity_raw WHERE dedupe_key = ?1",
            params![row.dedupe],
            |q| Ok((q.get(0)?, q.get(1)?, q.get(2)?, q.get(3)?, q.get(4)?, q.get(5)?)),
        )
        .optional()?;
    let wrote = match old {
        Some((text, at, was, kept_source, kept_vm, kept_summary)) => {
            let mut merged = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({}));
            let before = merged.clone();
            if let (Some(m), Some(n)) = (merged.as_object_mut(), r.as_object()) {
                // Where the row came from and when it started stay the first record's; a null or an
                // empty string never wipes a value.
                let empty = |v: &Value| v.is_null() || v.as_str() == Some("");
                for (k, v) in n.iter().filter(|(k, v)| !empty(v) && *k != "source" && *k != "ts") {
                    m.insert(k.clone(), v.clone());
                }
            }
            if merged == before {
                false
            } else {
                // The gate's line names the call; the run's names only the action, so it keeps the
                // stored one.
                let summary = if r.get("decision").is_some() {
                    row.summary.clone()
                } else {
                    kept_summary
                };
                let status = connector_status(&merged);
                let first = at.min(row.at);
                tx.execute(
                    "UPDATE activity_raw SET record = ?2, status = ?3, summary = ?4, occurred_at = ?5,
                     vm_id = COALESCE(vm_id, ?6) WHERE dedupe_key = ?1",
                    params![row.dedupe, merged.to_string(), status, summary, first, vm],
                )?;
                // The row is counted once, under what it says now.
                let counted = kept_vm.as_deref().or(vm).unwrap_or_default();
                bump_hourly(tx, at, kept_vm.as_deref().unwrap_or_default(), &kept_source, &was, -1)?;
                bump_hourly(tx, first, counted, &kept_source, status, 1)?;
                true
            }
        }
        None => {
            tx.execute(
                "INSERT INTO activity_raw (vm_id, source, status, dedupe_key, occurred_at, summary, record, created_at, routine)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                params![vm, source, row.status, row.dedupe, row.at, row.summary, r.to_string(), now_s()],
            )?;
            bump_hourly(tx, row.at, vm.unwrap_or_default(), source, &row.status, 1)?;
            true
        }
    };
    if let Some(waited) = r.get("follows").and_then(Value::as_str).filter(|f| !f.is_empty()) {
        let gone: Option<(i64, Option<String>, String, String)> = tx
            .query_row(
                "DELETE FROM activity_raw WHERE dedupe_key = ?1 RETURNING occurred_at, vm_id, source, status",
                params![format!("{prefix}{waited}")],
                |q| Ok((q.get(0)?, q.get(1)?, q.get(2)?, q.get(3)?)),
            )
            .optional()?;
        if let Some((at, vm, source, status)) = gone {
            bump_hourly(tx, at, &vm.unwrap_or_default(), &source, &status, -1)?;
        }
    }
    Ok(wrote)
}

fn bump_hourly(
    tx: &rusqlite::Transaction<'_>,
    at: i64,
    vm: &str,
    source: &str,
    status: &str,
    by: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO activity_hourly (hour, vm_id, source, status, count) VALUES (?1, ?2, ?3, ?4, MAX(?5, 0))
         ON CONFLICT (hour, vm_id, source, status) DO UPDATE SET count = MAX(count + ?5, 0)",
        params![at - at.rem_euclid(3600), vm, source, status, by],
    )?;
    Ok(())
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
