//! The local control plane over HTTP: `/api/vm-agent/*` as the SaaS serves it, so the conformance
//! cases (`rust/conformance/cases/cp`, target `local`) hold both to the same answers. A box token
//! (`{vmId}`, EdDSA) is checked against the key the agents table holds for that vm.
//!
//! With `hooks`, it also serves the test-only `/__conformance/*` routes the SaaS harness has
//! (`apps/saas/scripts/conformance-cp.ts`): seed, reset, answer-permission and read. The
//! `cc-local-contract` binary serves it that way; nothing else does.

use std::sync::Arc;

use base64::Engine;
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};

use crate::admin::replace_rules;
use crate::db::{Db, now_s};
use crate::plane::{Call, ControlPlane, LocalControlPlane};

const BODY_MAX: usize = 1024 * 1024;

pub struct Facade {
    pub plane: Arc<LocalControlPlane>,
    pub hooks: bool,
}

impl Facade {
    pub fn router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["all"]);
        let me = self.clone();
        r.route(
            "all",
            |_, _| true,
            move |req, _| {
                let me = me.clone();
                async move { me.handle(req).await }
            },
        );
        r
    }

    fn db(&self) -> &Db {
        &self.plane.db
    }

    /// The vm a box token names, when it verifies with that vm's key and has not expired.
    fn caller(&self, authorization: Option<&str>) -> Option<String> {
        let token = authorization?.strip_prefix("Bearer ")?.trim();
        let payload = token.split('.').nth(1)?;
        let claims: Value =
            serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        let vm = claims.get("vmId")?.as_str()?.to_string();
        let pem: String = self
            .db()
            .lock()
            .query_row("SELECT public_key FROM agents WHERE vm_id = ?1", [&vm], |r| r.get(0))
            .optional()
            .ok()
            .flatten()?;
        let key = cc_auth::jwt::VerifyKey::ed25519_spki_pem(&pem).ok()?;
        cc_auth::jwt::verify(token, &key, cc_auth::jwt::VerifyOptions::default()).ok()?;
        Some(vm)
    }

    async fn handle(&self, req: cc_http::Req) -> cc_http::Resp {
        let (parts, body) = req.into_parts();
        let path = cc_http::pathname(parts.uri.path());
        let raw = if parts.method == http::Method::GET {
            None
        } else {
            match cc_http::read_body(body, BODY_MAX).await {
                Some(b) => Some(b),
                None => return cc_http::json(413, &json!({"error": "batch too large"})),
            }
        };
        let body: Option<Value> = raw.as_ref().and_then(|b| serde_json::from_slice(b).ok());
        if let Some(hook) = path.strip_prefix("/__conformance/") {
            if !self.hooks {
                return cc_http::not_found();
            }
            let out = self.hook(hook, body.unwrap_or(Value::Null));
            return cc_http::json(200, &out.unwrap_or_else(|e| json!({"error": e})));
        }
        if !path.starts_with("/api/vm-agent/") {
            return cc_http::not_found();
        }
        let Some(vm) = self.caller(cc_http::header(&parts, "authorization")) else {
            return cc_http::unauthorized();
        };
        let call = Call {
            method: parts.method.to_string(),
            path,
            query: parts.uri.query().unwrap_or_default().to_string(),
            body,
        };
        let a = self.plane.call(&vm, call).await;
        cc_http::json(a.status, &a.body)
    }

    fn hook(&self, name: &str, body: Value) -> Result<Value, String> {
        let s = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let e = |e: rusqlite::Error| e.to_string();
        match name {
            // One organization per process: a seed starts from empty tables.
            "seed" | "reset" => {
                self.db()
                    .lock()
                    .execute_batch(
                        "DELETE FROM agents; DELETE FROM egress_rules; DELETE FROM ai_settings;
                         DELETE FROM permission_requests; DELETE FROM activity_raw; DELETE FROM activity_hourly;
                         DELETE FROM settings;",
                    )
                    .map_err(e)?;
                if name == "reset" {
                    return Ok(json!({"ok": true}));
                }
                for v in body.get("vms").and_then(Value::as_array).into_iter().flatten() {
                    let f = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
                    self.db()
                        .lock()
                        .execute(
                            "INSERT INTO agents (vm_id, role, name, private_ip, public_key, status, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            params![
                                f("id"),
                                f("role"),
                                f("name"),
                                f("private_ip"),
                                f("public_key"),
                                f("status").unwrap_or_else(|| "running".into()),
                                now_s()
                            ],
                        )
                        .map_err(e)?;
                }
                let rules = body
                    .get("egress_rules")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                replace_rules(self.db(), &rules).map_err(e)??;
                Ok(json!({"org_id": "local", "bootstrap": {}}))
            }
            "answer-permission" => {
                let status = match self.plane.pending_row(&s("permission_id")).map_err(e)? {
                    Some(row) => self.plane.resolve_permission(row, &s("resolution")).map_err(e)?,
                    None => None,
                };
                Ok(json!({"status": status}))
            }
            "read" => self.read(&s("what"), &s("id")).map_err(e),
            other => Err(format!("no hook {other} on the local control plane")),
        }
    }

    fn read(&self, what: &str, id: &str) -> rusqlite::Result<Value> {
        let c = self.db().lock();
        Ok(match what {
            "activity" => {
                let mut q = c.prepare("SELECT source, status, vm_id, summary FROM activity_raw ORDER BY occurred_at, id")?;
                let rows: Vec<Value> = q
                    .query_map([], |r| {
                        Ok(json!({"source": r.get::<_, String>(0)?, "status": r.get::<_, String>(1)?,
                                  "vmId": r.get::<_, Option<String>>(2)?, "summary": r.get::<_, String>(3)?}))
                    })?
                    .collect::<rusqlite::Result<_>>()?;
                json!({"rows": rows})
            }
            "permission" => c
                .query_row(
                    "SELECT status, kind, title FROM permission_requests WHERE external_id = ?1 ORDER BY id LIMIT 1",
                    [id],
                    |r| Ok(json!({"status": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "title": r.get::<_, String>(2)?})),
                )
                .optional()?
                .unwrap_or(Value::Null),
            "ca" => {
                drop(c);
                let ca: Value = self
                    .db()
                    .setting("ca")
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);
                ca
            }
            "vm" => c
                .query_row("SELECT public_key, status FROM agents WHERE vm_id = ?1", [id], |r| {
                    Ok(json!({"public_key": r.get::<_, Option<String>>(0)?, "status": r.get::<_, String>(1)?}))
                })
                .optional()?
                .unwrap_or(Value::Null),
            _ => {
                let mut m = Map::new();
                m.insert("error".into(), json!(format!("no read {what} on the local control plane")));
                Value::Object(m)
            }
        })
    }
}
