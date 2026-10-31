//! The firewall's two pushes about Opens (`routes/access-push.ts`), firewall-signed with purpose
//! `access`. The control plane can send neither: it cannot point this box's Open flow at a
//! firewall of its choosing, and it cannot end sessions by pretending to revoke.
//!
//!   POST /access/config  { firewallOrigin }          where `/__cc/open` sends the browser
//!   POST /access/revoke  { deviceIds } | { all: true } end those browsers' sessions here

use std::sync::Arc;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Req, Resp, json};
use hyper::Method;
use serde_json::{Value, json as j};

use super::access::Access;
use super::access_state::{now_ms, valid_firewall_origin};
use crate::app::App;

pub async fn handle(app: &App, access: &Arc<Access>, req: Req) -> Resp {
    if req.method() != Method::POST {
        return json(405, &j!({"error": "Method not allowed"}));
    }
    let pathname = cc_http::pathname(&req.uri().to_string());
    let read = ReadBody::Json { limit: 64 * 1024 };
    let body = match cc_http::firewall_request(&app.firewall_auth, req, "access", 0, read).await {
        FirewallRequest::Refused { .. } => return json(401, &j!({"error": "Unauthorized"})),
        FirewallRequest::Accepted {
            body: FirewallBody::Json(b),
            ..
        } => b,
        FirewallRequest::Accepted { .. } => return json(400, &j!({"error": "Invalid JSON body"})),
    };
    match pathname.as_str() {
        "/access/config" => {
            let origin = body
                .get("firewallOrigin")
                .and_then(Value::as_str)
                .map(str::to_lowercase)
                .unwrap_or_default();
            if !valid_firewall_origin(&origin) {
                return json(400, &j!({"error": "firewallOrigin must be https://<hostname>"}));
            }
            if access.state.set_firewall_origin(&origin).is_err() {
                return internal_error();
            }
            tracing::info!("[access] the firewall for Opens is {origin}");
            json(200, &j!({"ok": true, "firewallOrigin": origin}))
        }
        "/access/revoke" => {
            if body.get("all") == Some(&Value::Bool(true)) {
                if let Err(e) = access.sessions.rotate_secret() {
                    tracing::error!("[access] could not rotate the session secret: {e}");
                    return internal_error();
                }
                // The log redactor masks the new secret from now on. The TS loads its secrets
                // once, at start, so it keeps masking only the old one.
                if let Some(logs) = access.logs.get() {
                    logs.redaction.reload();
                }
                return json(200, &j!({"ok": true, "all": true}));
            }
            // `.length` is UTF-16 code units.
            let ids: Vec<String> = match body.get("deviceIds") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty() && s.encode_utf16().count() <= 64)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            if ids.is_empty() || ids.len() > 1000 {
                return json(400, &j!({"error": "deviceIds must be a non-empty list"}));
            }
            if access.state.revoke_devices(&ids, now_ms()).is_err() {
                return internal_error();
            }
            tracing::info!("[access] revoked {} browser(s); their sessions here end now", ids.len());
            json(200, &j!({"ok": true, "revoked": ids.len()}))
        }
        _ => json(404, &j!({"error": "Not found"})),
    }
}

/// A store that could not be written. The TS throws there, the rejection is unhandled and Node
/// stops the agent; here the push gets a 500, and nothing is said to be done that was not saved.
fn internal_error() -> Resp {
    json(500, &j!({"error": "Internal error"}))
}
