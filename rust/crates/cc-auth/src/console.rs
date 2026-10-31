//! The control plane's token on an agent box (`packages/vm-agent/src/auth.ts`, `verifyRequest`).
//!
//! The key opens only the method and path pairs on [`control_plane_may_call`]'s list, the token
//! must name this box, and it must carry no `purpose` (browser login tokens do). No jti, no replay
//! cache and no request binding: the TS does none, and the console's tokens live 30 s.

use serde_json::Value;

use crate::jwt::{self, Claims, VerifyKey, VerifyOptions};
use crate::request_path;

/// Everything the control plane's key may call, by the service this agent runs (`CC_SERVICE`).
/// Kept in the same order and with the same entries as `CONTROL_PLANE_ROUTES` in auth.ts; the
/// comments there say why each one is on it.
const OPENCLAW: &[&str] = &[
    "GET /health",
    "GET /health/summary",
    "POST /health/model",
    "GET /health/patches",
    "GET /activity/now",
    "GET /screen/thumb",
    "GET /status",
    "POST /start",
    "POST /stop",
    "POST /restart",
    "POST /mitm-ca/refresh",
    "GET /update",
    "GET /channels/status",
    "GET /llm/status",
    "GET /llm/models",
    "GET /tailscale/status",
    "GET /devices",
    "GET /google/status",
    "GET /drive/status",
    "GET /ssh/status",
    "GET /backup/plan",
    "GET /search/status",
    "GET /meetings/status",
    "GET /meetings/instructions",
    "GET /connectors/status",
    "GET /mcp-servers/status",
    "GET /skills",
    "POST /skills/enabled",
    "POST /skills/remove",
    "POST /skills/restore",
    "POST /notes/remove",
    "POST /notes/restore",
    "GET /storage",
    "POST /storage/grow",
    "POST /templates/poke",
];

const GBRAIN: &[&str] = &[
    "GET /health",
    "GET /status",
    "POST /start",
    "POST /stop",
    "POST /restart",
    "POST /mitm-ca/refresh",
    "GET /logs",
    "GET /update",
];

/// Whether the control plane's key may call this method and path here. An unknown service falls
/// back to the agent box's list, as the TS does.
pub fn control_plane_may_call(method: &str, url: &str, service: &str) -> bool {
    let Some(path) = request_path(url) else { return false };
    let list = if service == "gbrain" { GBRAIN } else { OPENCLAW };
    let want = format!("{method} {path}");
    list.iter().any(|r| *r == want)
}

/// Checks the console's bearer token for this request. `None` means 401.
pub struct ConsoleAuth {
    key: VerifyKey,
    /// The box's own id (`KEYS_DIR/vm_id`). When the file was missing at start, tokens are
    /// checked by signature only, as in the TS.
    own_vm_id: Option<String>,
    service: String,
}

impl ConsoleAuth {
    pub fn new(key: VerifyKey, own_vm_id: Option<String>, service: impl Into<String>) -> Self {
        Self {
            key,
            own_vm_id,
            service: service.into(),
        }
    }

    pub fn verify(&self, method: &str, url: &str, authorization: Option<&str>) -> Option<Claims> {
        let token = authorization?.strip_prefix("Bearer ")?;
        if !control_plane_may_call(method, url, &self.service) {
            return None;
        }
        let claims = jwt::verify(token, &self.key, VerifyOptions::default()).ok()?;
        if let Some(own) = &self.own_vm_id
            && claims.get("vmId") != Some(&Value::String(own.clone()))
        {
            return None;
        }
        // `payload.purpose !== undefined`: a JSON null counts as present.
        if claims.contains_key("purpose") {
            return None;
        }
        Some(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_uses_the_normalised_path_and_ignores_the_query() {
        assert!(control_plane_may_call("GET", "/health", "openclaw"));
        assert!(control_plane_may_call("GET", "/status?x=1", "openclaw"));
        assert!(control_plane_may_call("GET", "/channels/../status", "openclaw"));
        assert!(!control_plane_may_call("POST", "/health", "openclaw"));
        assert!(!control_plane_may_call("GET", "/logs", "openclaw"));
        assert!(control_plane_may_call("GET", "/logs", "gbrain"));
        assert!(!control_plane_may_call("GET", "/skills", "gbrain"));
        assert!(control_plane_may_call("GET", "/skills", "something-else"));
    }
}
