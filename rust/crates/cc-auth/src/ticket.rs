//! The box ticket the firewall signs for an Open (`verifyFirewallTicket` in
//! `packages/vm-agent/src/auth.ts`). Checking the bind cookie against `c`, spending the `jti` and
//! issuing the session are the caller's (W7, `/__cc/session`).

use serde_json::Value;

use crate::jwt::{self, VerifyKey, VerifyOptions};

/// A ticket claiming to live longer than this is refused: the firewall signs 60 s.
const TICKET_MAX_S: f64 = 120.0;

#[derive(Debug, Clone, PartialEq)]
pub struct FirewallTicket {
    pub vm_id: String,
    pub purpose: String,
    pub jti: String,
    pub exp: f64,
    pub c: String,
    pub device_id: String,
    pub can_write: bool,
    /// The raw `next` claim; the caller keeps it only if it names a page it serves (`isLoginPage`).
    pub next: Option<String>,
}

fn is_c(s: &str) -> bool {
    s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `purpose` is `browser-login` or `browser-view`.
pub fn verify_firewall_ticket(
    token: &str,
    key: &VerifyKey,
    vm_id: &str,
    purpose: &str,
    now: Option<i64>,
) -> Option<FirewallTicket> {
    let p = jwt::verify(
        token,
        key,
        VerifyOptions {
            clock_tolerance_s: 0,
            now,
        },
    )
    .ok()?;
    if p.get("purpose")?.as_str()? != purpose || p.get("vmId")?.as_str()? != vm_id {
        return None;
    }
    if !p.get("iss")?.as_str()?.starts_with("fw:") {
        return None;
    }
    let jti = p.get("jti")?.as_str()?.to_string();
    let exp = p.get("exp")?.as_f64()?;
    let iat = p.get("iat")?.as_f64()?;
    if exp - iat > TICKET_MAX_S {
        return None;
    }
    let c = p.get("c")?.as_str()?;
    if !is_c(c) {
        return None;
    }
    let device_id = p.get("deviceId")?.as_str()?;
    if device_id.is_empty() {
        return None;
    }
    Some(FirewallTicket {
        vm_id: vm_id.to_string(),
        purpose: purpose.to_string(),
        jti,
        exp,
        c: c.to_string(),
        device_id: device_id.to_string(),
        can_write: p.get("canWrite") == Some(&Value::Bool(true)),
        next: p.get("next").and_then(Value::as_str).map(str::to_string),
    })
}
