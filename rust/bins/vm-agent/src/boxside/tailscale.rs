//! Tailscale on the agent box (`tailscale.ts`, `routes/tailscale.ts`). The owner's auth key arrives
//! from the org firewall in one `POST /tailscale/apply` and goes to the root helper on stdin, never
//! in argv: `cc-tailscale up <hostname> <ssh0|ssh1>`, `logout`, `status`. The console can read which
//! tailnet the box is on, and can never put it on one.

use std::sync::Arc;
use std::time::Duration;

use cc_http::{FirewallBody, Req, Resp};
use cc_proc::Runner;
use serde_json::{Map, Value, json};

use super::exec::{ExecErr, exec, failure_line};
use super::web::{self, send_json};

const UP_TIMEOUT: Duration = Duration::from_secs(120);
/// `TAILSCALE_STATUS_MS`; the console's read timeout stays above it.
const CLI_TIMEOUT: Duration = Duration::from_secs(20);
const JOIN_SETTLE_TRIES: usize = 10;
const JOIN_SETTLE_DELAY: Duration = Duration::from_millis(1500);
const HELPER: &str = "/usr/local/bin/cc-tailscale";

pub const TAILSCALE_UNSUPPORTED_MESSAGE: &str =
    "This agent was built before Tailscale support. Update the agent (or rebuild it) to use Tailscale.";

/// A failure that means the box cannot run the helper (`UNSUPPORTED_RE`).
fn looks_unsupported(e: &ExecErr) -> bool {
    if e.not_found {
        return true;
    }
    let text = format!("{}\n{}\n{}", e.stderr, e.stdout, e.message).to_lowercase();
    [
        "a password is required",
        "a terminal is required",
        "command not found",
        "/tailscale: not found",
        "tailscale: no such file",
    ]
    .iter()
    .any(|p| text.contains(p))
}

/// `HOSTNAME_RE`: a name a tailnet will accept.
fn valid_hostname(h: &str) -> bool {
    let b = h.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// `AUTH_KEY_RE`: `tskey-auth-<id>-<secret>`.
pub fn valid_auth_key(k: &str) -> bool {
    let Some(rest) = k.strip_prefix("tskey-auth-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !a.is_empty() && !b.is_empty() && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_alphanumeric())
}

fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// `pickIp`: the first IPv4 on the tailnet, else the first address.
fn pick_ip(ips: Option<&Value>) -> Option<String> {
    let a = ips?.as_array()?;
    let v4 = a.iter().filter_map(Value::as_str).find(|i| {
        let p: Vec<&str> = i.split('.').collect();
        p.len() == 4 && p.iter().all(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()))
    });
    v4.map(str::to_string).or_else(|| s(a.first()))
}

/// `health`: the first complaint.
fn health(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Array(a)) => a.iter().find_map(|x| s(Some(x))),
        other => s(other),
    }
}

fn status_value(
    state: &str,
    name: Option<String>,
    ip: Option<String>,
    ssh: bool,
    backend: Option<String>,
    message: Option<String>,
) -> Value {
    json!({"state": state, "name": name, "ip": ip, "ssh": ssh, "backendState": backend, "message": message})
}

/// `status()`'s reading of `tailscale status --json`.
pub fn parse_status(raw: &str) -> Value {
    let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(raw) else {
        return status_value(
            "unavailable",
            None,
            None,
            false,
            None,
            Some("Tailscale did not report a status this box could read.".into()),
        );
    };
    let empty = Map::new();
    let me = parsed.get("Self").and_then(Value::as_object).unwrap_or(&empty);
    let backend = s(parsed.get("BackendState"));
    let name = s(me.get("DNSName"))
        .map(|n| n.strip_suffix('.').map(str::to_string).unwrap_or(n))
        .filter(|n| !n.is_empty())
        .or_else(|| s(me.get("HostName")));
    let ip = pick_ip(me.get("TailscaleIPs"));
    let ssh = me
        .get("sshHostKeys")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    match backend.as_deref() {
        Some("Running") if ip.is_some() => status_value("joined", name, ip, ssh, backend, None),
        Some("Starting") | Some("NoState") => status_value(
            "starting",
            name,
            ip,
            ssh,
            backend,
            Some("Tailscale is still starting on this box.".into()),
        ),
        b => {
            let message = if matches!(b, Some("NeedsLogin") | Some("Stopped")) {
                Some("This box is not signed in to a tailnet.".to_string())
            } else {
                health(parsed.get("Health"))
            };
            status_value("off", None, None, false, backend, message)
        }
    }
}

pub struct Tailscale {
    runner: Arc<dyn Runner>,
    settle_delay: Duration,
}

/// A failure the route answers with 409 (`TailscaleUnsupportedError`) or 500.
pub enum TsError {
    Unsupported,
    Failed(String),
}

impl Tailscale {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Self {
            runner,
            settle_delay: JOIN_SETTLE_DELAY,
        }
    }

    #[cfg(test)]
    pub fn with_settle_delay(mut self, d: Duration) -> Self {
        self.settle_delay = d;
        self
    }

    /// Never fails: a box without Tailscale answers `unavailable`.
    pub async fn status(&self) -> Value {
        match exec(
            self.runner.as_ref(),
            "sudo",
            &["-n", HELPER, "status"],
            CLI_TIMEOUT,
            None,
        )
        .await
        {
            Ok(out) => parse_status(&out.stdout),
            Err(e) => {
                let message = if looks_unsupported(&e) {
                    TAILSCALE_UNSUPPORTED_MESSAGE.to_string()
                } else {
                    failure_line(&e)
                };
                status_value("unavailable", None, None, false, None, Some(message))
            }
        }
    }

    /// Join the tailnet; the key is gone when this returns.
    pub async fn apply(&self, auth_key: &str, ssh: bool, hostname: &str) -> Result<Value, TsError> {
        if !valid_hostname(hostname) {
            return Err(TsError::Failed("that hostname is not one a tailnet will accept".into()));
        }
        let flag = if ssh { "ssh1" } else { "ssh0" };
        if let Err(e) = exec(
            self.runner.as_ref(),
            "sudo",
            &["-n", HELPER, "up", hostname, flag],
            UP_TIMEOUT,
            Some(&format!("{auth_key}\n")),
        )
        .await
        {
            if looks_unsupported(&e) {
                return Err(TsError::Unsupported);
            }
            return Err(TsError::Failed(format!(
                "Tailscale could not join the network: {}",
                failure_line(&e)
            )));
        }
        let mut status = self.status().await;
        let mut i = 1;
        while i < JOIN_SETTLE_TRIES && status["state"] != "joined" && status["state"] != "off" {
            tokio::time::sleep(self.settle_delay).await;
            status = self.status().await;
            i += 1;
        }
        if status["state"] != "joined" {
            return Err(TsError::Failed(
                status["message"].as_str().map(str::to_string).unwrap_or_else(|| {
                    "Tailscale accepted the key but the box has no address on the tailnet yet.".into()
                }),
            ));
        }
        let shown = status["name"]
            .as_str()
            .or(status["ip"].as_str())
            .unwrap_or("an unnamed node")
            .to_string();
        tracing::info!("[tailscale] joined as {shown} (ssh {})", if ssh { "on" } else { "off" });
        Ok(json!({"ok": true, "ssh": ssh, "node": {"name": status["name"], "ip": status["ip"]}}))
    }

    pub async fn logout(&self) -> Result<Value, TsError> {
        if let Err(e) = exec(
            self.runner.as_ref(),
            "sudo",
            &["-n", HELPER, "logout"],
            CLI_TIMEOUT,
            None,
        )
        .await
        {
            if looks_unsupported(&e) {
                return Err(TsError::Unsupported);
            }
            return Err(TsError::Failed(format!(
                "Tailscale could not leave the network: {}",
                failure_line(&e)
            )));
        }
        tracing::info!("[tailscale] left the tailnet");
        Ok(json!({"ok": true}))
    }
}

/// `handleTailscale`.
pub async fn handle(app: &crate::app::App, ts: &Tailscale, req: Req) -> Resp {
    let write = req.method() == http::Method::POST;
    let (parts, body) = match web::firewall_or_console(
        app,
        req,
        "tailscale",
        "network changes must come from the org firewall",
    )
    .await
    {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    if pathname == "/tailscale/status" && parts.method == http::Method::GET {
        return send_json(200, &ts.status().await, &[]);
    }
    if !write {
        return send_json(404, &json!({"error": "Not found"}), &[]);
    }
    let result = match pathname.as_str() {
        "/tailscale/logout" => ts.logout().await,
        "/tailscale/apply" => {
            let FirewallBody::Json(b) = &body else {
                return send_json(400, &json!({"ok": false, "error": "Invalid JSON body"}), &[]);
            };
            // Shape-checked, never echoed.
            let key = b.get("authKey").and_then(Value::as_str).filter(|k| valid_auth_key(k));
            let Some(key) = key else {
                return send_json(
                    400,
                    &json!({"ok": false, "error": "authKey must be a Tailscale auth key"}),
                    &[],
                );
            };
            let Some(hostname) = b.get("hostname").and_then(Value::as_str).filter(|h| !h.is_empty()) else {
                return send_json(400, &json!({"ok": false, "error": "hostname required"}), &[]);
            };
            ts.apply(key, b.get("ssh") == Some(&Value::Bool(true)), hostname).await
        }
        _ => return send_json(404, &json!({"error": "Not found"}), &[]),
    };
    match result {
        Ok(v) => send_json(200, &v, &[]),
        Err(TsError::Unsupported) => send_json(
            409,
            &json!({"ok": false, "code": "tailscale_unsupported", "error": TAILSCALE_UNSUPPORTED_MESSAGE}),
            &[],
        ),
        Err(TsError::Failed(e)) => send_json(500, &json!({"ok": false, "error": e}), &[]),
    }
}

#[cfg(test)]
mod tests;
