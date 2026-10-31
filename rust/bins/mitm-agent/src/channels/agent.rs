//! How the firewall calls an agent box (`agent-client.ts`): HTTPS to the agent's hostname with a
//! 30 s EdDSA token signed by this box's key, bound to the one request (`m p h b jti`), with the
//! purpose its path needs. The address comes from this firewall's identity map
//! (`app.contracts.identities`), never from a command.
//!
//! The client belongs to W3 (`agent-client.ts`); W4 keeps this copy until W3's lands, so the
//! channel and model commands can reach their agents. Same paths, purposes, budgets and error text.

use std::sync::Arc;
use std::time::Duration;

use cc_auth::keys::KeysDir;
use cc_client::HttpClient;
use cc_http::BoxFuture;
use serde_json::{Map, Value};

use crate::contracts::{AgentRoute, IdentityMap};

/// `budgets.ts`.
pub const AGENT_CALL_MS: u64 = 25_000;
pub const CHANNELS_APPLY_MS: u64 = 45_000;
pub const CONFIG_WRITE_MS: u64 = 90_000;
pub const APPROVE_MS: u64 = 70_000;
pub const LLM_PUSH_MS: u64 = 90_000;
pub const BACKUP_MS: u64 = 60 * 60_000;

/// The cap on a bounded answer (`/hooks/deliver`, `/phone/*`).
const BOUNDED_MAX: usize = 128 * 1024;

pub const UNKNOWN_AGENT: &str =
    "This firewall does not know that agent. If it was just created, try again in a minute.";
pub const NOT_RUNNING: &str = "The agent is not running. Start it and try again.";
pub const TIMED_OUT: &str = "The agent did not answer in time.";

/// Which agent a call is for. `hostname` is what a caller knew; the identity map decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub vm_id: String,
    pub hostname: String,
}

impl Target {
    pub fn new(vm_id: &str, hostname: &str) -> Self {
        Self {
            vm_id: vm_id.to_string(),
            hostname: hostname.to_string(),
        }
    }

    /// `{vmId, hostname}`, as code routes carry it.
    #[allow(dead_code)] // the code routes (H3)
    pub fn to_json(&self) -> Value {
        serde_json::json!({"vmId": self.vm_id, "hostname": self.hostname})
    }
}

/// Why a call failed. The message is the TS one, so what reaches the console reads the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentError {
    pub message: String,
    /// No answer: the work may or may not have happened (`AgentTimeoutError`).
    pub timed_out: bool,
}

impl AgentError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            timed_out: false,
        }
    }

    pub fn timeout() -> Self {
        Self {
            message: TIMED_OUT.into(),
            timed_out: true,
        }
    }

    /// `isAgentRefusal`: the agent answered 400 or 500, so nothing changed there.
    pub fn refused(&self) -> bool {
        self.message.starts_with("agent 400: ") || self.message.starts_with("agent 500: ")
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What the modules call, so their tests can stand in for the agent.
pub trait AgentCalls: Send + Sync {
    /// `timeout`: replaces the path's budget for this one call.
    fn post(
        &self,
        target: &Target,
        path: &str,
        body: Value,
        timeout: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>>;
    #[allow(dead_code)] // the reads of later groups (H3 on)
    fn get(
        &self,
        target: &Target,
        path: &str,
        timeout: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>>;
}

/// `timeoutFor`.
pub fn timeout_for(path: &str) -> Duration {
    let ms = if path.starts_with("/backup/") {
        BACKUP_MS
    } else if path == "/channels/pairings/approve" {
        APPROVE_MS
    } else if path == "/channels/apply" {
        CHANNELS_APPLY_MS
    } else if matches!(
        path,
        "/meetings/apply" | "/agentmail/apply" | "/search/apply" | "/connectors/apply" | "/mcp-servers/apply"
    ) {
        CONFIG_WRITE_MS
    } else {
        AGENT_CALL_MS
    };
    Duration::from_millis(ms)
}

/// `purposeForPath`.
pub fn purpose_for_path(path: &str) -> &'static str {
    let prefixed = [
        ("/doctor/", "doctor"),
        ("/llm/", "llm"),
        ("/search/", "search"),
        ("/connectors/", "connectors"),
        ("/mcp-servers/", "mcp-servers"),
    ];
    for (p, purpose) in prefixed {
        if path.starts_with(p) {
            return purpose;
        }
    }
    if path == "/update" || path.starts_with("/update/") {
        return "update";
    }
    let prefixed = [
        ("/backup/", "backup"),
        ("/ssh/", "ssh"),
        ("/tailscale/", "tailscale"),
        ("/drive/", "drive"),
        ("/phone/", "phone"),
        ("/secrets/", "secrets"),
        ("/logins/", "logins"),
        ("/agentmail/", "agentmail"),
        ("/google/", "google"),
        ("/hooks/", "hooks"),
    ];
    for (p, purpose) in prefixed {
        if path.starts_with(p) {
            return purpose;
        }
    }
    if path == "/devices" || path.starts_with("/devices/") {
        return "devices";
    }
    let prefixed = [
        ("/kill/", "kill"),
        ("/access/", "access"),
        ("/meetings/", "meetings"),
        ("/gbrain/", "gbrain"),
    ];
    for (p, purpose) in prefixed {
        if path.starts_with(p) {
            return purpose;
        }
    }
    if path == "/apply/pending" || path.starts_with("/apply/pending?") {
        return "apply-read";
    }
    if path == "/apply/ticket" {
        return "apply-ticket";
    }
    let prefixed = [
        ("/templates/check/", "template-check"),
        ("/templates/repair/", "template-repair"),
        ("/templates/capture/", "template-capture"),
        ("/disk/", "disk"),
        ("/health/", "health"),
    ];
    for (p, purpose) in prefixed {
        if path.starts_with(p) {
            return purpose;
        }
    }
    "channels"
}

/// The real client: the identity map for the address, the box key for the token.
pub struct AgentClient {
    keys: KeysDir,
    box_id: String,
    http: HttpClient,
    identities: Arc<dyn Fn() -> Option<Arc<dyn IdentityMap>> + Send + Sync>,
}

impl AgentClient {
    pub fn new(
        keys: KeysDir,
        box_id: &str,
        identities: Arc<dyn Fn() -> Option<Arc<dyn IdentityMap>> + Send + Sync>,
    ) -> Result<Self, String> {
        // Never followed: the token is for this host, and a redirect is not an answer.
        let http = HttpClient::new(false).map_err(|e| e.to_string())?;
        Ok(Self {
            keys,
            box_id: box_id.to_string(),
            http,
            identities,
        })
    }

    /// `agentHostFor`, as every TS agent client has it: the brain too (its model is pushed through
    /// here), and a pinned host. `agent()` alone left the brain unknown (seen on a customer's agent, 2026-10-29).
    fn route_for(&self, vm_id: &str) -> Option<AgentRoute> {
        (self.identities)()?.route_for(vm_id)
    }

    async fn request(
        &self,
        target: Target,
        method: &'static str,
        path: String,
        body: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<Map<String, Value>, AgentError> {
        let budget = timeout.unwrap_or_else(|| timeout_for(&path));
        let bounded = path == "/hooks/deliver" || path.starts_with("/phone/");
        // An agent the map does not have may have been created seconds ago: one look at the
        // console's list (`onUnknown: learnAgents`, at most once a while), then ask the map again.
        let mut route = self.route_for(&target.vm_id);
        if route.is_none()
            && let Some(core) = crate::core::core()
        {
            core.learn_agents().await;
            route = self.route_for(&target.vm_id);
        }
        let Some(route) = route else {
            return Err(AgentError::new(UNKNOWN_AGENT));
        };
        let sent = body.map(|b| serde_json::to_vec(&b).unwrap_or_default());
        let claims = cc_auth::sign::binding_claims(method, &path, Some(&route.host), sent.as_deref());
        let token =
            cc_auth::sign::agent_token(&self.keys, &self.box_id, &target.vm_id, purpose_for_path(&path), claims)
                .map_err(|e| AgentError::new(e.to_string()))?;
        let url = format!("{}{path}", route.base);
        let client = self.http.get();
        let mut req = if method == "POST" {
            client.post(&url)
        } else {
            client.get(&url)
        };
        req = req.bearer_auth(token).timeout(budget);
        if let Some(sent) = sent {
            req = req.header("content-type", "application/json").body(sent);
        }
        let res = match req.send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Err(AgentError::timeout()),
            // What Node's fetch says for every network failure.
            Err(_) => return Err(AgentError::new("fetch failed")),
        };
        let status = res.status().as_u16();
        let raw = if bounded {
            let mut res = res;
            let mut buf: Vec<u8> = Vec::new();
            loop {
                match res.chunk().await {
                    Ok(Some(c)) => {
                        buf.extend_from_slice(&c);
                        if buf.len() > BOUNDED_MAX {
                            return Err(AgentError::new("agent response too large"));
                        }
                    }
                    Ok(None) => break,
                    Err(e) if e.is_timeout() => return Err(AgentError::timeout()),
                    Err(_) => return Err(AgentError::new("terminated")),
                }
            }
            match String::from_utf8(buf) {
                Ok(s) => s,
                Err(_) => return Err(AgentError::new("The encoded data was not valid for encoding utf-8")),
            }
        } else {
            match res.text().await {
                Ok(t) => t,
                Err(e) if e.is_timeout() => return Err(AgentError::timeout()),
                Err(_) => return Err(AgentError::new("terminated")),
            }
        };
        let parsed: Map<String, Value> = if raw.is_empty() {
            Map::new()
        } else {
            serde_json::from_str::<Value>(&raw)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default()
        };
        if !(200..300).contains(&status) {
            if status == 503 {
                return Err(AgentError::new(NOT_RUNNING));
            }
            let detail = match parsed.get("error") {
                Some(Value::String(s)) => s.clone(),
                _ => raw.chars().take(200).collect(),
            };
            return Err(AgentError::new(format!("agent {status}: {detail}")));
        }
        Ok(parsed)
    }
}

impl AgentCalls for Arc<AgentClient> {
    fn post(
        &self,
        target: &Target,
        path: &str,
        body: Value,
        timeout: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        let me = self.clone();
        let (target, path) = (target.clone(), path.to_string());
        Box::pin(async move { me.request(target, "POST", path, Some(body), timeout).await })
    }

    fn get(
        &self,
        target: &Target,
        path: &str,
        timeout: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        let me = self.clone();
        let (target, path) = (target.clone(), path.to_string());
        Box::pin(async move { me.request(target, "GET", path, None, timeout).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_follow_the_path() {
        assert_eq!(purpose_for_path("/llm/apply"), "llm");
        assert_eq!(purpose_for_path("/channels/send"), "channels");
        assert_eq!(purpose_for_path("/update"), "update");
        assert_eq!(purpose_for_path("/updates"), "channels");
        assert_eq!(purpose_for_path("/apply/pending?x=1"), "apply-read");
        assert_eq!(purpose_for_path("/mcp-servers/apply"), "mcp-servers");
        assert_eq!(purpose_for_path("/health/summary"), "health");
    }

    #[test]
    fn refusals_are_400_and_500_only() {
        assert!(AgentError::new("agent 500: boom").refused());
        assert!(AgentError::new("agent 400: no").refused());
        assert!(!AgentError::new(NOT_RUNNING).refused());
        assert!(!AgentError::new("agent 502: bad").refused());
        assert!(!AgentError::timeout().refused());
    }

    #[test]
    fn budgets() {
        assert_eq!(timeout_for("/channels/apply"), Duration::from_millis(45_000));
        assert_eq!(timeout_for("/meetings/apply"), Duration::from_millis(90_000));
        assert_eq!(timeout_for("/llm/apply"), Duration::from_millis(25_000));
    }
}
