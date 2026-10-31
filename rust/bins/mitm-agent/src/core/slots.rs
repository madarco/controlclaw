//! W3's providers for the contract slots other workstreams read (`contracts.rs`): the agent
//! client, the emergency stop, the approvals, the credentials sync, the firewall's secrets, its
//! pages' frame, who opened one of its pages, and its Logs reader.

use std::sync::Arc;

use cc_http::BoxFuture;
use serde_json::{Map, Value};

use super::Core;
use super::access::{AccessFirewall, Authorized};
use super::agent_client::AgentTarget;
use super::fw_logs::FwLogsReader;
use super::fw_shell::{FwPage, fw_content, fw_minimal_page, fw_notice, fw_shell_page};
use super::grants::{GrantStore, now_s};
use super::sync::KillLocks;
use crate::contracts;

/// `makeAgentClient`: the address is the client's to find, from the identity map.
pub struct Agents(pub super::agent_client::AgentClient);

fn agent_error(e: super::agent_client::AgentError) -> contracts::AgentError {
    contracts::AgentError {
        timed_out: e.is_timeout(),
        message: e.to_string(),
    }
}

impl contracts::AgentClient for Agents {
    fn post(
        &self,
        vm_id: &str,
        path: &str,
        body: Value,
    ) -> BoxFuture<Result<Map<String, Value>, contracts::AgentError>> {
        let (c, target, path) = (self.0.clone(), AgentTarget::new(vm_id, ""), path.to_string());
        Box::pin(async move { c.post(&target, &path, &body).await.map_err(agent_error) })
    }

    fn get(&self, vm_id: &str, path: &str) -> BoxFuture<Result<Map<String, Value>, contracts::AgentError>> {
        let (c, target, path) = (self.0.clone(), AgentTarget::new(vm_id, ""), path.to_string());
        Box::pin(async move { c.get(&target, &path).await.map_err(agent_error) })
    }
}

/// `lockedVmIds`: the agent is under its own stop or the organization's.
pub struct Stop(pub Arc<dyn KillLocks>);

impl contracts::EmergencyStop for Stop {
    fn locked(&self, vm_id: &str) -> bool {
        self.0.locked_vm_ids(&[vm_id.to_string()]).iter().any(|v| v == vm_id)
    }
}

/// `grants.ts`: an approval is used once.
pub struct Grants(pub Arc<GrantStore>);

impl contracts::PermissionGrants for Grants {
    fn active(&self, permission_id: &str) -> bool {
        self.0.active(permission_id, now_s())
    }

    fn consume(&self, permission_id: &str) {
        self.0.delete(permission_id);
    }
}

/// `onCredentialsChanged`: the credentials written again at once from the last config, then a
/// sync in the background, whose failure is only logged (`index.ts` writes first, then syncs). A
/// command that changed a login does not wait on the control plane.
pub struct CredentialsSync(pub Arc<Core>);

impl contracts::CredentialsSync for CredentialsSync {
    fn changed(&self) -> BoxFuture<()> {
        let core = self.0.clone();
        Box::pin(async move {
            if let Err(e) = core.sync.write_credentials_now() {
                tracing::error!("[mitm-agent] could not write the credentials after a change: {e}");
            }
            tokio::spawn(async move {
                if let Err(e) = core.sync.run().await {
                    tracing::error!("[mitm-agent] sync after a credentials change failed: {e}");
                }
            });
        })
    }
}

/// `firewallSecrets`.
pub struct Secrets(pub Arc<Core>);

impl contracts::FirewallSecrets for Secrets {
    fn values(&self) -> Vec<String> {
        super::pages::firewall_secrets(&self.0)
    }
}

/// `fw-shell.ts`.
pub struct Shell;

fn page(active: &str) -> Option<FwPage> {
    match active {
        "logs" => Some(FwPage::Logs),
        "doctor" => Some(FwPage::Doctor),
        "logins" => Some(FwPage::Logins),
        "content" => Some(FwPage::Content),
        _ => None,
    }
}

impl contracts::FwShell for Shell {
    fn notice(&self, title: &str, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String {
        fw_notice(title, heading, text, id, script)
    }

    /// Every page passes the `consoleUrl` it worked out (`fwConsoleUrl`, `string | null`): `None` is
    /// the TS's `null`, no button.
    fn shell_page(&self, title: &str, active: &str, body: &str, console_url: Option<&str>, tail: &str) -> String {
        fw_shell_page(
            title,
            page(active),
            body,
            Some(console_url.map(str::to_string)),
            tail,
            None,
        )
    }

    fn minimal_page(&self, title: &str, body: &str, tail: &str) -> String {
        fw_minimal_page(title, body, tail)
    }

    /// `fwContent(html)`: the default, narrow. (The contract has no width; `fw_content` has.)
    fn content(&self, html: &str) -> String {
        fw_content(html, "narrow")
    }
}

/// `access.ts`: who opened one of this firewall's pages.
pub struct Pages(pub Arc<AccessFirewall>);

/// The pages about one agent (`authorizeOpen`, `authorizeDoctor`).
const OPEN_PAGES: [&str; 3] = ["doctor", "doctor-chat", "ai-review"];
/// The pages about this firewall (`authorizeTeamChat`, `authorizeLogins`, `authorizeFirewallPage`).
const FIREWALL_PAGES: [&str; 5] = ["team-chat", "logins", "firewall-logs", "doctor-start", "content-rules"];

fn header<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn person(a: Authorized) -> contracts::PagePerson {
    let mut extra = Map::new();
    extra.insert("vmId".into(), Value::String(a.vm_id));
    if let Some(s) = a.session_id {
        extra.insert("sessionId".into(), Value::String(s));
    }
    if let Some(n) = a.name {
        extra.insert("name".into(), Value::String(n));
    }
    if let Some(c) = a.doctor_choices {
        extra.insert("doctorChoices".into(), Value::Array(c));
    }
    if let Some(d) = a.doctor_agent {
        extra.insert("doctorAgent".into(), Value::String(d));
    }
    contracts::PagePerson {
        user_id: a.user_id,
        device_id: a.device_id,
        email: a.email,
        can_write: a.can_write,
        extra,
    }
}

impl contracts::PageAccess for Pages {
    fn origin(&self) -> Option<String> {
        self.0.origin()
    }

    fn authorize(
        &self,
        headers: &http::HeaderMap,
        intent: String,
        next: &str,
    ) -> BoxFuture<Option<contracts::PagePerson>> {
        let (a, next) = (self.0.clone(), next.to_string());
        let origin = header(headers, "origin").map(str::to_string);
        let cookie = header(headers, "cookie").map(str::to_string);
        Box::pin(async move {
            let (origin, cookie) = (origin.as_deref(), cookie.as_deref());
            let who = if OPEN_PAGES.contains(&next.as_str()) {
                a.authorize_open(origin, cookie, &intent, &next).await
            } else if FIREWALL_PAGES.contains(&next.as_str()) {
                a.authorize_firewall(origin, cookie, &intent, &next).await
            } else {
                // A page this firewall does not have: nobody.
                None
            };
            who.map(person)
        })
    }

    fn device_active(
        &self,
        headers: &http::HeaderMap,
        next: &str,
        user_id: &str,
        device_id: &str,
        vm_id: Option<&str>,
    ) -> bool {
        let cookie = header(headers, "cookie");
        match (next, vm_id) {
            // `deviceActive(req, userId, deviceId, vmId)`: the agent still known and not stopped.
            (n, Some(vm)) if OPEN_PAGES.contains(&n) => self.0.device_active(cookie, user_id, device_id, vm),
            // The pages about one agent always name it: without one, nothing holds.
            (n, None) if OPEN_PAGES.contains(&n) => false,
            ("logins", None) => self.0.logins_device_active(cookie, user_id, device_id),
            (n, None) if FIREWALL_PAGES.contains(&n) => self.0.firewall_device_active(cookie, user_id, device_id),
            (n, vm) => {
                tracing::warn!(
                    "[access] a grant for {n} was checked {}: refused",
                    if vm.is_some() {
                        "with an agent, which that page does not take"
                    } else {
                        "for a page this firewall does not have"
                    }
                );
                false
            }
        }
    }
}

/// `FwLogsReader.read`.
pub struct Logs(pub Arc<FwLogsReader>);

impl contracts::FwLogs for Logs {
    fn read(&self, range: &str, service: &str) -> BoxFuture<Result<Value, String>> {
        let (r, range, service) = (self.0.clone(), range.to_string(), service.to_string());
        Box::pin(async move { Ok(r.read(&range, &service).await) })
    }
}
