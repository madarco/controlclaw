//! The firewall's command actions: every action the firewall agent registers, its scope, and for
//! the actions a local control plane also sends, the payload's type. The spec is
//! docs/standalone/control-plane-contract.md; the firewall agent's tests check that this table and
//! the registry agree.
//!
//! The payload types describe what the handlers read today (`p.get(...)` in
//! `rust/bins/mitm-agent/src`). They do not replace that parsing: the handlers still take the raw
//! map. Each type keeps unknown fields (`extra`), and a field a handler can do without is an
//! `Option`, so a payload the firewall accepts always parses here.

use serde::{Deserialize, Serialize};

use crate::Extra;

pub mod agentmail;
pub mod ai;
pub mod apps;
pub mod autoapprove;
pub mod channels;
pub mod connectors;
pub mod drive;
pub mod email;
pub mod exit;
pub mod google;
pub mod health;
pub mod kill;
pub mod llm;
pub mod logins;
pub mod mcp;
pub mod rules;
pub mod search;
pub mod secrets;

/// Who sends an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Any control plane: the SaaS console and the local one in a standalone firewall.
    Both,
    /// Only the SaaS console. A standalone firewall registers it but nothing sends it.
    SaasOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSpec {
    pub action: &'static str,
    pub scope: Scope,
    /// The payload type's path under this module, for actions scoped [`Scope::Both`].
    pub payload: Option<&'static str>,
}

/// The proxy service actions the control channel runs itself (`sudo systemctl <action>`), with an
/// empty payload. Both control planes send them.
pub const SERVICE_ACTIONS: &[&str] = &["restart", "start", "stop"];

/// `{changeId, code}`: the second step of a change that needed a confirmation code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confirm {
    pub change_id: String,
    /// The code as typed; spaces are dropped by the firewall.
    #[serde(default)]
    pub code: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `{changeId?}`: drop the change waiting for a code (any change of the scope when absent).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `{changeId}`: drop the change waiting for a code, where the handler needs to be told which.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRef {
    pub change_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

/// A payload with no fields the handler reads (`{}`; anything else is kept and ignored).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Empty {
    #[serde(flatten)]
    pub extra: Extra,
}

/// Why [`check`] refused a payload.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("no such action")]
    Unknown,
    #[error("payload does not match: {0}")]
    Payload(#[from] serde_json::Error),
}

macro_rules! actions {
    ($( $name:literal => $scope:ident $( ($ty:path) )? ),* $(,)?) => {
        /// Every action the firewall agent registers, sorted by name. `start`, `stop` and
        /// `restart` are not here: the control channel runs them itself.
        pub const ACTIONS: &[ActionSpec] = &[
            $( ActionSpec { action: $name, scope: Scope::$scope, payload: actions!(@name $($ty)?) } ),*
        ];

        /// Parse `payload` as `action`'s type. A SaaS-only action has no type here, so any
        /// object passes.
        pub fn check(action: &str, payload: &serde_json::Value) -> Result<(), CheckError> {
            match action {
                "start" | "stop" | "restart" => actions!(@check payload Empty),
                $( $name => actions!(@check payload $($ty)?), )*
                _ => Err(CheckError::Unknown),
            }
        }
    };
    (@name) => { None };
    (@name $ty:path) => { Some(stringify!($ty)) };
    (@check $p:ident) => { Ok(()) };
    (@check $p:ident $ty:path) => {
        serde_json::from_value::<$ty>($p.clone()).map(|_| ()).map_err(CheckError::Payload)
    };
}

actions! {
    "access.revoke" => SaasOnly,
    "access.revoke_all" => SaasOnly,
    "agentmail.attach" => Both(agentmail::Attach),
    "agentmail.check" => Both(agentmail::Check),
    "agentmail.claim" => Both(agentmail::Claim),
    "agentmail.create" => Both(agentmail::Create),
    "agentmail.delete" => Both(agentmail::Delete),
    "agentmail.forget" => Both(agentmail::Forget),
    "agentmail.import" => Both(agentmail::Import),
    "agentmail.push" => Both(agentmail::Push),
    "agentmail.read" => Both(Empty),
    "agentmail.senders" => Both(agentmail::Senders),
    "agentmail.signup" => Both(agentmail::Signup),
    "ai.scan" => Both(Empty),
    "apply.cancel" => SaasOnly,
    "apply.confirm" => SaasOnly,
    "apply.propose" => SaasOnly,
    "apps.cancel" => Both(ChangeRef),
    "apps.confirm" => Both(Confirm),
    "apps.propose" => Both(apps::Propose),
    "apps.read" => Both(Empty),
    "auto-update.cancel" => SaasOnly,
    "auto-update.confirm" => SaasOnly,
    "auto-update.disable" => SaasOnly,
    "auto-update.propose" => SaasOnly,
    "autoapprove.cancel" => Both(ChangeRef),
    "autoapprove.confirm" => Both(Confirm),
    "autoapprove.propose" => Both(autoapprove::Propose),
    "autoapprove.read" => Both(Empty),
    "backup.firewall-restore" => SaasOnly,
    "backup.firewall-restore.cancel" => SaasOnly,
    "backup.firewall-restore.confirm" => SaasOnly,
    "backup.firewall-run" => SaasOnly,
    "backup.recovery.cancel" => SaasOnly,
    "backup.recovery.confirm" => SaasOnly,
    "backup.recovery.propose" => SaasOnly,
    "backup.recovery.rebind" => SaasOnly,
    "backup.restore.cancel" => SaasOnly,
    "backup.restore.confirm" => SaasOnly,
    "backup.restore.propose" => SaasOnly,
    "backup.run" => SaasOnly,
    "channels.cancel" => Both(Cancel),
    "channels.confirm" => Both(Confirm),
    "channels.propose" => Both(channels::Propose),
    "channels.push" => Both(channels::Push),
    "channels.read" => Both(Empty),
    "connectors.callback" => Both(connectors::Callback),
    "connectors.cancel" => Both(Cancel),
    "connectors.confirm" => Both(Confirm),
    "connectors.forget" => Both(connectors::Forget),
    "connectors.propose" => Both(connectors::Propose),
    "connectors.push" => Both(connectors::Push),
    "connectors.read" => Both(connectors::Read),
    "devices.cancel" => SaasOnly,
    "devices.confirm" => SaasOnly,
    "devices.propose" => SaasOnly,
    "doctor.confirm" => SaasOnly,
    "doctor.propose" => SaasOnly,
    "doctor.stop" => SaasOnly,
    "drive.cancel" => Both(Cancel),
    "drive.confirm" => Both(Confirm),
    "drive.propose" => Both(drive::Propose),
    "drive.push" => Both(drive::Push),
    "drive.read" => Both(Empty),
    "email.cancel" => Both(ChangeRef),
    "email.confirm" => Both(Confirm),
    "email.propose" => Both(email::Propose),
    "email.read" => Both(Empty),
    "exit.cancel" => Both(Cancel),
    "exit.check" => Both(Empty),
    "exit.confirm" => Both(Confirm),
    "exit.propose" => Both(exit::Propose),
    "firewall-update.cancel" => SaasOnly,
    "firewall-update.confirm" => SaasOnly,
    "firewall-update.propose" => SaasOnly,
    "gbrain.cancel" => SaasOnly,
    "gbrain.confirm" => SaasOnly,
    "gbrain.disconnect" => SaasOnly,
    "gbrain.propose" => SaasOnly,
    "google.callback" => Both(google::Callback),
    "google.cancel" => Both(Cancel),
    "google.confirm" => Both(Confirm),
    "google.forget" => Both(google::Forget),
    "google.propose" => Both(google::Propose),
    "google.push" => Both(google::Push),
    "google.read" => Both(Empty),
    "health.probe" => Both(health::Probe),
    "kill.cancel" => Both(kill::Cancel),
    "kill.confirm" => Both(kill::Confirm),
    "kill.engage" => Both(kill::Engage),
    "kill.release" => Both(kill::Release),
    "llm.cancel" => Both(Cancel),
    "llm.confirm" => Both(Confirm),
    "llm.propose" => Both(llm::Propose),
    "llm.push" => Both(llm::Push),
    "logins.1password_disconnect" => Both(Empty),
    "logins.1password_sync" => Both(Empty),
    "logins.cancel" => Both(logins::Cancel),
    "logins.confirm" => Both(logins::Confirm),
    "logins.propose" => Both(logins::Propose),
    "logins.read" => Both(Empty),
    "mcpcatalog.read" => Both(Empty),
    "mcpservers.callback" => Both(mcp::Callback),
    "mcpservers.cancel" => Both(Cancel),
    "mcpservers.confirm" => Both(Confirm),
    "mcpservers.forget" => Both(mcp::Forget),
    "mcpservers.propose" => Both(mcp::Propose),
    "mcpservers.push" => Both(mcp::Push),
    "mcpservers.read" => Both(Empty),
    "mcpservers.tools" => Both(mcp::Tools),
    "meetings.cancel" => SaasOnly,
    "meetings.confirm" => SaasOnly,
    "meetings.propose" => SaasOnly,
    "meetings.push" => SaasOnly,
    "phone.cancel" => SaasOnly,
    "phone.confirm" => SaasOnly,
    "phone.disconnect" => SaasOnly,
    "phone.forget" => SaasOnly,
    "phone.propose" => SaasOnly,
    "phone.push" => SaasOnly,
    "phone.read" => SaasOnly,
    "phone.unassign" => SaasOnly,
    "rules.cancel" => Both(ChangeRef),
    "rules.confirm" => Both(Confirm),
    "rules.propose" => Both(rules::Propose),
    "rules.read" => Both(Empty),
    "rules.try" => Both(rules::Try),
    "search.cancel" => Both(Cancel),
    "search.confirm" => Both(Confirm),
    "search.forget" => Both(search::Forget),
    "search.propose" => Both(search::Propose),
    "search.push" => Both(search::Push),
    "secrets.cancel" => Both(secrets::Cancel),
    "secrets.confirm" => Both(secrets::Confirm),
    "secrets.propose" => Both(secrets::Propose),
    "secrets.read" => Both(Empty),
    "secrets.retry" => Both(secrets::Retry),
    "ssh.cancel" => SaasOnly,
    "ssh.close" => SaasOnly,
    "ssh.confirm" => SaasOnly,
    "ssh.propose" => SaasOnly,
    "tailscale.cancel" => SaasOnly,
    "tailscale.confirm" => SaasOnly,
    "tailscale.propose" => SaasOnly,
    "teamchat.cancel" => SaasOnly,
    "teamchat.confirm" => SaasOnly,
    "teamchat.disable" => SaasOnly,
    "teamchat.forget" => SaasOnly,
    "teamchat.propose" => SaasOnly,
    "teamchat.push" => SaasOnly,
    "tplcheck.cancel" => SaasOnly,
    "tplcheck.confirm" => SaasOnly,
    "tplcheck.propose" => SaasOnly,
    "update-all.apply" => SaasOnly,
    "update-all.auto" => SaasOnly,
    "update-all.cancel" => SaasOnly,
    "update-all.confirm" => SaasOnly,
    "update-all.propose" => SaasOnly,
    "update.cancel" => SaasOnly,
    "update.confirm" => SaasOnly,
    "update.propose" => SaasOnly,
    "webhook.cancel" => SaasOnly,
    "webhook.confirm" => SaasOnly,
    "webhook.forget" => SaasOnly,
    "webhook.propose" => SaasOnly,
    "webhook.read" => SaasOnly,
    "webhook.sync" => SaasOnly,
}

#[cfg(test)]
mod tests;
