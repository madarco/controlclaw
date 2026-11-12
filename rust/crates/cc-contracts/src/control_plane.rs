//! What the firewall agent sends a control plane and what comes back: the bodies of the
//! `/api/vm-agent/*` endpoints it calls. The SaaS console and a standalone firewall's local control
//! plane answer the same contract; the spec is docs/standalone/control-plane-contract.md, and the
//! cases under `rust/conformance/cases/cp` check both against it.
//!
//! As everywhere in this crate, unknown fields are kept (`extra`), so a body read and written again
//! loses nothing. Each endpoint's scope is in [`ENDPOINTS`].

use serde::{Deserialize, Serialize};

use crate::commands::Scope;
use crate::{Extra, Num};

/// One endpoint of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    /// After the control plane's origin.
    pub path: &'static str,
    pub methods: &'static [&'static str],
    pub scope: Scope,
}

/// Every endpoint the firewall agent calls.
pub const ENDPOINTS: &[Endpoint] = &[
    Endpoint {
        path: "/api/vm-agent/firewall",
        methods: &["POST"],
        scope: Scope::Both,
    },
    Endpoint {
        path: "/api/vm-agent/egress-rules",
        methods: &["GET", "POST"],
        scope: Scope::Both,
    },
    Endpoint {
        path: "/api/vm-agent/identities",
        methods: &["GET"],
        scope: Scope::Both,
    },
    Endpoint {
        path: "/api/vm-agent/permission",
        methods: &["GET", "POST"],
        scope: Scope::Both,
    },
    Endpoint {
        path: "/api/vm-agent/activity",
        methods: &["POST"],
        scope: Scope::Both,
    },
    Endpoint {
        path: "/api/vm-agent/ca",
        methods: &["GET", "POST"],
        scope: Scope::Both,
    },
    Endpoint {
        path: "/api/vm-agent/store",
        methods: &["GET", "POST"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/vm-agent/webhooks",
        methods: &["GET"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/vm-agent/doctor",
        methods: &["POST"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/vm-agent/template-proposal",
        methods: &["POST"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/vm-agent/template-capture-draft",
        methods: &["POST"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/vm-agent/register",
        methods: &["POST"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/vm-agent/ready",
        methods: &["POST"],
        scope: Scope::SaasOnly,
    },
    Endpoint {
        path: "/api/mcp/agent",
        methods: &["POST"],
        scope: Scope::SaasOnly,
    },
];

/// `{"error": "..."}`, the body of every refusal (401, 403, 400, 404, 409).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ErrorReply {
    pub error: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- POST /firewall: the heartbeat ----

/// The proxy service as `systemctl is-active controlclaw-mitmproxy` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyState {
    Active,
    Inactive,
    Failed,
}

/// The beat, every few seconds. Each module adds its own fields ([`BEAT_FIELDS`]); they are kept in
/// `fields`. A control plane must not refuse a beat for a field it cannot read: it is the
/// firewall's only channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub proxy: ProxyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_s: Option<u64>,
    /// Results of commands since the last beat, at most 20; also reports a module makes on its own
    /// (a `command_id` with a prefix such as `llm.refresh:`, no command behind it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<CommandResult>>,
    #[serde(flatten)]
    pub fields: Extra,
}

/// How a command went. `status` is the service state for `start|stop|restart`, otherwise the
/// module's outcome (`applied`, `awaiting_code`, `invalid_code`, `failed`, ...).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: String,
    pub ok: bool,
    pub status: String,
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Extra>,
}

/// The answer to a beat: at most one command, handed out once.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatReply {
    pub command: Option<Command>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    /// An action of [`crate::commands::ACTIONS`], or `start|stop|restart`.
    pub action: String,
    #[serde(default)]
    pub payload: Extra,
}

/// The fields modules add to the beat, and who reads them.
pub const BEAT_FIELDS: &[(&str, Scope)] = &[
    ("access", Scope::SaasOnly),
    ("agentmail", Scope::Both),
    ("agents_moved", Scope::Both),
    ("agents_reach", Scope::Both),
    ("auto_approve", Scope::Both),
    ("auto_update", Scope::SaasOnly),
    ("backup", Scope::SaasOnly),
    ("code_recipients", Scope::Both),
    ("disk_reseal", Scope::SaasOnly),
    ("doctor_keys", Scope::SaasOnly),
    ("features", Scope::Both),
    ("included_ai", Scope::SaasOnly),
    ("inventory", Scope::SaasOnly),
    ("kill", Scope::Both),
    ("phone", Scope::SaasOnly),
    ("residential", Scope::Both),
    ("software", Scope::Both),
    ("stores", Scope::Both),
    ("team_chat", Scope::SaasOnly),
    ("template_checks", Scope::SaasOnly),
    ("update", Scope::SaasOnly),
];

// ---- GET|POST /egress-rules ----

/// The organization's enabled rules by priority (each rule as the proxy reads it), and the AI
/// review settings, `null` when it is off.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EgressRulesReply {
    pub rules: Vec<crate::rules::Rule>,
    #[serde(default)]
    pub ai: Option<AiSettings>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// `egress_ai_settings` with the key it uses; the key itself is in the firewall's LLM store.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiSettings {
    pub credential_id: String,
    pub provider: String,
    #[serde(default)]
    pub model: Option<String>,
    /// The inline review of requests.
    #[serde(default)]
    pub checks: bool,
    /// AI Log Review, the scan of past traffic.
    #[serde(default)]
    pub log_review: bool,
    #[serde(default)]
    pub daily_call_cap: Option<Num>,
    #[serde(default)]
    pub scan_interval_hours: Option<Num>,
    #[serde(default)]
    pub auto_approve_per_hour: Option<Num>,
    #[serde(default)]
    pub request_instructions: Option<String>,
    #[serde(default)]
    pub review_instructions: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- GET /identities ----

/// The organization's agents with a private address: how the firewall knows who sent a request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IdentitiesReply {
    pub identities: Vec<AgentIdentity>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub vm_id: String,
    pub private_ip: String,
    pub name: String,
    /// Where the firewall reaches the agent's vm-agent (channel pushes, health).
    #[serde(default)]
    pub hostname: Option<String>,
    /// The agent's pages for people (`<handle>.<domain>`).
    #[serde(default)]
    pub access_hostname: Option<String>,
    pub status: String,
    /// `openclaw` or `gbrain`.
    pub role: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- /permission ----

/// POST: ask a person. Idempotent on `permission_id`. A firewall raises `access`, `email_recipient`
/// and `app_call`; an agent `exec`, `plugin`, `system` and `meeting_request`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionRaise {
    pub permission_id: String,
    /// `access` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// `METHOD host/path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The agent the ask is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_vm_id: Option<String>,
    /// ISO time; none means the control plane's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// `email_recipient`, `app_call`, the AI review's reason and the rest are kept here.
    #[serde(flatten)]
    pub extra: Extra,
}

/// POST: a request the box settled itself.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionResolution {
    pub permission_id: String,
    /// `approved`, `denied`, `expired` or `revoked`.
    pub resolution: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
}

/// The answer to both POSTs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionAck {
    pub ok: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deduped: Option<bool>,
}

/// GET `?permission_id=`: where the request is. `unknown` for an id the box may not read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionStatus {
    /// `pending`, `approved`, `denied`, `expired`, `revoked`, `unknown`, or `approved_on_box` (an
    /// approval the agent settled itself, never one to carry out).
    pub status: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub always_allowed: bool,
    /// An approved email recipient: until when.
    #[serde(default)]
    pub valid_until: Option<String>,
}

/// GET with no id: this box's open requests (what `cc-perm --pending` lists).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermissionPending {
    pub pending: Vec<PendingRequest>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PendingRequest {
    pub permission_id: String,
    pub summary: String,
    pub created_at: String,
}

// ---- POST /activity ----

/// At most 500 records, at least one. Each has a `source` (`egress` when absent, for traffic),
/// and the control plane drops a duplicate by its id (`flow_id` for traffic).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActivityBatch {
    pub records: Vec<Extra>,
}

/// The sources a firewall ships, and who stores them.
pub const ACTIVITY_SOURCES: &[(&str, Scope)] = &[
    ("ai_review", Scope::Both),
    ("connector_call", Scope::Both),
    ("connector_run", Scope::Both),
    ("content_rule", Scope::Both),
    ("egress", Scope::Both),
    ("email_held", Scope::Both),
    ("ssh_login", Scope::SaasOnly),
    ("teamchat_stats", Scope::SaasOnly),
    ("webhook", Scope::SaasOnly),
];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActivityAck {
    pub accepted: u64,
    pub duplicates: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

// ---- /ca ----

/// POST: the firewall publishes its CA, signed with its own key so the control plane cannot swap it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CaPublish {
    /// PEM.
    pub ca_cert: String,
    /// Ed25519 over the PEM with the firewall's key, base64.
    pub ca_sig: String,
    /// The Doctor's SSH key and its signature (SaaS only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor_ssh_pub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor_ssh_sig: Option<String>,
}

/// GET, by an agent: the CA to trust and the firewall key that signed it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaReply {
    pub ca_cert: Option<String>,
    pub ca_sig: Option<String>,
    pub pub_key: Option<String>,
    pub private_ip: Option<String>,
    #[serde(rename = "doctor_ssh_pub", default)]
    pub doctor_ssh_pub: Option<String>,
    #[serde(rename = "doctor_ssh_sig", default)]
    pub doctor_ssh_sig: Option<String>,
}

// ---- GET /webhooks (SaaS only) ----

/// The live webhook registrations: ids, `enabled`, a name and limits. Never a target or a secret.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WebhooksReply {
    pub hooks: Vec<Extra>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_beat_keeps_the_module_fields() {
        let v = json!({
            "proxy": "active", "uptime_s": 8, "kill": {"org": null},
            "results": [{"command_id": "c1", "ok": true, "status": "active", "message": "restarted"}]
        });
        let b: Heartbeat = serde_json::from_value(v.clone()).expect("beat");
        assert_eq!(b.proxy, ProxyState::Active);
        assert!(b.fields.contains_key("kill"));
        assert_eq!(serde_json::to_value(&b).expect("json"), v);
    }

    #[test]
    fn the_endpoints_are_unique() {
        let mut paths: Vec<_> = ENDPOINTS.iter().map(|e| e.path).collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), ENDPOINTS.len());
        assert!(BEAT_FIELDS.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
