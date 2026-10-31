//! The environment the core reads, with the TS defaults (`index.ts:124-305`). `main` reads the few
//! every part shares into [`crate::app::Config`]; the rest of the core's are here.

use std::path::PathBuf;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// `parseInt(process.env.X ?? "<default>", 10)`: leading digits; the default when there are none.
fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| {
            v.trim()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap_or(default)
}

/// Where a standalone firewall keeps its files when `STATE_DIR` is not set.
pub const STANDALONE_STATE_DIR: &str = "/opt/controlclaw/state";

/// What reaches a control plane. A standalone firewall takes none of them as an address: each is
/// unset, a `file:` path or a `local:` endpoint (`main` refuses the rest).
pub const CONTROL_PLANE_VARS: &[&str] = &[
    "FIREWALL_URL",
    "STORE_URL",
    "RULES_URL",
    "IDENTITIES_URL",
    "WEBHOOKS_URL",
    "PERMISSION_URL",
    "CA_URL",
    "ACTIVITY_URL",
    "MIGRATE_FROM_URL",
    "CONTROLPLANE_MCP_URL",
];

pub use cc_client::local::is_local;

#[derive(Debug, Clone)]
pub struct CoreEnv {
    pub store_url: String,
    pub rules_url: String,
    pub identities_url: String,
    pub webhooks_url: String,
    pub ca_cert_path: String,
    pub ca_url: String,
    pub permission_url: String,
    pub pending_path: String,
    pub grants_path: PathBuf,
    pub permission_poll_ms: u64,
    pub permission_ttl: u64,
    pub activity_url: String,
    pub traffic_log_path: String,
    pub activity_cursor_path: PathBuf,
    pub activity_poll_ms: u64,
    pub sync_interval_ms: u64,
    pub sync_once: bool,
    pub ship_once: bool,
    pub migrate_from_url: String,
    pub master_password: String,
    pub migrate_source_box_id: String,
}

impl CoreEnv {
    pub fn from_env(proxy_config_dir: &std::path::Path) -> Self {
        let traffic_log_path = env_or("TRAFFIC_LOG_PATH", "");
        // Standalone: the firewall's own control plane (`cc-local`) answers the rules, the identity
        // map, permission requests, activity and the CA; the store is a file in the state folder.
        // A variable that is set wins (a `file:` path, as before the local control plane).
        let standalone = crate::app::Mode::from_env().is_ok_and(crate::app::Mode::standalone);
        let state = env_or("STATE_DIR", STANDALONE_STATE_DIR);
        let url = |name: &str, standalone_default: String| match env_or(name, "") {
            v if v.is_empty() && standalone => standalone_default,
            v => v,
        };
        let local = |endpoint: &str| format!("local:/api/vm-agent/{endpoint}");
        Self {
            store_url: url("STORE_URL", format!("file:{state}/store.json")),
            rules_url: url("RULES_URL", local("egress-rules")),
            identities_url: url("IDENTITIES_URL", local("identities")),
            webhooks_url: env_or("WEBHOOKS_URL", ""),
            ca_cert_path: env_or("CA_CERT_PATH", ""),
            ca_url: url("CA_URL", local("ca")),
            permission_url: url("PERMISSION_URL", local("permission")),
            // The proxy's asks: next to its other files unless named (the console's unit names it).
            pending_path: url(
                "PENDING_PATH",
                proxy_config_dir.join("pending.jsonl").display().to_string(),
            ),
            grants_path: std::env::var("GRANTS_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| proxy_config_dir.join("grants.json")),
            permission_poll_ms: env_num("PERMISSION_POLL_MS", 3000),
            permission_ttl: env_num("PERMISSION_TTL", 300),
            activity_url: url("ACTIVITY_URL", local("activity")),
            activity_cursor_path: std::env::var("ACTIVITY_CURSOR_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(format!("{traffic_log_path}.cursor"))),
            traffic_log_path,
            activity_poll_ms: env_num("ACTIVITY_POLL_MS", 5000),
            sync_interval_ms: env_num("SYNC_INTERVAL_MS", 60_000),
            sync_once: std::env::var("SYNC_ONCE").as_deref() == Ok("1"),
            ship_once: std::env::var("SHIP_ONCE").as_deref() == Ok("1"),
            migrate_from_url: env_or("MIGRATE_FROM_URL", ""),
            master_password: env_or("MASTER_PASSWORD", ""),
            migrate_source_box_id: env_or("MIGRATE_SOURCE_BOX_ID", ""),
        }
    }

    /// `usesHttp`: whether any control-plane URL is HTTP, so outbound calls carry a box token. A
    /// `local:` one counts too: the parts that talk to a control plane (the permission bridge, the
    /// activity shipper) run, and `StoreClient` answers it in process, unsigned.
    pub fn uses_http(&self, firewall_url: &str) -> bool {
        [&self.store_url, &self.rules_url, &self.activity_url]
            .iter()
            .any(|u| u.starts_with("http") || is_local(u))
            || firewall_url.starts_with("http")
    }
}
