//! What every part of the firewall agent shares, built once in `main` and handed to each
//! workstream's `register`. Workstreams keep their own state in their own folders.

use std::path::PathBuf;
use std::sync::Arc;

use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_http::Router;
use cc_proc::Runner;

use crate::commands::Commands;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
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

/// Who configures this firewall (`MITM_MODE`). `saas`, the default, is the ControlClaw console:
/// everything below is as it has always been. `standalone` is a firewall with no control plane
/// (docs/standalone/standalone-mode.md): the policy comes from files in the state folder, pages
/// open with a link the firewall signs itself, and the console's own modules stay off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Saas,
    Standalone,
}

impl Mode {
    /// `MITM_MODE`; an unknown value is `Err`, so a typo does not start a box in the wrong mode.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("MITM_MODE").unwrap_or_default().trim() {
            "" | "saas" => Ok(Mode::Saas),
            "standalone" => Ok(Mode::Standalone),
            other => Err(format!("MITM_MODE must be saas or standalone, not {other:?}")),
        }
    }

    pub fn saas(self) -> bool {
        self == Mode::Saas
    }

    pub fn standalone(self) -> bool {
        self == Mode::Standalone
    }
}

/// The environment `controlclaw-mitm-agent.service` sets (appendix D §0), with the TS defaults
/// from `index.ts:124-305`. Workstreams read the rest of theirs from the environment themselves.
#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub keys_dir: PathBuf,
    pub box_key_path: PathBuf,
    /// The address port 3100 listens on (`MITM_AGENT_LISTEN`): every address on a console
    /// firewall, whose cloud firewall closes it; loopback on a standalone one, where nothing does.
    pub listen: String,
    pub port: u16,
    pub org_id: String,
    pub box_id: String,
    pub proxy_config_dir: PathBuf,
    pub firewall_url: String,
    pub ingress_port: u16,
    pub ingress_bind: String,
    pub firewall_poll_ms: u64,
    pub agent_version: String,
    pub recovery_routes: bool,
    pub pool_marker: PathBuf,
    pub pool_peer: PathBuf,
}

impl Config {
    /// Panics on a bad `MITM_MODE`; `main` checks it first and says why.
    pub fn from_env() -> Self {
        let keys_dir: PathBuf = env_or("KEYS_DIR", "/opt/controlclaw/keys").into();
        let mode = Mode::from_env().unwrap_or_else(|e| panic!("{e}"));
        // A standalone firewall names itself: there is no console to give it an organization.
        let named = |name: &str, standalone: &str| match env_or(name, "") {
            v if v.is_empty() && mode.standalone() => standalone.to_string(),
            v => v,
        };
        Self {
            mode,
            box_key_path: std::env::var("BOX_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| keys_dir.join("box_key")),
            keys_dir,
            listen: listen_address(mode, &env_or("MITM_AGENT_LISTEN", "")),
            port: env_num("AGENT_PORT", 3100),
            org_id: named("ORG_ID", "local"),
            box_id: named("BOX_ID", "firewall"),
            proxy_config_dir: env_or("PROXY_CONFIG_DIR", "/run/mitm/config").into(),
            firewall_url: env_or("FIREWALL_URL", ""),
            ingress_port: env_num("INGRESS_PORT", 8790),
            ingress_bind: env_or("INGRESS_BIND", "127.0.0.1"),
            firewall_poll_ms: env_num("FIREWALL_POLL_MS", 5000),
            agent_version: env_or("MITM_AGENT_VERSION", "0.1.0"),
            // The recovery routes restore a backup from ControlClaw's store: off in standalone.
            recovery_routes: env_or("RECOVERY_ROUTES", if mode.standalone() { "0" } else { "1" }) != "0",
            pool_marker: env_or("CC_POOL_MARKER", "/etc/controlclaw/pool-unclaimed").into(),
            pool_peer: env_or("CC_POOL_PEER", "/etc/controlclaw/pool-peer.json").into(),
        }
    }
}

/// `MITM_AGENT_LISTEN` when set; otherwise every address (SaaS, as always) or loopback (standalone).
pub fn listen_address(mode: Mode, set: &str) -> String {
    match set.trim() {
        "" if mode.standalone() => "127.0.0.1".into(),
        "" => "0.0.0.0".into(),
        v => v.to_string(),
    }
}

pub struct App {
    pub config: Config,
    pub keys: KeysDir,
    /// The box key (base64), for every encrypted store.
    pub box_key: String,
    pub runner: Arc<dyn Runner>,
    pub http: HttpClient,
    pub console: ConsoleClient,
    /// What workstreams provide each other (`contracts.rs`).
    pub contracts: crate::contracts::Contracts,
    /// The boxes whose control-plane and backup traffic the proxy inspects (`core::cp_inspect`).
    pub cp_inspect: Arc<crate::core::cp_inspect::CpInspect>,
}

/// Where workstreams put what they serve. Their own listeners (the gates on the private address,
/// the loopback services the proxy calls) they open themselves from `register`.
pub struct Registry {
    /// Port 3100, plain HTTP (the staged archive an agent box downloads).
    pub plain: Router,
    /// Port 3100 over TLS (the recovery routes).
    pub tls: Router,
    /// `127.0.0.1:8790`, behind Caddy: pages, Open and enroll, webhooks, the phone stream.
    pub ingress: Router,
    /// Heartbeat commands, beat fields and reports.
    pub commands: Commands,
}

#[cfg(test)]
mod listen_tests {
    use super::*;

    #[test]
    fn standalone_listens_on_loopback_unless_told() {
        assert_eq!(listen_address(Mode::Saas, ""), "0.0.0.0");
        assert_eq!(listen_address(Mode::Standalone, ""), "127.0.0.1");
        assert_eq!(listen_address(Mode::Standalone, " 10.0.0.2 "), "10.0.0.2");
        assert_eq!(listen_address(Mode::Saas, "127.0.0.1"), "127.0.0.1");
    }
}
