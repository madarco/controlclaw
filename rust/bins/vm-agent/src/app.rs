//! What every part of the vm-agent shares: its settings, keys, token checks, the command runner
//! and the outbound clients. Built once in `main` and handed to each workstream's `register`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use cc_auth::console::ConsoleAuth;
use cc_auth::firewall::FirewallAuth;
use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_proc::Runner;

/// The environment the systemd unit sets (`controlclaw-agent.service`), with the TS defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub bind: String,
    pub keys_dir: PathBuf,
    pub state_dir: PathBuf,
    /// `CC_SERVICE`: `openclaw` on an agent box, `gbrain` on a brain box.
    pub service: String,
    pub gateway_port: u16,
    pub home: PathBuf,
    /// `/etc/controlclaw/pool-unclaimed`; a test can point it elsewhere.
    pub pool_marker: PathBuf,
    /// `CC_CONFORMANCE_ROUTES=1`: serve the rig's test route (`conformance_routes.rs`). Never on a box.
    pub conformance_routes: bool,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// `parseInt(x, 10)` on an env value: leading digits, else the default.
fn env_port(name: &str, default: u16) -> u16 {
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

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: env_port("AGENT_PORT", 3100),
            bind: env_or("AGENT_BIND", "127.0.0.1"),
            keys_dir: env_or("KEYS_DIR", "/opt/controlclaw/keys").into(),
            state_dir: env_or("STATE_DIR", "/opt/controlclaw/state").into(),
            service: env_or("CC_SERVICE", "openclaw"),
            gateway_port: env_port("OPENCLAW_GATEWAY_PORT", 18789),
            home: env_or("HOME", "/home/controlclaw").into(),
            pool_marker: env_or("CC_POOL_MARKER", "/etc/controlclaw/pool-unclaimed").into(),
            conformance_routes: std::env::var("CC_CONFORMANCE_ROUTES").is_ok_and(|v| v == "1"),
        }
    }

    /// Unmanaged mode: where to listen comes from the config file, and the agent's own state dir
    /// holds what `KEYS_DIR` and `STATE_DIR` hold on a managed box. No pool marker can exist there.
    pub fn unmanaged(file: &crate::unmanaged::config::AgentFile) -> Self {
        let mut c = Self::from_env();
        let (bind, port) = file.listen();
        let state = file.state_dir(&c.home);
        c.bind = bind;
        c.port = port;
        c.keys_dir = state.clone();
        c.state_dir = state.clone();
        c.service = "openclaw".into();
        c.pool_marker = state.join("no-pool");
        c.conformance_routes = false;
        c
    }
}

pub struct App {
    pub config: Config,
    pub keys: KeysDir,
    pub console_auth: ConsoleAuth,
    pub firewall_auth: FirewallAuth,
    pub runner: Arc<dyn Runner>,
    pub http: HttpClient,
    pub console: ConsoleClient,
    /// On an unclaimed pool box: whether the gateway and the certificate are ready (`poolHealthy`).
    pub pool_healthy: AtomicBool,
    /// The bootstrap reached its ready report: the CA, egress and OpenClaw's gateway (or the wait
    /// for it) are behind. Until then nothing else reports ready.
    pub bootstrap_ready: AtomicBool,
    /// What workstreams provide each other (`contracts.rs`).
    pub contracts: crate::contracts::Contracts,
    pub started: std::time::Instant,
    /// Set in unmanaged mode (`unmanaged/`): the config file and the OpenClaw install found.
    pub unmanaged: Option<Arc<crate::unmanaged::Unmanaged>>,
}
