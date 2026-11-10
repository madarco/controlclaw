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
    /// `AGENT_PORT`: 3102. Port 3100 is the firewall agent's (`docs/ops/t-vmagent-port-3102.md`).
    pub port: u16,
    /// `AGENT_LEGACY_PORT`: the same routes on a second port, 3100 while boxes move to 3102, so a
    /// caller that still dials 3100 keeps working. Off unless the unit sets it (the role does): on a
    /// standalone box 3100 is the firewall agent's, and the vm-agent must not take it first.
    pub legacy_port: Option<u16>,
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

/// `AGENT_LEGACY_PORT`: off when unset, empty, `0` or the main port itself. Anything that is not a
/// port number is off too, and said so: the unit sets it, so a bad value is a role bug.
fn legacy_port(raw: Option<&str>, main: u16) -> Option<u16> {
    let v = raw.map(str::trim).filter(|v| !v.is_empty())?;
    let Ok(p) = v.parse::<u16>() else {
        tracing::warn!("AGENT_LEGACY_PORT={v:?} is not a port; not listening on an old port");
        return None;
    };
    (p != 0 && p != main).then_some(p)
}

/// The vm-agent's port: 3100 is the firewall agent's, 3101 its AI judge and a locked box's listener.
pub const PORT: u16 = 3102;

impl Config {
    pub fn from_env() -> Self {
        let port = env_port("AGENT_PORT", PORT);
        Self {
            port,
            legacy_port: legacy_port(std::env::var("AGENT_LEGACY_PORT").ok().as_deref(), port),
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
        Self::unmanaged_from(Self::from_env(), file)
    }

    fn unmanaged_from(mut c: Self, file: &crate::unmanaged::config::AgentFile) -> Self {
        let (bind, port) = file.listen();
        let state = file.state_dir(&c.home);
        c.bind = bind;
        c.port = port;
        c.keys_dir = state.clone();
        c.state_dir = state.clone();
        c.service = "openclaw".into();
        c.pool_marker = state.join("no-pool");
        c.conformance_routes = false;
        // The old port is the managed role's transition only. Here 3100 is the firewall agent's on
        // the same machine, and the listen address and allow-list come from the config file alone.
        c.legacy_port = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_port_only_when_the_unit_asks() {
        assert_eq!(legacy_port(None, PORT), None);
        assert_eq!(legacy_port(Some("3100"), PORT), Some(3100));
        assert_eq!(legacy_port(Some(""), PORT), None);
        assert_eq!(legacy_port(Some("0"), PORT), None);
        assert_eq!(legacy_port(Some(" 3100 "), PORT), Some(3100));
        assert_eq!(legacy_port(Some("off"), PORT), None);
        assert_eq!(legacy_port(Some("3100,3101"), PORT), None);
        assert_eq!(legacy_port(Some("70000"), PORT), None);
        // Never a second listener on the main port.
        assert_eq!(legacy_port(Some("3100"), 3100), None);
        assert_eq!(legacy_port(Some("13100"), 40000), Some(13100));
    }

    #[test]
    fn an_unmanaged_agent_never_opens_the_old_port() {
        // As if the environment asked for it: the file's listen address is all an unmanaged agent has.
        let mut base = Config::from_env();
        base.legacy_port = Some(3100);
        let file = crate::unmanaged::config::parse(r#"{"mode":"unmanaged","listen":"127.0.0.1:3102"}"#).expect("parse");
        let c = Config::unmanaged_from(base, &file);
        assert_eq!((c.port, c.legacy_port), (3102, None));
    }
}
