//! The unmanaged mode's one config file (`CC_AGENT_CONFIG`, default `/etc/controlclaw/agent.json`).
//! A box our Ansible role set up never has it: no file means managed, exactly as before.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const CONFIG_ENV: &str = "CC_AGENT_CONFIG";
pub const DEFAULT_PATH: &str = "/etc/controlclaw/agent.json";

/// The file as written. Every field but `mode` may be left out.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    pub mode: String,
    /// `host:port` the agent listens on. Default `127.0.0.1:3100`.
    #[serde(default)]
    pub listen: Option<String>,
    /// The agent's own files: session secret, box keypair, channel state. Default
    /// `$XDG_STATE_HOME/controlclaw` (`~/.local/state/controlclaw`).
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// The id the firewall gave this agent at pairing; tokens must carry it once it is set.
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default)]
    pub openclaw: OpenClawHints,
}

/// The firewall this agent answers to. Set by pairing (a later step); empty until then.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    #[serde(default)]
    pub url: Option<String>,
    /// The firewall's Ed25519 public key (SPKI PEM). It signs both the firewall's tokens and, as the
    /// control plane of a standalone setup, the console's.
    #[serde(default)]
    pub public_key: Option<String>,
    /// The names the firewall signs this agent's tokens for (`h`). Without any, a token's host is
    /// not checked.
    #[serde(default)]
    pub hostnames: Option<Vec<String>>,
    /// The only addresses that may connect (the firewall as it reaches this agent): the agent
    /// listens on a shared network or a host bridge. Without any, every address may (tokens are
    /// still required).
    #[serde(default)]
    pub allow_from: Option<Vec<std::net::IpAddr>>,
    /// The firewall's address as OpenClaw reaches it (its gates: 3900 for app connections, 3940 for
    /// MCP servers): the tunnel's, the proxy's, or a container's gate.
    #[serde(default)]
    pub gate: Option<std::net::Ipv4Addr>,
}

/// What discovery would otherwise guess.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OpenClawHints {
    /// The `openclaw` program.
    #[serde(default)]
    pub cli: Option<String>,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// `auto` (default), `systemd-user`, `systemd-system`, `docker`, `pm2` or `process`.
    #[serde(default)]
    pub runs: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub pm2_name: Option<String>,
    #[serde(default)]
    pub gateway_port: Option<u16>,
}

pub const RUNS: &[&str] = &["auto", "systemd-user", "systemd-system", "docker", "pm2", "process"];

/// The path the agent reads.
pub fn path() -> PathBuf {
    std::env::var_os(CONFIG_ENV)
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_PATH), PathBuf::from)
}

/// `Ok(None)` when there is no file (managed). A file that does not parse, or names another mode,
/// is an error: guessing would run a box the wrong way.
pub fn load(path: &Path) -> Result<Option<AgentFile>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    parse(&raw).map(Some).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn parse(raw: &str) -> Result<AgentFile, String> {
    let f: AgentFile = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    if f.mode != "unmanaged" {
        return Err(format!("mode must be \"unmanaged\", not {:?}", f.mode));
    }
    if let Some(r) = &f.openclaw.runs
        && !RUNS.contains(&r.as_str())
    {
        return Err(format!("openclaw.runs must be one of {}", RUNS.join(", ")));
    }
    if let Some(l) = &f.listen {
        parse_listen(l)?;
    }
    Ok(f)
}

/// `host:port`, with a port that is a number.
fn parse_listen(raw: &str) -> Result<(String, u16), String> {
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => match port.parse() {
            Ok(p) => Ok((host.to_string(), p)),
            Err(_) => Err(format!("listen must be host:port, not {raw:?}")),
        },
        _ => Err(format!("listen must be host:port, not {raw:?}")),
    }
}

impl AgentFile {
    /// Checked by [`parse`]; the default for a file built in code with a bad value.
    pub fn listen(&self) -> (String, u16) {
        parse_listen(self.listen.as_deref().unwrap_or("127.0.0.1:3100"))
            .unwrap_or_else(|_| ("127.0.0.1".to_string(), 3100))
    }

    pub fn state_dir(&self, home: &Path) -> PathBuf {
        if let Some(d) = &self.state_dir {
            return d.clone();
        }
        match std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            Some(x) => PathBuf::from(x).join("controlclaw"),
            None => home.join(".local/state/controlclaw"),
        }
    }

    /// [`Firewall::allow_from`], empty for every address.
    pub fn allow_from(&self) -> Vec<std::net::IpAddr> {
        self.firewall.allow_from.clone().unwrap_or_default()
    }

    /// The firewall's key, when pairing has set one.
    pub fn firewall_key(&self) -> Option<&str> {
        self.firewall
            .public_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_least_file_and_its_defaults() {
        let f = parse(r#"{"mode":"unmanaged"}"#).expect("parse");
        assert_eq!(f.listen(), ("127.0.0.1".to_string(), 3100));
        assert_eq!(f.firewall_key(), None);
        assert!(f.state_dir(Path::new("/home/u")).ends_with("controlclaw"));
    }

    #[test]
    fn a_full_file() {
        let f = parse(
            r#"{"mode":"unmanaged","listen":"0.0.0.0:3200","state_dir":"/var/lib/cc","agent_id":"a1",
                "firewall":{"url":"https://fw.example","public_key":" PEM "},
                "openclaw":{"cli":"/x/openclaw","runs":"docker","container":"oc","gateway_port":18800}}"#,
        )
        .expect("parse");
        assert_eq!(f.listen(), ("0.0.0.0".to_string(), 3200));
        assert_eq!(f.state_dir(Path::new("/home/u")), PathBuf::from("/var/lib/cc"));
        assert_eq!(f.firewall_key(), Some("PEM"));
        assert_eq!(f.openclaw.container.as_deref(), Some("oc"));
    }

    #[test]
    fn refuses_another_mode_a_typo_and_an_unknown_runs() {
        assert!(parse(r#"{"mode":"managed"}"#).is_err());
        assert!(parse(r#"{"mode":"unmanaged","firewal":{}}"#).is_err());
        assert!(parse(r#"{"mode":"unmanaged","openclaw":{"runs":"launchd"}}"#).is_err());
        for bad in ["3200", "0.0.0.0:31OO", ":3100", "host:"] {
            assert!(
                parse(&format!(r#"{{"mode":"unmanaged","listen":"{bad}"}}"#)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn no_file_is_managed() {
        let d = tempfile::tempdir().expect("dir");
        assert_eq!(load(&d.path().join("agent.json")), Ok(None));
        std::fs::write(d.path().join("bad.json"), "{").expect("write");
        assert!(load(&d.path().join("bad.json")).is_err());
    }
}
