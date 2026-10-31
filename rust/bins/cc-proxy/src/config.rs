//! The proxy's settings, read from the same environment the mitmproxy unit sets
//! (controlclaw-ansible `tasks/mitmbox.yml`, appendix F §1.1). Defaults are `addon.py`'s.
//! Owner: W1.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The dev escape hatches (addon.py `_DEV_FLAGS`). Any of them set to something other than empty
/// or `0` makes the proxy refuse to start unless `MITM_ALLOW_DEV_FLAGS=1`, which only the smoke
/// rigs set: "dev flags are off on secured boxes" is a property of the binary, not a checklist.
pub const DEV_FLAGS: &[&str] = &[
    "MITM_DEV_LOG_SECRETS",
    "MITM_DEV_ALLOW_PLAINTEXT_STORE",
    "MITM_DEV_INSECURE_UPSTREAM",
    "MITM_DEV_ALLOW_DIRECT_EGRESS",
    // `name=ip:port,…`: answers the firewall's own resolution for those names (smoke tests only).
    "MITM_DEV_RESOLVE",
    // Lets passthrough reach private (not non-routable) addresses, where rigs' stand-ins live (#511).
    "MITM_DEV_PRIVATE_PASSTHROUGH",
    // Serves intercepted traffic while the checks (W2) are not built in: the W1 rig only.
    "MITM_DEV_WITHOUT_CHECKS",
    // `sni=cidr,...`: the Meet TURN ranges a rig's stand-in lives in (tests only).
    "MITM_DEV_MEET_RANGES",
];

/// How many connections one agent may hold open at once. redsocks on the agent box holds at most
/// 2,000 (`redsocks_conn_max`); twice that leaves room and still keeps one agent from using up the
/// unit's 65,536 descriptors (each intercepted connection holds two) and cutting the others, and the
/// control plane's channel, off.
pub const DEFAULT_MAX_PER_SOURCE: usize = 4096;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub rules_path: PathBuf,
    pub credentials_path: PathBuf,
    pub identities_path: PathBuf,
    pub grants_path: PathBuf,
    pub pending_path: PathBuf,
    pub exit_path: PathBuf,
    /// Empty: no traffic log file (the addon's default).
    pub log_file: Option<PathBuf>,
    pub log_max_bytes: u64,
    pub tenant: String,
    /// The control plane: intercepted and allowed for a box's own paths (`http::backup`), passed
    /// through by SNI for a box the firewall has not seen trust its CA yet (`cp_inspect`).
    pub control_plane_host: Option<String>,
    /// The backup store: the bucket's virtual-hosted name, or (with `backup_bucket`) a path-style
    /// store's own host.
    pub backup_host: Option<String>,
    /// `MITM_BACKUP_BUCKET`: the bucket of a store that is not AWS (path-style on `backup_host`).
    pub backup_bucket: Option<String>,
    /// `org.json` (`MITM_ORG_PATH`, else next to the rules): this firewall's organisation, written
    /// by the firewall agent's sync. Backup keys must start with it.
    pub org_path: PathBuf,
    /// Exact package hosts an updating box may reach (no wildcards).
    pub update_hosts: Vec<String>,
    /// Where the CA is: mitmproxy's `confdir`, which the unit passes as `--set confdir=...` rather
    /// than in the environment. `MITM_CA_DIR` is new; W1 sets it in the Rust unit.
    pub ca_dir: PathBuf,
    /// Dev flags that are set (allowed only with `MITM_ALLOW_DEV_FLAGS=1`).
    pub dev_flags: Vec<String>,
    /// `MITM_DEV_RESOLVE`: where a name resolves, instead of DNS. Empty on a real box.
    pub dev_resolve: HashMap<String, SocketAddr>,
    /// `MITM_DEV_PRIVATE_PASSTHROUGH`: an uninspected connection may go to a private address.
    pub dev_private_passthrough: bool,
    /// Open connections one source address may hold (`MITM_MAX_CONNECTIONS_PER_SOURCE`).
    pub max_per_source: usize,
    /// The meeting leases the agent publishes (`MITM_MEETING_MEDIA_PATH`, by the rules file).
    pub meeting_media_path: PathBuf,
    /// `MITM_DEV_MEET_RANGES`: extra Meet TURN ranges, `sni=cidr` (tests only).
    pub dev_meet_ranges: Vec<(String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("refusing to start with dev flags set outside a smoke test: {0:?}")]
    DevFlags(Vec<String>),
    #[error("{0} is not a number: {1}")]
    BadNumber(&'static str, String),
}

impl Config {
    pub fn from_env(listen: SocketAddr) -> Result<Self, ConfigError> {
        Self::from_vars(listen, &std::env::vars().collect())
    }

    /// From an explicit map, so tests do not touch the process environment.
    pub fn from_vars(listen: SocketAddr, env: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let get = |k: &str| env.get(k).map(String::as_str).unwrap_or("");
        let path = |k: &str, default: &str| PathBuf::from(if get(k).is_empty() { default } else { get(k) });
        let host = |k: &str| Some(get(k).trim().to_lowercase()).filter(|h| !h.is_empty());

        let dev_flags: Vec<String> = DEV_FLAGS
            .iter()
            .filter(|k| !matches!(get(k), "" | "0"))
            .map(|k| (*k).to_owned())
            .collect();
        // `1` allows every dev flag (the addon's switch); a comma list allows only those named, so a
        // rig can allow what it needs and still see any other flag refused.
        let allow = get("MITM_ALLOW_DEV_FLAGS");
        let refused: Vec<String> = dev_flags
            .iter()
            .filter(|f| allow != "1" && !allow.split(',').any(|a| a.trim() == f.as_str()))
            .cloned()
            .collect();
        if !refused.is_empty() {
            return Err(ConfigError::DevFlags(refused));
        }

        let max_per_source = match get("MITM_MAX_CONNECTIONS_PER_SOURCE") {
            "" => DEFAULT_MAX_PER_SOURCE,
            v => v
                .parse()
                .map_err(|_| ConfigError::BadNumber("MITM_MAX_CONNECTIONS_PER_SOURCE", v.to_owned()))?,
        };
        let log_max_bytes = match get("MITM_LOG_MAX_BYTES") {
            "" => 8 * 1024 * 1024,
            v => v
                .parse()
                .map_err(|_| ConfigError::BadNumber("MITM_LOG_MAX_BYTES", v.to_owned()))?,
        };
        Ok(Self {
            listen,
            rules_path: path("MITM_RULES_PATH", "/config/rules.json"),
            credentials_path: path("MITM_CREDENTIALS_PATH", "/config/credentials.json"),
            identities_path: path("MITM_IDENTITIES_PATH", "/config/identities.json"),
            grants_path: path("MITM_GRANTS_PATH", "/config/grants.json"),
            pending_path: path("MITM_PENDING_PATH", "/config/pending.jsonl"),
            exit_path: path("MITM_EXIT_PATH", "/config/exit.json"),
            log_file: Some(get("MITM_LOG_FILE")).filter(|p| !p.is_empty()).map(PathBuf::from),
            log_max_bytes,
            tenant: Some(get("MITM_TENANT"))
                .filter(|t| !t.is_empty())
                .unwrap_or("unknown")
                .to_owned(),
            control_plane_host: host("MITM_CONTROL_PLANE_HOST"),
            backup_host: host("MITM_BACKUP_HOST"),
            backup_bucket: Some(get("MITM_BACKUP_BUCKET").trim().to_owned()).filter(|b| !b.is_empty()),
            org_path: if get("MITM_ORG_PATH").is_empty() {
                path("MITM_RULES_PATH", "/config/rules.json")
                    .parent()
                    .map_or_else(|| PathBuf::from("org.json"), |d| d.join("org.json"))
            } else {
                PathBuf::from(get("MITM_ORG_PATH"))
            },
            update_hosts: get("MITM_UPDATE_HOSTS")
                .split(',')
                .map(|h| h.trim().to_lowercase())
                .filter(|h| !h.is_empty() && !h.contains('*') && h.contains('.'))
                .collect(),
            ca_dir: path("MITM_CA_DIR", "/opt/controlclaw/mitm/ca"),
            dev_resolve: get("MITM_DEV_RESOLVE")
                .split(',')
                .filter_map(|e| {
                    let (name, addr) = e.split_once('=')?;
                    Some((name.trim().to_lowercase(), addr.trim().parse().ok()?))
                })
                .collect(),
            dev_private_passthrough: dev_flags.iter().any(|f| f == "MITM_DEV_PRIVATE_PASSTHROUGH"),
            meeting_media_path: match get("MITM_MEETING_MEDIA_PATH") {
                "" => path("MITM_RULES_PATH", "/config/rules.json")
                    .parent()
                    .map(|d| d.join("meeting-media.json"))
                    .unwrap_or_else(|| PathBuf::from("meeting-media.json")),
                p => PathBuf::from(p),
            },
            dev_meet_ranges: get("MITM_DEV_MEET_RANGES")
                .split(',')
                .filter_map(|e| e.split_once('='))
                .map(|(s, c)| (s.trim().to_lowercase(), c.trim().to_owned()))
                .collect(),
            max_per_source,
            dev_flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    fn listen() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    #[test]
    fn dev_flags_need_the_smoke_switch() {
        assert!(matches!(
            Config::from_vars(listen(), &vars(&[("MITM_DEV_LOG_SECRETS", "1")])),
            Err(ConfigError::DevFlags(_))
        ));
        // `0` and empty are off, as the production unit pins them.
        assert!(Config::from_vars(listen(), &vars(&[("MITM_DEV_LOG_SECRETS", "0")])).is_ok());
        // A list allows only the flags it names.
        let list = |set: &[(&str, &str)]| Config::from_vars(listen(), &vars(set));
        assert!(
            list(&[
                ("MITM_DEV_INSECURE_UPSTREAM", "1"),
                (
                    "MITM_ALLOW_DEV_FLAGS",
                    "MITM_DEV_INSECURE_UPSTREAM, MITM_DEV_WITHOUT_CHECKS"
                )
            ])
            .is_ok()
        );
        assert!(matches!(
            list(&[
                ("MITM_DEV_INSECURE_UPSTREAM", "1"),
                ("MITM_DEV_LOG_SECRETS", "1"),
                ("MITM_ALLOW_DEV_FLAGS", "MITM_DEV_INSECURE_UPSTREAM")
            ]),
            Err(ConfigError::DevFlags(f)) if f == ["MITM_DEV_LOG_SECRETS"]
        ));
        let allowed = Config::from_vars(
            listen(),
            &vars(&[("MITM_DEV_INSECURE_UPSTREAM", "yes"), ("MITM_ALLOW_DEV_FLAGS", "1")]),
        );
        assert!(allowed.is_ok_and(|c| c.dev_flags == ["MITM_DEV_INSECURE_UPSTREAM"]));
    }

    #[test]
    fn reads_the_unit_environment() -> Result<(), ConfigError> {
        let c = Config::from_vars(
            listen(),
            &vars(&[
                ("MITM_CONTROL_PLANE_HOST", " ControlClaw.com "),
                (
                    "MITM_UPDATE_HOSTS",
                    "deb.nodesource.com, *.ubuntu.com,registry.npmjs.org,localhost",
                ),
                ("MITM_LOG_FILE", "/tmp/traffic.jsonl"),
            ]),
        )?;
        assert_eq!(c.control_plane_host.as_deref(), Some("controlclaw.com"));
        assert_eq!(c.update_hosts, ["deb.nodesource.com", "registry.npmjs.org"]);
        assert_eq!(c.tenant, "unknown");
        assert_eq!(c.log_max_bytes, 8 * 1024 * 1024);
        Ok(())
    }
}
