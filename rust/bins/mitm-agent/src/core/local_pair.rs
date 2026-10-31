//! Pairing on a standalone firewall (`cc_local::pairing`): the unauthenticated `POST /pair` on
//! `PAIR_BIND` (default `0.0.0.0:8801`), and `mitm-agent pair-code`, which makes a one-time code
//! for the admin to type on the agent's machine. Off in SaaS mode.
//!
//! The answer carries this firewall's public key (`KEYS_DIR/vm_public_key.pem`), its CA
//! (`CA_CERT_PATH`), and the addresses agents use: `PAIR_PROXY_ADDR` (host:port of the proxy) and
//! `PAIR_DNS_ADDR`, when they are set. The proxy names a paired agent at its next sync (a minute).
//!
//! WireGuard (remote agents), when `KEYS_DIR/wg_public_key` exists (install.sh --wireguard writes
//! it): pairing hands out `WG_ENDPOINT` (host:port) and a tunnel address in `WG_ADDRESS` (the
//! firewall's, default `10.77.0.1/24`), and the proxy's port there, `WG_PROXY_PORT` (default 8080: the
//! proxy's own port, not one Docker publishes). WireGuard is off without `WG_ENDPOINT`. The peers are written to `WG_PEERS_PATH` (default
//! `STATE_DIR/wg-peers.conf`) within seconds of a change; root applies them to the interface.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cc_local::Db;
use cc_local::pairing::{self, FirewallInfo, PairService};
use cc_local::wireguard::{self, WgInfo};

const DEFAULT_CA: &str = "/opt/controlclaw/mitm/ca/ca-cert.pem";
const DEFAULT_WG_ADDRESS: &str = "10.77.0.1/24";
const WG_PUBLIC_KEY: &str = "wg_public_key";

fn ca_path() -> PathBuf {
    std::env::var("CA_CERT_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| DEFAULT_CA.into())
        .into()
}

fn env_addr(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// What a pairing answers with, read each time.
pub fn firewall_info(keys_dir: &Path) -> Result<FirewallInfo, String> {
    let public_key = cc_auth::keys::read_key_file(keys_dir, "vm_public_key.pem")
        .ok_or_else(|| format!("no {}/vm_public_key.pem", keys_dir.display()))?;
    let ca = ca_path();
    let ca_pem = std::fs::read_to_string(&ca).map_err(|e| format!("{}: {e}", ca.display()))?;
    Ok(FirewallInfo {
        public_key: format!("{public_key}\n"),
        ca_pem,
        proxy: env_addr("PAIR_PROXY_ADDR"),
        dns: env_addr("PAIR_DNS_ADDR"),
        wg: wg_info(keys_dir)?,
    })
}

/// The firewall's own tunnel address, when it runs WireGuard: remote agents reach its gates there.
pub(crate) fn tunnel_address(keys_dir: &Path) -> Option<std::net::Ipv4Addr> {
    wg_info(keys_dir).ok().flatten().map(|w| w.address)
}

/// The firewall's WireGuard, when it runs one: its key file is there.
fn wg_info(keys_dir: &Path) -> Result<Option<WgInfo>, String> {
    let Some(public_key) = cc_auth::keys::read_key_file(keys_dir, WG_PUBLIC_KEY) else {
        return Ok(None);
    };
    if !wireguard::valid_key(&public_key) {
        return Err(format!("{}/{WG_PUBLIC_KEY} is not a WireGuard key", keys_dir.display()));
    }
    // The key file outlives a firewall set up again without WireGuard: on only with both.
    let Some(endpoint) = env_addr("WG_ENDPOINT") else {
        return Ok(None);
    };
    let addr = env_addr("WG_ADDRESS").unwrap_or_else(|| DEFAULT_WG_ADDRESS.into());
    let (ip, prefix) = addr
        .split_once('/')
        .and_then(|(ip, p)| Some((ip.parse().ok()?, p.parse().ok()?)))
        .ok_or_else(|| format!("WG_ADDRESS is an address with its prefix (10.77.0.1/24), not {addr}"))?;
    let proxy_port = match env_addr("WG_PROXY_PORT") {
        Some(p) => p.parse().map_err(|_| format!("WG_PROXY_PORT is a port, not {p}"))?,
        None => 8080,
    };
    Ok(Some(WgInfo {
        public_key,
        endpoint,
        address: ip,
        prefix,
        proxy_port,
    }))
}

/// Keeps `WG_PEERS_PATH` equal to the agents' WireGuard peers: checked every few seconds, so a
/// pairing, an unpairing or a change to the agents reaches the interface without a restart. The
/// file is replaced whole (a temp file, then a rename), only when it changes.
fn keep_peers(db: Arc<Db>, keys_dir: PathBuf) {
    let path: PathBuf = env_addr("WG_PEERS_PATH").map(PathBuf::from).unwrap_or_else(|| {
        Path::new(&std::env::var("STATE_DIR").unwrap_or_else(|_| super::env::STANDALONE_STATE_DIR.into()))
            .join("wg-peers.conf")
    });
    tokio::spawn(async move {
        let mut last = std::fs::read_to_string(&path).ok();
        loop {
            if keys_dir.join(WG_PUBLIC_KEY).exists() {
                let conf = wireguard::peers_conf(&db.lock());
                match conf {
                    Ok(conf) if last.as_deref() != Some(conf.as_str()) => {
                        let tmp = path.with_extension("conf.tmp");
                        match std::fs::write(&tmp, &conf).and_then(|()| std::fs::rename(&tmp, &path)) {
                            Ok(()) => {
                                tracing::info!("[cc-local] wireguard peers written to {}", path.display());
                                last = Some(conf);
                            }
                            Err(e) => tracing::error!("[cc-local] wireguard peers: {}: {e}", path.display()),
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::error!("[cc-local] wireguard peers: {e}"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });
}

/// The pairing endpoint, beside the admin API. `PAIR_BIND=off` keeps it closed.
pub async fn serve(db: Arc<Db>, keys_dir: PathBuf) {
    // The peers follow the agents even with the pairing endpoint closed (PUT /api/agents).
    keep_peers(db.clone(), keys_dir.clone());
    let Some(bind) = cc_local::api::pairing::pair_bind(std::env::var("PAIR_BIND").ok()) else {
        tracing::info!("[cc-local] pairing endpoint off (PAIR_BIND=off)");
        return;
    };
    if env_addr("PAIR_PROXY_ADDR").is_none() {
        tracing::warn!(
            "[cc-local] PAIR_PROXY_ADDR is not set: paired agents are not told the proxy's address and need --proxy"
        );
    }
    let service = PairService::new(db, Arc::new(move || firewall_info(&keys_dir)));
    match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => {
            tracing::info!("[cc-local] pairing endpoint on {bind}");
            tokio::spawn(cc_http::serve(l, Arc::new(service.router())));
        }
        Err(e) => tracing::error!("[cc-local] pairing endpoint on {bind}: {e}"),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: mitm-agent pair-code [--name <agent name>] [--ttl <minutes, 1-60>] [--address <the agent's IPv4, as the proxy sees it>] [--replace]"
    );
    std::process::exit(2);
}

/// `mitm-agent pair-code`: a one-time code, written to the running firewall's database. Run it as
/// the firewall's user (it owns `STATE_DIR/local.db`). Only `STATE_DIR` is read from the
/// environment.
pub fn pair_code(args: &[String]) -> ! {
    let (mut name, mut ttl, mut address, mut replace) = (None, None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = Some(it.next().unwrap_or_else(|| usage()).clone()),
            "--ttl" => ttl = Some(it.next().and_then(|t| t.parse::<i64>().ok()).unwrap_or_else(|| usage())),
            "--address" => address = Some(it.next().unwrap_or_else(|| usage()).clone()),
            "--replace" => replace = true,
            _ => usage(),
        }
    }
    let fail = |e: String| -> ! {
        eprintln!("mitm-agent pair-code: {e}");
        std::process::exit(1);
    };
    let state = std::env::var("STATE_DIR").unwrap_or_else(|_| super::env::STANDALONE_STATE_DIR.into());
    let path = Path::new(&state).join(super::local_cp::DB_FILE);
    if !path.exists() {
        // Only a standalone firewall has one (MITM_MODE=standalone).
        fail(format!(
            "{} does not exist: pairing is for a standalone firewall, once it has started",
            path.display()
        ));
    }
    let db = Db::open(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    let f = pairing::CodeFor {
        name: name.as_deref(),
        ttl_min: ttl,
        address: address.as_deref(),
        replace,
    };
    let c = pairing::create_code(&db, &f).unwrap_or_else(|e| fail(e));
    let minutes = (c.expires_at - cc_local::db::now_s() + 59) / 60;
    println!("{}", c.code);
    eprintln!(
        "On the agent's machine: controlclaw connect --firewall http://<this firewall>:8801 --mode <mode>, and type the code when it asks"
    );
    if let Some(a) = &c.address {
        eprintln!("The proxy will know the agent at {a}.");
    }
    if c.replace {
        eprintln!("It may take the place of an agent already at its address.");
    }
    eprintln!("It works once, within {minutes} minutes.");
    std::process::exit(0);
}
