//! WireGuard for agents on other machines (plan §4, "Identity without a private network"): the
//! firewall runs a WireGuard interface, each agent paired over it gets a peer and a tunnel address,
//! and that address is its identity at the proxy.
//!
//! This side keeps the peers in `agents` (`wg_public_key`, the tunnel address in `private_ip`) and
//! writes them as a WireGuard `[Peer]` list ([`peers_conf`]); the firewall's root side applies it to
//! the interface (`wg syncconf`), since the firewall agent has no right to.

use std::net::Ipv4Addr;

use base64::Engine;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// The firewall's side of the tunnel, as pairing hands it out.
#[derive(Debug, Clone, PartialEq)]
pub struct WgInfo {
    /// The firewall's WireGuard public key (base64).
    pub public_key: String,
    /// host:port agents reach the firewall's WireGuard at.
    pub endpoint: String,
    /// The firewall's address in the tunnel; the proxy and DNS listen on it.
    pub address: Ipv4Addr,
    /// The tunnel network's prefix length (24: 254 addresses).
    pub prefix: u8,
    /// The proxy's port on the tunnel address: its own, which the tunnel reaches directly.
    pub proxy_port: u16,
}

/// What the agent's machine needs to bring its side up, in the pairing answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WgAnswer {
    pub firewall_public_key: String,
    pub endpoint: String,
    /// The agent's tunnel address: its identity at the proxy.
    pub address: String,
    pub firewall_address: String,
}

/// A WireGuard key: 32 bytes, base64. Anything else never reaches the peers file.
pub fn valid_key(k: &str) -> bool {
    k.len() == 44
        && base64::engine::general_purpose::STANDARD
            .decode(k)
            .is_ok_and(|b| b.len() == 32)
}

/// The first free tunnel address, from `.2` (the peers filter takes `.2` to `.254`): not the
/// network's last, not the firewall's, not an agent's.
pub fn allocate(c: &Connection, wg: &WgInfo) -> Result<Ipv4Addr, String> {
    // A /24: the firewall's peers filter (wg-sync.sh) reads the tunnel network as one.
    if wg.prefix != 24 {
        return Err(format!("the tunnel network is /{}, not /24", wg.prefix));
    }
    let mask = u32::MAX << (32 - wg.prefix);
    let net = u32::from(wg.address) & mask;
    let used: std::collections::HashSet<String> = {
        let mut q = c
            .prepare("SELECT private_ip FROM agents WHERE private_ip IS NOT NULL")
            .map_err(|e| e.to_string())?;
        q.query_map([], |r| r.get(0))
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<_>>()
            .map_err(|e| e.to_string())?
    };
    (net + 2..net | !mask)
        .map(Ipv4Addr::from)
        .find(|ip| *ip != wg.address && !used.contains(&ip.to_string()))
        .ok_or_else(|| "the tunnel network is full".into())
}

/// The peers, as WireGuard's config format: one `[Peer]` for each agent with a WireGuard key,
/// allowed only its own tunnel address.
pub fn peers_conf(c: &Connection) -> rusqlite::Result<String> {
    let mut q = c.prepare(
        "SELECT vm_id, wg_public_key, private_ip FROM agents
         WHERE wg_public_key IS NOT NULL AND private_ip IS NOT NULL AND role <> 'mitm' ORDER BY vm_id",
    )?;
    let rows: Vec<(String, String, String)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out =
        String::from("# Written by the firewall agent from its agents (cc-local); applied with wg syncconf.\n");
    let mut seen = std::collections::HashSet::new();
    for (id, key, ip) in rows {
        // Checked again here: only a key and an address ever reach the file, each key once.
        if !valid_key(&key) || ip.parse::<Ipv4Addr>().is_err() {
            tracing::warn!("[cc-local] wireguard: {id} has a bad key or address; left out");
            continue;
        }
        if !seen.insert(key.clone()) {
            tracing::warn!("[cc-local] wireguard: {id} has another agent's key; left out");
            continue;
        }
        out.push_str(&format!("\n# {id}\n[Peer]\nPublicKey = {key}\nAllowedIPs = {ip}/32\n"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    const KEY: &str = "uEjM2N4pNCQnVBJm/eEtYhXeJ8JyBQlpS9Oa8HVnHlA=";

    fn wg() -> WgInfo {
        WgInfo {
            public_key: KEY.into(),
            endpoint: "203.0.113.1:51820".into(),
            address: "10.77.0.1".parse().expect("ip"),
            prefix: 24,
            proxy_port: 8080,
        }
    }

    #[test]
    fn keys_are_32_bytes_of_base64() {
        assert!(valid_key(KEY));
        assert!(!valid_key("uEjM2N4pNCQnVBJm/eEtYhXeJ8JyBQlpS9Oa8HVnHlA"));
        assert!(!valid_key("uEjM2N4pNCQnVBJm/eEtYhXeJ8JyBQlpS9Oa8HVnHl=\n"));
        assert!(!valid_key("x\n[Peer]\nAllowedIPs = 0.0.0.0/0"));
    }

    #[test]
    fn addresses_skip_the_firewall_and_the_agents() {
        let db = Db::memory().expect("db");
        let c = db.lock();
        assert_eq!(allocate(&c, &wg()), Ok("10.77.0.2".parse().expect("ip")));
        c.execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, created_at) VALUES ('a', 'openclaw', 'a', '10.77.0.2', 1)",
            [],
        )
        .expect("agent");
        assert_eq!(allocate(&c, &wg()), Ok("10.77.0.3".parse().expect("ip")));
        // A firewall not at .1: .1 is never handed out (the peers filter would drop it).
        let other = WgInfo {
            address: "10.77.0.9".parse().expect("ip"),
            ..wg()
        };
        assert_eq!(allocate(&c, &other), Ok("10.77.0.3".parse().expect("ip")));
        assert!(allocate(&c, &WgInfo { prefix: 16, ..wg() }).is_err(), "only a /24");
    }

    #[test]
    fn the_peers_file_has_each_key_once_with_its_own_address() {
        let db = Db::memory().expect("db");
        let c = db.lock();
        c.execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, wg_public_key, created_at) VALUES ('a', 'openclaw', 'a', '10.77.0.2', ?1, 1)",
            [KEY],
        )
        .expect("agent");
        c.execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, wg_public_key, created_at) VALUES ('b', 'openclaw', 'b', '10.77.0.3', 'bad\nkey', 1)",
            [],
        )
        .expect("agent");
        let conf = peers_conf(&c).expect("conf");
        assert!(conf.contains(&format!("[Peer]\nPublicKey = {KEY}\nAllowedIPs = 10.77.0.2/32\n")));
        assert!(!conf.contains("bad"), "{conf}");
    }
}
