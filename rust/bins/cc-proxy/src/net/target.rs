//! What every address the firewall may dial is checked against (addon.py `check_target`,
//! `server_connect`): a name is resolved (at most [`LOOKUP_TIMEOUT`]) and refused if ANY of its
//! addresses is non-routable or one of the firewall's own, and the address checked is the one
//! dialled, so a name cannot answer differently the second time (DNS rebinding). Passthrough
//! refuses a name that does not resolve; an inspected request keeps it unresolved
//! (`Destination::addr` is `None`) for its rules to judge, and the dial resolves it again and
//! refuses it if it still does not resolve.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The longest one lookup may take, at check time or at dial time; past it the name did not resolve.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Why `ip` is never connected to, or `None` if it may be. Looks through the IPv6 forms that carry
/// an IPv4 address (`::ffff:169.254.169.254`, NAT64 `64:ff9b::/96`, `::a.b.c.d`, 6to4 `2002::/16`).
pub fn non_routable_kind(ip: IpAddr) -> Option<&'static str> {
    match unwrap_any_v4(ip) {
        IpAddr::V4(a) if a.is_link_local() => Some("link-local"),
        IpAddr::V4(a) if a.is_loopback() => Some("loopback"),
        IpAddr::V4(a) if a.is_unspecified() => Some("unspecified"),
        IpAddr::V4(a) if a.is_multicast() => Some("multicast"),
        IpAddr::V6(a) if a.is_unicast_link_local() => Some("link-local"),
        IpAddr::V6(a) if a.is_loopback() => Some("loopback"),
        IpAddr::V6(a) if a.is_unspecified() => Some("unspecified"),
        IpAddr::V6(a) if a.is_multicast() => Some("multicast"),
        _ => None,
    }
}

/// Why the firewall never connects to `ip`, worded for a record: non-routable, or an address on
/// one of the firewall's own interfaces. A name the agent controls that resolves to the firewall
/// itself would otherwise be dialled over `lo`, past the Hetzner firewall and UFW, to its 3100 and
/// the private-address gates (3940 trusts the source address alone).
pub fn refusal(ip: IpAddr, shown: &str) -> Option<String> {
    if let Some(kind) = non_routable_kind(ip) {
        return Some(format!(
            "{shown} is a {kind} address; the firewall never connects there"
        ));
    }
    if is_own_address(ip) {
        return Some(format!(
            "{shown} is one of the firewall's own addresses; the firewall never connects there"
        ));
    }
    None
}

/// The IPv4 address an IPv6 form carries. `every_form` adds the IPv4-compatible and 6to4 forms:
/// only for refusing (non-routable, own address), never for `is_private`, where Python's lists
/// already cover `::/96` and `2002::/16` and unwrapping would make a 6to4 address look global.
fn embedded_v4(v6: Ipv6Addr, every_form: bool) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    let v4 = |hi: u16, lo: u16| Ipv4Addr::from(u32::from(hi) << 16 | u32::from(lo));
    // NAT64 64:ff9b::/96
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(v4(s[6], s[7]));
    }
    if !every_form {
        return None;
    }
    // IPv4-compatible ::a.b.c.d (deprecated, still routed by some stacks). `::` and `::1` are
    // IPv6's own unspecified and loopback addresses, not IPv4 ones.
    if s[..6] == [0; 6] && u32::from(s[6]) << 16 | u32::from(s[7]) > 1 {
        return Some(v4(s[6], s[7]));
    }
    // 6to4 2002:a.b.c.d::/48: the relay delivers to the IPv4 address it carries.
    (s[0] == 0x2002).then(|| v4(s[1], s[2]))
}

/// The IPv4 address an IPv6 form carries (`::ffff:a.b.c.d`, NAT64), or the address as it is.
fn unwrap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_v4(v6, false).map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// [`unwrap_v4`] through every IPv6 form that carries an IPv4 address, for refusing.
fn unwrap_any_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_v4(v6, true).map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// One address, whichever form it is written in.
pub fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    unwrap_v4(a) == unwrap_v4(b)
}

fn in_v4(a: Ipv4Addr, net: [u8; 4], bits: u32) -> bool {
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    u32::from(a) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn in_v6(a: Ipv6Addr, net: [u16; 8], bits: u32) -> bool {
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    u128::from(a) & mask == u128::from(Ipv6Addr::from(net)) & mask
}

/// Python's `ipaddress` `is_private` (3.12.4 and later, the lists in `_IPv4Constants` and
/// `_IPv6Constants`), plus what the production fix (#511) refuses besides: `fec0::/10` and the
/// IPv4-compatible `::a.b.c.d`.
pub fn is_private(ip: IpAddr) -> bool {
    match unwrap_v4(ip) {
        IpAddr::V4(a) => {
            let private = [
                ([0, 0, 0, 0], 8),
                ([10, 0, 0, 0], 8),
                ([127, 0, 0, 0], 8),
                ([169, 254, 0, 0], 16),
                ([172, 16, 0, 0], 12),
                ([192, 0, 0, 0], 24),
                ([192, 0, 0, 170], 31),
                ([192, 0, 2, 0], 24),
                ([192, 168, 0, 0], 16),
                ([198, 18, 0, 0], 15),
                ([198, 51, 100, 0], 24),
                ([203, 0, 113, 0], 24),
                ([240, 0, 0, 0], 4),
                ([255, 255, 255, 255], 32),
            ];
            let exceptions = [([192, 0, 0, 9], 32), ([192, 0, 0, 10], 32)];
            private.iter().any(|(n, b)| in_v4(a, *n, *b)) && !exceptions.iter().any(|(n, b)| in_v4(a, *n, *b))
        }
        IpAddr::V6(a) => {
            let private: [([u16; 8], u32); 12] = [
                ([0, 0, 0, 0, 0, 0, 0, 1], 128),
                ([0; 8], 128),
                ([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
                ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
                ([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
                ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
                ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
                ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
                ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
                ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
                // Not in Python's list; refused by #511 as well.
                ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
                ([0; 8], 96),
            ];
            let exceptions: [([u16; 8], u32); 6] = [
                ([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
                ([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
                ([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
                ([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
                ([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
                ([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
            ];
            private.iter().any(|(n, b)| in_v6(a, *n, *b)) && !exceptions.iter().any(|(n, b)| in_v6(a, *n, *b))
        }
    }
}

/// Python's `is_global`: not private, and not the shared range `100.64.0.0/10`.
pub fn is_global(ip: IpAddr) -> bool {
    !is_private(ip) && !matches!(unwrap_v4(ip), IpAddr::V4(a) if in_v4(a, [100, 64, 0, 0], 10))
}

/// Whether a connection that is passed through uninspected may go to `ip` (#511 `is_public_ip`):
/// a global address. `dev_private` (`MITM_DEV_PRIVATE_PASSTHROUGH`, smoke rigs only) also lets
/// through a private one that is not non-routable, where the rigs' stand-in servers live.
pub fn is_public(ip: IpAddr, dev_private: bool) -> bool {
    is_global(ip) || (dev_private && is_private(ip) && non_routable_kind(ip).is_none())
}

/// The addresses on the firewall's own interfaces, read from the kernel and re-read at most every
/// few seconds (an address can be added at run time: a floating IP, a new private network).
fn is_own_address(ip: IpAddr) -> bool {
    static OWN: Mutex<Option<(Instant, Vec<IpAddr>)>> = Mutex::new(None);
    const REFRESH: Duration = Duration::from_secs(5);
    let ip = unwrap_any_v4(ip);
    let mut own = OWN.lock().unwrap_or_else(PoisonError::into_inner);
    if own.as_ref().is_none_or(|(at, _)| at.elapsed() > REFRESH) {
        *own = Some((Instant::now(), own_addresses()));
    }
    own.as_ref().is_some_and(|(_, list)| list.contains(&ip))
}

/// IPv4 from the local routing table (`/proc/net/fib_trie`: each `/32 host LOCAL` entry), IPv6
/// from `/proc/net/if_inet6`. Without procfs the list is empty and only the address kinds above are
/// refused.
fn own_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(trie) = std::fs::read_to_string("/proc/net/fib_trie") {
        let mut last: Option<Ipv4Addr> = None;
        for line in trie.lines() {
            let t = line.trim_start_matches([' ', '|', '+', '-']).trim();
            if let Ok(a) = t.parse::<Ipv4Addr>() {
                last = Some(a);
            } else if t.starts_with("/32 host LOCAL")
                && let Some(a) = last
                && !out.contains(&IpAddr::V4(a))
            {
                out.push(IpAddr::V4(a));
            }
        }
    }
    if let Ok(v6) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in v6.lines() {
            if let Some(hex) = line.split_whitespace().next()
                && let Ok(n) = u128::from_str_radix(hex, 16)
            {
                out.push(IpAddr::V6(Ipv6Addr::from(n)));
            }
        }
    }
    out
}

/// Why a name gave no address to dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// It did not resolve (no such name, no answer, the resolver is down). Worded for a record.
    NotFound(String),
    /// An address it resolves to is one the firewall never connects to. Worded for a record.
    Refused(String),
}

impl ResolveError {
    pub fn into_message(self) -> String {
        match self {
            ResolveError::NotFound(m) | ResolveError::Refused(m) => m,
        }
    }
}

/// Resolve `host` and return every address, refusing the lot if any is non-routable or the
/// firewall's own. An IP literal is not looked up. A resolver that fails is a name that does not
/// resolve: nothing is dialled on a guess.
///
/// Through the system's `getaddrinfo`, as the addon resolves: `/etc/hosts`, `/etc/resolv.conf` and
/// their timeouts as they are at each lookup. On a box that goes to the local caching stub, which
/// keeps each answer for its TTL.
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    // `169.254.169.254.` is an address too, not a name to look up.
    let host = host
        .strip_suffix('.')
        .filter(|h| h.parse::<IpAddr>().is_ok())
        .unwrap_or(host);
    let shown = |ip: IpAddr| {
        if host == ip.to_string() {
            truncate(host, 120)
        } else {
            truncate(&format!("{host} ({ip})"), 120)
        }
    };
    let not_found = |e: &dyn std::fmt::Display| {
        ResolveError::NotFound(truncate(&format!("could not resolve {}: {e}", truncate(host, 60)), 200))
    };
    let ips: Vec<IpAddr> = match host.split('%').next().unwrap_or("").parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            let mut ips = Vec::new();
            let found = tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| not_found(&"the lookup timed out"))?;
            for a in found.map_err(|e| not_found(&e))? {
                if !ips.contains(&a.ip()) {
                    ips.push(a.ip());
                }
            }
            ips
        }
    };
    if ips.is_empty() {
        return Err(ResolveError::NotFound(format!(
            "could not resolve {}",
            truncate(host, 60)
        )));
    }
    for ip in &ips {
        if let Some(why) = refusal(*ip, &shown(*ip)) {
            return Err(ResolveError::Refused(why));
        }
    }
    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

/// [`resolve`], with either failure as the refusal text.
pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    resolve(host, port).await.map_err(ResolveError::into_message)
}

/// Resolve `host` and pick the address to dial: every address must pass, IPv4 preferred.
/// `Err` is the refusal, worded for the log record.
pub async fn check_target(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs = resolve_all(host, port).await?;
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| format!("could not resolve {}", truncate(host, 60)))
}

/// The first `max` characters, as Python's `s[:max]`.
pub fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    fn kind(s: &str) -> Option<&'static str> {
        non_routable_kind(ip(s))
    }

    #[test]
    fn global_is_pythons_is_global() {
        // Each of these is not global to Python's ipaddress (3.12.4+), or refused by #511 besides.
        for s in [
            "10.0.0.2",
            "172.16.1.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "0.1.2.3",
            "192.0.0.1",
            "192.0.0.171",
            "192.0.2.5",
            "198.51.100.5",
            "203.0.113.5",
            "240.0.0.1",
            "255.255.255.255",
            "127.0.0.1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "::1",
            "::",
            "::10.0.0.5",
            "::1.1.1.1",
            "::ffff:10.0.0.5",
            "64:ff9b::a00:5",
            "64:ff9b:1::5",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002:a00:5::1",
            "2002:101:101::1",
        ] {
            assert!(!is_global(ip(s)), "{s}");
        }
        for s in [
            "1.1.1.1",
            "100.128.0.1",
            "192.0.0.9",
            "192.0.0.10",
            "2606:4700::1111",
            "::ffff:1.1.1.1",
            "64:ff9b::101:101",
            "2001:1::1",
            "2001:3::1",
            "2001:20::1",
        ] {
            assert!(is_global(ip(s)), "{s}");
        }
        assert!(same_ip(ip("::ffff:203.0.113.5"), ip("203.0.113.5")));
        // The rigs' switch lets a private address through, never a non-routable one.
        assert!(is_public(ip("203.0.113.5"), true));
        assert!(!is_public(ip("203.0.113.5"), false));
        assert!(!is_public(ip("127.0.0.1"), true));
        assert!(!is_public(ip("100.64.0.1"), true), "shared space is not private either");
    }

    #[test]
    fn refuses_what_the_addon_refuses() {
        assert_eq!(kind("169.254.169.254"), Some("link-local"));
        assert_eq!(kind("::ffff:169.254.169.254"), Some("link-local"));
        assert_eq!(kind("64:ff9b::a9fe:a9fe"), Some("link-local"));
        // IPv4-compatible and 6to4 forms carry the address they reach.
        assert_eq!(kind("::169.254.169.254"), Some("link-local"));
        assert_eq!(kind("::127.0.0.1"), Some("loopback"));
        assert_eq!(kind("2002:a9fe:a9fe::1"), Some("link-local"));
        assert_eq!(kind("2002:7f00:1::"), Some("loopback"));
        assert_eq!(kind("::1"), Some("loopback"));
        assert_eq!(kind("::"), Some("unspecified"));
        // ... while is_global still counts every 6to4 address as private.
        assert!(!is_global("2002:808:808::1".parse().expect("an address")));
        assert_eq!(kind("127.0.0.1"), Some("loopback"));
        assert_eq!(kind("::1"), Some("loopback"));
        assert_eq!(kind("0.0.0.0"), Some("unspecified"));
        assert_eq!(kind("224.0.0.1"), Some("multicast"));
        assert_eq!(kind("fe80::1"), Some("link-local"));
        assert_eq!(kind("10.0.0.3"), None, "private addresses are for the rules to judge");
        assert_eq!(kind("93.184.216.34"), None);
    }

    #[test]
    fn refuses_the_firewalls_own_addresses() {
        // The kernel's lists are Linux's (the firewall's): nothing to read elsewhere.
        if !std::path::Path::new("/proc/net/fib_trie").exists() {
            return;
        }
        // Every machine has its loopback, and this one has whatever address the test runs on.
        let own = own_addresses();
        assert!(own.contains(&ip("127.0.0.1")), "{own:?}");
        if let Some(a) = own.iter().find(|a| non_routable_kind(**a).is_none()) {
            assert!(refusal(*a, "x").is_some_and(|w| w.contains("firewall's own")));
        }
        assert!(refusal(ip("93.184.216.34"), "x").is_none());
    }

    #[tokio::test]
    async fn checks_before_dialling() {
        assert!(check_target("127.0.0.1", 3101).await.is_err());
        assert!(check_target("[::1]", 3101).await.is_err());
        assert!(check_target("localhost", 80).await.is_err());
        assert_eq!(
            check_target("93.184.216.34", 443).await,
            Ok(SocketAddr::from(([93, 184, 216, 34], 443)))
        );
    }
}
