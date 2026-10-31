//! Checking where a connection really goes before anything is dialled.
//!
//! A client names its destination three times: the CONNECT target, the SNI and (inside TLS) the
//! Host header. It chooses all three. The firewall dials none of them as given: it resolves the
//! name itself and dials an address from its own answer. The result is the flow's
//! [`Destination`], which is all that swaps and rules may use.
//!
//! Every name is first put in its wire form ([`wire_name`]): lower case, no trailing dot, IDNA in
//! punycode, a valid host name or an IP address, nothing else. The passthrough decision, the
//! resolution and the Host check all use that one string, so a name cannot match as one thing and
//! be dialled as another.
//!
//! A CONNECT target that is an address need not be in the firewall's answer: object storage and
//! CDNs hand out a different address per query, and the agent's resolver caches apart from the
//! proxy's, so a strict match would refuse real traffic at random. Dialling only the firewall's own
//! answer is what keeps a faked SNI from opening a tunnel anywhere else; the mismatch is logged. A
//! CONNECT target that is another *name* than a passthrough SNI is refused (`destination_mismatch`,
//! as the production fix #511 does): the client said two different things.
//!
//! - Passthrough (control plane, backup store): the SNI, port 443, public addresses only.
//! - Intercepted TLS: the SNI (or the CONNECT address when there is none) on the CONNECT port. Every
//!   request inside the tunnel must name that host ([`host_agrees`]).
//! - Plain HTTP: each request's own host, on its port.
//!
//! Interception refuses non-routable addresses and the firewall's own: private ranges are real, if
//! internal, destinations, and the organization's rules judge them.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::config::Config;
use crate::flow::{Destination, Flow};
use crate::net::target::{ResolveError, is_public, resolve, resolve_all, same_ip, truncate};

/// Why a destination was refused, for the `block` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub rule: &'static str,
    pub error: String,
}

fn refused(rule: &'static str, error: impl Into<String>) -> Refused {
    Refused {
        rule,
        error: error.into(),
    }
}

/// The record rule for an address no rule can allow (addon.py `NON_ROUTABLE_RULE`).
pub const NON_ROUTABLE_RULE: &str = "non_routable_target";
/// The record rule for names that disagree (#511 `DESTINATION_RULE`).
pub const DESTINATION_RULE: &str = "destination_mismatch";

/// The only port a passthrough host is reached on.
pub const PASSTHROUGH_PORT: u16 = 443;

/// A host (with an optional port) in its wire form: an IP address as Rust writes it, or a host name
/// in lower case, without the root's trailing dot, an international name in punycode, made only of
/// LDH labels. `None` for anything else, which is refused wherever it appears.
///
/// Brackets are taken off only when they hold the whole host (`[v6]` or `[v6]:port`), and only an
/// IPv6 address may be in them: `[attacker.example].tailscale.com` is not a name.
pub fn wire_name(h: &str) -> Option<String> {
    let h = h.trim();
    if let Some(rest) = h.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let port_ok = after.is_empty() || after.strip_prefix(':').is_some_and(is_port);
        return port_ok
            .then(|| inner.parse::<Ipv6Addr>().ok())
            .flatten()
            .map(|a| a.to_string());
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let name = match h.rsplit_once(':') {
        Some((n, p)) if is_port(p) => n,
        Some(_) => return None,
        None => h,
    };
    if let Ok(ip) = name.parse::<std::net::Ipv4Addr>() {
        return Some(ip.to_string());
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    let ascii = if name.is_ascii() {
        name.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(name).ok()?
    };
    // A full-width or ideographic trailing dot becomes a plain one in the encoding.
    let ascii = ascii.strip_suffix('.').unwrap_or(&ascii).to_owned();
    is_host_name(&ascii).then_some(ascii)
}

fn is_port(p: &str) -> bool {
    !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit())
}

/// Dot-separated LDH labels: letters, digits and inner hyphens, 1-63 each, 253 in all (#511
/// `_HOST_NAME`, which a single label also satisfies here: `localhost` is a name).
fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

fn connect_ip(flow: &Flow) -> Option<IpAddr> {
    wire_name(&flow.connect.host)?.parse().ok()
}

fn not_a_name(raw: &str) -> Refused {
    refused(DESTINATION_RULE, format!("{} is not a host name", truncate(raw, 80)))
}

/// For a TLS connection passed through on its SNI: the firewall's own resolution of the SNI, on
/// port 443, public addresses only. A CONNECT target that is another name is refused.
pub async fn passthrough(flow: &Flow, sni: &str, config: &Config) -> Result<Destination, Refused> {
    let name = wire_name(sni).ok_or_else(|| not_a_name(sni))?;
    if let Some(d) = dev_resolved(&name, config) {
        return Ok(d);
    }
    if connect_ip(flow).is_none() && wire_name(&flow.connect.host).as_deref() != Some(name.as_str()) {
        return Err(mismatch(&name, &flow.connect.host));
    }
    if flow.connect.port != PASSTHROUGH_PORT {
        return Err(refused(
            "passthrough_mismatch",
            format!("{name} is passed through on port 443 only, not {}", flow.connect.port),
        ));
    }
    public(flow, name, PASSTHROUGH_PORT, config).await
}

/// For a TLS connection passed through on an organization's `tunnel` rule: the firewall's own
/// resolution of the SNI, on the port the client named (a rule may pin it), public addresses only.
pub async fn tunnel(flow: &Flow, sni: &str, config: &Config) -> Result<Destination, Refused> {
    let name = wire_name(sni).ok_or_else(|| not_a_name(sni))?;
    if let Some(d) = dev_resolved(&name, config) {
        return Ok(d);
    }
    if connect_ip(flow).is_none() && wire_name(&flow.connect.host).as_deref() != Some(name.as_str()) {
        return Err(mismatch(&name, &flow.connect.host));
    }
    public(flow, name, flow.connect.port, config).await
}

/// For raw TCP on a `tunnel` rule that names this address and port: the CONNECT target itself (the
/// rule is written against it). Uninspected, so public addresses only, as #511 keeps it.
pub async fn raw_tunnel(flow: &Flow, config: &Config) -> Result<Destination, Refused> {
    let name = wire_name(&flow.connect.host).ok_or_else(|| not_a_name(&flow.connect.host))?;
    public(flow, name, flow.connect.port, config).await
}

/// `name` resolved by the firewall, every address public, on `port`.
async fn public(flow: &Flow, name: String, port: u16, config: &Config) -> Result<Destination, Refused> {
    let addrs = resolve_all(&name, port)
        .await
        .map_err(|e| refused(NON_ROUTABLE_RULE, e))?;
    if let Some(a) = addrs
        .iter()
        .find(|a| !is_public(a.ip(), config.dev_private_passthrough))
    {
        let shown = if name == a.ip().to_string() {
            truncate(&name, 120)
        } else {
            truncate(&format!("{name} ({})", a.ip()), 120)
        };
        return Err(refused(
            NON_ROUTABLE_RULE,
            format!("{shown} is not a public address; an uninspected connection never goes there"),
        ));
    }
    let addr = pick(flow, &name, &addrs)?;
    Ok(Destination {
        name,
        port,
        addr: Some(addr),
    })
}

fn mismatch(name: &str, asked: &str) -> Refused {
    refused(
        DESTINATION_RULE,
        format!(
            "the TLS name is {} but the connection was asked for {}",
            truncate(name, 80),
            truncate(asked, 80)
        ),
    )
}

/// For an intercepted TLS connection: the SNI, or the CONNECT address when the client sent none,
/// resolved by the firewall, on the CONNECT port. Refused when any address is non-routable or the
/// firewall's own.
pub async fn intercepted(flow: &Flow, config: &Config) -> Result<Destination, Refused> {
    let raw = flow
        .sni
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&flow.connect.host);
    let name = wire_name(raw).ok_or_else(|| not_a_name(raw))?;
    // A CONNECT by another *name* than the TLS name (#511: the client said two different things).
    if connect_ip(flow).is_none() && wire_name(&flow.connect.host).as_deref() != Some(name.as_str()) {
        return Err(mismatch(&name, &flow.connect.host));
    }
    resolved(flow, name, flow.connect.port, config).await
}

/// For one plain-HTTP request: the host and port it names (absolute URI, else Host), resolved by
/// the firewall. There is no handshake to agree with, so the request's own host is the name.
pub async fn plain(flow: &Flow, host: &str, port: u16, config: &Config) -> Result<Destination, Refused> {
    let name = wire_name(host).ok_or_else(|| not_a_name(host))?;
    resolved(flow, name, port, config).await
}

/// An inspected destination. A name that does not resolve is not refused here: the rules still
/// judge the request, and the dial refuses it (addon.py: `_refuse_non_routable_http` is not strict,
/// `server_connect` is). Its address is then `None`, which nothing dials.
async fn resolved(flow: &Flow, name: String, port: u16, config: &Config) -> Result<Destination, Refused> {
    if let Some(d) = dev_resolved(&name, config) {
        return Ok(d);
    }
    let addrs = match resolve(&name, port).await {
        Ok(a) => a,
        Err(ResolveError::Refused(why)) => return Err(refused(NON_ROUTABLE_RULE, why)),
        Err(ResolveError::NotFound(why)) => {
            // The dial resolves again (a passing failure is not kept for the connection) and
            // refuses with the resolver's own words when it still fails.
            tracing::info!("[proxy] {why}; resolved again when it is dialled");
            return Ok(Destination { name, port, addr: None });
        }
    };
    let addr = pick(flow, &name, &addrs)?;
    Ok(Destination {
        name,
        port,
        addr: Some(addr),
    })
}

/// A CONNECT target that is itself an address the firewall never connects to (addon.py
/// `_refuse_non_routable_http` checks the connection's own address first, whatever the request
/// names): the refusal text, or `None`.
pub fn connect_refusal(flow: &Flow, config: &Config) -> Option<String> {
    // Smoke rigs map names onto local stand-ins and CONNECT to those addresses.
    if flow.sni.as_deref().is_some_and(|s| config.dev_resolve.contains_key(s)) {
        return None;
    }
    let ip = connect_ip(flow)?;
    crate::net::target::refusal(ip, &ip.to_string())
}

/// The client's address when it is one of the name's (keeps its choice among them), else the
/// first IPv4 one, else the first.
fn pick(flow: &Flow, name: &str, addrs: &[SocketAddr]) -> Result<SocketAddr, Refused> {
    let client = connect_ip(flow);
    let dial = client
        .and_then(|ip| addrs.iter().find(|a| same_ip(a.ip(), ip)))
        .or_else(|| addrs.iter().find(|a| a.is_ipv4()))
        .or(addrs.first())
        .copied()
        .ok_or_else(|| refused(NON_ROUTABLE_RULE, format!("could not resolve {name}")))?;
    if client.is_some_and(|ip| !same_ip(dial.ip(), ip)) {
        tracing::info!(
            "[proxy] {name}: CONNECT named {}, not one of its addresses; dialling {}",
            flow.connect.host,
            dial.ip()
        );
    }
    Ok(dial)
}

/// Smoke tests only (`MITM_DEV_RESOLVE`): the name is where the test says.
fn dev_resolved(name: &str, config: &Config) -> Option<Destination> {
    let addr = *config.dev_resolve.get(name)?;
    Some(Destination {
        name: name.to_owned(),
        port: addr.port(),
        addr: Some(addr),
    })
}

/// Whether a request inside an intercepted tunnel names the tunnel's destination, from the raw
/// authority or Host it sent. The port is not compared: the request is dialled to the
/// destination's port whatever it says, and rules match names. A request that names no host at
/// all goes to the destination and claims nothing else; one whose host is not a name never agrees.
pub fn host_agrees(destination: &Destination, claimed: Option<&str>) -> bool {
    claimed.is_none_or(|h| wire_name(h).as_deref() == Some(destination.name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::Authority;
    use std::collections::HashMap;

    fn config() -> Config {
        Config::from_vars(SocketAddr::from(([127, 0, 0, 1], 0)), &HashMap::new()).expect("config")
    }

    fn flow(connect: &str, port: u16, sni: Option<&str>) -> Flow {
        let mut f = Flow::new(
            IpAddr::from([10, 0, 0, 3]),
            Authority {
                host: connect.into(),
                port,
            },
        );
        f.sni = sni.map(str::to_owned);
        f
    }

    #[tokio::test]
    async fn intercepted_dials_the_firewalls_own_answer() {
        // An IP-literal SNI resolves to itself; the CONNECT target is something else entirely.
        let d = intercepted(&flow("198.51.100.7", 8443, Some("93.184.216.34")), &config()).await;
        assert_eq!(
            d,
            Ok(Destination {
                name: "93.184.216.34".into(),
                port: 8443,
                addr: Some(SocketAddr::from(([93, 184, 216, 34], 8443))),
            })
        );
        // No SNI: the CONNECT address is the name.
        let d = intercepted(&flow("93.184.216.9", 443, None), &config()).await;
        assert_eq!(d.map(|d| d.addr), Ok(Some(SocketAddr::from(([93, 184, 216, 9], 443)))));
    }

    #[tokio::test]
    async fn refuses_non_routable_names_and_addresses() {
        for (connect, sni) in [
            ("93.184.216.34", Some("169.254.169.254")),
            ("93.184.216.34", Some("localhost")),
            ("127.0.0.1", None),
            ("93.184.216.34", Some("[::ffff:169.254.169.254]")),
        ] {
            let r = intercepted(&flow(connect, 443, sni), &config()).await;
            assert!(
                matches!(
                    &r,
                    Err(Refused {
                        rule: NON_ROUTABLE_RULE,
                        ..
                    })
                ),
                "{connect} {sni:?}: {r:?}"
            );
        }
        // Private addresses are for the rules to judge.
        assert!(
            plain(&flow("10.0.0.50", 80, None), "10.0.0.50", 80, &config())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_left_to_the_dial() {
        // `.invalid` never resolves (RFC 6761): the rules still get to judge the request.
        let d = intercepted(&flow("93.184.216.34", 443, Some("nowhere.invalid")), &config()).await;
        assert!(
            d.as_ref()
                .is_ok_and(|d| d.addr.is_none() && d.name == "nowhere.invalid"),
            "{d:?}"
        );
        // Passthrough is strict: nothing passes on a name the firewall cannot resolve.
        let p = passthrough(&flow("93.184.216.34", 443, None), "nowhere.invalid", &config()).await;
        assert!(matches!(
            p,
            Err(Refused {
                rule: NON_ROUTABLE_RULE,
                ..
            })
        ));
        // The CONNECT address itself is checked first.
        assert!(
            connect_refusal(&flow("169.254.169.254", 80, None), &config()).is_some_and(|w| w.contains("link-local"))
        );
        assert!(connect_refusal(&flow("93.184.216.34", 80, None), &config()).is_none());
    }

    #[tokio::test]
    async fn passthrough_is_public_on_443_and_for_its_own_name() {
        let r = passthrough(&flow("93.184.216.34", 8443, None), "93.184.216.34", &config()).await;
        assert!(matches!(
            r,
            Err(Refused {
                rule: "passthrough_mismatch",
                ..
            })
        ));
        // Documentation and private ranges are not public (Python's is_global).
        for a in ["10.0.0.5", "203.0.113.5", "100.64.0.1"] {
            let r = passthrough(&flow(a, 443, None), a, &config()).await;
            assert!(
                matches!(
                    r,
                    Err(Refused {
                        rule: NON_ROUTABLE_RULE,
                        ..
                    })
                ),
                "{a}: {r:?}"
            );
        }
        // A CONNECT that names another host than the SNI.
        let r = passthrough(&flow("evil.example", 443, None), "cp.example", &config()).await;
        assert!(
            matches!(
                r,
                Err(Refused {
                    rule: DESTINATION_RULE,
                    ..
                })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn a_name_is_one_string_or_refused() {
        // The probe from the host review: brackets that are not the whole host are not unwrapped.
        assert_eq!(wire_name("[attacker.example].tailscale.com"), None);
        assert_eq!(wire_name("[api.telegram.org]junk"), None);
        assert_eq!(wire_name("[api.telegram.org]"), None);
        assert_eq!(wire_name("[2001:DB8::1]"), Some("2001:db8::1".into()));
        assert_eq!(wire_name("[2001:db8::1]:8443"), Some("2001:db8::1".into()));
        assert_eq!(wire_name("[2001:db8::1]x"), None);
        assert_eq!(wire_name("2001:db8::1"), Some("2001:db8::1".into()));
        assert_eq!(wire_name("Example.COM.:80"), Some("example.com".into()));
        assert_eq!(wire_name("bücher.example"), Some("xn--bcher-kva.example".into()));
        assert_eq!(wire_name("a b.example"), None);
        assert_eq!(wire_name("a_b.example"), None);
        assert_eq!(wire_name("-a.example"), None);
        assert_eq!(wire_name("a..example"), None);
        assert_eq!(wire_name("example.com:x"), None);
        assert_eq!(wire_name(""), None);
        assert_eq!(wire_name("localhost"), Some("localhost".into()));
    }

    #[test]
    fn a_request_must_name_its_tunnels_host() {
        let d = Destination {
            name: "api.example.com".into(),
            port: 443,
            addr: Some(SocketAddr::from(([203, 0, 113, 5], 443))),
        };
        assert!(host_agrees(&d, Some("api.example.com")));
        assert!(host_agrees(&d, Some("API.Example.com.")));
        assert!(host_agrees(&d, Some("api.example.com:443")));
        assert!(host_agrees(&d, None));
        assert!(!host_agrees(&d, Some("api.telegram.org")));
        assert!(!host_agrees(&d, Some("example.com")));
        assert!(!host_agrees(&d, Some("[api.example.com]junk")));
        assert!(!host_agrees(&d, Some("[api.example.com]")));
    }
}
