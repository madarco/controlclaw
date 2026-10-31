//! Pairing codes (`crate::pairing`): the admin makes one for each machine that joins, lists the
//! ones still waiting (never with the code) and revokes one. The pairing itself is `POST /pair` on
//! its own listener, with no login.

use std::net::IpAddr;

use http::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{Reply, Route};
use crate::pairing::{self, CodeFor, NewCode, PendingCode};

const TAG: &str = "pairing";

pub fn routes() -> Vec<Route> {
    vec![
        Route::write::<NewCodeBody, NewCode, _, _>(
            Method::POST,
            "/api/pairing/codes",
            TAG,
            "Make a one-time pairing code for one machine",
            |c, b| async move {
                let f = CodeFor {
                    name: b.name.as_deref(),
                    ttl_min: b.ttl_minutes,
                    address: b.address.as_deref(),
                    replace: b.replace,
                };
                pairing::create_code(&c.db, &f)
                    .map(|code| Reply::ok(&code))
                    .map_err(Reply::bad)
            },
        ),
        Route::get::<(), PendingCodes, _, _>(
            "/api/pairing/codes",
            TAG,
            "The pairing codes still waiting, without the codes",
            |c| async move {
                Ok(Reply::ok(&PendingCodes {
                    codes: pairing::list_pending(&c.db)?,
                }))
            },
        ),
        Route::get::<(), PairAddress, _, _>(
            "/api/pairing/address",
            TAG,
            "Where agents' machines reach this firewall's pairing endpoint, when it knows",
            |_| async move { Ok(Reply::ok(&pair_address(|k| std::env::var(k).ok()))) },
        ),
        Route::write::<super::NoBody, Revoked, _, _>(
            Method::DELETE,
            "/api/pairing/codes/:id",
            TAG,
            "Revoke a waiting pairing code",
            |c, _| async move {
                let id: i64 = c.param("id").parse().map_err(|_| Reply::not_found("Pairing code"))?;
                if !pairing::revoke(&c.db, id)? {
                    return Err(Reply::not_found("Pairing code"));
                }
                Ok(Reply::ok(&Revoked { id }))
            },
        ),
    ]
}

/// What the admin says about the machine the code is for.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewCodeBody {
    /// The agent's name on the firewall; the machine's own name when left out.
    #[serde(default)]
    pub name: Option<String>,
    /// How long the code works: 10 minutes by default, at most 60.
    #[serde(default)]
    pub ttl_minutes: Option<i64>,
    /// The IPv4 address the proxy will see the machine at, when it is not the one pairing comes
    /// from (a NAT, a reverse proxy, a container on the firewall's machine).
    #[serde(default)]
    pub address: Option<String>,
    /// Whether the machine may take the place of an agent already at its address.
    #[serde(default)]
    pub replace: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PendingCodes {
    pub codes: Vec<PendingCode>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Revoked {
    pub id: i64,
}

/// The address `controlclaw connect --firewall` takes, from what the firewall was set up with.
#[derive(Debug, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PairAddress {
    /// `false` with `PAIR_BIND=off`: this firewall takes no pairings.
    pub open: bool,
    /// The pairing port (`PAIR_BIND`'s, 8801 by default); `null` when closed.
    pub port: Option<u16>,
    /// On the firewall's network: the proxy's host (`PAIR_PROXY_ADDR`, which install.sh writes
    /// from `--listen`) and the pairing port. `null` when the firewall does not know it.
    pub url: Option<String>,
    /// From another network, over WireGuard's public address (`WG_ENDPOINT`), when that differs.
    pub remote_url: Option<String>,
}

/// Where the pairing endpoint listens when `PAIR_BIND` is not set.
pub const PAIR_DEFAULT_BIND: &str = "0.0.0.0:8801";

/// `PAIR_BIND` as the listener (mitm-agent `local_pair`) takes it: the default when unset, `None`
/// for `off`. The panel's address reads it through this too, so the two cannot differ.
pub fn pair_bind(raw: Option<String>) -> Option<String> {
    let bind = raw.unwrap_or_else(|| PAIR_DEFAULT_BIND.into());
    (bind != "off").then_some(bind)
}

/// A `host:port`, `[v6]:port`, bare host or bare IPv6 address: the host without brackets, and the
/// port when there is one.
fn split_addr(addr: &str) -> (String, Option<u16>) {
    let addr = addr.trim();
    if addr.parse::<IpAddr>().is_ok() {
        return (addr.to_string(), None);
    }
    match addr.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && (!h.contains(':') || h.starts_with('[')) => {
            (h.trim_matches(['[', ']']).to_string(), p.parse().ok())
        }
        _ => (addr.trim_matches(['[', ']']).to_string(), None),
    }
}

/// A host other machines reach: not empty, loopback or a wildcard. IPv6 comes back in brackets.
fn reachable(host: &str) -> Option<String> {
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() || ip.is_unspecified() => None,
        Ok(IpAddr::V6(_)) => Some(format!("[{host}]")),
        _ => Some(host.to_string()),
    }
}

/// From the firewall's settings (`get` reads one; the environment when served).
pub fn pair_address(get: impl Fn(&str) -> Option<String>) -> PairAddress {
    let closed = PairAddress {
        open: false,
        port: None,
        url: None,
        remote_url: None,
    };
    let Some(bind) = pair_bind(get("PAIR_BIND")) else {
        return closed;
    };
    let (bind_host, Some(port)) = split_addr(&bind) else {
        // No port: the listener cannot start on it.
        return closed;
    };
    let host_of = |k: &str| get(k).map(|v| split_addr(&v).0).and_then(|h| reachable(&h));
    let everywhere = bind_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_unspecified());
    let url_of = |h: String| format!("http://{h}:{port}");
    // Bound to one address: that is where machines reach it (none beyond this one on loopback).
    let local = if everywhere {
        host_of("PAIR_PROXY_ADDR")
    } else {
        reachable(&bind_host)
    };
    let remote = host_of("WG_ENDPOINT").filter(|h| everywhere && Some(h) != local.as_ref());
    PairAddress {
        open: true,
        port: Some(port),
        url: local.map(url_of),
        remote_url: remote.map(url_of),
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;

    fn with(vars: &[(&str, &str)]) -> PairAddress {
        let m: std::collections::HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        pair_address(|k| m.get(k).cloned())
    }

    #[test]
    fn nothing_known() {
        assert_eq!(
            with(&[]),
            PairAddress {
                open: true,
                port: Some(8801),
                url: None,
                remote_url: None
            }
        );
    }

    #[test]
    fn closed_as_the_listener_reads_it() {
        assert!(!with(&[("PAIR_BIND", "off"), ("PAIR_PROXY_ADDR", "10.0.0.5:8080")]).open);
        assert!(!with(&[("PAIR_BIND", "")]).open, "no port: the listener does not start");
        assert_eq!(pair_bind(None).as_deref(), Some(PAIR_DEFAULT_BIND));
        assert_eq!(pair_bind(Some("off".into())), None);
    }

    #[test]
    fn the_proxy_host_and_the_pairing_port() {
        let a = with(&[("PAIR_PROXY_ADDR", "10.0.0.5:8080")]);
        assert_eq!(a.url.as_deref(), Some("http://10.0.0.5:8801"));
        let a = with(&[("PAIR_PROXY_ADDR", " 10.0.0.5:8080 "), ("PAIR_BIND", "0.0.0.0:9901")]);
        assert_eq!(a.url.as_deref(), Some("http://10.0.0.5:9901"));
    }

    #[test]
    fn a_bind_to_one_address_is_that_address() {
        let a = with(&[
            ("PAIR_BIND", "10.0.0.7:8801"),
            ("PAIR_PROXY_ADDR", "10.0.0.5:8080"),
            ("WG_ENDPOINT", "203.0.113.7:51820"),
        ]);
        assert_eq!((a.url.as_deref(), a.remote_url), (Some("http://10.0.0.7:8801"), None));
        let a = with(&[("PAIR_BIND", "127.0.0.1:8801"), ("PAIR_PROXY_ADDR", "10.0.0.5:8080")]);
        assert_eq!((a.open, a.url), (true, None), "loopback: only this machine");
    }

    #[test]
    fn wireguard_from_another_network() {
        let a = with(&[("WG_ENDPOINT", "203.0.113.7:51820")]);
        assert_eq!(
            (a.url, a.remote_url.as_deref()),
            (None, Some("http://203.0.113.7:8801"))
        );
        let a = with(&[("WG_ENDPOINT", "10.0.0.5:51820"), ("PAIR_PROXY_ADDR", "10.0.0.5:8080")]);
        assert_eq!(a.remote_url, None, "the same host once");
    }

    #[test]
    fn loopback_wildcards_and_ipv6() {
        for v in ["127.0.0.1:8080", "0.0.0.0:8080", "localhost:8080", "[::1]:8080", "::1"] {
            assert_eq!(with(&[("PAIR_PROXY_ADDR", v)]).url, None, "{v}");
        }
        for v in ["[fd00::5]:8080", "fd00::5"] {
            assert_eq!(
                with(&[("PAIR_PROXY_ADDR", v)]).url.as_deref(),
                Some("http://[fd00::5]:8801"),
                "{v}"
            );
        }
        assert_eq!(
            with(&[("PAIR_PROXY_ADDR", "fw.lan")]).url.as_deref(),
            Some("http://fw.lan:8801")
        );
    }
}
