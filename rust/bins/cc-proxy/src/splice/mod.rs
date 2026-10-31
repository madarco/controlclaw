//! Relaying bytes without reading them. Owner: W1.
//!
//! What is passed through untouched (appendix F §1.4, feature 9): Tailscale for a box on its
//! owner's tailnet (by SNI) and the org's `tunnel` rules (TLS by SNI, raw TCP by IP and port).
//! Nothing passes through for a locked agent. The control plane and the backup store were
//! passed through by the addon; the owner decided on 2026-10-28 that they are intercepted. Each relay dials a destination `net::destination` checked, never the CONNECT
//! target as it came.
//!
//! W1 P7/P8: byte counting for residential and Meet TURN (`on_tcp_bytes`), budgets.

pub mod meet;

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::flow::Flow;
use crate::net::Shared;
use crate::net::hosts::host_matches;
use crate::net::identity::Ident;
use crate::net::rules::RuleView;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Tailscale's coordination, login and DERP hosts (addon.py `TAILSCALE_HOSTS`). Not configurable:
/// they are Tailscale's own.
pub const TAILSCALE_HOSTS: &[&str] = &["*.tailscale.com"];

/// Why a TLS connection is passed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// Tailscale, and the control plane and backup store for a box not marked `cp_inspect`:
    /// reached on 443, public addresses only.
    BuiltIn,
    /// An organization's `tunnel` rule: on the port the client named, public addresses only.
    Tunnel,
}

/// Whether this TLS connection goes through untouched (addon.py `tls_clienthello`). `ident` is the
/// agent's identity entry, read once for the connection.
pub fn tls_passthrough(shared: &Shared, flow: &Flow, ident: Option<&Ident>) -> Option<Pass> {
    let sni = flow.sni.as_deref().filter(|s| !s.is_empty())?;
    // The roll-out (addon.py `cp_inspected`): a box the firewall agent has not seen trust its CA
    // keeps its control plane (also under the stop) and its backup store (not under the stop)
    // passed through by name, as before, so a firewall updated before its agents does not cut them
    // off. Every other box's traffic to them is inspected (`http::backup`).
    let cfg = &shared.ctx.config;
    let locked = ident.is_some_and(|i| i.locked);
    if flow.connect.port == crate::net::destination::PASSTHROUGH_PORT
        // addon.py `cp_inspected`: a source with no agent, or not in the map, is inspected.
        && !(flow.vm_id.is_none() || ident.is_none_or(|i| i.cp_inspect))
    {
        let legacy = [
            cfg.control_plane_host.as_deref(),
            (!locked).then_some(cfg.backup_host.as_deref()).flatten(),
        ];
        if legacy.iter().flatten().any(|h| host_matches(h, sni)) {
            return Some(Pass::BuiltIn);
        }
    }
    if locked {
        // Under an emergency stop nothing passes through: a passed-through connection is never seen
        // again. The control plane, which the vm-agent's channel and the disk-unlock relay ride,
        // is intercepted and allowed by name (`http`).
        return None;
    }
    // The control plane and the backup store are intercepted, not passed through (owner,
    // 2026-10-28): the control plane's host routes by the inner Host, so a passthrough by name
    // reached any project on it. `http` holds them to their own Host (and bucket).
    if ident.is_some_and(|i| i.tailscale) && TAILSCALE_HOSTS.iter().any(|h| host_matches(h, sni)) {
        return Some(Pass::BuiltIn);
    }
    tunnel_matches(
        &shared.rules.get(),
        sni,
        Some(flow.connect.port),
        flow.vm_id.as_deref(),
        false,
    )
    .then_some(Pass::Tunnel)
}

/// Whether a `tunnel` rule names this destination (addon.py `tunnel_match`): TLS by SNI on any port
/// (or the rule's `match_port`), raw TCP by the CONNECT address and port. Never for a locked agent:
/// an emergency stop outranks every rule the organization wrote.
pub fn tunnel_matches(rules: &[RuleView], host: &str, port: Option<u16>, vm_id: Option<&str>, locked: bool) -> bool {
    if locked || (host.is_empty() && port.is_none()) {
        return false;
    }
    rules.iter().any(|rule| {
        rule.effect.as_deref() == Some("tunnel")
            && rule.applies_to(vm_id)
            && (host.is_empty() || rule.domain_matches(host, ""))
            && rule.port_matches(port)
    })
}

/// Dial the flow's checked destination (never the CONNECT target as such), write the bytes already
/// read, then copy both ways until both sides are done.
pub async fn passthrough(mut client: TcpStream, buffered: Vec<u8>, flow: &Flow) -> anyhow::Result<()> {
    let d = flow
        .destination()
        .ok_or_else(|| anyhow::anyhow!("passthrough without a checked destination"))?;
    // Never a name that did not resolve, nor any non-routable address, whatever path led here.
    let addr = d
        .addr
        .ok_or_else(|| anyhow::anyhow!("passthrough refused: {} did not resolve", d.name))?;
    if let Some(kind) = crate::net::target::non_routable_kind(addr.ip()) {
        anyhow::bail!("passthrough refused: {} is a {kind} address", addr.ip());
    }
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
    let _ = upstream.set_nodelay(true);
    upstream.write_all(&buffered).await?;
    drop(buffered);
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::rules::Rules;

    #[test]
    fn tunnel_rules_match_like_the_addon() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("rules.json");
        std::fs::write(
            &path,
            r#"[{"name":"web","effect":"allow","match_domain":"*"},
                {"name":"mine","effect":"tunnel","match_domain":"*.example.com","vm_id":"b"},
                {"name":"raw","effect":"tunnel","match_domain":"203.0.113.5","match_port":5432.9},
                {"name":"nodomain","effect":"tunnel","match_port":22},
                {"name":"badport","effect":"tunnel","match_domain":"203.0.113.6","match_port":"ssh"}]"#,
        )?;
        let rules = Rules::new(&path).get();
        let m =
            |host: &str, port: u16, vm: &str, locked: bool| tunnel_matches(&rules, host, Some(port), Some(vm), locked);
        assert!(m("203.0.113.5", 5432, "a", false));
        assert!(!m("203.0.113.5", 5433, "a", false));
        assert!(
            !m("203.0.113.5", 5432, "a", true),
            "an emergency stop outranks a tunnel"
        );
        assert!(m("api.example.com", 443, "b", false));
        assert!(!m("api.example.com", 443, "a", false), "another agent's rule");
        assert!(
            !m("203.0.113.9", 22, "a", false),
            "a rule without a domain never matches a host"
        );
        assert!(
            !m("203.0.113.6", 22, "a", false),
            "a port int() refuses matches nothing"
        );
        assert!(!tunnel_matches(&rules, "", None, Some("a"), false));
        Ok(())
    }
}
