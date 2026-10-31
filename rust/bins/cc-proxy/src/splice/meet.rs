//! The Meet TURN media relay (appendix F feature 27; addon.py `_MeetingMedia`, `meeting_lease`,
//! `meeting_destination`, 3515-3641).
//!
//! A meeting's audio rides TLS to Google's TURN servers, which are never intercepted. An agent may
//! reach them only while it holds a meeting lease the firewall agent published
//! (`meeting-media.json`, read on every check): to `meet.turns.goog` or `workspace.turns.goog`, on
//! 443, at an IPv4 address in that name's Google range, at most 8 connections per lease, all of
//! them sharing one byte budget that is charged before each send. Every second, and on every send,
//! the lease is checked again; a revoked or spent lease closes the connection. One record per
//! connection when it ends.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::flow::Flow;
use crate::net::Ctx;

pub const MAX_BYTES: f64 = 512.0 * 1024.0 * 1024.0;
pub const MAX_SECONDS: f64 = 4.0 * 60.0 * 60.0;
pub const MAX_CONNECTIONS: u32 = 8;

/// An IPv4 network: its address and prefix length.
type Net = ([u8; 4], u8);

/// Google's published ranges for each TURN name (reviewed network policy, 2026-10-02).
const RANGES: &[(&str, &[Net])] = &[
    ("meet.turns.goog", &[([142, 250, 82, 0], 24)]),
    (
        "workspace.turns.goog",
        &[([74, 125, 250, 0], 24), ([74, 125, 247, 128], 32)],
    ),
];

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// When the proxy started: a lease must have started after it (`MEETING_PROXY_STARTED`).
fn started() -> f64 {
    static STARTED: OnceLock<f64> = OnceLock::new();
    *STARTED.get_or_init(now)
}

/// Call at start, so leases from before this process are never honoured.
pub fn mark_start() {
    let _ = started();
}

fn cidr(net: &str) -> Option<Net> {
    let (a, b) = net.split_once('/').unwrap_or((net, "32"));
    Some((
        a.parse::<Ipv4Addr>().ok()?.octets(),
        b.parse().ok().filter(|b| *b <= 32)?,
    ))
}

fn in_net(ip: Ipv4Addr, (net, bits): Net) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(bits))
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

/// Whether `sni` is a Meet TURN name (`sni in MEETING_MEDIA_RANGES`).
pub fn is_meet_name(ctx: &Ctx, sni: &str) -> bool {
    RANGES.iter().any(|(n, _)| *n == sni) || ctx.config.dev_meet_ranges.iter().any(|(n, _)| n == sni)
}

/// addon.py `meeting_destination`: port 443, an IPv4 address in that name's ranges.
pub fn destination_ok(ctx: &Ctx, sni: &str, host: &str, port: u16) -> bool {
    in_ranges(&ctx.config.dev_meet_ranges, sni, host, port)
}

fn in_ranges(dev: &[(String, String)], sni: &str, host: &str, port: u16) -> bool {
    if port != 443 {
        return false;
    }
    let Ok(IpAddr::V4(ip)) = host.parse::<IpAddr>() else {
        return false;
    };
    let built_in = RANGES
        .iter()
        .filter(|(n, _)| *n == sni)
        .flat_map(|(_, nets)| nets.iter().copied())
        .any(|net| in_net(ip, net));
    built_in
        || dev
            .iter()
            .filter(|(n, _)| n == sni)
            .filter_map(|(_, c)| cidr(c))
            .any(|net| in_net(ip, net))
}

/// One valid lease: its id, budget and deadline.
#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub id: String,
    pub max_bytes: f64,
    pub deadline: f64,
}

/// addon.py `meeting_lease`: the agent's lease, if every field has the type and range the addon
/// checks; `lease_id` asks for that one lease only. Missing, broken or locked: none.
pub fn lease(ctx: &Ctx, vm_id: Option<&str>, lease_id: Option<&str>) -> Option<Lease> {
    let vm_id = vm_id.filter(|v| !v.is_empty())?;
    if ctx.locked(Some(vm_id)) {
        return None;
    }
    // Read on every check: missing, truncated or unreadable revokes all.
    let all: Value = serde_json::from_slice(&std::fs::read(&ctx.config.meeting_media_path).ok()?).ok()?;
    valid(all.as_object()?.get(vm_id)?, lease_id, started(), now())
}

/// One relay's view of its lease. The addon re-reads the file on every send; here each send costs
/// a `stat`: the file is read again when its inode, size or mtime changed (the agent replaces it by
/// rename) and on the one-second tick whatever they say, and the entry's times are checked against
/// the clock every time.
struct Watched {
    path: std::path::PathBuf,
    stamp: Option<(u64, u64, SystemTime)>,
    entry: Option<Value>,
}

impl Watched {
    fn new(ctx: &Ctx) -> Self {
        Watched {
            path: ctx.config.meeting_media_path.clone(),
            stamp: None,
            entry: None,
        }
    }

    fn stamp(&self) -> Option<(u64, u64, SystemTime)> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&self.path).ok()?;
        Some((m.ino(), m.len(), m.modified().ok()?))
    }

    fn current(&mut self, ctx: &Ctx, flow: &Flow, lease_id: &str, fresh: bool) -> Option<Lease> {
        let vm_id = flow.vm_id.as_deref().filter(|v| !v.is_empty())?;
        if ctx.locked(Some(vm_id)) {
            return None;
        }
        let stamp = self.stamp();
        if fresh || stamp.is_none() || stamp != self.stamp {
            self.stamp = stamp;
            self.entry = std::fs::read(&self.path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .and_then(|all| all.get(vm_id).cloned());
        }
        valid(self.entry.as_ref()?, Some(lease_id), started(), now())
    }
}

/// One agent's entry checked as the addon checks it, against the proxy's start and the time now.
fn valid(entry: &Value, lease_id: Option<&str>, proxy_started: f64, t: f64) -> Option<Lease> {
    let l = entry.as_object()?;
    // `type(v) in (int, float)`: a boolean is not a number here.
    let num = |k: &str| l.get(k).filter(|v| v.is_number()).and_then(Value::as_f64);
    let (start, expiry, deadline, budget) = (num("started")?, num("expires")?, num("deadline")?, num("max_bytes")?);
    let ok = proxy_started <= start
        && start <= t
        && t < expiry
        && expiry <= deadline.min(t + 60.0)
        && start < deadline
        && deadline <= start + MAX_SECONDS
        && 0.0 < budget
        && budget <= MAX_BYTES;
    let id = l.get("id")?.as_str()?;
    let id_ok = id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok || !id_ok || lease_id.is_some_and(|want| want != id) {
        return None;
    }
    Some(Lease {
        id: id.to_owned(),
        max_bytes: budget,
        deadline,
    })
}

/// Bytes and connections per lease, kept until the lease's deadline across reconnects.
#[derive(Debug, Default)]
struct Usage {
    bytes: f64,
    connections: u32,
    deadline: f64,
}

fn usage() -> &'static Mutex<std::collections::HashMap<String, Usage>> {
    static USAGE: OnceLock<Mutex<std::collections::HashMap<String, Usage>>> = OnceLock::new();
    USAGE.get_or_init(Default::default)
}

fn entry<'a>(u: &'a mut std::collections::HashMap<String, Usage>, lease: &Lease) -> &'a mut Usage {
    u.entry(lease.id.clone()).or_insert_with(|| Usage {
        deadline: lease.deadline,
        ..Usage::default()
    })
}

/// Take one of the lease's 8 connections, if one is free; `relay` gives it back.
pub fn reserve(lease: &Lease) -> bool {
    let mut u = usage().lock().unwrap_or_else(PoisonError::into_inner);
    // Spent budgets are kept until the lease's deadline, across reconnects and renewals.
    let t = now();
    u.retain(|_, x| x.deadline >= t || x.connections > 0);
    let e = entry(&mut u, lease);
    if e.connections >= MAX_CONNECTIONS {
        return false;
    }
    e.connections += 1;
    true
}

/// Relay one connection, `reserve`d: the client's TLS bytes go to the address it asked for (inside
/// Google's range, already checked), untouched, while the lease holds and the budget lasts.
pub async fn relay(
    ctx: &Ctx,
    client: TcpStream,
    buffered: Vec<u8>,
    flow: &Flow,
    sni: &str,
    lease: Lease,
) -> anyhow::Result<()> {
    let opened = Instant::now();
    let t0 = now();
    let counts = Arc::new(Mutex::new((0u64, 0u64)));
    let reason = run(ctx, client, buffered, flow, &lease, counts.clone()).await;
    {
        let mut u = usage().lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(e) = u.get_mut(&lease.id) {
            e.connections = e.connections.saturating_sub(1);
        }
    }
    let (bytes_in, bytes_out) = *counts.lock().unwrap_or_else(PoisonError::into_inner);
    let id = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(format!("{t0}{}", flow.id).as_bytes()))
    };
    ctx.log.append_value(&json!({
        "flow_id": format!("meet_{}", &id[..24]),
        "ts": crate::log::now(),
        "tenant": ctx.config.tenant,
        "vm_id": flow.vm_id,
        "host": sni,
        "port": 443,
        "effect": "tunnel",
        "rule": "meet-media-v1",
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "duration_ms": u64::try_from(opened.elapsed().as_millis()).unwrap_or(u64::MAX),
        "reason": reason,
        "rule_id": null,
    }));
    Ok(())
}

/// Charge `n` bytes to the lease before they go: false when the budget would be passed.
fn charge(lease: &Lease, n: usize) -> bool {
    let mut u = usage().lock().unwrap_or_else(PoisonError::into_inner);
    let e = entry(&mut u, lease);
    if e.bytes + n as f64 > lease.max_bytes {
        return false;
    }
    e.bytes += n as f64;
    true
}

/// Whether the connection may go on: the lease still valid, the connections and bytes in bounds.
fn still_ok(ctx: &Ctx, flow: &Flow, lease: &Lease, watched: &mut Watched, fresh: bool) -> bool {
    let Some(current) = watched.current(ctx, flow, &lease.id, fresh) else {
        return false;
    };
    let u = usage().lock().unwrap_or_else(PoisonError::into_inner);
    u.get(&lease.id)
        .is_some_and(|x| x.connections <= MAX_CONNECTIONS && x.bytes < current.max_bytes)
}

async fn run(
    ctx: &Ctx,
    client: TcpStream,
    buffered: Vec<u8>,
    flow: &Flow,
    lease: &Lease,
    counts: Arc<Mutex<(u64, u64)>>,
) -> &'static str {
    let Ok(ip) = flow.connect.host.parse::<IpAddr>() else {
        return "revoked_or_limit";
    };
    let addr = SocketAddr::new(ip, 443);
    let mut watched = Watched::new(ctx);
    let Ok(Ok(mut site)) = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await else {
        return "closed";
    };
    if !still_ok(ctx, flow, lease, &mut watched, false) {
        return "revoked_or_limit";
    }
    // The ClientHello is charged like every other byte, handshakes included.
    if !charge(lease, buffered.len()) {
        return "byte_limit";
    }
    if site.write_all(&buffered).await.is_err() {
        return "closed";
    }
    counts.lock().unwrap_or_else(PoisonError::into_inner).1 += buffered.len() as u64;
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = site.into_split();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let (mut a, mut b) = (vec![0u8; 16 * 1024], vec![0u8; 16 * 1024]);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if !still_ok(ctx, flow, lease, &mut watched, true) {
                    return "revoked_or_limit";
                }
            }
            r = cr.read(&mut a) => {
                let Ok(n) = r else { return "closed" };
                if n == 0 {
                    return "closed";
                }
                if !still_ok(ctx, flow, lease, &mut watched, false) {
                    return "revoked_or_limit";
                }
                if !charge(lease, n) {
                    return "byte_limit";
                }
                if sw.write_all(&a[..n]).await.is_err() {
                    return "closed";
                }
                counts.lock().unwrap_or_else(PoisonError::into_inner).1 += n as u64;
            }
            r = sr.read(&mut b) => {
                let Ok(n) = r else { return "closed" };
                if n == 0 {
                    return "closed";
                }
                if !still_ok(ctx, flow, lease, &mut watched, false) {
                    return "revoked_or_limit";
                }
                if !charge(lease, n) {
                    return "byte_limit";
                }
                if cw.write_all(&b[..n]).await.is_err() {
                    return "closed";
                }
                counts.lock().unwrap_or_else(PoisonError::into_inner).0 += n as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_googles() {
        assert!(in_net(Ipv4Addr::new(142, 250, 82, 9), RANGES[0].1[0]));
        assert!(!in_net(Ipv4Addr::new(142, 250, 83, 9), RANGES[0].1[0]));
        assert!(in_net(Ipv4Addr::new(74, 125, 247, 128), RANGES[1].1[1]));
        assert!(!in_net(Ipv4Addr::new(74, 125, 247, 129), RANGES[1].1[1]));
        assert_eq!(cidr("203.0.113.0/24"), Some(([203, 0, 113, 0], 24)));
        assert_eq!(cidr("bad"), None);
    }

    // test_meeting_media.py `test_destinations`.
    #[test]
    fn destinations() {
        assert!(in_ranges(&[], "meet.turns.goog", "142.250.82.1", 443));
        assert!(in_ranges(&[], "workspace.turns.goog", "74.125.247.128", 443));
        for (sni, host, port) in [
            ("meet.turns.goog", "74.125.250.1", 443),
            ("meet.google.com", "142.250.82.1", 443),
            ("meet.turns.goog", "142.250.82.1", 19305),
            ("meet.turns.goog", "169.254.169.254", 443),
            ("meet.turns.goog", "::ffff:142.250.82.1", 443),
            ("meet.turns.goog", "evil.test", 443),
        ] {
            assert!(!in_ranges(&[], sni, host, port), "{sni} {host} {port}");
        }
        let dev = [("meet.turns.goog".to_owned(), "203.0.113.0/24".to_owned())];
        assert!(in_ranges(&dev, "meet.turns.goog", "203.0.113.10", 443));
        assert!(!in_ranges(&dev, "workspace.turns.goog", "203.0.113.10", 443));
    }

    // test_meeting_media.py `test_lease_failures`.
    #[test]
    fn lease_failures() {
        let t = 1_000_000.0;
        let ok =
            json!({"id": "a".repeat(32), "started": t, "expires": t + 30.0, "deadline": t + 3600.0, "max_bytes": 4096});
        assert!(valid(&ok, None, t, t).is_some());
        assert!(valid(&ok, Some(&"a".repeat(32)), t, t).is_some());
        assert!(valid(&ok, Some(&"b".repeat(32)), t, t).is_none());
        // A lease from before this proxy started is never honoured.
        assert!(valid(&ok, None, t + 1.0, t + 1.0).is_none());
        for change in [
            json!({"expires": t - 1.0}),
            json!({"expires": t + 3600.0}),
            json!({"max_bytes": MAX_BYTES + 1.0}),
            json!({"max_bytes": 0}),
            json!({"deadline": t + 86400.0}),
            json!({"started": t - 86400.0}),
            json!({"max_bytes": "4096"}),
            json!({"max_bytes": true}),
            json!({"id": "A".repeat(32)}),
            json!({"id": "a".repeat(31)}),
        ] {
            let mut bad = ok.clone();
            for (k, v) in change.as_object().expect("an object") {
                bad[k] = v.clone();
            }
            assert!(valid(&bad, None, t, t).is_none(), "{change}");
        }
        assert!(valid(&json!("x"), None, t, t).is_none());
    }

    // test_meeting_media.py `test_budget_is_shared_and_checked_before_sending`.
    #[test]
    fn budget_is_shared_and_charged_first() {
        let lease = Lease {
            id: "c".repeat(32),
            max_bytes: 10.0,
            deadline: now() + 100.0,
        };
        assert!(charge(&lease, 6));
        // A second connection on the same lease: 6 + 5 would pass 10, so nothing is sent.
        assert!(!charge(&lease, 5));
        assert!(charge(&lease, 4));
        assert!(!charge(&lease, 1));
        let u = usage().lock().expect("not poisoned");
        assert_eq!(u[&lease.id].bytes, 10.0);
    }
}
