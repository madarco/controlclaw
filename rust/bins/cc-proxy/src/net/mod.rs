//! The listener and the connection's first steps. Owner: W1.
//!
//! Every agent connection arrives as `CONNECT <ip>:<port>` from redsocks (appendix F §1.1). The
//! proxy answers 200, reads the client's first bytes and decides by them, as mitmproxy's
//! `next_layer` does: TLS (read the whole ClientHello, then pass through or intercept), HTTP, or
//! other TCP (dropped unless a rule names its IP and port). An absolute-form request
//! (`GET http://host/...`) is plain HTTP sent to the proxy itself.
//!
//! Nothing is dialled before that decision (mitmproxy's `connection_strategy=lazy`).

pub mod destination;
pub mod head;
pub mod hosts;
pub mod identity;
pub mod io;
pub mod rules;
pub mod target;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use cc_contracts::Maybe;
use cc_contracts::traffic::TrafficRecord;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::flow::{Authority, Flow, Pipeline};
use crate::http;
use crate::log::TrafficLog;
use crate::residential;
use crate::splice::{self, Pass};
use crate::tls::{self, HelloError};
use head::{Head, Protocol};

/// What every connection and every step reads: settings, the shared files, the log, the CA.
pub struct Ctx {
    pub config: Config,
    pub identities: identity::Identities,
    pub rules: rules::Rules,
    pub log: TrafficLog,
    /// The interception CA; `None` when it could not be loaded (then nothing is intercepted).
    pub ca: Option<crate::tls::ca::Ca>,
    pub upstream_tls: crate::tls::config::Upstream,
    /// The upstream TLS to sites: BoringSSL copying the agent's ClientHello.
    pub mirror: crate::tls::mirror::UpstreamTls,
    /// `exit.json`: the residential exit.
    pub exit: crate::residential::ExitConfig,
    /// `org.json`: this firewall's organisation (`org_id`), as the firewall agent last wrote it.
    org: cc_contracts::MtimeCache<serde_json::Map<String, serde_json::Value>>,
}

impl Ctx {
    pub fn new(config: Config) -> Self {
        let ca = match crate::tls::ca::Ca::load(&config.ca_dir) {
            Ok(ca) => Some(ca),
            Err(e) => {
                tracing::error!("[proxy] {e}; TLS will not be intercepted");
                None
            }
        };
        let insecure = config.dev_flags.iter().any(|f| f == "MITM_DEV_INSECURE_UPSTREAM");
        Self {
            identities: identity::Identities::new(&config.identities_path),
            rules: rules::Rules::new(&config.rules_path),
            log: TrafficLog::new(config.log_file.clone(), config.log_max_bytes),
            ca,
            upstream_tls: crate::tls::config::Upstream::new(insecure),
            mirror: crate::tls::mirror::UpstreamTls::new(insecure),
            exit: crate::residential::ExitConfig::new(&config.exit_path),
            org: cc_contracts::MtimeCache::new(
                &config.org_path,
                cc_contracts::MissingPolicy::Empty,
                cc_contracts::OnError::KeepLast,
            ),
            config,
        }
    }

    /// addon.py `firewall_org_id`: the organisation in `org.json`, when it is a plain id (letters,
    /// digits, `_`, `-`, at most 64). None when the file is missing or says something else.
    pub fn org_id(&self) -> Option<String> {
        let org = self.org.get();
        org.get("org_id")
            .and_then(serde_json::Value::as_str)
            .filter(|o| {
                (1..=64).contains(&o.len()) && o.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
            .map(str::to_owned)
    }

    pub fn vm_id_for(&self, ip: &str) -> Option<String> {
        self.identities.vm_id_for_ip(ip)
    }

    /// Under an emergency stop (addon.py `kill_switched`). A source in no map is not locked.
    pub fn locked(&self, vm_id: Option<&str>) -> bool {
        self.identities.for_vm(vm_id).is_some_and(|e| e.locked)
    }

    /// The owner joined this box to their tailnet (addon.py `tailscale_allowed`).
    pub fn on_tailnet(&self, vm_id: Option<&str>) -> bool {
        self.identities.for_vm(vm_id).is_some_and(|e| e.tailscale)
    }

    /// A record with the fields every record carries (addon.py `_base_record`).
    pub fn record(&self, flow: &Flow, effect: &str) -> TrafficRecord {
        let mut rec = TrafficRecord::with_effect(crate::log::now(), effect);
        rec.flow_id = Maybe::Value(flow.id.clone());
        rec.tenant = Maybe::Value(self.config.tenant.clone());
        rec.vm_id = flow.vm_id.clone().map_or(Maybe::Null, Maybe::Value);
        rec
    }
}

/// What the connection handlers share: the context and the checks.
pub struct Shared {
    pub ctx: Arc<Ctx>,
    pub pipeline: Pipeline,
    /// Open connections per source address.
    open: std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>,
    /// Whether the checks (W2's steps: content rules, logins, email, MCP, voice...) are built in.
    /// Without them intercepted traffic is refused, never let through unchecked.
    pub checks_present: bool,
}

impl std::ops::Deref for Shared {
    type Target = Ctx;
    fn deref(&self) -> &Ctx {
        &self.ctx
    }
}

impl Shared {
    /// `pipeline` holds the checks `main` registered (W2's); W1's own steps are added here, each in
    /// its `flow::order` slot.
    pub fn new(config: Config, mut pipeline: Pipeline) -> Self {
        // Every W2 slot must have its step: one check present says nothing about the others.
        let missing: Vec<u16> = crate::flow::order::W2_REQUIRED
            .iter()
            .copied()
            .filter(|slot| !pipeline.has_slot(*slot))
            .collect();
        let checks_present = missing.is_empty() || config.dev_flags.iter().any(|f| f == "MITM_DEV_WITHOUT_CHECKS");
        if !checks_present {
            tracing::error!("[proxy] checks missing in slots {missing:?}; every intercepted request will be refused");
        }
        crate::splice::meet::mark_start();
        let ctx = Arc::new(Ctx::new(config));
        crate::log::record::register(&mut pipeline, &ctx);
        crate::http::policy::register(&mut pipeline, &ctx);
        crate::http::swaps::register(&mut pipeline, &ctx);
        crate::residential::register(&mut pipeline, &ctx);
        Self {
            ctx,
            pipeline,
            open: std::sync::Mutex::new(std::collections::HashMap::new()),
            checks_present,
        }
    }
}

/// Accept connections for as long as the process runs. A failed accept (out of descriptors, a
/// client that reset mid-handshake) is logged and waited out, never the end of the proxy.
pub async fn serve(listener: TcpListener, shared: Arc<Shared>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[proxy] accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(slot) = SourceSlot::take(&shared, peer_ip(peer)) else {
            // Over this agent's share: closed at once, so the others (and the control plane's
            // channel, which rides this proxy too) keep their descriptors.
            drop(stream);
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, shared).await {
                tracing::debug!("connection from {peer}: {e}");
            }
            drop(slot);
        });
    }
}

/// One open connection counted against its source address; given back when dropped.
struct SourceSlot {
    shared: Arc<Shared>,
    ip: IpAddr,
}

impl SourceSlot {
    fn take(shared: &Arc<Shared>, ip: IpAddr) -> Option<Self> {
        let mut open = shared.open.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = open.entry(ip).or_insert(0);
        if *n >= shared.config.max_per_source {
            if *n == shared.config.max_per_source {
                tracing::warn!(
                    "[proxy] {ip} holds {} connections, the most one source may; refusing more",
                    *n
                );
                *n += 1;
            }
            return None;
        }
        *n += 1;
        Some(Self {
            shared: shared.clone(),
            ip,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut open = self
            .shared
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = open.get_mut(&self.ip) {
            // Past the cap the count carries one extra, for "warned once"; it goes with the first close.
            let cap = self.shared.config.max_per_source;
            *n = if *n > cap { cap - 1 } else { n.saturating_sub(1) };
            if *n == 0 {
                open.remove(&self.ip);
            }
        }
    }
}

/// The source address as the identity map writes it: an IPv4 client on a dual-stack socket
/// arrives as `::ffff:a.b.c.d`.
pub fn peer_ip(peer: SocketAddr) -> IpAddr {
    match peer.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

async fn handle(mut client: TcpStream, peer: SocketAddr, shared: Arc<Shared>) -> anyhow::Result<()> {
    let _ = client.set_nodelay(true);
    let client_ip = peer_ip(peer);
    let mut buf = Vec::new();
    let connect = match head::read_head(&mut client, &mut buf).await? {
        Head::Connect(a) => a,
        Head::Absolute => {
            // Plain HTTP sent to the proxy itself; each request names where it goes.
            let mut flow = Flow::new(
                client_ip,
                Authority {
                    host: String::new(),
                    port: 0,
                },
            );
            flow.vm_id = shared.vm_id_for(&client_ip.to_string());
            let conn = Arc::new(http::Conn::new(shared.clone(), http::Mode::Absolute, &flow));
            http::serve_h1(conn, io::Prefixed::new(buf, client)).await;
            return Ok(());
        }
        Head::Other(_) => {
            client
                .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }
    };
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;

    let mut flow = Flow::new(client_ip, connect);
    flow.vm_id = shared.vm_id_for(&client_ip.to_string());

    // A client that waits for the server to speak first (SMTP, MySQL, FTP, POP, IMAP) sends
    // nothing. A tunnel rule for this address and port is then applied after a short silence, so
    // the server can speak. A TLS or HTTP client has spoken by then; without such a rule the bytes
    // are waited for as usual.
    if buf.is_empty()
        && address_tunnel(&shared, &flow)
        && tokio::time::timeout(head::SERVER_FIRST_WAIT, client.readable())
            .await
            .is_err()
    {
        return match destination::raw_tunnel(&flow, &shared.config).await {
            Ok(d) => {
                flow.set_destination(d);
                splice::passthrough(client, buf, &flow).await
            }
            Err(r) => block_flow(&shared, &flow, r).await,
        };
    }
    let Some(protocol) = head::sniff(&mut client, &mut buf).await? else {
        // Closed without a byte to judge by: nothing to decide, nothing to record.
        return Ok(());
    };
    match protocol {
        Protocol::Tls => {}
        // A tunnel rule for this address and port applies to whatever the bytes look like: the addon
        // runs `tunnel_match` on every connection that is not TLS, HTTP included.
        Protocol::Http | Protocol::Tcp => return not_tls(client, buf, flow, shared, protocol).await,
    }

    match tls::read_client_hello(&mut client, &mut buf, tls::HELLO_TIMEOUT).await {
        Ok(hello) => {
            flow.sni = hello.sni;
            flow.alpn = hello.alpn;
        }
        Err(HelloError::NotHello | HelloError::Timeout | HelloError::TooLarge | HelloError::BadSni(_)) => {
            return drop_flow(&shared, &flow).await;
        }
        // Gone before its ClientHello was whole: mitmproxy never decided such a connection either,
        // and wrote no record.
        Err(HelloError::Closed) => return Ok(()),
        Err(e) => return Err(e.into()),
    }

    // Meet TURN media first (addon.py `next_layer`): relayed for an agent with a meeting lease, at
    // Google's ranges, else closed. Never intercepted, never passed through otherwise.
    if let Some(sni) = flow.sni.clone()
        && splice::meet::is_meet_name(&shared.ctx, &sni)
    {
        let host = destination::wire_name(&flow.connect.host).unwrap_or_default();
        let lease = splice::meet::lease(&shared.ctx, flow.vm_id.as_deref(), None);
        return match lease {
            Some(l)
                if splice::meet::destination_ok(&shared.ctx, &sni, &host, flow.connect.port)
                    && splice::meet::reserve(&l) =>
            {
                splice::meet::relay(&shared.ctx, client, buf, &flow, &sni, l).await
            }
            _ => drop_flow(&shared, &flow).await,
        };
    }
    let ident = shared.identities.for_vm(flow.vm_id.as_deref());
    // Residential first (addon.py `next_layer` decides it before `tls_clienthello` could pass the
    // connection through direct): by SNI, or by the CONNECT address when there is none.
    let locked = ident.as_ref().is_some_and(|i| i.locked);
    let named = flow
        .sni
        .clone()
        .or_else(|| destination::wire_name(&flow.connect.host))
        .unwrap_or_default();
    if !residential::exempt(&shared.ctx, &named)
        && let Some(rule) = residential::residential_rule(
            &shared.rules.get(),
            &named,
            Some(flow.connect.port),
            flow.vm_id.as_deref(),
            locked,
        )
    {
        return residential::relay(&shared.ctx, client, buf, &flow, &named, flow.connect.port, &rule).await;
    }
    if let Some(pass) = splice::tls_passthrough(&shared, &flow, ident.as_ref()) {
        let sni = flow.sni.clone().unwrap_or_default();
        let checked = match pass {
            Pass::BuiltIn => destination::passthrough(&flow, &sni, &shared.config).await,
            Pass::Tunnel => destination::tunnel(&flow, &sni, &shared.config).await,
        };
        match checked {
            Ok(d) => flow.set_destination(d),
            Err(r) => return block_flow(&shared, &flow, r).await,
        }
        return splice::passthrough(client, buf, &flow).await;
    }
    tls::intercept(shared, client, buf, flow).await
}

/// Whether a tunnel rule names this connection's CONNECT address and port (not a residential one:
/// a client that has not spoken yet is only ever passed through, never relayed through the exit).
fn address_tunnel(shared: &Shared, flow: &Flow) -> bool {
    destination::wire_name(&flow.connect.host).is_some_and(|host| {
        splice::tunnel_matches(
            &shared.rules.get(),
            &host,
            Some(flow.connect.port),
            flow.vm_id.as_deref(),
            shared.locked(flow.vm_id.as_deref()),
        )
    })
}

/// A connection that is not TLS (addon.py `next_layer`): passed through when a `tunnel` rule names
/// this IP and port; otherwise HTTP is intercepted and anything else dropped (`_DeniedTCP`).
/// W1 P7: residential rules by IP and port.
async fn not_tls(
    client: TcpStream,
    buf: Vec<u8>,
    mut flow: Flow,
    shared: Arc<Shared>,
    protocol: Protocol,
) -> anyhow::Result<()> {
    // A CONNECT target that is not a host name or an address matches no rule: dropped.
    let Some(host) = destination::wire_name(&flow.connect.host) else {
        return drop_flow(&shared, &flow).await;
    };
    let locked = shared.locked(flow.vm_id.as_deref());
    // A residential rule pinned to this address and port, before any tunnel rule (`next_layer`).
    if let Some(rule) = residential::residential_rule(
        &shared.rules.get(),
        &host,
        Some(flow.connect.port),
        flow.vm_id.as_deref(),
        locked,
    ) {
        return residential::relay(&shared.ctx, client, buf, &flow, &host, flow.connect.port, &rule).await;
    }
    if !splice::tunnel_matches(
        &shared.rules.get(),
        &host,
        Some(flow.connect.port),
        flow.vm_id.as_deref(),
        locked,
    ) {
        if protocol == Protocol::Http {
            let conn = Arc::new(http::Conn::new(shared.clone(), http::Mode::PlainTunnel, &flow));
            http::serve_h1(conn, io::Prefixed::new(buf, client)).await;
            return Ok(());
        }
        return drop_flow(&shared, &flow).await;
    }
    match destination::raw_tunnel(&flow, &shared.config).await {
        Ok(d) => flow.set_destination(d),
        Err(r) => return block_flow(&shared, &flow, r).await,
    }
    splice::passthrough(client, buf, &flow).await
}

/// Close without contacting anything, as a `block` with the reason. For a non-routable address
/// this is addon.py's `_non_routable_record` from `server_connect`, flow id and all;
/// `passthrough_mismatch` is new (the addon dialled the CONNECT target).
async fn block_flow(shared: &Shared, flow: &Flow, why: destination::Refused) -> anyhow::Result<()> {
    let host = flow.sni.clone().unwrap_or_else(|| flow.connect.host.clone());
    let mut rec = shared.record(flow, "block");
    if why.rule == destination::NON_ROUTABLE_RULE {
        rec.flow_id = Maybe::Value(crate::log::non_routable_flow_id(&host, flow.connect.port));
    }
    rec.host = Maybe::Value(host);
    rec.port = Maybe::Value(u64::from(flow.connect.port).into());
    rec.rule = Maybe::Value(why.rule.into());
    rec.extra
        .insert("error".into(), target::truncate(&why.error, 200).into());
    shared.log.append(&rec);
    Ok(())
}

/// Close without contacting anything, and say so in the log (addon.py `tcp_start` + `_DeniedTCP`).
pub async fn drop_flow(shared: &Shared, flow: &Flow) -> anyhow::Result<()> {
    shared.log.append(&drop_record(shared, flow));
    Ok(())
}

/// The `drop` record. The host is the CONNECT target, as mitmproxy's `server_conn.address` is.
pub fn drop_record(shared: &Shared, flow: &Flow) -> TrafficRecord {
    let mut rec = shared.record(flow, "drop");
    rec.host = Maybe::Value(flow.connect.host.clone());
    rec.port = Maybe::Value(u64::from(flow.connect.port).into());
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_source_holds_at_most_its_share() -> Result<(), Box<dyn std::error::Error>> {
        let vars = [("MITM_MAX_CONNECTIONS_PER_SOURCE", "2")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let config = Config::from_vars("127.0.0.1:0".parse()?, &vars)?;
        let shared = Arc::new(Shared::new(config, Pipeline::new()));
        let a: IpAddr = "10.0.0.3".parse()?;
        let b: IpAddr = "10.0.0.4".parse()?;
        let first = SourceSlot::take(&shared, a);
        let second = SourceSlot::take(&shared, a);
        assert!(first.is_some() && second.is_some());
        assert!(SourceSlot::take(&shared, a).is_none());
        assert!(SourceSlot::take(&shared, a).is_none());
        assert!(SourceSlot::take(&shared, b).is_some(), "another agent is not affected");
        drop(first);
        let again = SourceSlot::take(&shared, a);
        assert!(again.is_some(), "a closed connection gives its slot back");
        assert!(SourceSlot::take(&shared, a).is_none());
        drop((second, again));
        assert!(!shared.open.lock().map(|m| m.contains_key(&a)).unwrap_or(true));
        Ok(())
    }

    #[test]
    fn checks_count_as_present_only_with_every_w2_slot() -> Result<(), Box<dyn std::error::Error>> {
        use crate::flow::{Flow, Hook, Step, StepFuture, Verdict, order};
        struct Nop;
        impl Step for Nop {
            fn name(&self) -> &'static str {
                "nop"
            }
            fn hooks(&self) -> &'static [Hook] {
                &[Hook::Request]
            }
            fn run<'a>(&'a self, _: Hook, _: &'a mut Flow) -> StepFuture<'a> {
                Box::pin(async { Verdict::Continue })
            }
        }
        let config = || Config::from_vars("127.0.0.1:0".parse().expect("addr"), &std::collections::HashMap::new());
        let mut some = Pipeline::new();
        some.push(order::EMAIL, Arc::new(Nop));
        assert!(
            !Shared::new(config()?, some).checks_present,
            "one W2 step is not all of them"
        );
        let mut all = Pipeline::new();
        for slot in order::W2_REQUIRED {
            all.push(*slot, Arc::new(Nop));
        }
        assert!(Shared::new(config()?, all).checks_present);
        Ok(())
    }

    #[test]
    fn a_mapped_peer_is_its_ipv4_address() {
        let p: SocketAddr = "[::ffff:10.0.0.3]:5000".parse().expect("addr");
        assert_eq!(peer_ip(p).to_string(), "10.0.0.3");
        let p: SocketAddr = "[2001:db8::3]:5000".parse().expect("addr");
        assert_eq!(peer_ip(p).to_string(), "2001:db8::3");
    }
}
