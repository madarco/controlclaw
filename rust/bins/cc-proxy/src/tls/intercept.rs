//! Intercepting a TLS connection: the leaf, the site first, the handshake with the agent, and HTTP
//! inside.
//!
//! Upstream first (owner, 2026-10-28): once the destination has passed its checks, the site is
//! dialled with a copy of the agent's ClientHello before the agent's handshake ends, and the agent
//! is offered only the protocol the site chose, so the two never disagree. Not for a locked agent,
//! a build without its checks, or a host whose host-wide rule blocks or asks: those are refused at
//! the first request, and the site never sees the firewall.

use std::sync::Arc;

use tokio::net::TcpStream;

use super::{HELLO_TIMEOUT, config, hello};
use crate::flow::{Destination, Flow};
use crate::http::upstream::{self, Fingerprint, Prepared};
use crate::http::{self, Conn, h2print};
use crate::net::Shared;
use crate::net::head::{self, Protocol};
use crate::net::io::Prefixed;

/// Intercept a TLS connection whose whole ClientHello is in `buf`: answer it with a leaf for the
/// name it asked for (the SNI, else the CONNECT address), then serve HTTP inside. Decrypted bytes
/// that are not HTTP (no HTTP ALPN, and not HTTP by their look) are dropped, as mitmproxy's
/// `next_layer` turns them into a TCP flow that `_DeniedTCP` closes.
pub async fn intercept(shared: Arc<Shared>, client: TcpStream, buf: Vec<u8>, flow: Flow) -> anyhow::Result<()> {
    if shared.ctx.ca.is_none() {
        // No CA to intercept with (it failed to load at start): closed, recorded under its name.
        let mut rec = crate::net::drop_record(&shared, &flow);
        if let Some(sni) = &flow.sni {
            rec.host = cc_contracts::Maybe::Value(sni.clone());
        }
        shared.log.append(&rec);
        return Ok(());
    }
    let Some(name) = flow
        .sni
        .clone()
        .or_else(|| crate::net::destination::wire_name(&flow.connect.host))
    else {
        return crate::net::drop_flow(&shared, &flow).await;
    };
    // An RSA signature for a name not seen yet: off the runtime's threads, so many new names at
    // once do not stall every other connection.
    let signer = shared.ctx.clone();
    let for_name = name.clone();
    let signed = tokio::task::spawn_blocking(move || signer.ca.as_ref().map(|ca| ca.leaf(&for_name))).await;
    let leaf = match signed {
        Ok(Some(Ok(l))) => l,
        Ok(Some(Err(e))) => {
            tracing::warn!("[proxy] no certificate for {name}: {e}");
            return crate::net::drop_flow(&shared, &flow).await;
        }
        _ => return crate::net::drop_flow(&shared, &flow).await,
    };
    let fingerprint = Arc::new(Fingerprint::new(
        hello::handshake_of(&buf).and_then(|h| hello::parse(&h)),
    ));
    let prepared = site_first(&shared, &flow, &fingerprint).await;
    // The agent is offered what the site chose. When the agent did not offer that (an h2-only
    // client, a site that picked HTTP/1.1 or nothing), what it offered, as before: the proxy
    // speaks each side's protocol and translates, rather than leave the agent with none.
    let offer: Vec<Vec<u8>> = match &prepared {
        Some((p, _)) if flow.alpn.iter().any(|a| a.as_slice() == p.alpn()) => vec![p.alpn().to_vec()],
        _ => flow.alpn.clone(),
    };
    tracing::debug!(
        "[proxy] {name}: site first {}, agent offered {:?}, offering {:?}",
        prepared
            .as_ref()
            .map_or("not dialled", |(p, _)| if p.alpn() == config::H2 {
                "h2"
            } else {
                "http/1.1"
            }),
        flow.alpn
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect::<Vec<_>>(),
        offer
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect::<Vec<_>>()
    );
    let acceptor = tokio_rustls::TlsAcceptor::from(config::server_config(leaf, &offer));
    let tls = match tokio::time::timeout(HELLO_TIMEOUT, acceptor.accept(Prefixed::new(buf, client))).await {
        Ok(Ok(s)) => s,
        // The agent refused our certificate or went away: mitmproxy writes no record either.
        Ok(Err(e)) => {
            tracing::debug!("[proxy] client TLS handshake with {name} failed: {e}");
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let conn = |prepared| Arc::new(Conn::intercepted(shared.clone(), &flow, fingerprint.clone(), prepared));
    match negotiated.as_deref() {
        Some(config::H2) => {
            // The agent's own HTTP/2 start, read before hyper serves it (and served unchanged):
            // the site's connection opens with the same.
            let mut tls = tls;
            let (start, print) = h2print::read(&mut tls).await?;
            if let Some(p) = print {
                let _ = fingerprint.h2.set(p);
            }
            http::serve_h2(conn(prepared), Prefixed::new(start, tls)).await;
        }
        Some(config::HTTP11) => http::serve_h1(conn(prepared), tls).await,
        _ => {
            // No HTTP ALPN: decide by the decrypted bytes, as `next_layer` does a second time.
            let mut tls = tls;
            let mut inner = Vec::new();
            match head::sniff(&mut tls, &mut inner).await? {
                Some(Protocol::Http) => http::serve_h1(conn(prepared), Prefixed::new(inner, tls)).await,
                Some(Protocol::Tcp | Protocol::Tls) => return crate::net::drop_flow(&shared, &flow).await,
                None => {}
            }
        }
    }
    Ok(())
}

/// How long the agent's handshake may wait for the site.
const SITE_FIRST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Dial the site before the agent's handshake ends, when nothing would refuse the agent's requests
/// to it anyway. `None`: dial at the first request instead (which refuses or records as usual).
async fn site_first(shared: &Shared, flow: &Flow, fingerprint: &Fingerprint) -> Option<(Prepared, Destination)> {
    let ctx = &shared.ctx;
    // No checks built in, a locked agent, no rules read yet (a cold start): every request is
    // refused, so the site is not dialled.
    if !shared.checks_present || ctx.locked(flow.vm_id.as_deref()) || !ctx.rules.loaded() {
        return None;
    }
    if crate::net::destination::connect_refusal(flow, &ctx.config).is_some() {
        return None;
    }
    let d = crate::net::destination::intercepted(flow, &ctx.config).await.ok()?;
    d.addr?;
    // A residential rule for the host, at any priority: a request may go through the exit, and
    // the site must never see this box first (host review of #615).
    let rules = ctx.rules.get();
    if !crate::residential::exempt(ctx, &d.name)
        && crate::residential::any_residential(&rules, &d.name, Some(d.port), flow.vm_id.as_deref())
    {
        return None;
    }
    // A rule for the whole host that blocks or asks (no method, no path): its requests are refused
    // or held, so the site is not dialled for them.
    let host_rule = crate::http::policy::match_rule(&rules, &d.name, "", "", flow.vm_id.as_deref());
    if host_rule
        .and_then(|r| {
            r.raw
                .get("effect")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|e| e != "allow")
    {
        return None;
    }
    // The agent's handshake waits for this: a site that does not answer soon is dialled again at
    // the first request instead, with the usual time to answer.
    match tokio::time::timeout(SITE_FIRST_TIMEOUT, upstream::prepare(ctx, fingerprint.hello(), &d))
        .await
        .unwrap_or_else(|_| Err(upstream::UpstreamError::Failed("timed out".into())))
    {
        Ok(p) => Some((p, d)),
        Err(e) => {
            // The first request dials again and answers with the error, as before.
            tracing::debug!("[proxy] site-first dial to {} failed: {e}", d.name);
            None
        }
    }
}
