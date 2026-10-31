//! `cc-proxy`: the firewall's egress proxy. See the crate docs in lib.rs.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(about = "ControlClaw egress proxy")]
struct Args {
    /// Where agents' redsocks connect (mitmproxy's `--listen-port 8080`, all addresses). Given
    /// more than once, the proxy listens on each (a standalone firewall's private address and its
    /// WireGuard address).
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let first = *args
        .listen
        .first()
        .ok_or_else(|| anyhow::anyhow!("--listen: at least one address"))?;
    let config = cc_proxy::config::Config::from_env(first)?;
    let mut pipeline = cc_proxy::flow::Pipeline::new();
    cc_proxy::checks::register(&mut pipeline);
    // The first address must bind; the others (a WireGuard address whose interface may come up
    // later) are retried, so they never take the first one down.
    let listener = tokio::net::TcpListener::bind(first).await?;
    // The bound address on stdout, so a test or a rig that asked for port 0 can find it.
    println!("listening on {}", listener.local_addr()?);
    let shared = Arc::new(cc_proxy::net::Shared::new(config, pipeline));
    for addr in args.listen.iter().skip(1).copied() {
        let shared = shared.clone();
        tokio::spawn(async move {
            loop {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(l) => {
                        tracing::info!("[proxy] listening on {addr}");
                        if let Err(e) = cc_proxy::net::serve(l, shared.clone()).await {
                            tracing::error!("[proxy] {addr}: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("[proxy] cannot listen on {addr} yet: {e}; trying again"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }
    cc_proxy::net::serve(listener, shared).await?;
    Ok(())
}
