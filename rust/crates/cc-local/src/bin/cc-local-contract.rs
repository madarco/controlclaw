//! The local control plane on its own, over HTTP, with the conformance hooks: what
//! `cc-conformance --target local` starts. An in-memory database; prints `listening <port>`.

use std::sync::Arc;

use cc_local::facade::Facade;
use cc_local::{Db, LocalControlPlane};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(0);
    let db = Arc::new(Db::memory().map_err(std::io::Error::other)?);
    let facade = Arc::new(Facade {
        plane: Arc::new(LocalControlPlane::new(db)),
        hooks: true,
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("listening {}", listener.local_addr()?.port());
    cc_http::serve(listener, Arc::new(facade.router())).await;
    Ok(())
}
