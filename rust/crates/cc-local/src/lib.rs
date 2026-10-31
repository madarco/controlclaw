//! A standalone firewall's own control plane (docs/plans/standalone-firewall.md §3, step 3).
//!
//! - [`plane`]: the contract between a firewall and its control plane, answered in process from
//!   SQLite ([`plane::LocalControlPlane`]), the same calls the SaaS answers over HTTP.
//! - [`db`]: the SQLite file and its tables.
//! - [`admin`]: the admin login (a setup token, then a password), sessions and CSRF, and the small
//!   HTTP API the panel and the tests use; config changes call the firewall's command handlers.
//! - `facade` (feature `contract` only): the contract served over HTTP with the conformance hooks,
//!   for the cases' `local` target.
//! - [`pairing`]: one-time codes, and the unauthenticated `POST /pair` that records an agent.
//! - [`panel`]: the local panel's files, served next to the API.
//! - [`wireguard`]: tunnel addresses and the peers list for agents paired over WireGuard.
//! - [`retention`]: raw activity kept 30 days, the hourly rollup 13 months.

pub mod admin;
pub mod api;
pub mod db;
#[cfg(feature = "contract")]
pub mod facade;
pub mod pairing;
pub mod panel;
pub mod plane;
pub mod retention;
pub mod wireguard;

pub use db::Db;
pub use plane::{Answer, Call, ControlPlane, LocalControlPlane};

/// Where a browser reaches the panel (`LOCAL_PANEL_URL`, else `http://localhost:<port>` of
/// `LOCAL_PANEL_BIND`): the origin OAuth sign-ins come back to (`<origin>/oauth/callback`), where the
/// panel's page posts the result to `POST /api/oauth/callback`.
pub fn panel_origin() -> String {
    if let Ok(u) = std::env::var("LOCAL_PANEL_URL")
        && let Ok(u) = url::Url::parse(u.trim())
    {
        return u.origin().ascii_serialization();
    }
    let bind = std::env::var("LOCAL_PANEL_BIND").unwrap_or_else(|_| "127.0.0.1:8800".into());
    let port = bind.rsplit_once(':').map_or("8800", |(_, p)| p);
    format!("http://localhost:{port}")
}
