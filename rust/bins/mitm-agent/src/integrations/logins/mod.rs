//! Website logins on the firewall: the store and its commands, the tools the agents use, and the
//! firewall page an owner types passwords into.

pub mod firewall;
pub mod mcp;
pub mod onepassword;
pub mod placeholder;
pub mod schema;
pub mod totp;
pub mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::app::{App, Registry};
use crate::integrations::Env;
use crate::integrations::tools_gate::LocalTools;

pub const ACTIONS: &[&str] = &[
    "read",
    "1password_disconnect",
    "1password_sync",
    "propose",
    "confirm",
    "cancel",
];

/// The logins module, or None when its store would not open (website logins are then off, as in
/// the TS). What it returns goes on the 3940 listener's `/logins/mcp`.
pub fn register(reg: &mut Registry, app: &Arc<App>, env: &Env) -> Option<Arc<dyn LocalTools>> {
    let traffic = env.get("TRAFFIC_LOG_PATH", "");
    let logins = match firewall::LoginsFirewall::new(
        app,
        PathBuf::from(env.get("LOGINS_STORE_PATH", "/opt/controlclaw/state/logins.enc")),
        (!traffic.is_empty()).then(|| PathBuf::from(traffic)),
        Some(app.config.proxy_config_dir.join("login-targets.json")),
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("[logins] module would not start, website logins disabled: {e}");
            return None;
        }
    };
    tracing::info!(
        "[mitm-agent] logins store loaded ({} login(s))",
        logins
            .summary()
            .get("logins")
            .and_then(|l| l.as_array())
            .map_or(0, Vec::len)
    );
    app.contracts
        .credentials
        .add(Arc::new(firewall::LoginCredentials(logins.clone())));
    for action in ACTIONS {
        let l = logins.clone();
        reg.commands.handle(&format!("logins.{action}"), move |p| {
            let l = l.clone();
            async move { l.handle(action, p).await }
        });
    }
    // 1Password, when connected: read its vaults again every hour. A read costs one call per vault
    // plus one per CHANGED item, against the customer's 1Password rate limits.
    every(Duration::from_secs(3600), {
        let l = logins.clone();
        move || {
            let l = l.clone();
            async move { l.one_password_sync().await }
        }
    });
    // Sign-in targets the proxy read off sign-in pages go into the sealed store (the proxy's own
    // list lives under /run and a reboot empties it).
    every(Duration::from_secs(60), {
        let l = logins.clone();
        move || {
            let l = l.clone();
            async move {
                l.ingest_learned_targets().await;
            }
        }
    });
    web::route(reg, web::LoginsWeb::new(app, logins.clone()));
    // In every firewall page's sidebar (the TS's `fwShellPages({logins: !!loginsWeb})`), while the
    // Open flow runs: without it the console will not open the page, and the link would end on a
    // notice.
    crate::core::fw_shell::set_page(crate::core::fw_shell::FwPage::Logins, super::access_ready);
    Some(Arc::new(mcp::LoginsTools(logins)))
}

/// `setInterval(fn, every)`: the first run after one period.
fn every<F, Fut>(period: Duration, f: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            f().await;
        }
    });
}
