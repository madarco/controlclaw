//! The vm-agent's connection to the local OpenClaw gateway (`startGatewayBridge` in index.ts): the
//! client, the one config write queue every writer shares, and the watcher that restarts OpenClaw
//! when it runs behind its saved config (T-111). Provided to the rest of the agent through the
//! `openclaw` contract slot.

use std::sync::Arc;
use std::time::Duration;

use cc_openclaw::config_queue::{ActivationOptions, BoxFuture, ConfigActivation, ConfigWriter};
use cc_openclaw::{GatewayClient, GatewayOptions};
use cc_proc::{Cmd, Runner};

use crate::app::App;
use crate::contracts::OpenClaw;

/// How far back the journal is read for OpenClaw's "restart still deferred" (`DEFERRED_WINDOW_S`).
const DEFERRED_WINDOW_S: u64 = 45;
const EXEC_TIMEOUT: Duration = Duration::from_secs(5);

/// `saasBaseUrl`: `CONTROLCLAW_URL`, else `config_api_url` with `/api/...` cut off.
pub fn saas_base_url(app: &App) -> Option<String> {
    if let Ok(u) = std::env::var("CONTROLCLAW_URL")
        && !u.is_empty()
    {
        return Some(u.strip_suffix('/').unwrap_or(&u).to_string());
    }
    let url = app.keys.read("config_api_url").filter(|u| !u.is_empty())?;
    Some(match url.find("/api/") {
        Some(i) => url[..i].to_string(),
        None => url,
    })
}

/// `restartStillDeferred`: whether OpenClaw logged lately that it holds its restart back for work
/// in flight.
pub async fn restart_still_deferred(runner: &dyn Runner, service: &str) -> bool {
    let since = format!("-{DEFERRED_WINDOW_S}s");
    let cmd = Cmd::sudo("journalctl")
        .args(["-u", service, "--since", &since, "--no-pager", "-o", "cat"])
        .timeout(EXEC_TIMEOUT);
    match runner.run(cmd).await {
        Ok(out) if out.success() => out.stdout_str().contains("restart still deferred"),
        _ => false,
    }
}

/// Start the client (once, after the agent listens) when the box has a gateway token and somewhere to report to (a pool box needs
/// no console yet), and put it in the `openclaw` slot. Without one the slot stays empty, as the TS
/// `gateway` stays null.
pub fn start(app: &Arc<App>) {
    let pool = app.config.pool_marker.exists();
    let Some(opts) = GatewayOptions::from_keys_dir(&app.config.keys_dir, app.config.gateway_port) else {
        tracing::info!(
            "[gateway] no openclaw_gateway_token / config_api_url in KEYS_DIR: audit + approvals bridge off"
        );
        return;
    };
    if !pool && saas_base_url(app).is_none() {
        tracing::info!(
            "[gateway] no openclaw_gateway_token / config_api_url in KEYS_DIR: audit + approvals bridge off"
        );
        return;
    }
    let client = GatewayClient::new(opts);
    let config = Arc::new(ConfigWriter::new(Arc::new(client.clone())));
    if !pool {
        // T-111: a write whose restart OpenClaw dropped leaves it running the old settings until
        // something restarts it. This notices and does.
        let (a, b) = (app.clone(), app.clone());
        let restart = Arc::new(move || -> BoxFuture<'static, Result<(), String>> {
            let a = a.clone();
            Box::pin(async move {
                let service = a.config.service.clone();
                super::openclaw::run_action(a.runner.as_ref(), "restart", &service).await
            })
        });
        let mut o = ActivationOptions::new(Arc::new(client.clone()), restart);
        o.restart_deferred = Some(Arc::new(move || -> BoxFuture<'static, bool> {
            let b = b.clone();
            Box::pin(async move { restart_still_deferred(b.runner.as_ref(), &b.config.service).await })
        }));
        let activation = ConfigActivation::new(o);
        activation.follow(&client);
    }
    client.start();
    app.contracts.openclaw.set(Arc::new(OpenClaw { client, config }));
}
