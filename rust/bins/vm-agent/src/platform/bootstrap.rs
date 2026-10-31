//! The secured-box bootstrap (`bootstrap` in index.ts), ordered so forced egress never strands the
//! box. Every step runs while egress is still open; the console locks it down on ready, the last
//! step:
//!
//! 1. make the on-box keypair (if absent) and register its public key (one-time token);
//! 2. install the firewall's CA, checked against the pinned key (W7);
//! 3. turn on transparent egress once the proxy answers (W7);
//! 4. wait for OpenClaw's gateway and for Caddy to serve this box's certificate (W7), side by side
//!    and bounded;
//! 5. report ready.
//!
//! An unclaimed pool box waits for the enrollment worker's CA instead, and only sets its health.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::Map;

use crate::app::App;

fn env_ms(name: &str, default: u64) -> Duration {
    Duration::from_millis(
        std::env::var(name)
            .ok()
            .and_then(|v| {
                v.trim()
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .ok()
            })
            .unwrap_or(default),
    )
}

/// OpenClaw is up: its gateway is connected, answers `config.get`, and runs the config it has saved
/// (T-111's check, `config_active`). A gateway that has just connected can still be on its way down
/// (a restart it is draining for) or behind its file; the console pushes the model and channels the
/// moment it hears ready, so ready waits for this (W1, 2026-10-29). False after `timeout`.
async fn gateway_settled(client: &cc_openclaw::GatewayClient, timeout: Duration) -> bool {
    cc_openclaw::config_queue::when_back(client, timeout).await
        && cc_openclaw::config_queue::await_active(client, Some(Duration::from_secs(10)), timeout).await
}

/// What the gateway and the certificate came to: true when there is nothing to wait for.
async fn wait_gateway_and_certificate(app: &App, none_is: bool) -> (bool, bool) {
    let gateway_timeout = env_ms("GATEWAY_READY_TIMEOUT_MS", 120_000);
    let cert_timeout = env_ms("CERT_READY_TIMEOUT_MS", 300_000);
    let client = app.contracts.openclaw.get().map(|o| o.client.clone());
    let hostname = app.keys.read("vm_hostname").filter(|h| !h.is_empty());
    let setup = app.contracts.box_setup.get();
    let gateway = async {
        match &client {
            Some(c) => gateway_settled(c, gateway_timeout).await,
            None => none_is,
        }
    };
    let certificate = async {
        match (&hostname, &setup) {
            (Some(h), Some(s)) => s.own_certificate(h.clone(), cert_timeout).await,
            (Some(_), None) => false,
            (None, _) => none_is,
        }
    };
    tokio::join!(gateway, certificate)
}

pub async fn run(app: Arc<App>, software: impl Fn() -> serde_json::Value) {
    let keys_dir = app.config.keys_dir.clone();
    if cc_auth::keys::ensure_vm_keypair(&keys_dir).is_none() {
        tracing::warn!("[keys] could not make or read the vm keypair");
    }
    let setup = app.contracts.box_setup.get();
    if app.config.pool_marker.exists() {
        // The root enrollment worker verifies and installs the pair's signed CA before this gate.
        for _ in 0..300 {
            if keys_dir.join("mitm_ca_fingerprint").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let Some(setup) = setup else { return };
        if !keys_dir.join("mitm_pinned_pubkey.pem").exists() || !setup.trust_ca_in_process() {
            return;
        }
        if !setup.enable_egress().await {
            return;
        }
        let (gateway, certificate) = wait_gateway_and_certificate(&app, false).await;
        app.pool_healthy.store(gateway && certificate, Ordering::Relaxed);
        return;
    }
    super::keys::register_public_key(&app).await;
    // A build without the box-side steps cannot install the CA, so it must not report ready
    // either: fail-safe, as a box whose CA failed (the steps come from W7's `boxside`).
    let Some(setup) = setup else {
        tracing::error!(
            "[bootstrap] this build has no CA install or egress steps — skipping ready report (box stays initializing)"
        );
        return;
    };
    setup.report_handle_certificate();
    if !setup.install_ca().await {
        // Never report ready, and so trigger lockdown, without a trusted proxy CA.
        tracing::error!("[bootstrap] mitm CA not installed — skipping ready report (box stays initializing)");
        return;
    }
    if !setup.enable_egress().await {
        tracing::error!("[bootstrap] transparent egress not active — skipping ready report (box stays initializing)");
        return;
    }
    let (gateway, certificate) = wait_gateway_and_certificate(&app, true).await;
    if !gateway {
        tracing::warn!(
            "[bootstrap] OpenClaw's gateway is still down or behind its saved config — reporting ready without it"
        );
    }
    if !certificate {
        let host = app.keys.read("vm_hostname").unwrap_or_default();
        tracing::warn!("[bootstrap] {host} still serves no valid certificate — reporting ready without it");
    }
    app.bootstrap_ready.store(true, Ordering::SeqCst);
    super::ready::report_ready(&app, Map::new(), software).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_openclaw::fake::{FakeGateway, FakeReply};
    use std::sync::atomic::AtomicBool;

    #[tokio::test]
    async fn ready_waits_until_openclaw_runs_its_saved_config() {
        let gw = FakeGateway::start("tok").await.expect("gateway");
        let applied = Arc::new(AtomicBool::new(false));
        let a = applied.clone();
        gw.on("config.get", move |_| {
            let applied = if a.load(Ordering::SeqCst) { "r2" } else { "r1" };
            FakeReply::Ok(serde_json::json!({ "configRevisionHash": "r2", "appliedConfigHash": applied }))
        });
        let mut o = cc_openclaw::GatewayOptions::new(gw.url(), "tok");
        o.min_backoff = Duration::from_millis(20);
        let client = cc_openclaw::GatewayClient::new(o);
        client.start();
        assert!(client.when_connected(Duration::from_secs(5)).await);
        // Connected, but behind its saved config: not ready yet.
        assert!(!gateway_settled(&client, Duration::from_millis(1500)).await);
        let a = applied.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            a.store(true, Ordering::SeqCst);
        });
        assert!(gateway_settled(&client, Duration::from_secs(5)).await);
        // A gateway that never answers is not ready either.
        gw.on("config.get", |_| FakeReply::Err {
            code: None,
            message: Some("restarting".into()),
        });
        assert!(!gateway_settled(&client, Duration::from_millis(1500)).await);
    }
}
