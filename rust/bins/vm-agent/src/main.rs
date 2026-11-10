//! The vm-agent: the Rust build of `packages/vm-agent` (docs/plans/rust-rewrite.md). It reads the
//! same environment and key files as the Node build, listens on the same port and answers the same
//! routes. Each workstream fills its own folder and registers its routes, timers and services from
//! its `register()`; this file only wires them up.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cc_auth::console::ConsoleAuth;
use cc_auth::firewall::FirewallAuth;
use cc_auth::jwt::VerifyKey;
use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_http::{Router, header, json, unauthorized};

mod app;
mod boxside;
mod conformance_routes;
mod contracts;
mod gbrain;
mod keys;
mod meetings;
mod phone;
mod platform;
mod stages;
#[cfg(test)]
mod tests;
mod unmanaged;

use app::{App, Config};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn die(message: &str) -> ! {
    tracing::error!("{message}");
    std::process::exit(1);
}

/// Everything `main` sets up before it listens, in the TS order. Exits like the TS does when the
/// console's key or the session secret cannot be had.
fn startup(config: Config) -> Arc<App> {
    let keys = KeysDir::new(&config.keys_dir);
    let pool = config.pool_marker.exists();
    // An unclaimed pool box has no console yet: a placeholder key whose private half only this box
    // holds, so no app can command it.
    if pool && !config.keys_dir.join("saas_public_key.pem").exists() {
        match cc_auth::keys::ensure_vm_keypair(&config.keys_dir) {
            Some(public) => {
                if let Err(e) =
                    cc_store::write_file(&config.keys_dir.join("saas_public_key.pem"), public.as_bytes(), 0o644)
                {
                    die(&format!("Pool signing key unavailable: {e}"));
                }
            }
            None => die("Pool signing key unavailable"),
        }
    }
    let saas_pem = match std::fs::read_to_string(config.keys_dir.join("saas_public_key.pem")) {
        Ok(p) => p,
        Err(e) => die(&format!("Failed to load SaaS public key: {e}")),
    };
    let saas_key = match VerifyKey::ed25519_spki_pem(&saas_pem) {
        Ok(k) => k,
        Err(e) => die(&format!("Failed to load SaaS public key: {e}")),
    };
    tracing::info!("Loaded SaaS public key");
    let vm_id = keys.vm_id();
    if vm_id.is_none() {
        tracing::warn!("No vm_id in KEYS_DIR: tokens are checked by signature only");
    }
    let latch = vm_id.as_ref().map(|_| config.state_dir.join("firewall-tokens-bound"));
    let pin_dir = config.keys_dir.clone();
    let host_keys = keys.clone();
    let firewall_auth = FirewallAuth::new(
        move || cc_auth::keys::read_key_file(&pin_dir, "mitm_pinned_pubkey.pem"),
        vm_id.clone(),
        move || host_keys.hostnames(),
        latch,
    );
    if let Err(e) = keys::ensure_session_secret(&config.keys_dir) {
        die(&format!("Failed to prepare the session secret: {e}"));
    }
    // W7: load the log redaction secrets (`loadRedactionSecrets`) once the session secret exists.
    let http = HttpClient::new(true).unwrap_or_else(|e| die(&format!("http client: {e}")));
    Arc::new(App {
        console_auth: ConsoleAuth::new(saas_key, vm_id, config.service.clone()),
        firewall_auth,
        runner: Arc::new(cc_proc::SystemRunner),
        console: ConsoleClient::new(keys.clone(), http.clone()),
        http,
        keys,
        pool_healthy: AtomicBool::new(false),
        bootstrap_ready: AtomicBool::new(false),
        contracts: contracts::Contracts::default(),
        started: std::time::Instant::now(),
        unmanaged: None,
        config,
    })
}

/// [`startup`] in unmanaged mode: no console key and no pool. The firewall's key from the config
/// file opens both the firewall's routes and the console's (in a standalone setup the firewall is
/// the control plane). Without one yet, the console gate holds this agent's own key, whose private
/// half nobody else has, and the firewall gate has none: every route is a 401 until pairing.
fn startup_unmanaged(config: Config, um: unmanaged::Unmanaged, runner: Arc<dyn cc_proc::Runner>) -> Arc<App> {
    let state = um.state_dir.clone();
    if let Err(e) = std::fs::create_dir_all(&state) {
        die(&format!("Failed to make the state dir {}: {e}", state.display()));
    }
    let Some(own) = cc_auth::keys::ensure_vm_keypair(&state) else {
        die("Failed to make the agent's keypair");
    };
    let firewall_key = um.file.firewall_key().map(str::to_string);
    if firewall_key.is_none() {
        tracing::warn!(
            "[unmanaged] no firewall.public_key in {}: every route answers 401 until this agent is paired",
            um.path.display()
        );
    }
    let console_key = match VerifyKey::ed25519_spki_pem(firewall_key.as_deref().unwrap_or(&own)) {
        Ok(k) => k,
        Err(e) => die(&format!("firewall.public_key is not an Ed25519 public key: {e}")),
    };
    let vm_id = um.file.agent_id.clone().filter(|v| !v.is_empty());
    if firewall_key.is_some() && vm_id.is_none() {
        // Tokens are then checked by signature only: one firewall key opens every agent it signs for.
        tracing::warn!(
            "[unmanaged] no agent_id in {}: tokens are not tied to this agent",
            um.path.display()
        );
    }
    let latch = vm_id.as_ref().map(|_| state.join("firewall-tokens-bound"));
    let hostnames: Vec<String> = um
        .file
        .firewall
        .hostnames
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|h| !h.trim().is_empty())
        .collect();
    if hostnames.is_empty() {
        tracing::warn!(
            "[unmanaged] no firewall.hostnames in {}: the host a firewall token was signed for is not checked",
            um.path.display()
        );
    }
    let firewall_auth = FirewallAuth::new(
        move || firewall_key.clone(),
        vm_id.clone(),
        move || hostnames.clone(),
        latch,
    )
    .quiet_unknown_host();
    if let Err(e) = keys::ensure_session_secret(&state) {
        die(&format!("Failed to prepare the session secret: {e}"));
    }
    let keys = KeysDir::new(&state);
    let http = HttpClient::new(true).unwrap_or_else(|e| die(&format!("http client: {e}")));
    tracing::info!("[unmanaged] config {}, state {}", um.path.display(), state.display());
    tracing::info!(
        "[unmanaged] OpenClaw: {}",
        serde_json::to_string(&um.install()).unwrap_or_default()
    );
    Arc::new(App {
        console_auth: ConsoleAuth::new(console_key, vm_id, config.service.clone()),
        firewall_auth,
        runner,
        console: ConsoleClient::new(keys.clone(), http.clone()),
        http,
        keys,
        pool_healthy: AtomicBool::new(false),
        bootstrap_ready: AtomicBool::new(false),
        contracts: contracts::Contracts::default(),
        started: std::time::Instant::now(),
        unmanaged: Some(Arc::new(um)),
        config,
    })
}

/// The whole router for this box's service.
pub fn router(app: &Arc<App>) -> Router {
    let brain = app.config.service == "gbrain";
    let mut router = Router::new(if brain { stages::BRAIN_BOX } else { stages::AGENT_BOX });
    if app.unmanaged.is_some() {
        let a = app.clone();
        router.gate(stages::CONSOLE, move |parts, _| {
            let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let ok = a
                .console_auth
                .verify(parts.method.as_str(), target, header(parts, "authorization"))
                .is_some();
            (!ok).then(unauthorized)
        });
        unmanaged::register(&mut router, app);
        return router;
    }
    if !brain {
        // W8: what the phone relay does with an upgrade it does not own (`PhoneStreamRelay.upgrade`).
        router.upgrades(Router::new(&[stages::UPGRADE]));
    }
    if app.config.pool_marker.exists() {
        // An unowned box answers only its health, without auth (`unclaimedStatus`). Captured once:
        // claiming the box restarts the agent.
        let a = app.clone();
        router.pre_gate(move |parts, _| {
            let ready = a.pool_healthy.load(Ordering::Relaxed);
            let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let status = if parts.method == hyper::Method::GET && target == "/health" {
                if ready { 200 } else { 503 }
            } else {
                401
            };
            Some(json(status, &serde_json::json!({"unclaimed": true, "ready": ready})))
        });
    }
    let a = app.clone();
    router.gate(stages::CONSOLE, move |parts, _| {
        let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let ok = a
            .console_auth
            .verify(parts.method.as_str(), target, header(parts, "authorization"))
            .is_some();
        (!ok).then(unauthorized)
    });
    // The agent box only: the brain box's router has no `prefixed` stage.
    if app.config.conformance_routes && !brain {
        tracing::warn!("serving the conformance rig's test route {}", conformance_routes::PATH);
        conformance_routes::register(&mut router, app);
    }
    if brain {
        gbrain::register(&mut router, app);
    } else {
        meetings::register(&mut router, app);
        phone::register(&mut router, app);
        gbrain::mcp::register(&mut router, app);
        boxside::register(&mut router, app);
        platform::register(&mut router, app);
    }
    router
}

/// Serve `addr` with the same router once it can be bound, trying every 10 s; says so once.
async fn serve_legacy(addr: String, router: Arc<Router>, allow: Vec<std::net::IpAddr>) {
    let mut warned = false;
    loop {
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                tracing::info!("ControlClaw agent also listening on {addr} (the old port)");
                return cc_http::serve_from(l, router, allow).await;
            }
            Err(e) if !warned => {
                tracing::warn!("not listening on the old port {addr} yet, trying every 10 s: {e}");
                warned = true;
            }
            Err(_) => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

#[tokio::main]
async fn main() {
    cc_http::log::init();
    let path = unmanaged::config::path();
    let file = match unmanaged::config::load(&path) {
        Ok(f) => f,
        Err(e) => die(&format!("Failed to read the agent config: {e}")),
    };
    // `vm-agent discover`: what an unmanaged agent would find here, as JSON, with or without a
    // config file.
    if std::env::args().nth(1).as_deref() == Some("discover") {
        let f = file.unwrap_or_default();
        let home = Config::from_env().home;
        let found = unmanaged::discover::dry_run(
            &unmanaged::CappedRunner::system(),
            &f.openclaw,
            &home,
            &f.state_dir(&home),
        )
        .await;
        println!("{}", serde_json::to_string_pretty(&found).unwrap_or_default());
        return;
    }
    let (config, app) = match file {
        None => {
            let config = Config::from_env();
            (config.clone(), None)
        }
        Some(f) => {
            let config = Config::unmanaged(&f);
            let state = f.state_dir(&config.home);
            let found =
                unmanaged::discover::discover(&unmanaged::CappedRunner::system(), &f.openclaw, &config.home, &state)
                    .await;
            let um = unmanaged::Unmanaged::new(f, path, &config.home, found);
            (
                config.clone(),
                Some(startup_unmanaged(
                    config,
                    um,
                    Arc::new(unmanaged::CappedRunner::system()),
                )),
            )
        }
    };
    let addr = format!("{}:{}", config.bind, config.port);
    let app = app.unwrap_or_else(|| startup(config));
    let router = Arc::new(router(&app));
    let listener = match &app.unmanaged {
        Some(_) => unmanaged::listen(&addr).await,
        None => match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => die(&format!("listen {addr}: {e}")),
        },
    };
    tracing::info!("ControlClaw agent listening on {addr}");
    // The old port, for callers that still dial it. Best effort and retried: the main port is what
    // Caddy tries first, and a port someone else holds for a while must not stop the agent.
    let allow = app.unmanaged.as_ref().map(|u| u.file.allow_from()).unwrap_or_default();
    if let Some(legacy) = app.config.legacy_port {
        tokio::spawn(serve_legacy(
            format!("{}:{legacy}", app.config.bind),
            router.clone(),
            allow.clone(),
        ));
    }
    // W6: the bootstrap (keys, CA, egress, gateway, HTTPS, ready) and the timers start from here.
    if app.unmanaged.is_some() {
        unmanaged::start(&app);
    } else if app.config.service != "gbrain" {
        platform::start(&app);
    } else {
        // W8: the brain's first boot, after the bind as `server.listen`'s callback in gbrain.ts.
        gbrain::start(&app);
    }
    if !allow.is_empty() {
        tracing::info!("[unmanaged] only {allow:?} may connect");
    }
    cc_http::serve_from(listener, router, allow).await;
}
