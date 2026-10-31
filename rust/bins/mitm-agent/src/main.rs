//! The firewall agent: the Rust build of `packages/mitm-agent` (docs/plans/rust-rewrite.md). Same
//! environment, key files, ports and heartbeat as the Node build. Each workstream fills its own
//! folder and registers its routes, commands and listeners from its `register()`; this file only
//! wires them up.

use std::sync::Arc;
use std::time::Duration;

use cc_auth::keys::KeysDir;
use cc_client::{ConsoleClient, HttpClient};
use cc_http::{Router, empty, json};

mod app;
mod channels;
mod commands;
mod contracts;
mod core;
mod integrations;
mod stages;
#[cfg(test)]
mod tests;

use app::{App, Config, Registry};
use commands::Commands;
use core::control::{ControlOptions, FirewallControl};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn die(message: &str) -> ! {
    tracing::error!("[mitm-agent] {message}");
    std::process::exit(1);
}

fn log(line: &str) {
    tracing::info!("{line}");
}

/// A pool box with no organization yet: its keys, and a health answer on loopback, nothing else.
async fn run_pool(config: Config) {
    cc_auth::keys::ensure_vm_keypair(&config.keys_dir);
    if let Err(e) = cc_crypto::secret_store::load_or_create_box_key(&config.box_key_path, &log) {
        die(&format!("box key: {e}"));
    }
    let runner = cc_proc::SystemRunner;
    let subject = format!("controlclaw-firewall-{}", config.box_id);
    core::recovery_tls::load_or_create(&runner, &config.keys_dir, &subject).await;
    core::startup::start_pool(&config);
    let mut router = Router::new(&[]);
    router.pre_gate(|parts, _| {
        let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let status = if parts.method == hyper::Method::GET && target == "/health" {
            200
        } else {
            503
        };
        Some(json(status, &serde_json::json!({"unclaimed": true})))
    });
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", config.port)).await {
        Ok(l) => l,
        Err(e) => die(&format!("listen: {e}")),
    };
    cc_http::serve(listener, Arc::new(router)).await;
}

/// Everything but the listeners, so the tests can build the same registry.
pub fn build(app: &Arc<App>) -> Registry {
    let mut ingress = Router::new(stages::INGRESS);
    ingress.fallback(cc_http::empty_not_found);
    let mut upgrades = Router::new(&[stages::INGRESS_UPGRADE]);
    upgrades.fallback(|| empty(403));
    ingress.upgrades(upgrades);
    let mut reg = Registry {
        plain: Router::new(stages::PLAIN),
        tls: Router::new(stages::TLS),
        ingress,
        commands: Commands::default(),
    };
    core::register(&mut reg, app);
    channels::register(&mut reg, app);
    integrations::register(&mut reg, app);
    reg
}

/// A standalone firewall talks to no control plane but its own: each of its control-plane
/// variables is unset, a `file:` path or a `local:` endpoint, so a box set up for the console never
/// starts half standalone.
fn check_standalone() {
    for name in core::env::CONTROL_PLANE_VARS {
        let v = std::env::var(name).unwrap_or_default();
        if !v.is_empty() && !v.starts_with("file:") && !core::env::is_local(&v) {
            die(&format!(
                "MITM_MODE=standalone takes no control plane: unset {name}, or make it a file: path or a local: endpoint"
            ));
        }
    }
}

/// `mitm-agent open <page>`: a link that opens one of this firewall's pages in a browser, signed
/// with its own key. Standalone only: it needs the key and the identity the running agent wrote in
/// `KEYS_DIR` (the console makes links otherwise). Only `KEYS_DIR` is read from the environment.
fn open_link(config: &Config, page: Option<&str>) -> ! {
    let pages: Vec<&str> = core::local_intent::PAGES.iter().map(|(n, _)| *n).collect();
    let Some(page) = page.filter(|p| pages.contains(p)) else {
        die(&format!("usage: mitm-agent open <{}>", pages.join("|")));
    };
    // Standalone only: the console makes the links of a SaaS firewall.
    if std::env::var("MITM_MODE").is_ok_and(|m| !m.trim().is_empty()) && config.mode.saas() {
        die("mitm-agent open is for a standalone firewall only (MITM_MODE=standalone)");
    }
    let Ok((org_id, box_id)) = core::local_intent::identity(&config.keys_dir) else {
        die(&format!(
            "mitm-agent open is for a standalone firewall only: {} has no {} (the agent writes it when it runs with MITM_MODE=standalone)",
            config.keys_dir.display(),
            core::local_intent::IDENTITY_FILE
        ));
    };
    let keys = KeysDir::new(&config.keys_dir);
    let Some(host) = keys
        .read("vm_hostname")
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
    else {
        die("no keys/vm_hostname: the name the browser reaches this firewall at");
    };
    let intent = core::local_intent::mint(&config.keys_dir, &org_id, &box_id, page)
        .unwrap_or_else(|e| die(&format!("could not sign the link: {e}")));
    match core::local_intent::link(&host, page, &intent) {
        Some(url) => {
            println!("{url}");
            println!("(works once, within {} seconds)", core::local_intent::INTENT_LIFETIME_S);
            std::process::exit(0);
        }
        None => die("unknown page"),
    }
}

#[tokio::main]
async fn main() {
    cc_http::log::init();
    if let Err(e) = app::Mode::from_env() {
        die(&e);
    }
    let config = Config::from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("open") {
        open_link(&config, args.get(1).map(String::as_str));
    }
    if args.first().map(String::as_str) == Some("pair-code") {
        core::local_pair::pair_code(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("reset-admin") {
        core::local_admin::reset_admin();
    }
    if config.mode.standalone() {
        check_standalone();
        tracing::info!(
            "[mitm-agent] standalone: no control plane (org={} box={})",
            config.org_id,
            config.box_id
        );
    }
    if config.pool_marker.exists() {
        return run_pool(config).await;
    }
    if config.org_id.is_empty() || config.box_id.is_empty() {
        die("ORG_ID and BOX_ID are required");
    }
    // Before anything calls a control plane (`SHIP_ONCE` in `early`, the first sync): a standalone
    // firewall's calls go to its own.
    let local = config
        .mode
        .standalone()
        .then(|| core::local_cp::open(&config).unwrap_or_else(|e| die(&format!("local control plane: {e}"))));
    core::startup::early(&config).await;
    // Standalone sets a file of its own when none is named (`CoreEnv`).
    if core::env::CoreEnv::from_env(&config.proxy_config_dir)
        .store_url
        .is_empty()
    {
        die("STORE_URL is required");
    }
    cc_auth::keys::ensure_vm_keypair(&config.keys_dir);
    if config.mode.standalone()
        && core::local_intent::ensure(&config.keys_dir, &config.org_id, &config.box_id).is_none()
    {
        die("could not make the key that signs this firewall's Open links");
    }
    let http = HttpClient::new(true).unwrap_or_else(|e| die(&format!("http client: {e}")));
    let box_key = core::startup::box_key(&config, &http).await;
    let keys = KeysDir::new(&config.keys_dir);
    let runner: Arc<dyn cc_proc::Runner> = Arc::new(cc_proc::SystemRunner);
    let recovery = if config.recovery_routes {
        core::recovery_tls::load_or_create(
            runner.as_ref(),
            &config.keys_dir,
            &format!("controlclaw-firewall-{}", config.box_id),
        )
        .await
    } else {
        None
    };
    let app = Arc::new(App {
        console: ConsoleClient::new(keys.clone(), http.clone()),
        config,
        keys,
        box_key,
        runner,
        http,
        contracts: contracts::Contracts::default(),
        cp_inspect: Arc::new(core::cp_inspect::CpInspect::from_env()),
    });
    let reg = build(&app);
    core::start(&app).await;
    let cfg = &app.config;

    let listener = match tokio::net::TcpListener::bind((cfg.listen.as_str(), cfg.port)).await {
        Ok(l) => l,
        Err(e) => die(&format!("listen {}:{}: {e}", cfg.listen, cfg.port)),
    };
    tracing::info!(
        "[mitm-agent] listening on {} (org={} box={})",
        cfg.port,
        cfg.org_id,
        cfg.box_id
    );
    let plain = Arc::new(reg.plain);
    match recovery.as_ref().map(|t| cc_http::tls_acceptor(&t.cert, &t.key)) {
        Some(Ok(acceptor)) => {
            tracing::info!("[mitm-agent] recovery routes on {} over TLS (/recovery/*)", cfg.port);
            if let Some(t) = &recovery {
                tracing::info!("[mitm-agent] recovery certificate fingerprint: {}", t.fingerprint);
            }
            tokio::spawn(cc_http::serve_mux(listener, plain, Arc::new(reg.tls), acceptor));
        }
        other => {
            if let Some(Err(e)) = other {
                tracing::error!("[recovery] {e}");
            }
            let why = if cfg.recovery_routes {
                "no certificate on this box, or backups are not set up"
            } else {
                "RECOVERY_ROUTES=0"
            };
            tracing::info!("[mitm-agent] recovery routes off ({why})");
            tokio::spawn(cc_http::serve(listener, plain));
        }
    }

    match tokio::net::TcpListener::bind((cfg.ingress_bind.as_str(), cfg.ingress_port)).await {
        Ok(l) => {
            tracing::info!(
                "[mitm-agent] webhook ingress on {}:{}",
                cfg.ingress_bind,
                cfg.ingress_port
            );
            tokio::spawn(cc_http::serve(l, Arc::new(reg.ingress)));
        }
        Err(e) => tracing::error!("[ingress] listener: {e}"),
    }

    if let Some(plane) = local {
        core::local_cp::serve(&app, plane, reg.commands).await;
    } else if !cfg.firewall_url.is_empty() {
        let control = FirewallControl::new(
            ControlOptions {
                firewall_url: cfg.firewall_url.clone(),
                agent_version: cfg.agent_version.clone(),
                service: "controlclaw-mitmproxy".into(),
                action_timeout: Duration::from_secs(30),
            },
            reg.commands,
            app.runner.clone(),
            app.console.clone(),
        );
        tokio::spawn(control.run(Duration::from_millis(cfg.firewall_poll_ms)));
    }
    std::future::pending::<()>().await;
}
