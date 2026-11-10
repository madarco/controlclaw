//! A standalone firewall's own control plane (`cc-local`), in this process: the SQLite file in
//! `STATE_DIR`, the `local:` endpoints every client of the agent answers (`cc_client::local`), the hourly
//! retention, and the admin API on `LOCAL_PANEL_BIND` (default `127.0.0.1:8800`), whose config
//! changes run the command handlers registered here directly. Off in SaaS mode.

use std::sync::Arc;

use cc_local::admin::{Admin, AdminConfig, Hooks};
use cc_local::{Db, LocalControlPlane};
use serde_json::Value;

use crate::app::App;
use crate::commands::Commands;

pub const DB_FILE: &str = "local.db";

/// Open the database and answer `local:` calls with it, as this firewall (`BOX_ID`).
pub fn open(app_config: &crate::app::Config) -> Result<Arc<LocalControlPlane>, String> {
    let state = std::env::var("STATE_DIR").unwrap_or_else(|_| super::env::STANDALONE_STATE_DIR.into());
    std::fs::create_dir_all(&state).map_err(|e| format!("{state}: {e}"))?;
    let path = std::path::Path::new(&state).join(DB_FILE);
    let db = Arc::new(Db::open(&path).map_err(|e| format!("{}: {e}", path.display()))?);
    let plane = Arc::new(LocalControlPlane::new(db.clone()));
    plane
        .register_self(&app_config.box_id)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // Every start, not only the first: a log rotated since then would leave the refusals unexplained.
    if plane.only_block_all().unwrap_or(false) {
        tracing::warn!(
            "[cc-local] \"Every other site\" is Block and there is no other rule: only the model keys and bots set up in the panel get through"
        );
    } else if db.created() {
        tracing::info!(
            "[cc-local] new database: every site is let through and logged; to lock it down set \"Every other site\" to Block in the panel (Internet access)"
        );
    }
    // Every client of the agent (StoreClient, ConsoleClient) answers `local:` URLs with it.
    let (p, caller) = (plane.clone(), app_config.box_id.clone());
    cc_client::local::set_handler(Arc::new(move |method, url, body| {
        let (p, caller) = (p.clone(), caller.clone());
        let rest = url.strip_prefix("local:").unwrap_or(url);
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let call = cc_local::Call {
            method: method.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            body,
        };
        Box::pin(async move {
            use cc_local::ControlPlane;
            let a = p.call(&caller, call).await;
            (a.status, a.body)
        })
    }));
    cc_local::retention::spawn(db);
    tracing::info!("[cc-local] control plane in {}", path.display());
    Ok(plane)
}

/// Where a browser reaches the panel: `cc_local::panel_origin`.
pub fn panel_origin() -> String {
    cc_local::panel_origin()
}

/// The admin API, once the handlers are registered. Logs the setup token while there is no admin.
pub async fn serve(app: &Arc<App>, plane: Arc<LocalControlPlane>, commands: Commands) {
    let commands = Arc::new(commands);
    let a = app.clone();
    let c = commands.clone();
    let hooks = Hooks {
        // As the signed-in admin: a change applies with no code sent to a person (plan §3).
        command: Arc::new(move |action, payload| {
            let handler = commands.handler(&action);
            Box::pin(async move {
                let (outcome, code) = crate::commands::run_as_admin(handler?, &action, payload).await;
                let mut v = serde_json::to_value(outcome).unwrap_or(Value::Null);
                if let (Some(code), Value::Object(m)) = (code, &mut v) {
                    m.insert(cc_local::api::LOCAL_CODE.into(), Value::String(code));
                }
                Some(v)
            })
        }),
        status: Arc::new(move || c.beat_fields()),
        rules_changed: Arc::new(|| super::sync::WAKE.notify_one()),
        open_link: Arc::new(move |page| {
            let keys = &a.config.keys_dir;
            let host = a
                .keys
                .read("vm_hostname")
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .ok_or("no keys/vm_hostname: the name the browser reaches this firewall at")?;
            let intent = super::local_intent::mint(keys, &a.config.org_id, &a.config.box_id, page)?;
            super::local_intent::link(&host, page, &intent).ok_or_else(|| format!("no page {page}"))
        }),
    };
    let bind = std::env::var("LOCAL_PANEL_BIND").unwrap_or_else(|_| "127.0.0.1:8800".into());
    let addr = bind.parse::<std::net::SocketAddr>().ok();
    let loopback = addr.map_or_else(
        || {
            bind.rsplit_once(':')
                .is_some_and(|(h, _)| h.eq_ignore_ascii_case("localhost"))
        },
        |a| a.ip().is_loopback(),
    );
    // The API speaks plain HTTP: beyond this machine the password and the setup token would cross
    // the network in clear. Reach it with an SSH tunnel, or put HTTPS in front of it on loopback.
    if !loopback && std::env::var("LOCAL_PANEL_INSECURE").as_deref() != Ok("1") {
        tracing::error!(
            "[cc-local] the admin API is not started: LOCAL_PANEL_BIND={bind} is beyond this machine and the API speaks plain HTTP. Bind it to 127.0.0.1 behind an SSH tunnel or HTTPS (Caddy, Tailscale Serve), or set LOCAL_PANEL_INSECURE=1"
        );
        return;
    }
    // Secure unless told: a browser keeps it on localhost (an SSH tunnel) and over HTTPS.
    let secure = std::env::var("LOCAL_PANEL_SECURE_COOKIE").as_deref() != Ok("0");
    let names = std::env::var("LOCAL_PANEL_HOSTS").unwrap_or_default();
    let config = AdminConfig::with_hosts(
        secure,
        names
            .split(',')
            .map(str::to_string)
            // A wildcard bind names no host: then LOCAL_PANEL_HOSTS must.
            .chain(addr.filter(|a| !a.ip().is_unspecified()).map(|a| a.ip().to_string())),
    );
    super::local_pair::serve(plane.db.clone(), app.config.keys_dir.clone()).await;
    super::node_relay::serve().await;
    let admin = Admin::new(plane.db.clone(), plane, hooks, config);
    // The bots', inboxes' and Google grants' rules from the firewall's own lists.
    let a = admin.clone();
    tokio::spawn(async move { a.read_managed().await });
    if let Some(t) = admin.setup_token() {
        tracing::warn!(
            "[cc-local] no admin yet: set the password with this one-time setup token (POST /api/setup): {t}"
        );
    }
    match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => {
            tracing::info!("[cc-local] admin API on {bind}");
            tokio::spawn(cc_http::serve(
                l,
                Arc::new(admin.router_with_panel(super::fw_shell::ui_dir())),
            ));
        }
        Err(e) => tracing::error!("[cc-local] admin API on {bind}: {e}"),
    }
}
