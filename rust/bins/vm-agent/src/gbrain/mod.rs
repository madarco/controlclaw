//! W8: the brain box entry (`CC_SERVICE=gbrain`, `packages/vm-agent/src/gbrain.ts`,
//! docs/plans/rust-workstreams/W8.md). Same binary, its own router: the routes before
//! `requireAuth` go in `stages::BRAIN_OPEN`, the console's in `stages::CONSOLE`.
//!
//! What a brain shares with an agent is the plumbing (the console's key, the on-box keypair, the
//! ready report, the unit lifecycle routes). Brain-only parts here:
//!
//! - `POST /llm/apply`: the brain's model key, firewall-signed (`llm`), never the console's (`key.rs`).
//! - `/gbrain/connect|disconnect|lock|connections`: who may use the brain, firewall-signed
//!   (`gbrain`), and the gate on the private address, port 3131 (`gate.rs`).
//! - The brain's Activity: agents' calls, the nightly run, the counts (`activity.rs`, `stats.rs`).
//!
//! From W7's box side, with the brain's options: the Open exchange under `/__cc/` (login routes
//! only, owners and admins, landing on GBrain's admin), the firewall's `/access/*` pushes, the
//! unit journal at `GET /logs` and `POST /mitm-ca/refresh` (`register_box_routes`).
//!
//! The first boot (keypair, the firewall's CA, egress, ready) is `boot.rs`, started from main.rs
//! once the listener is bound.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, firewall_request, json, send_json};
use cc_proc::{Cmd, Output, Runner};
use hyper::Method;
use serde_json::{Map, Value};

use crate::app::App;
use crate::platform::service_status;
use crate::stages;

pub mod activity;
/// The brain's backup: its staged kind for W7's backup service (`gbrain-backup.ts`).
pub mod backup;
/// The brain's first boot: keypair, CA, egress, ready (`gbrain.ts`).
pub mod boot;
pub mod gate;
pub mod key;
pub mod login;
/// `POST /gbrain/apply` on an agent box (`brain-mcp.ts`).
pub mod mcp;
pub mod stats;

/// `Date.now()`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `execFailureLine`: the last non-empty line of a failed command's output, colours stripped, for a
/// person. `message` is what Node's error said (`Command failed: <line>`, or a spawn error).
pub fn exec_failure_line(out: Option<&Output>, line: &str, spawn_error: Option<&str>) -> String {
    static ANSI: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;]*m").expect("regex"));
    let stderr = out.map(Output::stderr_str).unwrap_or_default();
    let stdout = out.map(Output::stdout_str).unwrap_or_default();
    let message = match spawn_error {
        Some(e) => e.to_string(),
        None => format!("Command failed: {line}\n{stderr}"),
    };
    let text = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        message
    };
    let text = ANSI.replace_all(&text, "");
    text.trim()
        .split('\n')
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or("command failed")
        .to_string()
}

/// Run a root helper; its stdout, or the line that says why it failed.
pub async fn run_helper(runner: &dyn Runner, cmd: Cmd) -> Result<String, String> {
    let line = std::iter::once(cmd.program.as_str())
        .chain(cmd.args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    match runner.run(cmd).await {
        Ok(out) if out.success() => Ok(out.stdout_str()),
        Ok(out) => Err(exec_failure_line(Some(&out), &line, None)),
        Err(e) => Err(exec_failure_line(None, &line, Some(&e.to_string()))),
    }
}

/// `saasBaseUrl`: `CONTROLCLAW_URL`, or `config_api_url` with `/api/...` cut off.
#[cfg_attr(test, allow(dead_code))]
fn saas_base_url(app: &App) -> Option<String> {
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

#[cfg_attr(test, allow(dead_code))]
fn gbrain_port() -> u16 {
    std::env::var("GBRAIN_PORT")
        .ok()
        .and_then(|v| {
            v.trim()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap_or(3130)
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    crate::platform::register_lifecycle(router, app);
    let gate = Arc::new(gate::BrainGate::new(
        &app.config.state_dir.join("gbrain-gate.json"),
        app.runner.clone(),
    ));
    register_llm_apply(router, app);
    register_gbrain_routes(router, app, &gate);
    register_backup(router, app, &gate);
    register_box_routes(router, app);
    // In-place updates, as on an agent (`/update`, before the console's gate: it checks its own tokens).
    crate::platform::update::register_on(router, app, stages::BRAIN_OPEN);
    let a = app.clone();
    router.exact(stages::CONSOLE, Method::GET, "/health", move |_, _| {
        let app = a.clone();
        async move {
            let gbrain = service_status(app.runner.as_ref(), "gbrain").await;
            let postgres = service_status(app.runner.as_ref(), "postgresql@16-gbrain").await;
            json(
                200,
                &serde_json::json!({
                    "status": "ok",
                    "role": "gbrain",
                    "uptime": app.started.elapsed().as_secs_f64(),
                    "services": {"gbrain": gbrain, "postgresql": postgres},
                }),
            )
        }
    });
    // The listener on the private address and the Activity loops are the running box's; a test
    // that builds the router starts neither.
    #[cfg(not(test))]
    {
        listen_gate(gate, gbrain_port());
        start_activity(app);
    }
    #[cfg(test)]
    let _ = gate;
}

/// After the listener is bound (main.rs): the brain's first boot, which ends in the ready report.
pub fn start(app: &Arc<App>) {
    tokio::spawn(boot::run(app.clone()));
}

/// What the brain serves of the login shim (`BRAIN_ACCESS_ROUTES`): the exchange, the check Caddy
/// asks before every `/admin` request, and sign-out.
const BRAIN_ACCESS_ROUTES: &[&str] = &[
    "/__cc/open",
    "/__cc/open/begin",
    "/__cc/enroll",
    "/__cc/login",
    "/__cc/session",
    "/__cc/verify",
    "/__cc/logout",
];

/// W7's box-side routes with the brain's options (gbrain.ts). `/__cc/*` and `/access/*` come before
/// the console's gate (the browser has a ticket and then a session cookie, the firewall signs its
/// pushes); `/logs` and `/mitm-ca/refresh` are the console's.
fn register_box_routes(router: &mut Router, app: &Arc<App>) {
    // The sign-in pages' "Back to console" goes to the console's Brain page, not an agent's.
    let access = crate::boxside::access(app, Some("/dashboard/brain".into()));
    let runner = app.runner.clone();
    let opts = crate::boxside::AccessOptions {
        only: Some(BRAIN_ACCESS_ROUTES),
        require_write: Some("Only owners and admins can open the brain.".into()),
        steps: Some(("Signing you in to GBrain".into(), "Loading the brain".into())),
        landing: Some(Arc::new(move || {
            let runner = runner.clone();
            Box::pin(async move {
                login::login_path(runner.as_ref()).await.map_err(|e| {
                    tracing::error!("[access] {e}");
                    "The brain did not give a sign-in link. It may be starting; try Open again in a minute.".to_string()
                })
            })
        })),
    };
    crate::boxside::register_access(router, app, &access, opts, stages::BRAIN_OPEN, stages::BRAIN_OPEN);

    // GBrain's unit journal: lifecycle and crash lines only (`handleUnitLogs`). The sign-in shim
    // holds it too, so a revoke of every browser (a new session secret) reloads its redaction; its
    // `/__cc/logs` page stays a 404 here, off the allow-list.
    let logs = crate::boxside::logs(app);
    let _ = access.logs.set(logs.clone());
    router.exact(stages::CONSOLE, Method::GET, "/logs", move |req, _| {
        let logs = logs.clone();
        async move {
            let (parts, _) = req.into_parts();
            let lines = crate::boxside::logs::parse_lines(crate::boxside::logs::query_lines(&parts).as_deref());
            logs.unit_snapshot(lines).await
        }
    });

    // Re-read the firewall's CA (after a firewall restore), as an agent does.
    // Also the brain's box setup, which its first boot runs (`boot.rs`).
    let steps = Arc::new(crate::boxside::setup::BoxSteps::new(app, None));
    app.contracts.box_setup.set(steps.clone());
    router.exact(stages::CONSOLE, Method::POST, "/mitm-ca/refresh", move |_, _| {
        let steps = steps.clone();
        async move {
            let _one = boot::CA.lock().await;
            crate::boxside::setup::handle_refresh(&steps).await
        }
    });
}

/// Backups of the brain (`/backup/*`, before the console's gate: each route checks its own tokens):
/// the agents' service with the brain's staged kind, for the `gbrain` kind only.
fn register_backup(router: &mut Router, app: &Arc<App>, gate: &Arc<gate::BrainGate>) {
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into()))
        .join(".openclaw");
    let spool = std::env::var("BACKUP_SPOOL_DIR")
        .map(Into::into)
        .unwrap_or_else(|_| app.config.state_dir.clone());
    let staged = backup::BrainStaged::new(crate::platform::common::Deps::of(app), gate.clone());
    let service = Arc::new(
        crate::boxside::backup::BackupService::new(
            home,
            spool,
            app.runner.clone(),
            app.http.clone(),
            app.config.service.clone(),
        )
        .with_staged(Arc::new(staged)),
    );
    let app = app.clone();
    router.prefix(stages::BRAIN_OPEN, "/backup/", move |req, _| {
        let (app, service) = (app.clone(), service.clone());
        async move { crate::boxside::backup::handle(&app, &service, req, backup::BRAIN_KINDS).await }
    });
}

/// `POST /llm/apply`: firewall-signed, and before the console's gate, so a console token cannot
/// point GBrain at a key of its choosing.
fn register_llm_apply(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.route(
        stages::BRAIN_OPEN,
        |m, p| m == Method::POST && p == "/llm/apply",
        move |req, _| {
            let app = a.clone();
            async move {
                let body =
                    match firewall_request(&app.firewall_auth, req, "llm", 0, ReadBody::Json { limit: 16384 }).await {
                        FirewallRequest::Refused { .. } => {
                            return send_json(
                                401,
                                &serde_json::json!({"error": "model changes must come from the org firewall"}),
                            );
                        }
                        FirewallRequest::Accepted { body, .. } => body,
                    };
                let body = match body {
                    FirewallBody::Json(m) => Some(m),
                    _ => None,
                };
                let input = match key::parse(body.as_ref()) {
                    Ok(i) => i,
                    Err(e) => return send_json(400, &serde_json::json!({"ok": false, "error": e})),
                };
                match key::apply(&input, app.runner.as_ref()).await {
                    Ok(changed) => {
                        tracing::info!(
                            "[llm] brain model key {}{}",
                            if input == key::BrainKey::Clear {
                                "removed"
                            } else {
                                "set"
                            },
                            if changed { "" } else { " (unchanged)" }
                        );
                        send_json(200, &serde_json::json!({"ok": true, "applied": [], "changed": changed}))
                    }
                    Err(e) => send_json(500, &serde_json::json!({"ok": false, "error": e})),
                }
            }
        },
    );
}

/// Which agents may use the brain: only the firewall, after the owner confirmed it with a code.
fn register_gbrain_routes(router: &mut Router, app: &Arc<App>, gate: &Arc<gate::BrainGate>) {
    let (a, g) = (app.clone(), gate.clone());
    router.prefix(stages::BRAIN_OPEN, "/gbrain/", move |req, _| {
        let (app, gate) = (a.clone(), g.clone());
        async move {
            let path = cc_http::pathname(&req.uri().to_string());
            let method = req.method().clone();
            let read = if method == Method::POST
                && matches!(path.as_str(), "/gbrain/connect" | "/gbrain/lock" | "/gbrain/disconnect")
            {
                ReadBody::Json { limit: 16384 }
            } else {
                ReadBody::No
            };
            let body = match firewall_request(&app.firewall_auth, req, "gbrain", 0, read).await {
                FirewallRequest::Refused { .. } => {
                    return send_json(
                        401,
                        &serde_json::json!({"error": "brain connections must come from the org firewall"}),
                    );
                }
                FirewallRequest::Accepted { body, .. } => match body {
                    FirewallBody::Json(m) => Some(m),
                    _ => None,
                },
            };
            gbrain_route(&gate, &method, &path, body.as_ref()).await
        }
    });
}

async fn gbrain_route(
    gate: &gate::BrainGate,
    method: &Method,
    path: &str,
    body: Option<&Map<String, Value>>,
) -> cc_http::Resp {
    let bad = |e: &str| send_json(400, &serde_json::json!({"ok": false, "error": e}));
    let failed = |e: String| send_json(500, &serde_json::json!({"ok": false, "error": e}));
    match (method.as_str(), path) {
        ("GET", "/gbrain/connections") => {
            let lock = gate.lock();
            send_json(
                200,
                &serde_json::json!({"ok": true, "connections": gate.list(), "lock": {"all": lock.all, "vmIds": lock.vm_ids}}),
            )
        }
        ("POST", "/gbrain/connect") => match gate::parse_connect(body) {
            Err(e) => bad(e),
            Ok(input) => match gate.connect(&input).await {
                Ok(()) => send_json(200, &serde_json::json!({"ok": true, "applied": []})),
                Err(e) => failed(e),
            },
        },
        ("POST", "/gbrain/lock") => match gate::parse_lock(body) {
            Err(e) => bad(e),
            Ok(lock) => match gate.set_lock(lock) {
                Ok(()) => send_json(200, &serde_json::json!({"ok": true, "applied": []})),
                Err(e) => failed(e.to_string()),
            },
        },
        ("POST", "/gbrain/disconnect") => match gate::parse_disconnect(body) {
            Err(e) => bad(e),
            Ok(vm_id) => match gate.disconnect(&vm_id).await {
                Ok(removed) => send_json(200, &serde_json::json!({"ok": true, "removed": removed, "applied": []})),
                Err(e) => failed(e),
            },
        },
        _ => send_json(404, &serde_json::json!({"error": "Not found"})),
    }
}

/// The gate, on the private address only. The NIC can come up after this process, so keep looking.
#[cfg_attr(test, allow(dead_code))]
fn listen_gate(gate: Arc<gate::BrainGate>, gbrain_port: u16) {
    tokio::spawn(async move {
        loop {
            let Some(ip) = gate::private_address() else {
                tracing::warn!("[gbrain-gate] no private address yet; trying again in 30 s");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            };
            match tokio::net::TcpListener::bind((ip.as_str(), gate::GATE_PORT)).await {
                Ok(listener) => {
                    tracing::info!(
                        "[gbrain-gate] listening on {ip}:{} ({} agent(s) connected)",
                        gate::GATE_PORT,
                        gate.list().len()
                    );
                    serve_gate(listener, gate, format!("127.0.0.1:{gbrain_port}")).await;
                    return;
                }
                Err(e) => {
                    tracing::error!(
                        "[gbrain-gate] could not listen on {ip}:{}: {e}; trying again in 30 s",
                        gate::GATE_PORT
                    );
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
    });
}

/// Serve the gate on `listener`, forwarding to GBrain at `target`.
pub async fn serve_gate(listener: tokio::net::TcpListener, gate: Arc<gate::BrainGate>, target: String) {
    let mut router = Router::new(&["gate"]);
    let target = Arc::new(target);
    router.route(
        "gate",
        |_, _| true,
        move |req, ctx| {
            let (gate, target) = (gate.clone(), target.clone());
            async move {
                let log = |l: &str| tracing::info!("{l}");
                gate::handle(&|ip| gate.admit(ip), &target, &log, req, ctx).await
            }
        },
    );
    cc_http::serve(listener, Arc::new(router)).await;
}

/// The brain's Activity: agents' calls from GBrain's admin feed, the nightly run's summary, counts.
#[cfg_attr(test, allow(dead_code))]
fn start_activity(app: &Arc<App>) {
    let Some(base) = saas_base_url(app) else {
        tracing::warn!("[brain-activity] no control plane URL in KEYS_DIR; Activity is not shipped");
        return;
    };
    let (keys, runner, http) = (app.keys.clone(), app.runner.clone(), app.http.clone());
    let state = app.config.state_dir.clone();
    activity::BrainActivity::new(activity::Options {
        console_http: Arc::new(move || http.get()),
        gbrain_url: format!("http://127.0.0.1:{}", gbrain_port()),
        login_path: Arc::new(move || {
            let runner = runner.clone();
            Box::pin(async move { login::login_path(runner.as_ref()).await })
        }),
        activity_url: format!("{base}/api/vm-agent/activity"),
        token: Arc::new(move || cc_auth::sign::box_token(&keys).map_err(|e| e.to_string())),
        report_path: "/var/lib/gbrain-report/last-cycle.json".into(),
        cursor_path: state.join("brain-cycle.cursor"),
        // GBrain's database and pages are on the encrypted container, the volume the state
        // directory is on.
        disk: Some(Arc::new(move || stats::brain_disk(&[Path::new(&state)]))),
        log: Arc::new(|l| tracing::info!("[brain-activity] {l}")),
    })
    .start();
}

#[cfg(test)]
mod tests;
