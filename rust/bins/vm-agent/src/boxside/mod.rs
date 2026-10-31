//! W7: the box side of the vm-agent (docs/plans/rust-workstreams/W7.md): `/__cc/` sign-in, sessions
//! and pages, the files API, backups and workspace export, disk and storage, SSH, Tailscale,
//! devices, egress and the firewall CA, the screen thumbnail, Drive, Google, AgentMail, Gmail wake.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cc_http::{BoxFuture, Router};
use hyper::Method;
use serde_json::Value;

use crate::app::App;
use crate::stages;

pub mod access;
mod access_push;
pub mod access_state;
pub mod agentmail;
pub mod archive;
pub mod backup;
pub mod devices;
pub mod drive;
mod exec;
pub mod export;
pub mod files;
pub mod gmail;
pub mod google;
pub mod logins;
pub mod logs;
pub mod screen;
pub mod session;
pub mod setup;
pub mod shell;
pub mod ssh;
pub mod storage;
pub mod tailscale;
#[cfg(test)]
pub mod testing;
pub mod web;
pub mod zip;

pub use access::{Access, AccessOptions};

/// Download workspace (`WorkspaceExporter`, workspace-export.ts), which the files API serves.
pub trait Exporter: Send + Sync {
    /// What the zip would hold and roughly how big (`plan()`).
    fn plan(&self) -> BoxFuture<Value>;
    /// A download is running.
    fn busy(&self) -> bool;
    /// The zip's name without `.zip`.
    fn base_name(&self) -> String;
    /// Write the zip to `out`; `done(completed, bytes)` once it ended or the browser went away.
    /// False, and nothing written, when another download holds the slot.
    fn stream(&self, out: tokio::sync::mpsc::Sender<Bytes>, done: Box<dyn FnOnce(bool, u64) + Send>) -> bool;
}

/// The sign-in shim, its sessions and the access store, built once (`access.ts`, `session.ts`,
/// `access-state.ts`). `console_page` is a brain box's "Back to console" path (`setConsolePage`).
pub fn access(app: &Arc<App>, console_page: Option<String>) -> Arc<Access> {
    let state = Arc::new(access_state::AccessState::new(&app.config.state_dir));
    let sessions = Arc::new(session::Sessions::new(app.config.keys_dir.clone(), state.clone()));
    Arc::new(Access::new(app, sessions, state, console_page))
}

/// `/__cc/*` with `opts`, and the firewall's `/access/*` pushes: what an agent box and a brain box
/// (W8's `gbrain::register`, with its allow-list) both serve.
pub fn register_access(
    router: &mut Router,
    app: &Arc<App>,
    access: &Arc<Access>,
    opts: AccessOptions,
    cc_stage: &str,
    push_stage: &str,
) {
    let a = access.clone();
    let opts = Arc::new(opts);
    router.prefix(cc_stage, "/__cc/", move |req, _| {
        let (a, opts) = (a.clone(), opts.clone());
        async move { a.handle(req, &opts).await }
    });
    let (a, app2) = (access.clone(), app.clone());
    router.prefix(push_stage, "/access/", move |req, _| {
        let (a, app2) = (a.clone(), app2.clone());
        async move { access_push::handle(&app2, &a, req).await }
    });
    app.contracts.sessions.set(Arc::new(session::SessionsContract {
        sessions: access.sessions.clone(),
        keys: app.keys.clone(),
    }));
    app.contracts.access.set(access.clone());
}

/// The log reader for this box's unit (`CC_SERVICE`), with the redaction secrets loaded
/// (`loadRedactionSecrets`, once the session secret exists). A brain box's W8 entry uses
/// `unit_snapshot` for its `GET /logs`.
pub fn logs(app: &Arc<App>) -> Arc<logs::Logs> {
    let redaction = Arc::new(logs::Redaction::load(&app.config.keys_dir));
    Arc::new(logs::Logs::new(
        app.runner.clone(),
        redaction,
        app.config.service.clone(),
    ))
}

/// The console's origin for the box's own calls (`saasBaseUrl`): `CONTROLCLAW_URL`, else the
/// config API URL without its `/api/...`.
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

/// One line on the Activity page for something the console did through this box
/// (`reportOwnAction` in index.ts): W6's, so the watchdog's lines and these share one sequence.
/// Fire and forget, a failure only logged.
pub fn report_own_action(
    app: &Arc<App>,
    tag: &'static str,
    action: &str,
    line: String,
    agent_id: &'static str,
    ok: bool,
) {
    let (app, action) = (app.clone(), action.to_string());
    tokio::spawn(async move {
        // The error carries no URL (`without_url`).
        if let Err(e) = crate::platform::watchdog::report_own_action(&app, tag, &action, &line, agent_id, ok).await {
            tracing::error!("[{tag}] activity report: {e}");
        }
    });
}

fn ssh_login_cursor(app: &App) -> std::path::PathBuf {
    app.config.state_dir.join("ssh-logins.cursor")
}

/// `startSshLoginWatch`: every minute, the box's sshd logins to the console's Activity page. Not
/// on a pool box (no organization yet), and off without a console origin.
fn start_ssh_login_watch(app: &Arc<App>, cursor: std::path::PathBuf) {
    if app.config.pool_marker.exists() {
        return;
    }
    let Some(base) = saas_base_url(app) else {
        tracing::info!("[ssh] no config_api_url in KEYS_DIR: login reporting off");
        return;
    };
    let watcher = ssh::SshLoginWatcher::new(app.runner.clone(), cursor);
    let console = app.console.clone();
    let url = format!("{base}/api/vm-agent/activity");
    tokio::spawn(async move {
        let every = ssh_login_poll();
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        loop {
            tick.tick().await;
            let ship = async |body: Value| -> Result<u16, String> {
                match console.post_json(&url, &body, Duration::from_secs(20)).await {
                    Ok(a) => Ok(a.status),
                    Err(cc_client::ClientError::Http(e)) => Err(e.without_url().to_string()),
                    Err(e) => Err(e.to_string()),
                }
            };
            if let Err(e) = watcher.tick(ship).await {
                tracing::error!("[ssh] login watch failed: {e}");
            }
        }
    });
}

/// `SSH_LOGIN_POLL_MS` (60 s; the env value is read as `parseInt` reads it).
fn ssh_login_poll() -> Duration {
    let ms = std::env::var("SSH_LOGIN_POLL_MS")
        .ok()
        .and_then(|v| web::parse_int(&v))
        .filter(|ms| *ms > 0)
        .unwrap_or(60_000);
    Duration::from_millis(ms as u64)
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let access = access(app, None);
    let logs = logs(app);
    let _ = access.logs.set(logs.clone());
    register_access(
        router,
        app,
        &access,
        AccessOptions::default(),
        stages::CC,
        stages::PREFIXED,
    );

    // The file explorer, before the console's gate (it takes the browser's session).
    let root = std::env::var("FILES_ROOT")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| "/home/controlclaw".into());
    let a2 = app.clone();
    let a3 = app.clone();
    let files = Arc::new(
        files::FilesService::new(root.into(), app.keys.vm_id())
            .on_write(Arc::new(move |w: files::FilesWrite| {
                let size = w
                    .size
                    .map(|s| format!(" ({})", files::human_bytes(s)))
                    .unwrap_or_default();
                let line = format!("files.{} · {}{size}", w.op, w.path);
                report_own_action(&a2, "files", w.op, line, "console", true);
            }))
            .template_review(Arc::new(move || {
                a3.contracts.template_review.get().and_then(|t| t.template_review())
            })),
    );
    // Download workspace: conversations from W6, meetings and calls from W8; an empty slot is a
    // folder that is not in the zip.
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into()))
        .join(".openclaw");
    let (k, c1, c2, c3, c4) = (app.keys.clone(), app.clone(), app.clone(), app.clone(), app.clone());
    let exporter = export::WorkspaceExporter::new(
        home,
        Arc::new(move || shell::agent_name_of(k.read("vm_hostname").filter(|h| !h.is_empty()).as_deref())),
        export::Sources {
            conversations: Arc::new(move || c1.contracts.transcripts.get().map(|t| t.list()).unwrap_or_default()),
            read_conversation: Arc::new(move |r| c2.contracts.transcripts.get().and_then(|t| t.read(r))),
            meetings: Arc::new(move || {
                c3.contracts
                    .export_records
                    .get()
                    .map(|e| e.meetings())
                    .unwrap_or_default()
            }),
            calls: Arc::new(move || c4.contracts.export_records.get().map(|e| e.calls()).unwrap_or_default()),
        },
    );
    if let Ok(mut e) = files.exporter.lock() {
        *e = Some(Arc::new(exporter));
    }
    let (f, a) = (files.clone(), access.clone());
    router.prefix(stages::PREFIXED, "/files/", move |req, _| {
        let (f, a) = (f.clone(), a.clone());
        async move { files::handle(&f, &a, req).await }
    });

    // Backups: run and restore from the firewall, the plan with either token.
    let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into()))
        .join(".openclaw");
    let spool = std::env::var("BACKUP_SPOOL_DIR")
        .map(Into::into)
        .unwrap_or_else(|_| app.config.state_dir.clone());
    let a5 = app.clone();
    let backups = Arc::new(
        backup::BackupService::new(
            home,
            spool,
            app.runner.clone(),
            app.http.clone(),
            app.config.service.clone(),
        )
        .with_hooks(Arc::new(move || a5.contracts.backup_hooks.get())),
    );
    let (b, a6) = (backups, app.clone());
    router.prefix(stages::PREFIXED, "/backup/", move |req, _| {
        let (b, a6) = (b.clone(), a6.clone());
        async move { backup::handle(&a6, &b, req, backup::AGENT_KINDS).await }
    });

    // Rescue shell access, Tailscale and the gateway's devices: writes from the firewall only.
    let ssh = Arc::new(ssh::SshAccess::new(
        app.runner.clone(),
        app.config.state_dir.join("ssh.json"),
    ));
    let (s1, a7) = (ssh.clone(), app.clone());
    router.prefix(stages::PREFIXED, "/ssh/", move |req, _| {
        let (s1, a7) = (s1.clone(), a7.clone());
        async move { ssh::handle(&a7, &s1, req).await }
    });
    let ts = Arc::new(tailscale::Tailscale::new(app.runner.clone()));
    let a8 = app.clone();
    router.prefix(stages::PREFIXED, "/tailscale/", move |req, _| {
        let (ts, a8) = (ts.clone(), a8.clone());
        async move { tailscale::handle(&a8, &ts, req).await }
    });
    let a9 = app.clone();
    let devices = Arc::new(devices::Devices::new(
        app.runner.clone(),
        Arc::new(move || a9.contracts.openclaw.get().map(|o| o.client.clone())),
    ));
    let a10 = app.clone();
    router.route(
        stages::PREFIXED,
        |_, p| p == "/devices" || p.starts_with("/devices/"),
        move |req, _| {
            let (d, a10) = (devices.clone(), a10.clone());
            async move { devices::handle(&a10, &d, req).await }
        },
    );
    start_ssh_login_watch(app, ssh_login_cursor(app));

    // Drive folders, the org Google account and AgentMail: writes from the firewall only. Drive
    // and Google need the role's script and `gog`; a box without them answers 501.
    let state = app.config.state_dir.clone();
    let drive = Arc::new(drive::Drive::new(
        app.runner.clone(),
        state.join("drive.json"),
        state.join("drive-mounts.json"),
    ));
    let drive = drive.supported().then_some(drive);
    if drive.is_none() {
        tracing::info!("[drive] cc-drive-apply is not on this box: Drive folders off until it is re-provisioned");
    }
    let google = Arc::new(google::Google::new(
        app.runner.clone(),
        google::env_path(&state),
        state.join("google.json"),
    ));
    let google = google.supported().then_some(google);
    match &google {
        Some(g) => app.contracts.google.set(g.clone()),
        None => {
            tracing::info!("[google] gog is not on this box: the org Google account is off until it is re-provisioned")
        }
    }
    let watch = Arc::new(gmail::GmailWatch::new(
        app.runner.clone(),
        "/etc/controlclaw/gmail-watch.env".into(),
        state.join("gmail-watch.json"),
    ));
    if watch.supported() {
        app.contracts.gmail_watch.set(watch);
    } else {
        tracing::info!("[gmail-watch] gog is not on this box: Gmail push is off until it is re-provisioned");
    }
    app.contracts
        .gmail_wake
        .set(Arc::new(gmail::GmailWake::new(app, state.join("openclaw-hooks.json"))));
    let agentmail = Arc::new(agentmail::AgentMail::new(
        app,
        "/home/controlclaw/.openclaw/.env".into(),
    ));
    app.contracts.agentmail.set(agentmail.clone());
    let (d, a11) = (drive.clone(), app.clone());
    router.prefix(stages::PREFIXED, "/drive/", move |req, _| {
        let (d, a11) = (d.clone(), a11.clone());
        async move { drive::handle(&a11, d.as_deref(), req).await }
    });
    let a12 = app.clone();
    router.prefix(stages::PREFIXED, "/agentmail/", move |req, _| {
        let (m, a12) = (agentmail.clone(), a12.clone());
        async move { agentmail::handle(&a12, &m, req).await }
    });
    // Website logins in the agent's browser: the firewall only.
    let (browser, a14) = (Arc::new(logins::BrowserLogins::default()), app.clone());
    router.prefix(stages::PREFIXED, "/logins/", move |req, _| {
        let (b, a14) = (browser.clone(), a14.clone());
        async move {
            let wake = a14.contracts.gmail_wake.get();
            logins::handle(&a14, &b, wake, req).await
        }
    });
    let (g, a13) = (google.clone(), app.clone());
    router.prefix(stages::PREFIXED, "/google/", move |req, _| {
        let (g, a13) = (g.clone(), a13.clone());
        async move { google::handle(&a13, g.as_deref(), req).await }
    });

    // The bootstrap steps W6 runs (the firewall's CA, egress, HTTPS ready), and the CA refresh the
    // console asks for after a firewall restore.
    let steps = Arc::new(setup::BoxSteps::new(app, Some(ssh)).with_drive(drive));
    app.contracts.box_setup.set(steps.clone());
    router.exact(stages::CONSOLE, Method::POST, "/mitm-ca/refresh", move |_, _| {
        let steps = steps.clone();
        async move { setup::handle_refresh(&steps).await }
    });
    let display = std::env::var("CC_SCREEN_DISPLAY").unwrap_or_else(|_| ":1".into());
    let thumbs = Arc::new(screen::ScreenThumbs::new(screen::screen_capture(display)));
    router.exact(stages::CONSOLE, Method::GET, "/screen/thumb", move |_, _| {
        let thumbs = thumbs.clone();
        async move { screen::handle(&thumbs).await }
    });

    // Storage, behind the console's token; the disk reseal, firewall-signed.
    let st = Arc::new(storage::Storage::new(app.runner.clone()));
    for path in ["/storage", "/storage/grow"] {
        let st = st.clone();
        router.route(
            stages::CONSOLE,
            move |_, p| p == path,
            move |req, _| {
                let st = st.clone();
                async move { storage::handle_storage(&st, req).await }
            },
        );
    }
    let (st, a4) = (st, app.clone());
    router.prefix(stages::PREFIXED, "/disk/", move |req, _| {
        let (st, a4) = (st.clone(), a4.clone());
        async move { storage::handle_disk(&a4, &st, req).await }
    });

    // The console's log routes. Not on the agent box's allow-list, so the gate answers 401 there;
    // served all the same, as the TS does.
    let l = logs.clone();
    router.exact(stages::CONSOLE, Method::GET, "/logs", move |req, _| {
        let l = l.clone();
        async move {
            let (parts, _) = req.into_parts();
            l.snapshot(logs::parse_lines(logs::query_lines(&parts).as_deref()))
                .await
        }
    });
    let l = logs;
    router.exact(stages::CONSOLE, Method::GET, "/logs/stream", move |_, _| {
        let l = l.clone();
        async move { l.stream() }
    });
}
