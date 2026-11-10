//! Unmanaged mode: the agent attaches to an OpenClaw that something else installed (the official
//! installer, Docker, pm2) instead of the one our Ansible role sets up. Chosen by the config file
//! (`config.rs`); without it the agent is the managed one, unchanged.
//!
//! What it does here: find the install (`discover.rs`), say what it found on `GET /status`, write
//! models and channels through the OpenClaw CLI (`cli_gateway.rs`), and start, stop and restart the
//! gateway the way it runs (`supervisor.rs`), also for the firewall's emergency stop (`/kill/*`). No control plane: the firewall's key from the config
//! file opens the routes, and pairing (a later step) writes that key. The SaaS modules and the
//! Ansible-only parts (bootstrap, CA install, egress, the pool, templates, backups, gbrain, disk,
//! Doctor, the watchdog, meetings, phone, the agent's pages) are not started.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};

use cc_http::{Router, json};
use cc_openclaw::ConfigWriter;
use hyper::Method;
use serde_json::{Value, json as j};

use crate::app::App;
use crate::stages;

pub mod cli_gateway;
pub mod config;
pub mod copy_out;
pub mod discover;
pub mod offline;
pub mod restart;
pub mod supervisor;

use config::AgentFile;
use discover::Install;
pub use offline::offline_writes;

pub struct Unmanaged {
    pub file: AgentFile,
    /// Where `file` was read from, for the log and `/status`.
    pub path: PathBuf,
    /// The agent's own files (`file.state_dir`, resolved).
    pub state_dir: PathBuf,
    pub install: RwLock<Install>,
    /// The CLI gateway and its write queue, once the agent listens and found a CLI.
    pub gateway: OnceLock<Arc<cli_gateway::CliGateway>>,
    pub writer: OnceLock<Arc<ConfigWriter>>,
    /// One restart at a time, whoever asks (`restart.rs`).
    pub restarts: restart::RestartGate,
}

impl Unmanaged {
    pub fn new(file: AgentFile, path: PathBuf, home: &std::path::Path, install: Install) -> Self {
        let state_dir = file.state_dir(home);
        Self {
            file,
            path,
            state_dir,
            install: RwLock::new(install),
            gateway: OnceLock::new(),
            writer: OnceLock::new(),
            restarts: restart::RestartGate::default(),
        }
    }

    pub fn install(&self) -> Install {
        match self.install.read() {
            Ok(i) => i.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    fn set_install(&self, found: Install) {
        match self.install.write() {
            Ok(mut i) => *i = found,
            Err(p) => *p.into_inner() = found,
        }
    }

    /// Look again (after a start or restart: a gateway that was not running may now be a service).
    pub async fn rediscover(&self, app: &App) {
        let found = discover::discover(
            app.runner.as_ref(),
            &self.file.openclaw,
            &app.config.home,
            &self.state_dir,
        )
        .await;
        self.set_install(found);
    }

    /// Whether the gateway answers its health check now.
    pub async fn answers(&self) -> bool {
        match self.gateway.get() {
            Some(g) => g.probe().await,
            None => false,
        }
    }

    /// The firewall part of `/status`.
    fn firewall(&self) -> Value {
        j!({ "url": self.file.firewall.url, "paired": self.file.firewall_key().is_some() })
    }
}

/// The managed agent's state words, from the service manager and the gateway's health.
async fn state(app: &App, um: &Unmanaged) -> (&'static str, bool) {
    let install = um.install();
    let (manager, answers) = tokio::join!(supervisor::manager_up(app.runner.as_ref(), &install), um.answers());
    (supervisor::state(manager, answers), answers)
}

/// The routes an unmanaged agent answers: health, status, start/stop/restart, models, channels.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let Some(um) = app.unmanaged.clone() else { return };
    app.contracts
        .platform
        .set(Arc::new(crate::platform::Platform::default()));

    let (a, u) = (app.clone(), um.clone());
    router.exact(stages::CONSOLE, Method::GET, "/health", move |_, _| {
        let (app, um) = (a.clone(), u.clone());
        async move {
            let service = match (um.install().runs, state(&app, &um).await.0) {
                (discover::Runs::NotFound, _) => "not-installed",
                (_, "running") => "running",
                _ => "stopped",
            };
            json(
                200,
                &j!({
                    "status": "ok",
                    "uptime": app.started.elapsed().as_secs_f64(),
                    "services": { "openclaw": service },
                }),
            )
        }
    });

    let (a, u) = (app.clone(), um.clone());
    router.exact(stages::CONSOLE, Method::GET, "/status", move |_, _| {
        let (app, um) = (a.clone(), u.clone());
        async move {
            let (state, answers) = state(&app, &um).await;
            json(
                200,
                &j!({
                    "ok": true,
                    "action": "status",
                    "mode": "unmanaged",
                    "active": state == "running",
                    "status": state,
                    "state": state,
                    "gateway": { "connected": answers },
                    "install": um.install(),
                    "firewall": um.firewall(),
                }),
            )
        }
    });

    for action in ["start", "stop", "restart"] {
        let (a, u) = (app.clone(), um.clone());
        let path = match action {
            "start" => "/start",
            "stop" => "/stop",
            _ => "/restart",
        };
        router.exact(stages::CONSOLE, Method::POST, path, move |_, _| {
            let (app, um) = (a.clone(), u.clone());
            async move {
                let result = match action {
                    "restart" => restart(&app, &um).await,
                    _ => act(&app, &um, action).await,
                };
                let (state, _) = state(&app, &um).await;
                let ok = result.is_ok();
                json(
                    if ok { 200 } else { 500 },
                    &j!({
                        "ok": ok,
                        "action": action,
                        "active": state == "running",
                        "status": state,
                        "message": match result { Ok(()) => format!("OpenClaw {state}"), Err(e) => e },
                        "install": um.install(),
                    }),
                )
            }
        });
    }

    crate::platform::llm::register(router, app);
    crate::platform::channels::register(router, app);
    crate::platform::search::register(router, app);
    crate::platform::secrets::register(router, app);
    crate::platform::mcp_servers::register(router, app);
    crate::platform::connectors::register(router, app);
    // The emergency stop: OpenClaw stopped the way it runs, started again on release.
    crate::platform::kill::register(router, app);
}

/// One start, stop or restart at a time, whoever asks; then a fresh look at the install, in the
/// background (a gateway that was not running may now be a service, or have moved).
pub async fn act(app: &Arc<App>, um: &Arc<Unmanaged>, action: &str) -> Result<(), String> {
    if action == "stop" {
        um.restarts.stopped();
    }
    let result = {
        let _one = crate::platform::UNIT_ACTIONS.lock().await;
        supervisor::act(app.runner.as_ref(), &um.install(), action).await
    };
    after_act(app, um, action);
    result
}

/// Restart OpenClaw, or join the restart that runs (`restart.rs`); `Ok` once it is under way past
/// [`restart::ANSWER_WITHIN`], as OpenClaw drains its work and comes back by itself.
pub async fn restart(app: &Arc<App>, um: &Arc<Unmanaged>) -> Result<(), String> {
    let r: Arc<dyn restart::Restarter> = Arc::new(Restarts {
        app: Arc::downgrade(app),
        um: Arc::downgrade(um),
    });
    um.restarts
        .restart(r, restart::ANSWER_WITHIN, || {
            tracing::info!("[unmanaged] OpenClaw is restarting: it finishes its work first, then starts again");
        })
        .await
}

struct Restarts {
    app: std::sync::Weak<App>,
    um: std::sync::Weak<Unmanaged>,
}

impl restart::Restarter for Restarts {
    fn issue(self: Arc<Self>) -> cc_http::BoxFuture<Result<(), supervisor::Failure>> {
        Box::pin(async move {
            let (Some(app), Some(um)) = (self.app.upgrade(), self.um.upgrade()) else {
                return Err(supervisor::Failure {
                    message: crate::platform::common::NOT_RUNNING.to_string(),
                    timed_out: false,
                });
            };
            let result = {
                let _one = crate::platform::UNIT_ACTIONS.lock().await;
                supervisor::act_timed(app.runner.as_ref(), &um.install(), "restart").await
            };
            after_act(&app, &um, "restart");
            result
        })
    }

    fn seen(self: Arc<Self>) -> cc_http::BoxFuture<restart::Seen> {
        Box::pin(async move {
            let (Some(app), Some(um)) = (self.app.upgrade(), self.um.upgrade()) else {
                return restart::Seen::Unknown;
            };
            let install = um.install();
            let (manager, answers) = tokio::join!(supervisor::manager_up(app.runner.as_ref(), &install), um.answers());
            // While it drains, systemd says `deactivating` and the gateway may still answer.
            match (manager, answers) {
                (Some(false), _) => restart::Seen::Down,
                (_, true) => restart::Seen::Up,
                (Some(true), false) => restart::Seen::Starting,
                (None, false) => restart::Seen::Unknown,
            }
        })
    }
}

/// After a start, stop or restart, whoever asked (also the emergency stop): a fresh look at the
/// gateway, and at the install in the background (a gateway that was not running may now be a
/// service, or have moved).
pub fn after_act(app: &Arc<App>, um: &Arc<Unmanaged>, action: &str) {
    let (app, um, action) = (app.clone(), um.clone(), action.to_string());
    tokio::spawn(async move {
        if let Some(g) = um.gateway.get() {
            g.probe().await;
        }
        if action != "stop" {
            um.rediscover(&app).await;
        }
    });
}

/// Whether OpenClaw is down: neither its service manager nor its gateway says it is up.
pub async fn is_down(app: &App, um: &Unmanaged) -> bool {
    state(app, um).await.0 == "stopped"
}

/// The most a command run here may print, on stdout and on stderr. In unmanaged mode the output of
/// most commands (the OpenClaw CLI through `docker exec`, discovery, the `.env` read) comes from an
/// OpenClaw the agent does not trust, possibly a container's, and the agent may be root: past this
/// the command is killed, whatever its own program says it would write.
pub const MAX_OUTPUT: usize = 32 * 1024 * 1024;

/// Every command with [`MAX_OUTPUT`] (unless it names a smaller cap).
pub struct CappedRunner<R>(pub R);

impl CappedRunner<cc_proc::SystemRunner> {
    pub fn system() -> Self {
        Self(cc_proc::SystemRunner)
    }
}

#[async_trait::async_trait]
impl<R: cc_proc::Runner> cc_proc::Runner for CappedRunner<R> {
    async fn run(&self, mut cmd: cc_proc::Cmd) -> Result<cc_proc::Output, cc_proc::RunError> {
        cmd.max_output = Some(cmd.max_output.map_or(MAX_OUTPUT, |m| m.min(MAX_OUTPUT)));
        self.0.run(cmd).await
    }
}

/// How often a listen address that is not there yet is tried again.
const BIND_AGAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// The listener, on an address that may come up after the agent: the tunnel's (remote mode) or a
/// Docker bridge's (`up --local`). Tried again while the address is not on this machine; any other
/// error stops the agent.
pub async fn listen(addr: &str) -> tokio::net::TcpListener {
    let mut said = false;
    loop {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => return l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                if !said {
                    said = true;
                    tracing::warn!(
                        "[unmanaged] {addr} is not on this machine yet: trying again every {}s",
                        BIND_AGAIN.as_secs()
                    );
                }
                tokio::time::sleep(BIND_AGAIN).await;
            }
            Err(e) => {
                tracing::error!("listen {addr}: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// How often an agent that found no running OpenClaw looks again.
const LOOK_AGAIN: std::time::Duration = std::time::Duration::from_secs(60);

/// Once the agent listens: the CLI gateway and the services behind the routes.
pub fn start(app: &Arc<App>) {
    let Some(um) = app.unmanaged.clone() else { return };
    let install = um.install();
    if install.cli.is_none() {
        tracing::warn!("[unmanaged] no OpenClaw found yet: models and channels answer \"not running\"");
    }
    // Through the wrapper discovery keeps current, and the port it last found.
    let weak = Arc::downgrade(&um);
    let gw = cli_gateway::CliGateway::new(
        app.runner.clone(),
        discover::wrapper_path(&um.state_dir).to_string_lossy().into_owned(),
        app.config.home.clone(),
        move || {
            weak.upgrade()
                .map_or(discover::DEFAULT_GATEWAY_PORT, |u| u.install().gateway_port)
        },
    );
    gw.start_probe();
    let _ = um.writer.set(Arc::new(ConfigWriter::new(gw.clone())));
    let _ = um.gateway.set(gw);
    let (a, u) = (Arc::downgrade(app), Arc::downgrade(&um));
    tokio::spawn(async move {
        let mut every = tokio::time::interval(LOOK_AGAIN);
        every.tick().await;
        loop {
            every.tick().await;
            let (Some(app), Some(um)) = (a.upgrade(), u.upgrade()) else {
                return;
            };
            if matches!(um.install().runs, discover::Runs::NotFound | discover::Runs::NotRunning) {
                um.rediscover(&app).await;
            }
        }
    });
    let Some(p) = app.contracts.platform.get() else { return };
    let deps = crate::platform::common::Deps::of(app);
    let state = um.state_dir.clone();
    let _ = p.llm.set(Arc::new(crate::platform::llm::LlmService::new(
        deps.clone(),
        Some(state.join("memory-index.json")),
        None,
        None,
    )));
    let container = match &install.runs {
        discover::Runs::Docker { container } => Some(container.clone()),
        _ => None,
    };
    let docker = container.is_some();
    // OpenClaw's folder. On this machine: its own, which the agent reads as OpenClaw's user. In a
    // container: the container's own path, read through `docker cp` and written through `docker
    // exec`, which resolve it inside the container: the agent (root, for Docker) never walks the
    // folder here. A container whose folder is not known: nothing is read or written there.
    let inside = container
        .as_ref()
        .and(install.container_state_dir.clone())
        .map(PathBuf::from);
    let openclaw = match (&container, &inside) {
        (Some(_), Some(i)) => i.clone(),
        (Some(_), None) => state.join("no-openclaw-folder"),
        (None, _) => install
            .state_dir
            .clone()
            .map_or_else(|| app.config.home.join(".openclaw"), PathBuf::from),
    };
    let gate = um.file.firewall.gate;
    // Search and MCP servers are OpenClaw config writes through its CLI; the secrets are its `.env`.
    let _ = p.search.set(Arc::new(crate::platform::search::SearchService::new(
        deps.clone(),
        Arc::new(|| false),
    )));
    let how = match (&container, &inside) {
        (Some(c), Some(i)) => Some(crate::platform::secrets::Unmanaged::Container {
            container: c.clone(),
            env_path: i.join(".env").to_string_lossy().into_owned(),
        }),
        (Some(_), None) => None,
        (None, _) => Some(crate::platform::secrets::Unmanaged::Host),
    };
    if let Some(how) = how {
        let _ = p.secrets.set(Arc::new(
            crate::platform::secrets::SecretsService::new(openclaw.join(".env"), deps.clone()).unmanaged(how),
        ));
    }
    let _ = p
        .mcp_servers
        .set(Arc::new(crate::platform::mcp_servers::McpServersService::new(
            deps.clone(),
            state.join("mcp-servers.json"),
        )));
    // App connections: OpenClaw dials the relay on this machine's loopback, which a container
    // cannot reach (and the gate checks the token and the source address, so the relay cannot sit
    // elsewhere): not for an OpenClaw in a container yet.
    if !docker {
        let connectors = Arc::new(
            crate::platform::connectors::ConnectorsService::new(
                deps.clone(),
                crate::platform::env_port("CONNECTOR_RELAY_PORT", 3111),
                state.join("connectors.json"),
                app.config.home.join(".config/oomol/connector.env"),
                Arc::new(|| false),
            )
            .with_gate(gate),
        );
        connectors.start_relay();
        let _ = p.connectors.set(connectors);
    }
    let _ = p.channels.set(Arc::new(
        crate::platform::channels::ChannelsService::new(
            deps,
            openclaw.join("credentials"),
            Some(state.join("channels.json")),
            (!docker || inside.is_some()).then(|| openclaw.join("state/openclaw.sqlite")),
            None,
            Arc::new(|| None),
        )
        // Copies only from a folder the container names: with none known, nothing is read.
        .reading_through(container.map(|c| {
            if inside.is_some() {
                copy_out(c, state.join("from-container"))
            } else {
                copy_nothing()
            }
        })),
    ));
}

/// OpenClaw's files in a container, read through a capped copy (`copy_out.rs`).
fn copy_out(container: String, into: PathBuf) -> crate::platform::channels::CopyOut {
    Arc::new(move |inside: &std::path::Path| copy_out::copy(&container, inside, &into))
}

/// A container whose folder is not known: nothing is read, here or there.
fn copy_nothing() -> crate::platform::channels::CopyOut {
    Arc::new(|_: &std::path::Path| None)
}

#[cfg(test)]
mod tests;
