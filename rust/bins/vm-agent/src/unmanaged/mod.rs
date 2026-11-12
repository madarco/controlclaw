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

/// How often a raised approval is asked about.
const APPROVALS_POLL_EVERY: std::time::Duration = std::time::Duration::from_secs(3);

/// OpenClaw's approvals to the firewall's gate, which checks the Auto approve rules and passes an
/// Ask on to its panel. No control plane here: with a firewall that does not take them yet, nothing
/// is raised. OpenClaw keeps an approval waiting only while a client that answers approvals is
/// connected (`caps: approvals`); with none it has no route and expires it at once. So the agent
/// keeps the gateway's WebSocket open, as a managed box does (the CLI cannot hold one).
///
/// Every minute it reads again where the firewall is (`agent.json`, which pairing rewrites), the
/// gateway's token, port and container; when any of them changed, or the bridge could not start, it
/// stops the old one and starts it again.
fn start_approvals(app: &Arc<App>, um: &Arc<Unmanaged>) {
    let app = app.clone();
    let um = Arc::downgrade(um);
    tokio::spawn(async move {
        let mut running: Option<(Setup, Running)> = None;
        let mut said = String::new();
        loop {
            let Some(u) = um.upgrade() else { break };
            let setup = Setup::now(&u).await;
            drop(u);
            match setup {
                Ok(s) if running.as_ref().is_some_and(|(r, _)| *r == s) => {}
                Ok(s) => {
                    if let Some((_, r)) = running.take() {
                        r.stop();
                        tracing::info!("[approvals] the firewall or OpenClaw changed: starting again");
                    }
                    match Running::start(&app, &s) {
                        Ok(r) => {
                            tracing::info!(
                                "[approvals] OpenClaw's approvals go to the firewall at {}:3940",
                                s.firewall
                            );
                            said.clear();
                            running = Some((s, r));
                        }
                        Err(why) if why != said => {
                            tracing::warn!("[approvals] {why}: trying again in a minute");
                            said = why;
                        }
                        Err(_) => {}
                    }
                }
                Err(why) => {
                    if let Some((_, r)) = running.take() {
                        r.stop();
                    }
                    if why != said {
                        tracing::info!("[approvals] {why}: OpenClaw's approvals stay in OpenClaw");
                        said = why;
                    }
                }
            }
            tokio::time::sleep(LOOK_AGAIN).await;
        }
        if let Some((_, r)) = running {
            r.stop();
        }
    });
}

/// Where the approvals bridge goes, as read now.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Setup {
    firewall: std::net::IpAddr,
    /// This agent's id at the firewall (`agent_id`): what its settles are signed for.
    agent_id: Option<String>,
    token: String,
    port: u16,
    /// OpenClaw's container and the gateway's port in it, when it runs in one.
    container: Option<(String, u16)>,
}

impl Setup {
    async fn now(u: &Unmanaged) -> Result<Self, String> {
        // `agent.json` as it is now: pairing rewrites it.
        let file = config::load(&u.path).ok().flatten().unwrap_or_else(|| u.file.clone());
        // The firewall's address this agent takes calls from: in a container set up by `up --all`
        // OpenClaw is on the firewall's agents network and this agent is not, so the gate there would
        // not know it. The firewall serves `/permission` on that address too. Else the gate.
        let firewall = file
            .allow_from()
            .first()
            .copied()
            .or(file.firewall.gate.map(std::net::IpAddr::V4))
            .ok_or_else(|| format!("no firewall address in {}", u.path.display()))?;
        // The gate's answers are taken as they come (plain HTTP): only over a private network.
        if !private_address(firewall) {
            return Err(format!(
                "the firewall's address {firewall} is not a private one, and approvals are not sent over the internet in clear"
            ));
        }
        let install = u.install();
        let config_file = install
            .config_file
            .clone()
            .ok_or_else(|| "OpenClaw's config file is not found yet".to_string())?;
        let token = gateway_token(&config_file, &install.runs)
            .await
            .ok_or_else(|| "no OpenClaw gateway token found".to_string())?;
        let container = match &install.runs {
            discover::Runs::Docker { container } => Some((
                container.clone(),
                gateway_port_in_config(&config_file).unwrap_or(install.gateway_port),
            )),
            _ => None,
        };
        Ok(Self {
            firewall,
            agent_id: file.agent_id.clone().filter(|v| !v.is_empty()),
            token,
            port: install.gateway_port,
            container,
        })
    }
}

/// A box token for `agent_id`, signed with this agent's own key; None when it cannot be made.
fn agent_token(keys: &cc_auth::keys::KeysDir, agent_id: &str) -> Option<String> {
    let pem = keys.read("vm_private_key.pem")?;
    let key = cc_auth::jwt::SignKey::ed25519_pkcs8_pem(&pem).ok()?;
    let mut claims = serde_json::Map::new();
    claims.insert("vmId".into(), serde_json::Value::String(agent_id.to_string()));
    cc_auth::jwt::sign(claims, &key, Some(30), None).ok()
}

/// A private network: RFC 1918, shared (100.64.0.0/10), loopback, link-local, and IPv6's unique local
/// and link-local addresses. A WireGuard tunnel's addresses are in one of these.
fn private_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private() || a.is_loopback() || a.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(a) => {
            let s = a.segments()[0];
            a.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

/// A started bridge: its gateway client and its tasks.
struct Running {
    client: cc_openclaw::GatewayClient,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    fn start(app: &Arc<App>, s: &Setup) -> Result<Self, String> {
        use crate::platform::approvals;
        let mut tasks = Vec::new();
        // The gateway answers approvals only to a client on its own loopback (a token client from
        // elsewhere loses its scopes without a paired device): in a container, through `docker exec`.
        let port = match &s.container {
            Some((container, inner)) => {
                let (port, relay) = container_loopback(container.clone(), *inner)
                    .ok_or_else(|| "no loopback relay to OpenClaw's container".to_string())?;
                tasks.push(relay);
                port
            }
            None => s.port,
        };
        let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|l| tracing::info!("{l}"));
        let ip = s.firewall;
        // Its settles carry its own token, which the firewall's control plane checks against the key
        // it paired with: `{vmId: agent_id}` signed with `vm_private_key.pem`.
        let (keys, agent_id) = (app.keys.clone(), s.agent_id.clone());
        let token: approvals::AgentToken = Arc::new(move || agent_token(&keys, agent_id.as_deref()?));
        let gate = approvals::gate_calls(Arc::new(move || Some(ip.to_string())), token, app.http.clone(), log);
        let redaction = Arc::new(crate::boxside::logs::Redaction::load(&app.config.keys_dir));
        let ws = cc_openclaw::GatewayClient::new(cc_openclaw::GatewayOptions::local(port, s.token.clone()));
        ws.start();
        let w = ws.clone();
        let bridge = Arc::new(approvals::ApprovalsBridge::new(approvals::ApprovalsOptions {
            call: Box::new(move |method, params| {
                let (w, method) = (w.clone(), method.to_string());
                Box::pin(async move {
                    w.call(&method, params, std::time::Duration::from_secs(10))
                        .await
                        .map_err(|e| e.to_string())
                })
            }),
            gate: Some(gate),
            console: None,
            redact: Box::new(move |t| redaction.redact(t)),
            log: Box::new(|l| tracing::info!("{l}")),
            now: Box::new(crate::platform::time::now_ms),
        }));
        tasks.extend(approvals::run_bridge(bridge, &ws, APPROVALS_POLL_EVERY));
        Ok(Self { client: ws, tasks })
    }

    fn stop(self) {
        self.client.stop();
        for t in self.tasks {
            t.abort();
        }
    }
}

/// `gateway.port` in OpenClaw's config file: the port inside its container.
fn gateway_port_in_config(config_file: &str) -> Option<u16> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(config_file).ok()?).ok()?;
    v.pointer("/gateway/port")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
}

/// What runs in the container for one connection: its stdin and stdout joined to the gateway's port
/// on the container's own loopback.
const LOOPBACK_RELAY: &str = "const s=require('net').connect(Number(process.argv[1]),'127.0.0.1');process.stdin.pipe(s);s.pipe(process.stdout);s.on('close',()=>process.exit(0));s.on('error',()=>process.exit(1));process.stdin.on('end',()=>s.end())";

/// A port on this machine's loopback where each connection reaches `port` on the container's own
/// loopback, through `docker exec -i <container> node`. None when it cannot listen.
fn container_loopback(container: String, port: u16) -> Option<(u16, tokio::task::JoinHandle<()>)> {
    let bound = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.set_nonblocking(true).map(|()| l))
        .and_then(tokio::net::TcpListener::from_std);
    let l = match bound {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("[approvals] no loopback relay to the gateway: {e}");
            return None;
        }
    };
    let local = l.local_addr().ok()?.port();
    let task = tokio::spawn(async move {
        loop {
            let (mut conn, peer) = match l.accept().await {
                Ok(c) => c,
                Err(_) => {
                    // Out of descriptors, say: not a busy loop.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
            };
            // Only this agent's own client: another user on this machine gets nothing through here
            // (the gateway would treat it as local).
            if !same_owner(owner_of_loopback_port(peer.port()), own_uid()) {
                continue;
            }
            let container = container.clone();
            tokio::spawn(async move {
                let child = tokio::process::Command::new("docker")
                    .args([
                        "exec",
                        "-i",
                        &container,
                        "node",
                        "-e",
                        LOOPBACK_RELAY,
                        &port.to_string(),
                    ])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn();
                let Ok(mut child) = child else { return };
                let (Some(mut stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
                    return;
                };
                let (mut r, mut w) = conn.split();
                let up = tokio::io::copy(&mut r, &mut stdin);
                let down = tokio::io::copy(&mut stdout, &mut w);
                let _ = tokio::select! { a = up => a, b = down => b };
                let _ = child.kill().await;
            });
        }
    });
    Some((local, task))
}

/// Both known and equal: an owner that cannot be read is nobody's.
fn same_owner(peer: Option<u32>, own: Option<u32>) -> bool {
    matches!((peer, own), (Some(a), Some(b)) if a == b)
}

/// The user that owns the TCP socket bound to `127.0.0.1:port` (`/proc/net/tcp`).
fn owner_of_loopback_port(port: u16) -> Option<u32> {
    let text = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let want = format!("0100007F:{port:04X}");
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.get(1) == Some(&want.as_str()))
            .then(|| f.get(7).and_then(|u| u.parse().ok()))
            .flatten()
    })
}

fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// `gateway.auth.token` in OpenClaw's config file, as the host reads it: the token itself, or where
/// it is (`{source: "env", id}`, what `openclaw onboard` writes for a container): this agent's own
/// environment, else the container's.
async fn gateway_token(config_file: &str, runs: &discover::Runs) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(config_file).ok()?).ok()?;
    let t = v.pointer("/gateway/auth/token")?;
    if let Some(s) = t.as_str() {
        return (!s.is_empty()).then(|| s.to_string());
    }
    if t.get("source").and_then(serde_json::Value::as_str) != Some("env") {
        return None;
    }
    let id = t
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|i| !i.is_empty())?;
    if let Ok(own) = std::env::var(id)
        && !own.is_empty()
    {
        return Some(own);
    }
    let discover::Runs::Docker { container } = runs else {
        return None;
    };
    let out = std::process::Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{range .Config.Env}}{{println .}}{{end}}",
            container,
        ])
        .output()
        .ok()?;
    let env = String::from_utf8_lossy(&out.stdout).into_owned();
    env.lines()
        .find_map(|l| l.strip_prefix(id).and_then(|r| r.strip_prefix('=')))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
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
    let _ = um.gateway.set(gw.clone());
    start_approvals(app, &um);
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
