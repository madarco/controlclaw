//! W6: the vm-agent platform and OpenClaw (docs/plans/rust-workstreams/W6.md). Health, status and
//! lifecycle, the bootstrap, models, channels, secrets, search, kill, hooks, apply and templates,
//! skills, MCP servers, connectors, update and software, the watchdog and metrics.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use cc_http::Router;

use crate::app::App;

// The born stamp is read by the templates and skills (G5).
pub mod activity_now;
pub mod allow;
pub mod approvals;
pub mod audit;
mod bootstrap;
#[allow(dead_code)]
pub mod born;
pub mod channels;
pub mod common;
pub mod connectors;
pub mod console_mcp;
pub mod cpu;
// The host key is for `/doctor/status` (G7).
#[allow(dead_code)]
pub mod doctor;
pub mod gateway;
mod health;
pub mod health_summary;
pub mod hooks;
// `verify_detached` and `sha256_hex` are for W7's CA install (`mitm-ca.ts` imports them from keys.ts).
#[allow(dead_code)]
pub mod keys;
pub mod kill;
pub mod llm;
pub mod mcp_servers;
pub mod metrics;
mod openclaw;
pub mod patch_check;
/// Public for the brain's first boot (W8's `gbrain::boot`).
mod ready;
/// The brain's first boot reports ready the same way (W8, gbrain/boot.rs).
pub use ready::report_ready;
pub mod run_titles;
pub mod search;
pub mod secrets;
pub mod session_shipper;
pub mod settle;
pub mod skill_files;
pub mod skills;
pub mod software;
pub mod stall;
pub mod state;
pub mod stop_mark;
pub mod templates;
pub mod time;
pub mod transcripts;
pub mod update;
pub mod watchdog;

pub use health::service_status;
/// One start, stop or restart at a time (the unmanaged agent's too).
pub use openclaw::UNIT_ACTIONS;
/// `GET /status`, `POST /start`, `/stop`, `/restart` for the unit in `CC_SERVICE`: the brain box
/// serves them too (`gbrain.ts` uses the same handlers).
pub use openclaw::register as register_lifecycle;
/// `runAction`: `sudo -n systemctl <action> <service>` (W8's phone setup restarts with it).
#[allow(unused_imports)]
pub use openclaw::run_action;

/// What the template service does when the console pokes it (`templateService.poke()`, then a tick
/// when the gateway is connected).
pub type Poke = Arc<dyn Fn() + Send + Sync>;

/// State W6's parts share on one box.
#[derive(Default)]
pub struct Platform {
    /// `consoleMcpConfigured()`: ControlClaw's tools are in this agent's OpenClaw config.
    pub console_mcp: Arc<AtomicBool>,
    /// Set by the template service once it runs.
    pub templates_poke: OnceLock<Poke>,
    /// The services, built once the agent listens (`null` before, as in the TS).
    pub llm: OnceLock<Arc<llm::LlmService>>,
    pub search: OnceLock<Arc<search::SearchService>>,
    pub secrets: OnceLock<Arc<secrets::SecretsService>>,
    pub channels: OnceLock<Arc<channels::ChannelsService>>,
    pub connectors: OnceLock<Arc<connectors::ConnectorsService>>,
    pub mcp_servers: OnceLock<Arc<mcp_servers::McpServersService>>,
    pub skills: OnceLock<Arc<skills::SkillsService>>,
    /// The template service's put-back of a skill or a set of notes.
    pub restore: OnceLock<skills::Restore>,
    /// Built once the agent listens, not on a pool box (`templateService`).
    pub templates: OnceLock<Arc<templates::TemplateService>>,
    /// The health summary and model probe a Final check asks for.
    pub health_probe: OnceLock<templates::HealthProbe>,
    /// CPU use for the meters, one read of /proc/stat every 10 s from start-up.
    pub cpu: OnceLock<Arc<cpu::CpuSampler>>,
    /// The watchdog's last findings (G6b); empty until it runs.
    pub watchdog: OnceLock<health_summary::WatchFn>,
    /// The oldest unfinished tool call or run.
    pub stalled: OnceLock<health_summary::StalledFn>,
    /// Fed from OpenClaw's audit ledger by the audit shipper.
    pub stalls: Arc<std::sync::Mutex<stall::StallTracker>>,
    /// The runs going now, for Doing now; fed by the audit shipper.
    pub now_runs: Arc<std::sync::Mutex<activity_now::NowTracker>>,
    /// How many approvals wait for the owner, and their sessions (the approvals bridge, G6d).
    pub approvals_open: OnceLock<Arc<dyn Fn() -> usize + Send + Sync>>,
    pub approval_sessions: OnceLock<Arc<dyn Fn() -> std::collections::HashSet<String> + Send + Sync>>,
}

impl Platform {
    pub fn console_mcp(&self) -> bool {
        self.console_mcp.load(Ordering::Relaxed)
    }
}

/// A brain box (`CC_SERVICE=gbrain`) rather than an agent.
pub fn is_brain(app: &App) -> bool {
    app.config.service == "gbrain"
}

/// `boxSoftware()` for this box. `doctor` is the Doctor key's fingerprint when the caller has
/// already read it; otherwise it is read here.
pub fn box_software(app: &App, doctor: Option<Option<&str>>) -> serde_json::Value {
    let console_mcp = app.contracts.platform.get().is_some_and(|p| p.console_mcp());
    let read;
    let fingerprint = match doctor {
        Some(f) => f,
        None => {
            read = doctor::status(std::path::Path::new(doctor::DOCTOR_KEY_FILE));
            read.as_deref()
        }
    };
    software::box_software(app, console_mcp, fingerprint)
}

/// What the agent box starts once it listens (index.ts, the `listen` callback): the gateway
/// bridge, then the bootstrap. Not on a brain box.
pub fn start(app: &Arc<App>) {
    gateway::start(app);
    if let Some(p) = app.contracts.platform.get() {
        let deps = common::Deps::of(app);
        // CPU use for the agent page's meters: one read of /proc/stat every 10 s, from start-up.
        let cpu = Arc::new(cpu::CpuSampler::proc_stat());
        cpu.start();
        let _ = p.cpu.set(cpu);
        let weak = Arc::downgrade(app);
        let _ = p.health_probe.set(Arc::new(move |verb: &'static str| {
            let weak = weak.clone();
            Box::pin(async move {
                let Some(app) = weak.upgrade() else {
                    return serde_json::Value::Null;
                };
                if verb == "health" {
                    health_summary::health_summary(&app).await
                } else {
                    health_summary::model_probe(&common::Deps::of(&app)).await
                }
            })
        }));
        start_metrics(app);
        let (stalls, weak) = (p.stalls.clone(), Arc::downgrade(app));
        let _ = p.stalled.set(Arc::new(move |now, min_ms| {
            // A call that is waiting for the owner's approval is not stuck.
            let open = weak
                .upgrade()
                .and_then(|a| a.contracts.platform.get().and_then(|p| p.approvals_open.get().cloned()))
                .map_or(0, |f| f());
            let mut s = common::lock(&stalls);
            if open > 0 {
                s.waiting(now);
            }
            s.oldest(now, min_ms)
        }));
        start_audit(app);
        start_watchdog(app);
        start_sessions(app);
        let state = app.config.state_dir.clone();
        let ca = app.config.keys_dir.join("mitm-ca.crt");
        // The phone's reply model follows the primary (W8's phone-model.ts, `phoneModelEntry`).
        let _ = p.llm.set(Arc::new(llm::LlmService::new(
            deps.clone(),
            Some(state.join("memory-index.json")),
            Some(ca),
            Some(Arc::new(crate::phone::model::phone_model_entry)),
        )));
        // A fixed path in the TS, not `$HOME`'s.
        let env = std::path::PathBuf::from("/home/controlclaw/.openclaw/.env");
        let _ = p.secrets.set(Arc::new(secrets::SecretsService::new(env, deps.clone())));
        let keys = app.keys.clone();
        let channels = Arc::new(channels::ChannelsService::new(
            deps.clone(),
            app.config.home.join(".openclaw/credentials"),
            Some(state.join("channels.json")),
            Some(app.config.home.join(".openclaw/state/openclaw.sqlite")),
            Some(app.config.keys_dir.join("mitm-ca.crt")),
            Arc::new(move || keys.read("mitm_box_private_ip").filter(|v| !v.is_empty())),
        ));
        let _ = p.channels.set(channels.clone());
        // Slack and WhatsApp installs a restart interrupted, and boxes set up before installs.
        on_connected(app, move || channels.reconcile());
        let relay_port = env_port("CONNECTOR_RELAY_PORT", 3111);
        let connectors = Arc::new(connectors::ConnectorsService::new(
            deps.clone(),
            relay_port,
            state.join("connectors.json"),
            app.config.home.join(".config/oomol/connector.env"),
            busy(app),
        ));
        // Always up, even with no connections: OpenClaw's config points at it.
        connectors.start_relay();
        // A leftover `mcpServers` keeps OpenClaw from starting: fixed on disk, then restarted
        // unless its owner stopped it.
        let config_file = app.config.home.join(".openclaw/openclaw.json");
        if connectors::repair_config_file(&config_file, connectors.entry().as_ref(), &|l| tracing::info!("{l}")) {
            let a = app.clone();
            tokio::spawn(async move {
                let state = state::current(a.runner.as_ref(), &a.config.service, None).await;
                tracing::info!("[connectors] moved mcpServers to mcp.servers in openclaw.json (OpenClaw {state})");
                if state != "stopped" {
                    let _ = openclaw::run_action(a.runner.as_ref(), "restart", &a.config.service).await;
                }
            });
        }
        let _ = p.connectors.set(connectors.clone());
        on_connected(app, move || connectors.heal());
        let _ = p.mcp_servers.set(Arc::new(mcp_servers::McpServersService::new(
            deps.clone(),
            state.join("mcp-servers.json"),
        )));
        let keys = app.keys.clone();
        let console = Arc::new(console_mcp::ConsoleMcpService::new(
            deps.clone(),
            Arc::new(move || keys.read("mitm_box_private_ip")),
            console_mcp::mcp_answers(app.http.get()),
            p.console_mcp.clone(),
        ));
        let c = console.clone();
        on_connected(app, move || c.ensure());
        tokio::spawn(async move {
            let mut every = tokio::time::interval(console_mcp::ENSURE_EVERY);
            // The first tick is now, and the connect handler already ran then.
            every.tick().await;
            loop {
                every.tick().await;
                console.ensure().await;
            }
        });
        let search = Arc::new(search::SearchService::new(deps, busy(app)));
        let _ = p.search.set(search.clone());
        // Boxes provisioned before search.ts switched unused plugins off: once, when OpenClaw answers.
        on_connected(app, move || search.heal());
        templates::start(app);
    }
    let a = app.clone();
    tokio::spawn(async move {
        let b = a.clone();
        bootstrap::run(a, move || box_software(&b, None)).await;
    });
}

/// CPU, memory and disk history for the agent's Home tab (`metrics.ts`): one sample a minute,
/// shipped with the activity log. Not on a box still in the pool (no organization yet), and only
/// with somewhere to send it. Needs no gateway: the numbers matter most when OpenClaw is down.
fn start_metrics(app: &Arc<App>) {
    if app.config.pool_marker.exists() {
        return;
    }
    let Some(base) = gateway::saas_base_url(app) else {
        return;
    };
    let post = metrics::activity_post(base, app.keys.clone(), app.http.clone());
    let (a, b) = (Arc::downgrade(app), Arc::downgrade(app));
    let read = metrics::Readers {
        disk: Box::new(|| {
            Box::pin(async {
                tokio::task::spawn_blocking(|| health_summary::disk_of(&health_summary::disk_paths()))
                    .await
                    .ok()
                    .flatten()
            })
        }),
        mem_pct: Box::new(|| health_summary::total_mem().and_then(health_summary::memory_used_pct)),
        load1: Box::new(health_summary::load1),
        // OpenClaw's state and the chat channels ride along for the console's problems list.
        openclaw_state: Box::new(move || {
            let a = a.clone();
            Box::pin(async move {
                let app = a.upgrade()?;
                let connected = app.contracts.openclaw.get().map(|o| o.client.connected());
                Some(
                    state::current(app.runner.as_ref(), &app.config.service, connected)
                        .await
                        .to_string(),
                )
            })
        }),
        // Read only while the gateway answers; a down gateway is the state's to say.
        channels: Box::new(move || {
            let b = b.clone();
            Box::pin(async move {
                let channels = b.upgrade()?.contracts.platform.get()?.channels.get().cloned()?;
                channels.channel_states().await.ok().flatten()
            })
        }),
    };
    let sampler = Arc::new(metrics::MetricSampler::new(
        cpu::CpuSampler::proc_stat(),
        read,
        post,
        Some(app.config.state_dir.join("channels-seen.json")),
        metrics::METRIC_QUEUE_MAX,
    ));
    sampler.prime();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(metrics::METRIC_SAMPLE);
        every.tick().await;
        loop {
            every.tick().await;
            sampler.tick().await;
        }
    });
}

/// The audit shipper (`audit.rs`): every `AUDIT_POLL_MS` (5 s) while the gateway is connected, on
/// an agent that belongs to an organization and has somewhere to report to.
fn start_audit(app: &Arc<App>) {
    let Some(p) = app.contracts.platform.get() else { return };
    if app.config.pool_marker.exists() || app.contracts.openclaw.get().is_none() {
        return;
    }
    let Some(base) = gateway::saas_base_url(app) else {
        return;
    };
    let base_for_approvals = base.clone();
    let home = app.config.home.join(".openclaw");
    let (stalls, runs) = (p.stalls.clone(), p.now_runs.clone());
    let (s2, r2) = (stalls.clone(), runs.clone());
    let a = Arc::downgrade(app);
    let shipper = Arc::new(audit::AuditShipper::new(audit::AuditOptions {
        connected: Box::new(move || {
            a.upgrade()
                .and_then(|a| a.contracts.openclaw.get().map(|o| o.client.connected()))
                .unwrap_or(false)
        }),
        call: audit::ledger_call(common::Deps::of(app)),
        cursor_path: app.config.state_dir.join("audit.cursor"),
        post: audit::activity_post_json(base, app.keys.clone(), app.http.clone()),
        on_events: Box::new(move |events| {
            common::lock(&stalls).record(events);
            common::lock(&runs).record(events);
        }),
        enrich: Box::new(move |mut records, events| {
            let home = home.clone();
            Box::pin(async move {
                let original = records.clone();
                // A panic in a read leaves the batch as the ledger gave it (the TS's try/catch).
                tokio::task::spawn_blocking(move || {
                    enrich_runs(&home, &mut records, &events);
                    records
                })
                .await
                .unwrap_or(original)
            })
        }),
        log: Box::new(|l| tracing::info!("{l}")),
    }));
    // A gateway that went away took its unfinished calls with it and will never write their end.
    on_connected(app, move || {
        let now = time::now_ms();
        common::lock(&s2).reset(now);
        common::lock(&r2).reset(now);
        Box::pin(async {})
    });
    start_approvals(app, base_for_approvals);
    let every_ms = std::env::var("AUDIT_POLL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5000);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_millis(every_ms));
        every.tick().await;
        loop {
            every.tick().await;
            // Its own task: a panic in one tick does not stop the shipper.
            let s = shipper.clone();
            if tokio::spawn(async move { s.tick().await }).await.is_err() {
                tracing::error!("[audit] tick failed");
            }
        }
    });
}

/// The approvals bridge (`approvals.rs`): OpenClaw's approvals to the firewall's gate (or, on an
/// older firewall, the console) and back.
/// Events as they come, a reconcile on every connect, the console asked every `APPROVAL_POLL_MS`.
fn start_approvals(app: &Arc<App>, base: String) {
    let Some(p) = app.contracts.platform.get() else { return };
    let Some(o) = app.contracts.openclaw.get() else { return };
    let deps = common::Deps::of(app);
    // The box's own secrets masked in what leaves it (`redact.ts`).
    let redaction = Arc::new(crate::boxside::logs::Redaction::load(&app.config.keys_dir));
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|l| tracing::info!("{l}"));
    let console = approvals::permission_calls(base, app.keys.clone(), app.http.clone(), log.clone());
    // The firewall's gate first (it checks the Auto approve rules); an unsecured box has none.
    let keys = app.keys.clone();
    let firewall = Arc::new(move || {
        keys.read("mitm_box_private_ip")
            .map(|ip| ip.trim().to_string())
            .filter(|ip| common::PRIVATE_IP.is_match(ip))
    });
    let keys = app.keys.clone();
    let token: approvals::AgentToken = Arc::new(move || cc_auth::sign::box_token(&keys).ok());
    let gate = approvals::gate_calls(firewall, token, app.http.clone(), log);
    let bridge = Arc::new(approvals::ApprovalsBridge::new(approvals::ApprovalsOptions {
        call: Box::new(move |method, params| {
            let (deps, method) = (deps.clone(), method.to_string());
            Box::pin(async move { deps.call(&method, params, std::time::Duration::from_secs(10)).await })
        }),
        gate: Some(gate),
        console: Some(console),
        redact: Box::new(move |t| redaction.redact(t)),
        log: Box::new(|l| tracing::info!("{l}")),
        now: Box::new(time::now_ms),
    }));
    let b = bridge.clone();
    let _ = p.approvals_open.set(Arc::new(move || b.pending_count()));
    let b = bridge.clone();
    let _ = p.approval_sessions.set(Arc::new(move || b.pending_sessions()));
    let every_ms = std::env::var("APPROVAL_POLL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(3000);
    let _ = approvals::run_bridge(bridge, &o.client, std::time::Duration::from_millis(every_ms));
}

/// A run's trigger and title, which the ledger does not carry (index.ts `enrich`). A heartbeat runs
/// in the main session like a direct message; only OpenClaw's own record of the run says which.
pub fn enrich_runs(
    home: &std::path::Path,
    records: &mut [serde_json::Map<String, serde_json::Value>],
    events: &[serde_json::Value],
) {
    use serde_json::{Value, json};
    let text = |r: &serde_json::Map<String, Value>, k: &str| r.get(k).and_then(Value::as_str).map(str::to_string);
    // The ledger's own session key: the record's is hashed for AgentMail.
    let raw_key = |run: &str| {
        events.iter().find_map(|e| {
            (e.get("kind").and_then(Value::as_str) == Some("agent_run")
                && e.get("runId").and_then(Value::as_str) == Some(run))
            .then(|| {
                e.get("sessionKey")
                    .and_then(Value::as_str)
                    .filter(|k| !k.is_empty())
                    .map(str::to_string)
            })
            .flatten()
        })
    };
    let is_run = |r: &serde_json::Map<String, Value>| text(r, "source").as_deref() == Some("agent_run");
    let runs: Vec<transcripts::RunRef> = records
        .iter()
        .filter(|r| is_run(r))
        .filter_map(|r| {
            let run_id = text(r, "run_id")?;
            Some(transcripts::RunRef {
                session_key: raw_key(&run_id).or_else(|| text(r, "session_key")),
                agent_id: text(r, "agent_id"),
                run_id,
            })
        })
        .collect();
    if runs.is_empty() {
        return;
    }
    let triggers = transcripts::run_triggers(home, &runs);
    for r in records.iter_mut() {
        if let Some(t) = text(r, "run_id").and_then(|id| triggers.get(&id).cloned())
            && is_run(r)
        {
            r.insert("trigger".into(), json!(t));
        }
    }
    // The first line of what the run was asked; not for a heartbeat or a scheduled job.
    let asked: Vec<transcripts::RunRef> = runs
        .iter()
        .filter(|r| !matches!(triggers.get(&r.run_id).map(String::as_str), Some("heartbeat" | "cron")))
        .cloned()
        .collect();
    let (titles, heartbeats) = if asked.is_empty() {
        Default::default()
    } else {
        run_titles::run_titles(home, &asked)
    };
    for r in records.iter_mut() {
        let Some(id) = text(r, "run_id").filter(|_| is_run(r)) else {
            continue;
        };
        if let Some(t) = titles.get(&id) {
            r.insert("title".into(), json!(t));
        }
        // OpenClaw's heartbeat prompt says what the trigger lookup could not.
        if text(r, "trigger").is_none_or(|t| t.is_empty()) && heartbeats.contains(&id) {
            r.insert("trigger".into(), json!("heartbeat"));
        }
    }
    // A run's start is shipped before OpenClaw writes its prompt: the message somebody sent is its
    // title until then.
    for r in records.iter_mut() {
        let Some(id) = text(r, "run_id").filter(|_| is_run(r)) else {
            continue;
        };
        let trigger = text(r, "trigger");
        if r.contains_key("title")
            || text(r, "status").as_deref() != Some("started")
            || trigger.is_some_and(|t| !t.is_empty() && t != "user")
        {
            continue;
        }
        let occurred = r.get("occurred_at").and_then(Value::as_f64).unwrap_or(0.0);
        let run = transcripts::RunRef {
            session_key: raw_key(&id).or_else(|| text(r, "session_key")),
            agent_id: text(r, "agent_id"),
            run_id: id,
        };
        let asker = run_titles::run_asker(home, &run, occurred as i64);
        // Only a message sent just before the run: a heartbeat must not take the last one somebody sent.
        let fresh = asker
            .at
            .is_some_and(|at| occurred - at <= activity_now::FRESH_MESSAGE_MS as f64);
        if let Some(t) = asker.text.filter(|_| fresh).and_then(|t| run_titles::title_of(&t)) {
            r.insert("title".into(), json!(t));
        }
    }
}

/// When meetings and calls started and ended, for the console's timeline (`session_shipper.rs`):
/// once a minute, with the gateway bridge (an agent of an organization, with somewhere to report).
fn start_sessions(app: &Arc<App>) {
    if app.config.pool_marker.exists() || app.contracts.openclaw.get().is_none() {
        return;
    }
    let Some(base) = gateway::saas_base_url(app) else {
        return;
    };
    let dir = crate::meetings::archive_paths(app).0;
    let cache = Arc::new(std::sync::Mutex::new(session_shipper::MeetingFileCache::new()));
    let weak = Arc::downgrade(app);
    let shipper = Arc::new(session_shipper::SessionShipper::new(
        Box::new(move |now| {
            let (dir, cache, weak) = (dir.clone(), cache.clone(), weak.clone());
            Box::pin(async move {
                // Meetings from the archive's files and calls from W8's phone service (SQLite):
                // each read off the runtime's threads, on its own, so one that fails keeps the other.
                let lookback = session_shipper::SESSION_LOOKBACK_MS;
                let mut out = tokio::task::spawn_blocking(move || {
                    session_shipper::meeting_sessions(&dir, now, lookback, &mut common::lock(&cache))
                })
                .await
                .unwrap_or_default();
                if let Some(p) = weak.upgrade().and_then(|a| phone_slot(&a)) {
                    let calls = tokio::task::spawn_blocking(move || p.call_sessions(now, lookback))
                        .await
                        .unwrap_or_default();
                    out.extend(calls.into_iter().map(session_shipper::Session::from));
                }
                out
            })
        }),
        app.config.state_dir.join("sessions.sent.json"),
        metrics::activity_post(base, app.keys.clone(), app.http.clone()),
    ));
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(60));
        every.tick().await;
        loop {
            every.tick().await;
            let s = shipper.clone();
            if tokio::spawn(async move { s.tick().await }).await.is_err() {
                tracing::error!("[sessions] tick failed");
            }
        }
    });
}

/// The watchdog (`watchdog.rs`) with the real probes, every 30 s. Not on a box still in the pool.
/// The redirector restart needs the sudoers line the role adds with it; on an older role sudo
/// refuses, and the watchdog logs that once and does not ask again.
fn start_watchdog(app: &Arc<App>) {
    let Some(p) = app.contracts.platform.get() else { return };
    if app.config.pool_marker.exists() {
        return;
    }
    let host = health_summary::control_plane_host(app);
    let port = app.config.gateway_port;
    // One address for both probes of a tick; `outbound` always runs first.
    let ip: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
    let w = |app: &Arc<App>| Arc::downgrade(app);
    let mitm = {
        let a = w(app);
        move || {
            a.upgrade()?
                .keys
                .read("mitm_box_private_ip")
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        }
    };
    let (m1, m2) = (mitm.clone(), mitm);
    let (h1, h2) = (host.clone(), host);
    let (http1, http2) = (app.http.clone(), app.http.clone());
    let (ip1, ip2) = (ip.clone(), ip);
    let (a1, a2, a3, a4, a5, a6, a7, a8) = (w(app), w(app), w(app), w(app), w(app), w(app), w(app), w(app));
    let dog = Arc::new(watchdog::Watchdog::new(watchdog::WatchdogDeps {
        unit_active_for: Box::new(move || {
            let a = a1.clone();
            Box::pin(async move { health_summary::openclaw_active_for(&common::Deps::of(&a.upgrade()?)).await })
        }),
        gateway_answers: Box::new(move || {
            Box::pin(watchdog::gateway_healthz(port, std::time::Duration::from_secs(10)))
        }),
        before_restart: Box::new(move || {
            let a = a2.clone();
            Box::pin(async move {
                if let Some(m) = a.upgrade().and_then(|a| a.contracts.meeting.get()) {
                    let _ = m.stop().await;
                }
            })
        }),
        restart_openclaw: Box::new(move || {
            let a = a3.clone();
            Box::pin(async move {
                let Some(a) = a.upgrade() else { return false };
                openclaw::run_action(a.runner.as_ref(), "restart", &a.config.service)
                    .await
                    .is_ok()
            })
        }),
        unit_down_for: Box::new(move || {
            let a = a7.clone();
            Box::pin(async move {
                let a = a.upgrade()?;
                let pool = a.config.pool_marker.exists();
                health_summary::openclaw_down_for(&common::Deps::of(&a), pool).await
            })
        }),
        stopped_on_purpose: Box::new(|| stop_mark::STOP_MARK.stopped_on_purpose(time::now_ms())),
        forget_stop: Box::new(|active_for| stop_mark::STOP_MARK.forget(active_for, time::now_ms())),
        start_openclaw: Box::new(move || {
            let a = a8.clone();
            Box::pin(async move {
                let Some(a) = a.upgrade() else { return false };
                stop_mark::STOP_MARK
                    .start_unless_stopped(a.runner.as_ref(), &a.config.service)
                    .await
            })
        }),
        outbound: Box::new(move || {
            let (host, mitm, ip, trusted) = (h1.clone(), m1(), ip1.clone(), http1.extra_roots_pem());
            Box::pin(async move {
                let (Some(host), Some(_)) = (host, mitm) else {
                    return None;
                };
                let found = watchdog::resolve_host(&host, std::time::Duration::from_secs(5)).await;
                *common::lock(&ip) = found.clone();
                Some(watchdog::tls_reachable(&host, &found?, 443, &trusted, std::time::Duration::from_secs(8)).await)
            })
        }),
        proxy_direct: Box::new(move || {
            let (host, mitm, ip, trusted) = (h2.clone(), m2(), common::lock(&ip2).clone(), http2.extra_roots_pem());
            Box::pin(async move {
                let (Some(host), Some(mitm), Some(ip)) = (host, mitm, ip) else {
                    return false;
                };
                let port = std::env::var("MITM_PROXY_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080);
                watchdog::proxy_tunnel_reachable(&mitm, port, &host, &ip, &trusted, std::time::Duration::from_secs(8))
                    .await
            })
        }),
        restart_redirector: Box::new(move || {
            let a = a4.clone();
            Box::pin(async move {
                let Some(a) = a.upgrade() else { return "failed" };
                let cmd = cc_proc::Cmd::new("sudo")
                    .args(["-n", "systemctl", "restart", "controlclaw-redsocks"])
                    .timeout(std::time::Duration::from_secs(15));
                match a.runner.run(cmd).await {
                    Ok(o) if o.success() => "ok",
                    Ok(o) if o.stderr_str().lines().any(|l| l.starts_with("sudo: ")) => "refused",
                    _ => "failed",
                }
            })
        }),
        hold: Box::new(move || {
            let a = a5.clone();
            Box::pin(async move {
                let a = a.upgrade()?;
                if update::running(&update::state_path(&a)) {
                    return Some("update");
                }
                // The run itself, whoever started it: its state file reads as failed after 45 silent minutes.
                let reprovision = cc_proc::Cmd::new("systemctl")
                    .args(["is-active", "cc-reprovision"])
                    .timeout(std::time::Duration::from_secs(5));
                if a.runner
                    .run(reprovision)
                    .await
                    .is_ok_and(|o| o.success() && o.stdout_str().trim() == "active")
                {
                    return Some("update");
                }
                // A Doctor session is a login of the `ccdoctor` user from the firewall.
                let cmd = cc_proc::Cmd::new("pgrep")
                    .args(["-u", "ccdoctor"])
                    .timeout(std::time::Duration::from_secs(5));
                match a.runner.run(cmd).await {
                    Ok(o) if o.success() && !o.stdout_str().trim().is_empty() => Some("doctor"),
                    _ => None,
                }
            })
        }),
        in_call: in_call(app),
        report: Box::new(move |what, ok| {
            let (a, line) = (a6.clone(), format!("watchdog · {what}"));
            tokio::spawn(async move {
                let Some(a) = a.upgrade() else { return };
                if let Err(e) =
                    watchdog::report_own_action(&a, "watchdog", "watchdog.restart", &line, "controlclaw", ok).await
                {
                    tracing::error!("[watchdog] {e}");
                }
            });
        }),
        now: Box::new(watchdog::monotonic_ms),
        log: Box::new(|l| tracing::info!("{l}")),
    }));
    let d = dog.clone();
    let _ = p.watchdog.set(Arc::new(move || Some(d.status())));
    tokio::spawn(async move {
        let mut every = tokio::time::interval(watchdog::TICK);
        every.tick().await;
        loop {
            every.tick().await;
            dog.tick().await;
        }
    });
}

/// Whether a meeting or a call is on. `meeting` is the meeting slot's `busy()` (None: no meeting
/// service, read as none, as the TS reads one it did not build). `phone` is the relay's `busy()` and,
/// when asked for, whether the voice plugin has a call open; None is an empty phone slot, which
/// reads as a call (fail closed).
pub fn call_on(meeting: Option<bool>, phone: Option<(bool, Option<bool>)>) -> bool {
    meeting.unwrap_or(false)
        || match phone {
            None => true,
            Some((relay, plugin)) => relay || plugin.unwrap_or(false),
        }
}

static PHONE_SLOT_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn phone_slot(app: &App) -> Option<Arc<dyn crate::contracts::PhoneControl>> {
    let p = app.contracts.phone.get();
    if p.is_none() && !PHONE_SLOT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!("[platform] no phone service: every check reads a call as possible");
    }
    p
}

/// A meeting, a call on the phone relay or an Update in progress: a restart now would cut it off
/// (index.ts `busy` for connectors and search).
pub fn busy(app: &Arc<App>) -> Arc<dyn Fn() -> bool + Send + Sync> {
    let app = Arc::downgrade(app);
    Arc::new(move || {
        let Some(app) = app.upgrade() else { return true };
        let meeting = app.contracts.meeting.get().map(|m| m.busy());
        let phone = phone_slot(&app).map(|p| (p.relay_busy(), None));
        call_on(meeting, phone) || update::running(&update::state_path(&app))
    })
}

/// The watchdog's `inCall`: a meeting, a call on the relay, or a call the voice plugin still has
/// open. The plugin's records are SQLite, read off the runtime's threads.
pub fn in_call(app: &Arc<App>) -> Box<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync> {
    let app = Arc::downgrade(app);
    Box::new(move || {
        let app = app.clone();
        Box::pin(async move {
            let Some(app) = app.upgrade() else { return true };
            let meeting = app.contracts.meeting.get().map(|m| m.busy());
            let phone = match phone_slot(&app) {
                None => None,
                Some(p) if p.relay_busy() => Some((true, None)),
                Some(p) => {
                    let open = tokio::task::spawn_blocking(move || p.call_in_progress())
                        .await
                        .unwrap_or(true);
                    Some((false, Some(open)))
                }
            };
            call_on(meeting, phone)
        })
    })
}

/// Run `f` now if the gateway is connected, and after every handshake (`client.onConnected`).
/// A watch keeps only the latest value, but marks every send: a drop and a reconnect while `f`
/// runs still show as a change, so no handshake is missed.
pub fn on_connected(app: &Arc<App>, f: impl Fn() -> cc_http::BoxFuture<()> + Send + Sync + 'static) {
    let Some(o) = app.contracts.openclaw.get() else { return };
    let mut rx = o.client.connection_state();
    tokio::spawn(async move {
        if *rx.borrow_and_update() {
            f().await;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow_and_update() {
                f().await;
            }
        }
    });
}

/// `parseInt(process.env.X ?? default, 10)`.
pub(crate) fn env_port(name: &str, default: u16) -> u16 {
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
        .unwrap_or(default)
}

pub fn register(router: &mut Router, app: &Arc<App>) {
    let platform = Arc::new(Platform::default());
    // Built at start-up in the TS, not once the agent listens: the report needs no gateway.
    let _ = platform.skills.set(Arc::new(skills::SkillsService::new(
        common::Deps::of(app),
        app.config.home.clone(),
        skill_files::notes_place(),
    )));
    app.contracts.platform.set(platform);
    // W7's Download workspace and Files page read these (`transcripts`, `template_review`).
    app.contracts.transcripts.set(Arc::new(transcripts::BoxRecords {
        openclaw_home: app.config.home.join(".openclaw"),
    }));
    app.contracts
        .template_review
        .set(Arc::new(templates::ReviewSlot::of(&app.config.state_dir)));
    health::register(router, app);
    openclaw::register(router, app);
    openclaw::register_poke(router, app);
    llm::register(router, app);
    search::register(router, app);
    secrets::register(router, app);
    channels::register(router, app);
    connectors::register(router, app);
    mcp_servers::register(router, app);
    skills::register(router, app);
    templates::register(router, app);
    health_summary::register(router, app);
    activity_now::register(router, app);
    kill::register(router, app);
    doctor::register(router, app);
    update::register_on(router, app, crate::stages::PREFIXED);
    hooks::register(router, app);
}

#[cfg(test)]
mod call_tests {
    use super::call_on;

    #[test]
    fn an_empty_phone_slot_is_a_call_and_an_empty_meeting_slot_is_not() {
        assert!(call_on(None, None));
        assert!(!call_on(None, Some((false, None))));
        assert!(call_on(Some(true), Some((false, None))));
        assert!(call_on(None, Some((true, None))));
        assert!(call_on(None, Some((false, Some(true)))), "a call the plugin has open");
        assert!(!call_on(Some(false), Some((false, Some(false)))));
    }
}
