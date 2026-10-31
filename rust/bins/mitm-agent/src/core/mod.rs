//! W3: the firewall core (docs/plans/rust-workstreams/W3.md): stores and sync to the proxy, the
//! heartbeat and its command registry, consent codes, CA publish, activity, permissions,
//! identities, Open and enroll, webhooks, kill, health, SSH, Tailscale, devices, exit, search,
//! backups and recovery, updates.
//!
//! `register` builds the core's modules (their stores load there, as the TS constructors load
//! theirs); [`start`] runs the first sync before the listeners open, as `main` does, then the
//! timers.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use cc_http::json;

use crate::app::{App, Registry};
use crate::stages;

pub mod activity;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod access;
pub mod access_store;
pub mod activity_sanitize;
pub mod apply;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod agent_client;
pub mod auto_update;
pub mod backup;
pub mod backup_manifest;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod beat;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod code_message;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod consent;
pub mod control;
pub mod cp_inspect;
pub mod devices;
pub mod disk_reseal;
pub mod env;
pub mod exit;
pub mod exit_check;
pub mod firewall_update;
pub mod fw_logs;
pub mod gbrain;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod fw_shell;
pub mod grants;
pub mod health;
pub mod identities;
#[allow(dead_code)] // the phone callbacks (W4) fill the rest
pub mod ingress;
pub mod keys;
pub mod kill;
pub mod kit;
pub mod local_admin;
pub mod local_cp;
pub mod local_intent;
pub mod local_open;
pub mod local_pair;
pub mod log_tail;
pub mod node_relay;
pub mod oidc;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod own_messages;
pub mod pages;
pub mod permissions;
// Also used by later groups (C3-C6), W4 and W5.
#[allow(dead_code)]
pub mod provenance;
pub mod ready;
pub mod recovery_notices;
pub mod recovery_routes;
pub mod recovery_tls;
pub mod requested_via;
pub mod search;
pub mod self_backup;
pub mod self_restore;
pub mod self_update;
pub mod slots;
pub mod software;
pub mod ssh;
pub mod startup;
pub mod store_client;
mod store_roundtrip;
pub mod sync;
pub mod tailscale;
pub mod update;
pub mod update_all;
#[allow(dead_code)] // W4's phone callbacks sign and check URL forms with it
pub mod url_form;
pub mod webhooks;

use activity::{ActivityShipper, OnShipped};
use env::CoreEnv;
use grants::GrantStore;
use identities::Agents;
use permissions::PermissionBridge;
use store_client::StoreClient;
use sync::Syncer;

/// Epoch milliseconds (`Date.now()`).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `RecoveryRoutes.owns`.
pub fn recovery_owns(path: &str) -> bool {
    path == "/recovery" || path.starts_with("/recovery/")
}

/// What the core's parts share. Other workstreams reach the pieces they need through
/// [`core()`] once `register` ran (the identity map also through `contracts::IdentityMap`).
pub struct Core {
    pub app: Arc<App>,
    pub env: CoreEnv,
    /// `usesHttp`: outbound calls to the control plane carry a box token (`getToken` is set).
    pub uses_http: bool,
    pub agents: Arc<Agents>,
    pub sync: Syncer,
    /// The one `grants.json` writer: people's approvals (the bridge) and the AI's (the judge).
    pub grants: Arc<GrantStore>,
    /// Set once the bridge runs (`revokeEmailGrants`).
    pub bridge: OnceLock<Arc<PermissionBridge>>,
    /// Called with each traffic batch the console took (`onShipped`: the exit's bytes, W4's
    /// included credit). Added in `register`, read when the shipper starts.
    pub traffic_watchers: Mutex<Vec<OnShipped>>,
    /// The Doctor SSH key and its signature, published with the CA (W5's `doctorKeys`).
    pub ca_extra: OnceLock<Arc<CaExtra>>,
    /// Calls to agents, by this firewall's own record of where they are.
    #[allow(dead_code)] // the commands of C3-C6
    pub agent: agent_client::AgentClient,
    /// The confirmation codes every module sends (also `contracts.consent`).
    pub consent: Arc<consent::Consent>,
    pub health: Arc<health::HealthFirewall>,
    /// Features and inventory sections for the beat.
    pub beat: beat::Beat,
    /// What `/ready` reports beside the software: the rescue session (C4), the Doctor key (W5).
    pub ready_ssh: OnceLock<ready::ReadSsh>,
    pub ready_doctor: OnceLock<ready::ReadDoctor>,
    /// The webhook registrations, on a box with a control channel (`webhooks`).
    pub webhooks: OnceLock<Arc<webhooks::Webhooks>>,
    /// More registrations the ingress serves (W4's phone callbacks), read per delivery.
    pub extra_registrations: Mutex<Vec<ingress::Registrations>>,
    /// The content rules on a verified webhook body (W4). Until it is set on a box whose content
    /// rules should run, deliveries wait (503), as the TS does while the module is not up.
    pub ingress_screen: OnceLock<ingress::Screen>,
    /// A Gmail push is read on the firewall, never replayed to the box (W4's `GmailPush.onPush`).
    pub gmail_push: OnceLock<Arc<dyn Fn(agent_client::AgentTarget, String) + Send + Sync>>,
    /// The emergency stop (`kill`), when its module started.
    pub kill: OnceLock<Arc<kill::Kill>>,
    pub tailscale: OnceLock<Arc<tailscale::Tailscale>>,
    pub exit: OnceLock<Arc<exit::Exit>>,
    pub brain: OnceLock<Arc<gbrain::Brain>>,
    pub backup: OnceLock<Arc<backup::Backup>>,
    pub disk_reseal: OnceLock<disk_reseal::DiskReseal>,
    pub recovery_notices: OnceLock<recovery_notices::RecoveryNotices>,
    /// This box's own update (W5's Firewall Doctor reruns it).
    pub firewall_update: OnceLock<Arc<firewall_update::FirewallUpdate>>,
    /// `applies`: W5 reads its MCP grants.
    pub apply: OnceLock<Arc<apply::Apply>>,
    /// What a recovery restore must find empty (`eligibility`): W4's channels and models, as how
    /// many agents they are bound to. `None` (or unset) is "cannot read the channel list": refused.
    pub restore_bound: OnceLock<Arc<dyn Fn() -> Option<usize> + Send + Sync>>,
    /// And W5's connectors. Unset, or `None` (a store that could not be read), is "cannot read the
    /// connectors": refused. A box with no connector runtime counts none, as the TS does.
    pub connectors_bound: OnceLock<Arc<dyn Fn() -> Option<usize> + Send + Sync>>,
}

/// The Doctor SSH public key and its signature, when Doctor runs.
pub type CaExtra = dyn Fn() -> Option<(String, String)> + Send + Sync;

static CORE: Mutex<Option<Arc<Core>>> = Mutex::new(None);

/// The core of the firewall this process runs, once `register` ran.
pub fn core() -> Option<Arc<Core>> {
    CORE.lock().ok()?.clone()
}

impl Core {
    pub fn new(app: &Arc<App>) -> Arc<Self> {
        let env = CoreEnv::from_env(&app.config.proxy_config_dir);
        let uses_http = env.uses_http(&app.config.firewall_url);
        let agents = Arc::new(Agents::default());
        agents.set_direct(app.config.mode.standalone());
        let client = StoreClient {
            http: app.http.clone(),
            keys: app.keys.clone(),
            token: uses_http,
        };
        let learn: Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync> = {
            let (client, url, agents) = (client.clone(), env.identities_url.clone(), agents.clone());
            Arc::new(move || {
                let (client, url, agents) = (client.clone(), url.clone(), agents.clone());
                Box::pin(async move {
                    if !url.is_empty() {
                        agents.learn(client.fetch_list(&url, "identities")).await;
                    }
                })
            })
        };
        let agent = agent_client::AgentClient::new(app.keys.clone(), &app.config.box_id, agents.clone(), Some(learn))
            .expect("an HTTP client for the agents");
        let buttons: Arc<dyn Fn() -> Option<Arc<dyn crate::contracts::CodeButtons>> + Send + Sync> = {
            let app = app.clone();
            Arc::new(move || app.contracts.buttons.get())
        };
        Arc::new(Self {
            consent: consent::Consent::new(agent.clone(), buttons),
            health: Arc::new(health::HealthFirewall::new(agent.clone(), agents.clone())),
            agent,
            beat: beat::Beat::default(),
            ready_ssh: OnceLock::new(),
            ready_doctor: OnceLock::new(),
            webhooks: OnceLock::new(),
            extra_registrations: Mutex::new(Vec::new()),
            ingress_screen: OnceLock::new(),
            gmail_push: OnceLock::new(),
            kill: OnceLock::new(),
            brain: OnceLock::new(),
            backup: OnceLock::new(),
            disk_reseal: OnceLock::new(),
            recovery_notices: OnceLock::new(),
            firewall_update: OnceLock::new(),
            apply: OnceLock::new(),
            restore_bound: OnceLock::new(),
            connectors_bound: OnceLock::new(),
            tailscale: OnceLock::new(),
            exit: OnceLock::new(),
            sync: Syncer::new(app.clone(), env.clone(), client, agents.clone()),
            grants: Arc::new(GrantStore::new(env.grants_path.clone())),
            app: app.clone(),
            env,
            uses_http,
            agents,
            bridge: OnceLock::new(),
            traffic_watchers: Mutex::new(Vec::new()),
            ca_extra: OnceLock::new(),
        })
    }
}

impl Core {
    /// `learnAgents`: one look at the identity map for an agent this firewall does not know yet
    /// (the agent client does this itself; W4's agent client calls this).
    pub async fn learn_agents(&self) {
        if self.env.identities_url.is_empty() {
            return;
        }
        self.agents
            .learn(self.sync.client.fetch_list(&self.env.identities_url, "identities"))
            .await;
    }
}

pub fn register(reg: &mut Registry, app: &Arc<App>) {
    let core = Core::new(app);
    // A recovery route reached without TLS is refused rather than answered in the clear.
    reg.plain.route(stages::PLAIN_TLS_ONLY, |_, p| recovery_owns(p), |_, _| async {
        json(426, &serde_json::json!({"error": "The recovery routes are HTTPS only. Use https:// and pin this box's certificate."}))
    });
    app.contracts
        .identities
        .set(Arc::new(identities::IdentityView(core.agents.clone())));
    app.contracts
        .consent
        .set(Arc::new(consent::ConsentView(core.consent.clone())));
    app.contracts
        .code_service
        .set(Arc::new(consent::ConsentView(core.consent.clone())));
    app.contracts.agents.set(Arc::new(slots::Agents(core.agent.clone())));
    app.contracts.grants.set(Arc::new(slots::Grants(core.grants.clone())));
    app.contracts
        .credentials_sync
        .set(Arc::new(slots::CredentialsSync(core.clone())));
    app.contracts
        .firewall_secrets
        .set(Arc::new(slots::Secrets(core.clone())));
    app.contracts.fw_shell.set(Arc::new(slots::Shell));
    own_messages::set_own_marker(app.config.proxy_config_dir.join("content-own.json"));
    pages::register(reg, &core);

    register_webhooks(reg, app, &core);
    register_controls(reg, app, &core);

    let health = core.health.clone();
    reg.commands.handle("health.probe", move |p| {
        let health = health.clone();
        async move { health.probe_command(p).await }
    });
    // Every token this firewall signs for an agent is for one request (agent-client.ts).
    core.beat.feature("bound_tokens", || true);
    let c = core.clone();
    reg.commands.status(
        &[
            "features",
            "inventory",
            "stores",
            "agents_reach",
            "agents_moved",
            "software",
        ],
        move || {
            let mut m = serde_json::Map::new();
            let features = c.beat.features();
            if !features.is_empty() {
                m.insert("features".into(), serde_json::json!(features));
            }
            if let Some(inv) = c.beat.inventory() {
                m.insert("inventory".into(), inv);
            }
            m.insert("stores".into(), beat::stores());
            let reach = c.health.summary();
            if !reach.is_empty() {
                m.insert("agents_reach".into(), serde_json::Value::Array(reach));
            }
            let moved = c.agents.moved();
            if !moved.is_empty() {
                m.insert("agents_moved".into(), serde_json::Value::Array(moved));
            }
            m.insert("software".into(), software::box_software());
            m
        },
    );
    if let Ok(mut c) = CORE.lock() {
        *c = Some(core);
    }
}

impl Core {
    /// `brain.syncLock()`, started and not awaited.
    pub fn sync_brain_lock(&self) {
        if let Some(b) = self.brain.get().cloned() {
            tokio::spawn(async move {
                if let Err(e) = b.sync_lock().await {
                    tracing::error!("[gbrain] lock: {e}");
                }
            });
        }
    }

    /// The consent instance and the channels' routes, for a module that sends codes.
    pub fn kit(&self, module: &'static str) -> kit::Kit {
        let app = self.app.clone();
        kit::Kit {
            consent: crate::contracts::CodeService::module(&consent::ConsentView(self.consent.clone()), module),
            routes: Arc::new(move || app.contracts.code_route_source.get()),
        }
    }

    fn store_path(var: &str, default: &str) -> std::path::PathBuf {
        std::env::var(var)
            .unwrap_or_else(|_| format!("/opt/controlclaw/state/{default}"))
            .into()
    }
}

/// Register one command whose handler is `f(module, payload)`.
fn handle<M, F, Fut>(reg: &mut Registry, action: &str, m: &Arc<M>, f: F)
where
    M: Send + Sync + 'static,
    F: Fn(Arc<M>, serde_json::Map<String, serde_json::Value>) -> Fut + Send + Sync + Copy + 'static,
    Fut: std::future::Future<Output = crate::commands::CommandOutcome> + Send + 'static,
{
    let m = m.clone();
    reg.commands.handle(action, move |p| f(m.clone(), p));
}

/// A proxy resync for a module whose change the proxy reads from the config: a full sync, or this
/// box's own settings written into the last config when the control plane cannot be reached. A
/// failure of both fails the command (`runSync` throwing).
fn resync(core: &Arc<Core>) -> Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync> {
    let c = core.clone();
    Arc::new(move || {
        let c = c.clone();
        Box::pin(async move { c.sync.publish_local().await })
    })
}

/// The emergency stop, Tailscale and the other controls that only exist with a control channel
/// (`if (FIREWALL_URL && getToken)` in `main`). A standalone firewall's control plane is its own
/// (`local_cp`): the stop, web search and the exit proxy (the user's own) run there, the rest is
/// the SaaS's (plan §8).
fn register_controls(reg: &mut Registry, app: &Arc<App>, core: &Arc<Core>) {
    let standalone = !app.config.mode.saas();
    if !standalone && (app.config.firewall_url.is_empty() || !core.uses_http) {
        return;
    }
    let (cfg, key) = (&app.config, &app.box_key);
    // The `locked` flag rides the identity map, so a stop is a config rewrite (`publishKillSwitch`).
    let c = core.clone();
    let on_locked: kill::OnLockedChanged = Arc::new(move || {
        let c = c.clone();
        Box::pin(async move {
            // A failure fails the command, as `publishKillSwitch` throwing does.
            c.sync.publish_kill_switch().await?;
            // And the brain's gate, which the proxy does not see. Started, not awaited: a brain
            // that is down must not hold up the stop; the kill tick retries it every minute.
            c.sync_brain_lock();
            Ok(())
        })
    });
    let k = Arc::new(kill::Kill::new(
        Core::store_path("KILL_STORE_PATH", "kill.enc"),
        key,
        &cfg.org_id,
        &cfg.box_id,
        core.agent.clone(),
        core.kit("kill"),
        on_locked,
    ));
    let s = k.summary();
    tracing::info!(
        "[mitm-agent] kill store loaded ({})",
        if !s["org"].is_null() {
            "the whole organisation is stopped".to_string()
        } else {
            format!("{} agent(s) stopped", s["agents"].as_array().map(Vec::len).unwrap_or(0))
        }
    );
    let _ = core.sync.hooks.kill.set(k.clone());
    let _ = core.kill.set(k.clone());
    app.contracts.emergency_stop.set(Arc::new(slots::Stop(k.clone())));
    handle(reg, "kill.engage", &k, |k, p| async move { k.engage(p).await });
    handle(reg, "kill.release", &k, |k, p| async move { k.release(p).await });
    handle(reg, "kill.confirm", &k, |k, p| async move { k.confirm(p).await });
    handle(reg, "kill.cancel", &k, |k, p| async move { k.cancel(p).await });
    core.beat.feature("kill_switch", || true);

    if !standalone {
        let on_ts: tailscale::OnChanged = resync(core);
        let t = Arc::new(tailscale::Tailscale::new(
            Core::store_path("TAILSCALE_STORE_PATH", "tailscale.enc"),
            key,
            &cfg.org_id,
            &cfg.box_id,
            core.agent.clone(),
            core.kit("tailscale"),
            on_ts,
        ));
        tracing::info!(
            "[mitm-agent] tailscale store loaded ({} agent(s) on the tailnet)",
            t.summary().len()
        );
        let x = t.clone();
        let _ = core.sync.hooks.tailscale.set(Arc::new(move || x.enabled_vm_ids()));
        let _ = core.tailscale.set(t.clone());
        handle(reg, "tailscale.propose", &t, |t, p| async move { t.propose(p).await });
        handle(reg, "tailscale.confirm", &t, |t, p| async move { t.confirm(p).await });
        handle(reg, "tailscale.cancel", &t, |t, p| async move { t.cancel(p) });
        core.beat.feature("tailscale", || true);

        // Nothing to load and nothing to fail: never quietly unavailable.
        let d = Arc::new(devices::Devices::new(core.agent.clone(), core.kit("devices")));
        handle(reg, "devices.propose", &d, |d, p| async move { d.propose(p).await });
        handle(reg, "devices.confirm", &d, |d, p| async move { d.confirm(p).await });
        handle(reg, "devices.cancel", &d, |d, p| async move { d.cancel(p) });
        core.beat.feature("devices", || true);

        // Support access: on an agent box a call to that box, on this one a local open.
        let local = Arc::new(ssh::SshLocal::new(
            Core::store_path("SSH_STATE_PATH", "ssh.json"),
            app.runner.clone(),
        ));
        let l = local.clone();
        let _ = core.ready_ssh.set(Arc::new(move || Some(l.status())));
        let sh = Arc::new(ssh::Ssh::new(
            core.agent.clone(),
            local,
            core.kit("ssh"),
            core.agents.clone(),
        ));
        handle(reg, "ssh.propose", &sh, |s, p| async move { s.propose(p).await });
        handle(reg, "ssh.confirm", &sh, |s, p| async move { s.confirm(p).await });
        handle(reg, "ssh.cancel", &sh, |s, p| async move { s.cancel(p) });
        handle(reg, "ssh.close", &sh, |s, p| async move { s.close(p).await });
    }

    // The proxy reads the exit from a file this writes, so the config lands before the result.
    let on_exit: exit::OnChanged = resync(core);
    let e = Arc::new(exit::Exit::new(
        Core::store_path("EXIT_STORE_PATH", "exit.enc"),
        key,
        &cfg.org_id,
        &cfg.box_id,
        core.kit("exit"),
        on_exit,
    ));
    let es = e.status();
    tracing::info!(
        "[mitm-agent] exit store loaded (residential exit {})",
        if es["configured"] == true {
            format!(
                "via {}, sticky {}",
                es["provider"].as_str().unwrap_or("?"),
                if es["sticky"] == true { "on" } else { "off" }
            )
        } else {
            "not set up".to_string()
        }
    );
    let x = e.clone();
    let _ = core.sync.hooks.exit_config.set(Arc::new(move || x.exit_config()));
    let x = e.clone();
    if let Ok(mut w) = core.traffic_watchers.lock() {
        w.push(Arc::new(move |records: &[serde_json::Value]| x.note_traffic(records)));
    }
    let x = e.clone();
    reg.commands.reports(move || x.drain_reports());
    let _ = core.exit.set(e.clone());
    handle(reg, "exit.propose", &e, |e, p| async move { e.propose(p).await });
    handle(reg, "exit.confirm", &e, |e, p| async move { e.confirm(p).await });
    handle(reg, "exit.cancel", &e, |e, p| async move { e.cancel(p) });
    handle(reg, "exit.check", &e, |e, _| async move { e.check_command().await });
    core.beat.feature("residential_exit", || true);

    // Web search changes a credential: when the control plane cannot be reached, only this
    // module's entries are replaced in the last config, an old key's included.
    let search_cell: Arc<OnceLock<Arc<search::Search>>> = Arc::new(OnceLock::new());
    let (c, cell) = (core.clone(), search_cell.clone());
    let on_search: search::OnChanged = Arc::new(move || {
        let (c, cell) = (c.clone(), cell.clone());
        Box::pin(async move {
            let Err(e) = c.sync.run().await else { return Ok(()) };
            let Some(se) = cell.get().cloned() else { return Err(e) };
            if c.sync.last().is_none() {
                return Err(e);
            }
            tracing::error!("[mitm-agent] sync failed ({e}); writing the web search key into the last config");
            let mine = se.clone();
            c.sync
                .replace_credentials(
                    move |v| se.owns(v),
                    move || crate::contracts::CredentialContributor::credentials(mine.as_ref()),
                )
                .await
        })
    });
    let se = Arc::new(search::Search::new(
        Core::store_path("SEARCH_STORE_PATH", "search.enc"),
        key,
        &cfg.org_id,
        &cfg.box_id,
        core.agent.clone(),
        core.kit("search"),
        std::env::var("LLM_PLAIN_KEYS").as_deref() == Ok("1"),
        on_search,
    ));
    let _ = search_cell.set(se.clone());
    let ss = se.summary();
    tracing::info!(
        "[mitm-agent] search store loaded ({}, {} agent(s))",
        match ss["provider"].as_str() {
            Some(p) => format!("{p} key {}", ss["hint"].as_str().unwrap_or("?")),
            None => "no key".to_string(),
        },
        ss["agents"]
    );
    app.contracts.credentials.add(se.clone());
    handle(reg, "search.propose", &se, |s, p| async move { s.propose(p).await });
    handle(reg, "search.confirm", &se, |s, p| async move { s.confirm(p).await });
    handle(reg, "search.cancel", &se, |s, p| async move { s.cancel(p) });
    handle(reg, "search.push", &se, |s, p| async move { s.push(p).await });
    handle(reg, "search.forget", &se, |s, p| async move { s.forget(p) });
    core.beat.feature("web_search", || true);

    if !standalone {
        // The whole map, brain included: `agents` is agents only. The lock comes from the kill store.
        let c = core.clone();
        let boxes: gbrain::Boxes = Arc::new(move || {
            c.sync
                .last()
                .and_then(|l| l.get("identities").and_then(|v| v.as_array()).cloned())
                .unwrap_or_default()
        });
        let c = core.clone();
        let lock: gbrain::Lock = Arc::new(move || match c.kill.get() {
            Some(k) => {
                let s = k.summary();
                let ids = s["agents"]
                    .as_array()
                    .map(|l| l.iter().map(|a| activity_sanitize::js_string(a.get("vmId"))).collect())
                    .unwrap_or_default();
                (k.org_stopped(), ids)
            }
            None => (false, Vec::new()),
        });
        let b = Arc::new(gbrain::Brain::new(
            Core::store_path("GBRAIN_STORE_PATH", "gbrain.enc"),
            key,
            &cfg.org_id,
            &cfg.box_id,
            core.agent.clone(),
            core.kit("gbrain"),
            boxes,
            lock,
        ));
        tracing::info!(
            "[mitm-agent] brain store loaded ({} agent(s) connected)",
            b.summary()["connections"]
        );
        let _ = core.brain.set(b.clone());
        handle(reg, "gbrain.propose", &b, |b, p| async move { b.propose(p).await });
        handle(reg, "gbrain.confirm", &b, |b, p| async move { b.confirm(p).await });
        handle(reg, "gbrain.cancel", &b, |b, p| async move { b.cancel(p) });
        handle(
            reg,
            "gbrain.disconnect",
            &b,
            |b, p| async move { b.disconnect(p).await },
        );
        core.beat.feature("gbrain", || true);

        register_backups(reg, app, core);
        register_updates(reg, app, core);
    }
    let c = core.clone();

    reg.commands.status(&["kill", "residential"], move || {
        let mut m = serde_json::Map::new();
        if let Some(k) = c.kill.get() {
            m.insert("kill".into(), k.summary());
        }
        if let Some(e) = c.exit.get() {
            m.insert("residential".into(), e.status());
        }
        m
    });
}

/// How long the process stays up after putting itself back, so the outcome rides a beat.
const SELF_RESTORE_RESTART_DELAY_MS: u64 = 20_000;

fn self_restore(app: &Arc<App>, label: &'static str) -> Arc<self_restore::SelfRestore> {
    let work_dir = std::env::var("BACKUP_WORK_DIR").unwrap_or_else(|_| "/opt/controlclaw/state".into());
    // `Restart=always` brings the process back on the restored state.
    let restart: self_restore::Restart = Arc::new(move || {
        tracing::info!(
            "[{label}] this firewall was put back from its backup; restarting in {}s",
            SELF_RESTORE_RESTART_DELAY_MS / 1000
        );
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(SELF_RESTORE_RESTART_DELAY_MS)).await;
            std::process::exit(0);
        });
    });
    Arc::new(self_restore::SelfRestore::new(
        &app.config.org_id,
        &app.config.box_id,
        work_dir.into(),
        app.http.get(),
        Some(app.runner.clone()),
        Some(restart),
    ))
}

/// Backups (`backup.ts`) and the recovery routes on 3100 over TLS (`recovery.ts`).
fn register_backups(reg: &mut Registry, app: &Arc<App>, core: &Arc<Core>) {
    let cfg = &app.config;
    // One instance for the console's restore and the recovery route's: one restore at a time.
    let restorer = self_restore(app, "backup");
    let b = Arc::new(backup::Backup::new(
        Core::store_path("BACKUP_STORE_PATH", "backup.enc"),
        &app.box_key,
        &cfg.org_id,
        &cfg.box_id,
        core.agent.clone(),
        core.kit("backup"),
        Some(self_backup::SelfBackup::new(&cfg.org_id, &cfg.box_id, app.http.get())),
        Some(restorer.clone()),
    ));
    // The key exists from the first beat.
    if let Err(e) = b.keypair() {
        tracing::error!("[backup] could not make this firewall's backup key: {e}");
    }
    let st = b.status();
    let fp = |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).map(str::to_string);
    tracing::info!(
        "[mitm-agent] backup store loaded (key {}, recovery key {})",
        st.as_ref()
            .and_then(|s| fp(s.get("fingerprint")))
            .unwrap_or_else(|| "not generated yet".into()),
        st.as_ref()
            .and_then(|s| s.get("recovery").and_then(|r| fp(r.get("fingerprint"))))
            .unwrap_or_else(|| "none".into())
    );
    // On the serial console: the owner checks these out of band.
    if let Some(f) = st.as_ref().and_then(|s| fp(s.get("fingerprint"))) {
        tracing::info!("[mitm-agent] backup key fingerprint: {f}");
    }
    b.announce_recovery();
    let _ = core.backup.set(b.clone());
    // A restore lifts no emergency stop: refused while one is on. And the backup commands freeze
    // before the swap, not after the restart is scheduled.
    let (kc, bc) = (Arc::downgrade(core), Arc::downgrade(&b));
    restorer.set_hooks(
        Arc::new(
            move || match kc.upgrade().and_then(|c| c.kill.get().map(|k| k.any_stopped())) {
                Some(false) => Ok(()),
                Some(true) => Err("An emergency stop is on. Release it before putting this firewall back.".into()),
                None => {
                    Err("This firewall cannot read its emergency stop right now, so it will not take a restore.".into())
                }
            },
        ),
        Arc::new(move |on| {
            if let Some(b) = bc.upgrade() {
                b.set_restoring(on);
            }
        }),
    );

    macro_rules! guarded {
        ($action:literal, $call:expr) => {
            handle(reg, $action, &b, |b, p| async move {
                if let Some(f) = b.frozen() {
                    return f;
                }
                #[allow(clippy::redundant_closure_call)]
                ($call)(b, p).await
            });
        };
    }
    guarded!("backup.run", |b: Arc<backup::Backup>, p| async move { b.run(p).await });
    guarded!("backup.firewall-run", |b: Arc<backup::Backup>, p| async move {
        b.run_self(p).await
    });
    guarded!("backup.restore.propose", |b: Arc<backup::Backup>, p| async move {
        b.propose_restore(p).await
    });
    guarded!("backup.restore.confirm", |b: Arc<backup::Backup>, p| async move {
        b.confirm_restore(p).await
    });
    guarded!("backup.restore.cancel", |b: Arc<backup::Backup>, p| async move {
        b.cancel_restore(p)
    });
    guarded!("backup.recovery.propose", |b: Arc<backup::Backup>, p| async move {
        b.propose_recovery(p).await
    });
    guarded!("backup.recovery.confirm", |b: Arc<backup::Backup>, p| async move {
        b.confirm_recovery(p).await
    });
    guarded!("backup.recovery.cancel", |b: Arc<backup::Backup>, p| async move {
        b.cancel_recovery(p)
    });
    guarded!("backup.recovery.rebind", |b: Arc<backup::Backup>, p| async move {
        b.rebind_recovery(p).await
    });
    guarded!("backup.firewall-restore", |b: Arc<backup::Backup>, p| async move {
        b.propose_self_restore(p).await
    });
    guarded!(
        "backup.firewall-restore.confirm",
        |b: Arc<backup::Backup>, p| async move { b.confirm_self_restore(p).await }
    );
    guarded!(
        "backup.firewall-restore.cancel",
        |b: Arc<backup::Backup>, p| async move { b.cancel_self_restore(p) }
    );
    let x = b.clone();
    reg.commands.reports(move || x.drain_reports());
    core.beat.feature("backups", || true);

    // The recovery routes, when this box has its certificate.
    let cert = cfg
        .recovery_routes
        .then(|| std::fs::read_to_string(cfg.keys_dir.join("recovery_cert.pem")).ok())
        .flatten()
        .map(|c| recovery_tls::cert_fingerprint(&c));
    let port = cfg.port;
    let routes = cert.as_ref().map(|c| {
        let c2 = core.clone();
        let eligibility: recovery_routes::Eligibility = Arc::new(move || {
            const UNREADABLE: &str =
                "This firewall cannot read its channel list or its model settings right now, so it will not take a restore. Try again shortly.";
            let bound = c2.restore_bound.get().and_then(|f| f()).ok_or_else(|| UNREADABLE.to_string())?
                + c2.connectors_bound.get().and_then(|f| f()).ok_or_else(|| UNREADABLE.to_string())?;
            if bound > 0 {
                return Err("This only works on a firewall nothing has been set up on yet. Putting one back replaces its keys, so the channels, models and integrations your agents use now would stop working. Take them off this firewall first.".into());
            }
            Ok(())
        });
        // The agent boxes reach this box on its private address.
        let base_url = std::env::var("CONNECTOR_GATE_BIND")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|ip| format!("http://{ip}:{port}"));
        Arc::new(recovery_routes::RecoveryRoutes::new(
            &cfg.org_id,
            &cfg.box_id,
            b.clone(),
            eligibility,
            Some(restorer.clone()),
            core.agent.clone(),
            core.agents.clone(),
            std::env::var("RECOVERY_STAGING_DIR")
                .unwrap_or_else(|_| "/opt/controlclaw/state/recovery".into())
                .into(),
            base_url,
            Some(c.clone()),
        ))
    });
    if let Some(r) = &routes {
        let x = r.clone();
        reg.plain.route(
            stages::PLAIN_STAGED,
            |m, p| *m == hyper::Method::GET && p.starts_with("/recovery/staged/"),
            move |req, _| {
                let x = x.clone();
                async move { x.serve_staged(req.uri().path()).await }
            },
        );
        let x = r.clone();
        reg.tls.route(
            stages::RECOVERY,
            |_, p| recovery_owns(p),
            move |req, _| {
                let x = x.clone();
                async move {
                    let path = req.uri().path().to_string();
                    x.handle(req, &path).await
                }
            },
        );
    }
    let enabled = routes.is_some();
    reg.commands.status(&["backup"], move || {
        let mut m = serde_json::Map::new();
        if let Some(mut s) = b.status() {
            s["recoveryRoutes"] = serde_json::json!({"enabled": enabled, "port": port, "certFingerprint": if enabled { cert.clone() } else { None }});
            m.insert("backup".into(), s);
        }
        m
    });
}

/// The disk seals that follow the recovery key, and the recovery-key notices: both need the
/// backups (the recovery key). The updates and apply below do not.
fn register_recovery_followers(app: &Arc<App>, core: &Arc<Core>, b: Arc<backup::Backup>) {
    let cfg = &app.config;
    let key = &app.box_key;

    // The disk seals follow the recovery key the backups hold.
    let b2 = b.clone();
    let target: disk_reseal::TargetFn = Arc::new(move || {
        let st = b2.status()?;
        let r = st.get("recovery").filter(|r| !r.is_null())?;
        let keys = b2.recovery_keys()?;
        Some(disk_reseal::Target {
            public_key: keys.public_key,
            fingerprint: keys.fingerprint,
            tofu: r.get("tofu") == Some(&serde_json::Value::Bool(true)),
        })
    });
    // Every box with a disk of its own: the agents and the brain (`browserIdentities`, parsed:
    // a name that is not a plain name is not taken), at the address calls go to.
    let c = core.clone();
    let listed: disk_reseal::ListedFn = Arc::new(move || {
        c.agents
            .browser_boxes()
            .iter()
            .filter_map(|i| {
                let vm = identities::vm_id_of(i);
                let hostname = c.agents.host_for(&vm)?;
                let name = identities::str_field(i, "name")
                    .map(str::to_string)
                    .unwrap_or_else(|| vm.clone());
                Some(disk_reseal::Listed {
                    vm_id: vm,
                    hostname,
                    name,
                })
            })
            .collect()
    });
    let pinned: disk_reseal::PinnedFn = Arc::new(|| pages::access().and_then(|a| a.pinned_agents()));
    // `identitiesSynced`: the identity list was read since start.
    let c = core.clone();
    let synced: disk_reseal::SyncedFn = Arc::new(move || c.agents.synced());
    let reseal = disk_reseal::DiskReseal::new(
        Core::store_path("DISK_RESEAL_PATH", "disk-reseal.enc"),
        key,
        &cfg.org_id,
        &cfg.box_id,
        core.agent.clone(),
        core.kit("disk-reseal"),
        app.runner.clone(),
        target,
        listed,
        pinned,
        synced,
    );
    let _ = b.reseal.set(Arc::new(reseal.clone()));
    let _ = core.disk_reseal.set(reseal);

    // An update can be confirmed with the recovery key when no channel takes the code (T-99).
    let b2 = b.clone();
    let notices = recovery_notices::RecoveryNotices::new(
        Core::store_path("RECOVERY_NOTICES_PATH", "recovery-notices.enc"),
        key,
        &cfg.org_id,
        &cfg.box_id,
        core.agent.clone(),
        core.kit("recovery-notices"),
        Arc::new(move || b2.recovery_keys().map(|k| k.public_key)),
    );
    let _ = core.consent.recovery.set(Arc::new(notices.clone()));
    let _ = core.recovery_notices.set(notices);
}

/// The disk seals that follow the recovery key, the recovery-key notices, updates (agent, batch,
/// nightly, this box) and apply.
fn register_updates(reg: &mut Registry, app: &Arc<App>, core: &Arc<Core>) {
    let cfg = &app.config;
    let key = &app.box_key;
    if let Some(b) = core.backup.get().cloned() {
        register_recovery_followers(app, core, b);
    }

    // The proxy has to know a box is updating before the run's first download.
    let c = core.clone();
    let on_windows: update::OnWindowsChanged = Arc::new(move || {
        let c = c.clone();
        Box::pin(async move { c.sync.publish_update_windows().await })
    });
    let u = Arc::new(update::Updates::new(
        core.agent.clone(),
        core.kit("update"),
        core.agents.clone(),
        on_windows,
    ));
    let x = u.clone();
    let _ = core.sync.hooks.update_windows.set(Arc::new(move || x.windows()));
    handle(reg, "update.propose", &u, |u, p| async move { u.propose(p).await });
    handle(reg, "update.confirm", &u, |u, p| async move { u.confirm(p).await });
    handle(reg, "update.cancel", &u, |u, p| async move { u.cancel(p) });

    let a = Arc::new(apply::Apply::new(
        core.agent.clone(),
        core.kit("apply"),
        core.agents.clone(),
    ));
    let _ = core.apply.set(a.clone());
    app.contracts.mcp_grants.set(Arc::new(apply::McpGrants(a.clone())));
    handle(reg, "apply.propose", &a, |a, p| async move { a.propose(p).await });
    handle(reg, "apply.confirm", &a, |a, p| async move { a.confirm(p).await });
    handle(reg, "apply.cancel", &a, |a, p| async move { a.cancel(p) });
    for f in ["templates_code", "skills_apply", "notes_apply", "apply_overwrite"] {
        core.beat.feature(f, || true);
    }

    let su = Arc::new(self_update::SelfUpdate::new(
        std::env::var("SELF_UPDATE_STATE_PATH")
            .unwrap_or_else(|_| "/opt/controlclaw/state/update.json".into())
            .into(),
        std::env::var("SELF_UPDATE_CONF_PATH")
            .unwrap_or_else(|_| "/etc/controlclaw/update.conf".into())
            .into(),
        app.runner.clone(),
    ));
    let fu = Arc::new(firewall_update::FirewallUpdate::new(su, core.kit("firewall-update")));
    tracing::info!(
        "[mitm-agent] self-update {}",
        if fu.supported() {
            "available"
        } else {
            "unavailable (this box has no update pin; rebuild only)"
        }
    );
    let _ = core.firewall_update.set(fu.clone());
    app.contracts
        .self_update
        .set(Arc::new(firewall_update::DoctorUpdate(fu.clone())));
    handle(
        reg,
        "firewall-update.propose",
        &fu,
        |f, p| async move { f.propose(p).await },
    );
    handle(
        reg,
        "firewall-update.confirm",
        &fu,
        |f, p| async move { f.confirm(p).await },
    );
    handle(reg, "firewall-update.cancel", &fu, |f, p| async move { f.cancel(p) });
    let x = fu.clone();
    core.beat.feature("self_update", move || x.supported());

    // The whole organization on one code, and the nightly grant.
    let grants = Arc::new(update_all::GrantStore::new(
        Core::store_path("UPDATE_ALL_STORE_PATH", "update-all.enc"),
        key,
        &cfg.org_id,
        &cfg.box_id,
    ));
    let g2 = grants.clone();
    let au = Arc::new(auto_update::AutoUpdate::new(
        core.kit("auto-update"),
        Arc::new(auto_update::AutoUpdateStore::new(
            Core::store_path("AUTO_UPDATE_STORE_PATH", "auto-update.enc"),
            key,
            &cfg.org_id,
            &cfg.box_id,
        )),
        Arc::new(move || {
            if g2.auto_grant_live(now_ms())
                && let Err(e) = g2.drop_grant(None)
            {
                tracing::error!("[update-all] could not drop the nightly batch: {e}");
            }
        }),
    ));
    handle(
        reg,
        "auto-update.propose",
        &au,
        |a, p| async move { a.propose(p).await },
    );
    handle(reg, "auto-update.confirm", &au, |a, p| async move { a.confirm(p) });
    handle(reg, "auto-update.cancel", &au, |a, p| async move { a.cancel(p) });
    handle(reg, "auto-update.disable", &au, |a, _| async move { a.disable() });
    let x = au.clone();
    let ua = Arc::new(update_all::UpdateAll::new(
        core.kit("update-all"),
        core.agents.clone(),
        u,
        fu.clone(),
        grants,
        Arc::new(move || x.confirmed_at()),
    ));
    handle(reg, "update-all.auto", &ua, |u, p| async move { u.automatic(p) });
    handle(reg, "update-all.propose", &ua, |u, p| async move { u.propose(p).await });
    handle(reg, "update-all.confirm", &ua, |u, p| async move { u.confirm(p) });
    handle(reg, "update-all.apply", &ua, |u, p| async move { u.apply_one(p).await });
    handle(reg, "update-all.cancel", &ua, |u, p| async move { u.cancel(p) });
    core.beat.feature("update_all", || true);
    core.beat.feature("auto_update", || true);

    let c = core.clone();
    reg.commands.status(&["update", "disk_reseal", "auto_update"], move || {
        let mut m = serde_json::Map::new();
        m.insert("update".into(), fu.status().to_json());
        let has_recovery = c
            .backup
            .get()
            .and_then(|b| b.status())
            .is_some_and(|s| s.get("recovery").is_some_and(|r| !r.is_null()));
        if has_recovery && let Some(r) = c.disk_reseal.get() {
            m.insert("disk_reseal".into(), r.report());
        }
        m.insert(
            "auto_update".into(),
            serde_json::json!({"confirmedAt": au.confirmed_at()}),
        );
        m
    });
}

/// The webhook family and the ingress (`webhooks.ts`, `startIngress` in `index.ts`).
fn register_webhooks(reg: &mut Registry, app: &Arc<App>, core: &Arc<Core>) {
    if !app.config.firewall_url.is_empty() && core.uses_http {
        let path = std::env::var("WEBHOOK_STORE_PATH").unwrap_or_else(|_| "/opt/controlclaw/state/webhooks.enc".into());
        let routes: Arc<dyn Fn() -> Option<Arc<dyn crate::contracts::CodeRouteSource>> + Send + Sync> = {
            let app = app.clone();
            Arc::new(move || app.contracts.code_route_source.get())
        };
        let w = Arc::new(webhooks::Webhooks::new(
            path.into(),
            &app.box_key,
            &app.config.org_id,
            &app.config.box_id,
            core.agent.clone(),
            crate::contracts::CodeService::module(&consent::ConsentView(core.consent.clone()), webhooks::MODULE),
            routes,
        ));
        tracing::info!(
            "[mitm-agent] webhook store loaded ({} registration(s))",
            w.registrations().len()
        );
        let _ = core.webhooks.set(w.clone());
        let x = w.clone();
        reg.commands.handle("webhook.propose", move |p| x.clone().propose(p));
        let x = w.clone();
        reg.commands.handle("webhook.confirm", move |p| {
            let x = x.clone();
            async move { x.confirm(p) }
        });
        let x = w.clone();
        reg.commands.handle("webhook.cancel", move |p| {
            let x = x.clone();
            async move { x.cancel(p) }
        });
        let x = w.clone();
        reg.commands.handle("webhook.sync", move |p| {
            let x = x.clone();
            async move { x.sync(&serde_json::Value::Object(p)) }
        });
        let x = w.clone();
        reg.commands.handle("webhook.forget", move |p| {
            let x = x.clone();
            async move { x.forget(p) }
        });
        let x = w.clone();
        reg.commands.handle("webhook.read", move |_| {
            let x = x.clone();
            async move { x.read() }
        });
        let x = w.clone();
        let _ = core
            .sync
            .hooks
            .webhook_sync
            .set(Arc::new(move |hooks: serde_json::Value| {
                let x = x.clone();
                Box::pin(async move {
                    x.sync(&serde_json::json!({"hooks": hooks}));
                    Ok(())
                }) as cc_http::BoxFuture<Result<(), String>>
            }));
        let x = w.clone();
        core.beat.inventory_section("webhooks", move || Some(x.inventory()));
    }

    let legacy = std::env::var("WEBHOOKS_PATH").unwrap_or_else(|_| "/opt/controlclaw/state/webhooks.json".into());
    let c = core.clone();
    // The legacy file is read again only when it changed, not on every delivery.
    let cache: Mutex<Option<(std::time::SystemTime, Vec<ingress::Registration>)>> = Mutex::new(None);
    let registrations: ingress::Registrations = Arc::new(move || {
        let mut out = match c.webhooks.get() {
            Some(w) => w.registrations(),
            // Fail closed: no readable set is no registration, a 404, never a stale copy.
            None => match std::fs::metadata(&legacy).and_then(|m| m.modified()) {
                Ok(mtime) => {
                    let mut cached = cache.lock().unwrap_or_else(|e| e.into_inner());
                    match cached.as_ref() {
                        Some((at, regs)) if *at == mtime => regs.clone(),
                        _ => match std::fs::read_to_string(&legacy) {
                            Ok(t) => {
                                let regs = serde_json::from_str(&t)
                                    .map(|v| ingress::parse_registrations(&v))
                                    .unwrap_or_default();
                                *cached = Some((mtime, regs.clone()));
                                regs
                            }
                            Err(e) => {
                                tracing::error!("[ingress] could not read {legacy}: {e}");
                                Vec::new()
                            }
                        },
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::error!("[ingress] could not read {legacy}: {e}");
                    }
                    Vec::new()
                }
            },
        };
        for more in c.extra_registrations.lock().map(|m| m.clone()).unwrap_or_default() {
            out.extend(more());
        }
        out
    });
    let agent = core.agent.clone().with_timeout(ingress::INGRESS_FORWARD_TIMEOUT_MS);
    let c = core.clone();
    let deliver: ingress::Deliver = Arc::new(move |reg, d| {
        let (agent, c) = (agent.clone(), c.clone());
        Box::pin(async move {
            let target = agent_client::AgentTarget::new(&reg.target.vm_id, &reg.target.hostname);
            if let (Some(push), Some(w)) = (c.gmail_push.get(), c.webhooks.get())
                && w.is_gmail(&reg.id)
            {
                push(target, d.body_b64);
                return Ok(ingress::Reply {
                    status: serde_json::json!(204),
                    ..Default::default()
                });
            }
            let mut body = serde_json::Map::new();
            body.insert("port".into(), ingress::num(reg.target.port));
            body.insert("path".into(), serde_json::json!(reg.target.path));
            body.insert("method".into(), serde_json::json!("POST"));
            body.insert("headers".into(), serde_json::Value::Object(d.headers));
            body.insert("bodyB64".into(), serde_json::json!(d.body_b64));
            if d.bounded {
                body.insert("query".into(), serde_json::json!(d.query));
                body.insert("responseMode".into(), serde_json::json!("bounded"));
            }
            let out = agent
                .post(&target, "/hooks/deliver", &serde_json::Value::Object(body))
                .await
                .map_err(|e| e.to_string())?;
            let status = out
                .get("status")
                .filter(|s| s.is_number())
                .cloned()
                .unwrap_or(serde_json::json!(502));
            Ok(if reg.bounded {
                ingress::Reply {
                    status,
                    body_b64: out
                        .get("bodyB64")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    content_type: out
                        .get("contentType")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                }
            } else {
                ingress::Reply {
                    status,
                    ..Default::default()
                }
            })
        }) as cc_http::BoxFuture<Result<ingress::Reply, String>>
    });
    let c = core.clone();
    let will_run = startup::content_rules_will_run(&app.config, &core.env);
    let screen: ingress::Screen = Arc::new(move |reg, body, ct, ce| match c.ingress_screen.get() {
        Some(s) => s(reg, body, ct, ce),
        None => Box::pin(async move { will_run.then(|| (503, "content rules not loaded".to_string())) }),
    });
    let log = (!core.env.traffic_log_path.is_empty()).then(|| core.env.traffic_log_path.clone());
    let ingress = Arc::new(ingress::Ingress::new(registrations, deliver, Some(screen), log));
    reg.ingress.route(
        stages::INGRESS_HOOKS,
        |_, p| ingress::owns_ingress_path(p),
        move |req, _| {
            let ingress = ingress.clone();
            async move {
                let path = req.uri().path().to_string();
                ingress.handle(req, &path).await
            }
        },
    );
}

/// `setInterval(f, every)`: the first run one period from now; one run at a time.
pub(crate) fn every<F, Fut>(period: Duration, f: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    // `setInterval(f, 0)` runs as often as it can; an interval of zero would panic.
    let period = period.max(Duration::from_millis(1));
    tokio::spawn(async move {
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            // Each pass in its own task: one that panics is logged by tokio, and the timer goes on.
            let _ = tokio::spawn(f()).await;
        }
    });
}

/// After `register`, before the listeners: the first sync (`SYNC_ONCE` exits after it), the
/// console's public key, then the timers, and the CA publish the first beat waits for.
pub async fn start(app: &Arc<App>) {
    let Some(core) = core() else { return };
    // Said loudly and once: a code with no approved sender goes back to the control plane.
    if provenance::dev_consent_allowed(std::path::Path::new(provenance::PROVENANCE_PATH)) {
        tracing::warn!(
            "[mitm-agent] DEV BUILD (ansible origin {}) — a confirmation code with no approved sender to reach is handed back to the control plane instead",
            provenance::ansible_origin(std::path::Path::new(provenance::PROVENANCE_PATH)).unwrap_or_default()
        );
    }
    // A box newly recorded for inspection (the 3940 gate's `/ca`): the identity map rewritten.
    let c = core.clone();
    let _ = app.cp_inspect.on_new.set(Arc::new(move || {
        if let Err(e) = c.sync.publish_cp_inspect() {
            tracing::error!("[cp-inspect] could not rewrite the identity map: {e}");
        }
    }));
    // Before any call signed with the key (the sync, the CA).
    keys::register_public_key(&app.config.keys_dir, &app.http).await;
    if let Err(e) = core.sync.run().await {
        // Fail closed: a stale or empty config is not left silently; it is said.
        if core.env.sync_once {
            tracing::error!("[mitm-agent] sync failed: {e}");
            std::process::exit(1);
        }
        tracing::error!("[mitm-agent] sync failed (keeping previous config): {e}");
    }
    if core.env.sync_once {
        tracing::info!("[mitm-agent] sync-once complete");
        std::process::exit(0);
    }
    // A standalone firewall has no console key: its pages open with its own (`local_intent`).
    if app.config.mode.saas()
        && let Err(e) = std::fs::read_to_string(app.config.keys_dir.join("saas_public_key.pem"))
    {
        tracing::error!("[mitm-agent] failed to load SaaS public key: {e}");
        std::process::exit(1);
    }

    let c = core.clone();
    every(Duration::from_millis(core.env.sync_interval_ms), move || {
        let c = c.clone();
        async move {
            if let Err(e) = c.sync.run().await {
                tracing::error!("[mitm-agent] resync: {e}");
            }
        }
    });
    // A standalone firewall's panel wakes the sync when it changes the rules (`sync::WAKE`).
    if !app.config.mode.saas() {
        let c = core.clone();
        tokio::spawn(async move {
            loop {
                sync::WAKE.notified().await;
                if let Err(e) = c.sync.run().await {
                    tracing::error!("[mitm-agent] resync: {e}");
                }
            }
        });
    }

    // The first beat waits for the CA, at most 10 s, and the publish goes on after that; without
    // a control channel nothing waits.
    let publish = tokio::spawn(startup::publish_ca(core.clone()));
    if !app.config.firewall_url.is_empty() && core.uses_http {
        control::before_first_beat(Box::pin(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), publish).await;
        }));
    }

    let env = &core.env;
    if !env.permission_url.is_empty() && !env.pending_path.is_empty() && core.uses_http {
        let bridge = Arc::new(PermissionBridge::new(
            core.grants.clone(),
            &env.pending_path,
            &env.permission_url,
            env.permission_ttl,
            core.sync.client.clone(),
        ));
        let _ = core.bridge.set(bridge.clone());
        tracing::info!("[mitm-agent] permission bridge enabled");
        every(Duration::from_millis(env.permission_poll_ms), move || {
            let b = bridge.clone();
            async move { b.tick().await }
        });
    }

    if !env.activity_url.is_empty() && !env.traffic_log_path.is_empty() && core.uses_http {
        let watchers = core.traffic_watchers.lock().map(|w| w.clone()).unwrap_or_default();
        let shipper = Arc::new(ActivityShipper::new(
            &env.traffic_log_path,
            &env.activity_cursor_path,
            &env.activity_url,
            core.sync.client.clone(),
            None,
            watchers,
        ));
        tracing::info!("[mitm-agent] activity shipper enabled");
        every(Duration::from_millis(env.activity_poll_ms), move || {
            let s = shipper.clone();
            async move {
                s.tick().await;
            }
        });
    }

    pages::start(&core);
    let h = core.health.clone();
    tokio::spawn(async move { h.tick().await });
    let h = core.health.clone();
    every(Duration::from_millis(health::HEALTH_REACH_MS), move || {
        let h = h.clone();
        async move { h.tick().await }
    });

    let (keys, http, c) = (app.keys.clone(), app.http.clone(), core.clone());
    tokio::spawn(async move {
        ready::report_ready(
            &keys,
            &http,
            || c.ready_ssh.get().cloned(),
            || c.ready_doctor.get().cloned(),
        )
        .await
    });

    if let Some(k) = core.kill.get().cloned() {
        // A locked box that reboots starts OpenClaw again; this stops it, without the console.
        let ids = |c: &Core| c.agents.agents().iter().map(identities::vm_id_of).collect::<Vec<_>>();
        let (k2, c2) = (k.clone(), core.clone());
        tokio::spawn(async move {
            k2.reconcile(&ids(&c2)).await;
        });
        core.sync_brain_lock();
        let c3 = core.clone();
        every(Duration::from_millis(kill::KILL_RECONCILE_MS), move || {
            let (k, c) = (k.clone(), c3.clone());
            async move {
                k.reconcile(&ids(&c)).await;
                // The brain's gate lock, retried at the same pace until the brain has it.
                c.sync_brain_lock();
            }
        });
    }

    if let Some(r) = core.disk_reseal.get().cloned() {
        // The first pass waits for the identity map and the channel list.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            r.tick().await;
            every(Duration::from_millis(disk_reseal::RESEAL_RETRY_MS), move || {
                let r = r.clone();
                async move { r.tick().await }
            });
        });
    }

    if let Some(n) = core.recovery_notices.get().cloned() {
        every(Duration::from_millis(recovery_notices::NOTICE_RETRY_MS), move || {
            let n = n.clone();
            async move { n.tick().await }
        });
    }

    if let Some(b) = core.brain.get().cloned() {
        // The gate matches what the owner confirmed. Removes or re-points only; never adds access.
        every(Duration::from_millis(gbrain::GBRAIN_RECONCILE_MS), move || {
            let b = b.clone();
            async move {
                if let Err(e) = b.reconcile().await {
                    tracing::error!("[gbrain] reconcile: {e}");
                }
            }
        });
    }

    // Who actually logged into this box, from sshd's journal; no traffic log needed.
    if !core.env.activity_url.is_empty() && core.uses_http {
        let w = Arc::new(ssh::SshLogins::new(
            app.runner.clone(),
            Core::store_path("SSH_LOGIN_CURSOR_PATH", "ssh-logins.cursor"),
            &core.env.activity_url,
            core.sync.client.clone(),
        ));
        let poll = std::env::var("SSH_LOGIN_POLL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60_000);
        every(Duration::from_millis(poll), move || {
            let w = w.clone();
            async move {
                w.tick().await;
            }
        });
    }

    if let Some(e) = core.exit.get().cloned() {
        // A no-op until the check is due (every 15 minutes) or when there is no exit.
        let e2 = e.clone();
        tokio::spawn(async move { e2.tick().await });
        let poll = std::env::var("EXIT_CHECK_POLL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60_000);
        every(Duration::from_millis(poll), move || {
            let e = e.clone();
            async move { e.tick().await }
        });
    }
}
