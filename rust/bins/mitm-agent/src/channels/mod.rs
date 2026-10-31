//! W4: channels and AI on the firewall (docs/plans/rust-workstreams/W4.md): channels, models, Google,
//! Drive, AgentMail, email rules, content rules, secrets, phone, meetings, the AI judge and review,
//! and the loopback services the proxy calls (3101, 8791-8794).

pub mod agent;
pub mod ai;
pub mod chan;
pub mod content_engine;
pub mod content_rules;
pub mod contracts_fill;
pub mod drive;
pub mod email;
pub mod gmail_push;
pub mod google;
pub mod google_drive;
pub mod included_credit;
pub mod js;
pub mod llm;
pub mod meetings;
pub mod new_agents;
pub mod phone;
pub mod secrets;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::app::{App, Registry};
use crate::commands::CommandOutcome;
use crate::contracts::{CredentialContributor, CredentialOrder, IdentityMap};

/// Milliseconds since the epoch, as `Date.now()`.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

pub(crate) fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

pub(crate) fn env_ms(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// `onCredentialsChanged`: rewrite the proxy config now (W3's sync), so a new key is swapped and a
/// removed one stops being, without waiting for the next periodic sync.
/// `onCredentialsChanged`: W3's credentials sync writes the proxy's credentials again at once and
/// then syncs; a build without it runs the whole sync and waits for it.
fn sync_now(app: &Arc<App>) -> Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync> {
    let app = app.clone();
    Arc::new(move || {
        let sync = app.contracts.credentials_sync.get();
        Box::pin(async move {
            if let Some(s) = sync {
                return s.changed().await;
            }
            if let Some(core) = crate::core::core()
                && let Err(e) = core.sync.run().await
            {
                tracing::error!("[mitm-agent] sync after a credential change failed: {e}");
            }
        })
    })
}

/// How many agents a restore would leave without their channels and models: the channels assigned
/// to an agent and the agents with a model. None while either store cannot be read: it may hold one.
fn restore_bound(channels_ready: bool, channels: &[Value], model_agents: Option<usize>) -> Option<usize> {
    let assigned = channels
        .iter()
        .filter(|c| c["assignedVmId"].as_str().is_some_and(|v| !v.is_empty()))
        .count();
    channels_ready.then_some(assigned + model_agents?)
}

/// A command's result: a thrown error in the TS is a failed command with its message.
pub(crate) fn finish(r: Result<CommandOutcome, String>) -> CommandOutcome {
    r.unwrap_or_else(|message| {
        let message: String = message.chars().take(500).collect();
        CommandOutcome::failed("failed", message)
    })
}

/// `IntegrationJudge` (W5): `integrationFits` and `labelTool` from the AI judge; the label epoch is
/// the content rules' pin as JSON, so a new pin labels the tools again (`index.ts` 1400).
struct IntegrationAi {
    judge: Arc<ai::judge::AiJudge>,
    pin: Arc<dyn Fn() -> Option<ai::judge::AiPin> + Send + Sync>,
}

impl crate::contracts::IntegrationJudge for IntegrationAi {
    fn integration_fits(
        &self,
        vm_id: &str,
        sentence: &str,
        integration: &str,
        tool: &str,
        input: &Value,
    ) -> cc_http::BoxFuture<String> {
        let j = self.judge.clone();
        let (vm, sentence, integration, tool, input) = (
            vm_id.to_string(),
            sentence.to_string(),
            integration.to_string(),
            tool.to_string(),
            input.clone(),
        );
        Box::pin(async move {
            j.integration_fits(&vm, &sentence, &integration, &tool, &input)
                .await
                .to_string()
        })
    }

    fn label_tool(
        &self,
        server: &str,
        name: &str,
        description: Option<&str>,
        argument_names: &[String],
    ) -> cc_http::BoxFuture<Option<String>> {
        let j = self.judge.clone();
        let (server, name, description, args) = (
            server.to_string(),
            name.to_string(),
            description.map(str::to_string),
            argument_names.to_vec(),
        );
        Box::pin(async move {
            j.label_tool(&server, &name, description.as_deref(), &args)
                .await
                .map(str::to_string)
        })
    }

    fn label_epoch(&self) -> String {
        (self.pin)().map_or_else(|| "null".into(), |p| content_rules::firewall::pin_json(&p).to_string())
    }
}

struct ChannelCredentials(Arc<chan::ChannelsFirewall>);

impl CredentialContributor for ChannelCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Channels
    }

    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

struct SecretCredentials(Arc<secrets::SecretsFirewall>);

impl CredentialContributor for SecretCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Secrets
    }

    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

struct LlmCredentials(Arc<llm::Llm>);

impl CredentialContributor for LlmCredentials {
    fn order(&self) -> CredentialOrder {
        CredentialOrder::Llm
    }

    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

pub fn register(reg: &mut Registry, app: &Arc<App>) {
    let identities: Arc<dyn Fn() -> Option<Arc<dyn IdentityMap>> + Send + Sync> = {
        let app = app.clone();
        Arc::new(move || app.contracts.identities.require().ok())
    };
    let agent = match agent::AgentClient::new(app.keys.clone(), &app.config.box_id, identities.clone()) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            tracing::error!("[mitm-agent] agent client would not start, W4 commands disabled: {e}");
            return;
        }
    };

    // When each agent first appeared in the identity map (T-103), from the rows each sync (or a
    // look for a new agent) actually read: never from a pinned host or anything on disk. The first
    // read is the baseline. With no core there is no map, nobody is ever new, and a new agent's
    // first model needs a code (fail closed).
    let first_seen = Arc::new(new_agents::AgentFirstSeen::default());
    let core = crate::core::core();
    match &core {
        Some(core) => {
            let f = first_seen.clone();
            core.agents.on_identities(Arc::new(move |agents, _browser_boxes| {
                f.observe(agents.iter().map(crate::core::identities::vm_id_of));
            }));
        }
        None => tracing::error!("[mitm-agent] no identity map: every new agent's first model needs a code"),
    }

    // The firewall's own model calls (the AI review) go out with the box's client and roots.
    cc_llm::structured::use_client(app.http.get());

    let included = Arc::new(included_credit::IncludedCreditWatch::default());
    // The activity shipper hands every batch the console took to `note` (`onShipped`).
    if let Some(core) = &core
        && let Ok(mut w) = core.traffic_watchers.lock()
    {
        let inc = included.clone();
        w.push(Arc::new(move |records: &[Value]| inc.note(records)));
    }

    // Each module's own codes: the module is part of the key (W3's code service).
    let http = match reqwest::Client::builder().use_rustls_tls().no_proxy().build() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("[mitm-agent] http client would not start, W4 commands disabled: {e}");
            return;
        }
    };
    // Channels (Telegram, Slack, WhatsApp): the connections, who may confirm changes, and the code
    // routes every other module sends its codes through.
    // A standalone firewall always: its calls to an agent are plain HTTP, so a bot's token never
    // goes to the agent, only a stand-in the proxy swaps on the way out.
    let placeholder_swap = env_or("CHANNELS_PLACEHOLDER_SWAP", "") == "1" || app.config.mode.standalone();
    let channels = chan::ChannelsFirewall::new(chan::ChannelsOptions {
        store_path: PathBuf::from(env_or("CHANNEL_STORE_PATH", "/opt/controlclaw/state/channels.enc")),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent: Arc::new(agent.clone()),
        identities: {
            let identities = identities.clone();
            Arc::new(move || {
                identities()
                    .map(|m| m.agents().into_iter().map(|a| (a.vm_id, a.hostname)).collect())
                    .unwrap_or_default()
            })
        },
        placeholder_swap,
        dev: contracts_fill::dev_build(),
        codes: contracts_fill::codes_for(app, "channels", false),
        on_credentials_changed: sync_now(app),
        now: Arc::new(now_ms),
        make_apply_id: Arc::new(|| uuid::Uuid::new_v4().to_string()),
        sleep: Arc::new(|d| Box::pin(tokio::time::sleep(d))),
    });
    {
        let summary = channels.summary();
        let assigned = summary.iter().filter(|c| !c["assignedVmId"].is_null()).count();
        tracing::info!(
            "[mitm-agent] channel store loaded ({} connection(s), {assigned} assigned, placeholder swap {})",
            summary.len(),
            if placeholder_swap { "on" } else { "off" }
        );
    }
    app.contracts
        .credentials
        .add(Arc::new(ChannelCredentials(channels.clone())));
    for (action, which) in [
        ("channels.propose", 0u8),
        ("channels.confirm", 1),
        ("channels.cancel", 2),
        ("channels.push", 3),
    ] {
        let c = channels.clone();
        reg.commands.handle(action, move |p| {
            let c = c.clone();
            async move {
                finish(match which {
                    0 => c.propose(p).await,
                    1 => c.confirm(p).await,
                    2 => c.cancel(p).await,
                    _ => c.push(p).await,
                })
            }
        });
    }
    // The connections as this firewall holds them (no secrets): what a standalone firewall's panel
    // lists, since no console keeps a copy.
    let c = channels.clone();
    reg.commands.handle("channels.read", move |_| {
        let c = c.clone();
        async move {
            let mut data = Map::new();
            data.insert("connections".into(), Value::Array(c.summary()));
            CommandOutcome {
                ok: true,
                status: "done".into(),
                message: None,
                data: Some(data),
            }
        }
    });
    // Approve with a button: the taps the proxy strips out of the agents' `getUpdates` (8793).
    let buttons = Arc::new(chan::buttons::CodeButtons::new(chan::buttons::CodeButtonsOptions {
        approved: {
            let c = channels.clone();
            Arc::new(move |conn: &str, sender: &str| c.is_code_recipient(conn, sender))
        },
        token_for: Some({
            let c = channels.clone();
            Arc::new(move |bot: &str| c.telegram_token(bot))
        }),
        changed: None,
        telegram: Arc::new(chan::buttons::LiveTelegram(app.http.get())),
        now: Arc::new(now_ms),
        make_numbers: None,
        shuffle: None,
    }));
    let listening = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let router = Arc::new(chan::buttons::router(buttons.clone()));
        let up = listening.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(("127.0.0.1", cc_contracts::loopback::CODE_BUTTONS_PORT)).await {
                Ok(l) => {
                    up.store(true, std::sync::atomic::Ordering::SeqCst);
                    cc_http::serve(l, router).await;
                    // A listener that stopped takes no taps: no more buttons.
                    up.store(false, std::sync::atomic::Ordering::SeqCst);
                    tracing::error!("[buttons] tap listener stopped; codes go out without buttons");
                }
                // Codes still go out, but no tap can reach this module.
                Err(_) => tracing::error!("[buttons] tap listener unavailable; codes go out without buttons"),
            }
        });
    }
    // Where codes go, and the buttons, for W3's consent codes and every module that sends one.
    let buttons_up = listening.clone();
    contracts_fill::fill(app, channels.clone(), buttons.clone(), listening);
    // Team chat's write of its channel to each agent (W5), the same way the channels are written.
    app.contracts
        .channel_writer
        .set(Arc::new(contracts_fill::Writer(Arc::new(chan::apply::ChannelWriter {
            agent: Arc::new(agent.clone()),
            now: Arc::new(now_ms),
            make_apply_id: Arc::new(|| uuid::Uuid::new_v4().to_string()),
            sleep: Arc::new(|d| Box::pin(tokio::time::sleep(d))),
        }))));
    // `channels` in the beat's inventory (left out by the beat when the store could not be read).
    let c = channels.clone();
    contracts_fill::inventory(app, "channels", move || {
        Some(
            c.summary()
                .iter()
                .map(|x| json!({"id": x["id"], "type": x["type"], "assignedVmId": x["assignedVmId"]}))
                .collect(),
        )
    });
    // `code_recipients`: who gets codes, who the agents allowed, and the codes out with buttons.
    // Left out when the channel store could not be read: it holds no answer then.
    let (c, b) = (channels.clone(), buttons.clone());
    reg.commands.status(&["code_recipients"], move || {
        let mut m = Map::new();
        if cc_crypto::store_health::is_store_unreadable("channels") {
            return m;
        }
        let mut r = c.code_recipients();
        let taps: Vec<Value> = b.beat().iter().map(|t| t.to_json()).collect();
        if !taps.is_empty() {
            r["taps"] = Value::Array(taps);
        }
        m.insert("code_recipients".into(), r);
        m
    });
    let c = channels.clone();
    tokio::spawn(async move {
        loop {
            c.tick().await;
            tokio::time::sleep(Duration::from_millis(chan::RECONCILE_INTERVAL_MS as u64)).await;
        }
    });

    let plain_keys = env_or("LLM_PLAIN_KEYS", "") == "1";
    let llm = llm::Llm::new(llm::LlmOptions {
        store_path: PathBuf::from(env_or("LLM_STORE_PATH", "/opt/controlclaw/state/llm.enc")),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent: Arc::new(agent.clone()),
        codes: contracts_fill::codes_for(app, "llm", false),
        // Every agent with an approved sender; nobody means trust on first use. `None` when that is
        // not known, and then nothing applies without a code.
        code_routes: {
            let c = channels.clone();
            Arc::new(move || c.code_routes_checked())
        },
        is_new_agent: Some({
            let f = first_seen.clone();
            Arc::new(move |vm: &str| f.is_new(vm))
        }),
        is_live_agent: Some({
            let f = first_seen.clone();
            Arc::new(move |vm: &str| f.is_live(vm))
        }),
        agent_has_channels: Some({
            let c = channels.clone();
            // A channel list that cannot be read may hold one: treated as having one (needs a code).
            Arc::new(move |vm: &str| !c.ready() || c.has_agent_connection(vm))
        }),
        plain_keys,
        on_credentials_changed: sync_now(app),
        fetch: Arc::new(llm::ReqwestFetch(http)),
        now: Arc::new(now_ms),
    });
    {
        let (creds, agents) = llm.summary();
        tracing::info!(
            "[mitm-agent] llm store loaded ({} credential(s), {agents} agent(s), keys {})",
            creds.len(),
            if plain_keys { "plain" } else { "at the proxy" }
        );
    }
    app.contracts.credentials.add(Arc::new(LlmCredentials(llm.clone())));
    // Doctor's own model calls (W5): a credential by id, refreshed first when due. Firewall-local,
    // never in a heartbeat or command result.
    app.contracts
        .doctor_credential
        .set(Arc::new(llm::LlmDoctor(llm.clone())));
    // What a recovery restore must find empty (`eligibility` in `index.ts`): the channels assigned
    // to an agent and the agents on one of the owner's own model credentials (the plan's included
    // key does not count: the console issues it again). A store that cannot be read may hold one, so it is
    // a refusal, not zero.
    if let Some(core) = &core {
        let (ch, l) = (channels.clone(), llm.clone());
        let _ = core.restore_bound.set(Arc::new(move || {
            restore_bound(ch.ready(), &ch.summary(), l.ready().then(|| l.agents_using_models()))
        }));
    }

    let l = llm.clone();
    reg.commands.handle("llm.propose", move |p| {
        let l = l.clone();
        async move { finish(l.propose(p).await) }
    });
    let l = llm.clone();
    reg.commands.handle("llm.confirm", move |p| {
        let l = l.clone();
        async move { finish(l.confirm(p).await) }
    });
    let l = llm.clone();
    reg.commands.handle("llm.cancel", move |p| {
        let l = l.clone();
        async move { finish(l.cancel(p).await) }
    });
    let l = llm.clone();
    reg.commands.handle("llm.push", move |p| {
        let l = l.clone();
        async move { finish(l.push(p).await) }
    });

    contracts_fill::feature(app, "included_ai", || true);
    // `credentials` in the beat's inventory: the model credentials, by id and provider.
    let l = llm.clone();
    contracts_fill::inventory(app, "credentials", move || {
        Some(
            l.summary()
                .0
                .iter()
                .map(|c| json!({"id": c.id, "provider": c.provider}))
                .collect(),
        )
    });
    // `included_ai`: which included-AI credential this firewall holds (null after a rebuild, so a
    // new key is sent). The `features` list is the beat's own (W3's `index.ts` part).
    let l = llm.clone();
    reg.commands.status(&["included_ai"], move || {
        let mut m = Map::new();
        m.insert(
            "included_ai".into(),
            l.included_credential_id().map_or(Value::Null, Value::String),
        );
        m
    });
    let (l, inc, ch) = (llm.clone(), included.clone(), channels.clone());
    reg.commands.reports(move || {
        let mut r = ch.drain_reports();
        r.extend(l.drain_reports());
        r.extend(inc.drain_reports());
        r
    });

    // The content rules pin the model their policies were accepted with; the judge reads it here.
    let content_slot: Arc<std::sync::OnceLock<Arc<content_rules::firewall::ContentRulesFirewall>>> = Arc::default();
    let pin: Arc<dyn Fn() -> Option<ai::judge::AiPin> + Send + Sync> = {
        let slot = content_slot.clone();
        Arc::new(move || slot.get().and_then(|c| c.ai_pin()))
    };
    let ai = ai::register(reg, app, llm.clone(), pin.clone());
    // The firewall's AI where W5's integration rules and MCP catalog ask it.
    match &ai {
        Some((judge, _)) => app.contracts.judge.set(Arc::new(IntegrationAi {
            judge: judge.clone(),
            pin,
        })),
        None => tracing::error!(
            "[ai] no AI judge on this firewall: integration rule sentences are not judged and MCP tools are not labelled"
        ),
    }
    // Phone and meetings run on ControlClaw's Twilio account and speech billing: off in a
    // standalone firewall (plan §8, "later").
    if app.config.mode.saas() {
        let ch = channels.clone();
        phone::register(
            reg,
            app,
            Arc::new(agent.clone()),
            Arc::new(move || ch.code_routes_checked()),
            llm.clone(),
        );
    }
    // Secrets and email-rule codes are typed on their cards or read out over MCP: no buttons.
    register_secrets(
        reg,
        app,
        agent.clone(),
        contracts_fill::codes_for(app, "secrets", true),
        channels.clone(),
    );
    let (google, google_http) = {
        let ch = channels.clone();
        google_drive::register(
            reg,
            app,
            Arc::new(agent.clone()),
            Arc::new(move || ch.code_routes_checked()),
            sync_now(app),
        )
    };
    let (agentmail, email_rules) = {
        let ch = channels.clone();
        email::register(
            reg,
            app,
            Arc::new(agent.clone()),
            contracts_fill::codes_for(app, "email", true),
            Arc::new(move || ch.code_routes_status()),
            sync_now(app),
            google.clone().zip(google_http),
        )
    };
    if app.config.mode.saas() {
        meetings::register(
            reg,
            app,
            Arc::new(agent.clone()),
            llm.clone(),
            google.clone(),
            agentmail.clone(),
            email_rules,
        );
    }
    // Words the TS sends whatever is set up: what meetings and phone settings may carry.
    for word in [
        "speech_families",
        "speech_wake",
        "speech_wake_sessions",
        "meeting_followup",
        "meeting_instructions",
        "speech_always",
        "meeting_full_agent",
        "meeting_present",
        "meeting_consult_model",
    ] {
        contracts_fill::feature(app, word, || true);
    }
    content_rules::register(
        reg,
        app,
        content_rules::ContentDeps {
            channels: channels.clone(),
            buttons: buttons.clone(),
            buttons_up: buttons_up.clone(),
            ai,
            agentmail,
            slot: content_slot,
        },
    );

    let l = llm.clone();
    let every = Duration::from_millis(env_ms("LLM_REFRESH_POLL_MS", 60_000).max(1));
    tokio::spawn(async move {
        loop {
            l.refresh_due().await;
            tokio::time::sleep(every).await;
        }
    });
}

/// Firewall-held custom secrets (`secrets.ts`).
fn register_secrets(
    reg: &mut Registry,
    app: &Arc<App>,
    agent: Arc<agent::AgentClient>,
    codes: Arc<dyn Fn() -> Option<Arc<dyn crate::contracts::ConsentCodes>> + Send + Sync>,
    channels: Arc<chan::ChannelsFirewall>,
) {
    // The module itself is what the revocation reads, so it is set once it exists.
    let me: Arc<std::sync::OnceLock<Arc<secrets::SecretsFirewall>>> = Arc::default();
    let changed = {
        let me = me.clone();
        Arc::new(move || -> cc_http::BoxFuture<()> {
            let me = me.clone();
            Box::pin(async move {
                // Revocation must not wait for the console: only this firewall's own secret
                // entries are replaced in the last config, at once (`index.ts` 985-995).
                let (Some(core), Some(s)) = (crate::core::core(), me.get().cloned()) else {
                    return;
                };
                let is_mine = |c: &Value| c.get("secret_name").is_some_and(crate::core::sync::js_truthy);
                if let Err(e) = core.sync.replace_credentials(is_mine, move || s.credentials()).await {
                    tracing::error!("[secrets] proxy config not rewritten: {e}");
                }
            })
        })
    };
    let secrets = match secrets::SecretsFirewall::new(secrets::SecretsOptions {
        store_path: PathBuf::from("/opt/controlclaw/state/secrets.enc"),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent: Arc::new(agent),
        codes,
        code_routes: Arc::new(move || channels.code_routes_status()),
        on_credentials_changed: changed,
    }) {
        Ok(s) => s,
        Err(_) => {
            tracing::error!("[secrets] encrypted store unavailable; commands disabled");
            return;
        }
    };
    let _ = me.set(secrets.clone());
    contracts_fill::feature(app, "secrets", || true);
    app.contracts
        .credentials
        .add(Arc::new(SecretCredentials(secrets.clone())));
    for action in ["read", "propose", "confirm", "cancel", "retry"] {
        let s = secrets.clone();
        reg.commands.handle(&format!("secrets.{action}"), move |p| {
            let s = s.clone();
            async move { s.command(action, p).await }
        });
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            secrets.reconcile().await;
        }
    });
}

#[cfg(test)]
mod wiring_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn a_restore_counts_assigned_channels_and_model_agents_and_refuses_an_unread_store() {
        let channels = [
            json!({"id": "c1", "assignedVmId": "vm-1"}),
            json!({"id": "c2", "assignedVmId": null}),
            json!({"id": "c3", "assignedVmId": ""}),
        ];
        assert_eq!(restore_bound(true, &channels, Some(2)), Some(3));
        assert_eq!(restore_bound(true, &[], Some(0)), Some(0));
        assert_eq!(restore_bound(false, &[], Some(0)), None);
        assert_eq!(restore_bound(true, &[], None), None, "a model store that was not read");
    }

    struct Counted(Arc<AtomicUsize>);

    impl crate::contracts::CredentialsSync for Counted {
        fn changed(&self) -> cc_http::BoxFuture<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    #[tokio::test]
    async fn a_credential_change_goes_through_the_credentials_sync_when_the_build_has_one() {
        let d = tempfile::tempdir().expect("dir");
        let app = crate::integrations::testing::app(d.path());
        let changed = sync_now(&app);
        // No sync on this build and no core: nothing to call, nothing breaks.
        changed().await;
        let n = Arc::new(AtomicUsize::new(0));
        app.contracts.credentials_sync.set(Arc::new(Counted(n.clone())));
        changed().await;
        changed().await;
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_integration_judge_slot_answers_from_the_ai_judge_and_the_content_rules_pin() {
        use crate::contracts::IntegrationJudge as _;
        let client = Arc::new(ai::model::AiClient::new(
            Arc::new(|| None),
            Arc::new(|_: &str| None),
            Arc::new(ai::model::LiveModels),
            Arc::new(|| 0),
        ));
        let pin: Arc<std::sync::Mutex<Option<ai::judge::AiPin>>> = Arc::default();
        let p = pin.clone();
        let judge = Arc::new(ai::judge::AiJudge::new(ai::judge::JudgeOptions {
            client,
            grants: None,
            grant_ttl_seconds: 300,
            policy_pin: Arc::new(|| None),
            now: Arc::new(|| 0),
        }));
        let slot = IntegrationAi {
            judge,
            pin: Arc::new(move || p.lock().unwrap_or_else(|e| e.into_inner()).clone()),
        };
        // No AI set up: it cannot answer, and the gate decides without it.
        let fits = slot
            .integration_fits("vm-1", "only reads", "github", "list_issues", &json!({}))
            .await;
        assert_eq!(fits, "unavailable");
        assert_eq!(slot.label_tool("srv", "delete_repo", None, &[]).await, None);
        // A new pin is a new epoch, so the tools are labelled again.
        assert_eq!(slot.label_epoch(), "null");
        *pin.lock().unwrap_or_else(|e| e.into_inner()) = Some(ai::judge::AiPin {
            provider: cc_llm::Provider::VercelGateway,
            model: "typesafe-ai/jev".into(),
            key_fingerprint: None,
        });
        assert!(slot.label_epoch().contains("typesafe-ai/jev"), "{}", slot.label_epoch());
    }
}
