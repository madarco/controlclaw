//! Content rules (`content-rules.ts` and its siblings; apps/saas/docs/features/content-rules.md):
//! the rules store and its coded changes, the proxy's rules file, the holds and notices on 8794, the
//! webhook screen on W3's ingress, the checks the integrations ask (W5's `AppContent`), the stopped
//! record and the firewall's own page.

pub mod admission;
pub mod firewall;
pub mod page;
pub mod schema;
pub mod stopped;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Map, Value};

use self::firewall::{
    CheckError, Checked, ContentRulesFirewall, ContentRulesOptions, LivePoster, content_rule_activity,
};
use self::stopped::ContentStoppedStore;
use super::ai::judge::AiJudge;
use super::ai::model::AiClient;
use super::chan::ChannelsFirewall;
use super::chan::buttons::CodeButtons;
use super::content_engine::body_text;
use super::email::agentmail::AgentMailFirewall;
use super::{env_or, now_ms};
use crate::app::{App, Registry};
use crate::contracts::{AppContent, AppHold, ChatContent, ChatHold, CheckedRule, ContentError};

const CONTENT_AUDIT_PATH: &str = "/opt/controlclaw/mitm/logs/content-rules.jsonl";

/// What `register` takes from the modules built before it.
pub struct ContentDeps {
    pub channels: Arc<ChannelsFirewall>,
    pub buttons: Arc<CodeButtons>,
    pub buttons_up: Arc<std::sync::atomic::AtomicBool>,
    pub ai: Option<(Arc<AiJudge>, Arc<AiClient>)>,
    pub agentmail: Option<Arc<AgentMailFirewall>>,
    /// Filled here once the rules load: the AI judge reads the policies' pin through it.
    pub slot: Arc<OnceLock<Arc<ContentRulesFirewall>>>,
}

fn checked_rule(c: &Checked) -> CheckedRule {
    CheckedRule {
        id: c.rule.id.clone(),
        name: c.rule.name.clone(),
        action: c.rule.action.clone(),
        reason: c.rule.reason.clone(),
        by: c.by.map(str::to_string),
    }
}

/// A gate's view of the content rules, for one channel: the integrations (`apps`, the connector gate
/// and the MCP gates) and the team chat gate (`teamchat`, 3930) read the rules the same way.
struct Gate {
    fw: Arc<ContentRulesFirewall>,
    channel: &'static str,
}

impl Gate {
    fn loaded(&self) -> bool {
        !self.fw.unreadable()
    }
    fn applies(&self, direction: &str) -> bool {
        // Unknown rules apply to everything: the check then refuses.
        self.fw.applies(direction, self.channel).unwrap_or(true)
    }
    fn check(
        &self,
        direction: &str,
        text: String,
        vm_id: Option<String>,
        once: Option<String>,
    ) -> cc_http::BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        let (fw, channel, direction) = (self.fw.clone(), self.channel, direction.to_string());
        Box::pin(async move {
            match fw
                .check(&direction, channel, &text, vm_id.as_deref(), once.as_deref())
                .await
            {
                Ok(r) => Ok(r.as_ref().map(checked_rule)),
                Err(CheckError::Content(e)) => Err(e),
                Err(CheckError::Unknown) => Err(ContentError::Failed("the content rules are not known".into())),
            }
        })
    }
    fn stopped_here(&self, rule: &CheckedRule, direction: &str, vm_id: Option<&str>, text: &str, id: Option<&str>) {
        let c = Checked::from_contract(rule, direction);
        self.fw.stopped_here(&c, self.channel, direction, vm_id, text, id);
    }
}

impl AppContent for Gate {
    fn loaded(&self) -> bool {
        Gate::loaded(self)
    }
    fn applies(&self, direction: &str) -> bool {
        Gate::applies(self, direction)
    }
    fn body_text(&self, body: &[u8], content_type: &str) -> Option<String> {
        body_text(body, Some(content_type)).ok().flatten()
    }
    fn check(
        &self,
        direction: &str,
        text: String,
        vm_id: Option<String>,
    ) -> cc_http::BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        Gate::check(self, direction, text, vm_id, None)
    }
    fn record(
        &self,
        rule: &str,
        direction: &str,
        action: &str,
        vm_id: Option<&str>,
        extra: Map<String, Value>,
    ) -> Option<String> {
        self.fw
            .record(rule, self.channel, direction, action, vm_id, extra, None)
    }
    fn hold(&self, hold: AppHold) -> cc_http::BoxFuture<Option<String>> {
        let fw = self.fw.clone();
        Box::pin(async move { fw.hold_app(hold).await })
    }
    fn stopped_here(&self, rule: &CheckedRule, direction: &str, vm_id: Option<&str>, text: &str, id: Option<&str>) {
        Gate::stopped_here(self, rule, direction, vm_id, text, id);
    }
}

impl ChatContent for Gate {
    fn loaded(&self) -> bool {
        Gate::loaded(self)
    }
    fn applies(&self, direction: &str) -> bool {
        Gate::applies(self, direction)
    }
    fn check(
        &self,
        direction: &str,
        text: String,
        vm_id: Option<String>,
        once: Option<String>,
    ) -> cc_http::BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        Gate::check(self, direction, text, vm_id, once)
    }
    fn record(
        &self,
        rule: &str,
        direction: &str,
        action: &str,
        vm_id: Option<&str>,
        extra: Map<String, Value>,
        once: Option<&str>,
    ) -> Option<String> {
        self.fw
            .record(rule, self.channel, direction, action, vm_id, extra, once)
    }
    fn hold(&self, hold: ChatHold) -> cc_http::BoxFuture<Option<String>> {
        let fw = self.fw.clone();
        Box::pin(async move { fw.hold_team_chat(hold).await })
    }
    fn stopped_here(&self, rule: &CheckedRule, direction: &str, vm_id: Option<&str>, text: &str, id: Option<&str>) {
        Gate::stopped_here(self, rule, direction, vm_id, text, id);
    }
}

pub fn register(reg: &mut Registry, app: &Arc<App>, deps: ContentDeps) {
    let Some(core) = crate::core::core() else {
        tracing::error!("[content-rules] the firewall core is not running; content rules are off");
        return;
    };
    // A box with no control channel, or an unclaimed pool box, never builds the module: W3 settled
    // the proxy's file for it at start.
    if !crate::core::startup::content_rules_will_run(&app.config, &core.env) {
        return;
    }
    let proxy_dir = app.config.proxy_config_dir.clone();
    let now: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(now_ms);
    let stopped = match ContentStoppedStore::new(
        PathBuf::from(env_or("CONTENT_STOPPED_PATH", "/opt/controlclaw/state/content-stopped")),
        &app.box_key,
        &app.config.org_id,
        &app.config.box_id,
        now.clone(),
    ) {
        Ok(s) => {
            let s = Arc::new(s);
            // Holds live in memory: any still waiting on the record went with the last process.
            s.settle_waiting("restarted");
            let p = s.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    if let Err(e) = p.prune() {
                        tracing::error!("[content-rules] stopped: prune: {e}");
                    }
                }
            });
            Some(s)
        }
        Err(e) => {
            tracing::error!("[mitm-agent] the content rules record would not open, stopped texts are not kept: {e}");
            None
        }
    };
    let poster = match LivePoster::new() {
        Ok(p) => Arc::new(p),
        Err(e) => {
            tracing::error!(
                "[mitm-agent] content rules would not start, rule changes disabled and messages refused: {e}"
            );
            ContentRulesFirewall::mark_unknown(&proxy_dir);
            return;
        }
    };
    let codes = {
        let app = app.clone();
        Arc::new(move || app.contracts.code_service.get().map(|s| s.module(firewall::CODE_SCOPE)))
    };
    let code_routes = {
        let app = app.clone();
        Arc::new(move || {
            app.contracts
                .code_route_source
                .get()
                .filter(|s| s.ready())
                .map(|s| s.routes())
                .unwrap_or_default()
        })
    };
    let buttons = {
        let (b, up) = (deps.buttons.clone(), deps.buttons_up.clone());
        Arc::new(move || up.load(std::sync::atomic::Ordering::SeqCst).then(|| b.clone()))
    };
    let (judge, identity) = match deps.ai.clone() {
        Some((judge, client)) => {
            let j: firewall::JudgeFn = Arc::new(move |ask| {
                let judge = judge.clone();
                Box::pin(async move { judge.content(&ask).await })
            });
            (
                Some(j),
                Arc::new(move || client.identity()) as Arc<dyn Fn() -> _ + Send + Sync>,
            )
        }
        None => (None, Arc::new(|| None) as Arc<dyn Fn() -> _ + Send + Sync>),
    };
    let ch = deps.channels.clone();
    let ch2 = deps.channels.clone();
    let am = deps.agentmail.clone();
    let built = ContentRulesFirewall::new(ContentRulesOptions {
        store_path: PathBuf::from(env_or(
            "CONTENT_RULES_STORE_PATH",
            "/opt/controlclaw/state/content-rules.enc",
        )),
        proxy_dir: proxy_dir.clone(),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        codes,
        code_routes,
        buttons,
        audit_path: Some(PathBuf::from(CONTENT_AUDIT_PATH)),
        telegram_token: Arc::new(move |bot, vm| ch.telegram_token_for_agent(bot, vm)),
        slack_token: Some(Arc::new(move |vm, auth| ch2.slack_token_for_agent(vm, auth))),
        agentmail_key: Some(Arc::new(move |inbox, vm| {
            let a = am.as_ref()?;
            a.inboxes_of(vm)
                .iter()
                .any(|i| i == inbox)
                .then(|| a.inbox_key(inbox))
                .flatten()
        })),
        // No kill switch means no stream: an agent that cannot be checked counts as stopped.
        locked: Arc::new(|vm: &str| {
            crate::core::core()
                .and_then(|c| c.sync.hooks.kill.get().cloned())
                .is_none_or(|k| k.locked_vm_ids(&[vm.to_string()]).iter().any(|v| v == vm))
        }),
        poster,
        now: now.clone(),
        ask_ms: firewall::HOLD_ASK_MS,
        stopped: stopped.clone(),
        judge,
        ai_identity: identity,
    });
    let rules = match built {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                "[mitm-agent] content rules would not start, rule changes disabled and messages refused: {e}"
            );
            ContentRulesFirewall::mark_unknown(&proxy_dir);
            return;
        }
    };
    let _ = deps.slot.set(rules.clone());
    tracing::info!("[mitm-agent] content rules loaded ({} rule(s))", rules.rules().len());

    for action in ["read", "propose", "confirm", "cancel", "try"] {
        let r = rules.clone();
        reg.commands.handle(&format!("rules.{action}"), move |p| {
            let r = r.clone();
            async move { r.command(action, p).await }
        });
    }

    // Holds, notices, own messages and stopped texts from the proxy (8794, loopback only).
    {
        let router = Arc::new(admission::router(rules.clone()));
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(("127.0.0.1", cc_contracts::loopback::CONTENT_RULES_PORT)).await {
                Ok(l) => cc_http::serve(l, router).await,
                Err(_) => {
                    tracing::error!("[content-rules] hold listener unavailable; held messages are stopped instead")
                }
            }
        });
    }
    let r = rules.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            r.sweep();
        }
    });

    // Verified webhook deliveries, before they are forwarded.
    let r = rules.clone();
    let screen: crate::core::ingress::Screen = Arc::new(move |reg, body, ct, ce| {
        let r = r.clone();
        Box::pin(async move { r.screen_webhook(&reg.target.vm_id, &body, &ct, &ce).await })
    });
    let _ = core.ingress_screen.set(screen);

    // App calls, MCP servers and MCP checks (W5).
    app.contracts.app_content.set(Arc::new(Gate {
        fw: rules.clone(),
        channel: "apps",
    }));
    app.contracts.chat_content.set(Arc::new(Gate {
        fw: rules.clone(),
        channel: "teamchat",
    }));

    // Which rule acted, where and when, for the console's counts and Activity: metadata only, its
    // own cursor. The texts stay here.
    if !core.env.activity_url.is_empty() && core.uses_http {
        let r = rules.clone();
        let shipper = Arc::new(crate::core::activity::ActivityShipper::new(
            CONTENT_AUDIT_PATH,
            &PathBuf::from(format!("{CONTENT_AUDIT_PATH}.cursor")),
            &core.env.activity_url,
            core.sync.client.clone(),
            Some(Arc::new(move |line: &Value| {
                content_rule_activity(line, &|id| r.name_of(id))
            })),
            Vec::new(),
        ));
        let every = Duration::from_millis(core.env.activity_poll_ms);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                shipper.tick().await;
            }
        });
    }

    // The firewall's own page of what was held or stopped.
    if let Some(access) = crate::core::pages::access() {
        let identities = {
            let app = app.clone();
            Arc::new(move |vm: &str| app.contracts.identities.require().ok()?.agent(vm)?.name)
        };
        let firewall_url = app.config.firewall_url.clone();
        let console = Arc::new(move || {
            firewall_url
                .starts_with("http")
                .then(|| {
                    url::Url::parse(&firewall_url)
                        .ok()?
                        .join("/dashboard/security?type=messages")
                        .ok()
                })
                .flatten()
                .map(|u| u.to_string())
        });
        let page = Arc::new(page::ContentRulesPage::new(
            access.clone(),
            rules.clone(),
            stopped,
            identities,
            console,
            Arc::new(|| now_ms() as u64),
        ));
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, path| page::owns_content_page_path(path),
            move |req, _| {
                let p = page.clone();
                async move {
                    crate::core::fw_logs::page_response(p.handle(&crate::core::fw_logs::page_request(req).await).await)
                }
            },
        );
        crate::core::fw_shell::set_page(crate::core::fw_shell::FwPage::Content, || true);
        crate::channels::contracts_fill::feature(app, "open_fw_content_rules", move || access.ready());
    }
    crate::channels::contracts_fill::feature(app, "content_rules", || true);
}
