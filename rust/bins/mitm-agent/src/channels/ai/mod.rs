//! The firewall's AI (apps/saas/docs/features/ai-firewall-review.md): the inline judge the proxy
//! calls on `127.0.0.1:3101` (`judge.rs`), the review after the fact and the scan (`review.rs`),
//! their history on this box (`trace_store.rs`), and `ai.scan`. The model is the organization's
//! own: the settings come with the egress rules (W3's sync), the key from the LLM store.

pub mod history;
#[cfg(test)]
mod history_tests;
pub mod judge;
pub mod model;
pub mod questions;
pub mod review;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod tests;
pub mod trace_store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, json};

use self::judge::{AiJudge, Grants, JudgeOptions};
use self::model::{AiClient, LiveModels};
use self::review::{AiReviewer, AiScanner, ReviewerOptions, ScannerOptions, findings_poster};
use self::trace_store::{AiReviewTraceStore, TraceSink};
use super::llm::Llm;
use super::{env_ms, env_or, now_ms};
use crate::app::{App, Registry};
use crate::commands::CommandOutcome;
use crate::core::log_tail::LogTail;

/// W3's `grants.json` writer.
struct CoreGrants(Arc<crate::core::grants::GrantStore>);

impl Grants for CoreGrants {
    fn set(&self, id: &str, expires_at: u64, scope: &str, by_ai: bool) {
        self.0.set(id, expires_at, scope, by_ai);
    }
}

/// The hostname of a URL, for the hosts the review never looks at.
fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(str::to_string)
}

/// The judge and the client, for the content rules' policies. `policy_pin` is the model and key
/// the content rules accepted with a code.
pub fn register(
    reg: &mut Registry,
    app: &Arc<App>,
    llm: Arc<Llm>,
    policy_pin: Arc<dyn Fn() -> Option<judge::AiPin> + Send + Sync>,
) -> Option<(Arc<AiJudge>, Arc<AiClient>)> {
    let Some(core) = crate::core::core() else {
        tracing::error!("[ai] the firewall core is not running; the AI review is off");
        return None;
    };
    let settings = {
        let core = core.clone();
        Arc::new(move || core.sync.ai_settings()) as model::SettingsFn
    };
    let key_for = {
        let llm = llm.clone();
        Arc::new(move |id: &str| llm.token_for(id)) as model::KeyFn
    };
    let now: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(now_ms);
    let client = Arc::new(AiClient::new(settings, key_for, Arc::new(LiveModels), now.clone()));

    // Inline review: loopback only, so only the proxy on this box can ask.
    let judge = Arc::new(AiJudge::new(JudgeOptions {
        client: client.clone(),
        grants: Some(Arc::new(CoreGrants(core.grants.clone()))),
        grant_ttl_seconds: core.env.permission_ttl,
        // The content rules say which model and key their policies were accepted with. Until they
        // load, no model is pinned and every AI policy check fails closed ("unpinned").
        policy_pin,
        now: now.clone(),
    }));
    let raw = env_or("AI_JUDGE_PORT", "3101");
    let port: u16 = match raw.trim().parse::<i64>() {
        Ok(p) if p <= 0 => 0,
        Ok(p) => u16::try_from(p).unwrap_or_else(|_| {
            tracing::error!("[ai] judge server: AI_JUDGE_PORT {raw} is not a port");
            0
        }),
        Err(_) => 0,
    };
    if port > 0 {
        let router = Arc::new(judge::router(judge.clone()));
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                Ok(l) => {
                    tracing::info!("[mitm-agent] ai judge listening on 127.0.0.1:{port}");
                    cc_http::serve(l, router).await;
                }
                Err(e) => tracing::error!("[ai] judge server: {e}"),
            }
        });
    }

    // The review's history: every model call, on this box only.
    let trace_dir = PathBuf::from(env_or("AI_TRACE_DIR", "/opt/controlclaw/state/ai-review-traces"));
    let traces: Option<Arc<AiReviewTraceStore>> = match AiReviewTraceStore::new(
        trace_dir,
        &app.box_key,
        &app.config.org_id,
        &app.config.box_id,
        Arc::new(cc_crypto::enc_file::encrypted_secret_values),
        now.clone(),
    ) {
        Ok(t) => Some(Arc::new(t)),
        Err(e) => {
            tracing::error!("[ai] review history would not start: {e}");
            None
        }
    };
    if let Some(t) = traces.clone() {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
                if let Err(e) = t.prune() {
                    tracing::error!("[ai] trace prune: {e}");
                }
            }
        });
    }
    // The history page: one agent's runs, opened from the console (`index.ts` 1920, 2071).
    if let Some(t) = traces.clone() {
        let agent_name = {
            let app = app.clone();
            Arc::new(move |vm: &str| app.contracts.identities.require().ok()?.agent(vm)?.name)
        };
        let page = history::AiReviewHistory::new(app, t, agent_name, now.clone());
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, p| history::owns(p),
            move |req, _| {
                let p = page.clone();
                async move { p.handle(req).await }
            },
        );
        // Offered only with a way in, as the TS's `access?.ready()`.
        let app = app.clone();
        core.beat.feature("ai_review_history", move || {
            app.contracts.page_access.get().is_some_and(|a| a.origin().is_some())
        });
    }
    let trace: Option<Arc<dyn TraceSink>> = traces.map(|t| t as Arc<dyn TraceSink>);

    // The review after the fact: needs the traffic log and somewhere to post findings.
    let env = &core.env;
    let scanner: Option<Arc<AiScanner>> =
        if !env.activity_url.is_empty() && !env.traffic_log_path.is_empty() && core.uses_http {
            let post = findings_poster(app.console.clone(), env.activity_url.clone());
            // The boxes' own calls to ControlClaw are not the agent's doing; never review them.
            let mut ignore_hosts: Vec<String> = Vec::new();
            for u in [&env.activity_url, &env.rules_url, &env.store_url] {
                if u.starts_with("http")
                    && let Some(h) = host_of(u)
                    && !ignore_hosts.contains(&h)
                {
                    ignore_hosts.push(h);
                }
            }
            let log = env.traffic_log_path.clone();
            let cursor = env_or("AI_CURSOR_PATH", &format!("{log}.ai-cursor"));
            let state = env_or("AI_SCAN_STATE_PATH", &format!("{log}.ai-scan.json"));
            let reviewer = Arc::new(AiReviewer::new(
                ReviewerOptions {
                    client: client.clone(),
                    post: post.clone(),
                    ignore_hosts: ignore_hosts.clone(),
                    trace: trace.clone(),
                    now: now.clone(),
                },
                LogTail::new(&log, &cursor, None),
            ));
            let scanner = Arc::new(AiScanner::new(ScannerOptions {
                log_path: PathBuf::from(&log),
                state_path: PathBuf::from(state),
                client: client.clone(),
                post,
                ignore_hosts,
                trace,
                now: now.clone(),
            }));
            tracing::info!("[mitm-agent] ai review loop enabled (runs when the org turns it on)");
            let every = Duration::from_millis(env_ms("AI_REVIEW_POLL_MS", 60_000).max(1));
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(every).await;
                    reviewer.tick().await;
                }
            });
            let s = scanner.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    s.maybe_scan().await;
                }
            });
            Some(scanner)
        } else {
            None
        };

    crate::channels::contracts_fill::feature(app, "ai_log_review", || true);

    let out = Some((judge.clone(), client.clone()));
    reg.commands.handle("ai.scan", move |_| {
        let (scanner, client) = (scanner.clone(), client.clone());
        async move {
            let Some(scanner) = scanner else {
                return CommandOutcome::failed("unavailable", "The traffic log is not set up on this firewall.");
            };
            if !client.review_on() {
                return CommandOutcome::failed("off", "AI Log Review is off or its key is not on the firewall yet.");
            }
            match scanner.scan().await {
                None => CommandOutcome::failed("failed", "The scan could not run; try again in a minute."),
                Some((findings, agents)) => {
                    let mut data = Map::new();
                    data.insert("findings".into(), json!(findings));
                    data.insert("agents".into(), json!(agents));
                    CommandOutcome {
                        ok: true,
                        status: "done".into(),
                        message: Some(format!("Scanned {agents} agent(s), {findings} finding(s).")),
                        data: Some(data),
                    }
                }
            }
        }
    });
    out
}
