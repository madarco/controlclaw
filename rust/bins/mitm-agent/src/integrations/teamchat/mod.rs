//! Team chat on the firewall: the ClickClack server every agent and every person of the
//! organization is in, the 3930 gate the agents reach it through, the people's way in on the
//! ingress, and the counts for the console's Overview.

pub mod api;
pub mod firewall;
pub mod gate;
pub mod helper;
pub mod stats;
pub mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Map;

use crate::app::{App, Registry};
use crate::integrations::{Env, Shared, js};

pub const ACTIONS: &[&str] = &["propose", "confirm", "cancel", "disable", "push", "forget"];

/// `content: () => contentRules ?? (contentRulesWillRun() ? "unknown" : null)`.
fn chat_content(app: &Arc<App>) -> gate::ChatContentNow {
    let will_run = !app.config.pool_marker.exists() && !app.config.firewall_url.is_empty();
    match app.contracts.chat_content.get() {
        Some(c) if c.loaded() => gate::ChatContentNow::On(c),
        Some(_) => gate::ChatContentNow::Unknown,
        None if will_run => gate::ChatContentNow::Unknown,
        None => gate::ChatContentNow::Off,
    }
}

/// Team chat runs where agents can reach this firewall's private address (`CONNECTOR_GATE_BIND`).
pub fn register(reg: &mut Registry, app: &Arc<App>, env: &Env, shared: &Shared) {
    let bind = env.gate_bind();
    if bind.is_empty() {
        return;
    }
    let Some(origin) = url::Url::parse(&app.config.firewall_url)
        .ok()
        .filter(|u| u.origin().is_tuple())
        .map(|u| u.origin().ascii_serialization())
    else {
        tracing::error!(
            "[mitm-agent] team chat module would not start, team chat commands disabled: no console address"
        );
        return;
    };
    let base = env.get("TEAMCHAT_URL", &format!("http://127.0.0.1:{}", firewall::TEAMCHAT_PORT));
    let gate_port: u16 = env.num("TEAMCHAT_GATE_PORT", firewall::TEAMCHAT_GATE_PORT);
    let api = Arc::new(api::ClickClack::new(&base));
    let keys = app.keys.clone();
    let chat = firewall::TeamChatFirewall::new(
        app,
        firewall::Options {
            path: PathBuf::from(env.get("TEAMCHAT_STORE_PATH", "/opt/controlclaw/state/teamchat.enc")),
            api: api.clone(),
            helper: Arc::new(helper::SudoHelper {
                path: env.get("TEAMCHAT_HELPER", helper::TEAMCHAT_HELPER),
                runner: app.runner.clone(),
            }),
            gateway_url: format!("http://{bind}:{gate_port}"),
            home_url: format!("{origin}/dashboard/team-chat"),
            hostname: Arc::new(move || keys.read("vm_hostname").filter(|h| !h.is_empty())),
            now: Arc::new(js::now_ms),
            sleep: Arc::new(|d| Box::pin(tokio::time::sleep(d))),
        },
    );
    tracing::info!(
        "[mitm-agent] team chat {}",
        if chat.available() {
            if chat.enabled() { "on" } else { "off" }
        } else {
            "not installed on this box"
        }
    );
    for action in ACTIONS {
        let c = chat.clone();
        reg.commands.handle(&format!("teamchat.{action}"), move |p| {
            let c = c.clone();
            async move { c.handle(action, p).await }
        });
    }
    let c = chat.clone();
    reg.commands.status(&["team_chat"], move || {
        let mut m = Map::new();
        if c.available() {
            m.insert("team_chat".into(), c.status());
        }
        m
    });
    web::route(reg, web::TeamChatWeb::new(app, chat.clone()));
    // `teamChat?.available() && teamChatWeb && access?.ready()`: ClickClack is installed here and
    // people can be signed in to it.
    let c = chat.clone();
    super::feature(app, "team_chat", move || c.available() && super::access_ready());

    // Reconcile every minute, and now.
    let c = chat.clone();
    tokio::spawn(async move {
        loop {
            c.reconcile().await;
            tokio::time::sleep(Duration::from_millis(firewall::TEAMCHAT_RECONCILE_MS)).await;
        }
    });

    let target = url::Url::parse(&base)
        .ok()
        .map(|u| (u.host_str().unwrap_or("127.0.0.1").to_string(), u.port().unwrap_or(80)))
        .unwrap_or(("127.0.0.1".into(), firewall::TEAMCHAT_PORT));
    let traffic = env.get("TRAFFIC_LOG_PATH", "");
    let c = chat.clone();
    let a = app.clone();
    let g = gate::TeamChatGate::new(gate::GateOptions {
        target,
        resolve: Arc::new(move |p| c.resolve(p)),
        locked: shared.locked.clone(),
        content: Arc::new(move || chat_content(&a)),
        log_path: (!traffic.is_empty()).then(|| PathBuf::from(traffic)),
    });
    let router = Arc::new(g.router());
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind((bind.as_str(), gate_port)).await {
            Ok(l) => {
                tracing::info!("[mitm-agent] team chat gate listening on {bind}:{gate_port}");
                cc_http::serve(l, router).await;
            }
            Err(e) => tracing::error!("[teamchat] gate: {e}"),
        }
    });

    // The Overview tab's counts: per channel and interval, never a message's text.
    let activity = env.get("ACTIVITY_URL", "");
    if !activity.is_empty() {
        let counter = stats::TeamChatCounter::new(
            PathBuf::from(env.get("TEAMCHAT_STATS_PATH", "/opt/controlclaw/state/teamchat-stats.json")),
            chat.clone(),
            api,
            stats::poster(app, activity),
            Arc::new(js::now_ms),
        );
        chat.counting.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(stats::TEAMCHAT_STATS_MS)).await;
                counter.tick().await;
            }
        });
    }
}
