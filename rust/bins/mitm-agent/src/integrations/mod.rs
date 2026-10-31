//! W5: integrations, logins and Doctor on the firewall (docs/plans/rust-workstreams/W5.md):
//! connectors, MCP servers and their rules, team chat, website logins, Doctor and the final check,
//! the gates on the private address (3900, 3930, 3940) and the MCP checks the proxy calls (8796).

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::app::{App, Registry};
use crate::commands::CommandOutcome;

pub mod apps_rules;
pub mod call_asks;
pub mod codes;
pub mod connectors;
pub mod doctor;
pub mod go_json;
pub mod js;
pub mod logins;
pub mod mcp;
pub mod ordmap;
pub mod teamchat;
#[cfg(test)]
pub mod testing;
pub mod tools_gate;

/// The environment, read once (the TS reads `process.env` at module load).
pub struct Env;

impl Env {
    pub fn get(&self, name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_string())
    }

    /// `parseInt(process.env.X ?? "default", 10)`, the default when it does not parse.
    pub fn num<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
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

    /// `CONNECTOR_GATE_BIND ?? PRIVATE_IP ?? ""`: the private address every gate listens on.
    pub fn gate_bind(&self) -> String {
        std::env::var("CONNECTOR_GATE_BIND")
            .or_else(|_| std::env::var("PRIVATE_IP"))
            .unwrap_or_default()
    }
}

/// The gates' addresses: the private one (`gate_bind`), and the firewall's tunnel address when it
/// runs WireGuard and that is not the same (remote agents dial the gates through the tunnel). With
/// no private address, the tunnel's is the gates' address.
pub(crate) fn gate_binds(app: &App, primary: String) -> (String, Option<String>) {
    let tunnel = if app.config.mode.standalone() {
        crate::core::local_pair::tunnel_address(&app.config.keys_dir).map(|a| a.to_string())
    } else {
        None
    };
    pick_binds(primary, tunnel)
}

fn pick_binds(primary: String, tunnel: Option<String>) -> (String, Option<String>) {
    match (primary.is_empty(), tunnel) {
        (true, Some(t)) => (t, None),
        (false, Some(t)) if t != primary => (primary, Some(t)),
        (_, _) => (primary, None),
    }
}

/// A gate's listener. On a standalone firewall an address that is not on this machine yet (the
/// tunnel's, before `wg-quick` brings it up) is tried again every 5 s; anything else, and any error
/// on a managed box, is logged once (`failed` and the error) and ends it. `up` is set while it serves.
pub(crate) fn serve_gate(
    app: &App,
    addr: String,
    port: u16,
    router: Arc<cc_http::Router>,
    listening: String,
    failed: &'static str,
    up: Option<Arc<std::sync::atomic::AtomicBool>>,
) {
    let retry = app.config.mode.standalone();
    tokio::spawn(async move {
        let mut said = false;
        loop {
            match tokio::net::TcpListener::bind((addr.as_str(), port)).await {
                Ok(l) => {
                    tracing::info!("{listening}");
                    if let Some(u) = &up {
                        u.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    cc_http::serve(l, router).await;
                    if let Some(u) = &up {
                        u.store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                    return;
                }
                Err(e) if retry && e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                    if !said {
                        said = true;
                        tracing::warn!("{failed} {addr} is not on this machine yet: trying again every 5s");
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    tracing::error!("{failed} {e}");
                    return;
                }
            }
        }
    });
}

/// What the gates and the MCP checks share: the rules, the content rules, the permission path and
/// the emergency stop, each looked up when a call needs it.
pub struct Shared {
    pub rules: Arc<dyn Fn() -> connectors::gate::RulesNow + Send + Sync>,
    pub content: Arc<dyn Fn() -> connectors::gate::ContentNow + Send + Sync>,
    pub asks: Option<Arc<dyn call_asks::Asks>>,
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

impl Shared {
    pub(crate) fn new(app: &Arc<App>, env: &Env, rules: Arc<apps_rules::firewall::AppRulesFirewall>) -> Self {
        let pending = env.get("PENDING_PATH", "");
        let asks: Option<Arc<dyn call_asks::Asks>> = (!pending.is_empty()).then(|| {
            Arc::new(call_asks::PendingFile {
                path: PathBuf::from(pending),
                app: app.clone(),
            }) as Arc<dyn call_asks::Asks>
        });
        // `contentRules ?? (contentRulesWillRun() ? "unknown" : null)`: content rules that should run
        // and are not up refuse every call.
        let will_run =
            !std::path::Path::new("/etc/controlclaw/pool-unclaimed").exists() && !app.config.firewall_url.is_empty();
        let a = app.clone();
        let content = Arc::new(move || match a.contracts.app_content.get() {
            Some(c) if c.loaded() => connectors::gate::ContentNow::On(c),
            Some(_) => connectors::gate::ContentNow::Unknown,
            None if will_run => connectors::gate::ContentNow::Unknown,
            None => connectors::gate::ContentNow::Off,
        });
        let b = app.clone();
        Self {
            rules: {
                let handle: Arc<dyn connectors::gate::GateRules> = Arc::new(apps_rules::firewall::Rules(rules));
                Arc::new(move || connectors::gate::RulesNow::On(handle.clone()))
            },
            content,
            asks,
            // No emergency stop on this build yet: whether an agent is stopped is not known, so it
            // counts as stopped. Fail closed.
            locked: Arc::new(move |vm| b.contracts.emergency_stop.get().is_none_or(|k| k.locked(vm))),
        }
    }
}

pub fn register(reg: &mut Registry, app: &Arc<App>) {
    let env = Env;
    // Integrations rules: app calls and calls to any MCP server, so they load on every firewall.
    let rules = apps_rules::firewall::AppRulesFirewall::new(
        app,
        PathBuf::from(env.get("APPS_RULES_PATH", "/opt/controlclaw/state/apps-rules.enc")),
    );
    tracing::info!(
        "[mitm-agent] integration rules loaded ({} rule(s))",
        rules.rules().len()
    );
    for action in ["read", "propose", "confirm", "cancel"] {
        let rules = rules.clone();
        reg.commands.handle(&format!("apps.{action}"), move |p| {
            let rules = rules.clone();
            async move { rules.handle(action, p).await }
        });
    }
    let shared = Shared::new(app, &env, rules);
    connectors::register(reg, app, &env, &shared);
    let login_tools = logins::register(reg, app, &env);
    mcp::register(reg, app, &env, &shared, login_tools);
    // Team chat, Doctor and its template checks are the console's: off in a standalone firewall.
    if app.config.mode.saas() {
        teamchat::register(reg, app, &env, &shared);
        doctor::register(reg, app, &env);
    }
}

/// A feature word on this app's beat (`index.ts` `features`), on W3's list.
pub fn feature(app: &Arc<App>, word: &'static str, on: impl Fn() -> bool + Send + Sync + 'static) {
    crate::channels::contracts_fill::feature(app, word, on);
}

/// `access?.ready()`: a page with no way in is not offered.
pub fn access_ready() -> bool {
    crate::core::pages::access().is_some_and(|a| a.ready())
}

pub fn outcome(ok: bool, status: &str, message: Option<String>, data: Option<Map<String, Value>>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.to_string(),
        message,
        data,
    }
}

/// A console call's failure as it may be logged: never the URL (`reqwest::Error` names it).
pub fn client_error(e: cc_client::ClientError) -> String {
    match e {
        cc_client::ClientError::Http(e) => format!("request failed: {}", e.without_url()),
        other => other.to_string(),
    }
}

/// A JSON answer with its length, as the TS writes them (`writeHead(status, {"content-type":
/// "application/json", "content-length"})`).
pub fn json_reply(status: u16, text: String) -> cc_http::Resp {
    let len = text.len();
    let mut r = cc_http::full(
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_GATEWAY),
        "application/json",
        text,
    );
    r.headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
    r
}

/// The object inside a JSON value; empty for anything else.
pub fn as_map(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// A handler that threw: `{ok: false, status: "failed", message}`.
pub fn failed(message: &str) -> CommandOutcome {
    outcome(false, "failed", Some(message.to_string()), None)
}

#[cfg(test)]
mod gate_bind_tests {
    use super::pick_binds;

    /// The private address and the tunnel's; the tunnel's alone when there is no private one.
    #[test]
    fn the_gates_listen_on_the_tunnel_too() {
        let t = || Some("10.77.0.1".to_string());
        assert_eq!(pick_binds("10.0.0.2".into(), t()), ("10.0.0.2".into(), t()));
        assert_eq!(pick_binds(String::new(), t()), ("10.77.0.1".into(), None));
        assert_eq!(pick_binds("10.77.0.1".into(), t()), ("10.77.0.1".into(), None));
        assert_eq!(pick_binds("10.0.0.2".into(), None), ("10.0.0.2".into(), None));
    }
}
