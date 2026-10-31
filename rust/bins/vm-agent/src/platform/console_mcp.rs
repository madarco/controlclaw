//! ControlClaw tools for agents (`console-mcp.ts`): `mcp.servers.controlclaw-console` at the
//! firewall's gate on the private network, written by this agent on every (re)connect and every
//! 15 minutes when missing, never removed. `controlclaw-logins` is added once the firewall answers
//! on its path. No secret: the gate knows this box by its address.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use cc_openclaw::config_queue::PatchOptions;
use serde_json::{Map, Value, json};

use super::common::{CONFIG_PATCH_RESTART, Deps, GATEWAY_READ, PRIVATE_IP, at};

pub const CONSOLE_MCP_NAME: &str = "controlclaw-console";
pub const CONSOLE_MCP_PORT: u16 = 3940;
pub const LOGINS_MCP_NAME: &str = "controlclaw-logins";
pub const ENSURE_EVERY: Duration = Duration::from_secs(15 * 60);

pub fn console_url(ip: Option<&str>) -> Option<String> {
    let ip = ip.unwrap_or_default().trim();
    PRIVATE_IP
        .is_match(ip)
        .then(|| format!("http://{ip}:{CONSOLE_MCP_PORT}/mcp"))
}

pub fn logins_url(ip: Option<&str>) -> Option<String> {
    let ip = ip.unwrap_or_default().trim();
    PRIVATE_IP
        .is_match(ip)
        .then(|| format!("http://{ip}:{CONSOLE_MCP_PORT}/logins/mcp"))
}

/// Whether an MCP server answers `initialize` at `url` (no proxy: the firewall is on the private
/// network). The answer's body is not read.
pub type Answers = Arc<dyn Fn(String) -> cc_http::BoxFuture<bool> + Send + Sync>;

pub fn mcp_answers(http: reqwest::Client) -> Answers {
    Arc::new(move |url: String| {
        let http = http.clone();
        Box::pin(async move {
            let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "controlclaw-vm-agent", "version": "1" } } });
            http.post(url)
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(body.to_string())
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
        })
    })
}

pub struct ConsoleMcpService {
    deps: Deps,
    firewall_ip: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    logins_served: Answers,
    running: tokio::sync::Mutex<()>,
    /// `consoleMcpConfigured()`, reported as `console_mcp`.
    configured: Arc<std::sync::atomic::AtomicBool>,
}

impl ConsoleMcpService {
    pub fn new(
        deps: Deps,
        firewall_ip: Arc<dyn Fn() -> Option<String> + Send + Sync>,
        logins_served: Answers,
        configured: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            deps,
            firewall_ip,
            logins_served,
            running: tokio::sync::Mutex::new(()),
            configured,
        }
    }

    /// Make sure the entry is there. Never fails; one run at a time (a second caller joins).
    pub fn ensure(self: &Arc<Self>) -> cc_http::BoxFuture<()> {
        let me = self.clone();
        Box::pin(async move {
            // `this.running ??= ...`: a caller during a run waits for that run, it does not start another.
            let Ok(_one) = me.running.try_lock() else {
                let _wait = me.running.lock().await;
                return;
            };
            me.run().await;
        })
    }

    async fn run(&self) {
        let ip = (self.firewall_ip)();
        let Some(url) = console_url(ip.as_deref()) else { return };
        let Some(w) = self.deps.client().filter(|w| w.gateway().connected()) else {
            return;
        };
        let result: Result<(), String> = async {
            let raw = self.deps.call("config.get", json!({}), GATEWAY_READ).await?;
            let servers = at(&raw, &["parsed", "mcp", "servers"])
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut want: Vec<(&str, String)> = vec![(CONSOLE_MCP_NAME, url)];
            if let Some(lu) = logins_url(ip.as_deref()) {
                let has = servers.get(LOGINS_MCP_NAME).and_then(|s| s.get("url")) == Some(&json!(lu));
                if has || (self.logins_served)(lu.clone()).await {
                    want.push((LOGINS_MCP_NAME, lu));
                }
            }
            let missing: Vec<&(&str, String)> = want
                .iter()
                .filter(|(n, u)| {
                    let have = servers.get(*n);
                    have.and_then(|h| h.get("url")) != Some(&json!(u))
                        || have.and_then(|h| h.get("transport")) != Some(&json!("streamable-http"))
                })
                .collect();
            if missing.is_empty() {
                self.configured.store(true, Ordering::Relaxed);
                return Ok(());
            }
            let mut entries = Map::new();
            for (n, u) in &missing {
                entries.insert((*n).to_string(), json!({ "url": u, "transport": "streamable-http" }));
            }
            let mut patch = Map::new();
            patch.insert("mcp".into(), json!({ "servers": entries }));
            let opts = PatchOptions {
                base_hash: raw
                    .get("hash")
                    .and_then(Value::as_str)
                    .filter(|h| !h.is_empty())
                    .map(str::to_string),
                snapshot: Some(raw.clone()),
                read_timeout: Some(GATEWAY_READ),
                ..PatchOptions::new(CONFIG_PATCH_RESTART)
            };
            w.patch(&patch, opts).await.map_err(|e| e.to_string())?;
            self.configured.store(true, Ordering::Relaxed);
            let names: Vec<String> = missing.iter().map(|(n, u)| format!("{n} ({u})")).collect();
            self.deps
                .log(&format!("[console-mcp] added to OpenClaw: {}", names.join(", ")));
            Ok(())
        }
        .await;
        if let Err(e) = result {
            self.deps.log(&format!(
                "[console-mcp] could not write the ControlClaw tools entry: {e}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};

    use super::super::llm::tests::rig;
    use super::*;

    #[test]
    fn the_url_is_the_firewalls_private_address_and_nothing_else() {
        assert_eq!(
            console_url(Some("10.0.0.2")).as_deref(),
            Some("http://10.0.0.2:3940/mcp")
        );
        assert_eq!(
            console_url(Some(" 10.0.0.2\n")).as_deref(),
            Some("http://10.0.0.2:3940/mcp")
        );
        assert_eq!(console_url(None), None);
        assert_eq!(console_url(Some("203.0.113.5")), None);
        assert_eq!(console_url(Some("10.0.0.2:80/evil")), None);
        assert_eq!(
            logins_url(Some("10.0.0.2")).as_deref(),
            Some("http://10.0.0.2:3940/logins/mcp")
        );
        assert_eq!(logins_url(Some("8.8.8.8")), None);
    }

    fn setup(
        config: Value,
        served: Arc<AtomicBool>,
        asked: Arc<Mutex<Vec<String>>>,
    ) -> (FakeOpenClawConfig, Arc<ConsoleMcpService>, Arc<AtomicBool>) {
        let oc = FakeOpenClawConfig::new(config, None, false);
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        let r = rig(gw);
        let configured = Arc::new(AtomicBool::new(false));
        let answers: Answers = Arc::new(move |u: String| {
            super::super::common::lock(&asked).push(u);
            let v = served.load(Ordering::SeqCst);
            Box::pin(async move { v })
        });
        let svc = Arc::new(ConsoleMcpService::new(
            r.deps.clone(),
            Arc::new(|| Some("10.0.0.2".into())),
            answers,
            configured.clone(),
        ));
        (oc, svc, configured)
    }

    #[tokio::test]
    async fn writes_the_entry_once_next_to_the_brains() {
        let (oc, svc, configured) = setup(
            json!({ "mcp": { "servers": { "gbrain": { "url": "http://10.0.0.9:3131/mcp", "transport": "streamable-http" } } } }),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Vec::new())),
        );
        assert!(!configured.load(Ordering::SeqCst));
        svc.ensure().await;
        let servers = oc.config()["mcp"]["servers"].clone();
        assert_eq!(
            servers[CONSOLE_MCP_NAME],
            json!({ "url": "http://10.0.0.2:3940/mcp", "transport": "streamable-http" })
        );
        assert!(servers.get("gbrain").is_some());
        assert!(configured.load(Ordering::SeqCst));
        svc.ensure().await;
        assert_eq!(
            oc.state().patches.len(),
            1,
            "a write restarts the gateway, so none for nothing"
        );
    }

    #[tokio::test]
    async fn the_login_tools_are_added_once_the_firewall_answers() {
        let served = Arc::new(AtomicBool::new(false));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (oc, svc, _) = setup(
            json!({ "mcp": { "servers": { "controlclaw-console": { "url": "http://10.0.0.2:3940/mcp", "transport": "streamable-http" } } } }),
            served.clone(),
            asked.clone(),
        );
        svc.ensure().await;
        assert!(oc.state().patches.is_empty(), "an older firewall: nothing to add");
        served.store(true, Ordering::SeqCst);
        svc.ensure().await;
        assert_eq!(
            oc.config()["mcp"]["servers"][LOGINS_MCP_NAME],
            json!({ "url": "http://10.0.0.2:3940/logins/mcp", "transport": "streamable-http" })
        );
        served.store(false, Ordering::SeqCst);
        svc.ensure().await;
        assert_eq!(
            oc.state().patches.len(),
            1,
            "an entry already there is not taken out on one missed answer"
        );
        assert_eq!(super::super::common::lock(&asked).len(), 2);
    }

    #[tokio::test]
    async fn a_failed_write_is_logged_not_thrown() {
        let oc = FakeOpenClawConfig::new(json!({}), None, false);
        let gw = Arc::new(FakeConfigGateway::new(oc, false));
        gw.hook(|_, _| Some(Err("boom".into())));
        let mut r = rig(gw);
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let l = lines.clone();
        r.deps.log = Arc::new(move |line| super::super::common::lock(&l).push(line.to_string()));
        let svc = Arc::new(ConsoleMcpService::new(
            r.deps.clone(),
            Arc::new(|| Some("10.0.0.2".into())),
            Arc::new(|_| Box::pin(async { false })),
            Arc::new(AtomicBool::new(false)),
        ));
        svc.ensure().await;
        assert!(
            super::super::common::lock(&lines)
                .join("\n")
                .contains("could not write")
        );
    }
}
