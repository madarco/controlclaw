//! How the firewall calls an agent box (`agent-client.ts`, `budgets.ts`): HTTPS to the agent's
//! hostname under `/__cc/agent` (on a standalone firewall, plain HTTP to the vm-agent at the
//! address pairing gave, [`AgentRoute`]), with a 30 s EdDSA token signed by this box's own key for exactly
//! that request (method, path, host, body hash, a fresh id), and a `purpose` the agent checks
//! against the route.
//!
//! Where a call goes is not a command's to say: a command names an agent by id, and the address
//! comes from this firewall's identity map (or its pin); an agent it does not know is not called.
//! Redirects are never followed: the token is for this host.

use std::sync::Arc;
use std::time::Duration;

use cc_auth::keys::KeysDir;
use cc_client::HttpClient;
use futures_util::StreamExt;
use serde_json::{Map, Value};

use super::identities::Agents;
use crate::contracts::{AGENT_PATH_PREFIX, AgentRoute};

// The firewall's half of the timeout chain (`budgets.ts`); `packages/vm-agent/src/budgets.ts` is
// the box's half, and each limit here sits above the box's own for the same work.
pub const COMMAND_BUDGET_MS: u64 = 100_000;
pub const AGENT_CALL_MS: u64 = 25_000;
pub const CHANNELS_APPLY_MS: u64 = 45_000;
pub const CONFIRM_APPLY_MS: u64 = 30_000;
pub const CONFIRM_POLL_MS: u64 = 2_000;
pub const CONFIRM_MIN_MS: u64 = 5_000;
pub const CONFIG_WRITE_MS: u64 = 90_000;
pub const APPROVE_MS: u64 = 70_000;
pub const LLM_PUSH_MS: u64 = 90_000;
pub const DEVICE_APPROVE_MS: u64 = 60_000;
pub const GBRAIN_CONNECT_MS: u64 = 30_000;
pub const KILL_WINDOW_SEND_MS: u64 = 45_000;
pub const KILL_WINDOW_RETRY_MS: u64 = 3_000;
pub const GBRAIN_APPLY_MS: u64 = 60_000;
pub const BACKUP_MS: u64 = 60 * 60_000;
/// What a bounded call (`/hooks/deliver`, `/phone/*`) reads of an answer.
const BOUNDED_BODY: usize = 128 * 1024;

/// `deadline`: `COMMAND_BUDGET_MS` from `started`, for a handler that calls a box more than once.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: tokio::time::Instant,
}

impl Deadline {
    pub fn new() -> Self {
        Self {
            at: tokio::time::Instant::now() + Duration::from_millis(COMMAND_BUDGET_MS),
        }
    }

    /// Milliseconds left, never negative.
    pub fn left(&self) -> u64 {
        self.at
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis() as u64
    }

    /// `ms`, or what is left of the budget when that is less.
    pub fn within(&self, ms: u64) -> u64 {
        ms.min(self.left())
    }
}

impl Default for Deadline {
    fn default() -> Self {
        Self::new()
    }
}

/// `purposeForPath`: the purpose a route takes, so a token minted for one cannot be used on another.
pub fn purpose_for_path(path: &str) -> &'static str {
    let starts = |p: &str| path.starts_with(p);
    if starts("/doctor/") {
        "doctor"
    } else if starts("/llm/") {
        "llm"
    } else if starts("/search/") {
        "search"
    } else if starts("/connectors/") {
        "connectors"
    } else if starts("/mcp-servers/") {
        "mcp-servers"
    } else if path == "/update" || starts("/update/") {
        "update"
    } else if starts("/backup/") {
        "backup"
    } else if starts("/ssh/") {
        "ssh"
    } else if starts("/tailscale/") {
        "tailscale"
    } else if starts("/drive/") {
        "drive"
    } else if starts("/phone/") {
        "phone"
    } else if starts("/secrets/") {
        "secrets"
    } else if starts("/logins/") {
        "logins"
    } else if starts("/agentmail/") {
        "agentmail"
    } else if starts("/google/") {
        "google"
    } else if starts("/hooks/") {
        "hooks"
    } else if path == "/devices" || starts("/devices/") {
        "devices"
    } else if starts("/kill/") {
        "kill"
    } else if starts("/access/") {
        "access"
    } else if starts("/meetings/") {
        "meetings"
    } else if starts("/gbrain/") {
        "gbrain"
    } else if path == "/apply/pending" || starts("/apply/pending?") {
        "apply-read"
    } else if path == "/apply/ticket" {
        "apply-ticket"
    } else if starts("/templates/check/") {
        "template-check"
    } else if starts("/templates/repair/") {
        "template-repair"
    } else if starts("/templates/capture/") {
        "template-capture"
    } else if starts("/disk/") {
        "disk"
    } else if starts("/health/") {
        "health"
    } else {
        "channels"
    }
}

/// The budget a route gets when the caller names none (`timeoutFor`).
fn timeout_for(path: &str, default_ms: u64) -> u64 {
    if path.starts_with("/backup/") {
        BACKUP_MS
    } else if path == "/channels/pairings/approve" {
        APPROVE_MS
    } else if path == "/channels/apply" {
        CHANNELS_APPLY_MS
    } else if [
        "/meetings/apply",
        "/agentmail/apply",
        "/search/apply",
        "/connectors/apply",
        "/mcp-servers/apply",
    ]
    .contains(&path)
    {
        CONFIG_WRITE_MS
    } else {
        default_ms
    }
}

/// Why no network answer came back, as the health check tells them apart (`reachErrorOf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    Refused,
    Dns,
    Tls,
    Timeout,
    Other,
}

/// A failed call. `Display` is the TS error's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// `AgentTimeoutError`: no answer in time. Says nothing about whether the work happened.
    Timeout,
    /// The agent answered with a non-2xx: `agent <status>: <detail>`, or the 503 sentence.
    Status { status: u16, message: String },
    /// No answer at all (`fetch failed`), with what the cause was.
    Network(NetError),
    /// Anything else, with its message (an unknown agent, an answer too large).
    Other(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Timeout => f.write_str("The agent did not answer in time."),
            AgentError::Status { message, .. } => f.write_str(message),
            AgentError::Network(_) => f.write_str("fetch failed"),
            AgentError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for AgentError {}

impl AgentError {
    /// `isAgentTimeout`.
    pub fn is_timeout(&self) -> bool {
        matches!(self, AgentError::Timeout)
    }

    /// `isAgentRefusal`: the agent ran the work and refused it (400 or 500), a definite outcome.
    pub fn is_refusal(&self) -> bool {
        matches!(self, AgentError::Status { status: 400 | 500, .. })
    }

    /// The status the agent answered with (503 for "not running"), or `None` when none came back.
    pub fn status(&self) -> Option<u16> {
        match self {
            AgentError::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// An agent as a command names it. The hostname is not used: the identity map says where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTarget {
    pub vm_id: String,
    pub hostname: String,
}

impl AgentTarget {
    pub fn new(vm_id: impl Into<String>, hostname: impl Into<String>) -> Self {
        Self {
            vm_id: vm_id.into(),
            hostname: hostname.into(),
        }
    }
}

/// Where a call goes, by agent id (`hostFor`); `None` for one this firewall does not know.
pub type HostFor = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Clone)]
pub struct AgentClient {
    keys: KeysDir,
    box_id: String,
    http: HttpClient,
    agents: Option<Arc<Agents>>,
    /// A look at the control plane's list for an agent created seconds ago (`onUnknown`).
    learn: Option<Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>>,
    default_ms: u64,
    /// Tests: where a hostname is served (`http://127.0.0.1:<port>`) instead of `https://<host>`.
    base_for: Option<HostFor>,
}

impl AgentClient {
    /// A client that calls agents at the addresses `agents` holds, looking at the control plane's
    /// list once (`learn`) for one it does not know.
    pub fn new(
        keys: KeysDir,
        box_id: &str,
        agents: Arc<Agents>,
        learn: Option<Arc<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>>,
    ) -> Result<Self, String> {
        Ok(Self {
            keys,
            box_id: box_id.to_string(),
            http: HttpClient::new(false).map_err(|e| e.to_string())?,
            agents: Some(agents),
            learn,
            default_ms: AGENT_CALL_MS,
            base_for: None,
        })
    }

    /// The same client with another default budget (`timeoutMs` on `makeAgentClient`).
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.default_ms = ms;
        self
    }

    #[cfg(test)]
    pub fn for_tests(keys: KeysDir, agents: Arc<Agents>, base_for: HostFor) -> Self {
        Self {
            keys,
            box_id: "fw_1".into(),
            http: HttpClient::new(false).expect("http"),
            agents: Some(agents),
            learn: None,
            default_ms: AGENT_CALL_MS,
            base_for: Some(base_for),
        }
    }

    fn route_for(&self, vm_id: &str) -> Option<AgentRoute> {
        self.agents.as_ref()?.route_for(vm_id)
    }

    pub async fn post(&self, agent: &AgentTarget, path: &str, body: &Value) -> Result<Map<String, Value>, AgentError> {
        self.request(agent, "POST", path, Some(body), None).await
    }

    pub async fn post_within(
        &self,
        agent: &AgentTarget,
        path: &str,
        body: &Value,
        timeout_ms: u64,
    ) -> Result<Map<String, Value>, AgentError> {
        self.request(agent, "POST", path, Some(body), Some(timeout_ms)).await
    }

    pub async fn get(&self, agent: &AgentTarget, path: &str) -> Result<Map<String, Value>, AgentError> {
        self.request(agent, "GET", path, None, None).await
    }

    pub async fn get_within(
        &self,
        agent: &AgentTarget,
        path: &str,
        timeout_ms: u64,
    ) -> Result<Map<String, Value>, AgentError> {
        self.request(agent, "GET", path, None, Some(timeout_ms)).await
    }

    async fn request(
        &self,
        agent: &AgentTarget,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout_ms: Option<u64>,
    ) -> Result<Map<String, Value>, AgentError> {
        let budget = Duration::from_millis(timeout_ms.unwrap_or_else(|| timeout_for(path, self.default_ms)));
        let started = tokio::time::Instant::now();
        let mut route = self.route_for(&agent.vm_id);
        if route.is_none()
            && let Some(learn) = &self.learn
        {
            learn().await;
            route = self.route_for(&agent.vm_id);
        }
        let Some(route) = route else {
            return Err(AgentError::Other(
                "This firewall does not know that agent. If it was just created, try again in a minute.".into(),
            ));
        };
        let left = budget.saturating_sub(started.elapsed());
        match tokio::time::timeout(left, self.send(agent, &route, method, path, body)).await {
            Ok(r) => r,
            Err(_) => Err(AgentError::Timeout),
        }
    }

    async fn send(
        &self,
        agent: &AgentTarget,
        route: &AgentRoute,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Map<String, Value>, AgentError> {
        let bounded = path == "/hooks/deliver" || path.starts_with("/phone/");
        let sent = body.map(|b| serde_json::to_vec(b).unwrap_or_default());
        let claims = cc_auth::sign::binding_claims(method, path, Some(&route.host), sent.as_deref());
        let token = cc_auth::sign::agent_token(&self.keys, &self.box_id, &agent.vm_id, purpose_for_path(path), claims)
            .map_err(|e| AgentError::Other(e.to_string()))?;
        let base = match &self.base_for {
            Some(f) => format!("{}{AGENT_PATH_PREFIX}", f(&route.host).unwrap_or_default()),
            None => route.base.clone(),
        };
        let url = format!("{base}{path}");
        let client = self.http.get();
        let mut req = if method == "POST" {
            client.post(&url)
        } else {
            client.get(&url)
        };
        req = req.bearer_auth(token);
        if let Some(b) = sent {
            req = req.header("content-type", "application/json").body(b);
        }
        let res = req.send().await.map_err(net_error)?;
        let status = res.status().as_u16();
        // A redirect is an error on a bounded call and an answer (not followed) on the rest.
        if bounded && (300..400).contains(&status) {
            return Err(AgentError::Network(NetError::Other));
        }
        let text = if bounded {
            let mut buf = Vec::new();
            let mut stream = res.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(net_error)?;
                buf.extend_from_slice(&chunk);
                if buf.len() > BOUNDED_BODY {
                    return Err(AgentError::Other("agent response too large".into()));
                }
            }
            String::from_utf8(buf)
                .map_err(|_| AgentError::Other("The encoded data was not valid for encoding utf-8".into()))?
        } else {
            res.text().await.map_err(net_error)?
        };
        let parsed = if text.is_empty() {
            Map::new()
        } else {
            match serde_json::from_str::<Value>(&text) {
                Ok(Value::Object(o)) => o,
                _ => Map::new(),
            }
        };
        if !(200..300).contains(&status) {
            let detail = match parsed.get("error") {
                Some(Value::String(s)) => s.clone(),
                // `text.slice(0, 200)` counts UTF-16 units.
                _ => String::from_utf16_lossy(&text.encode_utf16().take(200).collect::<Vec<u16>>()),
            };
            let message = if status == 503 {
                "The agent is not running. Start it and try again.".to_string()
            } else {
                format!("agent {status}: {detail}")
            };
            return Err(AgentError::Status { status, message });
        }
        Ok(parsed)
    }
}

/// What kind of network failure this was, for the health check (`reachErrorOf` reads the cause's
/// code). Read off the error's causes, not its own text, which names the URL and so the host.
fn net_error(e: reqwest::Error) -> AgentError {
    let mut kind = NetError::Other;
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind as K;
            kind = match io.kind() {
                K::ConnectionRefused | K::ConnectionReset | K::HostUnreachable | K::NetworkUnreachable => {
                    NetError::Refused
                }
                K::TimedOut => NetError::Timeout,
                _ if io.get_ref().is_some_and(|i| i.is::<rustls::Error>()) => NetError::Tls,
                _ => kind,
            };
        }
        if s.is::<rustls::Error>() {
            kind = NetError::Tls;
        }
        let text = s.to_string().to_lowercase();
        if kind == NetError::Other && (text.starts_with("dns error") || text.contains("failed to lookup address")) {
            kind = NetError::Dns;
        }
        source = s.source();
    }
    // reqwest's own timeout is only the connect one here (the call's budget is outside it): a
    // connection that never opened, not an answer that never came.
    if e.is_timeout() {
        kind = NetError::Timeout;
    }
    AgentError::Network(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    struct Seen {
        path: String,
        method: String,
        auth: String,
        body: Vec<u8>,
    }

    async fn agent_server(status: u16, answer: &'static str) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut router = cc_http::Router::new(&["all"]);
        router.route(
            "all",
            |_, _| true,
            move |req, _| {
                let s = s.clone();
                async move {
                    use http_body_util::BodyExt;
                    let (parts, body) = req.into_parts();
                    let raw = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                    s.lock().expect("lock").push(Seen {
                        path: parts.uri.path().to_string(),
                        method: parts.method.to_string(),
                        auth: cc_http::header(&parts, "authorization").unwrap_or_default().to_string(),
                        body: raw.to_vec(),
                    });
                    cc_http::full(
                        http::StatusCode::from_u16(status).expect("status"),
                        "application/json",
                        answer,
                    )
                }
            },
        );
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        (format!("http://{addr}"), seen)
    }

    fn claims(auth: &str) -> Value {
        use base64::Engine;
        let payload = auth.trim_start_matches("Bearer ").split('.').nth(1).expect("payload");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("b64");
        serde_json::from_slice(&raw).expect("json")
    }

    fn setup(base: &str) -> (tempfile::TempDir, AgentClient) {
        let d = tempfile::tempdir().expect("dir");
        cc_testkit::BoxKeys::write(&d.path().join("keys"), "fw_1", "fw.example").expect("keys");
        let agents = Arc::new(Agents::default());
        agents.set(&[json!({"vm_id": "vm-1", "hostname": "atlas.acme.ccl.bot"})]);
        let base = base.to_string();
        let c = AgentClient::for_tests(
            KeysDir::new(d.path().join("keys")),
            agents,
            Arc::new(move |_| Some(base.clone())),
        );
        (d, c)
    }

    /// A standalone firewall calls the vm-agent itself, at the address pairing gave: plain HTTP,
    /// no `/__cc/agent`, the token signed for that address. A SaaS firewall never takes it.
    #[tokio::test]
    async fn a_standalone_firewall_calls_the_vm_agent_where_pairing_said() {
        let (base, seen) = agent_server(200, "{\"ok\":true}").await;
        let d = tempfile::tempdir().expect("dir");
        cc_testkit::BoxKeys::write(&d.path().join("keys"), "fw_1", "fw.example").expect("keys");
        let agents = Arc::new(Agents::default());
        agents.set(&[
            json!({"vm_id": "vm-1", "private_ip": "10.0.0.3", "agent_addr": base.trim_start_matches("http://")}),
        ]);
        let c = AgentClient::new(KeysDir::new(d.path().join("keys")), "fw_1", agents.clone(), None).expect("client");
        let target = AgentTarget::new("vm-1", "");
        let err = c
            .post(&target, "/channels/apply", &json!({}))
            .await
            .expect_err("SaaS: no hostname");
        assert!(err.to_string().contains("does not know that agent"), "{err}");
        assert!(seen.lock().expect("lock").is_empty());
        agents.set_direct(true);
        c.post(&target, "/channels/apply", &json!({})).await.expect("ok");
        let seen = seen.lock().expect("lock").clone();
        assert_eq!(seen[0].path, "/channels/apply");
        let w = claims(&seen[0].auth);
        assert_eq!(
            (w["h"].clone(), w["p"].clone()),
            (json!("127.0.0.1"), json!("/channels/apply"))
        );
    }

    #[tokio::test]
    async fn calls_go_to_the_recorded_address_with_a_bound_token() {
        let (base, seen) = agent_server(200, "{\"ok\":true}").await;
        let (_d, c) = setup(&base);
        let out = c
            .post(
                &AgentTarget::new("vm-1", "evil.example"),
                "/channels/send",
                &json!({"type": "telegram", "to": "1", "text": "Código: 123 456"}),
            )
            .await
            .expect("ok");
        assert_eq!(out.get("ok"), Some(&json!(true)));
        c.get(&AgentTarget::new("vm-1", "x"), "/health/summary?fresh=1")
            .await
            .expect("ok");
        let seen = seen.lock().expect("lock").clone();
        assert_eq!(seen[0].path, "/__cc/agent/channels/send");
        let w = claims(&seen[0].auth);
        assert_eq!(w["h"], "atlas.acme.ccl.bot");
        assert_eq!(w["purpose"], "channels");
        assert_eq!(w["vmId"], "vm-1");
        assert_eq!(w["iss"], "fw_1");
        assert_eq!(w["m"], "POST");
        use sha2::Digest;
        assert_eq!(w["b"], hex::encode(sha2::Sha256::digest(&seen[0].body)));
        let r = claims(&seen[1].auth);
        assert_eq!(
            (
                r["m"].clone(),
                r["p"].clone(),
                r["purpose"].clone(),
                r.get("b").cloned()
            ),
            (json!("GET"), json!("/health/summary"), json!("health"), None)
        );
        assert_eq!(seen[1].method, "GET");
        assert_ne!(w["jti"], r["jti"]);
    }

    #[tokio::test]
    async fn unknown_agents_are_not_called() {
        let (base, seen) = agent_server(200, "{}").await;
        let (_d, c) = setup(&base);
        let e = c
            .post(&AgentTarget::new("vm-9", "evil.example"), "/ssh/close", &json!({}))
            .await
            .expect_err("unknown");
        assert!(e.to_string().contains("does not know that agent"));
        assert!(seen.lock().expect("lock").is_empty());
    }

    #[tokio::test]
    async fn refusals_and_not_running() {
        let (base, _) = agent_server(500, "{\"error\":\"gateway down\"}").await;
        let (_d, c) = setup(&base);
        let e = c.get(&AgentTarget::new("vm-1", "x"), "/update").await.expect_err("500");
        assert_eq!(e.to_string(), "agent 500: gateway down");
        assert!(e.is_refusal());
        let (base, _) = agent_server(503, "nope").await;
        let (_d, c) = setup(&base);
        let e = c.get(&AgentTarget::new("vm-1", "x"), "/update").await.expect_err("503");
        assert_eq!(e.to_string(), "The agent is not running. Start it and try again.");
        assert!(!e.is_refusal());
        let (base, _) = agent_server(401, "plain text").await;
        let (_d, c) = setup(&base);
        let e = c.get(&AgentTarget::new("vm-1", "x"), "/x").await.expect_err("401");
        assert_eq!(e.to_string(), "agent 401: plain text");
    }

    #[test]
    fn purposes() {
        assert_eq!(purpose_for_path("/ssh/close"), "ssh");
        assert_eq!(purpose_for_path("/apply/pending?x=1"), "apply-read");
        assert_eq!(purpose_for_path("/apply/ticket"), "apply-ticket");
        assert_eq!(purpose_for_path("/devices"), "devices");
        assert_eq!(purpose_for_path("/update"), "update");
        assert_eq!(purpose_for_path("/updates"), "channels");
        assert_eq!(purpose_for_path("/channels/send"), "channels");
        assert_eq!(timeout_for("/backup/run", 1), BACKUP_MS);
        assert_eq!(timeout_for("/search/apply", 1), CONFIG_WRITE_MS);
        assert_eq!(timeout_for("/x", 7), 7);
    }
}

/// The two sides joined (`token-binding.joined.test.ts`): this client against the agent's own check
/// (`cc_auth::firewall`, as the vm-agent routes use it), nothing stood in between but the network.
#[cfg(test)]
mod joined {
    use super::*;
    use cc_auth::firewall::FirewallAuth;
    use cc_http::{FirewallBody, FirewallRequest, ReadBody};
    use serde_json::json;
    use std::sync::Mutex;

    const HOST: &str = "atlas.acme.ccl.bot";

    struct Agent {
        base: String,
        tokens: Arc<Mutex<Vec<String>>>,
    }

    async fn agent(pinned: String, latch: std::path::PathBuf) -> Agent {
        let auth = Arc::new(FirewallAuth::new(
            move || Some(pinned.clone()),
            Some("vm-1".into()),
            || vec![HOST.to_string()],
            Some(latch),
        ));
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let t = tokens.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut router = cc_http::Router::new(&["all"]);
        router.route(
            "all",
            |_, _| true,
            move |mut req, _| {
                let (auth, t) = (auth.clone(), t.clone());
                async move {
                    // Caddy on the box hands the vm-agent the path without `/__cc/agent`.
                    let path = req.uri().path().trim_start_matches("/__cc/agent").to_string();
                    *req.uri_mut() = path.parse().expect("uri");
                    if let Some(a) = req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
                        t.lock().expect("lock").push(a.to_string());
                    }
                    let purpose = if req.uri().path().contains("/ssh/") { "ssh" } else { "channels" };
                    let read = if req.method() == http::Method::GET {
                        ReadBody::No
                    } else {
                        ReadBody::Json { limit: 16_384 }
                    };
                    match cc_http::firewall_request(&auth, req, purpose, 0, read).await {
                        FirewallRequest::Refused { reason, .. } => cc_http::json(
                            401,
                            &json!({"error": format!("the firewall's token was refused ({})", reason.map(|r| r.as_str()).unwrap_or("invalid"))}),
                        ),
                        FirewallRequest::Accepted {
                            body: FirewallBody::Rejected,
                            ..
                        } => cc_http::json(400, &json!({"error": "Bad request"})),
                        FirewallRequest::Accepted { body, .. } => {
                            let body = match body {
                                FirewallBody::Json(m) => Value::Object(m),
                                _ => Value::Null,
                            };
                            cc_http::json(200, &json!({"ok": true, "body": body}))
                        }
                    }
                }
            },
        );
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        Agent {
            base: format!("http://{addr}"),
            tokens,
        }
    }

    async fn setup(host_in_map: &str) -> (tempfile::TempDir, AgentClient, Agent, Arc<Agents>) {
        let d = tempfile::tempdir().expect("dir");
        let keys = cc_testkit::BoxKeys::write(&d.path().join("keys"), "fw-1", "fw.example").expect("keys");
        let a = agent(keys.vm.public_pem.clone(), d.path().join("firewall-tokens-bound")).await;
        let agents = Arc::new(Agents::default());
        agents.set(&[json!({"vm_id": "vm-1", "hostname": host_in_map})]);
        let base = a.base.clone();
        let c = AgentClient::for_tests(
            KeysDir::new(d.path().join("keys")),
            agents.clone(),
            Arc::new(move |_| Some(base.clone())),
        );
        (d, c, a, agents)
    }

    async fn resend(a: &Agent, method: &str, path: &str, token: &str, body: Option<&Value>) -> u16 {
        let client = reqwest::Client::new();
        let url = format!("{}/__cc/agent{path}", a.base);
        let mut req = if method == "POST" {
            client.post(url)
        } else {
            client.get(url)
        };
        req = req.header("authorization", token);
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(serde_json::to_vec(b).expect("json"));
        }
        req.send().await.expect("send").status().as_u16()
    }

    #[tokio::test]
    async fn what_the_firewall_signs_the_agent_takes_once() {
        let (_d, c, a, _) = setup(HOST).await;
        let t = AgentTarget::new("vm-1", "x");
        let out = c.post(&t, "/ssh/close", &json!({})).await.expect("close");
        assert_eq!(out.get("ok"), Some(&json!(true)));
        let msg = json!({"type": "telegram", "to": "1", "text": "Código: 123 456"});
        let out = c.post(&t, "/channels/send", &msg).await.expect("send");
        assert_eq!(out.get("body"), Some(&msg));
        let tokens = a.tokens.lock().expect("lock").clone();
        // Seen on the way: the close's token closes nothing again and opens nothing.
        assert_eq!(
            resend(&a, "POST", "/ssh/close", &tokens[0], Some(&json!({}))).await,
            401
        );
        assert_eq!(resend(&a, "POST", "/ssh/open", &tokens[0], Some(&json!({}))).await, 401);
        // A message's token does not carry another message.
        assert_eq!(
            resend(
                &a,
                "POST",
                "/channels/send",
                &tokens[1],
                Some(&json!({"type": "telegram", "to": "2", "text": "x"}))
            )
            .await,
            401
        );
    }

    #[tokio::test]
    async fn a_token_for_another_host_is_refused() {
        let (_d, c, _a, agents) = setup(HOST).await;
        // Once the agent has seen a bound token, a token for another name is refused.
        c.post(&AgentTarget::new("vm-1", "x"), "/ssh/close", &json!({}))
            .await
            .expect("close");
        agents.set(&[json!({"vm_id": "vm-1", "hostname": "evil.example"})]);
        let e = c
            .post(
                &AgentTarget::new("vm-1", "x"),
                "/ssh/open",
                &json!({"grantId": "g", "seconds": 60}),
            )
            .await
            .expect_err("refused");
        assert_eq!(e.to_string(), "agent 401: the firewall's token was refused (host)");
    }
}

/// `purpose.test.ts`: the agent's own route table and handlers (the vm-agent's TS source, read
/// here) name the purpose each route verifies; `purpose_for_path` must give the same.
#[cfg(test)]
mod purposes {
    use super::purpose_for_path;
    use regex::Regex;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn every_route_is_signed_with_the_purpose_the_agent_verifies() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packages/vm-agent/src");
        // The TS vm-agent stays in the private repo: the public export (standalone/oss) has only its
        // test fixtures.
        if !src.join("index.ts").is_file() {
            eprintln!("skipped: no packages/vm-agent to compare the routes with");
            return;
        }
        let index = std::fs::read_to_string(src.join("index.ts")).expect("vm-agent index.ts");
        let mut handler_file = HashMap::new();
        let imports = Regex::new(r#"import \{([^}]+)\} from "\./routes/([\w-]+)\.js";"#).expect("re");
        for m in imports.captures_iter(&index) {
            for name in m[1].split(',') {
                let name = name.trim().trim_start_matches("type ").trim().to_string();
                handler_file.insert(name, m[2].to_string());
            }
        }
        let dispatch =
            Regex::new(r#"url\.pathname(?:\.startsWith\("([^"]+)"\)|\s*===\s*"([^"]+)")[^{]*\{\s*await (handle\w+)\("#)
                .expect("re");
        let verify = Regex::new(r#"verifyMitmRequest\(\s*req\s*(?:,\s*"([^"]+)"\s*)?\)"#).expect("re");
        let purposes_in = |file: &str| -> HashSet<String> {
            let text = std::fs::read_to_string(src.join("routes").join(format!("{file}.ts"))).unwrap_or_default();
            verify
                .captures_iter(&text)
                .map(|c| c.get(1).map(|m| m.as_str()).unwrap_or("channels").to_string())
                .collect()
        };
        let mut checked = Vec::new();
        for m in dispatch.captures_iter(&index) {
            let Some(file) = handler_file.get(&m[3]) else { continue };
            let path = match (m.get(1), m.get(2)) {
                (Some(p), _) => format!("{}anything", p.as_str()),
                (_, Some(e)) => e.as_str().to_string(),
                _ => continue,
            };
            let purposes = purposes_in(file);
            if purposes.is_empty() {
                continue;
            }
            checked.push(file.clone());
            assert_eq!(purposes.len(), 1, "routes/{file}.ts verifies {purposes:?}");
            let want = purposes.into_iter().next().unwrap_or_default();
            assert_eq!(purpose_for_path(&path), want, "{path} (routes/{file}.ts)");
        }
        assert!(checked.len() >= 10, "only found {checked:?}");
        for f in ["channels", "llm", "google", "drive", "hooks", "update"] {
            assert!(checked.iter().any(|c| c == f), "missing {f}");
        }
        let verifying: HashSet<&String> = handler_file.values().filter(|f| !purposes_in(f).is_empty()).collect();
        let missed: Vec<&&String> = verifying.iter().filter(|f| !checked.contains(f)).collect();
        assert!(missed.is_empty(), "{missed:?}");
        assert_eq!(purpose_for_path("/google/apply"), "google");
    }
}

/// `budgets.test.ts`: the timeouts on the path console → firewall → agent box → OpenClaw nest. The
/// other two sides are read as text (`packages/vm-agent/src/budgets.ts`, the console's
/// `firewall.schema.ts`), so a number changed on one side only fails here.
#[cfg(test)]
mod budgets {
    use super::*;
    use regex::Regex;
    use std::collections::HashMap;

    /// `+ - * /` and parentheses over numbers, left to right with the usual precedence.
    fn eval(tokens: &[String], pos: &mut usize) -> Option<f64> {
        fn atom(t: &[String], p: &mut usize) -> Option<f64> {
            let tok = t.get(*p)?.clone();
            *p += 1;
            if tok == "(" {
                let v = eval(t, p)?;
                (t.get(*p)? == ")").then(|| *p += 1)?;
                return Some(v);
            }
            tok.parse().ok()
        }
        fn term(t: &[String], p: &mut usize) -> Option<f64> {
            let mut v = atom(t, p)?;
            while let Some(op) = t.get(*p).filter(|o| *o == "*" || *o == "/").cloned() {
                *p += 1;
                let r = atom(t, p)?;
                v = if op == "*" { v * r } else { v / r };
            }
            Some(v)
        }
        let mut v = term(tokens, pos)?;
        while let Some(op) = tokens.get(*pos).filter(|o| *o == "+" || *o == "-").cloned() {
            *pos += 1;
            let r = term(tokens, pos)?;
            v = if op == "+" { v + r } else { v - r };
        }
        Some(v)
    }

    fn constants(path: &str) -> HashMap<String, f64> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let src = std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        let decl = Regex::new(r"(?m)^export const ([A-Z][A-Z0-9_]*) = ([^;]+);$").expect("re");
        let token = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*|[0-9][0-9_]*|[-+*/()]|\S").expect("re");
        let mut out = HashMap::new();
        for m in decl.captures_iter(&src) {
            let mut tokens = Vec::new();
            let mut ok = true;
            for t in token.find_iter(&m[2]) {
                let t = t.as_str();
                if t.starts_with(|c: char| c.is_ascii_digit()) {
                    tokens.push(t.replace('_', ""));
                } else if t.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                    match out.get(t) {
                        Some(v) => tokens.push(format!("{v}")),
                        None => ok = false,
                    }
                } else if "+-*/()".contains(t) {
                    tokens.push(t.to_string());
                } else {
                    ok = false;
                }
            }
            let mut pos = 0;
            if ok
                && let Some(v) = eval(&tokens, &mut pos)
                && pos == tokens.len()
            {
                out.insert(m[1].to_string(), v);
            }
        }
        out
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // the TS asserts these the same way
    fn the_timeouts_nest() {
        // The TS files stay in the private repo: the public export (standalone/oss) has neither.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        if !root.join("apps/saas").is_dir() {
            eprintln!("skipped: no apps/saas or packages/vm-agent to compare the timeouts with");
            return;
        }
        let b = constants("packages/vm-agent/src/budgets.ts");
        let plane = constants("apps/saas/app/(mitm)/lib/firewall.schema.ts");
        let bx = |n: &str| {
            *b.get(n)
                .unwrap_or_else(|| panic!("vm-agent budgets.ts no longer exports {n}"))
        };
        let f = |v: u64| v as f64;
        let stale = *plane
            .get("FIREWALL_COMMAND_STALE_MS")
            .expect("FIREWALL_COMMAND_STALE_MS");
        assert!(f(COMMAND_BUDGET_MS) < stale && stale - f(COMMAND_BUDGET_MS) >= 10_000.0);
        const { assert!(CHANNELS_APPLY_MS + CONFIRM_APPLY_MS <= COMMAND_BUDGET_MS) };
        const { assert!(CHANNELS_APPLY_MS * 2 + CONFIRM_APPLY_MS > COMMAND_BUDGET_MS) };
        assert!(bx("APPLY_INLINE_WAIT_MS") + bx("GATEWAY_READ_MS") < f(CHANNELS_APPLY_MS));
        assert!(bx("CONFIG_PATCH_RESTART_MS") > 33_000.0 && bx("CONFIG_PATCH_RESTART_MS") > bx("CONFIG_PATCH_MS"));
        let ordinary = bx("GATEWAY_READ_MS") + bx("CONFIG_PATCH_RESTART_MS") + bx("SERVICE_ACTION_MS");
        assert!(f(CONFIG_WRITE_MS) >= ordinary && CONFIG_WRITE_MS > AGENT_CALL_MS);
        const { assert!(CONFIG_WRITE_MS + CONFIRM_MIN_MS <= COMMAND_BUDGET_MS) };
        let worst = 2.0 * (bx("GATEWAY_READ_MS") + bx("CONFIG_PATCH_RESTART_MS")) + bx("SERVICE_ACTION_MS");
        assert!(worst > f(COMMAND_BUDGET_MS) && f(CONFIG_WRITE_MS) < worst);
        const { assert!(APPROVE_MS > 53_000 && APPROVE_MS + AGENT_CALL_MS < COMMAND_BUDGET_MS) };
        assert!(f(DEVICE_APPROVE_MS) > bx("DEVICES_ACTION_MS").max(bx("DEVICES_ACTION_CLI_MS")));
        const { assert!(DEVICE_APPROVE_MS + AGENT_CALL_MS < COMMAND_BUDGET_MS) };
        assert!(f(GBRAIN_APPLY_MS) > bx("GATEWAY_READ_MS") + bx("CONFIG_PATCH_RESTART_MS"));
        const { assert!(GBRAIN_CONNECT_MS + GBRAIN_APPLY_MS < COMMAND_BUDGET_MS) };
        const { assert!(AGENT_CALL_MS * 2 + KILL_WINDOW_SEND_MS < COMMAND_BUDGET_MS) };
        const { assert!(LLM_PUSH_MS < COMMAND_BUDGET_MS) };
    }
}
