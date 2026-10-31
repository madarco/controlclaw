//! App integrations on the agent box (`connectors.ts`, `routes/connectors.ts`). The firewall sends
//! where its connector gate is, this agent's runtime token and its connections. This makes OpenClaw
//! have an MCP server for it (`mcp.servers.controlclaw-apps`, pointed at the loopback relay, since
//! OpenClaw's MCP config cannot carry a header), and writes `~/.config/oomol/connector.env` for the
//! `oo` CLI. The relay on `127.0.0.1:3111` adds the bearer and forwards only the execution routes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use cc_http::{Body, FirewallBody, Resp, Router, send_json};
use cc_openclaw::config_queue::PatchOptions;
use http_body_util::BodyExt;
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::js_slice;
use super::common::{CONFIG_PATCH_RESTART, Caller, Deps, GATEWAY_READ, caller, fail, lock, not_found, snapshot};
use super::time::{iso_ms, now_ms};
use crate::app::App;
use crate::stages;

/// Our entry in OpenClaw's `mcp.servers`, in the reserved `controlclaw-` prefix.
pub const MCP_SERVER_NAME: &str = "controlclaw-apps";
/// Its name before T-178, under `mcpServers` and on the test branch under `mcp.servers`.
const OLD_MCP_SERVER_NAME: &str = "controlclaw";
const HEAL_RETRY: Duration = Duration::from_secs(60);
const HEAL_WRITES: usize = 2;
const MAX_CONNECTIONS: usize = 100;
const RELAY_TIMEOUT: Duration = Duration::from_secs(120);

static SERVICE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_]{0,60}$").expect("regex"));
static ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9:._-]{1,128}$").expect("regex"));
/// What the relay forwards: the execution surface, the same list the firewall's gate allows.
static RELAYED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(/mcp|/mcp/tools|/v1/health)$|^/v1/apps(/|$)|^/v1/actions(/|$)|^/v1/proxy/").expect("regex")
});

fn is_record(v: &Value) -> bool {
    v.is_object()
}

/// What `mcp.servers.<name>` accepts, field by field (OpenClaw 2026.10's schema).
fn field_ok(k: &str, v: &Value) -> bool {
    let scalar_record = |v: &Value| {
        v.as_object()
            .is_some_and(|m| m.values().all(|x| x.is_string() || x.is_number() || x.is_boolean()))
    };
    match k {
        "enabled" | "supportsParallelToolCalls" | "sslVerify" => v.is_boolean(),
        "command" | "cwd" | "url" | "clientCert" | "clientKey" => v.is_string(),
        "args" => v.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
        "env" | "headers" => scalar_record(v),
        "transport" => matches!(v.as_str(), Some("stdio" | "sse" | "streamable-http")),
        "connectionTimeoutMs" | "requestTimeoutMs" => v.as_f64().is_some_and(|n| n > 0.0),
        "auth" => v == "oauth",
        "oauth" | "toolFilter" | "codex" => is_record(v),
        _ => false,
    }
}

/// `movedLegacy`: the other entries of a top-level `mcpServers`, as `mcp.servers` takes them.
fn moved_legacy(config: &Value, log: &dyn Fn(&str)) -> Map<String, Value> {
    let Some(legacy) = config.get("mcpServers").and_then(Value::as_object) else {
        return Map::new();
    };
    let taken = config
        .get("mcp")
        .and_then(|m| m.get("servers"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut out = Map::new();
    for (name, raw) in legacy {
        if name == OLD_MCP_SERVER_NAME || name == MCP_SERVER_NAME {
            continue;
        }
        if taken.contains_key(name) {
            log(&format!(
                "[connectors] mcpServers.{name} not moved: mcp.servers already has {name}"
            ));
            continue;
        }
        let Some(raw) = raw.as_object() else {
            log(&format!("[connectors] mcpServers.{name} not moved: not an object"));
            continue;
        };
        let kept: Map<String, Value> = raw
            .iter()
            .filter(|(k, v)| field_ok(k, v))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let dropped: Vec<&String> = raw.keys().filter(|k| !kept.contains_key(*k)).collect();
        if !kept.get("url").is_some_and(Value::is_string) && !kept.get("command").is_some_and(Value::is_string) {
            log(&format!(
                "[connectors] mcpServers.{name} not moved: it has neither a url nor a command OpenClaw accepts"
            ));
            continue;
        }
        if !dropped.is_empty() {
            let d: Vec<&str> = dropped.iter().map(|s| s.as_str()).collect();
            log(&format!(
                "[connectors] mcpServers.{name} moved without {} (not accepted under mcp.servers)",
                d.join(", ")
            ));
        }
        out.insert(name.clone(), Value::Object(kept));
    }
    out
}

/// `mcpPatch`: our entry (or None to take it away), the old name dropped, a legacy `mcpServers`
/// moved under `mcp.servers` and removed.
pub fn mcp_patch(config: &Value, entry: Option<&Value>, log: &dyn Fn(&str)) -> Map<String, Value> {
    let mut servers = moved_legacy(config, log);
    servers.insert(OLD_MCP_SERVER_NAME.into(), Value::Null);
    servers.insert(MCP_SERVER_NAME.into(), entry.cloned().unwrap_or(Value::Null));
    let mut patch = Map::new();
    patch.insert("mcp".into(), json!({ "servers": servers }));
    if config.get("mcpServers").is_some() {
        patch.insert("mcpServers".into(), Value::Null);
    }
    patch
}

fn has_old_entry(config: &Value) -> bool {
    config.get("mcpServers").is_some()
        || config
            .get("mcp")
            .and_then(|m| m.get("servers"))
            .and_then(Value::as_object)
            .is_some_and(|s| s.contains_key(OLD_MCP_SERVER_NAME))
}

/// `repairConfigFile`: take a top-level `mcpServers` out of `openclaw.json` on disk (OpenClaw will
/// not start with it). True when the file changed. A clean, missing or JSON5 file is left alone.
pub fn repair_config_file(path: &Path, entry: Option<&Value>, log: &dyn Fn(&str)) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let mode = std::fs::metadata(path).map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777);
    let Ok(mode) = mode else { return false };
    if !text.contains("mcpServers") {
        return false;
    }
    let Ok(mut config) = serde_json::from_str::<Value>(&text) else {
        log(&format!(
            "[connectors] {} mentions mcpServers but is not plain JSON; left as it is",
            path.display()
        ));
        return false;
    };
    if config.get("mcpServers").is_none() {
        return false;
    }
    let moved = moved_legacy(&config, log);
    let Some(obj) = config.as_object_mut() else {
        return false;
    };
    obj.remove("mcpServers");
    let mut mcp = obj.get("mcp").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut servers = mcp
        .get("servers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    servers.remove(OLD_MCP_SERVER_NAME);
    for (k, v) in moved {
        servers.insert(k, v);
    }
    if let Some(e) = entry {
        servers.insert(MCP_SERVER_NAME.into(), e.clone());
    }
    mcp.insert("servers".into(), Value::Object(servers));
    obj.insert("mcp".into(), Value::Object(mcp));
    let body = format!("{}\n", serde_json::to_string_pretty(&config).unwrap_or_default());
    // A stale `.tmp` would keep its own mode: the new one must be created with the file's.
    let _ = std::fs::remove_file(cc_store::tmp_path(path, cc_store::TmpName::Suffix));
    cc_store::write_atomic(path, body.as_bytes(), mode, cc_store::TmpName::Suffix).is_ok()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Gateway {
    pub url: String,
    pub token: String,
}

/// `state/connectors.json`. Connections are kept as they came (the TS stores the parsed objects).
#[derive(Debug, Clone, PartialEq, Default)]
struct State {
    gateway: Option<Gateway>,
    connections: Vec<Value>,
    updated_at: String,
}

fn read_state(path: &Path) -> State {
    let Some(v) = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return State::default();
    };
    let gateway = v.get("gateway").and_then(|g| {
        Some(Gateway {
            url: g.get("url")?.as_str()?.into(),
            token: g.get("token")?.as_str()?.into(),
        })
    });
    State {
        gateway,
        connections: v
            .get("connections")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        updated_at: v.get("updatedAt").and_then(Value::as_str).unwrap_or_default().into(),
    }
}

fn write_state(path: &Path, s: &State) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let gw = s.gateway.as_ref().map(|g| json!({ "url": g.url, "token": g.token }));
    let body = json!({ "gateway": gw, "connections": s.connections, "updatedAt": s.updated_at });
    cc_store::write_atomic(path, body.to_string().as_bytes(), 0o600, cc_store::TmpName::Suffix)
}

/// What `oo connector` reads: the relay's URL and this agent's runtime token.
pub fn cli_env_contents(relay_url: &str, token: &str) -> String {
    [
        "# Written by ControlClaw's vm-agent. The base URL is the loopback relay on this box;",
        "# the token is this agent's own OpenConnector runtime token.",
        &format!("OOMOL_CONNECT_BASE_URL={relay_url}"),
        &format!("OOMOL_CONNECT_RUNTIME_TOKEN={token}"),
        "",
    ]
    .join("\n")
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApplyInput {
    Remove,
    Set { gateway: Gateway, connections: Vec<Value> },
}

/// Whether OpenClaw's entry is the one the saved connections want. `null` is gone, as
/// JavaScript's check reads it.
fn entry_matches(have: Option<&Value>, want: Option<&Value>) -> bool {
    let have = have.filter(|h| !h.is_null());
    match want {
        Some(w) => have.is_some_and(|h| h.get("url") == w.get("url") && h.get("transport") == w.get("transport")),
        None => have.is_none(),
    }
}

/// `parseApply` (routes/connectors.ts).
pub fn parse_apply(body: &Map<String, Value>) -> Result<ApplyInput, String> {
    if body.get("remove") == Some(&json!(true)) {
        return Ok(ApplyInput::Remove);
    }
    let gw = body.get("gateway");
    let (Some(url), Some(token)) = (
        gw.and_then(|g| g.get("url")).and_then(Value::as_str),
        gw.and_then(|g| g.get("token"))
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty()),
    ) else {
        return Err("gateway.url and gateway.token are required".into());
    };
    let Ok(parsed) = url::Url::parse(url) else {
        return Err("gateway.url is not a URL".into());
    };
    if parsed.scheme() != "http" {
        return Err("gateway.url must be http (the relay dials it without TLS)".into());
    }
    let raw = body
        .get("connections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if raw.len() > MAX_CONNECTIONS {
        return Err(format!("at most {MAX_CONNECTIONS} connections"));
    }
    let mut connections = Vec::new();
    for c in raw {
        let s = |k: &str| c.get(k).and_then(Value::as_str);
        let Some(id) = s("id").filter(|v| ID_RE.is_match(v)) else {
            return Err("connections[].id is invalid".into());
        };
        let Some(service) = s("service").filter(|v| SERVICE_RE.is_match(v)) else {
            return Err("connections[].service is invalid".into());
        };
        let Some(alias) = s("alias").filter(|v| ID_RE.is_match(v)) else {
            return Err("connections[].alias is invalid".into());
        };
        connections.push(json!({
            "id": id,
            "service": service,
            "alias": alias,
            "label": s("label").map(|l| js_slice(l, 120)),
            "accountLabel": s("accountLabel").map(|l| js_slice(l, 200)),
        }));
    }
    Ok(ApplyInput::Set {
        gateway: Gateway {
            url: url.into(),
            token: token.into(),
        },
        connections,
    })
}

pub struct ConnectorsService {
    deps: Deps,
    relay_port: u16,
    state_path: PathBuf,
    cli_env_path: PathBuf,
    busy: Arc<dyn Fn() -> bool + Send + Sync>,
    state: Mutex<State>,
    gateway_reachable: Mutex<Option<bool>>,
    /// One MCP write at a time.
    patch_turn: tokio::sync::Mutex<()>,
    healing: tokio::sync::Mutex<()>,
    heal_waiting: AtomicBool,
    heal_writes: AtomicUsize,
    relay_started: AtomicBool,
    /// Unmanaged: where the relay reaches the firewall's gate (the tunnel's address, the proxy's),
    /// whatever host the firewall's `gateway.url` names. None: that host, as on a managed box.
    gate: Option<std::net::Ipv4Addr>,
    /// The relay's upstream client: kept-alive connections to the gate, as Node's global agent.
    upstream:
        hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, hyper::body::Incoming>,
}

/// A body that fails once nothing has come for `idle` (the TS's socket timeout).
struct IdleBody {
    inner: hyper::body::Incoming,
    idle: Duration,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl http_body::Body for IdleBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        use std::future::Future;
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                let idle = self.idle;
                self.sleep.as_mut().reset(tokio::time::Instant::now() + idle);
                Poll::Ready(frame.map(|f| f.map_err(std::io::Error::other)))
            }
            Poll::Pending => match self.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err(std::io::Error::other("timeout")))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl ConnectorsService {
    pub fn new(
        deps: Deps,
        relay_port: u16,
        state_path: PathBuf,
        cli_env_path: PathBuf,
        busy: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        let state = read_state(&state_path);
        Self {
            deps,
            relay_port,
            state_path,
            cli_env_path,
            busy,
            state: Mutex::new(state),
            gateway_reachable: Mutex::new(None),
            patch_turn: tokio::sync::Mutex::new(()),
            healing: tokio::sync::Mutex::new(()),
            heal_waiting: AtomicBool::new(false),
            heal_writes: AtomicUsize::new(0),
            relay_started: AtomicBool::new(false),
            gate: None,
            upstream: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http(),
        }
    }

    /// Unmanaged: the relay dials the gate at `gate`.
    pub fn with_gate(mut self, gate: Option<std::net::Ipv4Addr>) -> Self {
        self.gate = gate;
        self
    }

    pub fn relay_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.relay_port)
    }

    /// Our entry while this agent has app connections.
    pub fn entry(&self) -> Option<Value> {
        lock(&self.state)
            .gateway
            .is_some()
            .then(|| json!({ "url": format!("{}/mcp", self.relay_url()), "transport": "streamable-http" }))
    }

    pub async fn apply(&self, input: ApplyInput) -> Result<Value, String> {
        self.deps.gateway()?;
        let mut applied: Vec<&str> = Vec::new();
        let now = iso_ms(now_ms());
        match input {
            ApplyInput::Remove => {
                let s = State {
                    gateway: None,
                    connections: Vec::new(),
                    updated_at: now,
                };
                write_state(&self.state_path, &s).map_err(|e| e.to_string())?;
                *lock(&self.state) = s;
                let _ = std::fs::remove_file(&self.cli_env_path);
                self.patch_mcp(None).await?;
                applied.push("removed");
                self.deps
                    .log("[connectors] removed the MCP server entry and the CLI environment");
            }
            ApplyInput::Set { gateway, connections } => {
                let n = connections.len();
                let s = State {
                    gateway: Some(gateway.clone()),
                    connections,
                    updated_at: now,
                };
                write_state(&self.state_path, &s).map_err(|e| e.to_string())?;
                *lock(&self.state) = s;
                applied.push("state");
                cc_store::write_atomic(
                    &self.cli_env_path,
                    cli_env_contents(&self.relay_url(), &gateway.token).as_bytes(),
                    0o600,
                    cc_store::TmpName::Suffix,
                )
                .map_err(|e| e.to_string())?;
                applied.push("cli");
                self.patch_mcp(self.entry()).await?;
                applied.push("mcp");
                self.deps.log(&format!(
                    "[connectors] {n} connection(s) available through {}/mcp",
                    self.relay_url()
                ));
            }
        }
        Ok(json!({ "ok": true, "applied": applied }))
    }

    /// One MCP write at a time, built from a fresh read, once more when the file moved meanwhile.
    async fn patch_mcp(&self, entry: Option<Value>) -> Result<(), String> {
        let _turn = self.patch_turn.lock().await;
        match self.write_mcp(entry.as_ref()).await {
            Err(e) if e.to_lowercase().contains("config changed since last load") => {
                self.write_mcp(entry.as_ref()).await
            }
            r => r,
        }
    }

    async fn write_mcp(&self, entry: Option<&Value>) -> Result<(), String> {
        let raw = self.deps.call("config.get", json!({}), GATEWAY_READ).await?;
        let snap = snapshot(raw)?;
        let log = |l: &str| self.deps.log(l);
        let patch = mcp_patch(&Value::Object(snap.config.clone()), entry, &log);
        let w = self.deps.gateway()?;
        let opts = PatchOptions {
            base_hash: Some(snap.hash),
            snapshot: Some(snap.raw),
            read_timeout: Some(GATEWAY_READ),
            ..PatchOptions::new(CONFIG_PATCH_RESTART)
        };
        w.patch(&patch, opts).await.map_err(|e| e.to_string())
    }

    /// Bring OpenClaw in line with the saved state on (re)connect: only when they differ, not while
    /// busy, one at a time, at most twice per process. Never fails.
    pub fn heal(self: &Arc<Self>) -> cc_http::BoxFuture<()> {
        let me = self.clone();
        Box::pin(async move {
            if me.heal_waiting.load(Ordering::SeqCst) {
                return;
            }
            // `this.healing ??=`: a caller during a run waits for that run, it does not start another.
            let Ok(_one) = me.healing.try_lock() else {
                let _wait = me.healing.lock().await;
                return;
            };
            if (me.busy)() {
                me.heal_waiting.store(true, Ordering::SeqCst);
                let again = me.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(HEAL_RETRY).await;
                    again.heal_waiting.store(false, Ordering::SeqCst);
                    again.heal().await;
                });
                return;
            }
            if let Err(e) = me.heal_once().await {
                me.deps
                    .log(&format!("[connectors] could not check the MCP server entry: {e}"));
            }
        })
    }

    async fn heal_once(&self) -> Result<(), String> {
        let raw = self.deps.call("config.get", json!({}), GATEWAY_READ).await?;
        let config = Value::Object(snapshot(raw).map(|s| s.config).unwrap_or_default());
        let want = self.entry();
        if want.is_none() && lock(&self.state).updated_at.is_empty() {
            return Ok(());
        }
        let have = config
            .get("mcp")
            .and_then(|m| m.get("servers"))
            .and_then(|s| s.get(MCP_SERVER_NAME));
        let same = entry_matches(have, want.as_ref());
        if same && !has_old_entry(&config) {
            return Ok(());
        }
        if self.heal_writes.load(Ordering::SeqCst) >= HEAL_WRITES {
            self.deps.log("[connectors] the MCP server entry still differs from the saved connections; not writing it again until the vm-agent restarts");
            return Ok(());
        }
        self.heal_writes.fetch_add(1, Ordering::SeqCst);
        self.patch_mcp(want.clone()).await?;
        self.deps.log(&format!(
            "[connectors] {} the MCP server entry to match the saved connections",
            if want.is_some() { "added" } else { "removed" }
        ));
        Ok(())
    }

    pub async fn status(&self) -> Value {
        let configured = match self
            .deps
            .call("config.get", json!({}), GATEWAY_READ)
            .await
            .map(|raw| super::common::config_of(&raw))
        {
            // Only read: no hash needed, as in the TS.
            Ok(config) => config
                .get("mcp")
                .and_then(|m| m.get("servers"))
                .and_then(|s| s.get(MCP_SERVER_NAME))
                .is_some_and(super::llm::truthy),
            Err(e) => {
                self.deps
                    .log(&format!("[connectors] could not read the OpenClaw config: {e}"));
                false
            }
        };
        let s = lock(&self.state).clone();
        json!({
            "configured": configured,
            "relayUrl": self.relay_url(),
            "gatewayReachable": *lock(&self.gateway_reachable),
            "connections": s.connections,
            // `state.updatedAt ?? null`: an empty string stays one.
            "updatedAt": s.updated_at,
        })
    }

    /// The loopback relay: unauthenticated on purpose, on 127.0.0.1 only, its own port.
    pub fn start_relay(self: &Arc<Self>) {
        if self.relay_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        let mut router = Router::new(&["relay"]);
        let m = me.clone();
        router.route(
            "relay",
            |_, _| true,
            move |req, _| {
                let m = m.clone();
                async move { m.relay(req).await }
            },
        );
        let router = Arc::new(router);
        let addr = format!("127.0.0.1:{}", self.relay_port);
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => {
                    me.deps.log(&format!(
                        "[connectors] relay listening on {} (/mcp and /v1 only)",
                        me.relay_url()
                    ));
                    cc_http::serve(l, router).await;
                }
                Err(e) => me.deps.log(&format!("[connectors] relay: {e}")),
            }
        });
    }

    async fn relay(&self, req: cc_http::Req) -> Resp {
        let raw_path = req.uri().path().to_string();
        let json_resp = |status: u16, error: &str| cc_http::json(status, &json!({ "error": error }));
        if !RELAYED.is_match(&raw_path) {
            return json_resp(404, "Not found");
        }
        let Some(gw) = lock(&self.state).gateway.clone() else {
            return json_resp(503, "This agent has no app connections yet.");
        };
        let Ok(target) = url::Url::parse(&gw.url) else {
            return json_resp(502, "Your firewall's connector runtime is not answering.");
        };
        let named = self.gate.map(|g| g.to_string());
        let host = named
            .as_deref()
            .unwrap_or_else(|| target.host_str().unwrap_or_default());
        // On the gate, without a port named: the connector gate's own.
        let port = target.port().or(self.gate.map(|_| 3900));
        let host_header = match port {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let (mut parts, body) = req.into_parts();
        parts.uri = match format!("http://{host_header}{path_and_query}").parse() {
            Ok(u) => u,
            Err(_) => return self.relay_failed("bad target"),
        };
        if let Ok(v) = http::HeaderValue::from_str(&host_header) {
            parts.headers.insert(http::header::HOST, v);
        }
        if let Ok(v) = http::HeaderValue::from_str(&format!("Bearer {}", gw.token)) {
            parts.headers.insert(http::header::AUTHORIZATION, v);
        }
        let upstream = hyper::Request::from_parts(parts, body);
        match tokio::time::timeout(RELAY_TIMEOUT, self.upstream.request(upstream)).await {
            Ok(Ok(res)) => {
                *lock(&self.gateway_reachable) = Some(true);
                let (parts, body) = res.into_parts();
                let body: Body = IdleBody {
                    inner: body,
                    idle: RELAY_TIMEOUT,
                    sleep: Box::pin(tokio::time::sleep(RELAY_TIMEOUT)),
                }
                .boxed();
                hyper::Response::from_parts(parts, body)
            }
            Ok(Err(e)) => self.relay_failed(&e.to_string()),
            Err(_) => self.relay_failed("timeout"),
        }
    }

    fn relay_failed(&self, why: &str) -> Resp {
        *lock(&self.gateway_reachable) = Some(false);
        self.deps.log(&format!("[connectors] relay upstream failed: {why}"));
        cc_http::json(
            502,
            &json!({ "error": "Your firewall's connector runtime is not answering." }),
        )
    }
}

/// `/connectors/*`.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/connectors/", move |req, _| {
        let app = app.clone();
        async move {
            let write = req.method() == Method::POST;
            let (parts, who) = caller(&app, req, "connectors", 65_536).await;
            let Some(who) = who else {
                let error = if write {
                    "integration changes must come from the org firewall"
                } else {
                    "Unauthorized"
                };
                return send_json(401, &json!({ "error": error }));
            };
            let Some(service) = app.contracts.platform.get().and_then(|p| p.connectors.get().cloned()) else {
                let error = if app.unmanaged.is_some() {
                    "App connections are not available yet for an OpenClaw that runs in a container."
                } else {
                    "This box does not support app integrations yet."
                };
                return send_json(503, &json!({ "ok": false, "error": error }));
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            if path == "/connectors/status" && parts.method == Method::GET {
                return send_json(200, &service.status().await);
            }
            if path == "/connectors/apply" && write {
                let body = match who {
                    Caller::Firewall(FirewallBody::Json(b)) => b,
                    _ => return send_json(400, &json!({ "ok": false, "error": "Invalid JSON body" })),
                };
                let input = match parse_apply(&body) {
                    Ok(i) => i,
                    Err(e) => return send_json(400, &json!({ "ok": false, "error": e })),
                };
                return match service.apply(input).await {
                    Ok(v) => send_json(200, &v),
                    Err(e) => fail(&e, None),
                };
            }
            not_found()
        }
    });
}

#[cfg(test)]
mod tests {
    //! connectors.test.ts, at the service, with a fake gate behind the relay.

    use std::sync::atomic::AtomicBool;

    use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};

    use super::super::llm::tests::rig;
    use super::*;

    fn quiet(_: &str) {}

    struct T {
        oc: FakeOpenClawConfig,
        gw: Arc<FakeConfigGateway>,
        svc: Arc<ConnectorsService>,
        dir: tempfile::TempDir,
        busy: Arc<AtomicBool>,
        deps: Deps,
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    fn setup(config: Value) -> T {
        let oc = FakeOpenClawConfig::new(config, None, false);
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        let r = rig(gw.clone());
        let dir = tempfile::tempdir().expect("dir");
        let busy = Arc::new(AtomicBool::new(false));
        let b = busy.clone();
        let svc = Arc::new(ConnectorsService::new(
            r.deps.clone(),
            free_port(),
            dir.path().join("connectors.json"),
            dir.path().join("oomol/connector.env"),
            Arc::new(move || b.load(Ordering::SeqCst)),
        ));
        T {
            oc,
            gw,
            svc,
            dir,
            busy,
            deps: r.deps,
        }
    }

    fn servers(t: &T) -> Map<String, Value> {
        t.oc.config()["mcp"]["servers"].as_object().cloned().unwrap_or_default()
    }

    fn apply_input(gate: &str) -> ApplyInput {
        parse_apply(
            json!({ "gateway": { "url": gate, "token": "oct_agent-token" }, "connections": [{ "id": "rc-gitea-1", "service": "gitea", "alias": "work", "label": "Gitea" }] })
                .as_object()
                .expect("o"),
        )
        .expect("ok")
    }

    #[test]
    fn the_parser_refuses_a_malformed_apply() {
        let p = |v: Value| parse_apply(v.as_object().expect("o"));
        assert!(p(json!({})).is_err());
        assert_eq!(
            p(json!({ "gateway": { "url": "not a url", "token": "t" } })),
            Err("gateway.url is not a URL".into())
        );
        assert_eq!(
            p(json!({ "gateway": { "url": "ftp://x", "token": "t" } })),
            Err("gateway.url must be http (the relay dials it without TLS)".into())
        );
        assert!(p(json!({ "gateway": { "url": "https://fw.example:3900", "token": "t" } })).is_err());
        assert_eq!(
            p(
                json!({ "gateway": { "url": "http://x", "token": "t" }, "connections": [{ "id": "a b", "service": "gitea", "alias": "x" }] })
            ),
            Err("connections[].id is invalid".into())
        );
        assert_eq!(
            p(
                json!({ "gateway": { "url": "http://x", "token": "t" }, "connections": [{ "id": "a", "service": "Gitea Cloud", "alias": "x" }] })
            ),
            Err("connections[].service is invalid".into())
        );
        assert_eq!(p(json!({ "remove": true })), Ok(ApplyInput::Remove));
        assert!(p(json!({ "gateway": { "url": "http://x", "token": "t" }, "connections": [{ "id": "a", "service": "gitea", "alias": "x", "label": "L" }] })).is_ok());
    }

    #[test]
    fn the_cli_environment_points_at_the_relay() {
        let env = cli_env_contents("http://127.0.0.1:3111", "oct_x");
        assert!(env.lines().any(|l| l == "OOMOL_CONNECT_BASE_URL=http://127.0.0.1:3111"));
        assert!(env.lines().any(|l| l == "OOMOL_CONNECT_RUNTIME_TOKEN=oct_x"));
    }

    /// A gate that records the bearer of every request that reaches it.
    async fn gate(status: u16) -> (String, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let mut router = Router::new(&["gate"]);
        router.route(
            "gate",
            |_, _| true,
            move |req: cc_http::Req, _| {
                let s = s.clone();
                async move {
                    let auth = cc_http::header(&req.into_parts().0, "authorization")
                        .unwrap_or_default()
                        .to_string();
                    lock(&s).push(auth);
                    cc_http::json(status, &json!({ "ok": true }))
                }
            },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", l.local_addr().expect("a"));
        tokio::spawn(cc_http::serve(l, Arc::new(router)));
        (url, seen)
    }

    #[tokio::test]
    async fn apply_writes_the_entry_the_state_and_the_cli_env_and_the_relay_adds_the_bearer() {
        let t = setup(
            json!({ "mcp": { "servers": { "controlclaw-console": { "url": "http://10.0.0.2:3940/mcp", "transport": "streamable-http" } } } }),
        );
        let (gate_url, seen) = gate(200).await;
        let r = t.svc.apply(apply_input(&gate_url)).await.expect("ok");
        assert_eq!(r["applied"], json!(["state", "cli", "mcp"]));
        assert_eq!(
            servers(&t)[MCP_SERVER_NAME],
            json!({ "url": format!("{}/mcp", t.svc.relay_url()), "transport": "streamable-http" })
        );
        assert_eq!(servers(&t).len(), 2, "other MCP servers stay");
        assert!(
            !t.oc.config().to_string().contains("oct_agent-token"),
            "the token is never in OpenClaw's config"
        );
        let state: Value =
            serde_json::from_str(&std::fs::read_to_string(t.dir.path().join("connectors.json")).expect("s"))
                .expect("j");
        assert_eq!(state["gateway"]["token"], "oct_agent-token");
        let env = std::fs::read_to_string(t.dir.path().join("oomol/connector.env")).expect("env");
        assert!(env.contains("OOMOL_CONNECT_RUNTIME_TOKEN=oct_agent-token"));
        let status = t.svc.status().await;
        assert_eq!(status["configured"], json!(true));
        assert!(!status.to_string().contains("oct_agent-token"));
        assert_eq!(status["connections"][0]["id"], "rc-gitea-1");

        t.svc.start_relay();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let http = reqwest::Client::new();
        let relay = t.svc.relay_url();
        let res = http
            .post(format!("{relay}/mcp"))
            .body("{}")
            .send()
            .await
            .expect("relay");
        assert_eq!(res.status(), 200);
        assert_eq!(lock(&seen)[0], "Bearer oct_agent-token");
        let res = http
            .post(format!("{relay}/v1/actions/gitea.get_current_user"))
            .body("{}")
            .send()
            .await
            .expect("relay");
        assert_eq!(res.status(), 200);
        for path in [
            "/api/connections",
            "/",
            "/openapi.json",
            "/v1/connections",
            "/v1/providers/github/setup",
        ] {
            assert_eq!(
                http.get(format!("{relay}{path}")).send().await.expect("r").status(),
                404,
                "{path}"
            );
        }
        assert_eq!(lock(&seen).len(), 2, "nothing else was forwarded");

        // Remove: the entry, the CLI env and the relay's grant go.
        let r = t.svc.apply(ApplyInput::Remove).await.expect("ok");
        assert_eq!(r["applied"], json!(["removed"]));
        assert_eq!(servers(&t).keys().collect::<Vec<_>>(), ["controlclaw-console"]);
        assert!(!t.dir.path().join("oomol/connector.env").exists());
        assert_eq!(
            http.post(format!("{relay}/mcp"))
                .body("{}")
                .send()
                .await
                .expect("r")
                .status(),
            503
        );
    }

    #[tokio::test]
    async fn the_relay_passes_an_upstream_error_and_says_when_nobody_answers() {
        let t = setup(json!({}));
        let (gate_url, _) = gate(500).await;
        t.svc.apply(apply_input(&gate_url)).await.expect("ok");
        t.svc.start_relay();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let http = reqwest::Client::new();
        let relay = t.svc.relay_url();
        assert_eq!(
            http.post(format!("{relay}/mcp"))
                .body("{}")
                .send()
                .await
                .expect("r")
                .status(),
            500
        );
        t.svc
            .apply(apply_input(&format!("http://127.0.0.1:{}", free_port())))
            .await
            .expect("ok");
        let r = http.post(format!("{relay}/mcp")).body("{}").send().await.expect("r");
        assert_eq!(r.status(), 502);
        assert_eq!(
            r.json::<Value>().await.expect("j"),
            json!({ "error": "Your firewall's connector runtime is not answering." })
        );
        assert_eq!(t.svc.status().await["gatewayReachable"], json!(false));
    }

    #[tokio::test]
    async fn a_leftover_mcp_servers_is_moved_in_the_same_write() {
        let t = setup(
            json!({ "mcpServers": { "controlclaw": { "url": "http://127.0.0.1:1/mcp", "transport": "streamable-http" } } }),
        );
        t.svc.apply(apply_input("http://127.0.0.1:9")).await.expect("ok");
        assert_eq!(t.oc.config().get("mcpServers"), None);
        assert!(servers(&t).contains_key(MCP_SERVER_NAME));
        let said = Mutex::new(Vec::<String>::new());
        let log = |l: &str| lock(&said).push(l.to_string());
        let raw = mcp_patch(
            &json!({
                "mcpServers": {
                    "controlclaw": {},
                    "other": { "url": "o", "type": "http", "transport": "streamable-http", "headers": { "a": "1" }, "timeout": 5 },
                    "local": { "command": "x", "args": ["a", 1] },
                    "broken": { "type": "http" },
                    "taken": { "url": "old" },
                },
                "mcp": { "servers": { "taken": { "url": "new" } } },
            }),
            None,
            &log,
        );
        assert_eq!(
            Value::Object(raw),
            json!({ "mcp": { "servers": { "other": { "url": "o", "transport": "streamable-http", "headers": { "a": "1" } }, "local": { "command": "x" }, "controlclaw": null, "controlclaw-apps": null } }, "mcpServers": null })
        );
        let said = lock(&said).join("\n");
        assert!(said.contains("mcpServers.other moved without type, timeout"), "{said}");
        assert!(said.contains("mcpServers.local moved without args"));
        assert!(said.contains("mcpServers.broken not moved: it has neither a url nor a command"));
        assert!(said.contains("mcpServers.taken not moved: mcp.servers already has taken"));
        assert!(!mcp_patch(&json!({ "mcp": { "servers": {} } }), None, &quiet).contains_key("mcpServers"));
    }

    #[test]
    fn a_null_entry_is_no_entry() {
        let w = json!({ "url": "u", "transport": "streamable-http" });
        assert!(entry_matches(Some(&Value::Null), None));
        assert!(entry_matches(None, None));
        assert!(!entry_matches(Some(&w), None));
        assert!(entry_matches(Some(&w), Some(&w)));
        assert!(!entry_matches(Some(&Value::Null), Some(&w)));
    }

    #[tokio::test]
    async fn heal_adds_moves_and_removes_and_writes_nothing_when_level() {
        let t = setup(json!({ "mcp": { "servers": { "controlclaw-console": {} } } }));
        t.svc.apply(apply_input("http://127.0.0.1:9")).await.expect("ok");
        t.oc.external_write(
            json!({ "mcp": { "servers": { "controlclaw-apps": null } } }),
            Duration::ZERO,
        );
        t.svc.heal().await;
        assert!(servers(&t).contains_key(MCP_SERVER_NAME));
        let before = t.oc.state().patches.len();
        t.svc.heal().await;
        assert_eq!(
            t.oc.state().patches.len(),
            before,
            "a write restarts the gateway: none when nothing differs"
        );
        // A fresh process with no apps saved removes the entry.
        t.svc.apply(ApplyInput::Remove).await.expect("ok");
        t.oc.external_write(
            json!({ "mcp": { "servers": { "controlclaw-apps": { "url": "x", "transport": "streamable-http" } } } }),
            Duration::ZERO,
        );
        let fresh = Arc::new(ConnectorsService::new(
            t.deps.clone(),
            1,
            t.dir.path().join("connectors.json"),
            t.dir.path().join("e"),
            Arc::new(|| false),
        ));
        fresh.heal().await;
        assert_eq!(servers(&t).keys().collect::<Vec<_>>(), ["controlclaw-console"]);
    }

    #[tokio::test]
    async fn heal_waits_while_busy_never_judges_without_a_state_and_stops_after_two_writes() {
        let t = setup(
            json!({ "mcp": { "servers": { "controlclaw-apps": { "url": "x", "transport": "streamable-http" } } } }),
        );
        t.busy.store(true, Ordering::SeqCst);
        t.svc.heal().await;
        t.busy.store(false, Ordering::SeqCst);
        t.svc.heal().await;
        assert!(t.oc.state().patches.is_empty(), "waiting for its timer");
        let other = Arc::new(ConnectorsService::new(
            t.deps.clone(),
            1,
            t.dir.path().join("none/connectors.json"),
            t.dir.path().join("e"),
            Arc::new(|| false),
        ));
        other.heal().await;
        assert!(
            servers(&t).contains_key(MCP_SERVER_NAME),
            "no saved state: not ours to judge"
        );
        // A gateway that never takes the entry: two writes, then no more.
        t.svc.apply(apply_input("http://127.0.0.1:9")).await.expect("ok");
        let loaded = Arc::new(ConnectorsService::new(
            t.deps.clone(),
            1,
            t.dir.path().join("connectors.json"),
            t.dir.path().join("e"),
            Arc::new(|| false),
        ));
        t.gw.hook(|m, _| (m == "config.patch").then(|| Ok(json!({ "ok": true }))));
        t.oc.external_write(
            json!({ "mcp": { "servers": { "controlclaw-apps": null } } }),
            Duration::ZERO,
        );
        let patches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let p = patches.clone();
        t.gw.hook(move |m, _| {
            (m == "config.patch").then(|| {
                p.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "ok": true }))
            })
        });
        for _ in 0..4 {
            loaded.heal().await;
        }
        assert_eq!(patches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn repair_moves_our_leftover_and_keeps_the_rest() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().expect("dir");
        let path = d.path().join("openclaw.json");
        let entry = json!({ "url": "http://127.0.0.1:3111/mcp", "transport": "streamable-http" });
        std::fs::write(&path, json!({ "gateway": { "port": 1 }, "mcpServers": { "controlclaw": { "url": "old" }, "other": { "url": "o" } }, "mcp": { "servers": { "controlclaw-console": { "url": "c" }, "controlclaw": { "url": "test branch" } } } }).to_string()).expect("w");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::write(d.path().join("openclaw.json.tmp"), "stale").expect("w");
        assert!(repair_config_file(&path, Some(&entry), &quiet));
        let fixed: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("r")).expect("j");
        assert_eq!(fixed.get("mcpServers"), None);
        assert_eq!(
            fixed["mcp"]["servers"],
            json!({ "controlclaw-console": { "url": "c" }, "other": { "url": "o" }, "controlclaw-apps": entry })
        );
        assert_eq!(fixed["gateway"], json!({ "port": 1 }));
        assert_eq!(std::fs::metadata(&path).expect("m").permissions().mode() & 0o777, 0o600);
        assert!(
            !repair_config_file(&path, Some(&entry), &quiet),
            "a clean file is left alone"
        );
        std::fs::write(&path, json!({ "mcpServers": { "controlclaw": {} } }).to_string()).expect("w");
        assert!(repair_config_file(&path, None, &quiet));
        assert_eq!(
            serde_json::from_str::<Value>(&std::fs::read_to_string(&path).expect("r")).expect("j"),
            json!({ "mcp": { "servers": {} } })
        );
        std::fs::write(&path, "{ mcpServers: { controlclaw: {} }, // JSON5\n}").expect("w");
        let said = Mutex::new(String::new());
        assert!(!repair_config_file(&path, Some(&entry), &|l| lock(&said).push_str(l)));
        assert!(lock(&said).contains("not plain JSON"));
        assert!(!repair_config_file(
            &d.path().join("missing.json"),
            Some(&entry),
            &quiet
        ));
    }

    #[tokio::test]
    async fn apply_fails_cleanly_while_openclaw_is_down() {
        let t = setup(json!({}));
        t.gw.set_connected(false);
        assert_eq!(
            t.svc.apply(ApplyInput::Remove).await,
            Err("OpenClaw is not running on this box".into())
        );
    }
}
