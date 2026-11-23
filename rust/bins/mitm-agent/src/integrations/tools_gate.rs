//! The ControlClaw tools gate on `PRIVATE_IP:3940` (`controlplane-mcp-gate.ts`,
//! docs/plans/controlplane-mcp.md §5): how an agent box reaches ControlClaw's agent MCP. The agent's
//! OpenClaw has a bare URL to this listener and holds no token. For each call the gate:
//!
//! 1. maps the caller's private address to an agent of this organization (the identity map);
//! 2. refuses an agent under an emergency stop;
//! 3. reads the body (256 KB at most) and signs a 30-second token with this firewall's own key,
//!    carrying the agent's id and the body's sha256 (`purpose: "agent-mcp"`);
//! 4. posts the same body to the control plane and hands the answer back.
//!
//! On a standalone firewall it also relays agents' calls to the organization's brain
//! (`/brain/mcp`, docs/plans/standalone-brain.md B): only for an agent connected to it, not under
//! the emergency stop or the admin's brain lock, at most [`BRAIN_MAX_BODY`] a call and
//! [`BRAIN_IN_FLIGHT_PER_AGENT`] calls on their way per agent, with the answer
//! streamed back and [`BRAIN_IDLE`] of silence allowed.
//!
//! The same listener serves the agent's website logins tools (`/logins/mcp`, answered here) and the
//! organization's MCP servers (`/servers/<name>/mcp`, the server gate). It trusts the source
//! address alone (plan §3, a quirk kept).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::app::App;
use crate::integrations::connectors::gate::{remote_address, same_address};
use crate::integrations::js;
use crate::integrations::mcp::server_gate::{SERVER_GATE_PREFIX, ServerGate};
use cc_http::{BoxFuture, Ctx, Req, Resp};

pub const CONTROLPLANE_MCP_GATE_PORT: u16 = 3940;
pub const GATE_MAX_BODY: usize = 256 * 1024;
/// Per source address, per minute: far above what an agent needs, low enough to stop a loop.
pub const GATE_CALLS_PER_MINUTE: u32 = 120;
/// `/permission`'s calls a minute from one address (its own budget).
pub const PERMISSION_CALLS_PER_MINUTE: u32 = 600;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// The brain's path on this listener.
pub const BRAIN_PATH: &str = "/brain/mcp";
/// A call to the brain is held whole until it is sent (the token names its body's hash): at most
/// this much, read within [`BRAIN_BODY_WITHIN`]. A long page is well under it.
pub const BRAIN_MAX_BODY: usize = 4 * 1024 * 1024;
/// A body that trickles in holds a slot: it gets this long, not the listener's five minutes.
pub const BRAIN_BODY_WITHIN: Duration = Duration::from_secs(30);
/// Brain calls one agent may have on their way at once (read, held and sent), and all agents
/// together: with the body cap, what the firewall holds for the brain at most.
pub const BRAIN_IN_FLIGHT_PER_AGENT: usize = 4;
pub const BRAIN_IN_FLIGHT_TOTAL: usize = 16;
/// A brain answer can be a stream, and a `think` runs for minutes: this much silence is allowed.
pub const BRAIN_IDLE: Duration = Duration::from_secs(600);
/// Brain calls a minute from one address: its own budget, as searches come in bursts.
pub const BRAIN_CALLS_PER_MINUTE: u32 = 600;
/// Brain calls a minute from every agent together. Each takes a one-time id the brain keeps about
/// three minutes, and the brain keeps at most 12,000 of those for relayed calls (cc-auth): this
/// stays well under, so the brain never refuses the firewall's own calls as busy.
pub const BRAIN_CALLS_PER_MINUTE_TOTAL: u32 = 3_000;
/// Request headers the control plane may see. Never the caller's own authorization or cookies.
const FORWARD: &[&str] = &[
    "content-type",
    "accept",
    "mcp-protocol-version",
    "mcp-session-id",
    "last-event-id",
];
const ANSWER: &[&str] = &[
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
    "www-authenticate",
];

/// Tools the firewall answers itself on another path of the listener (the website logins, I3).
pub trait LocalTools: Send + Sync {
    fn path(&self) -> &str;
    /// The status and the JSON body (None: no body).
    fn answer(&self, vm_id: String, body: Bytes) -> BoxFuture<Result<(u16, Option<Value>), String>>;
}

/// Where the agent MCP lives, from the firewall's own control-plane URL.
pub fn control_plane_mcp_url(firewall_url: &str, over: Option<&str>) -> Option<String> {
    if let Some(o) = over.filter(|o| !o.is_empty()) {
        return Some(o.to_string());
    }
    let u = url::Url::parse(firewall_url).ok()?;
    let origin = u.origin();
    origin
        .is_tuple()
        .then(|| format!("{}/api/mcp/agent", origin.ascii_serialization()))
}

/// `GET /ca`: the vm id and the `installed` sha256 the box sent (when it is 64 hex characters);
/// the CA and its signature, None (404) without a CA, or an error (500, as the TS's throw).
pub type CaAnswer = Arc<dyn Fn(&str, Option<&str>) -> Result<Option<Value>, String> + Send + Sync>;

pub struct ToolsGate {
    app: Arc<App>,
    /// `GET /ca` (main #564), when this firewall has a CA to give.
    pub ca: std::sync::OnceLock<CaAnswer>,
    target: String,
    log_path: Option<PathBuf>,
    locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub local: Option<Arc<dyn LocalTools>>,
    servers: Option<Arc<ServerGate>>,
    windows: Mutex<HashMap<String, (i64, u32)>>,
    /// `/permission`'s own budget: an agent polling its approvals never starves its MCP calls.
    permission_windows: Mutex<HashMap<String, (i64, u32)>>,
    /// `/brain/mcp`'s own budget.
    brain_windows: Mutex<HashMap<String, (i64, u32)>>,
    /// Brain calls on their way, per agent address and in all.
    brain_in_flight: Arc<Mutex<HashMap<String, usize>>>,
    http: reqwest::Client,
}

fn refuse(status: u16) -> Resp {
    cc_http::empty(status)
}

impl ToolsGate {
    pub fn new(
        app: &Arc<App>,
        target: String,
        log_path: Option<PathBuf>,
        locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        local: Option<Arc<dyn LocalTools>>,
        servers: Option<Arc<ServerGate>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            ca: std::sync::OnceLock::new(),
            target,
            log_path,
            locked,
            local,
            servers,
            windows: Mutex::new(HashMap::new()),
            permission_windows: Mutex::new(HashMap::new()),
            brain_windows: Mutex::new(HashMap::new()),
            brain_in_flight: Arc::new(Mutex::new(HashMap::new())),
            // `redirect: "manual"`.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap_or_default(),
        })
    }

    /// The router for a standalone firewall's listener toward its agents' vm-agents (an agent in a
    /// container on another network than its vm-agent, as `up --all` sets it up): only `/permission`,
    /// and only for an agent whose paired vm-agent is at the caller's address.
    pub fn permission_router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["gate"]);
        let me = self.clone();
        r.route(
            "gate",
            |_, _| true,
            move |req, ctx| {
                let me = me.clone();
                async move { me.serve_vm_agent(req, ctx).await }
            },
        );
        r
    }

    async fn serve_vm_agent(self: Arc<Self>, req: Req, ctx: Ctx) -> Resp {
        let address = remote_address(&ctx);
        let address = address.strip_prefix("::ffff:").unwrap_or(&address).to_string();
        if req.uri().path() != PERMISSION_PATH {
            return refuse(404);
        }
        let agents: Vec<_> = self
            .app
            .contracts
            .identities
            .require()
            .map(|ids| {
                ids.agents()
                    .into_iter()
                    .filter(|a| {
                        ids.route_for(&a.vm_id)
                            .is_some_and(|r| same_address(Some(&address), Some(&r.host)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        // The caller is known by its address alone: two agents whose vm-agents share it cannot be told
        // apart, so neither is answered here.
        let agent = match agents.as_slice() {
            [one] => one.clone(),
            [] => {
                tracing::info!("[auto-approve] refused a call from {address}: not a paired agent's vm-agent");
                return marked(refuse(403));
            }
            _ => {
                tracing::warn!(
                    "[auto-approve] refused a call from {address}: {} paired agents have their vm-agent there",
                    agents.len()
                );
                return marked(refuse(403));
            }
        };
        if (self.locked)(&agent.vm_id) {
            return marked(refuse(403));
        }
        if self.over_permission_budget(&address) {
            return marked(refuse(429));
        }
        match self.app.contracts.agent_permissions.get() {
            Some(p) => permission(p, &agent.vm_id, req).await,
            None => marked(refuse(503)),
        }
    }

    pub fn router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["gate"]);
        let me = self.clone();
        r.route(
            "gate",
            |_, _| true,
            move |req, ctx| {
                let me = me.clone();
                async move { me.serve(req, ctx).await }
            },
        );
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        vm_id: &str,
        method: &str,
        status: u16,
        sent: usize,
        answered: usize,
        started_at: i64,
        refused: Option<&str>,
    ) {
        self.record_at("/mcp", vm_id, method, status, sent, answered, started_at, refused, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_at(
        &self,
        path: &str,
        vm_id: &str,
        method: &str,
        status: u16,
        sent: usize,
        answered: usize,
        started_at: i64,
        refused: Option<&str>,
        brain: Option<(&str, Option<&str>)>,
    ) {
        use crate::channels::ai::internal::{SIZES_FIELD, SIZES_OUT_IS_SENT, TOOLS_FLOW, TOOLS_HOST, TOOLS_RULE};
        let Some(p) = &self.log_path else { return };
        let now = js::now_ms();
        let mut rec = json!({
            "source": "egress",
            "flow_id": format!("{TOOLS_FLOW}{}", hex::encode(rand::random::<[u8; 10]>())),
            "ts": now as f64 / 1000.0,
            "method": super::mcp::client::cut(method, 16),
            "host": TOOLS_HOST,
            "path": path,
            "vm_id": vm_id,
            "effect": if refused.is_some() { "drop" } else { "allow" },
            "status": status,
            // As the proxy's records: `bytes_out` is what the agent sent, `bytes_in` the answer.
            "bytes_out": sent,
            "bytes_in": answered,
            SIZES_FIELD: SIZES_OUT_IS_SENT,
            "duration_ms": (now - started_at).max(0),
            "rule": match refused { Some(r) => format!("{TOOLS_RULE}: {r}"), None => TOOLS_RULE.into() },
        });
        // A brain call's tool, by name only, and the agent's scope there: the panel's Brain counts
        // read them.
        if let Some((scope, tool)) = brain {
            rec["scope"] = json!(scope);
            if let Some(t) = tool {
                rec["tool"] = json!(t);
            }
        }
        // Activity must never be what fails a call.
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(p) {
            let _ = f.write_all(format!("{}\n", js::stringify(&rec)).as_bytes());
        }
    }

    fn over_budget(&self, address: &str) -> bool {
        over(&self.windows, address, GATE_CALLS_PER_MINUTE)
    }

    fn over_permission_budget(&self, address: &str) -> bool {
        over(&self.permission_windows, address, PERMISSION_CALLS_PER_MINUTE)
    }

    fn over_brain_budget(&self, address: &str) -> bool {
        over(&self.brain_windows, address, BRAIN_CALLS_PER_MINUTE)
    }

    /// Every agent's brain calls together, counted only for calls that go on to the brain.
    fn over_brain_total(&self) -> bool {
        over(&self.brain_windows, "", BRAIN_CALLS_PER_MINUTE_TOTAL)
    }

    /// A slot for one brain call from `address`, or `None` when that agent, or every agent
    /// together, already has as many on their way as allowed. Freed when the slot is dropped.
    fn brain_slot(&self, address: &str) -> Option<BrainSlot> {
        let mut m = self.brain_in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let total: usize = m.values().sum();
        let mine = m.get(address).copied().unwrap_or(0);
        if total >= BRAIN_IN_FLIGHT_TOTAL || mine >= BRAIN_IN_FLIGHT_PER_AGENT {
            return None;
        }
        m.insert(address.to_string(), mine + 1);
        Some(BrainSlot {
            map: self.brain_in_flight.clone(),
            address: address.to_string(),
        })
    }
}

fn over(windows: &Mutex<HashMap<String, (i64, u32)>>, address: &str, limit: u32) -> bool {
    {
        let t = js::now_ms();
        let mut w = windows.lock().unwrap_or_else(|e| e.into_inner());
        match w.get_mut(address) {
            Some((start, count)) if t - *start < 60_000 => {
                *count += 1;
                *count > limit
            }
            _ => {
                w.insert(address.to_string(), (t, 1));
                if w.len() > 1000 {
                    w.clear();
                }
                false
            }
        }
    }
}

impl ToolsGate {
    async fn serve(self: Arc<Self>, req: Req, ctx: Ctx) -> Resp {
        let started_at = js::now_ms();
        let method = req.method().as_str().to_string();
        let address = remote_address(&ctx);
        let address = address.strip_prefix("::ffff:").unwrap_or(&address).to_string();
        let path = req.uri().path().to_string();
        let local = self.local.clone().filter(|l| l.path() == path);
        let servers = self.servers.clone().filter(|_| path.starts_with(SERVER_GATE_PREFIX));
        let ca = self.ca.get().cloned().filter(|_| path == "/ca");
        // OpenClaw's own approvals (`core/auto_approve.rs`): answered here once this firewall keeps
        // the rules; what it says before that is marked, so the agent tells it from an older firewall.
        let permissions = (path == PERMISSION_PATH).then(|| self.app.contracts.agent_permissions.get());
        let brain = self.app.contracts.brain_relay.get().filter(|_| path == BRAIN_PATH);
        if path != "/mcp"
            && local.is_none()
            && servers.is_none()
            && ca.is_none()
            && permissions.is_none()
            && brain.is_none()
        {
            return refuse(404);
        }
        // No identity map yet: nobody is known, so every caller is refused.
        let agent = self.app.contracts.identities.require().ok().and_then(|ids| {
            ids.agents()
                .into_iter()
                .find(|a| !a.private_ip.is_empty() && same_address(Some(&address), Some(&a.private_ip)))
        });
        let Some(agent) = agent else {
            tracing::info!("[cp-mcp] refused a call from {address}: not an agent of this organization");
            return refuse(403);
        };
        let vm_id = agent.vm_id.clone();
        // The signed CA, also under an emergency stop: a stopped box keeps its control-plane
        // channel, which needs this CA. `?installed=<sha256>` is the box saying it installed it.
        if let Some(ca) = ca {
            if method != "GET" {
                return refuse(405);
            }
            let installed = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .find(|(k, _)| k == "installed")
                .map(|(_, v)| v.into_owned())
                .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            // Reading, signing and (for a new box) rewriting the proxy's files: off the runtime.
            let who = vm_id.clone();
            let pair = match tokio::task::spawn_blocking(move || ca(&who, installed.as_deref())).await {
                Ok(Ok(Some(pair))) => pair,
                Ok(Ok(None)) => return refuse(404),
                Ok(Err(e)) => {
                    tracing::warn!("[cp-mcp] /ca for {vm_id} failed: {e}");
                    return refuse(500);
                }
                Err(_) => return refuse(500),
            };
            let body = js::stringify(&pair);
            let len = body.len();
            let mut r = cc_http::full(StatusCode::OK, "application/json", body);
            r.headers_mut()
                .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
            r.headers_mut()
                .insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return r;
        }
        if (self.locked)(&vm_id) {
            self.record(&vm_id, &method, 403, 0, 0, started_at, Some("emergency stop"));
            return refuse(403);
        }
        if let Some(b) = brain {
            return self.brain(b, &vm_id, &address, req, started_at).await;
        }
        if let Some(s) = servers {
            if self.over_budget(&address) {
                return refuse(429);
            }
            return s.handle(&vm_id, req).await;
        }
        if let Some(p) = permissions {
            if self.over_permission_budget(&address) {
                return marked(refuse(429));
            }
            return match p {
                Some(p) => permission(p, &vm_id, req).await,
                None => marked(refuse(503)),
            };
        }
        // Stateless server: a 2025 client's GET (an event stream) or DELETE is answered here.
        if method != "POST" {
            let mut r = refuse(405);
            r.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("POST"));
            return r;
        }
        if self.over_budget(&address) {
            self.record(&vm_id, &method, 429, 0, 0, started_at, Some("too many calls"));
            return refuse(429);
        }
        let declared = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
            .unwrap_or(0.0);
        if declared > GATE_MAX_BODY as f64 {
            self.record(&vm_id, &method, 413, 0, 0, started_at, Some("too large"));
            return refuse(413);
        }
        let headers = req.headers().clone();
        let body = match http_body_util::Limited::new(req.into_body(), GATE_MAX_BODY)
            .collect()
            .await
        {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                // A chunked body over the cap: answered, then the connection is closed.
                self.record(
                    &vm_id,
                    &method,
                    413,
                    GATE_MAX_BODY + 1,
                    0,
                    started_at,
                    Some("too large"),
                );
                let mut r = refuse(413);
                r.headers_mut()
                    .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
                return r;
            }
        };
        if let Some(l) = local {
            return match l.answer(vm_id.clone(), body).await {
                Ok((status, doc)) => {
                    let out = doc.map(|d| js::stringify(&d)).unwrap_or_default();
                    let len = out.len();
                    let mut r = cc_http::full(
                        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                        "application/json",
                        out,
                    );
                    r.headers_mut()
                        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
                    r
                }
                Err(e) => {
                    tracing::info!("[logins] tool call failed for {vm_id}: {e}");
                    refuse(500)
                }
            };
        }
        // No ControlClaw MCP behind this gate (a standalone firewall): answered here, and no token
        // is signed for a control plane that does not exist.
        if self.target.is_empty() {
            self.record(&vm_id, &method, 404, body.len(), 0, started_at, None);
            return refuse(404);
        }
        let mut claims = Map::new();
        claims.insert("purpose".into(), json!("agent-mcp"));
        claims.insert("agentVmId".into(), json!(vm_id));
        claims.insert("bodySha256".into(), json!(hex::encode(Sha256::digest(&body))));
        claims.insert("jti".into(), json!(hex::encode(rand::random::<[u8; 12]>())));
        let token = match cc_auth::sign::gate_token(&self.app.keys, claims) {
            Ok(t) => t,
            Err(e) => {
                tracing::info!("[cp-mcp] upstream failed for {vm_id}: {e}");
                self.record(&vm_id, &method, 502, body.len(), 0, started_at, None);
                return refuse(502);
            }
        };
        let mut up = self
            .http
            .post(&self.target)
            .timeout(UPSTREAM_TIMEOUT)
            .header("authorization", format!("Bearer {token}"));
        for h in FORWARD {
            let all: Vec<&HeaderValue> = headers.get_all(*h).iter().collect();
            if all.len() == 1 {
                up = up.header(*h, all[0].clone());
            }
        }
        let bytes_in = body.len();
        let answer = async {
            // Never the URL in what is logged.
            let r = up.body(body).send().await.map_err(|e| e.without_url().to_string())?;
            let status = r.status().as_u16();
            let h = r.headers().clone();
            let out = r.bytes().await.map_err(|e| e.without_url().to_string())?;
            Ok::<_, String>((status, h, out))
        }
        .await;
        match answer {
            Ok((status, h, out)) => {
                let mut r = cc_http::full(
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                    "",
                    out.clone(),
                );
                r.headers_mut()
                    .insert(http::header::CONTENT_LENGTH, HeaderValue::from(out.len()));
                for name in ANSWER {
                    if let Some(v) = h.get(*name) {
                        r.headers_mut().insert(*name, v.clone());
                    }
                }
                self.record(&vm_id, &method, status, bytes_in, out.len(), started_at, None);
                r
            }
            Err(e) => {
                tracing::info!("[cp-mcp] upstream failed for {vm_id}: {e}");
                self.record(&vm_id, &method, 502, bytes_in, 0, started_at, None);
                refuse(502)
            }
        }
    }
}

impl ToolsGate {
    /// `/brain/mcp`: one call relayed to the brain for `vm_id` (told by its address, not stopped).
    async fn brain(
        self: &Arc<Self>,
        relay: Arc<dyn crate::contracts::BrainRelay>,
        vm_id: &str,
        address: &str,
        req: Req,
        started_at: i64,
    ) -> Resp {
        let method = req.method().as_str().to_string();
        let rec = |status: u16, sent: usize, why: Option<&str>| {
            self.record_at(BRAIN_PATH, vm_id, &method, status, sent, 0, started_at, why, None);
        };
        if !matches!(method.as_str(), "POST" | "GET" | "DELETE") {
            let mut r = refuse(405);
            r.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("POST, GET, DELETE"));
            return r;
        }
        // The budget first, and no Activity row past it: an agent refused for another reason
        // cannot flood the log either.
        if self.over_brain_budget(address) {
            return brain_refusal(429, "Too many brain calls a minute. Wait a moment and try again.");
        }
        let brain_vm = match relay.relay_for(vm_id) {
            Ok(b) => b,
            Err(why) => {
                tracing::info!("[gbrain] refused a brain call from {vm_id}: {why}");
                rec(403, 0, Some(why));
                return refuse(403);
            }
        };
        if self.over_brain_total() {
            return brain_refusal(
                429,
                "The brain is taking too many calls a minute. Wait a moment and try again.",
            );
        }
        let Some(slot) = self.brain_slot(address) else {
            return brain_refusal(
                429,
                "Too many brain calls on their way at once. Wait for one to finish and try again.",
            );
        };
        let declared = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if declared > BRAIN_MAX_BODY as u64 {
            rec(413, 0, Some("too large"));
            return brain_refusal(413, "A brain call is at most 4 MB.");
        }
        let (parts, body) = req.into_parts();
        let Ok(Some(body)) = tokio::time::timeout(BRAIN_BODY_WITHIN, cc_http::read_body(body, BRAIN_MAX_BODY)).await
        else {
            rec(413, BRAIN_MAX_BODY + 1, Some("too large or too slow"));
            let mut r = brain_refusal(413, "A brain call is at most 4 MB, sent within 30 seconds.");
            r.headers_mut()
                .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
            return r;
        };
        let headers: Vec<(&'static str, HeaderValue)> = FORWARD
            .iter()
            .filter_map(|h| {
                let all: Vec<&HeaderValue> = parts.headers.get_all(*h).iter().collect();
                (all.len() == 1).then(|| (*h, all[0].clone()))
            })
            .collect();
        let sent = body.len();
        let tool = brain_tool(&body);
        let scope = relay.scope_of(vm_id).unwrap_or_default();
        let up = relay
            .send(brain_vm, vm_id.to_string(), method.clone(), headers, body)
            .await;
        // The brain has the call (or refused it): its body is no longer held here.
        drop(slot);
        let up = match up {
            Ok(r) => r,
            Err(e) => {
                tracing::info!("[gbrain] relaying {vm_id}'s call failed: {e}");
                rec(502, sent, None);
                return refuse(502);
            }
        };
        let status = up.status().as_u16();
        let mut out = http::Response::builder().status(status);
        for name in ANSWER {
            if let Some(v) = up.headers().get(*name) {
                out = out.header(*name, v.clone());
            }
        }
        if let Some(v) = up.headers().get(http::header::CACHE_CONTROL) {
            out = out.header(http::header::CACHE_CONTROL, v.clone());
        }
        // The answer as it comes (an SSE stream, a long `think`), and the row once it ended.
        let done = BrainCallDone {
            gate: self.clone(),
            vm_id: vm_id.to_string(),
            method,
            status,
            sent,
            answered: 0,
            started_at,
            tool,
            scope,
        };
        let frames = futures_util::stream::unfold(
            (Box::pin(up.bytes_stream()), done),
            |(mut stream, mut done)| async move {
                use futures_util::StreamExt;
                match tokio::time::timeout(BRAIN_IDLE, stream.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        done.answered += chunk.len();
                        Some((Ok(hyper::body::Frame::data(chunk)), (stream, done)))
                    }
                    Ok(Some(Err(e))) => Some((Err(std::io::Error::other(e.without_url())), (stream, done))),
                    Ok(None) => None,
                    Err(_) => Some((
                        Err(std::io::Error::other("the brain sent nothing for too long")),
                        (stream, done),
                    )),
                }
            },
        );
        let body: cc_http::Body = http_body_util::StreamBody::new(frames).boxed();
        out.body(body).unwrap_or_else(|_| refuse(502))
    }
}

/// One brain call on its way from an agent (`ToolsGate::brain_slot`).
struct BrainSlot {
    map: Arc<Mutex<HashMap<String, usize>>>,
    address: String,
}

impl Drop for BrainSlot {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.address) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.address);
            }
        }
    }
}

/// A refusal of a brain call the agent can read: `{error}`, and when to try again.
fn brain_refusal(status: u16, message: &str) -> Resp {
    let text = js::stringify(&json!({ "error": message }));
    let len = text.len();
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
        "application/json",
        text,
    );
    r.headers_mut()
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
    if status == 429 {
        r.headers_mut()
            .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    r
}

/// Writes a brain call's activity row when its answer ended (or the agent hung up).
struct BrainCallDone {
    gate: Arc<ToolsGate>,
    vm_id: String,
    method: String,
    status: u16,
    sent: usize,
    answered: usize,
    started_at: i64,
    tool: Option<String>,
    scope: String,
}

impl Drop for BrainCallDone {
    fn drop(&mut self) {
        // The brain's own refusal (a lock there, a token it did not take) shows as one.
        let refused = (self.status >= 400).then(|| format!("the brain answered {}", self.status));
        self.gate.record_at(
            BRAIN_PATH,
            &self.vm_id,
            &self.method,
            self.status,
            self.sent,
            self.answered,
            self.started_at,
            refused.as_deref(),
            Some((self.scope.as_str(), self.tool.as_deref())),
        );
    }
}

/// The tool a brain call runs (`tools/call`'s `params.name`), when it is a plain name: what the
/// panel counts as a search or a save. Nothing else of the body is kept.
fn brain_tool(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    if v.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let name = v.pointer("/params/name").and_then(Value::as_str)?;
    (!name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    .then(|| name.to_string())
}

/// Where an agent's vm-agent sends OpenClaw's approvals.
pub const PERMISSION_PATH: &str = "/permission";
/// A raise is a title, a few detail rows and ids: well under this.
const PERMISSION_MAX_BODY: usize = 16 * 1024;

/// `/permission` for the agent the gate named: `GET ?permission_id=` and `POST` (a raise, or a
/// request the agent settled itself), answered as the control plane answers them.
/// Every `/permission` answer says it is this gate's: a 404 without it is an older firewall.
pub const GATE_HEADER: &str = "x-cc-gate";
/// On a 404: this firewall does not check the rules yet (its store is not seeded).
pub const OFF_HEADER: &str = "x-cc-auto-approve";
/// The agent's own box token, which a settle carries to the control plane.
pub const AGENT_TOKEN_HEADER: &str = "x-cc-agent-token";

fn marked(mut r: Resp) -> Resp {
    r.headers_mut().insert(GATE_HEADER, HeaderValue::from_static("1"));
    r
}

async fn permission(p: Arc<dyn crate::contracts::AgentPermissions>, vm_id: &str, req: Req) -> Resp {
    if !p.active() {
        let mut r = marked(refuse(404));
        r.headers_mut().insert(OFF_HEADER, HeaderValue::from_static("off"));
        return r;
    }
    marked(answer_permission(p, vm_id, req).await)
}

async fn answer_permission(p: Arc<dyn crate::contracts::AgentPermissions>, vm_id: &str, req: Req) -> Resp {
    let reply = |(status, body): (u16, Value)| {
        let text = js::stringify(&body);
        let len = text.len();
        let mut r = cc_http::full(
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            "application/json",
            text,
        );
        r.headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
        r
    };
    match req.method().as_str() {
        "GET" => {
            let id = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .find(|(k, _)| k == "permission_id")
                .map(|(_, v)| v.into_owned())
                .filter(|v| (1..=128).contains(&v.len()));
            match id {
                Some(id) => reply(p.status(vm_id, &id).await),
                None => refuse(400),
            }
        }
        "POST" => {
            // A settle is the agent's own, as it always was: it carries the vm-agent's box token, which
            // the control plane checks. Anything else at the agent's address (OpenClaw) has none.
            let token = req
                .headers()
                .get(AGENT_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|t| !t.is_empty() && t.len() <= 4096)
                .map(str::to_string);
            let body = match http_body_util::Limited::new(req.into_body(), PERMISSION_MAX_BODY)
                .collect()
                .await
            {
                Ok(b) => b.to_bytes(),
                Err(_) => return refuse(413),
            };
            let Ok(v) = serde_json::from_slice::<Value>(&body) else {
                return refuse(400);
            };
            if v.get("resolution").is_some() {
                let Some(token) = token else { return refuse(403) };
                reply(p.settle(vm_id, v, &token).await)
            } else {
                reply(p.raise(vm_id, v).await)
            }
        }
        _ => {
            let mut r = refuse(405);
            r.headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("GET, POST"));
            r
        }
    }
}

#[cfg(test)]
mod tests;
