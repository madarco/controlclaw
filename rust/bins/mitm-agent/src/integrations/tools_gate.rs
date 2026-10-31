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
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
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
            // `redirect: "manual"`.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap_or_default(),
        })
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
        bytes_in: usize,
        bytes_out: usize,
        started_at: i64,
        refused: Option<&str>,
    ) {
        let Some(p) = &self.log_path else { return };
        let now = js::now_ms();
        let rec = json!({
            "source": "egress",
            "flow_id": format!("cpm-{}", hex::encode(rand::random::<[u8; 10]>())),
            "ts": now as f64 / 1000.0,
            "method": super::mcp::client::cut(method, 16),
            "host": "controlplane-mcp",
            "path": "/mcp",
            "vm_id": vm_id,
            "effect": if refused.is_some() { "drop" } else { "allow" },
            "status": status,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "duration_ms": (now - started_at).max(0),
            "rule": match refused { Some(r) => format!("controlclaw tools: {r}"), None => "controlclaw tools".into() },
        });
        // Activity must never be what fails a call.
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(p) {
            let _ = f.write_all(format!("{}\n", js::stringify(&rec)).as_bytes());
        }
    }

    fn over_budget(&self, address: &str) -> bool {
        let t = js::now_ms();
        let mut w = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        match w.get_mut(address) {
            Some((start, count)) if t - *start < 60_000 => {
                *count += 1;
                *count > GATE_CALLS_PER_MINUTE
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

    async fn serve(self: Arc<Self>, req: Req, ctx: Ctx) -> Resp {
        let started_at = js::now_ms();
        let method = req.method().as_str().to_string();
        let address = remote_address(&ctx);
        let address = address.strip_prefix("::ffff:").unwrap_or(&address).to_string();
        let path = req.uri().path().to_string();
        let local = self.local.clone().filter(|l| l.path() == path);
        let servers = self.servers.clone().filter(|_| path.starts_with(SERVER_GATE_PREFIX));
        let ca = self.ca.get().cloned().filter(|_| path == "/ca");
        if path != "/mcp" && local.is_none() && servers.is_none() && ca.is_none() {
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
        if let Some(s) = servers {
            if self.over_budget(&address) {
                return refuse(429);
            }
            return s.handle(&vm_id, req).await;
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

#[cfg(test)]
mod tests;
