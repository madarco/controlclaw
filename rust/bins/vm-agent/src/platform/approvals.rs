//! Bridges OpenClaw's own approvals (exec, plugin, system-agent) into the ControlClaw queue
//! (`approvals.ts`).
//!
//! `<family>.approval.requested` → `POST /permission` on the firewall's 3940 gate, which checks the
//! Auto approve rules and passes an Ask on to the control plane; approved or denied at once →
//! `approval.resolve`; pending → asked again every few seconds; `<family>.approval.resolved`
//! (answered in OpenClaw, cancelled, expired) → the resolution is posted so the console's card
//! clears. Decisions sent to the gateway are `allow-once` or `deny` only.
//!
//! A firewall that does not check the rules yet answers the gate with 404: the approval then goes to
//! the control plane's `/api/vm-agent/permission` as before (it runs the rules itself), and so does
//! every new one for [`GATE_OFF_MS`]. Each approval is asked about and settled where it was raised.
//!
//! What leaves the box: the command line (redacted, control characters stripped, cut at 200), cwd,
//! agent id, session key, host and OpenClaw's risk flags. Never environment, output or chat text.

use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock, Mutex};

use regex::Regex;
use serde_json::{Value, json};

use super::common::{Flag, js_slice, lock};
use super::time::iso_ms;

/// Event families → ControlClaw kinds. `openclaw.*` is OpenClaw's name for system-agent approvals.
pub const FAMILIES: [(&str, &str); 3] = [("exec", "exec"), ("plugin", "plugin"), ("openclaw", "system")];
pub const TITLE_MAX: usize = 200;
/// How long a gate that answered 404 is left alone before it is tried again.
pub const GATE_OFF_MS: i64 = 10 * 60_000;
/// The firewall's gate for its agents (`tools_gate.rs` in the mitm-agent).
pub const GATE_PORT: u16 = 3940;

// Control characters and ANSI escape sequences: a command line is untrusted text.
static CONTROL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x1f\x7f]").expect("regex"));
static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("regex"));

/// Plain, single-line, bounded text for the request card.
pub fn sanitize_title(text: &str, redact: &dyn Fn(&str) -> String) -> String {
    let flat = redact(text);
    let flat = CONTROL.replace_all(&flat, " ");
    let flat = SPACES.replace_all(&flat, " ");
    let flat = flat.trim();
    if flat.encode_utf16().count() > TITLE_MAX {
        format!("{}…", js_slice(flat, TITLE_MAX - 1))
    } else {
        flat.to_string()
    }
}

fn text(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

fn part<'a>(p: &'a Value, k: &str) -> &'a Value {
    match p.get(k) {
        Some(v) if v.is_object() => v,
        _ => &Value::Null,
    }
}

/// A one-line summary across the three families.
pub fn summary_of(kind: &str, p: &Value, redact: &dyn Fn(&str) -> String) -> String {
    let (r, pres) = (part(p, "request"), part(p, "presentation"));
    let candidate = [
        (r, "command"),
        (pres, "commandText"),
        (r, "rawCommand"),
        (r, "summary"),
        (pres, "summary"),
        (r, "title"),
        (pres, "title"),
        (r, "toolName"),
        (r, "pluginId"),
        (r, "action"),
    ]
    .iter()
    .find_map(|(o, k)| text(o.get(k)));
    sanitize_title(
        &candidate
            .map(str::to_string)
            .unwrap_or_else(|| format!("{kind} approval")),
        redact,
    )
}

pub fn detail_of(p: &Value, redact: &dyn Fn(&str) -> String) -> Vec<(String, String)> {
    let r = part(p, "request");
    let mut rows = Vec::new();
    let add = |rows: &mut Vec<(String, String)>, k: &str, v: Option<&Value>| {
        if let Some(s) = text(v) {
            rows.push((k.to_string(), sanitize_title(s, redact)));
        }
    };
    add(&mut rows, "agent", r.get("agentId"));
    add(&mut rows, "session", r.get("sessionKey"));
    add(&mut rows, "cwd", r.get("cwd"));
    add(&mut rows, "host", r.get("host"));
    // `r.pluginId ?? r.plugin`: a pluginId that is there but empty does not fall through.
    add(
        &mut rows,
        "plugin",
        r.get("pluginId").filter(|v| !v.is_null()).or(r.get("plugin")),
    );
    add(&mut rows, "tool", r.get("toolName"));
    if let Some(kinds) = r
        .pointer("/commandAnalysis/riskKinds")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    {
        let joined = kinds.iter().map(js_string).collect::<Vec<_>>().join(", ");
        rows.push(("risk".into(), sanitize_title(&joined, redact)));
    }
    add(&mut rows, "warning", r.get("warningText"));
    rows
}

/// `String(x)`.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// Gateway decision → console resolution. A deny without a resolver is OpenClaw giving up.
pub fn resolution_of(p: &Value) -> &'static str {
    let d = p
        .get("decision")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| p.get("status").and_then(Value::as_str))
        .unwrap_or("")
        .to_lowercase();
    if d.starts_with("allow") {
        return "approved";
    }
    if d == "deny" || d == "denied" {
        let by = p.get("resolvedBy").is_some_and(|v| match v {
            Value::String(s) => !s.is_empty(),
            Value::Null | Value::Bool(false) => false,
            _ => true,
        });
        return if by { "denied" } else { "expired" };
    }
    "expired"
}

/// Where an approval was raised: the firewall's gate, or the control plane itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Gate,
    Console,
}

/// What a permission endpoint answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// It took the call; the request's status word.
    Status(String),
    /// 404: a firewall that does not take approvals at its gate.
    Missing,
    /// Not reached, or refused: asked again on the next tick.
    Failed,
}

impl Answer {
    fn status(self) -> Option<String> {
        match self {
            Answer::Status(s) => Some(s),
            _ => None,
        }
    }
}

struct Tracked {
    kind: &'static str,
    approval_kind: String,
    payload: Value,
    expires_at: Option<f64>,
    /// None until the gate or the control plane took the POST; a tick raises it again meanwhile.
    via: Option<Via>,
    /// The gateway or the console decided; nothing more to do.
    done: bool,
    /// This bridge sent the decision, so the echoed `resolved` event is not news.
    resolved_by_us: bool,
}

/// A gateway method with its params.
pub type GatewayCall = Box<dyn Fn(&str, Value) -> cc_http::BoxFuture<Result<Value, String>> + Send + Sync>;
/// `POST` a body.
pub type PermissionPost = Box<dyn Fn(Value) -> cc_http::BoxFuture<Answer> + Send + Sync>;
/// `GET ?permission_id=`.
pub type PermissionGet = Box<dyn Fn(String) -> cc_http::BoxFuture<Answer> + Send + Sync>;

/// One place approvals are raised: the same calls on the gate and on the control plane.
pub struct Endpoint {
    pub post: PermissionPost,
    pub get: PermissionGet,
}

/// What the bridge needs from the box.
pub struct ApprovalsOptions {
    pub call: GatewayCall,
    /// The firewall's gate; none on a box with no firewall.
    pub gate: Option<Endpoint>,
    /// The control plane; none on an unmanaged box, which has only its firewall.
    pub console: Option<Endpoint>,
    pub redact: Box<dyn Fn(&str) -> String + Send + Sync>,
    pub log: Box<dyn Fn(&str) + Send + Sync>,
    pub now: Box<dyn Fn() -> i64 + Send + Sync>,
}

pub struct ApprovalsBridge {
    o: ApprovalsOptions,
    /// By approval id, in the order seen (a JS `Map`).
    tracked: Mutex<Vec<(String, Tracked)>>,
    in_flight: AtomicBool,
    /// Until when (ms) the gate is not tried, after it answered 404.
    gate_off_until: Mutex<i64>,
}

impl ApprovalsBridge {
    pub fn new(o: ApprovalsOptions) -> Self {
        Self {
            o,
            tracked: Mutex::new(Vec::new()),
            in_flight: AtomicBool::new(false),
            gate_off_until: Mutex::new(0),
        }
    }

    fn log(&self, line: &str) {
        (self.o.log)(&format!("[approvals] {line}"));
    }

    fn with<T>(&self, id: &str, f: impl FnOnce(&mut Tracked) -> T) -> Option<T> {
        lock(&self.tracked).iter_mut().find(|(i, _)| i == id).map(|(_, t)| f(t))
    }

    /// The session keys of the approvals still open, for Doing now.
    pub fn pending_sessions(&self) -> HashSet<String> {
        lock(&self.tracked)
            .iter()
            .filter(|(_, t)| !t.done)
            .filter_map(|(_, t)| {
                t.payload
                    .pointer("/request/sessionKey")
                    .and_then(Value::as_str)
                    .filter(|k| !k.is_empty())
            })
            .map(str::to_string)
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        lock(&self.tracked).iter().filter(|(_, t)| !t.done).count()
    }

    /// A gateway event: `<family>.approval.requested` or `.resolved`.
    pub async fn on_event(&self, event: &str, payload: &Value) {
        for (family, kind) in FAMILIES {
            if event == format!("{family}.approval.requested") {
                self.on_requested(kind, payload).await;
                return;
            }
            if event == format!("{family}.approval.resolved") {
                self.on_resolved(payload).await;
                return;
            }
        }
    }

    /// After a (re)connect: raise what is pending on the gateway, settle what vanished meanwhile.
    pub async fn reconcile(&self) {
        // Only entries from before the listing can have vanished.
        let known: Vec<String> = lock(&self.tracked).iter().map(|(i, _)| i.clone()).collect();
        let mut seen = HashSet::new();
        for (family, kind) in FAMILIES {
            let method = format!("{family}.approval.list");
            let list = match (self.o.call)(&method, json!({})).await {
                Ok(v) => v.as_array().cloned().unwrap_or_default(),
                Err(e) => {
                    self.log(&format!("{method} failed: {e}"));
                    continue;
                }
            };
            for p in list {
                let Some(id) = p.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) else {
                    continue;
                };
                seen.insert(id.to_string());
                if self.with(id, |_| ()).is_none() {
                    self.on_requested(kind, &p).await;
                }
            }
        }
        for id in known {
            let Some(approval_kind) = self
                .with(&id, |t| {
                    (!t.done && !seen.contains(&id)).then(|| t.approval_kind.clone())
                })
                .flatten()
            else {
                continue;
            };
            // Decided while away: the gateway's outcome, else expired.
            let mut resolution = "expired";
            if let Ok(got) = (self.o.call)("approval.get", json!({ "id": id, "kind": approval_kind })).await {
                let p = got.get("approval").filter(|a| !a.is_null()).cloned().unwrap_or(got);
                let has = |k: &str| p.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
                if has("decision") || has("status") {
                    resolution = resolution_of(&p);
                }
            }
            self.with(&id, |t| t.done = true);
            self.log(&format!("{id} gone from the gateway: {resolution}"));
            self.post_resolution(&id, resolution).await;
        }
    }

    pub async fn on_requested(&self, kind: &'static str, p: &Value) {
        let Some(id) = p.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) else {
            return;
        };
        {
            let mut tracked = lock(&self.tracked);
            if tracked.iter().any(|(i, _)| i == id) {
                return;
            }
            let approval_kind = p
                .get("approvalKind")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    if kind == "system" {
                        "openclaw".into()
                    } else {
                        kind.into()
                    }
                });
            tracked.push((
                id.to_string(),
                Tracked {
                    kind,
                    approval_kind,
                    payload: p.clone(),
                    expires_at: p.get("expiresAtMs").and_then(Value::as_f64),
                    via: None,
                    done: false,
                    resolved_by_us: false,
                },
            ));
        }
        self.raise(id).await;
    }

    fn endpoint(&self, via: Via) -> Option<&Endpoint> {
        match via {
            Via::Gate => self.o.gate.as_ref(),
            Via::Console => self.o.console.as_ref(),
        }
    }

    /// POST the body to the gate, else (none, or 404 lately) to the control plane. Where it was
    /// taken and the status; None when nobody took it (a tick tries again).
    async fn post_new(&self, body: Value) -> Option<(Via, String)> {
        let now = (self.o.now)();
        if let Some(gate) = &self.o.gate
            && now >= *lock(&self.gate_off_until)
        {
            match (gate.post)(body.clone()).await {
                Answer::Status(s) => return Some((Via::Gate, s)),
                // A firewall that does not check the rules yet: the control plane, for a while.
                Answer::Missing => {
                    *lock(&self.gate_off_until) = now + GATE_OFF_MS;
                    self.log("the firewall does not take approvals yet: asking ControlClaw");
                }
                // An emergency stop, or the firewall not reached: never around it.
                Answer::Failed => return None,
            }
        }
        let console = self.o.console.as_ref()?;
        (console.post)(body).await.status().map(|s| (Via::Console, s))
    }

    /// Raise the approval; a tick tries again when it fails.
    async fn raise(&self, id: &str) {
        let redact = |s: &str| (self.o.redact)(s);
        let Some(body) = self
            .with(id, |t| {
                (t.via.is_none() && !t.done).then(|| {
                    json!({
                        "permission_id": format!("oc:{id}"),
                        "kind": t.kind,
                        "title": summary_of(t.kind, &t.payload, &redact),
                        "detail": detail_of(&t.payload, &redact).into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                        // `expiresAt ? … : null`: zero is no expiry too.
                        "expires_at": t.expires_at.filter(|e| *e != 0.0).map(|e| iso_ms(e as i64)),
                    })
                })
            })
            .flatten()
        else {
            return;
        };
        let Some((via, status)) = self.post_new(body).await else {
            return;
        };
        let kind = self.with(id, |t| {
            t.via = Some(via);
            t.kind
        });
        let to = match via {
            Via::Gate => "the firewall",
            Via::Console => "ControlClaw",
        };
        self.log(&format!(
            "raised {} approval {id} with {to} → {status}",
            kind.unwrap_or_default()
        ));
        self.apply_status(id, &status).await;
    }

    pub async fn on_resolved(&self, p: &Value) {
        let Some(id) = p.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) else {
            return;
        };
        // Our own resolve echoes back as this event too; the control plane already knows.
        let fresh = self.with(id, |t| {
            if t.done {
                return false;
            }
            t.done = true;
            true
        });
        if fresh != Some(true) {
            return;
        }
        let resolution = resolution_of(p);
        self.log(&format!("{id} settled on the gateway: {resolution}"));
        self.post_resolution(id, resolution).await;
    }

    /// Asks the console about pending approvals. Called on an interval.
    pub async fn tick(&self) {
        let Some(_flying) = Flag::take(&self.in_flight) else {
            return;
        };
        let now = (self.o.now)() as f64;
        // Settled ids are kept an hour past expiry, so duplicate broadcasts stay idempotent.
        lock(&self.tracked)
            .retain(|(_, t)| !t.done || t.expires_at.is_some_and(|e| e != 0.0 && now <= e + 3_600_000.0));
        let ids: Vec<String> = lock(&self.tracked).iter().map(|(i, _)| i.clone()).collect();
        for id in ids {
            let Some((done, via, expired)) = self.with(&id, |t| {
                (
                    t.done,
                    t.via,
                    t.expires_at.is_some_and(|e| e != 0.0 && now > e + 60_000.0),
                )
            }) else {
                continue;
            };
            if done {
                continue;
            }
            if expired {
                // OpenClaw gave up and the event was missed. Clear the card.
                self.with(&id, |t| t.done = true);
                if via.is_some() {
                    self.post_resolution(&id, "expired").await;
                }
                continue;
            }
            let Some(ep) = via.and_then(|v| self.endpoint(v)) else {
                self.raise(&id).await;
                continue;
            };
            match (ep.get)(format!("oc:{id}")).await {
                Answer::Status(status) => self.apply_status(&id, &status).await,
                // The firewall stopped taking approvals (rolled back, or its rules could not be
                // read): raised again, which asks the control plane when the gate still says no.
                Answer::Missing if via == Some(Via::Gate) => {
                    self.with(&id, |t| t.via = None);
                }
                _ => {}
            }
        }
    }

    async fn apply_status(&self, id: &str, status: &str) {
        let Some(kind) = self.with(id, |t| (!t.done).then(|| t.approval_kind.clone())).flatten() else {
            return;
        };
        let decision = match status {
            "approved" => "allow-once",
            "denied" => "deny",
            "expired" => {
                self.with(id, |t| t.done = true);
                return;
            }
            _ => return,
        };
        match (self.o.call)(
            "approval.resolve",
            json!({ "id": id, "kind": kind, "decision": decision }),
        )
        .await
        {
            Ok(_) => {
                // Only now is it settled; a failed call leaves it pending so the next tick retries.
                self.with(id, |t| {
                    t.done = true;
                    t.resolved_by_us = true;
                });
                self.log(&format!("{id}: {decision}"));
            }
            Err(e) => self.log(&format!("approval.resolve {id} failed: {e}")),
        }
    }

    async fn post_resolution(&self, id: &str, resolution: &str) {
        // Told where it was raised; nobody saw one that was not.
        let Some(ep) = self.with(id, |t| t.via).flatten().and_then(|v| self.endpoint(v)) else {
            return;
        };
        let _ = (ep.post)(
            json!({ "permission_id": format!("oc:{id}"), "resolution": resolution, "resolved_by": "openclaw" }),
        )
        .await;
    }
}

/// The bridge, run against a gateway client: each approval event as it comes, a reconcile on every
/// connect and after events were lost (a lagged channel), and a tick every `every`. The tasks, so a
/// caller that sets it up again can stop them.
pub fn run_bridge(
    bridge: Arc<ApprovalsBridge>,
    client: &cc_openclaw::GatewayClient,
    every: std::time::Duration,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut events = client.events();
    let b = bridge.clone();
    let on_events = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) if ev.event.contains(".approval.") => {
                    let b = b.clone();
                    tokio::spawn(async move { b.on_event(&ev.event, &ev.payload).await });
                }
                Ok(_) => {}
                // Events were dropped: what is pending on the gateway is listed again.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => b.reconcile().await,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    });
    let mut connected = client.connection_state();
    let b = bridge.clone();
    let on_connect = tokio::spawn(async move {
        loop {
            if *connected.borrow_and_update() {
                b.reconcile().await;
            }
            if connected.changed().await.is_err() {
                return;
            }
        }
    });
    let ticks = tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.tick().await;
        loop {
            tick.tick().await;
            let b = bridge.clone();
            if tokio::spawn(async move { b.tick().await }).await.is_err() {
                tracing::error!("[approvals] tick failed");
            }
        }
    });
    vec![on_events, on_connect, ticks]
}

/// The real control-plane calls: `<base>/api/vm-agent/permission` with the box's token, 20 s.
pub fn permission_calls(
    base: String,
    keys: cc_auth::keys::KeysDir,
    http: cc_client::HttpClient,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Endpoint {
    let url = format!("{base}/api/vm-agent/permission");
    let (u1, k1, h1) = (url.clone(), keys.clone(), http.clone());
    let post = Box::new(move |body: Value| {
        let (url, keys, http, log) = (u1.clone(), k1.clone(), h1.get(), log.clone());
        Box::pin(async move {
            let Ok(token) = cc_auth::sign::box_token(&keys) else {
                return Answer::Failed;
            };
            let res = http
                .post(url)
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(body.to_string())
                .timeout(super::metrics::SHIP_TIMEOUT)
                .send()
                .await;
            answer(res, &*log, "POST").await
        }) as cc_http::BoxFuture<Answer>
    });
    let get = Box::new(move |permission_id: String| {
        let (url, keys, http) = (url.clone(), keys.clone(), http.get());
        Box::pin(async move {
            let Ok(token) = cc_auth::sign::box_token(&keys) else {
                return Answer::Failed;
            };
            let res = http
                .get(url)
                .query(&[("permission_id", permission_id)])
                .bearer_auth(token)
                .timeout(super::metrics::SHIP_TIMEOUT)
                .send()
                .await;
            answer(res, &|_| {}, "GET").await
        }) as cc_http::BoxFuture<Answer>
    });
    Endpoint { post, get }
}

/// The firewall's gate: `http://<firewall>:3940/permission`, plain HTTP on the private network with
/// no token (the gate knows the agent by its address). `firewall` is read at every call, so an
/// address written after start-up is used; none answers [`Answer::Missing`], as an old firewall.
/// The agent's own box token, which a settle sent to the gate carries (the gate refuses one without
/// it). None when the agent cannot sign: the settle is not sent, and the card runs out.
pub type AgentToken = Arc<dyn Fn() -> Option<String> + Send + Sync>;

pub fn gate_calls(
    firewall: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    token: AgentToken,
    http: cc_client::HttpClient,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> Endpoint {
    let url = move |f: &Arc<dyn Fn() -> Option<String> + Send + Sync>| {
        f().map(|ip| format!("http://{ip}:{GATE_PORT}/permission"))
    };
    let (f1, h1) = (firewall.clone(), http.clone());
    let post = Box::new(move |body: Value| {
        let (url, http, log) = (url(&f1), h1.get(), log.clone());
        let settle = body.get("resolution").is_some();
        let signed = if settle { token() } else { None };
        Box::pin(async move {
            let Some(url) = url else { return Answer::Missing };
            let mut req = http
                .post(url)
                .header("content-type", "application/json")
                .body(body.to_string())
                .timeout(super::metrics::SHIP_TIMEOUT);
            if settle {
                let Some(t) = signed else {
                    log("[approvals] cannot sign a settle for the firewall: not sent");
                    return Answer::Failed;
                };
                req = req.header(GATE_AGENT_TOKEN, t);
            }
            gate_answer(req.send().await, &*log, "gate POST").await
        }) as cc_http::BoxFuture<Answer>
    });
    let get = Box::new(move |permission_id: String| {
        let (url, http) = (url(&firewall), http.get());
        Box::pin(async move {
            let Some(url) = url else { return Answer::Missing };
            let res = http
                .get(url)
                .query(&[("permission_id", permission_id)])
                .timeout(super::metrics::SHIP_TIMEOUT)
                .send()
                .await;
            gate_answer(res, &|_| {}, "gate GET").await
        }) as cc_http::BoxFuture<Answer>
    });
    Endpoint { post, get }
}

/// The gate's headers (`tools_gate.rs` in the firewall agent).
const GATE_HEADER: &str = "x-cc-gate";
const GATE_OFF_HEADER: &str = "x-cc-auto-approve";
const GATE_AGENT_TOKEN: &str = "x-cc-agent-token";

/// The gate's answer. A 404 is "ask the control plane" only from a firewall that does not answer
/// approvals (no `x-cc-gate`: an older one) or says it does not check the rules yet (`x-cc-auto-approve:
/// off`). Any other 404, and a 503 while it starts, are tried again: the firewall is never gone around.
async fn gate_answer(
    res: Result<reqwest::Response, reqwest::Error>,
    log: &(dyn Fn(&str) + Send + Sync),
    what: &str,
) -> Answer {
    if let Ok(r) = &res
        && r.status().as_u16() == 404
    {
        let h = r.headers();
        let ours = h.get(GATE_HEADER).is_some();
        let off = h.get(GATE_OFF_HEADER).is_some_and(|v| v.as_bytes() == b"off");
        if ours && !off {
            log(&format!("[approvals] {what}: the firewall answered 404"));
            return Answer::Failed;
        }
        return Answer::Missing;
    }
    answer(res, log, what).await
}

async fn answer(
    res: Result<reqwest::Response, reqwest::Error>,
    log: &(dyn Fn(&str) + Send + Sync),
    what: &str,
) -> Answer {
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            log(&format!("[approvals] {what} failed: {}", e.without_url()));
            return Answer::Failed;
        }
    };
    let status = res.status().as_u16();
    if status == 404 {
        return Answer::Missing;
    }
    if !res.status().is_success() {
        log(&format!("[approvals] {what} failed: HTTP {status}"));
        return Answer::Failed;
    }
    match res.json::<Value>().await {
        Ok(out) => Answer::Status(
            out.get("status")
                .and_then(Value::as_str)
                .unwrap_or("pending")
                .to_string(),
        ),
        Err(_) => Answer::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(s: &str) -> String {
        s.replace("sekrit", "[redacted]")
    }

    #[test]
    fn titles_are_one_bounded_redacted_line() {
        assert_eq!(
            sanitize_title("rm -rf /\x1b[31m red\n\tsekrit", &none),
            "rm -rf / red [redacted]"
        );
        let long = "a".repeat(300);
        let t = sanitize_title(&long, &none);
        assert_eq!(t.encode_utf16().count(), TITLE_MAX);
        assert!(t.ends_with('…'));
        assert_eq!(
            summary_of("exec", &json!({ "request": { "command": "ls -la" } }), &none),
            "ls -la"
        );
        assert_eq!(
            summary_of("plugin", &json!({ "presentation": { "title": "Send mail" } }), &none),
            "Send mail"
        );
        assert_eq!(summary_of("system", &json!({}), &none), "system approval");
    }

    #[test]
    fn details_and_resolutions() {
        let p = json!({ "request": { "agentId": "main", "cwd": "/home", "commandAnalysis": { "riskKinds": ["net", "fs"] } } });
        assert_eq!(
            detail_of(&p, &none),
            vec![
                ("agent".into(), "main".into()),
                ("cwd".into(), "/home".into()),
                ("risk".into(), "net, fs".into())
            ]
        );
        assert_eq!(resolution_of(&json!({ "decision": "allow-once" })), "approved");
        assert_eq!(
            resolution_of(&json!({ "decision": "deny", "resolvedBy": "owner" })),
            "denied"
        );
        assert_eq!(resolution_of(&json!({ "decision": "deny" })), "expired");
        assert_eq!(resolution_of(&json!({ "status": "timeout" })), "expired");
    }

    struct Rig {
        bridge: ApprovalsBridge,
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        /// What the control plane was sent.
        posts: Arc<Mutex<Vec<Value>>>,
        /// What the gate was sent.
        gate_posts: Arc<Mutex<Vec<Value>>>,
        answer: Arc<Mutex<Option<String>>>,
        gate_answer: Arc<Mutex<Option<String>>>,
        gets: Arc<Mutex<Vec<(Via, String)>>>,
        now: Arc<Mutex<i64>>,
    }

    fn status(s: Option<&str>) -> Answer {
        s.map_or(Answer::Failed, |s| Answer::Status(s.to_string()))
    }

    /// `post_status`: what the control plane says to a POST (None: not reached). `gate`: none for a
    /// box with no firewall gate; `Some(None)` a gate that answers 404; `Some(Some(Answer))` one that
    /// answers so. `console`: false on an unmanaged box.
    fn rig_with(post_status: Option<&'static str>, gate: Option<Option<Answer>>, console: bool) -> Rig {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let posts = Arc::new(Mutex::new(Vec::new()));
        let gate_posts = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(Mutex::new(None::<String>));
        let gate_answer = Arc::new(Mutex::new(None::<String>));
        let gets = Arc::new(Mutex::new(Vec::new()));
        let now = Arc::new(Mutex::new(1_000_000_i64));
        let (c, p, a, g) = (calls.clone(), posts.clone(), answer.clone(), gets.clone());
        let console = console.then(|| Endpoint {
            post: Box::new(move |body| {
                lock(&p).push(body);
                Box::pin(async move { status(post_status) })
            }),
            get: Box::new(move |id| {
                lock(&g).push((Via::Console, id));
                let s = lock(&a).clone();
                Box::pin(async move { status(s.as_deref()) })
            }),
        });
        let (gp, ga, g2) = (gate_posts.clone(), gate_answer.clone(), gets.clone());
        let gate = gate.map(|on_post| Endpoint {
            post: Box::new(move |body| {
                lock(&gp).push(body);
                let a = on_post.clone().unwrap_or(Answer::Missing);
                Box::pin(async move { a })
            }),
            get: Box::new(move |id| {
                lock(&g2).push((Via::Gate, id));
                let s = lock(&ga).clone();
                Box::pin(async move { status(s.as_deref()) })
            }),
        });
        let n = now.clone();
        let bridge = ApprovalsBridge::new(ApprovalsOptions {
            call: Box::new(move |m, params| {
                lock(&c).push((m.to_string(), params));
                Box::pin(async { Ok(json!([])) })
            }),
            gate,
            console,
            redact: Box::new(|s| s.to_string()),
            log: Box::new(|_| {}),
            now: Box::new(move || *lock(&n)),
        });
        Rig {
            bridge,
            calls,
            posts,
            gate_posts,
            answer,
            gate_answer,
            gets,
            now,
        }
    }

    fn rig(post_status: Option<&'static str>) -> Rig {
        rig_with(post_status, None, true)
    }

    fn resolves(r: &Rig) -> Vec<Value> {
        lock(&r.calls)
            .iter()
            .filter(|(m, _)| m == "approval.resolve")
            .map(|(_, p)| p.clone())
            .collect()
    }

    #[tokio::test]
    async fn a_pending_request_is_resolved_once_the_console_decides() {
        let r = rig(Some("pending"));
        r.bridge
            .on_event(
                "exec.approval.requested",
                &json!({ "id": "a1", "request": { "command": "ls", "sessionKey": "agent:main:main" } }),
            )
            .await;
        assert_eq!(lock(&r.posts)[0]["permission_id"], json!("oc:a1"));
        assert_eq!(lock(&r.posts)[0]["kind"], json!("exec"));
        assert_eq!(r.bridge.pending_count(), 1);
        assert!(r.bridge.pending_sessions().contains("agent:main:main"));
        r.bridge.tick().await;
        assert!(resolves(&r).is_empty());
        *lock(&r.answer) = Some("approved".into());
        r.bridge.tick().await;
        assert_eq!(
            resolves(&r),
            vec![json!({ "id": "a1", "kind": "exec", "decision": "allow-once" })]
        );
        assert_eq!(r.bridge.pending_count(), 0);
        // The echo of our own resolve posts nothing more.
        let before = lock(&r.posts).len();
        r.bridge
            .on_event(
                "exec.approval.resolved",
                &json!({ "id": "a1", "decision": "allow-once" }),
            )
            .await;
        assert_eq!(lock(&r.posts).len(), before);
    }

    #[tokio::test]
    async fn a_request_decided_in_openclaw_clears_the_card() {
        let r = rig(Some("pending"));
        r.bridge
            .on_event("openclaw.approval.requested", &json!({ "id": "s1" }))
            .await;
        r.bridge
            .on_event(
                "openclaw.approval.resolved",
                &json!({ "id": "s1", "decision": "deny", "resolvedBy": "web" }),
            )
            .await;
        let last = lock(&r.posts).last().cloned().expect("post");
        assert_eq!(
            last,
            json!({ "permission_id": "oc:s1", "resolution": "denied", "resolved_by": "openclaw" })
        );
    }

    #[tokio::test]
    async fn a_console_that_did_not_take_it_is_asked_again_and_never_told_of_an_unseen_one() {
        let r = rig(None);
        r.bridge
            .on_event("plugin.approval.requested", &json!({ "id": "p1" }))
            .await;
        r.bridge.tick().await;
        assert_eq!(lock(&r.posts).len(), 2, "raised again on the tick");
        r.bridge
            .on_event(
                "plugin.approval.resolved",
                &json!({ "id": "p1", "decision": "allow-once" }),
            )
            .await;
        assert_eq!(lock(&r.posts).len(), 2, "never raised: no resolution posted");
    }

    #[tokio::test]
    async fn an_allow_from_the_gate_resolves_at_once_and_the_console_is_not_asked() {
        let r = rig_with(Some("pending"), Some(Some(Answer::Status("approved".into()))), true);
        r.bridge
            .on_event(
                "exec.approval.requested",
                &json!({ "id": "g1", "request": { "command": "git status" } }),
            )
            .await;
        assert_eq!(lock(&r.gate_posts)[0]["permission_id"], json!("oc:g1"));
        assert_eq!(lock(&r.gate_posts)[0]["title"], json!("git status"));
        assert_eq!(
            resolves(&r),
            vec![json!({ "id": "g1", "kind": "exec", "decision": "allow-once" })]
        );
        r.bridge.tick().await;
        assert!(lock(&r.posts).is_empty(), "the control plane was not asked");
        assert!(lock(&r.gets).is_empty());
    }

    #[tokio::test]
    async fn an_approval_raised_on_the_gate_is_asked_about_and_settled_there() {
        let r = rig_with(Some("approved"), Some(Some(Answer::Status("pending".into()))), true);
        r.bridge
            .on_event("plugin.approval.requested", &json!({ "id": "g2" }))
            .await;
        r.bridge.tick().await;
        assert_eq!(*lock(&r.gets), vec![(Via::Gate, "oc:g2".to_string())]);
        *lock(&r.gate_answer) = Some("denied".into());
        r.bridge.tick().await;
        assert_eq!(
            resolves(&r),
            vec![json!({ "id": "g2", "kind": "plugin", "decision": "deny" })]
        );
        // Settled in OpenClaw before: the gate is told, not the control plane.
        r.bridge
            .on_event("plugin.approval.requested", &json!({ "id": "g3" }))
            .await;
        r.bridge
            .on_event(
                "plugin.approval.resolved",
                &json!({ "id": "g3", "decision": "deny", "resolvedBy": "web" }),
            )
            .await;
        assert_eq!(
            lock(&r.gate_posts).last().cloned(),
            Some(json!({ "permission_id": "oc:g3", "resolution": "denied", "resolved_by": "openclaw" }))
        );
        assert!(lock(&r.posts).is_empty());
    }

    #[tokio::test]
    async fn a_gate_that_answers_404_sends_approvals_to_the_console_for_ten_minutes() {
        let r = rig_with(Some("pending"), Some(None), true);
        r.bridge
            .on_event("exec.approval.requested", &json!({ "id": "o1" }))
            .await;
        assert_eq!(lock(&r.gate_posts).len(), 1);
        assert_eq!(lock(&r.posts).len(), 1, "raised with the control plane instead");
        r.bridge.tick().await;
        assert_eq!(*lock(&r.gets), vec![(Via::Console, "oc:o1".to_string())]);
        // Remembered: the next one does not try the gate.
        r.bridge
            .on_event("exec.approval.requested", &json!({ "id": "o2" }))
            .await;
        assert_eq!(lock(&r.gate_posts).len(), 1);
        assert_eq!(lock(&r.posts).len(), 2);
        // Ten minutes later the gate is tried again.
        *lock(&r.now) += GATE_OFF_MS;
        r.bridge
            .on_event("exec.approval.requested", &json!({ "id": "o3" }))
            .await;
        assert_eq!(lock(&r.gate_posts).len(), 2);
    }

    #[tokio::test]
    async fn a_gate_that_refuses_is_never_gone_around() {
        let r = rig_with(Some("approved"), Some(Some(Answer::Failed)), true);
        r.bridge
            .on_event("exec.approval.requested", &json!({ "id": "f1" }))
            .await;
        r.bridge.tick().await;
        assert_eq!(lock(&r.gate_posts).len(), 2, "tried again on the tick");
        assert!(lock(&r.posts).is_empty(), "never sent around the firewall");
        assert!(resolves(&r).is_empty());
    }

    #[tokio::test]
    async fn an_unmanaged_box_has_only_its_firewall() {
        let r = rig_with(None, Some(Some(Answer::Status("denied".into()))), false);
        r.bridge
            .on_event("exec.approval.requested", &json!({ "id": "u1" }))
            .await;
        assert_eq!(
            resolves(&r),
            vec![json!({ "id": "u1", "kind": "exec", "decision": "deny" })]
        );
        // An old firewall and no control plane: nothing is raised, and it is tried again later.
        let old = rig_with(None, Some(None), false);
        old.bridge
            .on_event("exec.approval.requested", &json!({ "id": "u2" }))
            .await;
        assert_eq!(old.bridge.pending_count(), 1);
        assert!(resolves(&old).is_empty());
        let _ = (&old.answer, &old.calls);
    }
}

#[cfg(test)]
mod gate_answer_tests {
    use super::*;

    /// One raw HTTP answer on a fresh port; the URL to ask.
    async fn answering(raw: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/permission", l.local_addr().expect("addr"));
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(raw.as_bytes()).await;
            }
        });
        url
    }

    async fn ask(raw: &'static str) -> Answer {
        let url = answering(raw).await;
        gate_answer(reqwest::Client::new().get(url).send().await, &|_| {}, "test").await
    }

    #[tokio::test]
    async fn only_an_older_firewall_or_one_that_says_off_sends_approvals_around_it() {
        // An older firewall: no such route, no mark of the gate.
        let a = ask("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        assert!(matches!(a, Answer::Missing));
        // This firewall, not checking the rules yet.
        let a = ask("HTTP/1.1 404 Not Found\r\nx-cc-gate: 1\r\nx-cc-auto-approve: off\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        assert!(matches!(a, Answer::Missing));
        // Any other 404 of this gate (a control plane's, passed on): tried again, never around it.
        let a = ask("HTTP/1.1 404 Not Found\r\nx-cc-gate: 1\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        assert!(matches!(a, Answer::Failed));
        // Starting: tried again.
        let a =
            ask("HTTP/1.1 503 Service Unavailable\r\nx-cc-gate: 1\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        assert!(matches!(a, Answer::Failed));
        let a = ask("HTTP/1.1 200 OK\r\nx-cc-gate: 1\r\ncontent-type: application/json\r\ncontent-length: 19\r\nconnection: close\r\n\r\n{\"status\":\"denied\"}").await;
        assert!(matches!(a, Answer::Status(ref s) if s == "denied"), "{a:?}");
    }
}
