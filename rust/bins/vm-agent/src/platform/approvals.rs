//! Bridges OpenClaw's own approvals (exec, plugin, system-agent) into the ControlClaw queue
//! (`approvals.ts`).
//!
//! `<family>.approval.requested` → `POST /api/vm-agent/permission` (the control plane runs the org's
//! rules); approved or denied at once → `approval.resolve`; pending → asked again every few seconds;
//! `<family>.approval.resolved` (answered in OpenClaw, cancelled, expired) → the resolution is posted
//! so the console's card clears. Decisions sent to the gateway are `allow-once` or `deny` only.
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

struct Tracked {
    kind: &'static str,
    approval_kind: String,
    payload: Value,
    expires_at: Option<f64>,
    /// False until the control plane took the POST; a tick raises it again meanwhile.
    raised: bool,
    /// The gateway or the console decided; nothing more to do.
    done: bool,
    /// This bridge sent the decision, so the echoed `resolved` event is not news.
    resolved_by_us: bool,
}

/// A gateway method with its params.
pub type GatewayCall = Box<dyn Fn(&str, Value) -> cc_http::BoxFuture<Result<Value, String>> + Send + Sync>;
/// `POST` a body; Some(status word) when the control plane took it.
pub type PermissionPost = Box<dyn Fn(Value) -> cc_http::BoxFuture<Option<String>> + Send + Sync>;
/// `GET ?permission_id=`; Some(status word) when it answered.
pub type PermissionGet = Box<dyn Fn(String) -> cc_http::BoxFuture<Option<String>> + Send + Sync>;

/// What the bridge needs from the box.
pub struct ApprovalsOptions {
    pub call: GatewayCall,
    /// `POST` the body; Some(status word) when the control plane took it.
    pub post: PermissionPost,
    /// `GET ?permission_id=`; Some(status word) when it answered.
    pub get_status: PermissionGet,
    pub redact: Box<dyn Fn(&str) -> String + Send + Sync>,
    pub log: Box<dyn Fn(&str) + Send + Sync>,
    pub now: Box<dyn Fn() -> i64 + Send + Sync>,
}

pub struct ApprovalsBridge {
    o: ApprovalsOptions,
    /// By approval id, in the order seen (a JS `Map`).
    tracked: Mutex<Vec<(String, Tracked)>>,
    in_flight: AtomicBool,
}

impl ApprovalsBridge {
    pub fn new(o: ApprovalsOptions) -> Self {
        Self {
            o,
            tracked: Mutex::new(Vec::new()),
            in_flight: AtomicBool::new(false),
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
                    raised: false,
                    done: false,
                    resolved_by_us: false,
                },
            ));
        }
        self.raise(id).await;
    }

    /// POST the approval to the control plane; a tick tries again when it fails.
    async fn raise(&self, id: &str) {
        let redact = |s: &str| (self.o.redact)(s);
        let Some(body) = self
            .with(id, |t| {
                (!t.raised && !t.done).then(|| {
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
        let Some(status) = (self.o.post)(body).await else {
            return;
        };
        let kind = self.with(id, |t| {
            t.raised = true;
            t.kind
        });
        self.log(&format!("raised {} approval {id} → {status}", kind.unwrap_or_default()));
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
            let Some((done, raised, expired)) = self.with(&id, |t| {
                (
                    t.done,
                    t.raised,
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
                if raised {
                    self.post_resolution(&id, "expired").await;
                }
                continue;
            }
            if !raised {
                self.raise(&id).await;
                continue;
            }
            if let Some(status) = (self.o.get_status)(format!("oc:{id}")).await {
                self.apply_status(&id, &status).await;
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
        // The console never saw one that was not raised.
        if self.with(id, |t| t.raised) != Some(true) {
            return;
        }
        let _ = (self.o.post)(
            json!({ "permission_id": format!("oc:{id}"), "resolution": resolution, "resolved_by": "openclaw" }),
        )
        .await;
    }
}

/// The real control-plane calls: `<base>/api/vm-agent/permission` with the box's token, 20 s.
pub fn permission_calls(
    base: String,
    keys: cc_auth::keys::KeysDir,
    http: cc_client::HttpClient,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> (PermissionPost, PermissionGet) {
    let url = format!("{base}/api/vm-agent/permission");
    let (u1, k1, h1) = (url.clone(), keys.clone(), http.clone());
    let post = Box::new(move |body: Value| {
        let (url, keys, http, log) = (u1.clone(), k1.clone(), h1.get(), log.clone());
        Box::pin(async move {
            let token = cc_auth::sign::box_token(&keys).ok()?;
            let res = http
                .post(url)
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(body.to_string())
                .timeout(super::metrics::SHIP_TIMEOUT)
                .send()
                .await;
            let res = match res {
                Ok(r) => r,
                Err(e) => {
                    log(&format!("[approvals] POST failed: {}", e.without_url()));
                    return None;
                }
            };
            if !res.status().is_success() {
                log(&format!("[approvals] POST failed: HTTP {}", res.status().as_u16()));
                return None;
            }
            let out: Value = res.json().await.ok()?;
            Some(
                out.get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("pending")
                    .to_string(),
            )
        }) as cc_http::BoxFuture<Option<String>>
    });
    let get = Box::new(move |permission_id: String| {
        let (url, keys, http) = (url.clone(), keys.clone(), http.get());
        Box::pin(async move {
            let token = cc_auth::sign::box_token(&keys).ok()?;
            let res = http
                .get(url)
                .query(&[("permission_id", permission_id)])
                .bearer_auth(token)
                .timeout(super::metrics::SHIP_TIMEOUT)
                .send()
                .await
                .ok()?;
            if !res.status().is_success() {
                return None;
            }
            let body: Value = res.json().await.ok()?;
            body.get("status").and_then(Value::as_str).map(str::to_string)
        }) as cc_http::BoxFuture<Option<String>>
    });
    (post, get)
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
        posts: Arc<Mutex<Vec<Value>>>,
        answer: Arc<Mutex<Option<String>>>,
    }

    fn rig(post_status: Option<&'static str>) -> Rig {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let posts = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(Mutex::new(None::<String>));
        let (c, p, a) = (calls.clone(), posts.clone(), answer.clone());
        let bridge = ApprovalsBridge::new(ApprovalsOptions {
            call: Box::new(move |m, params| {
                lock(&c).push((m.to_string(), params));
                Box::pin(async { Ok(json!([])) })
            }),
            post: Box::new(move |body| {
                lock(&p).push(body);
                Box::pin(async move { post_status.map(str::to_string) })
            }),
            get_status: Box::new(move |_| {
                let s = lock(&a).clone();
                Box::pin(async move { s })
            }),
            redact: Box::new(|s| s.to_string()),
            log: Box::new(|_| {}),
            now: Box::new(|| 1_000_000),
        });
        Rig {
            bridge,
            calls,
            posts,
            answer,
        }
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
}
