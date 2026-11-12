//! The permission bridge (`permissions.ts`): the proxy's asks (`pending.jsonl`) become permission
//! requests on the console; an approval becomes a short grant in `grants.json`, which the proxy
//! reads, so the retried request passes and the secret is swapped in.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Map, Value, json};

use super::activity_sanitize::js_string;
use super::grants::{GrantStore, now_s};
use super::sync::js_truthy;

/// `EMAIL_GRANT_SECONDS`: approve once on an email recipient is one window to send.
pub const EMAIL_GRANT_SECONDS: u64 = 30 * 60;
/// An app call's approval is kept as long as the gate waits for its retry.
const APP_GRANT_SECONDS: u64 = 24 * 3600;

/// How many of this firewall's own asks keep their Auto approve decision in memory.
const DECIDED_MAX: usize = 10_000;

/// One call a person approves: an app action (`APP …`) or an MCP tool call (`MCP …`, `call_asks`).
fn call_ask(scope: &str) -> bool {
    scope.starts_with("APP ") || scope.starts_with("MCP ")
}

/// Approvals used once: an email recipient's window, one app call or MCP tool call.
fn once(scope: &str) -> bool {
    scope.starts_with("EMAIL ") || call_ask(scope)
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[derive(Default)]
struct State {
    /// Ids the console knows, polled for an answer, in the order they came.
    submitted: Vec<String>,
    /// `<id>|<agent>` already sent, so each agent is added to its request once.
    sent_for: HashSet<String>,
    meta: HashMap<String, Map<String, Value>>,
    /// Email recipient and app call ids granted once; never polled or granted again.
    granted_once: HashSet<String>,
    /// Revoked email approvals the console has not been told about yet.
    revoked_unsent: Vec<String>,
    /// What the Auto approve rules said about each of this firewall's own asks, decided once.
    decided: HashMap<String, (cc_contracts::auto_approve::Decision, String)>,
    /// `decided`'s ids, oldest first.
    decided_order: std::collections::VecDeque<String>,
    /// Decisions made here that the console has not taken yet, with when to give up (epoch s).
    reports: Vec<(Value, u64)>,
}

/// How long a decision made here is offered to the console before it is dropped: the agent already
/// has its answer, only the console's count and log miss it.
const REPORT_FOR_SECONDS: u64 = 600;

pub struct PermissionBridge {
    pub grants: Arc<GrantStore>,
    pending_path: String,
    url: String,
    ttl_seconds: u64,
    client: super::store_client::StoreClient,
    state: Mutex<State>,
    /// The Auto approve rules and this firewall's own vm id, once the core started.
    auto: OnceLock<(Arc<super::auto_approve::AutoApproveFirewall>, Option<String>)>,
}

impl PermissionBridge {
    pub fn new(
        grants: Arc<GrantStore>,
        pending_path: &str,
        url: &str,
        ttl_seconds: u64,
        client: super::store_client::StoreClient,
    ) -> Self {
        Self {
            grants,
            pending_path: pending_path.to_string(),
            url: url.to_string(),
            ttl_seconds,
            client,
            state: Mutex::new(State::default()),
            auto: OnceLock::new(),
        }
    }

    /// The Auto approve rules, checked on this firewall's own asks; `own_vm` is what the rules for
    /// its website and email asks name.
    pub fn with_auto(&self, rules: Arc<super::auto_approve::AutoApproveFirewall>, own_vm: Option<String>) {
        let _ = self.auto.set((rules, own_vm));
    }

    /// A JSON POST to the control plane's permission endpoint: the status and the body (`null` when
    /// it is not JSON).
    pub async fn post_json(&self, body: &Value) -> Result<(u16, Value), String> {
        let (status, text) = self.client.post_text(&self.url, body).await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// A POST made as an agent, with its own box token (a settle carried for it).
    pub async fn post_as(&self, body: &Value, agent_token: &str) -> Result<(u16, Value), String> {
        let (status, text) = self.client.post_as(&self.url, body, agent_token).await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// A GET with `query` (no leading `?`).
    pub async fn get_json(&self, query: &str) -> Result<(u16, Value), String> {
        let (status, text) = self.client.get_text(&format!("{}?{query}", self.url)).await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// A decision made here, for the console's count and log: offered on every tick until it is
    /// taken, refused for good, or ten minutes passed.
    pub fn report(&self, body: Value) {
        let mut st = self.st();
        if st.reports.len() < 1000 {
            st.reports.push((body, now_s() + REPORT_FOR_SECONDS));
        } else {
            tracing::warn!("[perm] too many decisions waiting for the console; one was dropped");
        }
    }

    async fn send_reports(&self) {
        let now = now_s();
        let due = {
            let mut st = self.st();
            st.reports.retain(|(_, until)| *until > now);
            st.reports.clone()
        };
        for (body, until) in due {
            let done = match self.post(&body).await {
                Ok(s) if (200..300).contains(&s) => true,
                Ok(s) if s != 429 && (400..500).contains(&s) => {
                    tracing::error!("[perm] ControlClaw refused a decision made here: HTTP {s}");
                    true
                }
                _ => false,
            };
            if done {
                let pid = body.get("permission_id").cloned();
                self.st()
                    .reports
                    .retain(|(b, u)| !(b.get("permission_id") == pid.as_ref() && *u == until));
            }
        }
    }

    /// What an approval writes for the proxy: a grant as long as its kind of ask is good for.
    fn grant_approved(&self, pid: &str, scope: &str, now: u64) {
        let ttl = if scope.starts_with("EMAIL ") {
            EMAIL_GRANT_SECONDS
        } else if call_ask(scope) {
            APP_GRANT_SECONDS
        } else {
            self.ttl_seconds
        };
        self.grants.set(pid, now + ttl, scope, false);
        if once(scope) {
            self.st().granted_once.insert(pid.to_string());
        }
    }

    /// The Auto approve rules on one of this firewall's own asks, decided once per id: an Allow is
    /// granted here, a Block is not. The raise then carries `decided` or `checked`.
    fn decide_own(&self, pid: &str, rec: &Map<String, Value>, body: &mut Map<String, Value>) {
        let Some((rules, own_vm)) = self.auto.get() else { return };
        let known = self.st().decided.get(pid).cloned();
        let (d, _) = match known {
            Some(k) => k,
            None => {
                let kind = body.get("kind").and_then(Value::as_str).unwrap_or("access");
                // An app call is the agent's; a website or email ask matches the firewall that raised it.
                let vm = if kind == "app_call" {
                    rec.get("vm_id").and_then(Value::as_str).map(str::to_string)
                } else {
                    own_vm.clone()
                };
                let Some(k) = rules.decide(&Value::Object(body.clone()), vm.as_deref()) else {
                    return;
                };
                let scope = rec
                    .get("scope")
                    .filter(|s| !s.is_null())
                    .map(|s| js_string(Some(s)))
                    .unwrap_or_default();
                match k.0.effect {
                    cc_contracts::auto_approve::Effect::Allow => self.grant_approved(pid, &scope, now_s()),
                    cc_contracts::auto_approve::Effect::Block => self.grants.delete(pid),
                    cc_contracts::auto_approve::Effect::Ask => {}
                }
                if k.0.effect != cc_contracts::auto_approve::Effect::Ask {
                    tracing::info!("[perm] {pid}: {} by an Auto approve rule", k.0.effect.as_str());
                }
                let mut st = self.st();
                // Kept as long as the ask can come back from `pending.jsonl`; a bounded number, the
                // oldest dropped (an id seen again is decided again, by the same rules).
                if st.decided.len() >= DECIDED_MAX
                    && let Some(old) = st.decided_order.pop_front()
                {
                    st.decided.remove(&old);
                }
                st.decided.insert(pid.to_string(), k.clone());
                st.decided_order.push_back(pid.to_string());
                drop(st);
                k
            }
        };
        super::auto_approve::mark(body, &d);
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub async fn tick(&self) {
        self.drain_pending().await;
        self.poll_grants().await;
        self.send_revoked().await;
        self.send_reports().await;
    }

    /// `revokeEmail`: end the email approvals whose scope matches (the email rules took that
    /// person off the lists) and tell the console, so `cc-perm status` says revoked.
    #[allow(dead_code)] // the email rules' (W4)
    pub fn revoke_email(&self, matches: impl Fn(&str) -> bool) -> Vec<String> {
        let mut out = Vec::new();
        let now = now_s() as f64;
        for (pid, grant) in self.grants.entries() {
            let scope = grant
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let expires = grant.get("expires_at").and_then(Value::as_f64).unwrap_or(f64::NAN);
            // An approval whose window is over expired; it was not revoked.
            if expires <= now
                || !scope.starts_with("EMAIL ")
                || grant.get("by").and_then(Value::as_str) == Some("ai")
                || !matches(&scope)
            {
                continue;
            }
            self.grants.delete(&pid);
            let mut st = self.st();
            st.granted_once.insert(pid.clone());
            if !st.revoked_unsent.contains(&pid) {
                st.revoked_unsent.push(pid.clone());
            }
            drop(st);
            out.push(scope);
            tracing::info!("[perm] revoked {pid}");
        }
        out
    }

    async fn post(&self, body: &Value) -> Result<u16, String> {
        self.client.post_text(&self.url, body).await.map(|(status, _)| status)
    }

    async fn send_revoked(&self) {
        let pending = self.st().revoked_unsent.clone();
        for pid in pending {
            let status = self.post(&json!({"permission_id": pid, "resolution": "revoked"})).await;
            // 404: the console never had it. Either way there is nothing more to tell.
            if let Ok(s) = status
                && ((200..300).contains(&s) || s == 404 || s == 403)
            {
                self.st().revoked_unsent.retain(|p| p != &pid);
            }
        }
    }

    /// Every new ask in `pending.jsonl` to the console (idempotent).
    async fn drain_pending(&self) {
        let Ok(text) = std::fs::read_to_string(&self.pending_path) else {
            return;
        };
        for line in text.split('\n').filter(|l| !l.is_empty()) {
            let Ok(Value::Object(rec)) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let id = rec.get("permission_id");
            if !id.is_some_and(js_truthy) {
                continue;
            }
            let pid = js_string(id);
            let vm = match rec.get("vm_id") {
                None | Some(Value::Null) => String::new(),
                v => js_string(v),
            };
            let key = format!("{pid}|{vm}");
            {
                let mut st = self.st();
                if st.sent_for.contains(&key) {
                    continue;
                }
                st.sent_for.insert(key.clone());
                if !st.submitted.contains(&pid) {
                    st.submitted.push(pid.clone());
                }
                st.meta.entry(pid.clone()).or_insert_with(|| rec.clone());
            }
            let mut body = match request_body(&rec) {
                Value::Object(o) => o,
                _ => Map::new(),
            };
            self.decide_own(&pid, &rec, &mut body);
            match self.post(&Value::Object(body)).await {
                Ok(s) if (200..300).contains(&s) => {}
                Ok(s) => {
                    // Said, never dropped quietly: the person would wait for a card that never came.
                    tracing::error!(
                        "[perm] ControlClaw refused request {pid} ({}): HTTP {s}",
                        rec.get("kind")
                            .filter(|k| !k.is_null())
                            .map(|k| js_string(Some(k)))
                            .unwrap_or_else(|| "?".into())
                    );
                    if s == 429 || s >= 500 {
                        self.st().sent_for.remove(&key);
                    }
                }
                Err(e) => {
                    self.st().sent_for.remove(&key);
                    tracing::error!("[perm] submit failed: {e}");
                }
            }
        }
    }

    /// Poll the open requests; an approval becomes a scoped, expiring grant for the proxy.
    async fn poll_grants(&self) {
        let now = now_s();
        self.grants.prune(now);
        let submitted = self.st().submitted.clone();
        for pid in submitted {
            if self.grants.active(&pid, now) || self.st().granted_once.contains(&pid) {
                continue;
            }
            let url = format!("{}?permission_id={}", self.url, encode_uri_component(&pid));
            let Ok((status, text)) = self.client.get_text(&url).await else {
                continue;
            };
            if !(200..300).contains(&status) {
                continue;
            }
            let Ok(body) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            match body.get("status").and_then(Value::as_str) {
                Some("approved") => {
                    let scope = self
                        .st()
                        .meta
                        .get(&pid)
                        .and_then(|m| m.get("scope"))
                        .filter(|s| !s.is_null())
                        .map(|s| js_string(Some(s)))
                        .unwrap_or_default();
                    self.grant_approved(&pid, &scope, now);
                    tracing::info!("[perm] granted {pid}");
                }
                Some("denied") | Some("expired") => self.grants.delete(&pid),
                _ => {}
            }
        }
    }
}

/// The request as the console takes it, keys in the TS order; absent fields stay absent.
fn request_body(rec: &Map<String, Value>) -> Value {
    let mut b = Map::new();
    let get = |k: &str| rec.get(k).cloned();
    let truthy = |k: &str| rec.get(k).is_some_and(js_truthy);
    b.insert("permission_id".into(), get("permission_id").unwrap_or(Value::Null));
    if let Some(s) = get("scope") {
        b.insert("scope".into(), s);
    }
    match rec.get("summary") {
        Some(s) if !s.is_null() => {
            b.insert("summary".into(), s.clone());
        }
        _ => {
            if let Some(s) = get("scope") {
                b.insert("summary".into(), s);
            }
        }
    }
    if truthy("kind") {
        b.insert("kind".into(), get("kind").unwrap_or(Value::Null));
    }
    let kind = rec.get("kind").and_then(Value::as_str);
    if kind == Some("email_recipient") && truthy("recipient") && truthy("mailbox") {
        b.insert("recipient".into(), get("recipient").unwrap_or(Value::Null));
        b.insert("mailbox".into(), get("mailbox").unwrap_or(Value::Null));
    }
    if kind == Some("app_call") {
        let mut app = Map::new();
        for k in ["service", "action"] {
            if let Some(v) = get(k) {
                app.insert(k.into(), v);
            }
        }
        for k in ["operation", "connection", "rule"] {
            app.insert(k.into(), get(k).unwrap_or(Value::Null));
        }
        b.insert("app".into(), Value::Object(app));
    }
    for k in ["host", "method", "path"] {
        if let Some(v) = get(k) {
            b.insert(k.into(), v);
        }
    }
    if truthy("ai_category") {
        b.insert("ai_reason".into(), get("ai_category").unwrap_or(Value::Null));
    }
    if truthy("vm_id") {
        b.insert("agent_vm_id".into(), get("vm_id").unwrap_or(Value::Null));
    }
    if truthy("expires_at") {
        b.insert("expires_at".into(), get("expires_at").unwrap_or(Value::Null));
    }
    Value::Object(b)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn request_bodies_keep_the_ts_shape() {
        let rec = json!({"permission_id": "p", "vm_id": "vm-a", "scope": "APP x", "kind": "app_call", "service": "gmail", "action": "send", "host": "h", "expires_at": "2026"});
        let b = request_body(rec.as_object().expect("obj"));
        assert_eq!(
            serde_json::to_string(&b).expect("json"),
            r#"{"permission_id":"p","scope":"APP x","summary":"APP x","kind":"app_call","app":{"service":"gmail","action":"send","operation":null,"connection":null,"rule":null},"host":"h","agent_vm_id":"vm-a","expires_at":"2026"}"#
        );
        assert_eq!(encode_uri_component("a b/é*"), "a%20b%2F%C3%A9*");
    }

    pub(crate) async fn console(
        answer: impl Fn(&str, Value) -> (u16, Value) + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<Value>>>) {
        let (url, seen, _) = console_with_auth(answer).await;
        (url, seen)
    }

    /// [`console`], with each POST's `authorization` header as well.
    pub(crate) async fn console_with_auth(
        answer: impl Fn(&str, Value) -> (u16, Value) + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<Value>>>, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let auths = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let au = auths.clone();
        let answer = Arc::new(answer);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut router = cc_http::Router::new(&["all"]);
        router.route(
            "all",
            |_, _| true,
            move |req, _| {
                let s = s.clone();
                let au = au.clone();
                let answer = answer.clone();
                async move {
                    use http_body_util::BodyExt;
                    let (parts, body) = req.into_parts();
                    let raw = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                    if parts.method == http::Method::POST {
                        s.lock().expect("lock").push(body.clone());
                        let a = parts
                            .headers
                            .get(http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        au.lock().expect("lock").push(a);
                    }
                    let (status, out) = answer(parts.method.as_str(), body);
                    cc_http::json(status, &out)
                }
            },
        );
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        (format!("http://{addr}/api/vm-agent/permission"), seen, auths)
    }

    pub(crate) fn bridge(dir: &std::path::Path, url: &str, grants: Arc<GrantStore>) -> PermissionBridge {
        cc_testkit::BoxKeys::write(&dir.join("keys"), "fw_1", "fw.example").expect("keys");
        PermissionBridge::new(
            grants,
            &dir.join("pending.jsonl").display().to_string(),
            url,
            300,
            super::super::store_client::StoreClient {
                http: cc_client::HttpClient::new(true).expect("http"),
                keys: cc_auth::keys::KeysDir::new(dir.join("keys")),
                token: true,
            },
        )
    }

    #[tokio::test]
    async fn revoking_email_approvals() {
        let d = tempfile::tempdir().expect("dir");
        std::fs::write(d.path().join("pending.jsonl"), "").expect("pending");
        let grants = Arc::new(GrantStore::new(d.path().join("grants.json")));
        let later = now_s() + 600;
        grants.set("perm_bob", later, "EMAIL agentmail:a@agentmail.to -> bob@y.com", false);
        grants.set(
            "perm_carol",
            later,
            "EMAIL agentmail:a@agentmail.to -> carol@y.com #1",
            false,
        );
        grants.set("perm_web", later, "GET example.com/", false);
        let (url, posts) = console(|_, _| (200, json!({}))).await;
        let b = bridge(d.path(), &url, grants.clone());
        let revoked = b.revoke_email(|s| s.contains("bob@y.com") || s.starts_with("GET"));
        assert_eq!(revoked, vec!["EMAIL agentmail:a@agentmail.to -> bob@y.com"]);
        let mut ids: Vec<String> = grants.entries().into_iter().map(|(k, _)| k).collect();
        ids.sort();
        assert_eq!(ids, vec!["perm_carol", "perm_web"]);
        b.tick().await;
        assert_eq!(
            *posts.lock().expect("lock"),
            vec![json!({"permission_id": "perm_bob", "resolution": "revoked"})]
        );
        b.tick().await;
        assert_eq!(posts.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn one_request_per_id_each_agent_once() {
        let d = tempfile::tempdir().expect("dir");
        let rec = |vm: &str| {
            json!({"permission_id": "perm_x", "vm_id": vm, "scope": "EMAIL gmail:g@gmail.com -> s@y.com", "summary": "s", "kind": "email_recipient"}).to_string()
        };
        std::fs::write(
            d.path().join("pending.jsonl"),
            format!("{}\n{}\n{}\n", rec("vm-a"), rec("vm-a"), rec("vm-b")),
        )
        .expect("pending");
        let (url, posts) = console(|_, _| (200, json!({"status": "pending"}))).await;
        let b = bridge(d.path(), &url, Arc::new(GrantStore::new(d.path().join("grants.json"))));
        b.tick().await;
        b.tick().await;
        let got: Vec<(Value, Value)> = posts
            .lock()
            .expect("lock")
            .iter()
            .map(|p| (p["permission_id"].clone(), p["agent_vm_id"].clone()))
            .collect();
        assert_eq!(
            got,
            vec![(json!("perm_x"), json!("vm-a")), (json!("perm_x"), json!("vm-b"))]
        );
    }

    #[tokio::test]
    async fn busy_is_asked_again_a_refusal_is_not() {
        let d = tempfile::tempdir().expect("dir");
        let rec = |id: &str| {
            json!({"permission_id": id, "vm_id": "vm-a", "scope": "MCP mcp:x #1", "summary": "s", "kind": "app_call", "service": "mcp:x", "action": "t"}).to_string()
        };
        std::fs::write(
            d.path().join("pending.jsonl"),
            format!("{}\n{}\n", rec("perm_busy"), rec("perm_bad")),
        )
        .expect("pending");
        let (url, posts) = console(|m, b| {
            if m != "POST" {
                return (200, json!({"status": "pending"}));
            }
            (if b["permission_id"] == "perm_busy" { 503 } else { 400 }, json!({}))
        })
        .await;
        let b = bridge(d.path(), &url, Arc::new(GrantStore::new(d.path().join("grants.json"))));
        b.tick().await;
        b.tick().await;
        let ids: Vec<Value> = posts
            .lock()
            .expect("lock")
            .iter()
            .map(|p| p["permission_id"].clone())
            .collect();
        assert_eq!(ids, vec![json!("perm_busy"), json!("perm_bad"), json!("perm_busy")]);
    }

    #[tokio::test]
    async fn an_approval_becomes_a_grant() {
        let d = tempfile::tempdir().expect("dir");
        let rec = json!({"permission_id": "perm_a", "scope": "EMAIL x -> y", "kind": "email_recipient"});
        std::fs::write(d.path().join("pending.jsonl"), format!("{rec}\n")).expect("pending");
        let (url, _) = console(|m, _| {
            (
                200,
                if m == "GET" {
                    json!({"status": "approved"})
                } else {
                    json!({})
                },
            )
        })
        .await;
        let grants = Arc::new(GrantStore::new(d.path().join("grants.json")));
        let b = bridge(d.path(), &url, grants.clone());
        b.tick().await;
        let g = grants.get("perm_a").expect("granted");
        assert_eq!(g["scope"], json!("EMAIL x -> y"));
        let left = g["expires_at"].as_u64().expect("n") - now_s();
        assert!((EMAIL_GRANT_SECONDS - 5..=EMAIL_GRANT_SECONDS).contains(&left));
        // Used once: not granted again after it is consumed.
        grants.delete("perm_a");
        b.tick().await;
        assert!(grants.get("perm_a").is_none());
    }

    #[tokio::test]
    async fn an_mcp_tool_calls_approval_is_kept_as_long_as_an_app_calls_and_used_once() {
        let d = tempfile::tempdir().expect("dir");
        let rec = json!({"permission_id": "perm_m", "vm_id": "vm-a", "scope": "MCP mcp:x t #1", "summary": "s", "kind": "app_call", "service": "mcp:x", "action": "t"});
        std::fs::write(d.path().join("pending.jsonl"), format!("{rec}\n")).expect("pending");
        let (url, _) = console(|m, _| {
            (
                200,
                if m == "GET" {
                    json!({"status": "approved"})
                } else {
                    json!({})
                },
            )
        })
        .await;
        let grants = Arc::new(GrantStore::new(d.path().join("grants.json")));
        let b = bridge(d.path(), &url, grants.clone());
        b.tick().await;
        let g = grants.get("perm_m").expect("granted");
        let left = g["expires_at"].as_u64().expect("n") - now_s();
        assert!(
            (APP_GRANT_SECONDS - 5..=APP_GRANT_SECONDS).contains(&left),
            "not the website grant's minutes"
        );
        grants.delete("perm_m");
        b.tick().await;
        assert!(grants.get("perm_m").is_none(), "used once: not granted again");
    }
}
