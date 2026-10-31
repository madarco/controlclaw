//! Stand-ins for the W5 tests: a firewall `App` with fixed keys, the contracts other workstreams
//! provide (codes, agents, code routes, content rules), and a small HTTP server for the fakes
//! (OpenConnector, an MCP server).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

use crate::app::{App, Config};
use crate::contracts::{
    AgentClient, AgentError, AppContent, AppHold, CheckedRule, CodeRequest, CodeRoutes, ConsentCodes, ContentError,
    SendResult, Verify,
};
use cc_http::BoxFuture;

pub fn app(dir: &std::path::Path) -> Arc<App> {
    let keys = dir.join("keys");
    cc_testkit::BoxKeys::write(&keys, "fw_1", "fw.example").expect("keys");
    let kd = cc_auth::keys::KeysDir::new(&keys);
    let http = cc_client::HttpClient::new(true).expect("http");
    Arc::new(App {
        config: Config {
            mode: crate::app::Mode::Saas,
            listen: "127.0.0.1".into(),
            keys_dir: keys.clone(),
            box_key_path: keys.join("box_key"),
            port: 0,
            org_id: "org1".into(),
            box_id: "fw1".into(),
            proxy_config_dir: dir.join("run"),
            firewall_url: String::new(),
            ingress_port: 0,
            ingress_bind: "127.0.0.1".into(),
            firewall_poll_ms: 50,
            agent_version: "0.1.0".into(),
            recovery_routes: false,
            pool_marker: dir.join("pool-unclaimed"),
            pool_peer: dir.join("pool-peer.json"),
        },
        console: cc_client::ConsoleClient::new(kd.clone(), http.clone()),
        keys: kd,
        box_key: cc_crypto::secret_store::generate_box_key(),
        runner: Arc::new(cc_proc::RecordingRunner::new()),
        http,
        contracts: crate::contracts::Contracts::default(),
        cp_inspect: Arc::new(crate::core::cp_inspect::CpInspect::new(&dir.join("cp-inspect.json"))),
    })
}

/// `ConsentCodes` as the TS keeps them: one pending change per scope, the code as given, five tries.
#[derive(Default)]
pub struct FakeCodes {
    pub code: Mutex<String>,
    pending: Mutex<HashMap<String, (String, Value, u32)>>,
    /// The summaries the code messages carried.
    pub sent: Mutex<Vec<String>>,
    /// The code messages sent through `CodeService`.
    pub asks: Mutex<Vec<Ask>>,
}

impl FakeCodes {
    pub fn new(code: &str) -> Arc<Self> {
        let me = Arc::new(Self::default());
        *me.code.lock().expect("lock") = code.to_string();
        me
    }
}

impl ConsentCodes for FakeCodes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        self.sent.lock().expect("lock").push(req.summary.clone());
        self.pending
            .lock()
            .expect("lock")
            .insert(req.scope, (req.change_id, req.proposal, 5));
        Box::pin(async {
            SendResult {
                sent_via: Some("telegram:Marco".into()),
                error: None,
                delivery_failed: false,
                expires_at_ms: 1_800_000_000_000,
            }
        })
    }

    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut p = self.pending.lock().expect("lock");
        let Some((id, proposal, tries)) = p.get_mut(scope) else {
            return Verify::Unknown;
        };
        if id != change_id {
            return Verify::Unknown;
        }
        let given: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if given == *self.code.lock().expect("lock") {
            let v = proposal.clone();
            p.remove(scope);
            return Verify::Ok(v);
        }
        *tries -= 1;
        let left = *tries;
        if left == 0 {
            p.remove(scope);
        }
        Verify::Wrong { tries_left: left }
    }

    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        let mut p = self.pending.lock().expect("lock");
        let hit = p.get(scope).is_some_and(|(id, _, _)| change_id.is_none_or(|c| c == id));
        if hit {
            p.remove(scope);
        }
        hit
    }

    fn forget(&self, scope: &str) {
        self.pending.lock().expect("lock").remove(scope);
    }
}

pub struct Routes(pub Mutex<Vec<Value>>);

impl CodeRoutes for Routes {
    fn routes(&self) -> Vec<Value> {
        self.0.lock().expect("lock").clone()
    }
    fn ready(&self) -> bool {
        true
    }
}

/// One owner who can be sent a code.
pub fn owner_route() -> Value {
    json!({"agentName": "marcobot", "target": {"vmId": "vm-a", "hostname": "a.vm.example"},
        "senders": [{"type": "telegram", "id": "42", "label": "Marco"}]})
}

#[derive(Default)]
pub struct FakeAgents {
    pub calls: Mutex<Vec<(String, String, Value)>>,
    pub fail: Mutex<Option<String>>,
    /// What every call answers (empty unless set).
    pub reply: Mutex<Map<String, Value>>,
}

impl AgentClient for FakeAgents {
    fn post(&self, vm_id: &str, path: &str, body: Value) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.calls
            .lock()
            .expect("lock")
            .push((vm_id.to_string(), path.to_string(), body));
        let fail = self.fail.lock().expect("lock").clone();
        let reply = self.reply.lock().expect("lock").clone();
        Box::pin(async move {
            match fail {
                Some(m) => Err(AgentError {
                    message: m,
                    timed_out: false,
                }),
                None => Ok(reply),
            }
        })
    }

    fn get(&self, vm_id: &str, path: &str) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.post(vm_id, path, Value::Null)
    }
}

/// The content rules as the TS gate tests stand them in: words in the text decide.
type Send_ = Box<dyn FnOnce() -> BoxFuture<Result<(), String>> + Send>;

#[derive(Default)]
pub struct FakeContent {
    pub lines: Mutex<Vec<(String, String, String)>>,
    pub holds: Mutex<Vec<(String, Option<Send_>)>>,
}

pub fn rule(id: &str, action: &str, reason: &str) -> CheckedRule {
    CheckedRule {
        id: id.into(),
        name: Some(id.into()),
        action: action.into(),
        reason: reason.into(),
        by: None,
    }
}

/// The strings of a JSON body, one per line, as `bodyText` reads JSON.
pub fn json_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| json_strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| json_strings(x, out)),
        _ => {}
    }
}

impl AppContent for FakeContent {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _direction: &str) -> bool {
        true
    }
    fn body_text(&self, body: &[u8], _content_type: &str) -> Option<String> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let mut out = Vec::new();
        json_strings(&v, &mut out);
        Some(out.join("\n"))
    }
    fn check(
        &self,
        direction: &str,
        text: String,
        _vm_id: Option<String>,
    ) -> BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        let found = match direction {
            "out" if text.contains("SECRET-OUT") => Some(rule("no-secrets", "block", "it carries a secret")),
            "out" if text.contains("HOLD-ME") => Some(rule("hold-it", "hold", "a person checks these")),
            "in" if text.contains("SECRET-IN") => Some(rule("no-secrets-in", "block", "the result carries a secret")),
            _ => None,
        };
        Box::pin(async move { Ok(found) })
    }
    fn record(
        &self,
        rule: &str,
        direction: &str,
        action: &str,
        _vm_id: Option<&str>,
        _extra: Map<String, Value>,
    ) -> Option<String> {
        self.lines
            .lock()
            .expect("lock")
            .push((rule.into(), direction.into(), action.into()));
        Some("line-1".into())
    }
    fn hold(&self, hold: AppHold) -> BoxFuture<Option<String>> {
        self.holds.lock().expect("lock").push((hold.what, Some(hold.send)));
        Box::pin(async { Some("hold-1".to_string()) })
    }
    fn stopped_here(
        &self,
        _rule: &CheckedRule,
        _direction: &str,
        _vm_id: Option<&str>,
        _text: &str,
        _id: Option<&str>,
    ) {
    }
}

impl FakeContent {
    /// Press Send on the hold at `i`.
    pub async fn send(&self, i: usize) -> Result<(), String> {
        let f = self.holds.lock().expect("lock")[i].1.take().expect("not sent yet");
        f().await
    }
}

/// What a fake server got.
#[derive(Debug, Clone)]
pub struct Got {
    pub method: String,
    /// Path and query.
    pub path: String,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Answer after this long.
    pub delay_ms: u64,
}

impl Answer {
    pub fn json(status: u16, v: &Value) -> Self {
        Self::typed(status, "application/json", serde_json::to_vec(v).expect("json"))
    }

    pub fn typed(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body,
            delay_ms: 0,
        }
    }
}

type Handler = Arc<dyn Fn(&Got) -> Answer + Send + Sync>;

/// A loopback HTTP server that answers with `handler` and keeps what it got.
pub struct FakeServer {
    pub port: u16,
    pub got: Arc<Mutex<Vec<Got>>>,
}

impl FakeServer {
    pub async fn start(handler: impl Fn(&Got) -> Answer + Send + Sync + 'static) -> Self {
        let handler: Handler = Arc::new(handler);
        let got: Arc<Mutex<Vec<Got>>> = Arc::default();
        let mut r = cc_http::Router::new(&["all"]);
        let g = got.clone();
        r.route(
            "all",
            |_, _| true,
            move |req: cc_http::Req, _| {
                let (handler, g) = (handler.clone(), g.clone());
                async move {
                    let (parts, body) = req.into_parts();
                    let body = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                    let got = Got {
                        method: parts.method.to_string(),
                        path: parts.uri.path_and_query().map(|p| p.to_string()).unwrap_or_default(),
                        headers: parts.headers,
                        body,
                    };
                    let a = handler(&got);
                    g.lock().expect("lock").push(got);
                    if a.delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(a.delay_ms)).await;
                    }
                    let mut resp = cc_http::full(http::StatusCode::from_u16(a.status).expect("status"), "", a.body);
                    for (k, v) in a.headers {
                        resp.headers_mut().insert(
                            http::HeaderName::from_bytes(k.as_bytes()).expect("name"),
                            http::HeaderValue::from_str(&v).expect("value"),
                        );
                    }
                    resp
                }
            },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        tokio::spawn(cc_http::serve(l, Arc::new(r)));
        Self { port, got }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn got(&self) -> Vec<Got> {
        self.got.lock().expect("lock").clone()
    }

    pub fn clear(&self) {
        self.got.lock().expect("lock").clear();
    }
}

/// The identity map: these agents, at these addresses.
pub struct Identities(pub Mutex<Vec<crate::contracts::AgentIdentity>>);

impl Identities {
    pub fn of(list: &[(&str, &str, &str)]) -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            list.iter()
                .map(|(vm, ip, name)| crate::contracts::AgentIdentity {
                    vm_id: vm.to_string(),
                    private_ip: ip.to_string(),
                    hostname: Some(format!("{vm}.vm.example")),
                    name: Some(name.to_string()),
                })
                .collect(),
        )))
    }
}

impl crate::contracts::IdentityMap for Identities {
    fn agents(&self) -> Vec<crate::contracts::AgentIdentity> {
        self.0.lock().expect("lock").clone()
    }
    fn agent(&self, vm_id: &str) -> Option<crate::contracts::AgentIdentity> {
        self.agents().into_iter().find(|a| a.vm_id == vm_id)
    }
    fn host_for(&self, vm_id: &str) -> Option<String> {
        self.agent(vm_id).and_then(|a| a.hostname).map(|h| h.to_lowercase())
    }
}

/// An emergency stop nobody pressed (or one that is pressed).
pub struct Stop(pub std::sync::atomic::AtomicBool);

impl crate::contracts::EmergencyStop for Stop {
    fn locked(&self, _vm_id: &str) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// W3's credentials sync: counts the writes.
#[derive(Default)]
pub struct Syncs(pub std::sync::atomic::AtomicUsize);

impl crate::contracts::CredentialsSync for Syncs {
    fn changed(&self) -> BoxFuture<()> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {})
    }
}

impl Syncs {
    pub fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// W3's `CodeService` over the same fake: every module's codes in one table by scope, and what each
/// message was made of.
pub struct FakeService(pub Arc<FakeCodes>);

/// What a code message was made of: the subject, the summary, and the parts' ask and typed lines.
pub type Ask = (String, String, Option<(String, Vec<(String, String)>)>);

struct FakeModule(Arc<FakeCodes>);

impl crate::contracts::CodeService for FakeService {
    fn module(&self, _: &'static str) -> Arc<dyn crate::contracts::ModuleCodes> {
        Arc::new(FakeModule(self.0.clone()))
    }
}

impl crate::contracts::ModuleCodes for FakeModule {
    fn send(&self, req: crate::contracts::CodeAsk) -> BoxFuture<crate::contracts::CodeSent> {
        let parts = req.parts.as_ref().map(|p| {
            (
                p.ask.clone(),
                p.typed.iter().map(|t| (t.label.clone(), t.text.clone())).collect(),
            )
        });
        self.0
            .asks
            .lock()
            .expect("lock")
            .push((req.agent_name.clone(), req.summary.clone(), parts));
        let old = CodeRequest {
            scope: req.scope,
            change_id: req.change_id,
            proposal: req.proposal,
            agent_name: req.agent_name,
            summary: req.summary,
            routes: vec![],
        };
        let sent = self.0.send(old);
        Box::pin(async move {
            let r = sent.await;
            match r.sent_via {
                Some(v) => crate::contracts::CodeSent::Sent {
                    sent_via: v,
                    expires_at: crate::integrations::js::iso(r.expires_at_ms),
                    attempts_left: 5,
                    recovery: None,
                },
                None => crate::contracts::CodeSent::Failed {
                    message: r.error.unwrap_or_default(),
                },
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> crate::contracts::CodeCheck {
        match self.0.verify(scope, change_id, code) {
            Verify::Ok(proposal) => crate::contracts::CodeCheck::Ok {
                proposal,
                sent_via: "telegram:Marco".into(),
            },
            Verify::Wrong { tries_left } => crate::contracts::CodeCheck::Wrong { tries_left },
            _ => crate::contracts::CodeCheck::Expired,
        }
    }
    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        ConsentCodes::cancel(&*self.0, scope, change_id)
    }
    fn forget(&self, scope: &str) {
        ConsentCodes::forget(&*self.0, scope)
    }
}
