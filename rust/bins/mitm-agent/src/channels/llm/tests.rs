//! `llm.test.ts`: the LLM commands against a fake agent box, fake consent codes and a fake token
//! endpoint. The code message itself is W3's (`consent-codes.ts`); here the codes carry the
//! subject and the summary, which is what this module decides.

#![allow(clippy::unwrap_used)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::store::{self, LlmStore};
use super::*;
use crate::channels::agent::{AgentCalls, AgentError, LLM_PUSH_MS, Target};
use crate::channels::new_agents::{AgentFirstSeen, NEW_AGENT_WINDOW_MS};
use crate::contracts::{CodeRequest, ConsentCodes, SendResult, Verify};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[derive(Debug, Clone)]
struct Call {
    target: Target,
    path: String,
    body: Value,
    timeout: Option<Duration>,
}

#[derive(Default)]
struct FakeAgent {
    calls: Mutex<Vec<Call>>,
    /// Every `/llm/apply` fails with this until cleared.
    apply_fails: Mutex<Option<AgentError>>,
    /// The next `/llm/apply` fails with this, once.
    fail_once: Mutex<VecDeque<AgentError>>,
}

impl FakeAgent {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
    fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
    fn applies(&self) -> Vec<Call> {
        self.calls().into_iter().filter(|c| c.path == "/llm/apply").collect()
    }
    fn sends(&self) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.path == "/channels/send")
            .collect()
    }
    fn last(&self) -> Call {
        self.calls().last().cloned().expect("a call")
    }
}

impl AgentCalls for Arc<FakeAgent> {
    fn post(
        &self,
        target: &Target,
        path: &str,
        body: Value,
        timeout: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.calls.lock().unwrap().push(Call {
            target: target.clone(),
            path: path.into(),
            body,
            timeout,
        });
        let fail = if path == "/llm/apply" {
            self.fail_once
                .lock()
                .unwrap()
                .pop_front()
                .or_else(|| self.apply_fails.lock().unwrap().clone())
        } else {
            None
        };
        Box::pin(async move {
            match fail {
                Some(e) => Err(e),
                None => Ok(json!({"ok": true}).as_object().cloned().unwrap()),
            }
        })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

struct Pending {
    change_id: String,
    proposal: Value,
    code: String,
    tries: u32,
}

/// Consent codes as `consent-codes.ts` keeps them: one change per scope, five tries, delivered to
/// the first route's first sender through the agent.
struct FakeCodes {
    agent: Arc<FakeAgent>,
    next: Arc<Mutex<String>>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl ConsentCodes for FakeCodes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        let code = self.next.lock().unwrap().clone();
        let route = req.routes.first().cloned().unwrap_or_default();
        let sender = route["senders"][0].clone();
        let target = Target::new(
            route["target"]["vmId"].as_str().unwrap_or_default(),
            route["target"]["hostname"].as_str().unwrap_or_default(),
        );
        let text = format!("{}|{}|{}", req.agent_name, req.summary, code);
        // The fake records the call when it is made; its answer is not needed.
        drop(self.agent.post(
            &target,
            "/channels/send",
            json!({"type": sender["type"], "to": sender["id"], "text": text}),
            None,
        ));
        self.pending.lock().unwrap().insert(
            req.scope.clone(),
            Pending {
                change_id: req.change_id,
                proposal: req.proposal,
                code,
                tries: CODE_ATTEMPTS,
            },
        );
        let via = format!(
            "{}:{}",
            sender["type"].as_str().unwrap_or_default(),
            sender["label"].as_str().unwrap_or_default()
        );
        Box::pin(async move {
            SendResult {
                sent_via: Some(via),
                error: None,
                delivery_failed: false,
                expires_at_ms: 1,
            }
        })
    }

    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut p = self.pending.lock().unwrap();
        let Some(entry) = p.get_mut(scope).filter(|e| e.change_id == change_id) else {
            return Verify::Expired;
        };
        let clean: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if clean == entry.code {
            let proposal = entry.proposal.clone();
            p.remove(scope);
            return Verify::Ok(proposal);
        }
        entry.tries -= 1;
        let left = entry.tries;
        if left == 0 {
            p.remove(scope);
        }
        Verify::Wrong { tries_left: left }
    }

    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        let mut p = self.pending.lock().unwrap();
        if change_id.is_none_or(|c| p.get(scope).is_some_and(|e| e.change_id == c)) {
            return p.remove(scope).is_some();
        }
        false
    }

    fn forget(&self, scope: &str) {
        self.pending.lock().unwrap().remove(scope);
    }
}

type TokenCall = (String, Vec<(String, String)>);

#[derive(Clone)]
struct TokenFake {
    calls: Arc<Mutex<Vec<TokenCall>>>,
    answer: Arc<Mutex<(u16, Value)>>,
}

impl TokenFetch for TokenFake {
    fn post_form(
        &self,
        url: &str,
        form: Vec<(String, String)>,
        _: Duration,
    ) -> BoxFuture<Result<(u16, Value), String>> {
        self.calls.lock().unwrap().push((url.into(), form));
        let a = self.answer.lock().unwrap().clone();
        Box::pin(async move { Ok(a) })
    }
}

struct World {
    dir: tempfile::TempDir,
    agent: Arc<FakeAgent>,
    codes: Arc<FakeCodes>,
    next_code: Arc<Mutex<String>>,
    routes: Arc<Mutex<Vec<Value>>>,
    now: Arc<AtomicI64>,
    refreshed: Arc<AtomicUsize>,
    token: TokenFake,
}

struct Opts {
    file: &'static str,
    plain: bool,
    new_agent: Option<VmPredicate>,
    live_agent: Option<VmPredicate>,
    channels: Option<VmPredicate>,
    clock_offset: i64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            file: "llm.enc",
            plain: false,
            new_agent: None,
            live_agent: None,
            channels: None,
            clock_offset: 0,
        }
    }
}

impl World {
    fn new() -> Self {
        let agent = Arc::new(FakeAgent::default());
        let next_code = Arc::new(Mutex::new("123456".to_string()));
        Self {
            dir: tempfile::tempdir().unwrap(),
            codes: Arc::new(FakeCodes {
                agent: agent.clone(),
                next: next_code.clone(),
                pending: Mutex::new(HashMap::new()),
            }),
            agent,
            next_code,
            routes: Arc::new(Mutex::new(vec![])),
            now: Arc::new(AtomicI64::new(1_789_552_800_000)), // 2026-09-16T10:00:00Z
            refreshed: Arc::new(AtomicUsize::new(0)),
            token: TokenFake {
                calls: Arc::default(),
                answer: Arc::new(Mutex::new((
                    200,
                    json!({"access_token": "acc-2", "refresh_token": "ref-2", "expires_in": 3600}),
                ))),
            },
        }
    }

    fn make(&self, o: Opts) -> Arc<Llm> {
        let codes = self.codes.clone();
        let routes = self.routes.clone();
        let refreshed = self.refreshed.clone();
        let now = self.now.clone();
        let offset = o.clock_offset;
        Llm::new(LlmOptions {
            store_path: self.dir.path().join(o.file),
            box_key: KEY.into(),
            org_id: "org1".into(),
            box_id: "fw1".into(),
            agent: Arc::new(self.agent.clone()),
            codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
            code_routes: Arc::new(move || Some(routes.lock().unwrap().clone())),
            is_new_agent: o.new_agent,
            is_live_agent: o.live_agent,
            agent_has_channels: o.channels,
            plain_keys: o.plain,
            on_credentials_changed: Arc::new(move || {
                refreshed.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {})
            }),
            fetch: Arc::new(self.token.clone()),
            now: Arc::new(move || now.load(Ordering::SeqCst) + offset),
        })
    }

    fn plain(&self) -> Arc<Llm> {
        self.make(Opts::default())
    }

    fn load(&self, file: &str) -> LlmStore {
        store::load(&self.dir.path().join(file), KEY, "org1", "fw1")
    }

    fn set_routes(&self, r: Vec<Value>) {
        *self.routes.lock().unwrap() = r;
    }

    fn code(&self, c: &str) {
        *self.next_code.lock().unwrap() = c.into();
    }

    fn now(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn data(o: &CommandOutcome) -> Value {
    Value::Object(o.data.clone().unwrap_or_default())
}

fn bot() -> Value {
    json!({"vmId": "vm1", "name": "marcobot", "hostname": "bot.vm.controlclaw.com", "model": "openai/gpt-5.6-sol", "role": "primary"})
}

fn openai_key() -> Value {
    json!({
        "changeId": "chg-1", "kind": "add", "credentialId": "cred-openai", "provider": "openai",
        "providerName": "OpenAI", "credKind": "api_key", "placeholder": "sk-cc-openai-abcdef123456",
        "hint": "…a1b2", "profileId": "openai:controlclaw",
        "swap": {"matchDomain": "api.openai.com", "locations": ["header:authorization"]},
        "agents": [bot()], "secret": {"apiKey": "sk-real-openai-key-a1b2"}
    })
}

fn merge(base: Value, over: Value) -> Map<String, Value> {
    let mut b = m(base);
    b.extend(m(over));
    b
}

fn approved() -> Vec<Value> {
    vec![
        json!({"target": {"vmId": "vm1", "hostname": "bot.vm.controlclaw.com"}, "senders": [{"type": "telegram", "id": "8734", "label": "Marco"}], "agentName": "marcobot"}),
    ]
}

fn code_text(summary: &str, code: &str) -> Value {
    json!(format!("{CODE_SUBJECT}|{summary}|{code}"))
}

#[tokio::test]
async fn the_main_flow() {
    let w = World::new();
    let fw = w.plain();

    // with nobody approved anywhere, the first key applies at once (TOFU) and the box gets a placeholder
    let r = fw.propose(m(openai_key())).await.unwrap();
    assert_eq!(r.status, "applied");
    let d = data(&r);
    assert_eq!(d["tofu"], json!(true));
    assert_eq!(d["summary"], json!("Add OpenAI key (…a1b2)"));
    assert_eq!(d["mode"], json!("placeholder"));
    assert_eq!(d["applied"], json!(["vm1"]));
    let calls = w.agent.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/llm/apply");
    assert_eq!(calls[0].target.hostname, "bot.vm.controlclaw.com");
    assert_eq!(
        calls[0].body,
        json!({
            "model": {"primary": "openai/gpt-5.6-sol", "fallbacks": []},
            "credentials": [{"provider": "openai", "kind": "api_key", "profileId": "openai:controlclaw", "value": "sk-cc-openai-abcdef123456", "model": "openai/gpt-5.6-sol"}],
            "remove": [],
        })
    );
    assert!(
        !calls[0].body.to_string().contains("sk-real"),
        "the real key never reaches the box"
    );
    let stored = w.load("llm.enc");
    assert_eq!(
        Value::Object(stored.credentials["cred-openai"].secret.clone()),
        json!({"apiKey": "sk-real-openai-key-a1b2"})
    );
    assert_eq!(
        serde_json::to_value(&stored.agents["vm1"].bindings).unwrap(),
        json!([{"credentialId": "cred-openai", "model": "openai/gpt-5.6-sol", "role": "primary"}])
    );
    assert_eq!(w.refreshed.load(Ordering::SeqCst), 1);

    // proxy credentials carry the real key for that agent only
    assert_eq!(
        fw.credentials(),
        vec![
            json!({"placeholder": "sk-cc-openai-abcdef123456", "match_domain": "api.openai.com", "secret": "sk-real-openai-key-a1b2", "locations": ["header:authorization"], "vm_id": "vm1", "model": true})
        ]
    );

    // once someone is approved on any agent, a change sends a code through that agent and waits
    w.set_routes(approved());
    w.agent.clear();
    w.code("481920");
    let r = fw
        .propose(merge(
            openai_key(),
            json!({
                "changeId": "chg-2", "kind": "add", "credentialId": "cred-anthropic", "provider": "anthropic",
                "providerName": "Anthropic", "placeholder": "sk-ant-cc-xyz", "hint": "…zz99",
                "profileId": "anthropic:controlclaw",
                "swap": {"matchDomain": "api.anthropic.com", "locations": ["header:x-api-key"]},
                "agents": [{"vmId": "vm1", "name": "marcobot", "hostname": "bot.vm.controlclaw.com", "model": "anthropic/claude-opus-5", "role": "secondary"}],
                "secret": {"apiKey": "sk-ant-real-zz99"},
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, "awaiting_code");
    assert_eq!(data(&r)["sentVia"], json!("telegram:Marco"));
    assert_eq!(data(&r)["attemptsLeft"], json!(CODE_ATTEMPTS));
    let calls = w.agent.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/channels/send");
    assert_eq!(calls[0].body["to"], json!("8734"));
    assert_eq!(calls[0].body["text"], code_text("Add Anthropic key (…zz99)", "481920"));
    assert!(
        !w.load("llm.enc").credentials.contains_key("cred-anthropic"),
        "nothing stored before the code"
    );

    // a wrong code counts down; the right one applies and pushes the whole state
    w.agent.clear();
    let wrong = fw
        .confirm(m(json!({"changeId": "chg-2", "code": "000000"})))
        .await
        .unwrap();
    assert_eq!(wrong.status, "invalid_code");
    assert_eq!(data(&wrong)["attemptsLeft"], json!(CODE_ATTEMPTS - 1));
    let right = fw
        .confirm(m(json!({"changeId": "chg-2", "code": "481 920"})))
        .await
        .unwrap();
    assert_eq!(right.status, "applied");
    assert_eq!(data(&right)["tofu"], json!(false));
    assert_eq!(data(&right)["sentVia"], json!("telegram:Marco"));
    let body = &w.agent.calls()[0].body;
    assert_eq!(
        body["model"],
        json!({"primary": "openai/gpt-5.6-sol", "fallbacks": ["anthropic/claude-opus-5"]})
    );
    let mut providers: Vec<String> = body["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["provider"].as_str().unwrap().to_string())
        .collect();
    providers.sort();
    assert_eq!(providers, ["anthropic", "openai"]);
    assert_eq!(fw.credentials().len(), 2);

    // promoting the fallback swaps the two slots; the box gets the new order
    w.agent.clear();
    w.code("222222");
    fw.propose(m(json!({
        "changeId": "chg-3", "kind": "set_model", "credentialId": "cred-anthropic", "provider": "anthropic",
        "providerName": "Anthropic",
        "agents": [{"vmId": "vm1", "name": "marcobot", "hostname": "bot.vm.controlclaw.com", "model": "anthropic/claude-sonnet-5", "role": "primary"}],
    })))
    .await
    .unwrap();
    assert_eq!(
        w.agent.calls()[0].body["text"],
        code_text("Switch marcobot's main model to Anthropic claude-sonnet-5", "222222")
    );
    let r = fw
        .confirm(m(json!({"changeId": "chg-3", "code": "222222"})))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(
        w.agent.calls()[1].body["model"],
        json!({"primary": "anthropic/claude-sonnet-5", "fallbacks": ["openai/gpt-5.6-sol"]})
    );
    let mut b = w.load("llm.enc").agents["vm1"].bindings.clone();
    b.sort_by(|x, y| x.credential_id.cmp(&y.credential_id));
    assert_eq!(
        serde_json::to_value(&b).unwrap(),
        json!([
            {"credentialId": "cred-anthropic", "model": "anthropic/claude-sonnet-5", "role": "primary"},
            {"credentialId": "cred-openai", "model": "openai/gpt-5.6-sol", "role": "secondary"},
        ])
    );

    // too many wrong codes drop the proposal; cancel drops it too
    w.code("111111");
    let rm = json!({"changeId": "chg-4", "kind": "remove", "credentialId": "cred-openai", "provider": "openai", "providerName": "OpenAI", "agents": []});
    fw.propose(m(rm.clone())).await.unwrap();
    for _ in 0..CODE_ATTEMPTS {
        fw.confirm(m(json!({"changeId": "chg-4", "code": "999999"})))
            .await
            .unwrap();
    }
    assert_eq!(
        fw.confirm(m(json!({"changeId": "chg-4", "code": "111111"})))
            .await
            .unwrap()
            .status,
        "expired"
    );
    fw.propose(merge(rm, json!({"changeId": "chg-5"}))).await.unwrap();
    assert_eq!(
        fw.cancel(m(json!({"changeId": "chg-5"}))).await.unwrap().status,
        "cancelled"
    );
    assert_eq!(
        fw.confirm(m(json!({"changeId": "chg-5", "code": "111111"})))
            .await
            .unwrap()
            .status,
        "expired"
    );

    // a Codex login is stored with its token endpoint and swaps on chatgpt.com
    w.agent.clear();
    w.code("555555");
    let expires = w.now() + 60 * 60_000;
    fw.propose(m(json!({
        "changeId": "chg-6", "kind": "add", "credentialId": "cred-codex", "provider": "openai_codex",
        "providerName": "ChatGPT", "credKind": "oauth", "placeholder": "eyJhbGciOiJub25lIn0.eyJjYyI6MX0.cc",
        "hint": "marco@example.com", "label": "marco@example.com", "profileId": "openai:controlclaw-chatgpt",
        "swap": {"matchDomain": "chatgpt.com", "locations": ["header:authorization"]},
        "oauth": {"tokenEndpoint": "https://auth.example/oauth/token", "clientId": "app_test"},
        "agents": [{"vmId": "vm2", "name": "second", "hostname": "second.vm.controlclaw.com", "model": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "role": "primary"}],
        "secret": {"oauth": {"access": "acc-1", "refresh": "ref-1", "expires": expires, "accountId": "acct_1", "email": "marco@example.com"}},
    })))
    .await
    .unwrap();
    assert_eq!(
        w.agent.calls()[0].body["text"],
        code_text("Connect ChatGPT (marco@example.com)", "555555")
    );
    let r = fw
        .confirm(m(json!({"changeId": "chg-6", "code": "555555"})))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    let c1 = w.agent.calls()[1].clone();
    assert_eq!(c1.target.vm_id, "vm2");
    assert_eq!(
        c1.body["credentials"][0],
        json!({
            "provider": "openai_codex", "kind": "oauth", "profileId": "openai:controlclaw-chatgpt",
            "value": "eyJhbGciOiJub25lIn0.eyJjYyI6MX0.cc",
            "model": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "codex": {"accountId": "acct_1"},
        })
    );
    let cred = fw.credentials().into_iter().find(|c| c["vm_id"] == "vm2").unwrap();
    assert_eq!(cred["secret"], json!("acc-1"));
    assert_eq!(cred["match_domain"], json!("chatgpt.com"));

    // choosing another fallback replaces the one in the slot, main model untouched
    let four = |model: &str, role: &str| json!({"vmId": "vm4", "name": "fourth", "hostname": "fourth.vm.controlclaw.com", "model": model, "role": role});
    w.code("333333");
    fw.propose(m(json!({"changeId": "chg-a", "kind": "bind", "credentialId": "cred-openai", "provider": "openai", "providerName": "OpenAI", "agents": [four("openai/gpt-5.6-sol", "primary")]}))).await.unwrap();
    fw.confirm(m(json!({"changeId": "chg-a", "code": "333333"})))
        .await
        .unwrap();
    w.code("444444");
    fw.propose(m(json!({"changeId": "chg-b", "kind": "bind", "credentialId": "cred-anthropic", "provider": "anthropic", "providerName": "Anthropic", "agents": [four("anthropic/claude-opus-5", "secondary")]}))).await.unwrap();
    fw.confirm(m(json!({"changeId": "chg-b", "code": "444444"})))
        .await
        .unwrap();
    w.agent.clear();
    w.code("555000");
    fw.propose(m(json!({"changeId": "chg-c", "kind": "bind", "credentialId": "cred-codex", "provider": "openai_codex", "providerName": "ChatGPT", "agents": [four("openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "secondary")]}))).await.unwrap();
    assert_eq!(
        w.agent.calls()[0].body["text"],
        code_text("Use ChatGPT gpt-5.6-sol on fourth as the fallback", "555000")
    );
    fw.confirm(m(json!({"changeId": "chg-c", "code": "555000"})))
        .await
        .unwrap();
    assert_eq!(
        w.agent.calls()[1].body["model"],
        json!({"primary": "openai/gpt-5.6-sol", "fallbacks": ["openai/gpt-5.6-sol@openai:controlclaw-chatgpt"]})
    );
    let mut roles: Vec<String> = w.load("llm.enc").agents["vm4"]
        .bindings
        .iter()
        .map(|b| format!("{}:{}", b.credential_id, b.role()))
        .collect();
    roles.sort();
    assert_eq!(
        roles,
        ["cred-codex:secondary", "cred-openai:primary"],
        "Anthropic is out of the slots"
    );

    // unbinding the main model moves the fallback up
    w.agent.clear();
    w.code("666000");
    fw.propose(m(json!({"changeId": "chg-d", "kind": "unbind", "credentialId": "cred-openai", "provider": "openai", "providerName": "OpenAI", "agents": [four("openai/gpt-5.6-sol", "primary")]}))).await.unwrap();
    fw.confirm(m(json!({"changeId": "chg-d", "code": "666000"})))
        .await
        .unwrap();
    assert_eq!(
        w.agent.calls()[1].body["model"],
        json!({"primary": "openai/gpt-5.6-sol@openai:controlclaw-chatgpt", "fallbacks": []})
    );
    assert_eq!(
        w.load("llm.enc").agents["vm4"]
            .bindings
            .iter()
            .map(|b| b.role().to_string())
            .collect::<Vec<_>>(),
        ["primary"]
    );

    // the access token is refreshed before it expires, with the rotated refresh token kept
    let before = w.refreshed.load(Ordering::SeqCst);
    fw.refresh_due().await;
    assert!(w.token.calls.lock().unwrap().is_empty(), "not due yet");
    w.now.fetch_add(60 * 60_000 - REFRESH_AHEAD_MS + 1000, Ordering::SeqCst);
    fw.refresh_due().await;
    let tc = w.token.calls.lock().unwrap().clone();
    assert_eq!(tc.len(), 1);
    assert_eq!(tc[0].0, "https://auth.example/oauth/token");
    assert_eq!(
        tc[0].1,
        vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), "ref-1".to_string()),
            ("client_id".to_string(), "app_test".to_string()),
        ]
    );
    let s = w.load("llm.enc").credentials["cred-codex"].secret.clone();
    assert_eq!(s["access"], json!("acc-2"));
    assert_eq!(s["refresh"], json!("ref-2"));
    assert_eq!(s["expires"], json!(w.now() + 3600 * 1000));
    assert_eq!(w.refreshed.load(Ordering::SeqCst), before + 1);
    assert_eq!(
        fw.credentials().into_iter().find(|c| c["vm_id"] == "vm2").unwrap()["secret"],
        json!("acc-2")
    );
    assert!(fw.drain_reports().is_empty());
    // Doctor gets the refreshed sign-in, never its refresh token.
    let d = crate::contracts::DoctorCredential::credential(&LlmDoctor(fw.clone()), "cred-codex")
        .await
        .unwrap();
    assert_eq!(d["secret"]["access"], json!("acc-2"));
    assert!(d["secret"].get("refresh").is_none(), "{d}");
    // and everything Doctor's own check reads is still there
    let got = crate::integrations::doctor::credentials::resolve(
        crate::integrations::doctor::stream::Cli::Codex,
        Some(&d),
        "gpt-5.6-sol",
        w.now(),
    )
    .expect("usable");
    assert_eq!(got.provider, "openai_codex");
    assert_eq!(got.env.get("OPENAI_API_KEY").map(String::as_str), Some("acc-2"));
    assert_eq!(
        got.env.get("CC_DOCTOR_OPENAI_ACCOUNT_ID").map(String::as_str),
        Some("acct_1")
    );

    // a refused refresh marks the credential failed and reports it once
    *w.token.answer.lock().unwrap() = (
        400,
        json!({"error": "invalid_grant", "error_description": "refresh token revoked"}),
    );
    w.now.fetch_add(3600 * 1000, Ordering::SeqCst);
    fw.refresh_due().await;
    let reports = fw.drain_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].command_id, "llm.refresh:cred-codex");
    assert!(reports[0].message.contains("refresh token revoked"));
    assert!(fw.drain_reports().is_empty());
    w.token.calls.lock().unwrap().clear();
    fw.refresh_due().await;
    assert!(
        w.token.calls.lock().unwrap().is_empty(),
        "a failed credential is not retried"
    );
    let (creds, _) = fw.summary();
    assert!(
        creds
            .iter()
            .find(|c| c.id == "cred-codex")
            .and_then(|c| c.failed.clone())
            .unwrap_or_default()
            .contains("Connect the account again")
    );

    // push re-applies an agent's state; a failure names the agent
    w.agent.clear();
    let r = fw
        .push(m(
            json!({"vmId": "vm1", "name": "marcobot", "hostname": "bot.vm.controlclaw.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    let mut applied: Vec<String> = serde_json::from_value(data(&r)["applied"].clone()).unwrap();
    applied.sort();
    assert_eq!(applied, ["cred-anthropic", "cred-openai"]);
    assert_eq!(w.agent.calls()[0].path, "/llm/apply");
    assert_eq!(
        w.agent.calls()[0].timeout,
        Some(Duration::from_millis(LLM_PUSH_MS)),
        "a push waits for a slow box, not the 25 s default"
    );
    *w.agent.apply_fails.lock().unwrap() = Some(AgentError::new("agent 500: boom"));
    let f = fw.push(m(json!({"vmId": "vm1"}))).await.unwrap();
    assert!(!f.ok);
    assert_eq!(
        data(&f)["failed"],
        json!([{"vmId": "vm1", "error": "agent 500: boom", "refused": true}])
    );
    *w.agent.apply_fails.lock().unwrap() = None;
    let none = fw.push(m(json!({"vmId": "vm-unknown"}))).await.unwrap();
    assert_eq!(data(&none), json!({"vmId": "vm-unknown", "applied": [], "failed": []}));

    // remove drops the credential from every bound agent and tells the boxes which profile to forget
    w.agent.clear();
    w.code("777777");
    fw.propose(m(json!({"changeId": "chg-7", "kind": "remove", "credentialId": "cred-openai", "provider": "openai", "providerName": "OpenAI", "agents": []}))).await.unwrap();
    assert!(
        w.agent.calls()[0].body["text"]
            .as_str()
            .unwrap()
            .contains("Remove OpenAI from the organization")
    );
    let r = fw
        .confirm(m(json!({"changeId": "chg-7", "code": "777777"})))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    let body = w.agent.calls()[1].body.clone();
    assert_eq!(
        body["remove"],
        json!([{"provider": "openai", "profileId": "openai:controlclaw", "kind": "api_key"}])
    );
    assert_eq!(body["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(body["model"]["primary"], json!("anthropic/claude-sonnet-5"));
    assert!(!w.load("llm.enc").credentials.contains_key("cred-openai"));

    // unbind takes a provider off one agent only
    w.agent.clear();
    w.code("888888");
    let mut x = bot();
    x["model"] = json!("x");
    fw.propose(m(json!({"changeId": "chg-8", "kind": "unbind", "credentialId": "cred-anthropic", "provider": "anthropic", "providerName": "Anthropic", "agents": [x]}))).await.unwrap();
    assert!(
        w.agent.calls()[0].body["text"]
            .as_str()
            .unwrap()
            .contains("Stop using Anthropic on marcobot")
    );
    fw.confirm(m(json!({"changeId": "chg-8", "code": "888888"})))
        .await
        .unwrap();
    assert_eq!(
        w.agent.calls()[1].body,
        json!({"model": {"primary": null, "fallbacks": []}, "credentials": [], "remove": [{"provider": "anthropic", "profileId": "anthropic:controlclaw", "kind": "api_key"}]})
    );
    assert_eq!(
        w.load("llm.enc").credentials["cred-anthropic"].provider,
        "anthropic",
        "the org still has it"
    );

    // the store survives a restart (new instance, same file)
    let fw = w.plain();
    // The unbind keeps the agent's entry; the restore check does not count it.
    assert!(w.load("llm.enc").agents.len() > fw.agents_using_models());
    let (creds, _) = fw.summary();
    let mut ids: Vec<String> = creds.iter().map(|c| c.id.clone()).collect();
    ids.sort();
    assert_eq!(ids, ["cred-anthropic", "cred-codex"]);

    // plain mode pushes the real key and leaves API keys out of the proxy list, OAuth still swapped
    w.set_routes(vec![]);
    let pfw = w.make(Opts {
        plain: true,
        ..Opts::default()
    });
    w.agent.clear();
    let mut b3 = bot();
    b3["vmId"] = json!("vm3");
    b3["hostname"] = json!("third.vm.controlclaw.com");
    pfw.propose(merge(
        openai_key(),
        json!({"changeId": "chg-9", "credentialId": "cred-openai2", "agents": [b3]}),
    ))
    .await
    .unwrap();
    assert_eq!(
        w.agent.calls()[0].body["credentials"][0]["value"],
        json!("sk-real-openai-key-a1b2")
    );
    let mut vms: Vec<String> = pfw
        .credentials()
        .iter()
        .map(|c| c["vm_id"].as_str().unwrap().to_string())
        .collect();
    vms.sort();
    assert_eq!(vms, ["vm2", "vm4"]);
}

#[tokio::test]
async fn a_refused_one_agent_change_is_rolled_back_and_the_old_state_sent_again() {
    let w = World::new();
    let solo = w.make(Opts {
        file: "rb.enc",
        ..Opts::default()
    });
    let nova = |model: &str, role: &str| json!({"vmId": "vm-nova", "name": "Nova", "hostname": "nova.vm.controlclaw.com", "model": model, "role": role});
    for (id, provider, model, role) in [
        ("cred-anthropic", "anthropic", "anthropic/claude-opus-5", "primary"),
        (
            "cred-included",
            "controlclaw",
            "controlclaw/anthropic/claude-sonnet-5",
            "secondary",
        ),
        ("cred-openai", "openai", "openai/gpt-5.6-sol", "primary"),
    ] {
        solo.propose(merge(
            openai_key(),
            json!({"changeId": format!("add-{id}"), "credentialId": id, "provider": provider, "providerName": provider,
                   "placeholder": format!("ph-{id}-0123456789"), "profileId": format!("{provider}:controlclaw"),
                   "agents": [nova(model, role)], "secret": {"apiKey": format!("real-{id}")}}),
        ))
        .await
        .unwrap();
    }
    let want = json!({"primary": "openai/gpt-5.6-sol", "fallbacks": ["controlclaw/anthropic/claude-sonnet-5"]});
    assert_eq!(w.agent.last().body["model"], want);

    w.agent.clear();
    w.agent.fail_once.lock().unwrap().push_back(AgentError::new(
        "agent 500: model: config.patch would remove entries from array path(s): agents.defaults.model.fallbacks",
    ));
    let r = solo
        .propose(m(json!({"changeId": "fb", "kind": "bind", "credentialId": "cred-anthropic", "provider": "anthropic", "providerName": "Anthropic", "agents": [nova("anthropic/claude-opus-5", "secondary")]})))
        .await
        .unwrap();
    assert_eq!(data(&r)["failed"][0]["refused"], json!(true));
    let posts = w.agent.calls();
    assert_eq!(posts.len(), 2, "the change, then the old state again");
    assert_eq!(posts[1].body["model"], want, "the box is sent back what it runs");
    w.agent.clear();
    solo.push(m(json!({"vmId": "vm-nova"}))).await.unwrap();
    assert_eq!(
        w.agent.calls()[0].body["model"],
        want,
        "later pushes do not try it again"
    );

    w.agent.clear();
    w.agent.fail_once.lock().unwrap().push_back(AgentError::new(
        "agent 500: model: config.patch would remove entries from array path(s): models.providers.controlclaw.models",
    ));
    let unbind = json!({"changeId": "unbind", "kind": "unbind", "credentialId": "cred-included", "provider": "controlclaw", "providerName": "Included", "agents": [nova("controlclaw/anthropic/claude-sonnet-5", "secondary")]});
    solo.propose(m(unbind.clone())).await.unwrap();
    assert_eq!(w.agent.calls()[1].body["model"], want);

    // A box that did not answer may have taken it: no rollback.
    w.agent.clear();
    w.agent.fail_once.lock().unwrap().push_back(AgentError::timeout());
    solo.propose(merge(unbind, json!({"changeId": "slow"}))).await.unwrap();
    assert_eq!(w.agent.calls().len(), 1);
    solo.push(m(json!({"vmId": "vm-nova"}))).await.unwrap();
    assert_eq!(
        w.agent.calls()[1].body["model"],
        json!({"primary": "openai/gpt-5.6-sol", "fallbacks": []})
    );
}

#[tokio::test]
async fn a_bind_only_adds_its_model_to_the_block_its_key_has() {
    let w = World::new();
    let fw = w.make(Opts {
        file: "pb.enc",
        ..Opts::default()
    });
    let agent = |vm: &str, model: &str| json!({"vmId": vm, "name": vm, "hostname": format!("{vm}.example"), "model": model, "role": "primary"});
    let block =
        |url: &str, id: &str| json!({"baseUrl": url, "api": "openai-completions", "models": [{"id": id, "name": id}]});
    const GW: &str = "https://ai-gateway.vercel.sh/v1";
    let add = |cred: &str, b: Option<Value>| {
        let mut p = json!({"changeId": format!("add-{cred}"), "credentialId": cred, "provider": "vercel-ai-gateway", "providerName": "Vercel AI Gateway",
               "placeholder": "vck-cc-0123456789abcdef", "profileId": "vercel-ai-gateway:controlclaw",
               "agents": [agent("vm1", "vercel-ai-gateway/x")], "secret": {"apiKey": "vck_real"}});
        if let Some(b) = b {
            p["providerBlock"] = b;
        }
        merge(openai_key(), p)
    };
    let bind = |change: &str, cred: &str, vm: &str, id: &str, b: Value| {
        m(
            json!({"changeId": change, "kind": "bind", "credentialId": cred, "provider": "vercel-ai-gateway",
                 "providerName": "Vercel AI Gateway", "providerBlock": b, "agents": [agent(vm, &format!("vercel-ai-gateway/{id}"))]}),
        )
    };
    let ids = |w: &World| -> Value {
        let models = &w.agent.last().body["credentials"][0]["providerBlock"]["models"];
        json!(
            models
                .as_array()
                .map(|l| l.iter().map(|m| m["id"].clone()).collect::<Vec<_>>())
        )
    };
    let refused = |r: Result<CommandOutcome, String>| r.map_or(true, |o| !o.ok);

    // The key comes with its endpoint; a bind adds its model there.
    fw.propose(add("cred-gw", Some(block(GW, "x")))).await.unwrap();
    w.agent.clear();
    fw.propose(bind("b1", "cred-gw", "vm2", "y", block(GW, "y")))
        .await
        .unwrap();
    assert_eq!(ids(&w), json!(["x", "y"]));

    // Another endpoint on a bind (a new agent's bind needs no code): refused, nothing kept.
    w.agent.clear();
    let r = fw
        .propose(bind("b2", "cred-gw", "vm3", "y", block("https://evil.example/v1", "y")))
        .await;
    assert!(refused(r), "a bind cannot move the key's endpoint");
    w.agent.clear();
    fw.push(m(json!({"vmId": "vm1"}))).await.unwrap();
    assert_eq!(
        w.agent.last().body["credentials"][0]["providerBlock"]["baseUrl"],
        json!(GW)
    );
    assert_eq!(ids(&w), json!(["x", "y"]));

    // Refused by the agent: only the model this bind added goes; one in use stays.
    w.agent
        .fail_once
        .lock()
        .unwrap()
        .push_back(AgentError::new("agent 500: model: unknown"));
    fw.propose(bind("b3", "cred-gw", "vm2", "z", block(GW, "z")))
        .await
        .unwrap();
    w.agent.clear();
    fw.push(m(json!({"vmId": "vm1"}))).await.unwrap();
    assert_eq!(ids(&w), json!(["x", "y"]));

    // A key stored with no block (before blocks came with binds) does not gain one from a bind.
    let plain = w.make(Opts {
        file: "pb2.enc",
        ..Opts::default()
    });
    plain.propose(add("cred-old", None)).await.unwrap();
    w.agent.clear();
    plain
        .propose(bind(
            "b4",
            "cred-old",
            "vm2",
            "y",
            block("https://evil.example/v1", "y"),
        ))
        .await
        .unwrap();
    assert!(w.agent.last().body["credentials"][0].get("providerBlock").is_none());
}

fn included(
    change_id: &str,
    cred: &str,
    placeholder: &str,
    allowed: Value,
    agents: Value,
    secret: &str,
) -> Map<String, Value> {
    m(json!({
        "changeId": change_id, "kind": "add", "credentialId": cred, "provider": "controlclaw",
        "providerName": "Included AI tokens", "credKind": "api_key", "placeholder": placeholder,
        "profileId": "controlclaw:included",
        "swap": {"matchDomain": "ai-gateway.vercel.sh", "locations": ["header:authorization"]},
        "allowedModels": allowed, "agents": agents, "secret": {"apiKey": secret},
    }))
}

#[tokio::test]
async fn included_tokens_and_provider_blocks() {
    let w = World::new();
    let ifw = w.plain();
    let block = json!({"baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [{"id": "moonshotai/kimi-k2.6", "name": "Kimi K2.6"}]});
    let mut p = included(
        "chg-inc",
        "cred-included",
        "vck-cc-included123",
        json!(["moonshotai/kimi-k2.6"]),
        json!([{"vmId": "vm5", "name": "fresh", "hostname": "fresh.vm.controlclaw.com", "model": "controlclaw/moonshotai/kimi-k2.6@controlclaw:included", "role": "primary"}]),
        "vck_real_gateway_key",
    );
    p.insert("hint".into(), json!("Included"));
    p.insert("providerBlock".into(), block.clone());
    let r = ifw.propose(p).await.unwrap();
    assert_eq!(r.status, "applied");
    let body = w.agent.calls()[0].body.clone();
    assert_eq!(body["credentials"][0]["providerBlock"], block);
    assert_eq!(body["credentials"][0]["value"], json!("vck-cc-included123"));
    assert!(!body.to_string().contains("vck_real"));
    let entry = ifw
        .credentials()
        .into_iter()
        .find(|c| c["placeholder"] == "vck-cc-included123")
        .unwrap();
    assert_eq!(entry["allowed_models"], json!(["moonshotai/kimi-k2.6"]));
    assert_eq!(entry["included"], json!(true));
    assert_eq!(ifw.included_credential_id().as_deref(), Some("cred-included"));
    w.agent.clear();
    ifw.propose(m(json!({"changeId": "chg-inc-rm", "kind": "remove", "credentialId": "cred-included", "provider": "controlclaw", "providerName": "Included AI tokens", "agents": []})))
        .await
        .unwrap();
    assert_eq!(
        w.agent.calls()[0].body["remove"],
        json!([{"provider": "controlclaw", "profileId": "controlclaw:included", "kind": "api_key", "providerBlock": true}])
    );
    assert_eq!(ifw.included_credential_id(), None);

    // a push brings a stored block up to date, compat included, and nothing else
    let bfw = w.make(Opts {
        file: "block.enc",
        ..Opts::default()
    });
    let mut p = included(
        "chg-block",
        "cred-block",
        "vck-cc-block",
        json!(["anthropic/claude-haiku-4.5"]),
        json!([{"vmId": "vm12", "name": "block", "hostname": "block.vm.controlclaw.com", "model": "controlclaw/anthropic/claude-haiku-4.5", "role": "primary"}]),
        "vck_real_block",
    );
    p.insert(
        "providerBlock".into(),
        json!({"baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [{"id": "anthropic/claude-haiku-4.5", "name": "Claude Haiku 4.5"}]}),
    );
    bfw.propose(p).await.unwrap();
    let sent = |w: &World| w.agent.last().body["credentials"][0]["providerBlock"].clone();
    assert_eq!(
        sent(&w)["models"],
        json!([{"id": "anthropic/claude-haiku-4.5", "name": "Claude Haiku 4.5"}])
    );
    let current = json!({"baseUrl": "https://ai-gateway.vercel.sh/v1", "api": "openai-completions", "models": [{"id": "anthropic/claude-haiku-4.5", "name": "Claude Haiku 4.5", "compat": {"supportsPromptCacheKey": true, "cacheControlFormat": "anthropic", "somethingElse": 1}}]});
    let push = |extra: Value| {
        merge(
            json!({"vmId": "vm12", "name": "block", "hostname": "block.vm.controlclaw.com"}),
            extra,
        )
    };
    bfw.push(push(
        json!({"providerBlocks": [{"credentialId": "cred-block", "providerBlock": current}]}),
    ))
    .await
    .unwrap();
    assert_eq!(
        sent(&w)["models"],
        json!([{"id": "anthropic/claude-haiku-4.5", "name": "Claude Haiku 4.5", "compat": {"supportsPromptCacheKey": true, "cacheControlFormat": "anthropic"}}])
    );
    bfw.push(push(json!({}))).await.unwrap();
    assert_eq!(
        sent(&w)["models"][0]["compat"],
        json!({"supportsPromptCacheKey": true, "cacheControlFormat": "anthropic"})
    );
    let mut elsewhere = current.clone();
    elsewhere["baseUrl"] = json!("https://elsewhere.example.com/v1");
    bfw.push(push(
        json!({"providerBlocks": [{"credentialId": "cred-block", "providerBlock": elsewhere}]}),
    ))
    .await
    .unwrap();
    assert_eq!(sent(&w)["baseUrl"], json!("https://ai-gateway.vercel.sh/v1"));
    bfw.push(push(
        json!({"providerBlocks": [{"credentialId": "cred-unknown", "providerBlock": current}]}),
    ))
    .await
    .unwrap();
    assert_eq!(sent(&w)["baseUrl"], json!("https://ai-gateway.vercel.sh/v1"));

    // plain mode never puts the included AI key on a box
    let pfw = w.make(Opts {
        file: "plain.enc",
        plain: true,
        ..Opts::default()
    });
    w.agent.clear();
    pfw.propose(included(
        "chg-inc-plain",
        "cred-included-2",
        "vck-cc-included456",
        json!(["moonshotai/kimi-k2.6"]),
        json!([{"vmId": "vm6", "name": "p", "hostname": "p.vm.controlclaw.com", "model": "controlclaw/moonshotai/kimi-k2.6", "role": "primary"}]),
        "vck_real_plain",
    ))
    .await
    .unwrap();
    assert!(!w.agent.calls()[0].body.to_string().contains("vck_real_plain"));
    assert!(
        pfw.credentials()
            .iter()
            .any(|c| c["placeholder"] == "vck-cc-included456" && c["secret"] == "vck_real_plain")
    );
}

#[tokio::test]
async fn memory_search() {
    let w = World::new();
    let mfw = w.plain();
    let memory = json!({"provider": "openai-compatible", "model": "openai/text-embedding-3-small", "baseUrl": "https://ai-gateway.vercel.sh/v1", "dreaming": false});
    let with_key = |m: &Value, k: &str| {
        let mut v = m.clone();
        v["apiKey"] = json!(k);
        v
    };
    let mut p = included(
        "chg-mem",
        "cred-mem",
        "vck-cc-included789",
        json!(["moonshotai/kimi-k2.6", "openai/text-embedding-3-small"]),
        json!([{"vmId": "vm7", "name": "mem", "hostname": "mem.vm.controlclaw.com", "model": "controlclaw/moonshotai/kimi-k2.6", "role": "primary"}]),
        "vck_real_mem",
    );
    p.insert("memory".into(), memory.clone());
    mfw.propose(p).await.unwrap();
    assert_eq!(
        w.agent.calls()[0].body["memory"],
        with_key(&memory, "vck-cc-included789")
    );
    assert!(!w.agent.calls()[0].body.to_string().contains("vck_real_mem"));

    w.agent.clear();
    mfw.propose(m(json!({
        "changeId": "chg-mem-other", "kind": "add", "credentialId": "cred-plain-key", "provider": "anthropic",
        "providerName": "Anthropic", "credKind": "api_key", "placeholder": "sk-ant-cc-1", "profileId": "anthropic:controlclaw",
        "swap": {"matchDomain": "api.anthropic.com", "locations": ["header:x-api-key"]},
        "agents": [{"vmId": "vm8", "name": "other", "hostname": "other.vm.controlclaw.com", "model": "anthropic/claude-opus-5", "role": "primary"}],
        "secret": {"apiKey": "sk-ant-real"},
    })))
    .await
    .unwrap();
    assert!(
        w.agent.calls()[0].body.get("memory").is_none(),
        "a box we never wrote a block to is left alone"
    );

    // a push carries the descriptor to a firewall that was set up without one
    let pfw = w.make(Opts {
        file: "old.enc",
        ..Opts::default()
    });
    pfw.propose(included(
        "chg-old",
        "cred-old",
        "vck-cc-old",
        json!(["moonshotai/kimi-k2.6"]),
        json!([{"vmId": "vm10", "name": "old", "hostname": "old.vm.controlclaw.com", "model": "controlclaw/moonshotai/kimi-k2.6", "role": "primary"}]),
        "vck_real_old",
    ))
    .await
    .unwrap();
    assert!(w.agent.last().body.get("memory").is_none());
    let allowed_of = |f: &Llm| {
        f.credentials()
            .into_iter()
            .find(|c| c["placeholder"] == "vck-cc-old")
            .unwrap()["allowed_models"]
            .clone()
    };
    assert_eq!(allowed_of(&pfw), json!(["moonshotai/kimi-k2.6"]));
    w.agent.clear();
    let before = w.refreshed.load(Ordering::SeqCst);
    let allowed = json!(["moonshotai/kimi-k2.6", "openai/text-embedding-3-small"]);
    let old = json!({"vmId": "vm10", "name": "old", "hostname": "old.vm.controlclaw.com"});
    pfw.push(merge(
        old.clone(),
        json!({"refresh": {"credentialId": "cred-old", "memory": memory, "allowedModels": allowed}}),
    ))
    .await
    .unwrap();
    assert_eq!(w.agent.calls()[0].body["memory"], with_key(&memory, "vck-cc-old"));
    assert_eq!(allowed_of(&pfw), allowed);
    assert!(w.refreshed.load(Ordering::SeqCst) > before);
    w.agent.clear();
    pfw.push(m(old.clone())).await.unwrap();
    assert_eq!(w.agent.calls()[0].body["memory"], with_key(&memory, "vck-cc-old"));

    // a clear that the box never took is still owed
    *w.agent.apply_fails.lock().unwrap() = Some(AgentError::new("the box did not answer"));
    w.agent.clear();
    pfw.push(merge(old.clone(), json!({"refresh": {"credentialId": "cred-old"}})))
        .await
        .unwrap();
    assert_eq!(w.agent.calls()[0].body["memory"], Value::Null);
    *w.agent.apply_fails.lock().unwrap() = None;
    w.agent.clear();
    pfw.push(m(old.clone())).await.unwrap();
    assert_eq!(w.agent.calls()[0].body["memory"], Value::Null, "still owed");
    w.agent.clear();
    pfw.push(m(old)).await.unwrap();
    assert!(w.agent.calls()[0].body.get("memory").is_none(), "ours is off");
    assert_eq!(allowed_of(&pfw), allowed, "an allow-list is only ever widened");

    // a descriptor the key's allow-list does not cover is ignored
    let gfw = w.make(Opts {
        file: "gate.enc",
        ..Opts::default()
    });
    gfw.propose(included(
        "chg-gate",
        "cred-gate",
        "vck-cc-gate",
        json!(["moonshotai/kimi-k2.6"]),
        json!([{"vmId": "vm11", "name": "gate", "hostname": "gate.vm.controlclaw.com", "model": "controlclaw/moonshotai/kimi-k2.6", "role": "primary"}]),
        "vck_real_gate",
    ))
    .await
    .unwrap();
    let other = json!({"provider": "openai-compatible", "model": "text-embedding-3-small", "baseUrl": "https://ai-gateway.vercel.sh/v1", "dreaming": false});
    let gate = json!({"vmId": "vm11", "name": "gate", "hostname": "gate.vm.controlclaw.com"});
    w.agent.clear();
    gfw.push(merge(
        gate.clone(),
        json!({"refresh": {"credentialId": "cred-gate", "memory": other}}),
    ))
    .await
    .unwrap();
    assert!(w.agent.calls()[0].body.get("memory").is_none());
    w.agent.clear();
    gfw.push(merge(gate, json!({"refresh": {"credentialId": "cred-gate", "memory": other, "allowedModels": ["moonshotai/kimi-k2.6", "text-embedding-3-small"]}})))
        .await
        .unwrap();
    assert_eq!(
        w.agent.calls()[0].body["memory"]["model"],
        json!("text-embedding-3-small")
    );
}

#[tokio::test]
async fn embeddings_paid_by_the_included_key() {
    let w = World::new();
    let efw = w.plain();
    let memory = json!({"provider": "openai-compatible", "model": "text-embedding-3-small", "baseUrl": "https://ai-gateway.vercel.sh/v1", "dreaming": true});
    let only = json!(["text-embedding-3-small", "openai/text-embedding-3-small"]);
    let with_key = |k: &str| {
        let mut v = memory.clone();
        v["apiKey"] = json!(k);
        v
    };
    efw.propose(included(
        "chg-emb-key",
        "cred-emb",
        "vck-cc-emb",
        json!([
            "moonshotai/kimi-k2.6",
            "text-embedding-3-small",
            "openai/text-embedding-3-small"
        ]),
        json!([]),
        "vck_real_emb",
    ))
    .await
    .unwrap();
    efw.propose(m(json!({
        "changeId": "chg-emb-chat", "kind": "add", "credentialId": "cred-chatgpt", "provider": "openai",
        "providerName": "ChatGPT", "credKind": "token", "placeholder": "eyJ-cc-codex-placeholder",
        "profileId": "openai:controlclaw-chatgpt", "swap": {"matchDomain": "chatgpt.com", "locations": ["header:authorization"]},
        "agents": [{"vmId": "vm20", "name": "ea-test", "hostname": "ea-test.vm.controlclaw.com", "model": "openai/gpt-5.6-codex@openai:controlclaw-chatgpt", "role": "primary"}],
        "secret": {"token": "chatgpt-oauth-token"},
    })))
    .await
    .unwrap();
    assert!(w.agent.last().body.get("memory").is_none());

    w.agent.clear();
    let before = w.refreshed.load(Ordering::SeqCst);
    let ea = json!({"vmId": "vm20", "name": "ea-test", "hostname": "ea-test.vm.controlclaw.com"});
    efw.push(merge(
        ea.clone(),
        json!({"refresh": {"credentialId": "cred-chatgpt", "memory": null}, "embeddings": {"credentialId": "cred-emb", "memory": memory, "allowedModels": only}}),
    ))
    .await
    .unwrap();
    let body = w.agent.calls()[0].body.clone();
    assert_eq!(body["memory"], with_key("vck-cc-emb"));
    assert!(!body.to_string().contains("vck_real_emb"));
    assert!(!body.to_string().contains("chatgpt-oauth-token"));
    assert_eq!(
        body["model"]["primary"],
        json!("openai/gpt-5.6-codex@openai:controlclaw-chatgpt")
    );
    assert_eq!(body["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(body["credentials"][0]["profileId"], json!("openai:controlclaw-chatgpt"));
    assert!(w.refreshed.load(Ordering::SeqCst) > before);
    let swap: Vec<Value> = efw.credentials().into_iter().filter(|c| c["vm_id"] == "vm20").collect();
    let payer = swap.iter().find(|c| c["placeholder"] == "vck-cc-emb").unwrap();
    assert_eq!(payer["secret"], json!("vck_real_emb"));
    assert_eq!(payer["allowed_models"], only);
    assert_eq!(payer["included"], json!(true));
    assert_eq!(swap.len(), 2);
    assert!(w.agent.sends().is_empty(), "a push never sends a code");
    assert_eq!(w.agent.applies().len(), 1);

    w.agent.clear();
    efw.push(m(ea.clone())).await.unwrap();
    assert_eq!(w.agent.calls()[0].body["memory"], with_key("vck-cc-emb"));
    w.agent.clear();
    w.plain().push(m(ea)).await.unwrap();
    assert_eq!(
        w.agent.calls()[0].body["memory"],
        with_key("vck-cc-emb"),
        "survives a restart"
    );

    // a push sends no code even when somebody is approved to be asked
    w.set_routes(vec![json!({"target": {"vmId": "vm40", "hostname": "nc.vm.controlclaw.com"}, "senders": [{"type": "telegram", "id": "99", "label": "Owner"}], "agentName": "nc"})]);
    w.agent.clear();
    let r = efw
        .push(m(json!({"vmId": "vm40", "name": "nc", "hostname": "nc.vm.controlclaw.com", "embeddings": {"credentialId": "cred-emb", "memory": memory, "allowedModels": only}})))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert!(w.agent.sends().is_empty());
    assert_eq!(w.agent.calls()[0].body["memory"], with_key("vck-cc-emb"));
    assert_eq!(
        w.agent.calls()[0].body["credentials"],
        json!([]),
        "no model, none invented"
    );
    assert_eq!(w.agent.calls()[0].body["model"]["primary"], Value::Null);
    w.set_routes(vec![]);

    // a push for an agent nobody pays for and nothing is bound to says nothing at all
    w.agent.clear();
    let r = efw
        .push(m(
            json!({"vmId": "vm22", "name": "stranger", "hostname": "stranger.vm.controlclaw.com", "embeddings": null}),
        ))
        .await
        .unwrap();
    assert!(w.agent.calls().is_empty());
    assert_eq!(r.status, "applied");

    // a payer whose allow-list does not cover the embedding model is refused
    w.agent.clear();
    efw.push(m(json!({"vmId": "vm32", "name": "r", "hostname": "r.vm.controlclaw.com", "embeddings": {"credentialId": "cred-emb", "memory": memory, "allowedModels": ["moonshotai/kimi-k2.6"]}})))
        .await
        .unwrap();
    assert!(w.agent.calls().is_empty());
    assert!(!efw.credentials().iter().any(|c| c["vm_id"] == "vm32"));

    // taking the included key away clears the block on agents it only paid for
    w.agent.clear();
    efw.propose(m(json!({"changeId": "chg-rm", "kind": "remove", "credentialId": "cred-emb", "provider": "controlclaw", "providerName": "Included AI tokens", "agents": []})))
        .await
        .unwrap();
    let pushed: Vec<String> = w.agent.calls().iter().map(|c| c.target.vm_id.clone()).collect();
    assert!(pushed.contains(&"vm20".to_string()) && pushed.contains(&"vm40".to_string()));
    assert!(w.agent.calls().iter().all(|c| c.body["memory"] == Value::Null));
    assert!(!efw.credentials().iter().any(|c| c["placeholder"] == "vck-cc-emb"));
}

#[tokio::test]
async fn a_new_agents_first_model() {
    let w = World::new();
    let clock = w.now.clone();
    let seen = Arc::new(AgentFirstSeen::new(Box::new(move || clock.load(Ordering::SeqCst))));
    let with_channels: Arc<Mutex<Vec<String>>> = Arc::default();
    let pred = |f: Arc<AgentFirstSeen>, live: bool| -> VmPredicate {
        Arc::new(move |v: &str| if live { f.is_live(v) } else { f.is_new(v) })
    };
    let ch = with_channels.clone();
    let make = |w: &World, offset: i64| {
        let ch = ch.clone();
        w.make(Opts {
            file: "llm-new.enc",
            new_agent: Some(pred(seen.clone(), false)),
            live_agent: Some(pred(seen.clone(), true)),
            channels: Some(Arc::new(move |v: &str| ch.lock().unwrap().iter().any(|x| x == v))),
            clock_offset: offset,
            ..Opts::default()
        })
    };
    let nfw = make(&w, 0);
    let codex = "openai/gpt-5.6-sol@openai:controlclaw-chatgpt";
    let agent = |vm: &str, model: &str| json!({"vmId": vm, "name": vm, "hostname": format!("{vm}.vm.controlclaw.com"), "model": model, "role": "primary"});
    let chatgpt = json!({
        "changeId": "chg-n1", "kind": "add", "credentialId": "cred-cgpt", "provider": "openai",
        "providerName": "ChatGPT", "credKind": "oauth", "placeholder": "eyJ.cc.placeholder",
        "label": "owner@example.com", "profileId": "openai:controlclaw-chatgpt",
        "swap": {"matchDomain": "chatgpt.com", "locations": ["header:authorization"]},
        "oauth": {"tokenEndpoint": "https://auth.openai.com/oauth/token", "clientId": "app_x"},
        "agents": [agent("old1", codex)],
        "secret": {"oauth": {"access": "acc", "refresh": "ref", "expires": w.now() + 3_600_000, "accountId": "acct", "email": "owner@example.com"}},
    });
    let bind = |id: &str, a: Value, extra: Value| {
        merge(
            json!({"changeId": id, "kind": "bind", "credentialId": "cred-cgpt", "provider": "openai", "providerName": "ChatGPT", "agents": [a]}),
            extra,
        )
    };
    let routes = vec![
        json!({"target": {"vmId": "old1", "hostname": "old1.vm.controlclaw.com"}, "senders": [{"type": "telegram", "id": "8734", "label": "Owner"}], "agentName": "old1"}),
    ];

    // nobody approved yet, the credential applies on first use as before
    seen.observe(vec!["old1".to_string()]);
    let r = nfw.propose(m(chatgpt.clone())).await.unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(data(&r)["tofu"], json!(true));
    assert!(data(&r).get("newAgent").is_none());

    // its first model on the approved credential applies with no code
    w.set_routes(routes.clone());
    w.now.fetch_add(60_000, Ordering::SeqCst);
    seen.observe(vec!["old1".to_string(), "new1".to_string()]);
    w.now.fetch_add(5 * 60_000, Ordering::SeqCst);
    w.agent.clear();
    let r = nfw
        .propose(bind(
            "chg-n2",
            agent("new1", "openai/gpt-5.6@openai:controlclaw-chatgpt"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(data(&r)["newAgent"], json!(true));
    assert_eq!(data(&r)["tofu"], json!(false));
    assert_eq!(
        data(&r)["summary"],
        json!("Use ChatGPT gpt-5.6 on new1 as the main model")
    );
    assert_eq!(data(&r)["applied"], json!(["new1"]));
    assert!(w.agent.sends().is_empty());
    assert_eq!(
        w.agent.applies()[0].body["model"]["primary"],
        json!("openai/gpt-5.6@openai:controlclaw-chatgpt")
    );

    let needs_code = |r: CommandOutcome, why: &str| assert_eq!(r.status, "awaiting_code", "{why}");
    // changing its model afterwards needs a code
    w.agent.clear();
    let r = nfw
        .propose(merge(
            Value::Object(bind("chg-n3", agent("new1", codex), json!({}))),
            json!({"kind": "set_model"}),
        ))
        .await
        .unwrap();
    needs_code(r, "set_model");
    assert_eq!(w.agent.sends().len(), 1);
    nfw.cancel(m(json!({"changeId": "chg-n3"}))).await.unwrap();
    // a second bind to the same agent needs a code
    needs_code(
        nfw.propose(bind("chg-n4", agent("new1", codex), json!({})))
            .await
            .unwrap(),
        "has a model",
    );
    // a new credential needs a code, even for a new agent
    seen.observe(vec!["old1".into(), "new1".into(), "new2".into()]);
    needs_code(
        nfw.propose(merge(
            chatgpt.clone(),
            json!({"changeId": "chg-n5", "credentialId": "cred-cgpt-2", "agents": [agent("new2", codex)]}),
        ))
        .await
        .unwrap(),
        "new credential",
    );
    // another provider's model, a fallback, a replacement or another provider needs a code
    let mut fallback = agent("new2", codex);
    fallback["role"] = json!("secondary");
    for (id, a, extra) in [
        (
            "chg-n6",
            agent("new2", "anthropic/claude-opus-5@openai:controlclaw-chatgpt"),
            json!({}),
        ),
        (
            "chg-n7",
            agent("new2", "openai/gpt-5.6-sol@openai:someone-else"),
            json!({}),
        ),
        ("chg-n8", fallback, json!({})),
        ("chg-n9", agent("new2", codex), json!({"replaces": "OpenAI"})),
        ("chg-n10", agent("new2", codex), json!({"provider": "anthropic"})),
    ] {
        needs_code(nfw.propose(bind(id, a, extra)).await.unwrap(), id);
    }
    // one with a channel on it needs a code
    with_channels.lock().unwrap().push("new2".into());
    needs_code(
        nfw.propose(bind("chg-n11", agent("new2", codex), json!({})))
            .await
            .unwrap(),
        "channel",
    );
    with_channels.lock().unwrap().clear();
    // once the window has passed, a code
    w.now.fetch_add(NEW_AGENT_WINDOW_MS + 1, Ordering::SeqCst);
    needs_code(
        nfw.propose(bind("chg-n12", agent("new2", codex), json!({})))
            .await
            .unwrap(),
        "window",
    );
    // one this firewall never saw, or saw before it started, needs a code
    for vm in ["never-seen", "old1"] {
        needs_code(
            nfw.propose(bind(&format!("chg-{vm}"), agent(vm, codex), json!({})))
                .await
                .unwrap(),
            vm,
        );
    }
    // a deleted agent's leftover binding does not count as the credential in use
    w.now.fetch_add(60_000, Ordering::SeqCst);
    seen.observe(vec!["new4".into()]);
    needs_code(
        nfw.propose(bind("chg-n14", agent("new4", codex), json!({})))
            .await
            .unwrap(),
        "deleted",
    );
    // a failed credential needs a code
    seen.observe(vec!["old1".into(), "new1".into(), "new3".into()]);
    *w.token.answer.lock().unwrap() = (400, json!({"error": "invalid_grant"}));
    let fetching = make(&w, 10 * 3_600_000);
    fetching.refresh_due().await;
    needs_code(
        fetching
            .propose(bind("chg-n13", agent("new3", codex), json!({})))
            .await
            .unwrap(),
        "failed",
    );
}

#[tokio::test]
async fn with_no_channels_module_a_proposal_is_refused_not_applied() {
    let w = World::new();
    let codes = w.codes.clone();
    let fw = Llm::new(LlmOptions {
        store_path: w.dir.path().join("closed.enc"),
        box_key: KEY.into(),
        org_id: "org1".into(),
        box_id: "fw1".into(),
        agent: Arc::new(w.agent.clone()),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
        code_routes: Arc::new(|| None),
        is_new_agent: None,
        is_live_agent: None,
        agent_has_channels: None,
        plain_keys: false,
        on_credentials_changed: Arc::new(|| Box::pin(async {})),
        fetch: Arc::new(w.token.clone()),
        now: Arc::new(|| 0),
    });
    let r = fw.propose(m(openai_key())).await.unwrap();
    assert!(!r.ok);
    assert_eq!(r.status, "failed");
    assert_eq!(r.message.as_deref(), Some(NO_ROUTES));
    assert!(w.agent.calls().is_empty(), "nothing pushed, nothing sent");
    assert!(fw.summary().0.is_empty(), "nothing stored");
}

#[test]
fn summaries_and_families() {
    let p = |agents: Value| {
        parse_proposal(&m(json!({"changeId": "c", "kind": "bind", "credentialId": "x", "provider": "openai", "providerName": "OpenAI", "agents": agents}))).unwrap()
    };
    assert_eq!(
        summarize(&p(json!([bot()]))),
        "Use OpenAI gpt-5.6-sol on marcobot as the main model"
    );
    let mut fb = bot();
    fb["role"] = json!("secondary");
    assert_eq!(
        summarize(&p(json!([fb]))),
        "Use OpenAI gpt-5.6-sol on marcobot as the fallback"
    );
    assert_eq!(summarize(&p(json!([]))), "Use OpenAI on the agent as the main model");
    assert_eq!(
        model_family("openai/gpt-5.6-sol@openai:controlclaw-chatgpt"),
        "openai@openai:controlclaw-chatgpt"
    );
    assert_eq!(model_family("openai/gpt-5.6"), "openai@");
    assert_eq!(model_family("controlclaw/moonshotai/kimi-k2.6"), "controlclaw@");
    assert_eq!(
        model_short("openai/gpt-5.6-sol@openai:controlclaw-chatgpt"),
        "gpt-5.6-sol"
    );
    assert_eq!(model_short("x@y"), "x@y");
    assert_eq!(form_encode(&[("a b".into(), "c&d=é".into())]), "a+b=c%26d%3D%C3%A9");
    assert!(
        parse_proposal(&m(
            json!({"changeId": "c", "kind": "nope", "credentialId": "x", "provider": "p"})
        ))
        .is_err()
    );
}

/// An agent that takes its time over `/llm/apply`.
struct SlowAgent;

impl AgentCalls for SlowAgent {
    fn post(
        &self,
        _: &Target,
        _: &str,
        _: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(Map::new())
        })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

#[tokio::test]
async fn a_slow_agent_holds_up_neither_a_refresh_nor_another_command() {
    let w = World::new();
    let codes = w.codes.clone();
    let now = w.now.clone();
    let fw = Llm::new(LlmOptions {
        store_path: w.dir.path().join("slow.enc"),
        box_key: KEY.into(),
        org_id: "org1".into(),
        box_id: "fw1".into(),
        agent: Arc::new(SlowAgent),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
        code_routes: Arc::new(|| Some(vec![])),
        is_new_agent: None,
        is_live_agent: None,
        agent_has_channels: None,
        plain_keys: false,
        on_credentials_changed: Arc::new(|| Box::pin(async {})),
        fetch: Arc::new(w.token.clone()),
        now: Arc::new(move || now.load(Ordering::SeqCst)),
    });
    // An OAuth login that is due for a refresh, applied with no agent to push to.
    let expires = w.now() + 60_000;
    fw.propose(m(json!({
        "changeId": "c1", "kind": "add", "credentialId": "cred-oauth", "provider": "openai_codex",
        "providerName": "ChatGPT", "credKind": "oauth", "placeholder": "ph-oauth-0123456789",
        "profileId": "openai:controlclaw-chatgpt", "swap": {"matchDomain": "chatgpt.com", "locations": ["header:authorization"]},
        "oauth": {"tokenEndpoint": "https://auth.example/oauth/token", "clientId": "app"}, "agents": [],
        "secret": {"oauth": {"access": "a1", "refresh": "r1", "expires": expires}},
    })))
    .await
    .unwrap();
    // A push to an agent that will not answer for 5 s.
    let slow = fw.clone();
    let push = tokio::spawn(async move {
        slow.propose(m(json!({"changeId": "c2", "kind": "add", "credentialId": "cred-key", "provider": "openai", "providerName": "OpenAI",
            "credKind": "api_key", "placeholder": "ph-key-0123456789", "profileId": "openai:controlclaw",
            "swap": {"matchDomain": "api.openai.com", "locations": ["header:authorization"]},
            "agents": [bot()], "secret": {"apiKey": "k"}})))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::timeout(Duration::from_secs(1), fw.refresh_due())
        .await
        .expect("the refresh does not wait for the push");
    assert_eq!(w.token.calls.lock().unwrap().len(), 1);
    let pushed = tokio::time::timeout(Duration::from_secs(1), fw.push(m(json!({"vmId": "vm-other"})))).await;
    assert!(pushed.is_ok(), "another command does not wait either");
    push.abort();
}

/// What Doctor reads through the contract is what its own credential check takes: the real key for
/// a stored API key, nothing for an id the store does not hold.
#[tokio::test]
async fn doctor_reads_a_stored_credential_through_the_contract() {
    use crate::contracts::DoctorCredential;
    use crate::integrations::doctor::credentials::resolve;
    use crate::integrations::doctor::stream::Cli;
    let w = World::new();
    let fw = w.plain();
    assert_eq!(fw.propose(m(openai_key())).await.unwrap().status, "applied");
    let doctor = LlmDoctor(fw.clone());
    let c = doctor.credential("cred-openai").await.expect("stored");
    let got = resolve(Cli::Codex, Some(&c), "gpt-5.6-sol", 0).expect("usable");
    assert_eq!(got.provider, "openai");
    assert_eq!(
        got.env.get("OPENAI_API_KEY").map(String::as_str),
        Some("sk-real-openai-key-a1b2")
    );
    assert!(doctor.credential("cred-nope").await.is_none());
}

/// What a recovery restore counts: an agent on one of the owner's credentials (a binding,
/// embeddings) or with a memory block that is not the included key's; not one on the plan's
/// included key alone, nor an entry an unbind emptied.
#[test]
fn the_agents_a_restore_would_break() {
    let memory = json!({"provider": "openai", "model": "text-embedding-3-small", "baseUrl": "https://x"});
    let owner_memory = json!({"provider": "openai", "model": "text-embedding-3-large", "baseUrl": "https://own"});
    let cred = |included: bool| {
        let mut c = json!({"provider": if included { "controlclaw" } else { "openai" }, "kind": "api_key", "placeholder": "p",
            "profileId": "x:controlclaw", "swap": {"matchDomain": "api.openai.com", "locations": []}, "secret": {}});
        if included {
            c["allowedModels"] = json!(["m"]);
            c["memory"] = memory.clone();
        }
        c
    };
    let emb = |id: &str| json!({"credentialId": id, "memory": memory, "allowedModels": []});
    let bind = |id: &str| json!([{"credentialId": id, "model": "m", "role": "primary"}]);
    // An owner's key with an allow-list is still the owner's.
    let mut listed = cred(false);
    listed["allowedModels"] = json!(["m"]);
    let st: super::store::LlmStore = serde_json::from_value(json!({
        "version": 1,
        "credentials": {"own": cred(false), "included": cred(true), "listed": listed},
        "agents": {
            "bound": {"name": "a", "bindings": bind("own")},
            "embeddings": {"name": "b", "bindings": [], "embeddings": emb("own")},
            "memory": {"name": "c", "bindings": [], "memory": owner_memory},
            "gone": {"name": "d", "bindings": bind("deleted")},
            "listed": {"name": "e", "bindings": bind("listed")},
            "stale memory": {"name": "f", "bindings": [], "embeddings": emb("included"), "memory": owner_memory},
            "included": {"name": "g", "bindings": bind("included"), "embeddings": emb("included"), "memory": memory},
            "included, memory from the binding": {"name": "h", "bindings": bind("included"), "memory": memory},
            "emptied": {"name": "i", "bindings": []},
        }
    }))
    .expect("store");
    assert_eq!(super::store::agents_using_models(&st), 6);
}
