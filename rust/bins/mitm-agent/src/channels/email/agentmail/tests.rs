//! `agentmail.test.ts`: signup once, claim, scoped keys, import, unassign and revoke, the
//! uncertain signup, the live organization shape, reconcile, and the sender list pushes.

#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::api::{AgentMailCalls, AgentMailError, ApiResult, error_code};
use super::*;
use crate::channels::agent::{AgentCalls, AgentError, Target};

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

#[derive(Default)]
struct Upstream {
    calls: Mutex<Vec<(String, String, Value, String)>>,
    verified: AtomicBool,
    error: Mutex<Option<String>>,
    scoped: AtomicBool,
    org: Mutex<String>,
    keys: AtomicUsize,
    live_shape: bool,
    imported_address: String,
    unreachable: bool,
}

impl AgentMailCalls for Arc<Upstream> {
    fn request(&self, method: &str, path: &str, key: Option<&str>, body: Option<Value>) -> BoxFuture<ApiResult> {
        let me = self.clone();
        let (method, path) = (method.to_string(), path.split('?').next().unwrap_or("").to_string());
        let auth = key.map(|k| format!("Bearer {k}")).unwrap_or_default();
        Box::pin(async move {
            if me.unreachable {
                return Err(AgentMailError::new("request_uncertain"));
            }
            me.calls
                .lock()
                .unwrap()
                .push((path.clone(), method.clone(), body.unwrap_or(json!({})), auth));
            if let Some(e) = me.error.lock().unwrap().clone() {
                let raw = json!({"message": e}).to_string();
                return Err(AgentMailError {
                    code: error_code(400, &raw),
                    http_status: 400,
                });
            }
            let org = me.org.lock().unwrap().clone();
            let verified = me.verified.load(Ordering::SeqCst);
            Ok(if path.ends_with("sign-up") {
                json!({"organization_id": org, "inbox_id": "first@agentmail.to", "api_key": "am_org_secret"})
            } else if path.ends_with("verify") {
                me.verified.store(true, Ordering::SeqCst);
                json!({"verified": true})
            } else if path.ends_with("organizations") {
                if me.live_shape {
                    json!({"organization_id": org, "authentication_type": "agent", "agent_verified": verified, "inbox_limit": 3})
                } else {
                    json!({"organization_id": org, "auth_type": if verified { "agent_verified" } else { "agent_unverified" }, "inbox_limit": 3})
                }
            } else if path == "/api-keys" {
                let mut row = json!({"api_key_id": "imported-key", "prefix": "am_import"});
                if me.scoped.load(Ordering::SeqCst) {
                    row["inbox_id"] = json!(me.imported_address);
                }
                json!({"api_keys": [row]})
            } else if path == "/inboxes" && method == "GET" {
                json!({"inboxes": [{"inbox_id": me.imported_address}]})
            } else if path.ends_with("/api-keys") {
                let n = me.keys.fetch_add(1, Ordering::SeqCst) + 1;
                json!({"api_key": format!("am_scoped_{n}"), "api_key_id": format!("key-{n}")})
            } else if method == "DELETE" {
                json!({})
            } else if path == "/inboxes" {
                json!({"inbox_id": "second@agentmail.to"})
            } else {
                panic!("unexpected request {path}")
            })
        })
    }
}

#[derive(Default)]
struct Agent {
    pushes: Mutex<Vec<Value>>,
    pending: AtomicBool,
    reads: AtomicUsize,
    status: Mutex<Option<Map<String, Value>>>,
    slow: AtomicBool,
}

impl AgentCalls for Arc<Agent> {
    fn post(
        &self,
        _: &Target,
        _: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.pushes.lock().unwrap().push(body);
        let r = if self.pending.load(Ordering::SeqCst) {
            json!({"ok": true, "status": "pending"})
        } else {
            json!({"ok": true})
        };
        Box::pin(async move { Ok(r.as_object().cloned().unwrap()) })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let me = self.clone();
        Box::pin(async move {
            while me.slow.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(me.status.lock().unwrap().clone().unwrap_or_default())
        })
    }
}

struct F {
    dir: tempfile::TempDir,
    up: Arc<Upstream>,
    agent: Arc<Agent>,
    allow: Arc<Mutex<Option<Vec<String>>>>,
}

fn fixture(live_shape: bool, imported: &str) -> F {
    let up = Upstream {
        live_shape,
        imported_address: imported.into(),
        ..Default::default()
    };
    *up.org.lock().unwrap() = "am-org".into();
    F {
        dir: tempfile::tempdir().unwrap(),
        up: Arc::new(up),
        agent: Arc::default(),
        allow: Arc::default(),
    }
}

fn plain() -> F {
    fixture(false, "imported@agentmail.to")
}

impl F {
    fn make_with(&self, api: Arc<dyn AgentMailCalls>) -> Arc<AgentMailFirewall> {
        let allow = self.allow.clone();
        AgentMailFirewall::new(AgentMailOptions {
            store_path: self.dir.path().join("agentmail.enc"),
            box_key: KEY.into(),
            org_id: "org".into(),
            box_id: "firewall".into(),
            agent: Arc::new(self.agent.clone()),
            on_credentials_changed: Arc::new(|| Box::pin(async {})),
            api,
            allow_from: Arc::new(move |_| allow.lock().unwrap().clone()),
            seed_senders: Arc::new(|_, _| {}),
        })
        .unwrap()
    }
    fn make(&self) -> Arc<AgentMailFirewall> {
        self.make_with(Arc::new(self.up.clone()))
    }
    fn error(&self, e: Option<&str>) {
        *self.up.error.lock().unwrap() = e.map(str::to_string);
    }
    fn imported(&self, scoped: bool) {
        self.up.scoped.store(scoped, Ordering::SeqCst);
        self.up.verified.store(true, Ordering::SeqCst);
    }
    fn last_push(&self) -> Value {
        self.agent.pushes.lock().unwrap().last().cloned().unwrap()
    }
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn signup() -> Value {
    json!({"vmId": "agent-1", "hostname": "agent-1.example.com", "changeId": "signup", "humanEmail": "owner@example.com", "username": "first"})
}

fn over(base: Value, o: Value) -> Map<String, Value> {
    let mut b = m(base);
    b.extend(m(o));
    b
}

async fn run(fw: &AgentMailFirewall, action: &str, p: Value) -> CommandOutcome {
    fw.command(action, m(p)).await
}

#[tokio::test]
async fn signup_once_claim_scoped_key_encrypted_store_and_metadata_only_results() {
    let f = plain();
    let fw = f.make();
    let s = run(&fw, "signup", signup()).await;
    assert_eq!(s.status, "awaiting_claim");
    assert!(fw.credentials().is_empty());
    fw.command("signup", over(signup(), json!({"changeId": "other-signup"})))
        .await;
    assert_eq!(
        f.up.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.0.ends_with("sign-up"))
            .count(),
        1
    );
    let result = run(&fw, "claim", json!({"changeId": "claim", "otpCode": "123456"})).await;
    assert!(result.ok);
    assert_eq!(f.agent.pushes.lock().unwrap().len(), 1);
    assert!(f.last_push()["placeholder"].as_str().unwrap().starts_with("CC-AMAIL-"));
    let mint =
        f.up.calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.0.ends_with("/api-keys") && c.1 == "POST")
            .cloned()
            .unwrap();
    assert_eq!(mint.2["permissions"].as_object().unwrap().len(), 9);
    assert_eq!(mint.3, "Bearer am_org_secret");
    for c in fw.credentials() {
        assert_eq!(c["vm_id"], "agent-1");
        assert_eq!(c["secret"], "am_scoped_1");
        assert_eq!(c["locations"], json!(["header:authorization", "query"]));
    }
    let seen = format!("{:?}{:?}{:?}", s.data, result.data, f.agent.pushes.lock().unwrap());
    assert!(!seen.contains("am_org_secret") && !seen.contains("am_scoped_") && !seen.contains("123456"));
    assert!(
        !std::fs::read_to_string(f.dir.path().join("agentmail.enc"))
            .unwrap()
            .contains("am_org_secret")
    );
    let st = store::load(&f.dir.path().join("agentmail.enc"), KEY, "org", "firewall").unwrap();
    assert_eq!(st.org_key.as_deref(), Some("am_org_secret"));
    let restored = f.make();
    assert_eq!(restored.credentials().len(), 2);
    assert!(
        run(&restored, "signup", signup()).await.ok,
        "the completed change is answered again"
    );
}

#[tokio::test]
async fn typed_upstream_errors() {
    for (message, code) in [
        ("user already exists", "user_exists"),
        ("username is taken", "username_taken"),
    ] {
        let f = plain();
        f.error(Some(message));
        let r = run(&f.make(), "signup", signup()).await;
        assert_eq!(r.data.as_ref().unwrap()["errorCode"], code);
        assert!(!format!("{r:?}").contains("am_"));
    }
}

#[tokio::test]
async fn import_org_and_inbox_scoped_keys() {
    for scoped in [false, true] {
        let f = plain();
        f.imported(scoped);
        let fw = f.make();
        assert!(
            run(
                &fw,
                "import",
                json!({"apiKey": "am_import_secret", "humanEmail": "owner@example.com"})
            )
            .await
            .ok
        );
        assert!(
            run(
                &fw,
                "attach",
                json!({"vmId": "agent-1", "hostname": "agent-1.example.com", "inboxId": "imported@agentmail.to"})
            )
            .await
            .ok
        );
        assert_eq!(
            fw.credentials()[0]["secret"],
            if scoped { "am_import_secret" } else { "am_scoped_1" }
        );
        let mints =
            f.up.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.1 == "POST" && c.0.ends_with("api-keys"))
                .count();
        assert_eq!(mints, if scoped { 0 } else { 1 });
        *f.up.org.lock().unwrap() = "different-org".into();
        let r = run(
            &fw,
            "import",
            json!({"apiKey": "am_import_secret", "humanEmail": "other@example.com"}),
        )
        .await;
        assert_eq!(r.data.unwrap()["errorCode"], "organization_mismatch");
    }
}

#[tokio::test]
async fn unassign_revokes_before_reattach_and_rotates_placeholder_and_key() {
    let f = plain();
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    run(&fw, "claim", json!({"otpCode": "123456"})).await;
    let old = fw.credentials()[0].clone();
    assert!(run(&fw, "forget", json!({"vmId": "agent-1"})).await.ok);
    assert!(fw.credentials().is_empty());
    assert!(
        f.up.calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.1 == "DELETE" && c.0.ends_with("key-1"))
    );
    assert_eq!(fw.summary()["inboxes"].as_array().unwrap().len(), 1);
    run(
        &fw,
        "attach",
        json!({"vmId": "agent-2", "hostname": "agent-2.example.com", "inboxId": "first@agentmail.to"}),
    )
    .await;
    let next = fw.credentials()[0].clone();
    assert_ne!(next["placeholder"], old["placeholder"]);
    assert_ne!(next["secret"], old["secret"]);
    assert_eq!(next["vm_id"], "agent-2");
    assert!(
        !run(
            &fw,
            "delete",
            json!({"inboxId": "first@agentmail.to", "confirmAddress": "wrong@agentmail.to"})
        )
        .await
        .ok
    );
}

#[tokio::test]
async fn a_network_ambiguous_signup_is_never_repeated_even_after_restart() {
    let f = plain();
    let dead = Upstream {
        unreachable: true,
        ..Default::default()
    };
    let api: Arc<dyn AgentMailCalls> = Arc::new(Arc::new(dead));
    let first = run(&f.make_with(api.clone()), "signup", signup()).await;
    assert_eq!(first.message.as_deref(), Some("request_uncertain"));
    let second = run(&f.make_with(api), "signup", signup()).await;
    assert_eq!(second.message.as_deref(), Some("signup_uncertain"));
}

#[tokio::test]
async fn live_organization_shape_requires_explicit_agent_verified() {
    let f = fixture(true, "imported@agentmail.to");
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    run(&fw, "check", json!({})).await;
    assert!(fw.credentials().is_empty());
    assert!(run(&fw, "claim", json!({"otpCode": "123456"})).await.ok);
    assert_eq!(fw.credentials().len(), 2);
}

#[tokio::test]
async fn failed_revocation_can_be_retried_when_attaching_elsewhere() {
    let f = plain();
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    run(&fw, "claim", json!({"otpCode": "123456"})).await;
    f.error(Some("temporary upstream failure"));
    assert!(!run(&fw, "forget", json!({"vmId": "agent-1"})).await.ok);
    assert_eq!(fw.summary()["inboxes"][0]["vmId"], Value::Null);
    assert!(fw.credentials().is_empty());
    f.error(None);
    assert!(
        run(
            &fw,
            "attach",
            json!({"vmId": "agent-2", "hostname": "two.example.com", "inboxId": "first@agentmail.to"})
        )
        .await
        .ok
    );
    assert_eq!(fw.credentials()[0]["vm_id"], "agent-2");
    assert_eq!(fw.credentials()[0]["secret"], "am_scoped_2");
}

#[tokio::test]
async fn read_refreshes_upstream_metadata_without_pushing_any_agent() {
    let f = plain();
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    run(&fw, "read", json!({})).await;
    assert!(
        f.up.calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.0.ends_with("/organizations"))
    );
    assert!(f.agent.pushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_assigned_imported_inbox_accepts_a_replacement_scoped_key() {
    let f = plain();
    f.imported(true);
    let fw = f.make();
    run(
        &fw,
        "import",
        json!({"apiKey": "am_import_old", "humanEmail": "owner@example.com"}),
    )
    .await;
    run(
        &fw,
        "attach",
        json!({"vmId": "agent-1", "hostname": "agent-1.example.com", "inboxId": "imported@agentmail.to"}),
    )
    .await;
    let old = fw.credentials()[0]["placeholder"].clone();
    run(
        &fw,
        "import",
        json!({"apiKey": "am_import_new", "humanEmail": "different@example.com"}),
    )
    .await;
    assert_eq!(fw.credentials()[0]["secret"], "am_import_new");
    assert_ne!(fw.credentials()[0]["placeholder"], old);
    assert_eq!(f.last_push()["humanEmail"], "owner@example.com");
}

#[tokio::test]
async fn unsupported_imported_inboxes_never_enter_heartbeat_metadata() {
    for scoped in [false, true] {
        let f = fixture(false, "owner@custom.example");
        f.imported(scoped);
        let fw = f.make();
        let r = run(
            &fw,
            "import",
            json!({"apiKey": "am_import_secret", "humanEmail": "owner@example.com"}),
        )
        .await;
        assert_eq!(r.ok, !scoped);
        if scoped {
            assert_eq!(r.data.unwrap()["errorCode"], "unsupported_inbox");
        }
        assert_eq!(fw.summary()["inboxes"], json!([]));
    }
}

#[tokio::test]
async fn slow_reconciliation_is_coalesced() {
    let f = plain();
    f.agent.pending.store(true, Ordering::SeqCst);
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    run(&fw, "claim", json!({"otpCode": "123456"})).await;
    f.agent.slow.store(true, Ordering::SeqCst);
    let a = fw.clone();
    let first = tokio::spawn(async move { a.reconcile().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    fw.reconcile().await; // returns at once: one is running
    assert_eq!(f.agent.reads.load(Ordering::SeqCst), 1);
    *f.agent.status.lock().unwrap() = Some(m(json!({"apply": {
        "inboxId": "first@agentmail.to",
        "placeholder": fw.credentials()[0]["placeholder"],
        "status": "active",
    }})));
    f.agent.slow.store(false, Ordering::SeqCst);
    first.await.unwrap();
    assert_eq!(fw.summary()["inboxes"][0]["status"], "active");
}

#[tokio::test]
async fn explicit_sender_edits_survive_reload_and_reassignment() {
    let f = plain();
    let fw = f.make();
    fw.command(
        "signup",
        over(
            signup(),
            json!({"allowedSenders": ["owner+mail@gmail.com", "owner@gmail.com"]}),
        ),
    )
    .await;
    run(&fw, "claim", json!({"otpCode": "123456"})).await;
    assert_eq!(
        f.last_push()["allowedSenders"],
        json!(["owner+mail@gmail.com", "owner@gmail.com"])
    );
    assert!(
        !run(
            &fw,
            "senders",
            json!({"inboxId": "first@agentmail.to", "allowedSenders": ["*"]})
        )
        .await
        .ok
    );
    run(
        &fw,
        "senders",
        json!({"inboxId": "first@agentmail.to", "allowedSenders": ["other+mail@gmail.com"]}),
    )
    .await;
    let reloaded = f.make();
    run(&reloaded, "forget", json!({"vmId": "agent-1"})).await;
    run(
        &reloaded,
        "attach",
        json!({"vmId": "agent-2", "hostname": "agent-1.example.com", "inboxId": "first@agentmail.to"}),
    )
    .await;
    assert_eq!(f.last_push()["allowedSenders"], json!(["other+mail@gmail.com"]));
    assert!(
        run(
            &reloaded,
            "senders",
            json!({"inboxId": "first@agentmail.to", "allowedSenders": ["o'connor@example.com"]})
        )
        .await
        .ok
    );
    assert_eq!(f.last_push()["allowedSenders"], json!(["o'connor@example.com"]));
    run(
        &reloaded,
        "senders",
        json!({"inboxId": "first@agentmail.to", "allowedSenders": []}),
    )
    .await;
    assert_eq!(f.last_push()["allowedSenders"], json!([]));
    assert_eq!(reloaded.summary()["inboxes"][0]["allowedSenders"], json!([]));
}

#[tokio::test]
async fn a_rules_change_re_pushes_an_inbox_only_when_its_sender_list_changed() {
    let f = plain();
    *f.allow.lock().unwrap() = Some(vec!["owner@gmail.com".into()]);
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    run(&fw, "claim", json!({"otpCode": "123456"})).await;
    let pushed = f.agent.pushes.lock().unwrap().len();
    assert_eq!(f.last_push()["allowedSenders"], json!(["owner@gmail.com"]));
    fw.refresh_senders().await;
    assert_eq!(f.agent.pushes.lock().unwrap().len(), pushed);
    *f.allow.lock().unwrap() = Some(vec!["*".into()]);
    fw.refresh_senders().await;
    assert_eq!(f.agent.pushes.lock().unwrap().len(), pushed + 1);
    assert_eq!(f.last_push()["allowedSenders"], json!(["*"]));
    fw.refresh_senders().await;
    assert_eq!(f.agent.pushes.lock().unwrap().len(), pushed + 1);
    assert!(
        !run(
            &fw,
            "senders",
            json!({"inboxId": "first@agentmail.to", "allowedSenders": ["x@y.com"]})
        )
        .await
        .ok
    );
}

#[tokio::test]
async fn review_fixes_replays_null_senders_and_bad_legacy_lists() {
    let f = plain();
    f.agent.pending.store(true, Ordering::SeqCst);
    let fw = f.make();
    run(&fw, "signup", signup()).await;
    // A change already done is `applied`, even while the account waits for its claim.
    assert_eq!(run(&fw, "signup", signup()).await.status, "applied");
    run(&fw, "claim", json!({"otpCode": "123456"})).await;
    // `allowedSenders: null` from the agent is the owner's address, as `??` reads it.
    *f.agent.status.lock().unwrap() = Some(m(json!({"apply": {
        "inboxId": "first@agentmail.to",
        "placeholder": fw.credentials()[0]["placeholder"],
        "status": "active",
        "allowedSenders": null,
    }})));
    fw.reconcile().await;
    assert_eq!(fw.summary()["inboxes"][0]["status"], "active");
    // A stored list that does not parse is not moved as an empty one.
    fw.command(
        "senders",
        m(json!({"inboxId": "first@agentmail.to", "allowedSenders": ["ok@x.com"]})),
    )
    .await;
    assert!(fw.legacy_senders().is_ok());
    fw.edit_inbox("first@agentmail.to", |i| {
        i.allowed_senders = Some(json!(["not an address"]))
    })
    .unwrap();
    assert!(fw.legacy_senders().is_err());
}
