//! `secrets.test.ts`: encrypted storage, consent, narrowing, per-agent placeholders, retry, and
//! the input checks. The code's expiry is the consent module's (W3) and is tested there.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::*;
use crate::channels::agent::AgentError;
use crate::contracts::SendResult;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[derive(Default)]
struct Agent {
    sent: Mutex<Vec<(String, Value)>>,
    offline: AtomicBool,
}

impl AgentCalls for Arc<Agent> {
    fn post(
        &self,
        _: &Target,
        path: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        let r = if self.offline.load(Ordering::SeqCst) && path == "/secrets/apply" {
            Err(AgentError::new("private-value"))
        } else {
            self.sent.lock().unwrap().push((path.into(), body));
            Ok(Map::new())
        };
        Box::pin(async move { r })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

#[derive(Default)]
struct Codes(Mutex<HashMap<String, (String, Value)>>);

impl ConsentCodes for Codes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        self.0.lock().unwrap().insert(req.scope, (req.change_id, req.proposal));
        Box::pin(async {
            SendResult {
                sent_via: Some("telegram:Owner".into()),
                error: None,
                delivery_failed: false,
                expires_at_ms: 600_000,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut m = self.0.lock().unwrap();
        match m.get(scope) {
            Some((c, _)) if c == change_id && code == "123456" => Verify::Ok(m.remove(scope).unwrap().1),
            Some((c, _)) if c == change_id => Verify::Wrong { tries_left: 4 },
            _ => Verify::Expired,
        }
    }
    fn cancel(&self, scope: &str, _: Option<&str>) -> bool {
        self.0.lock().unwrap().remove(scope).is_some()
    }
    fn forget(&self, scope: &str) {
        self.0.lock().unwrap().remove(scope);
    }
}

fn make(dir: &std::path::Path, agent: &Arc<Agent>, codes: &Arc<Codes>, routes: bool) -> Arc<SecretsFirewall> {
    let codes = codes.clone();
    SecretsFirewall::new(SecretsOptions {
        store_path: dir.join("secrets.enc"),
        box_key: KEY.into(),
        org_id: "org".into(),
        box_id: "box".into(),
        agent: Arc::new(agent.clone()),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
        code_routes: Arc::new(move || {
            Ok(if routes {
                vec![json!({"target": {"vmId": "a", "hostname": "a.example.com"}, "senders": [{"type": "telegram", "id": "1", "label": "Owner"}]})]
            } else {
                vec![]
            })
        }),
        on_credentials_changed: Arc::new(|| Box::pin(async {})),
    })
    .unwrap()
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn rules() -> Value {
    json!({"hosts": ["*.example.com"], "locations": [{"kind": "header", "name": "authorization", "prefix": "Bearer "}, {"kind": "query", "name": "key"}]})
}

fn proposal(over: Value) -> Map<String, Value> {
    let mut p = json!({
        "action": "create", "name": "API_TOKEN", "rules": rules(), "vmIds": ["a", "b"],
        "agents": [{"vmId": "a", "hostname": "a.example.com"}, {"vmId": "b", "hostname": "b.example.com"}],
        "secret": {"value": "private-value"}, "changeId": "one",
    });
    for (k, v) in over.as_object().unwrap() {
        p[k] = v.clone();
    }
    m(p)
}

#[tokio::test]
async fn storage_consent_narrowing_placeholders_and_retry() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(Agent::default());
    let codes = Arc::new(Codes::default());
    let fw = make(dir.path(), &agent, &codes, true);
    assert_eq!(fw.command("propose", proposal(json!({}))).await.status, "awaiting_code");
    assert!(fw.credentials().is_empty());
    assert!(!format!("{:?}", agent.sent.lock().unwrap()).contains("private-value"));
    let c = |change: &str, code: &str| m(json!({"name": "API_TOKEN", "changeId": change, "code": code}));
    assert_eq!(fw.command("confirm", c("one", "000000")).await.status, "invalid");
    let applied = fw.command("confirm", c("one", "123456")).await;
    assert_eq!(applied.status, "applied");
    assert!(!serde_json::to_string(&applied.data).unwrap().contains("private-value"));
    assert!(
        !std::fs::read_to_string(dir.path().join("secrets.enc"))
            .unwrap()
            .contains("private-value")
    );
    let creds = fw.credentials();
    assert_eq!(creds.len(), 2);
    assert_ne!(creds[0]["placeholder"], creds[1]["placeholder"]);
    let ph = creds[0]["placeholder"].as_str().unwrap();
    assert!(ph.starts_with("CC-SEC-") && ph.len() == 7 + 48 && ph[7..].bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!format!("{:?}", agent.sent.lock().unwrap()).contains("private-value"));
    assert_eq!(
        make(dir.path(), &agent, &codes, true).summary(),
        fw.summary(),
        "survives a restart"
    );

    // replace keeps the placeholder
    let r = fw
        .command("propose", m(json!({"action": "replace", "name": "API_TOKEN", "changeId": "replace", "secret": {"value": "replacement-only"}})))
        .await;
    assert_eq!(r.status, "awaiting_code");
    assert_eq!(fw.credentials()[0]["secret"], "private-value");
    assert_eq!(fw.command("confirm", c("replace", "123456")).await.status, "applied");
    assert_eq!(fw.credentials()[0]["secret"], "replacement-only");
    assert_eq!(fw.credentials()[0]["placeholder"], creds[0]["placeholder"]);
    assert!(!fw.summary().to_string().contains("replacement-only"));

    // narrowing applies without a code; an offline agent is retried
    agent.offline.store(true, Ordering::SeqCst);
    let narrow = proposal(
        json!({"action": "update", "changeId": "two", "vmIds": ["a"], "rules": {"hosts": ["api.example.com"], "locations": rules()["locations"]}, "secret": null}),
    );
    assert_eq!(fw.command("propose", narrow).await.status, "applied");
    assert_eq!(fw.credentials().len(), 1);
    agent.offline.store(false, Ordering::SeqCst);
    fw.reconcile().await;
    assert_eq!(agent.sent.lock().unwrap().last().unwrap().1, json!({"entries": []}));

    // widening needs a code; a delete applies at once and the pending change is gone
    assert_eq!(
        fw.command(
            "propose",
            proposal(json!({"action": "update", "changeId": "three", "secret": null}))
        )
        .await
        .status,
        "awaiting_code"
    );
    assert_eq!(
        fw.command(
            "propose",
            m(json!({"action": "delete", "name": "API_TOKEN", "changeId": "four"}))
        )
        .await
        .status,
        "applied"
    );
    assert_eq!(fw.command("confirm", c("three", "123456")).await.status, "expired");
    assert!(fw.credentials().is_empty());

    // nobody to send a code to: refused, nothing stored
    let none = make(tempfile::tempdir().unwrap().path(), &agent, &codes, false);
    let r = none.command("propose", proposal(json!({}))).await;
    assert!(!r.ok);
    assert_eq!(r.message.as_deref(), Some(NOBODY));
    assert!(none.credentials().is_empty());
    // a name that exists, or one that does not
    let r = fw.command("propose", proposal(json!({"changeId": "dup"}))).await;
    assert_eq!(r.status, "awaiting_code");
    let r = fw
        .command(
            "propose",
            m(json!({"action": "delete", "name": "OTHER", "changeId": "x"})),
        )
        .await;
    assert_eq!(r.message.as_deref(), Some("Secret not found."));
}

#[test]
fn unsafe_inputs_are_refused_and_broader_access_is_told_apart() {
    let base = json!({"action": "create", "name": "TOKEN", "rules": rules(), "vmIds": ["a"]});
    let parse = |over: Value, value: &str| {
        let mut b = base.clone();
        for (k, v) in over.as_object().unwrap() {
            b[k] = v.clone();
        }
        parse_input(b.as_object().unwrap(), Some(&json!(value)))
    };
    for name in ["NODE_OPTIONS", "HOME", "OPENCLAW_TOKEN", "A\nB"] {
        assert!(parse(json!({"name": name}), "safe").is_err(), "{name}");
    }
    for host in ["*", "https://example.com", "api.example.com/", "evil@example.com"] {
        assert!(
            parse(
                json!({"rules": {"hosts": [host], "locations": rules()["locations"]}}),
                "safe"
            )
            .is_err(),
            "{host}"
        );
    }
    assert!(parse(json!({}), "x\r\nInjected: 1").is_err());
    let Input::Create { spec, .. } = parse(json!({}), "safe").unwrap() else {
        panic!()
    };
    assert_eq!(spec.rules.hosts, ["*.example.com"]);
    let narrower = Spec {
        rules: Rules {
            hosts: vec!["api.example.com".into()],
            locations: spec.rules.locations.clone(),
        },
        ..spec.clone()
    };
    assert!(!widens(&spec, &narrower));
    assert!(widens(
        &spec,
        &Spec {
            vm_ids: vec!["a".into(), "b".into()],
            ..spec.clone()
        }
    ));
    let other_prefix = Spec {
        rules: Rules {
            hosts: spec.rules.hosts.clone(),
            locations: vec![Location::Header {
                name: "authorization".into(),
                prefix: String::new(),
            }],
        },
        ..spec.clone()
    };
    assert!(widens(&spec, &other_prefix));
    assert!(host_within("api.example.com", "*.example.com"));
    assert!(!host_within("example.com", "*.example.com"));
}

#[tokio::test]
async fn a_change_that_could_not_be_saved_is_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(Agent::default());
    let codes = Arc::new(Codes::default());
    let fw = make(dir.path(), &agent, &codes, true);
    assert_eq!(fw.command("propose", proposal(json!({}))).await.status, "awaiting_code");
    // The store's place is taken by a directory: the save fails.
    std::fs::create_dir(dir.path().join("secrets.enc")).unwrap();
    let c = m(json!({"name": "API_TOKEN", "changeId": "one", "code": "123456"}));
    assert_eq!(fw.command("confirm", c).await.status, "failed");
    assert!(fw.credentials().is_empty());
    assert_eq!(
        fw.command("read", m(json!({}))).await.data,
        Some(m(json!({"secrets": []})))
    );
    // Only what apply reads was handed to the codes: not the console's extra fields.
    let mut p = proposal(json!({"changeId": "two"}));
    p.insert("note".into(), json!("extra"));
    fw.command("propose", p).await;
    assert!(!format!("{:?}", codes.0.lock().unwrap()).contains("extra"));
}
