//! Outside AI apps on the brain (T-219), the firewall's half: a sign-in always takes a code, the
//! app's name comes from the brain, narrowing and removing need none, and reconcile only takes away.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::agent_client::AgentClient;
use super::gbrain::Brain;
use super::identities::Agents;
use super::kit::Kit;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRoute, CodeRouteSource, CodeSender, CodeSent, ModuleCodes};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// sha256 of the Connect page's approval secret, as the console sends it.
const APPROVAL: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// No code channel anywhere.
struct Nobody;

impl CodeRouteSource for Nobody {
    fn routes(&self) -> Vec<CodeRoute> {
        vec![]
    }
    fn ready(&self) -> bool {
        true
    }
    fn agent_allowed_count(&self) -> Option<u32> {
        Some(0)
    }
}

struct People;

impl CodeRouteSource for People {
    fn routes(&self) -> Vec<CodeRoute> {
        vec![CodeRoute {
            vm_id: "ag_1".into(),
            hostname: "ag-1.example".into(),
            senders: vec![CodeSender::Person {
                kind: "telegram".into(),
                id: "1".into(),
                label: Some("Marco".into()),
            }],
            telegram: None,
        }]
    }
    fn ready(&self) -> bool {
        true
    }
    fn agent_allowed_count(&self) -> Option<u32> {
        Some(0)
    }
}

/// The code `123456` is right for the last change asked about.
#[derive(Default)]
struct Codes {
    asks: Mutex<Vec<CodeAsk>>,
}

impl ModuleCodes for Codes {
    fn send(&self, req: CodeAsk) -> BoxFuture<CodeSent> {
        self.asks.lock().expect("lock").push(req);
        Box::pin(async {
            CodeSent::Sent {
                sent_via: "telegram:Marco".into(),
                expires_at: "2026-11-20T10:10:00.000Z".into(),
                attempts_left: 5,
                recovery: None,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> CodeCheck {
        let asks = self.asks.lock().expect("lock");
        match asks.last() {
            Some(a) if a.scope == scope && a.change_id == change_id && code == "123456" => CodeCheck::Ok {
                proposal: a.proposal.clone(),
                sent_via: "telegram:Marco".into(),
            },
            Some(_) => CodeCheck::Wrong { tries_left: 4 },
            None => CodeCheck::Expired,
        }
    }
    fn cancel(&self, _: &str, _: Option<&str>) -> bool {
        true
    }
    fn forget(&self, _: &str) {}
}

type Calls = Arc<Mutex<Vec<(String, String, Value)>>>;

/// The brain's vm-agent: answers the client routes and records every call.
async fn brain_box(calls: Calls, on_brain: Arc<Mutex<Value>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |req, _| {
            let (calls, on_brain) = (calls.clone(), on_brain.clone());
            async move {
                use http_body_util::BodyExt;
                let method = req.method().to_string();
                let path = req.uri().path().trim_start_matches("/__cc/agent").to_string();
                let raw = req
                    .into_body()
                    .collect()
                    .await
                    .map(|b| b.to_bytes())
                    .unwrap_or_default();
                let body = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                calls.lock().expect("lock").push((method.clone(), path.clone(), body));
                let out = match (method.as_str(), path.as_str()) {
                    ("POST", "/gbrain/clients/request") => {
                        json!({"ok": true, "request": {"name": "Claude", "site": "claude.ai", "approved": false}})
                    }
                    ("GET", "/gbrain/clients") => {
                        json!({"ok": true, "clients": on_brain.lock().expect("lock").clone()})
                    }
                    ("GET", "/gbrain/connections") => {
                        json!({"ok": true, "connections": [], "lock": {"all": false, "vmIds": []}})
                    }
                    _ => json!({"ok": true}),
                };
                cc_http::json(200, &out)
            }
        },
    );
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    format!("http://{addr}")
}

struct Rig {
    _dir: tempfile::TempDir,
    brain: Brain,
    codes: Arc<Codes>,
    calls: Calls,
    on_brain: Arc<Mutex<Value>>,
}

/// Code routes that can be taken away mid-test.
struct Switch(Arc<AtomicBool>);

impl CodeRouteSource for Switch {
    fn routes(&self) -> Vec<CodeRoute> {
        if self.0.load(Ordering::SeqCst) {
            People.routes()
        } else {
            vec![]
        }
    }
    fn ready(&self) -> bool {
        true
    }
    fn agent_allowed_count(&self) -> Option<u32> {
        Some(0)
    }
}

async fn rig() -> Rig {
    rig_with(Arc::new(People)).await
}

async fn rig_with(routes: Arc<dyn CodeRouteSource>) -> Rig {
    let dir = tempfile::tempdir().expect("dir");
    let calls: Calls = Arc::default();
    let on_brain = Arc::new(Mutex::new(json!([])));
    let base = brain_box(calls.clone(), on_brain.clone()).await;
    let rows = vec![
        json!({"vm_id": "br_1", "role": "gbrain", "private_ip": "10.0.0.9", "hostname": "brain-x.ccl.bot", "name": "brain-x"}),
        json!({"vm_id": "ag_1", "role": "openclaw", "private_ip": "10.0.0.3", "hostname": "ag-1.example", "name": "atlas"}),
    ];
    let agents = Arc::new(Agents::default());
    agents.set(&rows);
    let keys = dir.path().join("keys");
    cc_auth::keys::ensure_vm_keypair(&keys);
    let agent = AgentClient::for_tests(
        cc_auth::keys::KeysDir::new(&keys),
        agents,
        Arc::new(move |_| Some(base.clone())),
    );
    let codes = Arc::new(Codes::default());
    let kit = Kit {
        consent: codes.clone(),
        routes: Arc::new(move || Some(routes.clone())),
    };
    let brain = Brain::new(
        dir.path().join("gbrain.enc"),
        KEY,
        "org-1",
        "fw-1",
        agent,
        kit,
        Arc::new(move || rows.clone()),
        Arc::new(|| (false, vec![])),
    );
    Rig {
        _dir: dir,
        brain,
        codes,
        calls,
        on_brain,
    }
}

fn p(v: Value) -> Map<String, Value> {
    v.as_object().cloned().expect("object")
}

fn status(o: &CommandOutcome) -> Value {
    serde_json::to_value(o).expect("json")
}

fn posts(r: &Rig, path: &str) -> Vec<Value> {
    r.calls
        .lock()
        .expect("lock")
        .iter()
        .filter(|(m, p, _)| m == "POST" && p == path)
        .map(|(_, _, b)| b.clone())
        .collect()
}

#[tokio::test]
async fn a_sign_in_takes_a_code_and_the_name_is_the_brains() {
    let r = rig().await;
    let out = r
        .brain
        .client_propose(p(json!({
            "changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "req": "req-1", "approval": APPROVAL,
            "scope": "read_write", "expiresAt": null, "person": "Marco", "name": "Not what the brain says",
        })))
        .await;
    let s = status(&out);
    assert_eq!(s["status"], "awaiting_code", "{s}");
    assert!(posts(&r, "/gbrain/clients/connect").is_empty());
    {
        let asks = r.codes.asks.lock().expect("lock");
        let ask = asks.last().expect("ask");
        assert_eq!(ask.scope, "gbrain-client:c1");
        assert!(ask.summary.contains("Claude"), "{}", ask.summary);
        assert!(!ask.summary.contains("Not what"));
        let parts = ask.parts.as_ref().expect("parts");
        assert!(parts.ask.contains("read and write, no end date"), "{}", parts.ask);
        // The app's name is a typed line, apart from the firewall's words.
        assert!(!parts.ask.contains("Claude"));
        assert_eq!(parts.typed[0].text, "Claude");
        // What the app and the console say of themselves is labelled as their claim.
        assert_eq!(parts.typed[0].label, "Calls itself");
        assert_eq!(parts.typed[2].label, "Asked for in the console by");
        assert_eq!(parts.typed[1].text, "claude.ai");
        assert_eq!(parts.typed[2].text, "Marco");
    }
    // A wrong code changes nothing.
    let wrong = r
        .brain
        .client_confirm(p(json!({"changeId": "ch1", "clientId": "c1", "code": "000000"})))
        .await;
    assert_eq!(status(&wrong)["status"], "invalid_code");
    let done = r
        .brain
        .client_confirm(p(json!({"changeId": "ch1", "clientId": "c1", "code": "123456"})))
        .await;
    assert_eq!(status(&done)["status"], "applied", "{}", status(&done));
    assert_eq!(
        posts(&r, "/gbrain/clients/connect"),
        vec![json!({"id": "c1", "req": "req-1", "approval": APPROVAL, "scope": "read_write", "expiresAt": null})]
    );
    assert_eq!(r.brain.summary()["clients"], 1);

    // Read only, with an end date: narrower, so no code.
    let n = r
        .brain
        .client_propose(p(json!({"changeId": "ch2", "clientId": "c1", "brainVmId": "br_1", "scope": "read", "expiresAt": "2026-12-31T00:00:00.000Z"})))
        .await;
    assert_eq!(status(&n)["status"], "applied", "{}", status(&n));
    assert_eq!(r.codes.asks.lock().expect("lock").len(), 1);
    assert_eq!(
        posts(&r, "/gbrain/clients/connect").last().cloned(),
        Some(
            json!({"id": "c1", "req": null, "approval": null, "scope": "read", "expiresAt": "2026-12-31T00:00:00.000Z"})
        )
    );
    // A later end date, or none, is wider: a code again.
    let w = r
        .brain
        .client_propose(p(
            json!({"changeId": "ch3", "clientId": "c1", "brainVmId": "br_1", "scope": "read", "expiresAt": null}),
        ))
        .await;
    assert_eq!(status(&w)["status"], "awaiting_code");
    let w = r
        .brain
        .client_propose(p(json!({"changeId": "ch4", "clientId": "c1", "brainVmId": "br_1", "scope": "read_write", "expiresAt": "2026-12-01T00:00:00.000Z"})))
        .await;
    assert_eq!(status(&w)["status"], "awaiting_code");
    // Even an existing client's new sign-in takes a code: it hands the brain to a new holder.
    let again = r
        .brain
        .client_propose(p(json!({"changeId": "ch5", "clientId": "c1", "brainVmId": "br_1", "req": "req-2", "approval": APPROVAL, "scope": "read", "expiresAt": "2026-12-01T00:00:00.000Z"})))
        .await;
    assert_eq!(status(&again)["status"], "awaiting_code");

    // Removing needs none.
    let gone = r.brain.client_disconnect(p(json!({"clientId": "c1"}))).await;
    assert_eq!(status(&gone)["status"], "applied");
    assert_eq!(posts(&r, "/gbrain/clients/disconnect"), vec![json!({"id": "c1"})]);
    assert_eq!(r.brain.summary()["clients"], 0);
}

#[tokio::test]
async fn an_unknown_app_cannot_be_changed_and_bad_input_is_refused() {
    let r = rig().await;
    let out = r
        .brain
        .client_propose(p(
            json!({"changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "scope": "read"}),
        ))
        .await;
    assert_eq!(status(&out)["status"], "failed");
    let out = r
        .brain
        .client_propose(p(
            json!({"changeId": "ch1", "clientId": "../x", "brainVmId": "br_1", "scope": "read", "req": "r"}),
        ))
        .await;
    assert_eq!(status(&out)["status"], "failed");
    let out = r
        .brain
        .client_propose(p(json!({"changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "scope": "read", "req": "r", "approval": APPROVAL, "expiresAt": "soon"})))
        .await;
    assert_eq!(status(&out)["status"], "failed");
    // A sign-in without the approval secret's hash is not even asked about.
    let out = r
        .brain
        .client_propose(p(
            json!({"changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "scope": "read", "req": "r"}),
        ))
        .await;
    assert_eq!(status(&out)["status"], "failed");
    assert!(r.codes.asks.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn with_nowhere_to_send_a_code_no_app_gets_in() {
    let r = rig_with(Arc::new(Nobody)).await;
    let out = r
        .brain
        .client_propose(p(json!({"changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "req": "req-1", "approval": APPROVAL, "scope": "read"})))
        .await;
    let s = status(&out);
    assert_eq!(s["status"], "failed", "{s}");
    assert!(posts(&r, "/gbrain/clients/connect").is_empty());
    assert_eq!(r.brain.summary()["clients"], 0);
}

#[tokio::test]
async fn with_nowhere_to_send_a_code_no_app_is_widened_but_narrowing_still_works() {
    let on = Arc::new(AtomicBool::new(true));
    let r = rig_with(Arc::new(Switch(on.clone()))).await;
    r.brain
        .client_propose(p(json!({"changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "req": "req-1", "approval": APPROVAL, "scope": "read", "expiresAt": "2026-12-31T00:00:00.000Z"})))
        .await;
    let done = r
        .brain
        .client_confirm(p(json!({"changeId": "ch1", "clientId": "c1", "code": "123456"})))
        .await;
    assert_eq!(status(&done)["status"], "applied");
    on.store(false, Ordering::SeqCst);
    let before = posts(&r, "/gbrain/clients/connect").len();
    // Read and write, a later end date, no end date: each refused, nothing sent to the brain.
    for (scope, until) in [
        ("read_write", json!("2026-12-31T00:00:00.000Z")),
        ("read", json!("2027-06-30T00:00:00.000Z")),
        ("read", Value::Null),
    ] {
        let out = r
            .brain
            .client_propose(p(
                json!({"changeId": "chw", "clientId": "c1", "brainVmId": "br_1", "scope": scope, "expiresAt": until}),
            ))
            .await;
        assert_eq!(status(&out)["status"], "failed", "{scope} {until}");
    }
    assert_eq!(posts(&r, "/gbrain/clients/connect").len(), before);
    // An earlier end date still applies at once.
    let n = r
        .brain
        .client_propose(p(json!({"changeId": "chn", "clientId": "c1", "brainVmId": "br_1", "scope": "read", "expiresAt": "2026-12-01T00:00:00.000Z"})))
        .await;
    assert_eq!(status(&n)["status"], "applied");
    assert_eq!(posts(&r, "/gbrain/clients/connect").len(), before + 1);
}

#[tokio::test]
async fn reconcile_removes_unknown_apps_and_narrows_wider_ones() {
    let r = rig().await;
    r.brain
        .client_propose(p(json!({"changeId": "ch1", "clientId": "c1", "brainVmId": "br_1", "req": "req-1", "approval": APPROVAL, "scope": "read", "expiresAt": "2026-12-31T00:00:00.000Z"})))
        .await;
    r.brain
        .client_confirm(p(json!({"changeId": "ch1", "clientId": "c1", "code": "123456"})))
        .await;
    *r.on_brain.lock().expect("lock") = json!([
        {"id": "c1", "name": "Claude", "scope": "read_write", "expiresAt": null},
        {"id": "c9", "name": "Made elsewhere", "scope": "read", "expiresAt": null},
    ]);
    r.brain.reconcile().await.expect("reconcile");
    assert_eq!(posts(&r, "/gbrain/clients/disconnect"), vec![json!({"id": "c9"})]);
    assert_eq!(
        posts(&r, "/gbrain/clients/connect").last().cloned(),
        Some(json!({"id": "c1", "scope": "read", "expiresAt": "2026-12-31T00:00:00.000Z"}))
    );
    // Already as narrow as the store: nothing is sent.
    *r.on_brain.lock().expect("lock") = json!([{"id": "c1", "scope": "read", "expiresAt": "2026-12-01T00:00:00.000Z"}]);
    let before = r.calls.lock().expect("lock").len();
    r.brain.reconcile().await.expect("reconcile");
    assert!(
        r.calls.lock().expect("lock")[before..]
            .iter()
            .all(|(m, _, _)| m == "GET")
    );
}

// ---- a standalone firewall (docs/plans/standalone-brain.md B) ----

type StopState = Arc<Mutex<(bool, Vec<String>)>>;

struct Standalone {
    _dir: tempfile::TempDir,
    brain: Brain,
    calls: Calls,
    stop: StopState,
}

/// Boxes paired with this firewall: no hostnames, called at their paired address.
async fn standalone(gate: Option<&str>) -> Standalone {
    standalone_with(gate, Arc::new(Nobody)).await
}

async fn standalone_with(gate: Option<&str>, codes_to: Arc<dyn CodeRouteSource>) -> Standalone {
    let dir = tempfile::tempdir().expect("dir");
    let calls: Calls = Arc::default();
    let base = brain_box(calls.clone(), Arc::new(Mutex::new(json!([])))).await;
    let rows = vec![
        json!({"vm_id": "br_1", "role": "gbrain", "private_ip": "10.77.0.9", "agent_addr": "10.77.0.9:3100", "name": "brain"}),
        json!({"vm_id": "ag_1", "role": "openclaw", "private_ip": "172.31.251.10", "agent_addr": "172.31.252.1:3102", "name": "atlas"}),
        json!({"vm_id": "ag_2", "role": "openclaw", "private_ip": "10.77.0.2", "agent_addr": "10.77.0.2:3100", "name": "nova"}),
    ];
    let agents = Arc::new(Agents::default());
    agents.set(&rows);
    agents.set_direct(true);
    let keys = dir.path().join("keys");
    cc_auth::keys::ensure_vm_keypair(&keys);
    let agent = AgentClient::for_tests(
        cc_auth::keys::KeysDir::new(&keys),
        agents,
        Arc::new(move |_| Some(base.clone())),
    );
    let stop: StopState = Arc::default();
    let s = stop.clone();
    let brain = Brain::new(
        dir.path().join("gbrain.enc"),
        KEY,
        "local",
        "firewall",
        agent,
        Kit {
            consent: Arc::new(Codes::default()),
            routes: Arc::new(move || Some(codes_to.clone())),
        },
        Arc::new(move || rows.clone()),
        Arc::new(move || s.lock().expect("stop").clone()),
    )
    .standalone(gate.map(str::to_string));
    Standalone {
        _dir: dir,
        brain,
        calls,
        stop,
    }
}

fn calls_to(calls: &Calls, path: &str) -> Vec<Value> {
    calls
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, p, _)| p == path)
        .map(|(_, _, b)| b.clone())
        .collect()
}

#[tokio::test]
async fn standalone_agents_get_the_firewalls_gate_and_are_let_in_by_it() {
    let r = standalone(Some("172.31.251.2")).await;
    assert_eq!(r.brain.relay_for("ag_1"), Err("not connected"));
    let out = r
        .brain
        .propose(p(
            json!({"changeId": "c1", "agentVmId": "ag_1", "brainVmId": "br_1", "scope": "read_write"}),
        ))
        .await;
    assert_eq!(status(&out)["status"], "applied", "{}", status(&out));
    // The brain records the agent's address only; the agent's entry is this firewall's gate.
    assert_eq!(
        calls_to(&r.calls, "/gbrain/connect"),
        vec![json!({"vmId": "ag_1", "ip": "172.31.251.10", "scope": "read_write"})]
    );
    assert_eq!(
        calls_to(&r.calls, "/gbrain/apply"),
        vec![json!({"url": "http://172.31.251.2:3940/brain/mcp"})]
    );
    assert_eq!(r.brain.relay_for("ag_1"), Ok("br_1".into()));
    assert_eq!(r.brain.relay_for("ag_2"), Err("not connected"));

    // The emergency stop for one agent, then for everyone.
    r.stop.lock().expect("stop").1 = vec!["ag_1".into()];
    assert_eq!(r.brain.relay_for("ag_1"), Err("locked"));
    *r.stop.lock().expect("stop") = (true, vec![]);
    assert_eq!(r.brain.relay_for("ag_1"), Err("locked"));
    *r.stop.lock().expect("stop") = (false, vec![]);

    // The admin's lock: everyone off, the connection kept, and the brain told.
    let out = r.brain.set_admin_lock(p(json!({"locked": true}))).await;
    assert_eq!(status(&out)["status"], "applied");
    assert!(r.brain.admin_locked());
    assert_eq!(r.brain.relay_for("ag_1"), Err("locked"));
    assert_eq!(
        calls_to(&r.calls, "/gbrain/lock").last(),
        Some(&json!({"all": true, "vmIds": []}))
    );
    let read = status(&r.brain.read().await);
    assert_eq!(read["data"]["locked"], true);
    assert_eq!(read["data"]["connections"]["ag_1"]["scope"], "read_write");
    assert_eq!(read["data"]["gateUrl"], "http://172.31.251.2:3940/brain/mcp");
    r.brain.set_admin_lock(p(json!({"locked": false}))).await;
    assert_eq!(r.brain.relay_for("ag_1"), Ok("br_1".into()));
    assert_eq!(
        calls_to(&r.calls, "/gbrain/lock").last(),
        Some(&json!({"all": false, "vmIds": []}))
    );

    // Off again: out of the brain, and the entry written away on the agent.
    let out = r.brain.disconnect(p(json!({"agentVmId": "ag_1"}))).await;
    assert_eq!(status(&out)["data"]["pending"], false, "{}", status(&out));
    assert_eq!(calls_to(&r.calls, "/gbrain/disconnect"), vec![json!({"vmId": "ag_1"})]);
    assert_eq!(
        calls_to(&r.calls, "/gbrain/apply").last(),
        Some(&json!({"remove": true}))
    );
    assert_eq!(r.brain.relay_for("ag_1"), Err("not connected"));
}

#[tokio::test]
async fn standalone_without_the_tools_gate_connects_nobody() {
    let r = standalone(None).await;
    let out = r
        .brain
        .propose(p(
            json!({"changeId": "c1", "agentVmId": "ag_1", "brainVmId": "br_1", "scope": "read"}),
        ))
        .await;
    let s = status(&out);
    assert_eq!(s["ok"], false, "{s}");
    assert!(
        s["message"]
            .as_str()
            .unwrap_or_default()
            .contains("CONNECTOR_GATE_BIND"),
        "{s}"
    );
    assert!(calls_to(&r.calls, "/gbrain/connect").is_empty());
    assert!(calls_to(&r.calls, "/gbrain/apply").is_empty());
}

#[tokio::test]
async fn the_admin_lock_survives_a_restart() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gbrain.enc");
    let make = || {
        let keys = dir.path().join("keys");
        cc_auth::keys::ensure_vm_keypair(&keys);
        let agent = AgentClient::for_tests(
            cc_auth::keys::KeysDir::new(&keys),
            Arc::new(Agents::default()),
            Arc::new(|_| None),
        );
        Brain::new(
            path.clone(),
            KEY,
            "local",
            "firewall",
            agent,
            Kit {
                consent: Arc::new(Codes::default()),
                routes: Arc::new(|| Some(Arc::new(Nobody) as Arc<dyn CodeRouteSource>)),
            },
            Arc::new(Vec::new),
            Arc::new(|| (false, vec![])),
        )
        .standalone(Some("10.0.0.2".into()))
    };
    make().set_admin_lock(p(json!({"locked": true}))).await;
    assert!(make().admin_locked());
}

/// The panel's admin scope has someone to send the code to (the admin, who gets it back at once):
/// the change is proposed, then confirmed, with boxes that have no hostname.
#[tokio::test]
async fn a_standalone_connection_confirmed_with_its_code() {
    let r = standalone_with(Some("10.88.1.1"), Arc::new(People)).await;
    let out = r
        .brain
        .propose(p(
            json!({"changeId": "c1", "agentVmId": "ag_1", "brainVmId": "br_1", "scope": "read"}),
        ))
        .await;
    assert_eq!(status(&out)["status"], "awaiting_code", "{}", status(&out));
    let out = r
        .brain
        .confirm(p(json!({"changeId": "c1", "agentVmId": "ag_1", "code": "123456"})))
        .await;
    assert_eq!(status(&out)["status"], "applied", "{}", status(&out));
    assert_eq!(
        calls_to(&r.calls, "/gbrain/apply"),
        vec![json!({"url": "http://10.88.1.1:3940/brain/mcp"})]
    );
    assert_eq!(r.brain.relay_for("ag_1"), Ok("br_1".into()));
}
