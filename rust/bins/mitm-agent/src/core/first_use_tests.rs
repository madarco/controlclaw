//! First use for this firewall's own updates: with nobody set to get codes, an update of this box, a
//! batch that includes it and the nightly grant all apply at once (`tofu: true`); once somebody is
//! set, each asks for a code again, and a nightly grant written on first use stays.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::agent_client::AgentClient;
use super::auto_update::{AutoUpdate, AutoUpdateStore};
use super::firewall_update::FirewallUpdate;
use super::identities::Agents;
use super::kit::Kit;
use super::self_update::SelfUpdate;
use super::update::Updates;
use super::update_all::{GrantStore, UpdateAll};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRoute, CodeRouteSource, CodeSender, CodeSent, ModuleCodes};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// The people set to get codes: none until `add` is called.
#[derive(Default)]
struct People(AtomicBool);

impl CodeRouteSource for People {
    fn routes(&self) -> Vec<CodeRoute> {
        if !self.0.load(Ordering::SeqCst) {
            return vec![];
        }
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

/// Records every code asked for and every scope dropped.
#[derive(Default)]
struct Codes {
    asks: Mutex<Vec<String>>,
    forgot: Mutex<Vec<String>>,
}

impl ModuleCodes for Codes {
    fn send(&self, req: CodeAsk) -> BoxFuture<CodeSent> {
        self.asks.lock().expect("lock").push(req.scope);
        Box::pin(async {
            CodeSent::Sent {
                sent_via: "telegram:Marco".into(),
                expires_at: "2026-11-09T10:10:00.000Z".into(),
                attempts_left: 5,
                recovery: None,
            }
        })
    }
    fn verify(&self, _: &str, _: &str, _: &str) -> CodeCheck {
        CodeCheck::Expired
    }
    fn cancel(&self, _: &str, _: Option<&str>) -> bool {
        false
    }
    fn forget(&self, scope: &str) {
        self.forgot.lock().expect("lock").push(scope.into());
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    people: Arc<People>,
    codes: Arc<Codes>,
    runner: Arc<cc_proc::RecordingRunner>,
    fw: Arc<FirewallUpdate>,
    au: Arc<AutoUpdate>,
    ua: UpdateAll,
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let conf = dir.path().join("update.conf");
        std::fs::write(&conf, "ANSIBLE_REPO=https://x/y\nANSIBLE_REF=main\n").expect("conf");
        let runner = Arc::new(cc_proc::RecordingRunner::new());
        runner.answer(&["sudo"], cc_proc::ok(""));
        let people = Arc::new(People::default());
        let codes = Arc::new(Codes::default());
        let kit = {
            let people = people.clone();
            Kit {
                consent: codes.clone(),
                routes: Arc::new(move || Some(people.clone() as Arc<dyn CodeRouteSource>)),
            }
        };
        let fw = Arc::new(FirewallUpdate::new(
            Arc::new(SelfUpdate::new(dir.path().join("update.json"), conf, runner.clone())),
            kit.clone(),
        ));
        let au = Arc::new(AutoUpdate::new(
            kit.clone(),
            Arc::new(AutoUpdateStore::new(dir.path().join("auto-update.enc"), KEY, "o", "b")),
            Arc::new(|| {}),
        ));
        let keys = dir.path().join("keys");
        cc_auth::keys::ensure_vm_keypair(&keys);
        let agents = Arc::new(Agents::default());
        let agent = AgentClient::for_tests(cc_auth::keys::KeysDir::new(&keys), agents.clone(), Arc::new(|_| None));
        let updates = Arc::new(Updates::new(agent, kit.clone(), agents.clone(), Arc::new(no_windows)));
        let a = au.clone();
        let ua = UpdateAll::new(
            kit,
            agents,
            updates,
            fw.clone(),
            Arc::new(GrantStore::new(dir.path().join("update-all.enc"), KEY, "o", "b")),
            Arc::new(move || a.confirmed_at()),
        );
        Self {
            _dir: dir,
            people,
            codes,
            runner,
            fw,
            au,
            ua,
        }
    }

    /// The launch runs on its own task: waits for the first one (up to 5 s), then a little longer,
    /// so a second launch that should not happen has its chance to show.
    async fn launches(&self) -> usize {
        let count = || self.runner.calls().iter().filter(|c| c.program == "sudo").count();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while count() == 0 && std::time::Instant::now() < until {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        count()
    }
}

fn no_windows() -> BoxFuture<Result<(), String>> {
    Box::pin(async { Ok(()) })
}

fn payload(v: Value) -> Map<String, Value> {
    v.as_object().expect("object").clone()
}

fn data(o: &CommandOutcome) -> &Map<String, Value> {
    o.data.as_ref().expect("data")
}

fn batch(change_id: &str) -> Map<String, Value> {
    payload(json!({
        "changeId": change_id,
        "boxes": [
            {"vmId": "fw_1", "role": "mitm", "name": "your firewall"},
            {"vmId": "ag_1", "hostname": "ag-1.example", "name": "Ada"},
        ],
    }))
}

#[tokio::test]
async fn firewall_update_applies_on_first_use_then_asks_for_a_code() {
    let r = Rig::new();
    let first = r.fw.propose(payload(json!({"changeId": "c1"}))).await;
    assert!(first.ok, "{:?}", first.message);
    assert_eq!(first.status, "applied");
    assert_eq!(data(&first)["tofu"], json!(true));
    assert_eq!(data(&first)["phase"], json!("resolving"));
    assert_eq!(r.launches().await, 1);
    assert_eq!(
        *r.codes.forgot.lock().expect("lock"),
        vec!["firewall-update:self".to_string()]
    );
    assert!(r.codes.asks.lock().expect("lock").is_empty());

    r.people.0.store(true, Ordering::SeqCst);
    let second = r.fw.propose(payload(json!({"changeId": "c2"}))).await;
    assert_eq!(second.status, "awaiting_code");
    assert_eq!(
        *r.codes.asks.lock().expect("lock"),
        vec!["firewall-update:self".to_string()]
    );
    assert_eq!(r.launches().await, 1, "nothing starts before the code");
}

#[tokio::test]
async fn a_batch_with_the_firewall_applies_on_first_use_then_asks_for_a_code() {
    let r = Rig::new();
    let first = r.ua.propose(batch("b1")).await;
    assert!(first.ok, "{:?}", first.message);
    assert_eq!(first.status, "applied");
    assert_eq!(data(&first)["tofu"], json!(true));
    assert_eq!(data(&first)["boxes"], json!(["fw_1", "ag_1"]));
    assert!(
        r.codes
            .forgot
            .lock()
            .expect("lock")
            .contains(&"update-all:org".to_string())
    );
    // The grant covers the firewall: its slot starts this box's run.
    let fw =
        r.ua.apply_one(payload(json!({"changeId": "b1", "vmId": "fw_1", "role": "mitm"})))
            .await;
    assert!(fw.ok, "{:?}", fw.message);
    assert_eq!(r.launches().await, 1);

    r.people.0.store(true, Ordering::SeqCst);
    let second = r.ua.propose(batch("b2")).await;
    assert_eq!(second.status, "awaiting_code");
    assert_eq!(*r.codes.asks.lock().expect("lock"), vec!["update-all:org".to_string()]);
    // The first-use grant was for b1 only.
    let refused =
        r.ua.apply_one(payload(json!({"changeId": "b2", "vmId": "fw_1", "role": "mitm"})))
            .await;
    assert!(!refused.ok);
    assert_eq!(r.launches().await, 1);
}

#[tokio::test]
async fn the_nightly_grant_is_written_on_first_use_and_kept_when_somebody_is_added() {
    let r = Rig::new();
    assert_eq!(r.au.confirmed_at(), None);
    let first = r.au.propose(payload(json!({"changeId": "a1"}))).await;
    assert!(first.ok, "{:?}", first.message);
    assert_eq!(first.status, "applied");
    assert_eq!(data(&first)["tofu"], json!(true));
    let at = r.au.confirmed_at().expect("granted");
    assert_eq!(data(&first)["confirmedAt"], json!(at));
    assert_eq!(
        *r.codes.forgot.lock().expect("lock"),
        vec!["auto-update:org".to_string()]
    );

    // The nightly batch runs under it, the firewall included.
    let window_end = super::consent::iso(super::now_ms() + 60 * 60_000);
    let mut nightly = batch("n1");
    nightly.insert("windowEndsAt".into(), json!(window_end));
    let auto = r.ua.automatic(nightly);
    assert!(auto.ok, "{:?}", auto.message);

    // Somebody is added: the grant stays, and turning it on again asks for a code.
    r.people.0.store(true, Ordering::SeqCst);
    assert_eq!(r.au.confirmed_at(), Some(at));
    let again = r.au.propose(payload(json!({"changeId": "a2"}))).await;
    assert_eq!(again.status, "awaiting_code");
    assert_eq!(*r.codes.asks.lock().expect("lock"), vec!["auto-update:org".to_string()]);

    // Off needs no code, and ends it.
    assert!(r.au.disable().ok);
    assert_eq!(r.au.confirmed_at(), None);
}
