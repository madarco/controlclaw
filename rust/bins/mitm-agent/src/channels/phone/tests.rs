//! `phone.test.ts`: the firewall side of the phone against a fake Twilio (one number whose routing
//! the POSTs change), a fake agent box and fake codes.

#![allow(clippy::unwrap_used, clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::api::{PhoneError, TwilioCalls};
use super::firewall::*;
use super::policy::{SpeechPolicy, phone_limits};
use crate::channels::agent::{AgentCalls, AgentError, Target};
use crate::channels::llm::SpeechCredential;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeRequest, ConsentCodes, SendResult, Verify};

const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn sid() -> String {
    format!("AC{}", "a".repeat(32))
}
fn pn() -> String {
    format!("PN{}", "b".repeat(32))
}
fn token() -> String {
    "c".repeat(32)
}

struct Twilio {
    routing: Mutex<Map<String, Value>>,
    hold: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    route_down: AtomicBool,
    /// The token was revoked at Twilio: every call is a 401.
    revoked: AtomicBool,
}

impl TwilioCalls for Arc<Twilio> {
    fn send(
        &self,
        _: &str,
        _: &str,
        path: &str,
        fields: Option<Vec<(String, String)>>,
    ) -> BoxFuture<Result<Map<String, Value>, PhoneError>> {
        let me = self.clone();
        let path = path.to_string();
        Box::pin(async move {
            if me.revoked.load(Ordering::SeqCst) {
                return Err(PhoneError("invalid_credentials"));
            }
            if path.ends_with(&format!("{}.json", sid())) {
                return Ok(json!({"sid": sid(), "status": "active", "type": "Full"})
                    .as_object()
                    .cloned()
                    .unwrap());
            }
            if path.contains("IncomingPhoneNumbers.json") {
                let r = me.routing.lock().unwrap().clone();
                return Ok(json!({"incoming_phone_numbers": [r], "next_page_uri": null})
                    .as_object()
                    .cloned()
                    .unwrap());
            }
            let hold = me.hold.lock().unwrap().take();
            if let Some(h) = hold {
                let _ = h.await;
            }
            if let Some(f) = fields {
                if me.route_down.load(Ordering::SeqCst) {
                    return Err(PhoneError("request_uncertain"));
                }
                let mut r = me.routing.lock().unwrap();
                for (k, v) in f {
                    // VoiceUrl -> voice_url
                    let mut key = String::new();
                    for (i, c) in k.chars().enumerate() {
                        if c.is_ascii_uppercase() {
                            if i > 0 {
                                key.push('_');
                            }
                            key.push(c.to_ascii_lowercase());
                        } else {
                            key.push(c);
                        }
                    }
                    r.insert(key, json!(v));
                }
            }
            Ok(me.routing.lock().unwrap().clone())
        })
    }
}

#[derive(Default)]
struct Box_ {
    pushes: Mutex<Vec<Value>>,
    /// What `/phone/status` answers; `None`: the last push, active.
    status: Mutex<Option<Value>>,
    post_error: Mutex<Option<String>>,
}

impl AgentCalls for Arc<Box_> {
    fn post(
        &self,
        _: &Target,
        path: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        let r = match self.post_error.lock().unwrap().clone() {
            Some(e) => Err(AgentError::new(e)),
            None => {
                if path == "/phone/apply" {
                    self.pushes.lock().unwrap().push(body);
                }
                Ok(Map::new())
            }
        };
        Box::pin(async move { r })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        let answer = self.status.lock().unwrap().clone().unwrap_or_else(|| {
            let last = self.pushes.lock().unwrap().last().cloned();
            json!({"apply": last.map(|p| json!({"generation": p["generation"], "status": "active"}))})
        });
        Box::pin(async move { Ok(answer.as_object().cloned().unwrap()) })
    }
}

/// Codes as the consent module keeps them; a send fails with the agent's own error when it is down.
struct Codes {
    pending: Mutex<HashMap<String, (String, Value)>>,
    agent: Arc<Box_>,
}

impl ConsentCodes for Codes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        let err = self.agent.post_error.lock().unwrap().clone();
        if err.is_none() {
            self.pending
                .lock()
                .unwrap()
                .insert(req.scope, (req.change_id, req.proposal));
        }
        Box::pin(async move {
            SendResult {
                sent_via: err.is_none().then(|| "telegram:Owner".into()),
                error: err,
                delivery_failed: false,
                expires_at_ms: 0,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut p = self.pending.lock().unwrap();
        match p.get(scope) {
            Some((c, _)) if c == change_id && code == "123456" => Verify::Ok(p.remove(scope).unwrap().1),
            Some((c, _)) if c == change_id => Verify::Wrong { tries_left: 4 },
            _ => Verify::Expired,
        }
    }
    fn cancel(&self, scope: &str, id: Option<&str>) -> bool {
        let mut p = self.pending.lock().unwrap();
        if p.get(scope).is_some_and(|(c, _)| Some(c.as_str()) == id) {
            p.remove(scope);
            return true;
        }
        false
    }
    fn forget(&self, scope: &str) {
        self.pending.lock().unwrap().remove(scope);
    }
}

struct F {
    dir: tempfile::TempDir,
    twilio: Arc<Twilio>,
    agent: Arc<Box_>,
    codes: Arc<Codes>,
    coded: bool,
    ready: Arc<AtomicBool>,
    speech: bool,
}

fn fixture(coded: bool, speech: bool) -> F {
    let routing = json!({
        "account_sid": sid(), "sid": pn(), "phone_number": "+14155550123", "capabilities": {"voice": true},
        "voice_url": "https://old.example/voice", "voice_method": "POST", "status_callback": "",
        "status_callback_method": "POST", "voice_application_sid": "", "trunk_sid": "", "voice_fallback_url": "",
    });
    let agent = Arc::new(Box_::default());
    F {
        dir: tempfile::tempdir().unwrap(),
        twilio: Arc::new(Twilio {
            routing: Mutex::new(routing.as_object().cloned().unwrap()),
            hold: Mutex::new(None),
            route_down: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
        }),
        codes: Arc::new(Codes {
            pending: Mutex::default(),
            agent: agent.clone(),
        }),
        agent,
        coded,
        ready: Arc::new(AtomicBool::new(true)),
        speech,
    }
}

impl F {
    fn make(&self) -> Arc<PhoneFirewall> {
        let (codes, coded, ready, speech) = (self.codes.clone(), self.coded, self.ready.clone(), self.speech);
        PhoneFirewall::new(PhoneOptions {
            store_path: self.dir.path().join("phone.enc"),
            box_key: KEY.into(),
            org_id: "org".into(),
            box_id: "box".into(),
            public_origin: "https://firewall.example".into(),
            valid_target: Arc::new(|vm, host| vm == "agent-a" && host == "agent.example"),
            agent: Arc::new(self.agent.clone()),
            codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
            code_routes: Arc::new(move || {
                ready.load(Ordering::SeqCst).then(|| {
                    if coded {
                        vec![json!({"target": {"vmId": "agent-a", "hostname": "agent.example"}, "senders": [{"type": "telegram", "id": "123", "label": "Owner"}]})]
                    } else {
                        vec![]
                    }
                })
            }),
            on_credentials_changed: Arc::new(|| Box::pin(async {})),
            speech_credential: Arc::new(move |_: &SpeechPolicy| {
                speech.then(|| SpeechCredential {
                    secret: "speech-secret".into(),
                    host: "ai-gateway.vercel.sh".into(),
                    account_id: None,
                })
            }),
            locked: Arc::new(|_| false),
            api: Arc::new(self.twilio.clone()),
        })
        .unwrap()
    }
    fn routing(&self, k: &str) -> Value {
        self.twilio
            .routing
            .lock()
            .unwrap()
            .get(k)
            .cloned()
            .unwrap_or(Value::Null)
    }
    fn last_push(&self) -> Value {
        self.agent.pushes.lock().unwrap().last().cloned().unwrap()
    }
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn connect(id: &str) -> Map<String, Value> {
    m(json!({"changeId": id, "kind": "connect", "accountSid": sid(), "authToken": token()}))
}

fn assign(over: Value) -> Map<String, Value> {
    let mut a = m(
        json!({"changeId": "assign", "kind": "assign", "numberSid": pn(), "vmId": "agent-a", "hostname": "agent.example", "name": "A", "allowFrom": ["+14155550999"], "allowAll": false}),
    );
    a.extend(m(over));
    a
}

async fn call(fw: &PhoneFirewall, action: &str, p: Value) -> CommandOutcome {
    fw.command(action, m(p)).await
}

fn summary_assignment(fw: &PhoneFirewall) -> Value {
    fw.summary()["assignment"].clone()
}

#[tokio::test]
async fn retry_pushes_failed_setup_again_and_forwards_only_known_error_codes() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    for error in ["runtime_unsupported".to_string(), format!("private-token {}", sid())] {
        let generation = f.last_push()["generation"].clone();
        *f.agent.status.lock().unwrap() =
            Some(json!({"apply": {"generation": generation, "status": "failed", "error": error}}));
        fw.reconcile().await;
        let a = summary_assignment(&fw);
        assert_eq!(a["status"], "setup_failed");
        assert_eq!(
            a["setupError"],
            if error == "runtime_unsupported" {
                "runtime_unsupported"
            } else {
                "phone_setup_failed"
            }
        );
        assert!(!fw.summary().to_string().contains("private-token"));
        let before = f.agent.pushes.lock().unwrap().len();
        assert!(call(&fw, "push", json!({"vmId": "agent-a"})).await.ok);
        assert_eq!(f.agent.pushes.lock().unwrap().len(), before + 1);
        assert_eq!(summary_assignment(&fw)["status"], "pending");
        assert!(summary_assignment(&fw).get("setupError").is_none());
    }
    *f.agent.status.lock().unwrap() = None;
    fw.reconcile().await;
    assert_eq!(summary_assignment(&fw)["status"], "active");
}

#[tokio::test]
async fn retry_finishes_queued_cleanup_before_applying_again() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    fw.reconcile().await;
    assert_eq!(summary_assignment(&fw)["status"], "active");
    let generation = f.last_push()["generation"].clone();
    *f.agent.status.lock().unwrap() = Some(json!({"apply": {"generation": generation, "status": "failed"}}));
    fw.reconcile().await;
    assert_eq!(fw.summary()["cleanupPending"], true);
    let before = f.agent.pushes.lock().unwrap().len();
    call(&fw, "push", json!({"vmId": "agent-a"})).await;
    let pushes = f.agent.pushes.lock().unwrap().clone();
    assert_eq!(pushes[before]["placeholder"], Value::Null);
    assert!(pushes[before + 1]["placeholder"].is_string());
    assert_eq!(fw.summary()["cleanupPending"], false);
    *f.agent.status.lock().unwrap() = None;
    fw.reconcile().await;
    assert_eq!(summary_assignment(&fw)["status"], "active");
}

#[tokio::test]
async fn one_assignment_active_routing_an_encrypted_token_and_immediate_revocation() {
    let f = fixture(false, true);
    let fw = f.make();
    assert!(fw.command("propose", connect("connect")).await.ok);
    assert!(!fw.summary().to_string().contains(&token()));
    assert!(
        !std::fs::read_to_string(f.dir.path().join("phone.enc"))
            .unwrap()
            .contains(&token())
    );
    assert!(fw.command("propose", assign(json!({}))).await.ok);
    assert!(
        !fw.command("propose", assign(json!({"changeId": "second", "vmId": "agent-b"})))
            .await
            .ok
    );
    fw.reconcile().await;
    assert_eq!(summary_assignment(&fw)["status"], "active");
    assert_eq!(
        f.routing("voice_url"),
        json!("https://firewall.example/hook/".to_string() + &fw.hook().unwrap().1)
    );
    let (generation, _) = fw.hook().unwrap();
    let body = |from: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("AccountSid", sid().as_str()),
                ("CallSid", &format!("CA{}", "d".repeat(32))),
                ("Direction", "inbound"),
                ("From", from),
                ("To", "+14155550123"),
            ])
            .finish()
    };
    assert!(fw.authorize(&generation, body("+14155550999").as_bytes()));
    assert!(!fw.authorize(&generation, body("+14155550888").as_bytes()));
    let unassigned = call(&fw, "unassign", json!({})).await;
    assert!(unassigned.ok);
    assert!(fw.credentials().is_empty());
    assert!(!fw.authorize(&generation, body("+14155550999").as_bytes()));
    assert_eq!(f.routing("voice_url"), json!(""));
    assert_eq!(f.routing("status_callback"), json!(""));
    assert_eq!(fw.summary()["cleanupPending"], false);
}

#[tokio::test]
async fn coded_changes_bind_proposals_cancel_and_restart_invalidate_and_unreadable_is_not_first_use() {
    let f = fixture(true, true);
    let fw = f.make();
    assert_eq!(fw.command("propose", connect("connect")).await.status, "code_sent");
    assert_eq!(fw.summary()["status"], "disconnected");
    assert_eq!(
        call(&fw, "confirm", json!({"changeId": "connect", "code": "000000"}))
            .await
            .status,
        "invalid_code"
    );
    assert!(
        call(&fw, "confirm", json!({"changeId": "connect", "code": "123456"}))
            .await
            .ok
    );
    assert_eq!(fw.command("propose", assign(json!({}))).await.status, "code_sent");
    call(&fw, "unassign", json!({})).await;
    assert!(
        !call(&fw, "confirm", json!({"changeId": "assign", "code": "123456"}))
            .await
            .ok
    );
    assert_eq!(summary_assignment(&fw), Value::Null);
    assert_eq!(
        fw.command("propose", assign(json!({"changeId": "again"}))).await.status,
        "code_sent"
    );
    // A restart loses nothing it should keep, and an assign proposed before it is bound to it.
    let restarted = f.make();
    let r = call(&restarted, "confirm", json!({"changeId": "again", "code": "123456"})).await;
    assert!(r.ok, "an assign holds no secret, so it survives: {:?}", r.message);
    // A connect proposed before a restart does not: its token was only in memory.
    let f2 = fixture(true, true);
    let fw2 = f2.make();
    assert_eq!(fw2.command("propose", connect("c2")).await.status, "code_sent");
    assert!(
        !call(&f2.make(), "confirm", json!({"changeId": "c2", "code": "123456"}))
            .await
            .ok
    );
    f.ready.store(false, Ordering::SeqCst);
    let closed = fw.command("propose", assign(json!({"changeId": "closed"}))).await;
    assert!(!closed.ok);
}

#[tokio::test]
async fn unassign_while_a_lookup_is_in_flight_cannot_bring_the_assignment_back() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    *f.twilio.hold.lock().unwrap() = Some(rx);
    let fw2 = fw.clone();
    let pending = tokio::spawn(async move { fw2.command("propose", assign(json!({}))).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let fw3 = fw.clone();
    let revoke = tokio::spawn(async move { call(&fw3, "unassign", json!({})).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let _ = tx.send(());
    assert!(!pending.await.unwrap().ok);
    revoke.await.unwrap();
    assert_eq!(summary_assignment(&fw), Value::Null);
}

#[tokio::test]
async fn realtime_speech_binds_its_own_credential_and_refuses_what_is_not_there() {
    let speech =
        json!({"provider": "gateway", "credentialId": "included", "model": "openai/gpt-realtime-1.5", "maxMinutes": 5});
    for available in [true, false] {
        let f = fixture(false, available);
        let fw = f.make();
        fw.command("propose", connect("connect")).await;
        assert!(
            !fw.command(
                "propose",
                assign(json!({"changeId": "too-long", "speech": speech, "maxDurationSeconds": 301}))
            )
            .await
            .ok
        );
        let out = fw
            .command("propose", assign(json!({"speech": speech, "maxDurationSeconds": 120})))
            .await;
        assert_eq!(out.ok, available, "{:?}", out.message);
        if available {
            fw.reconcile().await;
            assert_eq!(fw.stream_binding().unwrap()["maxDurationSeconds"], 120);
            let creds = fw.credentials();
            assert_eq!(creds.iter().filter(|c| c.get("phone_speech").is_some()).count(), 1);
            assert_eq!(creds.iter().filter(|c| c.get("phone").is_some()).count(), 1);
            assert!(!fw.summary().to_string().contains("speech-secret"));
            assert_eq!(f.last_push()["speech"]["provider"], "gateway");
            call(&fw, "unassign", json!({})).await;
            assert!(fw.stream_binding().is_none());
            assert!(fw.credentials().is_empty());
        }
    }
}

#[test]
fn limits_are_clamped_and_must_be_numbers() {
    let l = |v: Value| phone_limits(&m(v));
    assert_eq!(
        l(json!({})).unwrap(),
        super::policy::Limits {
            max_duration_seconds: 300,
            max_concurrent_calls: 1
        }
    );
    assert_eq!(
        l(json!({"maxDurationSeconds": 99999, "maxConcurrentCalls": 99})).unwrap(),
        super::policy::Limits {
            max_duration_seconds: 3600,
            max_concurrent_calls: 5
        }
    );
    assert_eq!(
        l(json!({"maxDurationSeconds": -1, "maxConcurrentCalls": 0})).unwrap(),
        super::policy::Limits {
            max_duration_seconds: 60,
            max_concurrent_calls: 1
        }
    );
    assert_eq!(
        l(json!({"maxDurationSeconds": 121.9, "maxConcurrentCalls": 2.5})).unwrap(),
        super::policy::Limits {
            max_duration_seconds: 121,
            max_concurrent_calls: 2
        }
    );
    for v in [json!("600"), Value::Null] {
        assert!(l(json!({"maxDurationSeconds": v})).is_err());
    }
}

#[tokio::test]
async fn raising_a_limit_needs_the_exact_coded_proposal_and_lowering_needs_none() {
    let f = fixture(true, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    call(&fw, "confirm", json!({"changeId": "connect", "code": "123456"})).await;
    fw.command("propose", assign(json!({}))).await;
    call(&fw, "confirm", json!({"changeId": "assign", "code": "123456"})).await;
    for (id, d, c) in [("duration", 600, 1), ("concurrency", 300, 2), ("clamp", 9999, 99)] {
        let r = call(
            &fw,
            "propose",
            json!({"kind": "limits", "changeId": id, "maxDurationSeconds": d, "maxConcurrentCalls": c}),
        )
        .await;
        assert_eq!(r.status, "code_sent");
        let msg = r.message.unwrap();
        assert!(
            msg.contains("minutes per call, ") && msg.contains("calls at once"),
            "{msg}"
        );
        assert!(!call(&fw, "confirm", json!({"changeId": id, "code": "000000"})).await.ok);
        assert!(
            call(
                &fw,
                "confirm",
                json!({"changeId": id, "code": "123456", "maxDurationSeconds": 1})
            )
            .await
            .ok
        );
        let want = phone_limits(&m(json!({"maxDurationSeconds": d, "maxConcurrentCalls": c}))).unwrap();
        let a = summary_assignment(&fw);
        assert_eq!(
            (a["maxDurationSeconds"].as_i64(), a["maxConcurrentCalls"].as_i64()),
            (Some(want.max_duration_seconds), Some(want.max_concurrent_calls))
        );
    }
    let lowered = call(
        &fw,
        "propose",
        json!({"kind": "limits", "changeId": "lower", "maxDurationSeconds": 60, "maxConcurrentCalls": 1}),
    )
    .await;
    assert_eq!(lowered.status, "applied");
    assert_eq!(f.last_push()["maxDurationSeconds"], 60);
    fw.reconcile().await;
    assert_eq!(fw.stream_binding().unwrap()["maxConcurrentCalls"], 1);
    assert_eq!(fw.credentials().last().unwrap()["phone"]["max_duration"], 60);
}

#[tokio::test]
async fn nobody_approved_cannot_bypass_a_spending_limit_raise() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    assert!(!fw.command("propose", assign(json!({"maxConcurrentCalls": 2}))).await.ok);
    fw.command("propose", assign(json!({}))).await;
    assert!(
        !call(
            &fw,
            "propose",
            json!({"kind": "limits", "changeId": "raise", "maxDurationSeconds": 600, "maxConcurrentCalls": 1})
        )
        .await
        .ok
    );
    assert_eq!(
        call(
            &fw,
            "propose",
            json!({"kind": "limits", "changeId": "lower", "maxDurationSeconds": 60, "maxConcurrentCalls": 1})
        )
        .await
        .status,
        "applied"
    );
}

#[tokio::test]
async fn an_agent_restarting_is_not_reported_as_a_missing_channel() {
    let f = fixture(true, true);
    let fw = f.make();
    *f.agent.post_error.lock().unwrap() = Some("agent 500: OpenClaw is not running on this box".into());
    let r = fw.command("propose", connect("restart")).await;
    assert_eq!(r.message.as_deref(), Some("agent_restarting"));
    assert_eq!(fw.summary()["status"], "disconnected");
    *f.agent.post_error.lock().unwrap() = None;
    assert_eq!(fw.command("propose", connect("ready")).await.status, "code_sent");
}

#[tokio::test]
async fn disconnect_revokes_at_once_clears_only_our_routing_and_wipes_the_account() {
    for external in [false, true] {
        let f = fixture(true, true);
        let fw = f.make();
        fw.command("propose", connect("connect")).await;
        call(&fw, "confirm", json!({"changeId": "connect", "code": "123456"})).await;
        fw.command("propose", assign(json!({}))).await;
        call(&fw, "confirm", json!({"changeId": "assign", "code": "123456"})).await;
        fw.reconcile().await;
        call(
            &fw,
            "propose",
            json!({"changeId": "pending", "kind": "callers", "allowAll": true}),
        )
        .await;
        if external {
            let mut r = f.twilio.routing.lock().unwrap();
            r.insert("voice_url".into(), json!("https://new-owner.example/voice"));
            r.insert("status_callback".into(), json!("https://new-owner.example/status"));
        }
        f.twilio
            .routing
            .lock()
            .unwrap()
            .insert("sms_url".into(), json!("https://sms.example/"));
        // Narrowing access works with no approved channel.
        f.ready.store(false, Ordering::SeqCst);
        let r = call(&fw, "disconnect", json!({"changeId": "disconnect"})).await;
        assert!(r.ok && r.status == "applied", "{:?}", r.message);
        assert!(fw.credentials().is_empty() && fw.stream_binding().is_none() && fw.hook().is_none());
        assert_eq!(
            f.routing("voice_url"),
            json!(if external {
                "https://new-owner.example/voice"
            } else {
                ""
            })
        );
        assert_eq!(f.routing("sms_url"), json!("https://sms.example/"));
        assert_eq!(f.last_push()["placeholder"], Value::Null);
        assert!(
            !call(&fw, "confirm", json!({"changeId": "pending", "code": "123456"}))
                .await
                .ok
        );
        let stored =
            cc_crypto::enc_file::load_encrypted_json(&f.dir.path().join("phone.enc"), KEY, "org:box:twilio-voice")
                .unwrap()
                .unwrap();
        for k in ["accountSid", "token", "accountType", "assignment", "cleanup"] {
            assert_eq!(stored[k], Value::Null, "{k}");
        }
        assert_eq!(stored["numbers"], json!([]));
        assert_eq!(f.make().summary()["status"], "disconnected");
        assert!(
            call(&fw, "disconnect", json!({"changeId": "disconnect"})).await.ok,
            "a repeat is answered"
        );
    }
}

#[tokio::test]
async fn a_failed_disconnect_keeps_what_it_needs_to_retry_across_a_restart() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    fw.reconcile().await;
    f.twilio.route_down.store(true, Ordering::SeqCst);
    assert!(!call(&fw, "disconnect", json!({"changeId": "disconnect"})).await.ok);
    assert_eq!(fw.summary()["accountSid"], "AC…aaaa");
    assert_eq!(fw.summary()["cleanupPending"], true);
    assert!(fw.credentials().is_empty());
    f.twilio.route_down.store(false, Ordering::SeqCst);
    let restarted = f.make();
    assert!(call(&restarted, "disconnect", json!({"changeId": "retry"})).await.ok);
    assert_eq!(restarted.summary()["accountSid"], Value::Null);
    assert_eq!(f.routing("voice_url"), json!(""));
}

#[tokio::test]
async fn forget_is_per_agent_and_disconnect_works_after_unassign() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    fw.reconcile().await;
    call(&fw, "forget", json!({"vmId": "another-agent"})).await;
    assert!(summary_assignment(&fw).is_object());
    call(&fw, "unassign", json!({})).await;
    assert_eq!(fw.summary()["accountSid"], "AC…aaaa");
    assert_eq!(summary_assignment(&fw), Value::Null);
    f.ready.store(false, Ordering::SeqCst);
    assert!(call(&fw, "disconnect", json!({"changeId": "disconnect"})).await.ok);
    assert_eq!(fw.summary()["accountSid"], Value::Null);
}

#[tokio::test]
async fn summaries_mask_the_account_sid() {
    let f = fixture(true, true);
    let fw = f.make();
    let proposed = fw.command("propose", connect("masked")).await;
    assert_eq!(
        proposed.message.as_deref(),
        Some("Connect Twilio account AC…aaaa; keep its token on your firewall")
    );
    assert!(!format!("{proposed:?}").contains(&sid()));
    let confirmed = call(&fw, "confirm", json!({"changeId": "masked", "code": "123456"})).await;
    assert!(confirmed.ok);
    assert!(!format!("{confirmed:?}").contains(&sid()));
    assert!(call(&fw, "read", json!({})).await.ok);
    let stored = cc_crypto::enc_file::load_encrypted_json(&f.dir.path().join("phone.enc"), KEY, "org:box:twilio-voice")
        .unwrap()
        .unwrap();
    assert_eq!(stored["accountSid"], json!(sid()));
}

#[tokio::test]
async fn wake_words_change_without_a_code_and_reach_the_agent() {
    let f = fixture(true, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    call(&fw, "confirm", json!({"changeId": "connect", "code": "123456"})).await;
    fw.command(
        "propose",
        assign(json!({"wake": {"enabled": true, "words": ["Jarvis"]}})),
    )
    .await;
    call(&fw, "confirm", json!({"changeId": "assign", "code": "123456"})).await;
    assert_eq!(f.last_push()["wake"], json!({"enabled": true, "words": ["Jarvis"]}));
    let change = call(
        &fw,
        "propose",
        json!({"kind": "wake", "changeId": "wake", "wake": {"enabled": false, "words": ["Jarvis", "Maria Rossi"]}}),
    )
    .await;
    assert_eq!(change.status, "applied");
    assert_eq!(
        f.last_push()["wake"],
        json!({"enabled": false, "words": ["Jarvis", "Maria Rossi"]})
    );
    assert!(
        !call(
            &fw,
            "propose",
            json!({"kind": "wake", "changeId": "bad", "wake": {"enabled": true, "words": ["ok"]}})
        )
        .await
        .ok
    );
}

#[tokio::test]
async fn voice_settings_change_in_place_with_a_code_only_for_a_new_binding_or_a_raise() {
    let f = fixture(true, true);
    let fw = f.make();
    let realtime =
        json!({"provider": "gateway", "credentialId": "included", "model": "openai/gpt-realtime-1.5", "maxMinutes": 5});
    let mut live = realtime.clone();
    live["model"] = json!("openai/gpt-live-1");
    fw.command("propose", connect("connect")).await;
    call(&fw, "confirm", json!({"changeId": "connect", "code": "123456"})).await;
    fw.command("propose", assign(json!({"speech": realtime}))).await;
    call(&fw, "confirm", json!({"changeId": "assign", "code": "123456"})).await;
    fw.reconcile().await;
    let before = fw.stream_binding().unwrap();
    let coded = call(&fw, "propose", json!({"kind": "voice", "changeId": "live", "speech": live, "wake": {"enabled": true, "words": ["Jarvis"]}, "maxDurationSeconds": 600, "maxConcurrentCalls": 1})).await;
    assert_eq!(coded.status, "code_sent");
    let msg = coded.message.unwrap();
    for part in [
        "gateway openai/gpt-live-1 (billed per connected second)",
        "was gateway openai/gpt-realtime-1.5",
        "answer only when called Jarvis",
        "10 minutes per call (was 5)",
        "ends calls in progress",
    ] {
        assert!(msg.contains(part), "{part}: {msg}");
    }
    assert!(
        call(&fw, "confirm", json!({"changeId": "live", "code": "123456"}))
            .await
            .ok
    );
    let pushed = f.last_push();
    assert_eq!(pushed["generation"], before["generation"]);
    assert_eq!(pushed["speech"]["model"], "openai/gpt-live-1");
    assert_eq!(summary_assignment(&fw)["status"], "pending");
    assert!(fw.stream_binding().is_none());
    fw.reconcile().await;
    let after = fw.stream_binding().unwrap();
    assert_eq!(after["hook"], before["hook"]);
    assert_ne!(after["voicePlaceholder"], before["voicePlaceholder"]);
    let ph = after["voicePlaceholder"].as_str().unwrap();
    assert!(ph.starts_with("cc-speech-") && ph.len() == 10 + 48);
    let narrowed = call(&fw, "propose", json!({"kind": "voice", "changeId": "narrow", "speech": live, "wake": {"enabled": false, "words": ["Maria"]}, "maxDurationSeconds": 120, "maxConcurrentCalls": 1})).await;
    assert_eq!(narrowed.status, "applied");
    fw.reconcile().await;
    assert_eq!(
        fw.stream_binding().unwrap()["voicePlaceholder"],
        after["voicePlaceholder"]
    );
    let mixed = call(&fw, "propose", json!({"kind": "voice", "changeId": "mixed", "speech": live, "maxDurationSeconds": 60, "maxConcurrentCalls": 2})).await;
    assert_eq!(mixed.status, "code_sent");
    call(&fw, "cancel", json!({"changeId": "mixed"})).await;
    let classic = call(&fw, "propose", json!({"kind": "voice", "changeId": "classic", "speech": null, "maxDurationSeconds": 60, "maxConcurrentCalls": 1})).await;
    assert_eq!(classic.status, "applied");
    assert!(fw.credentials().iter().all(|c| c.get("phone_speech").is_none()));
}

#[tokio::test]
async fn an_unassign_that_cannot_be_saved_still_revokes_at_the_proxy() {
    let f = fixture(false, true);
    let fw = f.make();
    assert!(fw.command("propose", connect("connect")).await.ok);
    assert!(fw.command("propose", assign(json!({}))).await.ok);
    assert!(!fw.credentials().is_empty());
    // The store can no longer be written: a directory where its file was.
    let path = f.dir.path().join("phone.enc");
    let old = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("x"), "x").unwrap();
    let r = call(&fw, "unassign", json!({})).await;
    assert!(!r.ok);
    assert!(fw.credentials().is_empty());
    assert_eq!(summary_assignment(&fw), Value::Null);
    // A restart reads the old store, which still has the assignment: the tombstone keeps it revoked,
    // and once that is saved the tombstone goes.
    std::fs::remove_dir_all(&path).unwrap();
    std::fs::write(&path, old).unwrap();
    let restarted = f.make();
    assert_eq!(summary_assignment(&restarted), Value::Null);
    assert!(restarted.credentials().is_empty());
    assert_eq!(restarted.summary()["cleanupPending"], true);
    assert!(!f.dir.path().join("phone.enc.revoked").exists());
    assert_eq!(summary_assignment(&f.make()), Value::Null, "and stays revoked");
}

#[tokio::test]
async fn a_held_connect_token_goes_with_its_code() {
    let f = fixture(true, true);
    let fw = f.make();
    assert_eq!(fw.command("propose", connect("c1")).await.status, "code_sent");
    assert!(fw.holds_token());
    call(&fw, "cancel", json!({"changeId": "other"})).await;
    assert!(fw.holds_token(), "a cancel of another change keeps it");
    call(&fw, "cancel", json!({"changeId": "c1"})).await;
    assert!(!fw.holds_token());
    assert_eq!(fw.command("propose", connect("c2")).await.status, "code_sent");
    assert_eq!(
        call(&fw, "confirm", json!({"changeId": "c2", "code": "nope"}))
            .await
            .status,
        "invalid_code"
    );
    assert!(fw.holds_token());
    // The code expired.
    f.codes.pending.lock().unwrap().clear();
    assert_eq!(
        call(&fw, "confirm", json!({"changeId": "c2", "code": "123456"}))
            .await
            .status,
        "expired"
    );
    assert!(!fw.holds_token(), "an expired code drops it");
}

#[tokio::test]
async fn a_disconnect_with_a_token_twilio_no_longer_takes_removes_it_anyway() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    fw.reconcile().await;
    f.twilio.revoked.store(true, Ordering::SeqCst);
    // An unassign keeps trying: its cleanup waits for a token that works.
    assert!(!call(&fw, "unassign", json!({})).await.ok);
    assert_eq!(fw.summary()["cleanupPending"], true);
    // A disconnect gives the routing up and removes the dead token.
    assert!(call(&fw, "disconnect", json!({"changeId": "d"})).await.ok);
    assert_eq!(fw.summary()["accountSid"], Value::Null);
    assert_eq!(fw.summary()["cleanupPending"], false);
    assert_eq!(f.make().summary()["accountSid"], Value::Null, "and it stays gone");
}

#[tokio::test]
async fn no_admission_yet_refuses_the_delivery() {
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    let reg = fw.registrations().pop().unwrap();
    let prep = reg.prepare_delivery.unwrap();
    assert!(prep(b"CallSid=CAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "").is_err());
}

/// Twilio's own signature, made the way Twilio makes it (the configured URL, then each key and value
/// sorted by key), is what the hook checks; the agent gets the form re-signed with its placeholder.
#[tokio::test]
async fn the_hook_accepts_twilios_signature_and_re_signs_for_the_agent() {
    use crate::core::ingress::{Ingress, Reply, VerifyRule, owns_ingress_path};
    use crate::core::url_form::{decode_form, url_form_signature};
    let f = fixture(false, true);
    let fw = f.make();
    fw.command("propose", connect("connect")).await;
    fw.command("propose", assign(json!({}))).await;
    fw.reconcile().await;
    assert_eq!(summary_assignment(&fw)["status"], "active");
    let placeholder = f.last_push()["placeholder"].as_str().unwrap().to_string();
    let mut reg = fw.registrations().pop().unwrap();
    let Some(VerifyRule::Hmac(rule)) = reg.verify.first() else {
        panic!("no signature rule");
    };
    let public = rule.public_url.clone().unwrap();
    assert!(public.starts_with("https://firewall.example/hook/hk_"), "{public}");
    // The stream relay is not what this checks.
    reg.prepare_delivery = None;
    reg.rewrite_response = None;
    let seen: Arc<Mutex<Vec<Map<String, Value>>>> = Arc::default();
    let s = seen.clone();
    let regs = Arc::new(vec![reg]);
    let ingress = Arc::new(Ingress::new(
        Arc::new(move || regs.as_ref().clone()),
        Arc::new(move |_, d| {
            s.lock().unwrap().push(d.headers);
            Box::pin(async {
                Ok(Reply {
                    status: json!(200),
                    content_type: Some("application/xml".into()),
                    body_b64: Some("PFJlc3BvbnNlLz4=".into()),
                })
            })
        }),
        None,
        None,
    ));
    let mut router = cc_http::Router::new(&["hooks"]);
    router.route(
        "hooks",
        |_, p| owns_ingress_path(p),
        move |req, _| {
            let i = ingress.clone();
            async move {
                let path = req.uri().path().to_string();
                i.handle(req, &path).await
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = format!(
        "http://{}{}",
        listener.local_addr().unwrap(),
        public.trim_start_matches("https://firewall.example")
    );
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));

    let body = format!(
        "AccountSid={}&CallSid=CA{}&CallStatus=ringing&Direction=inbound&From=%2B14155550999&To=%2B14155550123",
        sid(),
        "d".repeat(32)
    );
    let form = decode_form(body.as_bytes()).unwrap();
    let post = |sig: String, query: &'static str| {
        reqwest::Client::new()
            .post(format!("{local}{query}"))
            .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
            .header("x-twilio-signature", sig)
            .body(body.clone())
            .send()
    };
    for query in ["", "?type=status"] {
        let signed = format!("{public}{query}");
        let res = post(url_form_signature(&token(), &signed, &form), query).await.unwrap();
        assert_eq!(res.status().as_u16(), 200, "{query}");
        let headers = seen.lock().unwrap().pop().expect("delivered");
        assert_eq!(
            headers["x-twilio-signature"],
            json!(url_form_signature(&placeholder, &signed, &form)),
            "{query}"
        );
    }
    // A signature made with another token is refused before the agent.
    let res = post(url_form_signature("d".repeat(32).as_str(), &public, &form), "")
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
    assert!(seen.lock().unwrap().is_empty());
}
