//! `phone-stream.test.ts` and `phone-admission.test.ts`: one-use signed streams, the relay and its
//! checks, fallback to classic, revocation, deadlines, the shared call budget and the leases.
//! Against a real websocket client (Twilio) and a websocket server standing in for the agent.

#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::stream::*;
use crate::core::url_form::url_form_signature;

const NATIVE: &str = r#"<Response><Connect><Stream url="wss://firewall.example/voice/stream/realtime/12345678-1234-1234-1234-123456789abc" /></Connect></Response>"#;

fn sid() -> String {
    format!("CA{}", "a".repeat(32))
}
fn stream_sid() -> String {
    format!("MZ{}", "c".repeat(32))
}
fn body_for(sid: &str, direction: &str) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("CallSid", sid)
        .append_pair("Direction", direction)
        .finish()
        .into_bytes()
}
fn body() -> Vec<u8> {
    body_for(&sid(), "inbound")
}
fn start_for(call: &str) -> Value {
    json!({
        "event": "start", "sequenceNumber": "1", "streamSid": stream_sid(),
        "start": {"accountSid": format!("AC{}", "b".repeat(32)), "callSid": call, "streamSid": stream_sid(),
            "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1}},
    })
}
fn connected() -> String {
    json!({"event": "connected", "protocol": "Call", "version": "1.0.0"}).to_string()
}

type Twilio = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct F {
    fw: Arc<PhoneStreams>,
    dir: tempfile::TempDir,
    clock: Arc<AtomicI64>,
    binding: Arc<Mutex<Option<Map<String, Value>>>>,
    ended: Arc<Mutex<Vec<String>>>,
    carrier_limits: Arc<Mutex<Vec<String>>>,
    frames: Arc<Mutex<Vec<Value>>>,
    /// The newest agent connection; the earlier ones stay open.
    agent: Arc<Mutex<Option<mpsc::UnboundedSender<Message>>>>,
    port: u16,
}

async fn fixture(carrier: &[&str]) -> F {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(AtomicI64::new(crate::channels::now_ms()));
    let binding = Arc::new(Mutex::new(Some(
        json!({
            "vmId": "vm", "hostname": "agent.example", "generation": "generation", "placeholder": "placeholder",
            "accountSid": format!("AC{}", "b".repeat(32)), "token": "secret",
            "hook": "https://firewall.example/hook/hk_test",
            "speech": {"provider": "gateway", "credentialId": "included", "model": "openai/gpt-realtime-1.5", "maxMinutes": 5},
            "voicePlaceholder": format!("cc-speech-{}", "a".repeat(48)),
            "maxDurationSeconds": 300, "speechAvailable": true,
        })
        .as_object()
        .cloned()
        .unwrap(),
    )));
    let ended: Arc<Mutex<Vec<String>>> = Arc::default();
    let carrier_limits: Arc<Mutex<Vec<String>>> = Arc::default();
    let frames: Arc<Mutex<Vec<Value>>> = Arc::default();
    let agent: Arc<Mutex<Option<mpsc::UnboundedSender<Message>>>> = Arc::default();
    let keep: Arc<Mutex<Vec<mpsc::UnboundedSender<Message>>>> = Arc::default();

    // The agent's end of the relay.
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    {
        let (frames, agent, keep) = (frames.clone(), agent.clone(), keep.clone());
        tokio::spawn(async move {
            while let Ok((s, _)) = backend.accept().await {
                let Ok(ws) = tokio_tungstenite::accept_async(s).await else {
                    continue;
                };
                let (mut sink, mut read) = ws.split();
                let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
                keep.lock().unwrap().push(tx.clone());
                *agent.lock().unwrap() = Some(tx);
                let frames = frames.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            m = read.next() => match m {
                                Some(Ok(Message::Text(t))) => frames.lock().unwrap().push(serde_json::from_str(&t).unwrap()),
                                Some(Ok(_)) => {}
                                _ => break,
                            },
                            out = rx.recv() => match out {
                                Some(m) => { if sink.send(m).await.is_err() { break } }
                                None => break,
                            },
                        }
                    }
                });
            }
        });
    }

    let states: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(carrier.iter().map(|s| s.to_string()).collect()));
    let (b, c, e, l) = (binding.clone(), clock.clone(), ended.clone(), carrier_limits.clone());
    let fw = PhoneStreams::new(PhoneStreamsOptions {
        binding: Arc::new(move || b.lock().unwrap().clone().map(Binding)),
        sign: Arc::new(|_, _| Ok(String::new())),
        host_for: Arc::new(|_| Some("agent.example".into())),
        media_dir: dir.path().to_path_buf(),
        control: Arc::new(move |sid, fields| {
            let (e, l, states) = (e.clone(), l.clone(), states.clone());
            Box::pin(async move {
                match fields {
                    None => {
                        let mut s = states.lock().unwrap();
                        let status = if s.len() > 1 { s.pop_front() } else { s.front().cloned() };
                        Some(json!({"status": status}).as_object().cloned().unwrap())
                    }
                    Some(f) => {
                        for (k, v) in f {
                            if k == "Status" {
                                e.lock().unwrap().push(sid.clone());
                            }
                            if k == "TimeLimit" {
                                l.lock().unwrap().push(v);
                            }
                        }
                        Some(Map::new())
                    }
                }
            })
        }),
        log_path: Some(dir.path().join("log")),
        now: Arc::new(move || c.load(Ordering::SeqCst)),
        agent_base: Some(Arc::new(move |_| format!("ws://127.0.0.1:{backend_port}"))),
    });
    fw.start();

    // Twilio's side: the ingress's upgrade route.
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let mut router = cc_http::Router::new(&["up"]);
    let s = fw.clone();
    router.route(
        "up",
        |_, _| true,
        move |req, _| {
            let s = s.clone();
            async move { s.upgrade(req) }
        },
    );
    let router = Arc::new(router);
    tokio::spawn(async move { cc_http::serve(server, router).await });

    F {
        fw,
        dir,
        clock,
        binding,
        ended,
        carrier_limits,
        frames,
        agent,
        port,
    }
}

impl F {
    fn issue(&self) -> String {
        self.issue_for(&body())
    }
    fn issue_for(&self, b: &[u8]) -> String {
        assert_eq!(self.fw.prepare(b, "").unwrap()["x-cc-phone-mode"], "realtime");
        let xml = self.fw.rewrite(NATIVE, b, "").unwrap();
        assert!(self.fw.response_allowed(&xml));
        regex::Regex::new(r#"url="([^"]+)""#).unwrap().captures(&xml).unwrap()[1].to_string()
    }
    /// Twilio connecting; `Err` when the firewall refused the upgrade.
    async fn connect(&self, url: &str, signature: Option<String>) -> Result<Twilio, ()> {
        let path = url::Url::parse(url).unwrap().path().to_string();
        let mut req = format!("ws://127.0.0.1:{}{path}", self.port)
            .into_client_request()
            .unwrap();
        let sig = signature.unwrap_or_else(|| url_form_signature("secret", url, &vec![]));
        req.headers_mut().insert("x-twilio-signature", sig.parse().unwrap());
        tokio_tungstenite::connect_async(req)
            .await
            .map(|(ws, _)| ws)
            .map_err(|_| ())
    }
    fn lease(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.dir.path().join("phone-media.json")).unwrap()).unwrap()
    }
    fn set(&self, k: &str, v: Value) {
        if let Some(b) = self.binding.lock().unwrap().as_mut() {
            b.insert(k.into(), v);
        }
    }
    fn limits(&self, d: i64, c: i64) {
        self.set("maxDurationSeconds", json!(d));
        self.set("maxConcurrentCalls", json!(c));
    }
    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }
    fn ended(&self) -> Vec<String> {
        self.ended.lock().unwrap().clone()
    }
    fn frames(&self) -> usize {
        self.frames.lock().unwrap().len()
    }
    fn agent_send(&self, v: Value) {
        self.agent
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(Message::text(v.to_string()))
            .unwrap();
    }
}

async fn wait_for(check: impl Fn() -> bool) {
    for _ in 0..300 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the expected state was not reached");
}

/// Until the server closes the socket.
async fn closed(ws: &mut Twilio) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(m)) = ws.next().await {
            if matches!(m, Message::Close(_)) {
                break;
            }
        }
    })
    .await
    .expect("closed in time");
}

async fn started(f: &F, url: &str) -> Twilio {
    let mut ws = f.connect(url, None).await.unwrap();
    ws.send(Message::text(connected())).await.unwrap();
    ws.send(Message::text(start_for(&sid()).to_string())).await.unwrap();
    wait_for(|| f.frames() == 2).await;
    ws
}

#[tokio::test]
async fn a_signed_one_use_stream_starts_before_its_lease_relays_and_is_revoked() {
    let f = fixture(&["in-progress"]).await;
    let url = f.issue();
    assert_eq!(f.lease(), json!({}));
    assert!(f.connect(&url, Some("wrong".into())).await.is_err());
    assert_eq!(f.lease(), json!({}));
    let mut ws = started(&f, &url).await;
    assert_eq!(f.lease()["vm"][0]["purpose"], "phone");
    assert!(f.connect(&url, None).await.is_err(), "one use");
    let payload = base64::engine::general_purpose::STANDARD.encode([255u8; 160]);
    ws.send(Message::text(
        json!({"event": "media", "sequenceNumber": "2", "streamSid": stream_sid(),
            "media": {"track": "inbound", "timestamp": "20", "payload": payload}})
        .to_string(),
    ))
    .await
    .unwrap();
    wait_for(|| f.frames() == 3).await;
    *f.binding.lock().unwrap() = None;
    closed(&mut ws).await;
    wait_for(|| f.lease() == json!({})).await;
    wait_for(|| f.ended() == vec![sid()]).await;
}

#[tokio::test]
async fn media_before_start_and_a_mismatched_account_fail_closed() {
    let mut bad_start = start_for(&sid());
    bad_start["start"]["accountSid"] = json!(format!("AC{}", "d".repeat(32)));
    for event in [
        json!({"event": "media", "sequenceNumber": "1", "streamSid": stream_sid()}),
        bad_start,
    ] {
        let f = fixture(&["in-progress"]).await;
        let mut ws = f.connect(&f.issue(), None).await.unwrap();
        ws.send(Message::text(connected())).await.unwrap();
        ws.send(Message::text(event.to_string())).await.unwrap();
        closed(&mut ws).await;
        assert_eq!(f.lease(), json!({}));
        wait_for(|| f.ended() == vec![sid()]).await;
        assert_eq!(f.frames(), 0, "nothing reached the agent");
    }
}

#[tokio::test]
async fn status_callbacks_cannot_allocate_a_ticket_and_other_destinations_fail() {
    let f = fixture(&["in-progress"]).await;
    f.fw.prepare(&body(), "?type=status").unwrap();
    assert!(f.fw.rewrite(NATIVE, &body(), "?type=status").is_err());
    f.fw.prepare(&body(), "").unwrap();
    for xml in [
        NATIVE.replace("firewall.example", "evil.example"),
        NATIVE.replace("/voice/stream/", "/admin/"),
        NATIVE.replace("<Connect>", r#"<Connect action="https://evil.example">"#),
        NATIVE.replace("/>", r#"><Parameter name="x" value="y"/></Stream>"#),
    ] {
        assert!(f.fw.rewrite(&xml, &body(), "").is_err(), "{xml}");
    }
    f.issue();
    assert_eq!(
        f.fw.rewrite(NATIVE, &body(), "").unwrap(),
        "<Response><Hangup/></Response>"
    );
    assert!(
        f.fw.prepare(format!("CallSid=CA{}", "f".repeat(32)).as_bytes(), "")
            .is_err()
    );
}

#[tokio::test]
async fn playback_without_mark_acknowledgement_is_bounded_to_two_seconds() {
    let f = fixture(&["in-progress"]).await;
    let mut ws = started(&f, &f.issue()).await;
    let payload = base64::engine::general_purpose::STANDARD.encode([0u8; 160]);
    for _ in 0..101 {
        f.agent_send(json!({"event": "media", "streamSid": stream_sid(), "media": {"payload": payload}}));
    }
    closed(&mut ws).await;
    wait_for(|| f.ended() == vec![sid()]).await;
    assert_eq!(f.lease(), json!({}));
}

#[tokio::test]
async fn an_agent_transport_failure_falls_back_to_classic_once() {
    let f = fixture(&["in-progress"]).await;
    let mut ws = started(&f, &f.issue()).await;
    f.agent
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .send(Message::Close(Some(
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: 1011.into(),
                reason: "".into(),
            },
        )))
        .unwrap();
    closed(&mut ws).await;
    wait_for(|| f.lease() == json!({})).await;
    assert!(f.ended().is_empty());
    assert_eq!(f.fw.prepare(&body(), "").unwrap()["x-cc-phone-mode"], "classic");
    assert!(f.fw.rewrite(NATIVE, &body(), "").is_err());
    let say = "<Response><Say>Please continue.</Say></Response>";
    assert_eq!(f.fw.rewrite(say, &body(), "").unwrap(), say);
    let log = std::fs::read_to_string(f.dir.path().join("log")).unwrap();
    assert!(log.contains("phone stream: close transport_agent_close_1011 inbound gateway openai/gpt-realtime-1.5"));
    assert!(!log.contains("secret"));
}

#[tokio::test]
async fn caller_policy_narrowing_or_a_rotated_credential_revokes_an_open_stream() {
    for k in ["callerPolicy", "speechRevision"] {
        let f = fixture(&["in-progress"]).await;
        let mut ws = started(&f, &f.issue()).await;
        let at = std::time::Instant::now();
        f.set(k, json!("changed"));
        closed(&mut ws).await;
        assert!(at.elapsed() < Duration::from_secs(1));
        wait_for(|| f.lease() == json!({})).await;
        wait_for(|| f.ended() == vec![sid()]).await;
    }
}

#[tokio::test]
async fn the_wss_signature_rejects_the_https_variant_and_an_expired_ticket() {
    let f = fixture(&["in-progress"]).await;
    let url = f.issue();
    let https = url_form_signature("secret", &url.replace("wss:", "https:"), &vec![]);
    assert!(f.connect(&url, Some(https)).await.is_err());
    f.advance(30_001);
    assert!(f.connect(&url, None).await.is_err(), "expired");
    assert_eq!(f.lease(), json!({}));
}

#[tokio::test]
async fn unsigned_refusal_floods_do_not_lock_out_the_signed_call() {
    let f = fixture(&["in-progress"]).await;
    let url = f.issue();
    for _ in 0..65 {
        assert!(f.connect(&url, Some("invalid".into())).await.is_err());
    }
    let mut ws = f.connect(&url, None).await.unwrap();
    ws.close(None).await.unwrap();
}

#[tokio::test]
async fn an_oversized_frame_ends_the_call_rather_than_falling_back() {
    let f = fixture(&["in-progress"]).await;
    let mut ws = f.connect(&f.issue(), None).await.unwrap();
    let _ = ws.send(Message::text("x".repeat(20_000))).await;
    closed(&mut ws).await;
    wait_for(|| f.ended() == vec![sid()]).await;
    assert!(f.fw.prepare(&body(), "").is_err());
}

#[tokio::test]
async fn unavailable_speech_is_classic_and_the_absolute_deadline_ends_it() {
    let f = fixture(&["in-progress"]).await;
    f.set("speechAvailable", json!(false));
    assert_eq!(f.fw.prepare(&body(), "").unwrap()["x-cc-phone-mode"], "classic");
    assert!(f.fw.rewrite(NATIVE, &body(), "").is_err());
    f.advance(300_001);
    wait_for(|| f.ended() == vec![sid()]).await;
    assert!(f.fw.prepare(&body(), "").is_err());
}

#[tokio::test]
async fn the_carrier_limit_is_applied_after_answering_without_extending_the_deadline() {
    let f = fixture(&["ringing", "ringing", "in-progress"]).await;
    f.limits(60, 1);
    f.set("speechAvailable", json!(false));
    f.fw.prepare(&body(), "").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(f.carrier_limits.lock().unwrap().is_empty());
    f.advance(1000);
    wait_for(|| f.carrier_limits.lock().unwrap().len() == 1).await;
    assert_eq!(*f.carrier_limits.lock().unwrap(), vec!["60".to_string()]);
    f.advance(59_001);
    wait_for(|| f.ended() == vec![sid()]).await;
}

#[tokio::test]
async fn assignment_concurrency_and_independent_deadlines() {
    for realtime in [false, true] {
        let f = fixture(&["in-progress"]).await;
        f.limits(3600, 5);
        if !realtime {
            f.set("speechAvailable", json!(false));
        }
        let mode = if realtime { "realtime" } else { "classic" };
        let call = |n: u32| body_for(&format!("CA{}", n.to_string().repeat(32)), "inbound");
        for n in 1..=5 {
            assert_eq!(f.fw.prepare(&call(n), "").unwrap()["x-cc-phone-mode"], mode);
        }
        assert!(f.fw.prepare(&call(6), "").unwrap_err().contains("concurrency"));
        f.advance(301_000);
        assert_eq!(f.fw.prepare(&call(1), "").unwrap()["x-cc-phone-mode"], mode);
        f.fw.end(&format!("CA{}", "1".repeat(32)), "completed", false);
        f.fw.prepare(&call(6), "").unwrap();
        f.advance(3_299_000);
        assert!(f.fw.prepare(&call(2), "").unwrap_err().contains("ended"));
        assert_eq!(f.fw.prepare(&call(6), "").unwrap()["x-cc-phone-mode"], mode);
        wait_for(|| f.ended().len() == 4).await;
        assert_eq!(
            f.fw.rewrite("<Response><Say>late</Say></Response>", &call(2), "")
                .unwrap(),
            "<Response><Hangup/></Response>"
        );
    }
}

#[tokio::test]
async fn lowered_limits_revoke_excess_calls() {
    let f = fixture(&["in-progress"]).await;
    f.limits(3600, 2);
    f.set("speechAvailable", json!(false));
    f.fw.prepare(&body(), "").unwrap();
    f.fw.prepare(&body_for(&format!("CA{}", "b".repeat(32)), "inbound"), "")
        .unwrap();
    f.limits(60, 1);
    f.advance(61_000);
    assert!(f.fw.prepare(&body(), "").is_err());
    wait_for(|| f.ended().len() == 2).await;
}

#[tokio::test]
async fn reservations_and_inbound_calls_share_one_budget() {
    let f = fixture(&["in-progress"]).await;
    f.limits(600, 2);
    let (vm, ph) = (json!("vm"), json!("placeholder"));
    let id = f.fw.reserve(&vm, &ph).unwrap();
    assert!(f.fw.reserve(&json!("other"), &ph).is_err());
    f.fw.prepare(&body(), "").unwrap();
    assert!(f.fw.reserve(&vm, &ph).unwrap_err().contains("concurrency"));
    let out_sid = format!("CA{}", "b".repeat(32));
    f.fw.settle_reservation(&id, Some(&json!(out_sid)), false);
    f.fw.prepare(&body_for(&out_sid, "outbound-api"), &format!("?ccCall={id}"))
        .unwrap();
    assert!(f.fw.reserve(&vm, &ph).unwrap_err().contains("concurrency"));
    f.fw.end(&sid(), "completed", false);
    let rejected = f.fw.reserve(&vm, &ph).unwrap();
    f.fw.settle_reservation(&rejected, None, true);
    assert!(f.fw.reserve(&vm, &ph).is_ok());
}

#[tokio::test]
async fn simultaneous_realtime_streams_publish_independent_leases() {
    let f = fixture(&["in-progress"]).await;
    f.limits(3600, 2);
    let mut first = f.connect(&f.issue(), None).await.unwrap();
    first.send(Message::text(connected())).await.unwrap();
    first.send(Message::text(start_for(&sid()).to_string())).await.unwrap();
    let second_sid = format!("CA{}", "d".repeat(32));
    let second_body = body_for(&second_sid, "inbound");
    let url = f.issue_for(&second_body);
    let mut second = f.connect(&url, None).await.unwrap();
    second.send(Message::text(connected())).await.unwrap();
    second
        .send(Message::text(start_for(&second_sid).to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    wait_for(|| f.lease()["vm"].as_array().is_some_and(|a| a.len() == 2)).await;
    let lease = f.lease();
    assert_ne!(lease["vm"][0]["id"], lease["vm"][1]["id"]);
    f.fw.end(&sid(), "completed", false);
    assert_eq!(f.lease()["vm"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn admission_is_bounded_checks_the_assignment_and_reserves_before_replying() {
    let f = fixture(&["in-progress"]).await;
    f.limits(600, 2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let router = Arc::new(admission_router(f.fw.clone()));
    tokio::spawn(async move { cc_http::serve(listener, router).await });
    let http = reqwest::Client::new();
    let post = |b: Value| {
        let (http, url) = (http.clone(), url.clone());
        async move { http.post(&url).body(b.to_string()).send().await.unwrap() }
    };
    assert_eq!(
        post(json!({"action": "reserve", "vmId": "other", "placeholder": "placeholder"}))
            .await
            .status(),
        403
    );
    let mut statuses = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let r = post(json!({"action": "reserve", "vmId": "vm", "placeholder": "placeholder"})).await;
        statuses.push(r.status().as_u16());
        if r.status() == 200 {
            ids.push(r.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string());
        }
    }
    statuses.sort();
    assert_eq!(statuses, [200, 200, 403]);
    let settled = post(json!({"action": "settle", "id": ids[0], "rejected": true})).await;
    assert_eq!(settled.status(), 200);
    assert_eq!(settled.json::<Value>().await.unwrap(), json!({"ok": true}));
    assert_eq!(
        post(json!({"action": "reserve", "vmId": "vm", "placeholder": "placeholder"}))
            .await
            .status(),
        200
    );
    assert_eq!(
        post(json!({"action": "reserve", "vmId": "vm", "placeholder": "x".repeat(4096)}))
            .await
            .status(),
        403
    );
    assert_eq!(http.get(&url).send().await.unwrap().status(), 403);
}

#[tokio::test]
async fn a_stream_the_firewall_ends_is_logged_with_its_call() {
    let f = fixture(&["in-progress"]).await;
    let mut ws = started(&f, &f.issue()).await;
    *f.binding.lock().unwrap() = None;
    closed(&mut ws).await;
    let path = f.dir.path().join("log");
    wait_for(|| {
        std::fs::read_to_string(&path)
            .unwrap_or_default()
            .contains("close revoked")
    })
    .await;
    let log = std::fs::read_to_string(&path).unwrap();
    let line: Value = serde_json::from_str(log.lines().find(|l| l.contains("close revoked")).unwrap()).unwrap();
    assert_eq!(line["vm_id"], "vm");
    assert_eq!(
        line["rule"],
        "phone stream: close revoked inbound gateway openai/gpt-realtime-1.5"
    );
    assert!(line["call_id"].is_string() && line["frames"].as_i64().unwrap() >= 2);
}

#[tokio::test]
async fn the_stream_answer_takes_whitespace_as_javascript_does() {
    let f = fixture(&["in-progress"]).await;
    f.fw.prepare(&body(), "").unwrap();
    // U+0085 is not whitespace in JavaScript: refused.
    let nel = NATIVE.replace("<Connect>", "\u{85}<Connect>");
    assert!(f.fw.rewrite(&nel, &body(), "").is_err());
    // U+FEFF is: accepted.
    let bom = format!("\u{feff}{NATIVE}\u{feff}");
    assert!(f.fw.rewrite(&bom, &body(), "").unwrap().contains("/phone-stream/"));
}

#[tokio::test]
async fn a_broken_handshake_does_not_spend_the_ticket() {
    let f = fixture(&["in-progress"]).await;
    let url = f.issue();
    let path = url::Url::parse(&url).unwrap().path().to_string();
    let sig = url_form_signature("secret", &url, &vec![]);
    // Signed, but not a websocket handshake.
    let res = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}{path}", f.port))
        .header("x-twilio-signature", &sig)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let mut ws = f.connect(&url, None).await.unwrap();
    ws.close(None).await.unwrap();
}

#[tokio::test]
async fn a_tick_that_fails_ends_every_call_for_good() {
    let f = fixture(&["in-progress"]).await;
    f.set("speechAvailable", json!(false));
    f.fw.prepare(&body(), "").unwrap();
    // Limits that do not read: the tick cannot run.
    f.set("maxDurationSeconds", json!("x"));
    wait_for(|| f.ended() == vec![sid()]).await;
    assert!(!f.dir.path().join("phone-media.json").exists());
    f.set("maxDurationSeconds", json!(300));
    assert!(
        f.fw.prepare(&body(), "").unwrap_err().contains("ended"),
        "its webhooks are refused"
    );
}
