//! `phone-stream.test.ts`: the relay against a fake voice-call plugin, with real tokens.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use base64::Engine;
use cc_auth::firewall::FirewallAuth;
use cc_testkit::{BoxKeys, Signer};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};

use super::*;

type Notes = Arc<Mutex<Vec<(String, StreamPatch)>>>;

struct Rig {
    _dir: tempfile::TempDir,
    keys: BoxKeys,
    url: String,
    binding: Arc<Mutex<Option<StreamBinding>>>,
    diagnostics: Arc<Mutex<Vec<String>>>,
    notes: Notes,
    plugin: Plugin,
}

/// The voice-call plugin's realtime listener: echoes text, records paths, can refuse with 401.
#[derive(Clone)]
struct Plugin {
    addr: String,
    paths: Arc<Mutex<Vec<String>>>,
    refuse: Arc<AtomicBool>,
    /// Closes every open stream when set.
    hang_up: tokio::sync::watch::Sender<u32>,
    stop: CancellationToken,
}

async fn plugin() -> Plugin {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let (hang_up, _) = tokio::sync::watch::channel(0u32);
    let p = Plugin {
        addr,
        paths: Arc::default(),
        refuse: Arc::default(),
        hang_up,
        stop: CancellationToken::new(),
    };
    let q = p.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = tokio::select! {
                c = listener.accept() => c.expect("accept"),
                () = q.stop.cancelled() => return,
            };
            let q = q.clone();
            tokio::spawn(async move {
                let paths = q.paths.clone();
                let refuse = q.refuse.load(Ordering::SeqCst);
                #[allow(clippy::result_large_err)] // tungstenite's callback type
                let cb = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                    if refuse {
                        let mut e = ErrorResponse::new(None);
                        *e.status_mut() = StatusCode::UNAUTHORIZED;
                        return Err(e);
                    }
                    paths.lock().expect("paths").push(req.uri().path().to_string());
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, cb).await else {
                    return;
                };
                let mut hang = q.hang_up.subscribe();
                loop {
                    tokio::select! {
                        m = ws.next() => match m {
                            Some(Ok(Message::Text(t))) => { let _ = ws.send(Message::Text(t)).await; }
                            Some(Ok(_)) => {}
                            _ => return,
                        },
                        _ = hang.changed() => { let _ = ws.close(None).await; }
                        () = q.stop.cancelled() => return,
                    }
                }
            });
        }
    });
    p
}

fn speech_binding() -> StreamBinding {
    StreamBinding {
        generation: "a".repeat(32),
        placeholder: Some(format!("CC-TWILIO-{}", "b".repeat(32))),
        speech: true,
        public_url: format!("https://firewall.example/hook/hk_{}", "d".repeat(32)),
        max_concurrent_calls: None,
        max_duration_seconds: None,
    }
}

async fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("dir");
    let keys = BoxKeys::write(&dir.path().join("keys"), "vm", "box.example").expect("keys");
    let pem = keys.firewall.public_pem.clone();
    let auth = Arc::new(FirewallAuth::new(
        move || Some(pem.clone()),
        Some("vm".into()),
        Vec::new,
        None,
    ));
    let binding = Arc::new(Mutex::new(Some(speech_binding())));
    let diagnostics: Arc<Mutex<Vec<String>>> = Arc::default();
    let notes: Notes = Arc::default();
    let plugin = plugin().await;
    let (b, d, n) = (binding.clone(), diagnostics.clone(), notes.clone());
    let relay = Relay::with(
        Arc::new(move || b.lock().expect("binding").clone()),
        Arc::new(move |e| d.lock().expect("diag").push(e.to_string())),
        Arc::new(move |sid, patch| n.lock().expect("notes").push((sid.to_string(), patch.clone()))),
        &plugin.addr,
    );
    let mut router = cc_http::Router::new(&["main"]);
    router.upgrades(cc_http::Router::new(&["upgrade"]));
    router.upgrades_mut().expect("upgrades").route(
        "upgrade",
        |_, _| true,
        move |req, _| {
            let (relay, auth) = (relay.clone(), auth.clone());
            async move { relay.upgrade(&auth, req).await }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}/phone/stream", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    Rig {
        _dir: dir,
        keys,
        url,
        binding,
        diagnostics,
        notes,
        plugin,
    }
}

fn sign(placeholder: &str, url: &str) -> String {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(placeholder.as_bytes()).expect("key");
    mac.update(url.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// A fresh envelope for a ticket made of one repeated character.
fn envelope(ticket_char: char, deadline_in_ms: i64) -> Value {
    let ticket = ticket_char.to_string().repeat(64);
    let url = format!("wss://firewall.example/phone-stream/{ticket}");
    json!({
        "generation": "a".repeat(32),
        "ticket": ticket,
        "callSid": format!("CA{}", "a".repeat(32)),
        "path": "/voice/stream/realtime/12345678-1234-1234-1234-123456789abc",
        "url": url,
        "deadline": now_ms() + deadline_in_ms,
        "signature": sign(&format!("CC-TWILIO-{}", "b".repeat(32)), &url),
    })
}

#[derive(Default)]
struct Opts {
    purpose: Option<&'static str>,
    unbound: bool,
    skew_s: i64,
}

type Client = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Opens a stream as the firewall does. `Err(status)` when the upgrade is refused.
async fn connect(r: &Rig, p: &Value, o: Opts) -> Result<Client, u16> {
    let raw = serde_json::to_string(p).expect("json");
    let key = tokio_tungstenite::tungstenite::handshake::client::generate_key();
    let digest = hex::encode(Sha256::digest(format!("{raw}\n{key}").as_bytes()));
    let now = cc_auth::jwt::now_s() + o.skew_s;
    let token = r.keys.sign_with_at(
        Signer::Firewall,
        json!({
            "vmId": "vm",
            "purpose": o.purpose.unwrap_or("phone"),
            "phoneStream": if o.unbound { "wrong".to_string() } else { digest },
        }),
        Some(30),
        Some(now),
    );
    let mut req = r.url.as_str().into_client_request().expect("request");
    let h = req.headers_mut();
    h.insert("sec-websocket-key", HeaderValue::from_str(&key).expect("key"));
    h.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("auth"),
    );
    h.insert(
        "x-cc-phone-stream",
        HeaderValue::from_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)).expect("env"),
    );
    match tokio_tungstenite::connect_async(req).await {
        Ok((ws, _)) => Ok(ws),
        Err(WsError::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("connect: {e}"),
    }
}

/// The close code the client ends up with.
/// Reads on after the close frame, so the reply goes out and the socket ends, as the `ws` client's
/// `close` event waits for.
async fn close_code(ws: &mut Client) -> Option<u16> {
    let mut code = None;
    while let Some(m) = ws.next().await {
        match m {
            Ok(Message::Close(f)) => code = f.map(|f| u16::from(f.code)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    code
}

async fn echo(ws: &mut Client, text: &str) -> String {
    ws.send(Message::text(text)).await.expect("send");
    loop {
        match ws.next().await.expect("frame").expect("ok") {
            Message::Text(t) => return t.to_string(),
            _ => continue,
        }
    }
}

fn last_diag(r: &Rig) -> Option<String> {
    r.diagnostics.lock().expect("diag").pop()
}

#[tokio::test]
async fn agent_stream_requires_signature_hmac_fresh_ticket_and_generation() {
    let r = rig().await;
    let e = envelope('e', 10_000);
    let with = |k: &str, v: Value| {
        let mut x = e.clone();
        x[k] = v;
        x
    };
    let cases: Vec<(Value, Opts, &str)> = vec![
        (
            e.clone(),
            Opts {
                purpose: Some("doctor"),
                ..Default::default()
            },
            "token",
        ),
        (
            e.clone(),
            Opts {
                unbound: true,
                ..Default::default()
            },
            "envelope_digest",
        ),
        (with("signature", json!("invalid")), Opts::default(), "signature"),
        (with("path", json!("/admin")), Opts::default(), "envelope_fields"),
        (with("generation", json!("b".repeat(32))), Opts::default(), "generation"),
        (
            e.clone(),
            Opts {
                skew_s: 200,
                ..Default::default()
            },
            "clock_skew",
        ),
        (with("deadline", json!(now_ms() + 400_000)), Opts::default(), "deadline"),
    ];
    for (p, o, reason) in cases {
        assert_eq!(connect(&r, &p, o).await.err(), Some(403), "{reason}");
        assert!(r.plugin.paths.lock().expect("paths").is_empty());
        assert_eq!(
            last_diag(&r).as_deref(),
            Some(format!("refused reason={reason}").as_str())
        );
    }
    // Refusals after the firewall-signed envelope checks out go into the call history; earlier
    // ones (a wrong token, a tampered envelope) cannot be tied to a call and only reach the log.
    let sid = format!("CA{}", "a".repeat(32));
    let seen: Vec<(String, Option<&str>, Option<String>)> = r
        .notes
        .lock()
        .expect("notes")
        .iter()
        .map(|(s, n)| (s.clone(), n.outcome, n.reason.clone()))
        .collect();
    let want: Vec<(String, Option<&str>, Option<String>)> =
        ["signature", "envelope_fields", "generation", "clock_skew", "deadline"]
            .iter()
            .map(|r| (sid.clone(), Some("refused"), Some(r.to_string())))
            .collect();
    assert_eq!(seen, want);
    r.notes.lock().expect("notes").clear();

    let mut ws = connect(&r, &e, Opts::default()).await.expect("open");
    assert_eq!(echo(&mut ws, "hello").await, "hello");
    assert_eq!(
        *r.plugin.paths.lock().expect("paths"),
        vec![e["path"].as_str().unwrap_or_default().to_string()]
    );

    // The same ticket again, and then another call while the one slot is taken.
    assert_eq!(connect(&r, &e, Opts::default()).await.err(), Some(403));
    assert_eq!(last_diag(&r).as_deref(), Some("refused reason=concurrency"));
    let mut next = envelope('f', 10_000);
    next["callSid"] = json!(format!("CA{}", "b".repeat(32)));
    assert_eq!(connect(&r, &next, Opts::default()).await.err(), Some(403));
    assert_eq!(
        r.plugin.paths.lock().expect("paths").len(),
        1,
        "default concurrency refuses another"
    );
    assert_eq!(last_diag(&r).as_deref(), Some("refused reason=concurrency"));

    r.binding.lock().expect("b").as_mut().expect("b").max_concurrent_calls = Some(2);
    let mut second = connect(&r, &next, Opts::default()).await.expect("second");
    assert_eq!(echo(&mut second, "second").await, "second");
    ws.close(None).await.expect("close");
    close_code(&mut ws).await;
    assert_eq!(echo(&mut second, "still open").await, "still open");
    // The settings go: the stream ends.
    let live = r.binding.lock().expect("b").take();
    close_code(&mut second).await;
    assert!(r.diagnostics.lock().expect("diag").is_empty());
    *r.binding.lock().expect("b") = live;

    // The plugin refuses the upgrade: the firewall learns its status.
    r.plugin.refuse.store(true, Ordering::SeqCst);
    let mut refused = connect(&r, &envelope('1', 10_000), Opts::default())
        .await
        .expect("open");
    assert_eq!(
        close_code(&mut refused).await,
        Some(4401),
        "the firewall learns the plugin refused with 401"
    );
    assert!(
        r.notes
            .lock()
            .expect("notes")
            .iter()
            .any(|(_, n)| n.local_code == Some(4401))
    );
    let diags = r.diagnostics.lock().expect("diag").clone();
    assert!(diags.contains(&"local_upgrade_refused status=401".to_string()));
    assert!(!diags.join(" ").contains("CC-TWILIO-"));
    r.plugin.refuse.store(false, Ordering::SeqCst);

    // T-138: a few seconds of clock drift either way must not refuse the stream; the deadline
    // moves onto the agent's clock.
    for (c, skew_s) in [('7', 3), ('8', -3)] {
        let p = envelope(c, skew_s * 1000 + 300_000);
        let mut drifted = connect(
            &r,
            &p,
            Opts {
                skew_s,
                ..Default::default()
            },
        )
        .await
        .expect("drifted");
        assert_eq!(echo(&mut drifted, "drift").await, "drift");
        drifted.close(None).await.expect("close");
        close_code(&mut drifted).await;
    }

    // The plugin closing an open stream is reported as such, not as a bare 1006.
    let mut open = connect(&r, &envelope('c', 10_000), Opts::default())
        .await
        .expect("open");
    assert_eq!(echo(&mut open, "ping").await, "ping");
    r.plugin.hang_up.send_modify(|n| *n += 1);
    assert_eq!(close_code(&mut open).await, Some(4013));

    // Nothing listening on the plugin port.
    r.plugin.stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut nobody = connect(&r, &envelope('d', 10_000), Opts::default())
        .await
        .expect("open");
    assert_eq!(close_code(&mut nobody).await, Some(4010));
    assert!(
        r.diagnostics
            .lock()
            .expect("diag")
            .contains(&"local_listener_unavailable".to_string())
    );
}

#[tokio::test]
async fn other_upgrades_and_reused_tickets_are_refused() {
    let r = rig().await;
    let mut req = r
        .url
        .replace("/phone/stream", "/phone/stream?x=1")
        .into_client_request()
        .expect("req");
    req.headers_mut()
        .insert("authorization", HeaderValue::from_static("Bearer x"));
    assert!(matches!(
        tokio_tungstenite::connect_async(req).await,
        Err(WsError::Http(resp)) if resp.status() == 403
    ));
    assert_eq!(last_diag(&r).as_deref(), Some("refused reason=route"));
    let e = envelope('9', 10_000);
    let mut ws = connect(&r, &e, Opts::default()).await.expect("open");
    ws.close(None).await.expect("close");
    close_code(&mut ws).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(connect(&r, &e, Opts::default()).await.err(), Some(403));
    assert_eq!(last_diag(&r).as_deref(), Some("refused reason=ticket_used"));
    // No phone settings at all.
    *r.binding.lock().expect("b") = None;
    assert_eq!(
        connect(&r, &envelope('2', 10_000), Opts::default()).await.err(),
        Some(403)
    );
    assert_eq!(last_diag(&r).as_deref(), Some("refused reason=not_assigned"));
    // Binary frames end the stream.
    *r.binding.lock().expect("b") = Some(speech_binding());
    let mut ws = connect(&r, &envelope('3', 10_000), Opts::default())
        .await
        .expect("open");
    ws.send(Message::binary(vec![1u8, 2, 3])).await.expect("send");
    assert_eq!(close_code(&mut ws).await, None);
}

#[test]
fn js_coercions() {
    assert_eq!(js_number(Some(&json!("12"))), 12.0);
    assert_eq!(js_number(Some(&json!(null))), 0.0);
    assert!(js_number(Some(&json!({}))).is_nan());
    assert_eq!(js_number(Some(&json!([5]))), 5.0);
    assert_eq!(js_number(Some(&json!("0xD"))), 13.0);
    assert_eq!(js_number(Some(&json!("0b11"))), 3.0);
    assert!(js_number(Some(&json!("0x"))).is_nan());
    assert_eq!(js_string(Some(&json!(["CA", "x"]))), "CA,x");
    assert_eq!(js_string(Some(&json!(3))), "3");
    assert_eq!(close::refused(401), 4401);
    assert_eq!(close::refused(99), 4011);
    assert_eq!(decode_envelope("eyJhIjoxfQ"), r#"{"a":1}"#);
}

/// A burst from the firewall larger than the plugin side's 12 KB limit, in one flush, is relayed
/// in full, and so is the plugin's echo of it past the firewall side's limit when the frames come
/// back fast: the readers wait for their writers instead of ending the call.
#[tokio::test]
async fn a_burst_over_the_buffer_limits_is_relayed() {
    let r = rig().await;
    let mut ws = connect(&r, &envelope('5', 10_000), Opts::default())
        .await
        .expect("open");
    assert_eq!(echo(&mut ws, "warm up").await, "warm up");
    let frame = format!(r#"{{"event":"media","media":{{"payload":"{}"}}}}"#, "A".repeat(400));
    let count = 50;
    for i in 0..count {
        ws.feed(Message::text(format!("{i:02}{frame}"))).await.expect("feed");
    }
    ws.flush().await.expect("flush");
    assert!(count * frame.len() > 20_000);
    for i in 0..count {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                assert!(t.as_str().starts_with(&format!("{i:02}")), "frame {i} out of order")
            }
            other => panic!("frame {i} not echoed: {other:?}"),
        }
    }
    assert!(r.diagnostics.lock().expect("diag").is_empty());
}
