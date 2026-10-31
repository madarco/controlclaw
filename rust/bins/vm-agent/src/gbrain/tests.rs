//! `gbrain-gate.test.ts`, `gbrain-key.test.ts`, `gbrain-login.test.ts`, `gbrain-activity.test.ts`
//! and the reader cases of `gbrain-stats.test.ts`.

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cc_http::{Ctx, Req, Resp, Router};
use cc_proc::{Output, RecordingRunner, ok};
use http_body_util::BodyExt;
use serde_json::{Value, json};

use super::activity::{BrainActivity, Options, map_brain_event, read_cycle_report, split_sse};
use super::gate::{self, Admission, BrainGate, gate_allows, parse_connect, parse_lock};
use super::*;

const TOKEN_A: &str = "gbrain_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN_B: &str = "gbrain_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fail(stderr: &str) -> Output {
    Output {
        code: Some(1),
        stderr: stderr.as_bytes().to_vec(),
        ..Default::default()
    }
}

/// The token helper: TOKEN_A on the first create, TOKEN_B after.
fn helper() -> RecordingRunner {
    let r = RecordingRunner::new();
    let n = Arc::new(AtomicUsize::new(0));
    r.answer_with(move |c| {
        (c.args.get(1).map(String::as_str) == Some("create")).then(|| {
            ok(&format!(
                "{}\n",
                if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    TOKEN_A
                } else {
                    TOKEN_B
                }
            ))
        })
    });
    r.answer(&["sudo"], ok("revoked\n"));
    r
}

fn args(r: &RecordingRunner) -> Vec<Vec<String>> {
    r.calls().into_iter().map(|c| c.args[1..].to_vec()).collect()
}

fn quiet() -> Arc<dyn Fn(&str) + Send + Sync> {
    Arc::new(|_| {})
}

fn token(a: Admission) -> String {
    match a {
        Admission::Token(t) => t,
        other => panic!("not admitted: {other:?}"),
    }
}

#[test]
fn the_connect_body() {
    let b = |v: Value| v.as_object().cloned();
    assert_eq!(
        parse_connect(b(json!({"vmId": "vm-1", "ip": "10.0.0.3", "scope": "read"})).as_ref()),
        Ok(gate::ConnectInput {
            vm_id: "vm-1".into(),
            ip: "10.0.0.3".into(),
            scope: "read".into()
        })
    );
    assert!(parse_connect(b(json!({"vmId": "vm-1", "ip": "203.0.113.5", "scope": "read"})).as_ref()).is_err());
    assert!(parse_connect(b(json!({"vmId": "vm-1", "ip": "10.0.0.3", "scope": "admin"})).as_ref()).is_err());
    assert!(parse_connect(b(json!({"vmId": "../x", "ip": "10.0.0.3", "scope": "read"})).as_ref()).is_err());
    assert_eq!(parse_connect(None), Err("a JSON body is required"));
}

#[test]
fn only_mcp_passes_the_gate() {
    use http::Method;
    assert!(gate_allows(&Method::POST, "/mcp"));
    assert!(gate_allows(&Method::GET, "/mcp?x=1"));
    assert!(gate_allows(&Method::DELETE, "/mcp"));
    for p in [
        "/admin",
        "/admin/auth/x",
        "/oauth/token",
        "/.well-known/oauth-authorization-server",
        "/mcp/../admin",
        "/health",
    ] {
        assert!(!gate_allows(&Method::POST, p), "{p}");
    }
    assert!(!gate_allows(&Method::PUT, "/mcp"));
}

#[tokio::test]
async fn connect_mints_a_token_keeps_it_0600_and_replaces_old_ones() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gbrain-gate.json");
    let r = helper();
    let g = BrainGate::with_log(&path, Arc::new(r.clone()), quiet());
    g.connect(
        &parse_connect(json!({"vmId": "vm-a", "ip": "10.0.0.3", "scope": "read_write"}).as_object()).expect("in"),
    )
    .await
    .expect("connect");
    assert_eq!(token(g.admit("::ffff:10.0.0.3")), TOKEN_A);
    assert_eq!(
        std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
        0o600
    );
    // The list the firewall reads carries no token.
    assert!(!serde_json::to_string(&g.list()).expect("s").contains(TOKEN_A));
    assert_eq!(args(&r)[0], ["create", "vm-a", "read_write"]);
    assert_eq!(r.calls()[0].program, "sudo");
    assert_eq!(r.calls()[0].args[0], "/usr/local/bin/cc-gbrain-token");

    // vm-b takes the address over: vm-a's token is revoked.
    g.connect(&parse_connect(json!({"vmId": "vm-b", "ip": "10.0.0.3", "scope": "read"}).as_object()).expect("in"))
        .await
        .expect("connect");
    assert_eq!(token(g.admit("10.0.0.3")), TOKEN_B);
    assert_eq!(
        g.list().iter().map(|e| e["vmId"].clone()).collect::<Vec<_>>(),
        vec![json!("vm-b")]
    );
    assert_eq!(args(&r).last().expect("call"), &["revoke", "vm-a"]);

    // It survives a restart.
    assert_eq!(
        token(BrainGate::with_log(&path, Arc::new(r.clone()), quiet()).admit("10.0.0.3")),
        TOKEN_B
    );

    assert_eq!(g.disconnect("vm-b").await, Ok(true));
    assert_eq!(g.admit("10.0.0.3"), Admission::Unknown);
    assert_eq!(args(&r).last().expect("call"), &["revoke", "vm-b"]);
    assert!(!std::fs::read_to_string(&path).expect("file").contains(TOKEN_B));
}

#[tokio::test]
async fn the_emergency_stop_survives_a_restart() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("g.json");
    let r = helper();
    let g = BrainGate::with_log(&path, Arc::new(r.clone()), quiet());
    for (vm, ip) in [("vm-a", "10.0.0.3"), ("vm-b", "10.0.0.4")] {
        g.connect(&gate::ConnectInput {
            vm_id: vm.into(),
            ip: ip.into(),
            scope: "read".into(),
        })
        .await
        .expect("connect");
    }
    g.set_lock(gate::Lock {
        all: false,
        vm_ids: vec!["vm-a".into()],
    })
    .expect("lock");
    assert_eq!(g.admit("10.0.0.3"), Admission::Stopped);
    assert!(matches!(g.admit("10.0.0.4"), Admission::Token(_)));
    let again = BrainGate::with_log(&path, Arc::new(r.clone()), quiet());
    assert_eq!(again.admit("10.0.0.3"), Admission::Stopped);
    assert_eq!(
        again.lock(),
        gate::Lock {
            all: false,
            vm_ids: vec!["vm-a".into()]
        }
    );
    again
        .set_lock(gate::Lock {
            all: true,
            vm_ids: vec![],
        })
        .expect("lock");
    assert_eq!(again.admit("10.0.0.4"), Admission::Stopped);
    again.set_lock(gate::Lock::default()).expect("lock");
    assert!(
        matches!(again.admit("10.0.0.3"), Admission::Token(_)),
        "a release needs no new token"
    );
    assert!(parse_lock(json!({"all": "yes", "vmIds": []}).as_object()).is_err());
    assert!(parse_lock(json!({"all": false, "vmIds": ["../x"]}).as_object()).is_err());
    assert_eq!(
        parse_lock(json!({"all": false, "vmIds": ["b", "a", "b"]}).as_object()),
        Ok(gate::Lock {
            all: false,
            vm_ids: vec!["a".into(), "b".into()]
        })
    );
}

#[tokio::test]
async fn a_helper_that_prints_no_token_lets_nobody_in() {
    let dir = tempfile::tempdir().expect("dir");
    let r = RecordingRunner::new();
    r.answer(&["sudo"], ok("Token created\n"));
    let g = BrainGate::with_log(&dir.path().join("g.json"), Arc::new(r), quiet());
    let e = g
        .connect(&gate::ConnectInput {
            vm_id: "vm-a".into(),
            ip: "10.0.0.3".into(),
            scope: "read".into(),
        })
        .await
        .expect_err("no token");
    assert!(e.contains("no usable token"));
    assert!(g.list().is_empty());
    // A helper that fails says why, with its last line.
    let r = RecordingRunner::new();
    r.answer(&["sudo"], fail("warn\ncc-gbrain-token: GBrain is down\n"));
    let g = BrainGate::with_log(&dir.path().join("h.json"), Arc::new(r), quiet());
    let e = g
        .connect(&gate::ConnectInput {
            vm_id: "vm-a".into(),
            ip: "10.0.0.3".into(),
            scope: "read".into(),
        })
        .await
        .expect_err("failed");
    assert_eq!(
        e,
        "could not create the agent's brain token: cc-gbrain-token: GBrain is down"
    );
}

/// A server on a random port whose answers come from `f`.
async fn serve<F, Fut>(f: F) -> String
where
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Resp> + Send + 'static,
{
    let mut router = Router::new(&["all"]);
    let f = Arc::new(f);
    router.route("all", |_, _| true, move |req, _| f(req));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    addr
}

async fn send(addr: &str, method: &str, path: &str, auth: Option<&str>) -> (u16, String) {
    let c = reqwest::Client::new();
    let mut r = c
        .request(method.parse().expect("method"), format!("http://{addr}{path}"))
        .body("{}");
    if let Some(a) = auth {
        r = r.header("authorization", a);
    }
    let res = r.send().await.expect("send");
    (res.status().as_u16(), res.text().await.expect("text"))
}

#[tokio::test]
async fn the_gate_forwards_known_addresses_with_their_own_token() {
    let seen: Arc<Mutex<Vec<(String, String, String)>>> = Arc::default();
    let s = seen.clone();
    let upstream = serve(move |req| {
        let s = s.clone();
        async move {
            let h = |n: &str| {
                req.headers()
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            };
            s.lock()
                .expect("seen")
                .push((req.uri().to_string(), h("authorization"), h("host")));
            cc_http::json(200, &json!({"ok": true}))
        }
    })
    .await;
    let state: Arc<Mutex<Admission>> = Arc::new(Mutex::new(Admission::Unknown));
    let (st, up) = (state.clone(), upstream.clone());
    let mut router = Router::new(&["gate"]);
    router.route(
        "gate",
        |_, _| true,
        move |req: Req, ctx: Ctx| {
            let (st, up) = (st.clone(), up.clone());
            async move {
                let admit = move |_: &str| st.lock().expect("state").clone();
                gate::handle(&admit, &up, &|_| {}, req, ctx).await
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));

    assert_eq!(send(&addr, "POST", "/mcp", None).await.0, 403);
    assert!(seen.lock().expect("seen").is_empty());

    *state.lock().expect("s") = Admission::Token(TOKEN_A.into());
    assert_eq!(send(&addr, "POST", "/mcp", Some("Bearer stolen")).await.0, 200);
    let first = seen.lock().expect("seen")[0].clone();
    assert_eq!(first.1, format!("Bearer {TOKEN_A}"));
    assert_eq!(first.2, upstream);

    assert_eq!(send(&addr, "GET", "/admin", None).await.0, 404);
    assert_eq!(seen.lock().expect("seen").len(), 1);

    *state.lock().expect("s") = Admission::Stopped;
    let (status, body) = send(&addr, "POST", "/mcp", None).await;
    assert_eq!(status, 403);
    assert!(body.contains("emergency stop"));
    assert_eq!(seen.lock().expect("seen").len(), 1);
}

#[tokio::test]
async fn the_gate_lets_go_of_gbrain_when_the_agent_hangs_up() {
    // GBrain streams events until its reader is gone.
    let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel::<()>();
    let upstream = serve(move |_req| {
        let closed_tx = closed_tx.clone();
        async move {
            let (tx, rx) =
                tokio::sync::mpsc::channel::<Result<hyper::body::Frame<hyper::body::Bytes>, std::io::Error>>(1);
            tokio::spawn(async move {
                loop {
                    let frame = hyper::body::Frame::data(hyper::body::Bytes::from_static(b"data: {}\n\n"));
                    if tx.send(Ok(frame)).await.is_err() {
                        let _ = closed_tx.send(());
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            });
            let body = http_body_util::StreamBody::new(tokio_stream_from(rx));
            let mut r = http::Response::new(BodyExt::boxed(body));
            r.headers_mut()
                .insert("content-type", "text/event-stream".parse().expect("ct"));
            r
        }
    })
    .await;
    let mut router = Router::new(&["gate"]);
    router.route(
        "gate",
        |_, _| true,
        move |req: Req, ctx: Ctx| {
            let up = upstream.clone();
            async move {
                let admit = |_: &str| Admission::Token(TOKEN_A.into());
                gate::handle(&admit, &up, &|_| {}, req, ctx).await
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    let mut res = reqwest::get(format!("http://{addr}/mcp")).await.expect("get");
    assert_eq!(res.status(), 200);
    assert!(res.chunk().await.expect("chunk").is_some());
    drop(res);
    let gone = tokio::time::timeout(std::time::Duration::from_secs(5), closed.recv()).await;
    assert!(
        matches!(gone, Ok(Some(()))),
        "GBrain's stream was not closed after the agent hung up"
    );
}

#[tokio::test]
async fn the_gate_lets_go_of_gbrain_when_the_agent_hangs_up_before_an_answer() {
    use tokio::io::AsyncReadExt;
    // A GBrain that takes the request and never answers (a long `think`).
    let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let upstream = up.local_addr().expect("addr").to_string();
    let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        let (mut s, _) = up.accept().await.expect("accept");
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = closed_tx.send(());
                    return;
                }
                Ok(_) => {}
            }
        }
    });
    let mut router = Router::new(&["gate"]);
    router.route(
        "gate",
        |_, _| true,
        move |req: Req, ctx: Ctx| {
            let up = upstream.clone();
            async move {
                let admit = |_: &str| Admission::Token(TOKEN_A.into());
                gate::handle(&admit, &up, &|_| {}, req, ctx).await
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    let call = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .body("{}")
        .send();
    // The agent gives up before GBrain answers.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), call)
            .await
            .is_err()
    );
    let gone = tokio::time::timeout(std::time::Duration::from_secs(5), closed.recv()).await;
    assert!(
        matches!(gone, Ok(Some(()))),
        "GBrain's connection stayed open after the agent hung up"
    );
}

/// A body stream from a channel's receiver.
fn tokio_stream_from<T: Send + 'static>(
    mut rx: tokio::sync::mpsc::Receiver<T>,
) -> impl futures_util::Stream<Item = T> + Send + 'static {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

const PLACEHOLDER: &str = "vck-cc-included-AbCd1234xYz09Qwe";

#[test]
fn the_brain_key_is_only_a_placeholder() {
    let b = |v: Value| v.as_object().cloned();
    assert_eq!(
        key::parse(
            b(json!({"credentials": [], "memory": {"provider": "openai-compatible", "apiKey": PLACEHOLDER}})).as_ref()
        ),
        Ok(key::BrainKey::Key(PLACEHOLDER.into()))
    );
    assert_eq!(
        key::parse(b(json!({"credentials": [], "memory": null})).as_ref()),
        Ok(key::BrainKey::Clear)
    );
    for api_key in [
        json!("sk-proj-abc123abc123abc123"),
        json!("vck-cc-included-"),
        json!("vck-cc-included-short"),
        json!("vck-cc-included-has spaces here"),
        json!(format!("{PLACEHOLDER}\nOPENAI_BASE_URL=https://evil.example")),
        json!(""),
        json!(42),
    ] {
        assert!(
            key::parse(b(json!({"memory": {"apiKey": api_key}})).as_ref()).is_err(),
            "{api_key}"
        );
    }
    assert!(key::parse(b(json!({"credentials": []})).as_ref()).is_err());
    assert!(key::parse(None).is_err());
}

#[tokio::test]
async fn the_brain_key_goes_on_stdin() {
    let r = RecordingRunner::new();
    r.answer(&["sudo"], ok("changed\n"));
    assert_eq!(key::apply(&key::BrainKey::Key(PLACEHOLDER.into()), &r).await, Ok(true));
    let c = &r.calls()[0];
    assert_eq!(
        (c.program.as_str(), c.args.clone()),
        ("sudo", vec!["/usr/local/bin/cc-gbrain-key".to_string()])
    );
    assert_eq!(c.stdin.as_deref(), Some(format!("{PLACEHOLDER}\n").as_bytes()));

    let r = RecordingRunner::new();
    r.answer(&["sudo"], ok("unchanged\n"));
    assert_eq!(key::apply(&key::BrainKey::Clear, &r).await, Ok(false));
    assert_eq!(r.calls()[0].stdin.as_deref(), Some(&b"-\n"[..]));

    let r = RecordingRunner::new();
    r.answer(&["sudo"], fail("cc-gbrain-key: no env file"));
    let e = key::apply(&key::BrainKey::Key(PLACEHOLDER.into()), &r)
        .await
        .expect_err("fails");
    assert!(e.starts_with("could not set the brain's model key"));
}

#[tokio::test]
async fn the_login_link() {
    assert_eq!(
        login::parse_login_link("https://brain-x.ccl.bot/admin/auth/Ab_c-1.2~3\n").as_deref(),
        Some("/admin/auth/Ab_c-1.2~3")
    );
    assert_eq!(
        login::parse_login_link("noise\nhttps://brain-x.ccl.bot/admin/auth/tok").as_deref(),
        Some("/admin/auth/tok")
    );
    for bad in [
        "http://brain-x.ccl.bot/admin/auth/tok",
        "https://evil.example/elsewhere",
        "https://brain-x.ccl.bot/admin/auth/tok?x=https://evil",
        "",
    ] {
        assert_eq!(login::parse_login_link(bad), None, "{bad}");
    }
    let r = RecordingRunner::new();
    r.answer(&["sudo"], fail("cc-gbrain-login-link: GBrain is not running"));
    assert!(
        login::login_path(&r)
            .await
            .expect_err("fails")
            .contains("GBrain is not running")
    );
    let r = RecordingRunner::new();
    r.answer(&["sudo"], ok("hello"));
    assert!(login::login_path(&r).await.expect_err("junk").contains("no login link"));
    let r = RecordingRunner::new();
    r.answer(&["sudo"], ok("https://b.ccl.bot/admin/auth/t1\n"));
    assert_eq!(login::login_path(&r).await.as_deref(), Ok("/admin/auth/t1"));
}

// What GBrain 0.60.10 put on /admin/events for a put_page through the gate.
const PUT: &str = r#"{"agent":"cc-og16xfj078hb36bavvml91or","operation":"put_page","params":{"redacted":true,"kind":"object","declared_keys":["content","slug"],"unknown_key_count":0,"approx_bytes":1024},"scopes":"read,write","latency_ms":341,"status":"success","timestamp":"2026-09-30T14:45:11.051Z"}"#;

#[test]
fn an_agents_call_becomes_a_record_with_no_content() {
    let r = map_brain_event(PUT).expect("record");
    assert_eq!(r["source"], "brain_call");
    assert_eq!(r["agent_vm_id"], "og16xfj078hb36bavvml91or");
    assert_eq!(r["operation"], "put_page");
    assert_eq!(r["ok"], true);
    assert_eq!(r["duration_ms"], 341);
    assert_eq!(r["ts"].as_f64(), Some(1_790_779_511.051));
    assert_eq!(map_brain_event(PUT).expect("again")["call_id"], r["call_id"]);
    assert_eq!(r["call_id"].as_str().map(str::len), Some(40));
    assert!(!r.to_string().contains("declared_keys"));
}

#[test]
fn only_the_gates_agents() {
    assert!(map_brain_event(&PUT.replace("cc-og16xfj078hb36bavvml91or", "claude-desktop")).is_none());
    assert!(map_brain_event("not json").is_none());
    assert!(map_brain_event(r#"{"agent":"cc-x","timestamp":"2026-09-30T00:00:00Z"}"#).is_none());
    assert_eq!(
        map_brain_event(&PUT.replace("\"success\"", "\"error\"")).expect("r")["ok"],
        false
    );
    assert!(map_brain_event(&PUT.replace("\"put_page\"", "\"tools/list\"")).is_none());
}

#[test]
fn sse_comments_and_partial_blocks() {
    let (events, rest) = split_sse(&format!(
        ": connected\n\ndata: {PUT}\n\ndata: {{\"a\":1}}\n\ndata: {{\"part"
    ));
    assert_eq!(events, vec![PUT.to_string(), "{\"a\":1}".to_string()]);
    assert_eq!(rest, "data: {\"part");
}

#[test]
fn the_nightly_report() {
    let r = read_cycle_report(
        &json!({"finished_at": "2026-10-01T02:31:00.000Z", "exit_code": 0, "status": "ok", "duration_ms": 195000.4, "cost_usd": 0.0241, "model_calls": 88, "totals": {"pages_extracted": 12, "note": "x"}})
            .to_string(),
    )
    .expect("report");
    assert_eq!(r["cycle_id"], "2026-10-01T02:31:00.000Z");
    assert_eq!(r["cost_usd"], 0.0241);
    assert_eq!(r["duration_ms"], 195000);
    assert_eq!(r["totals"], json!({"pages_extracted": 12}));
    assert!(read_cycle_report("{").is_none());
    assert!(read_cycle_report(r#"{"status":"ok"}"#).is_none());
    assert_eq!(
        activity::parse_iso("2026-10-01T04:31:00+02:00"),
        activity::parse_iso("2026-10-01T02:31:00Z")
    );
}

/// A fake console and GBrain: the console answers `status`; GBrain hands out cookies `c1`, `c2`
/// and refuses `c1` on its stats.
struct Fakes {
    url: String,
    posted: Arc<Mutex<Vec<Value>>>,
    status: Arc<Mutex<u16>>,
    seen: Arc<Mutex<Vec<String>>>,
    stats: Arc<Mutex<VecDeque<(u16, Value)>>>,
}

async fn fakes() -> Fakes {
    let posted: Arc<Mutex<Vec<Value>>> = Arc::default();
    let status = Arc::new(Mutex::new(503u16));
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let stats: Arc<Mutex<VecDeque<(u16, Value)>>> = Arc::default();
    let cookies = Arc::new(AtomicUsize::new(0));
    let (p, st, sn, sts) = (posted.clone(), status.clone(), seen.clone(), stats.clone());
    let addr = serve(move |req| {
        let (p, st, sn, sts, cookies) = (p.clone(), st.clone(), sn.clone(), sts.clone(), cookies.clone());
        async move {
            let path = req.uri().path().to_string();
            if path.starts_with("/admin/auth/") {
                let n = cookies.fetch_add(1, Ordering::SeqCst) + 1;
                let mut r = cc_http::empty(302);
                r.headers_mut().insert(
                    "set-cookie",
                    format!("gbrain_admin=c{n}; Path=/; HttpOnly").parse().expect("cookie"),
                );
                return r;
            }
            if path == "/admin/api/full-stats" {
                let cookie = req
                    .headers()
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                sn.lock().expect("seen").push(format!("{path} {cookie}"));
                let (code, body) = sts.lock().expect("stats").pop_front().unwrap_or((200, json!({})));
                return cc_http::json(code, &body);
            }
            let body = req.into_body().collect().await.expect("body").to_bytes();
            p.lock()
                .expect("posted")
                .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
            let code = *st.lock().expect("status");
            cc_http::json(code, &json!({}))
        }
    })
    .await;
    Fakes {
        url: format!("http://{addr}"),
        posted,
        status,
        seen,
        stats,
    }
}

fn reader(f: &Fakes, report: &std::path::Path, cursor: &std::path::Path) -> Arc<BrainActivity> {
    BrainActivity::new(Options {
        console_http: Arc::new(reqwest::Client::new),
        gbrain_url: f.url.clone(),
        login_path: Arc::new(|| Box::pin(async { Ok("/admin/auth/tok".to_string()) })),
        activity_url: format!("{}/api/vm-agent/activity", f.url),
        token: Arc::new(|| Ok("tok".into())),
        report_path: report.to_path_buf(),
        cursor_path: cursor.to_path_buf(),
        disk: None,
        log: Arc::new(|_| {}),
    })
}

#[tokio::test]
async fn a_nightly_run_is_shipped_once() {
    let dir = tempfile::tempdir().expect("dir");
    let report = dir.path().join("last-cycle.json");
    let cursor = dir.path().join("state").join("brain-cycle.cursor");
    std::fs::write(
        &report,
        json!({"finished_at": "2026-10-01T02:31:00.000Z", "exit_code": 0, "status": "ok", "cost_usd": 0.02, "totals": {}})
            .to_string(),
    )
    .expect("report");
    let f = fakes().await;
    let a = reader(&f, &report, &cursor);
    a.check_cycle().await.expect("cycle");
    assert_eq!(f.posted.lock().expect("p").len(), 1);
    *f.status.lock().expect("s") = 200;
    a.check_cycle().await.expect("cycle");
    assert_eq!(
        std::fs::read_to_string(&cursor).expect("cursor"),
        "2026-10-01T02:31:00.000Z"
    );
    a.check_cycle().await.expect("cycle");
    assert_eq!(f.posted.lock().expect("p").len(), 2, "not shipped again");
}

#[tokio::test]
async fn calls_are_batched_kept_and_capped() {
    let f = fakes().await;
    *f.status.lock().expect("s") = 502;
    let a = reader(
        &f,
        std::path::Path::new("/nonexistent"),
        std::path::Path::new("/nonexistent2"),
    );
    for i in 0..2500 {
        a.enqueue(map_brain_event(&PUT.replace("14:45:11.051Z", &format!("14:45:11.{:03}Z", i % 1000))).expect("r"));
    }
    assert_eq!(a.pending(), 2000);
    a.flush().await.expect("flush");
    assert_eq!(a.pending(), 2000);
    *f.status.lock().expect("s") = 200;
    a.flush().await.expect("flush");
    assert_eq!(a.pending(), 0);
    let sizes: Vec<usize> = f
        .posted
        .lock()
        .expect("p")
        .iter()
        .map(|b| b["records"].as_array().map_or(0, Vec::len))
        .collect();
    assert!(sizes[1..].iter().all(|n| *n <= 200));
}

#[tokio::test]
async fn stats_with_the_admin_cookie_replacing_a_refused_one_once() {
    let f = fakes().await;
    let full: Value = serde_json::from_str(
        r#"{"status":"ok","page_count":10000,"chunk_count":10000,"pages_by_type":{"project":2022}}"#,
    )
    .expect("json");
    f.stats.lock().expect("s").extend([(401, json!({})), (200, full)]);
    let a = reader(
        &f,
        std::path::Path::new("/nonexistent"),
        std::path::Path::new("/nonexistent"),
    );
    a.read_stats().await.expect("stats");
    assert_eq!(
        *f.seen.lock().expect("seen"),
        vec![
            "/admin/api/full-stats gbrain_admin=c1",
            "/admin/api/full-stats gbrain_admin=c2"
        ]
    );
    assert_eq!(a.pending(), 1);
    assert_eq!(a.admin_cookie().await.as_deref(), Ok("c3"));
}

#[tokio::test]
async fn a_stats_read_that_fails_queues_nothing() {
    let f = fakes().await;
    f.stats
        .lock()
        .expect("s")
        .push_back((503, json!({"error": "service_unavailable"})));
    let a = reader(
        &f,
        std::path::Path::new("/nonexistent"),
        std::path::Path::new("/nonexistent"),
    );
    assert!(a.read_stats().await.expect_err("fails").contains("HTTP 503"));
    assert_eq!(a.pending(), 0);
}

#[test]
fn the_private_address_is_the_first_interfaces() {
    let trie = "Local:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 10.9.0.1\n        /32 host LOCAL\n     |-- 10.0.0.3\n        /32 host LOCAL\n     |-- 127.0.0.1\n        /32 host LOCAL\n";
    let routes = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                  wg0\t0000090A\t00000000\t0001\t0\t0\t0\t0000FFFF\n\
                  enp7s0\t0000000A\t0100000A\t0003\t0\t0\t0\t0000FFFF\n";
    let devs = "h1\nh2\n    lo: 0\nenp7s0: 0\n  wg0: 0\n";
    assert_eq!(
        gate::pick_private_address(trie, routes, devs).as_deref(),
        Some("10.0.0.3")
    );
    // Without routes, the order the kernel lists them in.
    assert_eq!(gate::pick_private_address(trie, "", "").as_deref(), Some("10.9.0.1"));
    assert_eq!(
        gate::pick_private_address("Local:\n |-- 172.17.0.1\n  /32 host LOCAL\n", "", ""),
        None
    );
}

#[test]
fn a_gate_file_from_the_node_build_keeps_entries_with_missing_fields() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("g.json");
    std::fs::write(
        &path,
        format!(r#"{{"version":1,"entries":[{{"ip":"10.0.0.7","token":"{TOKEN_A}","vmId":"vm-x","note":"kept"}},{{"ip":5,"token":"x"}}]}}"#),
    )
    .expect("seed");
    let g = BrainGate::with_log(&path, Arc::new(RecordingRunner::new()), quiet());
    assert_eq!(token(g.admit("10.0.0.7")), TOKEN_A);
    assert_eq!(g.list(), vec![json!({"vmId": "vm-x", "ip": "10.0.0.7"})]);
    g.set_lock(gate::Lock::default()).expect("save");
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("file")).expect("json");
    assert_eq!(saved["entries"][0]["note"], "kept");
    assert!(saved["entries"][0].get("at").is_none());
}

#[test]
fn failure_lines() {
    let out = fail("\u{1b}[31mfirst\u{1b}[0m\nlast line\n\n");
    assert_eq!(exec_failure_line(Some(&out), "sudo x", None), "last line");
    assert_eq!(
        exec_failure_line(Some(&Output::default()), "sudo x", None),
        "Command failed: sudo x"
    );
    assert_eq!(
        exec_failure_line(None, "sudo x", Some("spawn sudo ENOENT")),
        "spawn sudo ENOENT"
    );
}

/// A disconnect that arrives while a connect waits for its token is not undone by that connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disconnect_during_a_connect_stays() {
    let dir = tempfile::tempdir().expect("dir");
    let r = RecordingRunner::new();
    r.answer_with(|c| {
        (c.args.get(1).map(String::as_str) == Some("create")).then(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            ok(&format!("{TOKEN_A}\n"))
        })
    });
    r.answer(&["sudo"], ok("revoked\n"));
    let g = Arc::new(BrainGate::with_log(&dir.path().join("g.json"), Arc::new(r), quiet()));
    let input = gate::ConnectInput {
        vm_id: "vm-a".into(),
        ip: "10.0.0.3".into(),
        scope: "read".into(),
    };
    let c = {
        let g = g.clone();
        tokio::spawn(async move { g.connect(&input).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    g.disconnect("vm-a").await.expect("disconnect");
    c.await.expect("join").expect("connect");
    // The connect ran first, whole; the disconnect after it.
    assert_eq!(g.admit("10.0.0.3"), Admission::Unknown);
    assert!(g.list().is_empty());
}

/// Request errors never carry the URL: the login link's path is a one-use admin token.
#[tokio::test]
async fn activity_errors_leave_the_url_out() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = closed.local_addr().expect("addr").port();
    drop(closed);
    let a = BrainActivity::new(Options {
        console_http: Arc::new(reqwest::Client::new),
        gbrain_url: format!("http://127.0.0.1:{port}"),
        login_path: Arc::new(|| Box::pin(async { Ok("/admin/auth/SECRET-ONE-USE".to_string()) })),
        activity_url: format!("http://127.0.0.1:{port}/api/vm-agent/activity?t=SECRET"),
        token: Arc::new(|| Ok("tok".into())),
        report_path: "/nonexistent".into(),
        cursor_path: "/nonexistent".into(),
        disk: None,
        log: Arc::new(|_| {}),
    });
    let e = a.admin_cookie().await.expect_err("nothing listens");
    assert!(!e.contains("SECRET") && !e.contains("/admin/auth"), "{e}");
    a.enqueue(json!({"source": "brain_call"}));
    let e = a.flush().await.expect_err("nothing listens");
    assert!(!e.contains("SECRET"), "{e}");
}

/// A stored token that cannot be a header gives a 502, and the agent's own one never goes on.
#[tokio::test]
async fn an_unusable_token_is_a_502() {
    let seen: Arc<Mutex<usize>> = Arc::default();
    let s = seen.clone();
    let upstream = serve(move |_req| {
        let s = s.clone();
        async move {
            *s.lock().expect("seen") += 1;
            cc_http::json(200, &json!({}))
        }
    })
    .await;
    let mut router = Router::new(&["gate"]);
    router.route(
        "gate",
        |_, _| true,
        move |req: Req, ctx: Ctx| {
            let up = upstream.clone();
            async move {
                let admit = |_: &str| Admission::Token("bad\ntoken".into());
                gate::handle(&admit, &up, &|_| {}, req, ctx).await
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    assert_eq!(send(&addr, "POST", "/mcp", Some("Bearer the-agents-own")).await.0, 502);
    assert_eq!(*seen.lock().expect("seen"), 0);
}

/// The production listener (`serve_gate`) with a real `BrainGate`: who it knows comes from
/// `gbrain-gate.json` by the caller's address, a header the caller set for its address never
/// reaches GBrain, and the emergency stop holds.
#[tokio::test]
async fn serve_gate_admits_by_the_callers_address_and_drops_its_forwarded_for() {
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let s = seen.clone();
    let upstream = serve(move |req| {
        let s = s.clone();
        async move {
            let h = |n: &str| {
                req.headers()
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            };
            s.lock().expect("seen").push((h("authorization"), h("x-forwarded-for")));
            cc_http::json(200, &json!({"ok": true}))
        }
    })
    .await;
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("gbrain-gate.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "version": 1,
            "entries": [{"vmId": "vm-1", "ip": "127.0.0.1", "scope": "read", "token": TOKEN_A}],
            "lock": {"all": false, "vmIds": []},
        }))
        .expect("json"),
    )
    .expect("write");
    let brain = Arc::new(BrainGate::with_log(&path, Arc::new(RecordingRunner::new()), quiet()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    tokio::spawn(serve_gate(listener, brain.clone(), upstream));

    let res = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("x-forwarded-for", "10.0.0.9")
        .header("authorization", "Bearer stolen")
        .body("{}")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(
        seen.lock().expect("seen").clone(),
        vec![(format!("Bearer {TOKEN_A}"), String::new())]
    );

    let mut lock = brain.lock();
    lock.vm_ids = vec!["vm-1".into()];
    brain.set_lock(lock).expect("lock");
    let (status, body) = send(&addr, "POST", "/mcp", None).await;
    assert_eq!(status, 403);
    assert!(body.contains("emergency stop"));
    assert_eq!(seen.lock().expect("seen").len(), 1);
}
