//! `teamchat-gate.test.ts`: the chat gate with real sockets, a fake ClickClack behind it.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::integrations::testing::{Answer, FakeServer, Got};

struct Gate {
    base: String,
    log: std::path::PathBuf,
    locked: Arc<Mutex<Vec<String>>>,
    ip_of_a: Arc<Mutex<String>>,
    _dir: tempfile::TempDir,
}

fn resolver(ip_of_a: Arc<Mutex<String>>) -> Resolve {
    Arc::new(move |p| match p {
        "cctc_a" => Some((
            "vm-a".into(),
            "ccb_real_a".into(),
            ip_of_a.lock().expect("lock").clone(),
        )),
        "cctc_b" => Some(("vm-b".into(), "ccb_real_b".into(), "10.0.0.4".into())),
        _ => None,
    })
}

async fn listen(g: Arc<TeamChatGate>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", l.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(l, Arc::new(g.router())));
    base
}

async fn gate(target: u16, content: Arc<dyn Fn() -> ChatContentNow + Send + Sync>) -> Gate {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("traffic.jsonl");
    std::fs::write(&log, "").expect("log");
    let locked: Arc<Mutex<Vec<String>>> = Arc::default();
    let ip_of_a = Arc::new(Mutex::new("127.0.0.1".to_string()));
    let l2 = locked.clone();
    let g = TeamChatGate::new(GateOptions {
        target: ("127.0.0.1".into(), target),
        resolve: resolver(ip_of_a.clone()),
        locked: Arc::new(move |vm| l2.lock().expect("lock").iter().any(|x| x == vm)),
        content,
        log_path: Some(log.clone()),
    });
    Gate {
        base: listen(g).await,
        log,
        locked,
        ip_of_a,
        _dir: dir,
    }
}

impl Gate {
    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("line"))
            .collect()
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().expect("client")
}

async fn get(base: &str, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut r = client().get(format!("{base}{path}"));
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.send().await.expect("send")
}

#[test]
fn webhooks_and_odd_spellings_of_a_path_are_refused() {
    assert!(!gate_allows("/api/hooks/slash/abc"));
    assert!(!gate_allows("/API/Hooks/slash/abc"));
    assert!(!gate_allows("/api/%61uth/x"));
    assert!(!gate_allows("/api/channels/x\\..\\auth"));
    assert!(!gate_allows("/api//auth"));
    assert!(!gate_allows("/api/./auth"));
    assert!(!gate_allows("/api/channels/../auth"));
    assert!(gate_allows("/api/channels/chn_1/messages?after=1"));
    assert!(MESSAGE_POST.is_match("/api/messages/msg_1/thread/replies"));
    assert!(!MESSAGE_POST.is_match("/api/messages/msg_1/replies"));
}

#[test]
fn every_visible_field_is_read_in_any_case() {
    let doc = serde_json::json!({"Display_Name": "a", "EMOJI": "b", "avatar_url": "c", "other": "d", "items": [{"label": "e"}]});
    let mut out = Vec::new();
    chat_text(&doc, false, 0, &mut out).expect("text");
    out.sort();
    assert_eq!(out, ["a", "b", "c", "e"]);
}

#[test]
fn only_the_chat_api_and_activity_paths_carry_no_ids_and_no_query() {
    assert!(gate_allows("/api/channels/chn_1/messages"));
    assert!(gate_allows("/api/realtime/ws"));
    assert!(!gate_allows("/api/auth/magic/consume"));
    assert!(!gate_allows("/api/bot-setup-codes/claim"));
    assert!(!gate_allows("/app"));
    assert!(!gate_allows("/healthz"));
    assert_eq!(
        template_path("/api/channels/chn_01m438dsf8j5gqgk0yfxnracf6/messages?after=5"),
        "/api/channels/[id]/messages"
    );
    assert_eq!(
        template_path("/api/messages/by-nonce?nonce=secret"),
        "/api/messages/by-nonce"
    );
    assert_eq!(
        template_path("/api/uploads/upl_01m438dsf8j5gqgk0yf"),
        "/api/uploads/[id]"
    );
}

#[tokio::test]
async fn the_swap_the_refusals_the_stop_the_cap_and_the_metadata_line() {
    let up = FakeServer::start(|g: &Got| Answer::json(200, &json!({"ok": true, "body": g.body.len()}))).await;
    let g = gate(up.port, Arc::new(|| ChatContentNow::Off)).await;
    // The placeholder becomes the real token, and the caller's own credentials are dropped.
    let r = get(
        &g.base,
        "/api/me",
        &[
            ("authorization", "Bearer cctc_a"),
            ("cookie", "__Host-cc-teamchat-session=x"),
            ("x-clickclack-user", "usr_owner"),
            ("x-forwarded-for", "1.2.3.4"),
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    let seen = up.got()[0].clone();
    assert_eq!(seen.headers["authorization"], "Bearer ccb_real_a");
    assert!(
        seen.headers.get("cookie").is_none()
            && seen.headers.get("x-clickclack-user").is_none()
            && seen.headers.get("x-forwarded-for").is_none()
    );
    assert_eq!(seen.headers["host"], format!("127.0.0.1:{}", up.port).as_str());
    // An unknown token, a real token, or none: a bare 404 and nothing upstream.
    up.clear();
    for auth in ["Bearer cctc_nope", "Bearer ccb_real_a", ""] {
        let h: Vec<(&str, &str)> = if auth.is_empty() {
            vec![]
        } else {
            vec![("authorization", auth)]
        };
        let r = get(&g.base, "/api/me", &h).await;
        assert_eq!(r.status(), 404);
        assert_eq!(r.text().await.expect("text"), "");
    }
    // Another agent's placeholder from this address: 404, logged against that agent.
    assert_eq!(
        get(&g.base, "/api/me", &[("authorization", "Bearer cctc_b")])
            .await
            .status(),
        404
    );
    let last = g.records().last().cloned().expect("line");
    assert_eq!((&last["vm_id"], &last["effect"]), (&json!("vm-b"), &json!("drop")));
    assert!(last["rule"].as_str().unwrap_or("").contains("wrong address"));
    // A path outside the chat API, or one with dot segments: 404 even with a good token.
    // Encoded as ClickClack may decode it: `%61` is `a`, `%2F` is `/`, `%2D` is `-`.
    for p in [
        "/api/auth/magic/consume",
        "/api/x/%2e%2e/auth/magic/consume",
        "/api/%61uth/magic/consume",
        "/api/me%2Fpush",
        "/api/bot%2Dsetup-codes/claim",
    ] {
        assert_eq!(
            get(&g.base, p, &[("authorization", "Bearer cctc_a")]).await.status(),
            404,
            "{p}"
        );
    }
    assert!(up.got().is_empty());
    // An agent under an emergency stop: 403.
    g.locked.lock().expect("lock").push("vm-a".into());
    assert_eq!(
        get(&g.base, "/api/me", &[("authorization", "Bearer cctc_a")])
            .await
            .status(),
        403
    );
    g.locked.lock().expect("lock").clear();
    // An agent whose address changed is refused on its old placeholder until the map catches up.
    *g.ip_of_a.lock().expect("lock") = "10.0.0.9".into();
    assert_eq!(
        get(&g.base, "/api/me", &[("authorization", "Bearer cctc_a")])
            .await
            .status(),
        404
    );
    *g.ip_of_a.lock().expect("lock") = "127.0.0.1".into();
    // A body over the cap is refused before it is read.
    let addr = g.base.trim_start_matches("http://").to_string();
    let mut s = tokio::net::TcpStream::connect(&addr).await.expect("connect");
    s.write_all(
        format!(
            "POST /api/uploads HTTP/1.1\r\nhost: x\r\nauthorization: Bearer cctc_a\r\ncontent-length: {}\r\n\r\nx",
            80 * 1024 * 1024
        )
        .as_bytes(),
    )
    .await
    .expect("write");
    let mut head = [0u8; 12];
    s.read_exact(&mut head).await.expect("read");
    assert_eq!(&head, b"HTTP/1.1 413");
    // Every request is in the traffic log as metadata.
    std::fs::write(&g.log, "").expect("log");
    let r = client()
        .post(format!(
            "{}/api/channels/chn_01m438dsf8j5gqgk0yfxnracf6/messages?q=hello",
            g.base
        ))
        .header("authorization", "Bearer cctc_a")
        .header("content-type", "application/json")
        .body(r#"{"body":"the secret plan"}"#)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 200);
    r.text().await.expect("text");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let rec = g.records().last().cloned().expect("line");
    assert_eq!(
        (
            &rec["host"],
            &rec["method"],
            &rec["path"],
            &rec["vm_id"],
            &rec["status"]
        ),
        (
            &json!("team-chat"),
            &json!("POST"),
            &json!("/api/channels/[id]/messages"),
            &json!("vm-a"),
            &json!(200)
        )
    );
    assert!(rec["bytes_in"].as_u64().unwrap_or(0) > 0);
    let text = std::fs::read_to_string(&g.log).expect("log");
    assert!(
        !text.contains("secret plan") && !text.contains("hello"),
        "no body, no query in the log"
    );
}

/// A ClickClack that speaks just enough of an upgrade: the real token gets a 101 and an echo.
async fn ws_upstream(seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                seen.lock().expect("lock").push(head.clone());
                if !head.to_lowercase().contains("authorization: bearer ccb_real_a") {
                    let _ = s
                        .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                        .await;
                    return;
                }
                let _ = s
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n")
                    .await;
                let mut b = [0u8; 64];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&[b"echo:", &b[..n]].concat()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn upgrade(base: &str, auth: &str) -> (String, Option<tokio::net::TcpStream>) {
    let mut s = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
        .await
        .expect("connect");
    s.write_all(format!("GET /api/realtime/ws?workspace_id=wsp_1 HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\nauthorization: {auth}\r\n\r\n").as_bytes())
        .await
        .expect("write");
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap_or(0) == 0 {
            break;
        }
        head.push(b[0]);
    }
    let status = String::from_utf8_lossy(&head)
        .split(' ')
        .nth(1)
        .unwrap_or("")
        .to_string();
    (status, Some(s))
}

#[tokio::test]
async fn the_realtime_socket_goes_through_with_the_swap_and_a_wrong_token_never_reaches_clickclack() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let port = ws_upstream(seen.clone()).await;
    let g = gate(port, Arc::new(|| ChatContentNow::Off)).await;
    // A length stated on an upgrade is not passed on: the upstream is not left waiting for a body.
    let mut s = tokio::net::TcpStream::connect(g.base.trim_start_matches("http://"))
        .await
        .expect("connect");
    s.write_all(b"GET /api/realtime/ws HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\nauthorization: Bearer cctc_a\r\ncontent-length: 500\r\n\r\n")
        .await
        .expect("write");
    let mut head = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut head))
        .await
        .expect("no hang")
        .expect("read");
    assert_eq!(&head, b"HTTP/1.1 101");
    assert!(!seen.lock().expect("lock")[0].to_lowercase().contains("content-length"));
    drop(s);
    seen.lock().expect("lock").clear();
    let (status, s) = upgrade(&g.base, "Bearer cctc_a").await;
    assert_eq!(status, "101");
    let mut s = s.expect("socket");
    s.write_all(b"ping").await.expect("write");
    let mut b = [0u8; 9];
    s.read_exact(&mut b).await.expect("read");
    assert_eq!(&b, b"echo:ping");
    drop(s);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rec = g.records().into_iter().rfind(|r| r["method"] == "WS").expect("ws line");
    assert_eq!(
        (&rec["status"], &rec["path"]),
        (&json!(101), &json!("/api/realtime/ws"))
    );
    assert!(seen.lock().expect("lock")[0].contains("ccb_real_a"));
    seen.lock().expect("lock").clear();
    for auth in ["Bearer cctc_nope", "Bearer cctc_b"] {
        assert_eq!(upgrade(&g.base, auth).await.0, "404", "{auth}");
    }
    assert!(seen.lock().expect("lock").is_empty());
}

/// One `record` call: rule, direction, action, extra.
type Line = (String, String, String, Map<String, Value>);
type Send_ = Box<dyn FnOnce() -> cc_http::BoxFuture<Result<(), String>> + Send>;

/// The content rules as the TS test stands them in: words decide.
#[derive(Default)]
struct Rules {
    records: Mutex<Vec<Line>>,
    stopped: Mutex<Vec<(String, String, String)>>,
    hold_answer: Mutex<Option<String>>,
    held: Mutex<Option<Send_>>,
}

fn rule(id: &str, action: &str, reason: &str, by: Option<&str>) -> CheckedRule {
    CheckedRule {
        id: id.into(),
        name: None,
        action: action.into(),
        reason: reason.into(),
        by: by.map(String::from),
    }
}

impl ChatContent for Rules {
    fn loaded(&self) -> bool {
        true
    }
    fn applies(&self, _: &str) -> bool {
        true
    }
    fn check(
        &self,
        direction: &str,
        text: String,
        _: Option<String>,
        _: Option<String>,
    ) -> cc_http::BoxFuture<Result<Option<CheckedRule>, ContentError>> {
        let r = if text.len() > 65_536 {
            Err(ContentError::TooLong)
        } else if text.contains("unjudged") {
            Ok(Some(rule("salary", "block", "no salaries", Some("failed"))))
        } else if direction == "out" && text.contains("customer list") {
            Ok(Some(rule("cust", "block", "no customer lists", None)))
        } else if direction == "out" && text.contains("GB82") {
            Ok(Some(rule("pay", "hold", "bank details need approval", None)))
        } else if direction == "out" && text.contains("sk-proj-") {
            Ok(Some(rule("secrets", "block", "it looks like a key", None)))
        } else if direction == "in" && text.contains("salary") {
            Ok(Some(rule("salary", "block", "no salaries", None)))
        } else {
            Ok(None)
        };
        Box::pin(async move { r })
    }
    fn record(
        &self,
        rule: &str,
        direction: &str,
        action: &str,
        _: Option<&str>,
        extra: Map<String, Value>,
        _: Option<&str>,
    ) -> Option<String> {
        self.records
            .lock()
            .expect("lock")
            .push((rule.into(), direction.into(), action.into(), extra));
        Some("line-id".into())
    }
    fn hold(&self, h: ChatHold) -> cc_http::BoxFuture<Option<String>> {
        *self.held.lock().expect("lock") = Some(h.send);
        let a = self.hold_answer.lock().expect("lock").clone();
        Box::pin(async move { a })
    }
    fn stopped_here(&self, rule: &CheckedRule, direction: &str, _: Option<&str>, text: &str, _: Option<&str>) {
        self.stopped
            .lock()
            .expect("lock")
            .push((rule.id.clone(), direction.into(), text.into()));
    }
}

fn msg(id: &str, text: &str) -> Value {
    json!({"id": id, "author_id": "usr_person", "body": text, "created_at": "2026-10-21T10:00:00Z"})
}

fn chat(g: &Got) -> Answer {
    if g.method == "POST" {
        let mut sent = serde_json::from_slice::<Value>(&g.body)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let mut m = crate::integrations::as_map(json!({"id": "msg_new", "author_id": "usr_bot"}));
        m.append(&mut sent);
        return Answer::json(201, &json!({"message": m}));
    }
    let p = g.path.as_str();
    let doc = if p == "/api/messages/msg_salary" {
        json!({"message": msg("msg_salary", "my salary is 50k")})
    } else if p == "/api/messages/msg_ok" || p == "/api/messages/msg_gz" {
        json!({"message": msg("msg_ok", "hello")})
    } else if p.starts_with("/api/channels/chn_unjudged/messages") {
        json!({"messages": [msg("u1", "hi"), msg("u2", "unjudged words")]})
    } else if p.starts_with("/api/channels/chn_nested/messages") {
        let mut a = msg("a", "the salary list");
        a["replies"] = json!([msg("b", "my salary is 50k")]);
        let mut c = msg("c", "hi");
        c["replies"] = json!([msg("d", "bye")]);
        json!({"messages": [a, c, msg("e", "salary again")]})
    } else if p.starts_with("/api/channels/chn_1/messages") {
        json!({"messages": [msg("m1", "hi"), msg("m2", "the salary list"), msg("m3", "bye")], "next": null})
    } else if p == "/api/messages/msg_forced_gz" {
        let mut a = Answer::typed(200, "application/json", vec![0x1f, 0x8b, 8, 0, 0, 0]);
        a.headers.push(("content-encoding".into(), "gzip".into()));
        return a;
    } else {
        json!({"ok": true})
    };
    Answer::json(200, &doc)
}

#[tokio::test]
async fn content_rules_on_writes_holds_and_reads() {
    let up = FakeServer::start(chat).await;
    let rules = Arc::new(Rules::default());
    *rules.hold_answer.lock().expect("lock") = Some("hold-1".into());
    let state = Arc::new(Mutex::new("on"));
    let (r2, s2) = (rules.clone(), state.clone());
    let g = gate(
        up.port,
        Arc::new(move || match *s2.lock().expect("lock") {
            "on" => ChatContentNow::On(r2.clone()),
            "unknown" => ChatContentNow::Unknown,
            _ => ChatContentNow::Off,
        }),
    )
    .await;
    let posted = || up.got().into_iter().filter(|x| x.method != "GET").collect::<Vec<_>>();
    let say = |path: &str, body: String, method: &str| {
        let m = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
        client()
            .request(m, format!("{}{path}", g.base))
            .header("authorization", "Bearer cctc_a")
            .header("content-type", "application/json")
            .body(body)
            .send()
    };
    let read = |path: &str| {
        client()
            .get(format!("{}{path}", g.base))
            .header("authorization", "Bearer cctc_a")
            .send()
    };

    // A message that passes is posted as it was, with the real token.
    let r = say(
        "/api/channels/chn_1/messages",
        r#"{"body":"hello team","nonce":"n1"}"#.into(),
        "POST",
    )
    .await
    .expect("send");
    assert_eq!(r.status(), 201);
    assert_eq!(posted().len(), 1);
    assert_eq!(posted()[0].headers["authorization"], "Bearer ccb_real_a");
    assert_eq!(
        serde_json::from_slice::<Value>(&posted()[0].body).expect("json"),
        json!({"body": "hello team", "nonce": "n1"})
    );

    // A stopped message never reaches ClickClack; the agent gets the reason.
    up.clear();
    let r = say(
        "/api/channels/chn_1/messages",
        r#"{"body":"here is the customer list"}"#.into(),
        "POST",
    )
    .await
    .expect("send");
    assert_eq!(r.status(), 403);
    assert!(
        r.json::<Value>().await.expect("json")["message"]
            .as_str()
            .unwrap_or("")
            .contains("no customer lists")
    );
    assert_eq!(
        rules
            .records
            .lock()
            .expect("lock")
            .last()
            .map(|x| (x.0.clone(), x.1.clone(), x.2.clone())),
        Some(("cust".into(), "out".into(), "block".into()))
    );
    assert_eq!(
        rules.stopped.lock().expect("lock").last().map(|x| x.0.clone()),
        Some("cust".into())
    );
    assert_eq!(
        say("/api/messages/msg_1", r#"{"body":"the customer list"}"#.into(), "PATCH")
            .await
            .expect("send")
            .status(),
        403
    );
    assert_eq!(
        say(
            "/api/dms/dm_1/messages",
            format!(r#"{{"body":"sk-proj-{}"}}"#, "A".repeat(40)),
            "POST"
        )
        .await
        .expect("send")
        .status(),
        403
    );
    assert!(posted().is_empty());

    // A held message: the agent is told it was posted; Send posts it with the token.
    let iban = r#"{"body":"pay GB82 WEST 1234 5698 7654 32"}"#;
    let r = say("/api/channels/chn_1/messages", iban.into(), "POST")
        .await
        .expect("send");
    assert_eq!(r.status(), 201);
    assert!(
        r.json::<Value>().await.expect("json")["message"]["id"]
            .as_str()
            .unwrap_or("")
            .starts_with("msg_held_")
    );
    assert!(posted().is_empty(), "not posted yet");
    let send = rules.held.lock().expect("lock").take().expect("held");
    send().await.expect("sent");
    assert_eq!(posted().len(), 1);
    assert_eq!(
        (
            posted()[0].path.as_str(),
            posted()[0].headers["authorization"].to_str().unwrap_or("")
        ),
        ("/api/channels/chn_1/messages", "Bearer ccb_real_a")
    );
    // Nobody to ask: stopped. An edit cannot be held: stopped.
    *rules.hold_answer.lock().expect("lock") = None;
    let r = say("/api/channels/chn_1/messages", iban.into(), "POST")
        .await
        .expect("send");
    assert_eq!(r.status(), 403);
    assert!(
        r.json::<Value>().await.expect("json")["message"]
            .as_str()
            .unwrap_or("")
            .contains("nobody could be asked")
    );
    *rules.hold_answer.lock().expect("lock") = Some("hold-2".into());
    assert_eq!(
        say("/api/messages/msg_1", iban.into(), "PATCH")
            .await
            .expect("send")
            .status(),
        403
    );
    // Not posted on Send once the agent is under an emergency stop.
    up.clear();
    assert_eq!(
        say("/api/channels/chn_1/messages", iban.into(), "POST")
            .await
            .expect("send")
            .status(),
        201
    );
    g.locked.lock().expect("lock").push("vm-a".into());
    let send = rules.held.lock().expect("lock").take().expect("held");
    assert!(send().await.expect_err("refused").contains("emergency stop"));
    g.locked.lock().expect("lock").clear();
    assert!(posted().is_empty());

    // A write that breaks off is never checked or sent as if it were the whole.
    up.clear();
    let mut raw = tokio::net::TcpStream::connect(g.base.trim_start_matches("http://"))
        .await
        .expect("connect");
    raw.write_all(b"POST /api/channels/chn_1/messages HTTP/1.1\r\nhost: x\r\nauthorization: Bearer cctc_a\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"body\":\"hel")
        .await
        .expect("write");
    drop(raw);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(posted().is_empty());

    // A body that looks like JSON and does not parse is not sent (the TS reads it as text); one too
    // long to check is not sent either.
    assert_eq!(
        say("/api/channels/chn_1/messages", "{not json".into(), "POST")
            .await
            .expect("send")
            .status(),
        403
    );
    assert_eq!(
        say(
            "/api/channels/chn_1/messages",
            "{not json, the customer list".into(),
            "POST"
        )
        .await
        .expect("send")
        .status(),
        403
    );
    assert_eq!(
        say(
            "/api/channels/chn_1/messages",
            format!(r#"{{"body":"{}"}}"#, "x".repeat(70_000)),
            "POST"
        )
        .await
        .expect("send")
        .status(),
        403
    );
    assert!(posted().is_empty());
    // A body that is not JSON at all is read as text, and sent when it passes.
    let r = client()
        .post(format!("{}/api/channels/chn_1/messages", g.base))
        .header("authorization", "Bearer cctc_a")
        .header("content-type", "text/plain")
        .body("hello there")
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 201);
    assert_eq!(posted().len(), 1);

    // Reading: a stopped message is not found, and is left out of a list.
    assert_eq!(read("/api/messages/msg_ok").await.expect("send").status(), 200);
    let r = read("/api/messages/msg_salary").await.expect("send");
    assert_eq!(r.status(), 404);
    assert!(!r.text().await.expect("text").contains("salary"));
    let list: Value = read("/api/channels/chn_1/messages?limit=50")
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let ids: Vec<Value> = list["messages"]
        .as_array()
        .expect("list")
        .iter()
        .map(|m| m["id"].clone())
        .collect();
    assert_eq!(ids, [json!("m1"), json!("m3")]);
    // A stopped message with replies: what follows it is judged as itself, not by its place.
    let nested: Value = read("/api/channels/chn_nested/messages")
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let shape: Vec<Value> = nested["messages"]
        .as_array()
        .expect("list")
        .iter()
        .map(|m| {
            json!([
                m["id"],
                m["replies"]
                    .as_array()
                    .map(|r| r.iter().map(|x| x["id"].clone()).collect::<Vec<_>>())
                    .unwrap_or_default()
            ])
        })
        .collect();
    assert_eq!(shape, [json!(["c", ["d"]])]);
    // One the AI could not judge: "try again", not hidden for good.
    let r = read("/api/channels/chn_unjudged/messages").await.expect("send");
    assert_eq!(r.status(), 503);
    assert!(!r.text().await.expect("text").contains("unjudged"));

    // A write that does not say it is JSON is read all the same.
    up.clear();
    let r = client()
        .post(format!("{}/api/channels/chn_1/messages", g.base))
        .header("authorization", "Bearer cctc_a")
        .header("content-type", "text/plain")
        .body(r#"{"body":"the customer list"}"#)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 403);
    let r = client()
        .post(format!("{}/api/channels/chn_1/messages", g.base))
        .header("authorization", "Bearer cctc_a")
        .body(format!("sk-proj-{}", "B".repeat(40)))
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 403, "not JSON at all: every word is read");
    assert!(posted().is_empty());

    // A read the rules check is asked for uncompressed; a compressed answer is refused, not passed.
    let r = client()
        .get(format!("{}/api/messages/msg_gz", g.base))
        .header("authorization", "Bearer cctc_a")
        .header("accept-encoding", "gzip, br")
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 200);
    assert_eq!(up.got().last().expect("got").headers["accept-encoding"], "identity");
    assert_eq!(read("/api/messages/msg_forced_gz").await.expect("send").status(), 502);

    // Rules unknown: writes and reads wait (503); no module: everything passes.
    *state.lock().expect("lock") = "unknown";
    assert_eq!(
        say("/api/channels/chn_1/messages", r#"{"body":"hello"}"#.into(), "POST")
            .await
            .expect("send")
            .status(),
        503
    );
    assert_eq!(read("/api/messages/msg_ok").await.expect("send").status(), 503);
    *state.lock().expect("lock") = "off";
    assert_eq!(
        say(
            "/api/channels/chn_1/messages",
            r#"{"body":"the customer list"}"#.into(),
            "POST"
        )
        .await
        .expect("send")
        .status(),
        201
    );
    assert_eq!(read("/api/messages/msg_salary").await.expect("send").status(), 200);
}

#[tokio::test]
async fn writes_clickclack_would_read_are_checked_however_they_are_written() {
    let up = FakeServer::start(chat).await;
    let rules = Arc::new(Rules::default());
    let r2 = rules.clone();
    let g = gate(up.port, Arc::new(move || ChatContentNow::On(r2.clone()))).await;
    let posted = || up.got().into_iter().filter(|x| x.method != "GET").count();
    let say = |path: &str, ct: &str, body: String| {
        client()
            .post(format!("{}{path}", g.base))
            .header("authorization", "Bearer cctc_a")
            .header("content-type", ct)
            .body(body)
            .send()
    };
    let refused = |r: reqwest::Response| async move {
        assert_eq!(r.status(), 403);
        r.json::<Value>().await.expect("json")["message"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    let json = "application/json";
    // Escaped words beside a lone surrogate: ClickClack (Go) decodes them, serde_json does not
    // parse the body, so the raw text would hide them. Not sent.
    let lone = r#"{"body":"customer list \ud800"}"#;
    let m = refused(
        say("/api/channels/chn_1/messages", json, lone.into())
            .await
            .expect("send"),
    )
    .await;
    assert!(m.contains("the check could not run"), "{m}");
    // The same without a JSON content type still looks like JSON.
    assert_eq!(
        say("/api/channels/chn_1/messages", "text/plain", lone.into())
            .await
            .expect("send")
            .status(),
        403
    );
    // Nesting past what the parser takes.
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    assert_eq!(
        say("/api/channels/chn_1/messages", json, deep)
            .await
            .expect("send")
            .status(),
        403
    );
    // Go matches field names in any case: `Body` is the message.
    let m = refused(
        say(
            "/api/channels/chn_1/messages",
            json,
            r#"{"Body":"here is the customer list"}"#.into(),
        )
        .await
        .expect("send"),
    )
    .await;
    assert!(m.contains("no customer lists"), "{m}");
    // A JSON message labelled multipart is decoded by ClickClack as JSON: checked.
    let m = refused(
        say(
            "/api/channels/chn_1/messages",
            "multipart/form-data; boundary=x",
            r#"{"body":"here is the customer list"}"#.into(),
        )
        .await
        .expect("send"),
    )
    .await;
    assert!(m.contains("no customer lists"), "{m}");
    assert_eq!(posted(), 0, "none of them reached ClickClack");
    // A real upload stays unchecked, as the TS leaves file uploads.
    let r = say(
        "/api/uploads",
        "multipart/form-data; boundary=x",
        "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\ncustomer list\r\n--x--\r\n"
            .into(),
    )
    .await
    .expect("send");
    assert_ne!(r.status(), 403);
    assert_eq!(posted(), 1);
}
