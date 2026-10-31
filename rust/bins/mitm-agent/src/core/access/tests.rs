//! `access.test.ts`: the firewall's half of browser enrollment, against a fake agent box.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cc_auth::jwt::{SignKey, VerifyKey, VerifyOptions};
use cc_testkit::Pair;
use serde_json::{Value, json};

use super::*;
use crate::contracts::{CodeRoute, CodeSender};
use crate::core::agent_client::AgentClient;
use crate::core::consent::{Consent, ConsentView};
use crate::core::identities::Agents;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";

struct World {
    _dir: tempfile::TempDir,
    store: std::path::PathBuf,
    access: Arc<AccessFirewall>,
    agents: Arc<Agents>,
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    fail: Arc<Mutex<HashSet<String>>>,
    routes: Arc<Mutex<Vec<CodeRoute>>>,
    ready: Arc<AtomicBool>,
    stopped: Arc<Mutex<HashSet<String>>>,
    clock: Arc<AtomicU64>,
    cp: Pair,
    fw: Pair,
    base: String,
    keys: std::path::PathBuf,
}

async fn agent_server(calls: Arc<Mutex<Vec<(String, Value)>>>, fail: Arc<Mutex<HashSet<String>>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |req, _| {
            let (calls, fail) = (calls.clone(), fail.clone());
            async move {
                use http_body_util::BodyExt;
                let path = req.uri().path().trim_start_matches("/__cc/agent").to_string();
                let raw = req
                    .into_body()
                    .collect()
                    .await
                    .map(|b| b.to_bytes())
                    .unwrap_or_default();
                calls
                    .lock()
                    .expect("lock")
                    .push((path.clone(), serde_json::from_slice(&raw).unwrap_or(Value::Null)));
                if fail.lock().expect("lock").contains(&path) {
                    return cc_http::json(404, &json!({"error": "Not found"}));
                }
                cc_http::json(200, &json!({"ok": true}))
            }
        },
    );
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    format!("http://{addr}")
}

fn identities() -> Vec<Value> {
    vec![
        json!({"vm_id": "vm-1", "hostname": "support.ccl.bot", "name": "support"}),
        json!({"vm_id": "vm-2", "hostname": "ops.ccl.bot", "name": "ops", "role": "openclaw"}),
    ]
}

fn make(dir: &std::path::Path, base: &str, w: Option<&World>, store: &str) -> World {
    let calls = w.map(|w| w.calls.clone()).unwrap_or_default();
    let fail = w.map(|w| w.fail.clone()).unwrap_or_default();
    let routes = w.map(|w| w.routes.clone()).unwrap_or_default();
    let ready = w
        .map(|w| w.ready.clone())
        .unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
    let stopped = w.map(|w| w.stopped.clone()).unwrap_or_default();
    let clock = w
        .map(|w| w.clock.clone())
        .unwrap_or_else(|| Arc::new(AtomicU64::new(parse_iso("2026-10-01T10:00:00.000Z") as u64)));
    let agents = w.map(|w| w.agents.clone()).unwrap_or_else(|| {
        let a = Arc::new(Agents::default());
        a.set(&identities());
        a
    });
    let keys = dir.join("keys");
    if !keys.exists() {
        cc_testkit::BoxKeys::write(&keys, "fw-1", "fw.example").expect("keys");
    }
    let b = base.to_string();
    let client = AgentClient::for_tests(
        cc_auth::keys::KeysDir::new(&keys),
        agents.clone(),
        Arc::new(move |_| Some(b.clone())),
    );
    let c = clock.clone();
    let consent = Consent::for_tests(
        client.clone(),
        Arc::new(|| None),
        Arc::new(move || c.load(Ordering::SeqCst)),
        "482913",
    );
    let (cp, fw) = (Pair::from_seed(9), Pair::from_seed(8));
    let (r1, r2, a1, s1, c1, fwp, cpp) = (
        routes.clone(),
        ready.clone(),
        agents.clone(),
        stopped.clone(),
        clock.clone(),
        fw.private_pem.clone(),
        cp.public_pem.clone(),
    );
    let path = dir.join(store);
    let access = AccessFirewall::new(AccessOptions {
        store: AccessStoreFile::new(&path, KEY, "org-1", "fw-1"),
        org_id: "org-1".into(),
        box_id: "fw-1".into(),
        agent: client,
        consent: crate::contracts::CodeService::module(&ConsentView(consent), super::MODULE),
        code_routes: Arc::new(move || r1.lock().expect("lock").clone()),
        channels_ready: Arc::new(move || r2.load(Ordering::SeqCst)),
        identities: Arc::new(move || a1.browser_boxes()),
        stopped: Arc::new(move |vm: &str| s1.lock().expect("lock").contains(vm)),
        hostname: Arc::new(|| Some("acme-fw.ccl.bot".into())),
        saas_public_key: Arc::new(move || Some(cpp.clone())),
        signing_key: Arc::new(move || Some(fwp.clone())),
        now: Arc::new(move || c1.load(Ordering::SeqCst)),
    });
    access.note_pins();
    World {
        _dir: tempfile::tempdir().expect("dir"),
        store: path,
        access,
        agents,
        calls,
        fail,
        routes,
        ready,
        stopped,
        clock,
        cp,
        fw,
        base: base.to_string(),
        keys,
    }
}

async fn world() -> (tempfile::TempDir, World) {
    let d = tempfile::tempdir().expect("dir");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(Mutex::new(HashSet::new()));
    let base = agent_server(calls.clone(), fail.clone()).await;
    let mut w = make(d.path(), &base, None, "access.enc");
    w.calls = calls.clone();
    w.fail = fail.clone();
    // Rebuild so the agent server's call list is the world's.
    let w2 = make(d.path(), &base, Some(&w), "access.enc");
    (d, w2)
}

impl World {
    fn now_s(&self) -> i64 {
        (self.clock.load(Ordering::SeqCst) / 1000) as i64
    }

    fn intent_with(&self, extra: Value, key: &Pair, lifetime: i64) -> String {
        let mut c = json!({"purpose": "open-intent", "orgId": "org-1", "vmId": "vm-1", "userId": "user-marco", "email": "marco@example.com", "canWrite": true, "next": "chat"})
            .as_object()
            .cloned()
            .expect("obj");
        if let Value::Object(e) = extra {
            c.extend(e);
        }
        c.insert("jti".into(), json!(token(8)));
        let k = SignKey::ed25519_pkcs8_pem(&key.private_pem).expect("key");
        cc_auth::jwt::sign(c, &k, Some(lifetime), Some(self.now_s())).expect("sign")
    }

    fn intent(&self, extra: Value) -> String {
        let cp = self.cp.clone();
        self.intent_with(extra, &cp, 60)
    }

    async fn post(&self, path: &str, form: &[(&str, &str)], origin: Option<&str>, cookie: Option<&str>) -> AccessReply {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        self.access
            .handle(
                path,
                AccessRequest {
                    method: "POST".into(),
                    origin: origin.map(str::to_string),
                    cookie: cookie.map(str::to_string),
                    user_agent: IPHONE.into(),
                    content_type: "application/x-www-form-urlencoded".into(),
                    body: Some(body.into_bytes()),
                },
            )
            .await
    }

    async fn open(&self, intent: &str, cookie: Option<&str>) -> AccessReply {
        self.post(
            OPEN_PATH,
            &[("intent", intent), ("c", &binding())],
            Some("https://support.ccl.bot"),
            cookie,
        )
        .await
    }

    fn verify_ticket(&self, t: &str) -> Value {
        let k = VerifyKey::ed25519_spki_pem(&self.fw.public_pem).expect("key");
        Value::Object(
            cc_auth::jwt::verify(
                t,
                &k,
                VerifyOptions {
                    clock_tolerance_s: 0,
                    now: Some(self.now_s()),
                },
            )
            .expect("ticket verifies"),
        )
    }

    fn approve_owner(&self) {
        *self.routes.lock().expect("lock") = vec![CodeRoute {
            vm_id: "vm-1".into(),
            hostname: "support.ccl.bot".into(),
            senders: vec![CodeSender::Person {
                kind: "telegram".into(),
                id: "42".into(),
                label: Some("@owner".into()),
            }],
            telegram: None,
        }];
    }

    fn sent_texts(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .filter(|(p, _)| p == "/channels/send")
            .map(|(_, b)| b["text"].as_str().unwrap_or_default().to_string())
            .collect()
    }
}

fn binding() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(token(32).as_bytes()))
}

fn frag(r: &AccessReply) -> std::collections::HashMap<String, String> {
    let loc = r.location.clone().unwrap_or_default();
    let hash = loc.split_once('#').map(|x| x.1).unwrap_or_default().to_string();
    url::form_urlencoded::parse(hash.as_bytes()).into_owned().collect()
}

fn cookie_from(r: &AccessReply, name: &str) -> String {
    r.cookies
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .and_then(|c| c.split(';').next())
        .map(|c| c[name.len() + 1..].to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn routes_origins_and_the_free_window() {
    let (_d, w) = world().await;
    assert!(owns_access_path(OPEN_PATH) && owns_access_path(CONFIRM_PATH) && !owns_access_path("/__cc/opens"));
    assert_eq!(crate::core::agent_client::purpose_for_path("/access/config"), "access");
    let i = w.intent(json!({}));
    assert_eq!(w.post(OPEN_PATH, &[("intent", &i)], None, None).await.status, 403);
    assert_eq!(
        w.post(OPEN_PATH, &[("intent", &i)], Some("https://evil.example"), None)
            .await
            .status,
        403
    );
    // Nobody approved: the browser is enrolled without a code and gets a ticket.
    let r = w.open(&i, None).await;
    assert_eq!(r.status, 303);
    let loc = r.location.clone().expect("location");
    assert!(loc.starts_with("https://support.ccl.bot/__cc/login#t="), "{loc}");
    let t = w.verify_ticket(&frag(&r)["t"]);
    assert_eq!(t["vmId"], "vm-1");
    assert_eq!(t["purpose"], "browser-login");
    assert_eq!(t["iss"], "fw:fw-1");
    assert_eq!(t["canWrite"], true);
    assert!(t["deviceId"].as_str().expect("id").starts_with("dev_"));
    assert!(t.get("next").is_none());
    let dev = cookie_from(&r, "__Host-cc_dev");
    assert_eq!(dev.len(), 43);
    assert!(r.cookies[0].ends_with("; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=7776000"));
    // Single use.
    assert_eq!(frag(&w.open(&i, None).await)["e"], "used");
    // An intent for another agent, posted from this one's page.
    assert_eq!(
        frag(&w.open(&w.intent(json!({"vmId": "vm-2"})), None).await)["e"],
        "invalid"
    );
    // Forged, foreign, long-lived, wrong purpose, a firewall page, a bad binding.
    let other = Pair::from_seed(7);
    for bad in [
        w.intent_with(json!({}), &other, 60),
        w.intent(json!({"orgId": "org-2"})),
        w.intent_with(json!({}), &w.cp.clone(), 600),
        w.intent(json!({"purpose": "box-ticket"})),
        w.intent(json!({"next": "nope"})),
        w.intent(json!({"next": "doctor", "sessionId": "s1"})),
        w.intent(json!({"userId": ""})),
    ] {
        assert_eq!(frag(&w.open(&bad, None).await)["e"], "invalid");
    }
    let r = w
        .post(
            OPEN_PATH,
            &[("intent", &w.intent(json!({}))), ("c", "short")],
            Some("https://support.ccl.bot"),
            None,
        )
        .await;
    assert_eq!(frag(&r)["e"], "invalid");
    // Expired.
    let old = w.intent(json!({}));
    w.clock.fetch_add(61_000, Ordering::SeqCst);
    assert_eq!(frag(&w.open(&old, None).await)["e"], "invalid");
    // screen and files.
    let r = w.open(&w.intent(json!({"next": "screen"})), None).await;
    assert!(
        r.location
            .clone()
            .expect("loc")
            .starts_with("https://support.ccl.bot/__cc/browser#t=")
    );
    assert_eq!(w.verify_ticket(&frag(&r)["t"])["purpose"], "browser-view");
    let r = w.open(&w.intent(json!({"next": "files"})), None).await;
    assert_eq!(w.verify_ticket(&frag(&r)["t"])["next"], "files");
    // Stopped.
    w.stopped.lock().expect("lock").insert("vm-1".into());
    assert_eq!(frag(&w.open(&w.intent(json!({})), None).await)["e"], "stopped");
    w.stopped.lock().expect("lock").clear();
    // The dev route alone does not close the free window.
    *w.routes.lock().expect("lock") = vec![CodeRoute {
        vm_id: "vm-1".into(),
        hostname: "support.ccl.bot".into(),
        senders: vec![CodeSender::Dev],
        telegram: None,
    }];
    assert!(w.access.free_window());
    // A malformed request is refused bare.
    let r = w
        .access
        .handle(
            OPEN_PATH,
            AccessRequest {
                method: "POST".into(),
                origin: Some("https://support.ccl.bot".into()),
                content_type: "application/json".into(),
                body: Some(b"{}".to_vec()),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(r, AccessReply::bare(400));
    let r = w
        .access
        .handle(
            OPEN_PATH,
            AccessRequest {
                method: "GET".into(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(r.status, 405);
}

#[tokio::test]
async fn codes_after_the_first_approval() {
    let (_d, w) = world().await;
    // Enrolled in the free window.
    let first = w.open(&w.intent(json!({})), None).await;
    let dev = format!("__Host-cc_dev={}", cookie_from(&first, "__Host-cc_dev"));
    w.approve_owner();
    // The first approval: the browsers enrolled without a code are listed to the owner, once.
    w.access.maybe_list().await;
    w.access.maybe_list().await;
    let texts = w.sent_texts();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].starts_with("ControlClaw: this browser was signed in to your agents without a code"));
    assert!(texts[0].contains(
        "- Safari on iPhone: first 2026-10-01, last 2026-10-01. ControlClaw says this was: marco@example.com"
    ));
    // That browser opens without a code.
    let r = w.open(&w.intent(json!({})), Some(&dev)).await;
    assert!(r.location.clone().expect("loc").contains("/__cc/login#t="));
    // A new browser gets a code, with the firewall's own summary.
    let r = w.open(&w.intent(json!({})), None).await;
    let loc = r.location.clone().expect("loc");
    assert!(
        loc.starts_with("https://support.ccl.bot/__cc/enroll#p=acc_") && loc.ends_with("&via=telegram"),
        "{loc}"
    );
    let p = frag(&r)["p"].clone();
    let pend = format!("__Host-cc_pend={}", cookie_from(&r, "__Host-cc_pend"));
    let msg = w.sent_texts().pop().expect("code sent");
    assert!(msg.starts_with("ControlClaw: A new browser wants to open the agent support (support.ccl.bot): Safari on iPhone\nCode: 482 913\n"));
    assert!(msg.ends_with("ControlClaw says this is: marco@example.com"));
    let status = w.access.status();
    assert_eq!(status["pending"]["vmId"], "vm-1");
    let confirm = |code: &'static str, cookie: Option<String>, origin: &'static str| {
        let (p, w) = (p.clone(), &w);
        async move {
            w.post(
                CONFIRM_PATH,
                &[("p", &p), ("code", code)],
                Some(origin),
                cookie.as_deref(),
            )
            .await
        }
    };
    // Without the pending cookie nothing is counted.
    assert_eq!(
        frag(&confirm("482913", None, "https://support.ccl.bot").await)["e"],
        "code_expired"
    );
    // From another agent's page.
    assert_eq!(
        frag(&confirm("482913", Some(pend.clone()), "https://ops.ccl.bot").await)["e"],
        "code_expired"
    );
    // A wrong code counts down; the right one enrolls and signs.
    let r = confirm("111111", Some(pend.clone()), "https://support.ccl.bot").await;
    assert!(
        r.location
            .clone()
            .expect("loc")
            .ends_with(&format!("/__cc/enroll#p={p}&e=invalid_code&left=4"))
    );
    let r = confirm("482 913", Some(pend.clone()), "https://support.ccl.bot").await;
    assert!(
        r.location
            .clone()
            .expect("loc")
            .starts_with("https://support.ccl.bot/__cc/login#t=")
    );
    assert_eq!(w.verify_ticket(&frag(&r)["t"])["vmId"], "vm-1");
    assert!(r.cookies.iter().any(|c| c.starts_with("__Host-cc_pend=; Path=/")));
    assert!(w.access.status()["pending"].is_null());
    // Five wrong codes end an enrollment.
    let r = w.open(&w.intent(json!({})), None).await;
    let p2 = frag(&r)["p"].clone();
    let pend = format!("__Host-cc_pend={}", cookie_from(&r, "__Host-cc_pend"));
    for left in (1..5).rev() {
        let r = w
            .post(
                CONFIRM_PATH,
                &[("p", &p2), ("code", "000000")],
                Some("https://support.ccl.bot"),
                Some(&pend),
            )
            .await;
        assert!(r.location.clone().expect("loc").ends_with(&format!("left={left}")));
    }
    let r = w
        .post(
            CONFIRM_PATH,
            &[("p", &p2), ("code", "000000")],
            Some("https://support.ccl.bot"),
            Some(&pend),
        )
        .await;
    assert_eq!(frag(&r)["e"], "code_expired");
    // A code that cannot be delivered says so.
    w.fail.lock().expect("lock").insert("/channels/send".into());
    assert_eq!(frag(&w.open(&w.intent(json!({})), None).await)["e"], "unreachable");
    // A channel store that would not open is never the free window.
    w.routes.lock().expect("lock").clear();
    w.ready.store(false, Ordering::SeqCst);
    assert!(!w.access.free_window());
    assert_eq!(frag(&w.open(&w.intent(json!({})), None).await)["e"], "unreachable");
}

#[tokio::test]
async fn pins_config_revocation_and_the_beat() {
    let (d, w) = world().await;
    // A pin never moves.
    w.agents.set(&[
        json!({"vm_id": "vm-1", "hostname": "elsewhere.ccl.bot", "name": "support"}),
        json!({"vm_id": "vm-2", "hostname": "ops.ccl.bot", "name": "ops"}),
    ]);
    w.access.note_pins();
    assert_eq!(w.access.pinned_host("vm-1").as_deref(), Some("support.ccl.bot"));
    // Pins survive a restart.
    let again = make(d.path(), &w.base, Some(&w), "access.enc");
    assert_eq!(again.access.pinned_host("vm-1").as_deref(), Some("support.ccl.bot"));
    assert!(w.store.exists() && w.keys.exists());
    // /access/config once to every agent, retried after a failure with a backoff.
    w.fail.lock().expect("lock").insert("/access/config".into());
    w.access.push_config().await;
    let configs = |w: &World| {
        w.calls
            .lock()
            .expect("lock")
            .iter()
            .filter(|(p, _)| p == "/access/config")
            .count()
    };
    assert_eq!(configs(&w), 2);
    w.access.push_config().await;
    assert_eq!(configs(&w), 2, "not before the retry time");
    w.fail.lock().expect("lock").clear();
    w.clock.fetch_add(CONFIG_RETRY_FIRST_MS, Ordering::SeqCst);
    w.access.push_config().await;
    assert_eq!(configs(&w), 4);
    w.clock.fetch_add(CONFIG_RETRY_MS, Ordering::SeqCst);
    w.access.push_config().await;
    assert_eq!(configs(&w), 4, "once taken, not again");
    let body = w
        .calls
        .lock()
        .expect("lock")
        .iter()
        .find(|(p, _)| p == "/access/config")
        .map(|x| x.1.clone());
    assert_eq!(body, Some(json!({"firewallOrigin": "https://acme-fw.ccl.bot"})));
    // Enroll, then revoke.
    let r = w.open(&w.intent(json!({"next": "chat"})), None).await;
    let id = w.verify_ticket(&frag(&r)["t"])["deviceId"]
        .as_str()
        .expect("id")
        .to_string();
    let beat = w.access.status();
    assert_eq!(beat["deviceCount"], 1);
    assert_eq!(beat["origin"], "https://acme-fw.ccl.bot");
    let dev = beat["devices"][0].as_object().expect("obj");
    let keys: Vec<&String> = dev.keys().collect();
    assert_eq!(
        keys,
        [
            "deviceId",
            "userId",
            "email",
            "label",
            "via",
            "createdAt",
            "lastUsedAt",
            "listed"
        ]
    );
    assert!(!beat.to_string().contains(&cookie_from(&r, "__Host-cc_dev")));
    let out = w
        .access
        .revoke(json!({"deviceIds": [id, "dev_x"]}).as_object().cloned().expect("o"))
        .await;
    assert_eq!(
        Value::Object(out.data.clone().expect("data")),
        json!({"revoked": [id], "unknown": ["dev_x"], "pushed": ["vm-1", "vm-2"], "failed": []})
    );
    assert_eq!(out.status, "applied");
    let bad = w.access.revoke(serde_json::Map::new()).await;
    assert_eq!(
        (bad.ok, bad.message.as_deref()),
        (false, Some("malformed access.revoke payload"))
    );
    let all = w.access.revoke_all().await;
    assert_eq!(
        Value::Object(all.data.expect("data")),
        json!({"revoked": 0, "pushed": ["vm-1", "vm-2"], "failed": []})
    );
}

#[test]
fn labels_and_messages() {
    assert_eq!(device_label(IPHONE), "Safari on iPhone");
    assert_eq!(
        device_label("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120"),
        "Edge on Windows"
    );
    assert_eq!(device_label("curl/8"), "A browser");
    assert!((parse_iso("2026-10-01T10:00:00.000Z") - 1_790_848_800_000.0).abs() < 1.0);
    assert!(parse_iso("nope").is_nan());
    let m = open_code_message(Some("Bad Name"), "vm-1", "<script>", None, "x\ny", "123456").expect("msg");
    assert!(m.starts_with(
        "ControlClaw: A new browser wants to open the agent vm-1 (address not on record): a browser\nCode: 123 456"
    ));
    assert_eq!(
        parse_doctor_choices(Some(
            &json!([{"id": "c", "label": "L", "provider": "p", "clis": ["claude", "x"], "models": [{"id": "m", "name": "M", "extra": 1}]}])
        )),
        Some(vec![
            json!({"id": "c", "label": "L", "provider": "p", "clis": ["claude"], "models": [{"id": "m", "name": "M"}]})
        ])
    );
    assert_eq!(
        parse_doctor_choices(Some(
            &json!([{"id": "c", "label": "L", "provider": "p", "clis": [], "models": []}])
        )),
        None
    );
}

/// The `PageAccess` slot W5's pages read (`slots::Pages`): which door each page goes through.
#[tokio::test]
async fn the_page_access_slot() {
    use crate::contracts::PageAccess;
    let (_d, w) = world().await;
    let r = w.open(&w.intent(json!({})), None).await;
    let dev = cookie_from(&r, "__Host-cc_dev");
    let pages = crate::core::slots::Pages(w.access.clone());
    let origin = pages.origin().expect("origin");
    let headers = |origin: &str| {
        let mut h = http::HeaderMap::new();
        h.insert("origin", origin.parse().expect("h"));
        h.insert("cookie", format!("__Host-cc_dev={dev}").parse().expect("h"));
        h
    };
    let h = headers(&origin);
    let fw = |extra: Value| {
        let mut e = json!({"vmId": "fw-1"});
        e.as_object_mut()
            .expect("o")
            .extend(extra.as_object().cloned().expect("o"));
        w.intent(e)
    };

    // A firewall page: this box, its origin, an enrolled browser; the intent once.
    let i = fw(json!({"next": "team-chat", "name": "Marco"}));
    let p = pages.authorize(&h, i.clone(), "team-chat").await.expect("team chat");
    assert_eq!(p.email.as_deref(), Some("marco@example.com"));
    assert_eq!(p.extra["name"], "Marco");
    assert_eq!(p.extra["vmId"], "fw-1");
    assert!(pages.authorize(&h, i, "team-chat").await.is_none(), "used once");
    assert!(pages.device_active(&h, "team-chat", "user-marco", &p.device_id, None));
    // Another origin, another page's intent, a page this firewall does not have.
    let i = fw(json!({"next": "team-chat"}));
    assert!(
        pages
            .authorize(&headers("https://evil.example"), i.clone(), "team-chat")
            .await
            .is_none()
    );
    assert!(pages.authorize(&h, i, "firewall-logs").await.is_none());
    assert!(pages.authorize(&h, fw(json!({"next": "nope"})), "nope").await.is_none());
    // The logins page: an owner or admin only.
    assert!(
        pages
            .authorize(&h, fw(json!({"next": "logins", "canWrite": false})), "logins")
            .await
            .is_none()
    );
    assert!(
        pages
            .authorize(&h, fw(json!({"next": "logins"})), "logins")
            .await
            .is_some()
    );

    // Doctor: an agent, a session, an owner; the grant holds while the agent is known and running.
    let doctor = json!({"next": "doctor", "sessionId": "s1"});
    let p = pages
        .authorize(&h, w.intent(doctor.clone()), "doctor")
        .await
        .expect("doctor");
    assert_eq!(
        (p.extra["vmId"].as_str(), p.extra["sessionId"].as_str()),
        (Some("vm-1"), Some("s1"))
    );
    let dev_id = p.device_id.clone();
    assert!(pages.device_active(&h, "doctor", "user-marco", &dev_id, Some("vm-1")));
    assert!(
        !pages.device_active(&h, "doctor", "user-marco", &dev_id, None),
        "an agent page names its agent"
    );
    assert!(
        !pages.device_active(&h, "doctor", "user-marco", &dev_id, Some("vm-9")),
        "an agent it does not know"
    );
    assert!(!pages.device_active(&h, "team-chat", "user-marco", &dev_id, Some("vm-1")));
    assert!(!pages.device_active(&h, "doctor", "someone-else", &dev_id, Some("vm-1")));
    let mut no = json!({"canWrite": false});
    no.as_object_mut()
        .expect("o")
        .extend(doctor.as_object().cloned().expect("o"));
    assert!(
        pages.authorize(&h, w.intent(no), "doctor").await.is_none(),
        "root on the agent: owners only"
    );
    w.stopped.lock().expect("lock").insert("vm-1".into());
    assert!(
        !pages.device_active(&h, "doctor", "user-marco", &dev_id, Some("vm-1")),
        "under the stop"
    );
    assert!(pages.authorize(&h, w.intent(doctor), "doctor").await.is_none());
    // The organization stopped: the firewall pages close, the logins page does not.
    w.stopped.lock().expect("lock").insert("fw-1".into());
    assert!(!pages.device_active(&h, "team-chat", "user-marco", &dev_id, None));
    assert!(pages.device_active(&h, "logins", "user-marco", &dev_id, None));
}

/// Standalone: a firewall-page intent enrolls the browser that brings it, once, from this
/// firewall's origin; an agent's intent, a replay and another origin are refused.
#[tokio::test]
async fn a_local_link_enrolls_the_browser_for_a_firewall_page() {
    let (_d, w) = world().await;
    // The routes have an owner: a console Open would need a code; the local link does not.
    w.approve_owner();
    let req = |origin: &str, cookie: Option<&str>| AccessRequest {
        method: "POST".into(),
        origin: Some(origin.into()),
        cookie: cookie.map(str::to_string),
        user_agent: IPHONE.into(),
        content_type: "application/x-www-form-urlencoded".into(),
        body: None,
    };
    let fw_page = |w: &World| w.intent_with(json!({"vmId": "fw-1", "next": "logins"}), &w.cp, 60);
    let origin = "https://acme-fw.ccl.bot";

    let agent_page = w.intent_with(json!({}), &w.cp, 60);
    assert_eq!(
        w.access
            .local_enroll(&req(origin, None), &agent_page)
            .await
            .expect("ok"),
        None
    );
    let other = fw_page(&w);
    assert_eq!(
        w.access
            .local_enroll(&req("https://evil.example", None), &other)
            .await
            .expect("ok"),
        None
    );

    let intent = fw_page(&w);
    let (next, cookie) = w
        .access
        .local_enroll(&req(origin, None), &intent)
        .await
        .expect("ok")
        .expect("enrolled");
    assert_eq!(next, "logins");
    assert!(cookie.starts_with(&format!("{DEV_COOKIE}=")), "{cookie}");
    assert_eq!(
        w.access.local_enroll(&req(origin, None), &intent).await.expect("ok"),
        None,
        "a replay"
    );

    // The enrolled browser now opens the page the usual way.
    let jar = cookie.split(';').next().expect("cookie").to_string();
    let open = fw_page(&w);
    let granted = w
        .access
        .authorize_firewall(Some(origin), Some(&jar), &open, "logins")
        .await;
    assert_eq!(granted.map(|g| g.user_id).as_deref(), Some("user-marco"));
}
