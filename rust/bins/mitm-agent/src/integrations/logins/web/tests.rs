//! `logins-web.test.ts`: the page over real HTTP, with W3's access and shell stood in and a real
//! logins store.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::contracts::{FwShell, PageAccess, PagePerson};
use crate::integrations::testing::{self, FakeAgents, Identities, Syncs};
use serde_json::Map;

const ORIGIN: &str = "https://acme-fw.ccl.bot";

#[derive(Default)]
struct Access {
    person: std::sync::Mutex<Option<PagePerson>>,
    inactive: AtomicBool,
}

impl PageAccess for Access {
    fn origin(&self) -> Option<String> {
        Some(ORIGIN.into())
    }
    fn authorize(&self, _: &HeaderMap, intent: String, next: &str) -> cc_http::BoxFuture<Option<PagePerson>> {
        assert_eq!((intent.as_str(), next), ("x", "logins"));
        let p = self.person.lock().expect("lock").clone();
        Box::pin(async move { p })
    }
    fn device_active(&self, _: &HeaderMap, next: &str, user_id: &str, device_id: &str, _: Option<&str>) -> bool {
        assert_eq!((next, user_id, device_id), ("logins", "u1", "dev_1"));
        !self.inactive.load(Ordering::SeqCst)
    }
}

/// The frame as `fw-shell.ts` draws it, cut to what the tests look for.
struct Shell;

impl FwShell for Shell {
    fn notice(&self, title: &str, _: Option<&str>, text: &str, _: Option<&str>, _: Option<&str>) -> String {
        format!("<title>{title}</title><p>{text}</p>")
    }
    fn shell_page(&self, title: &str, active: &str, body: &str, _: Option<&str>, tail: &str) -> String {
        assert_eq!(active, "logins");
        format!(
            "<title>{title}</title><nav aria-label=\"Firewall pages\"><a href=\"/__cc/logins/\" aria-current=\"page\">Logins</a></nav>{body}{tail}"
        )
    }
    fn minimal_page(&self, title: &str, body: &str, tail: &str) -> String {
        format!("<title>{title}</title><span>ControlClaw</span>{body}{tail}")
    }
    fn content(&self, html: &str) -> String {
        format!("<main>{html}</main>")
    }
}

struct Page {
    _dir: tempfile::TempDir,
    base: String,
    logins: Arc<LoginsFirewall>,
    access: Arc<Access>,
    http: reqwest::Client,
}

async fn page() -> Page {
    let dir = tempfile::tempdir().expect("dir");
    let mut app = testing::app(dir.path());
    Arc::get_mut(&mut app).expect("fresh").config.firewall_url = "https://console.example/api/vm-agent/firewall".into();
    app.contracts
        .identities
        .set(Identities::of(&[("a", "10.0.0.9", "Ada"), ("b", "10.0.0.8", "Bo")]));
    app.contracts.agents.set(Arc::new(FakeAgents::default()));
    app.contracts.credentials_sync.set(Arc::new(Syncs::default()));
    let access = Arc::new(Access::default());
    app.contracts.page_access.set(access.clone());
    app.contracts.fw_shell.set(Arc::new(Shell));
    let logins = LoginsFirewall::new(&app, dir.path().join("logins.enc"), None, None).expect("open");
    let mut router = cc_http::Router::new(crate::stages::INGRESS);
    router.fallback(cc_http::empty_not_found);
    let mut reg = crate::app::Registry {
        plain: cc_http::Router::new(crate::stages::PLAIN),
        tls: cc_http::Router::new(crate::stages::TLS),
        ingress: router,
        commands: crate::commands::Commands::default(),
    };
    route(&mut reg, LoginsWeb::new(&app, logins.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(reg.ingress)));
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("client");
    Page {
        _dir: dir,
        base,
        logins,
        access,
        http,
    }
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn header(&self, k: &str) -> String {
        self.headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }
}

impl Page {
    async fn call(&self, method: Method, path: &str, headers: &[(&str, &str)], body: Option<String>) -> Reply {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        let res = req.send().await.expect("send");
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        Reply {
            status,
            headers,
            body: res.text().await.unwrap_or_default(),
        }
    }

    async fn get(&self, path: &str, cookie: &str) -> Reply {
        self.call(Method::GET, path, &[("cookie", cookie)], None).await
    }

    async fn post(&self, path: &str, cookie: &str, body: Value) -> Reply {
        let h = [
            ("content-type", "application/json"),
            ("origin", ORIGIN),
            ("cookie", cookie),
        ];
        self.call(Method::POST, path, &h, Some(js::stringify(&body))).await
    }

    async fn open(&self, login: &str, request: &str) -> (String, String) {
        *self.access.person.lock().expect("lock") = Some(person(Some("owner@example.com")));
        let form = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("origin", ORIGIN),
        ];
        let r = self
            .call(
                Method::POST,
                "/__cc/logins/open",
                &form,
                Some(format!("intent=x&login={login}&request={request}")),
            )
            .await;
        assert_eq!(r.status, 303);
        let set = r.header("set-cookie");
        assert!(
            set.contains("Path=/__cc/logins; Secure; HttpOnly; SameSite=Strict; Max-Age=1800"),
            "{set}"
        );
        (set.split(';').next().unwrap_or("").to_string(), r.header("location"))
    }
}

fn person(email: Option<&str>) -> PagePerson {
    PagePerson {
        user_id: "u1".into(),
        device_id: "dev_1".into(),
        email: email.map(String::from),
        can_write: true,
        extra: Map::new(),
    }
}

#[tokio::test]
async fn refused_without_an_intent_in_an_enrolled_browser_or_from_another_origin() {
    let p = page().await;
    let form = |o: &'static str| [("content-type", "application/x-www-form-urlencoded"), ("origin", o)];
    assert_eq!(
        p.call(
            Method::POST,
            "/__cc/logins/open",
            &form(ORIGIN),
            Some("intent=x".into())
        )
        .await
        .status,
        403
    );
    *p.access.person.lock().expect("lock") = Some(person(None));
    assert_eq!(
        p.call(
            Method::POST,
            "/__cc/logins/open",
            &form("https://evil.example"),
            Some("intent=x".into())
        )
        .await
        .status,
        403
    );
    assert_eq!(p.get("/__cc/logins/", "").await.status, 403);
    let state = p.get("/__cc/logins/state", "").await;
    assert_eq!(
        (state.status, state.json()),
        (
            403,
            json!({"message": "This page has expired. Open Logins again from your ControlClaw console."})
        )
    );
    // A cookie that was never handed out, or one sent twice, is no grant.
    let (cookie, _) = p.open("", "").await;
    assert_eq!(
        p.get("/__cc/logins/state", &format!("{cookie}; {cookie}")).await.status,
        403
    );
    assert_eq!(
        p.get(
            "/__cc/logins/state",
            "__Secure-cc_logins=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .await
        .status,
        403
    );
    assert_eq!(p.get("/__cc/logins/state", &cookie).await.status, 200);
    // Not this page's: the router leaves it to the rest.
    assert!(!owns_logins_path("/__cc/loginsx"));
    assert_eq!(p.get("/__cc/loginsx", &cookie).await.status, 404);
}

#[tokio::test]
async fn the_page_has_a_strict_csp_save_creates_a_login_replace_scope_and_delete() {
    let p = page().await;
    let (cookie, location) = p.open("", "").await;
    assert_eq!(location, "/__cc/logins/");
    let pg = p.get("/__cc/logins/", &cookie).await;
    assert_eq!(pg.status, 200);
    let csp = pg.header("content-security-policy");
    assert!(csp.starts_with("default-src 'none'; script-src 'self'; style-src 'self'; font-src data:;"));
    assert!(!csp.contains("unsafe") && !csp.contains("http:") && !csp.contains("https:") && !csp.contains('*'));
    assert_eq!(pg.header("x-frame-options"), "DENY");
    // The policy allows no inline style and no inline script, so the page must carry none.
    assert!(!regex::Regex::new(r#"<style|style=""#).expect("re").is_match(&pg.body));
    assert!(!pg.body.contains("<script>"));
    assert!(
        pg.body.contains(r#"aria-label="Firewall pages""#),
        "the form sits in the firewall's shell"
    );
    // The link an agent sends in a chat: the same form, alone under the ControlClaw mark.
    let asked = p.get("/__cc/logins/?request=lr_abcdefgh12345678", &cookie).await;
    assert!(
        !asked.body.contains("<nav")
            && asked.body.contains("ControlClaw</span>")
            && asked.body.contains(r#"<form id="form""#)
    );
    assert!(
        p.get("/__cc/logins/?request=<x>", &cookie)
            .await
            .body
            .contains(r#"aria-label="Firewall pages""#)
    );
    let script = p.get("/__cc/logins/app.js", &cookie).await;
    assert_eq!(script.header("content-type"), "text/javascript; charset=utf-8");
    for id in regex::Regex::new(r#"\bel\("([a-z0-9]+)"\)"#)
        .expect("re")
        .captures_iter(&script.body)
    {
        assert!(
            pg.body.contains(&format!("id=\"{}\"", &id[1])),
            "the script's #{} is in the page",
            &id[1]
        );
    }
    assert_eq!(
        p.get("/__cc/logins/state", &cookie).await.json()["agents"],
        json!([{"vmId": "a", "name": "Ada"}, {"vmId": "b", "name": "Bo"}])
    );

    // Same-origin JSON only.
    let entry = json!({"name": "Acme", "sites": ["acme.example"], "loginUrl": "https://acme.example/login", "username": "ops", "password": "Hunter-22!", "vmIds": ["a"]});
    let evil = [
        ("content-type", "application/json"),
        ("origin", "https://evil.example"),
        ("cookie", cookie.as_str()),
    ];
    assert_eq!(
        p.call(Method::POST, "/__cc/logins/save", &evil, Some(js::stringify(&entry)))
            .await
            .status,
        403
    );
    let plain = [
        ("content-type", "text/plain"),
        ("origin", ORIGIN),
        ("cookie", cookie.as_str()),
    ];
    assert_eq!(
        p.call(Method::POST, "/__cc/logins/save", &plain, Some(js::stringify(&entry)))
            .await
            .status,
        415
    );
    let mut none = entry.clone();
    none["vmIds"] = json!([]);
    assert_eq!(p.post("/__cc/logins/save", &cookie, none).await.status, 400);
    let saved = p.post("/__cc/logins/save", &cookie, entry.clone()).await.json();
    assert_eq!(saved["ok"], true);
    assert!(!js::stringify(&saved).contains("Hunter"));
    assert_eq!(p.logins.credentials()[0]["secret"], "Hunter-22!");
    let id = saved["login"]["id"].as_str().expect("id").to_string();
    assert_eq!(p.logins.get(&id).expect("login")["createdBy"], "owner@example.com");

    // Replace, opened for that login.
    let (again, location) = p.open(&id, "").await;
    assert_eq!(location, format!("/__cc/logins/?login={id}"));
    let st = p.get(&format!("/__cc/logins/state?login={id}"), &again).await.json();
    assert_eq!(st["login"]["name"], "Acme");
    assert!(!js::stringify(&st).contains("Hunter"));
    let mut other = entry.clone();
    other["id"] = json!(id);
    other["password"] = json!("Other-pass-9");
    p.post("/__cc/logins/save", &again, other).await;
    assert_eq!(p.logins.credentials()[0]["secret"], "Other-pass-9");
    assert_eq!(p.logins.summary()["logins"].as_array().map(Vec::len), Some(1));

    // Extra sign-in paths, without the password.
    let scoped = p
        .post(
            "/__cc/logins/scope",
            &again,
            json!({"id": id, "signInPaths": ["/session", "/api/auth/"]}),
        )
        .await;
    assert_eq!(scoped.json()["login"]["signInPaths"], json!(["/session", "/api/auth/"]));
    assert_eq!(
        p.logins.credentials()[0]["sign_in_paths"],
        json!(["/session", "/api/auth/"])
    );
    let wrong = p
        .post(
            "/__cc/logins/scope",
            &again,
            json!({"id": id, "signInPaths": ["session"]}),
        )
        .await;
    assert_eq!(wrong.status, 400);
    assert!(
        wrong.json()["message"]
            .as_str()
            .unwrap_or("")
            .starts_with("Extra sign-in addresses: Use a path such as /session"),
        "{}",
        wrong.body
    );
    let slash = p
        .post(
            "/__cc/logins/scope",
            &again,
            json!({"id": id, "signInPaths": ["/a\\b"]}),
        )
        .await;
    assert!(
        slash.json()["message"]
            .as_str()
            .unwrap_or("")
            .contains("does not match this path: it has a backslash"),
        "{}",
        slash.body
    );
    let mut http_page = entry.clone();
    http_page["name"] = json!("Plain");
    http_page["loginUrl"] = json!("http://acme.example/login");
    let m = p.post("/__cc/logins/save", &again, http_page).await.json()["message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        m.starts_with("Sign-in page: Use the https address of the page with the password field")
            && m.contains("never put into a plain http page"),
        "{m}"
    );
    // An address the agent sent with its request is offered, never filled in by itself.
    assert!(script.body.contains("The agent suggests") || script.body.contains("suggesturl"));
    assert!(script.body.contains(r#"usesuggest").onclick"#));
    // The sign-in page itself can be set here too, without the password.
    let moved = p
        .post("/__cc/logins/scope", &again, json!({"id": id, "loginUrl": "https://acme.example/w/index.php?title=Special:UserLogin", "signInPaths": []}))
        .await;
    assert_eq!(
        moved.json()["login"]["loginUrl"],
        "https://acme.example/w/index.php?title=Special:UserLogin"
    );
    let mut no_page = entry.clone();
    no_page["name"] = json!("No page");
    no_page["loginUrl"] = Value::Null;
    let none = p.post("/__cc/logins/save", &again, no_page).await;
    assert_eq!(none.status, 400);
    assert!(
        none.json()["message"]
            .as_str()
            .unwrap_or("")
            .contains("Fill in the sign-in page")
    );
    let evil = [
        ("content-type", "application/json"),
        ("origin", "https://evil.example"),
        ("cookie", again.as_str()),
    ];
    let body = js::stringify(&json!({"id": id, "signInPaths": []}));
    assert_eq!(
        p.call(Method::POST, "/__cc/logins/scope", &evil, Some(body))
            .await
            .status,
        403
    );

    // A browser no longer enrolled loses the page at once.
    p.access.inactive.store(true, Ordering::SeqCst);
    assert_eq!(p.get("/__cc/logins/state", &again).await.status, 403);
    p.access.inactive.store(false, Ordering::SeqCst);

    assert_eq!(
        p.post("/__cc/logins/delete", &again, json!({"id": id})).await.status,
        200
    );
    assert_eq!(
        p.post("/__cc/logins/delete", &again, json!({"id": id})).await.status,
        404
    );
    assert_eq!(p.logins.summary()["logins"], json!([]));
    // Too much is not read.
    let big = format!("{{\"name\":\"{}\"}}", "x".repeat(BODY_BYTES));
    let h = [
        ("content-type", "application/json"),
        ("origin", ORIGIN),
        ("cookie", again.as_str()),
    ];
    let r = p.call(Method::POST, "/__cc/logins/save", &h, Some(big)).await;
    assert_eq!(
        (r.status, r.json()),
        (400, json!({"message": "That could not be read."}))
    );
}

#[tokio::test]
async fn a_chat_request_shown_answered_by_a_save_and_a_session_request_records_a_session() {
    let p = page().await;
    let (rid, _, _) = p
        .logins
        .request("a", &json!({"site": "acme.example", "reason": "To file the report"}))
        .expect("asked");
    let (cookie, location) = p.open("", &rid).await;
    assert_eq!(location, format!("/__cc/logins/?request={rid}"));
    let st = p
        .get(&format!("/__cc/logins/state?request={rid}"), &cookie)
        .await
        .json();
    let r = &st["request"];
    assert_eq!(
        json!({"site": r["site"], "agent": r["agent"], "reason": r["reason"], "answered": r["answered"]}),
        json!({"site": "acme.example", "agent": "Ada", "reason": "To file the report", "answered": false})
    );
    assert_eq!(
        p.get("/__cc/logins/state?request=lr_doesnotexist0", &cookie)
            .await
            .json()["request"],
        json!({"expired": true})
    );
    p.post(
        "/__cc/logins/save",
        &cookie,
        json!({"name": "Acme", "sites": ["acme.example"], "loginUrl": "https://acme.example/login", "username": "ops", "password": "Pw-123456", "vmIds": ["a"], "requestId": rid, "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}),
    )
    .await;
    assert_eq!(p.logins.request_status("a", &rid)["status"], "ready");

    let (sid, _, _) = p
        .logins
        .request("a", &json!({"site": "app.example", "kind": "session"}))
        .expect("asked");
    let tab = p
        .post("/__cc/logins/open-tab", &cookie, json!({"requestId": sid}))
        .await
        .json();
    assert_eq!(
        tab["screenUrl"],
        format!("https://console.example/logins/r/fw1/{sid}/screen?vm=a")
    );
    let done = p
        .post("/__cc/logins/session", &cookie, json!({"requestId": sid}))
        .await
        .json();
    assert_eq!(done["login"]["kind"], "session");
    assert_eq!(p.logins.request_status("a", &sid)["status"], "ready");
}
