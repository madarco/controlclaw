//! The admin login and the API, over HTTP: setup with the token once, a session cookie, CSRF on
//! every write, SaaS-only actions refused, commands straight to the handler.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::plane::{Call, ControlPlane};

struct World {
    base: String,
    http: reqwest::Client,
    plane: Arc<LocalControlPlane>,
    ran: Arc<Mutex<Vec<(String, Value)>>>,
    token: String,
}

async fn world() -> World {
    let db = Arc::new(Db::memory().expect("db"));
    let plane = Arc::new(LocalControlPlane::new(db.clone()));
    plane.register_self("fw").expect("self");
    let ran: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    let r = ran.clone();
    let hooks = Hooks {
        command: Arc::new(move |action, payload| {
            let r = r.clone();
            Box::pin(async move {
                if action == "health.probe" {
                    return None;
                }
                r.lock().expect("lock").push((action.clone(), Value::Object(payload)));
                Some(json!({"ok": true, "status": "applied"}))
            })
        }),
        open_link: Arc::new(|page| Ok(format!("https://fw.example/__cc/local/open#page={page}"))),
        ..Default::default()
    };
    let admin = Admin::new(
        db,
        plane.clone(),
        hooks,
        AdminConfig::with_hosts(false, ["fw.example".to_string()]),
    );
    let token = admin.setup_token().expect("a token with no admin");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(admin.router())));
    World {
        base,
        http: reqwest::Client::builder().cookie_store(true).build().expect("client"),
        plane,
        ran,
        token,
    }
}

impl World {
    async fn send(&self, method: reqwest::Method, path: &str, csrf: Option<&str>, body: Option<Value>) -> (u16, Value) {
        let mut r = self.http.request(method, format!("{}{path}", self.base));
        if let Some(c) = csrf {
            r = r.header("x-csrf-token", c);
        }
        if let Some(b) = body {
            r = r.json(&b);
        }
        let res = r.send().await.expect("send");
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn setup_login_csrf_and_commands() {
    let w = world().await;
    let post = reqwest::Method::POST;
    assert_eq!(
        w.send(reqwest::Method::GET, "/api/egress-rules", None, None).await.0,
        401
    );
    let (s, b) = w.send(reqwest::Method::GET, "/api/session", None, None).await;
    assert_eq!(
        (s, b["admin"].clone(), b["setup"].clone()),
        (200, json!(false), json!(true))
    );

    assert_eq!(
        w.send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": "nope", "password": "a long password"}))
        )
        .await
        .0,
        401
    );
    assert_eq!(
        w.send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "short"}))
        )
        .await
        .0,
        400
    );
    let (s, b) = w
        .send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    assert_eq!(
        w.send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "another password"}))
        )
        .await
        .0,
        409,
        "spent"
    );

    // A write without the token, or with another, is refused.
    let rules =
        json!({"rules": [{"name": "Allow example", "match_domain": "example.com", "effect": "allow", "priority": 10}]});
    assert_eq!(
        w.send(reqwest::Method::PUT, "/api/egress-rules", None, Some(rules.clone()))
            .await
            .0,
        403
    );
    assert_eq!(
        w.send(
            reqwest::Method::PUT,
            "/api/egress-rules",
            Some("x"),
            Some(rules.clone())
        )
        .await
        .0,
        403
    );
    assert_eq!(
        w.send(reqwest::Method::PUT, "/api/egress-rules", Some(&csrf), Some(rules))
            .await
            .0,
        200
    );
    let a = w
        .plane
        .call(
            "fw",
            Call {
                method: "GET".into(),
                path: "/api/vm-agent/egress-rules".into(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(a.body["rules"][0]["match_domain"], "example.com");

    // Commands: a SaaS-only action is refused, a malformed payload too, and the rest run at once.
    assert_eq!(
        w.send(
            post.clone(),
            "/api/commands",
            Some(&csrf),
            Some(json!({"action": "backup.run"}))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        w.send(
            post.clone(),
            "/api/commands",
            Some(&csrf),
            Some(json!({"action": "email.confirm", "payload": {"code": "1"}}))
        )
        .await
        .0,
        400
    );
    let (s, b) = w
        .send(
            post.clone(),
            "/api/commands",
            Some(&csrf),
            Some(json!({"action": "email.cancel", "payload": {"changeId": "c1"}})),
        )
        .await;
    assert_eq!((s, b), (200, json!({"ok": true, "status": "applied"})));
    assert_eq!(
        w.ran.lock().expect("lock")[0],
        ("email.cancel".to_string(), json!({"changeId": "c1"}))
    );
    assert_eq!(
        w.send(
            post.clone(),
            "/api/commands",
            Some(&csrf),
            Some(json!({"action": "health.probe", "payload": {"vmId": "a1"}}))
        )
        .await
        .0,
        404
    );

    let (s, b) = w
        .send(post.clone(), "/api/open", Some(&csrf), Some(json!({"page": "logins"})))
        .await;
    assert_eq!((s, b["url"].as_str().is_some()), (200, true));

    // Signed out, then in again with the password; a wrong one is refused.
    assert_eq!(w.send(post.clone(), "/api/logout", Some(&csrf), None).await.0, 200);
    assert_eq!(w.send(reqwest::Method::GET, "/api/agents", None, None).await.0, 401);
    assert_eq!(
        w.send(
            post.clone(),
            "/api/login",
            None,
            Some(json!({"password": "wrong password!"}))
        )
        .await
        .0,
        401
    );
    let (s, b) = w
        .send(
            post.clone(),
            "/api/login",
            None,
            Some(json!({"password": "a long password"})),
        )
        .await;
    assert_eq!(s, 200);
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    let agents = json!({"agents": [{"vm_id": "a1", "name": "agent-1", "private_ip": "10.0.0.3"}]});
    assert_eq!(
        w.send(reqwest::Method::PUT, "/api/agents", Some(&csrf), Some(agents))
            .await
            .0,
        200
    );
    let a = w
        .plane
        .call(
            "fw",
            Call {
                method: "GET".into(),
                path: "/api/vm-agent/identities".into(),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(a.body["identities"][0]["vm_id"], "a1");

    // A permission request is answered by its own id.
    let raise = json!({"permission_id": "p1", "kind": "access", "host": "example.com", "method": "GET"});
    let call = Call {
        method: "POST".into(),
        path: "/api/vm-agent/permission".into(),
        body: Some(raise),
        ..Default::default()
    };
    assert_eq!(w.plane.call("fw", call).await.status, 200);
    let (_, b) = w.send(reqwest::Method::GET, "/api/permissions", None, None).await;
    let id = b["requests"][0]["id"].as_i64().expect("id");
    let answer = |body: Value| {
        w.send(
            reqwest::Method::POST,
            "/api/permissions/answer",
            Some(&csrf),
            Some(body),
        )
    };
    assert_eq!(
        answer(json!({"permission_id": "p1", "resolution": "approved"})).await.0,
        400,
        "the box's id is not enough"
    );
    assert_eq!(answer(json!({"id": id, "resolution": "approved"})).await.0, 200);
    assert_eq!(
        answer(json!({"id": id, "resolution": "denied"})).await.0,
        409,
        "answered once"
    );
}

#[test]
fn passwords_are_argon2() {
    let h = Admin::hash_password("a long password").expect("hash");
    assert!(h.starts_with("$argon2id$"), "{h}");
    assert!(Admin::check_password("a long password", &h));
    assert!(!Admin::check_password("a long passworD", &h));
}

#[tokio::test]
async fn another_host_name_service_actions_and_the_throttle() {
    let w = world().await;
    let post = reqwest::Method::POST;
    // A page whose name resolves to 127.0.0.1 (DNS rebinding) sends its own name.
    let r = w
        .http
        .get(format!("{}/api/session", w.base))
        .header("host", "evil.example:8800")
        .send()
        .await
        .expect("send");
    assert_eq!(r.status().as_u16(), 421);
    let r = w
        .http
        .get(format!("{}/api/session", w.base))
        .header("host", "FW.example")
        .send()
        .await
        .expect("send");
    assert_eq!(r.status().as_u16(), 200, "a configured name, any case");

    let (_, b) = w
        .send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    let (s, b) = w
        .send(
            post.clone(),
            "/api/commands",
            Some(&csrf),
            Some(json!({"action": "restart"})),
        )
        .await;
    assert_eq!(s, 403, "{b}");

    // Ten tries a minute from one address; the eleventh is refused even with the right password.
    for _ in 0..10 {
        assert_eq!(
            w.send(
                post.clone(),
                "/api/login",
                None,
                Some(json!({"password": "wrong password!"}))
            )
            .await
            .0,
            401
        );
    }
    assert_eq!(
        w.send(post, "/api/login", None, Some(json!({"password": "a long password"})))
            .await
            .0,
        429
    );
}

#[tokio::test]
async fn pairing_codes_need_the_session_and_csrf() {
    let w = world().await;
    let post = reqwest::Method::POST;
    let path = "/api/pairing/codes";
    assert_eq!(w.send(post.clone(), path, None, Some(json!({}))).await.0, 401);
    let (_, b) = w
        .send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    assert_eq!(w.send(post.clone(), path, None, Some(json!({}))).await.0, 403);
    let (s, made) = w.send(post, path, Some(&csrf), Some(json!({"name": "pi"}))).await;
    assert_eq!(s, 200, "{made}");
    assert!(crate::pairing::normalize(made["code"].as_str().expect("code")).is_some());
    let (s, list) = w.send(reqwest::Method::GET, path, None, None).await;
    assert_eq!((s, list["codes"].as_array().map(Vec::len)), (200, Some(1)));
    let id = made["id"].as_i64().expect("id");
    let del = format!("{path}/{id}");
    assert_eq!(w.send(reqwest::Method::DELETE, &del, None, None).await.0, 403);
    assert_eq!(w.send(reqwest::Method::DELETE, &del, Some(&csrf), None).await.0, 200);
}

#[tokio::test]
async fn a_put_of_the_agents_keeps_what_pairing_recorded() {
    let w = world().await;
    let db = w.plane.db.clone();
    db.lock()
        .execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, public_key, created_at, paired_at, unpair_sha256, wg_public_key, agent_addr) VALUES ('agent_1', 'openclaw', 'a', '10.0.0.5', 'KEY', 5, 6, 'UNPAIR', 'WG', '172.31.252.1:3100')",
            [],
        )
        .expect("paired agent");
    let (_, b) = w
        .send(
            reqwest::Method::POST,
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    // What a panel does: GET (no key in it), rename one, PUT the list back.
    let (_, list) = w.send(reqwest::Method::GET, "/api/agents", None, None).await;
    let mut agents = list["agents"].clone();
    agents[0]["name"] = json!("renamed");
    let (s, b) = w
        .send(
            reqwest::Method::PUT,
            "/api/agents",
            Some(&csrf),
            Some(json!({"agents": agents})),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    type Row = (String, Option<String>, Option<i64>, i64, Option<String>, Option<String>);
    let row: Row = db
        .lock()
        .query_row(
            "SELECT name, public_key, paired_at, created_at, unpair_sha256, wg_public_key FROM agents WHERE vm_id = 'agent_1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .expect("row");
    let addr = |db: &crate::db::Db| -> Option<String> {
        db.lock()
            .query_row("SELECT agent_addr FROM agents WHERE vm_id = 'agent_1'", [], |r| {
                r.get(0)
            })
            .expect("addr")
    };
    assert_eq!(
        addr(&db).as_deref(),
        Some("172.31.252.1:3100"),
        "where its vm-agent listens"
    );
    // Without it in the list, kept; a bad one refused; a good one taken.
    agents[0]["agent_addr"] = json!("nowhere");
    let (s, _) = w
        .send(
            reqwest::Method::PUT,
            "/api/agents",
            Some(&csrf),
            Some(json!({"agents": agents})),
        )
        .await;
    assert_eq!(s, 400);
    agents[0]["agent_addr"] = json!("10.0.0.5:3101");
    let (s, _) = w
        .send(
            reqwest::Method::PUT,
            "/api/agents",
            Some(&csrf),
            Some(json!({"agents": agents})),
        )
        .await;
    assert_eq!(s, 200);
    assert_eq!(addr(&db).as_deref(), Some("10.0.0.5:3101"));
    // Moved to another address with none given: its vm-agent is at the new one (the default).
    agents[0]["agent_addr"] = Value::Null;
    agents[0]["private_ip"] = json!("10.0.0.9");
    let (s, _) = w
        .send(
            reqwest::Method::PUT,
            "/api/agents",
            Some(&csrf),
            Some(json!({"agents": agents})),
        )
        .await;
    assert_eq!(s, 400, "a WireGuard agent stays at its tunnel address");
    db.lock()
        .execute("UPDATE agents SET wg_public_key = NULL WHERE vm_id = 'agent_1'", [])
        .expect("not over the tunnel");
    let (s, _) = w
        .send(
            reqwest::Method::PUT,
            "/api/agents",
            Some(&csrf),
            Some(json!({"agents": agents})),
        )
        .await;
    assert_eq!(s, 200);
    assert_eq!(addr(&db), None);
    assert_eq!(
        row,
        (
            "renamed".into(),
            Some("KEY".into()),
            Some(6),
            5,
            Some("UNPAIR".into()),
            Some("WG".into())
        )
    );
}

#[tokio::test]
async fn the_password_changes_and_the_other_sessions_end() {
    let w = world().await;
    let post = reqwest::Method::POST;
    let path = "/api/admin/password";
    let (_, b) = w
        .send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    // Another browser, signed in before the change.
    let other = reqwest::Client::builder().cookie_store(true).build().expect("client");
    let r = other
        .post(format!("{}/api/login", w.base))
        .json(&json!({"password": "a long password"}))
        .send()
        .await
        .expect("send");
    assert_eq!(r.status().as_u16(), 200);
    let other_session = || async {
        let r = other.get(format!("{}/api/session", w.base)).send().await.expect("send");
        r.json::<Value>().await.expect("json")["admin"].as_bool()
    };
    assert_eq!(other_session().await, Some(true));

    let body = json!({"current": "a long password", "new": "another long password"});
    assert_eq!(
        w.send(post.clone(), path, None, Some(body.clone())).await.0,
        403,
        "CSRF"
    );
    let (s, b) = w
        .send(
            post.clone(),
            path,
            Some(&csrf),
            Some(json!({"current": "wrong password!", "new": "another long password"})),
        )
        .await;
    assert_eq!(s, 400, "{b}");
    let (s, b) = w
        .send(
            post.clone(),
            path,
            Some(&csrf),
            Some(json!({"current": "a long password", "new": "short"})),
        )
        .await;
    assert_eq!(s, 400, "{b}");
    let (s, b) = w.send(post.clone(), path, Some(&csrf), Some(body)).await;
    assert_eq!((s, b["signedOut"].as_u64()), (200, Some(1)), "{b}");

    assert_eq!(other_session().await, Some(false), "the other browser is signed out");
    let (s, b) = w.send(reqwest::Method::GET, "/api/session", None, None).await;
    assert_eq!((s, b["admin"].as_bool()), (200, Some(true)), "this one stays");
    let login = |pw: &'static str| {
        let other = other.clone();
        let url = format!("{}/api/login", w.base);
        async move {
            other
                .post(url)
                .json(&json!({"password": pw}))
                .send()
                .await
                .expect("send")
                .status()
                .as_u16()
        }
    };
    assert_eq!(login("a long password").await, 401);
    assert_eq!(login("another long password").await, 200);
}

#[tokio::test]
async fn wrong_current_passwords_use_the_login_throttle() {
    let w = world().await;
    let post = reqwest::Method::POST;
    let (_, b) = w
        .send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    let wrong = json!({"current": "wrong password!", "new": "another long password"});
    for _ in 0..10 {
        assert_eq!(
            w.send(post.clone(), "/api/admin/password", Some(&csrf), Some(wrong.clone()))
                .await
                .0,
            400
        );
    }
    let right = json!({"current": "a long password", "new": "another long password"});
    assert_eq!(
        w.send(post, "/api/admin/password", Some(&csrf), Some(right)).await.0,
        429
    );
}

#[tokio::test]
async fn a_reset_asks_for_setup_again_and_ends_every_session() {
    let db = Arc::new(Db::memory().expect("db"));
    let plane = Arc::new(LocalControlPlane::new(db.clone()));
    let admin = Admin::new(db.clone(), plane, Hooks::default(), AdminConfig::with_hosts(false, []));
    let first = admin.setup_token().expect("token");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(admin.router())));
    let http = reqwest::Client::builder().cookie_store(true).build().expect("client");
    let setup = |token: String| {
        let (http, url) = (http.clone(), format!("{base}/api/setup"));
        async move {
            http.post(url)
                .json(&json!({"token": token, "password": "a long password"}))
                .send()
                .await
                .expect("send")
                .status()
                .as_u16()
        }
    };
    let session = || async {
        let r = http.get(format!("{base}/api/session")).send().await.expect("send");
        r.json::<Value>().await.expect("json")
    };
    assert_eq!(setup(first.clone()).await, 200);
    assert_eq!(session().await["admin"], json!(true));

    let t = reset(&db).expect("reset");
    let s = session().await;
    assert_eq!(
        (s["admin"].clone(), s["setup"].clone()),
        (json!(false), json!(true)),
        "{s}"
    );
    assert_eq!(setup(first).await, 401, "the old token is spent");
    assert_eq!(setup(t).await, 200);
    assert_eq!(session().await["admin"], json!(true));
}

#[test]
fn a_password_change_writes_only_over_the_hash_it_checked() {
    let db = Arc::new(Db::memory().expect("db"));
    let plane = Arc::new(LocalControlPlane::new(db.clone()));
    let admin = Admin::new(db.clone(), plane, Hooks::default(), AdminConfig::with_hosts(false, []));
    let first = Admin::hash_password("a long password").expect("hash");
    db.lock()
        .execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES ('admin', ?1, 0)",
            [&first],
        )
        .expect("admin");
    let id = db.lock().last_insert_rowid();
    let (mine, _) = admin.start_session(id).expect("session");
    let (other, _) = admin.start_session(id).expect("session");
    let sess = |c: &str| admin.session(Some(&format!("{COOKIE}={c}"))).expect("signed in");
    let stored = || -> String {
        db.lock()
            .query_row("SELECT password_hash FROM admin_users", [], |r| r.get(0))
            .expect("hash")
    };

    // Another change landed between the check and the write: nothing is written, nobody is signed out.
    let theirs = Admin::hash_password("their long password").expect("hash");
    db.lock()
        .execute("UPDATE admin_users SET password_hash = ?1", [&theirs])
        .expect("update");
    let mine_new = Admin::hash_password("my long password").expect("hash");
    assert_eq!(admin.store_password(&sess(&mine), &first, &mine_new), Ok(None));
    assert_eq!(stored(), theirs);
    assert!(admin.session(Some(&format!("{COOKIE}={other}"))).is_some());

    // Over the hash it checked: written, and the other session ends.
    assert_eq!(admin.store_password(&sess(&mine), &theirs, &mine_new), Ok(Some(1)));
    assert_eq!(stored(), mine_new);
    assert!(admin.session(Some(&format!("{COOKIE}={other}"))).is_none());

    // A reset in flight: the admin is gone, so the change is refused.
    let s = sess(&mine);
    reset(&db).expect("reset");
    assert_eq!(admin.store_password(&s, &mine_new, &first), Ok(None));
}

#[tokio::test]
async fn a_change_that_lost_the_race_is_409() {
    let w = world().await;
    let post = reqwest::Method::POST;
    let (_, b) = w
        .send(
            post.clone(),
            "/api/setup",
            None,
            Some(json!({"token": w.token, "password": "a long password"})),
        )
        .await;
    let csrf = b["csrf"].as_str().expect("csrf").to_string();
    // Two changes from the same password at once: one wins, the other is 409 and writes nothing.
    let body = |n: &str| Some(json!({"current": "a long password", "new": n}));
    let (a, b) = tokio::join!(
        w.send(
            post.clone(),
            "/api/admin/password",
            Some(&csrf),
            body("first new password")
        ),
        w.send(
            post.clone(),
            "/api/admin/password",
            Some(&csrf),
            body("second new password")
        ),
    );
    let mut got = [a.0, b.0];
    got.sort_unstable();
    // Both may also run one after the other: then the second's current password is wrong (400).
    assert!(got == [200, 409] || got == [200, 400], "{a:?} {b:?}");
}
