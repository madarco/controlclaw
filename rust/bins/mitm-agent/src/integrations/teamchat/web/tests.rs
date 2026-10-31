//! `teamchat-web.test.ts`: the people's routes over real HTTP, with a running Team chat (fake
//! ClickClack) and W3's access stood in.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::contracts::{PageAccess, PagePerson};
use crate::integrations::teamchat::firewall::tests::rig;
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
    fn authorize(&self, _: &HeaderMap, _: String, next: &str) -> cc_http::BoxFuture<Option<PagePerson>> {
        assert_eq!(next, "team-chat");
        let p = self.person.lock().expect("lock").clone();
        Box::pin(async move { p })
    }
    fn device_active(&self, _: &HeaderMap, next: &str, _: &str, _: &str, _: Option<&str>) -> bool {
        assert_eq!(next, "team-chat");
        !self.inactive.load(Ordering::SeqCst)
    }
}

fn person() -> PagePerson {
    let mut extra = Map::new();
    extra.insert("name".into(), serde_json::json!("Marco"));
    PagePerson {
        user_id: "u1".into(),
        device_id: "dev_1".into(),
        email: None,
        can_write: true,
        extra,
    }
}

#[tokio::test]
async fn the_peoples_routes_open_verify_and_the_upgrade_shaped_check() {
    let r = rig();
    let access = Arc::new(Access::default());
    r.app.contracts.page_access.set(access.clone());
    let chat = r.turned_on().await;
    let mut ingress = cc_http::Router::new(crate::stages::INGRESS);
    ingress.fallback(cc_http::empty_not_found);
    let mut up = cc_http::Router::new(&[crate::stages::INGRESS_UPGRADE]);
    up.fallback(|| cc_http::empty(403));
    ingress.upgrades(up);
    let mut reg = crate::app::Registry {
        plain: cc_http::Router::new(crate::stages::PLAIN),
        tls: cc_http::Router::new(crate::stages::TLS),
        ingress,
        commands: crate::commands::Commands::default(),
    };
    route(&mut reg, TeamChatWeb::new(&r.app, chat.clone()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = l.local_addr().expect("addr").to_string();
    let base = format!("http://{addr}");
    tokio::spawn(cc_http::serve(l, Arc::new(reg.ingress)));
    let http = reqwest::Client::builder().no_proxy().build().expect("client");
    let verify = |cookie: Option<String>| {
        let mut q = http.get(format!("{base}/__cc/team-chat/verify"));
        if let Some(c) = cookie {
            q = q.header("cookie", c);
        }
        q.send()
    };
    let open = |origin: Option<&str>| {
        let mut q = http
            .post(format!("{base}/__cc/team-chat/open"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("intent=x");
        if let Some(o) = origin {
            q = q.header("origin", o);
        }
        q.send()
    };

    // verify: a bare 404 without a cookie, with a junk one, or with two.
    let c = "c".repeat(43);
    for cookie in [
        None,
        Some("__Host-cc_team_chat=nope".to_string()),
        Some(format!("__Host-cc_team_chat={c}; __Host-cc_team_chat={c}")),
    ] {
        let v = verify(cookie).await.expect("send");
        assert_eq!(v.status(), 404);
        assert_eq!(v.text().await.expect("text"), "");
    }
    // The open page posts back to itself, and its referrer policy keeps the Origin header.
    let p = http
        .get(format!("{base}/__cc/team-chat/open"))
        .send()
        .await
        .expect("send");
    assert_eq!(p.status(), 200);
    assert_eq!(p.headers()["referrer-policy"], "same-origin");
    assert!(
        p.headers()["content-security-policy"]
            .to_str()
            .unwrap_or("")
            .contains("frame-ancestors 'none'")
    );
    assert!(p.text().await.expect("text").contains("open.js"));
    // Open from another origin, with none, or `null`: refused bare.
    for o in [Some("https://evil.example"), None, Some("null")] {
        assert_eq!(open(o).await.expect("send").status(), 403, "{o:?}");
    }
    // An intent the access module refuses gets the page that says why, and no cookie.
    let refused = open(Some(ORIGIN)).await.expect("send");
    assert_eq!(refused.status(), 403);
    assert!(refused.headers().get("set-cookie").is_none());
    assert!(
        refused
            .text()
            .await
            .expect("text")
            .contains("already used to open one of your agents")
    );
    // Let in: a __Host- cookie, a page that consumes the magic link on this origin, verify 200.
    *access.person.lock().expect("lock") = Some(person());
    let ok = open(Some(ORIGIN)).await.expect("send");
    assert_eq!(ok.status(), 200);
    let set = ok.headers()["set-cookie"].to_str().expect("cookie").to_string();
    assert!(
        regex::Regex::new(
            r"^__Host-cc_team_chat=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=43200$"
        )
        .expect("re")
        .is_match(&set),
        "{set}"
    );
    let body = ok.text().await.expect("text");
    assert!(body.contains(r#"name="cc-team-chat" content="mgt_person0000000""#) && body.contains("login.js"));
    let js = http
        .get(format!("{base}/__cc/team-chat/login.js"))
        .send()
        .await
        .expect("send")
        .text()
        .await
        .expect("text");
    assert!(
        js.contains("/api/auth/magic/consume")
            && js.contains(r#""x-clickclack-csrf":"1""#)
            && js.contains(r#"location.replace("/app")"#)
    );
    let cookie = set.split(';').next().expect("pair").to_string();
    assert_eq!(verify(Some(cookie.clone())).await.expect("send").status(), 200);
    // verify follows the browser: removed from Devices, or Team chat turned off: a 404 again.
    access.inactive.store(true, Ordering::SeqCst);
    assert_eq!(verify(Some(cookie.clone())).await.expect("send").status(), 404);
    access.inactive.store(false, Ordering::SeqCst);
    // verify answers a WebSocket-shaped check with a status, never an upgrade.
    let ask = |cookie: Option<String>| {
        let addr = addr.clone();
        async move {
            let mut s = tokio::net::TcpStream::connect(&addr).await.expect("connect");
            let c = cookie.map(|c| format!("cookie: {c}\r\n")).unwrap_or_default();
            s.write_all(format!("GET /__cc/team-chat/verify HTTP/1.1\r\nhost: x\r\nconnection: Upgrade\r\nupgrade: websocket\r\n{c}\r\n").as_bytes())
                .await
                .expect("write");
            let mut head = [0u8; 12];
            s.read_exact(&mut head).await.expect("read");
            String::from_utf8_lossy(&head[9..12]).to_string()
        }
    };
    assert_eq!(ask(Some(cookie.clone())).await, "200");
    assert_eq!(ask(None).await, "404");
    // Team chat off: verify is a 404, and opening says it is off.
    chat.handle("disable", Map::new()).await;
    assert_eq!(verify(Some(cookie)).await.expect("send").status(), 404);
    let off = open(Some(ORIGIN)).await.expect("send");
    assert_eq!(off.status(), 503);
    assert!(off.headers().get("set-cookie").is_none());
}
