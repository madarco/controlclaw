//! `doctor-terminal.test.ts`: the terminal over HTTP and its WebSocket, with `cat` standing in
//! for `cc-doctor-attach`.

use std::sync::atomic::Ordering;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::*;
use crate::integrations::doctor::firewall::tests::fixture;
use crate::integrations::doctor::pages_test::{Access, ORIGIN, client, cookie_of, open, person, serve};
use serde_json::json;

#[tokio::test]
async fn the_terminal_checks_intent_role_origin_session_and_revocation_over_http_and_websocket() {
    let f = fixture(None, None);
    f.start().await;
    let access = Arc::new(Access::default());
    f.app.contracts.page_access.set(access.clone());
    let attach: Attach = Arc::new(|_, _, _| tokio::process::Command::new("cat"));
    let t = DoctorTerminal::new(&f.app, f.doctor.clone(), Some(attach), {
        let c = f.clock.clone();
        Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst))
    });
    let (t1, t2) = (t.clone(), t.clone());
    let base = serve(move |reg| {
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, p| owns(p),
            move |req, _| {
                let t = t1.clone();
                async move { t.handle(req).await }
            },
        );
        if let Some(up) = reg.ingress.upgrades_mut() {
            up.route(
                crate::stages::INGRESS_UPGRADE,
                |_, p| p == "/__cc/doctor/ws",
                move |req, _| {
                    let t = t2.clone();
                    async move { t.upgrade(req).await }
                },
            );
        }
    })
    .await;
    let page = client()
        .get(format!("{base}/__cc/doctor/open"))
        .send()
        .await
        .expect("send");
    assert_eq!(page.headers()["referrer-policy"], "same-origin");
    let set = |w: bool, sid: &str| {
        *access.person.lock().expect("lock") = Some(person(w, json!({"sessionId": sid, "vmId": "vm-1"})))
    };
    set(true, "session-1");
    assert_eq!(open(&base, "/__cc/doctor/open", "null").await.status(), 403);
    set(false, "session-1");
    assert_eq!(
        open(&base, "/__cc/doctor/open", ORIGIN).await.status(),
        403,
        "an owner or admin only"
    );
    set(true, "another-session");
    assert_eq!(open(&base, "/__cc/doctor/open", ORIGIN).await.status(), 403);
    set(true, "session-1");
    let r = open(&base, "/__cc/doctor/open", ORIGIN).await;
    assert_eq!(r.status(), 303);
    assert!(
        r.headers()["set-cookie"]
            .to_str()
            .unwrap_or("")
            .contains("Path=/__cc/doctor; Secure; HttpOnly; SameSite=Strict")
    );
    assert_eq!(f.doctor.session("session-1").expect("s")["mode"], "terminal");
    let cookie = cookie_of(&r);
    assert_eq!(
        client()
            .get(format!("{base}/__cc/doctor/"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("send")
            .status(),
        200
    );
    let ws = |origin: &str| {
        let mut req = format!("{}/__cc/doctor/ws", base.replace("http", "ws"))
            .into_client_request()
            .expect("request");
        req.headers_mut().insert("origin", origin.parse().expect("origin"));
        req.headers_mut().insert("cookie", cookie.parse().expect("cookie"));
        tokio_tungstenite::connect_async(req)
    };
    assert!(
        ws("https://evil.example.com").await.is_err(),
        "a cross-origin socket is refused"
    );
    let (mut sock, _) = ws(ORIGIN).await.expect("socket");
    sock.send(Message::text(r#"{"type":"input","data":"hello terminal"}"#))
        .await
        .expect("send");
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(3), sock.next())
        .await
        .expect("in time")
        .expect("message")
        .expect("ok");
    assert!(String::from_utf8_lossy(&echoed.into_data()).contains("hello terminal"));
    // A second socket replaces the first.
    let (mut second, _) = ws(ORIGIN).await.expect("socket");
    let closed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Some(Ok(m)) = sock.next().await {
            if m.is_close() {
                break;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the first socket is closed");
    second
        .send(Message::text(r#"{"type":"resize","cols":40,"rows":20}"#))
        .await
        .expect("send");
    let got = tokio::time::timeout(std::time::Duration::from_secs(3), second.next())
        .await
        .expect("in time")
        .expect("message")
        .expect("ok");
    assert!(String::from_utf8_lossy(&got.into_data()).contains("\"cols\":40"));
    // Something that is not a terminal message ends the socket.
    second
        .send(Message::text(r#"{"type":"input","data":5}"#))
        .await
        .expect("send");
    let ended = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Some(Ok(_)) = second.next().await {}
    })
    .await;
    assert!(ended.is_ok());
    // No longer enrolled: refused.
    access.inactive.store(true, Ordering::SeqCst);
    assert_eq!(
        client()
            .get(format!("{base}/__cc/doctor/"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("send")
            .status(),
        403
    );
}
