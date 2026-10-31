//! `doctor-chat.test.ts`: the chat over real HTTP, with access stood in and a real session.

use std::sync::atomic::Ordering;

use super::*;
use crate::integrations::doctor::firewall::tests::fixture;
use crate::integrations::doctor::pages_test::{Access, ORIGIN, client, cookie_of, open, person, serve};

#[tokio::test]
async fn the_chat_checks_enrollment_role_binding_origin_replay_streaming_and_revocation() {
    let f = fixture(None, None);
    f.start().await;
    let access = Arc::new(Access::default());
    f.app.contracts.page_access.set(access.clone());
    let chat = DoctorChat::new(&f.app, f.doctor.clone(), {
        let c = f.clock.clone();
        Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst))
    });
    let c = chat.clone();
    let base = serve(move |reg| {
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, p| p.starts_with(ROOT),
            move |req, _| {
                let c = c.clone();
                async move { c.handle(req).await }
            },
        )
    })
    .await;
    let set = |can_write: bool, sid: &str, vm: &str| {
        *access.person.lock().expect("lock") = Some(person(can_write, json!({"sessionId": sid, "vmId": vm})))
    };
    // No intent the access module takes, another origin, or another session or agent: refused.
    assert_eq!(open(&base, "/__cc/doctor/chat/open", ORIGIN).await.status(), 403);
    set(true, "session-1", "vm-1");
    assert_eq!(
        open(&base, "/__cc/doctor/chat/open", "https://evil.example")
            .await
            .status(),
        403
    );
    for (sid, vm) in [("session-other", "vm-1"), ("session-1", "vm-other")] {
        set(true, sid, vm);
        assert_eq!(
            open(&base, "/__cc/doctor/chat/open", ORIGIN).await.status(),
            403,
            "{sid} {vm}"
        );
    }
    assert_eq!(
        access.asked.lock().expect("lock").last().map(String::as_str),
        Some("doctor-chat")
    );
    set(true, "session-1", "vm-1");
    let r = open(&base, "/__cc/doctor/chat/open", ORIGIN).await;
    assert_eq!(r.status(), 303);
    assert!(
        r.headers()["set-cookie"]
            .to_str()
            .unwrap_or("")
            .contains("Path=/__cc/doctor/chat; Secure; HttpOnly; SameSite=Strict; Max-Age=7200")
    );
    let cookie = cookie_of(&r);
    // The same intent again: the access module took it once.
    assert_eq!(open(&base, "/__cc/doctor/chat/open", ORIGIN).await.status(), 403);
    assert_eq!(
        client()
            .get(format!("{base}{ROOT}/"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("send")
            .status(),
        200
    );
    let post = |path: &str, cookie: &str, origin: &str| {
        client()
            .post(format!("{base}{ROOT}{path}"))
            .header("cookie", cookie)
            .header("origin", origin)
            .header("content-type", "application/json")
            .body(r#"{"text":"private follow-up"}"#)
            .send()
    };
    assert_eq!(post("/message", &cookie, "null").await.expect("send").status(), 403);
    let runs = f.runs().len();
    assert_eq!(post("/message", &cookie, ORIGIN).await.expect("send").status(), 200);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(f.runs().len(), runs + 1);
    // A member who can only read: no message, no stop, no delete.
    set(false, "session-1", "vm-1");
    let read = cookie_of(&open(&base, "/__cc/doctor/chat/open", ORIGIN).await);
    for path in ["/message", "/stop", "/delete"] {
        assert_eq!(post(path, &read, ORIGIN).await.expect("send").status(), 403, "{path}");
    }
    let mut events = client()
        .get(format!("{base}{ROOT}/events"))
        .header("cookie", &read)
        .send()
        .await
        .expect("send");
    let first = events.chunk().await.expect("chunk").expect("data");
    assert!(String::from_utf8_lossy(&first).contains("Repair OpenClaw."));
    // The browser is no longer enrolled: the page is refused and the stream ends.
    access.inactive.store(true, Ordering::SeqCst);
    assert_eq!(
        client()
            .get(format!("{base}{ROOT}/"))
            .header("cookie", &cookie)
            .send()
            .await
            .expect("send")
            .status(),
        403
    );
    let ended = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Ok(Some(_)) = events.chunk().await {}
    })
    .await;
    assert!(ended.is_ok(), "the open stream closes");
}
