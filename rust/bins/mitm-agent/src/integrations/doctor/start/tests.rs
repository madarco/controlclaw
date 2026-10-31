//! `doctor-start.test.ts`: the choices, and a repair started on this page from the intent to the chat.

use super::*;
use crate::integrations::doctor::firewall::tests::fixture;
use crate::integrations::doctor::pages_test::{Access, ORIGIN, client, cookie_of, open, person, serve};

fn choices() -> Value {
    json!([
        {"id": "credential-1", "label": "Anthropic", "provider": "anthropic", "clis": ["claude"], "models": [{"id": "claude-sonnet-4-5", "name": "Sonnet"}]},
        {"id": "gw", "label": "Gateway", "provider": "vercel_gateway", "clis": ["claude", "codex"], "models": []},
    ])
}

#[test]
fn only_the_consoles_models_are_offered_except_for_a_gateway_key() {
    let c = choices().as_array().cloned().unwrap_or_default();
    assert!(choice_allows(&c, "claude", "credential-1", "claude-sonnet-4-5"));
    assert!(!choice_allows(&c, "claude", "credential-1", "claude-opus-5-5"));
    assert!(!choice_allows(&c, "codex", "credential-1", "claude-sonnet-4-5"));
    assert!(choice_allows(&c, "codex", "gw", "openai/anything"));
    assert!(!choice_allows(&c, "claude", "nope", "x"));
}

#[tokio::test]
async fn a_repair_from_an_owners_intent_the_code_from_the_same_browser_then_the_chat_with_the_problem_first() {
    let f = fixture(None, None);
    let access = Arc::new(Access::default());
    f.app.contracts.page_access.set(access.clone());
    let chat = DoctorChat::new(&f.app, f.doctor.clone(), {
        let c = f.clock.clone();
        Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst))
    });
    let targets = f.targets.clone();
    let start = DoctorStart::new(
        &f.app,
        f.doctor.clone(),
        chat,
        Arc::new(move || targets.lock().expect("lock").clone()),
        Arc::new(|| None),
        "/nonexistent".into(),
        Arc::new(js::now_ms),
    );
    let s = start.clone();
    let base = serve(move |reg| {
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, p| owns(p),
            move |req, _| {
                let s = s.clone();
                async move { s.handle(req).await }
            },
        )
    })
    .await;
    // Without the console's choices in the intent: refused.
    *access.person.lock().expect("lock") = Some(person(true, json!({})));
    assert_eq!(open(&base, "/__cc/doctor/start/open", ORIGIN).await.status(), 403);
    // A member's intent (no canWrite): refused, members cannot start Doctor.
    *access.person.lock().expect("lock") = Some(person(
        false,
        json!({"doctorChoices": choices(), "doctorAgent": "vm-1"}),
    ));
    assert_eq!(open(&base, "/__cc/doctor/start/open", ORIGIN).await.status(), 403);
    *access.person.lock().expect("lock") =
        Some(person(true, json!({"doctorChoices": choices(), "doctorAgent": "vm-1"})));
    let r = open(&base, "/__cc/doctor/start/open", ORIGIN).await;
    assert_eq!(r.status(), 303);
    let cookie = cookie_of(&r);
    let state: Value = client()
        .get(format!("{base}{ROOT}/state"))
        .header("cookie", &cookie)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(
        state["agents"],
        json!([{"vmId": "vm-1", "name": "agent-one", "ready": true}])
    );
    assert_eq!(state["selected"], "vm-1");
    let post = |path: &str, body: Value| {
        client()
            .post(format!("{base}{ROOT}{path}"))
            .header("cookie", &cookie)
            .header("origin", ORIGIN)
            .header("content-type", "application/json")
            .body(js::stringify(&body))
            .send()
    };
    let bad = post("/propose", json!({"vmId": "vm-1", "cli": "claude", "credentialId": "credential-1", "model": "claude-opus-5-5", "problem": "x"})).await.expect("send");
    assert_eq!(bad.status(), 400);
    let proposed: Value = post("/propose", json!({"vmId": "vm-1", "cli": "claude", "credentialId": "credential-1", "model": "claude-sonnet-4-5", "problem": "OpenClaw does not start."}))
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(
        (&proposed["ok"], &proposed["status"]),
        (&json!(true), &json!("awaiting_code"))
    );
    let sid = proposed["sessionId"].as_str().expect("id").to_string();
    assert!(proposed["summary"].as_str().unwrap_or("").contains("root access"));
    assert!(f.runs().is_empty(), "nothing runs before the code");
    let wrong = post("/confirm", json!({"sessionId": sid, "code": "000000"}))
        .await
        .expect("send");
    assert_eq!(wrong.status(), 409);
    let ok = post("/confirm", json!({"sessionId": sid, "code": "123456"}))
        .await
        .expect("send");
    assert_eq!(ok.status(), 200);
    assert!(
        ok.headers()["set-cookie"]
            .to_str()
            .unwrap_or("")
            .starts_with("__Secure-cc_doctor_chat=")
    );
    let body: Value = ok.json().await.expect("json");
    assert_eq!(
        body,
        json!({"ok": true, "status": "running", "sessionId": sid, "chat": "/__cc/doctor/chat/"})
    );
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(
        f.runs()[0].problem,
        "OpenClaw does not start.",
        "the problem is the first message and never left this box"
    );
}
