//! `ai-review-history.test.ts`: the history page over real HTTP, with W3's access stood in.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use serde_json::{Map, Value, json};

use super::history::{AiReviewHistory, ROOT};
use super::trace_store::{AiReviewRun, AiReviewTraceStore, TraceEvent, TraceSink};
use crate::integrations::doctor::pages_test::{Access, ORIGIN, client, cookie_of, open, person, serve};
use crate::integrations::doctor::transcript::{TRANSCRIPT_BOX, TRANSCRIPT_EMPTY, TRANSCRIPT_JS};

const NOW: i64 = 1_800_000_000_000;

fn run(id: &str, vm: &str, at: i64, outcome: &str) -> AiReviewRun {
    AiReviewRun {
        run_id: id.into(),
        vm_id: Some(vm.into()),
        kind: "review".into(),
        at,
        provider: Some("vercel_gateway".into()),
        model: Some("typesafe-ai/jev".into()),
        outcome: outcome.into(),
        severity: (outcome == "finding").then(|| "high".into()),
        category: None,
        events: vec![TraceEvent {
            seq: 1,
            kind: "tool_call".into(),
            text: "what was asked".into(),
            title: None,
            extra: Map::new(),
        }],
        extra: Map::new(),
    }
}

#[test]
fn the_page_draws_with_the_shared_transcript() {
    assert!(include_str!("page/history_app.js").starts_with(TRANSCRIPT_JS));
    let body = include_str!("page/history_body.html");
    assert!(body.contains(TRANSCRIPT_BOX) && body.contains(TRANSCRIPT_EMPTY));
}

#[tokio::test]
async fn one_agents_runs_open_from_an_intent_for_that_agent_only() {
    let d = tempfile::tempdir().expect("dir");
    let app = crate::integrations::testing::app(d.path());
    let clock = Arc::new(AtomicI64::new(NOW));
    let now = {
        let c = clock.clone();
        Arc::new(move || c.load(Ordering::SeqCst))
    };
    let store = Arc::new(
        AiReviewTraceStore::new(
            d.path().join("traces"),
            &app.box_key,
            "org1",
            "fw1",
            Arc::new(Vec::new),
            now.clone(),
        )
        .expect("store"),
    );
    store.record(run("run-old-0001", "vm-agent-0001", NOW - 60_000, "clear"));
    store.record(run("run-new-0002", "vm-agent-0001", NOW - 1_000, "finding"));
    store.record(run("run-other-03", "vm-agent-0002", NOW - 1_000, "finding"));
    let page = AiReviewHistory::new(
        &app,
        store,
        Arc::new(|vm: &str| (vm == "vm-agent-0001").then(|| "Atlas".to_string())),
        now,
    );
    let p = page.clone();
    let base = serve(move |reg| {
        reg.ingress.route(
            crate::stages::INGRESS_PAGES,
            |_, path| super::history::owns(path),
            move |req, _| {
                let p = p.clone();
                async move { p.handle(req).await }
            },
        )
    })
    .await;
    let get = |path: String, cookie: String| {
        let base = base.clone();
        async move {
            client()
                .get(format!("{base}{path}"))
                .header("cookie", cookie)
                .send()
                .await
                .expect("send")
        }
    };

    // With no access module on the build, nothing opens.
    assert_eq!(open(&base, &format!("{ROOT}/open"), ORIGIN).await.status(), 403);
    let access = Arc::new(Access::default());
    app.contracts.page_access.set(access.clone());
    let set = |vm: &str| *access.person.lock().expect("lock") = Some(person(false, json!({"vmId": vm})));
    // No intent, another origin, or an agent id that is not one: refused.
    assert_eq!(open(&base, &format!("{ROOT}/open"), ORIGIN).await.status(), 403);
    set("vm-agent-0001");
    assert_eq!(
        open(&base, &format!("{ROOT}/open"), "https://evil.example")
            .await
            .status(),
        403
    );
    set("../vm-agent-0001");
    assert_eq!(open(&base, &format!("{ROOT}/open"), ORIGIN).await.status(), 403);
    set("vm-agent-0001");
    let r = open(&base, &format!("{ROOT}/open"), ORIGIN).await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["location"], format!("{ROOT}/a/vm-agent-0001/").as_str());
    assert!(r.headers()["set-cookie"].to_str().unwrap_or("").ends_with(&format!(
        "; Path={ROOT}/a/vm-agent-0001; Secure; HttpOnly; SameSite=Strict; Max-Age=7200"
    )));
    assert_eq!(
        access.asked.lock().expect("lock").last().map(String::as_str),
        Some("ai-review")
    );
    let cookie = cookie_of(&r);

    // The agent's runs, newest first, without their events; then one run with them.
    let r = get(format!("{ROOT}/a/vm-agent-0001"), cookie.clone()).await;
    assert_eq!(r.status(), 308);
    assert_eq!(r.headers()["location"], format!("{ROOT}/a/vm-agent-0001/").as_str());
    let r = get(format!("{ROOT}/a/vm-agent-0001/"), cookie.clone()).await;
    assert_eq!(r.status(), 200);
    assert!(r.text().await.expect("text").contains("AI review history"));
    let v: Value = get(format!("{ROOT}/a/vm-agent-0001/runs"), cookie.clone())
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(v["agent"], "Atlas");
    let ids: Vec<&str> = v["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .filter_map(|r| r["runId"].as_str())
        .collect();
    assert_eq!(ids, ["run-new-0002", "run-old-0001"]);
    assert!(v["runs"][0].get("events").is_none());
    let v: Value = get(format!("{ROOT}/a/vm-agent-0001/runs?findings=1"), cookie.clone())
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(v["runs"].as_array().map(Vec::len), Some(1));
    let v: Value = get(
        format!("{ROOT}/a/vm-agent-0001/runs?before={}", NOW - 1_000),
        cookie.clone(),
    )
    .await
    .json()
    .await
    .expect("json");
    assert_eq!(v["runs"][0]["runId"], "run-old-0001");
    let v: Value = get(format!("{ROOT}/a/vm-agent-0001/runs/run-new-0002"), cookie.clone())
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(v["events"][0]["text"], "what was asked");
    let r = get(format!("{ROOT}/a/vm-agent-0001/runs/run-other-03"), cookie.clone()).await;
    assert_eq!(r.status(), 404, "another agent's run is not this agent's");
    assert_eq!(
        r.json::<Value>().await.expect("json")["message"],
        "That run is not on this firewall any more."
    );

    // The cookie is for that agent only, read-only, and ends with the browser's enrollment or after
    // two hours.
    assert_eq!(
        get(format!("{ROOT}/a/vm-agent-0002/runs"), cookie.clone())
            .await
            .status(),
        403
    );
    let r = client()
        .post(format!("{base}{ROOT}/a/vm-agent-0001/runs"))
        .header("cookie", &cookie)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 405);
    access.inactive.store(true, Ordering::SeqCst);
    assert_eq!(
        get(format!("{ROOT}/a/vm-agent-0001/runs"), cookie.clone())
            .await
            .status(),
        403
    );
    access.inactive.store(false, Ordering::SeqCst);
    assert_eq!(
        get(format!("{ROOT}/a/vm-agent-0001/runs"), cookie.clone())
            .await
            .status(),
        200
    );
    clock.store(NOW + 2 * 60 * 60_000, Ordering::SeqCst);
    assert_eq!(get(format!("{ROOT}/a/vm-agent-0001/runs"), cookie).await.status(), 403);
}
