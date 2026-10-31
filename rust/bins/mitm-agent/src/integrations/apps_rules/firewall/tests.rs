//! `apps-rules.test.ts`: the seeded rule, codes for loosening only, a store that will not open.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::integrations::apps_rules::schema::{AppEffect, AppMatch, AppOperation, AppRule};
use crate::integrations::testing::{self, FakeCodes, Routes, owner_route};

struct T {
    _dir: tempfile::TempDir,
    app: Arc<App>,
    path: PathBuf,
    codes: Arc<FakeCodes>,
    routes: Arc<Routes>,
}

impl T {
    fn new(routes: Vec<Value>) -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let app = testing::app(dir.path());
        let codes = FakeCodes::new("123456");
        let r = Arc::new(Routes(Mutex::new(routes)));
        app.contracts.consent.set(codes.clone());
        app.contracts.code_routes.set(r.clone());
        let path = dir.path().join("apps-rules.enc");
        Self {
            _dir: dir,
            app,
            path,
            codes,
            routes: r,
        }
    }

    fn make(&self) -> Arc<AppRulesFirewall> {
        AppRulesFirewall::new(&self.app, self.path.clone())
    }

    fn sent(&self) -> Vec<String> {
        self.codes.sent.lock().expect("lock").clone()
    }
}

async fn run(fw: &AppRulesFirewall, action: &str, p: Value) -> CommandOutcome {
    fw.handle(action, p.as_object().cloned().expect("o")).await
}

fn block() -> AppRule {
    let mut r = seeded_app_rule();
    r.id = "no-github-writes".into();
    r.name = "No GitHub writes".into();
    r.service = Some("github".into());
    r.match_ = AppMatch::Operation {
        operations: vec![AppOperation::Write],
    };
    r.then = AppEffect::Block;
    r
}

fn call() -> AppCall {
    AppCall {
        vm_id: "vm-a".into(),
        service: "github".into(),
        connection_id: None,
        action_id: Some("github.delete_repo".into()),
        operation: Some(AppOperation::Destructive),
        proxy: None,
        tool: None,
        input: Value::Null,
    }
}

fn ids(fw: &AppRulesFirewall) -> Vec<String> {
    fw.rules().into_iter().map(|r| r.id).collect()
}

fn put(rule: &AppRule, at: Option<usize>) -> Value {
    let mut c = json!({"op": "put", "rule": rule});
    if let Some(a) = at {
        c["at"] = json!(a);
    }
    c
}

#[tokio::test]
async fn every_new_store_starts_with_the_seeded_rule_and_a_deletion_sticks() {
    let t = T::new(vec![]);
    let fw = t.make();
    assert_eq!(ids(&fw), ["ask-destructive"]);
    assert_eq!(fw.decide(&call(), &[]).expect("rules").then, AppEffect::Ask);
    // Nobody approved yet: trust on first use, as every connector change.
    let r = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "delete", "id": "ask-destructive"}}),
    )
    .await;
    assert_eq!(r.status, "applied");
    assert_eq!(r.data.as_ref().and_then(|d| d.get("tofu")), Some(&json!(true)));
    assert!(t.make().rules().is_empty(), "not put back on the next start");
}

#[tokio::test]
async fn narrowing_applies_at_once_and_loosening_waits_for_the_code() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    let narrow = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": put(&block(), Some(0))}),
    )
    .await;
    assert_eq!(narrow.status, "applied");
    assert!(t.sent().is_empty());
    let loosen = run(
        &fw,
        "propose",
        json!({"changeId": "c2", "change": {"op": "delete", "id": "no-github-writes"}}),
    )
    .await;
    assert_eq!(loosen.status, "awaiting_code");
    assert_eq!(t.sent(), ["Delete the integration rule that blocks changing in github"]);
    assert_eq!(ids(&fw)[0], "no-github-writes", "not applied yet");
    let wrong = run(&fw, "confirm", json!({"changeId": "c2", "code": "000000"})).await;
    assert_eq!(wrong.status, "invalid");
    assert_eq!(wrong.data.as_ref().and_then(|d| d.get("attemptsLeft")), Some(&json!(4)));
    assert_eq!(
        run(&fw, "confirm", json!({"changeId": "c2", "code": "123456"}))
            .await
            .status,
        "applied"
    );
    assert_eq!(ids(&fw), ["ask-destructive"]);
    let read = run(&fw, "read", json!({})).await;
    assert_eq!((read.ok, read.status.as_str()), (true, "read"));
    assert_eq!(read.data.expect("data")["rules"][0]["id"], "ask-destructive");
}

#[tokio::test]
async fn a_malformed_change_is_refused() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    let mut bad = serde_json::to_value(block()).expect("json");
    bad["then"] = json!("maybe");
    let r = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "put", "rule": bad}}),
    )
    .await;
    assert!(!r.ok);
    assert_eq!(
        r.message.as_deref(),
        Some("The integration rules change could not be applied. Check the input, then retry.")
    );
    assert!(
        !run(
            &fw,
            "propose",
            json!({"changeId": "c1", "change": {"op": "delete", "id": "nope"}})
        )
        .await
        .ok
    );
    assert!(
        !run(
            &fw,
            "propose",
            json!({"change": {"op": "delete", "id": "ask-destructive"}})
        )
        .await
        .ok
    );
}

#[tokio::test]
async fn a_store_that_will_not_open_refuses_every_call_until_a_confirmed_change() {
    let t = T::new(vec![owner_route()]);
    std::fs::write(&t.path, "not a store").expect("write");
    let fw = t.make();
    assert_eq!(fw.decide(&call(), &[]), Err(RulesUnknown));
    assert_eq!(run(&fw, "read", json!({})).await.data.expect("d")["unreadable"], true);
    // Even a narrowing change needs the code here: it is what reseals the store.
    let r = run(&fw, "propose", json!({"changeId": "c1", "change": put(&block(), None)})).await;
    assert_eq!(r.status, "awaiting_code");
    assert!(t.sent()[0].starts_with("Your firewall could not read its integration rules."));
    run(&fw, "confirm", json!({"changeId": "c1", "code": "123456"})).await;
    assert_eq!(fw.decide(&call(), &[]).expect("rules").then, AppEffect::Ask);
    assert_eq!(ids(&fw), ["ask-destructive", "no-github-writes"]);
}

#[tokio::test]
async fn a_narrowing_change_leaves_a_change_waiting_for_its_code_alone() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    let first = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "delete", "id": "ask-destructive"}}),
    )
    .await;
    assert_eq!(first.status, "awaiting_code");
    assert_eq!(
        run(
            &fw,
            "propose",
            json!({"changeId": "c2", "change": put(&block(), Some(0))})
        )
        .await
        .status,
        "applied"
    );
    let r = run(&fw, "confirm", json!({"changeId": "c1", "code": "123456"})).await;
    assert!(!r.ok);
    assert!(r.message.expect("m").contains("changed while the code was on its way"));
    assert_eq!(ids(&fw), ["no-github-writes", "ask-destructive"]);
}

#[tokio::test]
async fn a_change_waiting_for_its_code_cannot_be_swapped_for_another_under_the_same_id() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    let mut allow_a = seeded_app_rule();
    allow_a.id = "a".into();
    allow_a.name = "allow some".into();
    allow_a.service = Some("github".into());
    allow_a.match_ = AppMatch::Actions {
        actions: vec!["github.get_user".into()],
    };
    allow_a.then = AppEffect::Allow;
    run(&fw, "propose", json!({"changeId": "c0", "change": put(&allow_a, None)})).await;
    assert_eq!(
        run(
            &fw,
            "propose",
            json!({"changeId": "c1", "change": {"op": "move", "id": "a", "to": 0}})
        )
        .await
        .status,
        "awaiting_code"
    );
    assert_eq!(
        run(
            &fw,
            "propose",
            json!({"changeId": "c2", "change": {"op": "delete", "id": "a"}})
        )
        .await
        .status,
        "applied"
    );
    let mut all = allow_a.clone();
    all.name = "allow all".into();
    all.service = None;
    all.match_ = AppMatch::Any;
    assert_eq!(
        run(&fw, "propose", json!({"changeId": "c3", "change": put(&all, None)}))
            .await
            .status,
        "applied"
    );
    let r = run(&fw, "confirm", json!({"changeId": "c1", "code": "123456"})).await;
    assert!(!r.ok);
    assert_eq!(
        ids(&fw),
        ["ask-destructive", "a"],
        "the allow-all stays last, under the ask"
    );
    let _ = &t.routes;
}

#[tokio::test]
async fn the_seeded_rule_under_its_old_name_is_renamed_and_unknown_store_fields_are_kept() {
    let t = T::new(vec![]);
    let mut old = seeded_app_rule();
    old.name = crate::integrations::apps_rules::schema::SEEDED_APP_RULE_OLD_NAME.into();
    let aad = "org1:fw1:apps-rules";
    let stored = json!({"version": 1, "rules": [old], "seeded": true, "later": {"x": 1}});
    cc_crypto::enc_file::save_encrypted_json(&t.path, &stored, &t.app.box_key, aad).expect("save");
    let fw = t.make();
    assert_eq!(fw.rules()[0].name, "Ask before destructive integration actions");
    let back = cc_crypto::enc_file::load_encrypted_json(&t.path, &t.app.box_key, aad)
        .expect("load")
        .expect("there");
    assert_eq!(back["later"], json!({"x": 1}), "a field the Node build wrote is kept");
}

#[tokio::test]
async fn with_no_confirmation_codes_on_this_build_a_loosening_change_is_refused_never_applied() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    let fw = AppRulesFirewall::new(&app, dir.path().join("apps-rules.enc"));
    let r = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "delete", "id": "ask-destructive"}}),
    )
    .await;
    assert_eq!((r.ok, r.status.as_str()), (false, "failed"));
    assert_eq!(r.message.as_deref(), Some(crate::integrations::codes::NOT_READY));
    assert_eq!(ids(&fw), ["ask-destructive"], "not applied");
    // A change that only narrows needs no code, so it still applies.
    assert_eq!(
        run(
            &fw,
            "propose",
            json!({"changeId": "c2", "change": put(&block(), Some(0))})
        )
        .await
        .status,
        "applied"
    );
}
