//! The Auto approve store: seeding once, codes only for what lets more through, a store that will
//! not open, the gate's requests and the firewall's own asks.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::core::grants::GrantStore;
use crate::core::permissions::tests::{bridge, console};
use crate::integrations::testing::{self, FakeCodes, FakeService, Routes, owner_route};

fn rule(id: &str, effect: &str) -> AutoRule {
    AutoRule {
        id: id.into(),
        name: format!("rule {id}"),
        description: String::new(),
        kinds: vec![],
        title_like: None,
        title_match: None,
        vm_id: None,
        effect: effect.into(),
        enabled: true,
    }
}

fn with(mut r: AutoRule, kinds: &[&str], title: Option<&str>, exact: bool, vm: Option<&str>) -> AutoRule {
    r.kinds = kinds.iter().map(|k| k.to_string()).collect();
    r.title_like = title.map(str::to_string);
    r.title_match = exact.then(|| "exact".to_string());
    r.vm_id = vm.map(str::to_string);
    r
}

fn put(r: &AutoRule) -> Change {
    Change::Put {
        rule: r.clone(),
        at: None,
    }
}

// --- widens ---------------------------------------------------------------------------------

#[test]
fn adding_rules() {
    let git = with(rule("git", "allow"), &["exec"], Some("git status"), false, Some("oc"));
    assert!(widens(&[], &put(&git)), "a new allow");
    assert!(!widens(&[], &put(&rule("b", "block"))), "a new block");
    assert!(!widens(&[], &put(&rule("a", "ask"))), "a new ask");
    let mut off = git.clone();
    off.enabled = false;
    assert!(!widens(&[], &put(&off)), "an allow that is off");
    // A wider allow already answers everything the new one would.
    let all_exec = with(rule("all", "allow"), &["exec"], None, false, None);
    assert!(!widens(std::slice::from_ref(&all_exec), &put(&git)));
    // Unless something above it asks about part of that.
    let ask_git = with(rule("ask", "ask"), &["exec"], Some("git"), false, None);
    assert!(widens(
        &[ask_git.clone(), all_exec.clone()],
        &Change::Put {
            rule: git.clone(),
            at: Some(0)
        }
    ));
    // Below the ask it is shadowed: nothing new.
    assert!(!widens(
        &[ask_git, all_exec],
        &Change::Put {
            rule: git.clone(),
            at: None
        }
    ));
    // Covered by a block above it: nothing new.
    let block_exec = with(rule("b", "block"), &["exec"], None, false, None);
    assert!(!widens(&[block_exec], &put(&git)));
}

#[test]
fn a_rule_that_names_no_kind_and_no_title_shadows_no_app_call() {
    let catch_all = rule("all", "block");
    let app = with(rule("app", "allow"), &["app_call"], None, false, None);
    assert!(
        widens(std::slice::from_ref(&catch_all), &put(&app)),
        "app calls pass a catch-all"
    );
    let exec = with(rule("x", "allow"), &["exec"], None, false, None);
    assert!(!widens(&[catch_all], &put(&exec)));
}

#[test]
fn changing_a_rule() {
    let git = with(rule("git", "allow"), &["exec"], Some("git status"), false, Some("oc"));
    let base = vec![git.clone()];
    let mut renamed = git.clone();
    renamed.name = "another name".into();
    assert!(!widens(&base, &put(&renamed)), "a rename");
    let mut narrower = git.clone();
    narrower.title_like = Some("git status --short".into());
    assert!(!widens(&base, &put(&narrower)), "a longer contains text");
    narrower.title_match = Some("exact".into());
    assert!(!widens(&base, &put(&narrower)), "exact");
    let mut wider = git.clone();
    wider.title_like = Some("git".into());
    assert!(widens(&base, &put(&wider)), "a shorter text");
    let mut no_title = git.clone();
    no_title.title_like = None;
    assert!(widens(&base, &put(&no_title)));
    let mut any_agent = git.clone();
    any_agent.vm_id = None;
    assert!(widens(&base, &put(&any_agent)), "every agent");
    let mut other_agent = git.clone();
    other_agent.vm_id = Some("other".into());
    assert!(widens(&base, &put(&other_agent)), "another agent");
    let mut any_kind = git.clone();
    any_kind.kinds = vec![];
    assert!(widens(&base, &put(&any_kind)), "every kind");
    let mut more_kinds = git.clone();
    more_kinds.kinds = vec!["exec".into(), "plugin".into()];
    assert!(widens(&base, &put(&more_kinds)));
    let mut to_ask = git.clone();
    to_ask.effect = "ask".into();
    assert!(!widens(&base, &put(&to_ask)), "allow to ask");
    let mut off = git.clone();
    off.enabled = false;
    assert!(!widens(&base, &put(&off)), "turned off");
    // Ask or Block to Allow, and an Allow turned on.
    assert!(widens(&[to_ask.clone()], &put(&git)));
    assert!(widens(&[off], &put(&git)));
    // Exact to contains.
    let mut exact = git.clone();
    exact.title_match = Some("exact".into());
    assert!(widens(&[exact], &put(&git)));
}

#[test]
fn deleting_and_moving() {
    let block_rm = with(rule("rm", "block"), &["exec"], Some("rm -rf"), false, None);
    let allow_all = with(rule("all", "allow"), &["exec"], None, false, None);
    let allow_ls = with(rule("ls", "allow"), &["exec"], Some("ls"), true, None);
    // A block above an allow that matches the same requests: the allow would answer them.
    assert!(widens(
        &[block_rm.clone(), allow_all.clone()],
        &Change::Delete { id: "rm".into() }
    ));
    // A block above an allow it does not overlap: at once.
    assert!(!widens(
        &[block_rm.clone(), allow_ls.clone()],
        &Change::Delete { id: "rm".into() }
    ));
    // Deleting an allow, or a block with nothing below: at once.
    assert!(!widens(
        &[block_rm.clone(), allow_all.clone()],
        &Change::Delete { id: "all".into() }
    ));
    assert!(!widens(
        std::slice::from_ref(&block_rm),
        &Change::Delete { id: "rm".into() }
    ));
    // An ask above an allow, as a block.
    let ask_rm = with(rule("ask", "ask"), &["exec"], Some("rm"), false, None);
    assert!(widens(
        &[ask_rm, allow_all.clone()],
        &Change::Delete { id: "ask".into() }
    ));
    // Moving the allow above the block, or the block below the allow.
    let base = vec![block_rm.clone(), allow_all.clone()];
    assert!(widens(
        &base,
        &Change::Move {
            id: "all".into(),
            to: 0
        }
    ));
    assert!(widens(&base, &Change::Move { id: "rm".into(), to: 1 }));
    // The other way round only tightens.
    let base = vec![allow_all.clone(), block_rm.clone()];
    assert!(!widens(&base, &Change::Move { id: "rm".into(), to: 0 }));
    assert!(!widens(
        &base,
        &Change::Move {
            id: "all".into(),
            to: 1
        }
    ));
    // A move past a rule it does not overlap.
    let other = with(rule("pl", "block"), &["plugin"], None, false, None);
    assert!(!widens(
        &[other, allow_all],
        &Change::Move {
            id: "all".into(),
            to: 0
        }
    ));
}

#[test]
fn covers_and_overlaps() {
    let c = |t: &str| with(rule("c", "allow"), &[], Some(t), false, None);
    let e = |t: &str| with(rule("e", "allow"), &[], Some(t), true, None);
    assert!(covers(&c("git"), &c("GIT status")));
    assert!(!covers(&c("git status"), &c("git")));
    assert!(covers(&c("git"), &e("my git")));
    assert!(!covers(&e("git"), &c("git")));
    assert!(covers(&e("Git"), &e("git")));
    assert!(overlaps(&c("a"), &c("b")), "a title can hold both");
    assert!(!overlaps(&e("a"), &e("b")));
    assert!(overlaps(&e("git status"), &c("status")));
    assert!(!overlaps(&e("ls"), &c("rm")));
    let k = |kinds: &[&str]| with(rule("k", "allow"), kinds, None, false, None);
    assert!(!overlaps(&k(&["exec"]), &k(&["plugin"])));
    assert!(overlaps(&k(&[]), &k(&["plugin"])));
    let vm = |v: &str| with(rule("v", "allow"), &[], None, false, Some(v));
    assert!(!overlaps(&vm("a"), &vm("b")));
    assert!(!covers(&vm("a"), &k(&["exec"])));
}

#[test]
fn changes_parse_strictly() {
    let r = json!({"id": "r1", "name": "n", "kinds": ["exec"], "effect": "allow"});
    assert!(matches!(
        parse_change(&json!({"op": "put", "rule": r})),
        Ok(Change::Put { .. })
    ));
    assert!(parse_change(&json!({"op": "put", "rule": r, "extra": 1})).is_err());
    let mut bad = r.clone();
    bad["kinds"] = json!(["shell"]);
    assert!(parse_change(&json!({"op": "put", "rule": bad})).is_err());
    let mut bad = r.clone();
    bad["secret"] = json!(1);
    assert!(parse_change(&json!({"op": "put", "rule": bad})).is_err());
    assert!(parse_change(&json!({"op": "delete", "id": "r 1"})).is_err());
    assert!(matches!(
        parse_change(&json!({"op": "move", "id": "r1", "to": 2})),
        Ok(Change::Move { to: 2, .. })
    ));
    assert!(parse_change(&json!({"op": "move", "id": "r1"})).is_err());
    // An empty title or agent is none.
    let mut empty = r.clone();
    empty["title_like"] = json!("");
    empty["vm_id"] = json!("");
    let Ok(Change::Put { rule, .. }) = parse_change(&json!({"op": "put", "rule": empty})) else {
        panic!("put")
    };
    assert_eq!((rule.title_like, rule.vm_id), (None, None));
}

// --- the store ------------------------------------------------------------------------------

struct T {
    _dir: tempfile::TempDir,
    app: Arc<App>,
    path: std::path::PathBuf,
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
        app.contracts.code_service.set(Arc::new(FakeService(codes.clone())));
        app.contracts.code_routes.set(r.clone());
        let path = dir.path().join("autoapprove-rules.enc");
        Self {
            _dir: dir,
            app,
            path,
            codes,
            routes: r,
        }
    }

    fn make(&self) -> Arc<AutoApproveFirewall> {
        AutoApproveFirewall::new(&self.app, self.path.clone())
    }
}

async fn run(fw: &AutoApproveFirewall, action: &str, p: Value) -> CommandOutcome {
    fw.handle(action, p.as_object().cloned().expect("o")).await
}

fn ids(fw: &AutoApproveFirewall) -> Vec<String> {
    fw.rules().into_iter().map(|r| r.id).collect()
}

fn seed(rules: Vec<AutoRule>) -> Value {
    json!({"app_names": {"github": "GitHub"}, "seed": rules})
}

#[tokio::test]
async fn the_console_seeds_it_once_and_only_then_is_it_checked() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    let exec = json!({"permission_id": "oc:1", "kind": "exec", "title": "git status"});
    assert!(!fw.active());
    assert!(
        fw.decide(&exec, Some("oc")).is_none(),
        "an older console: nothing is checked here"
    );
    // A reply with no `auto_approve` changes nothing.
    fw.synced(None);
    assert!(!fw.active());
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c0", "change": {"op": "put", "rule": rule("b", "block")}}),
    )
    .await;
    assert_eq!(o.status, "failed", "no change before the console's rules came");
    let mut bad = rule("bad id", "allow");
    bad.name = "x".into();
    fw.synced(Some(&seed(vec![
        with(rule("git", "allow"), &["exec"], Some("git status"), false, Some("oc")),
        bad,
    ])));
    assert!(fw.active());
    assert_eq!(ids(&fw), vec!["git"], "a rule that does not check is left out");
    let (d, _) = fw.decide(&exec, Some("oc")).expect("checked");
    assert_eq!(d.effect, Effect::Allow);
    // Taken once: a later seed is ignored, the names are kept.
    fw.synced(Some(&seed(vec![rule("other", "block")])));
    assert_eq!(ids(&fw), vec!["git"]);
    // It survives a restart, seeded.
    let again = t.make();
    assert!(again.active());
    assert_eq!(ids(&again), vec!["git"]);
    // An app call's title uses the names the sync sent.
    let app = json!({"permission_id": "p", "kind": "app_call", "app": {"service": "github", "action": "delete_repo", "connection": null}});
    fw.synced(Some(&json!({"app_names": {"github": "GitHub"}})));
    assert_eq!(fw.decide(&app, Some("oc")).expect("d").1, "Run delete_repo in GitHub");
}

#[tokio::test]
async fn a_console_with_no_seed_seeds_it_empty() {
    let t = T::new(vec![]);
    let fw = t.make();
    fw.synced(Some(&json!({"app_names": {}})));
    assert!(fw.active());
    assert!(fw.rules().is_empty());
}

#[tokio::test]
async fn codes_only_for_what_lets_more_through() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    fw.synced(Some(&seed(vec![])));
    // A block applies at once.
    let block = with(rule("rm", "block"), &["exec"], Some("rm -rf"), false, None);
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "put", "rule": block}}),
    )
    .await;
    assert_eq!(o.status, "applied");
    assert!(t.codes.sent.lock().expect("l").is_empty());
    // An allow waits for the code; the message names the rule, its typed texts at the end.
    let allow = with(rule("git", "allow"), &["exec"], Some("git status"), false, None);
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c2", "change": {"op": "put", "rule": allow}}),
    )
    .await;
    assert_eq!(o.status, "awaiting_code");
    assert_eq!(ids(&fw), vec!["rm"]);
    let asks = t.codes.asks.lock().expect("l").clone();
    let (_, summary, parts) = asks.last().cloned().expect("asked");
    assert!(
        summary.starts_with(
            "Add an Auto approve rule that approves shell commands whose text contains the text below from any agent"
        ),
        "{summary}"
    );
    assert!(
        !summary.contains("git status"),
        "typed text is not in the firewall's part"
    );
    let (_, typed) = parts.expect("parts");
    assert_eq!(
        typed,
        vec![
            ("Rule name".to_string(), "rule git".to_string()),
            ("Text".to_string(), "git status".to_string())
        ]
    );
    // A wrong code, then the right one.
    let o = run(&fw, "confirm", json!({"changeId": "c2", "code": "000000"})).await;
    assert_eq!(o.status, "invalid");
    let o = run(&fw, "confirm", json!({"changeId": "c2", "code": "123456"})).await;
    assert_eq!(o.status, "applied");
    assert_eq!(ids(&fw), vec!["rm", "git"]);
    // Deleting the block above that allow lets more through: a code.
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c3", "change": {"op": "delete", "id": "rm"}}),
    )
    .await;
    assert_eq!(o.status, "awaiting_code");
    // The rules change meanwhile: the code no longer applies it.
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c4", "change": {"op": "put", "rule": rule("x", "ask")}}),
    )
    .await;
    assert_eq!(o.status, "applied");
    let o = run(&fw, "confirm", json!({"changeId": "c3", "code": "123456"})).await;
    assert_eq!(o.status, "failed");
    assert!(
        o.message
            .unwrap_or_default()
            .contains("changed while the code was on its way")
    );
    // Cancel, and read.
    let o = run(&fw, "cancel", json!({"changeId": "c3"})).await;
    assert_eq!(o.status, "cancelled");
    let o = run(&fw, "read", json!({})).await;
    assert_eq!(o.data.expect("d")["rules"].as_array().map(Vec::len), Some(3));
}

#[tokio::test]
async fn nobody_to_ask_applies_at_once_and_says_so() {
    let t = T::new(vec![]);
    let fw = t.make();
    fw.synced(Some(&seed(vec![])));
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "put", "rule": rule("a", "allow")}}),
    )
    .await;
    assert_eq!(o.status, "applied");
    assert_eq!(o.data.expect("d")["tofu"], json!(true));
    let _ = &t.routes;
}

#[tokio::test]
async fn a_store_that_will_not_open_asks_about_everything() {
    let t = T::new(vec![owner_route()]);
    std::fs::write(&t.path, "not a store").expect("write");
    let fw = t.make();
    assert!(fw.active());
    let exec = json!({"permission_id": "oc:1", "kind": "exec", "title": "ls"});
    assert_eq!(fw.decide(&exec, Some("oc")).expect("d").0.effect, Effect::Ask);
    assert_eq!(
        run(&fw, "read", json!({})).await.data.expect("d")["unreadable"],
        json!(true)
    );
    // Even a block needs the code to reseal it.
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "put", "rule": rule("b", "block")}}),
    )
    .await;
    assert_eq!(o.status, "awaiting_code");
    let o = run(&fw, "confirm", json!({"changeId": "c1", "code": "123456"})).await;
    assert_eq!(o.status, "applied");
    assert_eq!(ids(&fw), vec!["b"]);
    assert_eq!(fw.decide(&exec, Some("oc")).expect("d").0.effect, Effect::Block);
}

#[tokio::test]
async fn a_standalone_firewall_starts_seeded_and_empty() {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    let mut cfg = app.config.clone();
    cfg.mode = crate::app::Mode::Standalone;
    let app = Arc::new(App {
        config: cfg,
        keys: app.keys.clone(),
        box_key: app.box_key.clone(),
        runner: app.runner.clone(),
        http: app.http.clone(),
        console: cc_client::ConsoleClient::new(app.keys.clone(), app.http.clone()),
        contracts: crate::contracts::Contracts::default(),
        cp_inspect: app.cp_inspect.clone(),
    });
    let fw = AutoApproveFirewall::new(&app, dir.path().join("a.enc"));
    assert!(fw.active());
    assert!(fw.rules().is_empty());
}

#[tokio::test]
async fn template_rules_are_added_under_the_template_code() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    fw.synced(Some(&seed(vec![rule("first", "block")])));
    let r = with(rule("tpl", "allow"), &["exec"], Some("npm test"), false, Some("oc"));
    {
        let held = fw.template_lock().await;
        fw.add_locked(&held, std::slice::from_ref(&r)).expect("added");
    }
    assert_eq!(ids(&fw), vec!["first", "tpl"]);
    // The same id again is refused, never replaced.
    assert!({
        let held = fw.template_lock().await;
        fw.add_locked(&held, std::slice::from_ref(&r)).is_err()
    });
    assert!(fw.fits(std::slice::from_ref(&r)).is_err());
}

#[tokio::test]
async fn a_template_rule_with_the_id_of_an_org_wide_block_takes_nothing_away() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    let block = with(rule("blk", "block"), &["exec"], Some("rm -rf"), false, None);
    fw.synced(Some(&seed(vec![block.clone()])));
    // A template that names the Block's id, as an Allow for one agent.
    let sneaky = with(rule("blk", "allow"), &["exec"], Some("rm -rf"), false, Some("oc"));
    assert!(
        fw.fits(std::slice::from_ref(&sneaky)).is_err(),
        "refused before any code is sent"
    );
    assert!({
        let held = fw.template_lock().await;
        fw.add_locked(&held, std::slice::from_ref(&sneaky)).is_err()
    });
    assert_eq!(fw.rules(), vec![block], "the Block is still there, for every agent");
}

// --- requests -------------------------------------------------------------------------------

fn seeded(t: &T, rules: Vec<AutoRule>) -> Arc<AutoApproveFirewall> {
    let fw = t.make();
    fw.synced(Some(&seed(rules)));
    fw
}

#[tokio::test]
async fn an_agents_approval_is_answered_here_or_sent_on() {
    let t = T::new(vec![]);
    let fw = seeded(
        &t,
        vec![
            with(rule("git", "allow"), &["exec"], Some("git status"), false, Some("oc")),
            with(rule("rm", "block"), &[], Some("rm -rf"), false, None),
            with(rule("curl", "ask"), &["exec"], Some("curl"), false, None),
        ],
    );
    let d = tempfile::tempdir().expect("dir");
    std::fs::write(d.path().join("pending.jsonl"), "").expect("pending");
    let (url, posts, auths) = crate::core::permissions::tests::console_with_auth(|m, b| match m {
        "GET" => (200, json!({"status": "pending"})),
        _ if b.get("resolution").is_some() => (200, json!({"ok": true, "status": "denied"})),
        _ => (200, json!({"ok": true, "status": "pending"})),
    })
    .await;
    let b = Arc::new(bridge(
        d.path(),
        &url,
        Arc::new(GrantStore::new(d.path().join("grants.json"))),
    ));
    let gate = AgentApprovals {
        store: fw,
        bridge: b.clone(),
    };
    let raise = |id: &str, title: &str| json!({"permission_id": id, "kind": "exec", "title": title, "agent_vm_id": "other", "decided": {"effect": "allow"}});
    // Allow: answered here, nothing asked of the console yet.
    let (s, body) = gate.raise("oc", raise("oc:1", "git status --short")).await;
    assert_eq!((s, body), (200, json!({"ok": true, "status": "approved"})));
    assert!(posts.lock().expect("l").is_empty(), "the console was not asked");
    // Block.
    assert_eq!(
        gate.raise("oc", raise("oc:2", "rm -rf /")).await.1["status"],
        json!("denied")
    );
    // The rule for one agent does not answer another's.
    assert_eq!(
        gate.raise("vm-2", raise("oc:3", "git status")).await.1["status"],
        json!("pending")
    );
    // An ask rule: sent on, naming it.
    assert_eq!(
        gate.raise("oc", raise("oc:4", "curl x")).await.1["status"],
        json!("pending")
    );
    // A kind an agent may not raise here.
    assert_eq!(
        gate.raise(
            "oc",
            json!({"permission_id": "m", "kind": "meeting_request", "title": "x"})
        )
        .await
        .0,
        403
    );
    {
        let p = posts.lock().expect("l").clone();
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[0]["agent_vm_id"],
            json!("vm-2"),
            "the agent the gate named, not the body's"
        );
        assert_eq!(p[0]["checked"], json!({"rule_id": null, "rule_name": null}));
        assert!(
            p[0].get("decided").is_none(),
            "what the agent said about a decision is dropped"
        );
        assert_eq!(p[1]["checked"], json!({"rule_id": "curl", "rule_name": "rule curl"}));
    }
    // The decisions reach the console on the next tick.
    b.tick().await;
    let p = posts.lock().expect("l").clone();
    let reports: Vec<_> = p.iter().filter(|x| x.get("decided").is_some()).cloned().collect();
    assert_eq!(reports.len(), 2);
    assert_eq!(
        reports[0]["decided"],
        json!({"effect": "allow", "rule_id": "git", "rule_name": "rule git"})
    );
    assert_eq!(reports[0]["agent_vm_id"], json!("oc"));
    assert_eq!(reports[1]["decided"]["effect"], json!("block"));
    // Taken: not sent again.
    b.tick().await;
    assert_eq!(
        posts
            .lock()
            .expect("l")
            .iter()
            .filter(|x| x.get("decided").is_some())
            .count(),
        2
    );
    // A settle goes on as the agent: with the agent's own token, nothing naming another box.
    let (_, s) = gate
        .settle(
            "oc",
            json!({"permission_id": "oc:4", "resolution": "denied", "agent_vm_id": "x", "decided": {"effect": "allow"}}),
            "agent-token",
        )
        .await;
    assert_eq!(s["status"], json!("denied"));
    assert_eq!(
        posts.lock().expect("l").last().expect("p"),
        &json!({"permission_id": "oc:4", "resolution": "denied", "via_gate": true}),
        "marked as carried by the gate: the control plane takes OpenClaw's own approvals only"
    );
    assert_eq!(auths.lock().expect("l").last().expect("a"), "Bearer agent-token");
    // A settle without the token is refused (the gate refuses it before this; here, the body route).
    let (code, _) = gate
        .raise("oc", json!({"permission_id": "oc:5", "resolution": "approved"}))
        .await;
    assert_eq!(code, 403);
    let (_, st) = gate.status("oc", "oc:4").await;
    assert_eq!(st["status"], json!("pending"));
}

#[tokio::test]
async fn a_report_the_console_cannot_take_now_is_offered_again() {
    let t = T::new(vec![]);
    let fw = seeded(&t, vec![rule("all", "allow")]);
    let d = tempfile::tempdir().expect("dir");
    std::fs::write(d.path().join("pending.jsonl"), "").expect("pending");
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let b2 = busy.clone();
    let (url, posts) = console(move |_, _| {
        if b2.load(std::sync::atomic::Ordering::SeqCst) {
            (503, json!({}))
        } else {
            (200, json!({"ok": true}))
        }
    })
    .await;
    let b = Arc::new(bridge(
        d.path(),
        &url,
        Arc::new(GrantStore::new(d.path().join("grants.json"))),
    ));
    let gate = AgentApprovals {
        store: fw,
        bridge: b.clone(),
    };
    gate.raise("oc", json!({"permission_id": "oc:1", "kind": "exec", "title": "ls"}))
        .await;
    b.tick().await;
    busy.store(false, std::sync::atomic::Ordering::SeqCst);
    b.tick().await;
    b.tick().await;
    assert_eq!(posts.lock().expect("l").len(), 2, "once refused as busy, once taken");
}

#[tokio::test]
async fn the_firewalls_own_asks() {
    let t = T::new(vec![]);
    let fw = seeded(
        &t,
        vec![
            with(
                rule("site", "allow"),
                &["access"],
                Some("example.org"),
                false,
                Some("fw_1"),
            ),
            with(
                rule("agent-site", "allow"),
                &["access"],
                Some("other.org"),
                false,
                Some("vm-a"),
            ),
            with(rule("mail", "block"), &["email_recipient"], None, false, None),
        ],
    );
    let d = tempfile::tempdir().expect("dir");
    let recs = [
        json!({"permission_id": "p_site", "vm_id": "vm-a", "scope": "GET example.org/", "host": "example.org", "method": "GET", "path": "/"}),
        json!({"permission_id": "p_other", "vm_id": "vm-a", "scope": "GET other.org/", "host": "other.org", "method": "GET", "path": "/"}),
        json!({"permission_id": "p_mail", "vm_id": "vm-a", "scope": "EMAIL x -> y", "summary": "Email y", "kind": "email_recipient"}),
    ];
    std::fs::write(
        d.path().join("pending.jsonl"),
        recs.iter().map(|r| format!("{r}\n")).collect::<String>(),
    )
    .expect("pending");
    let (url, posts) = console(|_, _| (200, json!({"status": "pending"}))).await;
    let grants = Arc::new(GrantStore::new(d.path().join("grants.json")));
    let b = bridge(d.path(), &url, grants.clone());
    b.with_auto(fw, Some("fw_1".into()));
    b.tick().await;
    let p = posts.lock().expect("l").clone();
    let by = |id: &str| p.iter().find(|x| x["permission_id"] == id).cloned().expect("posted");
    // Matched against the firewall: its own rule allows, the agent's does not.
    assert_eq!(
        by("p_site")["decided"],
        json!({"effect": "allow", "rule_id": "site", "rule_name": "rule site"})
    );
    assert!(grants.get("p_site").is_some(), "granted here, as an approval would be");
    assert_eq!(by("p_other")["checked"], json!({"rule_id": null, "rule_name": null}));
    assert!(grants.get("p_other").is_none());
    assert_eq!(by("p_mail")["decided"]["effect"], json!("block"));
    assert!(grants.get("p_mail").is_none());
}

#[tokio::test]
async fn every_list_has_a_higher_version_than_the_last_also_after_a_lost_store() {
    let t = T::new(vec![owner_route()]);
    let fw = t.make();
    assert_eq!(fw.list_version(), 0);
    let many: Vec<AutoRule> = (0..RULES_MAX + 3).map(|i| rule(&format!("r{i}"), "block")).collect();
    fw.synced(Some(&seed(many)));
    let seeded = fw.list_version();
    assert!(
        seeded >= crate::core::now_ms() - 60_000,
        "a new list starts at the clock"
    );
    assert_eq!(
        fw.rules().len(),
        RULES_MAX + 3,
        "a seed drops no rule, past the cap too"
    );
    let o = run(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"op": "delete", "id": "r0"}}),
    )
    .await;
    assert_eq!(o.status, "applied");
    let after = fw.list_version();
    assert!(after > seeded);
    assert_eq!(
        o.data.as_ref().and_then(|d| d.get("version")),
        Some(&json!(after)),
        "the list comes with its version"
    );
    let read = run(&fw, "read", json!({})).await;
    assert_eq!(read.data.as_ref().and_then(|d| d.get("version")), Some(&json!(after)));
    // A restart keeps it.
    assert_eq!(t.make().list_version(), after);
    // A firewall that lost its store and takes a seed again is still ahead of what it said before.
    std::fs::remove_file(&t.path).expect("rm");
    let rebuilt = t.make();
    rebuilt.synced(Some(&seed(vec![rule("x", "block")])));
    assert!(rebuilt.list_version() >= seeded);
}

#[test]
fn the_message_says_when_an_allow_goes_above_a_rule_that_asks_or_blocks() {
    let t = T::new(vec![owner_route()]);
    let block = with(rule("blk", "block"), &["exec"], Some("rm"), false, None);
    let other = with(rule("pay", "ask"), &["payment"], None, false, None);
    let rules = vec![block.clone(), other];
    let allow = with(rule("al", "allow"), &["exec"], None, false, None);
    // Last: nothing changes for the Block.
    let (w, typed) = describe(
        &t.app,
        &Change::Put {
            rule: allow.clone(),
            at: None,
        },
        &rules,
    );
    assert!(!w.contains("goes above"), "{w}");
    assert!(typed.iter().all(|l| l.label != "Above the rule"));
    // First: the Block no longer decides shell commands; the payment Ask is not touched.
    let (w, typed) = describe(
        &t.app,
        &Change::Put {
            rule: allow.clone(),
            at: Some(0),
        },
        &rules,
    );
    assert!(
        w.ends_with("It goes above 1 rule that asks or blocks for these requests, so it no longer applies to them"),
        "{w}"
    );
    assert!(!w.contains("rm"), "the typed text stays out of the firewall's words");
    assert!(
        typed
            .iter()
            .any(|l| l.label == "Above the rule" && l.text == block.name)
    );
    // A move does the same.
    let with_allow = vec![block.clone(), allow.clone()];
    let (w, _) = describe(&t.app, &Change::Move { id: "al".into(), to: 0 }, &with_allow);
    assert!(w.contains("It goes above 1 rule"), "{w}");
    // A Block moved down below the Allow: the Allow decides those requests now, and it says so.
    let (w, typed) = describe(
        &t.app,
        &Change::Move {
            id: "blk".into(),
            to: 1,
        },
        &with_allow,
    );
    assert!(
        w.ends_with("It goes below 1 rule that approves some of the same requests, so that rule approves them now"),
        "{w}"
    );
    assert!(
        typed
            .iter()
            .any(|l| l.label == "Below the rule" && l.text == allow.name)
    );
    // A Block moved up above the Allow says nothing of the kind.
    let allow_first = vec![allow.clone(), block.clone()];
    let (w, _) = describe(
        &t.app,
        &Change::Move {
            id: "blk".into(),
            to: 0,
        },
        &allow_first,
    );
    assert!(!w.contains("goes above") && !w.contains("goes below"), "{w}");
}
