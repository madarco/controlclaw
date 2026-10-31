//! `teamchat.test.ts`: Team chat on the firewall against a fake helper, a fake ClickClack API and
//! fake agent boxes.

use std::sync::atomic::AtomicI64;

use super::super::api::Res;
use super::*;
use crate::contracts::{AgentClient, AgentError, ChannelWriter, CodeRoutes};
use crate::integrations::testing::{self, FakeCodes, Identities};
use cc_http::BoxFuture;

const CODE: &str = "424242";

#[derive(Default)]
pub(crate) struct World {
    unit: Mutex<String>,
    installed: AtomicBool,
    helper_calls: Mutex<Vec<String>>,
    people: Mutex<Vec<(String, String)>>,
    bots: Mutex<Vec<(String, String, String)>>,
    session_valid: AtomicBool,
    roles: Mutex<HashMap<String, String>>,
    renamed: Mutex<Option<String>>,
    healthy: AtomicBool,
    applies: Mutex<Vec<(String, Value)>>,
    apply_fails: Mutex<Option<String>>,
    box_channel: Mutex<HashMap<String, Value>>,
}

struct Helper(Arc<World>);

impl TeamChatHelper for Helper {
    fn installed(&self) -> bool {
        self.0.installed.load(Ordering::SeqCst)
    }
    fn start(&self, hostname: String, home_url: String) -> BoxFuture<Result<(), String>> {
        self.0
            .helper_calls
            .lock()
            .expect("lock")
            .push(format!("start {hostname} {home_url}"));
        *self.0.unit.lock().expect("lock") = "active".into();
        Box::pin(async { Ok(()) })
    }
    fn stop(&self) -> BoxFuture<Result<(), String>> {
        self.0.helper_calls.lock().expect("lock").push("stop".into());
        *self.0.unit.lock().expect("lock") = "inactive".into();
        Box::pin(async { Ok(()) })
    }
    fn status(&self) -> BoxFuture<Result<String, String>> {
        let s = self.0.unit.lock().expect("lock").clone();
        Box::pin(async move { Ok(s) })
    }
    fn bootstrap(&self) -> BoxFuture<Result<(String, String), String>> {
        let mut c = self.0.helper_calls.lock().expect("lock");
        c.push("bootstrap".into());
        let token = format!("mgt_owner{}", c.len());
        Box::pin(async move { Ok(("usr_owner000000".into(), token)) })
    }
    fn login(&self, workspace_id: String, email: String, name: String) -> BoxFuture<Result<(String, String), String>> {
        self.0
            .helper_calls
            .lock()
            .expect("lock")
            .push(format!("login {workspace_id} {email} {name}"));
        let mut p = self.0.people.lock().expect("lock");
        let user = match p.iter().find(|(e, _)| *e == email) {
            Some((_, u)) => u.clone(),
            None => {
                let u = format!("usr_person{}aaaaaaa", p.len());
                p.push((email, u.clone()));
                u
            }
        };
        Box::pin(async move { Ok((user, "mgt_person0000000".to_string())) })
    }
}

struct Api(Arc<World>);

impl TeamChatApi for Api {
    fn healthy(&self) -> BoxFuture<bool> {
        let up = self.0.healthy.load(Ordering::SeqCst) && *self.0.unit.lock().expect("lock") == "active";
        Box::pin(async move { up })
    }
    fn consume(&self, magic_token: String) -> BoxFuture<Res<(String, String)>> {
        self.0.session_valid.store(true, Ordering::SeqCst);
        Box::pin(async move { Ok(("usr_owner000000".into(), format!("sst_{magic_token}"))) })
    }
    fn workspaces(&self, session: String) -> BoxFuture<Res<Vec<super::super::api::Workspace>>> {
        let valid = self.0.session_valid.load(Ordering::SeqCst);
        Box::pin(async move {
            if !valid {
                return Err(ApiError::new(401, "expired"));
            }
            assert!(session.starts_with("sst_"));
            Ok(vec![super::super::api::Workspace {
                id: "wsp_teamchat0000".into(),
                name: "ClickClack".into(),
                role: Some("owner".into()),
            }])
        })
    }
    fn rename_workspace(&self, _: String, _: String, name: String) -> BoxFuture<Res<()>> {
        *self.0.renamed.lock().expect("lock") = Some(name);
        Box::pin(async { Ok(()) })
    }
    fn create_bot(&self, _: String, workspace_id: String, _: String, handle: String) -> BoxFuture<Res<Bot>> {
        let valid = self.0.session_valid.load(Ordering::SeqCst);
        let w = self.0.clone();
        Box::pin(async move {
            if !valid {
                return Err(ApiError::new(401, "expired"));
            }
            assert_eq!(workspace_id, "wsp_teamchat0000");
            let mut bots = w.bots.lock().expect("lock");
            if bots.iter().any(|(_, h, _)| *h == handle) {
                return Err(ApiError::new(
                    400,
                    "ClickClack POST answered 400: handle is already taken",
                ));
            }
            let id = format!("usr_bot{}aaaaaaaa", bots.len());
            let token = format!("ccb_real{}{}", bots.len(), hex::encode(rand::random::<[u8; 4]>()));
            bots.push((id.clone(), handle.clone(), token.clone()));
            Ok(Bot {
                bot_user_id: id,
                token,
                handle,
            })
        })
    }
    fn remove_bot(&self, _: String, bot_user_id: String) -> BoxFuture<Res<()>> {
        self.0
            .bots
            .lock()
            .expect("lock")
            .retain(|(id, _, _)| *id != bot_user_id);
        Box::pin(async { Ok(()) })
    }
    fn set_role(&self, _: String, _: String, user_id: String, role: &'static str) -> BoxFuture<Res<()>> {
        self.0.roles.lock().expect("lock").insert(user_id, role.into());
        Box::pin(async { Ok(()) })
    }
}

struct Writer(Arc<World>);

impl ChannelWriter for Writer {
    fn write(&self, vm_id: &str, _: &str, kind: &str, body: Value) -> BoxFuture<Result<ApplyOutcome, String>> {
        assert_eq!(kind, "clickclack");
        self.0.applies.lock().expect("lock").push((vm_id.into(), body.clone()));
        let fails = self.0.apply_fails.lock().expect("lock").as_deref() == Some(vm_id);
        let mut boxes = self.0.box_channel.lock().expect("lock");
        if !fails {
            if body.get("remove") == Some(&json!(true)) {
                boxes.remove(vm_id);
            } else {
                boxes.insert(
                    vm_id.into(),
                    json!({"configured": true, "connected": true, "lastApply": {"state": "applied"}}),
                );
            }
        }
        Box::pin(async move {
            if fails {
                Err("agent 500: the plugin would not install".into())
            } else {
                Ok(ApplyOutcome::Applied)
            }
        })
    }
}

struct Boxes(Arc<World>);

impl AgentClient for Boxes {
    fn post(&self, _: &str, _: &str, _: Value) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
    fn get(&self, vm_id: &str, path: &str) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        assert_eq!(path, "/channels/status");
        let cc = self.0.box_channel.lock().expect("lock").get(vm_id).cloned();
        Box::pin(async move {
            Ok(as_map(match cc {
                Some(c) => json!({"channels": {"clickclack": c}}),
                None => json!({"channels": {}}),
            }))
        })
    }
}

pub(crate) struct Routes {
    list: Mutex<Vec<Value>>,
    ready: AtomicBool,
}

impl CodeRoutes for Routes {
    fn routes(&self) -> Vec<Value> {
        self.list.lock().expect("lock").clone()
    }
    fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
}

pub(crate) struct Rig {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) w: Arc<World>,
    pub(crate) ids: Arc<Identities>,
    pub(crate) routes: Arc<Routes>,
    pub(crate) codes: Arc<FakeCodes>,
    pub(crate) app: Arc<App>,
    pub(crate) clock: Arc<AtomicI64>,
    pub(crate) store: PathBuf,
}

fn ident(vm: &str, host: &str, name: &str, ip: &str) -> AgentIdentity {
    AgentIdentity {
        vm_id: vm.into(),
        private_ip: ip.into(),
        hostname: Some(host.into()),
        name: Some(name.into()),
    }
}

fn a() -> AgentIdentity {
    ident("vm-a", "sales.ccl.bot", "Sales", "10.0.0.3")
}

fn b() -> AgentIdentity {
    ident("vm-b", "ops.ccl.bot", "Ops Bot!", "10.0.0.4")
}

fn telegram_route() -> Value {
    json!({"target": {"vmId": "vm-a", "hostname": "sales.ccl.bot"}, "senders": [{"type": "telegram", "id": "55", "label": "Marco"}]})
}

pub(crate) fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("dir");
    let app = testing::app(dir.path());
    let w = Arc::new(World::default());
    *w.unit.lock().expect("lock") = "inactive".into();
    w.installed.store(true, Ordering::SeqCst);
    w.session_valid.store(true, Ordering::SeqCst);
    w.healthy.store(true, Ordering::SeqCst);
    let ids = Arc::new(Identities(Mutex::new(vec![a(), b()])));
    app.contracts.identities.set(ids.clone());
    let routes = Arc::new(Routes {
        list: Mutex::new(vec![telegram_route()]),
        ready: AtomicBool::new(true),
    });
    app.contracts.code_routes.set(routes.clone());
    let codes = FakeCodes::new(CODE);
    app.contracts.consent.set(codes.clone());
    app.contracts.channel_writer.set(Arc::new(Writer(w.clone())));
    app.contracts.agents.set(Arc::new(Boxes(w.clone())));
    let store = dir.path().join("teamchat.enc");
    Rig {
        _dir: dir,
        w,
        ids,
        routes,
        codes,
        app,
        clock: Arc::new(AtomicI64::new(js::now_ms())),
        store,
    }
}

impl Rig {
    pub(crate) fn make(&self) -> Arc<TeamChatFirewall> {
        let c = self.clock.clone();
        TeamChatFirewall::new(
            &self.app,
            Options {
                path: self.store.clone(),
                api: Arc::new(Api(self.w.clone())),
                helper: Arc::new(Helper(self.w.clone())),
                gateway_url: "http://10.0.0.2:3930".into(),
                home_url: "https://controlclaw.com/dashboard/team-chat".into(),
                hostname: Arc::new(|| Some("fw-x.ccl.bot".into())),
                now: Arc::new(move || c.load(Ordering::SeqCst)),
                sleep: Arc::new(|_| Box::pin(async {})),
            },
        )
    }
    pub(crate) async fn turned_on(&self) -> Arc<TeamChatFirewall> {
        self.routes.list.lock().expect("lock").clear();
        let tc = self.make();
        assert_eq!(
            tc.handle("propose", as_map(json!({"changeId": "c1"}))).await.status,
            "applied"
        );
        tc.reconcile().await;
        tc
    }
    fn applies(&self, vm: &str) -> Vec<Value> {
        self.w
            .applies
            .lock()
            .expect("lock")
            .iter()
            .filter(|(v, _)| v == vm)
            .map(|(_, b)| b.clone())
            .collect()
    }
    fn handles(&self) -> Vec<String> {
        let mut h: Vec<String> = self
            .w
            .bots
            .lock()
            .expect("lock")
            .iter()
            .map(|(_, h, _)| h.clone())
            .collect();
        h.sort();
        h
    }
    fn set_agents(&self, list: Vec<AgentIdentity>) {
        *self.ids.0.lock().expect("lock") = list;
    }
}

fn agents_of(st: &Value) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = st["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            (
                a["vmId"].as_str().unwrap_or("").into(),
                a["status"].as_str().unwrap_or("").into(),
            )
        })
        .collect();
    v.sort();
    v
}

fn person(can_write: bool, email: Option<&str>) -> Person {
    Person {
        user_id: "u1".into(),
        device_id: "dev_1".into(),
        name: Some("Marco".into()),
        email: email.map(String::from),
        can_write,
    }
}

#[test]
fn handles_are_clickclack_shaped_and_a_taken_one_gets_a_suffix() {
    assert_eq!(handle_for("Sales", 0), "sales");
    assert_eq!(handle_for("Ops Bot!", 0), "ops-bot");
    assert_eq!(handle_for("x", 0), "agentx");
    let long = handle_for(&"A".repeat(60), 3);
    assert!(long.len() <= 32);
    assert!(
        regex::Regex::new(r"^[a-z0-9][a-z0-9_-]{1,31}$")
            .expect("re")
            .is_match(&long)
    );
    assert_eq!(handle_for("Sales", 2), "sales-2");
    // What `normalize("NFKD")` and the patterns make of these in the TS (checked against it).
    assert_eq!(handle_for("José Núñez", 0), "jose-nu-n-ez");
    assert_eq!(handle_for("Ünïcode——Bot__", 0), "u-ni-code-bot");
    assert_eq!(handle_for("ﬁx", 0), "fix");
    assert_eq!(handle_for("--", 0), "agent");
    assert_eq!(handle_for("Ab", 0), "ab");
}

#[test]
fn a_persons_chat_identity_is_synthetic() {
    let e = person_email("org-1", "user-123");
    assert!(
        regex::Regex::new(r"^u-[0-9a-f]{24}@people\.team-chat\.invalid$")
            .expect("re")
            .is_match(&e)
    );
    assert_eq!(e, person_email("org-1", "user-123"));
    assert_ne!(e, person_email("org-2", "user-123"));
}

#[tokio::test]
async fn with_nobody_approved_turning_it_on_is_trust_on_first_use_and_the_dev_route_is_nobody() {
    let r = rig();
    r.routes.list.lock().expect("lock").clear();
    let tc = r.make();
    let o = tc.handle("propose", as_map(json!({"changeId": "c1"}))).await;
    assert_eq!(o.status, "applied");
    let d = o.data.clone().unwrap_or_default();
    assert_eq!((&d["tofu"], &d["summary"]), (&json!(true), &json!(ENABLE_SUMMARY)));
    assert!(tc.enabled());
    let r = rig();
    *r.routes.list.lock().expect("lock") = vec![
        json!({"target": {"vmId": "dev", "hostname": "dev"}, "senders": [{"type": "dev", "id": "dev", "label": "the control plane (dev build)"}]}),
    ];
    let o = r.make().handle("propose", as_map(json!({"changeId": "c1"}))).await;
    assert_eq!(
        (o.status.as_str(), &o.data.unwrap_or_default()["tofu"]),
        ("applied", &json!(true))
    );
}

#[tokio::test]
async fn with_somebody_approved_turning_it_on_sends_a_code_and_waits_for_it() {
    let r = rig();
    let tc = r.make();
    assert_eq!(
        tc.handle("propose", as_map(json!({"changeId": "c1"}))).await.status,
        "awaiting_code"
    );
    assert!(!tc.enabled());
    assert_eq!(
        r.codes.sent.lock().expect("lock").last().map(String::as_str),
        Some(ENABLE_SUMMARY)
    );
    assert_eq!(tc.status()["pending"]["changeId"], "c1");
    assert_eq!(
        tc.handle("confirm", as_map(json!({"changeId": "c1", "code": "000000"})))
            .await
            .status,
        "invalid_code"
    );
    assert!(!tc.enabled());
    assert_eq!(
        tc.handle("confirm", as_map(json!({"changeId": "c1", "code": CODE})))
            .await
            .status,
        "applied"
    );
    assert!(tc.enabled());
    assert_eq!(tc.status()["pending"], Value::Null);
}

#[tokio::test]
async fn an_unreadable_channel_list_or_no_codes_on_this_build_never_reads_as_nobody_to_ask() {
    let r = rig();
    r.routes.list.lock().expect("lock").clear();
    r.routes.ready.store(false, Ordering::SeqCst);
    let tc = r.make();
    assert_eq!(
        tc.handle("propose", as_map(json!({"changeId": "c1"}))).await.status,
        "failed"
    );
    assert!(!tc.enabled());
    // No code routes or consent codes at all: refused, never trust-on-first-use.
    let dir = tempfile::tempdir().expect("dir");
    let bare = testing::app(dir.path());
    let w = Arc::new(World::default());
    w.installed.store(true, Ordering::SeqCst);
    let tc = TeamChatFirewall::new(
        &bare,
        Options {
            path: dir.path().join("t.enc"),
            api: Arc::new(Api(w.clone())),
            helper: Arc::new(Helper(w)),
            gateway_url: String::new(),
            home_url: String::new(),
            hostname: Arc::new(|| None),
            now: Arc::new(js::now_ms),
            sleep: Arc::new(|_| Box::pin(async {})),
        },
    );
    let o = tc.handle("propose", as_map(json!({"changeId": "c1"}))).await;
    assert_eq!(
        (o.status.as_str(), o.message.as_deref()),
        ("failed", Some(crate::integrations::codes::NOT_READY))
    );
    assert!(!tc.enabled());
}

#[tokio::test]
async fn a_firewall_without_clickclack_refuses_and_cancel_drops_the_pending_code() {
    let r = rig();
    r.w.installed.store(false, Ordering::SeqCst);
    let o = r.make().handle("propose", as_map(json!({"changeId": "c1"}))).await;
    assert_eq!(o.status, "failed");
    assert!(o.message.unwrap_or_default().contains("Update the firewall"));
    let r = rig();
    let tc = r.make();
    tc.handle("propose", as_map(json!({"changeId": "c1"}))).await;
    tc.handle("cancel", as_map(json!({"changeId": "c1"}))).await;
    assert_eq!(
        tc.handle("confirm", as_map(json!({"changeId": "c1", "code": CODE})))
            .await
            .status,
        "expired"
    );
    assert_eq!(
        tc.handle("propose", Map::new()).await.message.as_deref(),
        Some("malformed teamchat.propose payload")
    );
}

#[tokio::test]
async fn on_starts_the_unit_sets_up_the_workspace_a_bot_per_agent_and_pushes_a_placeholder() {
    let r = rig();
    let tc = r.turned_on().await;
    assert_eq!(tc.status()["state"], "running");
    assert!(
        r.w.helper_calls
            .lock()
            .expect("lock")
            .contains(&"start fw-x.ccl.bot https://controlclaw.com/dashboard/team-chat".to_string())
    );
    assert_eq!(r.w.renamed.lock().expect("lock").as_deref(), Some("Team chat"));
    assert_eq!(r.handles(), ["ops-bot", "sales"]);
    let push = r.applies("vm-a")[0].clone();
    let s = &push["settings"];
    assert_eq!(push["type"], "clickclack");
    assert_eq!(
        (&s["baseUrl"], &s["apiBaseUrl"], &s["workspace"]),
        (
            &json!("https://fw-x.ccl.bot"),
            &json!("http://10.0.0.2:3930"),
            &json!("wsp_teamchat0000")
        )
    );
    assert!(s["token"].as_str().expect("token").starts_with("cctc_"));
    let all = js::stringify(&Value::Array(
        r.w.applies
            .lock()
            .expect("lock")
            .iter()
            .map(|(_, b)| b.clone())
            .collect(),
    ));
    assert!(!all.contains("ccb_real"), "no real token in anything sent to an agent");
    assert_eq!(
        agents_of(&tc.status()),
        [("vm-a".into(), "connected".into()), ("vm-b".into(), "connected".into())]
    );
    // Sealed on disk.
    let raw = std::fs::read_to_string(&r.store).expect("store");
    assert!(!raw.contains("ccb_real") && !raw.contains("sst_"));
    // A second reconcile pushes nothing new.
    let before = r.w.applies.lock().expect("lock").len();
    tc.reconcile().await;
    assert_eq!(r.w.applies.lock().expect("lock").len(), before);
    assert_eq!(r.w.bots.lock().expect("lock").len(), 2);
    // A fresh instance reads the same store.
    assert!(r.make().enabled());
    assert_eq!(tc.tokens().len(), 2);
}

#[tokio::test]
async fn the_gate_resolves_a_placeholder_only_for_its_own_agent_and_only_while_on() {
    let r = rig();
    let tc = r.turned_on().await;
    let placeholder = r.applies("vm-a")[0]["settings"]["token"]
        .as_str()
        .expect("token")
        .to_string();
    let (vm, token, ip) = tc.resolve(&placeholder).expect("resolved");
    assert_eq!((vm.as_str(), ip.as_str()), ("vm-a", "10.0.0.3"));
    assert!(token.starts_with("ccb_real"));
    assert!(tc.resolve("cctc_nope").is_none());
    let real = r.w.bots.lock().expect("lock")[0].2.clone();
    assert!(tc.resolve(&real).is_none(), "the real token is not a placeholder");
    tc.handle("disable", Map::new()).await;
    assert!(tc.resolve(&placeholder).is_none());
}

#[tokio::test]
async fn each_agent_is_told_the_other_agents_bots_and_told_again_when_that_changes() {
    let r = rig();
    r.set_agents(vec![a()]);
    let tc = r.turned_on().await;
    let last_peers = |vm: &str| {
        r.applies(vm)
            .last()
            .map(|b| b["settings"]["peers"].clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(last_peers("vm-a"), json!([]));
    r.set_agents(vec![a(), b()]);
    tc.reconcile().await;
    let bot_of = |h: &str| {
        r.w.bots
            .lock()
            .expect("lock")
            .iter()
            .find(|(_, x, _)| x == h)
            .map(|(id, _, _)| id.clone())
            .expect("bot")
    };
    assert_eq!(
        last_peers("vm-a"),
        json!([bot_of("ops-bot")]),
        "A is re-pushed with B's bot"
    );
    assert_eq!(last_peers("vm-b"), json!([bot_of("sales")]));
    assert_eq!(r.applies("vm-b").len(), 1, "a new agent joins on the next reconcile");
    let before = r.applies("vm-a").len();
    r.set_agents(vec![a()]);
    tc.reconcile().await;
    assert_eq!(r.applies("vm-a").len(), before + 1, "A is re-pushed once B is gone");
    assert_eq!(last_peers("vm-a"), json!([]));
}

#[tokio::test]
async fn a_deleted_agents_bot_is_deleted_an_empty_map_deletes_nothing_and_forget_is_at_once() {
    let r = rig();
    let tc = r.turned_on().await;
    r.set_agents(vec![]);
    tc.reconcile().await;
    assert_eq!(
        r.w.bots.lock().expect("lock").len(),
        2,
        "an empty identity map is not every agent deleted"
    );
    r.set_agents(vec![a()]);
    tc.reconcile().await;
    assert_eq!(r.handles(), ["sales"]);
    assert_eq!(agents_of(&tc.status()).len(), 1);

    let r = rig();
    let tc = r.turned_on().await;
    let o = tc.handle("forget", as_map(json!({"vmId": "vm-b"}))).await;
    assert_eq!(o.data.unwrap_or_default()["revoked"], true);
    assert_eq!(r.handles(), ["sales"]);
    // The identity map still lists the agent being deleted: it must not come back as a new bot.
    tc.reconcile().await;
    assert_eq!(r.handles(), ["sales"]);
    assert_eq!(
        r.applies("vm-a").last().expect("push")["settings"]["peers"],
        json!([]),
        "A no longer admits B's bot"
    );
}

#[tokio::test]
async fn an_agent_that_cannot_take_the_channel_is_failed_then_retried_later_or_on_push() {
    let r = rig();
    r.routes.list.lock().expect("lock").clear();
    *r.w.apply_fails.lock().expect("lock") = Some("vm-b".into());
    let tc = r.make();
    tc.handle("propose", as_map(json!({"changeId": "c1"}))).await;
    tc.reconcile().await;
    let st = tc.status();
    let bst = st["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .find(|x| x["vmId"] == "vm-b")
        .cloned()
        .expect("b");
    assert_eq!(bst["status"], "failed");
    assert!(bst["error"].as_str().unwrap_or("").contains("plugin"));
    *r.w.apply_fails.lock().expect("lock") = None;
    let tried = r.applies("vm-b").len();
    assert_eq!(tried, 1);
    tc.reconcile().await;
    assert_eq!(r.applies("vm-b").len(), tried, "not retried before its backoff");
    tc.handle("push", as_map(json!({"vmId": "vm-b"}))).await;
    tc.reconcile().await;
    assert_eq!(r.applies("vm-b").len(), tried + 1, "a push skips the backoff");
}

#[tokio::test]
async fn a_rebuilt_agent_that_lost_the_channel_or_holds_an_older_list_gets_it_written_again() {
    let r = rig();
    let tc = r.turned_on().await;
    r.w.box_channel.lock().expect("lock").remove("vm-a");
    r.clock.fetch_add(11 * 60_000, Ordering::SeqCst);
    tc.reconcile().await;
    tc.reconcile().await;
    assert_eq!(r.applies("vm-a").len(), 2);

    let r = rig();
    let tc = r.turned_on().await;
    let pushes = r.applies("vm-a").len();
    r.w.box_channel.lock().expect("lock").insert(
        "vm-a".into(),
        json!({"configured": true, "connected": true, "peers": []}),
    );
    r.clock.fetch_add(6 * 60_000, Ordering::SeqCst);
    tc.reconcile().await;
    tc.reconcile().await;
    assert_eq!(r.applies("vm-a").len(), pushes + 1);
    // A box that reports the right list, or none at all (an older agent), is left alone.
    let ops =
        r.w.bots
            .lock()
            .expect("lock")
            .iter()
            .find(|(_, h, _)| h == "ops-bot")
            .map(|(id, _, _)| id.clone())
            .expect("bot");
    r.w.box_channel.lock().expect("lock").insert(
        "vm-a".into(),
        json!({"configured": true, "connected": true, "peers": [ops]}),
    );
    r.w.box_channel
        .lock()
        .expect("lock")
        .insert("vm-b".into(), json!({"configured": true, "connected": true}));
    r.clock.fetch_add(6 * 60_000, Ordering::SeqCst);
    tc.reconcile().await;
    assert_eq!(r.applies("vm-a").len(), pushes + 1);
    assert_eq!(r.applies("vm-b").len(), 1);
}

#[tokio::test]
async fn an_expired_owner_session_is_replaced_once() {
    let r = rig();
    let tc = r.turned_on().await;
    r.w.session_valid.store(false, Ordering::SeqCst);
    r.set_agents(vec![a(), b(), ident("vm-c", "c.ccl.bot", "C", "10.0.0.5")]);
    tc.reconcile().await;
    assert_eq!(r.w.bots.lock().expect("lock").len(), 3);
    assert_eq!(
        r.w.helper_calls
            .lock()
            .expect("lock")
            .iter()
            .filter(|h| *h == "bootstrap")
            .count(),
        2
    );
}

#[tokio::test]
async fn off_takes_the_channel_off_every_agent_stops_the_unit_and_signs_everybody_out() {
    let r = rig();
    let tc = r.turned_on().await;
    let (_, cookie) = tc.admit(&person(true, Some("m@example.com"))).await.expect("admitted");
    assert!(tc.grant(&cookie).is_some());
    assert_eq!(tc.handle("disable", Map::new()).await.status, "applied");
    tc.reconcile().await;
    assert_eq!(*r.w.unit.lock().expect("lock"), "inactive");
    assert_eq!(tc.status()["state"], "off");
    for vm in ["vm-a", "vm-b"] {
        assert!(r.applies(vm).iter().any(|b| b["remove"] == true), "{vm}");
    }
    assert!(tc.grant(&cookie).is_none());
    assert_eq!(tc.status()["agents"], json!([]));
    assert_eq!(
        r.w.bots.lock().expect("lock").len(),
        2,
        "the bots and the history stay for when it is turned on again"
    );

    // A failed write may have left the block there: off reaches it, without waiting out its backoff.
    let r = rig();
    r.routes.list.lock().expect("lock").clear();
    *r.w.apply_fails.lock().expect("lock") = Some("vm-b".into());
    let tc = r.make();
    tc.handle("propose", as_map(json!({"changeId": "c1"}))).await;
    tc.reconcile().await;
    *r.w.apply_fails.lock().expect("lock") = None;
    tc.handle("disable", Map::new()).await;
    tc.reconcile().await;
    assert!(
        r.applies("vm-b").iter().any(|b| b["remove"] == true),
        "the failed agent is told to take it off, at once"
    );
}

#[tokio::test]
async fn people_a_members_chat_role_follows_their_console_role_and_the_grant_is_only_a_hash() {
    let r = rig();
    let tc = r.turned_on().await;
    let (magic, cookie) = tc.admit(&person(true, Some("m@example.com"))).await.expect("admitted");
    assert_eq!(magic, "mgt_person0000000");
    let calls = r.w.helper_calls.lock().expect("lock").clone();
    assert!(
        calls
            .iter()
            .any(|h| h.contains(&person_email("org1", "u1")) && h.ends_with(" Marco"))
    );
    assert!(
        !calls.iter().any(|h| h.contains("m@example.com")),
        "the real email is not passed on"
    );
    assert_eq!(
        r.w.roles.lock().expect("lock").values().cloned().collect::<Vec<_>>(),
        ["moderator"]
    );
    tc.admit(&person(false, None)).await.expect("admitted");
    assert_eq!(
        r.w.roles.lock().expect("lock").values().cloned().collect::<Vec<_>>(),
        ["member"]
    );
    assert!(!std::fs::read_to_string(&r.store).expect("store").contains(&cookie));
    assert!(tc.grant(&"x".repeat(43)).is_none());
    assert_eq!(tc.grant(&cookie).map(|g| g.user_id), Some("u1".into()));
    // Off: nobody is let in.
    let r = rig();
    assert!(r.make().admit(&person(false, None)).await.is_err());
}

#[tokio::test]
async fn the_beat_carries_state_and_status_only_and_a_clickclack_that_does_not_come_up_is_reported() {
    let r = rig();
    let tc = r.turned_on().await;
    let beat = js::stringify(&tc.status());
    assert!(!beat.contains("ccb_") && !beat.contains("cctc_") && !beat.contains("sst_"));
    let mut keys: Vec<String> = tc.status().as_object().expect("object").keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["agents", "enabled", "message", "pending", "state", "stats"]);

    let r = rig();
    r.w.healthy.store(false, Ordering::SeqCst);
    let tc = r.turned_on().await;
    assert_eq!(tc.status()["state"], "failed");
    assert!(tc.status()["message"].as_str().unwrap_or("").contains("did not answer"));
    assert!(r.w.bots.lock().expect("lock").is_empty());
}
