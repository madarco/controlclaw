//! `logins.test.ts`, the store and the agent's tools.

use std::sync::atomic::{AtomicI64, Ordering};

use super::*;
use crate::integrations::logins::mcp::answer_logins_mcp;
use crate::integrations::testing::{self, FakeAgents, FakeCodes, Identities, Routes, Syncs};

struct Rig {
    _dir: tempfile::TempDir,
    ids: Arc<Identities>,
    app: Arc<App>,
    fw: Arc<LoginsFirewall>,
    agents: Arc<FakeAgents>,
    syncs: Arc<Syncs>,
    codes: Arc<FakeCodes>,
    clock: Arc<AtomicI64>,
    store: PathBuf,
    log: PathBuf,
    targets: PathBuf,
}

fn rig(agents: &[(&str, &str)], console: &str) -> Rig {
    rig_with(agents, console, None)
}

fn rig_with(agents: &[(&str, &str)], console: &str, runner: Option<cc_proc::RecordingRunner>) -> Rig {
    let dir = tempfile::tempdir().expect("dir");
    let mut app = testing::app(dir.path());
    let a = Arc::get_mut(&mut app).expect("fresh");
    a.config.firewall_url = console.into();
    if let Some(r) = runner {
        a.runner = Arc::new(r);
    }
    let list: Vec<(&str, &str, &str)> = agents.iter().map(|(v, n)| (*v, "10.0.0.9", *n)).collect();
    let ids = Identities::of(&list);
    app.contracts.identities.set(ids.clone());
    let fake = Arc::new(FakeAgents::default());
    app.contracts.agents.set(fake.clone());
    let syncs = Arc::new(Syncs::default());
    app.contracts.credentials_sync.set(syncs.clone());
    let codes = FakeCodes::new("123456");
    app.contracts.consent.set(codes.clone());
    app.contracts
        .code_routes
        .set(Arc::new(Routes(std::sync::Mutex::new(vec![testing::owner_route()]))));
    let clock = Arc::new(AtomicI64::new(js::parse_iso("2026-10-10T00:00:00.000Z").expect("date")));
    let c = clock.clone();
    let (store, log, targets) = (
        dir.path().join("logins.enc"),
        dir.path().join("traffic.jsonl"),
        dir.path().join("login-targets.json"),
    );
    let fw = LoginsFirewall::with_clock(
        &app,
        store.clone(),
        Some(log.clone()),
        Some(targets.clone()),
        Arc::new(move || c.load(Ordering::SeqCst)),
    )
    .expect("open");
    Rig {
        ids,
        _dir: dir,
        app,
        fw,
        agents: fake,
        syncs,
        codes,
        clock,
        store,
        log,
        targets,
    }
}

impl Rig {
    fn again(&self) -> Arc<LoginsFirewall> {
        LoginsFirewall::new(&self.app, self.store.clone(), None, None).expect("open")
    }
    fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }
    async fn call(&self, vm: &str, body: Value) -> Value {
        answer_logins_mcp(&self.fw, vm, js::stringify(&body).as_bytes())
            .await
            .1
            .unwrap_or(Value::Null)
    }
    async fn tool(&self, vm: &str, name: &str, args: Value) -> Value {
        self.call(
            vm,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}),
        )
        .await["result"]
            .clone()
    }
    fn creds(&self, name: &str) -> Value {
        self.fw
            .credentials()
            .into_iter()
            .find(|c| c["login_name"] == name)
            .unwrap_or(Value::Null)
    }
    fn by_name(&self, name: &str) -> Value {
        self.fw.summary()["logins"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|l| l["name"] == name)
            .cloned()
            .unwrap_or(Value::Null)
    }
    fn traffic(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    async fn command(&self, action: &str, p: Value) -> CommandOutcome {
        self.fw.handle(action, as_map(p)).await
    }
}

fn text(r: &Value) -> String {
    r["content"][0]["text"].as_str().unwrap_or("").to_string()
}

fn parsed(r: &Value) -> Value {
    serde_json::from_str(&text(r)).unwrap_or(Value::Null)
}

fn with(base: &Value, extra: Value) -> Value {
    let mut m = base.as_object().cloned().unwrap_or_default();
    for (k, v) in as_map(extra) {
        m.insert(k, v);
    }
    Value::Object(m)
}

fn msg(r: Result<Value, Refused>) -> String {
    match r {
        Ok(v) => panic!("accepted: {v}"),
        Err(Refused::Message(m)) => m,
        Err(Refused::Invalid(i)) => format!("{}: {}", i.path, i.message),
    }
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(String::from))
        .collect()
}

#[tokio::test]
async fn where_the_password_may_go_sign_in_page_basic_extra_addresses_and_allowed_targets() {
    let r = rig(&[("a", "Ada")], "");
    let entry = json!({"name": "GitHub", "sites": ["github.com", "*.github.com"], "loginUrl": "https://github.com/login", "username": "ops", "password": "S3cret-pass!", "vmIds": ["a"]});
    // A login the proxy puts in needs a sign-in page it can read: https, a host, nothing odd.
    for bad in [
        Value::Null,
        json!("http://github.com/login"),
        json!("https:///bad.example/login"),
        json!("https://user:pw@github.com/login"),
        json!("https://github.com/login#x"),
        json!("https://github.com/a/../login"),
        json!("https://github.com/a;b"),
    ] {
        assert!(
            r.fw.put("o", &with(&entry, json!({"loginUrl": bad})), None)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let mut no_url = entry.clone();
    no_url.as_object_mut().expect("object").remove("loginUrl");
    assert!(r.fw.put("o", &no_url, None).await.is_err());
    // Extra addresses: a path, or a site and a path. Never a whole site, never an odd path.
    for bad in [
        "session",
        "/",
        "github.com/",
        "/*",
        "github.com/*",
        "github.com",
        "/x?",
        "/x?a",
        "/x?a=1&a=2",
        "/x?a=1&A=2",
        "/x?a[]=1",
        "/x?a=1;b=2",
        "/x?a%00=1",
        "/a/../b",
        "https://github.com/session",
        "/a//b",
        "/a b",
        "/a;b",
        "/a%252fb",
        "/x#y",
        "/a\\b",
        "/a*",
        "/a/*/b",
        "/a/*?x=1",
        "bad host/x",
    ] {
        assert!(
            r.fw.put("o", &with(&entry, json!({"signInPaths": [bad]})), None)
                .await
                .is_err(),
            "{bad}"
        );
    }
    let paths = json!(["/session", "api.github.com/auth/*", "/index.php?route=account/login"]);
    let made =
        r.fw.put("o", &with(&entry, json!({"signInPaths": paths})), None)
            .await
            .expect("made");
    assert_eq!(
        (
            &made["auth"],
            &made["signInPaths"],
            &made["learnedTargets"],
            &made["needsSignInPage"]
        ),
        (&json!("form"), &paths, &json!([]), &json!(false))
    );
    let id = made["id"].as_str().expect("id").to_string();
    // HTTP Basic and "typed into the page" need no sign-in page.
    let api =
        r.fw.put(
            "o",
            &with(
                &entry,
                json!({"name": "API", "sites": ["api.example"], "loginUrl": null, "auth": "basic"}),
            ),
            None,
        )
        .await
        .expect("basic");
    assert_eq!(
        (&api["auth"], &r.by_name("API")["needsSignInPage"]),
        (&json!("basic"), &json!(false))
    );
    let typed =
        r.fw.put(
            "o",
            &with(
                &entry,
                json!({"name": "Typed", "sites": ["typed.example"], "loginUrl": null, "mode": "type"}),
            ),
            None,
        )
        .await
        .expect("typed");
    assert_eq!(typed["needsSignInPage"], false);
    let c = r.creds("API");
    assert_eq!((&c["login_auth"], &c["login_url"]), (&json!("basic"), &Value::Null));
    let how = parsed(&r.tool("a", "login_use", json!({"login": "API"})).await)["how"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        how.contains("HTTP Basic") && how.contains("Authorization header"),
        "{how}"
    );

    // An imported login often has no usable sign-in page: it is marked, the agent is told, and the
    // owner sets the page without retyping the password.
    r.fw.import_rows(
        "o",
        &json!({"rows": [
            {"name": "Imported", "sites": ["shop.example"], "loginUrl": "http://shop.example/", "username": "u", "password": "Pw-imported-1"},
            {"name": "NoUrl", "sites": ["x.example"], "username": "u", "password": "Pw-imported-2"},
        ], "vmIds": ["a"]}),
    )
    .await
    .expect("import");
    assert_eq!(
        (
            &r.by_name("Imported")["needsSignInPage"],
            &r.by_name("NoUrl")["needsSignInPage"]
        ),
        (&json!(true), &json!(true))
    );
    let told = r.tool("a", "login_use", json!({"login": "Imported"})).await;
    assert_eq!(told["isError"], true);
    assert!(text(&told).contains("no sign-in page yet") && text(&told).contains("Sign-in page"));
    assert!(!text(&told).contains("password_placeholder"));
    assert!(
        r.traffic()
            .contains("login Imported: not handed to the agent, it has no sign-in page")
    );
    let imported = r.by_name("Imported")["id"].as_str().expect("id").to_string();
    let fixed = r
        .fw
        .set_scope(&json!({"id": imported, "loginUrl": "https://shop.example/index.php?route=account/login", "signInPaths": []}))
        .await
        .expect("fixed");
    assert_eq!(
        (&fixed["needsSignInPage"], fixed["loginUrl"].as_str()),
        (
            &json!(false),
            Some("https://shop.example/index.php?route=account/login")
        )
    );
    assert!(parsed(&r.tool("a", "login_use", json!({"login": "Imported"})).await)["password_placeholder"].is_string());
    assert!(
        r.fw.set_scope(&json!({"id": imported, "loginUrl": "http://shop.example/login", "signInPaths": []}))
            .await
            .is_err()
    );

    // What the proxy read off the sign-in page: taken in when it is for this page, https and on the
    // login's sites. It is pending until the owner allows it.
    let seen = |times: Vec<(&str, f64)>, page: &str| {
        let targets: Map<String, Value> = times
            .into_iter()
            .map(|(u, at)| {
                (
                    u.to_string(),
                    json!({"seen": at, "field": if u.ends_with("/session") { json!("password") } else { Value::Null }}),
                )
            })
            .collect();
        let doc = json!({id.clone(): {"page": page, "targets": targets}, "lg_gone0000000": {"page": page, "targets": targets}});
        std::fs::write(&r.targets, js::stringify(&doc)).expect("write");
    };
    let page = "https://github.com/login";
    let at = r.now() as f64 / 1000.0;
    let before = r.syncs.count();
    seen(vec![("https://github.com/session", at)], "https://github.com/other");
    assert!(
        !r.fw.ingest_learned_targets().await,
        "read off another page than the login's"
    );
    seen(
        vec![
            ("https://github.com/session", at),
            ("http://github.com/plain", at),
            ("https://evil.example/c", at),
            ("https://github.com/q?x=1", at - 30.0),
            ("https://github.com/q?x[]=1", at),
            ("https://gist.github.com/sso", at - 60.0),
            ("https://github.com/a;b", at),
            ("https://github.com/", at),
        ],
        page,
    );
    assert!(r.fw.ingest_learned_targets().await);
    assert_eq!(r.syncs.count(), before + 1);
    let gh = || r.creds("GitHub");
    let all = [
        "https://github.com/session",
        "https://github.com/q?x=1",
        "https://gist.github.com/sso",
    ];
    assert_eq!(
        (strs(&gh()["sign_in_targets"]), strs(&gh()["pending_targets"])),
        (vec![], all.map(String::from).to_vec())
    );
    let learned: Vec<Value> = r.fw.get(&id).expect("login")["learnedTargets"]
        .as_array()
        .expect("list")
        .iter()
        .map(|t| json!([t["url"], t["approved"], t["field"]]))
        .collect();
    let want: Vec<Value> = all
        .iter()
        .map(|u| {
            json!([
                u,
                false,
                if u.ends_with("/session") {
                    json!("password")
                } else {
                    Value::Null
                }
            ])
        })
        .collect();
    assert_eq!(learned, want);
    assert_eq!(
        gh()["sign_in_fields"],
        json!({"https://github.com/session": "password"})
    );
    assert!(!r.fw.ingest_learned_targets().await, "nothing new");

    // The owner allows one, removes one and changes the addresses. The removed one is not learned again.
    let edited = r
        .fw
        .set_scope(&json!({"id": id, "signInPaths": ["/session"], "approve": ["https://github.com/session", "https://never-seen.example/x"], "forget": ["https://gist.github.com/sso"]}))
        .await
        .expect("edited");
    let pairs: Vec<Value> = edited["learnedTargets"]
        .as_array()
        .expect("list")
        .iter()
        .map(|t| json!([t["url"], t["approved"]]))
        .collect();
    assert_eq!(edited["signInPaths"], json!(["/session"]));
    assert_eq!(
        pairs,
        vec![
            json!(["https://github.com/session", true]),
            json!(["https://github.com/q?x=1", false])
        ]
    );
    assert_eq!(
        (
            &gh()["sign_in_targets"],
            &gh()["pending_targets"],
            &gh()["refused_targets"]
        ),
        (
            &json!(["https://github.com/session"]),
            &json!(["https://github.com/q?x=1"]),
            &json!(["https://gist.github.com/sso"])
        )
    );
    assert!(!r.fw.ingest_learned_targets().await);
    assert_eq!(gh()["sign_in_targets"], json!(["https://github.com/session"]));
    // Unticking an allowed one removes it.
    r.fw.set_scope(&json!({"id": id, "signInPaths": ["/session"], "forget": ["https://github.com/session"]}))
        .await
        .expect("forget");
    assert_eq!(
        (&gh()["sign_in_targets"], &gh()["refused_targets"]),
        (
            &json!([]),
            &json!(["https://gist.github.com/sso", "https://github.com/session"])
        )
    );
    assert!(
        r.fw.set_scope(&json!({"id": id, "signInPaths": ["nope"]}))
            .await
            .is_err()
    );

    // At most five, the newest; gone 30 days after they were last on the page.
    let eight: Vec<(String, f64)> = (0..8)
        .map(|i| (format!("https://github.com/t{i}"), at + i as f64))
        .collect();
    seen(eight.iter().map(|(u, a)| (u.as_str(), *a)).collect(), page);
    r.fw.ingest_learned_targets().await;
    let five: Vec<String> = (3..8).rev().map(|i| format!("https://github.com/t{i}")).collect();
    assert_eq!(strs(&gh()["pending_targets"]), five);
    r.fw.set_scope(&json!({"id": id, "signInPaths": [], "approve": five}))
        .await
        .expect("approve");
    assert_eq!(strs(&gh()["sign_in_targets"]), five);
    r.advance(31 * 86_400_000);
    assert_eq!(
        (strs(&gh()["sign_in_targets"]), strs(&gh()["pending_targets"])),
        (vec![], vec![])
    );
    // Allowed and then gone from the page for 30 days: no longer used, and the page says so.
    let mut expired = strs(&gh()["expired_targets"]);
    expired.sort();
    let mut sorted = five.clone();
    sorted.sort();
    assert_eq!(expired, sorted);
    assert!(
        r.fw.get(&id).expect("login")["learnedTargets"]
            .as_array()
            .expect("list")
            .iter()
            .all(|t| t["expired"] == true && t["approved"] == true)
    );
    // Seen on the page again: it counts again, with the tick it had.
    let now_s = r.now() as f64 / 1000.0;
    seen(vec![("https://github.com/t7", now_s)], page);
    r.fw.ingest_learned_targets().await;
    assert_eq!(
        (strs(&gh()["sign_in_targets"]), strs(&gh()["expired_targets"]).len()),
        (vec!["https://github.com/t7".to_string()], 4)
    );
    seen(five.iter().map(|u| (u.as_str(), now_s)).collect(), page);
    r.fw.ingest_learned_targets().await;

    // A narrower site list drops what is no longer on it; a new sign-in page starts again.
    r.advance(-31 * 86_400_000);
    r.fw.put(
        "o",
        &with(&entry, json!({"sites": ["gist.github.com"], "loginUrl": page})),
        Some(&id),
    )
    .await
    .expect("narrow");
    assert_eq!(gh()["sign_in_targets"], json!([]));
    r.fw.put("o", &entry, Some(&id)).await.expect("wide");
    assert_eq!(strs(&gh()["sign_in_targets"]).len(), 5);
    r.fw.put(
        "o",
        &with(&entry, json!({"loginUrl": "https://github.com/signin"})),
        Some(&id),
    )
    .await
    .expect("new page");
    assert_eq!(
        (
            &gh()["sign_in_targets"],
            &gh()["pending_targets"],
            &gh()["refused_targets"],
            &gh()["login_url"]
        ),
        (&json!([]), &json!([]), &json!([]), &json!("https://github.com/signin"))
    );
}

#[tokio::test]
async fn store_page_console_narrowing_and_widening_proxy_entries_tools() {
    let r = rig(&[("a", "Ada"), ("b", "Bo")], "");
    let base = json!({"name": "n", "sites": ["github.com"], "loginUrl": "https://github.com/login", "username": "u", "password": "p"});
    assert!(
        msg(r
            .fw
            .put("owner@x", &with(&base, json!({"vmIds": ["nope"]})), None)
            .await)
        .contains("not part of this organization")
    );
    assert!(
        r.fw.put(
            "owner@x",
            &with(&base, json!({"sites": ["https://github.com/login"], "vmIds": ["a"]})),
            None
        )
        .await
        .is_err()
    );
    let entry = json!({"name": "GitHub ops", "sites": ["github.com"], "loginUrl": "https://github.com/login", "username": "ops", "password": "S3cret-pass!", "vmIds": ["a"]});
    let syncs = r.syncs.count();
    let made = r.fw.put("owner@x", &entry, None).await.expect("made");
    let id = made["id"].as_str().expect("id").to_string();
    assert_eq!(r.syncs.count(), syncs + 1);
    assert_eq!(made["createdBy"], "owner@x");
    assert!(!js::stringify(&Value::Object(r.fw.summary())).contains("S3cret-pass!"));
    // Encrypted at rest.
    assert!(
        !std::fs::read_to_string(&r.store)
            .expect("store")
            .contains("S3cret-pass!")
    );
    let creds = r.fw.credentials();
    assert_eq!(creds.len(), 1);
    let ph = creds[0]["placeholder"].as_str().expect("placeholder").to_string();
    let mut shown = creds[0].clone();
    shown["placeholder"] = json!("x");
    assert_eq!(
        shown,
        json!({"login_id": id, "login_name": "GitHub ops", "vm_id": "a", "placeholder": "x", "secret": "S3cret-pass!", "allowed_hosts": ["github.com"],
            "login_url": "https://github.com/login", "login_auth": "form", "sign_in_paths": [], "sign_in_targets": [], "pending_targets": [],
            "expired_targets": [], "sign_in_fields": {}, "refused_targets": []})
    );
    assert!(placeholder_fits(&ph, "S3cret-pass!"));

    // The agent's tools: list without secrets, use by name gives the placeholder; another agent gets nothing.
    let init = r
        .call(
            "a",
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "controlclaw-logins");
    let tools: Vec<Value> = r
        .call("a", json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(
        tools,
        [
            "logins_list",
            "login_use",
            "login_type",
            "login_request",
            "login_status",
            "login_code"
        ]
        .map(|t| json!(t))
        .to_vec()
    );
    let listed = text(&r.tool("a", "logins_list", json!({})).await);
    assert!(!listed.contains("S3cret") && !listed.contains(&ph));
    let used = r.tool("a", "login_use", json!({"login": "github OPS"})).await;
    let u = parsed(&used);
    assert_eq!(
        (u["password_placeholder"].as_str(), u["username"].as_str()),
        (Some(ph.as_str()), Some("ops"))
    );
    let how = u["how"].as_str().expect("how");
    assert!(
        regex::Regex::new(r"(?s)sign-in form on the sign_in_page.*works nowhere else.*blocked once.*tick the address")
            .expect("re")
            .is_match(how)
    );
    assert!(!text(&used).contains("S3cret"));
    assert_eq!(r.tool("b", "login_use", json!({"login": id})).await["isError"], true);
    let note = answer_logins_mcp(&r.fw, "a", br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).await;
    assert_eq!(note, (202, None));
    assert!(!r.fw.get(&id).expect("login")["lastUsedAt"].is_null());

    // Replacing with a password of the same shape keeps the placeholder; another shape gets a new one.
    r.fw.put("owner@x", &with(&entry, json!({"password": "N3wer-pass!!"})), Some(&id))
        .await
        .expect("same shape");
    assert_eq!(r.fw.credentials()[0]["placeholder"], json!(ph));
    r.fw.put("owner@x", &with(&entry, json!({"password": "short"})), Some(&id))
        .await
        .expect("other shape");
    assert_ne!(r.fw.credentials()[0]["placeholder"], json!(ph));

    // Console: widening needs a code (summary written here), narrowing does not.
    let widen = r
        .command("propose", json!({"action": "update", "id": id, "name": "GitHub ops", "sites": ["github.com", "api.github.com"], "vmIds": ["a", "b"], "changeId": "c1"}))
        .await;
    assert_eq!(widen.status, "awaiting_code");
    let message = r.codes.sent.lock().expect("lock").last().cloned().unwrap_or_default();
    assert!(
        message.contains("api.github.com") && message.contains("by Bo as well"),
        "{message}"
    );
    assert_eq!(
        r.command("confirm", json!({"id": id, "changeId": "c1", "code": "000000"}))
            .await
            .status,
        "invalid"
    );
    assert_eq!(
        r.command("confirm", json!({"id": id, "changeId": "c1", "code": "123 456"}))
            .await
            .status,
        "applied"
    );
    assert_eq!(r.fw.get(&id).expect("login")["vmIds"], json!(["a", "b"]));
    assert_eq!(r.fw.credentials().len(), 2);
    let narrow = r
        .command("propose", json!({"action": "update", "id": id, "name": "GitHub", "sites": ["github.com"], "vmIds": ["b"], "changeId": "c2"}))
        .await;
    assert_eq!(narrow.status, "applied");
    assert_eq!(
        r.fw.credentials()
            .iter()
            .map(|c| c["vm_id"].clone())
            .collect::<Vec<_>>(),
        vec![json!("b")]
    );

    // A fresh instance reads the same store.
    assert_eq!(r.again().summary()["logins"][0]["name"], "GitHub");

    let del = r
        .command("propose", json!({"action": "delete", "id": id, "changeId": "c3"}))
        .await;
    assert_eq!(del.status, "applied");
    assert!(r.fw.credentials().is_empty());
    let log = r.traffic();
    assert!(!log.contains("S3cret") && !log.contains("N3wer"));
    assert!(log.contains(r#""login":"GitHub ops""#));
    assert!(log.contains("deleted from the console"));
}

#[tokio::test]
async fn a_widening_is_refused_while_codes_cannot_be_sent() {
    let r = rig(&[("a", "Ada"), ("b", "Bo")], "");
    let made = r
        .fw
        .put("o", &json!({"name": "G", "sites": ["github.com"], "loginUrl": "https://github.com/login", "username": "u", "password": "Pw-1", "vmIds": ["a"]}), None)
        .await
        .expect("made");
    let id = made["id"].as_str().expect("id").to_string();
    // No consent codes and no code routes on this build: the change is refused, never applied.
    let empty = LoginsFirewall::new(&strip(&r), r.store.clone(), None, None).expect("open");
    let out = empty
        .handle("propose", as_map(json!({"action": "update", "id": id, "name": "G", "sites": ["github.com"], "vmIds": ["a", "b"], "changeId": "c1"})))
        .await;
    assert_eq!(
        (out.ok, out.status.as_str(), out.message.as_deref().unwrap_or("")),
        (false, "failed", crate::integrations::codes::NOT_READY)
    );
    assert_eq!(empty.get(&id).expect("login")["vmIds"], json!(["a"]));
    // Narrowing needs no code, so it still applies.
    let out = empty
        .handle("propose", as_map(json!({"action": "update", "id": id, "name": "G2", "sites": ["github.com"], "vmIds": ["a"], "changeId": "c2"})))
        .await;
    assert_eq!(out.status, "applied");
}

/// The same box and store, with no consent codes and no code routes.
fn strip(r: &Rig) -> Arc<App> {
    let app = App {
        config: r.app.config.clone(),
        keys: r.app.keys.clone(),
        box_key: r.app.box_key.clone(),
        runner: r.app.runner.clone(),
        http: r.app.http.clone(),
        console: r.app.console.clone(),
        contracts: crate::contracts::Contracts::default(),
        cp_inspect: r.app.cp_inspect.clone(),
    };
    app.contracts
        .identities
        .set(Identities::of(&[("a", "10.0.0.9", "Ada"), ("b", "10.0.0.9", "Bo")]));
    Arc::new(app)
}

#[tokio::test]
async fn requests_link_one_agents_own_answered_by_a_save_or_a_session_expiry() {
    let r = rig(
        &[("a", "Ada"), ("b", "Bo")],
        "https://console.example/api/vm-agent/firewall",
    );
    let asked = r
        .tool("a", "login_request", json!({"site": "https://acme.example/login", "reason": "To file the report", "url": "https://acme.example/login", "task": "File the report"}))
        .await;
    let req = parsed(&asked);
    let rid = req["request"].as_str().expect("id").to_string();
    assert!(
        regex::Regex::new(r"^https://console\.example/logins/r/fw1/lr_[A-Za-z0-9_-]+$")
            .expect("re")
            .is_match(req["link"].as_str().expect("link"))
    );
    assert_eq!(r.fw.get_request(&rid).expect("request").site, "acme.example");
    assert_eq!(
        r.fw.request_status("b", &rid),
        json!({"status": "expired"}),
        "another agent cannot read it"
    );
    assert_eq!(r.fw.request_status("a", &rid)["status"], "waiting");
    let acme = json!({"name": "Acme", "sites": ["acme.example"], "loginUrl": "https://acme.example/login", "username": "ops", "password": "Pw-12345678", "requestId": rid});
    assert!(
        msg(r.fw.put("owner@x", &with(&acme, json!({"vmIds": ["b"]})), None).await)
            .contains("Tick the agent that asked")
    );
    let mut no_url = with(&acme, json!({"vmIds": ["a"]}));
    no_url.as_object_mut().expect("object").remove("loginUrl");
    assert!(msg(r.fw.put("owner@x", &no_url, None).await).contains("Fill in the sign-in page"));
    r.fw.put(
        "owner@x",
        &with(
            &acme,
            json!({"vmIds": ["a"], "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}),
        ),
        None,
    )
    .await
    .expect("saved");
    assert_eq!(
        r.fw.request_status("a", &rid),
        json!({"status": "ready", "login": "Acme", "kind": "password"})
    );
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let calls = r.agents.calls.lock().expect("lock").clone();
    let woken = calls.iter().find(|(_, p, _)| p == "/logins/answered").expect("woken");
    assert_eq!(
        woken,
        &(
            "a".to_string(),
            "/logins/answered".to_string(),
            json!({"requestId": rid, "site": "acme.example", "login": "Acme", "kind": "password", "url": "https://acme.example/login", "task": "File the report"})
        ),
        "the agent is woken, with where and what"
    );
    assert_eq!(r.fw.summary()["logins"][0]["totp"], true);
    let code = parsed(&r.tool("a", "login_code", json!({"login": "Acme"})).await);
    assert!(
        regex::Regex::new(r"^\d{6}$")
            .expect("re")
            .is_match(code["code"].as_str().expect("code"))
    );
    // A session request: the person signs the agent in, the firewall opens the tab and keeps a record.
    let s = parsed(
        &r.tool("a", "login_request", json!({"site": "app.example", "kind": "session"}))
            .await,
    );
    let sid = s["request"].as_str().expect("id").to_string();
    assert!(r.fw.open_tab(&sid).await);
    assert_eq!(
        r.agents.calls.lock().expect("lock").last().cloned(),
        Some((
            "a".into(),
            "/logins/open-tab".into(),
            json!({"url": "https://app.example/"})
        ))
    );
    assert!(msg(r.fw.record_session("owner@x", &rid).await).contains("not for signing the agent in"));
    let session = r.fw.record_session("owner@x", &sid).await.expect("session");
    assert_eq!(session["kind"], "session");
    assert!(
        msg(r.fw.record_session("owner@x", &sid).await).contains("already answered"),
        "a double click records one session"
    );
    let session_id = session["id"].as_str().expect("id").to_string();
    let change = r.command("propose", json!({"action": "update", "id": session_id, "name": "x", "sites": ["app.example"], "vmIds": ["a"], "changeId": "z"})).await;
    assert!(!change.ok);
    assert_eq!(r.fw.credentials().len(), 1, "a session holds nothing for the proxy");
    assert_eq!(
        r.tool("a", "login_use", json!({"login": session_id})).await["isError"],
        true
    );
    let replace = json!({"name": "x", "sites": ["app.example"], "loginUrl": "https://app.example/login", "username": "", "password": "p", "vmIds": ["a"]});
    assert!(msg(r.fw.put("owner@x", &replace, Some(&session_id)).await).contains("no password to replace"));
    // Deleting it signs the agent out of the site; if the agent cannot be reached, the record stays.
    *r.agents.fail.lock().expect("lock") = Some("unreachable".into());
    let refused = r
        .command(
            "propose",
            json!({"action": "delete", "id": session_id, "changeId": "d1"}),
        )
        .await;
    assert!(!refused.ok);
    assert!(refused.message.as_deref().unwrap_or("").contains("still signed in"));
    assert!(r.fw.get(&session_id).is_some());
    *r.agents.fail.lock().expect("lock") = None;
    r.fw.remove(&session_id, "from the console").await.expect("removed");
    assert_eq!(
        r.agents.calls.lock().expect("lock").last().cloned(),
        Some((
            "a".into(),
            "/logins/clear-cookies".into(),
            json!({"sites": ["app.example"]})
        ))
    );
    // At most five open at once, and a request lives 30 minutes.
    for i in 0..5 {
        r.tool("a", "login_request", json!({"site": format!("s{i}.example")}))
            .await;
    }
    assert_eq!(
        r.tool("a", "login_request", json!({"site": "s6.example"})).await["isError"],
        true
    );
    r.advance(31 * 60_000);
    assert_eq!(r.fw.request_status("a", &rid)["status"], "expired");
    assert!(msg(r.fw.record_session("owner@x", &sid).await).contains("expired"));
}

#[tokio::test]
async fn type_mode_no_placeholder_the_box_types_it_switching_needs_a_code_csv_import() {
    let r = rig(&[("a", "Ada")], "");
    *r.agents.reply.lock().expect("lock") = as_map(json!({"ok": true}));
    let typed = r
        .fw
        .put("o", &json!({"name": "Steam", "sites": ["store.example"], "username": "me", "password": "Pw-9999", "vmIds": ["a"], "mode": "type"}), None)
        .await
        .expect("typed");
    assert_eq!(typed["mode"], "type");
    assert!(r.fw.credentials().is_empty(), "nothing for the proxy to swap");
    let used = parsed(&r.tool("a", "login_use", json!({"login": "Steam"})).await);
    assert!(used.get("password_placeholder").is_none());
    assert!(used["how"].as_str().expect("how").contains("login_type"));
    let out = r.tool("a", "login_type", json!({"login": "Steam"})).await;
    assert!(out.get("isError").is_none());
    assert!(
        !text(&out).contains("Pw-9999"),
        "the agent never gets the password back"
    );
    assert_eq!(
        r.agents.calls.lock().expect("lock").last().cloned(),
        Some((
            "a".into(),
            "/logins/type".into(),
            json!({"password": "Pw-9999", "sites": ["store.example"]})
        ))
    );
    *r.agents.reply.lock().expect("lock") = as_map(json!({"ok": false, "reason": "site"}));
    assert!(
        text(&r.tool("a", "login_type", json!({"login": "Steam"})).await).contains("not one of this login's sites")
    );
    *r.agents.reply.lock().expect("lock") = as_map(json!({"ok": false, "reason": "changed"}));
    let t = text(&r.tool("a", "login_type", json!({"login": "Steam"})).await);
    assert!(t.contains("page changed") && t.contains("nothing was typed"));
    // An agent box from before type mode.
    *r.agents.fail.lock().expect("lock") = Some("agent 404: not found".into());
    assert!(text(&r.tool("a", "login_type", json!({"login": "Steam"})).await).contains("too old to type passwords"));
    *r.agents.fail.lock().expect("lock") = Some("agent 4040".into());
    assert!(text(&r.tool("a", "login_type", json!({"login": "Steam"})).await).contains("did not answer"));
    *r.agents.fail.lock().expect("lock") = None;

    // From the console, swap → type needs a code; type → swap does not.
    let swap = r
        .fw
        .put("o", &json!({"name": "Bank", "sites": ["bank.example"], "loginUrl": "https://bank.example/login", "username": "me", "password": "Pw-1234", "vmIds": ["a"]}), None)
        .await
        .expect("swap");
    let sid = swap["id"].as_str().expect("id").to_string();
    let p = r.command("propose", json!({"action": "update", "id": sid, "name": "Bank", "sites": ["bank.example"], "vmIds": ["a"], "mode": "type", "changeId": "c1"})).await;
    assert_eq!(p.status, "awaiting_code");
    assert!(
        r.codes
            .sent
            .lock()
            .expect("lock")
            .last()
            .is_some_and(|m| m.contains("type the password into the page itself"))
    );
    assert_eq!(
        r.command("confirm", json!({"id": sid, "changeId": "c1", "code": "123456"}))
            .await
            .status,
        "applied"
    );
    assert_eq!(r.fw.get(&sid).expect("login")["mode"], "type");
    let back = r.command("propose", json!({"action": "update", "id": sid, "name": "Bank", "sites": ["bank.example"], "vmIds": ["a"], "mode": "swap", "changeId": "c2"})).await;
    assert_eq!(back.status, "applied");

    // Import.
    let before = r.fw.summary()["logins"].as_array().expect("list").len();
    let got = r
        .fw
        .import_rows(
            "o",
            &json!({"rows": [
                {"name": "A", "sites": ["a.example"], "username": "u", "password": "p1"},
                {"name": "B", "sites": ["b.example"], "username": "", "password": "p2", "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
                {"name": "Bad key", "sites": ["c.example"], "username": "", "password": "p3", "totp": "steam://abc"},
                {"name": "No password", "sites": ["d.example"], "username": "", "password": ""},
                {"name": "Bad\nname", "sites": ["e.example"], "username": "", "password": "p"},
            ], "vmIds": ["a"]}),
        )
        .await
        .expect("import");
    assert_eq!(got, (3, 2, false));
    assert_eq!(
        r.by_name("Bad key")["totp"],
        false,
        "a key that cannot be read is dropped, the login kept"
    );
    assert_eq!(r.fw.summary()["logins"].as_array().expect("list").len(), before + 3);
    assert_eq!(r.by_name("B")["totp"], true);
    assert!(
        cc_crypto::enc_file::encrypted_secret_values()
            .iter()
            .any(|v| v.contains("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
        "an imported seed is masked out of the logs, as the password is"
    );
    let bad =
        json!({"rows": [{"name": "C", "sites": ["c.example"], "username": "", "password": "x"}], "vmIds": ["nope"]});
    assert!(msg_import(r.fw.import_rows("o", &bad).await).contains("not part of this organization"));
}

fn msg_import(r: Result<(usize, usize, bool), Refused>) -> String {
    match r {
        Ok(v) => panic!("accepted: {v:?}"),
        Err(Refused::Message(m)) => m,
        Err(Refused::Invalid(i)) => i.message,
    }
}

#[tokio::test]
async fn names_sort_as_locale_compare_and_metadata_keeps_unknown_fields() {
    let r = rig(&[("a", "Ada")], "");
    for name in ["beta", "Alpha", "alpha"] {
        r.fw.put("o", &json!({"name": name, "sites": ["x.example"], "loginUrl": "https://x.example/login", "username": "u", "password": "Pw-1", "vmIds": ["a"]}), None)
            .await
            .expect("made");
    }
    let names: Vec<Value> = r.fw.list_for("a").iter().map(|l| l["name"].clone()).collect();
    assert_eq!(names, vec![json!("alpha"), json!("Alpha"), json!("beta")]);
    // A field a newer build wrote stays in the store and shows in the metadata, as `...rest` does.
    let id = r.by_name("beta")["id"].as_str().expect("id").to_string();
    r.fw.write()
        .logins
        .get_mut(&id)
        .expect("login")
        .extra
        .insert("note".into(), json!("kept"));
    r.fw.save().expect("saved");
    assert_eq!(r.again().get(&id).expect("login")["note"], "kept");
    assert!(r.again().get(&id).expect("login").get("password").is_none());
}

const TOKEN: &str = "ops_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

type Items = Arc<std::sync::Mutex<Map<String, Value>>>;

/// `op` as the TS test fakes it: two vaults, and the items in `items` (`v` is when one changed).
fn fake_op(items: Items, failing: Arc<std::sync::atomic::AtomicBool>) -> cc_proc::RecordingRunner {
    let r = cc_proc::RecordingRunner::new();
    r.answer_with(move |c| {
        if failing.load(Ordering::SeqCst) {
            return Some(cc_proc::exit(1, ""));
        }
        assert_eq!(c.env.get("OP_SERVICE_ACCOUNT_TOKEN").map(String::as_str), Some(TOKEN));
        let a: Vec<&str> = c.args.iter().map(String::as_str).collect();
        let items = items.lock().expect("lock");
        let out = match a.as_slice() {
            ["vault", ..] => json!([{"id": "v1aaaaaaaaaaaa", "name": "Agents"}, {"id": "v2bbbbbbbbbbbb", "name": "Finance"}]),
            ["item", "list", ..] => Value::Array(
                items
                    .iter()
                    .map(|(id, it)| json!({"id": id, "updated_at": it.get("v").and_then(Value::as_str).unwrap_or("2026-10-01T00:00:00Z")}))
                    .collect(),
            ),
            ["item", "get", id, ..] => items.get(*id).cloned().unwrap_or(Value::Null),
            _ => return None,
        };
        Some(cc_proc::ok(&js::stringify(&out)))
    });
    r
}

fn gets(r: &cc_proc::RecordingRunner, what: &str) -> usize {
    r.calls()
        .iter()
        .filter(|c| c.args.get(1).map(String::as_str) == Some(what))
        .count()
}

#[tokio::test]
async fn one_password_connect_mirror_keep_placeholders_drop_what_is_gone_disconnect() {
    let items: Items = Arc::new(std::sync::Mutex::new(as_map(json!({
        "i1": {"id": "i1", "title": "GitHub", "urls": [{"href": "https://github.com/login", "primary": true}, {"href": "api.github.com"}],
            "fields": [{"purpose": "USERNAME", "value": "ops"}, {"purpose": "PASSWORD", "value": "Gh-pass-123"}, {"type": "OTP", "value": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}]},
        "i2": {"id": "i2", "title": "No site", "urls": [], "fields": [{"purpose": "PASSWORD", "value": "x"}]},
        "i3": {"id": "i3", "title": "No password", "urls": [{"href": "https://a.example"}], "fields": []},
    }))));
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let op = fake_op(items.clone(), failing.clone());
    let r = rig_with(&[("a", "Ada")], "", Some(op.clone()));
    let fw = &r.fw;
    let names: Vec<String> = fw
        .one_password_vaults(TOKEN)
        .await
        .expect("vaults")
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Agents", "Finance"]);
    assert!(msg_vaults(fw.one_password_vaults("not-a-token").await).contains("starts with ops_"));
    let wrong = fw
        .one_password_connect(
            "o",
            &json!({"token": TOKEN, "vaultIds": ["v9zzzzzzzzzzzz"], "vmIds": ["a"]}),
        )
        .await;
    assert!(msg(wrong).contains("cannot open one of those vaults"));
    let status = fw
        .one_password_connect(
            "owner@x",
            &json!({"token": TOKEN, "vaultIds": ["v1aaaaaaaaaaaa"], "vmIds": ["a"]}),
        )
        .await
        .expect("connected");
    assert_eq!(
        (&status["vaults"][0]["name"], &status["items"], &status["lastError"]),
        (&json!("Agents"), &json!(1), &Value::Null)
    );
    assert_eq!(status["vaults"].as_array().map(Vec::len), Some(1));
    assert!(op.calls().iter().any(|c| c.args.iter().any(|a| a == "--reveal")));
    let gh = fw.summary()["logins"][0].clone();
    assert_eq!(
        json!({"name": gh["name"], "sites": gh["sites"], "username": gh["username"], "totp": gh["totp"], "source": gh["source"], "url": gh["loginUrl"]}),
        json!({"name": "GitHub", "sites": ["github.com", "api.github.com"], "username": "ops", "totp": true, "source": "1password", "url": "https://github.com/login"})
    );
    assert!(
        !js::stringify(&Value::Object(fw.summary())).contains(TOKEN),
        "the token never leaves"
    );
    assert!(!std::fs::read_to_string(&r.store).expect("store").contains("ops_"));
    let id = gh["id"].as_str().expect("id").to_string();
    let ph = fw.credentials()[0]["placeholder"].clone();
    // Managed in 1Password: the console cannot change or delete it.
    assert!(
        !r.command("propose", json!({"action": "delete", "id": id, "changeId": "c"}))
            .await
            .ok
    );
    // A failed read changes nothing.
    failing.store(true, Ordering::SeqCst);
    fw.one_password_sync().await;
    assert_eq!(fw.summary()["logins"].as_array().map(Vec::len), Some(1));
    assert!(
        fw.one_password_status()["lastError"]
            .as_str()
            .unwrap_or("")
            .contains("did not answer")
    );
    failing.store(false, Ordering::SeqCst);
    // An unchanged item is not read again; a changed one is.
    let before = gets(&op, "get");
    fw.one_password_sync().await;
    assert_eq!(gets(&op, "get"), before, "nothing changed: only item list was spent");
    items.lock().expect("lock")["i1"]["v"] = json!("2026-10-02T00:00:00Z");
    fw.one_password_sync().await;
    assert_eq!(gets(&op, "get"), before + 1);
    // Same password shape: same placeholder.
    assert_eq!(fw.credentials()[0]["placeholder"], ph);
    // The owner's own sign-in page, set on the firewall page, is kept over what 1Password says,
    // and so are the kind and the extra addresses.
    fw.set_scope(
        &json!({"id": id, "loginUrl": "https://github.com/session/new", "auth": "form", "signInPaths": ["/session"]}),
    )
    .await
    .expect("scope");
    items.lock().expect("lock")["i1"]["v"] = json!("2026-10-03T00:00:00Z");
    fw.one_password_sync().await;
    let c = fw.credentials()[0].clone();
    assert_eq!(
        (
            &c["login_url"],
            &c["sign_in_paths"],
            &fw.summary()["logins"][0]["needsSignInPage"]
        ),
        (
            &json!("https://github.com/session/new"),
            &json!(["/session"]),
            &json!(false)
        )
    );
    assert!(msg_bool(fw.remove(&id, "on the firewall page").await).contains("comes from 1Password"));
    // A read asked for while one runs waits for it and does not read again.
    let lists = gets(&op, "list");
    let running = fw.op_syncing.lock().await;
    assert!(fw.one_password_busy());
    let second = tokio::spawn({
        let fw = fw.clone();
        async move { fw.one_password_sync().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    drop(running);
    second.await.expect("joined");
    assert_eq!(gets(&op, "list"), lists);
    assert!(!fw.one_password_busy());
    // Item gone: login gone.
    items.lock().expect("lock").remove("i1");
    fw.one_password_sync().await;
    assert_eq!(fw.summary()["logins"], json!([]));
    items.lock().expect("lock").insert(
        "i1".into(),
        json!({"id": "i1", "title": "GitHub", "urls": [{"href": "https://github.com"}], "fields": [{"purpose": "PASSWORD", "value": "p"}]}),
    );
    fw.one_password_sync().await;
    assert_eq!(fw.summary()["logins"].as_array().map(Vec::len), Some(1));
    r.command("1password_disconnect", json!({})).await;
    assert_eq!(fw.summary()["logins"], json!([]));
    assert_eq!(fw.one_password_status(), Value::Null);
}

fn msg_vaults(r: Result<Vec<super::super::onepassword::OpVault>, Refused>) -> String {
    match r {
        Ok(v) => panic!("accepted: {v:?}"),
        Err(Refused::Message(m)) => m,
        Err(Refused::Invalid(i)) => i.message,
    }
}

fn msg_bool(r: Result<bool, Refused>) -> String {
    match r {
        Ok(v) => panic!("accepted: {v}"),
        Err(Refused::Message(m)) => m,
        Err(Refused::Invalid(i)) => i.message,
    }
}

#[tokio::test]
async fn a_store_the_disk_does_not_take_fails_the_change_and_a_removal_still_leaves_the_proxy() {
    let r = rig(&[("a", "Ada")], "");
    let entry = json!({"name": "G", "sites": ["github.com"], "loginUrl": "https://github.com/login", "username": "u", "password": "Pw-1", "vmIds": ["a"]});
    let made = r.fw.put("o", &entry, None).await.expect("made");
    let id = made["id"].as_str().expect("id").to_string();
    // The store's folder is now a file: nothing can be written there.
    let blocked = r._dir.path().join("blocked");
    std::fs::write(&blocked, "").expect("file");
    let c = r.clock.clone();
    let fw = LoginsFirewall::with_clock(
        &r.app,
        blocked.join("logins.enc"),
        None,
        None,
        Arc::new(move || c.load(Ordering::SeqCst)),
    )
    .expect("open");
    let before = r.syncs.count();
    assert_eq!(msg(fw.put("o", &entry, None).await), SAVE_FAILED);
    assert_eq!(
        r.syncs.count(),
        before,
        "the proxy is not told about a login that was not kept"
    );
    // A removal takes access away whatever the disk says, and says it was not kept.
    fw.write()
        .logins
        .insert(id.clone(), r.fw.read().logins.get(&id).cloned().expect("login"));
    assert_eq!(msg_bool(fw.remove(&id, "on the firewall page").await), SAVE_FAILED);
    assert_eq!(r.syncs.count(), before + 1);
    assert!(fw.get(&id).is_none());
}

#[tokio::test]
async fn an_agent_with_no_name_and_an_empty_hostname_is_named_by_its_id() {
    let r = rig(&[("a", "Ada")], "");
    *r.ids.0.lock().expect("lock") = vec![
        crate::contracts::AgentIdentity {
            vm_id: "a".into(),
            private_ip: "10.0.0.9".into(),
            hostname: Some("a.vm.example".into()),
            name: Some("Ada".into()),
        },
        crate::contracts::AgentIdentity {
            vm_id: "vm-x".into(),
            private_ip: "10.0.0.8".into(),
            hostname: Some(String::new()),
            name: None,
        },
    ];
    let made = r
        .fw
        .put("o", &json!({"name": "G", "sites": ["github.com"], "loginUrl": "https://github.com/login", "username": "u", "password": "Pw-1", "vmIds": ["a"]}), None)
        .await
        .expect("made");
    let p = r
        .command("propose", json!({"action": "update", "id": made["id"], "name": "G", "sites": ["github.com"], "vmIds": ["a", "vm-x"], "changeId": "c1"}))
        .await;
    assert_eq!(p.status, "awaiting_code");
    let m = r.codes.sent.lock().expect("lock").last().cloned().unwrap_or_default();
    assert!(m.contains("by vm-x as well"), "{m}");
}

#[test]
fn a_sync_merges_only_into_the_connection_it_read_with() {
    let src = |token: &str, vaults: Value, at: &str| -> OnePasswordSource {
        serde_json::from_value(json!({"vaults": vaults, "vmIds": [], "addedBy": null, "addedAt": at, "lastSyncAt": null, "lastError": null, "items": 0, "token": token}))
            .expect("source")
    };
    let read = src("ops_a", json!([{"id": "v1"}, {"id": "v2"}]), "2026-10-28T10:00:00.000Z");
    let mut later = read.clone();
    later.last_sync_at = Some("2026-10-28T10:05:00.000Z".into());
    later.items = 3;
    assert!(
        same_connection(&later, &read),
        "the same connection after a sync of its own"
    );
    for (what, other) in [
        (
            "fewer vaults",
            src("ops_a", json!([{"id": "v1"}]), "2026-10-28T10:00:00.000Z"),
        ),
        (
            "another token",
            src("ops_b", json!([{"id": "v1"}, {"id": "v2"}]), "2026-10-28T10:00:00.000Z"),
        ),
        (
            "connected again",
            src("ops_a", json!([{"id": "v1"}, {"id": "v2"}]), "2026-10-28T10:04:00.000Z"),
        ),
    ] {
        assert!(!same_connection(&other, &read), "{what}");
    }
}
