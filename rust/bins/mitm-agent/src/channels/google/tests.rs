//! `google.test.ts`: the org Google account against a fake agent box, a fake Google OAuth endpoint
//! and fake API probes.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::http::{GoogleHttp, HttpErr, Req, Resp};
use super::*;
use crate::channels::agent::{AgentCalls, AgentError, Target};
use crate::contracts::SendResult;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const CLIENT_ID: &str = "1234567890-abcdefghijklmnop.apps.googleusercontent.com";

fn id_token(email: &str) -> String {
    let part = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
    format!("{}.{}.", part(json!({"alg": "none"})), part(json!({"email": email})))
}

fn all_scopes() -> String {
    let mut v: Vec<String> = vec!["openid".into(), "email".into()];
    let sv = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    for s in tokens::scopes_for(
        &sv(&["gmail", "calendar", "contacts", "sheets", "docs"]),
        "full",
        "full",
    )
    .into_iter()
    .chain(tokens::scopes_for(
        &sv(&["gmail", "drive", "sheets", "docs"]),
        "read-send",
        "readonly",
    ))
    .chain(tokens::scopes_for(&sv(&["drive"]), "read-send", "file"))
    {
        if s.starts_with("https://") && !v.contains(&s) {
            v.push(s);
        }
    }
    v.join(" ")
}

#[derive(Default)]
struct Google {
    exchange: Mutex<(u16, Value)>,
    refresh: Mutex<(u16, Value)>,
    probe_errors: Mutex<HashMap<String, (u16, Value)>>,
    forms: Mutex<Vec<HashMap<String, String>>>,
    urls: Mutex<Vec<String>>,
}

impl GoogleHttp for Arc<Google> {
    fn send(&self, req: Req) -> BoxFuture<Result<Resp, HttpErr>> {
        let me = self.clone();
        Box::pin(async move {
            let reply = |status: u16, body: Value| {
                Ok(Resp {
                    status,
                    headers: vec![],
                    body: body.to_string().into_bytes(),
                })
            };
            if req.url.starts_with("https://oauth2.googleapis.com/token")
                || req.url.starts_with("https://stub.example/token")
            {
                let form: HashMap<String, String> = url::form_urlencoded::parse(req.body.as_deref().unwrap_or(&[]))
                    .into_owned()
                    .collect();
                let exchange = form.get("grant_type").map(String::as_str) == Some("authorization_code");
                me.forms.lock().unwrap().push(form);
                me.urls.lock().unwrap().push(req.url.clone());
                let (st, body) = if exchange {
                    me.exchange.lock().unwrap().clone()
                } else {
                    me.refresh.lock().unwrap().clone()
                };
                return reply(st, body);
            }
            me.urls.lock().unwrap().push(req.url.clone());
            for (needle, (st, body)) in me.probe_errors.lock().unwrap().iter() {
                if req.url.contains(needle.as_str()) {
                    return reply(*st, body.clone());
                }
            }
            reply(200, json!({"ok": true, "files": []}))
        })
    }
}

#[derive(Default)]
struct Box_ {
    calls: Mutex<Vec<(String, String, Value)>>,
    fails: Mutex<Option<String>>,
}

impl AgentCalls for Arc<Box_> {
    fn post(
        &self,
        t: &Target,
        path: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.calls.lock().unwrap().push((t.vm_id.clone(), path.into(), body));
        let r = match self.fails.lock().unwrap().clone() {
            Some(m) if path == "/google/apply" => Err(AgentError::new(m)),
            _ => Ok(Map::new()),
        };
        Box::pin(async move { r })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

#[derive(Default)]
struct Codes {
    pending: Mutex<HashMap<String, (String, Value)>>,
    sent: Mutex<Vec<String>>,
}

impl ConsentCodes for Codes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        self.sent.lock().unwrap().push(req.summary.clone());
        self.pending
            .lock()
            .unwrap()
            .insert(req.scope, (req.change_id, req.proposal));
        Box::pin(async {
            SendResult {
                sent_via: Some("telegram:Owner".into()),
                error: None,
                delivery_failed: false,
                expires_at_ms: 0,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut p = self.pending.lock().unwrap();
        match p.get(scope) {
            Some((c, _)) if c == change_id && code == "123456" => Verify::Ok(p.remove(scope).unwrap().1),
            Some((c, _)) if c == change_id => Verify::Wrong { tries_left: 4 },
            _ => Verify::Expired,
        }
    }
    fn cancel(&self, scope: &str, _: Option<&str>) -> bool {
        self.pending.lock().unwrap().remove(scope).is_some()
    }
    fn forget(&self, scope: &str) {
        self.pending.lock().unwrap().remove(scope);
    }
}

struct T {
    dir: tempfile::TempDir,
    google: Arc<Google>,
    agent: Arc<Box_>,
    codes: Arc<Codes>,
    routes: Arc<Mutex<Option<Vec<Value>>>>,
    now: Arc<AtomicI64>,
    synced: Arc<AtomicUsize>,
    codes_on: Arc<AtomicBool>,
}

const NOW: i64 = 1_790_330_400_000; // 2026-09-25T10:00:00Z

fn t() -> T {
    let google = Arc::new(Google::default());
    *google.exchange.lock().unwrap() = (
        200,
        json!({"access_token": "ya29.first", "refresh_token": "1//refresh-a", "expires_in": 3600, "id_token": id_token("agents@acme.com"), "scope": all_scopes()}),
    );
    *google.refresh.lock().unwrap() = (200, json!({"access_token": "ya29.second", "expires_in": 3600}));
    T {
        dir: tempfile::tempdir().unwrap(),
        google,
        agent: Arc::default(),
        codes: Arc::default(),
        routes: Arc::new(Mutex::new(Some(vec![]))),
        now: Arc::new(AtomicI64::new(NOW)),
        synced: Arc::default(),
        codes_on: Arc::new(AtomicBool::new(true)),
    }
}

impl T {
    fn make(&self) -> Arc<GoogleFirewall> {
        let (codes, on, routes, now, synced) = (
            self.codes.clone(),
            self.codes_on.clone(),
            self.routes.clone(),
            self.now.clone(),
            self.synced.clone(),
        );
        GoogleFirewall::new(GoogleOptions {
            store_path: self.dir.path().join("google.enc"),
            box_key: KEY.into(),
            org_id: "org1".into(),
            box_id: "fw1".into(),
            agent: Arc::new(self.agent.clone()),
            codes: Arc::new(move || {
                on.load(Ordering::SeqCst)
                    .then(|| codes.clone() as Arc<dyn ConsentCodes>)
            }),
            code_routes: Arc::new(move || routes.lock().unwrap().clone()),
            on_credentials_changed: Some(Arc::new(move || {
                synced.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {})
            })),
            http: Arc::new(self.google.clone()),
            now: Arc::new(move || now.load(Ordering::SeqCst)),
        })
        .unwrap()
    }
    fn with_routes(&self) {
        *self.routes.lock().unwrap() = Some(vec![
            json!({"target": {"vmId": "vm9", "hostname": "x.example"}, "senders": [{"type": "telegram", "id": "1"}], "agentName": "ops"}),
        ]);
    }
    fn applies_to(&self, vm: &str) -> Option<Value> {
        self.agent
            .calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|c| c.0 == vm && c.1 == "/google/apply")
            .map(|c| c.2.clone())
    }
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn support() -> Value {
    json!({"vmId": "vm1", "name": "support", "hostname": "support.vm.controlclaw.com"})
}
fn research() -> Value {
    json!({"vmId": "vm2", "name": "research", "hostname": "research.vm.controlclaw.com"})
}

/// A connect exactly as the control plane sends it: the secret at the top level.
fn connect(over: Value) -> Map<String, Value> {
    let mut p = m(json!({
        "changeId": "chg-connect",
        "kind": "connect_account",
        "client": {"clientId": CLIENT_ID, "redirectUri": "https://controlclaw.com/oauth/callback"},
        "clientSecret": "GOCSPX-secret",
        "services": ["gmail", "calendar"],
        "gmailScope": "read-send",
        "driveScope": "readonly",
        "audience": "external_production",
        "projectId": "acme-agents",
        "agents": [support()],
    }));
    p.extend(m(over));
    p
}

fn state_of(o: &CommandOutcome) -> String {
    let url = url::Url::parse(o.data.as_ref().unwrap()["authorizeUrl"].as_str().unwrap()).unwrap();
    url.query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned()
}

/// propose → consent → callback → confirm.
async fn connected(fw: &GoogleFirewall, over: Value) -> (CommandOutcome, CommandOutcome, CommandOutcome) {
    let started = fw.command("propose", connect(over)).await;
    let back = fw
        .command(
            "callback",
            m(json!({"state": state_of(&started), "code": "4/code-one"})),
        )
        .await;
    if back.status == "applied" {
        let b = back.clone();
        return (started, back, b);
    }
    let confirmed = fw
        .command("confirm", m(json!({"changeId": "chg-connect", "code": "123456"})))
        .await;
    (started, back, confirmed)
}

fn sv(x: &[&str]) -> Vec<String> {
    x.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_scopes_follow_the_choices() {
    let auth = "https://www.googleapis.com/auth/";
    let s = tokens::scopes_for(&sv(&["gmail", "calendar"]), "read-send", "readonly");
    assert_eq!(
        s,
        [
            "openid".to_string(),
            "email".into(),
            format!("{auth}gmail.readonly"),
            format!("{auth}gmail.send"),
            format!("{auth}calendar")
        ]
    );
    // Sheets and Docs follow Drive and are not asked twice.
    let s = tokens::scopes_for(&sv(&["drive", "sheets", "docs"]), "read-send", "readonly");
    assert_eq!(s.iter().filter(|x| x.ends_with("drive.readonly")).count(), 1);
    assert!(s.contains(&format!("{auth}spreadsheets.readonly")) && s.contains(&format!("{auth}documents.readonly")));
    // Calendar and Contacts do not follow the Drive choice.
    let s = tokens::scopes_for(&sv(&["calendar", "contacts"]), "read-send", "readonly");
    assert!(s.contains(&format!("{auth}calendar")) && s.contains(&format!("{auth}contacts")));
    let url = tokens::authorize_url(CLIENT_ID, "https://x/cb", &s, "st", "ch", Some("a@b.com"));
    let q: HashMap<String, String> = url::Url::parse(&url).unwrap().query_pairs().into_owned().collect();
    assert_eq!(q["access_type"], "offline");
    assert_eq!(q["prompt"], "consent");
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(!q.contains_key("include_granted_scopes"));
    assert_eq!(q["login_hint"], "a@b.com");
    assert_eq!(
        tokens::email_from_id_token(Some(&id_token("a@b.com"))).as_deref(),
        Some("a@b.com")
    );
    assert_eq!(tokens::email_from_id_token(Some("nope")), None);
    let (v, c) = tokens::make_pkce();
    assert_eq!(
        c,
        URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(v.as_bytes()))
    );
    assert!(store::is_valid_client_id(CLIENT_ID) && !store::is_valid_client_id("nope"));
    assert!(store::is_valid_project_id("acme-agents") && !store::is_valid_project_id("Acme"));
}

#[tokio::test]
async fn propose_callback_confirm_stores_grants_and_pushes() {
    let t = t();
    t.with_routes();
    let fw = t.make();
    let started = fw.command("propose", connect(json!({}))).await;
    assert_eq!(started.status, "awaiting_authorization");
    assert!(fw.summary()["account"].is_null(), "no account yet");
    // The verifier stays on the box: the URL has only the challenge.
    let url = started.data.as_ref().unwrap()["authorizeUrl"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!url.contains("GOCSPX"));
    let back = fw
        .command(
            "callback",
            m(json!({"state": state_of(&started), "code": "4/code-one"})),
        )
        .await;
    assert_eq!(back.status, "awaiting_code");
    let form = t.google.forms.lock().unwrap()[0].clone();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["client_secret"], "GOCSPX-secret");
    assert!(!form["code_verifier"].is_empty());
    assert!(!url.contains(&form["code_verifier"]));
    // The message names the account Google reported.
    assert!(t.codes.sent.lock().unwrap()[0].contains("agents@acme.com"));
    assert!(fw.credentials().is_empty(), "nothing spendable before the code");
    let confirmed = fw
        .command("confirm", m(json!({"changeId": "chg-connect", "code": "123456"})))
        .await;
    assert_eq!(confirmed.status, "applied");
    let d = confirmed.data.unwrap();
    assert_eq!(d["granted"], json!(["vm1"]));
    assert_eq!(d["accountLabel"], "agents@acme.com");
    let creds = fw.credentials();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["vm_id"], "vm1");
    assert_eq!(creds[0]["match_domain"], "*.googleapis.com");
    assert_eq!(creds[0]["locations"], json!(["header:authorization"]));
    assert_eq!(creds[0]["secret"], "ya29.first");
    let body = t.applies_to("vm1").unwrap();
    assert_eq!(body["connected"], true);
    assert_eq!(body["placeholder"], creds[0]["placeholder"]);
    // No secret of any kind in what leaves.
    let out = format!("{body}{}", fw.summary());
    for secret in ["GOCSPX", "1//refresh", "ya29"] {
        assert!(!out.contains(secret), "{secret}");
    }
    // The store survives a restart.
    let again = t.make();
    assert_eq!(again.credentials().len(), 1);
    assert_eq!(again.summary()["account"]["accountLabel"], "agents@acme.com");
}

#[tokio::test]
async fn the_exchange_and_refresh_use_the_stored_endpoint() {
    let t = t();
    let fw = t.make();
    let mut p = connect(json!({}));
    p["client"]["tokenEndpoint"] = json!("https://stub.example/token");
    let started = fw.command("propose", p).await;
    fw.command("callback", m(json!({"state": state_of(&started), "code": "c"})))
        .await;
    t.now.fetch_add(3_600_000, Ordering::SeqCst);
    fw.refresh_due().await;
    let urls: Vec<String> = t
        .google
        .urls
        .lock()
        .unwrap()
        .iter()
        .filter(|u| u.contains("token"))
        .cloned()
        .collect();
    assert_eq!(urls, ["https://stub.example/token", "https://stub.example/token"]);
}

#[tokio::test]
async fn refusals_at_the_callback() {
    // No refresh token.
    let t1 = t();
    t1.google
        .exchange
        .lock()
        .unwrap()
        .1
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    let (_, back, _) = connected(&t1.make(), json!({})).await;
    assert!(back.message.unwrap().contains("no refresh token"));
    // A disabled API, with Google's own sentence and no advice tail.
    let t2 = t();
    t2.google.probe_errors.lock().unwrap().insert(
        "gmail.googleapis.com".into(),
        (403, json!({"error": {"code": 403, "message": "Gmail API has not been used in project 123 before or it is disabled. If you enabled this API recently, wait.", "errors": [{"reason": "accessNotConfigured"}]}})),
    );
    let fw2 = t2.make();
    let (_, back, _) = connected(&fw2, json!({})).await;
    let msg = back.message.unwrap();
    assert!(
        msg.starts_with("This Google account cannot use everything you asked for. Gmail: Gmail API has not been used")
    );
    assert!(!msg.contains("If you enabled"));
    assert!(fw2.summary()["account"].is_null());
    // A throttled probe still connects.
    let t3 = t();
    t3.google.probe_errors.lock().unwrap().insert(
        "gmail.googleapis.com".into(),
        (
            403,
            json!({"error": {"errors": [{"reason": "rateLimitExceeded"}], "message": "slow"}}),
        ),
    );
    assert_eq!(connected(&t3.make(), json!({})).await.2.status, "applied");
    // Every granted service is probed once; Contacts through connections, never people/me.
    let t4 = t();
    connected(
        &t4.make(),
        json!({"services": ["gmail", "drive", "sheets", "docs", "contacts"]}),
    )
    .await;
    let urls = t4.google.urls.lock().unwrap().clone();
    assert_eq!(urls.iter().filter(|u| u.contains("drive/v3/files")).count(), 1);
    assert!(urls.iter().any(|u| u.contains("people/me/connections")));
    // Send-only Gmail is not probed.
    let t5 = t();
    t5.google.probe_errors.lock().unwrap().insert(
        "gmail.googleapis.com".into(),
        (
            403,
            json!({"error": {"errors": [{"reason": "insufficientPermissions"}]}}),
        ),
    );
    assert_eq!(
        connected(&t5.make(), json!({"services": ["gmail"], "gmailScope": "send"}))
            .await
            .2
            .status,
        "applied"
    );
}

#[tokio::test]
async fn state_expiry_cancel_and_restart() {
    let t = t();
    t.with_routes();
    let fw = t.make();
    let started = fw.command("propose", connect(json!({}))).await;
    let wrong = fw.command("callback", m(json!({"state": "nope", "code": "c"}))).await;
    assert_eq!(wrong.status, "failed");
    assert!(wrong.data.is_none(), "says nothing about why");
    // Overnight in a tab: dead.
    t.now.fetch_add(16 * 60_000, Ordering::SeqCst);
    assert_eq!(
        fw.command("callback", m(json!({"state": state_of(&started), "code": "c"})))
            .await
            .status,
        "expired"
    );
    // Cancelled at Google.
    let s2 = fw.command("propose", connect(json!({}))).await;
    let c = fw
        .command("callback", m(json!({"state": state_of(&s2), "error": "access_denied"})))
        .await;
    assert_eq!(c.message.as_deref(), Some("The Google sign-in was cancelled."));
    // A restart between the callback and the code.
    let s3 = fw.command("propose", connect(json!({}))).await;
    assert_eq!(
        fw.command("callback", m(json!({"state": state_of(&s3), "code": "c"})))
            .await
            .status,
        "awaiting_code"
    );
    let restarted = t.make();
    let r = restarted
        .command("confirm", m(json!({"changeId": "chg-connect", "code": "123456"})))
        .await;
    assert_eq!(r.status, "failed");
    assert!(r.message.unwrap().contains("restarted"));
}

#[tokio::test]
async fn first_use_unreadable_channels_and_no_codes() {
    // Trust on first use: it lands on the callback.
    let t1 = t();
    let fw = t1.make();
    let (_, back, _) = connected(&fw, json!({})).await;
    assert_eq!(back.status, "applied");
    assert_eq!(back.data.unwrap()["tofu"], true);
    // An unreadable channel list fails closed before anything is validated.
    let t2 = t();
    *t2.routes.lock().unwrap() = None;
    let r = t2
        .make()
        .command("propose", connect(json!({"client": {"clientId": "bad"}})))
        .await;
    assert_eq!(r.message.as_deref(), Some(NO_CHANNELS));
    // Somebody to ask, but no codes on this firewall: refused.
    let t3 = t();
    t3.with_routes();
    t3.codes_on.store(false, Ordering::SeqCst);
    let fw3 = t3.make();
    let started = fw3.command("propose", connect(json!({}))).await;
    let back = fw3
        .command("callback", m(json!({"state": state_of(&started), "code": "c"})))
        .await;
    assert_eq!(back.status, "failed");
    assert_eq!(back.message.as_deref(), Some(NO_CODES));
    assert!(fw3.summary()["account"].is_null());
}

#[tokio::test]
async fn grants_placeholders_revoke_disconnect_forget_and_push() {
    let t = t();
    let fw = t.make();
    connected(&fw, json!({"agents": [support(), research()]})).await;
    let creds = fw.credentials();
    assert_eq!(creds.len(), 2);
    assert_ne!(creds[0]["placeholder"], creds[1]["placeholder"]);
    let ph2 = creds[1]["placeholder"].clone();
    // Revoke one, with its box unreachable: the proxy stops at once.
    *t.agent.fails.lock().unwrap() = Some("The agent did not answer in time.".into());
    let r = fw
        .command(
            "propose",
            m(json!({"changeId": "r1", "kind": "revoke_agent", "agents": [support()]})),
        )
        .await;
    assert_eq!(r.status, "applied");
    assert_eq!(fw.credentials().len(), 1);
    assert_eq!(r.data.unwrap()["granted"], json!(["vm2"]));
    *t.agent.fails.lock().unwrap() = None;
    // A push re-applies, with the placeholder cleared for the revoked one.
    fw.command("push", m(json!({"vmId": "vm1"}))).await;
    assert_eq!(t.applies_to("vm1").unwrap()["placeholder"], Value::Null);
    // A re-provisioned box gets its placeholder back unchanged.
    fw.command("push", m(json!({"vmId": "vm2", "hostname": "new.example"})))
        .await;
    assert_eq!(t.applies_to("vm2").unwrap()["placeholder"], ph2);
    // Forget a deleted agent.
    fw.command("forget", m(json!({"vmId": "vm2"}))).await;
    assert!(fw.credentials().is_empty());
    assert!(!fw.summary()["agents"].to_string().contains("vm2"));
    // Disconnect clears every grant and tells every box.
    fw.command(
        "propose",
        m(json!({"changeId": "g", "kind": "grant_agent", "agents": [research()]})),
    )
    .await;
    let before = t.agent.calls.lock().unwrap().len();
    fw.command("propose", m(json!({"changeId": "f", "kind": "forget_account"})))
        .await;
    assert!(fw.credentials().is_empty());
    assert_eq!(t.agent.calls.lock().unwrap().len() - before, 2);
    assert!(fw.summary()["account"].is_null());
}

#[tokio::test]
async fn validation() {
    let t = t();
    let fw = t.make();
    let msg = |o: CommandOutcome| o.message.unwrap_or_default();
    assert!(
        msg(fw
            .command(
                "propose",
                connect(json!({"client": {"clientId": "nope", "redirectUri": "https://x"}}))
            )
            .await)
        .contains("client id")
    );
    assert!(
        msg(fw
            .command(
                "propose",
                connect(json!({"client": {"clientId": CLIENT_ID, "redirectUri": "http://evil.example/cb"}}))
            )
            .await)
        .contains("https")
    );
    assert_eq!(
        fw.command(
            "propose",
            connect(json!({"client": {"clientId": CLIENT_ID, "redirectUri": "http://localhost:3000/cb"}}))
        )
        .await
        .status,
        "awaiting_authorization"
    );
    assert!(
        msg(fw
            .command("propose", connect(json!({"projectId": "Bad_Project"})))
            .await)
        .contains("project id")
    );
    assert!(msg(fw.command("propose", connect(json!({"services": []}))).await).contains("at least one"));
    assert!(
        msg(fw
            .command(
                "propose",
                m(json!({"changeId": "g", "kind": "grant_agent", "agents": [support()]}))
            )
            .await)
        .contains("before giving")
    );
    let mut no_secret = connect(json!({}));
    no_secret.remove("clientSecret");
    assert!(msg(fw.command("propose", no_secret).await).contains("client secret"));
    connected(&fw, json!({})).await;
    assert!(
        msg(fw
            .command(
                "propose",
                m(json!({"changeId": "s", "kind": "set_services", "services": ["gmail", "drive"]}))
            )
            .await)
        .contains("Drive")
    );
    assert_eq!(
        fw.command(
            "propose",
            m(json!({"changeId": "s2", "kind": "set_services", "services": ["gmail"]}))
        )
        .await
        .status,
        "applied"
    );
}

#[tokio::test]
async fn a_reconnect_reports_only_the_granted_agents() {
    let t = t();
    let fw = t.make();
    connected(&fw, json!({"agents": [support(), research()]})).await;
    fw.command(
        "propose",
        m(json!({"changeId": "r", "kind": "revoke_agent", "agents": [research()]})),
    )
    .await;
    let (_, _, again) = connected(&fw, json!({"kind": "replace_account", "agents": []})).await;
    let d = again.data.unwrap();
    assert_eq!(d["granted"], json!(["vm1"]));
    assert_eq!(d["applied"], json!(["vm1", "vm2"]));
}

#[tokio::test]
async fn minting_rotation_failure_and_throttle() {
    let t = t();
    let fw = t.make();
    connected(&fw, json!({"audience": "external_testing"})).await;
    // Not due yet.
    fw.refresh_due().await;
    assert_eq!(fw.credentials()[0]["secret"], "ya29.first");
    t.now
        .fetch_add(3_600_000 - GOOGLE_REFRESH_AHEAD_MS + 1, Ordering::SeqCst);
    *t.google.refresh.lock().unwrap() = (
        200,
        json!({"access_token": "ya29.second", "expires_in": 3600, "refresh_token": "1//refresh-b"}),
    );
    let synced = t.synced.load(Ordering::SeqCst);
    fw.refresh_due().await;
    assert_eq!(fw.credentials()[0]["secret"], "ya29.second");
    assert!(t.synced.load(Ordering::SeqCst) > synced);
    // The rotated refresh token is the one spent next.
    t.now.fetch_add(3_600_000, Ordering::SeqCst);
    *t.google.refresh.lock().unwrap() = (429, json!({"error": "rate_limit_exceeded"}));
    fw.refresh_due().await;
    assert_eq!(
        t.google.forms.lock().unwrap().last().unwrap()["refresh_token"],
        "1//refresh-b"
    );
    assert_eq!(fw.credentials().len(), 1, "a throttle does not disconnect");
    // invalid_grant on a Testing app: dead, explained, reported once, not retried.
    *t.google.refresh.lock().unwrap() = (
        400,
        json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}),
    );
    fw.refresh_due().await;
    assert!(fw.credentials().is_empty());
    let failed = fw.summary()["account"]["failed"].as_str().unwrap().to_string();
    assert!(failed.contains("seven days"));
    assert_eq!(fw.drain_reports().len(), 1);
    let n = t.google.forms.lock().unwrap().len();
    fw.refresh_due().await;
    assert_eq!(t.google.forms.lock().unwrap().len(), n);
    assert!(fw.drive_access().unwrap().token.is_none());
}

#[tokio::test]
async fn a_narrower_grant_is_refused_and_revoked_only_on_a_first_connection() {
    let t = t();
    t.google.exchange.lock().unwrap().1["scope"] = json!("openid email https://www.googleapis.com/auth/gmail.readonly");
    let fw = t.make();
    let (_, back, _) = connected(&fw, json!({})).await;
    let msg = back.message.unwrap();
    assert!(msg.contains("Google granted only read Gmail"));
    assert!(msg.contains("send email from Gmail"));
    assert!(fw.summary()["account"].is_null());
    assert!(t.google.urls.lock().unwrap().iter().any(|u| u.contains("/revoke")));
    // A partial reconnect does not revoke: the live connection keeps working.
    let t2 = self::t();
    let fw2 = t2.make();
    connected(&fw2, json!({})).await;
    t2.google.exchange.lock().unwrap().1["scope"] = json!("openid email");
    connected(&fw2, json!({"kind": "replace_account"})).await;
    assert!(!t2.google.urls.lock().unwrap().iter().any(|u| u.contains("/revoke")));
    assert_eq!(fw2.credentials().len(), 1);
}

#[tokio::test]
async fn drive_access_names_the_scope_in_play() {
    let t = t();
    let fw = t.make();
    assert!(fw.drive_access().is_none());
    t.google.exchange.lock().unwrap().1["scope"] = json!(format!(
        "{} https://www.googleapis.com/auth/drive.readonly",
        all_scopes().replace("https://www.googleapis.com/auth/drive ", "")
    ));
    connected(&fw, json!({})).await;
    let d = fw.drive_access().unwrap();
    assert_eq!(d.token.as_deref(), Some("ya29.first"));
    assert_eq!(d.account_label.as_deref(), Some("agents@acme.com"));
    assert_eq!(fw.gmail_access(), Some(("agents@acme.com".into(), "ya29.first".into())));
}

#[test]
fn summaries() {
    let p = |kind: &str, agents: Vec<AgentRef>| Proposal {
        change_id: "c".into(),
        kind: kind.into(),
        client: None,
        services: sv(&["gmail", "calendar"]),
        gmail_scope: "read-send".into(),
        drive_scope: "readonly".into(),
        audience: "internal".into(),
        project_id: None,
        agents,
    };
    let a = |n: &str| AgentRef {
        vm_id: n.into(),
        name: n.into(),
        hostname: None,
    };
    assert_eq!(
        summarize(&p("connect_account", vec![]), Some("a@b.com")),
        "Connect the Google account a@b.com (Gmail, Calendar)"
    );
    assert_eq!(
        summarize(&p("connect_account", vec![]), None),
        "Connect the Google account (Gmail, Calendar)"
    );
    assert_eq!(
        summarize(&p("grant_agent", vec![a("x"), a("y"), a("z")]), None),
        "Give x, y and z the Google account"
    );
    assert_eq!(
        summarize(&p("revoke_agent", vec![]), None),
        "Take the Google account away from no agent yet"
    );
}

#[tokio::test]
async fn a_code_for_another_change_with_the_same_id_never_installs_a_held_account() {
    let t = t();
    t.with_routes();
    let fw = t.make();
    connected(&fw, json!({"agents": [support(), research()]})).await;
    // A replacement waits for its code, holding the new account...
    let started = fw.command("propose", connect(json!({"kind": "replace_account"}))).await;
    let back = fw
        .command(
            "callback",
            m(json!({"state": state_of(&started), "code": "4/code-two"})),
        )
        .await;
    assert_eq!(back.status, "awaiting_code");
    // ...then a revoke under the same change id: the person confirms the revoke, not the account.
    let revoke = fw
        .command(
            "propose",
            m(json!({"changeId": "chg-connect", "kind": "revoke_agent", "agents": [research()]})),
        )
        .await;
    assert_eq!(revoke.status, "awaiting_code", "{:?}", revoke.message);
    let confirmed = fw
        .command("confirm", m(json!({"changeId": "chg-connect", "code": "123456"})))
        .await;
    assert_eq!(confirmed.status, "applied");
    let d = confirmed.data.unwrap();
    assert_eq!(
        d["summary"], "Take the Google account away from research",
        "the revoke, not the held account"
    );
    assert_eq!(d["applied"], json!(["vm2"]));
}
