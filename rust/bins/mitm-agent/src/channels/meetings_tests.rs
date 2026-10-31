//! `meetings.test.ts`: approval and codes, the scoped apply, the media lease (revocation, renewal,
//! automatic joins, Full agent, presenting), speech credentials, and meeting instructions.

#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::*;
use crate::channels::agent::AgentError;
use crate::contracts::{CodeSender, TelegramRoute};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn base() -> Value {
    cc_meetings::policy::default_meeting_policy()
}

fn with(mut v: Value, over: Value) -> Value {
    for (k, x) in over.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

#[derive(Default)]
struct Agent {
    calls: Mutex<Vec<(String, Value)>>,
    refuse: Mutex<String>,
}

impl AgentCalls for Arc<Agent> {
    fn post(
        &self,
        _: &Target,
        path: &str,
        body: Value,
        _: Option<std::time::Duration>,
    ) -> cc_http::BoxFuture<Result<Map<String, Value>, AgentError>> {
        let refuse = self.refuse.lock().unwrap().clone();
        let r = if path == "/meetings/instructions" && !refuse.is_empty() {
            Err(AgentError::new(refuse))
        } else {
            self.calls.lock().unwrap().push((path.to_string(), body));
            Ok(Map::new())
        };
        Box::pin(async move { r })
    }
    fn get(
        &self,
        _: &Target,
        _: &str,
        _: Option<std::time::Duration>,
    ) -> cc_http::BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

/// The module's codes, as W3's consent codes keep them; the message is built as theirs is.
#[derive(Default)]
struct Codes {
    pending: Mutex<HashMap<String, (String, Value, u32)>>,
    sent: Mutex<Vec<String>>,
}

use std::collections::HashMap;

impl ModuleCodes for Codes {
    fn send(&self, req: CodeAsk) -> cc_http::BoxFuture<CodeSent> {
        let text = build_code_message("123456", req.parts.as_ref(), &req.agent_name, &req.summary, None, None).unwrap();
        self.sent.lock().unwrap().push(text);
        self.pending
            .lock()
            .unwrap()
            .insert(req.scope, (req.change_id, req.proposal, 5));
        Box::pin(async {
            CodeSent::Sent {
                sent_via: "telegram:Owner".into(),
                expires_at: "2026-10-28T10:10:00.000Z".into(),
                attempts_left: 5,
                recovery: None,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> CodeCheck {
        let mut p = self.pending.lock().unwrap();
        match p.get_mut(scope) {
            Some((id, proposal, _)) if id == change_id && code == "123456" => {
                let proposal = proposal.clone();
                p.remove(scope);
                CodeCheck::Ok {
                    proposal,
                    sent_via: "telegram:Owner".into(),
                }
            }
            Some((id, _, tries)) if id == change_id => {
                *tries -= 1;
                CodeCheck::Wrong { tries_left: *tries }
            }
            _ => CodeCheck::Expired,
        }
    }
    fn cancel(&self, scope: &str, change_id: Option<&str>) -> bool {
        let mut p = self.pending.lock().unwrap();
        if p.get(scope).is_some_and(|(id, _, _)| Some(id.as_str()) == change_id) {
            p.remove(scope);
            return true;
        }
        false
    }
    fn forget(&self, scope: &str) {
        self.pending.lock().unwrap().remove(scope);
    }
}

struct F {
    fw: Arc<MeetingsFirewall>,
    dir: tempfile::TempDir,
    agent: Arc<Agent>,
    codes: Arc<Codes>,
    now: Arc<AtomicI64>,
    locked: Arc<AtomicBool>,
    routes: Arc<AtomicBool>,
    speech: Arc<AtomicBool>,
    sync_fails: Arc<AtomicBool>,
}

fn route() -> CodeRoute {
    CodeRoute {
        vm_id: "a".into(),
        hostname: "a.test".into(),
        senders: vec![CodeSender::Person {
            kind: "telegram".into(),
            id: "owner".into(),
            label: Some("Owner".into()),
        }],
        telegram: None::<TelegramRoute>,
    }
}

fn fixture(routes: bool) -> F {
    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(Agent::default());
    let codes = Arc::new(Codes::default());
    let now = Arc::new(AtomicI64::new(1_760_090_400_000)); // 2025-10-10T10:00:00Z
    let (locked, r, speech, sync_fails) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(routes)),
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(false)),
    );
    let fw = make(&dir, &agent, &codes, &now, &locked, &r, &speech, &sync_fails);
    F {
        fw,
        dir,
        agent,
        codes,
        now,
        locked,
        routes: r,
        speech,
        sync_fails,
    }
}

#[allow(clippy::too_many_arguments)]
fn make(
    dir: &tempfile::TempDir,
    agent: &Arc<Agent>,
    codes: &Arc<Codes>,
    now: &Arc<AtomicI64>,
    locked: &Arc<AtomicBool>,
    routes: &Arc<AtomicBool>,
    speech: &Arc<AtomicBool>,
    sync_fails: &Arc<AtomicBool>,
) -> Arc<MeetingsFirewall> {
    let (codes, now, locked, routes, speech, sync_fails) = (
        codes.clone(),
        now.clone(),
        locked.clone(),
        routes.clone(),
        speech.clone(),
        sync_fails.clone(),
    );
    MeetingsFirewall::new(MeetingsOptions {
        store_path: dir.path().join("store"),
        media_dir: dir.path().to_path_buf(),
        box_key: KEY.into(),
        org_id: "org".into(),
        box_id: "fw".into(),
        agent: Arc::new(agent.clone()),
        identities: Arc::new(|| vec![("a".into(), Some("a.test".into()), None)]),
        firewall_origin: Arc::new(|| "https://fw.test".into()),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ModuleCodes>)),
        code_routes: Arc::new(move || {
            if routes.load(Ordering::SeqCst) {
                vec![route()]
            } else {
                vec![]
            }
        }),
        channels_ready: Arc::new(|| true),
        locked: Arc::new(move |_| locked.load(Ordering::SeqCst)),
        speech_credential: Arc::new(move |s: &Value| {
            (speech.load(Ordering::SeqCst) && s.get("credentialId") != Some(&json!("missing"))).then(|| {
                (
                    "test-access-token".into(),
                    "ai-gateway.vercel.sh".into(),
                    Some("test-account".into()),
                )
            })
        }),
        on_credentials_changed: Arc::new(move || {
            let fails = sync_fails.load(Ordering::SeqCst);
            Box::pin(async move { if fails { Err("sync unavailable".into()) } else { Ok(()) } })
        }),
        organizer_allowed: Arc::new(|_, claim: &Value| {
            claim["organizer"] == "boss@example.com" || claim["source"] == "calendar"
        }),
        own_account: Arc::new(|_| Some("agent@example.com".into())),
        now: Arc::new(move || now.load(Ordering::SeqCst)),
    })
    .unwrap()
}

impl F {
    async fn propose(&self, revision: i64, policy: Value) -> CommandOutcome {
        self.propose_with(revision, policy, None).await
    }
    async fn propose_with(&self, revision: i64, policy: Value, instructions: Option<Value>) -> CommandOutcome {
        let mut p = json!({"vmId": "a", "changeId": uuid(), "revision": revision, "policy": policy});
        if let Some(i) = instructions {
            p["instructions"] = i;
        }
        crate::channels::finish(self.fw.command("propose", p.as_object().cloned().unwrap()).await)
    }
    async fn confirm(&self, change_id: &str, code: &str) -> CommandOutcome {
        crate::channels::finish(
            self.fw
                .command(
                    "confirm",
                    json!({"vmId": "a", "changeId": change_id, "code": code})
                        .as_object()
                        .cloned()
                        .unwrap(),
                )
                .await,
        )
    }
    /// The change id of the last code sent.
    fn pending(&self) -> String {
        self.codes.pending.lock().unwrap().get("meetings:a").unwrap().0.clone()
    }
    fn token(&self) -> String {
        self.applies().last().unwrap()["media"]["token"]
            .as_str()
            .unwrap()
            .to_string()
    }
    fn applies(&self) -> Vec<Value> {
        self.agent
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == "/meetings/apply")
            .map(|(_, b)| b.clone())
            .collect()
    }
    fn last_message(&self) -> String {
        self.codes.sent.lock().unwrap().last().cloned().unwrap_or_default()
    }
    fn media_file(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.dir.path().join("meeting-media.json")).unwrap()).unwrap()
    }
    async fn server(&self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/__cc/meetings/media", listener.local_addr().unwrap());
        let mut router = cc_http::Router::new(&["m"]);
        let fw = self.fw.clone();
        router.route(
            "m",
            |_, _| true,
            move |req, _| {
                let fw = fw.clone();
                async move { fw.media(req).await }
            },
        );
        let router = Arc::new(router);
        tokio::spawn(async move { cc_http::serve(listener, router).await });
        url
    }
}

async fn media(url: &str, token: &str, body: Value) -> (u16, Value) {
    let r = reqwest::Client::new()
        .post(url)
        .bearer_auth(token)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_failed_credential_sync_rejects_the_change_before_the_agent_apply() {
    let f = fixture(false);
    f.sync_fails.store(true, Ordering::SeqCst);
    let r = f.propose(0, with(base(), json!({"enabled": true}))).await;
    assert_eq!((r.ok, r.message.as_deref()), (false, Some("sync unavailable")));
    assert!(f.applies().is_empty());
}

#[tokio::test]
async fn approval_scoped_apply_revocation_renewal_and_private_results() {
    let f = fixture(false);
    let r = f.propose(0, with(base(), json!({"enabled": true}))).await;
    assert_eq!(r.status, "applied");
    assert!(!json!(r.data).to_string().contains("token"));
    let token = f.token();
    let url = f.server().await;
    assert_eq!(media(&url, "wrong", json!({"action": "start"})).await.0, 403);
    let (s, lease) = media(&url, &token, json!({"action": "start"})).await;
    assert_eq!(s, 200);
    assert!(
        lease.get("wake_sessions").is_none(),
        "transcript meetings never get the wake allowance"
    );
    assert_eq!(media(&url, &token, json!({"action": "start"})).await.0, 409);
    assert_eq!(
        media(&url, &token, json!({"action": "renew", "leaseId": "another-call"}))
            .await
            .0,
        409
    );
    f.now.fetch_add(10_000, Ordering::SeqCst);
    let (_, renewed) = media(&url, &token, json!({"action": "renew", "leaseId": lease["id"]})).await;
    assert_eq!(renewed["deadline"], lease["deadline"]);
    assert_eq!(f.media_file()["a"]["id"], lease["id"]);
    f.locked.store(true, Ordering::SeqCst);
    f.fw.publish().unwrap();
    assert_eq!(f.media_file(), json!({}));
    assert_eq!(
        media(&url, &token, json!({"action": "renew", "leaseId": lease["id"]}))
            .await
            .0,
        403
    );
    f.locked.store(false, Ordering::SeqCst);
    f.propose(1, base()).await;
    assert_eq!(media(&url, &token, json!({"action": "start"})).await.0, 403);
    assert_eq!(f.propose(0, base()).await.status, "conflict");
}

#[tokio::test]
async fn an_owner_confirms_the_exact_proposal_and_codes_cannot_be_replayed() {
    let f = fixture(true);
    let r = f.propose(0, with(base(), json!({"enabled": true}))).await;
    assert_eq!(r.status, "awaiting_code");
    let id = f.pending();
    let other = crate::channels::finish(
        f.fw.command(
            "confirm",
            json!({"vmId": "another", "changeId": id, "code": "123456"})
                .as_object()
                .cloned()
                .unwrap(),
        )
        .await,
    );
    assert_eq!(other.status, "expired");
    assert_eq!(f.confirm(&id, "000000").await.status, "invalid_code");
    assert_eq!(f.confirm(&id, "123456").await.status, "applied");
    assert_eq!(f.confirm(&id, "123456").await.status, "expired");
    assert_eq!(f.applies().len(), 1);
}

#[tokio::test]
async fn speech_keeps_its_credential_on_the_firewall_and_loses_it_with_the_payer() {
    let f = fixture(false);
    let policy = with(
        base(),
        json!({"enabled": true, "defaultMode": "bidi", "speech": {"provider": "codex", "credentialId": "login", "model": "gpt-realtime", "maxMinutes": 15}}),
    );
    assert_eq!(f.propose(0, policy.clone()).await.status, "applied");
    let apply = f.applies().pop().unwrap();
    assert!(!apply.to_string().contains("test-access-token"));
    assert!(
        apply["speech"]["placeholder"]
            .as_str()
            .unwrap()
            .starts_with("cc-speech-")
    );
    let c = f.fw.credentials();
    assert_eq!(c[0]["secret"], "test-access-token");
    assert_eq!(c[0]["speech_account_id"], "test-account");
    assert_eq!(c[0]["speech"], json!({"provider": "codex", "model": "gpt-realtime"}));
    f.speech.store(false, Ordering::SeqCst);
    assert!(f.fw.credentials().is_empty());
    assert!(!f.propose(1, policy).await.ok);
}

#[tokio::test]
async fn wake_words_and_the_default_mode_change_without_a_code_and_speech_needs_one() {
    let f = fixture(true);
    let enabled = with(base(), json!({"enabled": true}));
    f.propose(0, enabled.clone()).await;
    assert_eq!(f.confirm(&f.pending(), "123456").await.status, "applied");
    let wake = with(
        enabled.clone(),
        json!({"wake": {"enabled": false, "words": ["Jarvis"]}}),
    );
    assert_eq!(
        f.propose(1, wake.clone()).await.status,
        "applied",
        "wake words alone: no code"
    );
    assert_eq!(
        f.propose(2, with(wake.clone(), json!({"followUp": {"enabled": true}})))
            .await
            .status,
        "applied"
    );
    assert_eq!(
        f.propose(
            3,
            with(
                wake.clone(),
                json!({"consultModel": "controlclaw/anthropic/claude-haiku-4.5"})
            )
        )
        .await
        .status,
        "applied"
    );
    assert_eq!(f.codes.sent.lock().unwrap().len(), 1, "no code was sent");
    let speech =
        json!({"provider": "gateway", "credentialId": "included", "model": "openai/gpt-live-1", "maxMinutes": 30});
    let voice = f
        .propose(4, with(enabled, json!({"defaultMode": "bidi", "speech": speech})))
        .await;
    assert_eq!(voice.status, "awaiting_code", "a new speech binding still needs a code");
}

#[tokio::test]
async fn automatic_joins_are_checked_on_the_lease() {
    let f = fixture(false);
    assert_eq!(
        f.propose(0, with(base(), json!({"enabled": true}))).await.status,
        "applied"
    );
    let token = f.token();
    let url = f.server().await;
    let email = json!({"source": "email", "organizer": "boss@example.com"});
    assert_eq!(
        media(&url, &token, json!({"action": "admit", "auto": email})).await.1,
        json!({"ok": false, "reason": "off"})
    );
    assert_eq!(
        media(&url, &token, json!({"action": "start", "auto": email})).await.0,
        403
    );
    assert_eq!(
        media(&url, &token, json!({"action": "renew", "leaseId": "x", "auto": email}))
            .await
            .0,
        400
    );
    assert_eq!(media(&url, &token, json!({"action": "admit"})).await.0, 400);
    let auto = json!({"enabled": true, "mode": "transcript", "email": true, "calendar": "off", "maxPerDay": 1});
    assert_eq!(
        f.propose(1, with(base(), json!({"enabled": true, "autoJoin": auto})))
            .await
            .status,
        "applied"
    );
    assert_eq!(f.token(), token, "the media grant is kept: same access");
    let cal = json!({"source": "calendar", "organizer": "boss@example.com"});
    assert_eq!(
        media(&url, &token, json!({"action": "admit", "auto": cal})).await.1,
        json!({"ok": false, "reason": "source_off"})
    );
    let stranger = json!({"source": "email", "organizer": "stranger@example.net"});
    assert_eq!(
        media(&url, &token, json!({"action": "admit", "auto": stranger}))
            .await
            .1,
        json!({"ok": false, "reason": "organizer"})
    );
    assert_eq!(
        media(&url, &token, json!({"action": "admit", "auto": email})).await.1,
        json!({"ok": true})
    );
    let (s, first) = media(&url, &token, json!({"action": "start", "auto": email})).await;
    assert_eq!(s, 200);
    assert_eq!(
        media(&url, &token, json!({"action": "stop", "leaseId": first["id"]}))
            .await
            .0,
        200
    );
    let (s, second) = media(&url, &token, json!({"action": "start", "auto": email})).await;
    assert_eq!((s, second["reason"].clone()), (403, json!("daily_limit")));
    assert_eq!(
        media(&url, &token, json!({"action": "start"})).await.0,
        200,
        "the owner's own Join is not counted"
    );
    f.now.fetch_add(24 * 3_600_000, Ordering::SeqCst);
    assert_eq!(
        media(&url, &token, json!({"action": "admit", "auto": email})).await.1,
        json!({"ok": true}),
        "a new day"
    );
}

#[tokio::test]
async fn more_automatic_reach_needs_a_code_less_does_not() {
    let f = fixture(true);
    let auto = json!({"enabled": true, "mode": "transcript", "email": true, "calendar": "invited", "maxPerDay": 5});
    f.propose(0, with(base(), json!({"enabled": true}))).await;
    f.confirm(&f.pending(), "123456").await;
    assert_eq!(
        f.propose(1, with(base(), json!({"enabled": true, "autoJoin": auto})))
            .await
            .status,
        "awaiting_code"
    );
    assert!(
        f.last_message()
            .contains("join meetings by itself, in Transcript, at most 5 a day: invites emailed to it by your allowed senders; events on the connected Google Calendar that invite it"),
        "{}",
        f.last_message()
    );
    assert_eq!(f.confirm(&f.pending(), "123456").await.status, "applied");
    let less = with(auto.clone(), json!({"calendar": "off", "maxPerDay": 2}));
    assert_eq!(
        f.propose(2, with(base(), json!({"enabled": true, "autoJoin": less})))
            .await
            .status,
        "applied"
    );
    let more = with(auto, json!({"calendar": "all", "maxPerDay": 2}));
    assert_eq!(
        f.propose(3, with(base(), json!({"enabled": true, "autoJoin": more})))
            .await
            .status,
        "awaiting_code"
    );
}

#[tokio::test]
async fn full_agent_and_presenting_need_a_code_and_the_lease_says_where() {
    let f = fixture(false);
    let full = with(base(), json!({"enabled": true, "fullAgent": {"enabled": true}}));
    let refused = f.propose(0, full).await;
    assert_eq!(refused.status, "failed");
    assert!(
        refused
            .message
            .unwrap()
            .contains("Full agent needs a confirmation code")
    );
    assert_eq!(
        f.propose(0, with(base(), json!({"enabled": true}))).await.status,
        "applied"
    );

    let f = fixture(true);
    let speech =
        json!({"provider": "gateway", "credentialId": "included", "model": "openai/gpt-live-1", "maxMinutes": 30});
    let auto = json!({"enabled": true, "mode": "bidi", "email": true, "calendar": "all", "maxPerDay": 5});
    let b = with(
        base(),
        json!({"enabled": true, "defaultMode": "bidi", "speech": speech, "autoJoin": auto}),
    );
    assert_eq!(f.propose(0, b.clone()).await.status, "awaiting_code");
    assert!(f.last_message().contains("Meeting tools are read-only"));
    f.confirm(&f.pending(), "123456").await;
    let on = with(b.clone(), json!({"fullAgent": {"enabled": true}}));
    assert_eq!(f.propose(1, on.clone()).await.status, "awaiting_code");
    assert!(
        f.last_message()
            .contains("anyone in a meeting the agent was sent to can ask it to do anything it can do")
    );
    assert!(
        !f.last_message().contains("join meetings by itself"),
        "the message is about Full agent only"
    );
    assert_eq!(f.confirm(&f.pending(), "123456").await.status, "applied");
    let token = f.token();
    let url = f.server().await;
    let lease = |auto: Option<Value>| {
        let (url, token) = (url.clone(), token.clone());
        async move {
            let mut b = json!({"action": "start"});
            if let Some(a) = auto {
                b["auto"] = a;
            }
            let (_, l) = media(&url, &token, b).await;
            media(&url, &token, json!({"action": "stop", "leaseId": l["id"]})).await;
            (l["full_agent"].clone(), l["wake_sessions"].clone())
        }
    };
    assert_eq!(lease(None).await, (json!(true), json!(40)), "joined from the console");
    let own = json!({"source": "calendar", "organizer": "Agent@example.com"});
    assert_eq!(lease(Some(own)).await.0, json!(true), "the agent's own event");
    let other = json!({"source": "calendar", "organizer": "owner@example.com"});
    assert_eq!(lease(Some(other)).await.0, Value::Null, "any other organizer");
    let off = with(b.clone(), json!({"fullAgent": {"enabled": false}}));
    assert_eq!(f.propose(2, off).await.status, "applied", "off needs no code");
    assert_eq!(lease(None).await.0, Value::Null);

    f.routes.store(false, Ordering::SeqCst);
    let refused = f.propose(3, with(b.clone(), json!({"present": true}))).await;
    assert!(
        refused
            .message
            .unwrap()
            .contains("Presenting needs a confirmation code")
    );
    f.routes.store(true, Ordering::SeqCst);
    assert_eq!(
        f.propose(3, with(b.clone(), json!({"present": true}))).await.status,
        "awaiting_code"
    );
    assert!(f.last_message().contains("present its own browser in meetings"));
    f.confirm(&f.pending(), "123456").await;
    let (_, l) = media(&url, &token, json!({"action": "start"})).await;
    assert_eq!(l["present"], json!(true));
}

#[tokio::test]
async fn meeting_instructions_always_need_a_code_and_are_written_before_the_settings() {
    let f = fixture(true);
    let on = with(base(), json!({"enabled": true, "followUp": {"enabled": true}}));
    f.propose(0, on.clone()).await;
    assert_eq!(f.confirm(&f.pending(), "123456").await.status, "applied");
    f.agent.calls.lock().unwrap().clear();
    let instructions = json!({"text": "After each meeting:\n- Upload the notes to Notion.\n\n- Message me a summary.", "version": "v1"});
    assert_eq!(
        f.propose_with(1, on.clone(), Some(instructions.clone())).await.status,
        "awaiting_code"
    );
    let message = f.last_message();
    assert!(message.contains("Confirm new meeting instructions for a.test."));
    assert!(message.contains("Line 2: - Upload the notes to Notion."));
    assert!(message.contains("Line 3: - Message me a summary."));
    assert!(message.find("Upload the notes").unwrap() > message.find("Code: ").unwrap());
    assert!(
        f.agent.calls.lock().unwrap().is_empty(),
        "nothing written before the code"
    );
    let done = f.confirm(&f.pending(), "123456").await;
    assert_eq!(done.status, "applied");
    let calls = f.agent.calls.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|c| c.0.as_str()).collect::<Vec<_>>(),
        ["/meetings/instructions", "/meetings/apply"]
    );
    assert_eq!(calls[0].1, instructions);
    assert_eq!(done.data.unwrap()["instructionsWritten"], true);

    *f.agent.refuse.lock().unwrap() =
        "agent 409: The instructions changed since you opened this page. Reload it, then save again.".into();
    f.propose_with(2, on.clone(), Some(json!({"text": "Stale", "version": "v1"})))
        .await;
    f.agent.calls.lock().unwrap().clear();
    let refused = f.confirm(&f.pending(), "123456").await;
    assert_eq!(refused.status, "failed");
    assert_eq!(refused.data.unwrap()["instructions"], "changed");
    assert!(f.agent.calls.lock().unwrap().is_empty());
    *f.agent.refuse.lock().unwrap() =
        "agent 409: This agent has not set up its workspace yet. Send it a first message, then save the instructions."
            .into();
    f.propose_with(2, on.clone(), Some(json!({"text": "Early", "version": "v1"})))
        .await;
    assert_eq!(
        f.confirm(&f.pending(), "123456").await.data.unwrap()["instructions"],
        "waiting"
    );
    f.agent.refuse.lock().unwrap().clear();

    let off = with(on.clone(), json!({"enabled": false}));
    assert_eq!(
        f.propose_with(2, off, Some(instructions.clone())).await.status,
        "awaiting_code"
    );
    f.routes.store(false, Ordering::SeqCst);
    let nobody = f.propose_with(2, on.clone(), Some(instructions)).await;
    assert!(
        nobody
            .message
            .as_deref()
            .unwrap()
            .contains("New meeting instructions need a confirmation code")
    );
    assert_eq!(nobody.data.unwrap()["instructions"], "no_code");
    assert_eq!(
        f.propose(2, on.clone()).await.status,
        "applied",
        "the settings alone still go without one"
    );
    for bad in [
        json!({"text": "x"}),
        json!({"text": "x".repeat(4001), "version": "v"}),
        json!({"text": "x", "version": "v", "path": "SOUL.md"}),
        json!("text"),
    ] {
        let r = f.propose_with(3, on.clone(), Some(bad)).await;
        assert_eq!(r.message.as_deref(), Some("Invalid meetings request"));
    }
}

#[tokio::test]
async fn the_instructions_message_shows_every_line_or_there_is_no_code() {
    let empty = build_code_message(
        "123456",
        Some(&instructions_code_parts("a.test", "  \n", "")),
        "a.test",
        "",
        None,
        None,
    )
    .unwrap();
    assert!(empty.contains("The new ones are empty: the agent will only save notes."));
    let long = format!("- {}", "x".repeat(600));
    let shown = build_code_message(
        "123456",
        Some(&instructions_code_parts(
            "a.test",
            &format!("After each meeting:\n{long}"),
            "",
        )),
        "a.test",
        "",
        None,
        None,
    )
    .unwrap();
    assert!(shown.ends_with("End: 4"), "{}", &shown[shown.len() - 40..]);
    assert!(shown.contains("its last line is “End: 4”. If it is not, do not use the code."));
    let joined: String = shown
        .lines()
        .filter(|l| l.starts_with("Line ") && !l.starts_with("Line 1:"))
        .map(|l| l.split_once(": ").unwrap().1)
        .collect();
    assert_eq!(joined, long);

    let f = fixture(true);
    let many: Vec<String> = (0..32)
        .map(|i| format!("- Step {i}: {}", "do the thing carefully ".repeat(4)))
        .collect();
    let refused = f
        .propose_with(0, base(), Some(json!({"text": many.join("\n"), "version": "v1"})))
        .await;
    assert_eq!(refused.status, "failed");
    assert_eq!(refused.data.unwrap()["instructions"], "too_long");
    assert!(f.codes.sent.lock().unwrap().is_empty(), "no code message");
}

#[tokio::test]
async fn the_instructions_are_shown_and_written_the_same_way() {
    assert_eq!(
        clean_instructions("  After\u{a0}each  meeting…\r\n\n\n\n-\tUpload ﬁles  "),
        ("After each meeting...\n\n- Upload files".to_string(), false)
    );
    assert!(
        clean_instructions("Upload\u{200b} the notes").1,
        "an invisible character"
    );
    assert!(clean_instructions("Upload\u{7} the notes").1, "a control character");
    assert!(
        !clean_instructions("👩\u{200d}💻 Persian نیم\u{200c}فاصله").1,
        "joiners that are part of the writing stay"
    );

    let f = fixture(true);
    let asked = f
        .propose_with(
            0,
            base(),
            Some(json!({"text": "After each meeting…\n-  Upload\u{a0}the notes", "version": "v1"})),
        )
        .await;
    assert_eq!(asked.status, "awaiting_code");
    assert!(
        f.last_message().ends_with("Line 2: - Upload the notes\nEnd: 2"),
        "{}",
        f.last_message()
    );
    f.confirm(&f.pending(), "123456").await;
    let written = f
        .agent
        .calls
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.0 == "/meetings/instructions")
        .unwrap()
        .1
        .clone();
    assert_eq!(
        written,
        json!({"text": "After each meeting...\n- Upload the notes", "version": "v1"})
    );
    let hidden = f
        .propose_with(
            1,
            base(),
            Some(json!({"text": "Upload\u{200b} the notes", "version": "v1"})),
        )
        .await;
    assert_eq!(hidden.data.unwrap()["instructions"], "characters");
}

/// Headers now, the body later: a request held across the body read.
async fn held(url: &str, token: &str, body: &str) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let u = url::Url::parse(url).unwrap();
    let mut s = tokio::net::TcpStream::connect((u.host_str().unwrap(), u.port().unwrap()))
        .await
        .unwrap();
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        u.path(),
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s
}

async fn finish(mut s: tokio::net::TcpStream, body: &str) -> (u16, Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(body.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let status = out[9..12].parse().unwrap();
    let json = out
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn starts_held_across_the_body_read_cannot_pass_the_daily_limit_together() {
    let f = fixture(false);
    let auto = json!({"enabled": true, "mode": "transcript", "email": true, "calendar": "off", "maxPerDay": 1});
    assert_eq!(
        f.propose(0, with(base(), json!({"enabled": true, "autoJoin": auto})))
            .await
            .status,
        "applied"
    );
    let token = f.token();
    let url = f.server().await;
    let body = json!({"action": "start", "auto": {"source": "email", "organizer": "boss@example.com"}}).to_string();
    // Both have sent their headers before either body is read.
    let first = held(&url, &token, &body).await;
    let second = held(&url, &token, &body).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (s, lease) = finish(first, &body).await;
    assert_eq!(s, 200);
    assert_eq!(
        media(&url, &token, json!({"action": "stop", "leaseId": lease["id"]}))
            .await
            .0,
        200
    );
    let (s, refused) = finish(second, &body).await;
    assert_eq!(
        (s, refused["reason"].clone()),
        (403, json!("daily_limit")),
        "the second join is over today's limit"
    );
}
