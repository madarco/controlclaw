//! `content-rules.test.ts`, `content-rules-page.test.ts` (the stopped record): every change needs a
//! code, the file the proxy reads, held messages with Send and Don't send, notices, webhooks, the
//! record, the audit as Activity, and the policies' AI pin. Against a fake Telegram, a fake code
//! module and a fake poster.

#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::firewall::*;
use super::schema::ContentRule;
use super::stopped::{ContentStoppedStore, NewStopped, RuleBrief, STOPPED_IN_PER_MINUTE};
use crate::channels::ai::judge::ContentAnswer;
use crate::channels::ai::model::AiIdentity;
use crate::channels::chan::buttons::{CodeButtons, CodeButtonsOptions, TAP_PREFIX, TelegramApi};
use crate::contracts::{CodeAsk, CodeCheck, CodeRoute, CodeSender, CodeSent, ModuleCodes, TelegramRoute};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const TOKEN: &str = "777000:AAbbccddeeffgghhiijjkkllmmnnoopp";
const BOT_ID: &str = "777000";
const PERSON: &str = "424242";

#[derive(Default)]
struct Tg {
    calls: Mutex<Vec<(String, Value)>>,
    next: AtomicI64,
    /// A chat Telegram is slow to answer for.
    slow: Mutex<Option<String>>,
}

impl TelegramApi for Arc<Tg> {
    fn call(&self, _: &str, method: &str, body: Value) -> BoxFuture<Result<Value, String>> {
        let slow = method == "sendMessage"
            && self
                .slow
                .lock()
                .unwrap()
                .as_deref()
                .is_some_and(|c| body["chat_id"] == json!(c));
        self.calls.lock().unwrap().push((method.into(), body));
        let r = if method == "sendMessage" {
            Ok(json!({"message_id": self.next.fetch_add(1, Ordering::SeqCst) + 101}))
        } else {
            Ok(json!(true))
        };
        Box::pin(async move {
            if slow {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            r
        })
    }
}

#[derive(Default)]
struct Codes {
    asks: Mutex<Vec<CodeAsk>>,
    pending: Mutex<Option<(String, Value, u32)>>,
    fail: AtomicBool,
}

impl ModuleCodes for Codes {
    fn send(&self, req: CodeAsk) -> BoxFuture<CodeSent> {
        let failed = self.fail.load(Ordering::SeqCst) || req.routes.is_empty();
        if !failed {
            *self.pending.lock().unwrap() = Some((req.change_id.clone(), req.proposal.clone(), 5));
        }
        self.asks.lock().unwrap().push(req);
        Box::pin(async move {
            if failed {
                CodeSent::Failed {
                    message: "nobody".into(),
                }
            } else {
                CodeSent::Sent {
                    sent_via: "telegram:Marco".into(),
                    expires_at: "2026-10-28T10:10:00.000Z".into(),
                    attempts_left: 5,
                    recovery: None,
                }
            }
        })
    }
    fn verify(&self, _: &str, change_id: &str, code: &str) -> CodeCheck {
        let mut p = self.pending.lock().unwrap();
        match p.as_mut() {
            Some((id, proposal, _)) if id == change_id && code == "246813" => {
                let proposal = proposal.clone();
                *p = None;
                CodeCheck::Ok {
                    proposal,
                    sent_via: "telegram:Marco".into(),
                }
            }
            Some((id, _, tries)) if id == change_id => {
                *tries -= 1;
                CodeCheck::Wrong { tries_left: *tries }
            }
            _ => CodeCheck::Expired,
        }
    }
    fn cancel(&self, _: &str, change_id: Option<&str>) -> bool {
        let mut p = self.pending.lock().unwrap();
        if p.as_ref().is_some_and(|(id, _, _)| Some(id.as_str()) == change_id) {
            *p = None;
            return true;
        }
        false
    }
    fn forget(&self, _: &str) {
        *self.pending.lock().unwrap() = None;
    }
}

type Call = (String, Vec<(String, String)>, String);

#[derive(Default)]
struct Post {
    calls: Mutex<Vec<Call>>,
    answer: Mutex<Option<(u16, Value)>>,
}

impl Poster for Arc<Post> {
    fn post(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        body: String,
    ) -> BoxFuture<Result<(u16, Option<Value>), String>> {
        self.calls.lock().unwrap().push((url, headers, body));
        let (s, v) = self
            .answer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or((200, json!({"ok": true})));
        Box::pin(async move { Ok((s, Some(v))) })
    }
}

struct F {
    dir: tempfile::TempDir,
    tg: Arc<Tg>,
    codes: Arc<Codes>,
    post: Arc<Post>,
    buttons: Arc<CodeButtons>,
    clock: Arc<AtomicI64>,
    routes: Arc<Mutex<Vec<CodeRoute>>>,
    locked: Arc<AtomicBool>,
    identity: Arc<Mutex<Option<AiIdentity>>>,
    judge: Arc<Mutex<Option<ContentAnswer>>>,
    judged: Arc<AtomicU64>,
    stopped: Option<Arc<ContentStoppedStore>>,
    ask_ms: u64,
}

fn route() -> CodeRoute {
    CodeRoute {
        vm_id: "vm-1".into(),
        hostname: "agent-1".into(),
        senders: vec![CodeSender::Person {
            kind: "telegram".into(),
            id: PERSON.into(),
            label: Some("Marco".into()),
        }],
        telegram: Some(TelegramRoute {
            connection_id: "conn-1".into(),
            bot_token: TOKEN.into(),
        }),
    }
}

fn fixture() -> F {
    let tg = Arc::new(Tg::default());
    let clock = Arc::new(AtomicI64::new(1_000_000));
    let c = clock.clone();
    let buttons = Arc::new(CodeButtons::new(CodeButtonsOptions {
        approved: Arc::new(|conn: &str, s: &str| conn == "conn-1" && (s == PERSON || s == "515151")),
        token_for: Some(Arc::new(|b: &str| (b == BOT_ID).then(|| TOKEN.to_string()))),
        changed: None,
        telegram: Arc::new(tg.clone()),
        now: Arc::new(move || c.load(Ordering::SeqCst)),
        make_numbers: None,
        shuffle: None,
    }));
    F {
        dir: tempfile::tempdir().unwrap(),
        tg,
        codes: Arc::default(),
        post: Arc::default(),
        buttons,
        clock,
        routes: Arc::new(Mutex::new(vec![route()])),
        locked: Arc::default(),
        identity: Arc::default(),
        judge: Arc::default(),
        judged: Arc::default(),
        stopped: None,
        ask_ms: 2000,
    }
}

impl F {
    fn with_stopped(mut self) -> Self {
        let c = self.clock.clone();
        self.stopped = Some(Arc::new(
            ContentStoppedStore::new(
                self.dir.path().join("stopped"),
                KEY,
                "org-1",
                "fw-1",
                Arc::new(move || c.load(Ordering::SeqCst)),
            )
            .unwrap(),
        ));
        self
    }

    fn make(&self) -> Result<Arc<ContentRulesFirewall>, String> {
        let (codes, routes, buttons, c, locked, identity, judge, judged) = (
            self.codes.clone(),
            self.routes.clone(),
            self.buttons.clone(),
            self.clock.clone(),
            self.locked.clone(),
            self.identity.clone(),
            self.judge.clone(),
            self.judged.clone(),
        );
        ContentRulesFirewall::new(ContentRulesOptions {
            store_path: self.dir.path().join("content-rules.enc"),
            proxy_dir: self.dir.path().to_path_buf(),
            box_key: KEY.into(),
            org_id: "org-1".into(),
            box_id: "fw-1".into(),
            codes: Arc::new(move || Some(codes.clone() as Arc<dyn ModuleCodes>)),
            code_routes: Arc::new(move || routes.lock().unwrap().clone()),
            buttons: Arc::new(move || Some(buttons.clone())),
            audit_path: Some(self.dir.path().join("audit.jsonl")),
            // The bot is agent vm-1's.
            telegram_token: Arc::new(|b, vm| (b == BOT_ID && vm == "vm-1").then(|| TOKEN.to_string())),
            slack_token: Some(Arc::new(|vm, _| (vm == "vm-1").then(|| "xoxb-real".to_string()))),
            agentmail_key: Some(Arc::new(|inbox, vm| {
                (inbox == "a@agentmail.to" && vm == "vm-1").then(|| "am-key".to_string())
            })),
            locked: Arc::new(move |_| locked.load(Ordering::SeqCst)),
            poster: Arc::new(self.post.clone()),
            now: Arc::new(move || c.load(Ordering::SeqCst)),
            ask_ms: self.ask_ms,
            stopped: self.stopped.clone(),
            judge: Some(Arc::new(move |_| {
                judged.fetch_add(1, Ordering::SeqCst);
                let a = judge
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(ContentAnswer::Failed("off".into()));
                Box::pin(async move { a })
            })),
            ai_identity: Arc::new(move || identity.lock().unwrap().clone()),
        })
    }

    fn file(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.dir.path().join("content-rules.json")).unwrap()).unwrap()
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn tg_calls(&self) -> Vec<(String, Value)> {
        self.tg.calls.lock().unwrap().clone()
    }

    fn posts(&self) -> Vec<Call> {
        self.post.calls.lock().unwrap().clone()
    }

    /// A tap on the last message with buttons sent to `from`.
    async fn tap(&self, choice: &str, from: &str) {
        let calls = self.tg_calls();
        let (i, sent) = calls
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (m, b))| m == "sendMessage" && b.get("reply_markup").is_some() && b["chat_id"] == json!(from))
            .or_else(|| {
                calls
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, (m, b))| m == "sendMessage" && b.get("reply_markup").is_some())
            })
            .unwrap();
        let data = sent.1["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
            .as_str()
            .unwrap();
        let nonce = data[TAP_PREFIX.len()..].split(':').next().unwrap();
        let message_id = 101 + calls[..i].iter().filter(|(m, _)| m == "sendMessage").count() as i64;
        let q = json!({
            "id": format!("q{i}"), "data": format!("{TAP_PREFIX}{nonce}:{choice}"),
            "from": {"id": from.parse::<i64>().unwrap()},
            "message": {"message_id": message_id, "chat": {"id": from.parse::<i64>().unwrap(), "type": "private"}},
        });
        self.buttons.taps(Some(BOT_ID), &[q]).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

fn rule(over: Value) -> Value {
    let mut r = json!({
        "id": "customer-data", "name": "Customer data", "direction": "out", "channels": ["telegram"],
        "patterns": ["customer list"], "detectors": ["iban"], "action": "block",
        "reason": "customer data stays in the company", "enabled": true,
    });
    for (k, v) in over.as_object().unwrap() {
        r[k] = v.clone();
    }
    r
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

async fn apply(fw: &ContentRulesFirewall, id: &str, change: Value) -> String {
    let p = fw
        .command("propose", m(json!({"changeId": id, "change": change})))
        .await;
    assert_eq!(p.status, "awaiting_code", "{:?}", p.message);
    fw.command("confirm", m(json!({"changeId": id, "code": "246813"})))
        .await
        .status
}

static KEYS: AtomicU64 = AtomicU64::new(0);

fn hold_body() -> Value {
    json!({
        "key": format!("{:032x}", KEYS.fetch_add(1, Ordering::SeqCst) + 1), "botId": BOT_ID, "method": "sendMessage",
        "body": json!({"chat_id": 99, "text": "IBAN GB82 WEST 1234 5698 7654 32"}).to_string(),
        "chatId": "99", "vmId": "vm-1",
        "rule": {"id": "bank", "name": "Bank details", "reason": "bank details need approval"},
    })
}

fn asks(f: &F) -> Vec<Value> {
    f.tg_calls()
        .into_iter()
        .filter(|(m, b)| m == "sendMessage" && b.get("reply_markup").is_some())
        .map(|(_, b)| b)
        .collect()
}

/// The last words each chat's question was edited to.
fn last_edit_to(f: &F, chat: &str) -> String {
    f.tg_calls()
        .into_iter()
        .filter(|(m, b)| m == "editMessageText" && b["chat_id"] == json!(chat))
        .map(|(_, b)| b["text"].as_str().unwrap_or_default().to_string())
        .next_back()
        .unwrap_or_default()
}

fn edits(f: &F) -> Vec<String> {
    f.tg_calls()
        .into_iter()
        .filter(|(m, _)| m == "editMessageText")
        .map(|(_, b)| b["text"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test]
async fn a_new_firewall_writes_an_empty_rule_file_for_the_proxy() {
    let f = fixture();
    f.make().unwrap();
    assert_eq!(f.file(), json!({"version": 1, "rules": []}));
}

#[tokio::test]
async fn every_change_waits_for_a_code_tightening_included_and_only_the_code_applies_it() {
    let f = fixture();
    let fw = f.make().unwrap();
    let p = fw
        .command(
            "propose",
            m(json!({"changeId": "c1", "change": {"op": "put", "rule": rule(json!({}))}})),
        )
        .await;
    assert_eq!(p.status, "awaiting_code");
    assert_eq!(p.data.as_ref().unwrap()["sentVia"], "telegram:Marco");
    assert_eq!(f.file()["rules"], json!([]), "nothing applied before the code");
    {
        let asks = f.codes.asks.lock().unwrap();
        let a = asks.last().unwrap();
        assert!(a.no_buttons);
        let parts = a.parts.as_ref().unwrap();
        assert_eq!(
            parts.ask,
            "Confirm to add a content rule that stops messages from your agents on Telegram."
        );
        let typed: Vec<(&str, &str)> = parts
            .typed
            .iter()
            .map(|t| (t.label.as_str(), t.text.as_str()))
            .collect();
        assert_eq!(
            typed,
            [
                ("Rule", "Customer data"),
                ("Reason", "customer data stays in the company"),
                ("Words", "customer list (1 in all)")
            ]
        );
    }
    assert_eq!(
        fw.command("confirm", m(json!({"changeId": "c1", "code": "000000"})))
            .await
            .status,
        "invalid"
    );
    assert_eq!(
        fw.command("confirm", m(json!({"changeId": "c1", "code": "246813"})))
            .await
            .status,
        "applied"
    );
    let mut written = rule(json!({}));
    written.as_object_mut().unwrap().shift_remove("enabled");
    assert_eq!(f.file()["rules"], json!([written]));
    let mut last = f.audit().pop().unwrap();
    last["ts"] = json!(0);
    last["id"] = json!("");
    assert_eq!(
        last,
        json!({"ts": 0, "id": "", "action": "rule_changed", "op": "put", "rule": "customer-data", "enabled": true, "ruleAction": "block"})
    );
    assert!(
        !std::fs::read_to_string(f.dir.path().join("audit.jsonl"))
            .unwrap()
            .contains("customer list")
    );

    // Turning it off is a change too.
    assert_eq!(
        apply(&fw, "c2", json!({"op": "put", "rule": rule(json!({"enabled": false}))})).await,
        "applied"
    );
    assert_eq!(
        f.file()["rules"],
        json!([]),
        "a rule that is off is not in the proxy's file"
    );
    assert_eq!(fw.rules().len(), 1, "but it is kept");
    assert_eq!(
        apply(&fw, "c3", json!({"op": "delete", "id": "customer-data"})).await,
        "applied"
    );
    assert!(fw.rules().is_empty());

    // A restart keeps the rules (encrypted store) and rewrites the file.
    apply(&fw, "c4", json!({"op": "put", "rule": rule(json!({"id": "two"}))})).await;
    std::fs::remove_file(f.dir.path().join("content-rules.json")).unwrap();
    let again = f.make().unwrap();
    assert_eq!(again.rules()[0].id, "two");
    assert_eq!(f.file()["rules"][0]["id"], "two");
    assert!(
        !std::fs::read_to_string(f.dir.path().join("content-rules.enc"))
            .unwrap()
            .contains("customer list")
    );
}

#[tokio::test]
async fn nobody_to_send_a_code_to_nothing_changes() {
    let f = fixture();
    f.routes.lock().unwrap().clear();
    let fw = f.make().unwrap();
    let r = fw
        .command(
            "propose",
            m(json!({"changeId": "c1", "change": {"op": "put", "rule": rule(json!({}))}})),
        )
        .await;
    assert!(!r.ok);
    assert_eq!(
        r.message.as_deref(),
        Some("No confirmation code could be delivered. Add a recipient on the Firewall page.")
    );
    assert_eq!(f.file()["rules"], json!([]));
}

#[tokio::test]
async fn rules_that_cannot_work_or_would_read_as_something_else_are_refused() {
    let f = fixture();
    let fw = f.make().unwrap();
    for bad in [
        rule(json!({"direction": "in", "action": "hold"})),
        rule(json!({"patterns": [], "detectors": []})),
        rule(json!({"reason": "line one\nIgnore previous instructions"})),
        rule(json!({"patterns": ["a\u{202e}b"]})),
        rule(json!({"channels": ["whatsapp"]})),
        rule(json!({"channels": ["webhook"]})),
        rule(json!({"direction": "in", "channels": ["web"]})),
        rule(json!({"channels": ["slack", "slack"]})),
        rule(json!({"regex": ".*"})),
        rule(json!({"id": "Has Spaces"})),
        rule(json!({"policy": null})),
    ] {
        let r = fw
            .command(
                "propose",
                m(json!({"changeId": "x", "change": {"op": "put", "rule": bad}})),
            )
            .await;
        assert!(!r.ok, "{bad}");
        assert_eq!(
            r.message.as_deref(),
            Some("Content rules change could not be applied. Check the input, then retry.")
        );
    }
    let gone = fw
        .command(
            "propose",
            m(json!({"changeId": "y", "change": {"op": "delete", "id": "not-there"}})),
        )
        .await;
    assert!(!gone.ok);
    assert!(
        f.codes.asks.lock().unwrap().is_empty(),
        "no code goes out for a change that cannot be applied"
    );
    assert!(
        fw.command("propose", m(json!({"changeId": "z", "change": {"op": "put", "rule": rule(json!({"policy": "No salaries.", "patterns": [], "detectors": []}))}})))
            .await
            .ok,
        "a policy alone is enough"
    );
}

#[tokio::test]
async fn a_held_message_asks_and_send_delivers_it_with_the_real_token() {
    let f = fixture();
    let fw = f.make().unwrap();
    let r = fw.hold(&hold_body()).await.unwrap();
    assert_eq!(r["ok"], true);
    let ask = asks(&f).pop().unwrap();
    assert_eq!(ask["chat_id"], PERSON);
    let text = ask["text"].as_str().unwrap();
    assert!(text.contains("held a Telegram message from your agent"), "{text}");
    assert!(text.contains("Message: IBAN GB82"));
    assert!(text.contains("It is for chat 99, through bot 777000."));
    let labels: Vec<&str> = ask["reply_markup"]["inline_keyboard"][0]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["text"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["Send", "Don't send"]);
    assert!(f.posts().is_empty(), "not sent yet");

    f.tap("ok", PERSON).await;
    let posts = f.posts();
    assert_eq!(posts.len(), 1, "sent on approval");
    assert_eq!(posts[0].0, format!("https://api.telegram.org/bot{TOKEN}/sendMessage"));
    assert_eq!(
        serde_json::from_str::<Value>(&posts[0].2).unwrap()["text"],
        "IBAN GB82 WEST 1234 5698 7654 32"
    );
    assert!(edits(&f).iter().any(|t| t.contains("Sent on your approval")));
    assert!(
        f.audit()
            .iter()
            .any(|l| l["action"] == "released" && l["hold"].is_string())
    );
    f.tap("ok", PERSON).await;
    assert_eq!(f.posts().len(), 1, "a second tap does nothing");
}

#[tokio::test]
async fn dont_send_a_strangers_tap_and_an_emergency_stop() {
    let f = fixture();
    let fw = f.make().unwrap();
    fw.hold(&hold_body()).await.unwrap();
    f.tap("ok", "555").await;
    assert!(f.posts().is_empty(), "someone else's tap sends nothing");
    f.tap("x", PERSON).await;
    assert!(f.posts().is_empty());
    assert!(edits(&f).iter().any(|t| t.contains("Not sent")));
    assert!(f.audit().iter().any(|l| l["action"] == "dropped"));

    f.locked.store(true, Ordering::SeqCst);
    fw.hold(&hold_body()).await.unwrap();
    f.tap("ok", PERSON).await;
    assert!(f.posts().is_empty(), "under an emergency stop, Send sends nothing");
    assert!(
        edits(&f)
            .iter()
            .any(|t| t.contains("It could not be sent: the agent is under an emergency stop."))
    );
}

#[tokio::test]
async fn nobody_to_ask_another_agents_bot_and_a_refusal_are_said() {
    let f = fixture().with_stopped();
    let fw = f.make().unwrap();
    let mut other = hold_body();
    other["vmId"] = json!("vm-2");
    assert_eq!(
        fw.hold(&other).await.unwrap(),
        json!({"ok": false}),
        "another agent's bot"
    );
    f.clock.fetch_add(1, Ordering::SeqCst);
    f.routes.lock().unwrap().clear();
    assert_eq!(
        fw.hold(&hold_body()).await.unwrap(),
        json!({"ok": false}),
        "nobody to ask"
    );
    let outcomes: Vec<Value> = f
        .stopped
        .as_ref()
        .unwrap()
        .list(None, None, None)
        .iter()
        .map(|e| json!(e.outcome))
        .collect();
    assert_eq!(outcomes, [json!("nobody_asked"), json!("refused")]);
    assert!(
        fw.hold(&json!({"key": "nope"})).await.is_err(),
        "a hold that does not read"
    );

    // Telegram refusing the released message is said in the question.
    *f.routes.lock().unwrap() = vec![route()];
    *f.post.answer.lock().unwrap() = Some((400, json!({"ok": false, "description": "Bad Request: chat not found"})));
    fw.hold(&hold_body()).await.unwrap();
    f.tap("ok", PERSON).await;
    assert!(
        edits(&f)
            .iter()
            .any(|t| t
                .contains("\nIt could not be sent: Telegram refused it (HTTP 400: Bad Request: chat not found).\n")),
        "{:?}",
        edits(&f)
    );
}

#[tokio::test]
async fn a_hold_the_proxy_stopped_waiting_for_does_not_survive() {
    let f = fixture();
    let fw = f.make().unwrap();
    // Cancelled after it was made.
    let body = hold_body();
    fw.hold(&body).await.unwrap();
    fw.cancel(&json!({"key": body["key"]})).unwrap();
    assert!(fw.held_now().is_empty());
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        edits(&f)
            .iter()
            .any(|t| t.contains("This request is closed. The message was not sent."))
    );
    // Cancelled before it was made.
    let body = hold_body();
    fw.cancel(&json!({"key": body["key"]})).unwrap();
    assert_eq!(fw.hold(&body).await.unwrap(), json!({"ok": false}));
    assert!(fw.held_now().is_empty());
    assert!(fw.cancel(&json!({"key": "x"})).is_err());
}

#[tokio::test]
async fn the_notice_to_the_chat_at_most_one_a_minute_and_slack_in_and_out() {
    let f = fixture();
    let fw = f.make().unwrap();
    let n = json!({"kind": "out", "botId": BOT_ID, "chatId": "99", "vmId": "vm-1", "reason": "customer data stays in the company."});
    fw.notice(fw.notice_input(&n).unwrap()).await;
    fw.notice(fw.notice_input(&n).unwrap()).await;
    let posts = f.posts();
    assert_eq!(posts.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&posts[0].2).unwrap()["text"],
        "ControlClaw: a message from your agent was not sent. Your organization's rules stopped it: customer data stays in the company."
    );
    f.clock.fetch_add(60_001, Ordering::SeqCst);
    fw.notice(fw.notice_input(&n).unwrap()).await;
    assert_eq!(f.posts().len(), 2);
    // Another agent's bot: no notice.
    let mut other = n.clone();
    other["vmId"] = json!("vm-2");
    other["chatId"] = json!("98");
    fw.notice(fw.notice_input(&other).unwrap()).await;
    assert_eq!(f.posts().len(), 2);

    let slack_in =
        json!({"channel": "slack", "kind": "in", "chatId": "C123", "userId": "U1", "vmId": "vm-1", "reason": "r"});
    fw.notice(fw.notice_input(&slack_in).unwrap()).await;
    let slack_out =
        json!({"channel": "slack", "kind": "out", "chatId": "C124", "threadTs": "1.2", "vmId": "vm-1", "reason": "r"});
    fw.notice(fw.notice_input(&slack_out).unwrap()).await;
    let posts = f.posts();
    assert_eq!(posts[2].0, "https://slack.com/api/chat.postEphemeral");
    assert_eq!(serde_json::from_str::<Value>(&posts[2].2).unwrap()["user"], "U1");
    assert_eq!(posts[3].0, "https://slack.com/api/chat.postMessage");
    assert_eq!(serde_json::from_str::<Value>(&posts[3].2).unwrap()["thread_ts"], "1.2");
    assert!(
        posts[3]
            .1
            .contains(&("authorization".into(), "Bearer xoxb-real".into()))
    );
    assert!(fw.notice_input(&json!({"kind": "sideways"})).is_err());
}

#[tokio::test]
async fn a_held_slack_form_goes_out_with_the_real_token_and_an_email_with_the_inbox_key() {
    let f = fixture();
    let fw = f.make().unwrap();
    let slack = json!({
        "channel": "slack", "method": "chat.postMessage", "body": "token=xoxb-placeholder&channel=C1&text=hello",
        "contentType": "form", "chatId": "C1", "vmId": "vm-1", "key": format!("{:032x}", 9_000), "text": "hello",
        "rule": {"id": "r", "name": "R", "reason": "why"},
    });
    fw.hold(&slack).await.unwrap();
    f.tap("ok", PERSON).await;
    let (url, headers, body) = f.posts().pop().unwrap();
    assert_eq!(url, "https://slack.com/api/chat.postMessage");
    assert_eq!(body, "channel=C1&text=hello");
    assert!(headers.contains(&("authorization".into(), "Bearer xoxb-real".into())));

    let email = json!({
        "channel": "email", "method": "POST", "path": "/v0/inboxes/a%40agentmail.to/messages/send",
        "body": json!({"to": ["x@example.com"], "text": "hi"}).to_string(), "chatId": "a@agentmail.to",
        "vmId": "vm-1", "key": format!("{:032x}", 9_001), "text": "hi", "rule": {"id": "r", "name": "R", "reason": "why"},
    });
    fw.hold(&email).await.unwrap();
    assert!(
        asks(&f).pop().unwrap()["text"]
            .as_str()
            .unwrap()
            .contains("It is for inbox a@agentmail.to, to x@example.com.")
    );
    f.tap("ok", PERSON).await;
    let (url, headers, _) = f.posts().pop().unwrap();
    assert_eq!(
        url,
        "https://api.agentmail.to/v0/inboxes/a%40agentmail.to/messages/send"
    );
    assert!(headers.contains(&("authorization".into(), "Bearer am-key".into())));
    let mut wrong = email.clone();
    wrong["chatId"] = json!("b@agentmail.to");
    assert_eq!(fw.hold(&wrong).await.unwrap(), json!({"ok": false}), "another inbox");
}

#[tokio::test]
async fn webhooks_stopped_200_unknown_503_and_no_rule_reads_nothing() {
    let f = fixture().with_stopped();
    let fw = f.make().unwrap();
    assert_eq!(
        fw.screen_webhook("vm-1", b"{\"a\":\"the customer list\"}", "application/json", "")
            .await,
        None
    );
    apply(
        &fw,
        "c1",
        json!({"op": "put", "rule": rule(json!({"direction": "in", "channels": ["webhook"]}))}),
    )
    .await;
    assert_eq!(
        fw.screen_webhook("vm-1", b"{\"a\":\"the customer list\"}", "application/json", "")
            .await,
        Some((200, "stopped by content rule customer-data".into()))
    );
    assert_eq!(
        fw.screen_webhook("vm-1", b"{\"a\":\"fine\"}", "application/json", "")
            .await,
        None
    );
    let line = f.audit().pop().unwrap();
    assert_eq!(
        (line["action"].clone(), line["channel"].clone()),
        (json!("block"), json!("webhook"))
    );
    let kept = f.stopped.as_ref().unwrap().list(None, None, None);
    assert_eq!(kept[0].text.as_deref(), Some("the customer list"));
    assert_eq!(kept[0].id, line["id"].as_str().unwrap());

    // A store that will not open: unknown, 503, and the proxy refuses.
    std::fs::write(f.dir.path().join("content-rules.enc"), "garbage").unwrap();
    let broken = f.make().unwrap();
    assert_eq!(f.file(), json!({"version": 1, "unreadable": true}));
    assert_eq!(
        broken.screen_webhook("vm-1", b"x", "text/plain", "").await,
        Some((503, "content rules not loaded".into()))
    );
    let read = broken.command("read", Map::new()).await;
    assert_eq!(read.data.unwrap()["unreadable"], true);
    // A confirmed change reseals it.
    assert_eq!(
        apply(&broken, "c2", json!({"op": "put", "rule": rule(json!({}))})).await,
        "applied"
    );
    assert_eq!(f.file()["rules"][0]["id"], "customer-data");
    assert!(!broken.unreadable());
}

#[tokio::test]
async fn a_read_the_agent_repeats_is_one_line_an_hour_under_the_same_id() {
    let f = fixture();
    let fw = f.make().unwrap();
    let a = fw
        .record("r", "teamchat", "in", "log", Some("vm-1"), Map::new(), Some("m1"))
        .unwrap();
    assert!(
        fw.record("r", "teamchat", "in", "log", Some("vm-1"), Map::new(), Some("m1"))
            .is_none()
    );
    f.clock.fetch_add(3_600_000, Ordering::SeqCst);
    let b = fw
        .record("r", "teamchat", "in", "log", Some("vm-1"), Map::new(), Some("m1"))
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a, audit_once_id("r|teamchat|in|log|vm-1|m1"));
    assert_eq!(f.audit().len(), 2);
}

#[test]
fn the_audit_as_activity_rows_metadata_only() {
    let name = |id: &str| (id == "r1").then(|| "Rule one".to_string());
    assert_eq!(
        content_rule_activity(
            &json!({"ts": 1.5, "id": "a", "rule": "r1", "channel": "telegram", "direction": "in", "action": "block", "vm_id": "vm-1", "ai": "found", "purpose": "phone", "text": "secret"}),
            &name
        ),
        Some(
            json!({"source": "content_rule", "id": "a", "ts": 1.5, "rule": "r1", "name": "Rule one", "channel": "telegram", "direction": "in", "action": "block", "vm_id": "vm-1", "purpose": "phone", "ai": "found"})
        )
    );
    assert_eq!(
        content_rule_activity(
            &json!({"ts": 1, "id": "a", "action": "rule_changed", "rule": "r1", "channel": "x"}),
            &name
        ),
        None
    );
    assert_eq!(
        content_rule_activity(
            &json!({"ts": 1, "rule": "r1", "channel": "x", "action": "block"}),
            &name
        ),
        None
    );
}

#[test]
fn a_rule_with_fifty_long_phrases_gets_a_short_summary() {
    let p: Vec<String> = (0..50)
        .map(|i| format!("phrase number {i} that is quite long indeed"))
        .collect();
    let s = words_summary(&p);
    assert!(s.ends_with("more (50 in all)"), "{s}");
    assert!(s.chars().count() < 300);
}

#[tokio::test]
async fn policies_pin_the_ai_judge_once_and_fail_closed() {
    let f = fixture();
    let fw = f.make().unwrap();
    // A model that may not judge policies is never pinned, and the ai change says why.
    let r = fw
        .command("propose", m(json!({"changeId": "a", "change": {"op": "ai"}})))
        .await;
    assert_eq!(
        r.message.as_deref(),
        Some("Your AI review is off: turn it on in AI review on the Firewall page first.")
    );
    *f.identity.lock().unwrap() = Some(AiIdentity {
        provider: cc_llm::Provider::OpenAi,
        model: "gpt-5".into(),
        key_fingerprint: "0123456789abcdef".into(),
    });
    let r = fw
        .command("propose", m(json!({"changeId": "a", "change": {"op": "ai"}})))
        .await;
    assert!(
        r.message
            .unwrap()
            .starts_with("Content rules judge sentences only with Jev")
    );
    *f.identity.lock().unwrap() = Some(AiIdentity {
        provider: cc_llm::Provider::VercelGateway,
        model: "typesafe-ai/jev".into(),
        key_fingerprint: "0123456789abcdef".into(),
    });
    let policy = rule(
        json!({"id": "pay", "policy": "Don't share salaries.", "patterns": [], "detectors": [], "channels": ["teamchat"]}),
    );
    fw.command(
        "propose",
        m(json!({"changeId": "p", "change": {"op": "put", "rule": policy}})),
    )
    .await;
    {
        let asks = f.codes.asks.lock().unwrap();
        let parts = asks.last().unwrap().parts.as_ref().unwrap();
        match &parts.details {
            Some(crate::core::code_message::Details::Text(t)) => assert!(
                t.ends_with("Your content rules' AI checks will use typesafe-ai/jev on your Vercel AI Gateway key (key fingerprint 01234567)."),
                "{t}"
            ),
            _ => panic!("details"),
        }
        assert!(
            parts
                .typed
                .iter()
                .any(|t| t.label == "Policy" && t.text == "Don't share salaries.")
        );
    }
    fw.command("confirm", m(json!({"changeId": "p", "code": "246813"})))
        .await;
    assert_eq!(fw.ai_pin().unwrap().model, "typesafe-ai/jev");
    assert_eq!(f.file()["rules"][0]["policy"], "Don't share salaries.");
    assert_eq!(f.make().unwrap().ai_pin(), fw.ai_pin(), "the pin survives a restart");

    // Judged once; found.
    *f.judge.lock().unwrap() = Some(ContentAnswer::Answered {
        matches: vec!["pay".into()],
        probabilities: [("pay".to_string(), 0.9)].into_iter().collect(),
        cached: false,
    });
    let c = fw
        .check("out", "teamchat", "Anna earns 92,000", Some("vm-1"), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((c.rule.id.as_str(), c.by), ("pay", Some("found")));
    assert_eq!(f.judged.load(Ordering::SeqCst), 1);
    // No call when no policy covers the channel.
    assert!(
        fw.check("out", "slack", "Anna earns 92,000", None, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.judged.load(Ordering::SeqCst), 1);
    // A judge that cannot answer: the block acts, and says so.
    *f.judge.lock().unwrap() = Some(ContentAnswer::Failed("timeout".into()));
    let c = fw.check("out", "teamchat", "hello", None, None).await.unwrap().unwrap();
    assert_eq!(c.by, Some("failed"));
    assert_eq!(
        c.rule.reason,
        "customer data stays in the company (the AI check could not run)"
    );

    // rules.try: nothing recorded.
    let lines = f.audit().len();
    let t = fw
        .command(
            "try",
            m(json!({"text": "hello", "direction": "out", "channel": "teamchat"})),
        )
        .await;
    assert_eq!(t.status, "tried");
    assert_eq!(t.data.as_ref().unwrap()["asked"], json!(["pay"]));
    assert_eq!(t.data.as_ref().unwrap()["failed"], "timeout");
    assert_eq!(f.audit().len(), lines);

    // A new key since the code was sent: not accepted under the old message.
    let jev = |fp: &str| AiIdentity {
        provider: cc_llm::Provider::VercelGateway,
        model: "typesafe-ai/jev".into(),
        key_fingerprint: fp.into(),
    };
    *f.identity.lock().unwrap() = Some(jev("1111111111111111"));
    fw.command("propose", m(json!({"changeId": "q", "change": {"op": "put", "rule": rule(json!({"id": "pay2", "policy": "x", "channels": ["teamchat"]}))}})))
        .await;
    *f.identity.lock().unwrap() = Some(jev("fedcba9876543210"));
    let r = fw
        .command("confirm", m(json!({"changeId": "q", "code": "246813"})))
        .await;
    assert!(!r.ok);
    assert!(
        r.message
            .unwrap()
            .starts_with("Your AI review changed while the code was on its way.")
    );
}

#[test]
fn the_stopped_record_newest_first_secrets_withheld_holds_settled_and_a_flood_counted() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(AtomicI64::new(1_761_600_000_000));
    let c = clock.clone();
    let s = ContentStoppedStore::new(
        dir.path().to_path_buf(),
        KEY,
        "o",
        "b",
        Arc::new(move || c.load(Ordering::SeqCst)),
    )
    .unwrap();
    let brief = RuleBrief {
        id: "r".into(),
        name: "R".into(),
        reason: "why".into(),
        ai: None,
    };
    let entry = |direction: &str, text: &str| NewStopped {
        rule: brief.clone(),
        channel: "webhook".into(),
        direction: direction.into(),
        action: "block".into(),
        vm_id: Some("vm-1".into()),
        text: Some(text.into()),
        withheld: None,
        outcome: None,
        id: None,
        at: None,
    };
    let hold = s
        .record(NewStopped {
            action: "hold".into(),
            outcome: Some("waiting".into()),
            ..entry("out", "held")
        })
        .unwrap();
    clock.fetch_add(1, Ordering::SeqCst);
    s.record(NewStopped {
        withheld: Some("secret".into()),
        ..entry("out", "sk-secret")
    });
    clock.fetch_add(1, Ordering::SeqCst);
    s.record(entry("out", &"x".repeat(2500)));
    let list = s.list(None, None, None);
    assert_eq!(list.len(), 3);
    assert!(list[0].cut && list[0].text.as_ref().unwrap().len() == 2000);
    assert_eq!(list[1].text, None);
    s.settle(&hold, clock.load(Ordering::SeqCst), "sent");
    assert_eq!(s.list(None, None, None)[2].outcome.as_deref(), Some("sent"));
    // Paging on.
    let page = s.list(Some(list[0].at), Some(&list[0].id), Some(1));
    assert_eq!(page[0].id, list[1].id);

    // Coming in: capped per agent and minute, the rest counted once the minute is over.
    clock.store(1_761_600_060_000, Ordering::SeqCst);
    for i in 0..(STOPPED_IN_PER_MINUTE + 3) {
        s.record(entry("in", &format!("m{i}")));
    }
    clock.fetch_add(60_000, Ordering::SeqCst);
    let all = s.list(None, None, Some(200));
    let flood: Vec<_> = all.iter().filter(|e| e.withheld.as_deref() == Some("flood")).collect();
    assert_eq!(flood.len(), 1);
    assert_eq!(flood[0].count, Some(3));
    assert_eq!(
        all.iter()
            .filter(|e| e.direction == "in" && e.withheld.is_none())
            .count() as u32,
        STOPPED_IN_PER_MINUTE
    );
    s.settle_waiting("restarted");
}

#[test]
fn the_schema_writes_rules_in_its_own_key_order() {
    let r: ContentRule = super::schema::parse_rule(&rule(json!({"policy": "p"}))).unwrap();
    let keys: Vec<String> = json!(r).as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "id",
            "name",
            "direction",
            "channels",
            "patterns",
            "detectors",
            "policy",
            "action",
            "reason",
            "enabled"
        ]
    );
}

#[tokio::test]
async fn an_answer_while_the_others_are_still_asked_acts_on_the_hold() {
    let f = fixture();
    let mut two = route();
    two.senders.push(CodeSender::Person {
        kind: "telegram".into(),
        id: "515151".into(),
        label: None,
    });
    *f.routes.lock().unwrap() = vec![two];
    *f.tg.slow.lock().unwrap() = Some("515151".into());
    let fw = f.make().unwrap();

    // Send by the first while the second is still being asked: it goes out once.
    let (fw2, body) = (fw.clone(), hold_body());
    let pending = tokio::spawn(async move { fw2.hold(&body).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.tap("ok", PERSON).await;
    assert_eq!(pending.await.unwrap().unwrap()["ok"], true);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(f.posts().len(), 1, "sent on the first answer");
    assert!(fw.held_now().is_empty(), "and not left waiting");
    assert!(
        last_edit_to(&f, PERSON).contains("Sent on your approval."),
        "the presser gets the result"
    );
    assert!(
        last_edit_to(&f, "515151").contains("Someone else pressed Send."),
        "the late offer says someone else pressed Send"
    );

    // Don't send by the first: the second cannot send it afterwards.
    let (fw2, body) = (fw.clone(), hold_body());
    let pending = tokio::spawn(async move { fw2.hold(&body).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.tap("x", PERSON).await;
    pending.await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.tap("ok", "515151").await;
    assert_eq!(
        f.posts().len(),
        1,
        "a message one person refused is not sent by another"
    );
    assert!(fw.held_now().is_empty());
}

#[tokio::test]
async fn a_compressed_webhook_is_read_as_the_agent_reads_it_and_an_unknown_encoding_is_stopped() {
    use std::io::Write;
    let f = fixture();
    let fw = f.make().unwrap();
    apply(
        &fw,
        "c1",
        json!({"op": "put", "rule": rule(json!({"direction": "in", "channels": ["webhook"]}))}),
    )
    .await;
    let body = br#"{"a":"the customer list"}"#;
    let gz = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(body).unwrap();
        e.finish().unwrap()
    };
    let zlib = {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(body).unwrap();
        e.finish().unwrap()
    };
    let raw = hex::decode("ab564a54b2522ac94855482e2d2ec9cf4d2d52c8c92c2e51aa0500").unwrap();
    let br = hex::decode("0b0c807b2261223a2274686520637573746f6d6572206c697374227d03").unwrap();
    let stopped = Some((200, "stopped by content rule customer-data".to_string()));
    for (bytes, enc) in [
        (&gz, "gzip"),
        (&gz, "x-gzip"),
        (&zlib, "deflate"),
        (&raw, "deflate"),
        (&br, "br"),
        (&gz, "identity, gzip"),
    ] {
        assert_eq!(
            fw.screen_webhook("vm-1", bytes, "application/json", enc).await,
            stopped,
            "{enc}"
        );
    }
    // Something the firewall cannot unpack is not forwarded as "not text".
    assert_eq!(
        fw.screen_webhook("vm-1", &gz, "application/json", "zstd").await,
        Some((200, "content check failed".into()))
    );
    assert_eq!(
        fw.screen_webhook("vm-1", b"not gzip", "application/json", "gzip").await,
        Some((200, "content check failed".into()))
    );
    // More than a check unpacks.
    let bomb = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![b'a'; 17 * 1024 * 1024]).unwrap();
        e.finish().unwrap()
    };
    assert_eq!(
        fw.screen_webhook("vm-1", &bomb, "text/plain", "gzip").await,
        Some((200, "content check failed".into()))
    );
}

#[tokio::test]
async fn send_before_a_slow_offer_is_back_is_never_reported_as_stopped() {
    let mut f = fixture().with_stopped();
    f.ask_ms = 150;
    let mut two = route();
    two.senders.push(CodeSender::Person {
        kind: "telegram".into(),
        id: "515151".into(),
        label: None,
    });
    *f.routes.lock().unwrap() = vec![two];
    // Slower than the asking may take.
    *f.tg.slow.lock().unwrap() = Some("515151".into());
    let fw = f.make().unwrap();
    let (fw2, body) = (fw.clone(), hold_body());
    let pending = tokio::spawn(async move { fw2.hold(&body).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.tap("ok", PERSON).await;
    let answer = pending.await.unwrap().unwrap();
    assert_eq!(
        answer["ok"], true,
        "the message went out: the agent is not told it was stopped"
    );
    assert_eq!(f.posts().len(), 1);
    let outcomes: Vec<Option<String>> = f
        .stopped
        .as_ref()
        .unwrap()
        .list(None, None, None)
        .into_iter()
        .map(|e| e.outcome)
        .collect();
    assert!(!outcomes.contains(&Some("nobody_asked".into())), "{outcomes:?}");
    // The slow offer comes back after the answer: it says someone else pressed Send.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(last_edit_to(&f, "515151").contains("Someone else pressed Send."));
    assert!(last_edit_to(&f, PERSON).contains("Sent on your approval."));
    assert!(fw.held_now().is_empty());

    // The proxy's /cancel during the asking, after Send: still sent, still not "stopped".
    let body = hold_body();
    let (fw2, b2) = (fw.clone(), body.clone());
    let pending = tokio::spawn(async move { fw2.hold(&b2).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.tap("ok", PERSON).await;
    fw.cancel(&json!({"key": body["key"]})).unwrap();
    assert_eq!(pending.await.unwrap().unwrap()["ok"], true);
    assert_eq!(f.posts().len(), 2);
}

/// The team chat gate's content rules (`ChatContent`, W5's 3930 gate): a held message asks the
/// people who get codes, and Send posts it; the rules apply to the `teamchat` channel.
#[tokio::test]
async fn a_team_chat_message_is_held_through_the_chat_content_slot() {
    use crate::contracts::{ChatContent as _, ChatHold, CheckedRule};
    let f = fixture();
    let fw = f.make().unwrap();
    let chat = super::Gate {
        fw: fw.clone(),
        channel: "teamchat",
    };
    assert!(chat.loaded());
    let sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s = sent.clone();
    let id = chat
        .hold(ChatHold {
            vm_id: "vm-1".into(),
            where_: "#general".into(),
            text: "the customer list is attached".into(),
            rule: CheckedRule {
                id: "customer-data".into(),
                name: Some("Customer data".into()),
                action: "hold".into(),
                reason: "customer data stays in the company".into(),
                by: None,
            },
            send: Box::new(move || {
                s.store(true, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            }),
        })
        .await;
    assert!(id.is_some());
    let ask = asks(&f).pop().unwrap();
    assert!(ask["text"].as_str().unwrap().contains("team chat message"), "{ask}");
    assert!(!sent.load(Ordering::SeqCst), "not sent yet");
    f.tap("ok", PERSON).await;
    assert!(sent.load(Ordering::SeqCst), "sent on approval");
    assert!(fw.held_now().is_empty());
}
