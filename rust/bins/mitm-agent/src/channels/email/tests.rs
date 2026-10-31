//! `email-rules.test.ts`: the authentication verdicts, address parsing, the rules' widening, the
//! commands with codes, outbound checks with one-window approvals and limits, inbound keep, strip
//! and hide, and the held counts.

#![allow(clippy::unwrap_used)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::auth::*;
use super::rules::*;
use super::schema::*;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeRequest, ConsentCodes, SendResult, Verify};

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

const GMAIL_AR: &str = "mx.google.com;       dkim=pass header.i=@agentmail.to header.s=tu4eio4jzssygxnjiy4day36ybs4eupz header.b=A9JkjarI;       dkim=pass header.i=@amazonses.com header.s=224i4yxa5dv7c2xz3womw6peuasteono header.b=UzvzwKB0;       spf=pass (google.com: domain of 010001a1084d415f@mail.agentmail.to designates 24.110.104.197 as permitted sender) smtp.mailfrom=010001a1084d415f@mail.agentmail.to;       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=agentmail.to";
const SES_AR: &str = "amazonses.com; spf=pass (spfCheck: domain of _spf.google.com designates 74.125.228.98 as permitted sender) client-ip=74.125.228.98; envelope-from=inbox.owner@gmail.com; helo=mail-ed2-f34.google.com; dkim=pass header.i=@gmail.com; dmarc=pass header.from=gmail.com;";

fn h(name: &str, value: &str) -> GmailHeader {
    GmailHeader {
        name: name.into(),
        value: value.into(),
    }
}

fn gmail_headers(ar: &str, from: &str) -> Vec<GmailHeader> {
    vec![
        h("Delivered-To", "inbox.owner@gmail.com"),
        h(
            "ARC-Authentication-Results",
            "i=1; mx.google.com; dkim=pass header.i=@agentmail.to; dmarc=pass header.from=agentmail.to",
        ),
        h("Received-SPF", "pass (google.com: …)"),
        h("Authentication-Results", ar),
        h("DKIM-Signature", "v=1; d=agentmail.to; s=x"),
        h("From", from),
        h("To", "inbox.owner@gmail.com"),
    ]
}

fn default_headers() -> Vec<GmailHeader> {
    gmail_headers(GMAIL_AR, "Ada Agent <agent12@agentmail.to>")
}

fn am_genuine() -> Map<String, Value> {
    m(json!({
        "message_id": "<m1@mail.gmail.com>",
        "from": "Ada Owner <inbox.owner@gmail.com>",
        "labels": ["received", "unread"],
        "authentication_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "headers": {"Authentication-Results": SES_AR, "In-Reply-To": "<x>"},
        "text": "hello",
    }))
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn with(base: &Map<String, Value>, over: Value) -> Map<String, Value> {
    let mut b = base.clone();
    for (k, v) in m(over) {
        if v.is_null() {
            b.remove(&k);
        } else {
            b.insert(k, v);
        }
    }
    b
}

fn ok_from(v: Verdict) -> (bool, Option<&'static str>, Option<String>) {
    (v.0.is_ok(), v.0.err(), v.1)
}

#[test]
fn authentication_results_parsing_and_the_gmail_verdict() {
    let ar = parse_auth_results(GMAIL_AR).unwrap();
    assert_eq!(ar.authserv_id, "mx.google.com");
    let rs: Vec<String> = ar
        .results
        .iter()
        .map(|r| format!("{}={}", r.method, r.result))
        .collect();
    assert_eq!(rs, ["dkim=pass", "dkim=pass", "spf=pass", "dmarc=pass"]);
    assert_eq!(ar.results[0].props["header.i"], "@agentmail.to");
    let inbox = vec!["INBOX".to_string()];
    assert_eq!(
        ok_from(gmail_verdict(&default_headers(), &inbox, RequireAuth::Aligned)),
        (true, None, Some("agent12@agentmail.to".into()))
    );
    assert_eq!(
        ok_from(gmail_verdict(
            &default_headers(),
            &["SPAM".into()],
            RequireAuth::Aligned
        )),
        (false, Some("spam"), Some("agent12@agentmail.to".into()))
    );
    // DMARC fail but an aligned DKIM pass passes only in "aligned".
    let dkim_only = "mx.google.com; dkim=pass header.i=@news.example.com; spf=softfail smtp.mailfrom=x@other.net; dmarc=fail (p=NONE) header.from=example.com";
    assert!(
        gmail_verdict(&gmail_headers(dkim_only, "a@example.com"), &[], RequireAuth::Aligned)
            .0
            .is_ok()
    );
    assert!(
        gmail_verdict(&gmail_headers(dkim_only, "a@example.com"), &[], RequireAuth::Dmarc)
            .0
            .is_err()
    );
    // DKIM for somebody else's domain, and SPF alone, never pass.
    for v in [
        "mx.google.com; dkim=pass header.i=@attacker.net; spf=pass smtp.mailfrom=x@attacker.net; dmarc=fail header.from=example.com",
        "mx.google.com; spf=pass smtp.mailfrom=bounce@example.com; dmarc=none header.from=example.com",
        "mx.google.com; dkim=pass header.d=com; dmarc=none header.from=example.com",
    ] {
        assert!(
            gmail_verdict(&gmail_headers(v, "a@example.com"), &[], RequireAuth::Aligned)
                .0
                .is_err(),
            "{v}"
        );
    }
    // The sender's own forged header comes after Gmail's and is never read.
    let mut forged = gmail_headers(
        "mx.google.com; dkim=none; spf=softfail; dmarc=fail header.from=example.com",
        "a@example.com",
    );
    forged.push(h(
        "Authentication-Results",
        "mx.google.com; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com",
    ));
    assert!(gmail_verdict(&forged, &[], RequireAuth::Aligned).0.is_err());
    let no_ar: Vec<_> = default_headers()
        .into_iter()
        .filter(|x| x.name != "Authentication-Results")
        .collect();
    assert!(gmail_verdict(&no_ar, &[], RequireAuth::Aligned).0.is_err());
    assert!(
        gmail_verdict(
            &gmail_headers("evil.example; dmarc=pass header.from=agentmail.to", "a@agentmail.to"),
            &[],
            RequireAuth::Aligned
        )
        .0
        .is_err()
    );
    let mut two = default_headers();
    two.push(h("From", "b@agentmail.to"));
    assert_eq!(
        ok_from(gmail_verdict(&two, &[], RequireAuth::Aligned)),
        (false, Some("bad_from"), None)
    );
    assert!(
        gmail_verdict(&gmail_headers(GMAIL_AR, "boss@example.com"), &[], RequireAuth::Dmarc)
            .0
            .is_err()
    );
}

#[test]
fn agentmail_verdict_labels_and_the_structured_field_gate() {
    let g = am_genuine();
    assert_eq!(
        ok_from(agentmail_verdict(&g)),
        (true, None, Some("inbox.owner@gmail.com".into()))
    );
    for labels in [
        json!(["received", "spam"]),
        json!(["received", "blocked"]),
        json!(["received", "unauthenticated"]),
        json!(["unread"]),
    ] {
        assert!(agentmail_verdict(&with(&g, json!({"labels": labels}))).0.is_err());
    }
    assert!(
        agentmail_verdict(&with(&g, json!({"authentication_results": null})))
            .0
            .is_err()
    );
    assert!(
        agentmail_verdict(&with(
            &g,
            json!({"authentication_results": {"spf": "pass", "dkim": "pass", "dmarc": "none"}})
        ))
        .0
        .is_err()
    );
    assert!(agentmail_verdict(&with(&g, json!({
        "authentication_results": {"spf": "softfail", "dkim": "none", "dmarc": "fail"},
        "headers": {"Authentication-Results": "amazonses.com; spf=pass; dkim=pass header.i=@gmail.com; dmarc=pass header.from=gmail.com;"},
    }))).0.is_err());
    assert!(
        agentmail_verdict(&with(
            &g,
            json!({"headers": {"Authentication-Results": SES_AR.replace("header.from=gmail.com", "header.from=other.com")}})
        ))
        .0
        .is_err()
    );
    assert_eq!(
        ok_from(agentmail_verdict(&with(&g, json!({"from": "a@x.com, b@y.com"})))),
        (false, Some("bad_from"), None)
    );
}

#[test]
fn address_parsing() {
    assert_eq!(
        parse_from_address(r#""inbox.owner@gmail.com" <spoof-test@controlclaw.com>"#).as_deref(),
        Some("spoof-test@controlclaw.com")
    );
    assert_eq!(
        parse_from_address("Bob (work) <BOB@Example.COM>").as_deref(),
        Some("bob@example.com")
    );
    assert_eq!(parse_from_address("a@x.com, b@y.com"), None);
    assert_eq!(parse_from_address("<a@x.com> <b@y.com>"), None);
    assert_eq!(parse_from_address("not an address"), None);
    assert_eq!(
        parse_address_list(r#""Doe, John" <j@x.com>, k@y.com"#).unwrap(),
        ["j@x.com", "k@y.com"]
    );
    assert_eq!(
        parse_address_list("Team: a@x.com, b@x.com;, c@y.com").unwrap(),
        ["a@x.com", "b@x.com", "c@y.com"]
    );
    assert_eq!(
        parse_address_list("undisclosed-recipients:;").unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(parse_address_list("<a@x.com"), None);
    assert_eq!(
        recipients_from_header_block(
            "From: me@x.com\r\nTo: Bob <bob@y.com>,\r\n c@z.com\r\nBcc: hidden@w.com\r\nSubject: s\r\n\r\nBODY To: evil@x.com"
        )
        .unwrap(),
        ["bob@y.com", "c@z.com", "hidden@w.com"]
    );
    assert_eq!(
        recipients_from_header_block("To: a@x.com\r\nResent-To: evil@x.com\r\n"),
        None
    );
    assert_eq!(recipients_from_header_block("To: a@x.com\r\nbroken line\r\n"), None);
    // An address in front of a ':' is refused, never dropped.
    assert_eq!(parse_address_list("evil@evil.com g: ok@ok.com;"), None);
    assert_eq!(parse_address_list("evil@x.com:ok@ok.com"), None);
    assert_eq!(recipients_from_header_block("To: evil@evil.com g: ok@ok.com;"), None);
    assert_eq!(parse_address_list("Team: a@x.com;").unwrap(), ["a@x.com"]);
}

fn ch(v: Value) -> EmailChange {
    parse_change(&v).unwrap()
}

fn ap(r: &EmailRules, v: Value) -> EmailRules {
    apply_change(r, &ch(v)).unwrap()
}

#[test]
fn rules_widening_needs_a_code_narrowing_and_limits_do_not() {
    let base = EmailRules::default();
    let sender = ap(
        &base,
        json!({"action": "add_sender", "entry": {"value": "Bob@Y.com", "mailbox": null}}),
    );
    assert_eq!(sender.inbound.senders[0].value, "bob@y.com");
    assert!(widens(&base, &sender));
    assert!(!widens(&sender, &base));
    assert!(widens(
        &base,
        &ap(
            &base,
            json!({"action": "add_recipient", "entry": {"value": "@acme.com", "mailbox": null}})
        )
    ));
    assert!(!widens(
        &base,
        &ap(&base, json!({"action": "set_outbound", "perHour": 200, "perDay": 2000}))
    ));
    let listed_only = ap(&base, json!({"action": "set_outbound", "mode": "listed"}));
    assert!(!widens(&base, &listed_only));
    assert!(widens(&listed_only, &base));
    let strict = ap(&base, json!({"action": "set_inbound_auth", "requireAuth": "dmarc"}));
    assert!(!widens(&base, &strict));
    assert!(widens(&strict, &base));
    let no_replies = ap(&base, json!({"action": "set_outbound", "repliesToSenders": false}));
    assert!(widens(&no_replies, &base));
    let mb = "agentmail:ana@agentmail.to";
    let blocked = ap(
        &base,
        json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "block"}),
    );
    assert_eq!(effective_mode(&blocked, mb), Mode::Block);
    assert_eq!(effective_mode(&blocked, "gmail:o@x.com"), Mode::Ask);
    assert!(!widens(&base, &blocked));
    assert!(widens(
        &blocked,
        &ap(
            &blocked,
            json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": null})
        )
    ));
    assert_eq!(
        effective_mode(
            &ap(
                &listed_only,
                json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "ask"})
            ),
            mb
        ),
        Mode::Listed
    );
    let anyone = ap(&base, json!({"action": "set_outbound", "mode": "anyone"}));
    assert!(widens(&base, &anyone));
    assert!(widens(&listed_only, &anyone));
    assert!(!widens(&anyone, &base));
    assert!(!widens(
        &anyone,
        &ap(&anyone, json!({"action": "set_outbound", "mode": "block"}))
    ));
    let one_asks = ap(
        &anyone,
        json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "ask"}),
    );
    assert!(!widens(&anyone, &one_asks));
    assert_eq!(effective_mode(&one_asks, mb), Mode::Ask);
    assert_eq!(effective_mode(&one_asks, "gmail:o@x.com"), Mode::Anyone);
    assert!(widens(
        &one_asks,
        &ap(
            &one_asks,
            json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "anyone"})
        )
    ));
    assert!(widens(
        &one_asks,
        &ap(
            &one_asks,
            json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": null})
        )
    ));
    let one_anyone = ap(
        &base,
        json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "anyone"}),
    );
    assert_eq!(effective_mode(&one_anyone, mb), Mode::Ask);
    assert!(!widens(&base, &one_anyone));
    assert!(widens(
        &one_anyone,
        &ap(&one_anyone, json!({"action": "set_outbound", "mode": "anyone"}))
    ));
    assert_eq!(
        describe_change(&ch(json!({"action": "set_outbound", "mode": "anyone"})), None),
        "Agents will be able to email anyone, with no list and no request to you"
    );
    assert_eq!(
        describe_change(
            &ch(json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "anyone"})),
            None
        ),
        "ana@agentmail.to will be able to email anyone, with no list and no request to you"
    );
    let follow = ch(json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": null}));
    assert_eq!(
        describe_change(&follow, Some(&apply_change(&one_asks, &follow).unwrap())),
        "ana@agentmail.to will follow the organization setting and be able to email anyone, with no list and no request to you"
    );
    assert_eq!(
        describe_change(&follow, Some(&apply_change(&blocked, &follow).unwrap())),
        "ana@agentmail.to will follow the organization setting"
    );
    let one_listed = ap(
        &base,
        json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "listed"}),
    );
    let loosen = ch(json!({"action": "set_mailbox_mode", "mailbox": mb, "mode": "anyone"}));
    assert!(widens(&one_listed, &apply_change(&one_listed, &loosen).unwrap()));
    assert_eq!(
        describe_change(&loosen, Some(&apply_change(&one_listed, &loosen).unwrap())),
        "ana@agentmail.to will ask before emailing someone new"
    );
    assert!(
        apply_change(
            &sender,
            &ch(json!({"action": "add_sender", "entry": {"value": "bob@y.com", "mailbox": null}}))
        )
        .is_err()
    );
    assert!(
        parse_change(&json!({"action": "add_sender", "entry": {"value": "not-an-address", "mailbox": null}})).is_none()
    );
    assert!(listed(&sender.inbound.senders, "BOB@y.com", mb));
    let e = |mailbox: Option<&str>| RuleEntry {
        value: "@y.com".into(),
        mailbox: mailbox.map(str::to_string),
    };
    assert!(listed(&[e(Some(mb))], "eve@y.com", mb));
    assert!(!listed(&[e(Some(mb))], "eve@y.com", "gmail:o@x.com"));
    assert!(!listed(&[e(None)], "eve@sub.y.com", mb));
    // Defaults.
    assert_eq!(base.outbound.mode, Mode::Ask);
    assert_eq!((base.outbound.per_hour, base.outbound.per_day), (20, 100));
    assert!(base.outbound.replies_to_senders);
    assert_eq!(base.inbound.require_auth, RequireAuth::Aligned);
}

// ---- the module --------------------------------------------------------------------------------

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
                expires_at_ms: 600_000,
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

#[derive(Default)]
struct Fake {
    messages: Mutex<HashMap<String, Map<String, Value>>>,
    drafts: Mutex<HashMap<String, Map<String, Value>>>,
    account: Option<String>,
    /// A draft lookup that never answers.
    hang: std::sync::atomic::AtomicBool,
}

impl EmailLookups for Arc<Fake> {
    fn agentmail_message(&self, _: &str, id: &str) -> BoxFuture<Result<Map<String, Value>, ()>> {
        let r = self.messages.lock().unwrap().get(id).cloned().ok_or(());
        Box::pin(async move { r })
    }
    fn agentmail_draft(&self, _: &str, id: &str) -> BoxFuture<Result<Map<String, Value>, ()>> {
        let r = self.drafts.lock().unwrap().get(id).cloned().unwrap_or_default();
        let hang = self.hang.load(Ordering::SeqCst);
        Box::pin(async move {
            if hang {
                std::future::pending::<()>().await;
            }
            Ok(r)
        })
    }
    fn gmail_draft_head(&self, _: &str) -> BoxFuture<Result<String, ()>> {
        Box::pin(async { Ok("To: drafted@y.com\r\nBcc: secret@z.com".to_string()) })
    }
    fn gmail_account(&self) -> Option<String> {
        self.account.clone()
    }
}

type Legacy = Option<Vec<(String, Vec<String>)>>;

struct Setup {
    dir: tempfile::TempDir,
    codes: Arc<Codes>,
    grants: Arc<Mutex<HashSet<String>>>,
    scoped: Arc<Mutex<HashMap<String, String>>>,
    fake: Arc<Fake>,
    now: Arc<AtomicI64>,
    legacy: Arc<Mutex<Legacy>>,
}

fn setup(legacy: Legacy, account: Option<&str>) -> Setup {
    Setup {
        dir: tempfile::tempdir().unwrap(),
        codes: Arc::default(),
        grants: Arc::default(),
        scoped: Arc::default(),
        fake: Arc::new(Fake {
            account: account.map(str::to_string),
            ..Default::default()
        }),
        now: Arc::new(AtomicI64::new(1_800_000_000_000)),
        legacy: Arc::new(Mutex::new(legacy)),
    }
}

fn plain() -> Setup {
    setup(Some(vec![]), Some("owner@gmail.com"))
}

impl Setup {
    fn make(&self) -> Arc<EmailRulesFirewall> {
        let (codes, grants, scoped, now, legacy) = (
            self.codes.clone(),
            self.grants.clone(),
            self.scoped.clone(),
            self.now.clone(),
            self.legacy.clone(),
        );
        let g2 = grants.clone();
        EmailRulesFirewall::new(EmailOptions {
            store_path: self.dir.path().join("email-rules.enc"),
            counters_path: self.dir.path().join("email-counters.json"),
            log_path: Some(self.dir.path().join("traffic.log")),
            box_key: KEY.into(),
            org_id: "org".into(),
            box_id: "box".into(),
            codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
            code_routes: Arc::new(|| {
                Ok(vec![json!({"target": {"vmId": "a", "hostname": "a.example.com"}, "senders": [{"type": "telegram", "id": "1", "label": "Owner"}]})])
            }),
            lookups: Arc::new(self.fake.clone()),
            grant_active: Arc::new(move |id| grants.lock().unwrap().contains(id)),
            revoke_grants: Some(Arc::new(move |matches| {
                let mut out = vec![];
                let mut g = g2.lock().unwrap();
                for (id, scope) in scoped.lock().unwrap().iter() {
                    if g.contains(id) && matches(scope) {
                        g.remove(id);
                        out.push(scope.clone());
                    }
                }
                out
            })),
            legacy_senders: Some(Arc::new(move || Ok(legacy.lock().unwrap().clone()))),
            on_changed: None,
            now: Arc::new(move || now.load(Ordering::SeqCst)),
        })
        .unwrap()
    }
    fn grant(&self, scope: &str) {
        let id = permission_id_for(scope);
        self.grants.lock().unwrap().insert(id.clone());
        self.scoped.lock().unwrap().insert(id, scope.into());
    }
    fn tick(&self, ms: i64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }
    fn sent(&self) -> String {
        self.codes.sent.lock().unwrap().join("\n")
    }
    fn log(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("traffic.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

async fn cmd(fw: &EmailRulesFirewall, action: &str, p: Value) -> CommandOutcome {
    fw.command(action, m(p)).await
}

async fn widen(fw: &EmailRulesFirewall, id: &str, change: Value) {
    assert_eq!(
        cmd(fw, "propose", json!({"changeId": id, "change": change}))
            .await
            .status,
        "awaiting_code"
    );
    assert_eq!(
        cmd(fw, "confirm", json!({"changeId": id, "code": "123456"}))
            .await
            .status,
        "applied"
    );
}

async fn narrow(fw: &EmailRulesFirewall, id: &str, change: Value) {
    assert_eq!(
        cmd(fw, "propose", json!({"changeId": id, "change": change}))
            .await
            .status,
        "applied"
    );
}

async fn reserve(fw: &EmailRulesFirewall, p: Value) -> Value {
    let mut base = m(json!({"action": "email.reserve", "vmId": "vm"}));
    base.extend(m(p));
    Value::Object(fw.reserve(&parse_reserve(&base).unwrap()).await.to_json())
}

const INBOX: &str = "ana@agentmail.to";

async fn send(fw: &EmailRulesFirewall, to: Value) -> Value {
    reserve(
        fw,
        json!({"provider": "agentmail", "inboxId": INBOX, "op": "send", "to": to}),
    )
    .await
}

fn scope_of(d: &Value, i: usize) -> String {
    d["asks"][i]["scope"].as_str().unwrap_or("").to_string()
}

fn settle(fw: &EmailRulesFirewall, d: &Value, rejected: bool) {
    fw.settle(d["id"].as_str().unwrap(), rejected);
}

#[tokio::test]
async fn propose_code_confirm_migration_and_persistence() {
    let s = setup(
        Some(vec![(
            "Ana@agentmail.to".into(),
            vec!["owner@x.com".into(), "Boss@x.com".into()],
        )]),
        Some("owner@gmail.com"),
    );
    let fw = s.make();
    let mb = "agentmail:ana@agentmail.to";
    assert_eq!(
        serde_json::to_value(&fw.rules().inbound.senders).unwrap(),
        json!([{"value": "owner@x.com", "mailbox": mb}, {"value": "boss@x.com", "mailbox": mb}])
    );
    assert_eq!(fw.allow_from(INBOX), ["owner@x.com", "boss@x.com"]);
    let pending = cmd(
        &fw,
        "propose",
        json!({"changeId": "c1", "change": {"action": "add_sender", "entry": {"value": "@acme.com", "mailbox": null}}}),
    )
    .await;
    assert_eq!(pending.status, "awaiting_code");
    assert!(s.sent().contains("Let anyone at acme.com email your agents"));
    assert_eq!(fw.rules().inbound.senders.len(), 2);
    assert_eq!(
        cmd(&fw, "confirm", json!({"changeId": "c1", "code": "000000"}))
            .await
            .status,
        "invalid"
    );
    assert_eq!(
        cmd(&fw, "confirm", json!({"changeId": "c1", "code": "123456"}))
            .await
            .status,
        "applied"
    );
    assert_eq!(fw.allow_from(INBOX), ["*"]);
    narrow(
        &fw,
        "c2",
        json!({"action": "remove_sender", "entry": {"value": "boss@x.com", "mailbox": mb}}),
    )
    .await;
    narrow(&fw, "c3", json!({"action": "set_outbound", "perHour": 5})).await;
    assert_eq!(
        cmd(
            &fw,
            "propose",
            json!({"changeId": "c4", "change": {"action": "add_sender", "entry": {"value": "nope"}}})
        )
        .await
        .status,
        "failed"
    );
    // Survives a restart, and the migration does not run twice.
    let again = s.make();
    assert_eq!(again.rules().inbound.senders.len(), 2);
    assert_eq!(again.rules().outbound.per_hour, 5);
    assert!(
        !std::fs::read_to_string(s.dir.path().join("email-rules.enc"))
            .unwrap()
            .contains("acme")
    );
}

#[tokio::test]
async fn nobody_to_send_a_code_to_refuses_a_widening() {
    let s = plain();
    let codes = s.codes.clone();
    let fw = EmailRulesFirewall::new(EmailOptions {
        store_path: s.dir.path().join("email-rules.enc"),
        counters_path: s.dir.path().join("email-counters.json"),
        log_path: None,
        box_key: KEY.into(),
        org_id: "org".into(),
        box_id: "box".into(),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
        code_routes: Arc::new(|| Ok(vec![])),
        lookups: Arc::new(s.fake.clone()),
        grant_active: Arc::new(|_| false),
        revoke_grants: None,
        legacy_senders: None,
        on_changed: None,
        now: Arc::new(|| 0),
    })
    .unwrap();
    let r = cmd(
        &fw,
        "propose",
        json!({"changeId": "c", "change": {"action": "set_outbound", "mode": "anyone"}}),
    )
    .await;
    assert_eq!(r.status, "failed");
    assert_eq!(
        r.message.as_deref(),
        Some("No confirmation code could be delivered. Add a recipient on the Firewall page.")
    );
    assert_eq!(fw.rules().outbound.mode, Mode::Ask);
    // Narrowing still applies.
    narrow(&fw, "d", json!({"action": "set_outbound", "mode": "listed"})).await;
}

#[tokio::test]
async fn outbound_listed_replies_ask_with_one_window_grants_block_limits() {
    let s = plain();
    let fw = s.make();
    widen(
        &fw,
        "a",
        json!({"action": "add_sender", "entry": {"value": "boss@x.com", "mailbox": null}}),
    )
    .await;
    let ok = send(&fw, json!("Boss <boss@x.com>")).await;
    assert_eq!(ok["decision"], "allow");
    settle(&fw, &ok, false);
    let ask = send(&fw, json!(["new@y.com", "boss@x.com"])).await;
    assert_eq!(
        ask,
        json!({"decision": "ask", "asks": [{"scope": format!("EMAIL agentmail:{INBOX} -> new@y.com"), "summary": format!("Send email to new@y.com from {INBOX}"), "recipient": "new@y.com", "mailbox": format!("agentmail:{INBOX}")}]})
    );
    assert_eq!(send(&fw, json!("new@y.com")).await, ask);
    s.grants.lock().unwrap().insert(permission_id_for(&recipient_scope(
        &format!("agentmail:{INBOX}"),
        "new@y.com",
        0,
    )));
    assert_eq!(send(&fw, json!("new@y.com")).await["decision"], "allow");
    s.grants.lock().unwrap().clear();
    assert_eq!(
        scope_of(&send(&fw, json!("new@y.com")).await, 0),
        format!("EMAIL agentmail:{INBOX} -> new@y.com #1")
    );
    s.tick(61 * 60_000);
    assert_eq!(
        scope_of(&send(&fw, json!("new@y.com")).await, 0),
        format!("EMAIL agentmail:{INBOX} -> new@y.com #2")
    );

    s.fake.messages.lock().unwrap().insert(
        "m1".into(),
        m(json!({"from": "Stranger <stranger@z.com>", "reply_to": [], "to": [INBOX], "cc": ["boss@x.com", "cc@z.com"]})),
    );
    let reply = reserve(
        &fw,
        json!({"provider": "agentmail", "inboxId": INBOX, "op": "reply", "messageId": "m1"}),
    )
    .await;
    assert_eq!(reply["asks"].as_array().unwrap().len(), 1);
    assert!(scope_of(&reply, 0).ends_with("-> stranger@z.com"));
    let all = reserve(
        &fw,
        json!({"provider": "agentmail", "inboxId": INBOX, "op": "reply_all", "messageId": "m1"}),
    )
    .await;
    let who: Vec<_> = all["asks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["recipient"].clone())
        .collect();
    assert_eq!(who, [json!("stranger@z.com"), json!("cc@z.com")]);
    s.fake
        .drafts
        .lock()
        .unwrap()
        .insert("d1".into(), m(json!({"to": ["boss@x.com"], "bcc": "hidden@evil.com"})));
    let draft = reserve(
        &fw,
        json!({"provider": "agentmail", "inboxId": INBOX, "op": "draft_send", "draftId": "d1"}),
    )
    .await;
    assert!(scope_of(&draft, 0).ends_with("hidden@evil.com"));
    assert_eq!(
        reserve(
            &fw,
            json!({"provider": "agentmail", "inboxId": INBOX, "op": "reply", "messageId": "gone"})
        )
        .await,
        json!({"decision": "block", "reason": "lookup_failed"})
    );

    let g = reserve(
        &fw,
        json!({"provider": "gmail", "op": "send", "head": "To: boss@x.com\r\nBcc: secret@z.com"}),
    )
    .await;
    assert_eq!(scope_of(&g, 0), "EMAIL gmail:owner@gmail.com -> secret@z.com");
    let gd = reserve(&fw, json!({"provider": "gmail", "op": "draft_send", "draftId": "r1"})).await;
    let who: Vec<_> = gd["asks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["recipient"].clone())
        .collect();
    assert_eq!(who, [json!("drafted@y.com"), json!("secret@z.com")]);
    assert_eq!(
        reserve(
            &fw,
            json!({"provider": "gmail", "op": "send", "head": "To: a@x.com\r\nResent-To: b@y.com"})
        )
        .await,
        json!({"decision": "block", "reason": "unreadable_recipients"})
    );
    let many: Vec<String> = (0..21).map(|i| format!("p{i}@x.com")).collect();
    assert_eq!(
        send(&fw, json!(many)).await,
        json!({"decision": "block", "reason": "too_many_recipients"})
    );
    assert_eq!(
        send(&fw, json!("not an address")).await,
        json!({"decision": "block", "reason": "unreadable_recipients"})
    );

    // anyone: asked for with a code that says so; then no list check and no request.
    assert_eq!(
        cmd(
            &fw,
            "propose",
            json!({"changeId": "any", "change": {"action": "set_outbound", "mode": "anyone"}})
        )
        .await
        .status,
        "awaiting_code"
    );
    assert!(
        s.sent()
            .contains("Agents will be able to email anyone, with no list and no request to you")
    );
    assert_eq!(send(&fw, json!("fresh@y.com")).await["decision"], "ask");
    assert_eq!(
        cmd(&fw, "confirm", json!({"changeId": "any", "code": "123456"}))
            .await
            .status,
        "applied"
    );
    let free = send(&fw, json!(["fresh@y.com", "other@z.com"])).await;
    assert_eq!(free["decision"], "allow");
    settle(&fw, &free, false);
    let gfree = reserve(
        &fw,
        json!({"provider": "gmail", "op": "send", "head": "To: nobody-knows@z.com\r\nBcc: secret@z.com"}),
    )
    .await;
    assert_eq!(gfree["decision"], "allow");
    settle(&fw, &gfree, true);
    assert_eq!(
        send(&fw, json!(many)).await,
        json!({"decision": "block", "reason": "too_many_recipients"})
    );
    narrow(&fw, "back", json!({"action": "set_outbound", "mode": "ask"})).await;
    assert_eq!(send(&fw, json!("fresh@y.com")).await["decision"], "ask");

    narrow(&fw, "b", json!({"action": "set_outbound", "mode": "listed"})).await;
    assert_eq!(
        send(&fw, json!("new@y.com")).await,
        json!({"decision": "block", "reason": "not_allowed"})
    );
    narrow(
        &fw,
        "c",
        json!({"action": "set_mailbox_mode", "mailbox": format!("agentmail:{INBOX}"), "mode": "block"}),
    )
    .await;
    assert_eq!(
        send(&fw, json!("boss@x.com")).await,
        json!({"decision": "block", "reason": "sending_off"})
    );
}

#[tokio::test]
async fn a_removal_bites_on_the_next_send_approvals_included() {
    let s = plain();
    let fw = s.make();
    let mb = format!("agentmail:{INBOX}");
    widen(
        &fw,
        "a",
        json!({"action": "add_recipient", "entry": {"value": "listed@x.com", "mailbox": null}}),
    )
    .await;
    let mixed = reserve(
        &fw,
        json!({"provider": "agentmail", "inboxId": INBOX, "op": "send", "to": "listed@x.com", "bcc": "new@y.com"}),
    )
    .await;
    assert_eq!(mixed["decision"], "ask");
    assert_eq!(mixed["asks"].as_array().unwrap().len(), 1);
    assert_eq!(mixed["asks"][0]["recipient"], "new@y.com");
    let gmixed = reserve(
        &fw,
        json!({"provider": "gmail", "op": "send", "head": "To: listed@x.com\r\nCc: new@y.com"}),
    )
    .await;
    assert_eq!(gmixed["decision"], "ask");
    narrow(&fw, "l", json!({"action": "set_outbound", "mode": "listed"})).await;
    assert_eq!(
        reserve(
            &fw,
            json!({"provider": "agentmail", "inboxId": INBOX, "op": "send", "to": "listed@x.com", "cc": "new@y.com"})
        )
        .await,
        json!({"decision": "block", "reason": "not_allowed"})
    );
    widen(&fw, "k", json!({"action": "set_outbound", "mode": "ask"})).await;

    assert_eq!(send(&fw, json!("listed@x.com")).await["decision"], "allow");
    narrow(
        &fw,
        "r",
        json!({"action": "remove_recipient", "entry": {"value": "listed@x.com", "mailbox": null}}),
    )
    .await;
    assert_eq!(send(&fw, json!("listed@x.com")).await["decision"], "ask");

    // "Always allow": approved once and listed. Removing the entry ends both.
    let scope = scope_of(&send(&fw, json!("bob@y.com")).await, 0);
    s.grant(&scope);
    widen(
        &fw,
        "b",
        json!({"action": "add_recipient", "entry": {"value": "bob@y.com", "mailbox": mb}}),
    )
    .await;
    assert_eq!(send(&fw, json!("bob@y.com")).await["decision"], "allow");
    s.tick(1000);
    narrow(
        &fw,
        "c",
        json!({"action": "remove_recipient", "entry": {"value": "bob@y.com", "mailbox": mb}}),
    )
    .await;
    assert!(s.grants.lock().unwrap().is_empty());
    assert_eq!(scope_of(&send(&fw, json!("bob@y.com")).await, 0), format!("{scope} #1"));
    s.grant(&scope);
    assert_eq!(send(&fw, json!("bob@y.com")).await["decision"], "ask");

    // Approved in the console but not yet polled: the late grant does not count for the old id.
    let late = scope_of(&send(&fw, json!("dave@y.com")).await, 0);
    widen(
        &fw,
        "h",
        json!({"action": "add_recipient", "entry": {"value": "dave@y.com", "mailbox": mb}}),
    )
    .await;
    s.tick(1000);
    narrow(
        &fw,
        "i",
        json!({"action": "remove_recipient", "entry": {"value": "dave@y.com", "mailbox": mb}}),
    )
    .await;
    s.grant(&late);
    let restarted = s.make();
    assert_eq!(
        scope_of(&send(&restarted, json!("dave@y.com")).await, 0),
        format!("{late} #1")
    );
    s.grant(&format!("{late} #1"));
    s.tick(1000);
    assert_eq!(send(&restarted, json!("dave@y.com")).await["decision"], "allow");

    // An approve-once for someone never listed survives an unrelated removal.
    let other = scope_of(&send(&fw, json!("carol@y.com")).await, 0);
    s.grant(&other);
    widen(
        &fw,
        "d",
        json!({"action": "add_recipient", "entry": {"value": "@z.com", "mailbox": null}}),
    )
    .await;
    narrow(
        &fw,
        "e",
        json!({"action": "remove_recipient", "entry": {"value": "@z.com", "mailbox": null}}),
    )
    .await;
    assert_eq!(send(&fw, json!("carol@y.com")).await["decision"], "allow");

    // Removing a sender ends the reply allowance and its approval.
    widen(
        &fw,
        "f",
        json!({"action": "add_sender", "entry": {"value": "@y.com", "mailbox": null}}),
    )
    .await;
    narrow(
        &fw,
        "g",
        json!({"action": "remove_sender", "entry": {"value": "@y.com", "mailbox": null}}),
    )
    .await;
    assert_eq!(send(&fw, json!("carol@y.com")).await["decision"], "ask");
}

#[tokio::test]
async fn rate_limits_count_sends_and_survive_a_restart() {
    let s = plain();
    let fw = s.make();
    widen(
        &fw,
        "a",
        json!({"action": "add_recipient", "entry": {"value": "@x.com", "mailbox": null}}),
    )
    .await;
    narrow(&fw, "b", json!({"action": "set_outbound", "perHour": 2, "perDay": 3})).await;
    let go = |fw: Arc<EmailRulesFirewall>, to: Value| async move {
        reserve(
            &fw,
            json!({"provider": "agentmail", "inboxId": "a@agentmail.to", "op": "send", "to": to}),
        )
        .await
    };
    let one = go(fw.clone(), json!(["a@x.com", "b@x.com"])).await;
    settle(&fw, &one, true);
    let two = go(fw.clone(), json!(["a@x.com", "b@x.com"])).await;
    let three = go(fw.clone(), json!(["a@x.com", "b@x.com"])).await;
    assert_eq!(
        go(fw.clone(), json!(["a@x.com"])).await,
        json!({"decision": "block", "reason": "hourly_limit"})
    );
    settle(&fw, &two, false);
    settle(&fw, &three, false);
    s.tick(61 * 60_000);
    let restarted = s.make();
    let four = go(restarted.clone(), json!("a@x.com")).await;
    assert_eq!(four["decision"], "allow");
    settle(&restarted, &four, false);
    assert_eq!(
        go(restarted.clone(), json!("a@x.com")).await,
        json!({"decision": "block", "reason": "daily_limit"})
    );
    assert_eq!(
        reserve(
            &restarted,
            json!({"provider": "gmail", "op": "send", "head": "To: a@x.com"})
        )
        .await["decision"],
        "allow"
    );
    assert!(
        !std::fs::read_to_string(s.dir.path().join("email-counters.json"))
            .unwrap()
            .contains("agentmail.to")
    );
}

#[tokio::test]
async fn anyone_the_limits_still_apply() {
    let s = plain();
    let fw = s.make();
    widen(&fw, "a", json!({"action": "set_outbound", "mode": "anyone"})).await;
    narrow(&fw, "b", json!({"action": "set_outbound", "perHour": 2, "perDay": 3})).await;
    for n in [1, 2] {
        let d = send(&fw, json!(format!("stranger{n}@y.com"))).await;
        settle(&fw, &d, false);
    }
    assert_eq!(
        send(&fw, json!("stranger3@y.com")).await,
        json!({"decision": "block", "reason": "hourly_limit"})
    );
    s.tick(61 * 60_000);
    let d = send(&fw, json!("stranger4@y.com")).await;
    settle(&fw, &d, false);
    assert_eq!(
        send(&fw, json!("stranger5@y.com")).await,
        json!({"decision": "block", "reason": "daily_limit"})
    );
}

async fn ask(fw: &EmailRulesFirewall, items: Value) -> Value {
    let items: Vec<Map<String, Value>> = items.as_array().unwrap().iter().map(|i| m(i.clone())).collect();
    Value::Array(
        fw.inbound(INBOX, &items)
            .await
            .iter()
            .map(InboundAction::to_json)
            .collect(),
    )
}

#[tokio::test]
async fn inbound_keep_strip_hide_held_counts_and_gmail_verdicts() {
    let s = setup(
        Some(vec![(INBOX.into(), vec!["inbox.owner@gmail.com".into()])]),
        Some("owner@gmail.com"),
    );
    let fw = s.make();
    let g = am_genuine();
    let entry =
        json!({"kind": "message", "message_id": "<m1@mail.gmail.com>", "from": g["from"], "labels": ["received"]});
    assert_eq!(
        ask(&fw, json!([entry])).await,
        json!([{"action": "strip", "reason": "unverified"}])
    );
    let mut full = g.clone();
    full.insert("kind".into(), json!("message"));
    assert_eq!(ask(&fw, json!([full])).await, json!([{"action": "keep"}]));
    assert_eq!(ask(&fw, json!([entry])).await, json!([{"action": "keep"}]));
    let forged = with(
        &full,
        json!({"message_id": "f1", "authentication_results": {"spf": "softfail", "dkim": "none", "dmarc": "fail"}}),
    );
    let hidden = json!([{"action": "hide", "reason": "unauthenticated"}]);
    assert_eq!(ask(&fw, json!([forged])).await, hidden);
    let mut e2 = entry.clone();
    e2["message_id"] = json!("f1");
    assert_eq!(ask(&fw, json!([e2])).await, hidden);
    assert_eq!(ask(&fw, json!([{"kind": "ref", "message_id": "f1"}])).await, hidden);
    assert_eq!(
        ask(
            &fw,
            json!([with(&full, json!({"message_id": "s1", "from": "x@gmail.com"}))])
        )
        .await,
        json!([{"action": "hide", "reason": "not_allowed"}])
    );
    let mut spam = entry.clone();
    spam["message_id"] = json!("s2");
    spam["labels"] = json!(["received", "spam"]);
    assert_eq!(ask(&fw, json!([spam])).await, hidden);
    assert_eq!(
        ask(
            &fw,
            json!([{"kind": "message", "message_id": "o1", "from": INBOX, "labels": ["sent"], "text": "mine"}])
        )
        .await,
        json!([{"action": "keep"}])
    );
    s.fake
        .messages
        .lock()
        .unwrap()
        .insert("r1".into(), with(&g, json!({"message_id": "r1"})));
    assert_eq!(
        ask(&fw, json!([{"kind": "ref", "message_id": "r1"}])).await,
        json!([{"action": "keep"}])
    );
    assert_eq!(
        ask(&fw, json!([{"kind": "ref", "message_id": "missing"}])).await,
        json!([{"action": "hide", "reason": "lookup_failed"}])
    );
    assert_eq!(
        ask(
            &fw,
            json!([{"kind": "thread", "senders": [g["from"], INBOX], "labels": []}])
        )
        .await,
        json!([{"action": "strip"}])
    );
    assert_eq!(
        ask(
            &fw,
            json!([{"kind": "thread", "senders": ["evil@x.com"], "labels": []}])
        )
        .await,
        json!([{"action": "hide", "reason": "not_allowed"}])
    );
    assert_eq!(
        ask(&fw, json!([{"kind": "thread", "senders": [INBOX], "labels": []}])).await,
        json!([{"action": "strip"}])
    );

    let inbox_label = vec!["INBOX".to_string()];
    assert_eq!(
        fw.gmail_inbound(&default_headers(), &inbox_label),
        (false, Some("not_allowed"), Some("agent12@agentmail.to".into()))
    );
    widen(
        &fw,
        "g",
        json!({"action": "add_sender", "entry": {"value": "agent12@agentmail.to", "mailbox": "gmail:owner@gmail.com"}}),
    )
    .await;
    assert_eq!(
        fw.gmail_inbound(&default_headers(), &inbox_label),
        (true, None, Some("agent12@agentmail.to".into()))
    );
    assert!(s.make().gmail_inbound(&default_headers(), &[]).0);
    assert_eq!(
        setup(Some(vec![]), None)
            .make()
            .gmail_inbound(&default_headers(), &[])
            .1,
        Some("no_account")
    );

    let held = fw.summary()["held"].as_array().unwrap().clone();
    assert!(
        held.iter()
            .any(|x| x["reason"] == "unauthenticated" && x["domain"] == "gmail.com" && x["count"] == 1)
    );
    assert!(
        held.iter()
            .any(|x| x["reason"] == "not_allowed" && x["mailbox"] == "gmail:owner@gmail.com")
    );

    let log = s.log();
    assert!(log.len() >= 3);
    assert!(
        log.iter()
            .all(|l| l["source"] == "email_held" && l["direction"] == "in" && l["id"].is_string())
    );
    let kinds: HashSet<String> = log
        .iter()
        .map(|l| format!("{}:{}", l["provider"].as_str().unwrap(), l["reason"].as_str().unwrap()))
        .collect();
    let want: HashSet<String> = held
        .iter()
        .map(|x| {
            format!(
                "{}:{}",
                x["mailbox"].as_str().unwrap().split(':').next().unwrap(),
                x["reason"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(kinds, want);
    for l in &log {
        let mut l = l.clone();
        l["provider"] = Value::Null;
        let t = l.to_string();
        assert!(
            !t.contains('@') && !t.contains("gmail.com") && !t.contains("agentmail.to"),
            "no address or domain"
        );
    }
    // The same message held twice is one line id.
    let g2 = plain();
    let gfw = g2.make();
    let mut with_id = default_headers();
    with_id.push(h("Message-ID", "<twice@mail.example.com>"));
    gfw.gmail_inbound(&with_id, &[]);
    gfw.gmail_inbound(&with_id, &[]);
    let twice = g2.log();
    assert_eq!(twice.len(), 2);
    assert_eq!(twice[0]["id"], twice[1]["id"]);
    let mut no_id = default_headers();
    no_id.push(h("Date", "Mon, 26 Oct 2026 10:00:00 +0000"));
    no_id.push(h("Subject", "hello"));
    gfw.gmail_inbound(&no_id, &[]);
    gfw.gmail_inbound(&no_id, &[]);
    let four = g2.log();
    assert_eq!(four[2]["id"], four[3]["id"]);
    assert_ne!(four[2]["id"], four[0]["id"]);
    assert!(!Value::Array(four).to_string().contains("hello"));
}

#[tokio::test]
async fn the_move_waits_for_a_readable_store_and_new_inboxes_get_the_owner_once() {
    let s = setup(None, Some("owner@gmail.com"));
    let fw = s.make();
    assert!(fw.rules().inbound.senders.is_empty());
    fw.seed_inbox("new@agentmail.to", Some("owner@x.com"));
    assert!(fw.rules().inbound.senders.is_empty(), "no seeding before the move");
    *s.legacy.lock().unwrap() = Some(vec![("old@agentmail.to".into(), vec!["boss@x.com".into()])]);
    let later = s.make();
    assert_eq!(
        serde_json::to_value(&later.rules().inbound.senders).unwrap(),
        json!([{"value": "boss@x.com", "mailbox": "agentmail:old@agentmail.to"}])
    );
    later.seed_inbox("old@agentmail.to", Some("owner@x.com"));
    assert_eq!(
        later.rules().inbound.senders.len(),
        1,
        "inboxes that were moved are not seeded again"
    );
    later.seed_inbox("New@agentmail.to", Some("owner@x.com"));
    assert_eq!(later.allow_from("new@agentmail.to"), ["owner@x.com"]);
    narrow(
        &later,
        "r",
        json!({"action": "remove_sender", "entry": {"value": "owner@x.com", "mailbox": "agentmail:new@agentmail.to"}}),
    )
    .await;
    later.seed_inbox("new@agentmail.to", Some("owner@x.com"));
    assert!(later.allow_from("new@agentmail.to").is_empty());
}

#[tokio::test]
async fn draft_lock_one_approval_window_and_verdicts_follow_the_rules() {
    let s = plain();
    let fw = s.make();
    s.fake
        .drafts
        .lock()
        .unwrap()
        .insert("d1".into(), m(json!({"to": ["boss@x.com"]})));
    widen(
        &fw,
        "a",
        json!({"action": "add_recipient", "entry": {"value": "boss@x.com", "mailbox": null}}),
    )
    .await;
    let d = json!({"provider": "agentmail", "inboxId": INBOX, "op": "draft_send", "draftId": "d1"});
    let sent = reserve(&fw, d.clone()).await;
    assert_eq!(sent["decision"], "allow");
    assert!(!fw.draft_write("agentmail", Some(INBOX), "d1"));
    assert_eq!(
        reserve(&fw, d).await,
        json!({"decision": "block", "reason": "draft_busy"})
    );
    settle(&fw, &sent, false);
    assert!(fw.draft_write("agentmail", Some(INBOX), "d1"));

    let scope = recipient_scope(&format!("agentmail:{INBOX}"), "new@y.com", 0);
    s.grants.lock().unwrap().insert(permission_id_for(&scope));
    assert_eq!(send(&fw, json!("new@y.com")).await["decision"], "allow");
    s.tick(31 * 60_000);
    assert_eq!(
        scope_of(&send(&s.make(), json!("new@y.com")).await, 0),
        format!("{scope} #1")
    );

    let msg = json!({"kind": "message", "message_id": "v1", "from": "Pat <pat@gmail.com>", "labels": ["received"], "authentication_results": {"dmarc": "pass"}, "text": "x"});
    assert_eq!(ask(&fw, json!([msg])).await[0]["action"], "hide");
    widen(
        &fw,
        "b",
        json!({"action": "add_sender", "entry": {"value": "pat@gmail.com", "mailbox": null}}),
    )
    .await;
    assert_eq!(
        ask(&fw, json!([{"kind": "ref", "message_id": "v1"}])).await,
        json!([{"action": "hide", "reason": "lookup_failed"}])
    );
}

#[test]
fn the_proxys_inputs_are_checked_as_zod_does() {
    let base = |over: Value| {
        let mut b = m(json!({"action": "email.reserve", "vmId": "vm", "provider": "agentmail", "op": "send"}));
        b.extend(m(over));
        parse_reserve(&b)
    };
    assert!(base(json!({})).is_ok());
    assert!(base(json!({"provider": "smtp"})).is_err());
    assert!(base(json!({"op": "bounce"})).is_err());
    assert!(base(json!({"vmId": ""})).is_err());
    assert!(base(json!({"inboxId": null})).is_err(), "null is not undefined");
    assert!(base(json!({"to": null})).is_ok());
    assert!(
        parse_inbound(&m(
            json!({"action": "email.inbound", "provider": "agentmail", "inboxId": "a", "items": [1]})
        ))
        .is_err()
    );
    assert!(
        parse_inbound(&m(
            json!({"action": "email.inbound", "provider": "gmail", "inboxId": "a", "items": []})
        ))
        .is_err()
    );
}

#[tokio::test]
async fn the_8792_listener_answers_the_proxy_and_refuses_anything_else() {
    let s = plain();
    let router = Arc::new(router(s.make()));
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { cc_http::serve(l, router).await });
    let http = reqwest::Client::new();
    let post = |path: &str, body: Value| {
        http.post(format!("http://127.0.0.1:{port}{path}"))
            .body(body.to_string())
            .send()
    };
    let r = post("/", json!({"action": "email.reserve", "vmId": "vm_1", "provider": "agentmail", "inboxId": INBOX, "op": "send", "to": "Bob <bob@y.com>"})).await.unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["decision"], "ask");
    assert_eq!(v["asks"][0]["scope"], format!("EMAIL agentmail:{INBOX} -> bob@y.com"));
    let v: Value = post("/", json!({"action": "email.inbound", "provider": "agentmail", "inboxId": INBOX, "items": [{"kind": "thread", "senders": ["evil@x.com"], "labels": []}]}))
        .await.unwrap().json().await.unwrap();
    assert_eq!(
        v,
        json!({"ok": true, "actions": [{"action": "hide", "reason": "not_allowed"}]})
    );
    let v: Value = post(
        "/",
        json!({"action": "email.draft_write", "provider": "agentmail", "draftId": "d1"}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(v, json!({"ok": true, "draftOk": true}));
    let v: Value = post("/", json!({"action": "email.settle", "id": "nope"}))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v, json!({"ok": true}));
    for (path, body) in [
        ("/", json!({"action": "email.other"})),
        ("/x", json!({"action": "email.settle", "id": "nope"})),
        (
            "/",
            json!({"action": "email.reserve", "vmId": "", "provider": "agentmail", "op": "send"}),
        ),
    ] {
        let r = post(path, body).await.unwrap();
        assert_eq!(r.status(), 403);
        assert_eq!(r.text().await.unwrap(), r#"{"ok":false}"#);
    }
    let r = http.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap();
    assert_eq!(r.status(), 403);
}

#[test]
fn a_first_start_whose_move_cannot_be_saved_does_not_start() {
    let s = plain();
    // The store's place is taken by a directory: the save fails.
    std::fs::create_dir(s.dir.path().join("email-rules.enc")).unwrap();
    let codes = s.codes.clone();
    let r = EmailRulesFirewall::new(EmailOptions {
        store_path: s.dir.path().join("email-rules.enc"),
        counters_path: s.dir.path().join("email-counters.json"),
        log_path: None,
        box_key: KEY.into(),
        org_id: "org".into(),
        box_id: "box".into(),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
        code_routes: Arc::new(|| Ok(vec![])),
        lookups: Arc::new(s.fake.clone()),
        grant_active: Arc::new(|_| false),
        revoke_grants: None,
        legacy_senders: Some(Arc::new(|| Ok(Some(vec![])))),
        on_changed: None,
        now: Arc::new(|| 0),
    });
    assert!(r.is_err());
}

#[tokio::test]
async fn review_fixes_bare_cr_empty_ids_and_an_unreadable_legacy_list() {
    // A bare CR inside a header line is refused, as JS's `.` refuses it.
    assert_eq!(
        recipients_from_header_block("To: ok@listed.com\r\nSubject: hi\rBcc: evil@x.com\r\n\r\n"),
        None
    );
    let s = plain();
    let fw = s.make();
    // An empty message id is no id: nothing held, nothing cached, a ref is a bad request.
    let msg = json!({"kind": "message", "message_id": "", "from": "x@gmail.com", "labels": ["received"], "authentication_results": {"dmarc": "pass"}, "text": "x"});
    assert_eq!(ask(&fw, json!([msg])).await[0]["reason"], "not_allowed");
    assert!(fw.summary()["held"].as_array().unwrap().is_empty());
    assert_eq!(
        ask(&fw, json!([{"kind": "ref", "message_id": ""}])).await,
        json!([{"action": "hide", "reason": "bad_request"}])
    );
    // A legacy list that does not parse: the rules do not start, and nothing is moved.
    let bad = setup(Some(vec![]), Some("owner@gmail.com"));
    let codes = bad.codes.clone();
    let r = EmailRulesFirewall::new(EmailOptions {
        store_path: bad.dir.path().join("email-rules.enc"),
        counters_path: bad.dir.path().join("email-counters.json"),
        log_path: None,
        box_key: KEY.into(),
        org_id: "org".into(),
        box_id: "box".into(),
        codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
        code_routes: Arc::new(|| Ok(vec![])),
        lookups: Arc::new(bad.fake.clone()),
        grant_active: Arc::new(|_| false),
        revoke_grants: None,
        legacy_senders: Some(Arc::new(|| Err(()))),
        on_changed: None,
        now: Arc::new(|| 0),
    });
    assert!(r.is_err());
    assert!(!bad.dir.path().join("email-rules.enc").exists());
}

/// Host review of #545, finding 1: the proxy hangs up while a draft lookup is still out; the draft
/// must not stay locked.
#[tokio::test]
async fn a_send_the_proxy_gave_up_on_does_not_lock_the_draft() {
    let s = plain();
    let fw = s.make();
    widen(
        &fw,
        "a",
        json!({"action": "add_recipient", "entry": {"value": "boss@x.com", "mailbox": null}}),
    )
    .await;
    s.fake
        .drafts
        .lock()
        .unwrap()
        .insert("d1".into(), m(json!({"to": ["boss@x.com"]})));
    let router = Arc::new(router(fw.clone()));
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { cc_http::serve(l, router).await });
    let body = json!({"action": "email.reserve", "vmId": "vm_1", "provider": "agentmail", "inboxId": INBOX, "op": "draft_send", "draftId": "d1"});
    s.fake.hang.store(true, Ordering::SeqCst);
    let http = reqwest::Client::new();
    let first = http
        .post(format!("http://127.0.0.1:{port}/"))
        .timeout(std::time::Duration::from_millis(300))
        .body(body.to_string())
        .send()
        .await;
    assert!(first.is_err(), "the client gave up");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    s.fake.hang.store(false, Ordering::SeqCst);
    // No time passes: only the release on drop can have freed the draft.
    let v: Value = http
        .post(format!("http://127.0.0.1:{port}/"))
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["decision"], "allow", "{v}");
    // An entry that never settled is stale after ten minutes even without the drop.
    let d = json!({"provider": "agentmail", "inboxId": INBOX, "op": "draft_send", "draftId": "d1"});
    assert_eq!(
        reserve(&fw, d.clone()).await,
        json!({"decision": "block", "reason": "draft_busy"})
    );
    s.tick(11 * 60_000);
    assert_eq!(reserve(&fw, d).await["decision"], "allow");
}

/// Host review of #545, finding 4: `.` and `..` ids would be normalised out of the lookup path.
#[test]
fn dot_ids_are_refused() {
    for (k, v) in [("messageId", ".."), ("draftId", "."), ("draftId", "..")] {
        let mut p = m(json!({"action": "email.reserve", "vmId": "vm", "provider": "agentmail", "op": "reply"}));
        p.insert(k.into(), json!(v));
        assert!(parse_reserve(&p).is_err(), "{k}={v}");
    }
    let ok =
        m(json!({"action": "email.reserve", "vmId": "vm", "provider": "agentmail", "op": "reply", "messageId": "..x"}));
    assert!(parse_reserve(&ok).is_ok());
}
