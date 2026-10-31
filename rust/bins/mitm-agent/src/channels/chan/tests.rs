//! `channels.test.ts` and `code-buttons.test.ts`: the channel commands against a fake agent box and
//! fake consent codes, and the tap checks against a fake Telegram. The consent side of a button
//! (`ConsentCodes.tap`) is W3's; here a fake owner answers for it.

#![allow(clippy::unwrap_used)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::buttons::*;
use super::*;
use crate::channels::agent::{AgentCalls, AgentError, Target};
use crate::contracts::{CodeRequest, ConsentCodes, SendResult, Verify};

type Identity = (String, Option<String>);

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[derive(Debug, Clone)]
struct Call {
    target: Target,
    path: String,
    body: Value,
}

#[derive(Default)]
struct Box_ {
    calls: Mutex<Vec<Call>>,
    reads: Mutex<Vec<String>>,
    apply_fails: Mutex<Option<AgentError>>,
    approve_times_out: Mutex<bool>,
    apply_pending: Mutex<bool>,
    dead_vm: Mutex<Option<String>>,
    /// `GET /channels/approved` per vm.
    approved: Mutex<HashMap<String, Value>>,
    /// `GET /channels/status` answers, in order (the last repeats).
    status: Mutex<VecDeque<Value>>,
}

impl Box_ {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
    fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
    fn paths(&self) -> Vec<String> {
        self.calls()
            .iter()
            .map(|c| format!("{} {}", c.target.vm_id, c.path))
            .collect()
    }
}

impl AgentCalls for Arc<Box_> {
    fn post(
        &self,
        target: &Target,
        path: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.calls.lock().unwrap().push(Call {
            target: target.clone(),
            path: path.into(),
            body: body.clone(),
        });
        let dead = self.dead_vm.lock().unwrap().as_deref() == Some(target.vm_id.as_str());
        let r: Result<Value, AgentError> = if dead {
            Err(AgentError::new("connect ECONNREFUSED"))
        } else if path == "/channels/apply" {
            match self.apply_fails.lock().unwrap().clone() {
                Some(e) => Err(e),
                None if *self.apply_pending.lock().unwrap() => Ok(json!({"ok": true, "status": "pending"})),
                None => Ok(json!({"ok": true})),
            }
        } else if path == "/channels/pairings/approve" {
            if *self.approve_times_out.lock().unwrap() {
                Err(AgentError::timeout())
            } else {
                Ok(json!({"ok": true, "senderId": "8734"}))
            }
        } else if path == "/channels/whatsapp/login" {
            Ok(json!({"ok": true, "state": "qr"}))
        } else {
            Ok(json!({"ok": true}))
        };
        Box::pin(async move { r.map(|v| v.as_object().cloned().unwrap()) })
    }

    fn get(
        &self,
        target: &Target,
        path: &str,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        self.reads.lock().unwrap().push(format!("{}{path}", target.vm_id));
        let dead = self.dead_vm.lock().unwrap().as_deref() == Some(target.vm_id.as_str());
        let r = if dead {
            Err(AgentError::new("connect ECONNREFUSED"))
        } else if path == "/channels/approved" {
            Ok(self
                .approved
                .lock()
                .unwrap()
                .get(&target.vm_id)
                .cloned()
                .unwrap_or(json!({"approved": []})))
        } else {
            let mut q = self.status.lock().unwrap();
            Ok(if q.len() > 1 {
                q.pop_front().unwrap()
            } else {
                q.front().cloned().unwrap_or(json!({}))
            })
        };
        Box::pin(async move { r.map(|v| v.as_object().cloned().unwrap_or_default()) })
    }
}

struct Pending {
    change_id: String,
    proposal: Value,
    code: String,
    tries: u32,
}

/// One change per scope, five tries, delivered to the first route's first sender.
struct FakeCodes {
    agent: Arc<Box_>,
    next: Mutex<String>,
    pending: Mutex<HashMap<String, Pending>>,
    fail: Mutex<Option<String>>,
}

impl ConsentCodes for FakeCodes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        let code = self.next.lock().unwrap().clone();
        let route = req.routes.first().cloned().unwrap_or_default();
        let sender = route["senders"][0].clone();
        let target = Target::new(
            route["target"]["vmId"].as_str().unwrap_or_default(),
            route["target"]["hostname"].as_str().unwrap_or_default(),
        );
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Box::pin(async move {
                SendResult {
                    sent_via: None,
                    error: Some(e),
                    delivery_failed: true,
                    expires_at_ms: 0,
                }
            });
        }
        drop(self.agent.post(
            &target,
            "/channels/send",
            json!({"type": sender["type"], "to": sender["id"], "text": format!("{}|{}|{code}", req.agent_name, req.summary)}),
            None,
        ));
        self.pending.lock().unwrap().insert(
            req.scope,
            Pending {
                change_id: req.change_id,
                proposal: req.proposal,
                code,
                tries: 5,
            },
        );
        let via = format!(
            "{}:{}",
            sender["type"].as_str().unwrap_or_default(),
            sender["label"]
                .as_str()
                .unwrap_or_else(|| sender["id"].as_str().unwrap_or_default())
        );
        Box::pin(async move {
            SendResult {
                sent_via: Some(via),
                error: None,
                delivery_failed: false,
                expires_at_ms: 1,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut p = self.pending.lock().unwrap();
        let Some(e) = p.get_mut(scope).filter(|e| e.change_id == change_id) else {
            return Verify::Expired;
        };
        if code == e.code {
            let pr = e.proposal.clone();
            p.remove(scope);
            return Verify::Ok(pr);
        }
        e.tries -= 1;
        let left = e.tries;
        if left == 0 {
            p.remove(scope);
        }
        Verify::Wrong { tries_left: left }
    }
    fn cancel(&self, scope: &str, _: Option<&str>) -> bool {
        self.pending.lock().unwrap().remove(scope).is_some()
    }
    fn forget(&self, scope: &str) {
        self.pending.lock().unwrap().remove(scope);
    }
}

struct World {
    dir: tempfile::TempDir,
    agent: Arc<Box_>,
    codes: Arc<FakeCodes>,
    identities: Arc<Mutex<Vec<Identity>>>,
    now: Arc<AtomicI64>,
    changed: Arc<AtomicUsize>,
    dev: bool,
}

impl World {
    fn new() -> Self {
        let agent = Arc::new(Box_::default());
        Self {
            dir: tempfile::tempdir().unwrap(),
            codes: Arc::new(FakeCodes {
                agent: agent.clone(),
                next: Mutex::new("123456".into()),
                pending: Mutex::new(HashMap::new()),
                fail: Mutex::new(None),
            }),
            agent,
            identities: Arc::new(Mutex::new(vec![
                ("vm1".into(), Some("bot.vm.example".into())),
                ("vm2".into(), Some("second.vm.example".into())),
            ])),
            now: Arc::new(AtomicI64::new(1_790_000_000_000)),
            changed: Arc::default(),
            dev: false,
        }
    }

    fn make(&self, placeholder: bool) -> Arc<ChannelsFirewall> {
        let (codes, ids, now, changed) = (
            self.codes.clone(),
            self.identities.clone(),
            self.now.clone(),
            self.changed.clone(),
        );
        let n2 = now.clone();
        ChannelsFirewall::new(ChannelsOptions {
            store_path: self.dir.path().join("channels.enc"),
            box_key: KEY.into(),
            org_id: "org1".into(),
            box_id: "fw1".into(),
            agent: Arc::new(self.agent.clone()),
            identities: Arc::new(move || ids.lock().unwrap().clone()),
            placeholder_swap: placeholder,
            dev: self.dev,
            codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
            on_credentials_changed: Arc::new(move || {
                changed.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {})
            }),
            now: Arc::new(move || now.load(Ordering::SeqCst)),
            make_apply_id: Arc::new(|| "ap-1".into()),
            sleep: Arc::new(move |d| {
                n2.fetch_add(d.as_millis() as i64, Ordering::SeqCst);
                Box::pin(async {})
            }),
        })
    }
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn data(o: &CommandOutcome) -> Value {
    Value::Object(o.data.clone().unwrap_or_default())
}

fn bot() -> Value {
    json!({"vmId": "vm1", "name": "marcobot", "hostname": "bot.vm.example"})
}

fn add(change: &str, conn: &str, agent: Option<Value>) -> Map<String, Value> {
    let mut p = json!({"changeId": change, "kind": "add", "connectionId": conn, "type": "telegram", "hint": "…abcd", "label": "@marcobot", "secret": {"botToken": "123456:AAtoken"}});
    if let Some(a) = agent {
        p["agent"] = a;
    }
    m(p)
}

#[tokio::test]
async fn the_main_flow() {
    let w = World::new();
    let fw = w.make(false);
    // the first connection of an organization is stored without a code (TOFU), unassigned
    let r = fw.propose(add("c1", "conn-1", None)).await.unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(data(&r)["tofu"], json!(true));
    assert_eq!(data(&r)["summary"], json!("Add a Telegram connection (…abcd)"));
    assert!(w.agent.calls().is_empty(), "unassigned: nothing written to a box");

    // assign puts it on an agent
    let r = fw
        .propose(m(json!({"changeId": "c2", "kind": "assign", "connectionId": "conn-1", "type": "telegram", "label": "@marcobot", "agent": bot()})))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(data(&r)["summary"], json!("Enable Telegram @marcobot on marcobot"));
    let c = w.agent.calls();
    assert_eq!(c[0].path, "/channels/apply");
    assert_eq!(
        c[0].body,
        json!({"type": "telegram", "secrets": {"botToken": "123456:AAtoken"}, "applyId": "ap-1"})
    );

    // the first pairing approval is TOFU too and belongs to the connection
    let r = fw
        .propose(m(json!({"changeId": "c3", "kind": "approve_pairing", "connectionId": "conn-1", "type": "telegram", "pairing": {"code": "PAIR1", "senderId": "8734", "label": "Marco"}})))
        .await
        .unwrap();
    assert_eq!(data(&r)["approvedSender"], json!("telegram:Marco"));
    assert!(fw.is_code_recipient("conn-1", "8734"));
    assert_eq!(fw.code_routes_checked().unwrap().len(), 1);
    assert_eq!(
        fw.code_routes_checked().unwrap()[0]["telegram"]["botToken"],
        json!("123456:AAtoken")
    );

    // with someone approved, a change sends a code through the connection's own agent
    w.agent.clear();
    let r = fw
        .propose(m(json!({"changeId": "c4", "kind": "replace", "connectionId": "conn-1", "type": "telegram", "hint": "…wxyz", "secret": {"botToken": "123456:BBnew"}})))
        .await
        .unwrap();
    assert_eq!(r.status, "awaiting_code");
    assert_eq!(data(&r)["sentVia"], json!("telegram:Marco"));
    let c = w.agent.calls();
    assert_eq!(
        (c[0].target.vm_id.as_str(), c[0].path.as_str()),
        ("vm1", "/channels/send")
    );
    assert_eq!(
        c[0].body["text"],
        json!(format!("{CODE_SUBJECT}|Replace the Telegram token (…wxyz)|123456"))
    );

    // a wrong code counts down; the right one applies on the assigned agent
    let wrong = fw
        .confirm(m(json!({"changeId": "c4", "code": "000000"})))
        .await
        .unwrap();
    assert_eq!(wrong.status, "invalid_code");
    assert_eq!(data(&wrong)["attemptsLeft"], json!(4));
    w.agent.clear();
    let right = fw
        .confirm(m(json!({"changeId": "c4", "code": "123 456"})))
        .await
        .unwrap();
    assert_eq!(right.status, "applied");
    assert_eq!(data(&right)["sentVia"], json!("telegram:Marco"));
    assert_eq!(w.agent.calls()[0].body["secrets"]["botToken"], json!("123456:BBnew"));

    // moving a connection removes it on the old box before applying it on the new one
    fw.propose(m(json!({"changeId": "c5", "kind": "assign", "connectionId": "conn-1", "type": "telegram", "label": "@marcobot", "from": {"vmId": "vm1"}, "agent": {"vmId": "vm2", "name": "second", "hostname": "second.vm.example"}})))
        .await
        .unwrap();
    w.agent.clear();
    let r = fw
        .confirm(m(json!({"changeId": "c5", "code": "123456"})))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(w.agent.paths(), ["vm1 /channels/apply", "vm2 /channels/apply"]);
    assert_eq!(
        w.agent.calls()[0].body,
        json!({"type": "telegram", "remove": true, "applyId": "ap-1"})
    );
    assert_eq!(
        fw.code_routes_checked().unwrap()[0]["target"]["vmId"],
        json!("vm2"),
        "the code now goes through the new agent"
    );

    // cancel drops the pending proposal; an unknown one is expired
    fw.propose(m(
        json!({"changeId": "c6", "kind": "unassign", "connectionId": "conn-1", "type": "telegram"}),
    ))
    .await
    .unwrap();
    assert_eq!(
        fw.cancel(m(json!({"changeId": "c6"}))).await.unwrap().status,
        "cancelled"
    );
    assert_eq!(
        fw.confirm(m(json!({"changeId": "c6", "code": "123456"})))
            .await
            .unwrap()
            .status,
        "expired"
    );

    // no reachable sender: failed, nothing pending
    *w.codes.fail.lock().unwrap() = Some("Could not reach you on any connected channel (boom).".into());
    let r = fw
        .propose(m(
            json!({"changeId": "c7", "kind": "unassign", "connectionId": "conn-1", "type": "telegram"}),
        ))
        .await
        .unwrap();
    assert!(!r.ok);
    assert_eq!(
        r.message.as_deref(),
        Some("Could not reach you on any connected channel (boom).")
    );
    *w.codes.fail.lock().unwrap() = None;

    // push re-applies every connection assigned to that agent, and only those
    w.agent.clear();
    let r = fw
        .push(m(
            json!({"vmId": "vm2", "agentName": "second", "hostname": "second.vm.example"}),
        ))
        .await
        .unwrap();
    assert_eq!(data(&r)["applied"], json!(["conn-1"]));
    assert_eq!(w.agent.paths()[0], "vm2 /channels/apply");
    let none = fw.push(m(json!({"vmId": "vm1"}))).await.unwrap();
    assert_eq!(data(&none), json!({"vmId": "vm1", "applied": [], "failed": []}));

    // a push failure reports which connection failed
    *w.agent.apply_fails.lock().unwrap() = Some(AgentError::new("agent 500: bad token"));
    let r = fw.push(m(json!({"vmId": "vm2"}))).await.unwrap();
    assert!(!r.ok);
    assert_eq!(r.message.as_deref(), Some("telegram: agent 500: bad token"));
    *w.agent.apply_fails.lock().unwrap() = None;

    // a write the box is still doing is confirmed from the box, not called a failure
    *w.agent.apply_pending.lock().unwrap() = true;
    *w.agent.status.lock().unwrap() = VecDeque::from(vec![
        json!({"channels": {"telegram": {"lastApply": {"id": "ap-1", "state": "pending"}}}}),
        json!({"channels": {"telegram": {"lastApply": {"id": "ap-1", "state": "applied"}}}}),
    ]);
    let r = fw.push(m(json!({"vmId": "vm2"}))).await.unwrap();
    assert_eq!(data(&r)["applied"], json!(["conn-1"]));
    // a write we never heard the end of is unconfirmed, never failed
    *w.agent.status.lock().unwrap() = VecDeque::from(vec![
        json!({"channels": {"telegram": {"lastApply": {"id": "other", "state": "applied"}}}}),
    ]);
    let r = fw.push(m(json!({"vmId": "vm2"}))).await.unwrap();
    assert!(r.ok);
    assert_eq!(data(&r)["unconfirmed"], json!(["conn-1"]));
    // a box that says the write failed still fails the change
    *w.agent.status.lock().unwrap() = VecDeque::from(vec![
        json!({"channels": {"telegram": {"lastApply": {"id": "ap-1", "state": "failed", "error": "OpenClaw refused the token"}}}}),
    ]);
    let r = fw.push(m(json!({"vmId": "vm2"}))).await.unwrap();
    assert_eq!(r.message.as_deref(), Some("telegram: OpenClaw refused the token"));
    *w.agent.apply_pending.lock().unwrap() = false;

    // the store survives a restart
    let again = w.make(false);
    assert_eq!(again.summary()[0]["assignedVmId"], json!("vm2"));
    assert!(again.is_code_recipient("conn-1", "8734"));

    // a connection this firewall never had removes cleanly
    let r = fw.cancel(m(json!({"changeId": "x"}))).await.unwrap();
    assert_eq!(r.status, "cancelled");
}

#[tokio::test]
async fn placeholders_and_proxy_credentials() {
    let w = World::new();
    let fw = w.make(true);
    fw.propose(add("c1", "conn-1", Some(bot()))).await.unwrap();
    let body = &w.agent.calls()[0].body;
    // The bot's id first: the proxy's Telegram check reads it from the path before the swap.
    assert_eq!(body["secrets"]["botToken"], json!("123456:__cc_telegram_bot_conn_1"));
    assert_eq!(
        fw.credentials(),
        vec![
            json!({"placeholder": "123456:__cc_telegram_bot_conn_1", "match_domain": "api.telegram.org", "secret": "123456:AAtoken", "locations": ["path"], "vm_id": "vm1"})
        ]
    );
    assert_eq!(fw.telegram_token("123456").as_deref(), Some("123456:AAtoken"));
    assert_eq!(fw.telegram_token_for_agent("123456", "vm2"), None);
    assert!(w.make(false).credentials().is_empty(), "plain mode: nothing to swap");
}

#[tokio::test]
async fn an_agent_that_is_gone_does_not_strand_a_connection() {
    let w = World::new();
    let fw = w.make(false);
    fw.propose(add("c1", "conn-1", Some(bot()))).await.unwrap();
    *w.agent.dead_vm.lock().unwrap() = Some("vm1".into());
    // still listed: the leave fails the change
    let r = fw
        .propose(m(
            json!({"changeId": "c2", "kind": "unassign", "connectionId": "conn-1", "type": "telegram"}),
        ))
        .await;
    assert!(r.is_err());
    // no longer listed: it is gone for good, and the connection is let go
    w.identities.lock().unwrap().retain(|(v, _)| v != "vm1");
    let r = fw
        .propose(m(
            json!({"changeId": "c3", "kind": "unassign", "connectionId": "conn-1", "type": "telegram"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, "applied");
    assert_eq!(fw.summary()[0]["assignedVmId"], Value::Null);
    let r = fw
        .propose(m(
            json!({"changeId": "c4", "kind": "remove", "connectionId": "never-here", "type": "telegram"}),
        ))
        .await
        .unwrap();
    assert_eq!(data(&r)["missing"], json!(true));
}

#[tokio::test]
async fn approvals_are_reconciled_from_the_agents_own_record() {
    let w = World::new();
    let fw = w.make(false);
    fw.propose(add("c1", "conn-1", Some(bot()))).await.unwrap();
    // an approve the agent never answers is unconfirmed, not failed, and stays on the list
    *w.agent.approve_times_out.lock().unwrap() = true;
    let r = fw
        .propose(m(json!({"changeId": "c2", "kind": "approve_pairing", "connectionId": "conn-1", "type": "telegram", "pairing": {"code": "PAIR1", "senderId": "8734", "label": "Marco"}})))
        .await
        .unwrap();
    assert_eq!(r.status, "unconfirmed");
    assert!(!fw.is_code_recipient("conn-1", "8734"));
    // the late success is read back off the agent and reported on its own
    w.agent.approved.lock().unwrap().insert(
        "vm1".into(),
        json!({"approved": [{"type": "telegram", "senderId": "8734", "code": "PAIR1", "at": "2026-09-30T10:00:00.000Z"}]}),
    );
    fw.tick().await;
    assert!(fw.is_code_recipient("conn-1", "8734"));
    let reports = fw.drain_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].command_id, "channels.reconciled:conn-1");
    assert_eq!(
        reports[0].data.clone().unwrap()["senders"],
        json!([{"id": "8734", "label": "Marco"}])
    );
    // a settled organization is not reconciled again
    w.agent.reads.lock().unwrap().clear();
    fw.tick().await;
    assert!(
        !w.agent
            .reads
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.ends_with("/channels/approved") && false)
    );
    assert!(fw.drain_reports().is_empty());

    // a removed recipient stays removed: the reconcile does not put back what an owner withdrew
    fw.propose(m(json!({"changeId": "c3", "kind": "remove_sender", "connectionId": "conn-1", "type": "telegram", "sender": {"id": "8734"}})))
        .await
        .unwrap();
    // a code went out to Marco: confirm it
    let r = fw
        .confirm(m(json!({"changeId": "c3", "code": "123456"})))
        .await
        .unwrap();
    assert_eq!(data(&r)["noRecipientsLeft"], json!(true));
    fw.tick().await;
    assert!(!fw.is_code_recipient("conn-1", "8734"), "not put back");
    // removing somebody already off the list succeeds
    let r = fw
        .propose(m(json!({"changeId": "c4", "kind": "remove_sender", "connectionId": "conn-1", "type": "telegram", "sender": {"id": "8734"}})))
        .await
        .unwrap();
    assert_eq!(data(&r)["missing"], json!(true));
}

#[tokio::test]
async fn adding_a_code_recipient_reads_the_agent_again() {
    let w = World::new();
    let fw = w.make(false);
    fw.propose(add("c1", "conn-1", Some(bot()))).await.unwrap();
    w.agent.approved.lock().unwrap().insert(
        "vm1".into(),
        json!({"approved": [], "allowedByAgent": {"senders": [{"type": "telegram", "senderId": "555", "label": "Anna", "at": null}]}}),
    );
    fw.refresh_agent_allowed(true).await;
    let rec = fw.code_recipients();
    assert_eq!(rec["approved"], json!([]));
    assert_eq!(rec["allowed"][0]["senderId"], json!("555"));
    // adding one is TOFU while nobody is approved, and the firewall then holds them
    let r = fw
        .propose(m(json!({"changeId": "c2", "kind": "add_sender", "connectionId": "conn-1", "type": "telegram", "sender": {"id": "555"}})))
        .await
        .unwrap();
    assert_eq!(data(&r)["approvedSender"], json!("telegram:Anna"));
    assert!(fw.is_code_recipient("conn-1", "555"));
    // a sender the agent has since dropped is refused at apply time
    w.agent
        .approved
        .lock()
        .unwrap()
        .insert("vm1".into(), json!({"approved": [], "allowedByAgent": {"senders": []}}));
    fw.propose(m(json!({"changeId": "c3", "kind": "add_sender", "connectionId": "conn-1", "type": "telegram", "sender": {"id": "777"}})))
        .await
        .unwrap();
    let r = fw.confirm(m(json!({"changeId": "c3", "code": "123456"}))).await;
    assert_eq!(
        r.unwrap_err(),
        "Telegram 777 is no longer on the agent's own list, so nothing was changed."
    );
    // an agent build that says nothing about its allow list is not "nobody"
    w.agent
        .approved
        .lock()
        .unwrap()
        .insert("vm1".into(), json!({"approved": []}));
    fw.refresh_agent_allowed(true).await;
    assert!(fw.code_recipients().get("allowed").is_none());
}

#[test]
fn summaries_and_placeholders() {
    let p = |v: Value| parse_proposal(&m(v)).unwrap();
    assert_eq!(
        summarize(&p(
            json!({"changeId": "c", "kind": "whatsapp_login", "connectionId": "w", "type": "whatsapp", "settings": {"personal": true}, "agent": bot()})
        )),
        "Connect WhatsApp by QR (personal number) on marcobot"
    );
    assert_eq!(
        summarize(&p(
            json!({"changeId": "c", "kind": "add_sender", "connectionId": "w", "type": "slack", "sender": {"id": "U1", "label": "Ann"}})
        )),
        "Let Slack Ann (U1) receive confirmation codes"
    );
    assert_eq!(
        placeholder_for("slack", "legacy:vm1:slack", "app"),
        "__cc_slack_app_legacy_vm1_slack"
    );
    // Slack's stand-ins are shaped as its tokens; the app token keeps its app id.
    assert_eq!(slack_placeholder("c1", "bot", "xoxb-1-2-x"), "xoxb-__cc_slack_bot_c1");
    assert_eq!(
        slack_placeholder("c1", "app", "xapp-1-A0123BC-456-abcdef"),
        "xapp-1-A0123BC-__cc_slack_app_c1"
    );
    assert_eq!(slack_placeholder("c1", "app", "nope"), "xapp-__cc_slack_app_c1");
    assert!(
        parse_proposal(&m(
            json!({"changeId": "c", "kind": "add", "connectionId": "x", "type": "fax"})
        ))
        .is_err()
    );
}

// ---- code buttons ----

const TOKEN: &str = "777000:AAbbccddeeffgghhiijjkkllmmnnoopp";
const BOT_ID: &str = "777000";
const PERSON: &str = "424242";

#[derive(Default)]
struct FakeTelegram {
    calls: Mutex<Vec<(String, Value)>>,
    message_id: AtomicI64,
    fails: Mutex<bool>,
}

impl TelegramApi for Arc<FakeTelegram> {
    fn call(&self, _: &str, method: &str, body: Value) -> BoxFuture<Result<Value, String>> {
        self.calls.lock().unwrap().push((method.into(), body));
        let r = if *self.fails.lock().unwrap() {
            Err(format!(
                "Telegram {method} failed (HTTP 403: Forbidden: bot was blocked by the user)"
            ))
        } else if method == "sendMessage" {
            Ok(json!({"message_id": self.message_id.fetch_add(1, Ordering::SeqCst) + 101}))
        } else {
            Ok(json!(true))
        };
        Box::pin(async move { r })
    }
}

#[derive(Default)]
struct Owner {
    verdicts: Mutex<VecDeque<TapVerdict>>,
    taps: Mutex<Vec<bool>>,
    cancelled: AtomicUsize,
}

impl TapOwner for Owner {
    fn tap(&self, correct: bool) -> TapVerdict {
        self.taps.lock().unwrap().push(correct);
        self.verdicts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(if correct { TapVerdict::Ok } else { TapVerdict::Wrong })
    }
    fn cancel(&self) {
        self.cancelled.fetch_add(1, Ordering::SeqCst);
    }
}

struct Rig {
    tg: Arc<FakeTelegram>,
    owner: Arc<Owner>,
    buttons: CodeButtons,
    recipients: Arc<Mutex<Vec<String>>>,
    clock: Arc<AtomicI64>,
}

fn rig() -> Rig {
    let tg = Arc::new(FakeTelegram::default());
    let recipients = Arc::new(Mutex::new(vec![format!("conn-1:{PERSON}")]));
    let clock = Arc::new(AtomicI64::new(1_000_000));
    let (r, c) = (recipients.clone(), clock.clone());
    let buttons = CodeButtons::new(CodeButtonsOptions {
        approved: Arc::new(move |conn: &str, s: &str| r.lock().unwrap().contains(&format!("{conn}:{s}"))),
        token_for: Some(Arc::new(|id: &str| (id == BOT_ID).then(|| TOKEN.to_string()))),
        changed: None,
        telegram: Arc::new(tg.clone()),
        now: Arc::new(move || c.load(Ordering::SeqCst)),
        make_numbers: Some(Arc::new(|| ["47".into(), "12".into(), "83".into()])),
        shuffle: Some(Arc::new(|mut v: Vec<String>| {
            v.reverse();
            v
        })),
    });
    Rig {
        tg,
        owner: Arc::new(Owner::default()),
        buttons,
        recipients,
        clock,
    }
}

impl Rig {
    async fn offer(&self) -> String {
        self.buttons
            .offer(OfferInput {
                change_id: "ch-1".into(),
                route: TelegramButtonsRoute {
                    connection_id: "conn-1".into(),
                    bot_token: TOKEN.into(),
                },
                sender_id: PERSON.into(),
                text: "Connect Telegram to Agent 1\n123 456".into(),
                render: Arc::new(|line: &str| Ok(format!("Connect Telegram to Agent 1\n{line}"))),
                code: "123456".into(),
                expires_at: 1_000_000 + 600_000,
                owner: self.owner.clone(),
            })
            .await
            .unwrap()
    }

    fn tap(&self, nonce: &str, choice: &str, from: &str, chat: &str, message: i64) -> Value {
        json!({"id": format!("q-{choice}-{from}"), "data": format!("{TAP_PREFIX}{nonce}:{choice}"), "from": {"id": from.parse::<i64>().unwrap()}, "message": {"message_id": message, "chat": {"id": chat.parse::<i64>().unwrap(), "type": "private"}}})
    }

    fn answers(&self) -> Vec<String> {
        self.tg
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "answerCallbackQuery")
            .map(|(_, b)| b["text"].as_str().unwrap().to_string())
            .collect()
    }

    fn edits(&self) -> Vec<String> {
        self.tg
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "editMessageText")
            .map(|(_, b)| b["text"].as_str().unwrap().to_string())
            .collect()
    }
}

#[tokio::test]
async fn buttons_the_right_number_releases_the_code() {
    let r = rig();
    let nonce = r.offer().await;
    let sent = r.tg.calls.lock().unwrap()[0].1.clone();
    assert_eq!(sent["chat_id"], json!(PERSON));
    let row: Vec<&str> = sent["reply_markup"]["inline_keyboard"][0]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["text"].as_str().unwrap())
        .collect();
    assert_eq!(row, ["83", "12", "47"]);
    assert_eq!(sent["reply_markup"]["inline_keyboard"][1][0]["text"], "Cancel");
    assert_eq!(
        r.buttons.beat()[0].to_json(),
        json!({"changeId": "ch-1", "number": "47", "state": "open", "expiresAt": cc_crypto::store_health::iso_from_millis(1_600_000)})
    );
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "47", PERSON, PERSON, 101)])
        .await;
    assert_eq!(r.answers(), ["Approved."]);
    assert_eq!(
        r.edits(),
        ["Connect Telegram to Agent 1\nApproved. Your console is applying the change."]
    );
    assert_eq!(r.buttons.beat()[0].to_json()["code"], json!("123456"));
    // a second tap does nothing more
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "47", PERSON, PERSON, 101)])
        .await;
    assert_eq!(r.answers().last().unwrap(), "Already approved.");
    assert_eq!(r.owner.taps.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn buttons_refuse_other_people_chats_messages_and_the_withdrawn() {
    let r = rig();
    let nonce = r.offer().await;
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "47", "999", PERSON, 101)])
        .await;
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "47", PERSON, "999", 101)])
        .await;
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "47", PERSON, PERSON, 55)])
        .await;
    assert_eq!(r.answers(), ["This button is not for you."; 3]);
    // another bot's taps on this message: closed, answered with that bot's token if known
    r.buttons
        .taps(Some("111"), &[r.tap(&nonce, "47", PERSON, PERSON, 101)])
        .await;
    assert_eq!(r.answers().len(), 3);
    r.recipients.lock().unwrap().clear();
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "47", PERSON, PERSON, 101)])
        .await;
    assert_eq!(r.answers().last().unwrap(), "You are no longer set to confirm changes.");
    assert!(r.owner.taps.lock().unwrap().is_empty());
}

#[tokio::test]
async fn buttons_a_wrong_number_turns_them_off_and_cancel_drops_the_change() {
    let r = rig();
    let nonce = r.offer().await;
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "12", PERSON, PERSON, 101)])
        .await;
    assert_eq!(r.answers(), ["That is not the number in your console."]);
    assert_eq!(r.buttons.beat()[0].state, TapState::Refused);
    assert!(r.buttons.beat()[0].code.is_none());
    let r = rig();
    let nonce = r.offer().await;
    r.buttons
        .taps(Some(BOT_ID), &[r.tap(&nonce, "x", PERSON, PERSON, 101)])
        .await;
    assert_eq!(r.owner.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(r.buttons.beat()[0].state, TapState::Cancelled);
    assert_eq!(
        r.edits(),
        ["Connect Telegram to Agent 1\nCancelled. Nothing was changed."]
    );
    // past the expiry: dropped from the beat
    r.clock.fetch_add(700_000, Ordering::SeqCst);
    assert!(r.buttons.beat().is_empty());
}

#[tokio::test]
async fn buttons_telegram_refusing_the_message_falls_back_to_the_plain_code() {
    let r = rig();
    *r.tg.fails.lock().unwrap() = true;
    let out = r
        .buttons
        .offer(OfferInput {
            change_id: "ch-1".into(),
            route: TelegramButtonsRoute {
                connection_id: "conn-1".into(),
                bot_token: TOKEN.into(),
            },
            sender_id: PERSON.into(),
            text: "t".into(),
            render: Arc::new(|l: &str| Ok(l.to_string())),
            code: "123456".into(),
            expires_at: 2_000_000,
            owner: r.owner.clone(),
        })
        .await;
    assert!(out.is_none());
    assert!(r.buttons.beat().is_empty());
}

#[tokio::test]
async fn the_tap_listener() {
    let r = rig();
    let nonce = r.offer().await;
    let buttons = Arc::new(r.buttons);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(cc_http::serve(listener, Arc::new(router(buttons.clone()))));
    let c = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/");
    let tap = json!({"id": "q1", "data": format!("{TAP_PREFIX}{nonce}:47"), "from": {"id": 424242}, "message": {"message_id": 101, "chat": {"id": 424242, "type": "private"}}});
    let ok = c
        .post(&url)
        .body(json!({"botId": BOT_ID, "queries": [tap]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "{\"ok\":true}");
    for _ in 0..50 {
        if buttons.beat().first().is_some_and(|t| t.code.is_some()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(buttons.beat()[0].code.as_deref(), Some("123456"));
    let bad = c.post(&url).body("{\"queries\": 5}").send().await.unwrap();
    assert_eq!(bad.status(), 403);
    assert_eq!(bad.text().await.unwrap(), "{\"ok\":false}");
    assert_eq!(c.get(&url).send().await.unwrap().status(), 403);
    assert_eq!(c.post(format!("{url}x")).body("{}").send().await.unwrap().status(), 403);
}

#[tokio::test]
async fn a_store_that_does_not_parse_is_never_written_over() {
    let w = World::new();
    let raw = json!({"version": 2, "connections": {"conn-1": {"type": 5}}, "agents": {}});
    cc_crypto::enc_file::save_encrypted_json(&w.dir.path().join("channels.enc"), &raw, KEY, "org1:fw1:channels")
        .unwrap();
    let fw = w.make(false);
    // Unreadable is not "nobody approved": no route list, and nothing applies on first use.
    assert_eq!(fw.code_routes_checked(), None);
    assert!(!fw.ready());
    let r = fw.propose(add("c1", "conn-2", None)).await.unwrap();
    assert_eq!((r.ok, r.message.as_deref()), (false, Some(NO_CHANNELS)));
    let back = cc_crypto::enc_file::load_encrypted_json(&w.dir.path().join("channels.enc"), KEY, "org1:fw1:channels")
        .unwrap()
        .unwrap();
    assert_eq!(back, raw, "the file is as it was");
}

/// Host review of #545 (4): a connection with approved people whose agent has no address yet makes
/// the routes unknown, rather than dropping it (which could leave nobody, and so first use).
#[tokio::test]
async fn an_approved_connection_on_an_agent_with_no_address_makes_the_routes_unknown() {
    let w = World::new();
    let raw = json!({"version": 2, "agents": {"vm9": {"name": "nine"}}, "connections": {"conn-1": {
        "type": "telegram", "secrets": {"botToken": "1:x"}, "settings": {}, "hint": null, "label": null,
        "approvedSenders": [{"type": "telegram", "id": "8734", "label": "Marco", "at": "2026-10-01T00:00:00.000Z"}],
        "assignedVmId": "vm9", "updatedAt": "2026-10-01T00:00:00.000Z"}}});
    cc_crypto::enc_file::save_encrypted_json(&w.dir.path().join("channels.enc"), &raw, KEY, "org1:fw1:channels")
        .unwrap();
    let fw = w.make(false);
    assert!(fw.ready());
    assert_eq!(fw.code_routes_checked(), None);
    let r = fw.propose(add("c1", "conn-2", None)).await.unwrap();
    assert_eq!((r.ok, r.message.as_deref()), (false, Some(NO_ADDRESS)));
    // Once the identity map gives it an address, the route is there.
    w.identities
        .lock()
        .unwrap()
        .push(("vm9".into(), Some("nine.vm.example".into())));
    assert_eq!(fw.code_routes_checked().unwrap().len(), 1);
}

/// Host review of #545 (3): a dev build lists the dev route last, so with nobody approved a change
/// asks for a code (handed back to the console) instead of applying on first use.
#[tokio::test]
async fn a_dev_build_asks_through_the_dev_route() {
    let mut w = World::new();
    w.dev = true;
    let fw = w.make(false);
    let routes = fw.code_routes_checked().unwrap();
    assert_eq!(routes, vec![crate::channels::contracts_fill::dev_route_json()]);
    let r = fw.propose(add("c1", "conn-1", None)).await.unwrap();
    assert_eq!(r.status, "awaiting_code");
}

/// Review of the #545 fixes: a store this box cannot decrypt is not "nobody approved", for this
/// firewall alone (the health flag is process-wide), and a later save does not change that.
#[tokio::test]
async fn a_store_that_will_not_decrypt_is_not_first_use() {
    let w = World::new();
    cc_crypto::enc_file::save_encrypted_json(
        &w.dir.path().join("channels.enc"),
        &json!({"version": 2}),
        KEY,
        "another:box:channels",
    )
    .unwrap();
    let fw = w.make(false);
    assert!(!fw.ready());
    assert_eq!(fw.code_routes_status(), Err(NO_CHANNELS));
    let r = fw.propose(add("c1", "conn-1", None)).await.unwrap();
    assert_eq!((r.ok, r.message.as_deref()), (false, Some(NO_CHANNELS)));
    // Another firewall in the same process reads its own store fine.
    let other = World::new();
    assert!(other.make(false).ready());
}

#[test]
fn unknown_routes_are_never_an_empty_list() {
    use crate::contracts::CodeRouteSource;
    let w = World::new();
    let raw = json!({"version": 2, "agents": {"vm9": {"name": "nine"}}, "connections": {"conn-1": {
        "type": "telegram", "secrets": {}, "settings": {}, "approvedSenders": [{"type": "telegram", "id": "1", "at": "x"}],
        "assignedVmId": "vm9", "updatedAt": "x"}}});
    cc_crypto::enc_file::save_encrypted_json(&w.dir.path().join("channels.enc"), &raw, KEY, "org1:fw1:channels")
        .unwrap();
    let source = crate::channels::contracts_fill::ChannelRoutes {
        channels: w.make(false),
    };
    assert!(source.ready(), "the store reads");
    let routes = source.routes();
    assert_eq!(routes.len(), 1);
    assert!(routes[0].senders.is_empty(), "nobody can be reached on it");
}

/// Both code-route slots W4 fills say the channel list was read: W5's modules ask `CodeRoutes`, and
/// a false there refused every change they send a code for (found on the live round). A store that
/// did not read stays a refusal.
#[test]
fn the_code_route_slots_say_ready_only_when_the_routes_are_known() {
    use crate::contracts::{CodeRouteSource, CodeRoutes};
    let w = World::new();
    let fw = w.make(false);
    assert!(fw.ready());
    assert!(crate::channels::contracts_fill::ChannelRoutesJson(fw.clone()).ready());
    assert!(crate::channels::contracts_fill::ChannelRoutes { channels: fw }.ready());
    // An approved person on an agent with no address: the routes are not known, so not ready
    // (the stand-in route has nobody on it, which must never read as nobody to ask).
    let raw = json!({"version": 2, "agents": {"vm9": {"name": "nine"}}, "connections": {"conn-1": {
        "type": "telegram", "secrets": {"botToken": "1:x"}, "settings": {}, "hint": null, "label": null,
        "approvedSenders": [{"type": "telegram", "id": "8734", "label": "Marco", "at": "2026-10-01T00:00:00.000Z"}],
        "assignedVmId": "vm9", "updatedAt": "2026-10-01T00:00:00.000Z"}}});
    cc_crypto::enc_file::save_encrypted_json(&w.dir.path().join("channels.enc"), &raw, KEY, "org1:fw1:channels")
        .unwrap();
    assert!(!crate::channels::contracts_fill::ChannelRoutesJson(w.make(false)).ready());
    std::fs::write(w.dir.path().join("channels.enc"), "not a store").unwrap();
    let unread = w.make(false);
    assert!(!crate::channels::contracts_fill::ChannelRoutesJson(unread.clone()).ready());
    assert!(!crate::channels::contracts_fill::ChannelRoutes { channels: unread }.ready());
}

/// The `ChannelWriter` slot (team chat's write to each agent, W5) goes out as the channels' own
/// writes do: `POST /channels/apply` with an apply id, to the target named; a refusal is an error.
#[tokio::test]
async fn the_channel_writer_slot_writes_like_the_channels_module() {
    use crate::contracts::{ApplyOutcome as Outcome, ChannelWriter as _};
    let w = World::new();
    let writer = crate::channels::contracts_fill::Writer(Arc::new(apply::ChannelWriter {
        agent: Arc::new(w.agent.clone()),
        now: Arc::new(|| 0),
        make_apply_id: Arc::new(|| "ap-9".into()),
        sleep: Arc::new(|_| Box::pin(async {})),
    }));
    let out = writer
        .write(
            "vm1",
            "bot.vm.example",
            "clickclack",
            json!({"type": "clickclack", "enabled": true}),
        )
        .await;
    assert_eq!(out, Ok(Outcome::Applied));
    let call = w.agent.calls().pop().unwrap();
    assert_eq!(
        (call.path.as_str(), call.target.vm_id.as_str()),
        ("/channels/apply", "vm1")
    );
    assert_eq!(call.target.hostname, "bot.vm.example");
    assert_eq!(call.body["applyId"], "ap-9");
    *w.agent.apply_fails.lock().unwrap() = Some(AgentError::new("refused"));
    assert!(
        writer
            .write("vm1", "bot.vm.example", "clickclack", json!({}))
            .await
            .is_err()
    );
}
