//! `gmail-push.test.ts`.

#![allow(clippy::unwrap_used, clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::*;
use crate::channels::agent::AgentError;
use crate::channels::google::http::{HttpErr, Resp};

fn target() -> Target {
    Target::new("vm-a", "a.example.com")
}

fn push(history_id: i64, email: &str) -> String {
    let data = STANDARD.encode(json!({"emailAddress": email, "historyId": history_id}).to_string());
    STANDARD.encode(json!({"message": {"data": data}}).to_string())
}

#[derive(Default)]
struct Gmail {
    requests: Mutex<Vec<(String, String, String)>>,
    history: Mutex<HashMap<String, (u16, Option<Value>)>>,
    messages: Mutex<HashMap<String, (String, Vec<&'static str>, Vec<(String, String)>)>>,
    token: Mutex<String>,
}

impl GoogleHttp for Arc<Gmail> {
    fn send(&self, req: Req) -> BoxFuture<Result<Resp, HttpErr>> {
        let me = self.clone();
        Box::pin(async move {
            let auth = req
                .headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .unwrap();
            assert_eq!(auth, format!("Bearer {}", me.token.lock().unwrap()));
            me.requests.lock().unwrap().push((
                req.method.into(),
                req.url.clone(),
                String::from_utf8(req.body.clone().unwrap_or_default()).unwrap(),
            ));
            let u = url::Url::parse(&req.url).unwrap();
            let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
            let ok = |v: Value| {
                Ok(Resp {
                    status: 200,
                    headers: vec![],
                    body: v.to_string().into_bytes(),
                })
            };
            let st = |s: u16| {
                Ok(Resp {
                    status: s,
                    headers: vec![],
                    body: vec![],
                })
            };
            if u.path().ends_with("/watch") {
                return ok(json!({"historyId": "100", "expiration": "1900000000000"}));
            }
            if u.path().ends_with("/history") {
                return match me.history.lock().unwrap().get(&q["startHistoryId"]).cloned() {
                    Some((_, Some(b))) => ok(b),
                    Some((s, None)) => st(s),
                    None => st(500),
                };
            }
            assert_eq!(q["format"], "metadata");
            let id = u.path().rsplit('/').next().unwrap().to_string();
            match me.messages.lock().unwrap().get(&id).cloned() {
                Some((thread, labels, headers)) => ok(json!({"id": id, "threadId": thread, "labelIds": labels,
                    "payload": {"headers": headers.iter().map(|(n, v)| json!({"name": n, "value": v})).collect::<Vec<_>>()}})),
                None => st(404),
            }
        })
    }
}

#[derive(Default)]
struct Box_ {
    wakes: Mutex<Vec<Value>>,
    down: AtomicBool,
}

impl AgentCalls for Arc<Box_> {
    fn post(
        &self,
        _: &Target,
        path: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        let r = if self.down.load(Ordering::SeqCst) {
            Err(AgentError::new("down"))
        } else {
            assert_eq!(path, "/hooks/gmail-wake");
            self.wakes.lock().unwrap().push(body);
            Ok(Map::new())
        };
        Box::pin(async move { r })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

struct S {
    dir: tempfile::TempDir,
    gmail: Arc<Gmail>,
    agent: Arc<Box_>,
    account: Arc<Mutex<Option<(String, String)>>>,
    now: Arc<Mutex<i64>>,
}

fn setup() -> S {
    let gmail = Arc::new(Gmail::default());
    *gmail.token.lock().unwrap() = "real-token".into();
    S {
        dir: tempfile::tempdir().unwrap(),
        gmail,
        agent: Arc::default(),
        account: Arc::new(Mutex::new(Some(("owner@gmail.com".into(), "real-token".into())))),
        now: Arc::new(Mutex::new(1_800_000_000_000)),
    }
}

impl S {
    fn make(&self) -> Arc<GmailPush> {
        let (a, now) = (self.account.clone(), self.now.clone());
        GmailPush::new(GmailPushOptions {
            state_path: self.dir.path().join("gmail-push.json"),
            access: Arc::new(move || a.lock().unwrap().clone()),
            verdict: Arc::new(|headers, _| {
                let from = headers
                    .iter()
                    .find(|h| h.name == "From")
                    .map_or("", |h| h.value.as_str());
                Some(if from.contains("boss") {
                    (true, None, Some("boss@x.com".into()))
                } else {
                    (false, Some("not_allowed".into()), None)
                })
            }),
            agent: Arc::new(self.agent.clone()),
            http: Arc::new(self.gmail.clone()),
            now: Arc::new(move || *now.lock().unwrap()),
        })
    }
    fn history(&self, from: &str, body: Value) {
        self.gmail
            .history
            .lock()
            .unwrap()
            .insert(from.into(), (200, Some(body)));
    }
    fn message(&self, id: &str, thread: &str, labels: Vec<&'static str>, headers: &[(&str, &str)]) {
        self.gmail.messages.lock().unwrap().insert(
            id.into(),
            (
                thread.into(),
                labels,
                headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            ),
        );
    }
    fn wake_ids(&self) -> Vec<String> {
        self.agent
            .wakes
            .lock()
            .unwrap()
            .iter()
            .map(|w| w["messageId"].as_str().unwrap().to_string())
            .collect()
    }
    fn watches(&self) -> usize {
        self.gmail
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.1.ends_with("/watch"))
            .count()
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(30)).await;
}

#[tokio::test]
async fn watch_then_each_push_reads_only_new_inbox_headers_and_wakes_for_allowed_senders() {
    let s = setup();
    let gp = s.make();
    assert!(gp.watch("hk_1", "projects/p/topics/gmail").await);
    let body: Value = serde_json::from_str(&s.gmail.requests.lock().unwrap()[0].2).unwrap();
    assert_eq!(
        body,
        json!({"topicName": "projects/p/topics/gmail", "labelIds": ["INBOX"], "labelFilterBehavior": "INCLUDE"})
    );
    s.history("100", json!({"historyId": "105", "history": [
        {"messagesAdded": [{"message": {"id": "m1", "labelIds": ["INBOX", "UNREAD"]}}]},
        {"messagesAdded": [{"message": {"id": "m2", "labelIds": ["INBOX"]}}, {"message": {"id": "m3", "labelIds": ["SENT"]}}]},
    ]}));
    s.message(
        "m1",
        "t1",
        vec!["INBOX"],
        &[("From", "Boss <boss@x.com>"), ("Subject", "Hi")],
    );
    s.message(
        "m2",
        "t2",
        vec!["INBOX"],
        &[("From", "stranger@y.com"), ("Subject", "Spam")],
    );
    gp.on_push(target(), &push(105, "owner@gmail.com"));
    settle().await;
    assert_eq!(
        *s.agent.wakes.lock().unwrap(),
        vec![json!({"messageId": "m1", "threadId": "t1", "from": "boss@x.com", "subject": "Hi"})]
    );
    let reqs = s.gmail.requests.lock().unwrap().clone();
    let m1 = reqs.iter().find(|r| r.1.contains("/messages/m1")).unwrap();
    let hs: Vec<String> = url::Url::parse(&m1.1)
        .unwrap()
        .query_pairs()
        .filter(|(k, _)| k == "metadataHeaders")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(hs, ["From", "Subject", "Authentication-Results", "Message-ID"]);
    assert!(!reqs.iter().any(|r| r.1.contains("/messages/m3")));
    // A repeated push changes nothing.
    s.history("105", json!({"historyId": "105"}));
    gp.on_push(target(), &push(105, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.agent.wakes.lock().unwrap().len(), 1);
    // The position survives a restart.
    let again = s.make();
    s.history(
        "105",
        json!({"historyId": "107", "history": [{"messagesAdded": [{"message": {"id": "m1", "labelIds": ["INBOX"]}}]}]}),
    );
    again.on_push(target(), &push(107, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.agent.wakes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_wake_is_retried_on_the_next_push_and_others_are_not_woken_twice() {
    let s = setup();
    let gp = s.make();
    gp.watch("hk_1", "projects/p/topics/gmail").await;
    s.history("100", json!({"historyId": "110", "history": [{"messagesAdded": [{"message": {"id": "a", "labelIds": ["INBOX"]}}, {"message": {"id": "b", "labelIds": ["INBOX"]}}]}]}));
    s.message("a", "ta", vec!["INBOX"], &[("From", "boss@x.com")]);
    s.message("b", "tb", vec!["INBOX"], &[("From", "boss@x.com")]);
    gp.on_push(target(), &push(110, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.wake_ids(), ["a", "b"]);
    s.history(
        "110",
        json!({"historyId": "111", "history": [{"messagesAdded": [{"message": {"id": "c", "labelIds": ["INBOX"]}}]}]}),
    );
    s.message("c", "tc", vec!["INBOX"], &[("From", "boss@x.com")]);
    s.agent.down.store(true, Ordering::SeqCst);
    gp.on_push(target(), &push(111, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.agent.wakes.lock().unwrap().len(), 2);
    s.agent.down.store(false, Ordering::SeqCst);
    gp.on_push(target(), &push(111, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.wake_ids(), ["a", "b", "c"]);
}

#[tokio::test]
async fn an_expired_history_id_a_foreign_mailbox_and_a_new_account() {
    let s = setup();
    let gp = s.make();
    gp.watch("hk_1", "projects/p/topics/gmail").await;
    s.gmail.history.lock().unwrap().insert("100".into(), (404, None));
    gp.on_push(target(), &push(200, "owner@gmail.com"));
    settle().await;
    assert_eq!(
        gp.lock().history_id.as_deref(),
        Some("200"),
        "started again from the push"
    );
    s.history(
        "200",
        json!({"historyId": "201", "history": [{"messagesAdded": [{"message": {"id": "z", "labelIds": ["INBOX"]}}]}]}),
    );
    s.message("z", "tz", vec!["INBOX"], &[("From", "boss@x.com")]);
    gp.on_push(target(), &push(201, "someone-else@gmail.com"));
    settle().await;
    assert!(s.agent.wakes.lock().unwrap().is_empty());
    gp.on_push(target(), &push(201, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.agent.wakes.lock().unwrap().len(), 1);
    // A different account: re-baselined from the push.
    *s.account.lock().unwrap() = Some(("new@gmail.com".into(), "real-token".into()));
    gp.on_push(target(), &push(900, "new@gmail.com"));
    settle().await;
    assert_eq!(s.agent.wakes.lock().unwrap().len(), 1);
    assert_eq!(gp.lock().history_id.as_deref(), Some("900"));
    *s.account.lock().unwrap() = None;
    gp.on_push(target(), &push(901, "owner@gmail.com"));
    settle().await;
    assert!(!gp.watch("hk_1", "projects/p/topics/gmail").await);
    gp.on_push(target(), "not base64 json");
    settle().await;
}

#[tokio::test]
async fn renewal_re_watches_when_due_or_when_the_topic_changed() {
    let s = setup();
    let gp = s.make();
    gp.renew_due(&[
        ("hk_1".into(), Some("projects/p/topics/a".into())),
        ("hk_2".into(), None),
    ])
    .await;
    assert_eq!(s.watches(), 1);
    gp.renew_due(&[("hk_1".into(), Some("projects/p/topics/a".into()))])
        .await;
    assert_eq!(s.watches(), 1);
    gp.renew_due(&[("hk_1".into(), Some("projects/p/topics/b".into()))])
        .await;
    assert_eq!(s.watches(), 2);
    *s.now.lock().unwrap() += WATCH_RENEW_MS;
    gp.renew_due(&[("hk_1".into(), Some("projects/p/topics/b".into()))])
        .await;
    assert_eq!(s.watches(), 3);
}

#[tokio::test]
async fn a_message_the_box_keeps_refusing_is_given_up_on_and_later_mail_still_wakes_it() {
    let s = setup();
    let gp = s.make();
    gp.watch("hk_1", "projects/p/topics/gmail").await;
    s.history("100", json!({"historyId": "120", "history": [{"messagesAdded": [{"message": {"id": "bad", "labelIds": ["INBOX"]}}]}]}));
    let long_x = "x".repeat(5000);
    s.message(
        "bad",
        "tb",
        vec!["INBOX"],
        &[("From", "boss@x.com"), ("Subject", &long_x)],
    );
    s.agent.down.store(true, Ordering::SeqCst);
    for _ in 0..5 {
        gp.on_push(target(), &push(120, "owner@gmail.com"));
        settle().await;
    }
    assert!(gp.lock().seen.contains(&"bad".to_string()));
    s.agent.down.store(false, Ordering::SeqCst);
    s.history("120", json!({"historyId": "121", "history": [{"messagesAdded": [{"message": {"id": "next", "labelIds": ["INBOX"]}}]}]}));
    let long_y = "y".repeat(5000);
    s.message(
        "next",
        "tn",
        vec!["INBOX"],
        &[("From", "boss@x.com"), ("Subject", &long_y)],
    );
    gp.on_push(target(), &push(121, "owner@gmail.com"));
    settle().await;
    assert_eq!(s.wake_ids(), ["next"]);
    assert_eq!(s.agent.wakes.lock().unwrap()[0]["subject"].as_str().unwrap().len(), 998);
}
