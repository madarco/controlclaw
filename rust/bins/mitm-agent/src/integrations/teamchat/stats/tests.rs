//! `teamchat-stats.test.ts`: the counts, and the pass against a fake ClickClack.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use super::*;
use crate::integrations::teamchat::api::{ChannelInfo, Member, Res};

const MIN: i64 = 60_000;

fn t0() -> i64 {
    js::parse_iso("2026-10-23T10:00:00.000Z").expect("date")
}

fn bots() -> HashMap<String, String> {
    [("usr_ada", "vm-ada"), ("usr_bob", "vm-bob")]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

fn handles() -> HashMap<String, String> {
    [("ada", "usr_ada"), ("bob", "usr_bob")]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

fn ctx() -> CounterContext {
    CounterContext {
        workspace_id: "wsp_1".into(),
        owner_user_id: "usr_owner".into(),
        bots: bots(),
        handles: handles(),
    }
}

static SEQ: AtomicI64 = AtomicI64::new(0);

fn msg(author: &str, at: i64, body: &str) -> Message {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    Message {
        id: format!("msg_{seq}"),
        seq,
        author_id: author.into(),
        author_kind: Some(
            if author.starts_with("usr_a") || author.starts_with("usr_b") {
                "bot"
            } else {
                "human"
            }
            .into(),
        ),
        thread_root_id: None,
        quoted_id: None,
        kind: Some("message".into()),
        created_at: at,
        body: body.into(),
        files: 0,
    }
}

fn count(list: &[Message], start: i64) -> (Option<ChannelCounts>, Vec<PairCount>) {
    let c: Vec<Counted> = list.iter().map(|m| to_counted(m, &handles())).collect();
    match count_channel_range(
        "chn_general",
        "general",
        &c,
        start,
        start + INTERVAL_MS,
        &bots(),
        "usr_owner",
    )
    .remove(&start)
    {
        Some((c, p)) => (Some(c), p),
        None => (None, vec![]),
    }
}

#[test]
fn a_mention_answered_in_4_minutes_counts_one_answered_in_6_does_not() {
    let t = t0();
    let mut list = vec![
        msg("usr_sara", t + MIN, "@ada flights please"),
        msg("usr_ada", t + 5 * MIN, "found some"),
        msg("usr_sara", t + 2 * MIN, "@bob anyone?"),
        msg("usr_bob", t + 8 * MIN, "late"),
    ];
    list.sort_by_key(|m| m.created_at);
    let c = count(&list, t).0.expect("counts");
    assert_eq!(
        (c.mentions, c.answered, c.reply_n, c.reply_ms_median),
        (2, 1, 1, Some(4 * MIN))
    );
    assert_eq!((c.people_msgs, c.agent_msgs), (2, 0));
}

#[test]
fn a_thread_reply_and_a_quote_both_answer_and_agents_pair_but_not_with_themselves() {
    let t = t0();
    let list = vec![
        msg("usr_sara", t, "@ada?"),
        msg("usr_ada", t + 30_000, "yes"),
        msg("usr_sara", t + MIN, "@bob?"),
        msg("usr_bob", t + 70_000, "> @bob?\nhere"),
    ];
    let c = count(&list, t).0.expect("counts");
    assert_eq!((c.answered, c.reply_ms_median, c.agent_msgs), (2, Some(20_000), 2));
    let list = vec![
        msg("usr_ada", t, "@bob can you add it to the notes"),
        msg("usr_ada", t + MIN, "note to self @ada"),
        msg("usr_bob", t + 2 * MIN, "done"),
    ];
    let (c, pairs) = count(&list, t);
    let c = c.expect("counts");
    assert_eq!((c.mentions, c.answered), (1, 1));
    assert_eq!(
        pairs,
        vec![PairCount {
            from_vm_id: "vm-ada".into(),
            to_vm_id: "vm-bob".into(),
            channel_id: "chn_general".into(),
            count: 1
        }]
    );
}

#[test]
fn files_count_system_messages_and_the_owner_do_not_and_an_empty_interval_has_no_counts() {
    let t = t0();
    let mut f = msg("usr_sara", t, "");
    f.files = 2;
    let mut j = msg("usr_sara", t + 1, "");
    j.kind = Some("member_joined".into());
    let c = count(&[f, j, msg("usr_owner", t + 2, "hello")], t).0.expect("counts");
    assert_eq!((c.files, c.people_msgs), (2, 1));
    assert!(count(&[msg("usr_sara", t - 1, "before")], t).0.is_none());
}

#[test]
fn handles_case_punctuation_emails_and_unknown_ones_and_no_text_is_kept() {
    assert_eq!(
        mentioned_bots("Hi @ADA, and @bob! mail x@ada.com @nobody", "usr_sara", &handles()),
        ["usr_ada", "usr_bob"]
    );
    let c = to_counted(&msg("usr_sara", t0(), "@ada the launch code is 1234"), &handles());
    assert_eq!(c.mentions, ["usr_ada"]);
    assert!(!format!("{c:?}").contains("launch"));
}

#[test]
fn one_walk_over_many_intervals_gives_what_counting_each_alone_gives_and_posts_are_split_by_size() {
    let t = t0();
    let mut list: Vec<Message> = (0..40)
        .map(|i| {
            let mut m = msg(
                if i % 3 != 0 { "usr_sara" } else { "usr_ada" },
                t + i * 47_000,
                if i % 5 != 0 { "hi" } else { "@bob look" },
            );
            m.files = if i % 7 != 0 { 0 } else { 1 };
            m
        })
        .collect();
    list.push(msg("usr_bob", t + 33 * 47_000, "ok"));
    list.sort_by_key(|m| m.created_at);
    let c: Vec<Counted> = list.iter().map(|m| to_counted(m, &handles())).collect();
    let end = t + 6 * INTERVAL_MS;
    let range = count_channel_range("chn_general", "general", &c, t, end, &bots(), "usr_owner");
    let mut start = t;
    while start < end {
        let one = count_channel_range(
            "chn_general",
            "general",
            &c,
            start,
            start + INTERVAL_MS,
            &bots(),
            "usr_owner",
        );
        assert_eq!(range.get(&start), one.get(&start));
        start += INTERVAL_MS;
    }
    let big = |i: i64| {
        let chs: Vec<Value> = (0..200)
            .map(|k| json!({"id": format!("chn_{k}"), "name": format!("channel-{k}"), "people_msgs": 1, "agent_msgs": 1, "files": 0, "mentions": 0, "answered": 0, "reply_ms_median": null, "reply_n": 0}))
            .collect();
        json!({"source": "teamchat_stats", "interval_start": js::iso(t + i * INTERVAL_MS), "channels": chs, "pairs": []})
    };
    let chunks = chunk_records((0..50).map(big).collect());
    assert!(chunks.len() > 1);
    assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), 50);
    for c in &chunks {
        assert!(js::stringify(&json!({"records": c})).len() < 512 * 1024);
    }
}

// ---- the pass ----

#[derive(Default)]
struct Fake {
    msgs: Mutex<HashMap<String, Vec<Message>>>,
    channels: Mutex<Vec<ChannelInfo>>,
    calls: AtomicUsize,
    /// Extra on `last_seq`: a deleted last message.
    extra: AtomicI64,
}

impl TeamChatReadApi for Fake {
    fn channel_list(&self, _: String, _: String) -> cc_http::BoxFuture<Res<Vec<ChannelInfo>>> {
        let mut list = self.channels.lock().expect("lock").clone();
        if list.is_empty() {
            let last = self
                .msgs
                .lock()
                .expect("lock")
                .get("chn_general")
                .and_then(|m| m.last().map(|x| x.seq))
                .unwrap_or(0);
            list = vec![ChannelInfo {
                id: "chn_general".into(),
                name: "general".into(),
                kind: Some("public".into()),
                last_seq: last + self.extra.load(Ordering::SeqCst),
                archived: false,
            }];
        }
        Box::pin(async move { Ok(list) })
    }
    fn members(&self, _: String, _: String) -> cc_http::BoxFuture<Res<Vec<Member>>> {
        let m = |id: &str, k: &str| Member {
            id: id.into(),
            kind: Some(k.into()),
        };
        let list = vec![
            m("usr_owner", "human"),
            m("usr_sara", "human"),
            m("usr_tom", "human"),
            m("usr_ada", "bot"),
        ];
        Box::pin(async move { Ok(list) })
    }
    fn messages(
        &self,
        _: String,
        channel_id: String,
        after_seq: i64,
        limit: i64,
    ) -> cc_http::BoxFuture<Res<Vec<Message>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if channel_id == "chn_bad" {
            return Box::pin(async { Err(ApiError::new(403, "ClickClack GET /api/channels/chn_… answered 403")) });
        }
        assert_ne!(channel_id, "chn_secret", "a private channel must not be read");
        let list: Vec<Message> = self
            .msgs
            .lock()
            .expect("lock")
            .get(&channel_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.seq > after_seq)
            .take(limit as usize)
            .collect();
        Box::pin(async move { Ok(list) })
    }
}

struct Pass {
    dir: tempfile::TempDir,
    api: Arc<Fake>,
    posted: Arc<Mutex<Vec<Vec<Value>>>>,
    ok: Arc<AtomicBool>,
    now: Arc<AtomicI64>,
    on: Arc<AtomicBool>,
}

fn setup(now: i64) -> Pass {
    let p = Pass {
        dir: tempfile::tempdir().expect("dir"),
        api: Arc::new(Fake::default()),
        posted: Arc::default(),
        ok: Arc::new(AtomicBool::new(true)),
        now: Arc::new(AtomicI64::new(now)),
        on: Arc::new(AtomicBool::new(true)),
    };
    p.api.msgs.lock().expect("lock").insert("chn_general".into(), vec![]);
    p
}

impl Pass {
    fn make(&self) -> Arc<TeamChatCounter> {
        let (posted, ok, now, on) = (self.posted.clone(), self.ok.clone(), self.now.clone(), self.on.clone());
        TeamChatCounter::with(
            self.dir.path().join("stats.json"),
            Arc::new(move || on.load(Ordering::SeqCst).then(ctx)),
            Arc::new(|_| Box::pin(async { Ok("sst".to_string()) })),
            self.api.clone(),
            Arc::new(move |r| {
                let (posted, ok) = (posted.clone(), ok.load(Ordering::SeqCst));
                Box::pin(async move {
                    if ok {
                        posted.lock().expect("lock").push(r);
                    }
                    ok
                })
            }),
            Arc::new(move || now.load(Ordering::SeqCst)),
        )
    }
    fn push(&self, m: Message) {
        self.api
            .msgs
            .lock()
            .expect("lock")
            .entry("chn_general".into())
            .or_default()
            .push(m);
    }
    fn counted(&self) -> Vec<Value> {
        self.posted
            .lock()
            .expect("lock")
            .iter()
            .flatten()
            .filter(|r| r["channels"].as_array().is_some_and(|c| !c.is_empty()))
            .cloned()
            .collect()
    }
}

#[tokio::test]
async fn a_pass_counts_finished_intervals_once_and_the_cursor_survives_a_restart() {
    let t = t0();
    let s = setup(t + 20 * MIN);
    s.push(msg("usr_sara", t + MIN, "@ada hi"));
    s.push(msg("usr_ada", t + 2 * MIN, "hello"));
    s.make().tick().await;
    let counted = s.counted();
    assert_eq!(counted.len(), 1);
    assert_eq!(counted[0]["interval_start"], js::iso(t));
    assert_eq!(counted[0]["channels"][0]["answered"], 1);
    let all: Vec<Value> = s.posted.lock().expect("lock").iter().flatten().cloned().collect();
    let last = all.last().expect("last");
    assert_eq!(last["people"], 2);
    assert_eq!(
        last["channel_list"],
        json!([{"id": "chn_general", "name": "general", "members": 3, "archived": false, "last_message_at": js::iso(t + 2 * MIN)}])
    );
    // A restart: the same messages are not counted again.
    s.now.fetch_add(INTERVAL_MS, Ordering::SeqCst);
    s.posted.lock().expect("lock").clear();
    s.make().tick().await;
    assert!(s.counted().is_empty());
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(s.dir.path().join("stats.json")).expect("state")).expect("json");
    let last_seq = s.api.msgs.lock().expect("lock")["chn_general"].last().expect("msg").seq;
    assert_eq!(state["channels"]["chn_general"]["seq"], last_seq);
}

#[tokio::test]
async fn an_interval_waits_until_its_mentions_could_have_been_answered() {
    let t = t0();
    let s = setup(t + INTERVAL_MS + 2 * MIN);
    s.push(msg("usr_sara", t + 4 * MIN, "@ada?"));
    let c = s.make();
    c.tick().await;
    assert!(s.counted().is_empty());
    s.push(msg("usr_ada", t + 7 * MIN, "here"));
    s.now.store(t + 2 * INTERVAL_MS + ANSWER_MS, Ordering::SeqCst);
    c.tick().await;
    let counted = s.counted();
    assert_eq!(
        (&counted[0]["interval_start"], &counted[0]["channels"][0]["answered"]),
        (&json!(js::iso(t)), &json!(1))
    );
}

#[tokio::test]
async fn a_refused_post_keeps_the_cursor_and_nothing_happens_while_off_or_past_a_deleted_message() {
    let t = t0();
    let s = setup(t + 20 * MIN);
    s.ok.store(false, Ordering::SeqCst);
    s.push(msg("usr_sara", t + MIN, "hi"));
    let c = s.make();
    assert_eq!(c.tick().await, None);
    s.ok.store(true, Ordering::SeqCst);
    c.tick().await;
    assert_eq!(s.counted()[0]["interval_start"], js::iso(t));

    let s = setup(t);
    s.on.store(false, Ordering::SeqCst);
    assert_eq!(s.make().tick().await, None);
    assert_eq!(s.api.calls.load(Ordering::SeqCst), 0);

    let s = setup(t + 20 * MIN);
    s.api.extra.store(1, Ordering::SeqCst);
    s.push(msg("usr_sara", t + MIN, "hi"));
    s.make().tick().await;
    assert_eq!(s.counted()[0]["interval_start"], js::iso(t));
}

#[tokio::test]
async fn the_buffer_is_cut_at_the_counted_floor_even_while_the_console_refuses_every_post() {
    let s = setup(t0());
    s.ok.store(false, Ordering::SeqCst);
    let c = s.make();
    for _ in 0..72 {
        s.push(msg("usr_sara", s.now.load(Ordering::SeqCst), "hi"));
        c.tick().await;
        s.now.fetch_add(60 * MIN, Ordering::SeqCst);
    }
    let n = c.mem.lock().await.buffer.get("chn_general").map(Vec::len).unwrap_or(0);
    // A day and a bit, not three days.
    assert!(n <= 26, "buffer holds {n}");
}

#[tokio::test]
async fn one_channel_that_will_not_read_does_not_stop_the_others_and_private_ones_are_never_named() {
    let t = t0();
    let s = setup(t + 20 * MIN);
    s.push(msg("usr_sara", t + MIN, "hi"));
    let last = s.api.msgs.lock().expect("lock")["chn_general"][0].seq;
    let ch = |id: &str, name: &str, kind: &str, last_seq: i64| ChannelInfo {
        id: id.into(),
        name: name.into(),
        kind: Some(kind.into()),
        last_seq,
        archived: false,
    };
    *s.api.channels.lock().expect("lock") = vec![
        ch("chn_bad", "bad", "public", 9),
        ch("chn_general", "general", "public", last),
        ch("chn_secret", "secret-plans", "private", 3),
    ];
    let c = s.make();
    c.tick().await;
    s.now.fetch_add(INTERVAL_MS, Ordering::SeqCst);
    c.tick().await;
    let all: Vec<Value> = s.posted.lock().expect("lock").iter().flatten().cloned().collect();
    let general = all
        .iter()
        .filter(|r| {
            r["channels"]
                .as_array()
                .is_some_and(|c| c.iter().any(|x| x["id"] == "chn_general"))
        })
        .count();
    assert_eq!(general, 1);
    assert!(
        c.mem.lock().await.failing.contains("chn_bad"),
        "logged once, remembered as failing"
    );
    let lists: Vec<Value> = all
        .iter()
        .filter_map(|r| r["channel_list"].as_array())
        .flatten()
        .cloned()
        .collect();
    assert!(!lists.is_empty());
    assert!(!lists.iter().any(|l| l["id"] == "chn_secret"));
}
