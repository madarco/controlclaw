//! `meeting-schedule.test.ts`, with the invite builder of `meeting-ics.test.ts`.

use std::sync::{Arc, Mutex, Weak};

use super::super::ics::tests::{Inv, invite};
use super::super::sources::InviteMail;
use super::*;

const MIN: i64 = MINUTE;
/// The fixture invite starts at 13:00Z and ends at 13:30Z.
fn t0() -> i64 {
    crate::phone::history::parse_iso("2026-10-12T12:00:00Z").expect("t0") as i64
}

type Hook = Arc<dyn Fn() -> BoxFuture<()> + Send + Sync>;

#[derive(Default)]
struct State {
    now: i64,
    busy: bool,
    settings: Option<Value>,
    mails: Vec<InviteMail>,
    events: Option<Vec<CalendarEvent>>,
    refusal: Option<String>,
    joins: Vec<(String, Value, i64)>,
    admits: usize,
    join_error: Option<JoinFailed>,
    left: Vec<String>,
    incomplete: bool,
    during_join: Option<Hook>,
    cursors: Vec<Option<String>>,
}

struct Fx {
    state: Arc<Mutex<State>>,
    dir: tempfile::TempDir,
    schedule: Arc<MeetingSchedule>,
    me: Arc<Mutex<Weak<MeetingSchedule>>>,
}

fn settings(extra: Value) -> Value {
    let mut s = json!({"enabled": true, "mode": "transcript", "email": true, "calendar": "invited", "maxPerDay": 5});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        s[k] = v;
    }
    s
}

fn make(state: &Arc<Mutex<State>>, dir: &std::path::Path) -> Arc<MeetingSchedule> {
    let st = |s: &Arc<Mutex<State>>| s.clone();
    let (a, b, c, d, e, f, g, h) = (
        st(state),
        st(state),
        st(state),
        st(state),
        st(state),
        st(state),
        st(state),
        st(state),
    );
    MeetingSchedule::new(ScheduleDeps {
        state_path: dir.join("schedule.json"),
        now: Arc::new(move || a.lock().expect("s").now),
        settings: Arc::new(move || b.lock().expect("s").settings.clone()),
        busy: Arc::new(move || c.lock().expect("s").busy),
        admit: Arc::new(move |_| {
            let mut s = d.lock().expect("s");
            s.admits += 1;
            let r = s.refusal.clone();
            Box::pin(async move { Ok(r) })
        }),
        join: Arc::new(move |url, auto, leave_at| {
            let e = e.clone();
            Box::pin(async move {
                let (error, hook) = {
                    let s = e.lock().expect("s");
                    (s.join_error.clone(), s.during_join.clone())
                };
                if let Some(err) = error {
                    return Err(err);
                }
                if let Some(h) = hook {
                    h().await;
                }
                let mut s = e.lock().expect("s");
                s.joins.push((url, auto, leave_at));
                s.busy = true;
                Ok((
                    format!("{:08}-1111-4111-8111-111111111111", s.joins.len()),
                    "transcript".to_string(),
                ))
            })
        }),
        leave: Arc::new(move |id| {
            let mut s = f.lock().expect("s");
            s.left.push(id);
            s.busy = false;
            Box::pin(async {})
        }),
        mail: Some(Arc::new(move |cursor| {
            let mut s = g.lock().expect("s");
            s.cursors.push(cursor);
            let batch = MailBatch {
                mails: std::mem::take(&mut s.mails),
                cursor: iso_ms(s.now),
                incomplete: s.incomplete,
            };
            Box::pin(async move { Ok(Some(batch)) })
        })),
        calendar: Some(Arc::new(move |_, _, _| {
            let events = h.lock().expect("s").events.clone();
            Box::pin(async move { Ok(events) })
        })),
    })
}

fn fixture_with(s: Option<Value>) -> Fx {
    let dir = tempfile::tempdir().expect("dir");
    let state = Arc::new(Mutex::new(State {
        now: t0(),
        settings: s,
        events: Some(vec![]),
        ..Default::default()
    }));
    let schedule = make(&state, dir.path());
    let me = Arc::new(Mutex::new(Arc::downgrade(&schedule)));
    Fx {
        state,
        dir,
        schedule,
        me,
    }
}

fn fixture() -> Fx {
    fixture_with(Some(settings(json!({}))))
}

fn mail(id: &str, ics: String) -> InviteMail {
    InviteMail {
        id: id.into(),
        from: "boss@example.com".into(),
        ics,
    }
}

impl Fx {
    fn s(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("s")
    }
    fn entries(&self) -> Vec<Value> {
        self.schedule.list()["entries"].as_array().cloned().unwrap_or_default()
    }
    fn at(&self, minutes: i64) {
        self.s().now = t0() + minutes * MIN;
    }
    fn mails(&self, m: Vec<InviteMail>) {
        self.s().mails = m;
    }
}

fn second(start: &'static str, end: &'static str) -> String {
    invite(Inv {
        uid: Some("second@google.com"),
        start: Some(start),
        end: Some(end),
        link: Some(Some("https://meet.google.com/xyz-abcd-efg")),
        ..Default::default()
    })
}

#[tokio::test]
async fn an_invite_is_scheduled_joined_a_minute_early_and_left_15_minutes_after_its_end() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    let mut entry = f.entries()[0].clone();
    entry["id"] = json!("");
    assert_eq!(
        entry,
        json!({"id": "", "source": "email", "start": "2026-10-12T13:00:00.000Z", "end": "2026-10-12T13:30:00.000Z",
            "title": "Weekly budget review", "organizer": "boss@example.com", "state": "scheduled", "meetingId": null, "note": null})
    );
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 0);
    assert_eq!(f.s().admits, 1, "the firewall is asked ahead");
    f.at(59);
    f.schedule.tick().await;
    assert_eq!(
        f.s().joins,
        [(
            "https://meet.google.com/abc-defg-hij".to_string(),
            json!({"source": "email", "organizer": "boss@example.com"}),
            crate::phone::history::parse_iso("2026-10-12T13:45:00Z").expect("t") as i64
        )]
    );
    assert_eq!(f.entries()[0]["state"], "joined");
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 1, "joined once");
}

/// Rust only: an invite whose recurrence the parser refuses is held as it was and the others are
/// scheduled. In the TS it stopped every later invite mail until it aged out.
#[tokio::test]
async fn an_invite_that_cannot_be_read_is_held_and_the_others_are_scheduled() {
    let f = fixture();
    let broken = invite(Inv {
        uid: Some("broken@google.com"),
        extra: Some("RRULE:FREQ=WEEKLY;BYMONTHDAY=15"),
        ..Default::default()
    });
    f.mails(vec![
        mail("m1", broken),
        mail("m2", second("20261012T150000Z", "20261012T153000Z")),
    ]);
    f.schedule.sync_email().await;
    let entries = f.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["start"], "2026-10-12T15:00:00.000Z");
    // A later mail sync is not held up by it either.
    f.mails(vec![mail("m3", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    assert_eq!(f.entries().len(), 2);
    // An update that makes a scheduled invite unreadable keeps what it had scheduled.
    let broken_update = invite(Inv {
        sequence: 1,
        extra: Some("RRULE:FREQ=WEEKLY;BYMONTHDAY=15"),
        ..Default::default()
    });
    f.mails(vec![mail("m4", broken_update)]);
    f.schedule.sync_email().await;
    let starts: Vec<Value> = f.entries().iter().map(|e| e["start"].clone()).collect();
    assert_eq!(starts.len(), 2);
    assert!(starts.contains(&json!("2026-10-12T13:00:00.000Z")));
}

#[tokio::test]
async fn the_schedule_survives_a_restart_the_same_mail_is_not_read_twice() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    let again = make(&f.state, f.dir.path());
    assert_eq!(again.list()["entries"].as_array().map(Vec::len), Some(1));
    f.mails(vec![mail(
        "m1",
        invite(Inv {
            method: Some("CANCEL"),
            sequence: 1,
            ..Default::default()
        }),
    )]);
    again.sync_email().await;
    assert_eq!(
        again.list()["entries"].as_array().map(Vec::len),
        Some(1),
        "a mail id already seen is skipped"
    );
}

#[tokio::test]
async fn an_update_moves_the_entry_and_keeps_its_id_a_cancellation_removes_it() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    let id = f.entries()[0]["id"].clone();
    f.mails(vec![mail(
        "m2",
        invite(Inv {
            sequence: 1,
            start: Some("20261012T140000Z"),
            end: Some("20261012T150000Z"),
            ..Default::default()
        }),
    )]);
    f.schedule.sync_email().await;
    let rows: Vec<(Value, Value)> = f
        .entries()
        .iter()
        .map(|e| (e["id"].clone(), e["start"].clone()))
        .collect();
    assert_eq!(rows, [(id, json!("2026-10-12T14:00:00.000Z"))]);
    f.mails(vec![mail(
        "m3",
        invite(Inv {
            method: Some("CANCEL"),
            sequence: 2,
            ..Default::default()
        }),
    )]);
    f.schedule.sync_email().await;
    assert!(f.entries().is_empty());
}

fn id_of(v: &Value) -> Map<String, Value> {
    json!({"id": v}).as_object().cloned().expect("o")
}

#[tokio::test]
async fn the_owners_cancel_holds_through_a_later_sync_and_restore_brings_the_join_back() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    let id = f.entries()[0]["id"].clone();
    f.schedule.set(&id_of(&id), "cancelled").expect("cancel");
    assert!(f.schedule.set(&id_of(&id), "cancelled").is_err());
    assert!(f.schedule.set(&id_of(&json!("nope")), "cancelled").is_err());
    f.mails(vec![mail(
        "m2",
        invite(Inv {
            sequence: 1,
            ..Default::default()
        }),
    )]);
    f.schedule.sync_email().await;
    f.at(60);
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 0);
    assert_eq!(f.entries()[0]["state"], "cancelled");
    f.schedule.set(&id_of(&id), "scheduled").expect("restore");
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 1);
}

#[tokio::test]
async fn two_meetings_at_once_the_earlier_one_is_joined_the_other_waits_and_is_then_skipped() {
    let f = fixture();
    f.mails(vec![
        mail("m1", invite(Inv::default())),
        mail("m2", second("20261012T130500Z", "20261012T140000Z")),
    ]);
    f.schedule.sync_email().await;
    f.at(59);
    f.schedule.tick().await;
    f.at(65);
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 1);
    f.at(76);
    f.schedule.tick().await;
    let s = &f.entries()[1];
    assert_eq!(
        (s["state"].clone(), s["note"].clone()),
        (json!("skipped"), json!("Another meeting was running"))
    );
}

#[tokio::test]
async fn a_meeting_that_ends_in_time_frees_the_agent_for_the_next_one_even_a_little_late() {
    let f = fixture();
    f.mails(vec![
        mail("m1", invite(Inv::default())),
        mail("m2", second("20261012T133000Z", "20261012T140000Z")),
    ]);
    f.schedule.sync_email().await;
    f.at(59);
    f.schedule.tick().await;
    f.at(90);
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 1, "still in the first meeting");
    f.s().busy = false;
    f.at(95);
    f.schedule.tick().await;
    assert_eq!(f.s().joins[1].0, "https://meet.google.com/xyz-abcd-efg");
}

#[tokio::test]
async fn a_refusal_from_the_firewall_is_shown_ahead_and_is_the_reason_when_the_join_is_skipped() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.s().refusal = Some("organizer".into());
    f.schedule.tick().await;
    assert_eq!(f.entries()[0]["note"], "The organizer is not an allowed sender");
    f.s().refusal = None;
    f.at(11);
    f.schedule.tick().await;
    assert_eq!(f.entries()[0]["note"], Value::Null, "asked again after ten minutes");
    f.s().join_error = Some(JoinFailed {
        refusal: Some("daily_limit".into()),
        message: "limit".into(),
    });
    f.at(60);
    f.schedule.tick().await;
    let e = &f.entries()[0];
    assert_eq!(
        (e["state"].clone(), e["note"].clone()),
        (
            json!("skipped"),
            json!("The limit of automatic joins for today is reached")
        )
    );
}

#[tokio::test]
async fn a_start_missed_while_the_agent_was_off_is_skipped_not_joined_late() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.at(71);
    f.schedule.tick().await;
    let e = &f.entries()[0];
    assert_eq!(
        (e["state"].clone(), e["note"].clone(), f.s().joins.len()),
        (
            json!("skipped"),
            json!("The agent was not running at the start time"),
            0
        )
    );
}

fn event(id: &str, start_min: i64, url: &str) -> CalendarEvent {
    CalendarEvent {
        id: id.into(),
        start: t0() + start_min * MIN,
        end: t0() + (start_min + 30) * MIN,
        url: url.into(),
        title: "Standup".into(),
        organizer: "me@example.com".into(),
    }
}

#[tokio::test]
async fn the_calendar_events_come_and_go_with_it_the_same_meeting_from_mail_and_calendar_is_one_entry() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.s().events = Some(vec![
        event("e1", 60, "https://meet.google.com/abc-defg-hij"),
        event("e2", 120, "https://meet.google.com/xyz-abcd-efg"),
    ]);
    f.schedule.sync_calendar().await;
    let rows = |f: &Fx| -> Vec<(Value, Value)> {
        f.entries()
            .iter()
            .map(|e| (e["source"].clone(), e["start"].clone()))
            .collect()
    };
    assert_eq!(
        rows(&f),
        [
            (json!("email"), json!("2026-10-12T13:00:00.000Z")),
            (json!("calendar"), json!("2026-10-12T14:00:00.000Z"))
        ]
    );
    f.s().events = Some(vec![event("e2", 150, "https://meet.google.com/xyz-abcd-efg")]);
    f.schedule.sync_calendar().await;
    assert_eq!(f.entries()[1]["start"], "2026-10-12T14:30:00.000Z", "moved");
    f.s().events = None;
    f.schedule.sync_calendar().await;
    assert_eq!(f.entries().len(), 2, "a calendar that cannot be read changes nothing");
    f.s().events = Some(vec![]);
    f.schedule.sync_calendar().await;
    let sources: Vec<Value> = f.entries().iter().map(|e| e["source"].clone()).collect();
    assert_eq!(sources, [json!("email")], "deleted from the calendar");
}

#[tokio::test]
async fn off_nothing_is_read_joined_or_listed_a_source_turned_off_drops_its_entries() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.s().settings = Some(settings(json!({"email": false})));
    f.schedule.tick().await;
    assert!(f.entries().is_empty());
    f.s().settings = None;
    f.mails(vec![mail(
        "m2",
        invite(Inv {
            uid: Some("x@google.com"),
            ..Default::default()
        }),
    )]);
    f.schedule.sync_email().await;
    f.at(60);
    f.schedule.tick().await;
    let (list, entries) = (f.schedule.list(), f.entries().len());
    let s = f.s();
    assert_eq!(
        (list["enabled"].clone(), entries, s.joins.len(), s.mails.len()),
        (json!(false), 0, 0, 1)
    );
}

#[tokio::test]
async fn a_meeting_moved_to_a_new_time_after_it_was_skipped_is_scheduled_again() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.at(71);
    f.schedule.tick().await;
    assert_eq!(f.entries()[0]["state"], "skipped");
    f.schedule.sync_email().await;
    assert_eq!(f.entries().len(), 1, "the same time is not scheduled twice");
    f.mails(vec![mail(
        "m2",
        invite(Inv {
            sequence: 1,
            start: Some("20261012T150000Z"),
            end: Some("20261012T153000Z"),
            ..Default::default()
        }),
    )]);
    f.schedule.sync_email().await;
    let rows: Vec<(Value, Value)> = f
        .entries()
        .iter()
        .map(|e| (e["state"].clone(), e["start"].clone()))
        .collect();
    assert_eq!(
        rows,
        [
            (json!("skipped"), json!("2026-10-12T13:00:00.000Z")),
            (json!("scheduled"), json!("2026-10-12T15:00:00.000Z"))
        ]
    );
}

#[tokio::test]
async fn back_to_back_a_scheduled_meeting_that_runs_over_is_left_when_the_next_one_starts() {
    let f = fixture();
    f.mails(vec![
        mail("m1", invite(Inv::default())),
        mail("m2", second("20261012T133000Z", "20261012T140000Z")),
    ]);
    f.schedule.sync_email().await;
    f.at(59);
    f.schedule.tick().await;
    f.at(89);
    f.schedule.tick().await;
    assert!(f.s().left.is_empty(), "not before the next one starts");
    f.at(90);
    f.schedule.tick().await;
    assert_eq!(f.s().left, ["00000001-1111-4111-8111-111111111111"]);
    f.schedule.tick().await;
    assert_eq!(f.s().joins[1].0, "https://meet.google.com/xyz-abcd-efg");
    let states: Vec<Value> = f.entries().iter().map(|e| e["state"].clone()).collect();
    assert_eq!(states, [json!("joined")], "the first has ended and is past");
}

#[tokio::test]
async fn a_meeting_the_owner_joined_by_hand_is_not_ended_for_a_scheduled_one() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.s().busy = true;
    f.at(65);
    f.schedule.tick().await;
    let s = f.s();
    assert_eq!((s.left.len(), s.joins.len()), (0, 0));
}

#[tokio::test]
async fn a_sync_or_a_cancel_that_lands_while_the_firewall_is_being_asked_does_not_lose_or_override_the_join() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.at(59);
    let (me, st) = (f.me.clone(), f.state.clone());
    f.s().during_join = Some(Arc::new(move || {
        let (me, st) = (me.clone(), st.clone());
        Box::pin(async move {
            st.lock().expect("s").mails = vec![mail(
                "m2",
                invite(Inv {
                    sequence: 1,
                    ..Default::default()
                }),
            )];
            let s = me.lock().expect("me").upgrade().expect("schedule");
            s.sync_email().await;
        })
    }));
    f.schedule.tick().await;
    f.s().during_join = None;
    let rows: Vec<(Value, Value)> = f
        .entries()
        .iter()
        .map(|e| (e["state"].clone(), e["meetingId"].clone()))
        .collect();
    assert_eq!(rows, [(json!("joined"), json!("00000001-1111-4111-8111-111111111111"))]);
    f.schedule.tick().await;
    assert_eq!(f.s().joins.len(), 1, "not joined a second time");

    let other = fixture();
    other.mails(vec![mail("m1", invite(Inv::default()))]);
    other.schedule.sync_email().await;
    other.at(59);
    let me = other.me.clone();
    other.s().during_join = Some(Arc::new(move || {
        let s = me.lock().expect("me").upgrade().expect("schedule");
        let id = s.list()["entries"][0]["id"].clone();
        s.set(&id_of(&id), "cancelled").expect("cancel");
        Box::pin(async {})
    }));
    other.schedule.tick().await;
    assert_eq!(
        (other.entries()[0]["state"].clone(), other.s().left.len()),
        (json!("cancelled"), 1),
        "the agent leaves again"
    );
}

#[tokio::test]
async fn an_invite_file_that_cannot_be_fetched_is_tried_again_then_given_up_so_later_mail_is_read() {
    let f = fixture();
    f.s().incomplete = true;
    for _ in 0..5 {
        f.s().now += MIN;
        f.schedule.sync_email().await;
    }
    assert_eq!(f.s().cursors, vec![None; 5]);
    f.s().incomplete = false;
    f.schedule.sync_email().await;
    assert!(
        f.s().cursors.last().expect("one").is_some(),
        "after five tries the cursor moves on"
    );
}

#[tokio::test]
async fn an_invite_that_arrives_after_the_meeting_started_says_so() {
    let f = fixture();
    f.at(75);
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    f.schedule.tick().await;
    let e = &f.entries()[0];
    assert_eq!(
        (e["state"].clone(), e["note"].clone()),
        (json!("skipped"), json!("The invite arrived after the meeting started"))
    );
}

/// Review: one entry that does not fit the state file is left out, not the whole schedule.
#[tokio::test]
async fn an_unreadable_entry_does_not_lose_the_schedule() {
    let f = fixture();
    f.mails(vec![mail("m1", invite(Inv::default()))]);
    f.schedule.sync_email().await;
    let path = f.dir.path().join("schedule.json");
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
    let mut broken = saved["entries"][0].clone();
    broken["title"] = Value::Null;
    broken["id"] = json!("x");
    saved["entries"].as_array_mut().expect("entries").push(broken);
    saved["entries"][0]["start"] = json!(saved["entries"][0]["start"].as_f64().expect("start") + 0.5);
    std::fs::write(&path, saved.to_string()).expect("write");
    let again = make(&f.state, f.dir.path());
    let entries = again.list()["entries"].as_array().cloned().unwrap_or_default();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["start"], "2026-10-12T13:00:00.000Z");
    assert_eq!(again.store().seen, ["m1"]);
}

/// Review: a Cancel during the join holds even when a sync drops the entry meanwhile.
#[tokio::test]
async fn a_cancel_during_the_join_holds_when_a_sync_drops_the_entry() {
    let f = fixture();
    f.s().settings = Some(settings(json!({"email": false, "calendar": "all"})));
    f.s().events = Some(vec![event("e1", 60, "https://meet.google.com/abc-defg-hij")]);
    f.schedule.sync_calendar().await;
    f.at(59);
    let (me, st) = (f.me.clone(), f.state.clone());
    f.s().during_join = Some(Arc::new(move || {
        let (me, st) = (me.clone(), st.clone());
        Box::pin(async move {
            let s = me.lock().expect("me").upgrade().expect("schedule");
            let id = s.list()["entries"][0]["id"].clone();
            s.set(&id_of(&id), "cancelled").expect("cancel");
            // Gone from the calendar too, a minute before its start.
            st.lock().expect("s").events = Some(vec![]);
            st.lock().expect("s").now -= 2 * MIN;
            s.sync_calendar().await;
            st.lock().expect("s").now += 2 * MIN;
        })
    }));
    f.schedule.tick().await;
    assert_eq!(f.s().left.len(), 1, "the agent leaves again");
    assert!(
        f.entries().is_empty(),
        "and the dropped entry is not brought back as joined"
    );
}
