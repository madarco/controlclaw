//! `meeting-ics.test.ts`, and the parity cases in `rust/conformance/cases/w8/ics/`: the files the
//! TS build (ical.js) reads there, with what it found (`expected.json`, written by `gen.mts`).

use serde_json::{Value, json};

use super::*;

const ZONE: &str = "BEGIN:VTIMEZONE\r\nTZID:Europe/Rome\r\nBEGIN:DAYLIGHT\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\nTZNAME:CEST\r\nDTSTART:19700329T020000\r\nRRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\nBEGIN:STANDARD\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\nTZNAME:CET\r\nDTSTART:19701025T030000\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nEND:VTIMEZONE";

#[derive(Default)]
pub(crate) struct Inv<'a> {
    pub(crate) uid: Option<&'a str>,
    pub(crate) method: Option<&'a str>,
    pub(crate) sequence: i64,
    pub(crate) start: Option<&'a str>,
    pub(crate) end: Option<&'a str>,
    pub(crate) extra: Option<&'a str>,
    /// `Some(None)`: no conference link.
    pub(crate) link: Option<Option<&'a str>>,
    pub(crate) zone: bool,
}

/// An invite as Google Calendar mails it.
pub(crate) fn invite(o: Inv) -> String {
    let mut l: Vec<String> = vec![
        "BEGIN:VCALENDAR".into(),
        "PRODID:-//Google Inc//Google Calendar 70.9054//EN".into(),
        "VERSION:2.0".into(),
        "CALSCALE:GREGORIAN".into(),
        format!("METHOD:{}", o.method.unwrap_or("REQUEST")),
    ];
    if o.zone {
        l.push(ZONE.into());
    }
    l.push("BEGIN:VEVENT".into());
    if o.zone {
        l.push(format!(
            "DTSTART;TZID=Europe/Rome:{}",
            o.start.unwrap_or("20261012T150000")
        ));
        l.push(format!("DTEND;TZID=Europe/Rome:{}", o.end.unwrap_or("20261012T153000")));
    } else {
        l.push(format!("DTSTART:{}", o.start.unwrap_or("20261012T130000Z")));
        l.push(format!("DTEND:{}", o.end.unwrap_or("20261012T133000Z")));
    }
    l.push("DTSTAMP:20261010T090000Z".into());
    l.push("ORGANIZER;CN=Boss:mailto:boss@example.com".into());
    l.push(format!("UID:{}", o.uid.unwrap_or("abc123@google.com")));
    l.push("ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=agent@agentmail.to;X-NUM-GUESTS=0:mailto:agent@agentmail.to".into());
    match o.link {
        Some(None) => {}
        Some(Some(link)) => l.push(format!("X-GOOGLE-CONFERENCE:{link}")),
        None => l.push("X-GOOGLE-CONFERENCE:https://meet.google.com/abc-defg-hij".into()),
    }
    l.push("DESCRIPTION:Join with Google Meet\\n\\nLearn more about Meet at: https://support.google.com/a/users/answer/9282720".into());
    l.push(format!("SEQUENCE:{}", o.sequence));
    l.push("STATUS:CONFIRMED".into());
    l.push("SUMMARY:Weekly  budget review".into());
    l.push("TRANSP:OPAQUE".into());
    if let Some(e) = o.extra {
        l.push(e.into());
    }
    l.push("END:VEVENT".into());
    l.push("END:VCALENDAR".into());
    l.join("\r\n")
}

const UID: &str = "abc123@google.com";

fn ms(iso_text: &str) -> i64 {
    let p = |a: usize, b: usize| iso_text[a..b].parse::<i64>().expect("digits");
    Civil::new(p(0, 4), p(5, 7), p(8, 10), p(11, 13), p(14, 16), p(17, 19)).0 * 1000
}

fn window() -> (i64, i64) {
    (ms("2026-10-10T00:00:00Z"), ms("2026-10-17T00:00:00Z"))
}

#[test]
fn a_single_invite() {
    let (from, to) = window();
    let all = expand_invites(UID, &[invite(Inv::default())], from, to).expect("expand");
    assert_eq!(all.len(), 1);
    let o = &all[0];
    assert_eq!(o.key, format!("{UID}|"));
    assert_eq!(o.uid, UID);
    assert_eq!(iso(o.start), "2026-10-12T13:00:00.000Z");
    assert_eq!(iso(o.end), "2026-10-12T13:30:00.000Z");
    assert_eq!(o.url, "https://meet.google.com/abc-defg-hij");
    assert_eq!(o.title, "Weekly budget review");
    assert_eq!(invite_uids(&invite(Inv::default())), vec![UID.to_string()]);
}

#[test]
fn times_in_a_named_zone_use_the_files_rules() {
    let (from, to) = window();
    let o = &expand_invites(
        UID,
        &[invite(Inv {
            zone: true,
            ..Default::default()
        })],
        from,
        to,
    )
    .expect("expand")[0];
    assert_eq!(iso(o.start), "2026-10-12T13:00:00.000Z", "15:00 in Rome, summer time");
    let winter = invite(Inv {
        zone: true,
        start: Some("20261102T150000"),
        end: Some("20261102T153000"),
        ..Default::default()
    });
    let w = &expand_invites(UID, &[winter], from, ms("2026-11-30T00:00:00Z")).expect("expand")[0];
    assert_eq!(iso(w.start), "2026-11-02T14:00:00.000Z", "15:00 in Rome, winter time");
}

#[test]
fn only_google_meet_links() {
    let (from, to) = window();
    assert!(
        expand_invites(
            UID,
            &[invite(Inv {
                link: Some(None),
                ..Default::default()
            })],
            from,
            to
        )
        .expect("expand")
        .is_empty()
    );
    assert!(
        expand_invites(
            UID,
            &[invite(Inv {
                link: Some(Some("https://zoom.us/j/123456")),
                ..Default::default()
            })],
            from,
            to
        )
        .expect("expand")
        .is_empty()
    );
    let in_location = invite(Inv {
        link: Some(None),
        extra: Some("LOCATION:https://meet.google.com/xyz-abcd-efg"),
        ..Default::default()
    });
    assert_eq!(
        expand_invites(UID, &[in_location], from, to).expect("expand")[0].url,
        "https://meet.google.com/xyz-abcd-efg"
    );
    assert_eq!(
        meet_link(&[Some("Join: https://meet.google.com/abc-defg-hij?authuser=0")]).as_deref(),
        Some("https://meet.google.com/abc-defg-hij")
    );
    assert_eq!(meet_link(&[Some("https://meet.google.com/abc-defg-hijk")]), None);
    assert_eq!(meet_link(&[Some("https://meet.google.com/lookup/abcdef"), None]), None);
}

#[test]
fn an_update_moves_the_meeting_and_an_older_file_does_not_move_it_back() {
    let (from, to) = window();
    let moved = invite(Inv {
        sequence: 1,
        start: Some("20261013T100000Z"),
        end: Some("20261013T110000Z"),
        ..Default::default()
    });
    let old = invite(Inv::default());
    assert_eq!(
        iso(expand_invites(UID, &[old.clone(), moved.clone()], from, to).expect("expand")[0].start),
        "2026-10-13T10:00:00.000Z"
    );
    assert_eq!(
        iso(expand_invites(UID, &[moved, old], from, to).expect("expand")[0].start),
        "2026-10-13T10:00:00.000Z"
    );
}

#[test]
fn a_cancellation_removes_the_meeting() {
    let (from, to) = window();
    let cancel = invite(Inv {
        method: Some("CANCEL"),
        sequence: 1,
        ..Default::default()
    });
    assert!(
        expand_invites(UID, &[invite(Inv::default()), cancel], from, to)
            .expect("expand")
            .is_empty()
    );
    let reply = invite(Inv {
        method: Some("REPLY"),
        ..Default::default()
    });
    assert_eq!(
        expand_invites(UID, &[invite(Inv::default()), reply.clone()], from, to)
            .expect("expand")
            .len(),
        1
    );
    assert!(invite_uids(&reply).is_empty());
    let other = invite(Inv {
        uid: Some("other@google.com"),
        method: Some("CANCEL"),
        ..Default::default()
    });
    assert_eq!(
        expand_invites(UID, &[invite(Inv::default()), other], from, to)
            .expect("expand")
            .len(),
        1
    );
    assert!(
        expand_invites(UID, &["not a calendar".into(), String::new()], from, to)
            .expect("expand")
            .is_empty()
    );
    assert!(invite_uids("BEGIN:VCALENDAR\r\nBEGIN:VEVENT").is_empty());
}

#[test]
fn a_weekly_meeting_with_one_moved_and_one_cancelled() {
    let from = window().0;
    let until = ms("2026-10-24T00:00:00Z");
    let weekly = invite(Inv {
        zone: true,
        extra: Some("RRULE:FREQ=WEEKLY;BYDAY=MO,WE"),
        ..Default::default()
    });
    let all = expand_invites(UID, std::slice::from_ref(&weekly), from, until).expect("expand");
    assert_eq!(
        all.iter().map(|o| iso(o.start)).collect::<Vec<_>>(),
        [
            "2026-10-12T13:00:00.000Z",
            "2026-10-14T13:00:00.000Z",
            "2026-10-19T13:00:00.000Z",
            "2026-10-21T13:00:00.000Z"
        ]
    );
    assert_eq!(all[1].key, format!("{UID}|2026-10-14T13:00:00.000Z"));
    let moved_wed = invite(Inv {
        zone: true,
        sequence: 1,
        start: Some("20261014T170000"),
        end: Some("20261014T173000"),
        extra: Some("RECURRENCE-ID;TZID=Europe/Rome:20261014T150000"),
        ..Default::default()
    });
    let cancelled_mon = invite(Inv {
        zone: true,
        method: Some("CANCEL"),
        sequence: 1,
        start: Some("20261019T150000"),
        end: Some("20261019T153000"),
        extra: Some("RECURRENCE-ID;TZID=Europe/Rome:20261019T150000"),
        ..Default::default()
    });
    let after = expand_invites(UID, &[weekly.clone(), moved_wed.clone(), cancelled_mon], from, until).expect("expand");
    assert_eq!(
        after.iter().map(|o| iso(o.start)).collect::<Vec<_>>(),
        [
            "2026-10-12T13:00:00.000Z",
            "2026-10-14T15:00:00.000Z",
            "2026-10-21T13:00:00.000Z"
        ]
    );
    assert_eq!(
        after[1].key,
        format!("{UID}|2026-10-14T13:00:00.000Z"),
        "the moved one keeps its place"
    );
    let cancel_all = invite(Inv {
        method: Some("CANCEL"),
        sequence: 2,
        ..Default::default()
    });
    assert!(
        expand_invites(UID, &[weekly, moved_wed, cancel_all], from, until)
            .expect("expand")
            .is_empty()
    );
}

#[test]
fn all_day_and_outside_the_window_are_not_scheduled() {
    let (from, to) = window();
    let all_day = invite(Inv::default())
        .replace("DTSTART:20261012T130000Z", "DTSTART;VALUE=DATE:20261012")
        .replace("DTEND:20261012T133000Z", "DTEND;VALUE=DATE:20261013");
    assert!(expand_invites(UID, &[all_day], from, to).expect("expand").is_empty());
    let later = invite(Inv {
        start: Some("20261101T130000Z"),
        end: Some("20261101T133000Z"),
        ..Default::default()
    });
    assert!(expand_invites(UID, &[later], from, to).expect("expand").is_empty());
}

/// The files the TS build read, and what it found.
#[test]
fn parity_with_the_ts_build() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases/w8/ics");
    let cases: serde_json::Map<String, Value> =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).expect("cases")).expect("json");
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).expect("expected")).expect("json");
    let mut names: Vec<&String> = cases.keys().collect();
    names.sort();
    let mut failed = Vec::new();
    for name in names {
        let c = &cases[name];
        let files: Vec<String> = c["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| f.as_str().unwrap_or_default().to_string())
            .collect();
        let uid = c["uid"].as_str().unwrap_or_default();
        let (from, to) = (
            ms(c["from"].as_str().unwrap_or_default()),
            ms(c["to"].as_str().unwrap_or_default()),
        );
        let got = json!({
            "uids": files.iter().map(|f| invite_uids(f)).collect::<Vec<_>>(),
            // Where ical.js throws, the TS recorded `{error}`; the port returns the same message.
            "occurrences": match expand_invites(uid, &files, from, to) {
                Ok(list) => json!(list.iter().map(|o| json!({
                    "key": o.key, "uid": o.uid, "start": iso(o.start), "end": iso(o.end), "url": o.url, "title": o.title,
                })).collect::<Vec<_>>()),
                Err(e) => json!({"error": e}),
            },
        });
        if got != expected[name] {
            failed.push(format!("{name}:\n  ts:   {}\n  rust: {}", expected[name], got));
        }
    }
    assert!(failed.is_empty(), "differs from the TS build:\n{}", failed.join("\n"));
}

/// A zone that repeats an observance daily from 1601 is cut off at `MAX_CHANGES`, rather than
/// worked out to 2031 for every parse.
#[test]
fn an_oversized_zone_is_cut_off() {
    let obs: String = (0..20)
        .map(|i| {
            format!(
                "BEGIN:STANDARD\r\nTZOFFSETFROM:+0{}00\r\nTZOFFSETTO:+0100\r\nDTSTART:16010101T000000\r\nRRULE:FREQ=DAILY\r\nEND:STANDARD\r\n",
                i % 9
            )
        })
        .collect();
    let file = format!(
        "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VTIMEZONE\r\nTZID:Big/Zone\r\n{obs}END:VTIMEZONE\r\nBEGIN:VEVENT\r\nUID:big\r\nDTSTART;TZID=Big/Zone:20261020T090000\r\nDTEND;TZID=Big/Zone:20261020T093000\r\nX-GOOGLE-CONFERENCE:https://meet.google.com/abc-defg-hij\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    );
    let started = std::time::Instant::now();
    let (from, to) = (ms("2026-10-01T00:00:00Z"), ms("2026-11-01T00:00:00Z"));
    assert_eq!(expand_invites("big", &[file], from, to).expect("expand").len(), 1);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );
}
