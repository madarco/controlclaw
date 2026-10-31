//! `meeting-sources.test.ts`, against a local server standing in for AgentMail, its download host
//! and Google Calendar.

use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;

type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// Serve `answer(path_and_query)` -> (status, body), recording what was asked and with what key.
async fn server(answer: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let answer = Arc::new(answer);
    let mut router = cc_http::Router::new(&["all"]);
    router.route(
        "all",
        |_, _| true,
        move |req, _| {
            let (s, answer) = (s.clone(), answer.clone());
            async move {
                let target = req.uri().path_and_query().map_or("/".to_string(), |p| p.to_string());
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                s.lock().expect("seen").push((target.clone(), auth));
                let (status, body) = answer(&target);
                cc_http::full(
                    http::StatusCode::from_u16(status).expect("status"),
                    "application/json",
                    body,
                )
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(cc_http::serve(listener, Arc::new(router)));
    (base, seen)
}

fn http(base: &str) -> Http {
    Http {
        client: cc_client::HttpClient::new(false).expect("client"),
        agentmail: format!("{base}/v0"),
        calendar: format!("{base}/calendar/v3"),
        downloads: format!("{base}/cdn/"),
    }
}

#[tokio::test]
async fn invite_mail_only_received_mail_with_a_calendar_file_fetched_with_the_boxs_placeholder() {
    let base = Arc::new(Mutex::new(String::new()));
    let b = base.clone();
    let (url, seen) = server(move |target| {
        let base = b.lock().expect("b").clone();
        if target.starts_with("/cdn/a9") {
            return (404, "gone".into());
        }
        if target.starts_with("/cdn/") {
            return (200, "BEGIN:VCALENDAR".into());
        }
        if target.contains("/attachments/") {
            let id = target.rsplit('/').next().unwrap_or_default();
            return (200, json!({"download_url": format!("{base}/cdn/{id}")}).to_string());
        }
        (200, json!({"messages": [
            {"message_id": "<m1@x>", "from": "Boss <Boss@Example.com>", "timestamp": "2026-10-10T10:00:00Z", "labels": ["received"], "attachments": [
                {"attachment_id": "a1", "filename": "invite.ics", "content_type": "application/ics", "size": 900},
                {"attachment_id": "a2", "filename": "logo.png", "content_type": "image/png", "size": 900},
                {"attachment_id": "a3", "content_type": "text/calendar; method=REQUEST", "size": 999_999}]},
            {"message_id": "m0", "from": "boss@example.com", "timestamp": "2026-10-10T09:00:00Z", "labels": ["received"], "attachments": [{"attachment_id": "a9", "filename": "old.ics", "size": 10}]},
            {"message_id": "m2", "from": "agent@agentmail.to", "timestamp": "2026-10-10T11:00:00Z", "labels": ["sent"], "attachments": [{"attachment_id": "b1", "filename": "x.ics", "size": 10}]},
            {"message_id": "m3", "from": "stranger@example.net", "timestamp": "2026-10-10T12:00:00Z", "labels": ["received", "blocked"], "attachments": []}
        ]}).to_string())
    })
    .await;
    *base.lock().expect("b") = url.clone();
    let now = parse_iso("2026-10-10T12:30:00Z").expect("t") as i64;
    let mailbox = Some(("agent@agentmail.to".to_string(), "CC-AMAIL-x".to_string()));
    let batch = read_invite_mail(&http(&url), mailbox, None, now).await.expect("read");
    // One file that is gone does not stop the rest.
    assert_eq!(
        batch,
        Some(MailBatch {
            mails: vec![InviteMail {
                id: "<m1@x>:a1".into(),
                from: "boss@example.com".into(),
                ics: "BEGIN:VCALENDAR".into()
            }],
            cursor: "2026-10-10T12:00:00Z".into(),
            incomplete: true,
        })
    );
    let seen = seen.lock().expect("seen").clone();
    assert_eq!(
        seen[0].0,
        "/v0/inboxes/agent%40agentmail.to/messages?limit=50&ascending=true&after=2026-09-26T12%3A30%3A00.000Z"
    );
    assert_eq!(seen[3].0, "/v0/inboxes/agent%40agentmail.to/messages/m0/attachments/a9");
    // The download link gets no key.
    let auths: Vec<Option<&str>> = seen.iter().map(|s| s.1.as_deref()).collect();
    assert_eq!(
        auths,
        [
            Some("Bearer CC-AMAIL-x"),
            Some("Bearer CC-AMAIL-x"),
            None,
            Some("Bearer CC-AMAIL-x"),
            None
        ]
    );
    assert_eq!(read_invite_mail(&http(&url), None, None, now).await, Ok(None));
    assert_eq!(address_of(Some(&json!("someone"))), None);
}

#[tokio::test]
async fn calendar_meet_events_the_account_has_not_declined_invited_means_invited() {
    let (url, seen) = server(|_| {
        (200, json!({"items": [
            {"id": "own", "summary": "My own meeting", "hangoutLink": "https://meet.google.com/aaa-bbbb-ccc", "start": {"dateTime": "2026-10-12T15:00:00+02:00"}, "end": {"dateTime": "2026-10-12T15:30:00+02:00"}, "organizer": {"email": "me@example.com", "self": true}},
            {"id": "guest", "summary": "Invited", "conferenceData": {"entryPoints": [{"uri": "tel:+1"}, {"uri": "https://meet.google.com/ddd-eeee-fff"}]}, "start": {"dateTime": "2026-10-12T16:00:00Z"}, "end": {"dateTime": "2026-10-12T17:00:00Z"}, "organizer": {"email": "Boss@example.com"}, "attendees": [{"email": "me@example.com", "self": true, "responseStatus": "needsAction"}]},
            {"id": "agent", "hangoutLink": "https://meet.google.com/ggg-hhhh-iii", "start": {"dateTime": "2026-10-12T18:00:00Z"}, "end": {"dateTime": "2026-10-12T19:00:00Z"}, "organizer": {"email": "me@example.com", "self": true}, "attendees": [{"email": "Agent@agentmail.to"}]},
            {"id": "declined", "hangoutLink": "https://meet.google.com/jjj-kkkk-lll", "start": {"dateTime": "2026-10-12T20:00:00Z"}, "end": {"dateTime": "2026-10-12T21:00:00Z"}, "organizer": {"email": "boss@example.com"}, "attendees": [{"self": true, "responseStatus": "declined"}]},
            {"id": "allday", "hangoutLink": "https://meet.google.com/mmm-nnnn-ooo", "start": {}, "end": {}, "organizer": {"email": "boss@example.com"}},
            {"id": "nolink", "start": {"dateTime": "2026-10-12T16:00:00Z"}, "end": {"dateTime": "2026-10-12T17:00:00Z"}, "organizer": {"email": "boss@example.com"}, "attendees": [{"self": true}]},
            {"id": "gone", "status": "cancelled", "hangoutLink": "https://meet.google.com/ppp-qqqq-rrr", "start": {"dateTime": "2026-10-12T16:00:00Z"}, "end": {"dateTime": "2026-10-12T17:00:00Z"}}
        ]}).to_string())
    })
    .await;
    let h = http(&url);
    let account = || Some(("CC-GOOG-x".to_string(), Some("me@example.com".to_string())));
    let agent = || Some("agent@agentmail.to".to_string());
    let from = parse_iso("2026-10-12T00:00:00Z").expect("t") as i64;
    let to = from + 24 * 3_600_000;
    let invited = read_calendar(&h, account(), agent(), from, to, "invited")
        .await
        .expect("read")
        .expect("some");
    let rows: Vec<(&str, &str, &str)> = invited
        .iter()
        .map(|e| (e.id.as_str(), e.organizer.as_str(), e.url.as_str()))
        .collect();
    assert_eq!(
        rows,
        [
            ("guest", "boss@example.com", "https://meet.google.com/ddd-eeee-fff"),
            ("agent", "me@example.com", "https://meet.google.com/ggg-hhhh-iii"),
        ]
    );
    let all = read_calendar(&h, account(), agent(), from, to, "all")
        .await
        .expect("read")
        .expect("some");
    assert_eq!(
        all.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["own", "guest", "agent"]
    );
    assert!(
        seen.lock().expect("seen")[0]
            .0
            .starts_with("/calendar/v3/calendars/primary/events?singleEvents=true&orderBy=startTime")
    );
    assert_eq!(read_calendar(&h, None, None, from, to, "all").await, Ok(None));
}

#[test]
fn env_files_and_addresses() {
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("gog.env");
    std::fs::write(
        &p,
        "GOG_ACCESS_TOKEN=\"CC-GOOG-x\"\n  CC_GOOGLE_SERVICES=calendar,gmail \nlower=no\nX='a\n",
    )
    .expect("write");
    let env = env_file(&p);
    assert_eq!(env.get("GOG_ACCESS_TOKEN").map(String::as_str), Some("CC-GOOG-x"));
    assert_eq!(
        env.get("CC_GOOGLE_SERVICES").map(String::as_str),
        Some("calendar,gmail")
    );
    assert_eq!(env.get("X").map(String::as_str), Some("'a"));
    assert!(!env.contains_key("lower"));
    assert_eq!(
        address_of(Some(&json!("Boss <Boss@Example.com> "))).as_deref(),
        Some("boss@example.com")
    );
}
