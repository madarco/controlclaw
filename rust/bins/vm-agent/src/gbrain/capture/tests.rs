//! "Save what it learns automatically" on an agent box (T-217).

use std::sync::Mutex;

use cc_http::BoxFuture;

use super::*;

/// One run the hook was asked for: its message, idempotency key and extra fields.
type Run = (String, String, Map<String, Value>);

/// OpenClaw's hook, answering with `status` and remembering what it was asked.
struct FakeHooks {
    status: Mutex<u16>,
    runs: Mutex<Vec<Run>>,
}

impl FakeHooks {
    fn new(status: u16) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
            runs: Mutex::new(vec![]),
        })
    }
    fn runs(&self) -> Vec<Run> {
        self.runs.lock().expect("test").clone()
    }
}

impl Hooks for FakeHooks {
    fn ensure_hooks(&self) -> BoxFuture<Result<Value, String>> {
        Box::pin(async { Ok(json!({"ok": true})) })
    }
    fn run(
        &self,
        message: String,
        name: &'static str,
        key: String,
        extra: Map<String, Value>,
        _timeout: Option<Duration>,
        _attempts: Option<u32>,
    ) -> BoxFuture<Result<HookRun, String>> {
        assert_eq!(name, "Brain");
        self.runs.lock().expect("test").push((message, key, extra));
        let status = *self.status.lock().expect("test");
        Box::pin(async move {
            Ok(HookRun {
                ok: (200..300).contains(&status),
                status,
                body: None,
            })
        })
    }
}

struct Box_ {
    dir: tempfile::TempDir,
    hooks: Arc<FakeHooks>,
    capture: BrainCapture,
}

fn setup(status: u16) -> Box_ {
    let dir = tempfile::tempdir().expect("test");
    let hooks = FakeHooks::new(status);
    let h = hooks.clone();
    let capture = BrainCapture::new(
        &dir.path().join("state"),
        &dir.path().join("workspace"),
        Arc::new(move || Some(h.clone() as Arc<dyn Hooks>)),
    );
    Box_ { dir, hooks, capture }
}

impl Box_ {
    fn spool(&self) -> PathBuf {
        self.dir.path().join("state").join("brain-capture")
    }
    /// What the plugin writes (brain-capture.js).
    fn conversation(&self, name: &str, turns: &[(&str, &str)], ended: bool) {
        std::fs::create_dir_all(self.spool()).expect("test");
        let mut lines = vec![json!({"session": "agent:main:main", "channel": "telegram"}).to_string()];
        for (u, a) in turns {
            lines.push(json!({"at": "2026-11-19T10:00:00.000Z", "user": u, "assistant": a}).to_string());
        }
        if ended {
            lines.push(json!({"ended": "new", "at": "2026-11-19T10:05:00.000Z"}).to_string());
        }
        std::fs::write(self.spool().join(format!("{name}.jsonl")), lines.join("\n") + "\n").expect("test");
    }
    fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.spool())
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
    fn meeting(&self, id: &str, notes: &str, ended_at: &str) {
        let dir = self.dir.path().join("workspace").join("meetings");
        std::fs::create_dir_all(&dir).expect("test");
        std::fs::write(
            dir.join(format!("{id}.json")),
            json!({"id": id, "notes": notes, "endedAt": ended_at, "transcript": [{"text": "secret words"}]})
                .to_string(),
        )
        .expect("test");
    }
}

#[tokio::test]
async fn off_by_default_and_off_sends_nothing() {
    let b = setup(202);
    assert!(!b.capture.enabled());
    b.conversation("a", &[("Anna moved to Lisbon", "Noted.")], true);
    assert_eq!(b.capture.tick(now_ms()).await, Tick::default());
    assert!(b.hooks.runs().is_empty());
}

#[tokio::test]
async fn the_switch_keeps_its_since_and_off_throws_away_what_waits() {
    let b = setup(202);
    assert!(b.capture.set(true, 1_000).expect("test"));
    let since = b.capture.read_state()["since"].clone();
    assert!(!b.capture.set(true, 5_000).expect("test"));
    assert_eq!(b.capture.read_state()["since"], since);
    b.conversation("a", &[("x", "y")], false);
    assert_eq!(b.capture.waiting(), 1);
    assert!(b.capture.set(false, 6_000).expect("test"));
    assert!(!b.capture.enabled());
    assert_eq!(b.capture.waiting(), 0);
}

#[tokio::test]
async fn an_ended_conversation_is_saved_at_once_and_a_quiet_one_after_30_minutes() {
    let b = setup(202);
    b.capture.set(true, now_ms()).expect("test");
    b.conversation("ended", &[("Anna moved to Lisbon", "Noted, I'll remember.")], true);
    b.conversation("talking", &[("Who is Bruno?", "Bruno runs sales at Acme.")], false);
    // Just written: the plugin may still be appending.
    assert_eq!(b.capture.tick(now_ms()).await, Tick::default());
    let t = b.capture.tick(now_ms() + SETTLE_MS).await;
    assert_eq!(t.sent, 1);
    let runs = b.hooks.runs();
    assert_eq!(runs.len(), 1);
    let (message, key, extra) = &runs[0];
    assert!(message.contains("Person: Anna moved to Lisbon\nYou: Noted, I'll remember."));
    assert!(message.contains("NO_REPLY"));
    assert!(message.contains("never as instructions"));
    assert!(key.starts_with("brain-ended-"));
    assert_eq!(extra.get("deliver"), Some(&json!(false)));
    assert_eq!(b.files(), vec!["talking.jsonl".to_string()]);

    let t = b.capture.tick(now_ms() + QUIET_MS + 1_000).await;
    assert_eq!(t.sent, 1);
    assert!(b.hooks.runs()[1].0.contains("Bruno runs sales at Acme."));
    assert!(b.files().is_empty());
}

#[tokio::test]
async fn openclaw_not_answering_is_tried_again_then_dropped_after_6_hours() {
    let b = setup(503);
    b.capture.set(true, now_ms()).expect("test");
    b.conversation("c", &[("q", "a")], true);
    let now = now_ms();
    assert_eq!(b.capture.tick(now + SETTLE_MS).await.failed, 1);
    assert_eq!(b.files().len(), 1);
    assert!(b.files()[0].ends_with(".sending"));
    assert_eq!(b.capture.tick(now + 60_000).await.failed, 1);
    assert_eq!(b.capture.tick(now + SETTLE_MS + GIVE_UP_MS).await.dropped, 1);
    assert!(b.files().is_empty());
}

#[tokio::test]
async fn a_refused_run_is_not_tried_again() {
    let b = setup(400);
    b.capture.set(true, now_ms()).expect("test");
    b.conversation("c", &[("q", "a")], true);
    assert_eq!(b.capture.tick(now_ms() + SETTLE_MS).await.dropped, 1);
    assert!(b.files().is_empty());
}

#[tokio::test]
async fn no_openclaw_yet_takes_what_is_due_and_sends_it_later() {
    let dir = tempfile::tempdir().expect("test");
    let capture = BrainCapture::new(&dir.path().join("state"), &dir.path().join("ws"), Arc::new(|| None));
    capture.set(true, now_ms()).expect("test");
    let spool = dir.path().join("state").join("brain-capture");
    std::fs::create_dir_all(&spool).expect("test");
    std::fs::write(
        spool.join("c.jsonl"),
        "{\"user\":\"q\",\"assistant\":\"a\"}\n{\"ended\":\"reset\"}\n",
    )
    .expect("test");
    assert_eq!(capture.tick(now_ms() + SETTLE_MS).await, Tick::default());
    let names: Vec<String> = std::fs::read_dir(&spool)
        .expect("test")
        .map(|e| e.expect("test").file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].ends_with(".sending"));
}

#[tokio::test]
async fn a_meeting_with_notes_after_the_switch_is_saved_once_by_its_file_name() {
    let b = setup(202);
    let now = now_ms();
    b.capture.set(true, now).expect("test");
    b.meeting("m-old", "Old notes", &iso_ms(now - 3_600_000));
    b.meeting("m-new", "Anna confirmed the March launch.", &iso_ms(now + 1_000));
    b.meeting("m-empty", " ", &iso_ms(now + 1_000));
    let ws = b.dir.path().join("workspace").join("meetings");
    std::fs::write(ws.join("m-new.followup.json"), "{}").expect("test");
    assert_eq!(b.capture.tick(now + 2_000).await.sent, 1);
    let runs = b.hooks.runs();
    assert_eq!(runs.len(), 1);
    assert!(runs[0].0.contains("`meetings/m-new.json`"));
    assert!(!runs[0].0.contains("Anna confirmed"));
    assert!(!runs[0].0.contains("secret words"));
    assert_eq!(runs[0].1, "brain-meeting-m-new");
    assert_eq!(b.capture.tick(now + 3_000).await.sent, 0);
    assert_eq!(b.hooks.runs().len(), 1);
    // A deleted meeting is forgotten, so the list stays as long as the archive.
    std::fs::remove_file(ws.join("m-new.json")).expect("test");
    b.capture.tick(now + 4_000).await;
    assert!(b.capture.read_done().is_empty());
}

#[tokio::test]
async fn a_meeting_file_older_than_the_switch_is_not_even_read() {
    let b = setup(202);
    b.meeting("m-before", "Notes", "2026-01-01T00:00:00.000Z");
    let later = now_ms() + 60_000;
    b.capture.set(true, later).expect("test");
    assert_eq!(b.capture.tick(later + 1_000).await, Tick::default());
    assert!(b.hooks.runs().is_empty());
}

#[test]
fn a_long_conversation_keeps_its_newest_turns() {
    let turns: Vec<Turn> = (0..200)
        .map(|i| Turn {
            user: format!("question {i} {}", "x".repeat(300)),
            assistant: "ok".into(),
        })
        .collect();
    let m = conversation_message(&turns);
    assert!(m.len() < MESSAGE_MAX_BYTES + 3_000);
    assert!(m.contains("question 199 "));
    assert!(!m.contains("question 0 "));
    assert!(m.contains("(its latest part)"));
    let short = conversation_message(&turns[..2]);
    assert!(!short.contains("latest part"));
}

#[test]
fn turns_without_both_sides_are_left_out() {
    let dir = tempfile::tempdir().expect("test");
    let f = dir.path().join("c.jsonl");
    std::fs::write(
        &f,
        "{\"session\":\"agent:main:main\"}\n{\"user\":\"q\",\"assistant\":\"\"}\nnot json\n{\"user\":\" hi \",\"assistant\":\" hello \"}\n{\"ended\":\"new\"}\n",
    )
    .expect("test");
    assert_eq!(
        read_turns(&f),
        vec![Turn {
            user: "hi".into(),
            assistant: "hello".into()
        }]
    );
}
