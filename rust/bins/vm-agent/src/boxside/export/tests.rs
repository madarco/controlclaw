//! `workspace-export.test.ts`: what goes into the zip and what stays out, the Markdown, a cancelled
//! download. Conversations, meetings and calls come in through the sources, as the W6 and W8 slots
//! give them.

use std::os::unix::fs::symlink;
use std::sync::Arc;

use serde_json::json;

use super::*;
use crate::boxside::Exporter;

const SECRET: &str = "sk-live-0123456789abcdef";
const MEETING_ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

fn home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("dir");
    let ws = dir.path().join(".openclaw/workspace");
    for d in [
        "memory",
        "skills/weekly-report",
        "reports",
        "notes",
        "node_modules/x",
        ".git",
        "meetings",
        "Drive",
        "empty-33",
    ] {
        std::fs::create_dir_all(ws.join(d)).expect("d");
    }
    for (p, c) in [
        ("AGENTS.md", "# Agents"),
        ("SOUL.md", "# Soul"),
        ("MEMORY.md", "# Memory"),
        ("USER.md", "# User"),
        ("memory/2026-10-01.md", "notes of the day"),
        ("skills/weekly-report/SKILL.md", "# Weekly report"),
        ("reports/q3.md", "Q3"),
        ("photo.jpg", "JPEG"),
        ("notes/.env", SECRET),
        ("notes/google-credentials.json", SECRET),
        ("notes/id_ed25519", SECRET),
        ("debug.log", "log"),
        ("node_modules/x/i.js", "x"),
        (".git/config", "git"),
        ("Drive/doc.txt", "in drive"),
    ] {
        std::fs::write(ws.join(p), c).expect("w");
    }
    std::fs::write(ws.join(format!("meetings/{MEETING_ID}.json")), "{}").expect("w");
    symlink("/etc", ws.join("etc-link")).expect("link");
    symlink("AGENTS.md", ws.join("file-link.md")).expect("link");
    std::fs::write(dir.path().join(".openclaw/openclaw.json"), SECRET).expect("w");
    dir
}

fn exporter(home: &Path) -> WorkspaceExporter {
    let meeting = json!({"id": MEETING_ID, "startedAt": "2026-10-02T14:30:00.000Z", "endedAt": "2026-10-02T15:00:00.000Z",
        "meetingCode": "abc-defg-hij", "mode": "transcript", "notes": "Ship on Monday", "sessionIds": [], "state": "complete",
        "transcript": [{"speaker": "Ada", "at": "2026-10-02T14:31:02.000Z", "text": "Let's ship it."}]});
    let call = json!({"id": "c1", "direction": "inbound", "from": "+…0123", "to": "+…9999", "startedAt": 1_791_014_400_000i64,
        "endedAt": 1_791_014_460_000i64, "durationSeconds": 60, "endReason": "completed",
        "transcript": [{"at": 1_791_014_405_000i64, "speaker": "caller", "text": "Is the shop open?"},
                       {"at": 1_791_014_409_000i64, "speaker": "agent", "text": "Yes, until six."}],
        "transcriptTruncated": false});
    let refs = vec![
        json!({"agentId": "main", "db": "x", "sessionId": "tg-1111-aaaa", "sessionKey": "agent:main:telegram:direct:42",
            "createdAt": 1_790_845_200_000i64, "label": "Marco", "bytes": 1000, "channels": ["telegram"]}),
        json!({"agentId": "main", "db": "x", "sessionId": "444", "sessionKey": "agent:main:main",
            "createdAt": 1_791_104_400_000i64, "label": null, "bytes": 500, "channels": ["telegram"]}),
    ];
    let conversation = json!({"agentId": "main", "sessionId": "tg-1111-aaaa", "sessionKey": "agent:main:telegram:direct:42",
        "channels": ["telegram"], "chatType": "direct", "peer": null, "label": "Marco", "startedAt": 1_790_845_200_000i64,
        "turns": [{"kind": "message", "at": 1_790_845_200_000i64, "role": "user", "text": "Remember the dentist", "sender": "Marco"},
                  {"kind": "message", "at": 1_790_845_200_000i64, "role": "assistant", "text": "Saved: dentist Friday 10:00."},
                  {"kind": "reset", "at": 1_790_845_300_000i64},
                  {"kind": "message", "at": 1_790_845_400_000i64, "role": "user", "text": "---\nhi", "sender": "Marco"}]});
    WorkspaceExporter::new(
        home.join(".openclaw"),
        Arc::new(|| "jarvis".to_string()),
        Sources {
            conversations: Arc::new(move || refs.clone()),
            read_conversation: Arc::new(move |r| (r["sessionId"] == "tg-1111-aaaa").then(|| conversation.clone())),
            meetings: Arc::new(move || vec![meeting.clone()]),
            calls: Arc::new(move || vec![call.clone()]),
        },
    )
}

#[test]
fn helpers_file_names_and_secret_names() {
    assert_eq!(
        conversation_file_name(
            Some(1_790_812_800_000),
            "agent:main:telegram:direct:42",
            None,
            "abcdef123456",
            &[]
        ),
        "2026-10-01-telegram-42-abcdef12.md"
    );
    for n in [
        ".env",
        ".env.local",
        "server.pem",
        "id_rsa",
        "gcp-credentials.json",
        "secrets.yaml",
        "auth-profiles.json",
        ".npmrc",
    ] {
        assert!(is_secret_name(n), "{n}");
    }
    for n in ["MEMORY.md", "report.pdf", "keyboard-notes.md", "tokenizer.py"] {
        assert!(!is_secret_name(n), "{n}");
    }
    assert_eq!(slug("Réunion d'équipe: Q3!", 40), "Reunion-d-equipe-Q3");
    assert_eq!(slug("---", 40), "");
    assert_eq!(channel_name("clickclack"), "Team chat");
    assert_eq!(channel_name("matrix"), "Matrix");
}

/// The zip's entries and contents, through `unzip`.
fn unzip(path: &Path) -> Option<(Vec<String>, String)> {
    let list = std::process::Command::new("unzip").arg("-Z1").arg(path).output().ok()?;
    let all = std::process::Command::new("unzip").arg("-p").arg(path).output().ok()?;
    let check = std::process::Command::new("unzip").arg("-tq").arg(path).output().ok()?;
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stdout));
    Some((
        String::from_utf8_lossy(&list.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
        String::from_utf8_lossy(&all.stdout).into_owned(),
    ))
}

async fn zip_of(ex: &WorkspaceExporter) -> (Vec<u8>, bool) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let (dtx, drx) = tokio::sync::oneshot::channel();
    ex.stream(
        tx,
        Box::new(move |done, _| {
            let _ = dtx.send(done);
        }),
    );
    let mut out = Vec::new();
    while let Some(b) = rx.recv().await {
        out.extend_from_slice(&b);
    }
    (out, drx.await.expect("done"))
}

#[tokio::test]
async fn the_zip_what_goes_in_what_stays_out_and_no_secret_anywhere() {
    let h = home();
    let ex = exporter(h.path());
    let plan = ex.plan().await;
    assert_eq!(plan["conversations"], 2);
    assert_eq!((plan["meetings"].clone(), plan["calls"].clone()), (json!(1), json!(1)));
    assert_eq!(plan["mounts"], json!(["Drive", "etc-link"]));
    assert_eq!(
        plan["secrets"],
        json!(["notes/.env", "notes/google-credentials.json", "notes/id_ed25519"])
    );
    assert!(
        plan["filename"]
            .as_str()
            .is_some_and(|f| f.starts_with("jarvis-workspace-") && f.ends_with(".zip"))
    );

    let (bytes, done) = zip_of(&ex).await;
    assert!(done);
    assert!(!ex.busy());
    let path = h.path().join("out.zip");
    std::fs::write(&path, &bytes).expect("w");
    let Some((entries, all)) = unzip(&path) else { return };
    let p = format!("{}/", ex.base_name());
    for e in [
        "README.md",
        "workspace/AGENTS.md",
        "workspace/memory/2026-10-01.md",
        "workspace/skills/weekly-report/SKILL.md",
        "workspace/reports/q3.md",
        "workspace/photo.jpg",
        "memory/MEMORY.md",
        "memory/USER.md",
        "memory/daily/2026-10-01.md",
        "conversations/2026-10-01-telegram-Marco-tg-1111-.md",
        "conversations/2026-10-04-telegram-444.md",
        "meetings/2026-10-02-1430-abc-defg-hij.md",
        "calls/2026-10-03-0800-inbound-0123.md",
    ] {
        assert!(
            entries.contains(&format!("{p}{e}")),
            "missing {e}\n{}",
            entries.join("\n")
        );
    }
    for bad in [
        ".env",
        "credentials",
        "id_ed25519",
        ".log",
        "node_modules",
        ".git/",
        "Drive",
        "etc-link",
        "file-link",
        MEETING_ID,
        "openclaw.json",
    ] {
        assert!(
            !entries.iter().any(|e| e.contains(bad)),
            "{bad} should not be in the zip"
        );
    }
    assert!(!all.contains(SECRET), "the secret appears in the zip");
    assert!(all.contains("# Marco"));
    assert!(all.contains("- Channel: Telegram (direct chat)"));
    assert!(all.contains("**jarvis** · 2026-10-01 09:00 UTC\n\nSaved: dentist Friday 10:00."));
    assert!(all.contains("*New session started · "));
    assert!(all.contains("\\---\nhi"));
    assert!(all.contains("- Length: 30 min"));
    assert!(all.contains("**Ada** (14:31:02): Let's ship it."));
    assert!(all.contains("**Caller** (08:00:05): Is the shop open?"));
    assert!(all.contains("**jarvis** (08:00:09): Yes, until six."));
    assert!(all.contains("This conversation has no messages to show."));
    assert!(all.contains("2 conversations"));
    assert!(all.contains("`Drive`"));
    assert!(all.contains("`notes/.env`"));
}

#[tokio::test]
async fn a_browser_that_cancels_stops_the_zip_and_frees_the_slot() {
    let h = home();
    // Enough to need more than one piece of the channel.
    // Stored, not deflated (a .jpg), so it really is 4 MB of output.
    std::fs::write(h.path().join(".openclaw/workspace/big.jpg"), vec![7u8; 4 * 1024 * 1024]).expect("w");
    let ex = exporter(h.path());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let (dtx, drx) = tokio::sync::oneshot::channel();
    ex.stream(
        tx,
        Box::new(move |done, _| {
            let _ = dtx.send(done);
        }),
    );
    assert!(ex.busy());
    let _ = rx.recv().await;
    drop(rx);
    assert!(!drx.await.expect("done"), "not completed");
    assert!(!ex.busy());
    // A second download while one runs is refused by the route; here the slot is free again.
    let (_, done) = zip_of(&ex).await;
    assert!(done);
}

#[test]
fn a_file_swapped_for_a_link_after_the_walk_is_not_read() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().expect("dir");
    let (f, secret) = (dir.path().join("notes.md"), dir.path().join("secret"));
    std::fs::write(&f, "mine").expect("w");
    std::fs::write(&secret, "token").expect("w");
    let m = std::fs::metadata(&f).expect("m");
    let id = (m.dev(), m.ino());
    assert!(open_unchanged(&f, id).is_some());
    std::fs::remove_file(&f).expect("rm");
    symlink(&secret, &f).expect("link");
    assert!(open_unchanged(&f, id).is_none(), "a link");
    std::fs::remove_file(&f).expect("rm");
    std::fs::write(&f, "other").expect("w");
    let m2 = std::fs::metadata(&f).expect("m");
    if (m2.dev(), m2.ino()) != id {
        assert!(open_unchanged(&f, id).is_none(), "another file");
    }
}
