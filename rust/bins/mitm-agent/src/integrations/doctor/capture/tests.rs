//! `doctor-capture.test.ts`: the agent's facts, the first message, the draft's checks, and a
//! capture session from its code to its Send.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::*;
use crate::integrations::as_map;
use crate::integrations::doctor::firewall::tests::{fixture, proposal, settle};

fn file(path: &str, content: &str, executable: bool) -> Value {
    json!({"path": path, "executable": executable, "content": content})
}

fn pack() -> Value {
    json!({"files": [
        file("template.yaml", "name: atlas-setup\nsteps:\n  - id: tool\n    run: { apply: scripts/tool-apply.sh, verify: scripts/tool-verify.sh }\n", false),
        file("scripts/tool-apply.sh", "#!/bin/sh\nnpm i -g @hubspot/cli@7\n", true),
        file("scripts/tool-verify.sh", "#!/bin/sh\nhs --version\n", true),
    ], "held": [{"id": "tool", "holds": true}], "at": "2026-10-13T10:00:00.000Z"})
}

fn with(base: Value, extra: Value) -> Value {
    let mut m = as_map(base);
    m.extend(as_map(extra));
    Value::Object(m)
}

fn plus(extra: Value) -> Value {
    let mut files = pack()["files"].as_array().cloned().unwrap_or_default();
    files.push(extra);
    with(pack(), json!({"files": files}))
}

const BASE: &str = "/home/controlclaw/.controlclaw/capture";

#[test]
fn the_facts_are_a_plain_path_and_the_first_message_names_the_folder_and_commands() {
    assert_eq!(
        read_capture_facts(&as_map(json!({"ok": true, "base": BASE}))).as_deref(),
        Some(BASE)
    );
    for bad in [
        json!({"base": "relative"}),
        json!({"base": "/home/x; rm -rf /"}),
        json!({"base": "/home/../etc"}),
        json!({"base": 7}),
        json!({}),
    ] {
        assert!(read_capture_facts(&as_map(bad.clone())).is_none(), "{bad}");
    }
    let t = capture_prompt(BASE, "session-1");
    for want in [
        "cc-runbook capture-folder --session session-1",
        "cc-runbook verify /home/controlclaw/.controlclaw/capture/session-1",
        "cc-runbook capture-pack --session session-1",
        "Change nothing on this agent outside that folder",
        "Run every command below on the agent, through this session's SSH connection",
        "Do not open or copy MEMORY.md",
    ] {
        assert!(t.contains(want), "{want}");
    }
}

#[test]
fn a_draft_is_read_strictly_and_refused_whole_for_a_secret_or_a_stand_in() {
    assert!(read_capture_pack(&pack(), &[]).is_ok());
    let refused = |raw: Value, why: &str, secrets: &[String]| {
        let r = read_capture_pack(&raw, secrets).expect_err("refused");
        assert!(r.join("\n").contains(why), "{why}: {r:?}");
    };
    refused(Value::Null, "not in the form", &[]);
    refused(with(pack(), json!({"apply": true})), "not in the form", &[]);
    refused(
        with(
            pack(),
            json!({"files": [with(pack()["files"][0].clone(), json!({"mode": "4755"}))]}),
        ),
        "not in the form",
        &[],
    );
    refused(plus(file("notes.txt", "x", false)), "path a template cannot have", &[]);
    refused(
        plus(file("scripts/../../etc/cron.d/x", "x", false)),
        "path a template cannot have",
        &[],
    );
    refused(
        plus(file("files/<img src=x onerror=alert(1)>", "x", false)),
        "path a template cannot have",
        &[],
    );
    refused(
        with(
            pack(),
            json!({"files": pack()["files"].as_array().expect("files")[1..].to_vec()}),
        ),
        "no template.yaml",
        &[],
    );
    refused(
        plus(file("files/big.md", &"x".repeat(64 * 1024 + 1), false)),
        "larger than 64 KB",
        &[],
    );
    let mut many = vec![pack()["files"][0].clone()];
    many.extend((0..40).map(|i| file(&format!("files/f{i}"), "x", false)));
    refused(with(pack(), json!({"files": many})), "at most 40 files", &[]);
    refused(plus(file("files/a.md", "a\u{0}b", false)), "not a text file", &[]);
    refused(
        with(pack(), json!({"held": [{"id": "tool", "holds": "yes"}]})),
        "not in the form",
        &[],
    );
    refused(
        with(
            pack(),
            json!({"held": [{"id": "tool", "holds": true, "note": "<b>held</b>"}]}),
        ),
        "not in the form",
        &[],
    );
    refused(with(pack(), json!({"at": "yesterday"})), "not in the form", &[]);
    refused(
        plus(file("files/USER.md", "Anna likes tea.\n", false)),
        "files/USER.md: a template never holds what the agent remembers",
        &[],
    );
    refused(
        plus(file("files/Memory/2026-10-01.md", "x\n", false)),
        "never holds what the agent remembers",
        &[],
    );
    refused(
        plus(file("files/credentials/telegram.json", "{}\n", false)),
        "never holds",
        &[],
    );
    for step in [
        "file: { path: IDENTITY.md, from: files/x.md }",
        "line: { file: \"memory/today.md\", match: \"^a\", line: \"a\" }",
        "file:\n      path: 'user.md'\n      from: files/x.md",
    ] {
        let raw = with(
            pack(),
            json!({"files": [file("template.yaml", &format!("name: t\nsteps:\n  - id: who\n    {step}\n"), false), file("files/x.md", "x\n", false)]}),
        );
        refused(raw, "a step writes a file a template never writes", &[]);
    }
    use base64::Engine;
    let secret = "sk-live-0123456789abcdef";
    let secrets = [secret.to_string(), "p@ss word/1234".to_string()];
    for form in [
        secret.to_string(),
        base64::engine::general_purpose::STANDARD.encode(secret),
        super::super::repair::encode_uri_component("p@ss word/1234"),
    ] {
        refused(
            plus(file("files/a.md", &format!("x {form}\n"), false)),
            "files/a.md: line 1 holds a value this firewall keeps secret",
            &secrets,
        );
    }
    refused(
        plus(file("files/a.md", "cctc_abcdefgh12345678\n", false)),
        "stand-in",
        &[],
    );
}

async fn ended(f: &crate::integrations::doctor::firewall::tests::Fx) {
    f.agents.gets.lock().expect("lock").insert(
        "/templates/capture/facts".into(),
        Ok(as_map(json!({"ok": true, "base": BASE}))),
    );
    *f.agents.post_answer.lock().expect("lock") = as_map(json!({"ok": true, "pack": pack()}));
    assert_eq!(
        f.doctor
            .handle("propose", proposal(json!({"kind": "template-capture"})))
            .await
            .status,
        "awaiting_code"
    );
    f.doctor
        .handle("confirm", as_map(json!({"sessionId": "session-1", "code": "123456"})))
        .await;
    settle().await;
    f.doctor.handle("stop", as_map(json!({"sessionId": "session-1"}))).await;
    settle().await;
}

#[tokio::test]
async fn the_code_says_root_and_one_hour_the_first_message_is_the_firewalls_and_the_draft_goes_on_a_press_once() {
    let f = fixture(None, None);
    f.agents.gets.lock().expect("lock").insert(
        "/templates/capture/facts".into(),
        Ok(as_map(json!({"ok": true, "base": BASE}))),
    );
    *f.agents.post_answer.lock().expect("lock") = as_map(json!({"ok": true, "pack": pack()}));
    f.doctor
        .handle("propose", proposal(json!({"kind": "template-capture"})))
        .await;
    let summary = f.codes.sent.lock().expect("lock")[0].clone();
    assert!(
        summary.contains("with root access to write a template from it") && summary.contains("1 hour"),
        "{summary}"
    );
    f.doctor
        .handle("confirm", as_map(json!({"sessionId": "session-1", "code": "123456"})))
        .await;
    settle().await;
    assert!(
        f.runs()[0]
            .problem
            .contains("cc-runbook capture-folder --session session-1")
    );
    f.doctor.handle("stop", as_map(json!({"sessionId": "session-1"}))).await;
    settle().await;
    let kept = f.doctor.record("session-1").expect("record").capture.expect("capture");
    assert_eq!(kept.pack.as_ref().map(|p| p.files.len()), Some(3));
    assert!(f.sent.lock().expect("lock").is_empty());
    assert_eq!(
        f.doctor.send_capture("session-1", "user-1", false).await,
        json!({"ok": true})
    );
    assert_eq!(f.sent.lock().expect("lock").len(), 1);
    let kept = f.doctor.record("session-1").expect("record").capture.expect("capture");
    assert_eq!(kept.sent_hash, Some(capture_hash(kept.pack.as_ref().expect("pack"))));
}

#[tokio::test]
async fn refused_with_no_code_when_the_agent_cannot_say_where_it_writes_or_nobody_is_approved() {
    let f = fixture(None, None);
    f.agents
        .gets
        .lock()
        .expect("lock")
        .insert("/templates/capture/facts".into(), Err("agent 404: none".into()));
    let o = f
        .doctor
        .handle("propose", proposal(json!({"kind": "template-capture"})))
        .await;
    assert!(
        !o.ok
            && o.message
                .unwrap_or_default()
                .contains("cannot be read by a capture session yet")
    );
    let f = fixture(None, None);
    f.agents
        .gets
        .lock()
        .expect("lock")
        .insert("/templates/capture/facts".into(), Ok(as_map(json!({"base": BASE}))));
    f.routes.0.lock().expect("lock").clear();
    let o = f
        .doctor
        .handle("propose", proposal(json!({"kind": "template-capture"})))
        .await;
    assert!(
        !o.ok
            && o.message
                .unwrap_or_default()
                .contains("Nobody is approved on a channel")
    );
    assert!(f.codes.sent.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_draft_waiting_in_controlclaw_is_replaced_only_when_the_person_says_so() {
    let f = fixture(None, None);
    f.draft_waiting.store(true, Ordering::SeqCst);
    ended(&f).await;
    assert_eq!(
        f.doctor.send_capture("session-1", "user-1", false).await,
        json!({"ok": false, "message": "A draft of this agent is waiting in ControlClaw.", "replace": true})
    );
    assert!(
        f.doctor
            .record("session-1")
            .expect("record")
            .capture
            .expect("capture")
            .sent_at
            .is_none()
    );
    assert_eq!(
        f.doctor.send_capture("session-1", "user-1", true).await,
        json!({"ok": true})
    );
    let replaces: Vec<Value> = f
        .sent
        .lock()
        .expect("lock")
        .iter()
        .map(|b| b.get("replace").cloned().unwrap_or(Value::Null))
        .collect();
    assert_eq!(replaces, [Value::Null, json!(true)]);
}
