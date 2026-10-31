//! `logs.test.ts`, and the stream: the backlog, a line appended to the file, the service event.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;

fn r() -> Redaction {
    let dir = tempfile::tempdir().expect("dir");
    Redaction::load(dir.path())
}

#[test]
fn cli_log_record_keeps_four_fields_and_drops_raw() {
    let r = r();
    let rec = json!({"type": "log", "time": "2026-09-09T16:51:11.224+00:00", "level": "INFO", "subsystem": "gateway/ws", "message": "⇄ res ✓ x", "raw": "{...}"});
    assert_eq!(
        map_cli_record(&r, &rec.to_string()),
        Some(
            json!({"time": "2026-09-09T16:51:11.224+00:00", "level": "info", "subsystem": "gateway/ws", "message": "⇄ res ✓ x"})
        )
    );
    assert_eq!(
        map_cli_record(&r, &json!({"type": "meta", "file": "/tmp/x"}).to_string()),
        None
    );
    assert_eq!(map_cli_record(&r, "not json"), None);
    let notice = map_cli_record(
        &r,
        &json!({"type": "notice", "message": "Log tail truncated"}).to_string(),
    );
    assert_eq!(notice.map(|n| n["level"].clone()), Some(json!("notice")));
}

#[test]
fn file_record_maps_rendered_message_level_and_subsystem() {
    let r = r();
    let raw = json!({"0": "{\"subsystem\":\"gateway/ws\"}", "1": {"durationMs": 5}, "2": "webchat disconnected",
        "_meta": {"logLevelName": "WARN", "name": "{\"subsystem\":\"gateway/ws\"}"},
        "time": "2026-09-09T16:59:44.762+00:00", "hostname": "h", "message": "webchat disconnected"});
    assert_eq!(
        map_file_record(&r, &raw.to_string()),
        Some(
            json!({"time": "2026-09-09T16:59:44.762+00:00", "level": "warn", "subsystem": "gateway/ws", "message": "webchat disconnected"})
        )
    );
    let module = json!({"_meta": {"logLevelName": "INFO", "name": "{\"module\":\"cron\",\"storeKey\":\"/x\"}"}, "time": "2026-09-09T12:00:00.000+00:00", "message": "cron: started"});
    assert_eq!(
        map_file_record(&r, &module.to_string()).map(|l| l["subsystem"].clone()),
        Some(json!("cron"))
    );
    let plain = json!({"_meta": {"logLevelName": "INFO", "name": "openclaw"}, "time": "2026-09-09T17:03:16.926+00:00", "message": "pong"});
    assert_eq!(
        map_file_record(&r, &plain.to_string()).map(|l| l["subsystem"].clone()),
        Some(json!("openclaw"))
    );
    assert_eq!(map_file_record(&r, &json!({"time": "x"}).to_string()), None);
}

#[test]
fn journal_keeps_systemd_lifecycle_and_crash_lines_only() {
    let r = r();
    let sys = json!({"__REALTIME_TIMESTAMP": "1788973826000000", "SYSLOG_IDENTIFIER": "systemd", "MESSAGE": "Started openclaw.service - OpenClaw AI Gateway."});
    assert_eq!(
        map_journal_record(&r, &sys.to_string()),
        Some(
            json!({"time": "2026-09-09T17:10:26.000Z", "level": "unit", "subsystem": "systemd", "message": "Started openclaw.service - OpenClaw AI Gateway."})
        )
    );
    let content = json!({"__REALTIME_TIMESTAMP": "1788973826000000", "SYSLOG_IDENTIFIER": "openclaw", "MESSAGE": "Source: Web Fetch"});
    assert_eq!(map_journal_record(&r, &content.to_string()), None);
    let crash = json!({"__REALTIME_TIMESTAMP": "1788973826000000", "SYSLOG_IDENTIFIER": "openclaw", "MESSAGE": "TypeError: Cannot read properties of undefined"});
    assert_eq!(
        map_journal_record(&r, &crash.to_string()).map(|l| l["subsystem"].clone()),
        Some(json!("stderr"))
    );
    let frame = json!({"__REALTIME_TIMESTAMP": "1788973826000000", "SYSLOG_IDENTIFIER": "openclaw", "MESSAGE": "    at Object.<anonymous> (/usr/lib/node_modules/openclaw/dist/x.mjs:1:1)"});
    assert_eq!(
        map_journal_record(&r, &frame.to_string()).map(|l| l["level"].clone()),
        Some(json!("error"))
    );
}

#[test]
fn systemctl_show_output_parses_to_a_service_state() {
    let st = parse_service_show(
        "Result=success\nNRestarts=2\nExecMainStartTimestamp=Wed 2026-09-09 12:09:34 UTC\nExecMainStatus=0\nActiveState=active\nSubState=running\n",
    );
    assert_eq!(st["active"], "active");
    assert_eq!(st["restarts"], 2);
    assert_eq!(st["since"], "2026-09-09T12:09:34.000Z");
    assert_eq!(st["exitStatus"], 0);
    let failed = parse_service_show("ActiveState=failed\nExecMainStatus=1\nExecMainStartTimestamp=\n");
    assert_eq!(failed["since"], Value::Null);
    assert_eq!(failed["result"], "unknown");
    assert_eq!(parse_service_show("")["exitStatus"], Value::Null);
}

#[test]
fn only_the_vm_agent_phone_lines_reach_the_log_masked() {
    let r = r();
    let rec = |m: &str| json!({"MESSAGE": m, "__REALTIME_TIMESTAMP": "1791139338000000"}).to_string();
    let refused = map_agent_phone_record(&r, &rec("[phone-stream] refused reason=clock_skew")).expect("line");
    assert_eq!(
        (refused["subsystem"].as_str(), refused["level"].as_str()),
        (Some("vm-agent/phone"), Some("warn"))
    );
    assert_eq!(
        map_agent_phone_record(&r, &rec("[phone] setup failed: plugin_install_failed")).map(|l| l["level"].clone()),
        Some(json!("warn"))
    );
    assert_eq!(
        map_agent_phone_record(&r, &rec("[phone] history: deleted 2 call(s)")).map(|l| l["level"].clone()),
        Some(json!("info"))
    );
    assert_eq!(
        map_agent_phone_record(&r, &rec("[phone] caller +14434481953")).map(|l| l["message"].clone()),
        Some(json!("[phone] caller +…1953"))
    );
    assert_eq!(
        map_agent_phone_record(&r, &rec("[files] opened /home/controlclaw/secret.md")),
        None
    );
    assert_eq!(
        map_agent_phone_record(&r, &rec("something [phone] in the middle")),
        None
    );
    assert_eq!(map_agent_phone_record(&r, "not json"), None);
}

#[test]
fn lines_are_clamped() {
    assert_eq!(parse_lines(None), 200);
    assert_eq!(parse_lines(Some("0")), 200);
    assert_eq!(parse_lines(Some("50x")), 50);
    assert_eq!(parse_lines(Some("5000")), 1000);
}

#[test]
fn the_box_secrets_are_masked() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("openclaw_gateway_token"), "gw-token-123456\n").expect("w");
    std::fs::write(dir.path().join("bootstrap_token"), "short\n").expect("w");
    let r = Redaction::load(dir.path());
    assert_eq!(r.reload(), 1, "a value under eight characters is not masked");
    assert!(!r.redact("x gw-token-123456 y").contains("gw-token-123456"));
}

/// "Sign out all browsers" makes a new session secret; the redactor masks that one too (Bugbot).
#[tokio::test]
async fn a_rotated_session_secret_is_masked() {
    let b = crate::boxside::testing::test_box();
    let access = crate::boxside::access(&b.app, None);
    let logs = crate::boxside::logs(&b.app);
    let _ = access.logs.set(logs.clone());
    let mut router = cc_http::Router::new(&["cc", "prefixed"]);
    crate::boxside::register_access(
        &mut router,
        &b.app,
        &access,
        crate::boxside::AccessOptions::default(),
        "cc",
        "prefixed",
    );
    let url = crate::boxside::testing::serve(router).await;
    let body = br#"{"all":true}"#;
    let token = b.keys.firewall_token("access", "POST", "/access/revoke", Some(body));
    let r = crate::boxside::testing::client()
        .post(format!("{url}/access/revoke"))
        .bearer_auth(token)
        .body(body.to_vec())
        .send()
        .await
        .expect("revoke");
    assert_eq!(r.status(), 200);
    let fresh = std::fs::read_to_string(b.keys.dir.join("session_secret")).expect("secret");
    // And the old one still is (Bugbot): lines from before the rotation can carry it.
    let old = hex::encode([7u8; 32]);
    assert!(!logs.redaction.redact(&format!("x {old} y")).contains(&old));
    assert_eq!(fresh.trim().len(), 64);
    assert!(
        !logs
            .redaction
            .redact(&format!("x {} y", fresh.trim()))
            .contains(fresh.trim())
    );
}

#[tokio::test]
async fn the_stream_sends_the_backlog_then_what_is_appended_and_the_service_state() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("openclaw-1.log");
    std::fs::write(&log, "{\"time\":\"2026-01-01T00:00:00.000Z\",\"message\":\"old\"}\n").expect("w");
    let runner = cc_proc::RecordingRunner::new();
    runner.answer(&["systemctl", "show"], cc_proc::ok("ActiveState=active\n"));
    let mut logs = Logs::new(Arc::new(runner), Arc::new(r()), "gbrain".into());
    logs.log_dir = dir.path().to_path_buf();
    let logs = Arc::new(logs);
    let resp = logs.stream();
    assert_eq!(resp.headers()["content-type"], "text/event-stream; charset=utf-8");
    let mut body = resp.into_body();
    use http_body_util::BodyExt;
    let mut got = String::new();
    let next = async |body: &mut cc_http::Body| -> String {
        let f = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("in time");
        f.expect("frame")
            .expect("ok")
            .into_data()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    got.push_str(&next(&mut body).await);
    assert!(got.contains("\"message\":\"old\""), "{got}");
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open")
        .write_all(b"{\"time\":\"2026-01-01T00:00:01.000Z\",\"message\":\"new\"}\n")
        .expect("append");
    while !(got.contains("\"message\":\"new\"") && got.contains("event: service")) {
        got.push_str(&next(&mut body).await);
    }
    assert!(got.contains("event: service\ndata: {\"active\":\"active\""), "{got}");
}
