//! What the Meetings page reads (`@controlclaw/meetings/archive`, `packages/meetings/src/archive.ts`):
//! a page of saved meetings as summaries, one meeting in full, and where an OpenClaw session opens in
//! the agent's dashboard. Run on the same inputs as the TS in `rust/conformance/cases/w8/meeting-policy/`.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::js::len16;
use crate::boxside::shell::encode_uri_component as encode;

pub const MEETINGS_PAGE_SIZE: usize = 20;

const LIVE: &[&str] = &["joining", "waiting", "active", "leaving"];

/// `sessionPath`: where a session key opens in the dashboard (OpenClaw's literal-key form), or
/// `None` for anything that is not a session key.
pub fn session_path(key: &str) -> Option<String> {
    // `/^agent:([a-z0-9][a-z0-9_-]{0,63}):(.+)$/i`: ASCII case only, and `.` is not a line end.
    static KEY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[aA][gG][eE][nN][tT]:([a-zA-Z0-9][a-zA-Z0-9_-]{0,63}):([^\n\r\u{2028}\u{2029}]+)$")
            .expect("regex")
    });
    let m = KEY.captures(key)?;
    if len16(key) > 300 {
        return None;
    }
    let (agent, rest) = (&m[1], &m[2]);
    if rest == "main" {
        return Some(format!("/chat/{}", encode(agent)));
    }
    let segments: Vec<String> = rest
        .split(':')
        .map(|x| match x {
            "." => "~dot".to_string(),
            ".." => "~dotdot".to_string(),
            x if x.starts_with('~') => format!("~{x}"),
            x => x.to_string(),
        })
        .collect();
    if segments.iter().any(String::is_empty) {
        return None;
    }
    Some(format!(
        "/chat/{}/{}{}",
        encode(agent),
        if segments.len() == 1 { "~key/" } else { "" },
        segments.iter().map(|s| encode(s)).collect::<Vec<_>>().join("/")
    ))
}

/// `meetingConsultSession`: the OpenClaw session of a meeting's voice lookups.
pub fn meeting_consult_session(session_id: &str) -> String {
    format!("agent:main:subagent:google-meet:{session_id}")
}

fn parse(v: Option<&Value>) -> f64 {
    v.and_then(Value::as_str)
        .and_then(crate::phone::history::parse_iso)
        .unwrap_or(f64::NAN)
}

/// `summarizeMeeting`: one row of the list.
pub fn summarize_meeting(m: &Value) -> Value {
    let end = if crate::phone::model::truthy(m.get("endedAt")) {
        parse(m.get("endedAt"))
    } else {
        f64::NAN
    };
    let start = parse(m.get("startedAt"));
    let state = m.get("state").cloned().unwrap_or(Value::Null);
    let live = state.as_str().is_some_and(|s| LIVE.contains(&s));
    let captions = m.get("transcript").and_then(Value::as_array).map_or(0, Vec::len);
    let error = crate::phone::model::truthy(m.get("error"));
    let duration = if !live && end.is_finite() && start.is_finite() {
        // `Math.max(0, Math.round((end - start) / 1000))`.
        json!(((end - start) / 1000.0 + 0.5).floor().max(0.0) as i64)
    } else {
        Value::Null
    };
    let notes = if crate::phone::model::truthy(m.get("notes")) {
        "ready"
    } else if live || (state == "complete" && captions > 0 && !error) {
        "pending"
    } else {
        "none"
    };
    let or_null = |k: &str| m.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "id": or_null("id"),
        "startedAt": or_null("startedAt"),
        "endedAt": or_null("endedAt"),
        "durationSeconds": duration,
        "mode": m.get("mode").filter(|v| !v.is_null()).cloned().unwrap_or(json!("transcript")),
        "meetingCode": or_null("meetingCode"),
        "state": state,
        "notes": notes,
        "captions": captions,
        "failed": m.get("state") == Some(&json!("failed")) || error,
    })
}

/// `meetingDetail`: one meeting in full, without the native session ids.
pub fn meeting_detail(m: &Value) -> Value {
    let mut out = Map::new();
    for k in [
        "id",
        "startedAt",
        "endedAt",
        "meetingCode",
        "gaps",
        "state",
        "transcript",
        "notes",
        "notesSource",
        "notesRetryAt",
        "error",
        "voiceSeconds",
        "voiceSessions",
        "voiceEnds",
        "transcriptNote",
        "followUp",
        "tasks",
    ] {
        if let Some(v) = m.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    out.insert(
        "mode".into(),
        m.get("mode")
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or(json!("transcript")),
    );
    out.insert("summary".into(), summarize_meeting(m));
    if m.get("mode") == Some(&json!("bidi")) {
        static NATIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^meet_[0-9a-f-]{36}$").expect("regex"));
        let lookups: Vec<Value> = m
            .get("sessionIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|id| NATIVE.is_match(id))
            .take(20)
            .map(|id| {
                let key = meeting_consult_session(id);
                json!({"key": key, "path": session_path(&key)})
            })
            .collect();
        out.insert("lookupSessions".into(), Value::Array(lookups));
    }
    Value::Object(out)
}

/// `meetingsPage`: page `page` (1-based, clamped) of meetings already newest first.
pub fn meetings_page(all: &[Value], page: f64) -> Value {
    let size = MEETINGS_PAGE_SIZE;
    let last = all.len().div_ceil(size).max(1);
    let p = if page.is_finite() { page.floor() } else { 1.0 };
    let p = p.max(1.0).min(last as f64) as usize;
    let rows: Vec<Value> = all
        .iter()
        .skip((p - 1) * size)
        .take(size)
        .map(summarize_meeting)
        .collect();
    json!({"meetings": rows, "page": p, "pageSize": size, "total": all.len()})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `archive.test.ts`: "a session key becomes its path in the OpenClaw dashboard".
    #[test]
    fn session_paths() {
        assert_eq!(
            session_path("agent:main:subagent:google-meet:meet_d81611be-3c2d-41d2-8aa3-f59bcbb0087f").as_deref(),
            Some("/chat/main/subagent/google-meet/meet_d81611be-3c2d-41d2-8aa3-f59bcbb0087f")
        );
        assert_eq!(
            session_path("agent:main:meeting-565ba65b-task-1").as_deref(),
            Some("/chat/main/~key/meeting-565ba65b-task-1")
        );
        assert_eq!(session_path("agent:main:main").as_deref(), Some("/chat/main"));
        assert_eq!(
            session_path("agent:main:a:..:~b:x y/z").as_deref(),
            Some("/chat/main/a/~dotdot/~~b/x%20y%2Fz")
        );
        for bad in [
            "main",
            "agent:main:",
            "agent:main:a::b",
            "agent::x",
            "javascript:alert(1)",
        ] {
            assert_eq!(session_path(bad), None, "{bad}");
        }
    }
}
