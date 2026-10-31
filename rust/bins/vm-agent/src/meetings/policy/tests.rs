//! `packages/meetings/src/index.test.ts`, `consult-model.test.ts` and `archive.test.ts` by parity: every call in
//! `rust/conformance/cases/w8/meeting-policy/cases.json` answers as the TS did (`expected.json`,
//! written by `gen.mts` there).

use serde_json::{Value, json};

use super::*;

fn answer(fn_name: &str, args: &[Value]) -> Value {
    let a = |i: usize| args.get(i);
    let s = |i: usize| a(i).and_then(Value::as_str);
    let ok = |v: Value| json!({"ok": v});
    let result = |r: Result<Value, String>| match r {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"error": e}),
    };
    match fn_name {
        "speechFamily" => ok(json!(speech_family_of(a(0), a(1)))),
        "providerModelId" => ok(json!(provider_model_id(
            s(0).unwrap_or_default(),
            s(1).unwrap_or_default()
        ))),
        "parseSpeechPolicy" => result(parse_speech_policy(a(0))),
        "wakeWordProblem" => ok(json!(wake_word_problem(a(0).unwrap_or(&Value::Null)))),
        "wakeWordWarning" => ok(json!(wake_word_warning(s(0).unwrap_or_default()))),
        "parseWakePolicy" => result(parse_wake_policy(a(0))),
        "parseAutoJoinPolicy" => result(parse_auto_join_policy(a(0))),
        "autoJoinWidens" => ok(json!(auto_join_widens(
            a(0).filter(|v| !v.is_null()),
            a(1).filter(|v| !v.is_null())
        ))),
        "autoJoinSummary" => ok(json!(auto_join_summary(a(0).unwrap_or(&Value::Null)))),
        "parseFollowUpPolicy" => result(parse_follow_up_policy(a(0))),
        "parseFullAgentPolicy" => result(parse_full_agent_policy(a(0))),
        "fullAgentWidens" => ok(json!(full_agent_widens(a(0), a(1)))),
        "fullAgentSummary" => ok(json!(full_agent_summary())),
        "presentSummary" => ok(json!(present_summary())),
        "presentWidens" => ok(json!(present_widens(
            a(0).filter(|v| !v.is_null()),
            a(1).filter(|v| !v.is_null())
        ))),
        "fullAgentMeeting" => ok(json!(full_agent_meeting(a(0).unwrap_or(&Value::Null), a(1), s(2)))),
        "wakeSessions" => ok(json!(wake_sessions(a(0).unwrap_or(&Value::Null)))),
        "alwaysListening" => ok(json!(always_listening(a(0).unwrap_or(&Value::Null)))),
        "parseMeetingPolicy" => result(parse_meeting_policy(a(0))),
        "canonicalMeetUrl" => result(canonical_meet_url(a(0)).map(Value::String)),
        "normalizeMeetLink" => result(normalize_meet_link(a(0)).map(Value::String)),
        "isMeetPage" => ok(json!(is_meet_page(s(0).unwrap_or_default(), s(1).unwrap_or_default()))),
        "parseAutoJoinClaim" => result(parse_auto_join_claim(a(0))),
        "consultModelChoices" => {
            let providers: Vec<String> = a(0)
                .and_then(Value::as_array)
                .map(|p| p.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default();
            let listed = a(1).and_then(Value::as_object).cloned().unwrap_or_default();
            ok(json!(consult_model_choices(&providers, &listed)))
        }
        "effectiveConsultModel" => {
            let choices = a(1).and_then(Value::as_array).cloned().unwrap_or_default();
            ok(json!(effective_consult_model(s(0), &choices)))
        }
        "sessionPath" => ok(json!(super::super::pages::session_path(s(0).unwrap_or_default()))),
        "meetingConsultSession" => ok(json!(super::super::pages::meeting_consult_session(
            s(0).unwrap_or_default()
        ))),
        "summarizeMeeting" => ok(super::super::pages::summarize_meeting(a(0).unwrap_or(&Value::Null))),
        "meetingDetail" => ok(super::super::pages::meeting_detail(a(0).unwrap_or(&Value::Null))),
        // `Number.isFinite(page)`: anything but a number reads as page 1.
        "meetingsPage" => ok(super::super::pages::meetings_page(
            a(0).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default(),
            a(1).and_then(Value::as_f64).unwrap_or(f64::NAN),
        )),
        other => panic!("no case for {other}"),
    }
}

/// Intentional differences from the TS (`expected.json` keeps what the TS answered): a setting that
/// must be one word is not taken as a one-element array (`["bidi"]`), which `String(x)` let through.
fn intentional(case: &Value) -> Option<Value> {
    let one_element = |v: &Value| v.as_array().is_some_and(|a| a.len() == 1);
    let args = case["args"].as_array()?;
    let first = args.first()?;
    match case["fn"].as_str()? {
        "parseSpeechPolicy" if one_element(&first["provider"]) => {
            Some(json!({"error": "Choose a supported speech model and a call limit from 5 to 60 minutes"}))
        }
        "parseAutoJoinPolicy" if one_element(&first["mode"]) || one_element(&first["calendar"]) => Some(json!({
            "error": format!("Choose where invites come from and 1 to {AUTO_JOIN_MAX_PER_DAY} joins a day")
        })),
        "parseMeetingPolicy" if one_element(&first["defaultMode"]) => {
            Some(json!({"error": "Invalid owner-browser Google Meet settings"}))
        }
        _ => None,
    }
}

/// Rust only: the same refusals inside a meeting policy (its speech and automatic joining).
#[test]
fn one_element_arrays_inside_a_meeting_policy_are_refused() {
    let policy = |speech: Value, auto: Value| {
        json!({"enabled": true, "platforms": ["google-meet"], "defaultMode": "transcript", "invokers": "owner-browser",
            "speech": speech, "autoJoin": auto})
    };
    let speech =
        json!({"provider": "gateway", "credentialId": "k", "model": "openai/gpt-realtime-1.5", "maxMinutes": 30});
    let auto = json!({"enabled": true, "mode": "transcript", "email": true, "calendar": "off", "maxPerDay": 5});
    assert!(parse_meeting_policy(Some(&policy(speech.clone(), auto.clone()))).is_ok());
    let mut s = speech.clone();
    s["provider"] = json!(["gateway"]);
    assert!(parse_meeting_policy(Some(&policy(s, auto.clone()))).is_err());
    for (k, v) in [("mode", "bidi"), ("calendar", "all")] {
        let mut a = auto.clone();
        a[k] = json!([v]);
        assert!(parse_meeting_policy(Some(&policy(speech.clone(), a))).is_err(), "{k}");
    }
    // What a box already keeps is read as before: a widening is never missed.
    let mut kept = auto.clone();
    kept["calendar"] = json!(["invited"]);
    let mut next = auto;
    next["calendar"] = json!("all");
    assert!(auto_join_widens(Some(&kept), Some(&next)));
}

#[test]
fn every_case_answers_as_the_ts() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../../conformance/cases/w8/meeting-policy/cases.json"
    ))
    .expect("cases");
    let expected: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../../conformance/cases/w8/meeting-policy/expected.json"
    ))
    .expect("expected");
    assert_eq!(cases.len(), expected.len());
    let mut failed = Vec::new();
    for (case, want) in cases.iter().zip(&expected) {
        let args = case["args"].as_array().cloned().unwrap_or_default();
        let got = answer(case["fn"].as_str().expect("fn"), &args);
        // Only where the TS took the value: the Rust answer is then the refusal.
        let want = &want
            .get("ok")
            .and_then(|_| intentional(case))
            .unwrap_or_else(|| want.clone());
        // Text, so key order counts as it does in the TS's JSON (`Value`'s own `==` ignores it).
        #[allow(clippy::cmp_owned)]
        if got.to_string() != want.to_string() {
            failed.push(format!("{case}\n  want {want}\n  got  {got}"));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} differ:\n{}",
        failed.len(),
        cases.len(),
        failed.join("\n")
    );
}

#[test]
fn the_providers_and_defaults() {
    assert_eq!(consult_providers(), ["openai", "anthropic", "controlclaw"]);
    assert_eq!(wake_of(&json!({})), meeting_wake_default());
    assert_eq!(phone_wake_default()["enabled"], false);
    assert_eq!(
        parse_meeting_policy(Some(&default_meeting_policy())),
        Ok(default_meeting_policy())
    );
    assert_eq!(
        auto_join_refusal("organizer"),
        Some("The organizer is not an allowed sender")
    );
    assert!(OP_ID.is_match("0f8e2b1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"));
}
