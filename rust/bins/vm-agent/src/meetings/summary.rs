//! Meeting notes (`meeting-summary.ts`): the transcript goes to a short-lived `node` running the
//! notes program, which imports OpenClaw's isolated completion and tries the utility model, then the
//! primary, with a lean config (model providers only), then with the whole config. The program is
//! JavaScript carried unchanged from the TS (`page_scripts.json`, `notes`).

use std::sync::LazyLock;
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use regex::Regex;
use serde_json::{Value, json};

use super::archive::Caption;
use super::js::{head16, js_number, js_string, len16, tail16};

/// The notes program (`NOTES_PROGRAM`).
pub fn notes_program() -> &'static str {
    super::scripts::notes()
}

const MAX_INPUT: usize = 48_000;
const HALF: usize = 24_000;
const MAX_NOTES: usize = 30_000;
const MARKER: &str = "\nCC_MEETING_NOTES\n";
const PARTIAL: &str =
    "Partial summary: the middle of this long transcript was omitted. Read the full transcript below.\n\n";

/// What each try in the program reported: the model, how long it took, and OpenClaw's error.
/// Never transcript text (`notesTries`).
pub fn notes_tries(stderr: &str) -> String {
    static SPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").expect("regex"));
    stderr
        .split('\n')
        .filter_map(|line| line.strip_prefix("CC_NOTES_TRY "))
        .filter_map(|json| serde_json::from_str::<Value>(json).ok())
        // `null.model` throws in the TS, and that try is dropped.
        .filter(|t| !t.is_null())
        .map(|t| {
            let model = head16(&js_string(t.get("model")), 80);
            let lean = crate::phone::model::truthy(t.get("lean"));
            let ok = crate::phone::model::truthy(t.get("ok"));
            // `Number(t.seconds) || 0`.
            let seconds = js_number(t.get("seconds"));
            let seconds = if seconds.is_nan() || seconds == 0.0 {
                0.0
            } else {
                seconds
            };
            let seconds = js_string(Some(&serde_json::json!(seconds)));
            let error = match t.get("error").and_then(Value::as_str) {
                Some(e) if !ok => format!(": {}", head16(&SPACE.replace_all(e, " "), 200)),
                _ => String::new(),
            };
            format!(
                "{model}{} {} in {seconds} s{error}",
                if lean { "" } else { " (all plugins)" },
                if ok { "answered" } else { "failed" }
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The transcript as the notes call is given it: at most 48,000 characters, the middle cut out of a
/// longer one. The second value says it was cut.
pub fn notes_input(captions: &[Caption]) -> (String, bool) {
    let rows: Vec<Value> = captions
        .iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            for k in ["at", "speaker", "text"] {
                if let Some(v) = c.get(k) {
                    m.insert(k.into(), v.clone());
                }
            }
            Value::Object(m)
        })
        .collect();
    let full = json!(rows).to_string();
    if len16(&full) <= MAX_INPUT {
        return (full, false);
    }
    (
        format!(
            "{}\n[Middle omitted from summary input; full transcript is saved.]\n{}",
            head16(&full, HALF),
            tail16(&full, HALF)
        ),
        true,
    )
}

/// Run the notes program on the transcript (`summarizeMeeting`): the notes, or the failure with
/// what each try reported.
pub async fn summarize_meeting(runner: &dyn Runner, node: &str, captions: &[Caption]) -> Result<String, String> {
    let (input, cut) = notes_input(captions);
    let cmd = Cmd::new(node)
        .args(["--input-type=module", "-e", notes_program()])
        .stdin(input)
        .timeout(Duration::from_secs(600));
    let out = runner.run(cmd).await;
    // Only the tail of what it wrote to stderr: the lines about each try are short and come last.
    let stderr = out.as_ref().map(|o| tail16(&o.stderr_str(), 8000)).unwrap_or_default();
    let failed = |code: Option<i32>| {
        let tries = notes_tries(&stderr);
        let why = if tries.is_empty() {
            format!(
                "the notes process ended with {} before a model was tried",
                code.map_or("a signal".to_string(), |c| c.to_string())
            )
        } else {
            tries
        };
        format!("Notes generation failed ({why})")
    };
    let out = out.map_err(|_| failed(None))?;
    let stdout = out.stdout_str();
    // The TS kills a program that writes more than 100,000 characters of answer.
    if out.code != Some(0) || len16(&stdout) > 100_000 {
        return Err(failed(out.code));
    }
    let Some(at) = stdout.rfind(MARKER) else {
        return Err(failed(out.code));
    };
    let parsed: Value = serde_json::from_str(&stdout[at + MARKER.len()..]).map_err(|_| failed(out.code))?;
    let Some(text) = parsed
        .get("text")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty() && len16(t) <= MAX_NOTES)
    else {
        return Err(failed(out.code));
    };
    tracing::info!("[meetings] notes written: {}", notes_tries(&stderr));
    Ok(if cut {
        format!("{PARTIAL}{text}")
    } else {
        text.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_proc::{Output, RecordingRunner};

    fn caption(text: &str) -> Caption {
        json!({"at": "2026-10-01T10:00:00.000Z", "speaker": "Alice", "text": text, "source": {"id": "x", "revision": 1}})
            .as_object()
            .cloned()
            .expect("o")
    }

    #[test]
    fn tries_are_read_for_the_journal_only() {
        let stderr = [
            "[model-fetch] noise".to_string(),
            format!("CC_NOTES_TRY {}", json!({"model": "controlclaw/moonshotai/kimi-k2.6", "lean": true, "seconds": 175, "ok": false, "error": "prepared model runtime publication\n(workspace plugins; agent main) timed out"})),
            "CC_NOTES_TRY not json".to_string(),
            format!("CC_NOTES_TRY {}", json!({"model": "controlclaw/moonshotai/kimi-k2.6", "lean": false, "seconds": 19, "ok": true})),
        ]
        .join("\n");
        assert_eq!(
            notes_tries(&stderr),
            "controlclaw/moonshotai/kimi-k2.6 failed in 175 s: prepared model runtime publication (workspace plugins; agent main) timed out; controlclaw/moonshotai/kimi-k2.6 (all plugins) answered in 19 s"
        );
        assert_eq!(notes_tries("nothing here"), "");
        // A try that is `null` is dropped; a number model and text seconds read as the TS reads them.
        assert_eq!(notes_tries("CC_NOTES_TRY null"), "");
        assert_eq!(
            notes_tries(r#"CC_NOTES_TRY {"model":5,"lean":true,"seconds":"12","ok":true}"#),
            "5 answered in 12 s"
        );
    }

    #[test]
    fn the_program_carries_the_config_function() {
        assert!(
            notes_program().contains("const notesConfig = function notesConfig")
                || notes_program().contains("const notesConfig = (")
        );
        assert!(notes_program().contains("notesConfig(cfg, [selected.provider, selected.runtimeProvider])"));
    }

    #[test]
    fn a_long_transcript_loses_its_middle() {
        let (short, cut) = notes_input(&[caption("Hello.")]);
        assert!(!cut);
        assert_eq!(
            short,
            r#"[{"at":"2026-10-01T10:00:00.000Z","speaker":"Alice","text":"Hello."}]"#
        );
        let long: Vec<Caption> = (0..2000)
            .map(|i| caption(&format!("Line {i} of the meeting.")))
            .collect();
        let (text, cut) = notes_input(&long);
        assert!(cut);
        assert!(text.contains("\n[Middle omitted from summary input; full transcript is saved.]\n"));
        assert!(len16(&text) <= 48_000 + 80);
    }

    #[tokio::test]
    async fn notes_come_from_the_programs_marker_and_failures_say_why() {
        let ok = RecordingRunner::new();
        ok.answer(
            &["node"],
            Output {
                code: Some(0),
                stdout: format!("noise{MARKER}{}", json!({"text": "Summary: launch on Thursday."})).into_bytes(),
                stderr: format!(
                    "CC_NOTES_TRY {}\n",
                    json!({"model": "m/x", "lean": true, "seconds": 3, "ok": true})
                )
                .into_bytes(),
                ..Default::default()
            },
        );
        assert_eq!(
            summarize_meeting(&ok, "node", &[caption("Launch on Thursday.")]).await,
            Ok("Summary: launch on Thursday.".into())
        );
        let call = &ok.calls()[0];
        assert_eq!(call.args[..2], ["--input-type=module", "-e"]);
        assert_eq!(call.args[2], notes_program());
        assert!(String::from_utf8_lossy(call.stdin.as_deref().unwrap_or_default()).contains("Launch on Thursday."));

        let failed = RecordingRunner::new();
        failed.answer(
            &["node"],
            Output {
                code: Some(1),
                stderr: format!(
                    "CC_NOTES_TRY {}\n",
                    json!({"model": "m/x", "lean": true, "seconds": 120, "ok": false, "error": "timed out"})
                )
                .into_bytes(),
                ..Default::default()
            },
        );
        assert_eq!(
            summarize_meeting(&failed, "node", &[caption("x")]).await,
            Err("Notes generation failed (m/x failed in 120 s: timed out)".into())
        );
        let none = RecordingRunner::new();
        none.answer(
            &["node"],
            Output {
                code: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(
            summarize_meeting(&none, "node", &[caption("x")]).await,
            Err("Notes generation failed (the notes process ended with 1 before a model was tried)".into())
        );
    }
}
