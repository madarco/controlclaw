//! Content rules on the voice (appendix F feature 23, addon.py 6013-6179): the question to the
//! main agent and its answer, gpt-realtime (gateway and OpenAI frames) and gpt-live (delegations
//! built from the input transcript), in meetings and calls.
//!
//! A question a rule stops is replaced by a fixed sentence (realtime) or answered by the firewall
//! on the socket (live); an answer a rule stops is replaced by a refusal the voice speaks. A hold
//! stops (no one can be asked in time). The refusal never repeats the words a rule looks for.

use serde_json::{Map, Value, json};

use super::{Voice, obj, purpose_of};
use crate::checks::content::CheckError;
use crate::checks::content::engine::{self, Action};
use crate::checks::pyjson;
use crate::flow::Flow;

pub const VOICE_BLOCKED_QUESTION: &str = "This request was blocked by the firewall. Reply only with the word blocked.";
/// Seconds of transcript a question is built from (the box's own window is 45 s, by its clock).
pub const VOICE_QUESTION_WINDOW: f64 = 50.0;
pub const VOICE_ANSWER_PREFIXES: [&str; 3] = [
    "Result of the lookup:",
    "Result of a task:",
    "Answer to an earlier lookup:",
];
pub const VOICE_PLAIN_REASON: &str = "this is not discussed here";
pub const VOICE_APPEND_MAX: usize = 4000;
pub const VOICE_APPLIES_EVERY: f64 = 5.0;

/// What a frame becomes.
pub enum Outcome {
    Keep,
    /// The event was changed in place: the frame carries it re-encoded.
    Rewrite,
    /// The frame is dropped, and this frame goes to the provider in its place.
    Answer(Vec<u8>),
}

/// `_voice_refusal`: what the voice says instead.
pub fn refusal(reason: &str) -> String {
    // A reason that ends a sentence itself is not given a second full stop.
    let text = format!(
        "Blocked by your organization's rules: {}. Tell the person plainly that you cannot help with this here. This is a policy decision, not a technical failure.",
        reason.trim_end_matches([' ', '.'])
    );
    text.chars().take(VOICE_APPEND_MAX).collect()
}

pub use crate::checks::json::unescape_loose;

/// `_voice_texts`: every string in an answer, JSON in a string included; escapes undone where it
/// does not parse.
pub fn texts(value: &Value) -> String {
    let mut out = Vec::new();
    if crate::checks::telegram::texts(value, true, &mut out, 0, &[]).is_err() {
        // A repeated key or nesting too deep: the raw text is checked instead.
        out = vec![match value {
            Value::String(s) => s.clone(),
            v => pyjson::dumps(v),
        }];
    }
    out.iter()
        .map(|t| if t.contains('\\') { unescape_loose(t) } else { t.clone() })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The rule that stops a text: its id, reason and action.
pub struct Stop {
    pub reason: String,
}

/// `_voice_rule`: the rule that stops this text, recorded; `None` when it may pass. Rules that
/// cannot be read stop it when `must_check` (a question, an answer of the agent's), and let the
/// box's own lines through.
async fn voice_rule(
    voice: &Voice,
    flow: &mut Flow,
    v: &Map<String, Value>,
    direction: &str,
    text: &str,
    must_check: bool,
) -> Result<Option<Stop>, CheckError> {
    let purpose = purpose_of(v);
    let rules = match voice.content.rules() {
        Ok(r) => r,
        Err(_) => {
            if !must_check {
                return Ok(None);
            }
            // Once per socket and direction: a call does not write a line for every frame.
            let mut extra = Map::new();
            extra.insert("detail".into(), json!("rules unknown"));
            extra.insert("purpose".into(), json!(purpose));
            let once = flow.id.clone();
            voice
                .content
                .audit(Some(flow), "error", "voice", direction, "block", Some(&once), extra);
            return Ok(Some(Stop {
                reason: "the firewall's rules are not available".into(),
            }));
        }
    };
    if text.is_empty() || !engine::applies(&rules, direction, "voice") {
        return Ok(None);
    }
    let (id, reason, action) = match voice
        .content
        .acting(Some(flow), &rules, direction, "voice", text, None)
        .await
    {
        Ok(Some(r)) => (r.id, r.reason, r.action),
        Ok(None) => return Ok(None),
        Err(CheckError::TooLong(_)) => ("error".to_owned(), "it is too long to check".to_owned(), Action::Block),
        Err(e) => return Err(e),
    };
    let mut extra = Map::new();
    extra.insert("purpose".into(), json!(purpose));
    if action == Action::Hold {
        extra.insert("held".into(), json!(false));
    }
    voice
        .content
        .audit(Some(flow), &id, "voice", direction, "block", None, extra);
    // A reason that names what a rule looks for would say it aloud: a plain one instead.
    let mut plain = false;
    for d in ["in", "out"] {
        if !engine::evaluate(&rules, d, "voice", &reason)?.hits.is_empty() {
            plain = true;
            break;
        }
    }
    Ok(Some(Stop {
        reason: if plain { VOICE_PLAIN_REASON.to_owned() } else { reason },
    }))
}

/// `_voice_reads_in`: whether to keep this socket's transcript (a rule reads voice coming in, or
/// the rules are unknown). Asked again every 5 s.
fn reads_in(voice: &Voice, state: &mut Map<String, Value>) -> bool {
    let now = (voice.clock)();
    let at = state
        .get("applies_at")
        .and_then(Value::as_f64)
        .unwrap_or(-VOICE_APPLIES_EVERY);
    if now - at >= VOICE_APPLIES_EVERY {
        let applies = voice
            .content
            .rules()
            .map_or(true, |r| engine::applies(&r, "in", "voice"));
        state.insert("applies".into(), json!(applies));
        state.insert("applies_at".into(), json!(now));
    }
    state.get("applies") == Some(&Value::Bool(true))
}

fn starts_answer(content: &str) -> bool {
    VOICE_ANSWER_PREFIXES.iter().any(|p| content.starts_with(p))
}

/// `content_rules_voice`: one frame the voice policy let through. An error means the frame could
/// not be checked: the caller closes the voice.
pub async fn check(
    voice: &Voice,
    flow: &mut Flow,
    v: &mut Map<String, Value>,
    from_client: bool,
    event: &mut Value,
) -> Result<Outcome, CheckError> {
    let Some(ev) = event.as_object_mut() else {
        return Ok(Outcome::Keep);
    };
    let kind = ev.get("type").and_then(Value::as_str).unwrap_or("").to_owned();
    if v.get("family").and_then(Value::as_str) == Some("live") {
        if !from_client {
            match kind.as_str() {
                "session.input_transcript.delta" | "session.output_transcript.delta" => {
                    let Some(delta) = ev.get("delta").and_then(Value::as_str) else {
                        return Ok(Outcome::Keep);
                    };
                    let state = obj(v, "content");
                    if !reads_in(voice, state) {
                        return Ok(Outcome::Keep);
                    }
                    let now = (voice.clock)();
                    let heard = state.entry("heard").or_insert_with(|| json!([]));
                    if let Some(h) = heard.as_array_mut() {
                        h.push(json!([now, delta]));
                        let old = h
                            .iter()
                            .take_while(|e| now - e[0].as_f64().unwrap_or(now) > VOICE_QUESTION_WINDOW)
                            .count();
                        h.drain(..old);
                    }
                }
                "session.delegation.created" => {
                    let did = ev
                        .get("delegation")
                        .and_then(Value::as_object)
                        .and_then(|d| d.get("id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let Some(did) = did.filter(|d| !d.is_empty() && d.chars().count() <= 200) else {
                        return Ok(Outcome::Keep); // the box refuses it itself
                    };
                    let now = (voice.clock)();
                    let joined: String = obj(v, "content")
                        .get("heard")
                        .and_then(Value::as_array)
                        .map(|h| {
                            h.iter()
                                .filter(|e| now - e[0].as_f64().unwrap_or(f64::NEG_INFINITY) <= VOICE_QUESTION_WINDOW)
                                .filter_map(|e| e[1].as_str())
                                .collect()
                        })
                        .unwrap_or_default();
                    let text = joined.trim_matches(engine::py_space);
                    let Some(stop) = voice_rule(voice, flow, v, "in", text, true).await? else {
                        return Ok(Outcome::Keep);
                    };
                    // The box never starts this lookup. The answer is spoken, but the box plays the
                    // voice only to someone who addressed it, as for its own answers.
                    let answer = pyjson::dumps(&json!({"type": "session.commentary.append", "delegation_id": did,
                                                       "content": refusal(&stop.reason)}));
                    return Ok(Outcome::Answer(answer.into_bytes()));
                }
                _ => {}
            }
            return Ok(Outcome::Keep);
        }
        if matches!(kind.as_str(), "session.commentary.append" | "session.thinking.append")
            && let Some(content) = ev.get("content").and_then(Value::as_str).map(str::to_owned)
        {
            let answer = ev.get("delegation_id").is_some_and(|d| !d.is_null()) || starts_answer(&content);
            // Quiet context (lines of the meeting heard) is not the agent's words.
            if kind == "session.thinking.append" && !answer {
                return Ok(Outcome::Keep);
            }
            // The box's own spoken lines (the greeting, an acknowledgement) are checked when the
            // rules are known, and not stopped for want of them.
            if let Some(stop) = voice_rule(voice, flow, v, "out", &content, answer).await? {
                if let Some(ev) = event.as_object_mut() {
                    ev.insert("content".into(), json!(refusal(&stop.reason)));
                }
                return Ok(Outcome::Rewrite);
            }
        }
        return Ok(Outcome::Keep);
    }
    let call_key = if v.get("provider").and_then(Value::as_str) == Some("gateway") {
        "callId"
    } else {
        "call_id"
    };
    if !from_client {
        if !matches!(
            kind.as_str(),
            "function-call-arguments-done" | "response.function_call_arguments.done"
        ) {
            return Ok(Outcome::Keep);
        }
        let args = match ev.get("arguments") {
            Some(Value::String(raw)) => match crate::checks::json::loads(raw) {
                Ok(a) => a,
                Err(_) => return Ok(Outcome::Keep), // the box refuses it itself
            },
            _ => Value::Null,
        };
        let Some(call_id) = ev.get(call_key).and_then(Value::as_str).map(str::to_owned) else {
            return Ok(Outcome::Keep);
        };
        let Some(args) = args.as_object() else {
            return Ok(Outcome::Keep);
        };
        let asked = json!({"question": args.get("question").cloned().unwrap_or(Value::Null),
                           "context": args.get("context").cloned().unwrap_or(Value::Null)});
        let Some(stop) = voice_rule(voice, flow, v, "in", &texts(&asked), true).await? else {
            return Ok(Outcome::Keep);
        };
        if let Some(ev) = event.as_object_mut() {
            ev.insert(
                "arguments".into(),
                json!(pyjson::dumps(&json!({"question": VOICE_BLOCKED_QUESTION}))),
            );
        }
        let state = obj(v, "content");
        let blocked = state.entry("blocked").or_insert_with(|| json!({}));
        if let Some(b) = blocked.as_object_mut() {
            // An id seen before keeps its place, as in a dict.
            b.insert(call_id, json!(stop.reason));
            while b.len() > 50 {
                let Some(first) = b.keys().next().cloned() else { break };
                b.shift_remove(&first);
            }
        }
        return Ok(Outcome::Rewrite);
    }
    if !matches!(kind.as_str(), "conversation-item-create" | "conversation.item.create") {
        return Ok(Outcome::Keep);
    }
    let Some(item) = ev.get("item").and_then(Value::as_object) else {
        return Ok(Outcome::Keep);
    };
    if !matches!(
        item.get("type").and_then(Value::as_str),
        Some("function-call-output" | "function_call_output")
    ) {
        return Ok(Outcome::Keep);
    }
    let reason = match item.get(call_key) {
        Some(Value::String(id)) => obj(v, "content")
            .get_mut("blocked")
            .and_then(Value::as_object_mut)
            .and_then(|b| b.shift_remove(id))
            .and_then(|r| r.as_str().map(str::to_owned)),
        // A key that cannot be looked up (a list) raised in the addon: the voice is closed.
        Some(Value::Array(_) | Value::Object(_)) => {
            return Err(CheckError::Failed("a call id that is not a key".into()));
        }
        _ => None,
    };
    let output = item.get("output").cloned().unwrap_or(Value::Null);
    let reason = match reason {
        Some(r) => Some(r),
        None => voice_rule(voice, flow, v, "out", &texts(&output), true)
            .await?
            .map(|s| s.reason),
    };
    let Some(reason) = reason else {
        return Ok(Outcome::Keep);
    };
    if let Some(item) = event
        .as_object_mut()
        .and_then(|e| e.get_mut("item"))
        .and_then(Value::as_object_mut)
    {
        item.insert(
            "output".into(),
            json!(pyjson::dumps(
                &json!({"status": "blocked", "message": refusal(&reason)})
            )),
        );
    }
    Ok(Outcome::Rewrite)
}
