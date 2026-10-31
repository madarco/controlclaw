//! The meetings settings (`@controlclaw/meetings`, `packages/meetings/src/index.ts` and
//! `consult-model.ts`): what the firewall's signed apply may carry, the speech and wake rules the
//! phone shares, Meet links, and the model the meeting voice's lookups run on.
//!
//! Values stay JSON, read the way the TS reads them: `String(x)` where the TS converts, strict
//! `===` where it compares, and the parsed settings rebuilt with the TS's key order. The TS and
//! this file are run on the same inputs in `rust/conformance/cases/w8/meeting-policy/`.
//!
//! One intentional difference (Rust only): where settings are parsed, a field that must be one word
//! (`mode`, `defaultMode`, `calendar`, the speech `provider`) is text, not anything `String(x)`
//! makes that word (`["bidi"]`). Settings already kept are still read the TS's way (`reach`,
//! `speech_family_of`), so nothing a box holds changes meaning, and a widening is never missed.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::js::{head16, js_space, js_string, js_tidy, js_word, len16, safe_int, truthy};

fn re(p: &str) -> Regex {
    Regex::new(p).expect("regex")
}

/// Only these keys.
fn only(m: &Map<String, Value>, allowed: &[&str]) -> bool {
    m.keys().all(|k| allowed.contains(&k.as_str()))
}

/// `!value || typeof value !== "object" || Array.isArray(value)` fails; the object otherwise.
fn object(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// A present value of `p[key]` (`p.key !== undefined`).
fn has(m: &Map<String, Value>, key: &str) -> bool {
    m.contains_key(key)
}

// ---- Speech -------------------------------------------------------------------------------

const REALTIME_SUFFIX: &str = r"(?:-[a-z0-9][a-z0-9.-]{0,23})?";

/// `speechFamily` on text: `realtime` or `live` for a model the provider offers. The JS suffix
/// has a lookahead that refuses transcription and translation models; it is checked apart.
pub fn speech_family(provider: &str, model: &str) -> Option<&'static str> {
    static GATEWAY_REALTIME: LazyLock<Regex> =
        LazyLock::new(|| re(&format!(r"^openai/gpt-realtime{REALTIME_SUFFIX}$")));
    static GATEWAY_LIVE: LazyLock<Regex> = LazyLock::new(|| re(r"^openai/gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?$"));
    static OPENAI_REALTIME: LazyLock<Regex> = LazyLock::new(|| re(&format!(r"^gpt-realtime{REALTIME_SUFFIX}$")));
    static OPENAI_LIVE: LazyLock<Regex> = LazyLock::new(|| re(r"^gpt-live-[0-9]{1,3}(?:\.[0-9]{1,3})?$"));
    // `-(?![a-z0-9.-]*(?:whisper|translate|transcribe))`: no such word after the first dash.
    let not_transcription = |prefix: &str| {
        model
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_none_or(|rest| !["whisper", "translate", "transcribe"].iter().any(|w| rest.contains(w)))
    };
    match provider {
        "gateway" if GATEWAY_REALTIME.is_match(model) && not_transcription("openai/gpt-realtime") => Some("realtime"),
        "gateway" if GATEWAY_LIVE.is_match(model) => Some("live"),
        "openai" if OPENAI_REALTIME.is_match(model) && not_transcription("gpt-realtime") => Some("realtime"),
        "openai" if OPENAI_LIVE.is_match(model) => Some("live"),
        "codex" if model == "gpt-realtime" => Some("realtime"),
        _ => None,
    }
}

/// `speechFamily(provider, model)` on any values: the provider is looked up as `String(provider)`,
/// as a property key is; the model must be text.
pub fn speech_family_of(provider: Option<&Value>, model: Option<&Value>) -> Option<&'static str> {
    speech_family(&js_string(provider), model?.as_str()?)
}

/// `providerModelId`: the Gateway id without `openai/` for an OpenAI key.
pub fn provider_model_id(provider: &str, gateway_id: &str) -> String {
    if provider == "gateway" {
        gateway_id.to_string()
    } else {
        gateway_id.strip_prefix("openai/").unwrap_or(gateway_id).to_string()
    }
}

/// `parseSpeechPolicy`: `null` for `null`, the settings, or the TS's error.
pub fn parse_speech_policy(v: Option<&Value>) -> Result<Value, String> {
    static CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-zA-Z0-9_-]{1,100}$"));
    if v.is_some_and(Value::is_null) {
        return Ok(Value::Null);
    }
    let p = object(v).ok_or("Invalid speech settings")?;
    let credential = p.get("credentialId").and_then(Value::as_str);
    let minutes = safe_int(p.get("maxMinutes"));
    let ok = only(p, &["provider", "credentialId", "model", "maxMinutes"])
        // Rust only: the provider is text (the TS took `["gateway"]`).
        && p.get("provider").is_some_and(Value::is_string)
        && speech_family_of(p.get("provider"), p.get("model")).is_some()
        && credential.is_some_and(|c| CREDENTIAL.is_match(c))
        && !(credential == Some("included") && p.get("provider") != Some(&json!("gateway")))
        && minutes.is_some_and(|m| (5..=60).contains(&m));
    if !ok {
        return Err("Choose a supported speech model and a call limit from 5 to 60 minutes".into());
    }
    let mut out = Map::new();
    out.insert("provider".into(), p.get("provider").cloned().unwrap_or(Value::Null));
    out.insert("credentialId".into(), json!(credential));
    out.insert("model".into(), p["model"].clone());
    out.insert("maxMinutes".into(), json!(minutes));
    Ok(Value::Object(out))
}

// ---- Wake words ---------------------------------------------------------------------------

pub const DEFAULT_WAKE_WORDS: &[&str] = &["ControlClaw"];

/// `MEETING_WAKE_DEFAULT`: on, so the agent stays out of conversations it is not part of.
pub fn meeting_wake_default() -> Value {
    json!({"enabled": true, "words": DEFAULT_WAKE_WORDS})
}

/// `PHONE_WAKE_DEFAULT`: off, a call is a one-to-one conversation.
pub fn phone_wake_default() -> Value {
    json!({"enabled": false, "words": DEFAULT_WAKE_WORDS})
}

const COMMON_WORDS: &[&str] = &[
    "hey",
    "hi",
    "hello",
    "ok",
    "okay",
    "yes",
    "yeah",
    "no",
    "stop",
    "thanks",
    "thank",
    "please",
    "the",
    "and",
    "but",
    "so",
    "well",
    "right",
    "sure",
    "sorry",
    "what",
    "why",
    "how",
    "who",
    "can",
    "could",
    "would",
    "will",
    "just",
    "now",
    "here",
    "there",
    "this",
    "that",
    "you",
    "we",
    "they",
    "agent",
    "assistant",
    "computer",
    "everyone",
    "guys",
    "team",
];

/// `wakeWordProblem`: why a name cannot be used, or `None`.
pub fn wake_word_problem(word: &Value) -> Option<&'static str> {
    static SHAPE: LazyLock<Regex> = LazyLock::new(|| re(r"^[\p{L}\p{N}][\p{L}\p{N} '’-]*$"));
    static LETTER: LazyLock<Regex> = LazyLock::new(|| re(r"\p{L}"));
    let Some(w) = word.as_str() else {
        return Some("Enter a name");
    };
    let w = js_tidy(w);
    if !(3..=32).contains(&len16(&w)) {
        return Some("Use 3 to 32 characters");
    }
    if !SHAPE.is_match(&w) {
        return Some("Use letters, numbers, spaces, hyphens or apostrophes");
    }
    if LETTER.find_iter(&w).count() < 3 {
        return Some("Use at least 3 letters");
    }
    if w.split(' ').count() > 3 {
        return Some("Use at most 3 words");
    }
    if w.split([' ', '-'])
        .all(|part| COMMON_WORDS.contains(&part.to_lowercase().as_str()))
    {
        return Some("Too common: people say it all the time");
    }
    None
}

/// `wakeWordWarning`: a name of one short syllable is easy to hear by mistake.
pub fn wake_word_warning(word: &str) -> Option<&'static str> {
    static VOWELS: LazyLock<Regex> = LazyLock::new(|| re(r"[aeiouy]+"));
    let vowels = VOWELS.find_iter(&word.to_lowercase()).count();
    (!word.contains(' ') && vowels <= 1).then_some("A short name is easy to hear by mistake")
}

/// `parseWakePolicy`: the names tidied, or the TS's error.
pub fn parse_wake_policy(v: Option<&Value>) -> Result<Value, String> {
    const INVALID: &str = "Invalid wake words";
    let p = object(v).ok_or(INVALID)?;
    let (Some(enabled), Some(words)) = (
        p.get("enabled").and_then(Value::as_bool),
        p.get("words").and_then(Value::as_array),
    ) else {
        return Err(INVALID.into());
    };
    if !only(p, &["enabled", "words"]) {
        return Err(INVALID.into());
    }
    let words: Vec<Value> = words
        .iter()
        .map(|w| w.as_str().map_or_else(|| w.clone(), |s| json!(js_tidy(s))))
        .collect();
    if words.is_empty() || words.len() > 5 {
        return Err("Use one to five names".into());
    }
    for w in &words {
        if let Some(problem) = wake_word_problem(w) {
            return Err(format!("{}: {problem}", head16(&js_string(Some(w)), 32)));
        }
    }
    let mut seen = HashSet::new();
    if !words.iter().all(|w| seen.insert(js_string(Some(w)).to_lowercase())) {
        return Err("Each name only once".into());
    }
    Ok(json!({"enabled": enabled, "words": words}))
}

// ---- Joining by itself, after the meeting, Full agent, presenting --------------------------

pub const AUTO_JOIN_MAX_PER_DAY: i64 = 20;

/// `parseAutoJoinPolicy`.
pub fn parse_auto_join_policy(v: Option<&Value>) -> Result<Value, String> {
    let p = object(v).ok_or("Invalid automatic joining settings")?;
    let per_day = safe_int(p.get("maxPerDay"));
    let ok = only(p, &["enabled", "mode", "email", "calendar", "maxPerDay"])
        && p.get("enabled").is_some_and(Value::is_boolean)
        && p.get("email").is_some_and(Value::is_boolean)
        && ["transcript", "bidi"].contains(&js_word(p.get("mode")))
        && ["off", "invited", "all"].contains(&js_word(p.get("calendar")))
        && per_day.is_some_and(|n| (1..=AUTO_JOIN_MAX_PER_DAY).contains(&n));
    if !ok {
        return Err(format!(
            "Choose where invites come from and 1 to {AUTO_JOIN_MAX_PER_DAY} joins a day"
        ));
    }
    Ok(json!({
        "enabled": p["enabled"],
        "mode": p["mode"],
        "email": p["email"],
        "calendar": p["calendar"],
        "maxPerDay": per_day,
    }))
}

fn reach(calendar: Option<&Value>) -> f64 {
    // `reach[next.calendar]`: an unknown key is `undefined`, which compares false either way.
    match js_string(calendar).as_str() {
        "off" => 0.0,
        "invited" => 1.0,
        "all" => 2.0,
        _ => f64::NAN,
    }
}

/// `autoJoinWidens`: the agent may join more by itself than before, which needs a code.
pub fn auto_join_widens(previous: Option<&Value>, next: Option<&Value>) -> bool {
    let enabled = |v: Option<&Value>| truthy(v.and_then(|v| v.get("enabled")));
    let (Some(next), true) = (next, enabled(next)) else {
        return false;
    };
    let Some(previous) = previous.filter(|p| enabled(Some(p))) else {
        return true;
    };
    let number = |v: &Value| v.get("maxPerDay").and_then(Value::as_f64).unwrap_or(f64::NAN);
    (truthy(next.get("email")) && !truthy(previous.get("email")))
        || reach(next.get("calendar")) > reach(previous.get("calendar"))
        || (next.get("mode") == Some(&json!("bidi")) && previous.get("mode") != Some(&json!("bidi")))
        || number(next) > number(previous)
}

/// `autoJoinSummary`: what the confirmation message says about joining without the owner.
pub fn auto_join_summary(auto: &Value) -> String {
    let calendar = auto.get("calendar").and_then(Value::as_str);
    let mut from = Vec::new();
    if truthy(auto.get("email")) {
        from.push("invites emailed to it by your allowed senders");
    }
    if calendar == Some("invited") {
        from.push("events on the connected Google Calendar that invite it");
    }
    if calendar == Some("all") {
        from.push("every event with a Meet link on the connected Google Calendar");
    }
    let from = from.join("; ");
    format!(
        "Let the agent join meetings by itself, in {}, at most {} a day: {}.",
        if auto.get("mode") == Some(&json!("bidi")) {
            "Bidi"
        } else {
            "Transcript"
        },
        js_string(auto.get("maxPerDay")),
        if from.is_empty() { "no source chosen yet" } else { &from }
    )
}

/// `parseFollowUpPolicy`.
pub fn parse_follow_up_policy(v: Option<&Value>) -> Result<Value, String> {
    const INVALID: &str = "Invalid after-meeting setting";
    let p = object(v).ok_or(INVALID)?;
    match p.get("enabled") {
        Some(Value::Bool(b)) if only(p, &["enabled"]) => Ok(json!({"enabled": b})),
        _ => Err(INVALID.into()),
    }
}

/// `parseFullAgentPolicy`.
pub fn parse_full_agent_policy(v: Option<&Value>) -> Result<Value, String> {
    const INVALID: &str = "Invalid Full agent setting";
    let p = object(v).ok_or(INVALID)?;
    match p.get("enabled") {
        Some(Value::Bool(b)) if only(p, &["enabled"]) => Ok(json!({"enabled": b})),
        _ => Err(INVALID.into()),
    }
}

/// `fullAgentWidens`: turning Full agent on needs a code; turning it off needs none.
pub fn full_agent_widens(previous: Option<&Value>, next: Option<&Value>) -> bool {
    truthy(next.and_then(|n| n.get("enabled"))) && !truthy(previous.and_then(|p| p.get("enabled")))
}

pub fn full_agent_summary() -> &'static str {
    "Full agent in meetings: anyone in a meeting the agent was sent to can ask it to do anything it can do (files, packages, messages), and names in a meeting can be faked. This applies to meetings joined from the console and to events organized by the agent's own Google account. Firewall rules and confirmation codes still apply."
}

/// `fullAgentMeeting`: Full agent on, and joined from the console (no claim) or from an event the
/// agent's own Google account organized.
pub fn full_agent_meeting(policy: &Value, claim: Option<&Value>, own_account: Option<&str>) -> bool {
    if !truthy(policy.get("fullAgent").and_then(|f| f.get("enabled"))) {
        return false;
    }
    let Some(claim) = claim.filter(|c| !c.is_null()) else {
        return true;
    };
    claim.get("source") == Some(&json!("calendar"))
        && own_account.is_some_and(|own| {
            !own.is_empty()
                && claim
                    .get("organizer")
                    .and_then(Value::as_str)
                    .is_some_and(|o| o.to_lowercase() == own.to_lowercase())
        })
}

/// `presentWidens`: turning presenting on needs a code; turning it off needs none.
pub fn present_widens(previous: Option<&Value>, next: Option<&Value>) -> bool {
    next == Some(&Value::Bool(true)) && previous != Some(&Value::Bool(true))
}

pub fn present_summary() -> &'static str {
    "Let the agent present its own browser in meetings: everyone in the meeting sees the page it shows, including sites it is signed in to. Saved website logins stay on the firewall."
}

// ---- The settings ---------------------------------------------------------------------------

/// Voice sessions with audio a gpt-live meeting may open (`WAKE_SESSIONS`).
pub const WAKE_SESSIONS: i64 = 40;

/// `policy.wake ?? MEETING_WAKE_DEFAULT`.
pub fn wake_of(policy: &Value) -> Value {
    match policy.get("wake") {
        None | Some(Value::Null) => meeting_wake_default(),
        Some(w) => w.clone(),
    }
}

fn live(policy: &Value) -> bool {
    let speech = policy.get("speech");
    truthy(speech)
        && speech_family_of(
            speech.and_then(|s| s.get("provider")),
            speech.and_then(|s| s.get("model")),
        ) == Some("live")
}

/// `wakeSessions`: how many voice sessions the firewall allows in one meeting; 0 for one session.
pub fn wake_sessions(policy: &Value) -> i64 {
    let wake_on = truthy(wake_of(policy).get("enabled"));
    if truthy(policy.get("enabled")) && live(policy) && (wake_on || policy.get("always") == Some(&Value::Bool(true))) {
        WAKE_SESSIONS
    } else {
        0
    }
}

/// `alwaysListening`: gpt-live, the wake word off, and chosen.
pub fn always_listening(policy: &Value) -> bool {
    live(policy) && !truthy(wake_of(policy).get("enabled")) && policy.get("always") == Some(&Value::Bool(true))
}

pub fn default_meeting_policy() -> Value {
    json!({"enabled": false, "platforms": ["google-meet"], "defaultMode": "transcript", "invokers": "owner-browser", "speech": null})
}

pub const MEET_HOST_VERSION: &str = "2026.9.7";
pub const MEET_PLUGIN_VERSION: &str = "2026.9.7";

/// `OP_ID`: a lowercase UUID.
pub static OP_ID: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"));

/// `parseMeetingPolicy`: the settings with the TS's key order, or the TS's error (the first one
/// the TS would throw).
pub fn parse_meeting_policy(v: Option<&Value>) -> Result<Value, String> {
    static CONSULT_MODEL: LazyLock<Regex> =
        LazyLock::new(|| re(r"^(main|[a-z0-9][a-z0-9_-]{0,40}/[A-Za-z0-9][A-Za-z0-9._:/-]{0,120})$"));
    let p = object(v).ok_or("Invalid meetings settings")?;
    let keys = [
        "enabled",
        "platforms",
        "defaultMode",
        "invokers",
        "speech",
        "wake",
        "always",
        "reminders",
        "followUp",
        "autoJoin",
        "fullAgent",
        "present",
        "consultModel",
    ];
    let optional_bool = |k: &str| !has(p, k) || p[k].is_boolean();
    let ok = only(p, &keys)
        && p.get("enabled").is_some_and(Value::is_boolean)
        && p.get("platforms")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 1 && a[0] == "google-meet")
        && ["transcript", "bidi"].contains(&js_word(p.get("defaultMode")))
        && p.get("invokers") == Some(&json!("owner-browser"))
        && optional_bool("always")
        && optional_bool("reminders")
        && optional_bool("present")
        && (!has(p, "consultModel") || p["consultModel"].as_str().is_some_and(|m| CONSULT_MODEL.is_match(m)));
    if !ok {
        return Err("Invalid owner-browser Google Meet settings".into());
    }
    let speech = parse_speech_policy(p.get("speech"))?;
    if p.get("defaultMode") == Some(&json!("bidi")) && speech.is_null() {
        return Err("Bidi needs a speech provider".into());
    }
    let auto_join = if has(p, "autoJoin") {
        Some(parse_auto_join_policy(p.get("autoJoin"))?)
    } else {
        None
    };
    if auto_join
        .as_ref()
        .is_some_and(|a| truthy(a.get("enabled")) && a.get("mode") == Some(&json!("bidi")))
        && speech.is_null()
    {
        return Err("Bidi needs a speech provider".into());
    }
    let mut out = Map::new();
    out.insert("enabled".into(), p["enabled"].clone());
    out.insert("platforms".into(), json!(["google-meet"]));
    out.insert("defaultMode".into(), p["defaultMode"].clone());
    out.insert("invokers".into(), json!("owner-browser"));
    out.insert("speech".into(), speech);
    if has(p, "wake") {
        out.insert("wake".into(), parse_wake_policy(p.get("wake"))?);
    }
    if let Some(a) = auto_join {
        out.insert("autoJoin".into(), a);
    }
    if has(p, "followUp") {
        out.insert("followUp".into(), parse_follow_up_policy(p.get("followUp"))?);
    }
    for k in ["always", "reminders"] {
        if has(p, k) {
            out.insert(k.into(), p[k].clone());
        }
    }
    if has(p, "fullAgent") {
        out.insert("fullAgent".into(), parse_full_agent_policy(p.get("fullAgent"))?);
    }
    for k in ["present", "consultModel"] {
        if has(p, k) {
            out.insert(k.into(), p[k].clone());
        }
    }
    Ok(Value::Object(out))
}

// ---- Meet links and claims --------------------------------------------------------------------

/// `canonicalMeetUrl`: only `https://meet.google.com/abc-defg-hij`.
pub fn canonical_meet_url(v: Option<&Value>) -> Result<String, String> {
    static LINK: LazyLock<Regex> = LazyLock::new(|| re(r"^https://meet\.google\.com/[a-z]{3}-[a-z]{4}-[a-z]{3}$"));
    let link = v
        .and_then(Value::as_str)
        .filter(|s| len16(s) <= 200)
        .ok_or("Enter a Google Meet link")?;
    if !LINK.is_match(link) {
        return Err("Use a link like https://meet.google.com/abc-defg-hij".into());
    }
    Ok(link.to_string())
}

/// `isMeetPage` (#538): whether a browser page is the meeting `meet_url` (a `canonical_meet_url`).
/// Google answers `meet.google.com/<code>` with a redirect to `meet.google.com/meet/<code>` (seen
/// 2026-10-28), so both paths are the same meeting; a query string or a trailing slash does not
/// matter. Any other host, code or path is another page, and so is one that is not a URL.
pub fn is_meet_page(page_url: &str, meet_url: &str) -> bool {
    let Ok(page) = url::Url::parse(page_url) else {
        return false;
    };
    let path = page.path().strip_suffix('/').unwrap_or(page.path());
    // `/^\/meet(?=\/[^/]+$)/`: `/meet` only in front of exactly one more segment.
    let path = match path.strip_prefix("/meet") {
        Some(rest) if rest.len() > 1 && rest.starts_with('/') && !rest[1..].contains('/') => rest,
        _ => path,
    };
    format!("{}{path}", page.origin().ascii_serialization()) == meet_url
}

/// `normalizeMeetLink`: a link as a person pastes it (spaces, no scheme, a query, a fragment or
/// one trailing slash), which must then pass `canonicalMeetUrl`.
pub fn normalize_meet_link(v: Option<&Value>) -> Result<String, String> {
    let input = v.and_then(Value::as_str).ok_or("Enter a Google Meet link")?;
    let mut link = crate::js::js_trim(input);
    if len16(link) > 200 {
        return Err("Enter a Google Meet link".into());
    }
    if let Some(at) = link.find(['?', '#']) {
        link = &link[..at];
    }
    let link = link.strip_suffix('/').unwrap_or(link);
    let link = if link.starts_with("meet.google.com/") {
        format!("https://{link}")
    } else {
        link.to_string()
    };
    canonical_meet_url(Some(&json!(link)))
}

/// `parseAutoJoinClaim`: `{source, organizer}` with the organizer in lower case.
pub fn parse_auto_join_claim(v: Option<&Value>) -> Result<Value, String> {
    const INVALID: &str = "Invalid automatic join";
    let p = object(v).ok_or(INVALID)?;
    let source = p
        .get("source")
        .and_then(Value::as_str)
        .filter(|s| *s == "email" || *s == "calendar");
    let organizer = p.get("organizer").and_then(Value::as_str);
    let (true, Some(source), Some(organizer)) = (only(p, &["source", "organizer"]), source, organizer) else {
        return Err(INVALID.into());
    };
    // `/^[^\s@<>"]{1,64}@[a-z0-9.-]{1,180}$/i`, without the `u` flag: the name's length counts
    // UTF-16 units.
    let (name, domain) = organizer.split_once('@').ok_or(INVALID)?;
    let name_ok = (1..=64).contains(&len16(name)) && !name.chars().any(|c| js_space(c) || "@<>\"".contains(c));
    let domain_ok = (1..=180).contains(&domain.len())
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !name_ok || !domain_ok {
        return Err(INVALID.into());
    }
    Ok(json!({"source": source, "organizer": organizer.to_lowercase()}))
}

/// `AUTO_JOIN_REFUSALS`: why the firewall will not let the agent join by itself.
pub fn auto_join_refusal(reason: &str) -> Option<&'static str> {
    Some(match reason {
        "off" => "Joining automatically is off",
        "source_off" => "This kind of invite is off in the settings",
        "organizer" => "The organizer is not an allowed sender",
        "daily_limit" => "The limit of automatic joins for today is reached",
        _ => return None,
    })
}

// ---- The model of the meeting voice's lookups (`consult-model.ts`) --------------------------

/// `CONSULT_MODEL_MAIN`: the agent's main model.
pub const CONSULT_MODEL_MAIN: &str = "main";

/// `CONSULT_FAST_MODELS`: (provider, ref, name), best first.
pub const CONSULT_FAST_MODELS: &[(&str, &str, &str)] = &[
    ("openai", "openai/gpt-6-luna", "GPT-6 Luna"),
    ("openai", "openai/gpt-5.6-luna", "GPT-5.6 Luna"),
    ("openai", "openai/gpt-5.4-mini", "GPT-5.4 mini"),
    ("anthropic", "anthropic/claude-haiku-5-5", "Claude Haiku 5.5"),
    ("anthropic", "anthropic/claude-haiku-4-5", "Claude Haiku 4.5"),
    ("controlclaw", "controlclaw/openai/gpt-5.4-mini", "GPT-5.4 mini"),
    (
        "controlclaw",
        "controlclaw/anthropic/claude-haiku-4.5",
        "Claude Haiku 4.5",
    ),
];

/// `CONSULT_PROVIDERS`: the providers whose model lists decide the choices.
pub fn consult_providers() -> Vec<&'static str> {
    let mut out: Vec<&str> = Vec::new();
    for (provider, _, _) in CONSULT_FAST_MODELS {
        if !out.contains(provider) {
            out.push(provider);
        }
    }
    out
}

/// `consultModelChoices`: `{ref, name}` for each fast model whose provider the agent has and whose
/// model OpenClaw lists for it.
pub fn consult_model_choices(providers: &[String], listed: &Map<String, Value>) -> Vec<Value> {
    CONSULT_FAST_MODELS
        .iter()
        .filter(|(provider, r, _)| {
            providers.iter().any(|p| p == provider)
                && listed
                    .get(*provider)
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|id| id == r))
        })
        .map(|(_, r, name)| json!({"ref": r, "name": name}))
        .collect()
}

/// `effectiveConsultModel`: the model the consult runs on, `None` for the main model. Unset, or a
/// model the agent can no longer use, follows the first choice.
pub fn effective_consult_model(saved: Option<&str>, choices: &[Value]) -> Option<String> {
    if saved == Some(CONSULT_MODEL_MAIN) {
        return None;
    }
    if let Some(s) = saved.filter(|s| !s.is_empty())
        && choices.iter().any(|c| c.get("ref").and_then(Value::as_str) == Some(s))
    {
        return Some(s.to_string());
    }
    choices
        .first()
        .and_then(|c| c.get("ref"))
        .and_then(Value::as_str)
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::is_meet_page;

    /// `packages/meetings/src/index.test.ts` on main (#538).
    #[test]
    fn the_meeting_page_is_the_same_meeting_at_the_code_and_at_googles_meet_redirect() {
        let meet = "https://meet.google.com/abc-defg-hij";
        for page in [
            "https://meet.google.com/abc-defg-hij",
            "https://meet.google.com/abc-defg-hij/",
            "https://meet.google.com/abc-defg-hij?hl=en",
            "https://meet.google.com/meet/abc-defg-hij?hl=en",
            "https://meet.google.com/meet/abc-defg-hij/",
        ] {
            assert!(is_meet_page(page, meet), "{page}");
        }
        for page in [
            "https://meet.google.com/xyz-defg-hij",
            "https://meet.google.com/meet/xyz-defg-hij",
            "https://meet.google.com/",
            "https://meet.google.com/meet",
            "https://meet.google.com/meet/meet/abc-defg-hij",
            "https://accounts.google.com/meet/abc-defg-hij",
            "https://meet.google.com.evil.example/abc-defg-hij",
            "http://meet.google.com/abc-defg-hij",
            "not a url",
            // Not in the TS test; `/meet/` and `/meetx/<code>` are other pages there too.
            "https://meet.google.com/meet/",
            "https://meet.google.com/meetx/abc-defg-hij",
        ] {
            assert!(!is_meet_page(page, meet), "{page}");
        }
    }
}
