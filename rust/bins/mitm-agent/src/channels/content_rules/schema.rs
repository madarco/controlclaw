//! The shape of a content rule and of a change to one (`content-rules-schema.ts`), as zod reads
//! them: the console imports that file, so both refuse the same things. Strict: a key the schema
//! does not name is refused.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::channels::content_engine::{CONTENT_CHANNELS, EngineRule};
use crate::channels::js::js_len;

pub const CONTENT_DETECTORS: [&str; 4] = ["secrets", "iban", "card", "emails"];
pub const CONTENT_POLICY_MAX: usize = 300;
pub const CONTENT_RULES_MAX: usize = 50;
/// Channels a message only comes in on (webhooks) or only goes out on (the web).
const IN_ONLY: &[&str] = &["webhook"];
const OUT_ONLY: &[&str] = &["web"];

/// A content rule as the console writes it and the store keeps it, in the schema's key order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentRule {
    pub id: String,
    pub name: String,
    pub direction: String,
    pub channels: Vec<String>,
    pub patterns: Vec<String>,
    pub detectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    pub action: String,
    pub reason: String,
    pub enabled: bool,
}

impl ContentRule {
    pub fn engine(&self) -> EngineRule {
        EngineRule {
            id: self.id.clone(),
            name: Some(self.name.clone()),
            direction: self.direction.clone(),
            channels: self.channels.clone(),
            patterns: self.patterns.clone(),
            detectors: self.detectors.clone(),
            action: self.action.clone(),
            reason: self.reason.clone(),
            policy: self.policy.clone(),
        }
    }
}

/// A change to the rules (`contentChange`).
#[derive(Debug, Clone, PartialEq)]
pub enum ContentChange {
    Put(ContentRule),
    Delete(String),
    /// Accept the AI review's current model and key for the policies.
    Ai,
}

impl ContentChange {
    pub fn op(&self) -> &'static str {
        match self {
            ContentChange::Put(_) => "put",
            ContentChange::Delete(_) => "delete",
            ContentChange::Ai => "ai",
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            ContentChange::Put(r) => serde_json::json!({"op": "put", "rule": r}),
            ContentChange::Delete(id) => serde_json::json!({"op": "delete", "id": id}),
            ContentChange::Ai => serde_json::json!({"op": "ai"}),
        }
    }
}

/// Text a person typed, kept to one plain line: no control or format characters, nothing
/// private-use or unassigned, no line or paragraph separators, and no runs of spaces.
fn plain_line(s: &str) -> bool {
    static ALLOWED: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[^\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]+$").expect("regex"));
    !s.starts_with(' ') && !s.contains("  ") && !s.ends_with(' ') && ALLOWED.is_match(s)
}

fn one_line(v: Option<&Value>, max: usize) -> Result<String, String> {
    let s = v.and_then(Value::as_str).ok_or("not a string")?;
    if js_len(s) < 1 || js_len(s) > max || !plain_line(s) {
        return Err("must be one plain line".into());
    }
    Ok(s.to_string())
}

fn rule_id(v: Option<&Value>) -> Result<String, String> {
    static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,63}$").expect("regex"));
    v.and_then(Value::as_str)
        .filter(|s| ID.is_match(s))
        .map(str::to_string)
        .ok_or_else(|| "invalid id".into())
}

fn one_of(v: Option<&Value>, allowed: &[&str]) -> Result<String, String> {
    v.and_then(Value::as_str)
        .filter(|s| allowed.contains(s))
        .map(str::to_string)
        .ok_or_else(|| "not one of the allowed values".into())
}

fn strict(m: &Map<String, Value>, keys: &[&str]) -> Result<(), String> {
    match m.keys().find(|k| !keys.contains(&k.as_str())) {
        Some(k) => Err(format!("unknown key {k}")),
        None => Ok(()),
    }
}

/// `contentRule.parse`.
pub fn parse_rule(v: &Value) -> Result<ContentRule, String> {
    let m = v.as_object().ok_or("not an object")?;
    strict(
        m,
        &[
            "id",
            "name",
            "direction",
            "channels",
            "patterns",
            "detectors",
            "policy",
            "action",
            "reason",
            "enabled",
        ],
    )?;
    let channels = m.get("channels").and_then(Value::as_array).ok_or("no channels")?;
    if channels.is_empty() || channels.len() > CONTENT_CHANNELS.len() {
        return Err("channels".into());
    }
    let channels = channels
        .iter()
        .map(|c| one_of(Some(c), &CONTENT_CHANNELS))
        .collect::<Result<Vec<_>, _>>()?;
    let patterns = m.get("patterns").and_then(Value::as_array).ok_or("no patterns")?;
    if patterns.len() > 50 {
        return Err("patterns".into());
    }
    let patterns = patterns
        .iter()
        .map(|p| one_line(Some(p), 100))
        .collect::<Result<Vec<_>, _>>()?;
    let detectors = m.get("detectors").and_then(Value::as_array).ok_or("no detectors")?;
    if detectors.len() > CONTENT_DETECTORS.len() {
        return Err("detectors".into());
    }
    let detectors = detectors
        .iter()
        .map(|d| one_of(Some(d), &CONTENT_DETECTORS))
        .collect::<Result<Vec<_>, _>>()?;
    // zod's `.optional()`: absent only, never null.
    let policy = match m.get("policy") {
        None => None,
        Some(p) => Some(one_line(Some(p), CONTENT_POLICY_MAX)?),
    };
    let r = ContentRule {
        id: rule_id(m.get("id"))?,
        name: one_line(m.get("name"), 80)?,
        direction: one_of(m.get("direction"), &["in", "out", "both"])?,
        channels,
        patterns,
        detectors,
        policy,
        action: one_of(m.get("action"), &["block", "hold", "log"])?,
        reason: one_line(m.get("reason"), 200)?,
        enabled: m.get("enabled").and_then(Value::as_bool).ok_or("enabled")?,
    };
    let mut seen = std::collections::HashSet::new();
    if !r.channels.iter().all(|c| seen.insert(c)) {
        return Err("a channel is listed twice".into());
    }
    if r.patterns.len() + r.detectors.len() == 0 && r.policy.is_none() {
        return Err("a rule needs a policy, a word or a detector".into());
    }
    // Nothing holds a message coming in: the agent's next poll would have to hand it over later.
    if r.action == "hold" && r.direction != "out" {
        return Err("only a message going out can be held".into());
    }
    // A rule that could never fire is a mistake the person should see now, not a silent no-op.
    let fires = |c: &String| match r.direction.as_str() {
        "out" => !IN_ONLY.contains(&c.as_str()),
        "in" => !OUT_ONLY.contains(&c.as_str()),
        _ => true,
    };
    if !r.channels.iter().any(fires) {
        return Err("these channels never carry messages in that direction".into());
    }
    Ok(r)
}

/// `contentChange.parse`.
pub fn parse_change(v: &Value) -> Result<ContentChange, String> {
    let m = v.as_object().ok_or("not an object")?;
    match m.get("op").and_then(Value::as_str) {
        Some("put") => {
            strict(m, &["op", "rule"])?;
            Ok(ContentChange::Put(parse_rule(m.get("rule").ok_or("no rule")?)?))
        }
        Some("delete") => {
            strict(m, &["op", "id"])?;
            Ok(ContentChange::Delete(rule_id(m.get("id"))?))
        }
        Some("ai") => {
            strict(m, &["op"])?;
            Ok(ContentChange::Ai)
        }
        _ => Err("unknown op".into()),
    }
}
