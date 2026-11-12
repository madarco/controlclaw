//! The Auto approve rules, as the firewall keeps and checks them (docs/plans/fwapprove: the console's
//! `evaluateRules` moved here). A control plane sends them in its `egress-rules` reply under
//! [`REPLY_KEY`]; the firewall answers a permission request with the first rule that matches.
//!
//! The console keeps the same check for firewalls that do not have it yet
//! (`packages/console-ui/src/lib/auto-approve.ts`). Both run the cases in `auto-approve-cases.json`,
//! so the two cannot drift.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `egress-rules` reply's key. A control plane that sends it wants the firewall to check them.
pub const REPLY_KEY: &str = "auto_approve";

/// Kinds a person always answers: no rule matches them.
pub const PERSON_ONLY: [&str; 2] = ["settings_change", "meeting_request"];

/// The kinds an agent's vm-agent raises (OpenClaw's own approvals). `meeting_request` is not one:
/// no rule answers it, and the vm-agent raises it to the control plane itself.
pub const AGENT_KINDS: [&str; 3] = ["exec", "plugin", "system"];

/// A title is cut to this many UTF-16 units, as the console cuts it.
pub const TITLE_MAX: usize = 200;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Empty: every kind.
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub title_like: Option<String>,
    /// `contains` (absent) or `exact`, both ignoring case.
    #[serde(default)]
    pub title_match: Option<String>,
    /// Only requests for this box.
    #[serde(default)]
    pub vm_id: Option<String>,
    /// `allow`, `ask` or `block`.
    pub effect: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

/// The kinds a rule may name (`permissionKindSchema` in the console).
pub const RULE_KINDS: [&str; 11] = [
    "payment",
    "delete",
    "access",
    "email_recipient",
    "app_call",
    "other",
    "exec",
    "plugin",
    "system",
    "settings_change",
    "meeting_request",
];
pub const NAME_MAX: usize = 200;
pub const DESCRIPTION_MAX: usize = 1000;
pub const TITLE_LIKE_MAX: usize = 500;
pub const RULES_MAX: usize = 500;

impl AutoRule {
    /// A rule as a store may hold it: what a change, a seed or a template brings is checked here.
    pub fn check(&self) -> Result<(), String> {
        let id_ok = (1..=64).contains(&self.id.len())
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !id_ok {
            return Err("id".into());
        }
        let name = self.name.trim();
        if name.is_empty() || name.encode_utf16().count() > NAME_MAX {
            return Err("name".into());
        }
        if self.description.encode_utf16().count() > DESCRIPTION_MAX {
            return Err("description".into());
        }
        if self.kinds.len() > RULE_KINDS.len() || self.kinds.iter().any(|k| !RULE_KINDS.contains(&k.as_str())) {
            return Err("kinds".into());
        }
        if self
            .title_like
            .as_deref()
            .is_some_and(|t| t.encode_utf16().count() > TITLE_LIKE_MAX)
        {
            return Err("title_like".into());
        }
        if !matches!(self.title_match.as_deref(), None | Some("contains") | Some("exact")) {
            return Err("title_match".into());
        }
        if self.vm_id.as_deref().is_some_and(|v| v.is_empty() || v.len() > 100) {
            return Err("vm_id".into());
        }
        Effect::parse(&self.effect).ok_or_else(|| "effect".to_string())?;
        Ok(())
    }

    pub fn effect(&self) -> Option<Effect> {
        Effect::parse(&self.effect)
    }

    /// The title it matches, if any (an empty one is none).
    pub fn title(&self) -> Option<&str> {
        self.title_like.as_deref().filter(|t| !t.is_empty())
    }

    pub fn exact(&self) -> bool {
        self.title_match.as_deref() == Some("exact")
    }
}

/// The reply's `auto_approve` object. Its presence says the control plane wants the firewall to keep
/// and check the rules.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AutoApprove {
    /// App ids to the names the console shows, for an app call's title.
    #[serde(default)]
    pub app_names: BTreeMap<String, String>,
    /// The rules the console kept before the firewall did, sent until the firewall says it has its
    /// own (`auto_approve` in the beat's features). Taken once, by a store never seeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<Vec<AutoRule>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Ask,
    Block,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Ask => "ask",
            Effect::Block => "block",
        }
    }

    /// The request's status: `approved`, `pending` or `denied`.
    pub fn status(self) -> &'static str {
        match self {
            Effect::Allow => "approved",
            Effect::Ask => "pending",
            Effect::Block => "denied",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Effect::Allow),
            "ask" => Some(Effect::Ask),
            "block" => Some(Effect::Block),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    pub rule: Option<MatchedRule>,
}

impl Decision {
    const ASK: Decision = Decision {
        effect: Effect::Ask,
        rule: None,
    };
}

/// `[A-Za-z0-9_.:/-]`: a tool or action name as MCP and the app catalog spell them.
fn plain(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '-')
}

/// A plain name of 1 to 128 characters at the start of `s`, and what follows it.
fn plain_name(s: &str) -> Option<&str> {
    let end = s.find(|c: char| !plain(c)).unwrap_or(s.len());
    (1..=128).contains(&end).then(|| &s[end..])
}

/// The console's `PLAIN_ACTION`: "Run the tool <name> on the MCP server <host>" or
/// "Run <name> in <app>". A name with a space could hold another rule's text.
pub fn plain_action(title: &str) -> bool {
    if let Some(rest) = title.strip_prefix("Run the tool ")
        && let Some(rest) = plain_name(rest)
        && let Some(host) = rest.strip_prefix(" on the MCP server ")
        && !host.is_empty()
        && !host.chars().any(char::is_whitespace)
    {
        return true;
    }
    title
        .strip_prefix("Run ")
        .and_then(plain_name)
        .and_then(|rest| rest.strip_prefix(" in "))
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| !c.is_whitespace())
}

/// The first rule that matches the request, else Ask. `vm_id` is the box the rules are matched
/// against: the agent for its own approvals and app calls, the firewall for its website and email
/// asks (that is what "Always allow" writes for those).
pub fn evaluate(rules: &[AutoRule], kind: &str, title: &str, vm_id: Option<&str>) -> Decision {
    if PERSON_ONLY.contains(&kind) {
        return Decision::ASK;
    }
    // An app call an Integrations rule asks about is answered only by a rule written for it: one
    // that names the kind or the title. A catch-all allow for shell commands must not approve
    // deletes in connected apps.
    let app_call = kind == "app_call";
    if app_call && !plain_action(title) {
        return Decision::ASK;
    }
    let lower = title.to_lowercase();
    for r in rules {
        if !r.enabled {
            continue;
        }
        if !r.kinds.is_empty() && !r.kinds.iter().any(|k| k == kind) {
            continue;
        }
        let title_like = r.title();
        if app_call && r.kinds.is_empty() && title_like.is_none() {
            continue;
        }
        if let Some(needle) = title_like {
            let needle = needle.to_lowercase();
            let hit = if r.exact() {
                lower == needle
            } else {
                lower.contains(&needle)
            };
            if !hit {
                continue;
            }
        }
        if let Some(v) = r.vm_id.as_deref().filter(|v| !v.is_empty())
            && Some(v) != vm_id
        {
            continue;
        }
        let Some(effect) = Effect::parse(&r.effect) else {
            continue;
        };
        return Decision {
            effect,
            rule: Some(MatchedRule {
                id: r.id.clone(),
                name: r.name.clone(),
            }),
        };
    }
    Decision::ASK
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// `s.slice(0, n)` in UTF-16 units, never splitting a pair.
fn js_slice(s: &str, n: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > n {
            return &s[..i];
        }
    }
    s
}

/// The title the console gives a raise (`permission/route.ts`), so a rule written against the card
/// matches here: an app call is "Run the tool <tool> on the MCP server <host>" or
/// "Run <action> in <App> (<connection>)", a website or email ask its summary (else
/// "METHOD host"), anything else its `title`. Trimmed and cut at [`TITLE_MAX`]. None when empty.
pub fn request_title(raise: &Value, app_names: &BTreeMap<String, String>) -> Option<String> {
    let kind = text(raise, "kind").unwrap_or("access");
    let app = raise.get("app").filter(|a| a.is_object());
    let raw = if let (true, Some(app)) = (kind == "app_call", app) {
        let service = text(app, "service").unwrap_or("");
        let action = text(app, "action").unwrap_or("");
        match service.strip_prefix("mcp:") {
            Some(host) => format!("Run the tool {action} on the MCP server {host}"),
            None => {
                let name = app_names.get(service).map(String::as_str).unwrap_or(service);
                match text(app, "connection").filter(|c| !c.is_empty()) {
                    Some(c) => format!("Run {action} in {name} ({c})"),
                    None => format!("Run {action} in {name}"),
                }
            }
        }
    } else if matches!(kind, "access" | "email_recipient" | "app_call") {
        match text(raise, "summary") {
            Some(s) => s.to_string(),
            None => format!(
                "{} {}",
                text(raise, "method").unwrap_or("GET"),
                text(raise, "host").unwrap_or("")
            ),
        }
    } else {
        text(raise, "title")?.to_string()
    };
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if t.encode_utf16().count() > TITLE_MAX {
        return Some(format!("{}…", js_slice(t, TITLE_MAX - 1)));
    }
    Some(t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cases() -> Value {
        serde_json::from_str(include_str!("../auto-approve-cases.json")).expect("auto-approve-cases.json")
    }

    #[test]
    fn the_shared_cases() {
        let all = cases();
        let rules = all["rules"].as_object().expect("rules");
        for c in all["cases"].as_array().expect("cases") {
            let list: Vec<AutoRule> = c["rules"]
                .as_array()
                .expect("names")
                .iter()
                .map(|n| serde_json::from_value(rules[n.as_str().expect("name")].clone()).expect("rule"))
                .collect();
            let r = &c["request"];
            let d = evaluate(
                &list,
                r["kind"].as_str().expect("kind"),
                r["title"].as_str().expect("title"),
                r["vm_id"].as_str(),
            );
            let name = c["name"].as_str().unwrap_or("");
            assert_eq!(d.effect.as_str(), c["expect"]["effect"], "{name}");
            assert_eq!(
                d.rule.map(|m| m.id),
                c["expect"]["rule_id"].as_str().map(str::to_string),
                "{name}"
            );
        }
    }

    #[test]
    fn the_shared_titles() {
        for c in cases()["titles"].as_array().expect("titles") {
            let names: BTreeMap<String, String> = serde_json::from_value(c["app_names"].clone()).expect("names");
            assert_eq!(
                request_title(&c["request"], &names),
                c["title"].as_str().map(str::to_string),
                "{}",
                c["name"]
            );
        }
    }

    #[test]
    fn plain_actions() {
        assert!(plain_action("Run the tool a on the MCP server h"));
        assert!(!plain_action("Run the tool a on the MCP server h x"));
        assert!(!plain_action("Run the tool  on the MCP server h"));
        assert!(!plain_action(&format!(
            "Run the tool {} on the MCP server h",
            "a".repeat(129)
        )));
        assert!(plain_action("Run x in G"));
        assert!(!plain_action("Run x in  G"));
        assert!(!plain_action("Run x y in G"));
    }

    #[test]
    fn the_reply_key_reads_and_an_unknown_effect_is_skipped() {
        let a: AutoApprove = serde_json::from_value(json!({
            "seed": [{"id": "1", "name": "n", "effect": "maybe"}, {"id": "2", "name": "m", "effect": "block"}],
        }))
        .expect("parse");
        let seed = a.seed.expect("seed");
        assert_eq!(evaluate(&seed, "exec", "x", None).rule.map(|r| r.id), Some("2".into()));
        assert!(seed[0].check().is_err() && seed[1].check().is_ok());
        assert!(a.app_names.is_empty());
        let none: AutoApprove = serde_json::from_value(json!({})).expect("parse");
        assert!(none.seed.is_none());
    }
}
