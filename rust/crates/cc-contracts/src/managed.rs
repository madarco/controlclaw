//! The website rules a control plane adds by itself for a model provider or a channel that is set
//! up, so an agent keeps reaching them when "Every other site" is Block. The list is
//! `managed-egress.json`, which the SaaS reads too (`packages/console-ui/src/lib/managed-egress.ts`
//! has the same data, and a test there compares the two).
//!
//! A managed rule carries `managed` (its source's key) in the rule the firewall reads. Only a
//! control plane's code writes that field: the proxy copies it into the traffic record, and the AI
//! log review and the Activity log tell these requests apart by it, never by the rule's name or
//! host (an owner's rule named "Telegram" is the owner's).

use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::{Value, json};

/// The rule's field naming its source, and the record's.
pub const FIELD: &str = "managed";
/// Every managed rule's id starts with this; no other rule's does.
pub const ID_PREFIX: &str = "managed:";

#[derive(Debug, Clone, Deserialize)]
pub struct Host {
    pub domain: String,
    /// A substring of the path, as `match_path` is.
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Source {
    pub key: String,
    /// `provider` or `channel`.
    pub kind: String,
    pub name: String,
    pub hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
struct File {
    priority: i64,
    sources: Vec<Source>,
}

static FILE: LazyLock<File> =
    LazyLock::new(|| serde_json::from_str(include_str!("../managed-egress.json")).expect("managed-egress.json"));

/// Before every rule a person adds (theirs are 0 or more), after the brain's own (-20, -10).
pub fn priority() -> i64 {
    FILE.priority
}

pub fn sources() -> &'static [Source] {
    &FILE.sources
}

pub fn source(key: &str) -> Option<&'static Source> {
    FILE.sources.iter().find(|s| s.key == key)
}

/// The rule's name: what it is for, as the rules list and the traffic log show it.
pub fn rule_name(s: &Source) -> String {
    match s.kind.as_str() {
        "provider" => format!("Model provider: {}", s.name),
        _ => format!("Channel: {}", s.name),
    }
}

/// The rules for one source, for every agent (`vm_id` none) or one, in the form the firewall reads.
pub fn rules(s: &Source, vm_id: Option<&str>) -> Vec<Value> {
    s.hosts
        .iter()
        .map(|h| {
            let mut id = format!("{ID_PREFIX}{}:{}", s.key, h.domain);
            if let Some(v) = vm_id {
                id.push(':');
                id.push_str(v);
            }
            let mut r = json!({
                "id": id,
                "name": rule_name(s),
                "match_domain": h.domain,
                "effect": "allow",
                "priority": priority(),
                FIELD: s.key,
            });
            if let Some(p) = &h.path {
                r["match_path"] = json!(p);
            }
            if let Some(v) = vm_id {
                r["vm_id"] = json!(v);
            }
            r
        })
        .collect()
}

/// A routine request, from its traffic record: let through under a managed rule (`managed`, and a
/// `managed:` rule id), carrying the organization's own key or token, which the firewall put in
/// (`swapped`), and answered without an error. The agent's model calls and its bot's polling. The AI
/// log review does not read these, and Activity leaves them out unless asked: one definition for
/// both, so nothing the review flagged is ever hidden. Anything refused, asked, failed, refused by
/// the provider or sent with a key the firewall did not put in is not routine.
pub fn is_routine(r: &Value) -> bool {
    let s = |k: &str| r.get(k).and_then(Value::as_str);
    let absent = |k: &str| r.get(k).is_none_or(Value::is_null);
    s(FIELD).is_some_and(|m| !m.is_empty())
        && s("effect") == Some("allow")
        && s("rule_id").is_some_and(|id| id.starts_with(ID_PREFIX))
        && r.get("swapped")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        && absent("error")
        && absent("model_error")
        && (absent("included") || s("included") == Some("ok"))
        && r.get("status")
            .is_none_or(|v| v.is_null() || v.as_f64().is_some_and(|n| n < 400.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_reads_and_every_rule_is_exact() {
        assert!(priority() < 0);
        assert!(!sources().is_empty());
        for s in sources() {
            assert!(matches!(s.kind.as_str(), "provider" | "channel"), "{}", s.key);
            for h in &s.hosts {
                // One host each: a wildcard would open another tenant's endpoints on a shared domain.
                assert!(!h.domain.contains('*') && h.domain.contains('.'), "{}", h.domain);
            }
        }
        let r = rules(source("telegram").expect("telegram"), Some("vm1"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["id"], "managed:telegram:api.telegram.org:vm1");
        assert_eq!(r[0]["managed"], "telegram");
        assert_eq!(r[0]["vm_id"], "vm1");
        assert_eq!(r[0]["effect"], "allow");
        let c = rules(source("openai_codex").expect("codex"), None);
        assert_eq!(c[0]["match_domain"], "chatgpt.com");
        assert!(c[0].get("vm_id").is_none() && c[0].get("match_path").is_none());
    }

    #[test]
    fn routine_is_the_owners_key_through_a_managed_rule_with_no_error() {
        let base = json!({"effect": "allow", "rule_id": "managed:telegram:api.telegram.org:a1", "managed": "telegram",
                          "swapped": ["CC-TG-1"], "status": 200});
        assert!(is_routine(&base));
        let with = |k: &str, v: Value| {
            let mut r = base.clone();
            r[k] = v;
            is_routine(&r)
        };
        assert!(with("included", json!("ok")));
        assert!(!with("swapped", json!([])), "someone else's token");
        assert!(!with("effect", json!("block")));
        assert!(!with("status", json!(502)));
        assert!(!with("error", json!("upstream_reset")));
        assert!(!with("model_error", json!("credit")));
        assert!(!with("included", json!("used_up")));
        assert!(!with("rule_id", json!("r1")), "an owner's rule");
        assert!(!with("managed", Value::Null));
    }
}
