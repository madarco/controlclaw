//! Small pieces of the plumbing's own (W1) that the checks need before it lands: the redacted path
//! a permission request carries (`redact_path`) and the AgentMail key behind an agent's
//! placeholder (`credentials_for` narrowed to that one use). W1: replace these with yours.

use super::creds::Creds;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

static TELEGRAM_TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"/bot\d+:[A-Za-z0-9_-]{20,}(/|$)"));
static MEETING: LazyLock<Regex> = LazyLock::new(|| re(r"[a-z]{3}-[a-z]{4}-[a-z]{3}"));

/// `redact_path`: the query-stripped path with any embedded credential, id or meeting code out.
pub fn redact_path(path: &str, host: &str) -> String {
    let p = path.split('?').next().unwrap_or("");
    let h = host.to_lowercase();
    if h == "api.twilio.com" {
        return p
            .split('/')
            .map(|s| {
                if ["", "2010-04-01", "Accounts", "Calls", "Calls.json"].contains(&s) {
                    s
                } else {
                    "{id}"
                }
            })
            .collect::<Vec<_>>()
            .join("/");
    }
    if h == "api.agentmail.to" || h == "ws.agentmail.to" {
        const KEEP: &[&str] = &[
            "v0",
            "inboxes",
            "messages",
            "threads",
            "drafts",
            "attachments",
            "send",
            "reply",
            "reply-all",
            "forward",
            "raw",
            "api-keys",
            "organizations",
        ];
        return p
            .split('/')
            .map(|s| if s.is_empty() || KEEP.contains(&s) { s } else { "{id}" })
            .collect::<Vec<_>>()
            .join("/");
    }
    let clean = TELEGRAM_TOKEN.replace_all(p, "/bot<redacted>$1");
    // `(?<![a-z])[a-z]{3}-[a-z]{4}-[a-z]{3}(?![a-z])`, the edges checked by hand.
    let mut out = String::new();
    let mut last = 0;
    let mut from = 0;
    while let Some(m) = MEETING.find_at(&clean, from) {
        let before = clean[..m.start()]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_lowercase());
        let after = clean[m.end()..].chars().next().is_some_and(|c| c.is_ascii_lowercase());
        if before || after {
            from = m.start() + 1;
            continue;
        }
        out.push_str(&clean[last..m.start()]);
        out.push_str("<meeting>");
        last = m.end();
        from = m.end();
    }
    out.push_str(&clean[last..]);
    out
}

/// `host_matches`: exact, `*`, or `*.example.com`.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(base) = pattern.strip_prefix("*.") {
        return host == base || host.ends_with(&format!(".{base}"));
    }
    host.eq_ignore_ascii_case(pattern)
}

/// `secret_host_matches`: exact, or `*.example.com` for the names under it (not the name itself).
pub fn secret_host_matches(pattern: &str, host: &str) -> bool {
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.');
    let pattern = pattern.to_lowercase();
    if let Some(base) = pattern.strip_prefix("*.") {
        return host.ends_with(&pattern[1..]) && host != base;
    }
    !pattern.contains('*') && host == pattern
}

/// The secret behind `placeholder` for `api.agentmail.to` and this agent
/// (`_secret_value(c) for c in credentials_for(AGENTMAIL_API, vm_id) if c.placeholder == token`).
pub fn agentmail_key(creds: &Creds, vm_id: Option<&str>, placeholder: &str) -> Option<String> {
    if placeholder.is_empty() {
        return None;
    }
    creds
        .for_host("api.agentmail.to", vm_id)
        .into_iter()
        .find(|c| c.get("placeholder").and_then(Value::as_str) == Some(placeholder))
        .and_then(|c| c.get("secret").and_then(Value::as_str).map(str::to_owned))
}

/// `any(c.get("model") for c in credentials_for(host, vm_id))`.
pub fn model_credential(creds: &Creds, vm_id: Option<&str>, host: &str) -> bool {
    creds
        .for_host(host, vm_id)
        .iter()
        .any(|c| crate::checks::creds::truthy(c.get("model")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_as_the_record_has_them() {
        assert_eq!(
            redact_path("/v0/inboxes/a%40agentmail.to/messages/m1/reply?x=1", "api.agentmail.to"),
            "/v0/inboxes/{id}/messages/{id}/reply"
        );
        assert_eq!(
            redact_path("/bot123:AAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage", "api.telegram.org"),
            "/bot<redacted>/sendMessage"
        );
        assert_eq!(redact_path("/abc-defg-hij/x", "meet.google.com"), "/<meeting>/x");
        assert_eq!(redact_path("/xabc-defg-hij", "meet.google.com"), "/xabc-defg-hij");
        assert_eq!(
            redact_path("/2010-04-01/Accounts/AC1/Calls.json", "api.twilio.com"),
            "/2010-04-01/Accounts/{id}/Calls.json"
        );
    }

    fn write_newer(p: &std::path::Path, body: &str) {
        std::fs::write(p, body).expect("write");
        crate::checks::testkit::bump(p);
    }

    #[test]
    fn the_org_model_is_not_this_agents_when_it_has_its_own() {
        let dir = tempfile::tempdir().expect("dir");
        let p = dir.path().join("credentials.json");
        write_newer(
            &p,
            r#"[{"placeholder": "P", "match_domain": "api.example.com", "secret": "o", "model": "x"},
                            {"placeholder": "P", "match_domain": "api.example.com", "secret": "m", "vm_id": "a"}]"#,
        );
        let creds = Creds::new(p);
        assert!(!model_credential(&creds, Some("a"), "api.example.com"));
        assert!(model_credential(&creds, Some("b"), "api.example.com"));
    }

    #[test]
    fn the_agentmail_key_for_this_agent() {
        let dir = tempfile::tempdir().expect("dir");
        let p = dir.path().join("credentials.json");
        let creds = Creds::new(p.clone());
        std::fs::write(
            &p,
            r#"[{"placeholder": "PH", "match_domain": "api.agentmail.to", "secret": "org"},
                {"placeholder": "PH", "match_domain": "api.agentmail.to", "secret": "mine", "vm_id": "vm1"},
                {"placeholder": "PH", "match_domain": "api.agentmail.to", "secret": "theirs", "vm_id": "vm2"}]"#,
        )
        .expect("write");
        assert_eq!(agentmail_key(&creds, Some("vm1"), "PH").as_deref(), Some("mine"));
        assert_eq!(agentmail_key(&creds, Some("vm3"), "PH").as_deref(), Some("org"));
        assert_eq!(agentmail_key(&creds, Some("vm1"), "other"), None);
        write_newer(
            &p,
            r#"[{"placeholder": "CS", "secret_name": "am", "allowed_hosts": ["api.agentmail.to"], "secret": "custom", "vm_id": "vm1"}]"#,
        );
        assert_eq!(
            agentmail_key(&creds, Some("vm1"), "CS").as_deref(),
            Some("custom"),
            "a custom secret of this agent"
        );
        assert_eq!(agentmail_key(&creds, Some("vm2"), "CS"), None);
    }
}
