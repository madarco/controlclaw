//! Host patterns, as addon.py `host_matches`: exact (case-insensitive), `*`, or `*.example.com`
//! (which also matches `example.com` itself).

pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(base) = pattern.strip_prefix("*.") {
        // Case-sensitive in the addon for wildcards; hosts reach here lower-cased.
        return host == base || host.strip_suffix(base).is_some_and(|rest| rest.ends_with('.'));
    }
    host.eq_ignore_ascii_case(pattern)
}

#[cfg(test)]
mod tests {
    use super::host_matches;

    #[test]
    fn matches_like_the_addon() {
        assert!(host_matches("*", "anything"));
        assert!(host_matches("*.slack.com", "wss.slack.com"));
        assert!(host_matches("*.slack.com", "slack.com"));
        assert!(!host_matches("*.slack.com", "evilslack.com"));
        assert!(host_matches("ControlClaw.com", "controlclaw.com"));
        assert!(!host_matches("controlclaw.com", "api.controlclaw.com"));
    }
}
