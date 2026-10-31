//! The settings the checks read, from the same environment the mitmproxy unit sets. Defaults and
//! fallbacks are `addon.py`'s, including the difference between a variable that is unset (the
//! default) and one set to the empty string (the feature off), as `os.environ.get` has it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Settings {
    /// `MITM_CREDENTIALS_PATH`: the folder of the files the mitm-agent writes is taken from it.
    pub credentials_path: PathBuf,
    /// `MITM_LOG_FILE`, empty for none.
    pub log_file: Option<PathBuf>,
    pub log_max_bytes: u64,
    /// `MITM_CONTENT_RULES_PATH` (default: next to the credentials).
    pub content_rules_path: PathBuf,
    /// `content-own.json`, next to the content rules.
    pub content_own_path: PathBuf,
    /// `MITM_CONTENT_AUDIT_FILE` (default: `content-rules.jsonl` next to the traffic log; none without one).
    pub content_audit_path: Option<PathBuf>,
    /// `MITM_CONTENT_RULES_URL`: the mitm-agent's holds, records and notices (8794).
    pub content_rules_url: String,
    /// `MITM_CONTENT_POLICY_URL`: the judge's `/content` (3101); empty turns the AI check off.
    pub content_policy_url: String,
    pub content_policy_timeout: Duration,
    /// `MITM_CODE_BUTTONS_URL`: where button taps go (8793).
    pub code_buttons_url: String,
    /// `MITM_EMAIL_ADMISSION_URL`: the email rules (8792).
    pub email_admission_url: String,
    /// `MITM_CONTROL_PLANE_HOST`: the console's own channel, which the web check leaves alone.
    pub control_plane_host: Option<String>,
    /// `MITM_MCP_ADMISSION_URL`: MCP tool calls (8796), without a trailing `/`.
    pub mcp_admission_url: String,
    /// `MITM_PENDING_PATH`: permission requests for the mitm-agent.
    pub pending_path: PathBuf,
    /// `MITM_LOGIN_TARGETS_PATH`: sign-in form targets read off login pages (next to the credentials).
    pub login_targets_path: PathBuf,
    /// `MITM_IDENTITIES_PATH`: the kill switch's `locked` flag (a voice lease ends with it).
    pub identities_path: PathBuf,
    /// `MITM_MEETING_MEDIA_PATH`: meeting leases (next to `MITM_RULES_PATH`).
    pub meeting_media_path: PathBuf,
    /// `MITM_PHONE_MEDIA_PATH`: call leases (next to `MITM_RULES_PATH`).
    pub phone_media_path: PathBuf,
}

impl Settings {
    pub fn from_env() -> Self {
        Self::from_vars(&std::env::vars().collect())
    }

    pub fn from_vars(env: &HashMap<String, String>) -> Self {
        // `os.environ.get(k, default)`: the default only when the variable is not set at all.
        let get = |k: &str, default: &str| env.get(k).cloned().unwrap_or_else(|| default.to_owned());
        let credentials_path = PathBuf::from(get("MITM_CREDENTIALS_PATH", "/config/credentials.json"));
        let log = get("MITM_LOG_FILE", "");
        let log_file = Some(log.clone()).filter(|l| !l.is_empty()).map(PathBuf::from);
        let content_rules_path = PathBuf::from(get(
            "MITM_CONTENT_RULES_PATH",
            &dirname(&credentials_path).join("content-rules.json").to_string_lossy(),
        ));
        let content_own_path = dirname(&content_rules_path).join("content-own.json");
        let audit_default = log_file
            .as_ref()
            .map(|l| dirname(l).join("content-rules.jsonl").to_string_lossy().into_owned())
            .unwrap_or_default();
        let content_audit_path = Some(get("MITM_CONTENT_AUDIT_FILE", &audit_default))
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        let judge = get("MITM_AI_JUDGE_URL", "http://127.0.0.1:3101/judge")
            .trim()
            .to_owned();
        let policy_default = if judge.is_empty() {
            String::new()
        } else {
            format!(
                "{}/content",
                judge.rsplit_once('/').map_or(judge.as_str(), |(head, _)| head)
            )
        };
        let rules_dir = dirname(Path::new(&get("MITM_RULES_PATH", "/config/rules.json")));
        Self {
            identities_path: PathBuf::from(get("MITM_IDENTITIES_PATH", "/config/identities.json")),
            meeting_media_path: PathBuf::from(get(
                "MITM_MEETING_MEDIA_PATH",
                &rules_dir.join("meeting-media.json").to_string_lossy(),
            )),
            phone_media_path: PathBuf::from(get(
                "MITM_PHONE_MEDIA_PATH",
                &rules_dir.join("phone-media.json").to_string_lossy(),
            )),
            log_max_bytes: get("MITM_LOG_MAX_BYTES", "8388608").parse().unwrap_or(8 * 1024 * 1024),
            content_rules_url: get("MITM_CONTENT_RULES_URL", "http://127.0.0.1:8794"),
            content_policy_url: get("MITM_CONTENT_POLICY_URL", &policy_default).trim().to_owned(),
            email_admission_url: get("MITM_EMAIL_ADMISSION_URL", "http://127.0.0.1:8792/"),
            control_plane_host: Some(get("MITM_CONTROL_PLANE_HOST", "").trim().to_lowercase())
                .filter(|h| !h.is_empty()),
            mcp_admission_url: get("MITM_MCP_ADMISSION_URL", "http://127.0.0.1:8796")
                .trim_end_matches('/')
                .to_owned(),
            pending_path: PathBuf::from(get("MITM_PENDING_PATH", "/config/pending.jsonl")),
            login_targets_path: PathBuf::from(get(
                "MITM_LOGIN_TARGETS_PATH",
                &dirname(&credentials_path).join("login-targets.json").to_string_lossy(),
            )),
            code_buttons_url: get("MITM_CODE_BUTTONS_URL", "http://127.0.0.1:8793/"),
            content_policy_timeout: seconds(&get("MITM_CONTENT_POLICY_TIMEOUT", "3.5"), 3.5),
            credentials_path,
            log_file,
            content_rules_path,
            content_own_path,
            content_audit_path,
        }
    }
}

/// `os.path.dirname`: the part before the last `/` (empty for a bare name).
fn dirname(p: &Path) -> PathBuf {
    p.parent().map(Path::to_path_buf).unwrap_or_default()
}

fn seconds(raw: &str, default: f64) -> Duration {
    let s = raw
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|s| s.is_finite() && *s >= 0.0)
        .unwrap_or(default);
    // A wait longer than a year is no limit at all (`urllib` takes it as one), and past
    // `Duration`'s range it cannot be built: a year is the cap.
    Duration::try_from_secs_f64(s.min(365.0 * 86400.0)).unwrap_or(Duration::from_millis(3500))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn defaults_follow_the_addon() {
        let s = Settings::from_vars(&vars(&[
            ("MITM_CREDENTIALS_PATH", "/run/mitm/config/credentials.json"),
            ("MITM_LOG_FILE", "/opt/controlclaw/mitm/logs/traffic.jsonl"),
        ]));
        assert_eq!(s.content_rules_path, Path::new("/run/mitm/config/content-rules.json"));
        assert_eq!(s.content_own_path, Path::new("/run/mitm/config/content-own.json"));
        assert_eq!(
            s.content_audit_path.as_deref(),
            Some(Path::new("/opt/controlclaw/mitm/logs/content-rules.jsonl"))
        );
        assert_eq!(s.content_rules_url, "http://127.0.0.1:8794");
        assert_eq!(s.content_policy_url, "http://127.0.0.1:3101/content");
        assert_eq!(s.content_policy_timeout, Duration::from_millis(3500));
    }

    #[test]
    fn a_timeout_out_of_range_does_not_stop_the_start() {
        for v in ["1e20", "inf", "-3", "nope", "1e308"] {
            let s = Settings::from_vars(&vars(&[("MITM_CONTENT_POLICY_TIMEOUT", v)]));
            assert!(s.content_policy_timeout <= Duration::from_secs(365 * 86400), "{v}");
        }
    }

    #[test]
    fn an_empty_judge_turns_the_policies_off() {
        let s = Settings::from_vars(&vars(&[("MITM_AI_JUDGE_URL", "")]));
        assert_eq!(s.content_policy_url, "");
        assert!(s.content_audit_path.is_none(), "no traffic log, no audit file");
        let s = Settings::from_vars(&vars(&[
            ("MITM_AI_JUDGE_URL", ""),
            ("MITM_CONTENT_POLICY_URL", " http://x/c "),
        ]));
        assert_eq!(s.content_policy_url, "http://x/c");
    }
}
