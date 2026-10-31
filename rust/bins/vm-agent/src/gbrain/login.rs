//! A single-use GBrain admin login link (`gbrain-login.ts`, docs/plans/gbrain.md §9).
//!
//! GBrain issues one only to its owner credential, and only over HTTPS or loopback, so a root
//! helper with a fixed command (`cc-gbrain-login-link`) prints it. What is used here is its path,
//! `/admin/auth/<token>`, good for 5 minutes and one use. The Open exchange sends the browser there,
//! and the activity reader follows one over loopback for the admin cookie its event stream needs.

use std::sync::LazyLock;
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use regex::Regex;

use super::run_helper;

const HELPER: &str = "/usr/local/bin/cc-gbrain-login-link";
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
static LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^https://[^/\s]+(/admin/auth/[A-Za-z0-9_.~-]+)$").expect("regex"));

pub fn parse_login_link(stdout: &str) -> Option<String> {
    let line = stdout.trim().split('\n').next_back().unwrap_or_default().trim();
    LINK.captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

pub async fn login_path(runner: &dyn Runner) -> Result<String, String> {
    let cmd = Cmd::new("sudo").arg(HELPER).timeout(HELPER_TIMEOUT);
    let stdout = run_helper(runner, cmd)
        .await
        .map_err(|e| format!("could not get a GBrain login link: {e}"))?;
    parse_login_link(&stdout).ok_or_else(|| "GBrain returned no login link".into())
}
