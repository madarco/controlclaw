//! The brain's model key (`gbrain-key.ts`, docs/plans/gbrain.md §6), as the firewall hands it over.
//!
//! The firewall's `llm.push` for a brain is the one it sends an agent with no model of its own: a
//! `POST /llm/apply` whose `memory.apiKey` is the organization's included key's placeholder, or
//! `memory: null` when that key no longer pays. That one value is all a brain takes from it. A root
//! helper with a fixed path (`cc-gbrain-key`) writes it into GBrain's env file and restarts GBrain
//! when it changed, taking the value on stdin rather than argv.
//!
//! Only a value shaped like the included key's placeholder is accepted, here and again in the
//! helper: whatever reaches GBrain's env file is something the firewall swaps on one host and
//! nowhere else, never a real key.

use std::sync::LazyLock;
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use regex::Regex;
use serde_json::{Map, Value};

use super::run_helper;

static BRAIN_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^vck-cc-included-[A-Za-z0-9]{8,64}$").expect("regex"));
/// What the helper is given to take the key away again.
const CLEAR: &str = "-";
const HELPER: &str = "/usr/local/bin/cc-gbrain-key";
const HELPER_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrainKey {
    Key(String),
    Clear,
}

/// What `/llm/apply` carries, reduced to what a brain uses. The error is why it was refused.
pub fn parse(body: Option<&Map<String, Value>>) -> Result<BrainKey, &'static str> {
    let Some(memory) = body.and_then(|b| b.get("memory")) else {
        return Err("memory is required: a brain takes its model key from memory.apiKey");
    };
    if memory.is_null() {
        return Ok(BrainKey::Clear);
    }
    let key = memory.get("apiKey").and_then(Value::as_str).unwrap_or_default();
    if !BRAIN_KEY.is_match(key) {
        return Err("memory.apiKey is not an included-key placeholder");
    }
    Ok(BrainKey::Key(key.into()))
}

/// Hand the key to the helper; whether it changed.
pub async fn apply(input: &BrainKey, runner: &dyn Runner) -> Result<bool, String> {
    let value = match input {
        BrainKey::Key(k) => k.as_str(),
        BrainKey::Clear => CLEAR,
    };
    let cmd = Cmd::new("sudo")
        .arg(HELPER)
        .stdin(format!("{value}\n"))
        .timeout(HELPER_TIMEOUT);
    run_helper(runner, cmd)
        .await
        .map(|out| out.trim() == "changed")
        .map_err(|e| format!("could not set the brain's model key: {e}"))
}
