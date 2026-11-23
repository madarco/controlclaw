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
//!
//! A standalone brain (`standalone.rs`) has no included AI: it is paid by the user's own key, which
//! the firewall holds. It also takes the panel's placeholders for that key (cc-local's `llm.rs`):
//! OpenAI's (`sk-cc-openai-<24 hex>`) and the Vercel AI Gateway's (`vck-cc-<24 hex>`), each with its
//! provider's base URL and no other, so GBrain sends the stand-in only to the host where the firewall
//! swaps it. The helper gets both, `<key> <base url>`, and writes `OPENAI_BASE_URL` too.

use std::sync::LazyLock;
use std::time::Duration;

use cc_proc::Runner;
use regex::Regex;
use serde_json::{Map, Value};

use super::run_helper;

static BRAIN_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^vck-cc-included-[A-Za-z0-9]{8,64}$").expect("regex"));
/// What the helper is given to take the key away again.
const CLEAR: &str = "-";
const HELPER: &str = "/usr/local/bin/cc-gbrain-key";
const HELPER_TIMEOUT: Duration = Duration::from_secs(60);

/// A standalone brain's placeholders, each with the one base URL it may be sent to.
const OWN_KEYS: &[(&str, &str)] = &[
    ("sk-cc-openai-", "https://api.openai.com/v1"),
    ("vck-cc-", "https://ai-gateway.vercel.sh/v1"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrainKey {
    Key(String),
    /// A standalone brain's: the user's key's placeholder, and where GBrain sends it.
    Own {
        key: String,
        base_url: String,
    },
    Clear,
}

/// One of [`OWN_KEYS`]: the prefix, then 24 lower-case hex characters (`mint_placeholder`).
fn own_key(key: &str) -> Option<&'static str> {
    OWN_KEYS.iter().find_map(|(prefix, url)| {
        let tail = key.strip_prefix(prefix)?;
        (tail.len() == 24 && tail.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then_some(*url)
    })
}

/// [`parse`] for a standalone brain: the included placeholder is never one there (no included AI),
/// so only the user's key's, and `memory.baseUrl` must be that provider's own when it is given.
pub fn parse_standalone(body: Option<&Map<String, Value>>) -> Result<BrainKey, &'static str> {
    let Some(memory) = body.and_then(|b| b.get("memory")) else {
        return Err("memory is required: a brain takes its model key from memory.apiKey");
    };
    if memory.is_null() {
        return Ok(BrainKey::Clear);
    }
    let key = memory.get("apiKey").and_then(Value::as_str).unwrap_or_default();
    let Some(base_url) = own_key(key) else {
        return Err("memory.apiKey is not a placeholder for an OpenAI or AI Gateway key");
    };
    match memory.get("baseUrl") {
        None | Some(Value::Null) => {}
        Some(Value::String(u)) if u.trim_end_matches('/') == base_url => {}
        Some(_) => return Err("memory.baseUrl is not that provider's"),
    }
    Ok(BrainKey::Own {
        key: key.into(),
        base_url: base_url.into(),
    })
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
        BrainKey::Key(k) => k.clone(),
        BrainKey::Own { key, base_url } => format!("{key} {base_url}"),
        BrainKey::Clear => CLEAR.into(),
    };
    let cmd = super::helper(HELPER)
        .stdin(format!("{value}\n"))
        .timeout(HELPER_TIMEOUT);
    run_helper(runner, cmd)
        .await
        .map(|out| out.trim() == "changed")
        .map_err(|e| format!("could not set the brain's model key: {e}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn body(v: Value) -> Option<Map<String, Value>> {
        v.as_object().cloned()
    }

    #[test]
    fn a_saas_brain_takes_only_the_included_placeholder() {
        let ok = body(json!({"memory": {"apiKey": "vck-cc-included-abcdefgh12"}}));
        assert_eq!(
            parse(ok.as_ref()),
            Ok(BrainKey::Key("vck-cc-included-abcdefgh12".into()))
        );
        let own = body(json!({"memory": {"apiKey": "sk-cc-openai-0123456789abcdef01234567"}}));
        assert!(parse(own.as_ref()).is_err());
    }

    #[test]
    fn a_standalone_brain_takes_the_users_placeholders_with_their_own_base_url() {
        let openai = body(
            json!({"memory": {"apiKey": "sk-cc-openai-0123456789abcdef01234567", "baseUrl": "https://api.openai.com/v1"}}),
        );
        assert_eq!(
            parse_standalone(openai.as_ref()),
            Ok(BrainKey::Own {
                key: "sk-cc-openai-0123456789abcdef01234567".into(),
                base_url: "https://api.openai.com/v1".into()
            })
        );
        let gateway = body(json!({"memory": {"apiKey": "vck-cc-0123456789abcdef01234567"}}));
        assert_eq!(
            parse_standalone(gateway.as_ref()),
            Ok(BrainKey::Own {
                key: "vck-cc-0123456789abcdef01234567".into(),
                base_url: "https://ai-gateway.vercel.sh/v1".into()
            })
        );
        assert_eq!(
            parse_standalone(body(json!({"memory": null})).as_ref()),
            Ok(BrainKey::Clear)
        );
        for bad in [
            // A real key, the included placeholder, another base URL, upper case, too short, a space.
            json!({"apiKey": "sk-proj-0123456789abcdef01234567"}),
            json!({"apiKey": "vck-cc-included-abcdefgh12"}),
            json!({"apiKey": "sk-cc-openai-0123456789abcdef01234567", "baseUrl": "https://evil.example/v1"}),
            json!({"apiKey": "vck-cc-0123456789abcdef01234567", "baseUrl": "https://api.openai.com/v1"}),
            json!({"apiKey": "vck-cc-0123456789ABCDEF01234567"}),
            json!({"apiKey": "vck-cc-0123456789abcdef0123"}),
            json!({"apiKey": "vck-cc-0123456789abcdef01234567 x"}),
            json!({"apiKey": "vck-cc-0123456789abcdef01234567", "baseUrl": 123}),
        ] {
            assert!(
                parse_standalone(body(json!({"memory": bad})).as_ref()).is_err(),
                "{bad}"
            );
        }
        assert!(parse_standalone(None).is_err());
    }

    #[tokio::test]
    async fn the_helper_gets_the_key_and_its_base_url_on_stdin() {
        let runner = cc_proc::RecordingRunner::new();
        runner.answer(&["sudo"], cc_proc::ok("changed\n"));
        let own = BrainKey::Own {
            key: "vck-cc-0123456789abcdef01234567".into(),
            base_url: "https://ai-gateway.vercel.sh/v1".into(),
        };
        assert_eq!(apply(&own, &runner).await, Ok(true));
        let call = &runner.calls()[0];
        assert_eq!(call.args, vec![HELPER.to_string()]);
        assert_eq!(
            call.stdin.as_deref(),
            Some(&b"vck-cc-0123456789abcdef01234567 https://ai-gateway.vercel.sh/v1\n"[..])
        );
    }
}
