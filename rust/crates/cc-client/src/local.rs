//! `local:` addresses: a control plane in this process (a standalone firewall's `cc-local`) instead
//! of one across the network. Every client here answers a `local:` URL with the handler set at
//! start, unsigned, and an `http` URL as before; nothing else changes for its callers.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use serde_json::Value;

/// `(method, url, body)` to `(status, body)`.
pub type LocalHandler =
    Arc<dyn Fn(&str, &str, Option<Value>) -> Pin<Box<dyn Future<Output = (u16, Value)> + Send>> + Send + Sync>;

static HANDLER: OnceLock<LocalHandler> = OnceLock::new();

/// Answer `local:` URLs with `h` from now on (once, at start).
pub fn set_handler(h: LocalHandler) {
    let _ = HANDLER.set(h);
}

pub fn is_local(url: &str) -> bool {
    url.starts_with("local:")
}

/// The in-process answer for a `local:` URL; `None` for any other URL. With no handler set the
/// answer is a 503, as an unreachable control plane would give.
pub async fn call(method: &str, url: &str, body: Option<&Value>) -> Option<(u16, Value)> {
    if !is_local(url) {
        return None;
    }
    Some(match HANDLER.get() {
        Some(h) => h(method, url, body.cloned()).await,
        None => (503, serde_json::json!({"error": "no local control plane"})),
    })
}
