//! Which MCP app asked for a command, while it is handled (`requested-via.ts`). A task-local, as
//! the TS keeps it in `AsyncLocalStorage`.
//!
//! Also whether the command came from a standalone firewall's signed-in admin (`cc-local`'s API):
//! the control plane and the firewall are then one trust domain, so no code is sent to a person
//! (`Consent::send` puts it in this task's slot instead, which only the local API reads).

use std::future::Future;

use serde_json::{Map, Value};

tokio::task_local! {
    static VIA: Option<String>;
    /// The code of the change the admin's command proposed, for the local API to confirm with.
    static LOCAL_ADMIN: std::cell::RefCell<Option<String>>;
}

/// `cleanClientName`: letters, digits, spaces and `._-`, one line, at most 40 characters.
pub fn clean_client_name(value: &Value) -> Option<String> {
    let s = value.as_str()?;
    let spaced = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let kept: String = spaced
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
        .collect();
    let squeezed = kept.split(' ').filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" ");
    let clean: String = squeezed.chars().take(40).collect::<String>().trim().to_string();
    (!clean.is_empty()).then_some(clean)
}

/// The app's name for a payload whose `requestedVia.kind` is `mcp`; `None` otherwise.
pub fn from_payload(payload: &Map<String, Value>) -> Option<String> {
    let via = payload.get("requestedVia")?.as_object()?;
    if via.get("kind")?.as_str()? != "mcp" {
        return None;
    }
    Some(
        via.get("client")
            .and_then(clean_client_name)
            .unwrap_or_else(|| "an MCP app".to_string()),
    )
}

pub async fn scope<F: Future>(via: Option<String>, f: F) -> F::Output {
    VIA.scope(via, f).await
}

/// Run `f` as the standalone firewall's signed-in admin: its answer, and the code a change it
/// proposed is held for (never sent to anyone, never logged).
pub async fn as_local_admin<F: Future>(f: F) -> (F::Output, Option<String>) {
    LOCAL_ADMIN
        .scope(std::cell::RefCell::new(None), async {
            let out = f.await;
            (out, LOCAL_ADMIN.with(|c| c.borrow_mut().take()))
        })
        .await
}

/// The command being handled came from the local admin API (never in SaaS mode).
pub fn local_admin() -> bool {
    LOCAL_ADMIN.try_with(|_| ()).is_ok()
}

/// Keep the code for the admin's API; false outside its scope.
pub fn hand_code_to_admin(code: &str) -> bool {
    LOCAL_ADMIN
        .try_with(|c| *c.borrow_mut() = Some(code.to_string()))
        .is_ok()
}

/// The one route the admin's commands see (`ChannelsFirewall::code_routes_status`): somebody to
/// ask, so a module that refuses with nobody to send a code to goes on to `Consent::send`.
pub fn admin_route() -> Value {
    serde_json::json!({
        "target": {"vmId": "local-admin", "hostname": "local-admin"},
        "senders": [{"type": "local-admin", "id": "admin", "label": "the signed-in admin"}],
        "agentName": "this firewall",
    })
}

/// `currentRequestedVia`, for the handlers W4 and W5 port.
#[allow(dead_code)]
pub fn current() -> Option<String> {
    VIA.try_with(Clone::clone).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names() {
        assert_eq!(
            clean_client_name(&json!("  Claude\n  Desktop <x>  ")).as_deref(),
            Some("Claude Desktop x")
        );
        assert_eq!(clean_client_name(&json!("<>")), None);
        let p = json!({"requestedVia": {"kind": "mcp"}});
        assert_eq!(from_payload(p.as_object().expect("obj")).as_deref(), Some("an MCP app"));
        let p = json!({"requestedVia": {"kind": "console", "client": "x"}});
        assert_eq!(from_payload(p.as_object().expect("obj")), None);
    }

    #[tokio::test]
    async fn scoped() {
        assert_eq!(current(), None);
        assert_eq!(
            scope(Some("App".into()), async { current() }).await.as_deref(),
            Some("App")
        );
        assert!(!local_admin());
        assert!(!hand_code_to_admin("1"));
        let (inside, code) = as_local_admin(async { (local_admin(), hand_code_to_admin("123456")) }).await;
        assert_eq!((inside, code.as_deref()), ((true, true), Some("123456")));
    }
}
