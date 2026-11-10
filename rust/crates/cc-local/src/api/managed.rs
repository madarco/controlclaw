//! What the channel rules are made from (`plane::managed_rules`): the bots, AgentMail inboxes and
//! Google grants the firewall holds, each read from its module (`channels.read`, `agentmail.read`,
//! `google.read`) and kept as `[{type, vmId}]` under `managed_seen:<part>`. Kept whenever a page
//! reads them or a change is made here, at start and every few minutes after; a part that changes
//! starts a sync of the rules.

use serde_json::{Value, json};

use super::{Ctx, Result, data_of};

pub const SEEN_PREFIX: &str = "managed_seen:";

/// Keep one part's list; a change wakes the sync.
pub fn store(c: &Ctx, part: &str, mut seen: Vec<Value>) -> Result<()> {
    seen.sort_by_key(Value::to_string);
    seen.dedup();
    let now = Value::Array(seen).to_string();
    let key = format!("{SEEN_PREFIX}{part}");
    if c.db.setting(&key).as_deref() != Some(now.as_str()) {
        c.db.set_setting(&key, &now)?;
        (c.hooks.rules_changed)();
    }
    Ok(())
}

fn entry(kind: &str, vm: Option<&str>) -> Option<Value> {
    Some(json!({"type": kind, "vmId": vm.filter(|v| !v.is_empty())?}))
}

/// `agentmail.read`'s inboxes that are on an agent.
pub fn agentmail(data: &Value) -> Vec<Value> {
    data.get("inboxes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|i| entry("agentmail", i.get("vmId").and_then(Value::as_str)))
        .collect()
}

/// `google.read`'s agents with the account, when it is connected and Gmail is one of its services.
pub fn google(data: &Value) -> Vec<Value> {
    let account = data.get("account").unwrap_or(&Value::Null);
    let gmail = account.get("connected").and_then(Value::as_bool) == Some(true)
        && account
            .get("services")
            .and_then(Value::as_array)
            .is_some_and(|s| s.iter().any(|v| v == "gmail"));
    if !gmail {
        return Vec::new();
    }
    data.get("agents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("granted").and_then(Value::as_bool) == Some(true))
        .filter_map(|a| entry("gmail", a.get("vmId").and_then(Value::as_str)))
        .collect()
}

/// One module's list, or none when the module does not run on this firewall (404).
async fn read(c: &Ctx, action: &str) -> Result<Option<Value>> {
    match c.command(action, json!({})).await {
        Ok(a) => data_of(a).map(Some),
        Err(e) if e.status == 404 => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read AgentMail and Google again (after a change to either).
pub async fn refresh_accounts(c: &Ctx) -> Result<()> {
    if let Some(mail) = read(c, "agentmail.read").await? {
        store(c, "agentmail", agentmail(&mail))?;
    }
    if let Some(g) = read(c, "google.read").await? {
        store(c, "gmail", google(&g))?;
    }
    Ok(())
}

/// Read everything: the bots, then the accounts. Each part that answers is kept.
pub async fn refresh_all(c: &Ctx) -> Result<()> {
    let bots = super::channels::refresh(c).await;
    let accounts = refresh_accounts(c).await;
    bots.and(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inboxes_and_grants_on_an_agent() {
        assert_eq!(
            agentmail(&json!({"inboxes": [{"inboxId": "a@x", "vmId": "a1"}, {"inboxId": "b@x", "vmId": null}]})),
            vec![json!({"type": "agentmail", "vmId": "a1"})]
        );
        let g = |connected: bool, services: Value| {
            google(&json!({
                "account": {"connected": connected, "services": services},
                "agents": [{"vmId": "a1", "granted": true}, {"vmId": "a2", "granted": false}],
            }))
        };
        assert_eq!(
            g(true, json!(["gmail", "calendar"])),
            vec![json!({"type": "gmail", "vmId": "a1"})]
        );
        assert!(g(true, json!(["calendar"])).is_empty(), "no Gmail, no rule");
        assert!(g(false, json!(["gmail"])).is_empty(), "not connected");
        assert!(google(&json!({"account": null, "agents": []})).is_empty());
    }
}
