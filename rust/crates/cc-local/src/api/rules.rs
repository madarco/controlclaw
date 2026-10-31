//! Security rules: content rules (messages), app rules (integrations and MCP servers) and email
//! rules, as the SaaS's `contentRules.*`, `appRules.*` and `emailRules.*` do them. They live on the
//! firewall: a read is the module's `<ns>.read`, a change its `<ns>.propose`, applied at once for
//! the signed-in admin ([`Ctx::apply`]). The shapes are the firewall's own: `change` is checked
//! against `cc-contracts` (`rules::Change`, `apps::Change`, `email::Change`).

use http::Method;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, checked, data_of};

const TAG: &str = "rules";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), Value, _, _>(
            "/api/content-rules",
            TAG,
            "The content rules, the always-on ones, held messages and the AI's state (`rules.read`), and whether the AI review is on",
            |c| async move {
                let mut v = data_of(c.command("rules.read", json!({})).await?)?;
                let ai_on = super::egress::ai_checks_on(&c.db);
                if let Value::Object(m) = &mut v {
                    m.insert("aiOn".into(), json!(ai_on));
                }
                Ok(Reply::ok(&v))
            },
        ),
        Route::write::<ChangeBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/content-rules/change",
            TAG,
            "Add or change a content rule (`{op: put, rule}`), delete one (`{op: delete, id}`), or take the AI's current state (`{op: ai}`)",
            |c, b| async move { change(&c, "rules", b.change).await },
        ),
        Route::write::<TryBody, Value, _, _>(
            Method::POST,
            "/api/content-rules/try",
            TAG,
            "Which rule would act on a message (`rules.try`); nothing is kept",
            |c, b| async move {
                let p = checked("rules.try", serde_json::to_value(b).unwrap_or_default())?;
                Ok(Reply::ok(&data_of(c.command("rules.try", Value::Object(p)).await?)?))
            },
        ),
        Route::get::<(), Value, _, _>("/api/app-rules", TAG, "The app rules (`apps.read`)", |c| async move {
            Ok(Reply::ok(&data_of(c.command("apps.read", json!({})).await?)?))
        }),
        Route::write::<ChangeBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/app-rules/change",
            TAG,
            "Add or change an app rule (`{op: put, rule, at?}`), delete one (`{op: delete, id}`), or move one (`{op: move, id, to}`)",
            |c, b| async move { change(&c, "apps", b.change).await },
        ),
        Route::get::<(), Value, _, _>(
            "/api/app-rules/mcp",
            TAG,
            "The MCP servers an app rule can name (`mcpcatalog.read`)",
            |c| async move { Ok(Reply::ok(&data_of(c.command("mcpcatalog.read", json!({})).await?)?)) },
        ),
        Route::get::<(), Value, _, _>(
            "/api/email-rules",
            TAG,
            "Who may email the agents and whom they may email, and held mail (`email.read`)",
            |c| async move { Ok(Reply::ok(&data_of(c.command("email.read", json!({})).await?)?)) },
        ),
        Route::write::<ChangeBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/email-rules/change",
            TAG,
            "Change the email rules: `{action: add_sender | remove_sender | add_recipient | remove_recipient, entry}`, `{action: set_inbound_auth, requireAuth}`, `{action: set_outbound, ...}`, `{action: set_mailbox_mode, mailbox, mode}`",
            |c, b| async move { change(&c, "email", b.change).await },
        ),
    ]
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeBody {
    /// The module's change, as `cc-contracts` types it.
    pub change: Value,
}

#[derive(Debug, Deserialize, serde::Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TryBody {
    /// At most 20,000 characters.
    pub text: String,
    /// `in` or `out`.
    pub direction: String,
    /// `telegram`, `slack`, `email`, `web`, `webhook`, `teamchat`, `voice` or `apps`.
    pub channel: String,
    /// The rule being edited, tried as if saved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<Value>,
}

async fn change(c: &Ctx, ns: &str, change: Value) -> Result {
    let mut p = Map::new();
    p.insert("changeId".into(), json!(super::new_id("chg")));
    p.insert("change".into(), change);
    let p = checked(&format!("{ns}.propose"), Value::Object(p))?;
    Ok(c.apply(ns, p).await?.reply())
}
