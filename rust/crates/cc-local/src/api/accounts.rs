//! Google, AgentMail and website logins, as the SaaS's `google.*`, `agentmail.*` and `logins.*`
//! procedures do them. All three keep their state on the firewall: a read is the module's own
//! (`google.read`, `agentmail.read`, `logins.read`). Changes are applied at once for the signed-in
//! admin. A Google connection is your own OAuth client; the sign-in comes back to the panel's
//! `/oauth/callback` and finishes through `POST /api/oauth/callback`. AgentMail takes no codes. A
//! login's password is never sent here: it is typed on the firewall's own Logins page
//! (`POST /api/open {page: logins}`).

use http::Method;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, agent_ref, checked, data_of, new_id};

const TAG: &str = "accounts";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), Value, _, _>(
            "/api/google",
            TAG,
            "The Google account, its services and the agents that have it (`google.read`), and the redirect address to register",
            |c| async move {
                let mut v = data_of(c.command("google.read", json!({})).await?)?;
                super::managed::store(&c, "gmail", super::managed::google(&v))?;
                if let Value::Object(m) = &mut v {
                    let uri = redirect_uri();
                    let ok = google_takes(&uri);
                    m.insert("redirectOk".into(), json!(ok));
                    if !ok {
                        m.insert("redirectProblem".into(), json!(REDIRECT_PROBLEM));
                    }
                    m.insert("redirectUri".into(), json!(uri));
                }
                Ok(Reply::ok(&v))
            },
        ),
        Route::write::<GoogleConnect, CommandAnswer, _, _>(
            Method::POST,
            "/api/google",
            TAG,
            "Connect your Google OAuth client (or replace it): the answer's data has the address to send the browser to",
            |c, b| async move { google_connect(&c, b).await },
        ),
        Route::write::<GoogleGrant, CommandAnswer, _, _>(
            Method::POST,
            "/api/google/agents/:vmId",
            TAG,
            "Give an agent the Google account, or take it away (`granted: false`)",
            |c, b| async move {
                let kind = if b.granted { "grant_agent" } else { "revoke_agent" };
                let agent = agent_ref(&c.db, c.param("vmId"))?;
                google_apply(&c, kind, |p| {
                    p.insert("agents".into(), json!([agent]));
                })
                .await
            },
        ),
        Route::write::<GoogleServices, CommandAnswer, _, _>(
            Method::PUT,
            "/api/google/services",
            TAG,
            "Change which Google services the agents may use",
            |c, b| async move {
                let services = services(&b.services)?;
                google_apply(&c, "set_services", |p| {
                    p.insert("services".into(), json!(services));
                    p.insert("agents".into(), json!([]));
                })
                .await
            },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::DELETE,
            "/api/google",
            TAG,
            "Forget the Google account: every agent loses it",
            |c, _| async move {
                google_apply(&c, "forget_account", |p| {
                    p.insert("agents".into(), json!([]));
                })
                .await
            },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/google/agents/:vmId/push",
            TAG,
            "Write the account to an agent again",
            |c, _| async move {
                let a = agent_ref(&c.db, c.param("vmId"))?;
                let p = checked(
                    "google.push",
                    json!({"vmId": a["vmId"], "hostname": a["hostname"], "name": a["name"]}),
                )?;
                Ok(c.command("google.push", Value::Object(p)).await?.reply())
            },
        ),
        Route::get::<(), Value, _, _>(
            "/api/agentmail",
            TAG,
            "The AgentMail account and its inboxes (`agentmail.read`)",
            |c| async move {
                let v = data_of(c.command("agentmail.read", json!({})).await?)?;
                super::managed::store(&c, "agentmail", super::managed::agentmail(&v))?;
                Ok(Reply::ok(&v))
            },
        ),
        Route::write::<Value, CommandAnswer, _, _>(
            Method::POST,
            "/api/agentmail/:action",
            TAG,
            "An AgentMail action: signup, claim, check, create, import, attach, senders, forget, delete, push. The body is the action's (`cc-contracts` agentmail); `vmId` is filled in with the agent's name and address.",
            |c, b| async move { agentmail(&c, b).await },
        ),
        Route::get::<(), Value, _, _>(
            "/api/logins",
            TAG,
            "The website logins, never their passwords (`logins.read`), and the 1Password link",
            |c| async move { Ok(Reply::ok(&data_of(c.command("logins.read", json!({})).await?)?)) },
        ),
        Route::write::<LoginChange, CommandAnswer, _, _>(
            Method::POST,
            "/api/logins/change",
            TAG,
            "Change a login's name, sites, agents or mode (`action: update`), or delete it (`action: delete`)",
            |c, b| async move { login_change(&c, b).await },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/logins/1password/sync",
            TAG,
            "Read the logins from 1Password again",
            |c, _| async move { Ok(c.command("logins.1password_sync", json!({})).await?.reply()) },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::POST,
            "/api/logins/1password/disconnect",
            TAG,
            "Disconnect 1Password",
            |c, _| async move { Ok(c.command("logins.1password_disconnect", json!({})).await?.reply()) },
        ),
    ]
}

/// The services a Google connection can give (the SaaS's `GOOGLE_SERVICES`).
const SERVICES: &[&str] = &["gmail", "calendar", "drive", "contacts", "sheets", "docs"];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleConnect {
    /// `….apps.googleusercontent.com`
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub project_id: Option<String>,
    /// `gmail`, `calendar`, `drive`, `contacts`, `sheets`, `docs`.
    pub services: Vec<String>,
    /// `full`, `readonly`, `send` or `read-send`; `read-send` when left out.
    #[serde(default)]
    pub gmail_scope: Option<String>,
    /// `full`, `readonly` or `file`.
    #[serde(default)]
    pub drive_scope: Option<String>,
    /// `internal`, `external_production` or `external_testing`.
    pub audience: String,
    /// The agents that get it once it is connected.
    #[serde(default)]
    pub vm_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoogleGrant {
    pub granted: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoogleServices {
    pub services: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginChange {
    /// `update` or `delete`.
    pub action: String,
    /// The login's id (`lg_…`).
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// The sites it may be used on.
    #[serde(default)]
    pub sites: Option<Vec<String>>,
    /// The agents that may use it.
    #[serde(default)]
    pub vm_ids: Option<Vec<String>>,
    /// `swap` (the proxy puts the password in) or `type` (the firewall types it into the page).
    #[serde(default)]
    pub mode: Option<String>,
}

/// What a panel address Google refuses gets told.
const REDIRECT_PROBLEM: &str = "Google sends a sign-in back only to an https:// address, or to http://localhost. Open the panel through an SSH tunnel to localhost, or set LOCAL_PANEL_URL to its https:// address.";

/// Google takes a redirect on `https://`, or plain `http://` on localhost (and loopback addresses).
pub(crate) fn google_takes(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|u| match u.scheme() {
        "https" => true,
        "http" => matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    })
}

/// Where Google sends the browser back: the panel's own page.
fn redirect_uri() -> String {
    format!("{}/oauth/callback", crate::panel_origin())
}

fn services(list: &[String]) -> Result<Vec<String>> {
    if list.is_empty() || list.iter().any(|s| !SERVICES.contains(&s.as_str())) {
        return Err(Reply::bad(format!("services: some of {}", SERVICES.join(", "))));
    }
    Ok(list.to_vec())
}

fn one_of(name: &str, v: &str, of: &[&str]) -> Result<()> {
    if of.contains(&v) {
        Ok(())
    } else {
        Err(Reply::bad(format!("{name}: one of {}", of.join(", "))))
    }
}

async fn google_apply(c: &Ctx, kind: &str, fill: impl FnOnce(&mut Map<String, Value>)) -> Result {
    let mut p = Map::new();
    p.insert("changeId".into(), json!(new_id("chg")));
    p.insert("kind".into(), json!(kind));
    fill(&mut p);
    let p = checked("google.propose", Value::Object(p))?;
    let r = c.apply("google", p).await?;
    accounts_changed(c).await;
    Ok(r.reply())
}

/// After a change to Google or AgentMail: their agents' rules as the firewall now has them. A read
/// that fails leaves them for the next one (`api::managed`).
async fn accounts_changed(c: &Ctx) {
    if let Err(e) = super::managed::refresh_accounts(c).await {
        tracing::warn!("[cc-local] the accounts' rules: {}", e.body);
    }
}

async fn google_connect(c: &Ctx, b: GoogleConnect) -> Result {
    let id = b.client_id.trim();
    if !id.ends_with(".apps.googleusercontent.com") {
        return Err(Reply::bad(
            "clientId: an OAuth client id (….apps.googleusercontent.com)",
        ));
    }
    if b.client_secret.trim().is_empty() {
        return Err(Reply::bad("clientSecret: the OAuth client's secret"));
    }
    if !google_takes(&redirect_uri()) {
        return Err(Reply::bad(REDIRECT_PROBLEM));
    }
    let services = services(&b.services)?;
    let gmail = b.gmail_scope.unwrap_or_else(|| "read-send".into());
    one_of("gmailScope", &gmail, &["full", "readonly", "send", "read-send"])?;
    if let Some(d) = &b.drive_scope {
        one_of("driveScope", d, &["full", "readonly", "file"])?;
    }
    one_of(
        "audience",
        &b.audience,
        &["internal", "external_production", "external_testing"],
    )?;
    let all = super::agent_refs(&c.db)?;
    let agents: Vec<Value> = b
        .vm_ids
        .iter()
        .map(|v| {
            all.iter()
                .find(|a| a["vmId"] == v.as_str())
                .cloned()
                .ok_or_else(|| Reply::not_found("Agent"))
        })
        .collect::<Result<_>>()?;
    // Replace when an account is there already: the firewall's own read says.
    let had = data_of(c.command("google.read", json!({})).await?)?
        .get("account")
        .is_some_and(|a| !a.is_null());
    google_apply(c, if had { "replace_account" } else { "connect_account" }, |p| {
        p.insert("client".into(), json!({"clientId": id, "redirectUri": redirect_uri()}));
        p.insert("clientSecret".into(), json!(b.client_secret.trim()));
        p.insert("services".into(), json!(services));
        p.insert("gmailScope".into(), json!(gmail));
        p.insert("driveScope".into(), json!(b.drive_scope));
        p.insert("audience".into(), json!(b.audience));
        p.insert("projectId".into(), json!(b.project_id));
        p.insert("agents".into(), json!(agents));
    })
    .await
}

/// The SaaS's `agentmail.change`: the action from the path, its body as `cc-contracts` types it.
/// An agent named by `vmId` gets its address and name from the agents here.
/// An inbox is written to the agent itself, at the address this firewall paired it at: never one a
/// request names. Any `hostname` sent is dropped; for signup, create and attach the paired agent's is
/// set, and an agent with none is refused. `name` stays the caller's (the inbox's own display name).
/// Also what `/api/commands` runs for `agentmail.*`.
pub fn agentmail_address(c: &Ctx, action: &str, p: &mut Map<String, Value>) -> Result<()> {
    p.remove("hostname");
    let Some(vm) = p.get("vmId").and_then(Value::as_str).map(str::to_string) else {
        return Ok(());
    };
    // Only an agent this firewall knows, whatever the action.
    let a = agent_ref(&c.db, &vm)?;
    if !matches!(action, "signup" | "create" | "attach") {
        return Ok(());
    }
    let Some(h) = a["hostname"].as_str().filter(|h| !h.is_empty()) else {
        return Err(Reply::bad("This agent has no address yet: pair it first."));
    };
    p.insert("hostname".into(), json!(h));
    Ok(())
}

async fn agentmail(c: &Ctx, body: Value) -> Result {
    const ACTIONS: &[&str] = &[
        "signup", "claim", "check", "create", "import", "attach", "senders", "forget", "delete", "push",
    ];
    let action = c.param("action");
    if !ACTIONS.contains(&action) {
        return Err(Reply::not_found("AgentMail action"));
    }
    let mut p = match body {
        Value::Object(m) => m,
        Value::Null => Map::new(),
        _ => return Err(Reply::bad("body: an object")),
    };
    agentmail_address(c, action, &mut p)?;
    p.entry("changeId").or_insert_with(|| json!(new_id("chg")));
    let full = format!("agentmail.{action}");
    let p = checked(&full, Value::Object(p))?;
    let r = c.run(&full, Value::Object(p)).await?;
    accounts_changed(c).await;
    Ok(r.reply())
}

async fn login_change(c: &Ctx, b: LoginChange) -> Result {
    one_of("action", &b.action, &["update", "delete"])?;
    if !b.id.starts_with("lg_") {
        return Err(Reply::bad("id: a login's id (lg_…)"));
    }
    if let Some(m) = &b.mode {
        one_of("mode", m, &["swap", "type"])?;
    }
    if let Some(v) = &b.vm_ids {
        let all = super::agent_refs(&c.db)?;
        if v.iter().any(|id| !all.iter().any(|a| a["vmId"] == id.as_str())) {
            return Err(Reply::not_found("Agent"));
        }
    }
    let mut p = Map::new();
    p.insert("changeId".into(), json!(new_id("chg")));
    p.insert("id".into(), json!(b.id));
    p.insert("action".into(), json!(b.action));
    for (k, v) in [
        ("name", json!(b.name)),
        ("sites", json!(b.sites)),
        ("vmIds", json!(b.vm_ids)),
        ("mode", json!(b.mode)),
    ] {
        if !v.is_null() {
            p.insert(k.into(), v);
        }
    }
    let p = checked("logins.propose", Value::Object(p))?;
    let mut with = Map::new();
    with.insert("id".into(), json!(b.id));
    Ok(c.apply_as("logins.propose", "logins.confirm", p, with).await?.reply())
}
