//! Telegram and Slack bots, as the SaaS's `channels.*` procedures do them: add a bot (its token goes
//! to the firewall in a `channels.propose` and is kept only there), replace its token, move it to
//! another agent, approve a pairing code, remove it. Applied at once for the signed-in admin. The
//! list is the firewall's own (`channels.read`), so it is right whatever happened to a change: an
//! assignment the firewall kept although the agent could not be reached, say.

use http::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, agent_ref, checked, data_of, new_id};

const TAG: &str = "channels";

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), ChannelsView, _, _>(
            "/api/channels",
            TAG,
            "The bots, and who may get confirmation codes for agents' requests",
            |c| async move { Ok(Reply::ok(&view(&c).await?)) },
        ),
        Route::write::<NewChannel, ChannelChange, _, _>(
            Method::POST,
            "/api/channels",
            TAG,
            "Add a Telegram or Slack bot",
            |c, b| async move { add(&c, b).await },
        ),
        Route::write::<NewToken, ChannelChange, _, _>(
            Method::PUT,
            "/api/channels/:id/token",
            TAG,
            "Replace a bot's token",
            |c, b| async move { replace(&c, b).await },
        ),
        Route::write::<Assign, ChannelChange, _, _>(
            Method::POST,
            "/api/channels/:id/assign",
            TAG,
            "Give the bot to an agent (from the one it had)",
            |c, b| async move { assign(&c, Some(&b.vm_id)).await },
        ),
        Route::write::<super::NoBody, ChannelChange, _, _>(
            Method::POST,
            "/api/channels/:id/unassign",
            TAG,
            "Take the bot from its agent",
            |c, _| async move { assign(&c, None).await },
        ),
        Route::write::<Pairing, ChannelChange, _, _>(
            Method::POST,
            "/api/channels/:id/pairing",
            TAG,
            "Approve a pairing code a person got from the bot",
            |c, b| async move { pairing(&c, b).await },
        ),
        Route::write::<super::NoBody, ChannelChange, _, _>(
            Method::DELETE,
            "/api/channels/:id",
            TAG,
            "Remove a bot; `?force=true` removes it even when its agent cannot be told (an agent that is gone)",
            |c, _| async move { remove(&c).await },
        )
        .with_query::<RemoveQuery>(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChannelType {
    Telegram,
    Slack,
}

impl ChannelType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Telegram => "telegram",
            Self::Slack => "slack",
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub id: String,
    /// `telegram` or `slack`.
    pub r#type: String,
    pub label: Option<String>,
    /// The token's last four characters.
    pub hint: String,
    pub vm_id: Option<String>,
    pub agent_name: Option<String>,
    /// People approved to talk to it.
    pub approved_senders: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChannelsView {
    pub channels: Vec<Channel>,
    /// The firewall's own account of who gets codes (`code_recipients`): approved and allowed senders.
    pub code_recipients: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewChannel {
    pub r#type: ChannelType,
    pub bot_token: String,
    /// Slack only: the app-level token (socket mode).
    #[serde(default)]
    pub app_token: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// The agent it answers for; none yet when left out.
    #[serde(default)]
    pub vm_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewToken {
    pub bot_token: String,
    #[serde(default)]
    pub app_token: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assign {
    pub vm_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pairing {
    /// The code the bot sent the person (4 to 16 characters).
    pub code: String,
    /// The person's id on the channel.
    pub sender_id: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ChannelChange {
    pub result: CommandAnswer,
    pub channels: Vec<Channel>,
}

struct Row {
    id: String,
    kind: String,
    label: Option<String>,
    hint: String,
    vm_id: Option<String>,
}

/// The firewall's connections, with the agents' names.
async fn list(c: &Ctx) -> Result<Vec<Channel>> {
    let data = data_of(c.command("channels.read", json!({})).await?)?;
    let names: std::collections::HashMap<String, String> = super::agent_refs(&c.db)?
        .into_iter()
        .filter_map(|a| Some((a["vmId"].as_str()?.to_string(), a["name"].as_str()?.to_string())))
        .collect();
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let list: Vec<Channel> = data
        .get("connections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|x| {
            let vm = s(x, "assignedVmId");
            Channel {
                id: s(x, "id").unwrap_or_default(),
                r#type: s(x, "type").unwrap_or_default(),
                label: s(x, "label"),
                hint: s(x, "hint").unwrap_or_default(),
                agent_name: vm.as_ref().and_then(|v| names.get(v).cloned()),
                vm_id: vm,
                approved_senders: x.get("approvedSenders").and_then(Value::as_i64).unwrap_or(0),
            }
        })
        .collect();
    seen(c, &list)?;
    Ok(list)
}

/// Read the bots and keep their agents for the channel rules.
pub async fn refresh(c: &Ctx) -> Result<()> {
    list(c).await.map(|_| ())
}

/// Keep the bots that have an agent, for their rules (`api::managed`).
fn seen(c: &Ctx, list: &[Channel]) -> Result<()> {
    super::managed::store(
        c,
        "channels",
        list.iter()
            .filter_map(|x| Some(json!({"type": x.r#type, "vmId": x.vm_id.as_deref()?})))
            .collect(),
    )
}

async fn view(c: &Ctx) -> Result<ChannelsView> {
    Ok(ChannelsView {
        channels: list(c).await?,
        code_recipients: (c.hooks.status)().remove("code_recipients").unwrap_or(Value::Null),
    })
}

async fn row(c: &Ctx, id: &str) -> Result<Row> {
    list(c)
        .await?
        .into_iter()
        .find(|x| x.id == id)
        .map(|x| Row {
            id: x.id,
            kind: x.r#type,
            label: x.label,
            hint: x.hint,
            vm_id: x.vm_id,
        })
        .ok_or_else(|| Reply::not_found("Channel"))
}

fn hint(token: &str) -> String {
    let tail: Vec<char> = token.chars().rev().take(4).collect();
    format!("…{}", tail.into_iter().rev().collect::<String>())
}

/// The `channels.propose` payload, as the SaaS's `proposalPayload` makes it.
fn payload(kind: &str, r: &Row, agent: Option<Value>) -> Map<String, Value> {
    let v = json!({
        "changeId": new_id("chg"),
        "kind": kind,
        "connectionId": r.id,
        "type": r.kind,
        "hint": r.hint,
        "label": r.label,
        "agent": agent,
    });
    v.as_object().cloned().unwrap_or_default()
}

/// Bot changes one at a time: an agent has one bot of a type, checked before and kept after.
static CHANGES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Propose and confirm at once.
async fn apply(c: &Ctx, p: Map<String, Value>) -> Result<CommandAnswer> {
    let p = checked("channels.propose", Value::Object(p))?;
    c.apply("channels", p).await
}

/// The answer, and the list as the firewall holds it now.
async fn reply(c: &Ctx, result: CommandAnswer) -> Result {
    Ok(Reply {
        status: if result.ok { 200 } else { 409 },
        body: serde_json::to_value(ChannelChange {
            result,
            channels: list(c).await?,
        })
        .unwrap_or(Value::Null),
    })
}

fn tokens(kind: &str, bot: &str, app: Option<&str>) -> Result<Value> {
    let bot = bot.trim();
    if bot.len() < 8 {
        return Err(Reply::bad("botToken: the bot's token"));
    }
    let app = app.map(str::trim).filter(|a| !a.is_empty());
    if kind == "slack" && app.is_none() {
        return Err(Reply::bad("Slack needs both a bot token and an app-level token."));
    }
    let mut s = json!({"botToken": bot});
    if let Some(a) = app {
        s["appToken"] = json!(a);
    }
    Ok(s)
}

/// An agent has one bot of a type.
async fn type_free(c: &Ctx, vm: &str, kind: &str, except: Option<&str>) -> Result<()> {
    let taken = list(c)
        .await?
        .into_iter()
        .any(|x| x.vm_id.as_deref() == Some(vm) && x.r#type == kind && Some(x.id.as_str()) != except);
    if taken {
        return Err(Reply::error(409, format!("That agent has a {kind} bot already.")));
    }
    Ok(())
}

async fn add(c: &Ctx, b: NewChannel) -> Result {
    let _one = CHANGES.lock().await;
    let kind = b.r#type.as_str();
    let secret = tokens(kind, &b.bot_token, b.app_token.as_deref())?;
    let agent = match &b.vm_id {
        Some(v) => {
            type_free(c, v, kind, None).await?;
            Some(agent_ref(&c.db, v)?)
        }
        None => None,
    };
    let r = Row {
        id: new_id("ch"),
        kind: kind.into(),
        label: b.label.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()),
        hint: hint(b.bot_token.trim()),
        vm_id: b.vm_id.clone(),
    };
    let mut p = payload("add", &r, agent);
    p.insert("secret".into(), secret);
    let result = apply(c, p).await?;
    reply(c, result).await
}

async fn replace(c: &Ctx, b: NewToken) -> Result {
    let _one = CHANGES.lock().await;
    let mut r = row(c, c.param("id")).await?;
    let secret = tokens(&r.kind, &b.bot_token, b.app_token.as_deref())?;
    r.hint = hint(b.bot_token.trim());
    if let Some(l) = b.label.map(|l| l.trim().to_string()).filter(|l| !l.is_empty()) {
        r.label = Some(l);
    }
    let agent = r.vm_id.as_deref().map(|v| agent_ref(&c.db, v)).transpose()?;
    let mut p = payload("replace", &r, agent);
    p.insert("secret".into(), secret);
    let result = apply(c, p).await?;
    reply(c, result).await
}

async fn assign(c: &Ctx, to: Option<&str>) -> Result {
    let _one = CHANGES.lock().await;
    let r = row(c, c.param("id")).await?;
    let (kind, agent, from) = match to {
        Some(v) => {
            type_free(c, v, &r.kind, Some(&r.id)).await?;
            let from = r
                .vm_id
                .as_deref()
                .filter(|f| *f != v)
                .and_then(|f| agent_ref(&c.db, f).ok());
            ("assign", agent_ref(&c.db, v)?, from)
        }
        None => {
            let Some(v) = r.vm_id.as_deref() else {
                return Err(Reply::bad("This bot has no agent."));
            };
            // An agent unpaired since is still named, so its bot can be taken back.
            (
                "unassign",
                agent_ref(&c.db, v).unwrap_or_else(|_| json!({"vmId": v})),
                None,
            )
        }
    };
    let mut p = payload(kind, &r, Some(agent));
    if let Some(f) = from {
        p.insert("from".into(), json!({"vmId": f["vmId"], "hostname": f["hostname"]}));
    }
    let result = apply(c, p).await?;
    reply(c, result).await
}

async fn pairing(c: &Ctx, b: Pairing) -> Result {
    let _one = CHANGES.lock().await;
    let r = row(c, c.param("id")).await?;
    let code = b.code.trim();
    if !(4..=16).contains(&code.len()) {
        return Err(Reply::bad("code: 4 to 16 characters"));
    }
    let Some(vm) = r.vm_id.as_deref() else {
        return Err(Reply::bad("Give the bot to an agent first."));
    };
    let mut p = payload("approve_pairing", &r, Some(agent_ref(&c.db, vm)?));
    p.insert(
        "pairing".into(),
        json!({"code": code, "senderId": b.sender_id.trim(), "label": b.label}),
    );
    let result = apply(c, p).await?;
    reply(c, result).await
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct RemoveQuery {
    /// Remove it even when its agent cannot be told. The agent keeps a stand-in that no longer works.
    #[serde(default)]
    pub force: Option<bool>,
}

async fn remove(c: &Ctx) -> Result {
    let q: RemoveQuery = c.query()?;
    let _one = CHANGES.lock().await;
    let r = row(c, c.param("id")).await?;
    let agent = r.vm_id.as_deref().and_then(|v| agent_ref(&c.db, v).ok());
    let mut p = payload("remove", &r, agent);
    if q.force == Some(true) {
        p.insert("force".into(), json!(true));
    }
    let result = apply(c, p).await?;
    reply(c, result).await
}
