//! The few ClickClack HTTP calls the firewall makes (`teamchat-api.ts`), on loopback
//! (`127.0.0.1:3931`), as the workspace's system owner ("ControlClaw"). A fixed list of named
//! methods: nothing a command payload carries ever becomes a path or a body field here.
//!
//! The owner's session comes from a magic link the root helper mints (`cc-teamchat login`) and that
//! this module consumes. Bot creation and removal need a human session in ClickClack (a bot token
//! cannot manage bots), which is why the firewall holds one at all.

use std::sync::LazyLock;
use std::time::Duration;

use cc_http::BoxFuture;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::integrations::connectors::runtime::enc;
use crate::integrations::js;

const CALL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq)]
pub struct Bot {
    pub bot_user_id: String,
    pub token: String,
    pub handle: String,
}

/// `TeamChatApiError`: an answer ClickClack gave (its status), or a failure to reach it (`status`
/// 0: not one the callers single out).
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type Res<T> = Result<T, ApiError>;

#[derive(Debug, Clone, PartialEq)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub role: Option<String>,
}

/// A channel as the counter sees it: `last_seq` lets it skip a channel with nothing new.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelInfo {
    pub id: String,
    pub name: String,
    pub kind: Option<String>,
    pub last_seq: i64,
    /// Only when ClickClack's list says so; 0.7.1 keeps it in the database alone.
    pub archived: bool,
}

/// One message, metadata only: the body is read for @handles and dropped by the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: String,
    pub seq: i64,
    pub author_id: String,
    pub author_kind: Option<String>,
    pub thread_root_id: Option<String>,
    pub quoted_id: Option<String>,
    pub kind: Option<String>,
    pub created_at: i64,
    pub body: String,
    pub files: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub id: String,
    pub kind: Option<String>,
}

/// The bot management calls (`TeamChatApi`).
pub trait TeamChatApi: Send + Sync {
    fn healthy(&self) -> BoxFuture<bool>;
    fn consume(&self, magic_token: String) -> BoxFuture<Res<(String, String)>>;
    fn workspaces(&self, session: String) -> BoxFuture<Res<Vec<Workspace>>>;
    fn rename_workspace(&self, session: String, workspace_id: String, name: String) -> BoxFuture<Res<()>>;
    fn create_bot(
        &self,
        session: String,
        workspace_id: String,
        display_name: String,
        handle: String,
    ) -> BoxFuture<Res<Bot>>;
    fn remove_bot(&self, session: String, bot_user_id: String) -> BoxFuture<Res<()>>;
    fn set_role(
        &self,
        session: String,
        workspace_id: String,
        user_id: String,
        role: &'static str,
    ) -> BoxFuture<Res<()>>;
}

/// The reads the counter makes (`TeamChatReadApi`), as the owner.
pub trait TeamChatReadApi: Send + Sync {
    fn channel_list(&self, session: String, workspace_id: String) -> BoxFuture<Res<Vec<ChannelInfo>>>;
    fn members(&self, session: String, workspace_id: String) -> BoxFuture<Res<Vec<Member>>>;
    /// At most `limit` messages after `after_seq`, oldest first.
    fn messages(&self, session: String, channel_id: String, after_seq: i64, limit: i64)
    -> BoxFuture<Res<Vec<Message>>>;
}

/// `str(v)`: a non-empty string.
pub fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|x| !x.is_empty()).map(String::from)
}

/// `int(v)`: a finite number, floored, else 0.
fn int(v: Option<&Value>) -> i64 {
    v.and_then(Value::as_f64)
        .filter(|f| f.is_finite())
        .map(|f| f.floor() as i64)
        .unwrap_or(0)
}

fn author_kind(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|k| *k == "human" || *k == "bot")
        .map(String::from)
}

fn list<'a>(r: &'a Map<String, Value>, key: &str) -> Vec<&'a Map<String, Value>> {
    r.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .collect()
}

/// A message from ClickClack's list, reduced to what is counted.
pub fn read_message(m: &Map<String, Value>) -> Option<Message> {
    let id = s(m.get("id"))?;
    let created = m.get("created_at").map(|v| match v {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    });
    let created_at = js::parse_iso(created.as_deref().unwrap_or(""))?;
    let empty = Map::new();
    let author = m.get("author").and_then(Value::as_object).unwrap_or(&empty);
    let files = match m.get("attachments") {
        Some(Value::Array(a)) => a.len() as i64,
        _ => int(m.get("attachment_count")),
    };
    Some(Message {
        id,
        seq: int(m.get("channel_seq").filter(|v| !v.is_null()).or(m.get("seq"))),
        author_id: s(m.get("author_id")).or(s(author.get("id"))).unwrap_or_default(),
        author_kind: author_kind(author.get("kind")),
        thread_root_id: s(m.get("thread_root_id")),
        quoted_id: s(m.get("quoted_message_id")),
        kind: s(m.get("kind")),
        created_at,
        body: m
            .get("body")
            .and_then(Value::as_str)
            .or(m.get("text").and_then(Value::as_str))
            .unwrap_or("")
            .to_string(),
        files,
    })
}

/// The path as the error line names it: no query, ids cut to their kind.
fn log_path(path: &str) -> String {
    static IDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/(usr|wsp|chn)_[0-9a-z]+").expect("pattern"));
    IDS.replace_all(path.split('?').next().unwrap_or(""), "/${1}_…")
        .into_owned()
}

/// `makeTeamChatApi({ baseUrl })`.
#[derive(Clone)]
pub struct ClickClack {
    base: String,
    http: reqwest::Client,
}

impl ClickClack {
    pub fn new(base_url: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            // `redirect: "error"`: a redirect is a failed call.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::custom(|a| a.error("redirect")))
                .no_proxy()
                .build()
                .unwrap_or_default(),
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        session: Option<&str>,
        body: Option<Value>,
    ) -> Res<Map<String, Value>> {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = self
            .http
            .request(m, format!("{}{path}", self.base))
            .timeout(CALL)
            .header("accept", "application/json");
        if let Some(t) = session {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if let Some(b) = &body {
            req = req.header("content-type", "application/json").body(js::stringify(b));
        }
        // Never the URL in an error: a path names ids, and the base is ours, but keep it out anyway.
        let res = req
            .send()
            .await
            .map_err(|e| ApiError::new(0, e.without_url().to_string()))?;
        let status = res.status().as_u16();
        let text = res
            .text()
            .await
            .map_err(|e| ApiError::new(0, e.without_url().to_string()))?;
        if !(200..300).contains(&status) {
            // ClickClack's error bodies are short JSON; keep a bounded line for the log.
            let cut = crate::integrations::connectors::firewall::js_slice(&text, 160);
            return Err(ApiError::new(
                status,
                format!("ClickClack {method} {} answered {status}: {cut}", log_path(path)),
            ));
        }
        if text.is_empty() {
            return Ok(Map::new());
        }
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(o)) => Ok(o),
            // `JSON.parse` of a non-object, read as a record: every field is missing.
            Ok(_) => Ok(Map::new()),
            Err(_) => Err(ApiError::new(
                502,
                format!("ClickClack {method} answered something that is not JSON"),
            )),
        }
    }
}

impl TeamChatApi for ClickClack {
    fn healthy(&self) -> BoxFuture<bool> {
        let me = self.clone();
        Box::pin(async move {
            me.http
                .get(format!("{}/healthz", me.base))
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
        })
    }

    fn consume(&self, magic_token: String) -> BoxFuture<Res<(String, String)>> {
        let me = self.clone();
        Box::pin(async move {
            let r = me
                .call(
                    "POST",
                    "/api/auth/magic/consume",
                    None,
                    Some(json!({"token": magic_token})),
                )
                .await?;
            let session = s(r.get("token")).or(s(r.get("session").and_then(|x| x.get("token"))));
            let user = s(r.get("user").and_then(|x| x.get("id")));
            match (session, user) {
                (Some(session), Some(user)) => Ok((user, session)),
                _ => Err(ApiError::new(502, "ClickClack did not return a session")),
            }
        })
    }

    fn workspaces(&self, session: String) -> BoxFuture<Res<Vec<Workspace>>> {
        let me = self.clone();
        Box::pin(async move {
            let r = me.call("GET", "/api/workspaces", Some(&session), None).await?;
            Ok(list(&r, "workspaces")
                .into_iter()
                .filter_map(|w| {
                    Some(Workspace {
                        id: s(w.get("id"))?,
                        name: w.get("name").map(js_string).unwrap_or_default(),
                        role: s(w.get("role")),
                    })
                })
                .collect())
        })
    }

    fn rename_workspace(&self, session: String, workspace_id: String, name: String) -> BoxFuture<Res<()>> {
        let me = self.clone();
        Box::pin(async move {
            me.call(
                "PATCH",
                &format!("/api/workspaces/{}", enc(&workspace_id)),
                Some(&session),
                Some(json!({"name": name})),
            )
            .await
            .map(|_| ())
        })
    }

    fn create_bot(
        &self,
        session: String,
        workspace_id: String,
        display_name: String,
        handle: String,
    ) -> BoxFuture<Res<Bot>> {
        let me = self.clone();
        Box::pin(async move {
            let r = me
                .call(
                    "POST",
                    &format!("/api/workspaces/{}/bots", enc(&workspace_id)),
                    Some(&session),
                    Some(json!({"display_name": display_name, "handle": handle, "scopes": ["bot:write"]})),
                )
                .await?;
            let bot = r.get("bot");
            let token = s(r.get("bot_token").and_then(|t| t.get("token")));
            let id = s(bot.and_then(|b| b.get("id")));
            match (token, id) {
                (Some(token), Some(bot_user_id)) => Ok(Bot {
                    bot_user_id,
                    token,
                    handle: s(bot.and_then(|b| b.get("handle"))).unwrap_or(handle),
                }),
                _ => Err(ApiError::new(502, "ClickClack did not return a bot token")),
            }
        })
    }

    fn remove_bot(&self, session: String, bot_user_id: String) -> BoxFuture<Res<()>> {
        let me = self.clone();
        Box::pin(async move {
            // Deleting the bot, not only its membership: its tokens die with it, its old messages
            // keep rendering under the former handle, and the handle is free for an agent made
            // again later under the same name.
            match me
                .call(
                    "DELETE",
                    &format!("/api/bots/{}", enc(&bot_user_id)),
                    Some(&session),
                    None,
                )
                .await
            {
                // Already gone is the outcome we wanted.
                Err(e) if e.status == 404 => Ok(()),
                r => r.map(|_| ()),
            }
        })
    }

    fn set_role(
        &self,
        session: String,
        workspace_id: String,
        user_id: String,
        role: &'static str,
    ) -> BoxFuture<Res<()>> {
        let me = self.clone();
        Box::pin(async move {
            me.call(
                "PATCH",
                &format!(
                    "/api/workspaces/{}/moderation/members/{}",
                    enc(&workspace_id),
                    enc(&user_id)
                ),
                Some(&session),
                Some(json!({"role": role})),
            )
            .await
            .map(|_| ())
        })
    }
}

impl TeamChatReadApi for ClickClack {
    fn channel_list(&self, session: String, workspace_id: String) -> BoxFuture<Res<Vec<ChannelInfo>>> {
        let me = self.clone();
        Box::pin(async move {
            let r = me
                .call(
                    "GET",
                    &format!("/api/workspaces/{}/channels", enc(&workspace_id)),
                    Some(&session),
                    None,
                )
                .await?;
            Ok(list(&r, "channels")
                .into_iter()
                .filter_map(|c| {
                    Some(ChannelInfo {
                        id: s(c.get("id"))?,
                        name: c.get("name").map(js_string).unwrap_or_default(),
                        kind: s(c.get("kind")),
                        last_seq: int(c.get("last_seq")),
                        archived: s(c.get("archived_at")).is_some() || c.get("archived") == Some(&Value::Bool(true)),
                    })
                })
                .collect())
        })
    }

    fn members(&self, session: String, workspace_id: String) -> BoxFuture<Res<Vec<Member>>> {
        let me = self.clone();
        Box::pin(async move {
            let r = me
                .call(
                    "GET",
                    &format!("/api/workspaces/{}/members", enc(&workspace_id)),
                    Some(&session),
                    None,
                )
                .await?;
            Ok(list(&r, "members")
                .into_iter()
                .filter_map(|m| {
                    // `m.user ?? m`: a null or missing user is the member itself.
                    let user = m
                        .get("user")
                        .and_then(Value::as_object)
                        .filter(|_| m.get("user").is_some_and(|u| !u.is_null()))
                        .unwrap_or(m);
                    let id = s(m.get("user_id")).or(s(user.get("id")))?;
                    let kind = user.get("kind").filter(|k| !k.is_null()).or(m.get("kind"));
                    Some(Member {
                        id,
                        kind: author_kind(kind),
                    })
                })
                .collect())
        })
    }

    fn messages(
        &self,
        session: String,
        channel_id: String,
        after_seq: i64,
        limit: i64,
    ) -> BoxFuture<Res<Vec<Message>>> {
        let me = self.clone();
        Box::pin(async move {
            let path = format!(
                "/api/channels/{}/messages?after_seq={}&limit={}",
                enc(&channel_id),
                after_seq.max(0),
                limit.clamp(1, 200)
            );
            let r = me.call("GET", &path, Some(&session), None).await?;
            let mut out: Vec<Message> = list(&r, "messages").into_iter().filter_map(read_message).collect();
            out.sort_by_key(|m| m.seq);
            Ok(out)
        })
    }
}

/// `String(v ?? "")` for a name field.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => js::stringify(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_read_for_what_is_counted_and_paths_never_name_ids() {
        let m = read_message(
            json!({"id": "msg_1", "channel_seq": 4, "created_at": "2026-10-10T10:00:00.000Z", "author": {"id": "usr_b", "kind": "bot"}, "body": "hi @ana", "attachments": [{}, {}]})
                .as_object()
                .expect("object"),
        )
        .expect("message");
        assert_eq!(
            (m.seq, m.author_id.as_str(), m.author_kind.as_deref(), m.files),
            (4, "usr_b", Some("bot"), 2)
        );
        assert!(read_message(json!({"id": "x", "created_at": "never"}).as_object().expect("object")).is_none());
        assert_eq!(
            log_path("/api/workspaces/wsp_abc123/moderation/members/usr_x9?x=1"),
            "/api/workspaces/wsp_…/moderation/members/usr_…"
        );
    }
}
