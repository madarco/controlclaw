//! AgentMail's REST API (`agentmail-api.ts`). It runs only on the firewall, and an upstream body
//! never reaches an error or a result: a failure is one of a few fixed codes.

use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub struct AgentMailError {
    pub code: &'static str,
    pub http_status: u16,
}

impl AgentMailError {
    pub fn new(code: &'static str) -> Self {
        Self { code, http_status: 0 }
    }
}

pub type ApiResult = Result<Value, AgentMailError>;

/// One call: method, path under `/v0`, the key it is made with, and the JSON body.
pub trait AgentMailCalls: Send + Sync {
    fn request(
        &self,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> cc_http::BoxFuture<ApiResult>;
}

static USER_EXISTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)user.already.exists").expect("regex"));
static TAKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)username.*(taken|exists|unavailable)|inbox.already.exists").expect("regex"));

/// The code an upstream refusal maps to, from its status and body.
pub fn error_code(status: u16, raw: &str) -> &'static str {
    if USER_EXISTS.is_match(raw) {
        "user_exists"
    } else if TAKEN.is_match(raw) {
        "username_taken"
    } else {
        match status {
            401 => "invalid_key",
            403 => "permission_denied",
            429 => "rate_limited",
            _ => "upstream_error",
        }
    }
}

pub struct LiveAgentMail {
    pub http: reqwest::Client,
    pub base: String,
}

impl LiveAgentMail {
    /// Redirects are not followed (`redirect: "error"`): one is a failed call.
    pub fn new() -> Result<Self, String> {
        let http = cc_client::HttpClient::new(false).map_err(|e| e.to_string())?.get();
        Ok(Self {
            http,
            base: "https://api.agentmail.to/v0".into(),
        })
    }
}

impl AgentMailCalls for LiveAgentMail {
    fn request(
        &self,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> cc_http::BoxFuture<ApiResult> {
        let url = format!("{}{path}", self.base);
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = self
            .http
            .request(method, url)
            .timeout(Duration::from_secs(30))
            .header("content-type", "application/json");
        if let Some(k) = key {
            req = req.bearer_auth(k);
        }
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        Box::pin(async move {
            // The URL can carry an inbox or message id: the error is not logged or returned.
            let Ok(res) = req.send().await else {
                return Err(AgentMailError::new("request_uncertain"));
            };
            let status = res.status();
            if status.is_redirection() {
                return Err(AgentMailError::new("request_uncertain"));
            }
            if !status.is_success() {
                let raw = res.text().await.unwrap_or_default();
                return Err(AgentMailError {
                    code: error_code(status.as_u16(), &raw),
                    http_status: status.as_u16(),
                });
            }
            if status.as_u16() == 204 {
                return Ok(json!({}));
            }
            let Ok(text) = res.text().await else {
                return Err(AgentMailError::new("invalid_response"));
            };
            if text.is_empty() {
                return Ok(json!({}));
            }
            serde_json::from_str(&text).map_err(|_| AgentMailError::new("invalid_response"))
        })
    }
}

const INBOX_PERMISSIONS: [&str; 9] = [
    "inbox_read",
    "message_read",
    "message_send",
    "message_update",
    "draft_read",
    "draft_create",
    "draft_update",
    "draft_delete",
    "draft_send",
];

pub fn enc(s: &str) -> String {
    crate::core::permissions::encode_uri_component(s)
}

pub async fn organization(api: &dyn AgentMailCalls, key: &str) -> ApiResult {
    api.request("GET", "/organizations", Some(key), None).await
}

/// Every inbox the key sees, page by page; more than 1000 is refused.
pub async fn inboxes(api: &dyn AgentMailCalls, key: &str) -> Result<Vec<Value>, AgentMailError> {
    let mut all = vec![];
    let mut token: Option<String> = None;
    loop {
        let path = match &token {
            Some(t) => format!("/inboxes?page_token={}", enc(t)),
            None => "/inboxes".into(),
        };
        let page = api.request("GET", &path, Some(key), None).await?;
        // `page.inboxes` must be a list, as the TS's spread needs.
        let items = page
            .get("inboxes")
            .and_then(Value::as_array)
            .ok_or(AgentMailError::new("internal_error"))?;
        all.extend(items.iter().cloned());
        token = page
            .get("next_page_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        if all.len() > 1000 {
            return Err(AgentMailError::new("too_many_inboxes"));
        }
        if token.is_none() {
            return Ok(all);
        }
    }
}

/// The key's own row: exactly one key whose prefix (8 or more characters) the key starts with. A
/// single visible inbox does not prove an inbox-scoped key.
pub async fn scope(api: &dyn AgentMailCalls, key: &str) -> Result<Value, AgentMailError> {
    let mut matches = vec![];
    let mut token: Option<String> = None;
    loop {
        let path = match &token {
            Some(t) => format!("/api-keys?page_token={}", enc(t)),
            None => "/api-keys".into(),
        };
        let page = api.request("GET", &path, Some(key), None).await?;
        let rows = page
            .get("api_keys")
            .and_then(Value::as_array)
            .ok_or(AgentMailError::new("internal_error"))?;
        matches.extend(
            rows.iter()
                .filter(|r| {
                    r.get("prefix")
                        .and_then(Value::as_str)
                        .is_some_and(|p| crate::channels::js::js_len(p) >= 8 && key.starts_with(p))
                })
                .cloned(),
        );
        token = page
            .get("next_page_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        if token.is_none() {
            break;
        }
    }
    if matches.len() != 1 {
        return Err(AgentMailError::new("scope_unverified"));
    }
    Ok(matches.remove(0))
}

pub async fn mint(api: &dyn AgentMailCalls, key: &str, inbox_id: &str) -> ApiResult {
    let permissions: serde_json::Map<String, Value> = INBOX_PERMISSIONS
        .iter()
        .map(|p| ((*p).to_string(), Value::Bool(true)))
        .collect();
    api.request(
        "POST",
        &format!("/inboxes/{}/api-keys", enc(inbox_id)),
        Some(key),
        Some(json!({"name": "ControlClaw agent", "permissions": permissions})),
    )
    .await
}

/// A key already gone (404) is revoked.
pub async fn revoke(api: &dyn AgentMailCalls, key: &str, inbox_id: &str, key_id: &str) -> Result<(), AgentMailError> {
    match api
        .request(
            "DELETE",
            &format!("/inboxes/{}/api-keys/{}", enc(inbox_id), enc(key_id)),
            Some(key),
            None,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(e) if e.http_status == 404 => Ok(()),
        Err(e) => Err(e),
    }
}
