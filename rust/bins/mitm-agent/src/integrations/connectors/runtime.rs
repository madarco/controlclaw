//! The only door between the control plane and OpenConnector's management API
//! (`connector-client.ts`). OpenConnector listens on loopback of this box; its admin token is
//! generated here and never leaves. Every call the control plane can cause is one of the named
//! methods below: no path or method comes from a command payload, so a compromised control plane
//! cannot reach an admin route this file does not name.

use std::time::Duration;

use serde_json::{Map, Value, json};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(40);

/// A provider call can be slow; a 400 from the runtime is a message for the person, not a crash.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeError {
    pub message: String,
    pub code: Option<String>,
    pub status: u16,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// `RuntimeConnection`, as the runtime answers it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuntimeConnection {
    pub id: String,
    pub service: String,
    pub alias: Option<String>,
    pub status: Option<String>,
    pub auth_type: Option<String>,
    pub display_name: Option<String>,
    pub account_label: Option<String>,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

impl RuntimeConnection {
    pub fn from_value(v: &Value) -> Self {
        Self {
            id: s(v, "id").unwrap_or_default(),
            service: s(v, "service").unwrap_or_default(),
            alias: s(v, "alias"),
            status: s(v, "status"),
            auth_type: s(v, "authType"),
            display_name: s(v, "displayName"),
            account_label: s(v, "accountLabel"),
        }
    }
}

/// `RuntimeAuthorization`.
#[derive(Debug, Clone, PartialEq)]
pub struct Authorization {
    pub authorization_url: Value,
    pub state_handle: String,
    pub connection_request_id: String,
    pub expires_at: Option<Value>,
}

#[derive(Clone)]
pub struct ConnectorRuntime {
    base: String,
    admin_token: String,
    http: reqwest::Client,
    timeout: Duration,
}

impl ConnectorRuntime {
    /// `base_url`: e.g. `http://127.0.0.1:3910`.
    pub fn new(base_url: &str, admin_token: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            admin_token: admin_token.to_string(),
            // `redirect: "manual"`: a redirect is an answer here, never followed.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                // Node's fetch takes no proxy from the environment.
                .no_proxy()
                .build()
                .unwrap_or_default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>, auth: bool) -> RuntimeResult<Value> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .timeout(self.timeout);
        if auth {
            req = req.header("Authorization", format!("Bearer {}", self.admin_token));
        }
        if let Some(b) = &body {
            req = req
                .header("content-type", "application/json")
                .body(crate::integrations::js::stringify(b));
        }
        let res = match req.send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                return Err(RuntimeError {
                    message: "The connector runtime did not answer in time.".into(),
                    code: Some("timeout".into()),
                    status: 504,
                });
            }
            Err(_) => {
                return Err(RuntimeError {
                    message: "The connector runtime is not reachable on this firewall.".into(),
                    code: Some("unreachable".into()),
                    status: 503,
                });
            }
        };
        let status = res.status().as_u16();
        let text = match res.text().await {
            Ok(t) => t,
            Err(e) if e.is_timeout() => {
                return Err(RuntimeError {
                    message: "The connector runtime did not answer in time.".into(),
                    code: Some("timeout".into()),
                    status: 504,
                });
            }
            Err(_) => String::new(),
        };
        let parsed: Value = if text.is_empty() {
            json!({})
        } else {
            serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
        };
        // A redirect is a success on the OAuth callback (the runtime sends the browser to returnUri).
        if (300..400).contains(&status) {
            return Ok(json!({}));
        }
        let ok = (200..300).contains(&status);
        if !ok || parsed.get("success") == Some(&Value::Bool(false)) {
            let code = parsed.get("errorCode").and_then(Value::as_str).map(str::to_string);
            let message = parsed
                .get("message")
                .and_then(Value::as_str)
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("connector runtime {status}"));
            return Err(RuntimeError { message, code, status });
        }
        // `/v1` wraps in `data`; `/api` answers plainly.
        Ok(match parsed.get("data") {
            Some(d) => d.clone(),
            None => parsed,
        })
    }

    async fn get(&self, path: &str) -> RuntimeResult<Value> {
        self.call(reqwest::Method::GET, path, None, true).await
    }

    async fn post(&self, path: &str, body: Value) -> RuntimeResult<Value> {
        self.call(reqwest::Method::POST, path, Some(body), true).await
    }

    // ---- reads ----

    pub async fn setup(&self, service: &str) -> RuntimeResult<Value> {
        self.get(&format!("/v1/providers/{}/setup", enc(service))).await
    }

    pub async fn connections(&self) -> RuntimeResult<Vec<RuntimeConnection>> {
        let v = self.get("/v1/connections").await?;
        Ok(v.as_array()
            .map(|a| a.iter().map(RuntimeConnection::from_value).collect())
            .unwrap_or_default())
    }

    /// Redacted audit records; never a credential, never a request body.
    pub async fn runs(&self, limit: usize) -> RuntimeResult<Vec<Value>> {
        let r = self.get(&format!("/api/runs?limit={limit}")).await?;
        Ok(match r {
            Value::Array(a) => a,
            other => other
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        })
    }

    pub async fn request_status(&self, request_id: &str) -> RuntimeResult<Value> {
        self.get(&format!("/v1/connection-requests/{}", enc(request_id))).await
    }

    // ---- connections ----

    pub async fn connect_api_key(&self, service: &str, body: Value) -> RuntimeResult<RuntimeConnection> {
        let v = self
            .post(&format!("/v1/connections/{}/connect/api-key", enc(service)), body)
            .await?;
        Ok(RuntimeConnection::from_value(&v))
    }

    pub async fn connect_custom(&self, service: &str, body: Value) -> RuntimeResult<RuntimeConnection> {
        let v = self
            .post(
                &format!("/v1/connections/{}/connect/custom-credential", enc(service)),
                body,
            )
            .await?;
        Ok(RuntimeConnection::from_value(&v))
    }

    pub async fn replace_api_key(&self, app_id: &str, body: Value) -> RuntimeResult<RuntimeConnection> {
        let v = self
            .post(&format!("/v1/connections/by-id/{}/connect/api-key", enc(app_id)), body)
            .await?;
        Ok(RuntimeConnection::from_value(&v))
    }

    pub async fn replace_custom(&self, app_id: &str, body: Value) -> RuntimeResult<RuntimeConnection> {
        let v = self
            .post(
                &format!("/v1/connections/by-id/{}/connect/custom-credential", enc(app_id)),
                body,
            )
            .await?;
        Ok(RuntimeConnection::from_value(&v))
    }

    /// There is no `/v1` delete, so this is the console route the runtime documents for it.
    pub async fn delete_connection(&self, service: &str, alias: Option<&str>) -> RuntimeResult<Value> {
        let q = alias
            .filter(|a| !a.is_empty())
            .map(|a| format!("?connectionName={}", enc(a)))
            .unwrap_or_default();
        self.call(
            reqwest::Method::DELETE,
            &format!("/api/connections/{}{q}", enc(service)),
            None,
            true,
        )
        .await
    }

    // ---- OAuth (the customer's own app) ----

    pub async fn put_oauth_config(&self, service: &str, body: Value) -> RuntimeResult<Value> {
        self.call(
            reqwest::Method::PUT,
            &format!("/api/oauth/configs/{}", enc(service)),
            Some(body),
            true,
        )
        .await
    }

    pub async fn start_authorization(&self, service: &str, body: Value) -> RuntimeResult<Authorization> {
        let v = self
            .post(&format!("/v1/connections/{}/connect", enc(service)), body)
            .await?;
        Ok(authorization(&v))
    }

    pub async fn reauthorize(&self, app_id: &str, body: Value) -> RuntimeResult<Authorization> {
        let v = self
            .post(&format!("/v1/connections/by-id/{}/connect", enc(app_id)), body)
            .await?;
        Ok(authorization(&v))
    }

    /// Replay a callback the provider delivered to the control plane. Unauthenticated on the
    /// runtime's side by design: the `code` is worthless without the PKCE verifier and the client
    /// secret, which never leave this box.
    pub async fn complete_callback(&self, query: &str) -> RuntimeResult<Value> {
        self.call(reqwest::Method::GET, &format!("/oauth/callback?{query}"), None, false)
            .await
    }

    // ---- runtime tokens ----

    fn token_body(name: &str, allowed_actions: &[String], allowed_connections: &[String]) -> Value {
        json!({"name": name, "allowedActions": allowed_actions, "allowedConnections": allowed_connections,
            "blockedActions": [], "allowedProxies": []})
    }

    /// The token and its record id.
    pub async fn create_token(
        &self,
        name: &str,
        allowed_actions: &[String],
        allowed_connections: &[String],
    ) -> RuntimeResult<(String, String)> {
        let v = self
            .post(
                "/api/runtime-tokens",
                Self::token_body(name, allowed_actions, allowed_connections),
            )
            .await?;
        Ok((
            s(&v, "token").unwrap_or_default(),
            v.get("record").and_then(|r| s(r, "id")).unwrap_or_default(),
        ))
    }

    /// A PUT must always send `allowedConnections`, or it silently drops the restriction.
    pub async fn update_token(
        &self,
        id: &str,
        name: &str,
        allowed_actions: &[String],
        allowed_connections: &[String],
    ) -> RuntimeResult<Value> {
        self.call(
            reqwest::Method::PUT,
            &format!("/api/runtime-tokens/{}", enc(id)),
            Some(Self::token_body(name, allowed_actions, allowed_connections)),
            true,
        )
        .await
    }

    pub async fn revoke_token(&self, id: &str) -> RuntimeResult<Value> {
        self.call(
            reqwest::Method::DELETE,
            &format!("/api/runtime-tokens/{}", enc(id)),
            None,
            true,
        )
        .await
    }
}

fn authorization(v: &Value) -> Authorization {
    Authorization {
        authorization_url: v.get("authorizationUrl").cloned().unwrap_or(Value::Null),
        state_handle: s(v, "stateHandle").unwrap_or_default(),
        connection_request_id: s(v, "connectionRequestId").unwrap_or_default(),
        expires_at: v.get("expiresAt").cloned(),
    }
}

/// `encodeURIComponent`.
pub fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `new URLSearchParams(pairs).toString()`.
pub fn search_params(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

/// An object from a list of pairs, dropping the empty ones the TS spreads away.
pub fn obj(pairs: Vec<(&str, Option<Value>)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        if let Some(v) = v {
            m.insert(k.to_string(), v);
        }
    }
    Value::Object(m)
}
