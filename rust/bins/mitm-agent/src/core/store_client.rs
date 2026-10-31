//! The control plane's stores (`store-client.ts`): the sealed record at `STORE_URL`, and the plain
//! lists (egress rules, identities, webhooks). A `file:` URL reads a local file, for the smoke tests.

use std::time::Duration;

use cc_auth::keys::KeysDir;
use cc_client::HttpClient;
use cc_crypto::secret_store::StoreRecord;
use serde_json::Value;

/// `fetch` has no timeout of its own; undici gives up on headers and body after 300 s.
const FETCH_TIMEOUT: Duration = Duration::from_secs(300);

/// Outbound calls to the control plane, with a box token when `token` is on (`getToken` set).
#[derive(Clone)]
pub struct StoreClient {
    pub http: HttpClient,
    pub keys: KeysDir,
    pub token: bool,
}

/// A `local:` URL's answer (`cc_client::local`) as the response an HTTP control plane would have
/// sent, so every caller below reads it the same way.
async fn local_response(url: &str, method: &str, body: Option<&Value>) -> Option<Result<reqwest::Response, String>> {
    let (status, body) = cc_client::local::call(method, url, body).await?;
    let r = http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body).unwrap_or_default())
        .map_err(|e| e.to_string());
    Some(r.map(reqwest::Response::from))
}

fn file_path(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("file:")?;
    Some(rest.strip_prefix("//").unwrap_or(rest))
}

impl StoreClient {
    /// A GET to the control plane: the status and the body as text.
    pub async fn get_text(&self, url: &str) -> Result<(u16, String), String> {
        let res = self.get(url).await?;
        let status = res.status().as_u16();
        Ok((status, res.text().await.unwrap_or_default()))
    }

    /// A JSON POST to the control plane: the status and the body as text.
    pub async fn post_text(&self, url: &str, body: &Value) -> Result<(u16, String), String> {
        let res = self.post(url, body).await?;
        let status = res.status().as_u16();
        Ok((status, res.text().await.unwrap_or_default()))
    }

    async fn get(&self, url: &str) -> Result<reqwest::Response, String> {
        if let Some(r) = local_response(url, "GET", None).await {
            return r;
        }
        let mut req = self.http.get().get(url).timeout(FETCH_TIMEOUT);
        if self.token {
            let token = cc_auth::sign::box_token(&self.keys).map_err(|e| e.to_string())?;
            req = req.bearer_auth(token);
        }
        req.send().await.map_err(|_| "fetch failed".to_string())
    }

    async fn post(&self, url: &str, body: &Value) -> Result<reqwest::Response, String> {
        if let Some(r) = local_response(url, "POST", Some(body)).await {
            return r;
        }
        let mut req = self
            .http
            .get()
            .post(url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap_or_default())
            .timeout(FETCH_TIMEOUT);
        if self.token {
            let token = cc_auth::sign::box_token(&self.keys).map_err(|e| e.to_string())?;
            req = req.bearer_auth(token);
        }
        req.send().await.map_err(|_| "fetch failed".to_string())
    }

    /// `fetchRecord`: `None` for a 404 (or a missing file).
    pub async fn fetch_record(&self, url: &str) -> Result<Option<StoreRecord>, String> {
        let raw: Value = if let Some(path) = file_path(url) {
            match std::fs::read_to_string(path) {
                Ok(text) => serde_json::from_str(&text).map_err(|e| e.to_string())?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.to_string()),
            }
        } else {
            let res = self.get(url).await?;
            if res.status().as_u16() == 404 {
                return Ok(None);
            }
            if !res.status().is_success() {
                return Err(format!("store GET failed: {}", res.status().as_u16()));
            }
            res.json().await.map_err(|e| e.without_url().to_string())?
        };
        serde_json::from_value(raw).map(Some).map_err(|e| e.to_string())
    }

    /// `putRecord`.
    pub async fn put_record(&self, url: &str, record: &StoreRecord) -> Result<(), String> {
        let body = serde_json::to_value(record).map_err(|e| e.to_string())?;
        if let Some(path) = file_path(url) {
            let text = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
            return cc_store::write_file(std::path::Path::new(path), &text, 0o600).map_err(|e| e.to_string());
        }
        let res = self.post(url, &body).await?;
        if !res.status().is_success() {
            return Err(format!("store POST failed: {}", res.status().as_u16()));
        }
        Ok(())
    }

    /// `fetchList`: what is under `key` (or a bare array from a file), as it came: a value that is
    /// not a list is the caller's to refuse, as the TS fails the sync on it.
    pub async fn fetch_list(&self, url: &str, key: &str) -> Result<Value, String> {
        if let Some(path) = file_path(url) {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Value::Array(Vec::new())),
                Err(e) => return Err(e.to_string()),
            };
            let parsed: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            return match parsed {
                Value::Array(a) => Ok(Value::Array(a)),
                other => under(&other, key),
            };
        }
        let res = self.get(url).await?;
        if !res.status().is_success() {
            return Err(format!("{key} GET failed: {}", res.status().as_u16()));
        }
        let body: Value = res.json().await.map_err(|e| e.without_url().to_string())?;
        under(&body, key)
    }

    /// `fetchPolicy`: the egress rules, as they came, and the AI review settings (`null` when off).
    pub async fn fetch_policy(&self, url: &str) -> Result<(Value, Value), String> {
        if let Some(path) = file_path(url) {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok((Value::Array(Vec::new()), Value::Null));
                }
                Err(e) => return Err(e.to_string()),
            };
            let parsed: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            if let Value::Array(a) = parsed {
                return Ok((Value::Array(a), Value::Null));
            }
            return Ok((
                under(&parsed, "rules")?,
                parsed.get("ai").cloned().unwrap_or(Value::Null),
            ));
        }
        let res = self.get(url).await?;
        if !res.status().is_success() {
            return Err(format!("rules GET failed: {}", res.status().as_u16()));
        }
        let body: Value = res.json().await.map_err(|e| e.without_url().to_string())?;
        Ok((under(&body, "rules")?, body.get("ai").cloned().unwrap_or(Value::Null)))
    }
}

/// `body[key] ?? []`: whatever is there, `[]` for nothing or `null`. Reading a key of `null` throws
/// in the TS, and fails the sync here too.
fn under(body: &Value, key: &str) -> Result<Value, String> {
    if body.is_null() {
        return Err(format!("Cannot read properties of null (reading '{key}')"));
    }
    Ok(match body.get(key) {
        None | Some(Value::Null) => Value::Array(Vec::new()),
        Some(v) => v.clone(),
    })
}
