//! Twilio's REST API (`phone-api.ts`). Basic auth with the account SID and token, no redirects, a
//! 1 MiB cap on answers, and a failure is one of a few fixed codes: no URL or body in it.

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::core::activity_sanitize::js_string;
use crate::core::sync::js_truthy;

#[derive(Debug, Clone, PartialEq)]
pub struct PhoneError(pub &'static str);

static ACCOUNT_SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^AC[0-9a-f]{32}$").expect("regex"));
static NUMBER_SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^PN[0-9a-f]{32}$").expect("regex"));
pub static E164: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\+[1-9][0-9]{6,14}$").expect("regex"));

pub fn is_account_sid(s: &str) -> bool {
    ACCOUNT_SID.is_match(s)
}
pub fn is_number_sid(s: &str) -> bool {
    NUMBER_SID.is_match(s)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneNumber {
    pub sid: String,
    pub number: String,
    pub voice: bool,
    pub blocked_routing: bool,
}

/// One call: account, token, path under `api.twilio.com`, and a form for a POST.
pub trait TwilioCalls: Send + Sync {
    fn send(
        &self,
        sid: &str,
        token: &str,
        path: &str,
        fields: Option<Vec<(String, String)>>,
    ) -> cc_http::BoxFuture<Result<Map<String, Value>, PhoneError>>;
}

pub struct LiveTwilio(pub reqwest::Client);

impl LiveTwilio {
    pub fn new() -> Result<Self, String> {
        Ok(Self(
            cc_client::HttpClient::new(false).map_err(|e| e.to_string())?.get(),
        ))
    }
}

impl TwilioCalls for LiveTwilio {
    fn send(
        &self,
        sid: &str,
        token: &str,
        path: &str,
        fields: Option<Vec<(String, String)>>,
    ) -> cc_http::BoxFuture<Result<Map<String, Value>, PhoneError>> {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{sid}:{token}"));
        let mut b = self
            .0
            .request(
                if fields.is_some() {
                    reqwest::Method::POST
                } else {
                    reqwest::Method::GET
                },
                format!("https://api.twilio.com{path}"),
            )
            .timeout(Duration::from_secs(15))
            .header("authorization", format!("Basic {auth}"))
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(f) = fields {
            b = b.body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(f)
                    .finish(),
            );
        }
        Box::pin(async move {
            let Ok(mut res) = b.send().await else {
                return Err(PhoneError("request_uncertain"));
            };
            let status = res.status();
            if !status.is_success() {
                return Err(PhoneError(match status.as_u16() {
                    401 => "invalid_credentials",
                    429 => "rate_limited",
                    _ if status.is_redirection() => "request_uncertain",
                    _ => "twilio_refused",
                }));
            }
            let mut body = vec![];
            loop {
                match res.chunk().await {
                    Ok(Some(c)) => {
                        body.extend_from_slice(&c);
                        if body.len() > 1024 * 1024 {
                            return Err(PhoneError("invalid_response"));
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Err(PhoneError("request_uncertain")),
                }
            }
            match serde_json::from_slice::<Value>(&body) {
                Ok(Value::Object(m)) => Ok(m),
                Ok(_) => Err(PhoneError("invalid_response")),
                Err(_) => Err(PhoneError("request_uncertain")),
            }
        })
    }
}

/// `PhoneApi.request`: the path must stay under the account.
pub async fn request(
    api: &dyn TwilioCalls,
    sid: &str,
    token: &str,
    path: &str,
    fields: Option<Vec<(String, String)>>,
) -> Result<Map<String, Value>, PhoneError> {
    if !is_account_sid(sid)
        || !path.starts_with(&format!("/2010-04-01/Accounts/{sid}"))
        || path.contains("..")
        || path.contains('#')
    {
        return Err(PhoneError("invalid_input"));
    }
    api.send(sid, token, path, fields).await
}

pub async fn account(api: &dyn TwilioCalls, sid: &str, token: &str) -> Result<&'static str, PhoneError> {
    let r = request(api, sid, token, &format!("/2010-04-01/Accounts/{sid}.json"), None).await?;
    if r.get("sid").and_then(Value::as_str) != Some(sid) || r.get("status").and_then(Value::as_str) != Some("active") {
        return Err(PhoneError("account_unavailable"));
    }
    Ok(if r.get("type").and_then(Value::as_str) == Some("Trial") {
        "Trial"
    } else {
        "Full"
    })
}

pub fn number_metadata(sid: &str, r: &Map<String, Value>) -> Result<PhoneNumber, PhoneError> {
    let number_sid = js_string(r.get("sid"));
    let number = js_string(r.get("phone_number"));
    if r.get("account_sid").and_then(Value::as_str) != Some(sid)
        || !is_number_sid(&number_sid)
        || !E164.is_match(&number)
    {
        return Err(PhoneError("invalid_response"));
    }
    Ok(PhoneNumber {
        sid: number_sid,
        number,
        voice: r.get("capabilities").and_then(|c| c.get("voice")) == Some(&Value::Bool(true)),
        blocked_routing: r.get("voice_application_sid").is_some_and(js_truthy)
            || r.get("trunk_sid").is_some_and(js_truthy),
    })
}

/// Every voice number on the account, following Twilio's pages (at most ten, all under the account).
pub async fn numbers(api: &dyn TwilioCalls, sid: &str, token: &str) -> Result<Vec<PhoneNumber>, PhoneError> {
    let mut rows = vec![];
    let mut seen: Vec<String> = vec![];
    let prefix = format!("/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json?");
    let mut path = Some(format!("{prefix}PageSize=100"));
    while let Some(p) = path {
        if seen.contains(&p) || seen.len() >= 10 || !p.starts_with(&prefix) {
            return Err(PhoneError("invalid_pagination"));
        }
        seen.push(p.clone());
        let r = request(api, sid, token, &p, None).await?;
        let list = r
            .get("incoming_phone_numbers")
            .and_then(Value::as_array)
            .ok_or(PhoneError("invalid_response"))?;
        for n in list {
            if n.get("capabilities").and_then(|c| c.get("voice")) == Some(&Value::Bool(true)) {
                rows.push(number_metadata(
                    sid,
                    n.as_object().ok_or(PhoneError("invalid_response"))?,
                )?);
            }
        }
        if rows.len() > 1000 {
            return Err(PhoneError("too_many_numbers"));
        }
        path = r.get("next_page_uri").and_then(Value::as_str).map(str::to_string);
    }
    Ok(rows)
}

pub async fn number(
    api: &dyn TwilioCalls,
    sid: &str,
    token: &str,
    number_sid: &str,
) -> Result<Map<String, Value>, PhoneError> {
    if !is_number_sid(number_sid) {
        return Err(PhoneError("invalid_input"));
    }
    request(
        api,
        sid,
        token,
        &format!("/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers/{number_sid}.json"),
        None,
    )
    .await
}

pub async fn route(
    api: &dyn TwilioCalls,
    sid: &str,
    token: &str,
    number_sid: &str,
    fields: Vec<(String, String)>,
) -> Result<Map<String, Value>, PhoneError> {
    request(
        api,
        sid,
        token,
        &format!("/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers/{number_sid}.json"),
        Some(fields),
    )
    .await
}

/// `routingHash`: the number's routing fields as `JSON.stringify` writes them (`undefined` as `null`).
pub fn routing_hash(r: &Map<String, Value>) -> String {
    let pick = |k: &str| r.get(k).cloned().unwrap_or(Value::Null);
    let v = Value::Array(
        [
            "voice_url",
            "voice_method",
            "status_callback",
            "status_callback_method",
            "voice_application_sid",
            "trunk_sid",
            "voice_fallback_url",
        ]
        .iter()
        .map(|k| pick(k))
        .collect(),
    );
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}
