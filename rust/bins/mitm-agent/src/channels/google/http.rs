//! The HTTP the Google modules make (OAuth, the API probes, Drive's write check, Gmail push), behind
//! one call so the tests can stand in for Google. A failure carries only whether it timed out: a
//! reqwest error's text includes the URL, which can carry a token.

use std::time::Duration;

use serde_json::{Map, Value};

/// Every call. Google is usually fast; a hung connection must not hold a change open.
pub const GOOGLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Req {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl Req {
    pub fn get(url: impl Into<String>, bearer: &str) -> Self {
        Self {
            method: "GET",
            url: url.into(),
            headers: vec![("authorization".into(), format!("Bearer {bearer}"))],
            body: None,
            timeout: GOOGLE_TIMEOUT,
        }
    }
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    /// The body as a JSON object; `{}` for anything else, as `res.json().catch(() => ({}))`.
    pub fn json(&self) -> Map<String, Value> {
        serde_json::from_slice::<Value>(&self.body)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HttpErr {
    pub timed_out: bool,
}

impl HttpErr {
    /// What a person reads; never the error's own text.
    pub fn reason(self) -> &'static str {
        if self.timed_out {
            "Google did not answer in time."
        } else {
            "Google could not be reached."
        }
    }
}

pub trait GoogleHttp: Send + Sync {
    fn send(&self, req: Req) -> cc_http::BoxFuture<Result<Resp, HttpErr>>;
}

/// Redirects are not followed: one is a failed call.
pub struct LiveHttp(pub reqwest::Client);

impl LiveHttp {
    pub fn new() -> Result<Self, String> {
        Ok(Self(
            cc_client::HttpClient::new(false).map_err(|e| e.to_string())?.get(),
        ))
    }
}

impl GoogleHttp for LiveHttp {
    fn send(&self, req: Req) -> cc_http::BoxFuture<Result<Resp, HttpErr>> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut b = self.0.request(method, &req.url).timeout(req.timeout);
        for (k, v) in &req.headers {
            b = b.header(k, v);
        }
        if let Some(body) = req.body {
            b = b.body(body);
        }
        Box::pin(async move {
            let res = b.send().await.map_err(|e| HttpErr {
                timed_out: e.is_timeout(),
            })?;
            let status = res.status().as_u16();
            let headers = res
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect();
            let body = res
                .bytes()
                .await
                .map_err(|e| HttpErr {
                    timed_out: e.is_timeout(),
                })?
                .to_vec();
            Ok(Resp { status, headers, body })
        })
    }
}

/// `application/x-www-form-urlencoded`, as `URLSearchParams` writes it.
pub fn form_body(form: &[(&str, &str)]) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish()
        .into_bytes()
}

/// `postForm`: the status and the JSON body (`{}` when it is not JSON).
pub async fn post_form(
    http: &dyn GoogleHttp,
    url: &str,
    form: &[(&str, &str)],
) -> Result<(u16, Map<String, Value>), HttpErr> {
    let res = http
        .send(Req {
            method: "POST",
            url: url.into(),
            headers: vec![
                ("content-type".into(), "application/x-www-form-urlencoded".into()),
                ("accept".into(), "application/json".into()),
            ],
            body: Some(form_body(form)),
            timeout: GOOGLE_TIMEOUT,
        })
        .await?;
    Ok((res.status, res.json()))
}
