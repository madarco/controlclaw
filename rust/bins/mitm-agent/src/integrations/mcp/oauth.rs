//! Signing the firewall in to a remote MCP server with OAuth (`mcp-oauth.ts`, the MCP
//! authorization spec 2025-06-18):
//!
//! 1. Discovery: the server's 401 names its protected resource metadata (RFC 9728), else the
//!    well-known address is tried; that names the authorization server, whose metadata (RFC 8414 or
//!    OpenID discovery) gives the endpoints. A server from before RFC 9728 is its own.
//! 2. A client: registered on the spot (RFC 7591), or the id and secret a person typed.
//! 3. Authorization code with PKCE (S256) and `resource` (RFC 8707). The redirect goes to
//!    ControlClaw's `/oauth/callback`, which relays `state` and `code` here; the verifier and the
//!    client secret never leave this box.
//! 4. Refresh, by the firewall.
//!
//! Every request goes through `public_fetch`: https to a public address only.

use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use super::client::cut;
use super::public::{PublicAnswer, Request, public_fetch, public_https_url};
use crate::integrations::js;

const MAX_META: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthServerMeta {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OauthDiscovery {
    /// What the token is for: the protected resource metadata's `resource`, or the server's URL.
    pub resource: String,
    pub meta: AuthServerMeta,
    /// The scopes to ask for, when the server says which.
    pub scope: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// `none`, `client_secret_post` or `client_secret_basic`.
    pub auth_method: String,
    pub registered: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Milliseconds since the epoch.
    pub expires_at: Option<f64>,
    pub scope: Option<String>,
    /// Who signed in, when the server says (an OpenID `id_token`): for a person to read only.
    #[serde(default)]
    pub account: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpOauthError(pub String);

fn err<T>(m: impl Into<String>) -> Result<T, McpOauthError> {
    Err(McpOauthError(m.into()))
}

/// The account an `id_token` names (email, user name or name), unverified.
pub fn id_token_account(id_token: Option<&Value>) -> Option<String> {
    let t = id_token?.as_str()?;
    let part = t.split('.').nth(1).filter(|p| !p.is_empty())?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part.trim_end_matches('='))
        .ok()?;
    let claims: Value = serde_json::from_slice(&raw).ok()?;
    let pick = ["email", "preferred_username", "name"]
        .iter()
        .find_map(|k| claims.get(*k).and_then(Value::as_str).filter(|v| !v.is_empty()))?;
    static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\p{Cc}\p{Cf}]").expect("pattern"));
    Some(cut(&CONTROL.replace_all(pick, ""), 120))
}

fn json_of(answer: &PublicAnswer) -> Option<Map<String, Value>> {
    serde_json::from_slice::<Value>(&answer.body).ok()?.as_object().cloned()
}

fn https(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    public_https_url(s).map(|_| s.to_string())
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    Some(
        v?.as_array()?
            .iter()
            .filter_map(|s| s.as_str().map(str::to_string))
            .take(100)
            .collect(),
    )
}

/// One `key="value"` (or bare token) parameter of a `WWW-Authenticate` header.
pub fn auth_param(header: Option<&str>, name: &str) -> Option<String> {
    let text = header.unwrap_or_default();
    let re = Regex::new(&format!(
        r#"(?i)(?:^|[\s,]){}\s*=\s*(?:"([^"]*)"|([^\s,]+))"#,
        regex::escape(name)
    ))
    .ok()?;
    let m = re.captures(text)?;
    m.get(1).or(m.get(2)).map(|g| g.as_str().to_string())
}

/// `https://a.b/x/y` → `https://a.b/.well-known/<name>/x/y`.
fn well_known(base: &Url, name: &str, with_path: bool) -> Option<Url> {
    let path = if with_path && base.path() != "/" {
        base.path().trim_end_matches('/').to_string()
    } else {
        String::new()
    };
    Url::parse(&format!("{}/.well-known/{name}{path}", origin(base))).ok()
}

/// `URL#origin`.
pub fn origin(u: &Url) -> String {
    u.origin().ascii_serialization()
}

async fn get_json(url: &Url) -> Option<Map<String, Value>> {
    let req = Request {
        headers: vec![
            ("accept".into(), "application/json".into()),
            ("mcp-protocol-version".into(), "2025-06-18".into()),
        ],
        ..Request::default()
    };
    let answer = public_fetch(url, req, MAX_META).await.ok()?;
    if answer.status != 200 {
        return None;
    }
    json_of(&answer)
}

fn as_meta(doc: Option<Map<String, Value>>) -> Option<AuthServerMeta> {
    let doc = doc?;
    let authorization_endpoint = https(doc.get("authorization_endpoint"))?;
    let token_endpoint = https(doc.get("token_endpoint"))?;
    Some(AuthServerMeta {
        issuer: doc
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        authorization_endpoint,
        token_endpoint,
        registration_endpoint: https(doc.get("registration_endpoint")),
        code_challenge_methods_supported: strings(doc.get("code_challenge_methods_supported")),
        token_endpoint_auth_methods_supported: strings(doc.get("token_endpoint_auth_methods_supported")),
        scopes_supported: strings(doc.get("scopes_supported")),
        extra: Map::new(),
    })
}

/// Two URLs the same but for a trailing slash.
fn same_url(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// The authorization server's metadata, by the orders RFC 8414 and OpenID discovery give.
async fn auth_server_meta(issuer: &Url) -> Option<AuthServerMeta> {
    let mut tries: Vec<Url> = [
        well_known(issuer, "oauth-authorization-server", true),
        well_known(issuer, "openid-configuration", true),
    ]
    .into_iter()
    .flatten()
    .collect();
    if issuer.path() != "/" {
        if let Ok(u) = Url::parse(&format!(
            "{}{}/.well-known/openid-configuration",
            origin(issuer),
            issuer.path().trim_end_matches('/')
        )) {
            tries.push(u);
        }
        tries.extend(well_known(issuer, "oauth-authorization-server", false));
    }
    for url in tries {
        let meta = as_meta(get_json(&url).await);
        // RFC 8414 §3.3: the issuer the metadata names is the one it was asked for, or it is not used.
        if let Some(m) = meta
            && same_url(&m.issuer, issuer.as_str())
        {
            return Some(m);
        }
    }
    None
}

/// RFC 9728 §3.3: the resource the metadata is for must be the server it was read for: its own
/// URL, or its origin or a path above it.
pub fn resource_matches(resource: &str, server: &Url) -> bool {
    let own = format!("{}{}", origin(server), server.path());
    let own = own.trim_end_matches('/');
    let r = resource.trim_end_matches('/');
    r == own || r == origin(server) || own.starts_with(&format!("{r}/"))
}

/// Find out how a server wants to be signed in to. `challenge` is the `WWW-Authenticate` of the
/// 401 the server gave an unauthenticated `initialize`, when there was one.
pub async fn discover(server: &Url, challenge: Option<&str>) -> Result<OauthDiscovery, McpOauthError> {
    let mut prm = None;
    if let Some(named) = https(auth_param(challenge, "resource_metadata").map(Value::String).as_ref())
        && let Ok(u) = Url::parse(&named)
    {
        prm = get_json(&u).await;
    }
    if prm.is_none()
        && let Some(u) = well_known(server, "oauth-protected-resource", true)
    {
        prm = get_json(&u).await;
    }
    if prm.is_none()
        && server.path() != "/"
        && let Some(u) = well_known(server, "oauth-protected-resource", false)
    {
        prm = get_json(&u).await;
    }
    let scope_hint = auth_param(challenge, "scope");
    let mut resource = format!("{}{}", origin(server), server.path());
    let mut scopes = None;
    let issuer = match &prm {
        Some(prm) => {
            let first = strings(prm.get("authorization_servers"))
                .unwrap_or_default()
                .into_iter()
                .find(|s| public_https_url(s).is_some());
            let Some(first) = first else {
                return err("The server's sign-in information names no authorization server the firewall can reach.");
            };
            if let Some(r) = prm.get("resource").and_then(Value::as_str) {
                if public_https_url(r).is_none() || !resource_matches(r, server) {
                    return err(
                        "The server's sign-in information is for another address, so the firewall did not use it.",
                    );
                }
                resource = r.to_string();
            }
            scopes = strings(prm.get("scopes_supported"));
            Url::parse(&first).map_err(|e| McpOauthError(e.to_string()))?
        }
        // Before RFC 9728 (spec 2025-03-26): the MCP server's own origin is its authorization server.
        None => Url::parse(&origin(server)).map_err(|e| McpOauthError(e.to_string()))?,
    };
    let host = issuer.host_str().unwrap_or_default().to_string();
    let host = match issuer.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    let Some(meta) = auth_server_meta(&issuer).await else {
        return err(format!("The firewall could not read the sign-in settings of {host}."));
    };
    if let Some(m) = &meta.code_challenge_methods_supported
        && !m.iter().any(|x| x == "S256")
    {
        return err(format!(
            "{host} does not support PKCE with S256, which the firewall needs."
        ));
    }
    let scope = scope_hint.or_else(|| scopes.filter(|s| !s.is_empty()).map(|s| s.join(" ")));
    Ok(OauthDiscovery {
        resource,
        meta,
        scope,
        extra: Map::new(),
    })
}

fn why(doc: Option<&Map<String, Value>>, status: u16) -> String {
    let d = doc.and_then(|d| d.get("error_description")).and_then(Value::as_str);
    let e = doc.and_then(|d| d.get("error")).and_then(Value::as_str);
    cut(
        &d.or(e).map(str::to_string).unwrap_or_else(|| format!("HTTP {status}")),
        200,
    )
}

/// Register the firewall as a client of this authorization server (RFC 7591).
pub async fn register(meta: &AuthServerMeta, redirect_uri: &str, name: &str) -> Result<OauthClient, McpOauthError> {
    let Some(endpoint) = &meta.registration_endpoint else {
        return err("This server does not let the firewall register itself. Type a client id and secret.");
    };
    let supported = &meta.token_endpoint_auth_methods_supported;
    // A secret kept on the firewall is safer than none, but a server that only takes public clients gets one.
    let auth_method = match supported {
        None => "client_secret_post",
        Some(s) if s.iter().any(|m| m == "client_secret_post") => "client_secret_post",
        Some(s) if s.iter().any(|m| m == "client_secret_basic") => "client_secret_basic",
        Some(_) => "none",
    };
    let body = json!({"client_name": name, "redirect_uris": [redirect_uri], "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"], "token_endpoint_auth_method": auth_method});
    let url = Url::parse(endpoint).map_err(|e| McpOauthError(e.to_string()))?;
    let req = Request {
        method: "POST",
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("accept".into(), "application/json".into()),
        ],
        body: Some(Bytes::from(js::stringify(&body))),
        ..Request::default()
    };
    let answer = public_fetch(&url, req, MAX_META)
        .await
        .map_err(|e| McpOauthError(format!("The firewall could not register with the server: {e}.")))?;
    let doc = json_of(&answer);
    let client_id = doc.as_ref().and_then(|d| d.get("client_id")).and_then(Value::as_str);
    let Some(client_id) = client_id.filter(|_| answer.status < 300) else {
        return err(format!(
            "The server refused the firewall's registration: {}.",
            why(doc.as_ref(), answer.status)
        ));
    };
    let secret = doc
        .as_ref()
        .and_then(|d| d.get("client_secret"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let method = doc
        .as_ref()
        .and_then(|d| d.get("token_endpoint_auth_method"))
        .and_then(Value::as_str);
    let auth_method = match (secret, method) {
        (None, _) => "none",
        (Some(_), Some(m @ ("client_secret_basic" | "client_secret_post"))) => m,
        (Some(_), _) if auth_method == "none" => "client_secret_post",
        _ => auth_method,
    };
    Ok(OauthClient {
        client_id: client_id.to_string(),
        client_secret: secret.map(str::to_string),
        auth_method: auth_method.into(),
        registered: true,
        extra: Map::new(),
    })
}

pub struct Authorization {
    pub url: String,
    pub state: String,
    pub verifier: String,
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The address a person opens to sign in, and the two values the callback is checked and finished with.
pub fn authorization_url(
    d: &OauthDiscovery,
    client: &OauthClient,
    redirect_uri: &str,
) -> Result<Authorization, McpOauthError> {
    let verifier = b64url(&rand::random::<[u8; 32]>());
    let state = b64url(&rand::random::<[u8; 24]>());
    let mut url = Url::parse(&d.meta.authorization_endpoint).map_err(|e| McpOauthError(e.to_string()))?;
    // `searchParams.set`: one of each, so a parameter the endpoint already had is replaced.
    const SET: &[&str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "resource",
        "scope",
    ];
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| !SET.contains(&k.as_ref()) || (k == "scope" && d.scope.is_none()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in &kept {
            q.append_pair(k, v);
        }
        q.append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", &state)
            .append_pair("code_challenge", &b64url(&Sha256::digest(verifier.as_bytes())))
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", &d.resource);
        if let Some(s) = &d.scope {
            q.append_pair("scope", s);
        }
    }
    Ok(Authorization {
        url: url.to_string(),
        state,
        verifier,
    })
}

/// `encodeURIComponent`.
fn enc(s: &str) -> String {
    crate::integrations::connectors::runtime::enc(s)
}

async fn token_request(
    d: &OauthDiscovery,
    client: &OauthClient,
    params: Vec<(&str, String)>,
    now: f64,
) -> Result<OauthTokens, McpOauthError> {
    let mut form: Vec<(String, String)> = params.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    form.push(("resource".into(), d.resource.clone()));
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
    ];
    match (&client.auth_method[..], &client.client_secret) {
        ("client_secret_basic", Some(secret)) => {
            let pair = format!("{}:{}", enc(&client.client_id), enc(secret));
            headers.push((
                "authorization".into(),
                format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair)),
            ));
        }
        (method, secret) => {
            form.push(("client_id".into(), client.client_id.clone()));
            if method == "client_secret_post"
                && let Some(s) = secret
            {
                form.push(("client_secret".into(), s.clone()));
            }
        }
    }
    let encoded = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &form {
            ser.append_pair(k, v);
        }
        ser.finish()
    };
    let url = Url::parse(&d.meta.token_endpoint).map_err(|e| McpOauthError(e.to_string()))?;
    let req = Request {
        method: "POST",
        headers,
        body: Some(Bytes::from(encoded)),
        timeout: Duration::from_secs(15),
    };
    let answer = public_fetch(&url, req, MAX_META)
        .await
        .map_err(|e| McpOauthError(format!("The firewall could not reach the sign-in server: {e}.")))?;
    let doc = json_of(&answer);
    let access = doc
        .as_ref()
        .and_then(|d| d.get("access_token"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let Some(access) = access.filter(|_| answer.status < 300) else {
        return err(format!(
            "The sign-in server refused: {}.",
            why(doc.as_ref(), answer.status)
        ));
    };
    let doc = doc.unwrap_or_default();
    let expires_in = match doc.get("expires_in") {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    let refresh = params
        .iter()
        .find(|(k, _)| *k == "refresh_token")
        .map(|(_, v)| v.clone());
    Ok(OauthTokens {
        access_token: access,
        refresh_token: doc
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or(refresh),
        expires_at: expires_in
            .filter(|e| e.is_finite() && *e > 0.0)
            .map(|e| now + e * 1000.0),
        scope: doc.get("scope").and_then(Value::as_str).map(str::to_string),
        account: id_token_account(doc.get("id_token")),
        extra: Map::new(),
    })
}

/// The code from the callback, for tokens.
pub async fn exchange_code(
    d: &OauthDiscovery,
    client: &OauthClient,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    now: f64,
) -> Result<OauthTokens, McpOauthError> {
    token_request(
        d,
        client,
        vec![
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            ("code_verifier", verifier.into()),
            ("redirect_uri", redirect_uri.into()),
        ],
        now,
    )
    .await
}

pub async fn refresh_tokens(
    d: &OauthDiscovery,
    client: &OauthClient,
    refresh_token: &str,
    now: f64,
) -> Result<OauthTokens, McpOauthError> {
    token_request(
        d,
        client,
        vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh_token.into()),
        ],
        now,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        let h = r#"Bearer error="invalid_token", resource_metadata="https://a.example/.well-known/oauth-protected-resource/mcp", scope=read"#;
        assert_eq!(
            auth_param(Some(h), "resource_metadata").as_deref(),
            Some("https://a.example/.well-known/oauth-protected-resource/mcp")
        );
        assert_eq!(auth_param(Some(h), "scope").as_deref(), Some("read"));
        assert_eq!(auth_param(None, "scope"), None);
        let server = Url::parse("https://a.example/v1/mcp").expect("url");
        assert!(resource_matches("https://a.example/v1/mcp/", &server));
        assert!(resource_matches("https://a.example", &server));
        assert!(resource_matches("https://a.example/v1", &server));
        assert!(!resource_matches("https://b.example/v1/mcp", &server));
        assert!(!resource_matches("https://a.example/v2", &server));
        let claims = b64url(br#"{"email":"ana@example.com\u0000","name":"Ana"}"#);
        assert_eq!(
            id_token_account(Some(&json!(format!("x.{claims}.y")))).as_deref(),
            Some("ana@example.com")
        );
        assert_eq!(id_token_account(Some(&json!("nope"))), None);
    }

    #[test]
    fn the_sign_in_address_sets_each_parameter_once() {
        let d = OauthDiscovery {
            resource: "https://a.example/mcp".into(),
            meta: AuthServerMeta {
                issuer: "https://a.example".into(),
                authorization_endpoint: "https://a.example/authorize?redirect_uri=https://other/cb&state=x&tenant=t1"
                    .into(),
                token_endpoint: "https://a.example/token".into(),
                registration_endpoint: None,
                code_challenge_methods_supported: None,
                token_endpoint_auth_methods_supported: None,
                scopes_supported: None,
                extra: Map::new(),
            },
            scope: None,
            extra: Map::new(),
        };
        let client = OauthClient {
            client_id: "c".into(),
            client_secret: None,
            auth_method: "none".into(),
            registered: true,
            extra: Map::new(),
        };
        let a = authorization_url(&d, &client, "https://cp.example/oauth/callback").expect("url");
        let u = Url::parse(&a.url).expect("url");
        let all = |k: &str| {
            u.query_pairs()
                .filter(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(all("redirect_uri"), ["https://cp.example/oauth/callback"]);
        assert_eq!(all("state"), std::slice::from_ref(&a.state));
        assert_eq!(all("tenant"), ["t1"], "the endpoint's own parameters stay");
    }
}
