//! Talking to Google's OAuth and API endpoints (`google-tokens.ts`, docs/plans/google-account.md
//! §2, §3): the primitives every Google route shares (the two "is this refusal permanent?"
//! readings), and the org account's authorization URL, PKCE pair, code exchange and service probes.
//! Nothing here writes to a store.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::http::{GoogleHttp, Req, post_form};

pub const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// The OAuth errors that mean the grant is gone. Anything else is retryable: retrying a dead grant
/// is cheap, disconnecting a live one is not.
const FATAL_OAUTH_ERRORS: [&str; 5] = [
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "invalid_scope",
    "access_denied",
];

/// `str`: a non-empty string.
pub fn s(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|x| !x.is_empty()).map(str::to_string)
}

/// Whether Google's OAuth answer means "stop asking".
pub fn is_permanent_refusal(status: u16, body: &Map<String, Value>) -> bool {
    (status == 400 || status == 401) && s(body.get("error")).is_some_and(|c| FATAL_OAUTH_ERRORS.contains(&c.as_str()))
}

const FATAL_API_REASONS: [&str; 7] = [
    "accessNotConfigured",
    "forbidden",
    "insufficientFilePermissions",
    "insufficientPermissions",
    "authError",
    "unauthorized",
    "domainPolicy",
];
const TRANSIENT_API_REASONS: [&str; 7] = [
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "dailyLimitExceeded",
    "quotaExceeded",
    "backendError",
    "RESOURCE_EXHAUSTED",
    "UNAVAILABLE",
];

/// The API error object, when the body has one.
pub fn api_error(body: &Map<String, Value>) -> Option<&Map<String, Value>> {
    body.get("error").and_then(Value::as_object)
}

/// Whether a Google API answer means "stop asking", as opposed to "ask again in a minute". Both
/// error shapes are read; an unrecognised 403 falls back to the message, so an API never enabled is
/// never mistaken for a throttle.
pub fn is_permanent_api_refusal(status: u16, body: &Map<String, Value>) -> bool {
    if status == 401 {
        return true;
    }
    if status != 403 {
        return false;
    }
    let e = api_error(body);
    let reason = e
        .and_then(|e| e.get("errors"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|x| x.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let grpc = e.and_then(|e| e.get("status")).and_then(Value::as_str).unwrap_or("");
    if TRANSIENT_API_REASONS.contains(&reason) || TRANSIENT_API_REASONS.contains(&grpc) {
        return false;
    }
    if FATAL_API_REASONS.contains(&reason) || grpc == "PERMISSION_DENIED" {
        return true;
    }
    let msg = e
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    ["has not been used in project", "is disabled", "has not been enabled"]
        .iter()
        .any(|p| msg.contains(p))
}

/// Google answers `{error, error_description}` on every OAuth route; say what it said.
pub fn reason_of(body: &Map<String, Value>, status: u16) -> String {
    s(body.get("error_description"))
        .or_else(|| s(body.get("error")))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

/// A sentence ends in `.`, `!` or `?`; one that does not gets a full stop.
pub fn ensure_sentence(text: &str) -> String {
    if text.ends_with(['.', '!', '?']) {
        text.to_string()
    } else {
        format!("{text}.")
    }
}

// ---- the org's Google account ----

pub const GOOGLE_IDENTITY_SCOPES: [&str; 2] = ["openid", "email"];
pub const GOOGLE_SERVICES: [&str; 6] = ["gmail", "calendar", "drive", "contacts", "sheets", "docs"];

pub fn is_google_service(v: &str) -> bool {
    GOOGLE_SERVICES.contains(&v)
}
pub fn is_gmail_scope(v: &str) -> bool {
    matches!(v, "full" | "readonly" | "send" | "read-send")
}
pub fn is_drive_scope_choice(v: &str) -> bool {
    matches!(v, "full" | "readonly" | "file")
}

const AUTH: &str = "https://www.googleapis.com/auth/";

fn gmail_scopes(choice: &str) -> Vec<String> {
    let names: &[&str] = match choice {
        "full" => &["gmail.modify", "gmail.settings.basic", "gmail.settings.sharing"],
        "readonly" => &["gmail.readonly"],
        "send" => &["gmail.send"],
        _ => &["gmail.readonly", "gmail.send"],
    };
    names.iter().map(|n| format!("{AUTH}{n}")).collect()
}

fn drive_scopes(choice: &str) -> String {
    match choice {
        "full" => format!("{AUTH}drive"),
        "file" => format!("{AUTH}drive.file"),
        _ => format!("{AUTH}drive.readonly"),
    }
}

/// What a person reads for a scope: the permission's name on Google's consent screen, roughly.
pub fn scope_name(scope: &str) -> String {
    let name = match scope.strip_prefix(AUTH).unwrap_or("") {
        "gmail.readonly" => "read Gmail",
        "gmail.send" => "send email from Gmail",
        "gmail.modify" => "read, send and organise Gmail",
        "gmail.settings.basic" => "manage Gmail settings",
        "gmail.settings.sharing" => "manage Gmail sharing settings",
        "calendar" => "see and change Calendar",
        "drive" => "see and change all Drive files",
        "drive.readonly" => "see Drive files",
        "drive.file" => "use Drive files opened with this app",
        "contacts" => "see and change Contacts",
        "contacts.other.readonly" => "see other contacts",
        "spreadsheets" => "see and change Sheets",
        "spreadsheets.readonly" => "see Sheets",
        "documents" => "see and change Docs",
        "documents.readonly" => "see Docs",
        _ => return scope.replacen(AUTH, "", 1),
    };
    name.into()
}

/// The asked-for scopes Google did not grant (a person can untick any on the consent screen). The
/// identity scopes are not counted.
pub fn missing_scopes(requested: &[String], granted: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|s| !GOOGLE_IDENTITY_SCOPES.contains(&s.as_str()) && !granted.contains(s))
        .cloned()
        .collect()
}

/// Best effort: give back a grant we are not going to keep. Never fails.
pub async fn revoke_google_token(http: &dyn GoogleHttp, token: &str) {
    let url = format!(
        "https://oauth2.googleapis.com/revoke?token={}",
        crate::core::permissions::encode_uri_component(token)
    );
    let _ = http
        .send(Req {
            method: "POST",
            url,
            headers: vec![("content-type".into(), "application/x-www-form-urlencoded".into())],
            body: None,
            timeout: std::time::Duration::from_secs(10),
        })
        .await;
}

/// The scopes to ask consent for, deduplicated. Only Gmail and Drive are narrowable; Sheets and
/// Docs follow the Drive choice; Calendar and Contacts do not.
pub fn scopes_for(services: &[String], gmail_scope: &str, drive_scope: &str) -> Vec<String> {
    let mut out: Vec<String> = GOOGLE_IDENTITY_SCOPES.iter().map(|s| s.to_string()).collect();
    let mut add = |s: String| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    let ro = drive_scope == "readonly";
    for service in services {
        match service.as_str() {
            "gmail" => gmail_scopes(gmail_scope).into_iter().for_each(&mut add),
            "calendar" => add(format!("{AUTH}calendar")),
            "drive" => add(drive_scopes(drive_scope)),
            "contacts" => {
                add(format!("{AUTH}contacts"));
                add(format!("{AUTH}contacts.other.readonly"));
            }
            "sheets" => {
                add(drive_scopes(drive_scope));
                add(format!(
                    "{AUTH}{}",
                    if ro { "spreadsheets.readonly" } else { "spreadsheets" }
                ));
            }
            "docs" => {
                add(drive_scopes(drive_scope));
                add(format!("{AUTH}{}", if ro { "documents.readonly" } else { "documents" }));
            }
            _ => {}
        }
    }
    out
}

/// A PKCE pair (S256). The verifier stays on this box for the life of one authorization.
pub fn make_pkce() -> (String, String) {
    let mut raw = [0u8; 48];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// The `state` that routes a callback back to the change that started it.
pub fn make_state() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>())
}

/// Where to send the person to consent. `access_type=offline` with `prompt=consent` makes Google
/// return a refresh token every time; `include_granted_scopes` is deliberately not set.
pub fn authorize_url(
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    challenge: &str,
    login_hint: Option<&str>,
) -> String {
    let mut url = url::Url::parse(GOOGLE_AUTH_ENDPOINT).expect("url");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");
        if let Some(h) = login_hint.filter(|h| !h.is_empty()) {
            q.append_pair("login_hint", h);
        }
    }
    url.to_string()
}

pub enum Exchange {
    Ok {
        refresh: String,
        access: String,
        /// Absolute ms.
        expires: i64,
        account_label: Option<String>,
        granted_scopes: Vec<String>,
    },
    /// The callback asks for a new authorization either way: Google will not take a code twice.
    Err { reason: String },
}

pub struct ExchangeInput<'a> {
    pub code: &'a str,
    pub verifier: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub token_endpoint: &'a str,
}

fn expires_in(body: &Map<String, Value>) -> i64 {
    body.get("expires_in").and_then(Value::as_f64).unwrap_or(3600.0) as i64
}

/// Turn the `code` the person's browser came back with into a refresh token. A missing
/// `refresh_token` is a failure: the connection would work for an hour and then die.
pub async fn exchange_code(http: &dyn GoogleHttp, o: ExchangeInput<'_>, now: i64) -> Exchange {
    let endpoint = if o.token_endpoint.is_empty() {
        GOOGLE_TOKEN_ENDPOINT
    } else {
        o.token_endpoint
    };
    let (status, body) = match post_form(
        http,
        endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", o.code),
            ("code_verifier", o.verifier),
            ("client_id", o.client_id),
            ("client_secret", o.client_secret),
            ("redirect_uri", o.redirect_uri),
        ],
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            return Exchange::Err {
                reason: e.reason().into(),
            };
        }
    };
    let Some(access) = s(body.get("access_token")).filter(|_| status == 200) else {
        return Exchange::Err {
            reason: ensure_sentence(&reason_of(&body, status)),
        };
    };
    let Some(refresh) = s(body.get("refresh_token")) else {
        return Exchange::Err {
            reason: "Google returned no refresh token, so the connection would stop working within the hour. \
                     This happens when the account has already authorized this app: remove ControlClaw's access \
                     at myaccount.google.com/permissions and connect again."
                .into(),
        };
    };
    Exchange::Ok {
        refresh,
        access,
        expires: now + expires_in(&body) * 1000,
        account_label: email_from_id_token(s(body.get("id_token")).as_deref()),
        granted_scopes: s(body.get("scope"))
            .unwrap_or_default()
            .split(' ')
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect(),
    }
}

/// The `email` claim of an `id_token`. Not verified, and need not be: it came back over TLS from
/// Google's token endpoint in answer to a request carrying the client secret. Only a label.
pub fn email_from_id_token(id_token: Option<&str>) -> Option<String> {
    let part = id_token?.split('.').nth(1)?;
    let raw = URL_SAFE_NO_PAD.decode(part.trim_end_matches('=')).ok()?;
    let claims: Value = serde_json::from_slice(&raw).ok()?;
    s(claims.get("email"))
}

/// What a refresh answered.
pub enum Mint {
    Ok {
        token: String,
        expires: i64,
        refresh: Option<String>,
    },
    Err {
        permanent: bool,
        reason: String,
        rate_limited: bool,
    },
}

/// Spend a refresh token. Google requires the client secret on a refresh.
pub async fn refresh_token(
    http: &dyn GoogleHttp,
    endpoint: &str,
    refresh: &str,
    client_id: &str,
    client_secret: &str,
    now: i64,
) -> Mint {
    let (status, body) = match post_form(
        http,
        endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ],
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            return Mint::Err {
                permanent: false,
                reason: e.reason().into(),
                rate_limited: false,
            };
        }
    };
    mint_answer(status, &body, now, Some(refresh))
}

/// A token endpoint's answer, read the same way for a refresh and a service-account assertion. A
/// throttle is a 429 or an `error` naming a rate limit.
pub fn mint_answer(status: u16, body: &Map<String, Value>, now: i64, refresh: Option<&str>) -> Mint {
    match s(body.get("access_token")).filter(|_| status == 200) {
        Some(token) => Mint::Ok {
            token,
            expires: now + expires_in(body) * 1000,
            refresh: s(body.get("refresh_token")).filter(|r| Some(r.as_str()) != refresh),
        },
        None => {
            let code = s(body.get("error")).unwrap_or_default().to_lowercase();
            Mint::Err {
                permanent: is_permanent_refusal(status, body),
                reason: reason_of(body, status),
                rate_limited: status == 429 || code.contains("rate_limit") || code.contains("ratelimit"),
            }
        }
    }
}

fn probe_url(service: &str) -> Option<(&'static str, &'static str)> {
    Some(match service {
        "gmail" => ("https://gmail.googleapis.com/gmail/v1/users/me/profile", "Gmail API"),
        "calendar" => (
            "https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1",
            "Calendar API",
        ),
        "drive" | "sheets" | "docs" => (
            "https://www.googleapis.com/drive/v3/files?pageSize=1&fields=files(id)",
            "Drive API",
        ),
        "contacts" => (
            "https://people.googleapis.com/v1/people/me/connections?personFields=names&pageSize=1",
            "People API",
        ),
        _ => return None,
    })
}

pub struct Refusal {
    pub service: String,
    pub permanent: bool,
    pub reason: String,
}

/// One cheap call per granted service: a token mints for a project whose API was never enabled.
/// Send-only Gmail is not probed (nothing read-free proves the API is on).
pub async fn probe_services(
    http: &dyn GoogleHttp,
    token: &str,
    services: &[String],
    gmail_scope: &str,
) -> Vec<Refusal> {
    let mut out = vec![];
    let mut seen: Vec<&str> = vec![];
    for service in services {
        if service == "gmail" && gmail_scope == "send" {
            continue;
        }
        let Some((url, _api)) = probe_url(service) else {
            continue;
        };
        if seen.contains(&url) {
            continue;
        }
        seen.push(url);
        if let Err((permanent, reason)) = probe_one(http, token, url).await {
            out.push(Refusal {
                service: service.clone(),
                permanent,
                reason,
            });
        }
    }
    out
}

/// Google's own sentence, trimmed of the "If you enabled this API recently…" tail.
pub fn google_message(body: &Map<String, Value>, fallback: String, tail: &str) -> String {
    let msg = api_error(body).and_then(|e| s(e.get("message"))).unwrap_or(fallback);
    ensure_sentence(msg.split(tail).next().unwrap_or("").trim())
}

async fn probe_one(http: &dyn GoogleHttp, token: &str, url: &str) -> Result<(), (bool, String)> {
    let res = http
        .send(Req::get(url, token))
        .await
        .map_err(|e| (false, e.reason().to_string()))?;
    if res.ok() {
        return Ok(());
    }
    let body = res.json();
    Err((
        is_permanent_api_refusal(res.status, &body),
        google_message(&body, format!("Google answered {}", res.status), " If you enabled"),
    ))
}
