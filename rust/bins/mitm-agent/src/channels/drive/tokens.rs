//! Where a Drive access token comes from (`drive-tokens.ts`): a service-account assertion signed
//! here, an OAuth refresh, or nothing at all for a connection that borrows the org Google account.
//! Plus the Drive probe, the error reading, and the write check. No source writes to the store.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};

use super::store::{DRIVE_READ_SCOPE, DRIVE_WRITE_SCOPE, DriveAccount, DriveSecret};
use crate::channels::google::http::{GOOGLE_TIMEOUT, GoogleHttp, Req, post_form};
use crate::channels::google::tokens::{
    Mint, api_error, ensure_sentence, is_permanent_api_refusal, mint_answer, refresh_token, s,
};

/// Google's own ceiling for a service-account assertion.
const ASSERTION_TTL_SEC: i64 = 3600;

/// The org Google account as Drive folders see it, read on demand and never stored here.
pub use crate::channels::google::DriveAccess as Borrowed;

/// The Drive scope a borrowed account can back, or `None`: `drive.file` would mount empty.
pub fn scope_for_borrowed(account: Option<&Borrowed>) -> Option<&'static str> {
    match account.and_then(|a| a.drive_scope) {
        Some("full") => Some(DRIVE_WRITE_SCOPE),
        Some("readonly") => Some(DRIVE_READ_SCOPE),
        _ => None,
    }
}

/// A Mint, plus the rotated secret and the label a source can report.
pub struct Minted {
    pub mint: Mint,
    pub secret: Option<DriveSecret>,
    pub account_label: Option<String>,
}

fn refused(permanent: bool, reason: impl Into<String>) -> Minted {
    Minted {
        mint: Mint::Err {
            permanent,
            reason: reason.into(),
            rate_limited: false,
        },
        secret: None,
        account_label: None,
    }
}

/// The PEM body of a PKCS#8 key, as DER.
fn pkcs8_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    STANDARD.decode(body).ok()
}

/// The signed RS256 assertion for a service account.
pub fn sign_assertion(
    client_email: &str,
    private_key: &str,
    token_uri: &str,
    subject: Option<&str>,
    scope: &str,
    now_ms: i64,
) -> Option<String> {
    let der = pkcs8_der(private_key)?;
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der).ok()?;
    let iat = now_ms / 1000;
    let mut claims = json!({"scope": scope});
    if let Some(sub) = subject {
        claims["sub"] = json!(sub);
    }
    claims["iss"] = json!(client_email);
    claims["aud"] = json!(token_uri);
    claims["iat"] = json!(iat);
    claims["exp"] = json!(iat + ASSERTION_TTL_SEC);
    let head = URL_SAFE_NO_PAD.encode(json!({"alg": "RS256", "typ": "JWT"}).to_string());
    let body = URL_SAFE_NO_PAD.encode(claims.to_string());
    let input = format!("{head}.{body}");
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .ok()?;
    Some(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// Mint for an account by its kind. A `google_account` connection has no source on purpose.
pub async fn mint(http: &dyn GoogleHttp, account: &DriveAccount, now: i64) -> Minted {
    match (account.kind.as_str(), &account.secret) {
        ("google_account", _) => refused(true, "This connection borrows the Google account's token."),
        (
            "service_account",
            Some(DriveSecret::ServiceAccount {
                client_email,
                private_key,
                token_uri,
                subject,
            }),
        ) => {
            let Some(assertion) = sign_assertion(
                client_email,
                private_key,
                token_uri,
                subject.as_deref(),
                &account.scope,
                now,
            ) else {
                // A key that will not parse or sign will never parse or sign.
                return refused(
                    true,
                    "The service account key could not be used: it is not an RSA private key in PKCS#8 PEM form.",
                );
            };
            let answer = post_form(
                http,
                token_uri,
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                    ("assertion", &assertion),
                ],
            )
            .await;
            match answer {
                Err(e) => refused(false, e.reason()),
                Ok((status, body)) => Minted {
                    mint: match mint_answer(status, &body, now, None) {
                        Mint::Ok { token, expires, .. } => Mint::Ok {
                            token,
                            expires,
                            refresh: None,
                        },
                        err => err,
                    },
                    secret: None,
                    account_label: Some(client_email.clone()),
                },
            }
        }
        ("service_account", _) => refused(true, "This connection is not a service account."),
        (_, Some(DriveSecret::OAuth { refresh })) => {
            let Some(o) = &account.oauth else {
                return refused(true, "This connection has no token endpoint.");
            };
            let m = refresh_token(http, &o.token_endpoint, refresh, &o.client_id, &o.client_secret, now).await;
            let secret = match &m {
                Mint::Ok { refresh: Some(r), .. } => Some(DriveSecret::OAuth { refresh: r.clone() }),
                _ => None,
            };
            Minted {
                mint: m,
                secret,
                account_label: None,
            }
        }
        _ => refused(true, "This connection is not an OAuth account."),
    }
}

/// What a refused Drive API call means for the person reading the message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriveErrorKind {
    RateLimited,
    StorageQuota,
    NoAccess,
    Other,
}

const RATE_LIMIT_REASONS: [&str; 4] = [
    "userRateLimitExceeded",
    "rateLimitExceeded",
    "dailyLimitExceeded",
    "quotaExceeded",
];
const NO_ACCESS_REASONS: [&str; 7] = [
    "insufficientFilePermissions",
    "insufficientPermissions",
    "forbidden",
    "notFound",
    "cannotAddParent",
    "domainPolicy",
    "appNotAuthorizedToFile",
];

fn message_of(body: &Map<String, Value>) -> Option<String> {
    api_error(body).and_then(|e| s(e.get("message")))
}

pub fn classify_drive_error(status: u16, body: &Map<String, Value>) -> DriveErrorKind {
    let e = api_error(body);
    let reasons: Vec<&str> = e
        .and_then(|e| e.get("errors"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| x.get("reason").and_then(Value::as_str).unwrap_or(""))
                .collect()
        })
        .unwrap_or_default();
    let grpc = e.and_then(|e| e.get("status")).and_then(Value::as_str).unwrap_or("");
    let message = message_of(body).unwrap_or_default().to_lowercase();
    if status == 429 || reasons.iter().any(|r| RATE_LIMIT_REASONS.contains(r)) {
        return DriveErrorKind::RateLimited;
    }
    if reasons.contains(&"storageQuotaExceeded") || message.contains("storage quota") {
        return DriveErrorKind::StorageQuota;
    }
    if grpc == "RESOURCE_EXHAUSTED" {
        return DriveErrorKind::RateLimited;
    }
    if reasons.is_empty() && grpc.is_empty() && message.contains("rate limit exceeded") {
        return DriveErrorKind::RateLimited;
    }
    if reasons.iter().any(|r| NO_ACCESS_REASONS.contains(r)) || grpc == "PERMISSION_DENIED" || grpc == "NOT_FOUND" {
        return DriveErrorKind::NoAccess;
    }
    if status == 403 || status == 404 {
        return DriveErrorKind::NoAccess;
    }
    DriveErrorKind::Other
}

/// Ask Drive one cheap question with a fresh token: a token mints for a project whose Drive API
/// was never enabled.
pub async fn probe_drive(http: &dyn GoogleHttp, token: &str) -> Result<(), (bool, String)> {
    let res = http
        .send(Req::get(
            "https://www.googleapis.com/drive/v3/files?pageSize=1&fields=files(id)",
            token,
        ))
        .await
        .map_err(|e| (false, e.reason().to_string()))?;
    if res.ok() {
        return Ok(());
    }
    let body = res.json();
    if classify_drive_error(res.status, &body) == DriveErrorKind::RateLimited {
        return Err((false, "Google is limiting requests right now.".into()));
    }
    let message = message_of(&body).unwrap_or_else(|| format!("Drive answered {}", res.status));
    Err((
        is_permanent_api_refusal(res.status, &body),
        ensure_sentence(message.split(" If you enabled").next().unwrap_or("").trim()),
    ))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), in ms.
fn http_date_ms(v: &str) -> Option<i64> {
    let parts: Vec<&str> = v.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    let m = MONTHS.iter().position(|x| x == month)? as i64 + 1;
    let hms: Vec<i64> = time.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let [h, mi, se] = hms.as_slice() else { return None };
    let days = days_from_civil(year.parse().ok()?, m, day.parse().ok()?);
    Some(((days * 86_400) + h * 3600 + mi * 60 + se) * 1000)
}

/// `Retry-After` as seconds or an HTTP date, in ms from `now`.
pub fn retry_after_ms(header: Option<&str>, now: i64) -> Option<i64> {
    let t = header?.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        // Saturating: a huge number is "later than any budget", never an overflow.
        return Some(t.parse::<i64>().map_or(i64::MAX, |n| n.saturating_mul(1000)));
    }
    http_date_ms(t).map(|at| (at - now).max(0))
}

/// The write check's whole budget, retries included (the console waits 30 s for a change).
pub const WRITE_CHECK_BUDGET_MS: i64 = 20_000;
const WRITE_CHECK_TRIES: u32 = 3;
const WRITE_CHECK_BACKOFF_MS: f64 = 2_000.0;
const MIN_ATTEMPT_MS: i64 = 2_000;

#[derive(Debug, Clone, PartialEq)]
pub enum WriteCheck {
    Ok,
    Refused {
        kind: DriveErrorKind,
        transient: bool,
        reason: String,
    },
}

/// The write check's clock, sleep and jitter, so tests can run the retries without waiting.
#[derive(Clone)]
pub struct WriteCheckOptions {
    pub sleep: Arc<dyn Fn(i64) -> cc_http::BoxFuture<()> + Send + Sync>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
    pub random: Arc<dyn Fn() -> f64 + Send + Sync>,
    pub budget_ms: i64,
}

impl Default for WriteCheckOptions {
    fn default() -> Self {
        Self {
            sleep: Arc::new(|ms| Box::pin(tokio::time::sleep(Duration::from_millis(ms.max(0) as u64)))),
            now: Arc::new(crate::channels::now_ms),
            random: Arc::new(rand::random::<f64>),
            budget_ms: WRITE_CHECK_BUDGET_MS,
        }
    }
}

/// Can this identity actually create a file in that folder? Editor permission is not enough (a
/// service account owns no storage), so it does the thing: a one-byte media upload, then a delete
/// not waited for. Transient answers are retried inside the budget.
pub async fn probe_folder_write(
    http: Arc<dyn GoogleHttp>,
    token: &str,
    folder_id: &str,
    o: &WriteCheckOptions,
) -> WriteCheck {
    let deadline = (o.now)() + o.budget_ms;
    let mut attempt = 1;
    loop {
        let left = deadline - (o.now)();
        let timeout = (GOOGLE_TIMEOUT.as_millis() as i64).min(left.max(MIN_ATTEMPT_MS));
        let (result, retry_after) = write_once(&http, token, folder_id, timeout, &*o.now).await;
        let transient = matches!(result, WriteCheck::Refused { transient: true, .. });
        if !transient || attempt >= WRITE_CHECK_TRIES {
            return result;
        }
        let backoff = WRITE_CHECK_BACKOFF_MS * 3f64.powi(attempt as i32 - 1) * (0.5 + (o.random)());
        let wait = (backoff as i64).max(retry_after.unwrap_or(0));
        // A wait past the budget is not waited: the last answer stands.
        if (o.now)().saturating_add(wait).saturating_add(MIN_ATTEMPT_MS) > deadline {
            return result;
        }
        (o.sleep)(wait).await;
        attempt += 1;
    }
}

async fn write_once(
    http: &Arc<dyn GoogleHttp>,
    token: &str,
    folder_id: &str,
    timeout_ms: i64,
    now: &(dyn Fn() -> i64 + Send + Sync),
) -> (WriteCheck, Option<i64>) {
    let boundary = "cc-write-check";
    let metadata = json!({"name": ".controlclaw-write-check", "parents": [folder_id]}).to_string();
    let body = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\nx\r\n--{boundary}--"
    );
    let res = http
        .send(Req {
            method: "POST",
            url:
                "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true&fields=id"
                    .into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {token}")),
                ("content-type".into(), format!("multipart/related; boundary={boundary}")),
            ],
            body: Some(body.into_bytes()),
            timeout: Duration::from_millis(timeout_ms.max(1) as u64),
        })
        .await;
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            return (
                WriteCheck::Refused {
                    kind: DriveErrorKind::Other,
                    transient: true,
                    reason: e.reason().into(),
                },
                None,
            );
        }
    };
    let body = res.json();
    if !res.ok() {
        let kind = classify_drive_error(res.status, &body);
        let message = message_of(&body).unwrap_or_else(|| format!("Drive refused the write with {}.", res.status));
        return (
            WriteCheck::Refused {
                kind,
                // A 5xx is Google having a bad moment, not an answer about the folder.
                transient: kind == DriveErrorKind::RateLimited || res.status >= 500,
                reason: ensure_sentence(message.split(" Leverage shared drives").next().unwrap_or("").trim()),
            },
            retry_after_ms(res.header("retry-after"), now()),
        );
    }
    let Some(id) = s(body.get("id")) else {
        return (
            WriteCheck::Refused {
                kind: DriveErrorKind::Other,
                transient: false,
                reason: format!("Drive answered {} without creating the file.", res.status),
            },
            None,
        );
    };
    // Not waited for: the answer is known, and a hung delete must not hold the change open.
    let (h, t) = (http.clone(), token.to_string());
    tokio::spawn(async move {
        let _ = h
            .send(Req {
                method: "DELETE",
                url: format!(
                    "https://www.googleapis.com/drive/v3/files/{}?supportsAllDrives=true",
                    crate::core::permissions::encode_uri_component(&id)
                ),
                headers: vec![("authorization".into(), format!("Bearer {t}"))],
                body: None,
                timeout: GOOGLE_TIMEOUT,
            })
            .await;
    });
    (WriteCheck::Ok, None)
}
