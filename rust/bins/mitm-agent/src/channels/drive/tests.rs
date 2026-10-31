//! `drive.test.ts` and `drive-tokens.test.ts`: the token sources, the error readings, the write
//! check, and the folders module against a fake agent box, a fake Google and a borrowed account.

#![allow(clippy::unwrap_used, clippy::type_complexity)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cc_http::BoxFuture;
use serde_json::{Map, Value, json};

use super::tokens::*;
use super::*;
use crate::channels::agent::{AgentCalls, AgentError, Target};
use crate::channels::google::http::{GoogleHttp, HttpErr, Req, Resp};
use crate::contracts::SendResult;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// A throwaway RSA key, made for these tests.
const SA_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDE8MEF+TEOKd1c\nRqpRSI3FBkvob+8RCVdSDEsX+thci8SV91I7519Bilg7HM3HRSp0McDRN0x6GHoj\n+CjT0m1ZkrzKAw/MzI/1v8ORQ00aIjNUZMGESLfd/iWqk15t3rQj7vNi2QwUG45w\nqAtP5uvz9pcvLiY7E2gVGXFryAxwqRd2PnuQX+yur/ZaoIpoU979b1Q9cQFP4irW\nDXYdzerFa/Zo2Izf4avRX9fZ6rS0qsExPp3CCihNppayBCiLxsaXWkWzrvRSy2ct\na2ZSp5TxibosXt26v8pZ8KUjFqwTKnNR+VL50RgxjWbjZUKot57lOd81P2nxhOWe\njeI3ei4tAgMBAAECggEABdFW4mZKHLD/6QntXhlWlsto0qT72vT7r2DNlxfB7Hn0\nhLmZpEthdP4xPQ3MxmY0qtoNaCDKEZFHimh6TEebE1pSWWVdwh8I4amYjWH/lRYN\njiCr1syPIe+wDSntUDGUALu+VN00jiOCQbG1I9cegUZ3kN08I+Ke4ICv6Q8vzuQi\nkn12eG1peJCWnwqZQ5YKSF8XI05TXsVP1L0yQL3eN1R73ikIbwNOv8ayDJ2sPf1z\ndf7wqyiaVDX3jD+VaqmPZFvIu2welrJr0kPcDSIiJw3iKYJs4uN2Iq8f5K8tQTTs\nVcKw6TqTOTE+u5OoCW3HSpYqs0DKOgQoY0b+bvpHwQKBgQDvE4mynIxCSPMkq2uj\nidEq/dNUMeMr2T1tcTME/eF2QJrlueQo8VJzUbDXs2Br7KSxTyTNomR7V/D0Kopi\n9yFUunf9vxhNeToXogh5AtM42KmjsmF4CmKwTH6VZ5a21xNm9NJTXjx6gF6q+8lW\nMj4eVpnhqR8H4/LB/h0LmoupEwKBgQDS4aTKSg6nfcu8k4qMIk4XpYKtN0LmxeRl\nUjR+F3Hh2RZ14zL9UHHllB7kNWMHxKBRA6Jz0CPkY6/ZPplJg9sfoCqZg9CRUgd1\nAehwWqXoomQoik8QW7CJX0Ms2T4dYeJ7FVjkpKPlILlSijPGw/yUm6fBD+V6AzS6\n+WHNXE7zvwKBgQCDCOJf0w3NBs69Onc0m0TZm2VIsE8iqV7RrUmZYs1AUwiTAN/c\n0Oev7QZQMzCV9o4N4KL7UhZgxEJ8kRRoSasrFUjO+v4G+HqumVCrgrDiZ14TKqHh\neU+98S8wFCa28AriUy00JGJhghpg/L/NTpxdZHnTBS7M1FMpoG2q/nmtoQKBgQDA\n2JB2XVshWCykethMZmK7xSPHe622lGnVLmPKm24NdxTPIcJTXOmLZPULBLdXNzzU\nWVqKRmFMTs1VAaX0UJxmQ3YxhRWKj1U6b1A8zujB4R9u42yCLRc3yOIJdXEUNZuD\nq3XrQZSPyGkxTikjL78ft2ilaQAVoDDse3ow7qVUyQKBgHtx6qUO22J+7wgkmPDY\nHLhNtz32DDMRCL52hExAeQ4Nf8AAwal6b1hk1JT9wUK4tLz+GeA6q3F8Rh5P/mpP\n+dQ58aONzWo6RLsarRQprdY0+I9rSlE5JLSdHljvmdtgJcWvOl3yXW9NBDqKuJsi\n0fQv+bxX763FpiOnObQ7jlG7\n-----END PRIVATE KEY-----";
const NOW: i64 = 1_790_330_400_000;

/// Answers by URL fragment; a queue per fragment, the last answer repeats.
#[derive(Default)]
struct Google {
    answers: Mutex<Vec<(String, VecDeque<(u16, Value, Vec<(String, String)>)>)>>,
    seen: Mutex<Vec<(String, String, String)>>,
    down: AtomicBool,
}

impl Google {
    fn on(&self, needle: &str, answers: Vec<(u16, Value)>) {
        self.on_h(needle, answers.into_iter().map(|(s, b)| (s, b, vec![])).collect());
    }
    fn on_h(&self, needle: &str, answers: Vec<(u16, Value, Vec<(String, String)>)>) {
        let mut a = self.answers.lock().unwrap();
        a.retain(|(n, _)| n != needle);
        a.insert(0, (needle.into(), answers.into()));
    }
    fn hits(&self, needle: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, u, _)| u.contains(needle))
            .count()
    }
}

impl GoogleHttp for Arc<Google> {
    fn send(&self, req: Req) -> BoxFuture<Result<Resp, HttpErr>> {
        let me = self.clone();
        Box::pin(async move {
            let body = String::from_utf8(req.body.clone().unwrap_or_default()).unwrap_or_default();
            me.seen.lock().unwrap().push((req.method.into(), req.url.clone(), body));
            if me.down.load(Ordering::SeqCst) {
                return Err(HttpErr { timed_out: false });
            }
            let mut a = me.answers.lock().unwrap();
            for (needle, q) in a.iter_mut() {
                if req.url.contains(needle.as_str()) {
                    let (st, b, h) = if q.len() > 1 {
                        q.pop_front().unwrap()
                    } else {
                        q[0].clone()
                    };
                    return Ok(Resp {
                        status: st,
                        headers: h,
                        body: b.to_string().into_bytes(),
                    });
                }
            }
            Ok(Resp {
                status: 200,
                headers: vec![],
                body: json!({"files": []}).to_string().into_bytes(),
            })
        })
    }
}

fn form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
}

fn sa_account() -> DriveAccount {
    DriveAccount {
        kind: "service_account".into(),
        account_label: None,
        scope: store::DRIVE_WRITE_SCOPE.into(),
        oauth: None,
        secret: Some(DriveSecret::ServiceAccount {
            client_email: "drive@proj.iam.gserviceaccount.com".into(),
            private_key: SA_KEY.into(),
            token_uri: "https://oauth2.googleapis.com/token".into(),
            subject: None,
        }),
        access: None,
        failed: None,
        updated_at: "x".into(),
        extra: Map::new(),
    }
}

fn oauth_account() -> DriveAccount {
    DriveAccount {
        kind: "oauth".into(),
        oauth: Some(DriveOAuth {
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            client_id: "cid".into(),
            client_secret: "csec".into(),
        }),
        secret: Some(DriveSecret::OAuth { refresh: "1//r".into() }),
        ..sa_account()
    }
}

fn claims_of(assertion: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(assertion.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

#[tokio::test]
async fn a_service_account_signs_an_rs256_assertion_and_exchanges_it() {
    let g = Arc::new(Google::default());
    g.on(
        "oauth2.googleapis.com/token",
        vec![(200, json!({"access_token": "ya29.sa", "expires_in": 3600}))],
    );
    let m = mint(&g.clone(), &sa_account(), NOW).await;
    let Mint::Ok { token, expires, .. } = m.mint else {
        panic!("refused")
    };
    assert_eq!(token, "ya29.sa");
    assert_eq!(expires, NOW + 3_600_000);
    assert_eq!(m.account_label.as_deref(), Some("drive@proj.iam.gserviceaccount.com"));
    let (_, _, body) = g.seen.lock().unwrap()[0].clone();
    let f = form(&body);
    assert_eq!(f["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
    let assertion = &f["assertion"];
    let head: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(assertion.split('.').next().unwrap()).unwrap()).unwrap();
    assert_eq!(head, json!({"alg": "RS256", "typ": "JWT"}));
    let c = claims_of(assertion);
    assert_eq!(c["iss"], "drive@proj.iam.gserviceaccount.com");
    assert_eq!(c["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(c["scope"], store::DRIVE_WRITE_SCOPE);
    assert_eq!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(), 3600);
    assert!(c.get("sub").is_none());
    // The signature verifies with the key's public half.
    let der: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(SA_KEY.lines().filter(|l| !l.starts_with("-----")).collect::<String>())
        .unwrap();
    let kp = ring::signature::RsaKeyPair::from_pkcs8(&der).unwrap();
    let (input, sig) = assertion.rsplit_once('.').unwrap();
    use ring::signature::KeyPair;
    ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, kp.public_key().as_ref())
        .verify(input.as_bytes(), &URL_SAFE_NO_PAD.decode(sig).unwrap())
        .unwrap();
    // Domain-wide delegation puts the subject in.
    let mut a = sa_account();
    if let Some(DriveSecret::ServiceAccount { subject, .. }) = a.secret.as_mut() {
        *subject = Some("boss@acme.com".into());
    }
    mint(&g.clone(), &a, NOW).await;
    let (_, _, body) = g.seen.lock().unwrap()[1].clone();
    assert_eq!(claims_of(&form(&body)["assertion"])["sub"], "boss@acme.com");
    // A key that will not parse fails permanently, without calling Google.
    let mut bad = sa_account();
    if let Some(DriveSecret::ServiceAccount { private_key, .. }) = bad.secret.as_mut() {
        *private_key = "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----".into();
    }
    assert!(matches!(
        mint(&g.clone(), &bad, NOW).await.mint,
        Mint::Err { permanent: true, .. }
    ));
    assert_eq!(g.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn oauth_refresh_rotation_and_refusals() {
    let g = Arc::new(Google::default());
    g.on(
        "token",
        vec![(
            200,
            json!({"access_token": "ya29.o", "expires_in": 3600, "refresh_token": "1//r2"}),
        )],
    );
    let m = mint(&g.clone(), &oauth_account(), NOW).await;
    let f = form(&g.seen.lock().unwrap()[0].2);
    assert_eq!(
        (
            f["grant_type"].as_str(),
            f["client_secret"].as_str(),
            f["refresh_token"].as_str()
        ),
        ("refresh_token", "csec", "1//r")
    );
    assert_eq!(
        m.secret,
        Some(DriveSecret::OAuth {
            refresh: "1//r2".into()
        })
    );
    let case = |st: u16, body: Value| {
        let g = g.clone();
        async move {
            g.on("token", vec![(st, body)]);
            match mint(&g, &oauth_account(), NOW).await.mint {
                Mint::Err {
                    permanent,
                    rate_limited,
                    ..
                } => (permanent, rate_limited),
                Mint::Ok { .. } => panic!("ok"),
            }
        }
    };
    assert_eq!(case(400, json!({"error": "invalid_grant"})).await, (true, false));
    assert_eq!(case(503, json!({"error": "backend"})).await, (false, false));
    assert_eq!(case(429, json!({"error": "rate_limit_exceeded"})).await, (false, true));
    assert_eq!(case(403, json!({"error": "rate_limit_exceeded"})).await, (false, true));
    assert_eq!(case(400, json!({"error": "invalid_request"})).await, (false, false));
    // A network error is retryable.
    g.down.store(true, Ordering::SeqCst);
    assert!(matches!(
        mint(&g.clone(), &oauth_account(), NOW).await.mint,
        Mint::Err { permanent: false, .. }
    ));
    // Each source refuses the other's account.
    g.down.store(false, Ordering::SeqCst);
    let mut swapped = sa_account();
    swapped.secret = Some(DriveSecret::OAuth { refresh: "x".into() });
    assert!(matches!(
        mint(&g.clone(), &swapped, NOW).await.mint,
        Mint::Err { permanent: true, .. }
    ));
}

#[test]
fn readings_of_google_errors() {
    use crate::channels::google::tokens::{is_permanent_api_refusal, is_permanent_refusal};
    let o = |v: Value| v.as_object().cloned().unwrap();
    assert!(is_permanent_refusal(400, &o(json!({"error": "invalid_grant"}))));
    assert!(!is_permanent_refusal(403, &o(json!({"error": "invalid_grant"}))));
    assert!(!is_permanent_refusal(500, &o(json!({"error": "invalid_client"}))));
    assert!(!is_permanent_api_refusal(
        403,
        &o(json!({"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}))
    ));
    assert!(is_permanent_api_refusal(
        403,
        &o(json!({"error": {"errors": [{"reason": "accessNotConfigured"}]}}))
    ));
    assert!(is_permanent_api_refusal(
        403,
        &o(json!({"error": {"status": "PERMISSION_DENIED"}}))
    ));
    assert!(!is_permanent_api_refusal(
        403,
        &o(json!({"error": {"status": "RESOURCE_EXHAUSTED"}}))
    ));
    assert!(is_permanent_api_refusal(
        403,
        &o(json!({"error": {"message": "Drive API has not been used in project 1"}}))
    ));
    assert!(is_permanent_api_refusal(401, &o(json!({}))));
    let k = |st: u16, v: Value| classify_drive_error(st, &o(v));
    assert_eq!(k(429, json!({})), DriveErrorKind::RateLimited);
    assert_eq!(
        k(403, json!({"error": {"errors": [{"reason": "dailyLimitExceeded"}]}})),
        DriveErrorKind::RateLimited
    );
    assert_eq!(
        k(
            403,
            json!({"error": {"errors": [{"reason": "storageQuotaExceeded"}], "status": "RESOURCE_EXHAUSTED"}})
        ),
        DriveErrorKind::StorageQuota
    );
    assert_eq!(
        k(
            403,
            json!({"error": {"message": "The user's Drive storage quota has been exceeded."}})
        ),
        DriveErrorKind::StorageQuota
    );
    assert_eq!(
        k(403, json!({"error": {"status": "RESOURCE_EXHAUSTED"}})),
        DriveErrorKind::RateLimited
    );
    assert_eq!(
        k(403, json!({"error": {"message": "Rate Limit Exceeded"}})),
        DriveErrorKind::RateLimited
    );
    assert_eq!(
        k(
            403,
            json!({"error": {"errors": [{"reason": "insufficientFilePermissions"}]}})
        ),
        DriveErrorKind::NoAccess
    );
    assert_eq!(k(404, json!({})), DriveErrorKind::NoAccess);
    assert_eq!(k(500, json!({})), DriveErrorKind::Other);
    assert_eq!(retry_after_ms(Some("7"), 0), Some(7000));
    assert_eq!(retry_after_ms(None, 0), None);
    assert_eq!(retry_after_ms(Some("99999999999999999999"), 0), Some(i64::MAX));
    assert_eq!(retry_after_ms(Some("soon"), 0), None);
    let at = 784_111_777_000; // Sun, 06 Nov 1994 08:49:37 GMT
    assert_eq!(
        retry_after_ms(Some("Sun, 06 Nov 1994 08:49:37 GMT"), at - 5000),
        Some(5000)
    );
    assert_eq!(
        retry_after_ms(Some("Sun, 06 Nov 1994 08:49:37 GMT"), at + 5000),
        Some(0)
    );
    let b = |s: Option<&'static str>| Borrowed {
        account_label: None,
        token: Some("t".into()),
        drive_scope: s,
        failed: None,
    };
    assert_eq!(
        scope_for_borrowed(Some(&b(Some("full")))),
        Some(store::DRIVE_WRITE_SCOPE)
    );
    assert_eq!(
        scope_for_borrowed(Some(&b(Some("readonly")))),
        Some(store::DRIVE_READ_SCOPE)
    );
    assert_eq!(scope_for_borrowed(Some(&b(Some("file")))), None);
    assert_eq!(scope_for_borrowed(None), None);
}

#[tokio::test]
async fn probe_drive_reads_throttles_disabled_apis_and_bare_answers() {
    let g = Arc::new(Google::default());
    assert!(probe_drive(&g.clone(), "t").await.is_ok());
    g.on(
        "drive/v3/files",
        vec![(
            403,
            json!({"error": {"errors": [{"reason": "userRateLimitExceeded"}], "message": "x"}}),
        )],
    );
    assert_eq!(
        probe_drive(&g.clone(), "t").await,
        Err((false, "Google is limiting requests right now.".into()))
    );
    g.on("drive/v3/files", vec![(403, json!({"error": {"errors": [{"reason": "accessNotConfigured"}], "message": "Drive API has not been used in project 9. If you enabled this API recently, wait"}}))]);
    assert_eq!(
        probe_drive(&g.clone(), "t").await,
        Err((true, "Drive API has not been used in project 9.".into()))
    );
    g.on("drive/v3/files", vec![(500, json!(null))]);
    assert_eq!(
        probe_drive(&g.clone(), "t").await,
        Err((false, "Drive answered 500.".into()))
    );
}

fn quick(sleeps: Arc<Mutex<Vec<i64>>>, clock: Arc<AtomicI64>) -> WriteCheckOptions {
    let c2 = clock.clone();
    WriteCheckOptions {
        sleep: Arc::new(move |ms| {
            sleeps.lock().unwrap().push(ms);
            c2.fetch_add(ms, Ordering::SeqCst);
            Box::pin(async {})
        }),
        now: Arc::new(move || clock.load(Ordering::SeqCst)),
        random: Arc::new(|| 0.5),
        budget_ms: WRITE_CHECK_BUDGET_MS,
    }
}

const UPLOAD: &str = "upload/drive/v3/files";

#[tokio::test]
async fn the_write_check_retries_throttles_and_server_errors_only() {
    let throttle = (
        403,
        json!({"error": {"errors": [{"reason": "userRateLimitExceeded"}], "message": "User rate limit exceeded."}}),
    );
    // Three tries with growing backoff, then the throttle.
    let g = Arc::new(Google::default());
    g.on(UPLOAD, vec![throttle.clone()]);
    let sleeps = Arc::new(Mutex::new(vec![]));
    let r = probe_folder_write(
        Arc::new(g.clone()),
        "t",
        "folder123456",
        &quick(sleeps.clone(), Arc::new(AtomicI64::new(0))),
    )
    .await;
    assert!(matches!(
        r,
        WriteCheck::Refused {
            kind: DriveErrorKind::RateLimited,
            transient: true,
            ..
        }
    ));
    assert_eq!(g.hits(UPLOAD), 3);
    assert_eq!(*sleeps.lock().unwrap(), vec![2000, 6000]);
    // A retry that gets through passes, and the probe file is deleted.
    let g = Arc::new(Google::default());
    g.on(UPLOAD, vec![throttle.clone(), (200, json!({"id": "file1"}))]);
    let r = probe_folder_write(
        Arc::new(g.clone()),
        "t",
        "folder123456",
        &quick(Arc::default(), Arc::new(AtomicI64::new(0))),
    )
    .await;
    assert_eq!(r, WriteCheck::Ok);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        g.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, u, _)| m == "DELETE" && u.contains("file1"))
            .count(),
        1
    );
    let (_, _, body) = g
        .seen
        .lock()
        .unwrap()
        .iter()
        .find(|(_, u, _)| u.contains(UPLOAD))
        .cloned()
        .unwrap();
    assert!(body.contains(r#""parents":["folder123456"]"#) && body.contains("\r\n\r\nx\r\n"));
    // Retry-After that points past the budget stops at once.
    let g = Arc::new(Google::default());
    g.on_h(
        UPLOAD,
        vec![(
            throttle.0,
            throttle.1.clone(),
            vec![("retry-after".into(), "60".into())],
        )],
    );
    let sleeps = Arc::new(Mutex::new(vec![]));
    probe_folder_write(
        Arc::new(g.clone()),
        "t",
        "folder123456",
        &quick(sleeps.clone(), Arc::new(AtomicI64::new(0))),
    )
    .await;
    assert_eq!(g.hits(UPLOAD), 1);
    assert!(sleeps.lock().unwrap().is_empty());
    // Retry-After within the budget wins over the backoff.
    let g = Arc::new(Google::default());
    g.on_h(
        UPLOAD,
        vec![
            (throttle.0, throttle.1.clone(), vec![("retry-after".into(), "5".into())]),
            (200, json!({"id": "f"}), vec![]),
        ],
    );
    let sleeps = Arc::new(Mutex::new(vec![]));
    probe_folder_write(
        Arc::new(g.clone()),
        "t",
        "folder123456",
        &quick(sleeps.clone(), Arc::new(AtomicI64::new(0))),
    )
    .await;
    assert_eq!(*sleeps.lock().unwrap(), vec![5000]);
    // A server error is retried and reported transient.
    let g = Arc::new(Google::default());
    g.on(UPLOAD, vec![(503, json!({}))]);
    let r = probe_folder_write(
        Arc::new(g.clone()),
        "t",
        "folder123456",
        &quick(Arc::default(), Arc::new(AtomicI64::new(0))),
    )
    .await;
    assert!(matches!(
        r,
        WriteCheck::Refused {
            transient: true,
            kind: DriveErrorKind::Other,
            ..
        }
    ));
    assert_eq!(g.hits(UPLOAD), 3);
    // Storage, access and other refusals are final at once.
    for body in [
        json!({"error": {"errors": [{"reason": "storageQuotaExceeded"}], "message": "The user's Drive storage quota has been exceeded. Leverage shared drives instead."}}),
        json!({"error": {"errors": [{"reason": "insufficientFilePermissions"}], "message": "no"}}),
    ] {
        let g = Arc::new(Google::default());
        g.on(UPLOAD, vec![(403, body)]);
        let r = probe_folder_write(
            Arc::new(g.clone()),
            "t",
            "folder123456",
            &quick(Arc::default(), Arc::new(AtomicI64::new(0))),
        )
        .await;
        assert!(matches!(r, WriteCheck::Refused { transient: false, .. }));
        if let WriteCheck::Refused { reason, .. } = r {
            assert!(!reason.contains("Leverage"));
        }
        assert_eq!(g.hits(UPLOAD), 1);
    }
}

// ---- the module ------------------------------------------------------------------------------

#[derive(Default)]
struct Box_ {
    calls: Mutex<Vec<(String, Value)>>,
    down: Mutex<Vec<String>>,
}

impl AgentCalls for Arc<Box_> {
    fn post(
        &self,
        t: &Target,
        path: &str,
        body: Value,
        _: Option<Duration>,
    ) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        assert_eq!(path, "/drive/apply");
        self.calls.lock().unwrap().push((t.vm_id.clone(), body));
        let r = if self.down.lock().unwrap().contains(&t.vm_id) {
            Err(AgentError::new("The agent did not answer in time."))
        } else {
            Ok(Map::new())
        };
        Box::pin(async move { r })
    }
    fn get(&self, _: &Target, _: &str, _: Option<Duration>) -> BoxFuture<Result<Map<String, Value>, AgentError>> {
        Box::pin(async { Ok(Map::new()) })
    }
}

#[derive(Default)]
struct Codes(Mutex<HashMap<String, (String, Value)>>, Mutex<Vec<String>>);

impl ConsentCodes for Codes {
    fn send(&self, req: CodeRequest) -> BoxFuture<SendResult> {
        self.1.lock().unwrap().push(req.summary.clone());
        self.0.lock().unwrap().insert(req.scope, (req.change_id, req.proposal));
        Box::pin(async {
            SendResult {
                sent_via: Some("telegram:Owner".into()),
                error: None,
                delivery_failed: false,
                expires_at_ms: 0,
            }
        })
    }
    fn verify(&self, scope: &str, change_id: &str, code: &str) -> Verify {
        let mut p = self.0.lock().unwrap();
        match p.get(scope) {
            Some((c, _)) if c == change_id && code == "123456" => Verify::Ok(p.remove(scope).unwrap().1),
            Some((c, _)) if c == change_id => Verify::Wrong { tries_left: 4 },
            _ => Verify::Expired,
        }
    }
    fn cancel(&self, scope: &str, _: Option<&str>) -> bool {
        self.0.lock().unwrap().remove(scope).is_some()
    }
    fn forget(&self, scope: &str) {
        self.0.lock().unwrap().remove(scope);
    }
}

struct T {
    dir: tempfile::TempDir,
    google: Arc<Google>,
    agent: Arc<Box_>,
    codes: Arc<Codes>,
    routes: Arc<Mutex<Option<Vec<Value>>>>,
    now: Arc<AtomicI64>,
    borrowed: Arc<Mutex<Option<Borrowed>>>,
}

fn t() -> T {
    let g = Arc::new(Google::default());
    g.on(
        "oauth2.googleapis.com/token",
        vec![(200, json!({"access_token": "ya29.drive", "expires_in": 3600}))],
    );
    g.on(UPLOAD, vec![(200, json!({"id": "probe"}))]);
    T {
        dir: tempfile::tempdir().unwrap(),
        google: g,
        agent: Arc::default(),
        codes: Arc::default(),
        routes: Arc::new(Mutex::new(Some(vec![]))),
        now: Arc::new(AtomicI64::new(NOW)),
        borrowed: Arc::default(),
    }
}

impl T {
    fn make(&self) -> Arc<DriveFirewall> {
        let (codes, routes, now, b) = (
            self.codes.clone(),
            self.routes.clone(),
            self.now.clone(),
            self.borrowed.clone(),
        );
        let clock = Arc::new(AtomicI64::new(0));
        DriveFirewall::new(DriveOptions {
            store_path: self.dir.path().join("drive.enc"),
            box_key: KEY.into(),
            org_id: "org1".into(),
            box_id: "fw1".into(),
            agent: Arc::new(self.agent.clone()),
            codes: Arc::new(move || Some(codes.clone() as Arc<dyn ConsentCodes>)),
            code_routes: Arc::new(move || routes.lock().unwrap().clone()),
            google_account: Arc::new(move || b.lock().unwrap().clone()),
            on_credentials_changed: None,
            http: Arc::new(self.google.clone()),
            now: Arc::new(move || now.load(Ordering::SeqCst)),
            write_check: quick(Arc::default(), clock),
        })
        .unwrap()
    }
    fn with_routes(&self) {
        *self.routes.lock().unwrap() = Some(vec![
            json!({"target": {"vmId": "vm9", "hostname": "x"}, "senders": [{"type": "telegram", "id": "1"}]}),
        ]);
    }
    fn last_to(&self, vm: &str) -> Option<Value> {
        self.agent
            .calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|c| c.0 == vm)
            .map(|c| c.1.clone())
    }
    fn borrow(&self, scope: Option<&'static str>, token: Option<&str>) {
        *self.borrowed.lock().unwrap() = Some(Borrowed {
            account_label: Some("me@gmail.com".into()),
            token: token.map(str::to_string),
            drive_scope: scope,
            failed: None,
        });
    }
}

fn m(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

fn a1() -> Value {
    json!({"vmId": "vm1", "name": "support", "hostname": "support.example"})
}
fn a2() -> Value {
    json!({"vmId": "vm2", "name": "research", "hostname": "research.example"})
}

fn connect_sa(scope: &str) -> Map<String, Value> {
    m(json!({
        "changeId": "c1", "kind": "connect_account",
        "account": {"kind": "service_account", "scope": scope, "accountLabel": null},
        "secret": {"clientEmail": "drive@proj.iam.gserviceaccount.com", "privateKey": SA_KEY, "tokenUri": "https://oauth2.googleapis.com/token"},
    }))
}

fn folder(id: &str, name: &str, mode: &str, agents: Value, kind: &str) -> Map<String, Value> {
    m(
        json!({"changeId": format!("f-{id}-{kind}"), "kind": kind, "folder": {"id": id, "folderId": format!("{name}FolderId00"), "name": name, "mode": mode}, "agents": agents}),
    )
}

#[tokio::test]
async fn connect_add_mount_codes_credentials_and_push() {
    let t = t();
    let fw = t.make();
    assert!(
        !store::is_valid_folder_name("../etc")
            && !store::is_valid_folder_name("Trailing ")
            && store::is_valid_folder_name("Shared docs")
    );
    assert!(!store::is_valid_folder_id("short") && store::is_valid_folder_id("1AbCdEfGhIjKl"));
    // An account first.
    let r = fw
        .command("propose", folder("f1", "Docs", "ro", json!([a1()]), "add_folder"))
        .await;
    assert!(r.message.unwrap().contains("Connect a Google account"));
    // First use: applies at once and mints.
    let c = fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    assert_eq!(c.status, "applied");
    assert_eq!(c.data.as_ref().unwrap()["tofu"], true);
    assert_eq!(
        c.data.as_ref().unwrap()["accountLabel"],
        "drive@proj.iam.gserviceaccount.com"
    );
    let sum = fw.summary().to_string();
    assert!(!sum.contains("ya29") && !sum.contains("PRIVATE KEY"));
    // With somebody to ask: a code, then the right one applies.
    t.with_routes();
    let p = fw
        .command("propose", folder("f1", "Docs", "ro", json!([a1(), a2()]), "add_folder"))
        .await;
    assert_eq!(p.status, "awaiting_code");
    assert_eq!(
        t.codes.1.lock().unwrap()[0],
        "Mount the Drive folder Docs (read-only) on support and research"
    );
    assert_eq!(
        fw.command("confirm", m(json!({"changeId": "f-f1-add_folder", "code": "000000"})))
            .await
            .status,
        "invalid_code"
    );
    let ok = fw
        .command("confirm", m(json!({"changeId": "f-f1-add_folder", "code": "123456"})))
        .await;
    assert_eq!(ok.status, "applied");
    assert_eq!(ok.data.as_ref().unwrap()["sentVia"], "telegram:Owner");
    let body = t.last_to("vm1").unwrap();
    assert_eq!(
        body["mounts"],
        json!([{"name": "Docs", "folderId": "DocsFolderId00", "mode": "ro"}])
    );
    assert_eq!(body["connected"], true);
    assert!(!body.to_string().contains("ya29"));
    let creds = fw.credentials();
    assert_eq!(creds.len(), 2);
    assert_eq!(creds[0]["match_domain"], "www.googleapis.com");
    assert_ne!(creds[0]["placeholder"], creds[1]["placeholder"]);
    // Unassign pushes the shorter set to the one that lost it.
    *t.routes.lock().unwrap() = Some(vec![]);
    fw.command("propose", folder("f1", "Docs", "ro", json!([a2()]), "unassign"))
        .await;
    assert_eq!(t.last_to("vm2").unwrap()["mounts"], json!([]));
    assert_eq!(fw.credentials().len(), 1);
    // A push re-applies what the firewall holds; one for a stranger is a no-op.
    assert_eq!(
        fw.command("push", m(json!({"vmId": "vm1"}))).await.data.unwrap()["mounts"],
        json!(["Docs"])
    );
    assert_eq!(fw.command("push", m(json!({"vmId": "nobody"}))).await.status, "applied");
    // A box down: named, and the change is kept.
    t.agent.down.lock().unwrap().push("vm1".into());
    let r = fw
        .command("propose", folder("f2", "Notes", "ro", json!([a1()]), "add_folder"))
        .await;
    assert_eq!(r.data.unwrap()["failed"][0]["vmId"], "vm1");
    assert_eq!(fw.summary()["folders"].as_array().unwrap().len(), 2);
    t.agent.down.lock().unwrap().clear();
    // Forgetting unmounts everywhere.
    fw.command("propose", m(json!({"changeId": "x", "kind": "forget_account"})))
        .await;
    assert!(fw.credentials().is_empty());
    assert_eq!(t.last_to("vm1").unwrap()["mounts"], json!([]));
    // A store reopens under its own binding only.
    assert!(t.make().summary()["accounts"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn refusals_caps_names_and_rows() {
    let t = t();
    let fw = t.make();
    t.google.on(
        "oauth2.googleapis.com/token",
        vec![(
            400,
            json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."}),
        )],
    );
    let r = fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    assert_eq!(
        r.message.as_deref(),
        Some("Google refused this connection: Invalid JWT Signature.")
    );
    assert!(fw.summary()["accounts"].as_array().unwrap().is_empty());
    t.google.on(
        "oauth2.googleapis.com/token",
        vec![(429, json!({"error": "rate_limit_exceeded"}))],
    );
    let r = fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    assert_eq!(r.data.unwrap()["transient"], true);
    assert!(
        r.message
            .unwrap()
            .starts_with("Google is limiting requests from drive@proj")
    );
    t.google.on(
        "oauth2.googleapis.com/token",
        vec![(200, json!({"access_token": "ya29.drive", "expires_in": 3600}))],
    );
    t.google.on(
        "drive/v3/files?pageSize",
        vec![(
            403,
            json!({"error": {"errors": [{"reason": "accessNotConfigured"}], "message": "Drive API is disabled."}}),
        )],
    );
    let r = fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    assert_eq!(
        r.message.as_deref(),
        Some("The key works, but Drive does not answer for it: Drive API is disabled.")
    );
    t.google.on("drive/v3/files?pageSize", vec![(503, json!({}))]);
    assert_eq!(
        fw.command("propose", connect_sa(store::DRIVE_READ_SCOPE)).await.status,
        "applied",
        "a blip still connects"
    );
    t.google
        .on("drive/v3/files?pageSize", vec![(200, json!({"files": []}))]);
    // A read-write folder on a read-only connection.
    assert!(
        fw.command("propose", folder("f1", "Docs", "rw", json!([a1()]), "add_folder"))
            .await
            .message
            .unwrap()
            .contains("read-only")
    );
    fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    for (i, n) in ["One", "Two", "Three", "Four"].iter().enumerate() {
        assert_eq!(
            fw.command(
                "propose",
                folder(&format!("f{i}"), n, "ro", json!([a1()]), "add_folder")
            )
            .await
            .status,
            "applied"
        );
    }
    assert!(
        fw.command("propose", folder("f9", "Five", "ro", json!([a1()]), "add_folder"))
            .await
            .message
            .unwrap()
            .contains("at most 4")
    );
    assert!(
        fw.command("propose", folder("f8", "One", "ro", json!([]), "add_folder"))
            .await
            .message
            .unwrap()
            .contains("already mounted as One")
    );
    let mut repoint = folder("f0", "One", "ro", json!([]), "add_folder");
    repoint["folder"]["folderId"] = json!("SomeOtherFolder1");
    assert!(
        fw.command("propose", repoint)
            .await
            .message
            .unwrap()
            .contains("different folder")
    );
    // Reconnecting without write access while a folder is read-write.
    fw.command("propose", folder("f0", "One", "rw", json!([a1()]), "edit_folder"))
        .await;
    let r = fw.command("propose", connect_sa(store::DRIVE_READ_SCOPE)).await;
    assert!(
        r.message
            .unwrap()
            .contains("One is mounted read-write. Make it read-only first")
    );
    // An unreadable channel store blocks the change.
    *t.routes.lock().unwrap() = None;
    assert_eq!(
        fw.command("propose", folder("f1", "Two", "ro", json!([]), "edit_folder"))
            .await
            .message
            .as_deref(),
        Some(crate::channels::google::NO_CHANNELS)
    );
}

#[tokio::test]
async fn read_write_folders_are_probed_by_writing() {
    let t = t();
    let fw = t.make();
    fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    t.google.on(UPLOAD, vec![(403, json!({"error": {"errors": [{"reason": "storageQuotaExceeded"}], "message": "Service Accounts do not have storage quota. Leverage shared drives instead."}}))]);
    let r = fw
        .command("propose", folder("f1", "Docs", "rw", json!([a1()]), "add_folder"))
        .await;
    assert_eq!(
        r.message.as_deref(),
        Some(
            "Docs cannot be mounted read-write. Service Accounts do not have storage quota. A service account has no storage of its own, so it can only write to a folder on a shared drive, or with domain-wide delegation. Mount it read-only instead."
        )
    );
    // Read-only folders are not probed.
    let before = t.google.hits(UPLOAD);
    fw.command("propose", folder("f2", "Ro", "ro", json!([a1()]), "add_folder"))
        .await;
    assert_eq!(t.google.hits(UPLOAD), before);
    // A permission refusal names the account and says Editor; it is not retried.
    t.google.on(
        UPLOAD,
        vec![(
            403,
            json!({"error": {"errors": [{"reason": "insufficientFilePermissions"}], "message": "No."}}),
        )],
    );
    let before = t.google.hits(UPLOAD);
    let r = fw
        .command("propose", folder("f3", "Shared", "rw", json!([a1()]), "add_folder"))
        .await;
    assert!(
        r.message
            .unwrap()
            .contains("Share the folder with drive@proj.iam.gserviceaccount.com as Editor")
    );
    assert_eq!(t.google.hits(UPLOAD) - before, 1);
    // A throttle through every retry: limiting requests, no sharing advice, transient.
    t.google.on(
        UPLOAD,
        vec![(403, json!({"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}))],
    );
    let r = fw
        .command("propose", folder("f4", "Busy", "rw", json!([a1()]), "add_folder"))
        .await;
    assert_eq!(r.data.unwrap()["transient"], true);
    let msg = r.message.unwrap();
    assert!(
        msg.contains("limiting requests") && msg.ends_with("or add the folder read-only.") && !msg.contains("Editor")
    );
    // An outage is a try-again.
    t.google.on(UPLOAD, vec![(503, json!({}))]);
    let r = fw
        .command("propose", folder("f5", "Down", "rw", json!([a1()]), "add_folder"))
        .await;
    assert!(r.message.unwrap().contains("could not be checked for writing"));
    // A folder that can be written is accepted.
    t.google.on(UPLOAD, vec![(200, json!({"id": "probe"}))]);
    assert_eq!(
        fw.command("propose", folder("f6", "Fine", "rw", json!([a1()]), "add_folder"))
            .await
            .status,
        "applied"
    );
}

#[tokio::test]
async fn minting_inside_the_window_permanent_and_transient_failures_and_a_replaced_account() {
    let t = t();
    let fw = t.make();
    fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await;
    fw.command("propose", folder("f1", "Docs", "ro", json!([a1()]), "add_folder"))
        .await;
    let mints = t.google.hits("oauth2.googleapis.com/token");
    fw.refresh_due().await;
    assert_eq!(t.google.hits("oauth2.googleapis.com/token"), mints, "not due");
    t.now
        .fetch_add(3_600_000 - DRIVE_REFRESH_AHEAD_MS + 1, Ordering::SeqCst);
    t.google.on("oauth2.googleapis.com/token", vec![(503, json!({}))]);
    fw.refresh_due().await;
    assert_eq!(fw.credentials()[0]["secret"], "ya29.drive", "a blip keeps the token");
    t.google.on(
        "oauth2.googleapis.com/token",
        vec![(400, json!({"error": "invalid_grant"}))],
    );
    fw.refresh_due().await;
    assert!(fw.credentials().is_empty());
    assert_eq!(fw.drain_reports()[0].command_id, "drive.token:account");
    assert!(
        fw.summary()["accounts"][0]["failed"]
            .as_str()
            .unwrap()
            .starts_with("Google refused the connection")
    );
}

#[tokio::test]
async fn a_borrowed_connection() {
    let t = t();
    let fw = t.make();
    let borrow = |scope: &str| {
        m(
            json!({"changeId": "b", "kind": "connect_account", "account": {"kind": "google_account", "scope": scope, "accountLabel": null}}),
        )
    };
    // Nothing to borrow.
    assert!(
        fw.command("propose", borrow(store::DRIVE_WRITE_SCOPE))
            .await
            .message
            .unwrap()
            .contains("no Google account connected")
    );
    // More Drive than Google granted.
    t.borrow(Some("readonly"), Some("ya29.google"));
    assert!(
        fw.command("propose", borrow(store::DRIVE_WRITE_SCOPE))
            .await
            .message
            .unwrap()
            .contains("does not grant that much")
    );
    // A secret on a borrowed connection.
    let mut with_secret = borrow(store::DRIVE_READ_SCOPE);
    with_secret.insert("secret".into(), json!({"refresh": "x"}));
    assert!(
        fw.command("propose", with_secret)
            .await
            .message
            .unwrap()
            .contains("must not carry a secret")
    );
    // Mints nothing, stores no secret, spends the Google token.
    t.borrow(Some("full"), Some("ya29.google"));
    let mints = t.google.hits("token");
    assert_eq!(
        fw.command("propose", borrow(store::DRIVE_WRITE_SCOPE)).await.status,
        "applied"
    );
    assert_eq!(t.google.hits("token"), mints);
    fw.command("propose", folder("f1", "Docs", "rw", json!([a1()]), "add_folder"))
        .await;
    assert_eq!(fw.credentials()[0]["secret"], "ya29.google");
    let raw = std::fs::read_to_string(t.dir.path().join("drive.enc")).unwrap();
    assert!(!raw.contains("ya29"));
    // The swapped token follows the account; refresh leaves it alone.
    t.borrow(Some("full"), Some("ya29.google2"));
    assert_eq!(fw.credentials()[0]["secret"], "ya29.google2");
    t.now.fetch_add(10 * 3_600_000, Ordering::SeqCst);
    fw.refresh_due().await;
    assert_eq!(t.google.hits("token"), mints);
    // A move re-applies once, not on every refresh.
    let pushes = t.agent.calls.lock().unwrap().len();
    fw.on_google_account_changed().await;
    fw.on_google_account_changed().await;
    assert_eq!(t.agent.calls.lock().unwrap().len(), pushes + 1);
    // Narrowed to read-only: mounts read-only, the summary says why.
    t.borrow(Some("readonly"), Some("ya29.google2"));
    assert_eq!(fw.apply_body("vm1")["mounts"][0]["mode"], "ro");
    assert!(
        fw.summary()["accounts"][0]["failed"]
            .as_str()
            .unwrap()
            .contains("Read only")
    );
    // Restart while the account is down: the boxes are still told.
    t.borrow(Some("readonly"), None);
    let again = t.make();
    let pushes = t.agent.calls.lock().unwrap().len();
    again.on_google_account_changed().await;
    assert_eq!(t.agent.calls.lock().unwrap().len(), pushes + 1);
    assert_eq!(t.last_to("vm1").unwrap()["connected"], false);
    // No Google module at all: reported as not working.
    *t.borrowed.lock().unwrap() = None;
    assert_eq!(again.summary()["accounts"][0]["connected"], false);
    assert!(
        again.summary()["accounts"][0]["failed"]
            .as_str()
            .unwrap()
            .contains("no Google account connected")
    );
    // A user account's write refusal gets the user-account sentence.
    t.borrow(Some("full"), Some("ya29.google3"));
    t.google.on(
        UPLOAD,
        vec![(
            403,
            json!({"error": {"errors": [{"reason": "insufficientFilePermissions"}], "message": "No."}}),
        )],
    );
    let r = again
        .command("propose", folder("f2", "Theirs", "rw", json!([a1()]), "add_folder"))
        .await;
    assert!(r.message.unwrap().contains("me@gmail.com owns storage"));
}

#[test]
fn summaries_read_as_sentences() {
    let p = |kind: &str, account: Option<ProposedAccount>, agents: Vec<AgentRef>| Proposal {
        change_id: "c".into(),
        kind: kind.into(),
        account_id: None,
        account,
        secret: None,
        folder: Some(ProposedFolder {
            id: "f".into(),
            folder_id: "x".into(),
            name: "Docs".into(),
            mode: "rw".into(),
        }),
        agents,
    };
    let acc = |kind: &str, label: Option<&str>| {
        Some(ProposedAccount {
            kind: kind.into(),
            scope: "s".into(),
            account_label: label.map(str::to_string),
            oauth: None,
        })
    };
    assert_eq!(
        summarize(&p(
            "connect_account",
            acc("google_account", Some("me@gmail.com")),
            vec![]
        )),
        "Connect Google Drive folders using the Google account you connected (me@gmail.com)"
    );
    assert_eq!(
        summarize(&p("replace_account", acc("service_account", None), vec![])),
        "Reconnect Google Drive folders using a service account key"
    );
    assert_eq!(
        summarize(&p("add_folder", None, vec![])),
        "Add the Drive folder Docs (read and write)"
    );
    assert_eq!(
        summarize(&p("edit_folder", None, vec![])),
        "Change the Drive folder Docs to read and write"
    );
    assert_eq!(
        summarize(&p("remove_folder", None, vec![])),
        "Stop mounting the Drive folder Docs everywhere"
    );
    assert_eq!(
        summarize(&p("unassign", None, vec![])),
        "Stop mounting the Drive folder Docs on no agent yet"
    );
}

/// Review: a connect's secret never reaches the consent module; a restart before the code asks for
/// a new connection.
#[tokio::test]
async fn a_connects_secret_stays_on_the_firewall_until_the_code() {
    let t = t();
    t.with_routes();
    let fw = t.make();
    assert_eq!(
        fw.command("propose", connect_sa(store::DRIVE_WRITE_SCOPE)).await.status,
        "awaiting_code"
    );
    let kept = format!("{:?}", t.codes.0.lock().unwrap());
    assert!(!kept.contains("PRIVATE KEY"), "{kept}");
    let mut oauth = m(json!({
        "changeId": "c2", "kind": "connect_account",
        "account": {"kind": "oauth", "scope": store::DRIVE_WRITE_SCOPE, "oauth": {"tokenEndpoint": "https://oauth2.googleapis.com/token", "clientId": "cid", "clientSecret": "csec-1"}},
        "secret": {"refresh": "1//refresh-x"},
    }));
    assert_eq!(fw.command("propose", oauth.clone()).await.status, "awaiting_code");
    let kept = format!("{:?}", t.codes.0.lock().unwrap());
    assert!(!kept.contains("csec-1") && !kept.contains("1//refresh-x"), "{kept}");
    let ok = fw
        .command("confirm", m(json!({"changeId": "c2", "code": "123456"})))
        .await;
    assert_eq!(ok.status, "applied", "{:?}", ok.message);
    let mint = t
        .google
        .seen
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(_, u, _)| u.contains("token"))
        .cloned()
        .unwrap();
    let f = form(&mint.2);
    assert_eq!(
        (f["client_secret"].as_str(), f["refresh_token"].as_str()),
        ("csec-1", "1//refresh-x")
    );
    // A restart between the proposal and the code.
    oauth.insert("changeId".into(), json!("c3"));
    fw.command("propose", oauth).await;
    let again = t.make();
    let r = again
        .command("confirm", m(json!({"changeId": "c3", "code": "123456"})))
        .await;
    assert!(r.message.unwrap().contains("restarted"));
}

#[test]
fn only_drive_scopes_and_the_delegated_subject_in_the_summary() {
    let p = |scope: &str| {
        json!({
            "changeId": "c", "kind": "connect_account",
            "account": {"kind": "service_account", "scope": scope},
            "secret": {"clientEmail": "sa@p.iam.gserviceaccount.com", "privateKey": "k", "tokenUri": "https://oauth2.googleapis.com/token", "subject": "ceo@acme.com"},
        })
        .as_object()
        .cloned()
        .unwrap()
    };
    let ok = parse_proposal(&p("https://www.googleapis.com/auth/drive")).unwrap();
    assert!(ok.account.is_some());
    assert_eq!(
        summarize(&ok),
        "Connect Google Drive folders using a service account key, acting as ceo@acme.com"
    );
    for wide in [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/drive https://mail.google.com/",
    ] {
        assert!(parse_proposal(&p(wide)).unwrap().account.is_none(), "{wide}");
    }
}
